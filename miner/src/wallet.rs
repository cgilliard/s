//! The node's wallet: a 12-word BIP39 phrase, one-time keys derived per
//! output, and the outputs paid to them, in an LMDB environment of its own
//! under the data directory.
//!
//! # Keys and memos
//!
//! The phrase's BIP39 seed hashes to a master secret `m`. Every output the
//! wallet creates gets a fresh random 124-bit nonce `r` (four field
//! elements) and its own key, generated from `H(m, r)`. Its memo, which goes
//! on chain with the commitment, is
//!
//! ```text
//! memo = r[4] | amount limbs + pad[0..3] | pad[3]      pad = H(m, r)'
//! ```
//!
//! so only the wallet can tell its outputs apart (the last element checks a
//! guess) and read their amounts. Recovery from the phrase alone
//! ([`Wallet::scan`]) reads every unspent memo from the UTXO set, keeps the
//! ones whose check matches, decrypts the amount and confirms it by
//! recomputing the commitment. The pad depends on each output's own nonce,
//! so a guessed phrase must be tested output by output.
//!
//! # Leaves
//!
//! A key's XMSS tree has 16 leaves. An output this wallet created signs from
//! leaves 0 to 7: its spend, then up to seven cancellations. An output found
//! by [`Wallet::scan`] signs from leaves 8 to 15, starting at a random one
//! and wrapping, so a restored copy never signs from a leaf the original
//! used, and two restored copies rarely collide. The leaf is recorded and
//! committed before a signature is made, so a crash can waste a leaf but
//! never reuse one; the eighth signature is the last.
//!
//! # Outputs and slates
//!
//! An output record carries its nonce, amount, commitment and a state:
//! `Unspent`, `Reserved` by a pending slate, or `Spent` by a signed
//! transaction. Whether an unspent output is confirmed is whether the UTXO
//! set holds its commitment.
//!
//! A payment is negotiated in a [`Slate`] passed between the two wallets as
//! a file: [`Wallet::send`] picks and reserves inputs, adds change and writes
//! the amount and fee; [`Wallet::receive_slate`] adds the recipient's output;
//! [`Wallet::finalize`] checks the balance, signs and marks the inputs
//! spent. A finalized payment can be cancelled ([`Wallet::cancel_sent`]) by
//! signing a replacement that pays the inputs back to the wallet with a
//! higher fee, which the mempool accepts in its place.
//!
//! # Names
//!
//! A name registration (see `docs/NAMES.md`) draws one nonce `r` like an
//! output: the owner key is generated from `H(m, r)` under its own domain,
//! the commit's salt is `H(m, r)` under another, and the memo of both the
//! commit's output and the name's record is the output memo with a zero
//! amount, so [`Wallet::scan_names`] recovers registered names from the
//! records every node keeps (the memo opens and the owner key's hash is
//! the record's owner) and pending commits from the commit outputs (the
//! memo opens; the name itself is learned when the user reveals it, by
//! recomputing the commit). Every signed operation rotates the owner key
//! to a fresh nonce; the old key's leaves work like an output's for
//! cancellations. A transfer is an update to a record the recipient wrote
//! ([`Wallet::name_offer`]), signed by the owner ([`Wallet::name_transfer`]).
//! Operations ride in a transaction of the wallet's that pays their fee
//! ([`Wallet::carry`]).

use std::collections::HashSet;
use std::path::Path;

use heed::types::{Bytes, Str};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::bip39;
use crate::codec::{Reader, Writer};
use crate::mempool::{MAX_TX_SIZE, Policy};
use crate::names::{self, MIN_REVEAL, NameOp, NameSet, Record, commit_hash, name_hash};
use crate::poseidon2::{DIGEST, Fp, digest_to_bytes};
use crate::state_tree::open_env;
use crate::transaction::{
    Commitment, INPUT_SIZE, Key, Memo, OUTPUT_SIZE, Output, Transaction, UnsignedTransaction, amount_fps, hash_domain,
    key_commitment, pubkey_hash,
};
use crate::utxo::{self, UtxoSet};
use crate::xmss::{PublicKey, SEED_SIZE};

const META_ENTROPY: &str = "entropy";
const META_SEED: &str = "seed";
const META_FORMAT: &str = "format";
/// Set by a restore: the wallet's outputs are still to be found on chain.
const META_SCAN_PENDING: &str = "scan_pending";
/// Height and hash of the block up to which the wallet has looked for its
/// outputs' positions.
const META_SYNCED: &str = "synced";
/// Version of the on-disk layout: 3 is BIP39 phrases and per-output keys;
/// 5 adds the name tables.
const FORMAT: u8 = 5;
/// Upper bound only, reserved as address space; the file grows as needed.
const MAP_SIZE: usize = 64 << 30;
const SLATE_MAGIC: &[u8; 8] = b"tabslt02";

const DOM_MASTER: u32 = 0x30;
const DOM_PAD: u32 = 0x31;
const DOM_KEY: u32 = 0x32;
const DOM_OWNER: u32 = 0x33;
const DOM_SALT: u32 = 0x34;
/// Nonce elements in a memo.
const NONCE: usize = 4;
/// Leaves a key may sign from, in each half of its tree.
pub const LEAVES_PER_HALF: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Unspent,
    /// Picked as an input of a pending slate.
    Reserved,
    /// Signed away by a finalized transaction.
    Spent,
}

impl State {
    fn to_u8(self) -> u8 {
        match self {
            State::Unspent => 0,
            State::Reserved => 1,
            State::Spent => 2,
        }
    }

    fn from_u8(b: u8) -> Option<State> {
        match b {
            0 => Some(State::Unspent),
            1 => Some(State::Reserved),
            2 => Some(State::Spent),
            _ => None,
        }
    }
}

/// An output paid to one of the wallet's keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owned {
    pub commitment: Commitment,
    pub nonce: [Fp; NONCE],
    pub amount: u64,
    pub state: State,
    /// Unix time the record was made.
    pub created: u64,
    /// Found by [`Wallet::scan`] rather than created by this wallet: signs
    /// from leaves 8 to 15.
    pub recovered: bool,
    /// Offset of the first leaf within the key's half (random when
    /// recovered, zero otherwise).
    pub start: u8,
    /// Signatures made so far, at most [`LEAVES_PER_HALF`].
    pub used: u8,
    /// Where the output landed in the UTXO set, once a block added it
    /// (see [`Wallet::locate`]).
    pub position: Option<u64>,
}

impl Owned {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        w.fps(&self.nonce);
        w.u64(self.amount);
        w.0.push(self.state.to_u8());
        w.u64(self.created);
        w.0.push(self.recovered as u8);
        w.0.push(self.start);
        w.0.push(self.used);
        if let Some(p) = self.position {
            w.u64(p);
        }
        w.finish()
    }

    fn from_bytes(commitment: Commitment, bytes: &[u8]) -> Option<Owned> {
        let mut r = Reader(bytes);
        let nonce = [r.fp()?, r.fp()?, r.fp()?, r.fp()?];
        let amount = r.u64()?;
        let state = State::from_u8(r.take(1)?[0])?;
        let created = r.u64()?;
        let flags = r.take(3)?;
        let (recovered, start, used) = (flags[0] == 1, flags[1], flags[2]);
        if flags[0] > 1 || u32::from(start) >= LEAVES_PER_HALF || u32::from(used) > LEAVES_PER_HALF {
            return None;
        }
        let position = if r.is_empty() { None } else { Some(r.u64()?) };
        r.is_empty().then_some(Owned { commitment, nonce, amount, state, created, recovered, start, used, position })
    }

    /// Signatures this output can still make.
    pub fn signatures_left(&self) -> u32 {
        LEAVES_PER_HALF - u32::from(self.used)
    }
}

/// A commit this wallet made, or found by a scan, awaiting its reveal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCommit {
    pub commit: Commitment,
    pub nonce: [Fp; NONCE],
    /// Unknown for a commit found by a scan, until the user reveals it.
    pub name: Option<Vec<u8>>,
    pub value: Commitment,
    pub created: u64,
    pub recovered: bool,
}

impl PendingCommit {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.fps(&self.nonce);
        let name = self.name.as_deref().unwrap_or(&[]);
        w.0.push(name.len() as u8);
        w.0.extend_from_slice(name);
        w.digest(&self.value);
        w.u64(self.created);
        w.0.push(self.recovered as u8);
        w.finish()
    }

    fn from_bytes(commit: Commitment, bytes: &[u8]) -> Option<PendingCommit> {
        let mut r = Reader(bytes);
        let nonce = [r.fp()?, r.fp()?, r.fp()?, r.fp()?];
        let n = r.take(1)?[0] as usize;
        let name = r.take(n)?.to_vec();
        let value = r.digest()?;
        let created = r.u64()?;
        let recovered = r.take(1)?[0] == 1;
        r.is_empty().then_some(PendingCommit {
            commit,
            nonce,
            name: (n > 0).then_some(name),
            value,
            created,
            recovered,
        })
    }
}

/// Where a name of the wallet's stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameStage {
    /// Its reveal is signed; the record is not on chain yet.
    Revealed,
    /// The chain's record names this wallet's key.
    Owned,
    /// The wallet wrote a record for it, to receive it from its owner.
    Offered,
}

/// A name this wallet owns, or is about to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedName {
    pub name: Vec<u8>,
    /// The current owner key's nonce.
    pub nonce: [Fp; NONCE],
    pub value: Commitment,
    pub created: u64,
    pub stage: NameStage,
    /// Found by a scan: the key signs from leaves 8 to 15.
    pub recovered: bool,
    pub start: u8,
    pub used: u8,
    /// A rotation signed but not yet on chain: the new key's nonce and the
    /// value written.
    pub pending: Option<([Fp; NONCE], Commitment)>,
    /// Signed over to another wallet; the record goes once the chain shows it.
    pub transferring: bool,
}

impl OwnedName {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.fps(&self.nonce);
        w.digest(&self.value);
        w.u64(self.created);
        w.0.push(match self.stage {
            NameStage::Revealed => 0,
            NameStage::Owned => 1,
            NameStage::Offered => 2,
        });
        w.0.extend_from_slice(&[self.recovered as u8, self.start, self.used, self.transferring as u8]);
        match &self.pending {
            Some((nonce, value)) => {
                w.0.push(1);
                w.fps(nonce);
                w.digest(value);
            }
            None => w.0.push(0),
        }
        w.finish()
    }

    fn from_bytes(name: Vec<u8>, bytes: &[u8]) -> Option<OwnedName> {
        let mut r = Reader(bytes);
        let nonce = [r.fp()?, r.fp()?, r.fp()?, r.fp()?];
        let value = r.digest()?;
        let created = r.u64()?;
        let stage = match r.take(1)?[0] {
            0 => NameStage::Revealed,
            1 => NameStage::Owned,
            2 => NameStage::Offered,
            _ => return None,
        };
        let flags = r.take(4)?;
        let (recovered, start, used, transferring) = (flags[0] == 1, flags[1], flags[2], flags[3] == 1);
        if u32::from(start) >= LEAVES_PER_HALF || u32::from(used) > LEAVES_PER_HALF {
            return None;
        }
        let pending = match r.take(1)?[0] {
            0 => None,
            1 => Some(([r.fp()?, r.fp()?, r.fp()?, r.fp()?], r.digest()?)),
            _ => return None,
        };
        r.is_empty().then_some(OwnedName {
            name,
            nonce,
            value,
            created,
            stage,
            recovered,
            start,
            used,
            pending,
            transferring,
        })
    }

    /// Signatures the current owner key can still make.
    pub fn signatures_left(&self) -> u32 {
        LEAVES_PER_HALF - u32::from(self.used)
    }
}

/// A payment under negotiation. Stage 1: the sender's inputs, change and
/// terms. Stage 2: the recipient's output added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slate {
    pub id: [u8; 32],
    pub stage: u8,
    pub amount: u64,
    pub fee: u64,
    pub inputs: Vec<(PublicKey, u64)>,
    /// The sender's change (if any) first, then the recipient's outputs.
    pub outputs: Vec<Output>,
    /// How many of `outputs` are the sender's change.
    pub change: u32,
}

impl Slate {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.0.extend_from_slice(SLATE_MAGIC);
        w.0.extend_from_slice(&self.id);
        w.0.push(self.stage);
        w.u64(self.amount);
        w.u64(self.fee);
        w.u32(self.change);
        w.u32(self.inputs.len() as u32);
        for (pk, amount) in &self.inputs {
            w.0.extend_from_slice(&pk.to_bytes());
            w.u64(*amount);
        }
        w.u32(self.outputs.len() as u32);
        for o in &self.outputs {
            w.0.extend_from_slice(&o.to_bytes());
        }
        w.finish()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Slate> {
        let mut r = Reader(bytes);
        if r.take(8)? != SLATE_MAGIC {
            return None;
        }
        let id: [u8; 32] = r.take(32)?.try_into().ok()?;
        let stage = r.take(1)?[0];
        let amount = r.u64()?;
        let fee = r.u64()?;
        let change = r.u32()?;
        let n = r.len(PublicKey::SIZE + 8)?;
        let mut inputs = Vec::with_capacity(n);
        for _ in 0..n {
            let pk = PublicKey::from_bytes(r.take(PublicKey::SIZE)?)?;
            inputs.push((pk, r.u64()?));
        }
        let n = r.len(OUTPUT_SIZE)?;
        let mut outputs = Vec::with_capacity(n);
        for _ in 0..n {
            outputs.push(Output::from_bytes(r.take(OUTPUT_SIZE)?)?);
        }
        if (change as usize) > outputs.len() || !(1..=2).contains(&stage) {
            return None;
        }
        r.is_empty().then_some(Slate { id, stage, amount, fee, inputs, outputs, change })
    }

    /// The unsigned transaction a stage-2 slate describes.
    pub fn unsigned(&self) -> UnsignedTransaction {
        UnsignedTransaction::new(self.inputs.clone(), self.outputs.clone())
    }

    pub fn id_hex(&self) -> String {
        hex(&self.id)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What the sender keeps about a pending slate: its inputs and change, by
/// commitment, and the amount and fee it offered, which the answered
/// slate must still show.
struct Pending {
    inputs: Vec<Commitment>,
    change: Option<Commitment>,
    amount: u64,
    fee: u64,
}

/// What the sender keeps about a finalized payment, to cancel it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub txid: Commitment,
    pub inputs: Vec<Commitment>,
    pub fee: u64,
    pub size: usize,
    pub created: u64,
}

fn write_commitments(w: &mut Writer, cs: &[Commitment]) {
    w.u32(cs.len() as u32);
    for c in cs {
        w.digest(c);
    }
}

fn read_commitments(r: &mut Reader) -> Option<Vec<Commitment>> {
    let n = r.len(32)?;
    (0..n).map(|_| r.digest()).collect()
}

impl Pending {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        write_commitments(&mut w, &self.inputs);
        w.0.push(self.change.is_some() as u8);
        if let Some(c) = &self.change {
            w.digest(c);
        }
        w.u64(self.amount);
        w.u64(self.fee);
        w.finish()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Pending> {
        let mut r = Reader(bytes);
        let inputs = read_commitments(&mut r)?;
        let change = match r.take(1)?[0] {
            0 => None,
            1 => Some(r.digest()?),
            _ => return None,
        };
        let amount = r.u64()?;
        let fee = r.u64()?;
        r.is_empty().then_some(Pending { inputs, change, amount, fee })
    }
}

impl Sent {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        write_commitments(&mut w, &self.inputs);
        w.u64(self.fee);
        w.u64(self.size as u64);
        w.u64(self.created);
        w.finish()
    }

    fn from_bytes(txid: Commitment, bytes: &[u8]) -> Option<Sent> {
        let mut r = Reader(bytes);
        let inputs = read_commitments(&mut r)?;
        let fee = r.u64()?;
        let size = r.u64()? as usize;
        let created = r.u64()?;
        r.is_empty().then_some(Sent { txid, inputs, fee, size, created })
    }
}

#[derive(Debug)]
pub enum WalletError {
    Heed(heed::Error),
    Utxo(utxo::Error),
    Io(std::io::Error),
    Phrase(bip39::PhraseError),
    Corrupt(&'static str),
    /// Not enough confirmed, unreserved funds.
    Insufficient {
        have: u128,
        need: u128,
    },
    /// The slate is malformed or not at the expected stage.
    BadSlate(&'static str),
    /// No pending slate or sent payment with that id.
    Unknown,
    /// An output has made all the signatures its leaves allow.
    Exhausted,
    /// The replacement fee does not exceed the original's.
    FeeTooLow {
        min: u64,
    },
    /// The wallet was written by an incompatible version.
    OldFormat,
    /// Restoring over an existing wallet.
    Exists,
    /// An input has not been seen in a block yet.
    Unconfirmed,
    /// A name operation the wallet cannot make.
    Name(String),
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletError::Heed(e) => write!(f, "wallet database: {e}"),
            WalletError::Utxo(e) => write!(f, "{e}"),
            WalletError::Io(e) => write!(f, "{e}"),
            WalletError::Phrase(e) => write!(f, "{e}"),
            WalletError::Corrupt(w) => write!(f, "corrupt wallet record: {w}"),
            WalletError::Insufficient { have, need } => write!(f, "insufficient funds: have {have}, need {need}"),
            WalletError::BadSlate(w) => write!(f, "bad slate: {w}"),
            WalletError::Unknown => f.write_str("no pending slate or sent payment with that id"),
            WalletError::Exhausted => f.write_str("an input has no signatures left"),
            WalletError::FeeTooLow { min } => write!(f, "the fee must be at least {min} base units"),
            WalletError::OldFormat => f.write_str("wallet database is from an older format"),
            WalletError::Exists => f.write_str("a wallet already exists in that directory"),
            WalletError::Unconfirmed => f.write_str("an input is not confirmed yet"),
            WalletError::Name(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for WalletError {}

impl From<heed::Error> for WalletError {
    fn from(e: heed::Error) -> Self {
        WalletError::Heed(e)
    }
}

impl From<utxo::Error> for WalletError {
    fn from(e: utxo::Error) -> Self {
        WalletError::Utxo(e)
    }
}

impl From<std::io::Error> for WalletError {
    fn from(e: std::io::Error) -> Self {
        WalletError::Io(e)
    }
}

impl From<bip39::PhraseError> for WalletError {
    fn from(e: bip39::PhraseError) -> Self {
        WalletError::Phrase(e)
    }
}

pub type Result<T> = core::result::Result<T, WalletError>;

/// Totals of a wallet's outputs by status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    /// Unspent and on chain: spendable.
    pub confirmed: u128,
    /// Unspent and not yet on chain: incoming.
    pub pending: u128,
    /// Picked as inputs of a pending slate, not yet signed.
    pub reserved: u128,
    /// Signed away by a payment that has not confirmed: about to leave.
    pub locked: u128,
}

/// A signed transaction and, for every input whose last signature it was,
/// that input's commitment.
pub struct Signed {
    pub tx: Transaction,
    pub last_signatures: Vec<Commitment>,
}

pub struct Wallet {
    env: Env,
    master: [Fp; DIGEST],
    meta: Database<Str, Bytes>,
    outputs: Database<Bytes, Bytes>,
    slates: Database<Bytes, Bytes>,
    sent: Database<Bytes, Bytes>,
    /// Pending commits by commit hash.
    commits: Database<Bytes, Bytes>,
    /// Names by name.
    names: Database<Bytes, Bytes>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_bytes<const N: usize>() -> std::io::Result<[u8; N]> {
    let mut out = [0u8; N];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut out)?;
    Ok(out)
}

/// A uniformly random field element, by rejection.
fn random_fp() -> std::io::Result<Fp> {
    loop {
        let v = u32::from_le_bytes(random_bytes::<4>()?) & 0x7fff_ffff;
        if let Some(x) = Fp::from_le_bytes(v.to_le_bytes()) {
            return Ok(x);
        }
    }
}

/// The master secret of a BIP39 seed.
fn master_of(seed: &[u8; 64]) -> [Fp; DIGEST] {
    hash_domain(DOM_MASTER, &crate::pow::pack_bytes(seed))
}

impl Wallet {
    #[allow(clippy::type_complexity)]
    fn open_env(dir: &Path) -> Result<(Env, Database<Str, Bytes>, [Database<Bytes, Bytes>; 5])> {
        let env = open_env(dir, MAP_SIZE).map_err(|e| match e {
            crate::state_tree::Error::Heed(h) => WalletError::Heed(h),
            other => WalletError::Utxo(utxo::Error::Tree(other)),
        })?;
        let mut wtxn = env.write_txn()?;
        let meta = env.create_database(&mut wtxn, Some("meta"))?;
        let outputs = env.create_database(&mut wtxn, Some("outputs"))?;
        let slates = env.create_database(&mut wtxn, Some("slates"))?;
        let sent = env.create_database(&mut wtxn, Some("sent"))?;
        let commits = env.create_database(&mut wtxn, Some("commits"))?;
        let names = env.create_database(&mut wtxn, Some("names"))?;
        wtxn.commit()?;
        Ok((env, meta, [outputs, slates, sent, commits, names]))
    }

    /// Opens the wallet in `dir`, creating one with a fresh phrase if there
    /// is none. Returns the wallet and, if it was just created, its phrase.
    pub fn open(dir: &Path) -> Result<(Wallet, Option<String>)> {
        let (env, meta, [outputs, slates, sent, commits, names]) = Self::open_env(dir)?;
        let mut wtxn = env.write_txn()?;
        let created = match meta.get(&wtxn, META_SEED)? {
            Some(_) => {
                if meta.get(&wtxn, META_FORMAT)? != Some(&[FORMAT][..]) {
                    return Err(WalletError::OldFormat);
                }
                None
            }
            None => {
                if meta.get(&wtxn, META_ENTROPY)?.is_some() || !outputs.is_empty(&wtxn)? {
                    return Err(WalletError::OldFormat);
                }
                let entropy = random_bytes::<{ bip39::ENTROPY_BYTES }>()?;
                let phrase = bip39::phrase(&entropy);
                let seed = bip39::seed(&phrase, "")?;
                meta.put(&mut wtxn, META_ENTROPY, &entropy)?;
                meta.put(&mut wtxn, META_SEED, &seed)?;
                meta.put(&mut wtxn, META_FORMAT, &[FORMAT])?;
                Some(phrase)
            }
        };
        let seed: [u8; 64] = meta
            .get(&wtxn, META_SEED)?
            .ok_or(WalletError::Corrupt("seed"))?
            .try_into()
            .map_err(|_| WalletError::Corrupt("seed"))?;
        wtxn.commit()?;
        Ok((Wallet { env, master: master_of(&seed), meta, outputs, slates, sent, commits, names }, created))
    }

    /// Creates a wallet in `dir` from a phrase and passphrase; the outputs
    /// come back with [`Wallet::scan`] once the chain is synced.
    pub fn restore(dir: &Path, phrase: &str, passphrase: &str) -> Result<Wallet> {
        let entropy = bip39::entropy(phrase)?;
        let seed = bip39::seed(phrase, passphrase)?;
        let (env, meta, [outputs, slates, sent, commits, names]) = Self::open_env(dir)?;
        let mut wtxn = env.write_txn()?;
        if meta.get(&wtxn, META_SEED)?.is_some() || !outputs.is_empty(&wtxn)? {
            return Err(WalletError::Exists);
        }
        meta.put(&mut wtxn, META_ENTROPY, &entropy)?;
        meta.put(&mut wtxn, META_SEED, &seed)?;
        meta.put(&mut wtxn, META_FORMAT, &[FORMAT])?;
        meta.put(&mut wtxn, META_SCAN_PENDING, &[1])?;
        wtxn.commit()?;
        Ok(Wallet { env, master: master_of(&seed), meta, outputs, slates, sent, commits, names })
    }

    /// Whether a restore is waiting for its first scan.
    pub fn scan_pending(&self) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        Ok(self.meta.get(&rtxn, META_SCAN_PENDING)?.is_some())
    }

    /// Marks the restore's first scan done.
    pub fn clear_scan_pending(&self) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.meta.delete(&mut wtxn, META_SCAN_PENDING)?;
        wtxn.commit()?;
        Ok(())
    }

    /// The wallet's 12-word phrase.
    pub fn phrase(&self) -> Result<String> {
        let rtxn = self.env.read_txn()?;
        let e: [u8; bip39::ENTROPY_BYTES] = self
            .meta
            .get(&rtxn, META_ENTROPY)?
            .ok_or(WalletError::Corrupt("entropy"))?
            .try_into()
            .map_err(|_| WalletError::Corrupt("entropy"))?;
        Ok(bip39::phrase(&e))
    }

    fn with_master(&self, domain: u32, nonce: &[Fp; NONCE]) -> [Fp; DIGEST] {
        let mut input = [Fp::ZERO; DIGEST + NONCE];
        input[..DIGEST].copy_from_slice(&self.master);
        input[DIGEST..].copy_from_slice(nonce);
        hash_domain(domain, &input)
    }

    /// The key of the output with nonce `nonce`, at its first leaf.
    pub fn key(&self, nonce: &[Fp; NONCE]) -> Key {
        let seed: [u8; SEED_SIZE] = digest_to_bytes(&self.with_master(DOM_KEY, nonce));
        Key::generate(&seed)
    }

    fn memo(&self, nonce: &[Fp; NONCE], amount: u64) -> Memo {
        let pad = self.with_master(DOM_PAD, nonce);
        let mut memo = [Fp::ZERO; DIGEST];
        memo[..NONCE].copy_from_slice(nonce);
        for (i, a) in amount_fps(amount).iter().enumerate() {
            memo[NONCE + i] = a.add(&pad[i]);
        }
        memo[DIGEST - 1] = pad[3];
        memo
    }

    /// The nonce and amount a memo holds, if it is one of this wallet's.
    fn open_memo(&self, memo: &Memo) -> Option<([Fp; NONCE], u64)> {
        let nonce: [Fp; NONCE] = memo[..NONCE].try_into().unwrap();
        let pad = self.with_master(DOM_PAD, &nonce);
        if memo[DIGEST - 1] != pad[3] {
            return None;
        }
        let limb = |i: usize| (memo[NONCE + i] - pad[i]).to_canonical() as u64;
        let (lo, mid, hi) = (limb(0), limb(1), limb(2));
        if lo >= 1 << 30 || mid >= 1 << 30 || hi >= 1 << 4 {
            return None;
        }
        Some((nonce, lo | mid << 30 | hi << 60))
    }

    /// A fresh output paying `amount` to this wallet, with its memo,
    /// recorded as unspent (and unconfirmed until the UTXO set holds it).
    pub fn receive(&self, amount: u64) -> Result<Output> {
        let nonce = [random_fp()?, random_fp()?, random_fp()?, random_fp()?];
        let pk = self.key(&nonce).public_key();
        let out = Output::with_memo(&pubkey_hash(&pk), amount, self.memo(&nonce, amount));
        let mut wtxn = self.env.write_txn()?;
        let o = Owned {
            commitment: out.commitment,
            nonce,
            amount,
            state: State::Unspent,
            created: unix_now(),
            recovered: false,
            start: 0,
            used: 0,
            position: None,
        };
        self.record(&mut wtxn, &o)?;
        wtxn.commit()?;
        Ok(out)
    }

    fn record(&self, wtxn: &mut RwTxn, o: &Owned) -> Result<()> {
        self.outputs.put(wtxn, &digest_to_bytes(&o.commitment), &o.to_bytes())?;
        Ok(())
    }

    fn owned_in(&self, rtxn: &RoTxn, c: &Commitment) -> Result<Option<Owned>> {
        match self.outputs.get(rtxn, &digest_to_bytes(c))? {
            None => Ok(None),
            Some(b) => Owned::from_bytes(*c, b).map(Some).ok_or(WalletError::Corrupt("output")),
        }
    }

    /// The record of an output, by commitment.
    pub fn owned(&self, c: &Commitment) -> Result<Option<Owned>> {
        let rtxn = self.env.read_txn()?;
        self.owned_in(&rtxn, c)
    }

    fn set_state(&self, wtxn: &mut RwTxn, c: &Commitment, state: State) -> Result<()> {
        let mut o = self.owned_in(wtxn, c)?.ok_or(WalletError::Corrupt("missing output"))?;
        o.state = state;
        self.record(wtxn, &o)
    }

    /// Every recorded output, oldest first.
    pub fn outputs(&self) -> Result<Vec<Owned>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.outputs.iter(&rtxn)? {
            let (k, b) = item?;
            let c = crate::poseidon2::digest_from_bytes(k).ok_or(WalletError::Corrupt("output key"))?;
            out.push(Owned::from_bytes(c, b).ok_or(WalletError::Corrupt("output"))?);
        }
        out.sort_by_key(|o| (o.created, digest_to_bytes(&o.commitment)));
        Ok(out)
    }

    /// Whether the UTXO set holds `o` where the wallet last saw it land.
    pub fn held(&self, o: &Owned, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<bool> {
        match o.position {
            Some(p) => Ok(utxo.holds(rtxn, p, &o.commitment)?),
            None => Ok(false),
        }
    }

    /// Height and hash of the block up to which [`Wallet::locate`] has been
    /// given the outputs, if any.
    pub fn synced(&self) -> Result<Option<(u32, [u8; 32])>> {
        let rtxn = self.env.read_txn()?;
        match self.meta.get(&rtxn, META_SYNCED)? {
            None => Ok(None),
            Some(b) if b.len() == 36 => {
                Ok(Some((u32::from_le_bytes(b[..4].try_into().unwrap()), b[4..].try_into().unwrap())))
            }
            Some(_) => Err(WalletError::Corrupt("synced")),
        }
    }

    /// Records that the outputs of every block up to `hash`, at `height`,
    /// have been given to [`Wallet::locate`].
    pub fn set_synced(&self, height: u32, hash: &[u8; 32]) -> Result<()> {
        let mut b = height.to_le_bytes().to_vec();
        b.extend_from_slice(hash);
        let mut wtxn = self.env.write_txn()?;
        self.meta.put(&mut wtxn, META_SYNCED, &b)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Records the positions of this wallet's outputs among `outputs`, the
    /// outputs a block added from position `first` on. Returns how many it
    /// found.
    pub fn locate(&self, first: u64, outputs: &[crate::block::BlockOutput]) -> Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        let mut n = 0;
        for (i, out) in outputs.iter().enumerate() {
            if let Some(mut o) = self.owned_in(&wtxn, &out.commitment)? {
                o.position = Some(first + i as u64);
                self.record(&mut wtxn, &o)?;
                n += 1;
            }
        }
        wtxn.commit()?;
        Ok(n)
    }

    /// Unspent, unreserved outputs the UTXO set holds that can still sign,
    /// largest first.
    pub fn spendable(&self, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Vec<Owned>> {
        let mut keep: Vec<Owned> = Vec::new();
        for o in self.outputs()? {
            if o.state == State::Unspent && o.signatures_left() > 0 && self.held(&o, utxo, rtxn)? {
                keep.push(o);
            }
        }
        keep.sort_by(|a, b| b.amount.cmp(&a.amount).then(a.created.cmp(&b.created)));
        Ok(keep)
    }

    /// Confirmed (unspent and in the UTXO set), pending (unspent, not yet
    /// there), reserved (in a pending slate) and locked (signed, still in
    /// the UTXO set) totals.
    pub fn balance(&self, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Balance> {
        let mut b = Balance::default();
        for o in self.outputs()? {
            let held = self.held(&o, utxo, rtxn)?;
            match (o.state, held) {
                (State::Unspent, true) => b.confirmed += o.amount as u128,
                (State::Unspent, false) => b.pending += o.amount as u128,
                (State::Reserved, _) => b.reserved += o.amount as u128,
                (State::Spent, true) => b.locked += o.amount as u128,
                (State::Spent, false) => {}
            }
        }
        Ok(b)
    }

    /// Forgets an unspent output that will never land, by commitment: the
    /// reward of a block the miner abandoned. Returns whether a record went.
    pub fn forget(&self, c: &Commitment) -> Result<bool> {
        let mut wtxn = self.env.write_txn()?;
        let gone = match self.owned_in(&wtxn, c)? {
            Some(o) if o.state == State::Unspent => self.outputs.delete(&mut wtxn, &digest_to_bytes(c))?,
            _ => false,
        };
        wtxn.commit()?;
        Ok(gone)
    }

    /// Deletes unspent records the UTXO set does not hold: outputs of blocks
    /// or payments that never landed. The change of a pending slate stays,
    /// as does anything in `keep`: the outputs of pooled transactions and
    /// the reward of the block being mined, which may yet land. Returns
    /// how many.
    pub fn prune_pending(&self, utxo: &UtxoSet, rtxn: &RoTxn, keep: &HashSet<Commitment>) -> Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        let mut pending_change = HashSet::new();
        for item in self.slates.iter(&wtxn)? {
            let (_, b) = item?;
            if let Some(c) = Pending::from_bytes(b).ok_or(WalletError::Corrupt("slate"))?.change {
                pending_change.insert(c);
            }
        }
        let mut n = 0;
        for o in self.outputs()? {
            let in_flight = keep.contains(&o.commitment) || pending_change.contains(&o.commitment);
            if o.state == State::Unspent && !in_flight && !self.held(&o, utxo, rtxn)? {
                self.outputs.delete(&mut wtxn, &digest_to_bytes(&o.commitment))?;
                n += 1;
            }
        }
        wtxn.commit()?;
        Ok(n)
    }

    /// Finds this wallet's unspent outputs in the UTXO set by their memos
    /// and records the ones it does not know, as recovered, and where the
    /// known ones are. Returns how many were added and their total.
    pub fn scan(&self, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<(usize, u128)> {
        self.memo_scan(utxo, rtxn, true)
    }

    /// Finds where this wallet's known outputs are in the UTXO set by their
    /// memos: after a gap in [`Wallet::locate`] too long to fill from the
    /// blocks kept.
    pub fn relocate(&self, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<()> {
        self.memo_scan(utxo, rtxn, false).map(|_| ())
    }

    fn memo_scan(&self, utxo: &UtxoSet, rtxn: &RoTxn, add: bool) -> Result<(usize, u128)> {
        let mut found = Vec::new();
        let mut moved = Vec::new();
        for (position, memo) in utxo.memos(rtxn)? {
            let Some((nonce, amount)) = self.open_memo(&memo) else {
                continue;
            };
            let commitment = utxo.get(rtxn, position)?;
            let pk = self.key(&nonce).public_key();
            if key_commitment(&pubkey_hash(&pk), amount) != commitment {
                continue;
            }
            match self.owned(&commitment)? {
                Some(mut o) if o.position != Some(position) => {
                    o.position = Some(position);
                    moved.push(o);
                }
                Some(_) => {}
                None if add => found.push(Owned {
                    commitment,
                    nonce,
                    amount,
                    state: State::Unspent,
                    created: unix_now(),
                    recovered: true,
                    start: random_bytes::<1>()?[0] % LEAVES_PER_HALF as u8,
                    used: 0,
                    position: Some(position),
                }),
                None => {}
            }
        }
        let mut wtxn = self.env.write_txn()?;
        for o in found.iter().chain(&moved) {
            self.record(&mut wtxn, o)?;
        }
        wtxn.commit()?;
        Ok((found.len(), found.iter().map(|o| o.amount as u128).sum()))
    }

    /// The key of `c` positioned at its next leaf. The leaf is recorded as
    /// used and committed before the key is returned. Also returns whether
    /// this is the output's last signature.
    fn signing_key(&self, wtxn: &mut RwTxn, c: &Commitment) -> Result<(Key, bool)> {
        let mut o = self.owned_in(wtxn, c)?.ok_or(WalletError::Corrupt("missing output"))?;
        if u32::from(o.used) >= LEAVES_PER_HALF {
            return Err(WalletError::Exhausted);
        }
        let base = if o.recovered { LEAVES_PER_HALF } else { 0 };
        let leaf = base + (u32::from(o.start) + u32::from(o.used)) % LEAVES_PER_HALF;
        o.used += 1;
        let last = u32::from(o.used) == LEAVES_PER_HALF;
        self.record(wtxn, &o)?;
        let mut key = self.key(&o.nonce);
        key.set_next_index(u64::from(leaf));
        Ok((key, last))
    }

    /// [`Wallet::signing_key`] in a transaction of its own.
    #[cfg(test)]
    fn next_signing_key(&self, c: &Commitment) -> Result<(Key, bool)> {
        let mut wtxn = self.env.write_txn()?;
        let r = self.signing_key(&mut wtxn, c)?;
        wtxn.commit()?;
        Ok(r)
    }

    /// Signs `unsigned`, whose inputs must be the wallet's outputs `inputs`
    /// in order, gives each input its output's position, and marks them
    /// spent, all within `wtxn`: the leaves used, the spent marks and
    /// whatever the caller records about the payment land together, or,
    /// if the process dies first, not at all.
    fn sign(&self, wtxn: &mut RwTxn, unsigned: UnsignedTransaction, inputs: &[Commitment]) -> Result<Signed> {
        for c in inputs {
            if self.owned_in(wtxn, c)?.is_none_or(|o| o.signatures_left() == 0) {
                return Err(WalletError::Exhausted);
            }
        }
        let mut positions = Vec::with_capacity(inputs.len());
        for c in inputs {
            positions.push(self.owned_in(wtxn, c)?.and_then(|o| o.position).ok_or(WalletError::Unconfirmed)?);
        }
        let mut keys = Vec::with_capacity(inputs.len());
        let mut last_signatures = Vec::new();
        for c in inputs {
            let (key, last) = self.signing_key(wtxn, c)?;
            if last {
                last_signatures.push(*c);
            }
            keys.push(key);
        }
        let tx = unsigned.sign(|i, pk, msg| {
            let key = &mut keys[i];
            if key.public_key() != *pk {
                return Err(WalletError::BadSlate("input key is not the wallet's"));
            }
            key.sign(msg).map_err(|_| WalletError::Exhausted)
        })?;
        let mut tx = tx;
        tx.set_positions(&positions);
        for c in inputs {
            self.set_state(wtxn, c, State::Spent)?;
        }
        Ok(Signed { tx, last_signatures })
    }

    /// The smallest fee a payment from `inputs` inputs may carry, with a
    /// recipient output and change: what the pool asks ([`Policy::min_fee`]).
    pub fn min_fee(inputs: usize) -> u64 {
        Policy::MAINNET.min_fee(inputs, 2)
    }

    /// Starts a payment of `amount` with `fee` (or the smallest the pool
    /// takes, if `None`): picks confirmed inputs largest first, reserves
    /// them, adds change to a fresh output, and returns the stage-1 slate
    /// for the recipient. Change below the dust limit goes to the fee.
    pub fn send(&self, amount: u64, fee: Option<u64>, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Slate> {
        if amount == 0 {
            return Err(WalletError::BadSlate("amount is zero"));
        }
        let dust = Policy::MAINNET.dust;
        if amount < dust {
            return Err(WalletError::BadSlate("amount is below the dust limit"));
        }
        let coins = self.spendable(utxo, rtxn)?;
        // The fee depends on the inputs, which depend on the fee: with a
        // fee for the inputs chosen so far, choose again until it holds.
        let mut inputs = 1;
        let given = fee;
        let fee = loop {
            let fee = given.unwrap_or_else(|| Self::min_fee(inputs));
            let need = amount as u128 + fee as u128;
            let mut picked = 0usize;
            let mut total = 0u128;
            for c in &coins {
                if total >= need {
                    break;
                }
                total += c.amount as u128;
                picked += 1;
            }
            if total < need {
                return Err(WalletError::Insufficient { have: total, need });
            }
            let min = Self::min_fee(picked.max(1));
            if given.is_some() && fee < min {
                return Err(WalletError::FeeTooLow { min });
            }
            if picked <= inputs {
                break fee;
            }
            inputs = picked;
        };
        let need = amount as u128 + fee as u128;
        let mut picked = Vec::new();
        let mut total = 0u128;
        for c in coins {
            if total >= need {
                break;
            }
            total += c.amount as u128;
            picked.push(c);
        }
        let change_amount = (total - need) as u64;
        let fee = if change_amount < dust { fee + change_amount } else { fee };
        let mut outputs = Vec::new();
        let mut change = None;
        if change_amount >= dust {
            let out = self.receive(change_amount)?;
            change = Some(out.commitment);
            outputs.push(out);
        }
        let mut wtxn = self.env.write_txn()?;
        for c in &picked {
            self.set_state(&mut wtxn, &c.commitment, State::Reserved)?;
        }
        let id = random_bytes::<32>()?;
        let pending = Pending { inputs: picked.iter().map(|c| c.commitment).collect(), change, amount, fee };
        self.slates.put(&mut wtxn, &id, &pending.to_bytes())?;
        wtxn.commit()?;
        let inputs = picked.iter().map(|c| (self.key(&c.nonce).public_key(), c.amount)).collect();
        Ok(Slate { id, stage: 1, amount, fee, inputs, outputs, change: u32::from(change.is_some()) })
    }

    /// The recipient's step: adds an output for the slate's amount, recorded
    /// as unspent, and advances the slate to stage 2.
    pub fn receive_slate(&self, slate: &mut Slate) -> Result<()> {
        if slate.stage != 1 {
            return Err(WalletError::BadSlate("not a stage-1 slate"));
        }
        if slate.outputs.len() != slate.change as usize {
            return Err(WalletError::BadSlate("already has a recipient output"));
        }
        let out = self.receive(slate.amount)?;
        slate.outputs.push(out);
        slate.stage = 2;
        Ok(())
    }

    /// The sender's last step: checks the stage-2 slate against the pending
    /// record and the balance, signs the inputs (marking them spent),
    /// records the payment for [`Wallet::cancel_sent`], and returns the
    /// transaction to pool.
    pub fn finalize(&self, slate: &Slate) -> Result<Signed> {
        if slate.stage != 2 {
            return Err(WalletError::BadSlate("not a stage-2 slate"));
        }
        let pending = {
            let rtxn = self.env.read_txn()?;
            let b = self.slates.get(&rtxn, &slate.id)?.ok_or(WalletError::Unknown)?;
            Pending::from_bytes(b).ok_or(WalletError::Corrupt("slate"))?
        };
        if pending.inputs.len() != slate.inputs.len() {
            return Err(WalletError::BadSlate("inputs changed"));
        }
        for (c, (pk, amount)) in pending.inputs.iter().zip(&slate.inputs) {
            let o = self.owned(c)?.ok_or(WalletError::Corrupt("reserved input"))?;
            if self.key(&o.nonce).public_key() != *pk || o.amount != *amount {
                return Err(WalletError::BadSlate("inputs changed"));
            }
        }
        if slate.outputs.len() <= slate.change as usize {
            return Err(WalletError::BadSlate("no recipient output"));
        }
        // The recipient may only have added its output: the amount and
        // fee offered must stand, or it could pocket the fee.
        if slate.amount != pending.amount || slate.fee != pending.fee {
            return Err(WalletError::BadSlate("amount or fee changed"));
        }
        let ins: u128 = slate.inputs.iter().map(|(_, a)| *a as u128).sum();
        let outs: u128 = slate.outputs.iter().map(|o| o.amount as u128).sum();
        let paid: u128 = slate.outputs[slate.change as usize..].iter().map(|o| o.amount as u128).sum();
        if paid != slate.amount as u128 || ins != outs + slate.fee as u128 {
            return Err(WalletError::BadSlate("amounts do not balance"));
        }
        // The change output, memo included: a changed memo would still
        // spend, but a wallet restored from the phrase could never find it.
        let change_ok = match pending.change {
            Some(c) => {
                let o = self.owned(&c)?.ok_or(WalletError::Corrupt("change output"))?;
                let pk = self.key(&o.nonce).public_key();
                let ours = Output::with_memo(&pubkey_hash(&pk), o.amount, self.memo(&o.nonce, o.amount));
                slate.change == 1 && slate.outputs[0].to_bytes() == ours.to_bytes()
            }
            None => slate.change == 0,
        };
        if !change_ok {
            return Err(WalletError::BadSlate("change output changed"));
        }
        // What the pool will refuse is not worth a signature.
        if slate.outputs.iter().any(|o| o.amount == 0) {
            return Err(WalletError::BadSlate("an output is for zero"));
        }
        if slate.outputs.iter().any(|o| o.amount < Policy::MAINNET.dust) {
            return Err(WalletError::BadSlate("an output is below the dust limit"));
        }
        if 8 + slate.inputs.len() * INPUT_SIZE + slate.outputs.len() * OUTPUT_SIZE > MAX_TX_SIZE {
            return Err(WalletError::BadSlate("too many outputs for one transaction"));
        }
        let mut wtxn = self.env.write_txn()?;
        let signed = self.sign(&mut wtxn, slate.unsigned(), &pending.inputs)?;
        self.slates.delete(&mut wtxn, &slate.id)?;
        let sent = Sent {
            txid: signed.tx.txid(),
            inputs: pending.inputs,
            fee: slate.fee,
            size: signed.tx.size(),
            created: unix_now(),
        };
        self.sent.put(&mut wtxn, &digest_to_bytes(&sent.txid), &sent.to_bytes())?;
        wtxn.commit()?;
        Ok(signed)
    }

    /// Abandons a pending slate: its inputs become spendable again and its
    /// change record is dropped.
    pub fn cancel_slate(&self, id: &[u8; 32]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let b = self.slates.get(&wtxn, id)?.ok_or(WalletError::Unknown)?;
        let pending = Pending::from_bytes(b).ok_or(WalletError::Corrupt("slate"))?;
        for c in &pending.inputs {
            self.set_state(&mut wtxn, c, State::Unspent)?;
        }
        if let Some(c) = pending.change {
            self.outputs.delete(&mut wtxn, &digest_to_bytes(&c))?;
        }
        self.slates.delete(&mut wtxn, id)?;
        wtxn.commit()?;
        Ok(())
    }

    /// The smallest fee a replacement of `sent` may pay: its fee plus one
    /// base unit per byte of the replacement (see [`crate::mempool`]).
    pub fn min_replacement_fee(sent: &Sent) -> u64 {
        sent.fee + (8 + sent.inputs.len() * INPUT_SIZE + OUTPUT_SIZE) as u64
    }

    /// Cancels a finalized payment that is not yet confirmed: signs a
    /// replacement spending the same inputs back to a fresh output of this
    /// wallet with `fee` (at least [`Wallet::min_replacement_fee`]), using
    /// each input's next leaf. The payment's record now points at the
    /// replacement, which can itself be cancelled while leaves remain.
    pub fn cancel_sent(&self, txid: &Commitment, fee: Option<u64>) -> Result<Signed> {
        let sent = {
            let rtxn = self.env.read_txn()?;
            let b = self.sent.get(&rtxn, &digest_to_bytes(txid))?.ok_or(WalletError::Unknown)?;
            Sent::from_bytes(*txid, b).ok_or(WalletError::Corrupt("sent"))?
        };
        let min = Self::min_replacement_fee(&sent);
        let fee = fee.unwrap_or(min);
        if fee < min {
            return Err(WalletError::FeeTooLow { min });
        }
        let mut inputs = Vec::with_capacity(sent.inputs.len());
        let mut total = 0u128;
        for c in &sent.inputs {
            let o = self.owned(c)?.ok_or(WalletError::Corrupt("sent input"))?;
            total += o.amount as u128;
            inputs.push((self.key(&o.nonce).public_key(), o.amount));
        }
        if total <= fee as u128 {
            return Err(WalletError::Insufficient { have: total, need: fee as u128 + 1 });
        }
        let back = self.receive((total - fee as u128) as u64)?;
        let mut wtxn = self.env.write_txn()?;
        let signed = match self.sign(&mut wtxn, UnsignedTransaction::new(inputs, vec![back]), &sent.inputs) {
            Ok(s) => s,
            Err(e) => {
                drop(wtxn);
                self.forget(&back.commitment)?;
                return Err(e);
            }
        };
        self.sent.delete(&mut wtxn, &digest_to_bytes(txid))?;
        let next =
            Sent { txid: signed.tx.txid(), inputs: sent.inputs, fee, size: signed.tx.size(), created: unix_now() };
        self.sent.put(&mut wtxn, &digest_to_bytes(&next.txid), &next.to_bytes())?;
        wtxn.commit()?;
        Ok(signed)
    }

    /// Finalized payments that can still be cancelled: those with an input
    /// the UTXO set still holds.
    pub fn sent(&self, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Vec<Sent>> {
        let wrtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.sent.iter(&wrtxn)? {
            let (k, b) = item?;
            let txid = crate::poseidon2::digest_from_bytes(k).ok_or(WalletError::Corrupt("sent key"))?;
            let s = Sent::from_bytes(txid, b).ok_or(WalletError::Corrupt("sent"))?;
            let mut open = false;
            for c in &s.inputs {
                if let Some(o) = self.owned_in(&wrtxn, c)? {
                    open |= self.held(&o, utxo, rtxn)?;
                }
            }
            if open {
                out.push(s);
            }
        }
        out.sort_by_key(|s| s.created);
        Ok(out)
    }

    /// Ids of pending slates with the amounts reserved for them.
    pub fn pending_slates(&self) -> Result<Vec<([u8; 32], u128)>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.slates.iter(&rtxn)? {
            let (id, b) = item?;
            let pending = Pending::from_bytes(b).ok_or(WalletError::Corrupt("slate"))?;
            let mut reserved = 0u128;
            for c in &pending.inputs {
                reserved += self.owned_in(&rtxn, c)?.map_or(0, |o| o.amount as u128);
            }
            out.push((id.try_into().map_err(|_| WalletError::Corrupt("slate id"))?, reserved));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

impl Wallet {
    /// The owner key of the name registration with nonce `nonce`.
    pub fn owner_key(&self, nonce: &[Fp; NONCE]) -> Key {
        let seed: [u8; SEED_SIZE] = digest_to_bytes(&self.with_master(DOM_OWNER, nonce));
        Key::generate(&seed)
    }

    fn owner_hash(&self, nonce: &[Fp; NONCE]) -> Commitment {
        pubkey_hash(&self.owner_key(nonce).public_key())
    }

    /// The commit salt of the registration with nonce `nonce`.
    fn salt(&self, nonce: &[Fp; NONCE]) -> Commitment {
        self.with_master(DOM_SALT, nonce)
    }

    /// The record this wallet writes for `name` under the key of `nonce`.
    fn name_record(&self, name: &[u8], nonce: &[Fp; NONCE], value: &Commitment) -> Result<Record> {
        Record::new(name, self.owner_hash(nonce), *value, self.memo(nonce, 0))
            .ok_or_else(|| WalletError::Name(format!("{} is not a valid name", String::from_utf8_lossy(name))))
    }

    fn commit_of(&self, name: &[u8], nonce: &[Fp; NONCE]) -> Option<Commitment> {
        let nh = name_hash(&names::name_elements(name)?);
        Some(commit_hash(&nh, &self.salt(nonce), &self.owner_hash(nonce)))
    }

    fn put_commit(&self, wtxn: &mut RwTxn, c: &PendingCommit) -> Result<()> {
        self.commits.put(wtxn, &digest_to_bytes(&c.commit), &c.to_bytes())?;
        Ok(())
    }

    fn put_name(&self, wtxn: &mut RwTxn, n: &OwnedName) -> Result<()> {
        self.names.put(wtxn, &n.name, &n.to_bytes())?;
        Ok(())
    }

    fn name_in(&self, rtxn: &RoTxn, name: &[u8]) -> Result<Option<OwnedName>> {
        match self.names.get(rtxn, name)? {
            None => Ok(None),
            Some(b) => OwnedName::from_bytes(name.to_vec(), b).map(Some).ok_or(WalletError::Corrupt("name")),
        }
    }

    /// The wallet's record of `name`, if any.
    pub fn owned_name(&self, name: &[u8]) -> Result<Option<OwnedName>> {
        let rtxn = self.env.read_txn()?;
        self.name_in(&rtxn, name)
    }

    /// Every name the wallet holds or awaits, by name.
    pub fn owned_names(&self) -> Result<Vec<OwnedName>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.names.iter(&rtxn)? {
            let (k, b) = item?;
            out.push(OwnedName::from_bytes(k.to_vec(), b).ok_or(WalletError::Corrupt("name"))?);
        }
        Ok(out)
    }

    /// Every commit awaiting its reveal, oldest first.
    pub fn pending_commits(&self) -> Result<Vec<PendingCommit>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.commits.iter(&rtxn)? {
            let (k, b) = item?;
            let c = crate::poseidon2::digest_from_bytes(k).ok_or(WalletError::Corrupt("commit key"))?;
            out.push(PendingCommit::from_bytes(c, b).ok_or(WalletError::Corrupt("commit"))?);
        }
        out.sort_by_key(|c| c.created);
        Ok(out)
    }

    /// Starts registering `name` with `value`: a commit operation to carry
    /// in a transaction, remembered for the reveal.
    pub fn name_commit(&self, name: &[u8], value: Commitment) -> Result<NameOp> {
        if !names::valid_name(name) {
            return Err(WalletError::Name(format!("{} is not a valid name", String::from_utf8_lossy(name))));
        }
        let rtxn = self.env.read_txn()?;
        if self.name_in(&rtxn, name)?.is_some() {
            return Err(WalletError::Name("the wallet already holds that name".into()));
        }
        drop(rtxn);
        if self.pending_commits()?.iter().any(|c| c.name.as_deref() == Some(name)) {
            return Err(WalletError::Name("the wallet has already committed to that name".into()));
        }
        let nonce = [random_fp()?, random_fp()?, random_fp()?, random_fp()?];
        let commit = self.commit_of(name, &nonce).expect("validated name");
        let entry =
            PendingCommit { commit, nonce, name: Some(name.to_vec()), value, created: unix_now(), recovered: false };
        let mut wtxn = self.env.write_txn()?;
        self.put_commit(&mut wtxn, &entry)?;
        wtxn.commit()?;
        Ok(NameOp::Commit { commit, memo: self.memo(&nonce, 0) })
    }

    /// Reveals `name` from its commit, for a block at `height`, once the
    /// commit is at least `wait` blocks old (at least [`MIN_REVEAL`]). A
    /// commit found by a scan is matched to the name here. The name's
    /// record is then awaited on chain.
    pub fn name_reveal(&self, name: &[u8], wait: u32, registry: &NameSet, rtxn: &RoTxn, height: u32) -> Result<NameOp> {
        let pending = self.pending_commits()?;
        let entry = pending
            .iter()
            .find(|c| c.name.as_deref() == Some(name))
            .or_else(|| pending.iter().find(|c| c.name.is_none() && self.commit_of(name, &c.nonce) == Some(c.commit)))
            .cloned()
            .ok_or_else(|| WalletError::Name(format!("no commit for {}", String::from_utf8_lossy(name))))?;
        let position = registry
            .commit_position(rtxn, &entry.commit)
            .map_err(|e| WalletError::Name(e.to_string()))?
            .ok_or_else(|| WalletError::Name("the commit is not on chain yet".into()))?;
        let commit = registry
            .commit_at(rtxn, position)
            .map_err(|e| WalletError::Name(e.to_string()))?
            .ok_or_else(|| WalletError::Name("the commit is not on chain yet".into()))?;
        let wait = wait.max(MIN_REVEAL);
        if height < commit.height.saturating_add(wait) {
            return Err(WalletError::Name(format!(
                "the commit is {} blocks old; wait {} more",
                height.saturating_sub(commit.height),
                commit.height + wait - height
            )));
        }
        let record = self.name_record(name, &entry.nonce, &entry.value)?;
        let op = NameOp::Reveal { record, salt: self.salt(&entry.nonce), commit: position };
        let owned = OwnedName {
            name: name.to_vec(),
            nonce: entry.nonce,
            value: entry.value,
            created: unix_now(),
            stage: NameStage::Revealed,
            recovered: entry.recovered,
            start: if entry.recovered { random_bytes::<1>()?[0] % LEAVES_PER_HALF as u8 } else { 0 },
            used: 0,
            pending: None,
            transferring: false,
        };
        let mut wtxn = self.env.write_txn()?;
        self.put_name(&mut wtxn, &owned)?;
        self.commits.delete(&mut wtxn, &digest_to_bytes(&entry.commit))?;
        wtxn.commit()?;
        Ok(op)
    }

    /// Signs `record` as the current owner of its name with the key's next
    /// leaf, recording the signature; also returns whether it was the key's
    /// last. The entry is written with the caller's changes.
    fn sign_update(&self, wtxn: &mut RwTxn, entry: &mut OwnedName, record: Record) -> Result<(NameOp, bool)> {
        if u32::from(entry.used) >= LEAVES_PER_HALF {
            return Err(WalletError::Exhausted);
        }
        let base = if entry.recovered { LEAVES_PER_HALF } else { 0 };
        let leaf = base + (u32::from(entry.start) + u32::from(entry.used)) % LEAVES_PER_HALF;
        entry.used += 1;
        let last = u32::from(entry.used) == LEAVES_PER_HALF;
        let mut key = self.owner_key(&entry.nonce);
        key.set_next_index(u64::from(leaf));
        let op = NameOp::update(record, &mut key).map_err(|e| WalletError::Name(e.to_string()))?;
        self.put_name(wtxn, entry)?;
        Ok((op, last))
    }

    /// Changes `name`'s value, rotating its owner key: an update operation
    /// to carry in a transaction, and whether it took the current key's
    /// last signature (after which it cannot be cancelled and replaced).
    pub fn name_update(&self, name: &[u8], value: Commitment) -> Result<(NameOp, bool)> {
        let mut wtxn = self.env.write_txn()?;
        let mut entry = self
            .name_in(&wtxn, name)?
            .filter(|n| n.stage == NameStage::Owned)
            .ok_or_else(|| WalletError::Name(format!("the wallet does not own {}", String::from_utf8_lossy(name))))?;
        if entry.pending.is_some() || entry.transferring {
            return Err(WalletError::Name("an operation on that name is already signed".into()));
        }
        let nonce = [random_fp()?, random_fp()?, random_fp()?, random_fp()?];
        let record = self.name_record(name, &nonce, &value)?;
        entry.pending = Some((nonce, value));
        let op = self.sign_update(&mut wtxn, &mut entry, record)?;
        wtxn.commit()?;
        Ok(op)
    }

    /// Prepares to receive `name` from its owner: a record under a fresh key
    /// of this wallet's, for the owner to sign over ([`Wallet::name_transfer`]).
    pub fn name_offer(&self, name: &[u8], value: Commitment) -> Result<Record> {
        let rtxn = self.env.read_txn()?;
        if self.name_in(&rtxn, name)?.is_some() {
            return Err(WalletError::Name("the wallet already holds that name".into()));
        }
        drop(rtxn);
        let nonce = [random_fp()?, random_fp()?, random_fp()?, random_fp()?];
        let record = self.name_record(name, &nonce, &value)?;
        let entry = OwnedName {
            name: name.to_vec(),
            nonce,
            value,
            created: unix_now(),
            stage: NameStage::Offered,
            recovered: false,
            start: 0,
            used: 0,
            pending: None,
            transferring: false,
        };
        let mut wtxn = self.env.write_txn()?;
        self.put_name(&mut wtxn, &entry)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Signs `record`, written by its recipient, over as the owner of its
    /// name: an update operation to carry in a transaction, and whether it
    /// took the key's last signature.
    pub fn name_transfer(&self, record: Record) -> Result<(NameOp, bool)> {
        let mut wtxn = self.env.write_txn()?;
        let mut entry =
            self.name_in(&wtxn, &record.name)?.filter(|n| n.stage == NameStage::Owned).ok_or_else(|| {
                WalletError::Name(format!("the wallet does not own {}", String::from_utf8_lossy(&record.name)))
            })?;
        if entry.pending.is_some() || entry.transferring {
            return Err(WalletError::Name("an operation on that name is already signed".into()));
        }
        if record.owner == self.owner_hash(&entry.nonce) {
            return Err(WalletError::Name("the record keeps the current owner".into()));
        }
        entry.transferring = true;
        let op = self.sign_update(&mut wtxn, &mut entry, record)?;
        wtxn.commit()?;
        Ok(op)
    }

    /// Brings the wallet's names in line with the chain's records: a reveal
    /// or a rotation seen on chain settles, an offered name arrives, a
    /// transferred one leaves, and a name whose record names someone else's
    /// key is dropped. Returns how many entries changed.
    pub fn sync_names(&self, registry: &NameSet, rtxn: &RoTxn) -> Result<usize> {
        let mut changed = 0;
        let mut wtxn = self.env.write_txn()?;
        for mut entry in self.owned_names()? {
            let Some(record) = registry.lookup(rtxn, &entry.name).map_err(|e| WalletError::Name(e.to_string()))? else {
                continue;
            };
            let mine = record.owner == self.owner_hash(&entry.nonce);
            let rotated = entry.pending.as_ref().is_some_and(|(n, _)| record.owner == self.owner_hash(n));
            if rotated {
                let (nonce, value) = entry.pending.take().unwrap();
                entry.nonce = nonce;
                entry.value = value;
                entry.recovered = false;
                entry.start = 0;
                entry.used = 0;
                entry.stage = NameStage::Owned;
                self.put_name(&mut wtxn, &entry)?;
                changed += 1;
            } else if mine {
                if entry.stage != NameStage::Owned || entry.value != record.value {
                    entry.stage = NameStage::Owned;
                    entry.value = record.value;
                    self.put_name(&mut wtxn, &entry)?;
                    changed += 1;
                }
            } else if entry.transferring || entry.stage != NameStage::Offered {
                // Signed away, or registered by someone else first.
                self.names.delete(&mut wtxn, &entry.name)?;
                changed += 1;
            }
        }
        wtxn.commit()?;
        Ok(changed)
    }

    /// Recovery: finds the wallet's names among the registry's records and
    /// its pending commits among the commit outputs. Returns how many of
    /// each were new.
    pub fn scan_names(&self, utxo: &UtxoSet, registry: &NameSet, rtxn: &RoTxn) -> Result<(usize, usize)> {
        let err = |e: names::Error| WalletError::Name(e.to_string());
        let mut found_names = Vec::new();
        for record in registry.records_in(rtxn, 0, crate::name_trie::Key::MAX).map_err(err)? {
            let Some((nonce, 0)) = self.open_memo(&record.memo) else {
                continue;
            };
            if record.owner != self.owner_hash(&nonce) || self.owned_name(&record.name)?.is_some() {
                continue;
            }
            found_names.push(OwnedName {
                name: record.name.clone(),
                nonce,
                value: record.value,
                created: unix_now(),
                stage: NameStage::Owned,
                recovered: true,
                start: random_bytes::<1>()?[0] % LEAVES_PER_HALF as u8,
                used: 0,
                pending: None,
                transferring: false,
            });
        }
        let mut found_commits = Vec::new();
        let known = self.pending_commits()?;
        for (position, commit) in registry.commits(rtxn).map_err(err)? {
            let Some((nonce, 0)) = self.open_memo(&utxo.memo(rtxn, position)?) else {
                continue;
            };
            if known.iter().any(|c| c.commit == commit.hash) {
                continue;
            }
            found_commits.push(PendingCommit {
                commit: commit.hash,
                nonce,
                name: None,
                value: [Fp::ZERO; DIGEST],
                created: unix_now(),
                recovered: true,
            });
        }
        let mut wtxn = self.env.write_txn()?;
        for n in &found_names {
            self.put_name(&mut wtxn, n)?;
        }
        for c in &found_commits {
            self.put_commit(&mut wtxn, c)?;
        }
        wtxn.commit()?;
        Ok((found_names.len(), found_commits.len()))
    }

    /// The smallest fee a transaction carrying `ops` from `inputs` inputs
    /// with change may pay.
    pub fn min_carry_fee(inputs: usize, ops: &[NameOp]) -> u64 {
        let size = 12 + inputs * INPUT_SIZE + OUTPUT_SIZE + ops.iter().map(NameOp::size).sum::<usize>();
        Policy::MAINNET.min_fee_for(size)
    }

    /// Signs a transaction of this wallet's that carries `ops` and pays
    /// `fee` (or the smallest the pool takes): confirmed inputs largest
    /// first, change to a fresh output. Recorded like a payment, so it can
    /// be cancelled while unconfirmed.
    pub fn carry(&self, ops: Vec<NameOp>, fee: Option<u64>, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Signed> {
        if ops.is_empty() {
            return Err(WalletError::Name("nothing to carry".into()));
        }
        let dust = Policy::MAINNET.dust;
        let coins = self.spendable(utxo, rtxn)?;
        let mut inputs = 1;
        let fee = loop {
            let fee = fee.unwrap_or_else(|| Self::min_carry_fee(inputs, &ops));
            let mut picked = 0usize;
            let mut total = 0u128;
            for c in &coins {
                if total >= fee as u128 {
                    break;
                }
                total += c.amount as u128;
                picked += 1;
            }
            if total < fee as u128 {
                return Err(WalletError::Insufficient { have: total, need: fee as u128 });
            }
            let min = Self::min_carry_fee(picked.max(1), &ops);
            if fee < min {
                return Err(WalletError::FeeTooLow { min });
            }
            if picked <= inputs {
                break fee;
            }
            inputs = picked;
        };
        let mut picked = Vec::new();
        let mut total = 0u128;
        for c in coins {
            if total >= fee as u128 {
                break;
            }
            total += c.amount as u128;
            picked.push(c);
        }
        let change_amount = (total - fee as u128) as u64;
        let (fee, outputs, change) = if change_amount >= dust {
            let out = self.receive(change_amount)?;
            (fee, vec![out], Some(out.commitment))
        } else {
            (fee + change_amount, vec![], None)
        };
        let inputs: Vec<(PublicKey, u64)> =
            picked.iter().map(|c| (self.key(&c.nonce).public_key(), c.amount)).collect();
        let commitments: Vec<Commitment> = picked.iter().map(|c| c.commitment).collect();
        let mut wtxn = self.env.write_txn()?;
        let signed = match self.sign(&mut wtxn, UnsignedTransaction::with_ops(inputs, outputs, ops), &commitments) {
            Ok(s) => s,
            Err(e) => {
                drop(wtxn);
                if let Some(c) = change {
                    self.forget(&c)?;
                }
                return Err(e);
            }
        };
        let sent =
            Sent { txid: signed.tx.txid(), inputs: commitments, fee, size: signed.tx.size(), created: unix_now() };
        self.sent.put(&mut wtxn, &digest_to_bytes(&sent.txid), &sent.to_bytes())?;
        wtxn.commit()?;
        Ok(signed)
    }
}

/// 32 bytes from 64 hex digits.
pub fn digest_from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::DUST;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("tabminer-wallet-{}-{name}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn utxo(dir: &TempDir) -> (Env, UtxoSet) {
        let env = open_env(&dir.0.join("utxo"), 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let u = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        wtxn.commit().unwrap();
        (env, u)
    }

    /// Adds `outs` to the set as a block would, and shows the block to
    /// `wallet` as the node does.
    fn land(env: &Env, u: &UtxoSet, wallet: &Wallet, outs: &[&Output]) {
        let mut wtxn = env.write_txn().unwrap();
        let first = u.next_position(&wtxn).unwrap();
        let outs: Vec<_> = outs.iter().map(|o| o.block_output()).collect();
        u.add_outputs(&mut wtxn, &outs).unwrap();
        wtxn.commit().unwrap();
        wallet.locate(first, &outs).unwrap();
    }

    #[test]
    fn phrase_memos_and_persistence() {
        let dir = TempDir::new("basic");
        let (env, u) = utxo(&dir);
        let (phrase, a_commitment) = {
            let (w, created) = Wallet::open(&dir.0.join("wallet")).unwrap();
            let phrase = created.expect("a new wallet has a phrase");
            assert_eq!(phrase.split(' ').count(), 12);
            assert_eq!(w.phrase().unwrap(), phrase);
            let a = w.receive(100).unwrap();
            let b = w.receive(u64::MAX).unwrap();
            assert_ne!(a.memo, b.memo);
            assert_eq!(w.open_memo(&a.memo), Some((a.memo[..4].try_into().unwrap(), 100)));
            assert_eq!(w.open_memo(&b.memo).unwrap().1, u64::MAX);
            land(&env, &u, &w, &[&a]);
            assert_eq!(w.owned(&a.commitment).unwrap().unwrap().position, Some(0));
            assert_eq!(w.owned(&b.commitment).unwrap().unwrap().position, None);
            let rtxn = env.read_txn().unwrap();
            assert_eq!(
                w.balance(&u, &rtxn).unwrap(),
                Balance { confirmed: 100, pending: u64::MAX as u128, reserved: 0, locked: 0 }
            );
            (phrase, a.commitment)
        };
        let (w, created) = Wallet::open(&dir.0.join("wallet")).unwrap();
        assert!(created.is_none());
        assert_eq!(w.phrase().unwrap(), phrase);
        assert_eq!(w.outputs().unwrap().len(), 2);
        // Another wallet cannot read the memo.
        let (other, _) = Wallet::open(&dir.0.join("other")).unwrap();
        let o = w.owned(&a_commitment).unwrap().unwrap();
        assert!(other.open_memo(&w.memo(&o.nonce, 100)).is_none());
        let rtxn = env.read_txn().unwrap();
        // What is kept, as being in flight, is not pruned.
        let b_commitment = w.outputs().unwrap().into_iter().find(|o| o.commitment != a_commitment).unwrap().commitment;
        assert_eq!(w.prune_pending(&u, &rtxn, &HashSet::from([b_commitment])).unwrap(), 0);
        assert_eq!(w.prune_pending(&u, &rtxn, &HashSet::new()).unwrap(), 1);
        assert_eq!(w.outputs().unwrap().len(), 1);
        assert!(matches!(Wallet::restore(&dir.0.join("wallet"), &phrase, ""), Err(WalletError::Exists)));
    }

    #[test]
    fn leaves_normal_and_recovered() {
        let dir = TempDir::new("leaves");
        let (env, u) = utxo(&dir);
        let (w, created) = Wallet::open(&dir.0.join("wallet")).unwrap();
        let phrase = created.unwrap();
        let a = w.receive(50).unwrap();
        land(&env, &u, &w, &[&a]);
        // Normal output: leaves 0..7 in order, the eighth flagged last.
        for i in 0..8u64 {
            let (k, last) = w.next_signing_key(&a.commitment).unwrap();
            assert_eq!(k.next_index(), i);
            assert_eq!(last, i == 7);
        }
        assert!(matches!(w.next_signing_key(&a.commitment), Err(WalletError::Exhausted)));
        // A restored copy finds it and signs from 8..15, from a random start,
        // wrapping within that half, eight times.
        let r = Wallet::restore(&dir.0.join("restored"), &phrase, "").unwrap();
        assert!(r.scan_pending().unwrap());
        assert!(!w.scan_pending().unwrap());
        let rtxn = env.read_txn().unwrap();
        assert_eq!(r.scan(&u, &rtxn).unwrap(), (1, 50));
        assert_eq!(r.scan(&u, &rtxn).unwrap(), (0, 0));
        let o = r.owned(&a.commitment).unwrap().unwrap();
        assert!(o.recovered && o.amount == 50 && o.position == Some(0));
        // A known output whose position was lost is found again by memo.
        let mut lost = w.owned(&a.commitment).unwrap().unwrap();
        lost.position = None;
        let mut wtxn = w.env.write_txn().unwrap();
        w.record(&mut wtxn, &lost).unwrap();
        wtxn.commit().unwrap();
        w.relocate(&u, &rtxn).unwrap();
        assert_eq!(w.owned(&a.commitment).unwrap().unwrap().position, Some(0));
        assert_eq!(w.outputs().unwrap().len(), 1);
        let mut seen = Vec::new();
        for i in 0..8u32 {
            let (k, last) = r.next_signing_key(&a.commitment).unwrap();
            assert!((8..16).contains(&k.next_index()));
            assert_eq!(k.next_index() as u32, 8 + (u32::from(o.start) + i) % 8);
            assert_eq!(last, i == 7);
            seen.push(k.next_index());
        }
        seen.sort_unstable();
        assert_eq!(seen, (8..16).collect::<Vec<_>>());
        assert!(matches!(r.next_signing_key(&a.commitment), Err(WalletError::Exhausted)));
        // A wrong passphrase finds nothing.
        let wrong = Wallet::restore(&dir.0.join("wrong"), &phrase, "x").unwrap();
        assert_eq!(wrong.scan(&u, &rtxn).unwrap(), (0, 0));
    }

    #[test]
    fn slate_finalize_and_cancel() {
        let dir = TempDir::new("slate");
        let (env, u) = utxo(&dir);
        let (alice, _) = Wallet::open(&dir.0.join("alice")).unwrap();
        let (bob, _) = Wallet::open(&dir.0.join("bob")).unwrap();
        let a1 = alice.receive(60_000_000).unwrap();
        let a2 = alice.receive(50_000_000).unwrap();
        land(&env, &u, &alice, &[&a1, &a2]);
        let rtxn = env.read_txn().unwrap();
        let fee = Wallet::min_fee(2);
        assert!(matches!(
            alice.send(200_000_000, Some(1), &u, &rtxn),
            Err(WalletError::Insufficient { have: 110_000_000, need }) if need == 200_000_001
        ));
        assert!(
            matches!(alice.send(70_000_000, Some(fee - 1), &u, &rtxn), Err(WalletError::FeeTooLow { min }) if min == fee)
        );
        assert!(matches!(alice.send(DUST - 1, None, &u, &rtxn), Err(WalletError::BadSlate(_))));
        // Without a fee given, the smallest one for the inputs it takes.
        assert_eq!(alice.send(70_000_000, None, &u, &rtxn).unwrap().fee, fee);
        for (id, _) in alice.pending_slates().unwrap() {
            alice.cancel_slate(&id).unwrap();
        }
        let slate = alice.send(70_000_000, Some(fee), &u, &rtxn).unwrap();
        let change = 110_000_000 - 70_000_000 - fee;
        assert_eq!((slate.stage, slate.inputs.len(), slate.change), (1, 2, 1));
        assert_eq!(slate.outputs[0].amount, change);
        assert_eq!(
            alice.balance(&u, &rtxn).unwrap(),
            Balance { confirmed: 0, pending: change as u128, reserved: 110_000_000, locked: 0 }
        );
        let mut received = Slate::from_bytes(&slate.to_bytes()).unwrap();
        assert_eq!(received, slate);
        assert!(matches!(bob.finalize(&received), Err(WalletError::BadSlate(_))));
        bob.receive_slate(&mut received).unwrap();
        assert!(matches!(bob.receive_slate(&mut received), Err(WalletError::BadSlate(_))));
        let received = Slate::from_bytes(&received.to_bytes()).unwrap();
        assert!(matches!(bob.finalize(&received), Err(WalletError::Unknown)));
        let mut greedy = received.clone();
        greedy.outputs[1] = Output::new(&bob.key(&[Fp::ONE; 4]).public_key(), 70_000_001);
        assert!(matches!(alice.finalize(&greedy), Err(WalletError::BadSlate("amounts do not balance"))));
        // The recipient may not move the fee into its own pocket.
        let mut greedy = received.clone();
        greedy.fee = 0;
        greedy.amount = 70_000_000 + fee;
        greedy.outputs[1] = Output::new(&bob.key(&[Fp::ONE; 4]).public_key(), 70_000_000 + fee);
        assert!(matches!(alice.finalize(&greedy), Err(WalletError::BadSlate("amount or fee changed"))));
        // Nor touch the change's memo, which a restored wallet needs.
        let mut spoiled = received.clone();
        spoiled.outputs[0].memo[5] = spoiled.outputs[0].memo[5].add(&Fp::ONE);
        assert_eq!(spoiled.outputs[0].commitment, received.outputs[0].commitment);
        assert!(matches!(alice.finalize(&spoiled), Err(WalletError::BadSlate("change output changed"))));
        // Nor add what the pool would refuse.
        let mut dust = received.clone();
        dust.outputs[1] = Output::new(&bob.key(&[Fp::ONE; 4]).public_key(), 70_000_000 - (DUST - 1));
        dust.outputs.push(Output::new(&bob.key(&[Fp::ONE; 4]).public_key(), DUST - 1));
        assert!(matches!(alice.finalize(&dust), Err(WalletError::BadSlate("an output is below the dust limit"))));
        // The change stays through a prune while the slate is pending.
        assert_eq!(alice.prune_pending(&u, &rtxn, &HashSet::new()).unwrap(), 0);
        let signed = alice.finalize(&received).unwrap();
        let tx = signed.tx;
        assert!(tx.verify_signatures() && tx.balance() == fee as i128 && signed.last_signatures.is_empty());
        // Each input names where its output is.
        assert_eq!(tx.spent_positions(), vec![0, 1]);
        assert!(matches!(alice.finalize(&received), Err(WalletError::Unknown)));
        // Signed but not confirmed: the inputs are locked, not reserved.
        assert_eq!(
            alice.balance(&u, &rtxn).unwrap(),
            Balance { confirmed: 0, pending: change as u128, reserved: 0, locked: 110_000_000 }
        );
        // The recipient's output carries a memo only bob can open.
        assert!(bob.open_memo(&tx.outputs[1].memo).is_some());
        assert!(alice.open_memo(&tx.outputs[1].memo).is_none());

        // Cancel: same inputs back to alice with a higher fee, next leaves.
        let sent = alice.sent(&u, &rtxn).unwrap();
        assert_eq!(sent.len(), 1);
        let min = Wallet::min_replacement_fee(&sent[0]);
        assert!(matches!(alice.cancel_sent(&tx.txid(), Some(min - 1)), Err(WalletError::FeeTooLow { .. })));
        let replaced = alice.cancel_sent(&tx.txid(), None).unwrap().tx;
        assert!(replaced.verify_signatures());
        assert_eq!(replaced.spent_commitments(), tx.spent_commitments());
        assert_eq!(replaced.spent_positions(), tx.spent_positions());
        assert_eq!(replaced.balance() as u64, min);
        assert_eq!(replaced.inputs[0].signature.index, 1);
        assert!(matches!(alice.cancel_sent(&tx.txid(), None), Err(WalletError::Unknown)));
        // It can be cancelled again until the leaves run out: 8 signatures
        // in all, the last one flagged.
        let mut id = replaced.txid();
        for n in 2..8 {
            let s = alice.cancel_sent(&id, Some(min * n)).unwrap();
            assert_eq!(s.last_signatures.len(), if n == 7 { 2 } else { 0 });
            id = s.tx.txid();
        }
        assert!(matches!(alice.cancel_sent(&id, Some(min * 9)), Err(WalletError::Exhausted)));

        // Cancelling a slate frees its inputs.
        drop(rtxn);
        let a3 = alice.receive(9_000_000).unwrap();
        land(&env, &u, &alice, &[&a3]);
        let rtxn = env.read_txn().unwrap();
        let s2 = alice.send(4_000_000, None, &u, &rtxn).unwrap();
        assert_eq!(alice.balance(&u, &rtxn).unwrap().reserved, 9_000_000);
        alice.cancel_slate(&s2.id).unwrap();
        assert_eq!(alice.balance(&u, &rtxn).unwrap().reserved, 0);
        assert!(matches!(alice.cancel_slate(&s2.id), Err(WalletError::Unknown)));
        assert_eq!(digest_from_hex(&s2.id_hex()), Some(s2.id));
    }

    #[test]
    fn names_commit_reveal_update_transfer_and_recover() {
        use crate::names::{BlockNameOp, NameSet};
        let dir = TempDir::new("names");
        let (env, u) = utxo(&dir);
        let registry = {
            let mut wtxn = env.write_txn().unwrap();
            let n = NameSet::open(&env, &mut wtxn, "n").unwrap();
            wtxn.commit().unwrap();
            n
        };
        // The chain, as far as the wallet sees it: applies a carried
        // transaction's operations (and sweeps) at `height`.
        let apply = |tx: &Transaction, height: u32| {
            let mut wtxn = env.write_txn().unwrap();
            let ops: Vec<BlockNameOp> = tx.ops.iter().map(NameOp::block_op).collect();
            for (c, p) in tx.spent_commitments().iter().zip(tx.spent_positions()) {
                assert!(u.spend_at(&mut wtxn, c, p).unwrap());
            }
            let first = u.next_position(&wtxn).unwrap();
            let outs: Vec<_> = tx.outputs.iter().map(|o| o.block_output()).collect();
            u.add_outputs(&mut wtxn, &outs).unwrap();
            registry.apply(&u, &mut wtxn, height, &ops, &[]).unwrap();
            wtxn.commit().unwrap();
            (first, outs)
        };
        let (alice, phrase) = Wallet::open(&dir.0.join("alice")).unwrap();
        let (bob, _) = Wallet::open(&dir.0.join("bob")).unwrap();
        let coin = alice.receive(10_000_000).unwrap();
        land(&env, &u, &alice, &[&coin]);
        let value = |n: u32| -> Commitment { core::array::from_fn(|i| Fp::new(n * 100 + i as u32)) };

        // Commit, carried by a transaction paying the minimum fee.
        let commit = alice.name_commit(b"alice", value(1)).unwrap();
        assert!(alice.name_commit(b"Alice", value(1)).is_err());
        assert!(alice.name_commit(b"alice", value(1)).is_err());
        let rtxn = env.read_txn().unwrap();
        let signed = alice.carry(vec![commit.clone()], None, &u, &rtxn).unwrap();
        drop(rtxn);
        assert_eq!(signed.tx.ops, vec![commit.clone()]);
        assert_eq!(signed.tx.balance() as u64, Wallet::min_carry_fee(1, &signed.tx.ops));
        assert!(signed.tx.verify_signatures());
        let (first, outs) = apply(&signed.tx, 1);
        alice.locate(first, &outs).unwrap();
        let NameOp::Commit { commit: c, .. } = &commit else { unreachable!() };
        assert_eq!(alice.pending_commits().unwrap()[0].commit, *c);
        // Reveal: too early at 12 with a longer wait, refused; at 13 fine.
        let rtxn = env.read_txn().unwrap();
        assert!(alice.name_reveal(b"alice", 0, &registry, &rtxn, 12).is_err());
        assert!(alice.name_reveal(b"alice", 20, &registry, &rtxn, 13).is_err());
        assert!(alice.name_reveal(b"bob", 0, &registry, &rtxn, 13).is_err());
        let reveal = alice.name_reveal(b"alice", 0, &registry, &rtxn, 13).unwrap();
        let signed = alice.carry(vec![reveal.clone()], None, &u, &rtxn).unwrap();
        drop(rtxn);
        assert!(alice.pending_commits().unwrap().is_empty());
        assert_eq!(alice.owned_name(b"alice").unwrap().unwrap().stage, NameStage::Revealed);
        let (first, outs) = apply(&signed.tx, 13);
        alice.locate(first, &outs).unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(alice.sync_names(&registry, &rtxn).unwrap(), 1);
        let owned = alice.owned_name(b"alice").unwrap().unwrap();
        assert_eq!((owned.stage, owned.value), (NameStage::Owned, value(1)));
        let on_chain = registry.lookup(&rtxn, b"alice").unwrap().unwrap();
        assert_eq!(on_chain.owner, alice.owner_hash(&owned.nonce));
        assert_eq!(alice.open_memo(&on_chain.memo), Some((owned.nonce, 0)));

        // Update: the key rotates once the chain shows the new owner.
        let (update, last) = alice.name_update(b"alice", value(2)).unwrap();
        assert!(!last);
        assert!(alice.name_update(b"alice", value(3)).is_err());
        assert!(update.verify_owner(&on_chain.owner));
        let signed = alice.carry(vec![update], None, &u, &rtxn).unwrap();
        drop(rtxn);
        let (first, outs) = apply(&signed.tx, 14);
        alice.locate(first, &outs).unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(alice.sync_names(&registry, &rtxn).unwrap(), 1);
        let rotated = alice.owned_name(b"alice").unwrap().unwrap();
        assert_ne!(rotated.nonce, owned.nonce);
        assert_eq!((rotated.value, rotated.used, rotated.pending), (value(2), 0, None));
        assert_eq!(registry.lookup(&rtxn, b"alice").unwrap().unwrap().owner, alice.owner_hash(&rotated.nonce));

        // Transfer to bob: his record, her signature.
        let offer = bob.name_offer(b"alice", value(5)).unwrap();
        assert_eq!(bob.owned_name(b"alice").unwrap().unwrap().stage, NameStage::Offered);
        assert!(alice.name_transfer(Record::new(b"carol", offer.owner, value(1), offer.memo).unwrap()).is_err());
        let (transfer, _) = alice.name_transfer(offer.clone()).unwrap();
        assert!(alice.name_update(b"alice", value(3)).is_err());
        let signed = alice.carry(vec![transfer], None, &u, &rtxn).unwrap();
        drop(rtxn);
        let (first, outs) = apply(&signed.tx, 15);
        alice.locate(first, &outs).unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(alice.sync_names(&registry, &rtxn).unwrap(), 1);
        assert!(alice.owned_name(b"alice").unwrap().is_none());
        assert_eq!(bob.sync_names(&registry, &rtxn).unwrap(), 1);
        assert_eq!(bob.owned_name(b"alice").unwrap().unwrap().stage, NameStage::Owned);
        assert_eq!(registry.lookup(&rtxn, b"alice").unwrap().unwrap(), offer);

        // Bob commits to another name; a restored bob finds his name and
        // the pending commit, and reveals it once told the name.
        let coin = bob.receive(10_000_000).unwrap();
        drop(rtxn);
        land(&env, &u, &bob, &[&coin]);
        let commit = bob.name_commit(b"bob_2", value(7)).unwrap();
        let rtxn = env.read_txn().unwrap();
        let signed = bob.carry(vec![commit], None, &u, &rtxn).unwrap();
        drop(rtxn);
        apply(&signed.tx, 20);
        let (_, bob_phrase) = (0, bob.phrase().unwrap());
        let restored = Wallet::restore(&dir.0.join("bob2"), &bob_phrase, "").unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(restored.scan_names(&u, &registry, &rtxn).unwrap(), (1, 1));
        assert_eq!(restored.scan_names(&u, &registry, &rtxn).unwrap(), (0, 0));
        let found = restored.owned_name(b"alice").unwrap().unwrap();
        assert!(found.recovered && found.stage == NameStage::Owned && found.value == value(5));
        let pending = &restored.pending_commits().unwrap()[0];
        assert!(pending.recovered && pending.name.is_none());
        assert!(restored.name_reveal(b"wrong", 0, &registry, &rtxn, 40).is_err());
        let reveal = restored.name_reveal(b"bob_2", 0, &registry, &rtxn, 40).unwrap();
        let NameOp::Reveal { record, .. } = &reveal else { unreachable!() };
        assert_eq!(record.owner, restored.owner_hash(&pending.nonce));
        // Alice's restored wallet finds nothing: the name left her.
        let alice2 = Wallet::restore(&dir.0.join("alice2"), &phrase.unwrap(), "").unwrap();
        assert_eq!(alice2.scan_names(&u, &registry, &rtxn).unwrap(), (0, 0));
    }
}
