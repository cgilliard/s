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

use std::path::Path;

use heed::types::{Bytes, Str};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::bip39;
use crate::codec::{Reader, Writer};
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
/// Version of the on-disk layout: 3 is BIP39 phrases and per-output keys.
const FORMAT: u8 = 3;
const MAP_SIZE: usize = 1 << 30;
const SLATE_MAGIC: &[u8; 8] = b"tabslt02";

const DOM_MASTER: u32 = 0x30;
const DOM_PAD: u32 = 0x31;
const DOM_KEY: u32 = 0x32;
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
        r.is_empty().then_some(Owned { commitment, nonce, amount, state, created, recovered, start, used })
    }

    /// Signatures this output can still make.
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
/// commitment.
struct Pending {
    inputs: Vec<Commitment>,
    change: Option<Commitment>,
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
        r.is_empty().then_some(Pending { inputs, change })
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
            WalletError::FeeTooLow { min } => write!(f, "the replacement fee must be at least {min}"),
            WalletError::OldFormat => f.write_str("wallet database is from an older format"),
            WalletError::Exists => f.write_str("a wallet already exists in that directory"),
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
    fn open_env(dir: &Path) -> Result<(Env, Database<Str, Bytes>, [Database<Bytes, Bytes>; 3])> {
        let env = open_env(dir, MAP_SIZE).map_err(|e| match e {
            crate::state_tree::Error::Heed(h) => WalletError::Heed(h),
            other => WalletError::Utxo(utxo::Error::Tree(other)),
        })?;
        let mut wtxn = env.write_txn()?;
        let meta = env.create_database(&mut wtxn, Some("meta"))?;
        let outputs = env.create_database(&mut wtxn, Some("outputs"))?;
        let slates = env.create_database(&mut wtxn, Some("slates"))?;
        let sent = env.create_database(&mut wtxn, Some("sent"))?;
        wtxn.commit()?;
        Ok((env, meta, [outputs, slates, sent]))
    }

    /// Opens the wallet in `dir`, creating one with a fresh phrase if there
    /// is none. Returns the wallet and, if it was just created, its phrase.
    pub fn open(dir: &Path) -> Result<(Wallet, Option<String>)> {
        let (env, meta, [outputs, slates, sent]) = Self::open_env(dir)?;
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
        Ok((Wallet { env, master: master_of(&seed), meta, outputs, slates, sent }, created))
    }

    /// Creates a wallet in `dir` from a phrase and passphrase; the outputs
    /// come back with [`Wallet::scan`] once the chain is synced.
    pub fn restore(dir: &Path, phrase: &str, passphrase: &str) -> Result<Wallet> {
        let entropy = bip39::entropy(phrase)?;
        let seed = bip39::seed(phrase, passphrase)?;
        let (env, meta, [outputs, slates, sent]) = Self::open_env(dir)?;
        let mut wtxn = env.write_txn()?;
        if meta.get(&wtxn, META_SEED)?.is_some() || !outputs.is_empty(&wtxn)? {
            return Err(WalletError::Exists);
        }
        meta.put(&mut wtxn, META_ENTROPY, &entropy)?;
        meta.put(&mut wtxn, META_SEED, &seed)?;
        meta.put(&mut wtxn, META_FORMAT, &[FORMAT])?;
        wtxn.commit()?;
        Ok(Wallet { env, master: master_of(&seed), meta, outputs, slates, sent })
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

    /// Unspent, unreserved outputs the UTXO set holds that can still sign,
    /// largest first.
    pub fn spendable(&self, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Vec<Owned>> {
        let mut keep: Vec<Owned> = Vec::new();
        for o in self.outputs()? {
            if o.state == State::Unspent && o.signatures_left() > 0 && utxo.contains(rtxn, &o.commitment)? {
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
            let held = utxo.contains(rtxn, &o.commitment)?;
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
    /// or payments that never landed. Returns how many.
    pub fn prune_pending(&self, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<usize> {
        let mut wtxn = self.env.write_txn()?;
        let mut n = 0;
        for o in self.outputs()? {
            if o.state == State::Unspent && !utxo.contains(rtxn, &o.commitment)? {
                self.outputs.delete(&mut wtxn, &digest_to_bytes(&o.commitment))?;
                n += 1;
            }
        }
        wtxn.commit()?;
        Ok(n)
    }

    /// Finds this wallet's unspent outputs in the UTXO set by their memos
    /// and records the ones it does not know, as recovered. Returns how many
    /// were added and their total.
    pub fn scan(&self, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<(usize, u128)> {
        let mut found = Vec::new();
        for (position, memo) in utxo.memos(rtxn)? {
            let Some((nonce, amount)) = self.open_memo(&memo) else {
                continue;
            };
            let commitment = utxo.get(rtxn, position)?;
            let pk = self.key(&nonce).public_key();
            if key_commitment(&pubkey_hash(&pk), amount) != commitment || self.owned(&commitment)?.is_some() {
                continue;
            }
            found.push(Owned {
                commitment,
                nonce,
                amount,
                state: State::Unspent,
                created: unix_now(),
                recovered: true,
                start: random_bytes::<1>()?[0] % LEAVES_PER_HALF as u8,
                used: 0,
            });
        }
        let mut wtxn = self.env.write_txn()?;
        for o in &found {
            self.record(&mut wtxn, o)?;
        }
        wtxn.commit()?;
        Ok((found.len(), found.iter().map(|o| o.amount as u128).sum()))
    }

    /// The key of `c` positioned at its next leaf. The leaf is recorded as
    /// used and committed before the key is returned. Also returns whether
    /// this is the output's last signature.
    fn signing_key(&self, c: &Commitment) -> Result<(Key, bool)> {
        let mut wtxn = self.env.write_txn()?;
        let mut o = self.owned_in(&wtxn, c)?.ok_or(WalletError::Corrupt("missing output"))?;
        if u32::from(o.used) >= LEAVES_PER_HALF {
            return Err(WalletError::Exhausted);
        }
        let base = if o.recovered { LEAVES_PER_HALF } else { 0 };
        let leaf = base + (u32::from(o.start) + u32::from(o.used)) % LEAVES_PER_HALF;
        o.used += 1;
        let last = u32::from(o.used) == LEAVES_PER_HALF;
        self.record(&mut wtxn, &o)?;
        wtxn.commit()?;
        let mut key = self.key(&o.nonce);
        key.set_next_index(u64::from(leaf));
        Ok((key, last))
    }

    /// Signs `unsigned`, whose inputs must be the wallet's outputs `inputs`
    /// in order, and marks them spent.
    fn sign(&self, unsigned: UnsignedTransaction, inputs: &[Commitment]) -> Result<Signed> {
        if inputs.iter().any(|c| self.owned(c).ok().flatten().is_none_or(|o| o.signatures_left() == 0)) {
            return Err(WalletError::Exhausted);
        }
        let mut keys = Vec::with_capacity(inputs.len());
        let mut last_signatures = Vec::new();
        for c in inputs {
            let (key, last) = self.signing_key(c)?;
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
        let mut wtxn = self.env.write_txn()?;
        for c in inputs {
            self.set_state(&mut wtxn, c, State::Spent)?;
        }
        wtxn.commit()?;
        Ok(Signed { tx, last_signatures })
    }

    /// Starts a payment of `amount` with `fee`: picks confirmed inputs
    /// largest first, reserves them, adds change to a fresh output, and
    /// returns the stage-1 slate for the recipient.
    pub fn send(&self, amount: u64, fee: u64, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Slate> {
        let need = amount as u128 + fee as u128;
        if amount == 0 {
            return Err(WalletError::BadSlate("amount is zero"));
        }
        let coins = self.spendable(utxo, rtxn)?;
        let have: u128 = coins.iter().map(|c| c.amount as u128).sum();
        if have < need {
            return Err(WalletError::Insufficient { have, need });
        }
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
        let mut outputs = Vec::new();
        let mut change = None;
        if change_amount > 0 {
            let out = self.receive(change_amount)?;
            change = Some(out.commitment);
            outputs.push(out);
        }
        let mut wtxn = self.env.write_txn()?;
        for c in &picked {
            self.set_state(&mut wtxn, &c.commitment, State::Reserved)?;
        }
        let id = random_bytes::<32>()?;
        let pending = Pending { inputs: picked.iter().map(|c| c.commitment).collect(), change };
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
        let ins: u128 = slate.inputs.iter().map(|(_, a)| *a as u128).sum();
        let outs: u128 = slate.outputs.iter().map(|o| o.amount as u128).sum();
        let paid: u128 = slate.outputs[slate.change as usize..].iter().map(|o| o.amount as u128).sum();
        if paid != slate.amount as u128 || ins != outs + slate.fee as u128 {
            return Err(WalletError::BadSlate("amounts do not balance"));
        }
        let change_ok = match pending.change {
            Some(c) => slate.change == 1 && slate.outputs[0].commitment == c,
            None => slate.change == 0,
        };
        if !change_ok {
            return Err(WalletError::BadSlate("change output changed"));
        }
        let signed = self.sign(slate.unsigned(), &pending.inputs)?;
        let mut wtxn = self.env.write_txn()?;
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
        let signed = match self.sign(UnsignedTransaction::new(inputs, vec![back]), &sent.inputs) {
            Ok(s) => s,
            Err(e) => {
                self.forget(&back.commitment)?;
                return Err(e);
            }
        };
        let mut wtxn = self.env.write_txn()?;
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
                open |= utxo.contains(rtxn, c)?;
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

    fn land(env: &Env, u: &UtxoSet, outs: &[&Output]) {
        let mut wtxn = env.write_txn().unwrap();
        for o in outs {
            u.add_output(&mut wtxn, &o.block_output()).unwrap();
        }
        wtxn.commit().unwrap();
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
            land(&env, &u, &[&a]);
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
        assert_eq!(w.prune_pending(&u, &rtxn).unwrap(), 1);
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
        land(&env, &u, &[&a]);
        // Normal output: leaves 0..7 in order, the eighth flagged last.
        for i in 0..8u64 {
            let (k, last) = w.signing_key(&a.commitment).unwrap();
            assert_eq!(k.next_index(), i);
            assert_eq!(last, i == 7);
        }
        assert!(matches!(w.signing_key(&a.commitment), Err(WalletError::Exhausted)));
        // A restored copy finds it and signs from 8..15, from a random start,
        // wrapping within that half, eight times.
        let r = Wallet::restore(&dir.0.join("restored"), &phrase, "").unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(r.scan(&u, &rtxn).unwrap(), (1, 50));
        assert_eq!(r.scan(&u, &rtxn).unwrap(), (0, 0));
        let o = r.owned(&a.commitment).unwrap().unwrap();
        assert!(o.recovered && o.amount == 50);
        let mut seen = Vec::new();
        for i in 0..8u32 {
            let (k, last) = r.signing_key(&a.commitment).unwrap();
            assert!((8..16).contains(&k.next_index()));
            assert_eq!(k.next_index() as u32, 8 + (u32::from(o.start) + i) % 8);
            assert_eq!(last, i == 7);
            seen.push(k.next_index());
        }
        seen.sort_unstable();
        assert_eq!(seen, (8..16).collect::<Vec<_>>());
        assert!(matches!(r.signing_key(&a.commitment), Err(WalletError::Exhausted)));
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
        let a1 = alice.receive(60_000).unwrap();
        let a2 = alice.receive(50_000).unwrap();
        land(&env, &u, &[&a1, &a2]);
        let rtxn = env.read_txn().unwrap();
        assert!(matches!(
            alice.send(200_000, 1, &u, &rtxn),
            Err(WalletError::Insufficient { have: 110_000, need: 200_001 })
        ));
        let slate = alice.send(70_000, 2, &u, &rtxn).unwrap();
        assert_eq!((slate.stage, slate.inputs.len(), slate.change), (1, 2, 1));
        assert_eq!(slate.outputs[0].amount, 39_998);
        assert_eq!(
            alice.balance(&u, &rtxn).unwrap(),
            Balance { confirmed: 0, pending: 39_998, reserved: 110_000, locked: 0 }
        );
        let mut received = Slate::from_bytes(&slate.to_bytes()).unwrap();
        assert_eq!(received, slate);
        assert!(matches!(bob.finalize(&received), Err(WalletError::BadSlate(_))));
        bob.receive_slate(&mut received).unwrap();
        assert!(matches!(bob.receive_slate(&mut received), Err(WalletError::BadSlate(_))));
        let received = Slate::from_bytes(&received.to_bytes()).unwrap();
        assert!(matches!(bob.finalize(&received), Err(WalletError::Unknown)));
        let mut greedy = received.clone();
        greedy.outputs[1] = Output::new(&bob.key(&[Fp::ONE; 4]).public_key(), 70_001);
        assert!(matches!(alice.finalize(&greedy), Err(WalletError::BadSlate("amounts do not balance"))));
        let signed = alice.finalize(&received).unwrap();
        let tx = signed.tx;
        assert!(tx.verify_signatures() && tx.balance() == 2 && signed.last_signatures.is_empty());
        assert!(matches!(alice.finalize(&received), Err(WalletError::Unknown)));
        // Signed but not confirmed: the inputs are locked, not reserved.
        assert_eq!(
            alice.balance(&u, &rtxn).unwrap(),
            Balance { confirmed: 0, pending: 39_998, reserved: 0, locked: 110_000 }
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
        let a3 = alice.receive(9).unwrap();
        land(&env, &u, &[&a3]);
        let rtxn = env.read_txn().unwrap();
        let s2 = alice.send(4, 0, &u, &rtxn).unwrap();
        assert_eq!(alice.balance(&u, &rtxn).unwrap().reserved, 9);
        alice.cancel_slate(&s2.id).unwrap();
        assert_eq!(alice.balance(&u, &rtxn).unwrap().reserved, 0);
        assert!(matches!(alice.cancel_slate(&s2.id), Err(WalletError::Unknown)));
        assert_eq!(digest_from_hex(&s2.id_hex()), Some(s2.id));
    }
}
