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

use crate::address;
use crate::bip39;
use crate::chacha20poly1305;
use crate::codec::{Reader, Writer};
use crate::mempool::{MAX_TX_SIZE, Policy};
use crate::mldsa;
use crate::mlkem;
use crate::names::{self, MIN_REVEAL, NameOp, NameSet, Record, commit_hash, name_hash};
use crate::policy::{Cond, CondWitness, Mode, Policy as SpendPolicy, Signer, rebind_message};
use crate::poseidon2::{DIGEST, Fp, digest_to_bytes};
use crate::proofs::{Burn, Claim, Receipt};
use crate::state_tree::open_env;
use crate::transaction::{
    Commitment, EMPTY_MEMO, INPUT_SIZE, Key, Memo, OUTPUT_SIZE, Output, Transaction, UnsignedTransaction, hash_domain,
    key_commitment, memo_slot, pubkey_hash, slot_parts,
};
use crate::utxo::{self, UtxoSet};
use crate::xmss::{Digest, PublicKey, SEED_SIZE};

const META_SECRET: &str = "secret";
const META_FORMAT: &str = "format";
/// Set by a restore: the wallet's outputs are still to be found on chain.
const META_SCAN_PENDING: &str = "scan_pending";
/// Height and hash of the block up to which the wallet has looked for its
/// outputs' positions.
const META_SYNCED: &str = "synced";
/// The counter the identity key is derived with (`docs/PRIVACY.md`, fix
/// 5), a `u64`, and whether the address is off (present: off).
const META_ADDRESS: &str = "address";
const META_ADDRESS_OFF: &str = "address_off";
/// Version of the on-disk layout: 3 is BIP39 phrases and per-output keys;
/// 5 adds the name tables; 6 stores keys with their tree height (slate
/// format 3).
const FORMAT: u8 = 8;
/// Upper bound only, reserved as address space; the file grows as needed.
const MAP_SIZE: usize = 64 << 30;
const SLATE_MAGIC: &[u8; 8] = b"tabslt05";

const DOM_MASTER: u32 = 0x30;
const DOM_TAG: u32 = 0x31;
const DOM_KEY: u32 = 0x32;
const DOM_OWNER: u32 = 0x33;
const DOM_SALT: u32 = 0x34;
const DOM_CHANNEL: u32 = 0x35;
const DOM_IDENTITY: u32 = 0x36;
const DOM_RELAY: u32 = 0x37;
/// Tree height of the channel keys this wallet makes unless told
/// otherwise: 65,536 states.
pub const CHANNEL_HEIGHT: usize = 16;
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

/// A key of this wallet listed in a tracked policy: which listed key it
/// is, the nonce it derives from, its tree height, and the leaves used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyKey {
    pub index: u8,
    pub nonce: [Fp; NONCE],
    pub height: u8,
    pub used: u32,
}

/// An output under a spend policy this wallet is party to: a multisig, an
/// HTLC, a channel state or a factory (see `docs/ELTOO.md`). Unlike plain
/// outputs these are not found again from the seed: the policy comes from
/// the parties' agreement, so a wallet keeps it, as channel wallets keep
/// their channel state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyOutput {
    pub commitment: Commitment,
    pub policy: SpendPolicy,
    pub amount: u64,
    pub memo: Memo,
    pub state: State,
    pub created: u64,
    pub position: Option<u64>,
    pub keys: Vec<PolicyKey>,
}

impl PolicyOutput {
    fn to_bytes(&self) -> Vec<u8> {
        let policy = self.policy.to_bytes();
        let mut w = Writer::with_capacity(64 + policy.len());
        w.u32(policy.len() as u32);
        w.0.extend_from_slice(&policy);
        w.u64(self.amount);
        w.fps(&self.memo);
        w.0.push(self.state.to_u8());
        w.u64(self.created);
        w.0.push(self.position.is_some() as u8);
        w.u64(self.position.unwrap_or(0));
        w.u32(self.keys.len() as u32);
        for k in &self.keys {
            w.0.push(k.index);
            w.fps(&k.nonce);
            w.0.push(k.height);
            w.u32(k.used);
        }
        w.finish()
    }

    fn from_bytes(commitment: Commitment, bytes: &[u8]) -> Option<PolicyOutput> {
        let mut r = Reader(bytes);
        let n = r.u32()? as usize;
        let policy = SpendPolicy::from_bytes(r.take(n)?)?;
        let amount = r.u64()?;
        let memo = [r.fp()?, r.fp()?, r.fp()?, r.fp()?, r.fp()?];
        let state = State::from_u8(r.take(1)?[0])?;
        let created = r.u64()?;
        let has = r.take(1)?[0];
        let position = r.u64()?;
        let position = (has == 1).then_some(position);
        let n = r.len(1 + 4 * NONCE + 1 + 4)?;
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n {
            let index = r.take(1)?[0];
            let nonce = [r.fp()?, r.fp()?, r.fp()?, r.fp()?];
            let height = r.take(1)?[0];
            let used = r.u32()?;
            keys.push(PolicyKey { index, nonce, height, used });
        }
        r.is_empty().then_some(PolicyOutput { commitment, policy, amount, memo, state, created, position, keys })
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
    /// The sender's id (its address's 32 bytes), or the hash of a secret
    /// it keeps when it does not name itself: what the receipt binds.
    pub sender: Digest,
    /// The recipient's receipt for its output (`docs/PROOFS.md`): every
    /// answered (stage-2) slate carries one.
    pub receipt: Option<Receipt>,
}

impl Slate {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.0.extend_from_slice(SLATE_MAGIC);
        w.0.extend_from_slice(&self.id);
        w.digest(&self.sender);
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
        if let Some(r) = &self.receipt {
            r.write(&mut w);
        }
        w.finish()
    }

    /// A slate from its bytes; `None` if malformed, as an answered slate
    /// without a receipt is.
    pub fn from_bytes(bytes: &[u8]) -> Option<Slate> {
        let mut r = Reader(bytes);
        if r.take(8)? != SLATE_MAGIC {
            return None;
        }
        let id: [u8; 32] = r.take(32)?.try_into().ok()?;
        let sender = r.digest()?;
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
        let receipt = if stage == 2 { Some(Receipt::read(&mut r)?) } else { None };
        r.is_empty().then_some(Slate { id, stage, amount, fee, inputs, outputs, change, sender, receipt })
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
    /// What the slate names as its sender: our address then (it may
    /// change before the answer, `docs/PRIVACY.md` fix 5), or the tag of
    /// `secret`.
    sender: Digest,
    /// The secret whose tag the slate names in place of our address, if
    /// it does not name us (`docs/PRIVACY.md`, fix 4).
    secret: Option<[u8; 32]>,
}

/// What the sender keeps about a finalized payment, to cancel it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub txid: Commitment,
    pub inputs: Vec<Commitment>,
    pub fee: u64,
    pub size: usize,
    pub created: u64,
    /// The signed transaction, to send again ([`Wallet::resend`]).
    pub tx: Transaction,
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
        w.digest(&self.sender);
        if let Some(s) = &self.secret {
            w.0.extend_from_slice(s);
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
        let amount = r.u64()?;
        let fee = r.u64()?;
        let sender = r.digest()?;
        let secret = match r.0.len() {
            0 => None,
            32 => Some(r.take(32)?.try_into().ok()?),
            _ => return None,
        };
        Some(Pending { inputs, change, amount, fee, sender, secret })
    }
}

impl Sent {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        write_commitments(&mut w, &self.inputs);
        w.u64(self.fee);
        w.u64(self.size as u64);
        w.u64(self.created);
        w.0.extend_from_slice(&self.tx.to_bytes());
        w.finish()
    }

    fn from_bytes(txid: Commitment, bytes: &[u8]) -> Option<Sent> {
        let mut r = Reader(bytes);
        let inputs = read_commitments(&mut r)?;
        let fee = r.u64()?;
        let size = r.u64()? as usize;
        let created = r.u64()?;
        let tx = Transaction::from_bytes(r.0)?;
        Some(Sent { txid, inputs, fee, size, created, tx })
    }
}

/// A payment this wallet made, or a burn, kept for its proof
/// (`docs/PROOFS.md`): the output it created and whose it is, and where
/// it landed once the chain has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    pub txid: Commitment,
    /// The recipient's output, or the burn output.
    pub output: Output,
    pub claim: Claim,
    pub created: u64,
    /// The main-chain block that created the output, and its position.
    pub landed: Option<(u32, u64)>,
    /// The output's path to that block's state root.
    pub path: Option<crate::state_tree::Proof>,
}

impl Payment {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.0.extend_from_slice(&self.output.to_bytes());
        self.claim.write(&mut w);
        w.u64(self.created);
        match self.landed {
            Some((h, p)) => {
                w.0.push(1);
                w.u32(h);
                w.u64(p);
            }
            None => w.0.push(0),
        }
        match &self.path {
            Some(p) => {
                w.0.push(1);
                w.0.extend_from_slice(&p.to_bytes());
            }
            None => w.0.push(0),
        }
        w.finish()
    }

    fn from_bytes(txid: Commitment, bytes: &[u8]) -> Option<Payment> {
        let mut r = Reader(bytes);
        let output = Output::from_bytes(r.take(OUTPUT_SIZE)?)?;
        let claim = Claim::read(&mut r)?;
        let created = r.u64()?;
        let landed = match r.take(1)?[0] {
            0 => None,
            1 => Some((r.u32()?, r.u64()?)),
            _ => return None,
        };
        let path = match r.take(1)?[0] {
            0 => None,
            1 => Some(crate::state_tree::Proof::from_bytes(r.take(crate::state_tree::Proof::SIZE)?)?),
            _ => return None,
        };
        r.is_empty().then_some(Payment { txid, output, claim, created, landed, path })
    }

    /// Its proof, once it has landed and its path is known.
    pub fn proof(&self) -> Option<crate::proofs::Proof> {
        let (height, position) = self.landed?;
        Some(crate::proofs::Proof {
            height,
            position,
            key_hash: self.output.key_hash,
            amount: self.output.amount,
            memo: self.output.memo,
            path: self.path.clone()?,
            claim: self.claim.clone(),
        })
    }

    pub fn is_burn(&self) -> bool {
        matches!(self.claim, Claim::Burn(_))
    }
}

/// What [`Wallet::take_slate`] made of a slate.
pub enum Incoming {
    /// A payment to us, answered: to return to the sender.
    Answered(Slate),
    /// Our payment, answered and signed: to pool.
    Finalized(Slate, Signed),
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
    /// The wallet's password is wrong (or none was given for a locked
    /// wallet).
    WrongPassword,
    /// Restoring over an existing wallet.
    Exists,
    /// An input has not been seen in a block yet.
    Unconfirmed,
    /// The transaction's inputs are no longer unspent on chain: it (or
    /// another spend of them) has landed.
    Landed,
    /// A name operation the wallet cannot make.
    Name(String),
    /// A policy spend could not be made.
    Policy(&'static str),
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
            WalletError::WrongPassword => f.write_str("wrong wallet password"),
            WalletError::Exists => f.write_str("a wallet already exists in that directory"),
            WalletError::Unconfirmed => f.write_str("an input is not confirmed yet"),
            WalletError::Landed => f.write_str("the inputs are already spent on chain"),
            WalletError::Name(m) => f.write_str(m),
            WalletError::Policy(m) => write!(f, "policy: {m}"),
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
    /// Policy outputs by commitment.
    policies: Database<Bytes, Bytes>,
    /// Payments and burns by txid, kept for their proofs.
    payments: Database<Bytes, Bytes>,
    /// Rewards of blocks this wallet mined, until settled: commitment →
    /// height ‖ block hash (zero until the block is found).
    rewards: Database<Bytes, Bytes>,
    /// The identity key's counter and whether the address is off, as
    /// stored.
    address: std::sync::atomic::AtomicU64,
    address_off: std::sync::atomic::AtomicBool,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `N` bytes from the system's random source.
pub fn random_bytes<const N: usize>() -> std::io::Result<[u8; N]> {
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

/// PBKDF2 rounds for a wallet password's key: about a quarter of a second on
/// a desktop core. The count is stored with the record, so it can change.
const PASSWORD_ROUNDS: u32 = 200_000;

/// What [`Wallet::open_with`] asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ask {
    /// A password for a new wallet; empty for none.
    New,
    /// The password of an existing, locked wallet.
    Unlock,
}

/// The wallet's secret: the phrase's entropy and its BIP39 seed (which
/// also depends on the BIP39 passphrase), stored as one record:
///
/// ```text
/// 0 | entropy (16) | seed (64)                                 no password
/// 1 | rounds (4) | salt (16) | nonce (12) | sealed entropy|seed (80 + 16)
/// ```
///
/// Locked under ChaCha20-Poly1305 with a key PBKDF2-HMAC-SHA512 makes from
/// the password; the header is the associated data.
struct Secret {
    entropy: [u8; bip39::ENTROPY_BYTES],
    seed: [u8; 64],
}

impl Secret {
    fn plain(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(bip39::ENTROPY_BYTES + 64);
        out.extend_from_slice(&self.entropy);
        out.extend_from_slice(&self.seed);
        out
    }

    fn from_plain(b: &[u8]) -> Option<Secret> {
        if b.len() != bip39::ENTROPY_BYTES + 64 {
            return None;
        }
        Some(Secret {
            entropy: b[..bip39::ENTROPY_BYTES].try_into().ok()?,
            seed: b[bip39::ENTROPY_BYTES..].try_into().ok()?,
        })
    }

    fn key(password: &str, salt: &[u8], rounds: u32) -> [u8; 32] {
        let mut s = b"tabminer wallet".to_vec();
        s.extend_from_slice(salt);
        bip39::pbkdf2_hmac_sha512(password.as_bytes(), &s, rounds)[..32].try_into().unwrap()
    }

    /// The record, locked under `password` unless it is empty.
    fn seal(&self, password: &str) -> std::io::Result<Vec<u8>> {
        if password.is_empty() {
            let mut out = vec![0];
            out.extend_from_slice(&self.plain());
            return Ok(out);
        }
        let salt = random_bytes::<16>()?;
        let nonce = random_bytes::<{ chacha20poly1305::NONCE_LEN }>()?;
        let mut out = vec![1];
        out.extend_from_slice(&PASSWORD_ROUNDS.to_le_bytes());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        let key = Self::key(password, &salt, PASSWORD_ROUNDS);
        let sealed = chacha20poly1305::seal(&key, &nonce, &out, &self.plain());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Whether a record is locked.
    fn locked(b: &[u8]) -> bool {
        b.first() == Some(&1)
    }

    /// Opens a record; a plain one ignores the password.
    fn open(b: &[u8], password: &str) -> Result<Secret> {
        const HEADER: usize = 1 + 4 + 16 + chacha20poly1305::NONCE_LEN;
        match b.first() {
            Some(0) => Secret::from_plain(&b[1..]).ok_or(WalletError::Corrupt("secret")),
            Some(1) if b.len() > HEADER => {
                let rounds = u32::from_le_bytes(b[1..5].try_into().unwrap());
                let salt = &b[5..21];
                let nonce: [u8; chacha20poly1305::NONCE_LEN] = b[21..HEADER].try_into().unwrap();
                let key = Self::key(password, salt, rounds);
                let plain = chacha20poly1305::open(&key, &nonce, &b[..HEADER], &b[HEADER..])
                    .ok_or(WalletError::WrongPassword)?;
                Secret::from_plain(&plain).ok_or(WalletError::Corrupt("secret"))
            }
            _ => Err(WalletError::Corrupt("secret")),
        }
    }
}

/// Makes the wallet directory private to its owner.
fn restrict(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

impl Wallet {
    #[allow(clippy::type_complexity)]
    fn open_env(dir: &Path) -> Result<(Env, Database<Str, Bytes>, [Database<Bytes, Bytes>; 8])> {
        let env = open_env(dir, MAP_SIZE).map_err(|e| match e {
            crate::state_tree::Error::Heed(h) => WalletError::Heed(h),
            other => WalletError::Utxo(utxo::Error::Tree(other)),
        })?;
        restrict(dir)?;
        let mut wtxn = env.write_txn()?;
        let meta = env.create_database(&mut wtxn, Some("meta"))?;
        let outputs = env.create_database(&mut wtxn, Some("outputs"))?;
        let slates = env.create_database(&mut wtxn, Some("slates"))?;
        let sent = env.create_database(&mut wtxn, Some("sent"))?;
        let commits = env.create_database(&mut wtxn, Some("commits"))?;
        let names = env.create_database(&mut wtxn, Some("names"))?;
        let policies = env.create_database(&mut wtxn, Some("policies"))?;
        let payments = env.create_database(&mut wtxn, Some("payments"))?;
        let rewards = env.create_database(&mut wtxn, Some("rewards"))?;
        wtxn.commit()?;
        Ok((env, meta, [outputs, slates, sent, commits, names, policies, payments, rewards]))
    }

    /// Opens the wallet in `dir` without a password, creating one with a
    /// fresh phrase if there is none. Returns the wallet and, if it was
    /// just created, its phrase.
    pub fn open(dir: &Path) -> Result<(Wallet, Option<String>)> {
        Self::open_with(dir, &mut |_| Ok(String::new()))
    }

    /// Opens the wallet in `dir`, asking `ask` for its password if it is
    /// locked, or for a new one if there is no wallet yet and one is
    /// created with a fresh phrase. Returns the wallet and, if it was just
    /// created, its phrase.
    pub fn open_with(dir: &Path, ask: &mut dyn FnMut(Ask) -> Result<String>) -> Result<(Wallet, Option<String>)> {
        let (env, meta, [outputs, slates, sent, commits, names, policies, payments, rewards]) = Self::open_env(dir)?;
        let rtxn = env.read_txn()?;
        let record = meta.get(&rtxn, META_SECRET)?.map(<[u8]>::to_vec);
        let fresh = record.is_none() && meta.len(&rtxn)? == 0 && outputs.is_empty(&rtxn)?;
        drop(rtxn);
        let (secret, created) = match record {
            Some(record) => {
                let rtxn = env.read_txn()?;
                if meta.get(&rtxn, META_FORMAT)? != Some(&[FORMAT][..]) {
                    return Err(WalletError::OldFormat);
                }
                drop(rtxn);
                let password = if Secret::locked(&record) { ask(Ask::Unlock)? } else { String::new() };
                (Secret::open(&record, &password)?, None)
            }
            None if !fresh => return Err(WalletError::OldFormat),
            None => {
                let entropy = random_bytes::<{ bip39::ENTROPY_BYTES }>()?;
                let phrase = bip39::phrase(&entropy);
                let secret = Secret { entropy, seed: bip39::seed(&phrase, "")? };
                let record = secret.seal(&ask(Ask::New)?)?;
                let mut wtxn = env.write_txn()?;
                meta.put(&mut wtxn, META_SECRET, &record)?;
                meta.put(&mut wtxn, META_FORMAT, &[FORMAT])?;
                wtxn.commit()?;
                (secret, Some(phrase))
            }
        };
        let rtxn = env.read_txn()?;
        let address = match meta.get(&rtxn, META_ADDRESS)? {
            Some(b) => u64::from_le_bytes(b.try_into().map_err(|_| WalletError::Corrupt("address"))?),
            None => 0,
        };
        let off = meta.get(&rtxn, META_ADDRESS_OFF)?.is_some();
        drop(rtxn);
        Ok((
            Wallet {
                env,
                master: master_of(&secret.seed),
                meta,
                outputs,
                slates,
                sent,
                commits,
                names,
                policies,
                payments,
                rewards,
                address: address.into(),
                address_off: off.into(),
            },
            created,
        ))
    }

    /// Creates a wallet in `dir` from a phrase and BIP39 passphrase, locked
    /// under `password` unless it is empty; the outputs come back with
    /// [`Wallet::scan`] once the chain is synced.
    pub fn restore(dir: &Path, phrase: &str, passphrase: &str, password: &str) -> Result<Wallet> {
        let secret = Secret { entropy: bip39::entropy(phrase)?, seed: bip39::seed(phrase, passphrase)? };
        let (env, meta, [outputs, slates, sent, commits, names, policies, payments, rewards]) = Self::open_env(dir)?;
        let mut wtxn = env.write_txn()?;
        if meta.get(&wtxn, META_SECRET)?.is_some() || !outputs.is_empty(&wtxn)? {
            return Err(WalletError::Exists);
        }
        meta.put(&mut wtxn, META_SECRET, &secret.seal(password)?)?;
        meta.put(&mut wtxn, META_FORMAT, &[FORMAT])?;
        meta.put(&mut wtxn, META_SCAN_PENDING, &[1])?;
        // Old addresses are abandoned, never reused: a restore starts from
        // a fresh one (`docs/PRIVACY.md`, fix 5).
        let address = u64::from_le_bytes(random_bytes::<8>()?) >> 4;
        meta.put(&mut wtxn, META_ADDRESS, &address.to_le_bytes())?;
        wtxn.commit()?;
        Ok(Wallet {
            env,
            master: master_of(&secret.seed),
            meta,
            outputs,
            slates,
            sent,
            commits,
            names,
            policies,
            payments,
            rewards,
            address: address.into(),
            address_off: false.into(),
        })
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

    fn secret_record(&self) -> Result<Vec<u8>> {
        let rtxn = self.env.read_txn()?;
        Ok(self.meta.get(&rtxn, META_SECRET)?.ok_or(WalletError::Corrupt("secret"))?.to_vec())
    }

    /// Whether the wallet's secret is locked under a password.
    pub fn locked(&self) -> Result<bool> {
        Ok(Secret::locked(&self.secret_record()?))
    }

    /// The wallet's 12-word phrase; `password` is checked if the wallet is
    /// locked.
    pub fn phrase(&self, password: &str) -> Result<String> {
        Ok(bip39::phrase(&Secret::open(&self.secret_record()?, password)?.entropy))
    }

    /// Locks the wallet's secret under `new` instead of `old` (either may
    /// be empty, for none).
    pub fn set_password(&self, old: &str, new: &str) -> Result<()> {
        let record = self.secret_record()?;
        let sealed = Secret::open(&record, old)?.seal(new)?;
        let mut wtxn = self.env.write_txn()?;
        if self.meta.get(&wtxn, META_SECRET)? != Some(&record[..]) {
            return Err(WalletError::Corrupt("secret changed meanwhile"));
        }
        self.meta.put(&mut wtxn, META_SECRET, &sealed)?;
        wtxn.commit()?;
        Ok(())
    }

    fn with_master(&self, domain: u32, nonce: &[Fp; NONCE]) -> [Fp; DIGEST] {
        let mut input = [Fp::ZERO; DIGEST + NONCE];
        input[..DIGEST].copy_from_slice(&self.master);
        input[DIGEST..].copy_from_slice(nonce);
        hash_domain(domain, &input)
    }

    /// The wallet's Dilithium (ML-DSA-65) key, from the master key and
    /// the address counter (`docs/PRIVACY.md`, fix 5): its hash is the
    /// wallet's address.
    pub fn identity_key(&self) -> mldsa::SecretKey {
        let i = self.address.load(std::sync::atomic::Ordering::Acquire);
        let mut input = self.master.to_vec();
        input.extend_from_slice(&[Fp::new((i & ((1 << 30) - 1)) as u32), Fp::new((i >> 30 & ((1 << 30) - 1)) as u32)]);
        let seed: [u8; mldsa::SEED_LEN] = digest_to_bytes(&hash_domain(DOM_IDENTITY, &input));
        mldsa::keygen(&seed)
    }

    /// Whether the address is off: no sessions, nobody can reach the
    /// wallet, though it can still pay.
    pub fn address_off(&self) -> bool {
        self.address_off.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Moves to a new address: the counter goes up one and the address is
    /// on. The old address is abandoned, never used again. Returns the new
    /// key.
    pub fn next_address(&self) -> Result<mldsa::SecretKey> {
        let i = self.address.load(std::sync::atomic::Ordering::Acquire) + 1;
        if i >= 1 << 60 {
            return Err(WalletError::Corrupt("address counter"));
        }
        let mut wtxn = self.env.write_txn()?;
        self.meta.put(&mut wtxn, META_ADDRESS, &i.to_le_bytes())?;
        self.meta.delete(&mut wtxn, META_ADDRESS_OFF)?;
        wtxn.commit()?;
        self.address.store(i, std::sync::atomic::Ordering::Release);
        self.address_off.store(false, std::sync::atomic::Ordering::Release);
        Ok(self.identity_key())
    }

    /// Turns the address off; [`Wallet::next_address`] turns a new one on.
    pub fn turn_address_off(&self) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        self.meta.put(&mut wtxn, META_ADDRESS_OFF, &[1])?;
        wtxn.commit()?;
        self.address_off.store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// The relay's Dilithium (ML-DSA-65) key, from the master key under its
    /// own domain tag: apart from the wallet's identity, so a relay's
    /// listed id is not its operator's payment address, and kept by a
    /// restore from the phrase (`docs/ONION.md`). It signs in hedged mode.
    pub fn relay_key(&self) -> mldsa::SecretKey {
        let seed: [u8; mldsa::SEED_LEN] = digest_to_bytes(&hash_domain(DOM_RELAY, &self.master));
        // It signs whatever anyone asks (every channel and hop): hedged.
        mldsa::keygen(&seed).hedged()
    }

    /// The wallet's id on the message layer: the hash of its Dilithium
    /// public key (`docs/ONION.md`).
    pub fn id(&self) -> Digest {
        address::id_of(self.identity_key().public_key())
    }

    /// The wallet's `tab1…` address: its id in text.
    pub fn address(&self) -> String {
        address::encode(&self.id())
    }

    /// A fresh ephemeral Kyber (ML-KEM-768) key and its announcement,
    /// signed by the wallet's Dilithium key with sequence number `seq`,
    /// valid until `expiry` and bound to the rendezvous point's session
    /// `nonce` (`docs/ONION.md`). The Kyber key is random, never derived
    /// or stored: a key compromised later opens nothing sent before it
    /// was rotated.
    pub fn fresh_announce(
        &self,
        seq: u64,
        expiry: u64,
        nonce: u64,
    ) -> Result<(mlkem::SecretKey, crate::onion::Announce)> {
        let kyber = mlkem::keygen(&random_bytes::<64>()?);
        let announce = crate::onion::Announce::make(&self.identity_key(), kyber.public_key(), seq, expiry, nonce);
        Ok((kyber, announce))
    }

    /// The key of the output with nonce `nonce`, at its first leaf.
    pub fn key(&self, nonce: &[Fp; NONCE]) -> Key {
        let seed: [u8; SEED_SIZE] = digest_to_bytes(&self.with_master(DOM_KEY, nonce));
        Key::generate(&seed)
    }

    /// The memo of the output with nonce `nonce`: the nonce, then a tag
    /// from the master key by which a scan tells this wallet's outputs
    /// from others' (a stranger's matches once in 2^31; the commitment
    /// confirms a match). The amount is public (`docs/AMOUNTS.md`).
    fn memo(&self, nonce: &[Fp; NONCE]) -> Memo {
        let mut memo = EMPTY_MEMO;
        memo[..NONCE].copy_from_slice(nonce);
        memo[NONCE] = self.with_master(DOM_TAG, nonce)[0];
        memo
    }

    /// The nonce a memo holds, if its tag is this wallet's.
    fn open_memo(&self, memo: &Memo) -> Option<[Fp; NONCE]> {
        let nonce: [Fp; NONCE] = memo[..NONCE].try_into().unwrap();
        (memo[NONCE] == self.with_master(DOM_TAG, &nonce)[0]).then_some(nonce)
    }

    /// The 32-byte memo of a name record: the memo padded with zeros, as a
    /// memo slot of amount zero.
    fn name_memo(&self, nonce: &[Fp; NONCE]) -> Digest {
        memo_slot(&self.memo(nonce), 0)
    }

    /// The nonce a name memo ([`Wallet::name_memo`]) holds, if it is one of
    /// this wallet's.
    fn open_name_memo(&self, memo: &Digest) -> Option<[Fp; NONCE]> {
        match slot_parts(memo)? {
            (m, 0) => self.open_memo(&m),
            _ => None,
        }
    }

    /// A fresh output paying `amount` to this wallet, with its memo,
    /// recorded as unspent (and unconfirmed until the UTXO set holds it).
    pub fn receive(&self, amount: u64) -> Result<Output> {
        let nonce = [random_fp()?, random_fp()?, random_fp()?, random_fp()?];
        let pk = self.key(&nonce).public_key();
        let out = Output::with_memo(&pubkey_hash(&pk), amount, self.memo(&nonce));
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
            if let Some(mut p) = self.policy_in(&wtxn, &out.commitment)? {
                p.position = Some(first + i as u64);
                self.record_policy(&mut wtxn, &p)?;
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
        self.rewards.delete(&mut wtxn, &digest_to_bytes(c))?;
        wtxn.commit()?;
        Ok(gone)
    }

    /// Notes that the output `c` is the reward of a block being built at
    /// `height`, to be forgotten if the block never makes the main chain
    /// ([`Wallet::prune_rewards`]).
    pub fn note_reward(&self, c: &Commitment, height: u32) -> Result<()> {
        let mut v = height.to_le_bytes().to_vec();
        v.extend_from_slice(&[0; 32]);
        let mut wtxn = self.env.write_txn()?;
        self.rewards.put(&mut wtxn, &digest_to_bytes(c), &v)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Notes the hash of the block whose reward is `c`, once it is found and
    /// before it is submitted.
    pub fn reward_found(&self, c: &Commitment, hash: &[u8; 32]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        if let Some(b) = self.rewards.get(&wtxn, &digest_to_bytes(c))? {
            let mut v = b[..4].to_vec();
            v.extend_from_slice(hash);
            self.rewards.put(&mut wtxn, &digest_to_bytes(c), &v)?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Settles the rewards of blocks this wallet mined, `tip` being the main
    /// chain's height and `settle` the depth below which no
    /// reorganization reaches. A reward is forgotten when its block was
    /// never found (a crash or an exit while mining), is unknown to the
    /// chain or invalid (`known` says), or is still off the main chain once
    /// `settle` blocks deep; a reward that landed and is that deep is
    /// simply no longer tracked. `keep` is the reward of the block being
    /// mined. Returns how many rewards were forgotten.
    pub fn prune_rewards(
        &self,
        utxo: &UtxoSet,
        rtxn: &RoTxn,
        tip: u32,
        settle: u32,
        known: impl Fn(&[u8; 32]) -> bool,
        keep: Option<Commitment>,
    ) -> Result<usize> {
        let mut records = Vec::new();
        {
            let wrtxn = self.env.read_txn()?;
            for item in self.rewards.iter(&wrtxn)? {
                let (k, v) = item?;
                let c = crate::poseidon2::digest_from_bytes(k).ok_or(WalletError::Corrupt("reward key"))?;
                if v.len() != 36 {
                    return Err(WalletError::Corrupt("reward"));
                }
                let height = u32::from_le_bytes(v[..4].try_into().unwrap());
                let hash: [u8; 32] = v[4..].try_into().unwrap();
                records.push((c, height, hash));
            }
        }
        let mut forgotten = 0;
        for (c, height, hash) in records {
            if keep == Some(c) {
                continue;
            }
            let settled = tip >= height.saturating_add(settle);
            let drop_record = |w: &Self| -> Result<()> {
                let mut wtxn = w.env.write_txn()?;
                w.rewards.delete(&mut wtxn, &digest_to_bytes(&c))?;
                wtxn.commit()?;
                Ok(())
            };
            let o = match self.owned(&c)? {
                Some(o) if o.state == State::Unspent => o,
                // Spent by the wallet: it landed.
                _ => {
                    drop_record(self)?;
                    continue;
                }
            };
            if self.held(&o, utxo, rtxn)? {
                if settled {
                    drop_record(self)?;
                }
            } else if hash == [0; 32] || !known(&hash) || settled {
                self.forget(&c)?;
                forgotten += 1;
            }
        }
        Ok(forgotten)
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

    /// Forgets pending commits that never reached the chain: not in the
    /// registry, and not among `pooled` (commits carried by pooled
    /// transactions, which may yet land). Returns the names forgotten.
    pub fn prune_commits(&self, registry: &NameSet, rtxn: &RoTxn, pooled: &HashSet<Commitment>) -> Result<Vec<String>> {
        let mut gone = Vec::new();
        let mut wtxn = self.env.write_txn()?;
        for c in self.pending_commits()? {
            let on_chain =
                registry.commit_position(rtxn, &c.commit).map_err(|e| WalletError::Name(e.to_string()))?.is_some();
            if !on_chain && !pooled.contains(&c.commit) && !c.recovered {
                self.commits.delete(&mut wtxn, &digest_to_bytes(&c.commit))?;
                gone.push(c.name.as_deref().map_or("?".to_string(), |n| String::from_utf8_lossy(n).into_owned()));
            }
        }
        wtxn.commit()?;
        Ok(gone)
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
        for (position, commitment, memo, amount) in utxo.memos(rtxn)? {
            let Some(nonce) = self.open_memo(&memo) else {
                continue;
            };
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
    /// With `named` the slate names our address, which the recipient's
    /// receipt then binds; otherwise it names the hash of a secret we keep
    /// (`docs/PRIVACY.md`, fix 4), and the recipient learns nothing of us.
    pub fn send(&self, amount: u64, fee: Option<u64>, named: bool, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Slate> {
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
        let secret = if named { None } else { Some(random_bytes::<32>()?) };
        let sender = secret.as_ref().map_or_else(|| self.id(), crate::proofs::sender_tag);
        let pending =
            Pending { inputs: picked.iter().map(|c| c.commitment).collect(), change, amount, fee, sender, secret };
        self.slates.put(&mut wtxn, &id, &pending.to_bytes())?;
        wtxn.commit()?;
        let inputs = picked.iter().map(|c| (self.key(&c.nonce).public_key(), c.amount)).collect();
        Ok(Slate {
            id,
            stage: 1,
            amount,
            fee,
            inputs,
            outputs,
            change: u32::from(change.is_some()),
            sender,
            receipt: None,
        })
    }

    /// The recipient's step: adds an output for the slate's amount, recorded
    /// as unspent, signs its receipt for it (`docs/PROOFS.md`) and advances
    /// the slate to stage 2.
    pub fn receive_slate(&self, slate: &mut Slate) -> Result<()> {
        if slate.stage != 1 {
            return Err(WalletError::BadSlate("not a stage-1 slate"));
        }
        if slate.outputs.len() != slate.change as usize {
            return Err(WalletError::BadSlate("already has a recipient output"));
        }
        let out = self.receive(slate.amount)?;
        slate.receipt = Some(Receipt::sign(&self.identity_key(), &out, &slate.id, &slate.sender));
        slate.outputs.push(out);
        slate.stage = 2;
        Ok(())
    }

    /// A slate that came over the message layer (`docs/ONION.md`), from
    /// the id `from` when known (a named sender, or the id an answer is
    /// from): a stage-1 slate gets our output and is to go back; a stage-2
    /// one, the answer to ours, is signed. `sent_to` is the id this wallet
    /// sent that slate to over the network, if it did: only that id may
    /// answer it.
    pub fn take_slate(
        &self,
        bytes: &[u8],
        from: Option<&Commitment>,
        sent_to: Option<&Commitment>,
    ) -> Result<Incoming> {
        let mut slate = Slate::from_bytes(bytes).ok_or(WalletError::BadSlate("malformed"))?;
        match slate.stage {
            1 => {
                self.receive_slate(&mut slate)?;
                Ok(Incoming::Answered(slate))
            }
            2 => {
                let from = from.ok_or(WalletError::BadSlate("an answer from no one known"))?;
                if sent_to.is_some_and(|to| to != from) {
                    return Err(WalletError::BadSlate("answered by an id it was not sent to"));
                }
                if slate.receipt.as_ref().is_some_and(|r| r.recipient() != *from) {
                    return Err(WalletError::BadSlate("the receipt is another id's"));
                }
                let signed = self.finalize(&slate)?;
                Ok(Incoming::Finalized(slate, signed))
            }
            _ => Err(WalletError::BadSlate("unknown stage")),
        }
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
                let ours = Output::with_memo(&pubkey_hash(&pk), o.amount, self.memo(&o.nonce));
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
        if 12 + slate.inputs.len() * INPUT_SIZE + slate.outputs.len() * OUTPUT_SIZE > MAX_TX_SIZE {
            return Err(WalletError::BadSlate("too many outputs for one transaction"));
        }
        // The receipt: the recipient acknowledges its one output as a
        // payment from us in this slate (`docs/PROOFS.md`).
        if slate.outputs.len() != slate.change as usize + 1 {
            return Err(WalletError::BadSlate("not one recipient output"));
        }
        let receipt = slate.receipt.clone().ok_or(WalletError::BadSlate("no receipt"))?;
        let paid_to = slate.outputs[slate.change as usize];
        if slate.sender != pending.sender || !receipt.verify(&paid_to, &slate.id, &slate.sender) {
            return Err(WalletError::BadSlate("the receipt does not hold"));
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
            tx: signed.tx.clone(),
        };
        self.sent.put(&mut wtxn, &digest_to_bytes(&sent.txid), &sent.to_bytes())?;
        let claim = Claim::Payment { sender: slate.sender, secret: pending.secret, slate_id: slate.id, receipt };
        let payment =
            Payment { txid: sent.txid, output: paid_to, claim, created: sent.created, landed: None, path: None };
        self.payments.put(&mut wtxn, &digest_to_bytes(&payment.txid), &payment.to_bytes())?;
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
        sent.fee + (12 + sent.inputs.len() * INPUT_SIZE + OUTPUT_SIZE) as u64
    }

    /// Cancels a finalized payment that is not yet confirmed: signs a
    /// replacement spending the same inputs back to a fresh output of this
    /// wallet with `fee` (at least [`Wallet::min_replacement_fee`]), using
    /// each input's next leaf. The payment's record now points at the
    /// replacement, which can itself be cancelled while leaves remain.
    pub fn cancel_sent(&self, txid: &Commitment, fee: Option<u64>, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Signed> {
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
            if !self.held(&o, utxo, rtxn)? {
                return Err(WalletError::Landed);
            }
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
        // Cancelled: the payment (or burn) will not land.
        self.payments.delete(&mut wtxn, &digest_to_bytes(txid))?;
        let next = Sent {
            txid: signed.tx.txid(),
            inputs: sent.inputs,
            fee,
            size: signed.tx.size(),
            created: unix_now(),
            tx: signed.tx.clone(),
        };
        self.sent.put(&mut wtxn, &digest_to_bytes(&next.txid), &next.to_bytes())?;
        wtxn.commit()?;
        // The replacement carries none of the original's name operations:
        // their entries go back to where they were before it was signed.
        // Should the original land after all, `sync_names` adopts what it
        // wrote.
        for op in &sent.tx.ops {
            self.undo_name_op(op)?;
        }
        Ok(signed)
    }

    /// A sent transaction as it was signed, to send again: its inputs at
    /// the positions this wallet now knows for their outputs (a
    /// reorganization may have moved them; positions are not signed).
    pub fn resend(&self, txid: &Commitment) -> Result<Transaction> {
        let sent = {
            let rtxn = self.env.read_txn()?;
            let b = self.sent.get(&rtxn, &digest_to_bytes(txid))?.ok_or(WalletError::Unknown)?;
            Sent::from_bytes(*txid, b).ok_or(WalletError::Corrupt("sent"))?
        };
        let mut tx = sent.tx;
        let mut positions = tx.spent_positions();
        if sent.inputs.len() == positions.len() {
            for (p, c) in positions.iter_mut().zip(&sent.inputs) {
                let known = match self.owned(c)? {
                    Some(o) => o.position,
                    None => self.policy_output(c)?.and_then(|o| o.position),
                };
                if let Some(q) = known {
                    *p = q;
                }
            }
            tx.set_positions(&positions);
        }
        Ok(tx)
    }

    /// Every payment and burn this wallet made that was not cancelled,
    /// oldest first.
    pub fn payments(&self) -> Result<Vec<Payment>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.payments.iter(&rtxn)? {
            let (k, b) = item?;
            let txid = crate::poseidon2::digest_from_bytes(k).ok_or(WalletError::Corrupt("payment key"))?;
            out.push(Payment::from_bytes(txid, b).ok_or(WalletError::Corrupt("payment"))?);
        }
        out.sort_by_key(|p| p.created);
        Ok(out)
    }

    /// Notes which payments' outputs are among `outputs`, the outputs the
    /// main-chain block at `height` added from position `first` on (by
    /// commitment and memo: burns of one amount share a commitment).
    /// Returns those that landed there anew, whose paths are to be made.
    pub fn land_payments(
        &self,
        height: u32,
        first: u64,
        outputs: &[crate::block::BlockOutput],
    ) -> Result<Vec<Payment>> {
        let mut wtxn = self.env.write_txn()?;
        let mut landed = Vec::new();
        let mut all = Vec::new();
        for item in self.payments.iter(&wtxn)? {
            let (k, b) = item?;
            let txid = crate::poseidon2::digest_from_bytes(k).ok_or(WalletError::Corrupt("payment key"))?;
            all.push(Payment::from_bytes(txid, b).ok_or(WalletError::Corrupt("payment"))?);
        }
        for mut p in all {
            let Some(i) = outputs.iter().position(|o| o.commitment == p.output.commitment && o.memo == p.output.memo)
            else {
                continue;
            };
            let at = (height, first + i as u64);
            if p.landed == Some(at) {
                continue;
            }
            p.landed = Some(at);
            p.path = None;
            self.payments.put(&mut wtxn, &digest_to_bytes(&p.txid), &p.to_bytes())?;
            landed.push(p);
        }
        if !landed.is_empty() {
            wtxn.commit()?;
        }
        Ok(landed)
    }

    /// Finds payments not yet seen landing among the unspent outputs, by
    /// commitment and memo, with the height of the block that created
    /// each: after a gap [`Wallet::land_payments`] could not follow block
    /// by block (a fast sync, a long time offline). A payment whose output
    /// was spent meanwhile is not found. Returns those found.
    pub fn find_payments(&self, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Vec<Payment>> {
        let waiting: Vec<Payment> = self.payments()?.into_iter().filter(|p| p.landed.is_none()).collect();
        if waiting.is_empty() {
            return Ok(Vec::new());
        }
        let mut found = Vec::new();
        for (position, commitment, memo, _) in utxo.memos(rtxn)? {
            let Some(i) = waiting.iter().position(|p| p.output.commitment == commitment && p.output.memo == memo)
            else {
                continue;
            };
            if found.iter().any(|p: &Payment| p.txid == waiting[i].txid) {
                continue;
            }
            let Some((_, _, height)) = utxo.output_at(rtxn, position)? else {
                continue;
            };
            let mut p = waiting[i].clone();
            p.landed = Some((height, position));
            p.path = None;
            found.push(p);
        }
        if !found.is_empty() {
            let mut wtxn = self.env.write_txn()?;
            for p in &found {
                self.payments.put(&mut wtxn, &digest_to_bytes(&p.txid), &p.to_bytes())?;
            }
            wtxn.commit()?;
        }
        Ok(found)
    }

    /// Keeps the path of payment `txid`'s output, which landed in block
    /// `height` at `position`: checked to lead to `state_root`, that
    /// block's, from the output's leaf.
    pub fn set_payment_path(
        &self,
        txid: &Commitment,
        height: u32,
        position: u64,
        path: crate::state_tree::Proof,
        state_root: &Digest,
    ) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let b = self.payments.get(&wtxn, &digest_to_bytes(txid))?.ok_or(WalletError::Unknown)?;
        let mut p = Payment::from_bytes(*txid, b).ok_or(WalletError::Corrupt("payment"))?;
        let o = &p.output;
        let leaf = crate::transaction::output_leaf(&o.commitment, &o.memo, o.amount, height);
        if p.landed != Some((height, position)) || !path.verify(state_root, position, &leaf) {
            return Err(WalletError::Corrupt("payment path"));
        }
        p.path = Some(path);
        self.payments.put(&mut wtxn, &digest_to_bytes(txid), &p.to_bytes())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Burns `amount` for `beneficiary` with `purpose` (`docs/PROOFS.md`):
    /// a transaction of this wallet's paying an output to the key hash
    /// zero, which nobody can spend, whose memo names the beneficiary. The
    /// burn is recorded for its proof like a payment.
    pub fn burn(
        &self,
        amount: u64,
        beneficiary: &Digest,
        purpose: &[u8],
        fee: Option<u64>,
        utxo: &UtxoSet,
        rtxn: &RoTxn,
    ) -> Result<Signed> {
        if purpose.len() > crate::proofs::MAX_PURPOSE {
            return Err(WalletError::BadSlate("the purpose is longer than 255 bytes"));
        }
        let dust = Policy::MAINNET.dust;
        if amount < dust {
            return Err(WalletError::BadSlate("amount is below the dust limit"));
        }
        let burn = Burn { beneficiary: *beneficiary, nonce: random_bytes::<32>()?, purpose: purpose.to_vec() };
        let burned = burn.output(amount);
        let coins = self.spendable(utxo, rtxn)?;
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
        let (fee, mut outputs, change) = if change_amount >= dust {
            let out = self.receive(change_amount)?;
            (fee, vec![out], Some(out.commitment))
        } else {
            (fee + change_amount, vec![], None)
        };
        outputs.push(burned);
        let inputs: Vec<(PublicKey, u64)> =
            picked.iter().map(|c| (self.key(&c.nonce).public_key(), c.amount)).collect();
        let commitments: Vec<Commitment> = picked.iter().map(|c| c.commitment).collect();
        let mut wtxn = self.env.write_txn()?;
        let signed = match self.sign(&mut wtxn, UnsignedTransaction::new(inputs, outputs), &commitments) {
            Ok(s) => s,
            Err(e) => {
                drop(wtxn);
                if let Some(c) = change {
                    self.forget(&c)?;
                }
                return Err(e);
            }
        };
        let created = unix_now();
        let sent = Sent {
            txid: signed.tx.txid(),
            inputs: commitments,
            fee,
            size: signed.tx.size(),
            created,
            tx: signed.tx.clone(),
        };
        self.sent.put(&mut wtxn, &digest_to_bytes(&sent.txid), &sent.to_bytes())?;
        let payment =
            Payment { txid: sent.txid, output: burned, claim: Claim::Burn(burn), created, landed: None, path: None };
        self.payments.put(&mut wtxn, &digest_to_bytes(&payment.txid), &payment.to_bytes())?;
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
        Record::new(name, self.owner_hash(nonce), *value, self.name_memo(nonce))
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
        Ok(NameOp::Commit { commit, memo: self.memo(&nonce) })
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

    /// Undoes what [`Wallet::name_commit`], [`Wallet::name_reveal`],
    /// [`Wallet::name_update`] or [`Wallet::name_transfer`] recorded, when
    /// no transaction could carry the operation (too few funds, say): a
    /// commit is forgotten, a revealed name goes back to its commit, an
    /// update or transfer is no longer signed. A signing leaf an update used
    /// stays used: the signature was made, and a leaf signs once.
    pub fn undo_name_op(&self, op: &NameOp) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        match op {
            NameOp::Commit { commit, .. } => {
                self.commits.delete(&mut wtxn, &digest_to_bytes(commit))?;
            }
            NameOp::Reveal { record, .. } => {
                if let Some(entry) = self.name_in(&wtxn, &record.name)?.filter(|n| n.stage == NameStage::Revealed) {
                    let commit = self.commit_of(&entry.name, &entry.nonce).ok_or(WalletError::Corrupt("name"))?;
                    let back = PendingCommit {
                        commit,
                        nonce: entry.nonce,
                        name: Some(entry.name.clone()),
                        value: entry.value,
                        created: entry.created,
                        recovered: entry.recovered,
                    };
                    self.put_commit(&mut wtxn, &back)?;
                    self.names.delete(&mut wtxn, &record.name)?;
                }
            }
            NameOp::Update { record, .. } => {
                if let Some(mut entry) = self.name_in(&wtxn, &record.name)? {
                    entry.pending = None;
                    entry.transferring = false;
                    self.put_name(&mut wtxn, &entry)?;
                }
            }
        }
        wtxn.commit()?;
        Ok(())
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
    /// key is dropped. A reveal or rotation the wallet cancelled but that
    /// landed anyway is adopted from the record's memo. Returns how many
    /// entries changed.
    pub fn sync_names(&self, registry: &NameSet, rtxn: &RoTxn) -> Result<usize> {
        let mut changed = 0;
        let mut wtxn = self.env.write_txn()?;
        // A pending commit whose reveal landed after all.
        for c in self.pending_commits()? {
            let Some(name) = &c.name else { continue };
            let Some(record) = registry.lookup(rtxn, name).map_err(|e| WalletError::Name(e.to_string()))? else {
                continue;
            };
            if record.owner == self.owner_hash(&c.nonce) && self.name_in(&wtxn, name)?.is_none() {
                let entry = OwnedName {
                    name: name.clone(),
                    nonce: c.nonce,
                    value: record.value,
                    created: c.created,
                    stage: NameStage::Owned,
                    recovered: c.recovered,
                    start: if c.recovered { random_bytes::<1>()?[0] % LEAVES_PER_HALF as u8 } else { 0 },
                    used: 0,
                    pending: None,
                    transferring: false,
                };
                self.put_name(&mut wtxn, &entry)?;
                self.commits.delete(&mut wtxn, &digest_to_bytes(&c.commit))?;
                changed += 1;
            }
        }
        for mut entry in self.owned_names()? {
            let Some(record) = registry.lookup(rtxn, &entry.name).map_err(|e| WalletError::Name(e.to_string()))? else {
                continue;
            };
            let mine = record.owner == self.owner_hash(&entry.nonce);
            let mut rotated = entry.pending.as_ref().is_some_and(|(n, _)| record.owner == self.owner_hash(n));
            if !mine && !rotated && !entry.transferring {
                // A rotation whose pending entry a cancel dropped.
                if let Some(n) = self.open_name_memo(&record.memo).filter(|n| record.owner == self.owner_hash(n)) {
                    entry.pending = Some((n, record.value));
                    rotated = true;
                }
            }
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
            let Some(nonce) = self.open_name_memo(&record.memo) else {
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
            let Some(nonce) = self.open_name_memo(&utxo.slot(rtxn, position)?) else {
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
        let size = 16 + inputs * INPUT_SIZE + OUTPUT_SIZE + ops.iter().map(NameOp::size).sum::<usize>();
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
        let sent = Sent {
            txid: signed.tx.txid(),
            inputs: commitments,
            fee,
            size: signed.tx.size(),
            created: unix_now(),
            tx: signed.tx.clone(),
        };
        self.sent.put(&mut wtxn, &digest_to_bytes(&sent.txid), &sent.to_bytes())?;
        wtxn.commit()?;
        Ok(signed)
    }

    // ---------------------------------------------------------------------
    // Policies: multisig, HTLCs, channels (docs/ELTOO.md)
    // ---------------------------------------------------------------------

    /// A channel key: an XMSS key of `height` levels (1 to 20) derived from
    /// the seed by `nonce`, for thresholds in policies. Building one costs
    /// `2^height` leaves (about a second per 2^16 per core), so callers
    /// make tall keys off the prompt thread.
    pub fn channel_key(&self, nonce: &[Fp; NONCE], height: usize) -> Key {
        let seed: [u8; SEED_SIZE] = digest_to_bytes(&self.with_master(DOM_CHANNEL, nonce));
        Key::generate_with_height(&seed, height)
    }

    /// The hash of a channel key: what a policy lists.
    pub fn channel_key_hash(&self, nonce: &[Fp; NONCE], height: usize) -> Commitment {
        pubkey_hash(&self.channel_key(nonce, height).public_key())
    }

    /// A fresh nonce for a channel key.
    pub fn fresh_nonce() -> Result<[Fp; NONCE]> {
        Ok([random_fp()?, random_fp()?, random_fp()?, random_fp()?])
    }

    fn record_policy(&self, wtxn: &mut RwTxn, p: &PolicyOutput) -> Result<()> {
        self.policies.put(wtxn, &digest_to_bytes(&p.commitment), &p.to_bytes())?;
        Ok(())
    }

    fn policy_in(&self, rtxn: &RoTxn, c: &Commitment) -> Result<Option<PolicyOutput>> {
        match self.policies.get(rtxn, &digest_to_bytes(c))? {
            None => Ok(None),
            Some(b) => PolicyOutput::from_bytes(*c, b).map(Some).ok_or(WalletError::Corrupt("policy output")),
        }
    }

    /// Tracks an output under `policy` paying `amount` with `memo` that this
    /// wallet is party to with `keys` (its keys among the policy's), so it
    /// can sign spends of it. Returns the output, for a funding transaction
    /// ([`Wallet::fund`]) or another policy spend's outputs.
    pub fn track_policy(&self, policy: &SpendPolicy, amount: u64, memo: Memo, keys: Vec<PolicyKey>) -> Result<Output> {
        if !policy.valid() {
            return Err(WalletError::Policy("malformed policy"));
        }
        let out = policy.output(amount, memo);
        let p = PolicyOutput {
            commitment: out.commitment,
            policy: policy.clone(),
            amount,
            memo,
            state: State::Unspent,
            created: unix_now(),
            position: None,
            keys,
        };
        let mut wtxn = self.env.write_txn()?;
        self.record_policy(&mut wtxn, &p)?;
        wtxn.commit()?;
        Ok(out)
    }

    pub fn policy_output(&self, c: &Commitment) -> Result<Option<PolicyOutput>> {
        let rtxn = self.env.read_txn()?;
        self.policy_in(&rtxn, c)
    }

    /// Every tracked policy output, oldest first.
    pub fn policy_outputs(&self) -> Result<Vec<PolicyOutput>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.policies.iter(&rtxn)? {
            let (k, v) = item?;
            let c = crate::poseidon2::digest_from_bytes(k).ok_or(WalletError::Corrupt("policy key"))?;
            out.push(PolicyOutput::from_bytes(c, v).ok_or(WalletError::Corrupt("policy output"))?);
        }
        out.sort_by_key(|p| p.created);
        Ok(out)
    }

    /// The smallest fee a transaction paying `outputs` from `inputs` inputs
    /// with change may carry.
    pub fn min_fund_fee(inputs: usize, outputs: usize) -> u64 {
        Policy::MAINNET.min_fee(inputs, outputs + 1)
    }

    /// Pays `outputs` (a channel's funding output, say) from this wallet's
    /// confirmed outputs with `fee` (or the smallest the pool takes), change
    /// to a fresh output; the outputs are tracked by whoever owns them.
    pub fn fund(&self, outputs: Vec<Output>, fee: Option<u64>, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Signed> {
        if outputs.is_empty() || outputs.iter().any(|o| o.amount == 0) {
            return Err(WalletError::BadSlate("nothing to fund"));
        }
        let amount: u128 = outputs.iter().map(|o| o.amount as u128).sum();
        let dust = Policy::MAINNET.dust;
        let coins = self.spendable(utxo, rtxn)?;
        let mut inputs = 1;
        let given = fee;
        let fee = loop {
            let fee = given.unwrap_or_else(|| Self::min_fund_fee(inputs, outputs.len()));
            let need = amount + fee as u128;
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
            let min = Self::min_fund_fee(picked.max(1), outputs.len());
            if given.is_some() && fee < min {
                return Err(WalletError::FeeTooLow { min });
            }
            if picked <= inputs {
                break fee;
            }
            inputs = picked;
        };
        let need = amount + fee as u128;
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
        let mut outputs = outputs;
        let (fee, change) = if change_amount >= dust {
            let out = self.receive(change_amount)?;
            outputs.push(out);
            (fee, Some(out.commitment))
        } else {
            (fee + change_amount, None)
        };
        let inputs: Vec<(PublicKey, u64)> =
            picked.iter().map(|c| (self.key(&c.nonce).public_key(), c.amount)).collect();
        let commitments: Vec<Commitment> = picked.iter().map(|c| c.commitment).collect();
        let mut wtxn = self.env.write_txn()?;
        let signed = match self.sign(&mut wtxn, UnsignedTransaction::new(inputs, outputs), &commitments) {
            Ok(s) => s,
            Err(e) => {
                drop(wtxn);
                if let Some(c) = change {
                    self.forget(&c)?;
                }
                return Err(e);
            }
        };
        let sent = Sent {
            txid: signed.tx.txid(),
            inputs: commitments,
            fee,
            size: signed.tx.size(),
            created: unix_now(),
            tx: signed.tx.clone(),
        };
        self.sent.put(&mut wtxn, &digest_to_bytes(&sent.txid), &sent.to_bytes())?;
        wtxn.commit()?;
        Ok(signed)
    }

    /// A spend of the tracked policy output `c` through its leaf `leaf`
    /// into `outputs`, with the state number and covered run a channel
    /// update or settlement names (zero and empty otherwise). The spend
    /// carries no signatures yet: each party signs with
    /// [`Wallet::sign_policy`] in turn, passing the transaction's bytes
    /// along; a hash lock's preimage goes into its witness directly.
    pub fn policy_spend(
        &self,
        c: &Commitment,
        leaf: usize,
        outputs: Vec<Output>,
        state: u32,
        covered: (u8, u8),
    ) -> Result<Transaction> {
        let p = self.policy_output(c)?.ok_or(WalletError::Unknown)?;
        let position = p.position.ok_or(WalletError::Unconfirmed)?;
        if leaf >= p.policy.leaves.len() {
            return Err(WalletError::Policy("no such leaf"));
        }
        let mut spend = p.policy.spend(leaf, p.amount, position);
        spend.state = state;
        spend.covered = covered;
        let tx = UnsignedTransaction::new(vec![], outputs)
            .with_policy_inputs(vec![spend])
            .sign(|_, _, _| Err::<crate::transaction::Sig, WalletError>(WalletError::Unknown))?;
        Ok(tx)
    }

    /// Signs the policy spend `tx` with every key of this wallet the leaf's
    /// thresholds list that has not signed yet: over the body hash, or for
    /// a rebindable threshold the rebindable message with leaf index equal
    /// to the state number. Returns how many signatures were added. The
    /// leaves used are recorded; a rebindable key never signs a state it
    /// has passed.
    pub fn sign_policy(&self, tx: &mut Transaction) -> Result<usize> {
        let Some(input) = tx.policy_inputs.first() else {
            return Err(WalletError::Policy("no policy input"));
        };
        let c = input.commitment();
        let mut p = self.policy_output(&c)?.ok_or(WalletError::Unknown)?;
        let body = tx.body_hash();
        let covered = input.covered_outputs(&tx.outputs).ok_or(WalletError::Policy("covered run past the outputs"))?;
        let state = input.state;
        let leaf = input.leaf.clone();
        let mut added = 0;
        let mut witness = input.witness.clone();
        for (k, cond) in leaf.conds.iter().enumerate() {
            let Cond::Thresh { mode, keys, .. } = cond else { continue };
            let CondWitness::Signatures(signers) = &mut witness[k] else {
                return Err(WalletError::Policy("witness does not fit the threshold"));
            };
            for key in p.keys.iter_mut() {
                let idx = key.index as usize;
                if idx >= keys.len() || signers.iter().any(|s| s.key == key.index) {
                    continue;
                }
                let mut sk = self.channel_key(&key.nonce, key.height as usize);
                if pubkey_hash(&sk.public_key()) != keys[idx] {
                    continue;
                }
                let (msg, index) = match mode {
                    Mode::Body => (body, key.used as u64),
                    Mode::Rebindable { channel } => (rebind_message(channel, state, &covered), state as u64),
                };
                if index < key.used as u64 && matches!(mode, Mode::Rebindable { .. }) {
                    return Err(WalletError::Policy("this key has signed a later state"));
                }
                if index >= sk.leaves() {
                    return Err(WalletError::Exhausted);
                }
                sk.set_next_index(index);
                let signature = sk.sign(&msg).map_err(|_| WalletError::Exhausted)?;
                key.used = (index + 1) as u32;
                signers.push(Signer { key: key.index, pubkey: sk.public_key(), signature });
                added += 1;
            }
            signers.sort_by_key(|s| s.key);
        }
        if added > 0 {
            tx.policy_inputs[0].witness = witness;
            let mut wtxn = self.env.write_txn()?;
            self.record_policy(&mut wtxn, &p)?;
            wtxn.commit()?;
        }
        Ok(added)
    }

    /// Records a policy spend this wallet published: the policy output is
    /// spent and the transaction is remembered as sent.
    pub fn policy_sent(&self, tx: &Transaction) -> Result<()> {
        let Some(input) = tx.policy_inputs.first() else {
            return Err(WalletError::Policy("no policy input"));
        };
        let c = input.commitment();
        let mut p = self.policy_output(&c)?.ok_or(WalletError::Unknown)?;
        p.state = State::Spent;
        let fee = tx.balance().max(0) as u64;
        let mut wtxn = self.env.write_txn()?;
        self.record_policy(&mut wtxn, &p)?;
        let sent = Sent { txid: tx.txid(), inputs: vec![c], fee, size: tx.size(), created: unix_now(), tx: tx.clone() };
        self.sent.put(&mut wtxn, &digest_to_bytes(&sent.txid), &sent.to_bytes())?;
        wtxn.commit()?;
        Ok(())
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
        u.add_outputs(&mut wtxn, &outs, 0).unwrap();
        wtxn.commit().unwrap();
        wallet.locate(first, &outs).unwrap();
    }

    /// Two wallets run an eltoo channel through the policy API: funding,
    /// an update signed by both with rebindable signatures, a cooperative
    /// close, a covenant settlement after the delay, and a three-party
    /// factory settling into channel outputs; a 2-of-3 multisig too.
    #[test]
    fn channels_and_multisig_through_the_policy_api() {
        use crate::policy::{Cond, Leaf, Mode, Policy as SpendPolicy, PolicyError};
        let dir = TempDir::new("channel");
        let (env, u) = utxo(&dir);
        let (a, _) = Wallet::open(&dir.0.join("a")).unwrap();
        let (b, _) = Wallet::open(&dir.0.join("b")).unwrap();
        let (c, _) = Wallet::open(&dir.0.join("c")).unwrap();
        const H: usize = 6;
        let d = |x: u32| {
            let mut v = [Fp::ZERO; DIGEST];
            v[0] = Fp::new(x);
            v
        };
        let land_all = |outs: &[&Output], wallets: &[&Wallet]| {
            let mut wtxn = env.write_txn().unwrap();
            let first = u.next_position(&wtxn).unwrap();
            let outs: Vec<_> = outs.iter().map(|o| o.block_output()).collect();
            u.add_outputs(&mut wtxn, &outs, 0).unwrap();
            wtxn.commit().unwrap();
            for w in wallets {
                w.locate(first, &outs).unwrap();
            }
        };
        let coin = a.receive(10_000).unwrap();
        land_all(&[&coin], &[&a]);

        // Channel keys and the state policy shape.
        let (na, nb, nc) =
            (Wallet::fresh_nonce().unwrap(), Wallet::fresh_nonce().unwrap(), Wallet::fresh_nonce().unwrap());
        let (ka, kb, kc) = (a.channel_key_hash(&na, H), b.channel_key_hash(&nb, H), c.channel_key_hash(&nc, H));
        let key_a = || PolicyKey { index: 0, nonce: na, height: H as u8, used: 0 };
        let key_b = || PolicyKey { index: 1, nonce: nb, height: H as u8, used: 0 };
        let channel = d(1);
        let state_policy = |n: u32, settle: &[Output]| {
            let pairs: Vec<(Commitment, Digest)> = settle.iter().map(|o| (o.commitment, o.slot())).collect();
            SpendPolicy::new(vec![
                Leaf::new(vec![
                    Cond::Thresh { mode: Mode::Rebindable { channel }, m: 2, keys: vec![ka, kb] },
                    Cond::State(n),
                ]),
                Leaf::new(vec![Cond::Older(10), Cond::Outputs(pairs)]),
                Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 2, keys: vec![ka, kb] }]),
            ])
        };

        // Open: A funds 5000; state 0 refunds A.
        let refund0 = a.receive(5000).unwrap();
        let p0 = state_policy(0, &[refund0]);
        let funding = a.track_policy(&p0, 5000, crate::transaction::memo5(d(50)), vec![key_a()]).unwrap();
        assert_eq!(b.track_policy(&p0, 5000, crate::transaction::memo5(d(50)), vec![key_b()]).unwrap(), funding);
        let signed = {
            let rtxn = env.read_txn().unwrap();
            a.fund(vec![funding], None, &u, &rtxn).unwrap()
        };
        assert_eq!(signed.tx.outputs[0], funding);
        assert_eq!(signed.tx.inputs.len(), 1);
        assert!(signed.tx.verify_signatures());
        let outs: Vec<&Output> = signed.tx.outputs.iter().collect();
        land_all(&outs, &[&a, &b]);
        assert_eq!(a.policy_output(&funding.commitment).unwrap().unwrap().position, Some(1));
        assert_eq!(b.policy_output(&funding.commitment).unwrap().unwrap().position, Some(1));
        assert_eq!(a.policy_outputs().unwrap().len(), 1);

        // Update to state 1: B is paid 2000. B proposes and signs, A signs.
        let refund1 = a.receive(3000).unwrap();
        let pay1 = b.receive(2000).unwrap();
        let p1 = state_policy(1, &[refund1, pay1]);
        let state1 = a.track_policy(&p1, 5000, crate::transaction::memo5(d(51)), vec![key_a()]).unwrap();
        b.track_policy(&p1, 5000, crate::transaction::memo5(d(51)), vec![key_b()]).unwrap();
        let mut update = b.policy_spend(&funding.commitment, 0, vec![state1], 1, (0, 1)).unwrap();
        assert_eq!(b.sign_policy(&mut update).unwrap(), 1);
        assert_eq!(update.check_policy_inputs(1, |_| Some(0)), Err(PolicyError::Signatures));
        let mut update = Transaction::from_bytes(&update.to_bytes()).unwrap();
        assert_eq!(a.sign_policy(&mut update).unwrap(), 1);
        assert_eq!(a.sign_policy(&mut update).unwrap(), 0, "already signed");
        assert_eq!(update.check_policy_inputs(1, |_| Some(0)), Ok(()));
        assert_eq!(update.weight(), 2);
        // Having signed state 1, B's key will not sign state 1 (or 0) again.
        let mut stale = b.policy_spend(&funding.commitment, 0, vec![state1], 1, (0, 1)).unwrap();
        assert!(matches!(b.sign_policy(&mut stale), Err(WalletError::Policy(_))));

        // Cooperative close of the funding output straight to final outputs.
        let (fa, fb) = (a.receive(2990).unwrap(), b.receive(2000).unwrap());
        let mut close = a.policy_spend(&funding.commitment, 2, vec![fa, fb], 0, (0, 0)).unwrap();
        assert_eq!(a.sign_policy(&mut close).unwrap(), 1);
        assert_eq!(b.sign_policy(&mut close).unwrap(), 1);
        assert_eq!(close.check_policy_inputs(1, |_| Some(0)), Ok(()));
        assert_eq!(close.balance(), 10);

        // Unilateral: the update lands; after the delay anyone settles into
        // the covenant's outputs, no signature needed.
        land_all(&[&state1], &[&a, &b]);
        let created = u64::from(a.policy_output(&state1.commitment).unwrap().unwrap().position.is_some());
        assert_eq!(created, 1);
        let settle = b.policy_spend(&state1.commitment, 1, vec![refund1, pay1], 0, (0, 2)).unwrap();
        assert_eq!(settle.policy_inputs[0].signatures(), 0);
        assert_eq!(settle.check_policy_inputs(9, |_| Some(0)), Err(PolicyError::Locked));
        assert_eq!(settle.check_policy_inputs(10, |_| Some(0)), Ok(()));
        b.policy_sent(&settle).unwrap();
        assert_eq!(b.policy_output(&state1.commitment).unwrap().unwrap().state, State::Spent);
        // A wrong covered run is refused by the check.
        let wrong = b.policy_spend(&state1.commitment, 1, vec![pay1, refund1], 0, (0, 2)).unwrap();
        assert_eq!(wrong.check_policy_inputs(10, |_| Some(0)), Err(PolicyError::Covenant));

        // A factory of A, B and C settling into two channel outputs (A with
        // B, A with C), 3-of-3 to update.
        let chan_ab = state_policy(0, &[refund0]).output(3000, crate::transaction::memo5(d(60)));
        let chan_ac =
            SpendPolicy::new(vec![Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 2, keys: vec![ka, kc] }])])
                .output(2000, crate::transaction::memo5(d(61)));
        let factory = SpendPolicy::new(vec![
            Leaf::new(vec![
                Cond::Thresh { mode: Mode::Rebindable { channel: d(2) }, m: 3, keys: vec![ka, kb, kc] },
                Cond::State(0),
            ]),
            Leaf::new(vec![
                Cond::Older(10),
                Cond::Outputs(vec![(chan_ab.commitment, chan_ab.slot()), (chan_ac.commitment, chan_ac.slot())]),
            ]),
            Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 3, keys: vec![ka, kb, kc] }]),
        ]);
        let fout = a.track_policy(&factory, 5000, crate::transaction::memo5(d(70)), vec![key_a()]).unwrap();
        b.track_policy(&factory, 5000, crate::transaction::memo5(d(70)), vec![key_b()]).unwrap();
        c.track_policy(
            &factory,
            5000,
            crate::transaction::memo5(d(70)),
            vec![PolicyKey { index: 2, nonce: nc, height: H as u8, used: 0 }],
        )
        .unwrap();
        land_all(&[&fout], &[&a, &b, &c]);
        let mut regroup = a.policy_spend(&fout.commitment, 2, vec![chan_ab, chan_ac], 0, (0, 0)).unwrap();
        for w in [&a, &b, &c] {
            assert_eq!(w.sign_policy(&mut regroup).unwrap(), 1);
        }
        assert_eq!(regroup.check_policy_inputs(1, |_| Some(0)), Ok(()));
        assert_eq!(regroup.weight(), 3);
        let settle_f = c.policy_spend(&fout.commitment, 1, vec![chan_ab, chan_ac], 0, (0, 2)).unwrap();
        assert_eq!(settle_f.check_policy_inputs(10, |_| Some(0)), Ok(()));

        // A 2-of-3 multisig, A and C signing.
        let multisig =
            SpendPolicy::new(vec![Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 2, keys: vec![ka, kb, kc] }])]);
        let mout = a.track_policy(&multisig, 1000, crate::transaction::memo5(d(80)), vec![key_a()]).unwrap();
        c.track_policy(
            &multisig,
            1000,
            crate::transaction::memo5(d(80)),
            vec![PolicyKey { index: 2, nonce: nc, height: H as u8, used: 0 }],
        )
        .unwrap();
        land_all(&[&mout], &[&a, &c]);
        let mut spend = c.policy_spend(&mout.commitment, 0, vec![c.receive(990).unwrap()], 0, (0, 0)).unwrap();
        assert_eq!(c.sign_policy(&mut spend).unwrap(), 1);
        assert_eq!(a.sign_policy(&mut spend).unwrap(), 1);
        assert_eq!(spend.check_policy_inputs(1, |_| Some(0)), Ok(()));
        // Reopened wallets keep their policy outputs.
        drop(a);
        let (a, _) = Wallet::open(&dir.0.join("a")).unwrap();
        assert_eq!(a.policy_outputs().unwrap().len(), 4);
    }

    #[test]
    fn rewards_of_blocks_that_lose_are_forgotten() {
        let dir = TempDir::new("rewards");
        let (env, u) = utxo(&dir);
        let (w, _) = Wallet::open(&dir.0.join("wallet")).unwrap();
        let reward = |height: u32, hash: Option<u8>| {
            let o = w.receive(1_000).unwrap();
            w.note_reward(&o.commitment, height).unwrap();
            if let Some(h) = hash {
                w.reward_found(&o.commitment, &[h; 32]).unwrap();
            }
            o
        };
        let never_found = reward(5, None).commitment;
        let unknown = reward(6, Some(1)).commitment;
        let side = reward(7, Some(2)).commitment;
        let mining = reward(9, None).commitment;
        let o = reward(8, Some(3));
        let main = o.commitment;
        land(&env, &u, &w, &[&o]);
        let known = |h: &[u8; 32]| h[0] != 1;
        let prune = |tip| {
            let rtxn = env.read_txn().unwrap();
            w.prune_rewards(&u, &rtxn, tip, 100, known, Some(mining)).unwrap()
        };
        let have = |c: &Commitment| w.owned(c).unwrap().is_some();
        assert_eq!(prune(10), 2);
        assert!(!have(&never_found) && !have(&unknown));
        assert!(have(&side) && have(&main) && have(&mining));
        // Past the reorganization depth the side block's reward goes; the
        // landed one stays, no longer tracked.
        assert_eq!(prune(107), 1);
        assert!(!have(&side) && have(&main) && have(&mining));
        assert_eq!(prune(108), 0);
        let rtxn = w.env.read_txn().unwrap();
        assert!(w.rewards.get(&rtxn, &digest_to_bytes(&main)).unwrap().is_none());
        assert!(w.rewards.get(&rtxn, &digest_to_bytes(&mining)).unwrap().is_some());
    }

    #[test]
    fn a_password_locks_the_secret() {
        let dir = TempDir::new("password");
        let path = dir.0.join("wallet");
        let (w, created) = Wallet::open_with(&path, &mut |a| {
            assert_eq!(a, Ask::New);
            Ok("hunter2".into())
        })
        .unwrap();
        let phrase = created.unwrap();
        let master = w.master;
        assert!(w.locked().unwrap());
        assert_eq!(w.phrase("hunter2").unwrap(), phrase);
        assert!(matches!(w.phrase(""), Err(WalletError::WrongPassword)));
        // The record holds neither the entropy nor the seed in the clear.
        let record = w.secret_record().unwrap();
        let entropy = bip39::entropy(&phrase).unwrap();
        assert!(!record.windows(entropy.len()).any(|x| x == entropy));
        drop(w);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o700);
        }
        assert!(matches!(Wallet::open(&path), Err(WalletError::WrongPassword)));
        let (w, created) = Wallet::open_with(&path, &mut |a| {
            assert_eq!(a, Ask::Unlock);
            Ok("hunter2".into())
        })
        .unwrap();
        assert!(created.is_none());
        assert_eq!(w.master, master);
        // Changing it needs the old one; removing it leaves a plain record.
        assert!(matches!(w.set_password("wrong", "x"), Err(WalletError::WrongPassword)));
        w.set_password("hunter2", "").unwrap();
        assert!(!w.locked().unwrap());
        drop(w);
        let (w, _) = Wallet::open(&path).unwrap();
        assert_eq!(w.master, master);
        // A restore can be locked too.
        let r = Wallet::restore(&dir.0.join("restored"), &phrase, "", "pw").unwrap();
        assert!(r.locked().unwrap());
        assert_eq!(r.master, master);
    }

    #[test]
    fn phrase_memos_and_persistence() {
        let dir = TempDir::new("basic");
        let (env, u) = utxo(&dir);
        let (phrase, a_commitment) = {
            let (w, created) = Wallet::open(&dir.0.join("wallet")).unwrap();
            let phrase = created.expect("a new wallet has a phrase");
            assert_eq!(phrase.split(' ').count(), 12);
            assert_eq!(w.phrase("").unwrap(), phrase);
            let a = w.receive(100).unwrap();
            let b = w.receive(u64::MAX).unwrap();
            assert_ne!(a.memo, b.memo);
            assert_eq!(w.open_memo(&a.memo), Some(a.memo[..4].try_into().unwrap()));
            assert!(w.open_memo(&b.memo).is_some());
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
        assert_eq!(w.phrase("").unwrap(), phrase);
        assert_eq!(w.outputs().unwrap().len(), 2);
        // Another wallet cannot read the memo.
        let (other, _) = Wallet::open(&dir.0.join("other")).unwrap();
        let o = w.owned(&a_commitment).unwrap().unwrap();
        assert!(other.open_memo(&w.memo(&o.nonce)).is_none());
        // The identity comes from the phrase and the address counter:
        // another wallet has a different one, the next address another,
        // and a restore starts from a fresh one, never an old one.
        let address = w.address();
        assert_eq!(address.len(), address::LEN);
        assert_eq!(address::decode(&address), Some(w.id()));
        assert_ne!(other.address(), address);
        let restored = Wallet::restore(&dir.0.join("restored"), &phrase, "", "").unwrap();
        assert_ne!(restored.address(), address);
        // The relay's key: from the phrase too, but not the wallet's.
        let relay = address::id_of(w.relay_key().public_key());
        assert_ne!(relay, w.id());
        assert_eq!(address::id_of(restored.relay_key().public_key()), relay);
        let key = w.identity_key();
        assert_eq!(address::id_of(key.public_key()), w.id());
        assert!(mldsa::verify(key.public_key(), b"hello", b"", &key.sign(b"hello", b"")));
        // The next address; off and on again.
        let first = w.id();
        assert!(!w.address_off());
        w.turn_address_off().unwrap();
        assert!(w.address_off());
        let next = address::id_of(w.next_address().unwrap().public_key());
        assert_ne!(next, first);
        assert_eq!(w.id(), next);
        assert!(!w.address_off());
        w.turn_address_off().unwrap();
        // Announcements: a fresh Kyber key each time, signed under the id.
        let (k1, a1) = w.fresh_announce(1, unix_now() + 60, 9).unwrap();
        let (_, a2) = w.fresh_announce(2, unix_now() + 60, 9).unwrap();
        assert_eq!(a1.id, w.id());
        assert!(a1.verify(unix_now()) && a2.verify(unix_now()));
        assert_ne!(a1.kyber, a2.kyber);
        assert_eq!(k1.public_key(), &a1.kyber[..]);
        assert_eq!(restored.fresh_announce(1, unix_now() + 60, 9).unwrap().1.id, restored.id());
        let rtxn = env.read_txn().unwrap();
        // What is kept, as being in flight, is not pruned.
        let b_commitment = w.outputs().unwrap().into_iter().find(|o| o.commitment != a_commitment).unwrap().commitment;
        assert_eq!(w.prune_pending(&u, &rtxn, &HashSet::from([b_commitment])).unwrap(), 0);
        assert_eq!(w.prune_pending(&u, &rtxn, &HashSet::new()).unwrap(), 1);
        assert_eq!(w.outputs().unwrap().len(), 1);
        assert!(matches!(Wallet::restore(&dir.0.join("wallet"), &phrase, "", ""), Err(WalletError::Exists)));
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
        let r = Wallet::restore(&dir.0.join("restored"), &phrase, "", "").unwrap();
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
        let wrong = Wallet::restore(&dir.0.join("wrong"), &phrase, "x", "").unwrap();
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
            alice.send(200_000_000, Some(1), false, &u, &rtxn),
            Err(WalletError::Insufficient { have: 110_000_000, need }) if need == 200_000_001
        ));
        assert!(
            matches!(alice.send(70_000_000, Some(fee - 1), false, &u, &rtxn), Err(WalletError::FeeTooLow { min }) if min == fee)
        );
        assert!(matches!(alice.send(DUST - 1, None, false, &u, &rtxn), Err(WalletError::BadSlate(_))));
        // Without a fee given, the smallest one for the inputs it takes.
        assert_eq!(alice.send(70_000_000, None, false, &u, &rtxn).unwrap().fee, fee);
        for (id, _) in alice.pending_slates().unwrap() {
            alice.cancel_slate(&id).unwrap();
        }
        let slate = alice.send(70_000_000, Some(fee), false, &u, &rtxn).unwrap();
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
        spoiled.outputs[0].memo[4] = spoiled.outputs[0].memo[4].add(&Fp::ONE);
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
        // Kept as signed, to send again.
        assert_eq!(alice.resend(&tx.txid()).unwrap(), tx);
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
        assert!(matches!(alice.cancel_sent(&tx.txid(), Some(min - 1), &u, &rtxn), Err(WalletError::FeeTooLow { .. })));
        let replaced = alice.cancel_sent(&tx.txid(), None, &u, &rtxn).unwrap().tx;
        assert!(replaced.verify_signatures());
        assert_eq!(replaced.spent_commitments(), tx.spent_commitments());
        assert_eq!(replaced.spent_positions(), tx.spent_positions());
        assert_eq!(replaced.balance() as u64, min);
        assert_eq!(replaced.inputs[0].signature.index, 1);
        assert!(matches!(alice.cancel_sent(&tx.txid(), None, &u, &rtxn), Err(WalletError::Unknown)));
        // It can be cancelled again until the leaves run out: 8 signatures
        // in all, the last one flagged.
        let mut id = replaced.txid();
        for n in 2..8 {
            let s = alice.cancel_sent(&id, Some(min * n), &u, &rtxn).unwrap();
            assert_eq!(s.last_signatures.len(), if n == 7 { 2 } else { 0 });
            id = s.tx.txid();
        }
        assert!(matches!(alice.cancel_sent(&id, Some(min * 9), &u, &rtxn), Err(WalletError::Exhausted)));

        // Cancelling a slate frees its inputs.
        drop(rtxn);
        let a3 = alice.receive(9_000_000).unwrap();
        land(&env, &u, &alice, &[&a3]);
        let rtxn = env.read_txn().unwrap();
        let s2 = alice.send(4_000_000, None, false, &u, &rtxn).unwrap();
        assert_eq!(alice.balance(&u, &rtxn).unwrap().reserved, 9_000_000);
        alice.cancel_slate(&s2.id).unwrap();
        assert_eq!(alice.balance(&u, &rtxn).unwrap().reserved, 0);
        assert!(matches!(alice.cancel_slate(&s2.id), Err(WalletError::Unknown)));
        assert_eq!(digest_from_hex(&s2.id_hex()), Some(s2.id));
    }

    /// A name operation no transaction could carry (no funds) is undone, so
    /// it can be tried again; a commit that never reached the chain is
    /// pruned.
    #[test]
    fn name_operations_without_funds_are_undone() {
        use crate::names::NameSet;
        let dir = TempDir::new("names-undo");
        let (env, u) = utxo(&dir);
        let registry = {
            let mut wtxn = env.write_txn().unwrap();
            let n = NameSet::open(&env, &mut wtxn, "n").unwrap();
            wtxn.commit().unwrap();
            n
        };
        let (w, _) = Wallet::open(&dir.0.join("w")).unwrap();
        let op = w.name_commit(b"bob", w.id()).unwrap();
        let rtxn = env.read_txn().unwrap();
        assert!(matches!(w.carry(vec![op.clone()], None, &u, &rtxn), Err(WalletError::Insufficient { .. })));
        drop(rtxn);
        // Without the undo, the commit stays and a retry is refused.
        assert!(w.name_commit(b"bob", w.id()).is_err());
        w.undo_name_op(&op).unwrap();
        assert!(w.pending_commits().unwrap().is_empty());
        w.name_commit(b"bob", w.id()).unwrap();
        // A commit carried by nothing: pruned; one in the pool: kept.
        let pooled: HashSet<Commitment> = w.pending_commits().unwrap().iter().map(|c| c.commit).collect();
        let rtxn = env.read_txn().unwrap();
        assert!(w.prune_commits(&registry, &rtxn, &pooled).unwrap().is_empty());
        assert_eq!(w.prune_commits(&registry, &rtxn, &HashSet::new()).unwrap(), vec!["bob".to_string()]);
        assert!(w.pending_commits().unwrap().is_empty());
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
            u.add_outputs(&mut wtxn, &outs, 0).unwrap();
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
        // Cancelled, the reveal goes back to its commit; the original
        // landing anyway is adopted below.
        let rtxn = env.read_txn().unwrap();
        alice.cancel_sent(&signed.tx.txid(), None, &u, &rtxn).unwrap();
        drop(rtxn);
        assert!(alice.owned_name(b"alice").unwrap().is_none());
        assert_eq!(alice.pending_commits().unwrap()[0].commit, *c);
        let (first, outs) = apply(&signed.tx, 13);
        alice.locate(first, &outs).unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(alice.sync_names(&registry, &rtxn).unwrap(), 1);
        let owned = alice.owned_name(b"alice").unwrap().unwrap();
        assert_eq!((owned.stage, owned.value), (NameStage::Owned, value(1)));
        let on_chain = registry.lookup(&rtxn, b"alice").unwrap().unwrap();
        assert_eq!(on_chain.owner, alice.owner_hash(&owned.nonce));
        assert_eq!(alice.open_name_memo(&on_chain.memo), Some(owned.nonce));

        // Update: the key rotates once the chain shows the new owner.
        let (update, last) = alice.name_update(b"alice", value(2)).unwrap();
        assert!(!last);
        assert!(alice.name_update(b"alice", value(3)).is_err());
        assert!(update.verify_owner(&on_chain.owner));
        let signed = alice.carry(vec![update], None, &u, &rtxn).unwrap();
        // Cancelled, the update is no longer pending (its leaf stays used);
        // the original landing anyway is adopted from its memo.
        let replacement = alice.cancel_sent(&signed.tx.txid(), None, &u, &rtxn).unwrap().tx.txid();
        drop(rtxn);
        let entry = alice.owned_name(b"alice").unwrap().unwrap();
        assert!(entry.pending.is_none() && entry.used == 1);
        let (first, outs) = apply(&signed.tx, 14);
        // Its inputs spent on chain, the replacement cannot be cancelled.
        let rtxn = env.read_txn().unwrap();
        assert!(matches!(alice.cancel_sent(&replacement, None, &u, &rtxn), Err(WalletError::Landed)));
        drop(rtxn);
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
        let (_, bob_phrase) = (0, bob.phrase("").unwrap());
        let restored = Wallet::restore(&dir.0.join("bob2"), &bob_phrase, "", "").unwrap();
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
        let alice2 = Wallet::restore(&dir.0.join("alice2"), &phrase.unwrap(), "", "").unwrap();
        assert_eq!(alice2.scan_names(&u, &registry, &rtxn).unwrap(), (0, 0));
    }
}
