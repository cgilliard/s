//! The node's wallet: hierarchical one-time keys and the outputs paid to
//! them, in an LMDB environment of its own under the data directory.
//!
//! Key `i` is generated from `H(master || i)`, and every output the wallet
//! receives goes to a fresh key, so no key ever signs for two outputs. A
//! key's XMSS tree still has [`crate::transaction::TREE_HEIGHT`] worth of
//! leaves; the next leaf of each key is kept here and advanced, and
//! committed, before a signature is produced, so a crash can burn a leaf
//! but never reuse one.
//!
//! An output record carries its key, amount and commitment, and a state:
//! `Unspent`, `Reserved` by a pending slate, or `Spent` by a finalized
//! transaction. Whether an unspent output is confirmed is not stored: it is
//! whether the UTXO set holds its commitment. Nothing on chain reveals
//! amounts or ownership, so this database, not the seed alone, is what a
//! backup must contain.
//!
//! # Slates
//!
//! A payment is negotiated in a [`Slate`] passed between the two wallets as
//! a file. [`Wallet::send`] picks and reserves inputs, adds change to a fresh
//! key and writes the amount and fee; [`Wallet::receive_slate`] adds the
//! recipient's output on a fresh key; [`Wallet::finalize`] checks the
//! balance, signs every input and marks them spent. The transaction then
//! goes to the mempool. [`Wallet::cancel`] releases a slate's inputs.

use std::path::Path;

use heed::byteorder::BigEndian;
use heed::types::{Bytes, Str, U64};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::codec::{Reader, Writer};
use crate::poseidon2::{DIGEST, Fp, digest_from_bytes, digest_to_bytes, hash};
use crate::state_tree::open_env;
use crate::transaction::{Commitment, Key, Output, Transaction, UnsignedTransaction};
use crate::utxo::{self, UtxoSet};
use crate::xmss::{PublicKey, SEED_SIZE};

const META_SEED: &str = "seed";
const META_NEXT_KEY: &str = "next_key";
const MAP_SIZE: usize = 1 << 30;
const SLATE_MAGIC: &[u8; 8] = b"tabslt01";

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
    pub key_index: u64,
    pub amount: u64,
    pub commitment: Commitment,
    pub state: State,
    /// Unix time the record was made.
    pub created: u64,
}

impl Owned {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(8 + 32 + 1 + 8);
        w.u64(self.amount);
        w.digest(&self.commitment);
        w.0.push(self.state.to_u8());
        w.u64(self.created);
        w.finish()
    }

    fn from_bytes(key_index: u64, bytes: &[u8]) -> Option<Owned> {
        let mut r = Reader(bytes);
        let amount = r.u64()?;
        let commitment = r.digest()?;
        let state = State::from_u8(r.take(1)?[0])?;
        let created = r.u64()?;
        r.is_empty().then_some(Owned { key_index, amount, commitment, state, created })
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
        let n = r.len(crate::transaction::OUTPUT_SIZE)?;
        let mut outputs = Vec::with_capacity(n);
        for _ in 0..n {
            outputs.push(Output::from_bytes(r.take(crate::transaction::OUTPUT_SIZE)?)?);
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
        self.id.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// What the sender keeps about a pending slate.
struct Pending {
    inputs: Vec<u64>,
    change: Option<u64>,
}

impl Pending {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u64(self.change.map_or(u64::MAX, |c| c));
        w.u32(self.inputs.len() as u32);
        for i in &self.inputs {
            w.u64(*i);
        }
        w.finish()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Pending> {
        let mut r = Reader(bytes);
        let change = r.u64()?;
        let n = r.len(8)?;
        let inputs = (0..n).map(|_| r.u64()).collect::<Option<Vec<_>>>()?;
        r.is_empty().then_some(Pending { inputs, change: (change != u64::MAX).then_some(change) })
    }
}

#[derive(Debug)]
pub enum WalletError {
    Heed(heed::Error),
    Utxo(utxo::Error),
    Io(std::io::Error),
    Corrupt(&'static str),
    /// Not enough confirmed, unreserved funds.
    Insufficient {
        have: u128,
        need: u128,
    },
    /// The slate is malformed or not at the expected stage.
    BadSlate(&'static str),
    /// No pending slate of this wallet has that id.
    UnknownSlate,
    /// A key ran out of leaves.
    Exhausted,
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletError::Heed(e) => write!(f, "wallet database: {e}"),
            WalletError::Utxo(e) => write!(f, "{e}"),
            WalletError::Io(e) => write!(f, "{e}"),
            WalletError::Corrupt(w) => write!(f, "corrupt wallet record: {w}"),
            WalletError::Insufficient { have, need } => write!(f, "insufficient funds: have {have}, need {need}"),
            WalletError::BadSlate(w) => write!(f, "bad slate: {w}"),
            WalletError::UnknownSlate => f.write_str("no pending slate with that id"),
            WalletError::Exhausted => f.write_str("key has no leaves left"),
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

pub type Result<T> = core::result::Result<T, WalletError>;

pub struct Wallet {
    env: Env,
    master: [u8; 32],
    meta: Database<Str, Bytes>,
    outputs: Database<U64<BigEndian>, Bytes>,
    leaves: Database<U64<BigEndian>, U64<BigEndian>>,
    slates: Database<Bytes, Bytes>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_bytes() -> std::io::Result<[u8; 32]> {
    let mut out = [0u8; 32];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut out)?;
    Ok(out)
}

impl Wallet {
    /// Opens the wallet in `dir`, creating it with a seed from the operating
    /// system if there is none.
    pub fn open(dir: &Path) -> Result<Wallet> {
        let env = open_env(dir, MAP_SIZE).map_err(|e| match e {
            crate::state_tree::Error::Heed(h) => WalletError::Heed(h),
            other => WalletError::Utxo(utxo::Error::Tree(other)),
        })?;
        let mut wtxn = env.write_txn()?;
        let meta: Database<Str, Bytes> = env.create_database(&mut wtxn, Some("meta"))?;
        let outputs = env.create_database(&mut wtxn, Some("outputs"))?;
        let leaves = env.create_database(&mut wtxn, Some("leaves"))?;
        let slates = env.create_database(&mut wtxn, Some("slates"))?;
        let master = match meta.get(&wtxn, META_SEED)? {
            Some(b) => b.try_into().map_err(|_| WalletError::Corrupt("seed"))?,
            None => {
                let seed = random_bytes()?;
                meta.put(&mut wtxn, META_SEED, &seed)?;
                meta.put(&mut wtxn, META_NEXT_KEY, &0u64.to_le_bytes())?;
                seed
            }
        };
        wtxn.commit()?;
        Ok(Wallet { env, master, meta, outputs, leaves, slates })
    }

    /// The master seed, hex encoded. Not enough to recover funds on its own.
    pub fn seed_hex(&self) -> String {
        self.master.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn next_key_in(&self, rtxn: &RoTxn) -> Result<u64> {
        let b = self.meta.get(rtxn, META_NEXT_KEY)?.ok_or(WalletError::Corrupt("next key"))?;
        Ok(u64::from_le_bytes(b.try_into().map_err(|_| WalletError::Corrupt("next key"))?))
    }

    /// Allocates a fresh key index.
    fn fresh_key(&self, wtxn: &mut RwTxn) -> Result<u64> {
        let i = self.next_key_in(wtxn)?;
        self.meta.put(wtxn, META_NEXT_KEY, &(i + 1).to_le_bytes())?;
        Ok(i)
    }

    /// Number of keys generated so far.
    pub fn keys(&self) -> Result<u64> {
        let rtxn = self.env.read_txn()?;
        self.next_key_in(&rtxn)
    }

    /// Key number `i`, at its first leaf. For signing use
    /// [`Wallet::signing_key`], which advances the stored leaf.
    pub fn key(&self, i: u64) -> Key {
        let mut input: Vec<Fp> =
            self.master.chunks(4).map(|c| Fp::from_u64(u32::from_le_bytes(c.try_into().unwrap()) as u64)).collect();
        input.push(Fp::from_u64(i & 0x3fff_ffff));
        input.push(Fp::from_u64(i >> 30));
        let seed: [u8; SEED_SIZE] = digest_to_bytes(&hash(&input));
        Key::generate(&seed)
    }

    /// Key `i` positioned at its next unused leaf. The leaf is marked used
    /// and committed before the key is returned, so it is never reused even
    /// if the signature is lost.
    pub fn signing_key(&self, i: u64) -> Result<Key> {
        let mut wtxn = self.env.write_txn()?;
        let leaf = self.leaves.get(&wtxn, &i)?.unwrap_or(0);
        if leaf >= Key::LEAVES {
            return Err(WalletError::Exhausted);
        }
        self.leaves.put(&mut wtxn, &i, &(leaf + 1))?;
        wtxn.commit()?;
        let mut key = self.key(i);
        key.set_next_index(leaf);
        Ok(key)
    }

    fn record(&self, wtxn: &mut RwTxn, o: &Owned) -> Result<()> {
        self.outputs.put(wtxn, &o.key_index, &o.to_bytes())?;
        Ok(())
    }

    fn owned_in(&self, rtxn: &RoTxn, key_index: u64) -> Result<Option<Owned>> {
        match self.outputs.get(rtxn, &key_index)? {
            None => Ok(None),
            Some(b) => Owned::from_bytes(key_index, b).map(Some).ok_or(WalletError::Corrupt("output")),
        }
    }

    fn set_state(&self, wtxn: &mut RwTxn, key_index: u64, state: State) -> Result<()> {
        let mut o = self.owned_in(wtxn, key_index)?.ok_or(WalletError::Corrupt("missing output"))?;
        o.state = state;
        self.record(wtxn, &o)
    }

    /// A fresh key's output paying `amount`, recorded as unspent (and
    /// unconfirmed until the UTXO set holds it).
    pub fn receive(&self, amount: u64) -> Result<Output> {
        let mut wtxn = self.env.write_txn()?;
        let key_index = self.fresh_key(&mut wtxn)?;
        let out = Output::new(&self.key(key_index).public_key(), amount);
        let o = Owned { key_index, amount, commitment: out.commitment, state: State::Unspent, created: unix_now() };
        self.record(&mut wtxn, &o)?;
        wtxn.commit()?;
        Ok(out)
    }

    /// Every recorded output, by key index.
    pub fn outputs(&self) -> Result<Vec<Owned>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.outputs.iter(&rtxn)? {
            let (k, b) = item?;
            out.push(Owned::from_bytes(k, b).ok_or(WalletError::Corrupt("output"))?);
        }
        Ok(out)
    }

    /// Unspent, unreserved outputs the UTXO set holds, largest first.
    pub fn spendable(&self, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Vec<Owned>> {
        let mut keep: Vec<Owned> = Vec::new();
        for o in self.outputs()? {
            if o.state == State::Unspent && utxo.contains(rtxn, &o.commitment)? {
                keep.push(o);
            }
        }
        keep.sort_by(|a, b| b.amount.cmp(&a.amount).then(a.key_index.cmp(&b.key_index)));
        Ok(keep)
    }

    /// Confirmed (unspent and in the UTXO set), pending (unspent, not yet
    /// there) and reserved totals.
    pub fn balance(&self, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Balance> {
        let mut b = Balance::default();
        for o in self.outputs()? {
            let held = utxo.contains(rtxn, &o.commitment)?;
            match (o.state, held) {
                (State::Unspent, true) => b.confirmed += o.amount as u128,
                (State::Unspent, false) => b.pending += o.amount as u128,
                (State::Reserved, _) => b.reserved += o.amount as u128,
                (State::Spent, _) => {}
            }
        }
        Ok(b)
    }

    /// Forgets an unspent output that will never land, by commitment: the
    /// reward of a block the miner abandoned. Returns whether a record went.
    pub fn forget(&self, commitment: &Commitment) -> Result<bool> {
        let mut wtxn = self.env.write_txn()?;
        let mut gone = false;
        for o in self.outputs()? {
            if o.state == State::Unspent && o.commitment == *commitment {
                self.outputs.delete(&mut wtxn, &o.key_index)?;
                gone = true;
            }
        }
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
                self.outputs.delete(&mut wtxn, &o.key_index)?;
                n += 1;
            }
        }
        wtxn.commit()?;
        Ok(n)
    }

    /// Signs `unsigned`, whose inputs must all be the wallet's keys given by
    /// `key_indexes` in order, marking them spent.
    fn sign(&self, unsigned: UnsignedTransaction, key_indexes: &[u64]) -> Result<Transaction> {
        let keys: Vec<Key> = key_indexes.iter().map(|&i| self.signing_key(i)).collect::<Result<_>>()?;
        let tx = unsigned
            .sign(|i, pk, msg| {
                let mut key = keys[i].clone();
                if key.public_key() != *pk {
                    return Err(WalletError::BadSlate("input key is not the wallet's"));
                }
                key.sign(msg).map_err(|_| WalletError::Exhausted)
            })
            .map_err(|e| e)?;
        let mut wtxn = self.env.write_txn()?;
        for &i in key_indexes {
            self.set_state(&mut wtxn, i, State::Spent)?;
        }
        wtxn.commit()?;
        Ok(tx)
    }

    /// Starts a payment of `amount` with `fee`: picks confirmed inputs
    /// largest first, reserves them, adds change to a fresh key, and returns
    /// the stage-1 slate for the recipient.
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
        let mut wtxn = self.env.write_txn()?;
        let mut outputs = Vec::new();
        let mut change = None;
        if change_amount > 0 {
            let k = self.fresh_key(&mut wtxn)?;
            let out = Output::new(&self.key(k).public_key(), change_amount);
            let rec = Owned {
                key_index: k,
                amount: change_amount,
                commitment: out.commitment,
                state: State::Unspent,
                created: unix_now(),
            };
            self.record(&mut wtxn, &rec)?;
            outputs.push(out);
            change = Some(k);
        }
        for c in &picked {
            self.set_state(&mut wtxn, c.key_index, State::Reserved)?;
        }
        let id = random_bytes()?;
        let pending = Pending { inputs: picked.iter().map(|c| c.key_index).collect(), change };
        self.slates.put(&mut wtxn, &id, &pending.to_bytes())?;
        wtxn.commit()?;
        let inputs = picked.iter().map(|c| (self.key(c.key_index).public_key(), c.amount)).collect();
        Ok(Slate { id, stage: 1, amount, fee, inputs, outputs, change: u32::from(change.is_some()) })
    }

    /// The recipient's step: adds an output for the slate's amount on a
    /// fresh key, recorded as unspent, and advances the slate to stage 2.
    pub fn receive_slate(&self, slate: &mut Slate) -> Result<()> {
        if slate.stage != 1 {
            return Err(WalletError::BadSlate("not a stage-1 slate"));
        }
        if slate.outputs.len() != slate.change as usize {
            return Err(WalletError::BadSlate("already has a recipient output"));
        }
        let out = Wallet::receive(self, slate.amount)?;
        slate.outputs.push(out);
        slate.stage = 2;
        Ok(())
    }

    /// The sender's last step: checks the stage-2 slate against the pending
    /// record and the balance, signs the inputs (marking them spent) and
    /// returns the transaction to pool.
    pub fn finalize(&self, slate: &Slate) -> Result<Transaction> {
        if slate.stage != 2 {
            return Err(WalletError::BadSlate("not a stage-2 slate"));
        }
        let pending = {
            let rtxn = self.env.read_txn()?;
            let b = self.slates.get(&rtxn, &slate.id)?.ok_or(WalletError::UnknownSlate)?;
            Pending::from_bytes(b).ok_or(WalletError::Corrupt("slate"))?
        };
        if pending.inputs.len() != slate.inputs.len() {
            return Err(WalletError::BadSlate("inputs changed"));
        }
        for (&k, (pk, _)) in pending.inputs.iter().zip(&slate.inputs) {
            if self.key(k).public_key() != *pk {
                return Err(WalletError::BadSlate("inputs changed"));
            }
        }
        let ins: u128 = slate.inputs.iter().map(|(_, a)| *a as u128).sum();
        let outs: u128 = slate.outputs.iter().map(|o| o.amount as u128).sum();
        let paid: u128 = slate.outputs[slate.change as usize..].iter().map(|o| o.amount as u128).sum();
        if slate.outputs.len() <= slate.change as usize {
            return Err(WalletError::BadSlate("no recipient output"));
        }
        if paid != slate.amount as u128 || ins != outs + slate.fee as u128 {
            return Err(WalletError::BadSlate("amounts do not balance"));
        }
        if let Some(k) = pending.change {
            let rtxn = self.env.read_txn()?;
            let rec = self.owned_in(&rtxn, k)?.ok_or(WalletError::Corrupt("change output"))?;
            if slate.outputs.first().map(|o| o.commitment) != Some(rec.commitment) {
                return Err(WalletError::BadSlate("change output changed"));
            }
        }
        let tx = self.sign(slate.unsigned(), &pending.inputs)?;
        let mut wtxn = self.env.write_txn()?;
        self.slates.delete(&mut wtxn, &slate.id)?;
        wtxn.commit()?;
        Ok(tx)
    }

    /// Abandons a pending slate: its inputs become spendable again and its
    /// change record is dropped.
    pub fn cancel(&self, id: &[u8; 32]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let b = self.slates.get(&wtxn, id)?.ok_or(WalletError::UnknownSlate)?;
        let pending = Pending::from_bytes(b).ok_or(WalletError::Corrupt("slate"))?;
        for &k in &pending.inputs {
            self.set_state(&mut wtxn, k, State::Unspent)?;
        }
        if let Some(k) = pending.change {
            self.outputs.delete(&mut wtxn, &k)?;
        }
        self.slates.delete(&mut wtxn, id)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Ids of pending slates with the amounts reserved for them.
    pub fn pending_slates(&self) -> Result<Vec<([u8; 32], u128)>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.slates.iter(&rtxn)? {
            let (id, b) = item?;
            let pending = Pending::from_bytes(b).ok_or(WalletError::Corrupt("slate"))?;
            let mut reserved = 0u128;
            for &k in &pending.inputs {
                reserved += self.owned_in(&rtxn, k)?.map_or(0, |o| o.amount as u128);
            }
            out.push((id.try_into().map_err(|_| WalletError::Corrupt("slate id"))?, reserved));
        }
        Ok(out)
    }
}

/// Totals of a wallet's outputs by status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    pub confirmed: u128,
    pub pending: u128,
    pub reserved: u128,
}

const _: () = assert!(SEED_SIZE == DIGEST * 4);

/// Reads a digest from 32 bytes, for slate ids shown as hex.
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

#[allow(dead_code)]
fn _digest_check(b: &[u8]) -> Option<Commitment> {
    digest_from_bytes(b)
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

    #[test]
    fn outputs_balances_and_leaves_persist() {
        let dir = TempDir::new("basic");
        let (env, u) = utxo(&dir);
        let seed = {
            let w = Wallet::open(&dir.0.join("wallet")).unwrap();
            let a = w.receive(100).unwrap();
            let b = w.receive(50).unwrap();
            // a lands, b does not (yet).
            let mut wtxn = env.write_txn().unwrap();
            u.add(&mut wtxn, &a.commitment).unwrap();
            wtxn.commit().unwrap();
            let rtxn = env.read_txn().unwrap();
            assert_eq!(w.balance(&u, &rtxn).unwrap(), Balance { confirmed: 100, pending: 50, reserved: 0 });
            assert_eq!(w.spendable(&u, &rtxn).unwrap().len(), 1);
            // Signing keys advance leaves durably.
            let k0 = w.signing_key(0).unwrap();
            assert_eq!(k0.next_index(), 0);
            let k0 = w.signing_key(0).unwrap();
            assert_eq!(k0.next_index(), 1);
            assert_eq!(w.keys().unwrap(), 2);
            let _ = b;
            w.seed_hex()
        };
        let w = Wallet::open(&dir.0.join("wallet")).unwrap();
        assert_eq!(w.seed_hex(), seed);
        assert_eq!(w.signing_key(0).unwrap().next_index(), 2);
        assert_eq!(w.outputs().unwrap().len(), 2);
        let rtxn = env.read_txn().unwrap();
        let c = w.receive(7).unwrap();
        assert_eq!(w.outputs().unwrap().len(), 3);
        assert!(w.forget(&c.commitment).unwrap());
        assert!(!w.forget(&c.commitment).unwrap());
        assert_eq!(w.prune_pending(&u, &rtxn).unwrap(), 1);
        assert_eq!(w.outputs().unwrap().len(), 1);
        for _ in 0..(Key::LEAVES - 3) {
            w.signing_key(0).unwrap();
        }
        assert!(matches!(w.signing_key(0), Err(WalletError::Exhausted)));
    }

    #[test]
    fn slate_roundtrip_send_receive_finalize() {
        let dir = TempDir::new("slate");
        let (env, u) = utxo(&dir);
        let alice = Wallet::open(&dir.0.join("alice")).unwrap();
        let bob = Wallet::open(&dir.0.join("bob")).unwrap();
        let a1 = alice.receive(60).unwrap();
        let a2 = alice.receive(50).unwrap();
        {
            let mut wtxn = env.write_txn().unwrap();
            u.add(&mut wtxn, &a1.commitment).unwrap();
            u.add(&mut wtxn, &a2.commitment).unwrap();
            wtxn.commit().unwrap();
        }
        let rtxn = env.read_txn().unwrap();
        assert!(matches!(alice.send(200, 1, &u, &rtxn), Err(WalletError::Insufficient { have: 110, need: 201 })));
        // 70 + fee 2 needs both coins (60 first, then 50): change 38.
        let slate = alice.send(70, 2, &u, &rtxn).unwrap();
        assert_eq!(slate.stage, 1);
        assert_eq!(slate.inputs.len(), 2);
        assert_eq!(slate.change, 1);
        assert_eq!(slate.outputs[0].amount, 38);
        assert_eq!(alice.balance(&u, &rtxn).unwrap(), Balance { confirmed: 0, pending: 38, reserved: 110 });
        assert_eq!(alice.pending_slates().unwrap().len(), 1);
        // Across the wire.
        let bytes = slate.to_bytes();
        let mut received = Slate::from_bytes(&bytes).unwrap();
        assert_eq!(received, slate);
        assert!(matches!(bob.finalize(&received), Err(WalletError::BadSlate(_))));
        bob.receive_slate(&mut received).unwrap();
        assert_eq!(received.stage, 2);
        assert_eq!(received.outputs.len(), 2);
        assert_eq!(received.outputs[1].amount, 70);
        assert!(matches!(bob.receive_slate(&mut received), Err(WalletError::BadSlate(_))));
        assert_eq!(bob.balance(&u, &rtxn).unwrap(), Balance { confirmed: 0, pending: 70, reserved: 0 });
        let received = Slate::from_bytes(&received.to_bytes()).unwrap();
        // Bob cannot finalize Alice's slate; a tampered amount fails.
        assert!(matches!(bob.finalize(&received), Err(WalletError::UnknownSlate)));
        let mut greedy = received.clone();
        greedy.outputs[1] = Output::new(&bob.key(0).public_key(), 71);
        assert!(matches!(alice.finalize(&greedy), Err(WalletError::BadSlate("amounts do not balance"))));
        let tx = alice.finalize(&received).unwrap();
        assert!(tx.verify_signatures());
        assert_eq!(tx.balance(), 2);
        assert_eq!(tx.inputs.len(), 2);
        assert!(matches!(alice.finalize(&received), Err(WalletError::UnknownSlate)));
        assert_eq!(alice.balance(&u, &rtxn).unwrap(), Balance { confirmed: 0, pending: 38, reserved: 0 });
        assert!(alice.outputs().unwrap().iter().filter(|o| o.state == State::Spent).count() == 2);
        // Cancelling a slate frees its inputs and drops the change.
        drop(rtxn);
        let a3 = alice.receive(9).unwrap();
        {
            let mut wtxn = env.write_txn().unwrap();
            u.add(&mut wtxn, &a3.commitment).unwrap();
            wtxn.commit().unwrap();
        }
        let rtxn = env.read_txn().unwrap();
        let s2 = alice.send(4, 0, &u, &rtxn).unwrap();
        assert_eq!(alice.balance(&u, &rtxn).unwrap().reserved, 9);
        alice.cancel(&s2.id).unwrap();
        assert_eq!(alice.balance(&u, &rtxn).unwrap(), Balance { confirmed: 9, pending: 38, reserved: 0 });
        assert!(matches!(alice.cancel(&s2.id), Err(WalletError::UnknownSlate)));
        assert_eq!(digest_from_hex(&s2.id_hex()), Some(s2.id));
    }
}
