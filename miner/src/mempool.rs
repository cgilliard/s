//! The memory pool: valid, unconfirmed transactions waiting to be mined.
//!
//! A transaction enters the pool ([`Mempool::insert`]) only if it decodes,
//! spends at least one input, has a non-negative balance (its fee), carries a
//! valid signature on every input, spends outputs the UTXO set holds, and
//! conflicts with nothing already pooled. The proof cannot tell a user
//! transaction from a block reward, so the non-negative fee is this policy
//! rule, not consensus: a negative-balance transaction would be paid out of
//! the miner's reward.
//!
//! A transaction that spends an output a pooled one already spends
//! replaces it (and any other it conflicts with) if its fee is at least
//! theirs together plus [`REPLACEMENT_FEE_PER_BYTE`] per byte of its own
//! size; that is how a wallet cancels a payment. The bump keeps a sender
//! from churning the network with free replacements.
//!
//! When the pool is full, a new transaction with a higher fee per byte
//! evicts the lowest. After every change of tip the pool is revalidated
//! ([`Mempool::revalidate`]): transactions whose inputs are now spent leave
//! the pool but are shelved for a while, and return if a reorganization
//! makes their inputs unspent again. Blocks carry no transactions, so this
//! shelf is the only way a reorganized-out transaction can come back.
//!
//! The miner takes transactions by fee rate with [`Mempool::select`], and
//! pays itself the subsidy plus their fees.

use std::collections::HashMap;
use std::time::Instant;

use heed::RoTxn;

use crate::pow::Digest;
use crate::transaction::{Commitment, Transaction};
use crate::utxo::{self, UtxoSet};

/// Largest transaction accepted, in bytes (about 50 inputs).
pub const MAX_TX_SIZE: usize = 128 << 10;
/// Default pool capacity in bytes.
pub const DEFAULT_CAPACITY: usize = 64 << 20;
/// Shelved transactions kept, at most.
const SHELF: usize = 1024;
/// Base units per byte a replacement must add over what it replaces.
pub const REPLACEMENT_FEE_PER_BYTE: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Already in the pool.
    Known,
    /// No inputs: only a block reward looks like that.
    NoInputs,
    TooLarge(usize),
    /// Outputs exceed inputs.
    NegativeFee,
    /// Zero-amount output or duplicate input.
    Malformed,
    BadSignature,
    /// An input's output is not unspent.
    UnknownInput(Commitment),
    /// Spends an output pooled transactions spend, without paying enough
    /// to replace them.
    ReplacementFee {
        min: u64,
    },
    /// The pool is full of better-paying transactions.
    Full,
}

impl core::fmt::Display for Reject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Reject::Known => f.write_str("already in the pool"),
            Reject::NoInputs => f.write_str("no inputs"),
            Reject::TooLarge(n) => write!(f, "{n} bytes exceeds the transaction size limit"),
            Reject::NegativeFee => f.write_str("outputs exceed inputs"),
            Reject::Malformed => f.write_str("malformed transaction"),
            Reject::BadSignature => f.write_str("invalid signature"),
            Reject::UnknownInput(_) => f.write_str("spends an output that is not unspent"),
            Reject::ReplacementFee { min } => {
                write!(f, "conflicts with a pooled transaction; a replacement must pay at least {min}")
            }
            Reject::Full => f.write_str("pool is full"),
        }
    }
}

impl std::error::Error for Reject {}

#[derive(Clone, Debug)]
pub struct Entry {
    pub tx: Transaction,
    pub txid: Digest,
    pub fee: u64,
    pub size: usize,
    pub added: Instant,
}

impl Entry {
    /// Fee per byte, scaled by 2^16 for integer comparison.
    fn rate(&self) -> u128 {
        ((self.fee as u128) << 16) / self.size as u128
    }
}

pub struct Mempool {
    txs: HashMap<Digest, Entry>,
    /// Spent commitment to the pooled transaction spending it.
    spends: HashMap<Commitment, Digest>,
    bytes: usize,
    capacity: usize,
    /// Transactions dropped for spent inputs, oldest first, in case a
    /// reorganization brings their inputs back.
    shelf: Vec<Entry>,
}

/// Checks a transaction against everything but the pool and the UTXO set.
fn check_static(tx: &Transaction) -> Result<u64, Reject> {
    if tx.inputs.is_empty() {
        return Err(Reject::NoInputs);
    }
    let size = tx.size();
    if size > MAX_TX_SIZE {
        return Err(Reject::TooLarge(size));
    }
    if tx.outputs.iter().any(|o| o.amount == 0) {
        return Err(Reject::Malformed);
    }
    let mut spent = tx.spent_commitments();
    spent.sort_unstable_by_key(|c| crate::poseidon2::digest_to_bytes(c));
    if spent.windows(2).any(|w| w[0] == w[1]) {
        return Err(Reject::Malformed);
    }
    let fee = tx.balance();
    if fee < 0 {
        return Err(Reject::NegativeFee);
    }
    if !tx.verify_signatures() {
        return Err(Reject::BadSignature);
    }
    Ok(fee.min(u64::MAX as i128) as u64)
}

impl Mempool {
    pub fn new(capacity: usize) -> Mempool {
        Mempool { txs: HashMap::new(), spends: HashMap::new(), bytes: 0, capacity, shelf: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn contains(&self, txid: &Digest) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn get(&self, txid: &Digest) -> Option<&Transaction> {
        self.txs.get(txid).map(|e| &e.tx)
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.txs.values()
    }

    /// Validates and adds `tx`; returns its id.
    pub fn insert(&mut self, tx: Transaction, utxo: &UtxoSet, rtxn: &RoTxn) -> Result<Digest, Reject> {
        let txid = tx.txid();
        if self.txs.contains_key(&txid) {
            return Err(Reject::Known);
        }
        let fee = check_static(&tx)?;
        let mut conflicts: Vec<Digest> = Vec::new();
        for c in tx.spent_commitments() {
            if let Some(other) = self.spends.get(&c)
                && !conflicts.contains(other)
            {
                conflicts.push(*other);
            }
            if !utxo.contains(rtxn, &c).map_err(|_| Reject::UnknownInput(c))? {
                return Err(Reject::UnknownInput(c));
            }
        }
        let size = tx.size();
        if !conflicts.is_empty() {
            let replaced: u64 = conflicts.iter().map(|id| self.txs[id].fee).sum();
            let min = replaced.saturating_add(REPLACEMENT_FEE_PER_BYTE * size as u64);
            if fee < min {
                return Err(Reject::ReplacementFee { min });
            }
        }
        let entry = Entry { size, tx, txid, fee, added: Instant::now() };
        // Replaced transactions go first, so their room counts; they are
        // put back if the new one still does not fit.
        let removed: Vec<Entry> = conflicts.iter().filter_map(|id| self.remove(id)).collect();
        if let Err(e) = self.make_room(&entry) {
            for e in removed {
                self.add(e);
            }
            return Err(e);
        }
        self.add(entry);
        Ok(txid)
    }

    /// Evicts the lowest-rate transactions until `entry` fits, or refuses
    /// if `entry` pays less than what it would evict.
    fn make_room(&mut self, entry: &Entry) -> Result<(), Reject> {
        if entry.size > self.capacity {
            return Err(Reject::Full);
        }
        while self.bytes + entry.size > self.capacity {
            let worst = self.txs.values().min_by_key(|e| (e.rate(), std::cmp::Reverse(e.added))).map(|e| e.txid);
            match worst {
                Some(id) if self.txs[&id].rate() < entry.rate() => {
                    self.remove(&id);
                }
                _ => return Err(Reject::Full),
            }
        }
        Ok(())
    }

    fn add(&mut self, entry: Entry) {
        for c in entry.tx.spent_commitments() {
            self.spends.insert(c, entry.txid);
        }
        self.bytes += entry.size;
        self.txs.insert(entry.txid, entry);
    }

    /// Removes a transaction; returns it if it was pooled.
    pub fn remove(&mut self, txid: &Digest) -> Option<Entry> {
        let entry = self.txs.remove(txid)?;
        for c in entry.tx.spent_commitments() {
            self.spends.remove(&c);
        }
        self.bytes -= entry.size;
        Some(entry)
    }

    /// After the tip changed: drops transactions whose inputs are no longer
    /// unspent, shelving them, and brings back shelved ones that became
    /// valid again. Returns how many left and how many returned.
    pub fn revalidate(&mut self, utxo: &UtxoSet, rtxn: &RoTxn) -> utxo::Result<(usize, usize)> {
        let mut gone = Vec::new();
        for e in self.txs.values() {
            for c in e.tx.spent_commitments() {
                if !utxo.contains(rtxn, &c)? {
                    gone.push(e.txid);
                    break;
                }
            }
        }
        for id in &gone {
            if let Some(e) = self.remove(id) {
                self.shelf.push(e);
            }
        }
        if self.shelf.len() > SHELF {
            let excess = self.shelf.len() - SHELF;
            self.shelf.drain(..excess);
        }
        let mut back = 0;
        let mut keep = Vec::with_capacity(self.shelf.len());
        for e in std::mem::take(&mut self.shelf) {
            let mut ok = !self.txs.contains_key(&e.txid);
            for c in e.tx.spent_commitments() {
                if !ok {
                    break;
                }
                ok = utxo.contains(rtxn, &c)? && !self.spends.contains_key(&c);
            }
            if ok && self.make_room(&e).is_ok() {
                self.add(e);
                back += 1;
            } else if ok {
                keep.push(e);
            } else {
                keep.push(e);
            }
        }
        // Shelved entries that are spent for good age out with the shelf.
        self.shelf = keep;
        Ok((gone.len(), back))
    }

    /// Transactions by fee rate, highest first, while `fits` accepts the
    /// running selection (it is called with the candidate list including
    /// the next transaction).
    pub fn select(&self, mut fits: impl FnMut(&[&Transaction]) -> bool) -> Vec<Transaction> {
        let mut entries: Vec<&Entry> = self.txs.values().collect();
        entries.sort_by(|a, b| b.rate().cmp(&a.rate()).then(a.added.cmp(&b.added)));
        let mut chosen: Vec<&Transaction> = Vec::new();
        for e in entries {
            chosen.push(&e.tx);
            if !fits(&chosen) {
                chosen.pop();
                break;
            }
        }
        chosen.into_iter().cloned().collect()
    }

    /// Sum of the fees of `txs`.
    pub fn fees(txs: &[Transaction]) -> u64 {
        txs.iter().map(|t| t.balance().max(0) as u64).sum()
    }

    /// Ids of pooled transactions, in no particular order.
    pub fn ids(&self) -> Vec<Digest> {
        self.txs.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_tree::open_env;
    use crate::transaction::{Key, Output, UnsignedTransaction};
    use crate::xmss::PublicKey;

    fn key(tag: u8) -> Key {
        let mut s = [0u8; 32];
        s[0] = tag;
        Key::generate(&s)
    }

    fn pk(tag: u8) -> PublicKey {
        key(tag).public_key()
    }

    /// A transaction spending `amount` from key `tag` to key 100 with `fee`.
    fn spend(tag: u8, amount: u64, fee: u64) -> Transaction {
        let mut k = key(tag);
        let outs = vec![Output::new(&pk(100), amount - fee)];
        UnsignedTransaction::new(vec![(k.public_key(), amount)], outs).sign_with(&mut k).unwrap()
    }

    #[test]
    fn pool_validates_orders_and_revalidates() {
        let dir = std::env::temp_dir().join(format!("tabminer-mempool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = open_env(&dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        // Outputs: key 1 with 100000, key 2 with 50, key 3 with 10.
        for (tag, amount) in [(1u8, 100_000u64), (2, 50), (3, 10)] {
            utxo.add(&mut wtxn, &Output::new(&pk(tag), amount).commitment).unwrap();
        }
        wtxn.commit().unwrap();

        let mut pool = Mempool::new(1 << 20);
        let rtxn = env.read_txn().unwrap();
        let t1 = spend(1, 100_000, 5);
        let t2 = spend(2, 50, 10);
        let id1 = pool.insert(t1.clone(), &utxo, &rtxn).unwrap();
        let id2 = pool.insert(t2.clone(), &utxo, &rtxn).unwrap();
        assert_eq!(pool.insert(t1.clone(), &utxo, &rtxn), Err(Reject::Known));
        assert_eq!(pool.len(), 2);
        // Conflicts, unknown inputs, negative fees, bad signatures, rewards.
        let double = spend(1, 100_000, 6);
        let min = 5 + double.size() as u64;
        assert_eq!(pool.insert(double, &utxo, &rtxn), Err(Reject::ReplacementFee { min }));
        let unknown = spend(4, 7, 1);
        assert!(matches!(pool.insert(unknown, &utxo, &rtxn), Err(Reject::UnknownInput(_))));
        let mut k3 = key(3);
        let generous =
            UnsignedTransaction::new(vec![(pk(3), 10)], vec![Output::new(&pk(100), 11)]).sign_with(&mut k3).unwrap();
        assert_eq!(pool.insert(generous, &utxo, &rtxn), Err(Reject::NegativeFee));
        let mut forged = spend(3, 10, 1);
        forged.outputs[0] = Output::new(&pk(101), 9);
        assert_eq!(pool.insert(forged, &utxo, &rtxn), Err(Reject::BadSignature));
        let reward = UnsignedTransaction::new(vec![], vec![Output::new(&pk(100), 5)])
            .sign(|_, _, _| Err::<crate::transaction::Sig, ()>(()))
            .unwrap();
        assert_eq!(pool.insert(reward, &utxo, &rtxn), Err(Reject::NoInputs));

        // Selection: t2 pays a higher rate (same size, bigger fee).
        let all = pool.select(|_| true);
        assert_eq!(all.iter().map(|t| t.txid()).collect::<Vec<_>>(), vec![id2, id1]);
        assert_eq!(Mempool::fees(&all), 15);
        let one = pool.select(|c| c.len() <= 1);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].txid(), id2);
        drop(rtxn);

        // Spending key 1's output on chain drops t1 to the shelf; undoing
        // the spend brings it back.
        let mut wtxn = env.write_txn().unwrap();
        let c1 = Output::new(&pk(1), 100_000).commitment;
        assert!(utxo.spend_at(&mut wtxn, &c1, 0).unwrap());
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(pool.revalidate(&utxo, &rtxn).unwrap(), (1, 0));
        assert!(!pool.contains(&id1) && pool.contains(&id2));
        drop(rtxn);
        let mut wtxn = env.write_txn().unwrap();
        utxo.unspend(&mut wtxn, &c1, &crate::state_tree::EMPTY, 0).unwrap();
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(pool.revalidate(&utxo, &rtxn).unwrap(), (0, 1));
        assert!(pool.contains(&id1));

        // Replacement: paying the old fee plus a byte's worth per byte
        // takes t1's place.
        let mut k1 = key(1);
        let bump = 5 + t1.size() as u64;
        let replacement =
            UnsignedTransaction::new(vec![(k1.public_key(), 100_000)], vec![Output::new(&pk(1), 100_000 - bump)])
                .sign_with(&mut k1)
                .unwrap();
        let rid = pool.insert(replacement.clone(), &utxo, &rtxn).unwrap();
        assert!(pool.contains(&rid) && !pool.contains(&id1));
        assert_eq!(pool.len(), 2);
        // The original cannot come back.
        assert!(matches!(pool.insert(t1.clone(), &utxo, &rtxn), Err(Reject::ReplacementFee { .. })));
        pool.remove(&rid);
        pool.insert(t1.clone(), &utxo, &rtxn).unwrap();

        // Capacity: a tiny pool evicts the lower rate for a higher one and
        // refuses a lower one.
        let mut small = Mempool::new(t1.size());
        small.insert(t1.clone(), &utxo, &rtxn).unwrap();
        assert_eq!(small.insert(t2.clone(), &utxo, &rtxn), Ok(id2));
        assert!(!small.contains(&id1));
        assert_eq!(small.insert(t1.clone(), &utxo, &rtxn), Err(Reject::Full));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
