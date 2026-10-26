//! The unspent output set: outputs stored in the sparse [`StateTree`] at
//! counter positions, with a lookup from commitment to position.
//!
//! Every output ever created gets the next position from a monotonically
//! increasing counter (positions are never reused), and its commitment is
//! written as the leaf at that position. Spending an output clears the leaf.
//! Because a transaction input identifies the output it spends only by its
//! commitment, an index from commitment to positions is kept alongside the
//! tree. Two outputs with the same key and amount have the same commitment;
//! they occupy distinct positions and [`UtxoSet::spend`] consumes the lowest
//! one first.
//!
//! Three named LMDB databases live under a common prefix: `<prefix>.tree`
//! (the Merkle tree), `<prefix>.index` (commitment bytes followed by the
//! big-endian position, no value) and `<prefix>.meta` (the counter). All
//! operations take the caller's transaction so a block can update the set
//! and its own records atomically.

use heed::byteorder::BigEndian;
use heed::types::{Bytes, Str, U64, Unit};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::poseidon2::{DIGEST, digest_to_bytes};
use crate::state_tree::{self, CAPACITY, Digest, Proof, StateTree};
use crate::transaction::{Commitment, Output};

const COMMITMENT_BYTES: usize = DIGEST * 4;
const INDEX_KEY_LEN: usize = COMMITMENT_BYTES + 8;
const META_NEXT_POSITION: &str = "next_position";

/// Errors from UTXO set operations.
#[derive(Debug)]
pub enum Error {
    Tree(state_tree::Error),
    Heed(heed::Error),
    /// All `2^DEPTH` positions have been assigned.
    Full,
    /// An index entry could not be decoded.
    CorruptIndex,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Tree(e) => write!(f, "{e}"),
            Error::Heed(e) => write!(f, "lmdb error: {e}"),
            Error::Full => f.write_str("utxo set is full: no positions left"),
            Error::CorruptIndex => f.write_str("corrupt utxo index entry"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Tree(e) => Some(e),
            Error::Heed(e) => Some(e),
            _ => None,
        }
    }
}

impl From<state_tree::Error> for Error {
    fn from(e: state_tree::Error) -> Self {
        Error::Tree(e)
    }
}

impl From<heed::Error> for Error {
    fn from(e: heed::Error) -> Self {
        Error::Heed(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

fn index_key(commitment: &Commitment, position: u64) -> [u8; INDEX_KEY_LEN] {
    let mut k = [0u8; INDEX_KEY_LEN];
    k[..COMMITMENT_BYTES].copy_from_slice(&digest_to_bytes(commitment));
    k[COMMITMENT_BYTES..].copy_from_slice(&position.to_be_bytes());
    k
}

/// Handle to the UTXO set.
#[derive(Clone)]
pub struct UtxoSet {
    tree: StateTree,
    index: Database<Bytes, Unit>,
    meta: Database<Str, U64<BigEndian>>,
}

impl UtxoSet {
    /// Opens the set stored under `prefix` in `env`, creating its databases
    /// if needed. The transaction must be committed by the caller.
    pub fn open(env: &Env, wtxn: &mut RwTxn, prefix: &str) -> Result<UtxoSet> {
        let tree = StateTree::open(env, wtxn, &format!("{prefix}.tree"))?;
        let index = env.create_database(wtxn, Some(&format!("{prefix}.index")))?;
        let meta = env.create_database(wtxn, Some(&format!("{prefix}.meta")))?;
        Ok(UtxoSet { tree, index, meta })
    }

    /// The underlying Merkle tree.
    pub fn tree(&self) -> &StateTree {
        &self.tree
    }

    /// Current Merkle root of the set.
    pub fn root(&self, rtxn: &RoTxn) -> Result<Digest> {
        Ok(self.tree.root(rtxn)?)
    }

    /// Position the next added output will receive; also the number of
    /// outputs ever added.
    pub fn next_position(&self, rtxn: &RoTxn) -> Result<u64> {
        Ok(self.meta.get(rtxn, META_NEXT_POSITION)?.unwrap_or(0))
    }

    /// Adds `output` at the next position and returns that position.
    pub fn add(&self, wtxn: &mut RwTxn, output: &Output) -> Result<u64> {
        let position = self.next_position(wtxn)?;
        if position >= CAPACITY {
            return Err(Error::Full);
        }
        self.tree.update(wtxn, position, &output.commitment)?;
        self.index.put(wtxn, &index_key(&output.commitment, position), &())?;
        self.meta.put(wtxn, META_NEXT_POSITION, &(position + 1))?;
        Ok(position)
    }

    /// Positions of all unspent outputs with this commitment, ascending.
    pub fn positions(&self, rtxn: &RoTxn, commitment: &Commitment) -> Result<Vec<u64>> {
        let prefix = digest_to_bytes(commitment);
        let mut out = Vec::new();
        for item in self.index.prefix_iter(rtxn, &prefix[..])? {
            let (key, ()) = item?;
            if key.len() != INDEX_KEY_LEN {
                return Err(Error::CorruptIndex);
            }
            out.push(u64::from_be_bytes(key[COMMITMENT_BYTES..].try_into().unwrap()));
        }
        Ok(out)
    }

    /// Whether at least one unspent output has this commitment.
    pub fn contains(&self, rtxn: &RoTxn, commitment: &Commitment) -> Result<bool> {
        let prefix = digest_to_bytes(commitment);
        let mut iter = self.index.prefix_iter(rtxn, &prefix[..])?;
        Ok(iter.next().transpose()?.is_some())
    }

    /// Spends the lowest-positioned unspent output with this commitment,
    /// clearing its leaf. Returns the position, or `None` if there is none.
    pub fn spend(&self, wtxn: &mut RwTxn, commitment: &Commitment) -> Result<Option<u64>> {
        let Some(&position) = self.positions(wtxn, commitment)?.first() else {
            return Ok(None);
        };
        self.spend_at(wtxn, commitment, position)?;
        Ok(Some(position))
    }

    /// Spends the output with this commitment at exactly `position`.
    /// Returns `false` if no such unspent output exists.
    pub fn spend_at(&self, wtxn: &mut RwTxn, commitment: &Commitment, position: u64) -> Result<bool> {
        if !self.index.delete(wtxn, &index_key(commitment, position))? {
            return Ok(false);
        }
        self.tree.remove(wtxn, position)?;
        Ok(true)
    }

    /// Commitment stored at `position`, or the empty digest if spent or
    /// never assigned.
    pub fn get(&self, rtxn: &RoTxn, position: u64) -> Result<Digest> {
        Ok(self.tree.get(rtxn, position)?)
    }

    /// Merkle proof for the leaf at `position`.
    pub fn prove(&self, rtxn: &RoTxn, position: u64) -> Result<Proof> {
        Ok(self.tree.prove(rtxn, position)?)
    }

    /// Number of unspent outputs.
    pub fn len(&self, rtxn: &RoTxn) -> Result<u64> {
        Ok(self.index.len(rtxn)?)
    }

    pub fn is_empty(&self, rtxn: &RoTxn) -> Result<bool> {
        Ok(self.len(rtxn)? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_tree::{EMPTY, empty_root, open_env};
    use crate::transaction::Key;
    use crate::xmss::PublicKey;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let p = std::env::temp_dir().join(format!("tabminer-utxo-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn setup(name: &str) -> (TempDir, Env, UtxoSet) {
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let set = UtxoSet::open(&env, &mut wtxn, "utxo").unwrap();
        wtxn.commit().unwrap();
        (dir, env, set)
    }

    fn pk(tag: u8) -> PublicKey {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        Key::generate(&seed).public_key()
    }

    #[test]
    fn add_assigns_sequential_positions() {
        let (_dir, env, set) = setup("add");
        let a = pk(1);
        let outs = [Output::new(&a, 1), Output::new(&a, 2), Output::new(&pk(2), 3)];
        let mut wtxn = env.write_txn().unwrap();
        assert_eq!(set.next_position(&wtxn).unwrap(), 0);
        assert_eq!(set.root(&wtxn).unwrap(), empty_root());
        for (i, o) in outs.iter().enumerate() {
            assert_eq!(set.add(&mut wtxn, o).unwrap(), i as u64);
        }
        wtxn.commit().unwrap();

        let rtxn = env.read_txn().unwrap();
        assert_eq!(set.next_position(&rtxn).unwrap(), 3);
        assert_eq!(set.len(&rtxn).unwrap(), 3);
        for (i, o) in outs.iter().enumerate() {
            assert_eq!(set.get(&rtxn, i as u64).unwrap(), o.commitment);
            assert_eq!(set.positions(&rtxn, &o.commitment).unwrap(), vec![i as u64]);
            assert!(set.contains(&rtxn, &o.commitment).unwrap());
            let proof = set.prove(&rtxn, i as u64).unwrap();
            assert!(proof.verify(&set.root(&rtxn).unwrap(), i as u64, &o.commitment));
        }
        assert!(!set.contains(&rtxn, &Output::new(&a, 99).commitment).unwrap());
        assert_eq!(set.get(&rtxn, 3).unwrap(), EMPTY);

        // Root equals the plain tree with the same leaves.
        let (_d2, env2, tree2) = {
            let dir = TempDir::new("add-ref");
            let env = open_env(&dir.0, 64 << 20).unwrap();
            let mut w = env.write_txn().unwrap();
            let t = StateTree::open(&env, &mut w, "t").unwrap();
            w.commit().unwrap();
            (dir, env, t)
        };
        let mut w = env2.write_txn().unwrap();
        let r = tree2.apply(&mut w, outs.iter().enumerate().map(|(i, o)| (i as u64, o.commitment))).unwrap();
        assert_eq!(r, set.root(&rtxn).unwrap());
    }

    #[test]
    fn spend_removes_lowest_duplicate_first() {
        let (_dir, env, set) = setup("spend");
        let a = pk(3);
        let dup = Output::new(&a, 10);
        let other = Output::new(&a, 11);
        let mut wtxn = env.write_txn().unwrap();
        set.add(&mut wtxn, &dup).unwrap(); // 0
        set.add(&mut wtxn, &other).unwrap(); // 1
        set.add(&mut wtxn, &dup).unwrap(); // 2
        let root_three = set.root(&wtxn).unwrap();
        assert_eq!(set.positions(&wtxn, &dup.commitment).unwrap(), vec![0, 2]);

        assert_eq!(set.spend(&mut wtxn, &dup.commitment).unwrap(), Some(0));
        assert_eq!(set.get(&wtxn, 0).unwrap(), EMPTY);
        assert_eq!(set.get(&wtxn, 2).unwrap(), dup.commitment);
        assert_eq!(set.positions(&wtxn, &dup.commitment).unwrap(), vec![2]);
        assert_ne!(set.root(&wtxn).unwrap(), root_three);
        assert_eq!(set.len(&wtxn).unwrap(), 2);
        // Positions are never reused.
        assert_eq!(set.next_position(&wtxn).unwrap(), 3);

        assert_eq!(set.spend(&mut wtxn, &dup.commitment).unwrap(), Some(2));
        assert_eq!(set.spend(&mut wtxn, &dup.commitment).unwrap(), None);
        assert!(!set.contains(&wtxn, &dup.commitment).unwrap());
        assert!(!set.spend_at(&mut wtxn, &other.commitment, 0).unwrap());
        assert!(set.spend_at(&mut wtxn, &other.commitment, 1).unwrap());
        assert!(set.is_empty(&wtxn).unwrap());
        assert_eq!(set.root(&wtxn).unwrap(), empty_root());
        assert_eq!(set.tree().stored_nodes(&wtxn).unwrap(), 0);
        // Non-membership proof for a spent position.
        let proof = set.prove(&wtxn, 0).unwrap();
        assert!(proof.verify(&set.root(&wtxn).unwrap(), 0, &EMPTY));
        wtxn.commit().unwrap();
    }

    #[test]
    fn counter_and_index_persist_and_abort_cleanly() {
        let dir = TempDir::new("persist");
        let o = Output::new(&pk(4), 5);
        let root;
        {
            let env = open_env(&dir.0, 64 << 20).unwrap();
            let mut wtxn = env.write_txn().unwrap();
            let set = UtxoSet::open(&env, &mut wtxn, "utxo").unwrap();
            set.add(&mut wtxn, &o).unwrap();
            set.add(&mut wtxn, &o).unwrap();
            root = set.root(&wtxn).unwrap();
            wtxn.commit().unwrap();

            let mut wtxn = env.write_txn().unwrap();
            set.spend(&mut wtxn, &o.commitment).unwrap();
            set.add(&mut wtxn, &o).unwrap();
            wtxn.abort();
        }
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let set = UtxoSet::open(&env, &mut wtxn, "utxo").unwrap();
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(set.root(&rtxn).unwrap(), root);
        assert_eq!(set.next_position(&rtxn).unwrap(), 2);
        assert_eq!(set.positions(&rtxn, &o.commitment).unwrap(), vec![0, 1]);
    }
}
