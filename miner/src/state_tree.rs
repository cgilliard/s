//! Persistent sparse Merkle tree of depth [`DEPTH`] backed by LMDB (heed).
//!
//! Keys are integers below `2^DEPTH`; values are 32-byte digests, with the
//! all-zero digest meaning "empty". Internal nodes are
//! `poseidon2::compress(left, right)`, one permutation each. The tree is
//! sparse: a subtree containing no non-empty leaf has a fixed default hash
//! per level, and such nodes are never written to the database. Setting a
//! leaf back to empty removes its path, so a tree with no leaves stores no
//! nodes at all.
//!
//! Every operation runs inside a caller-supplied heed transaction so that the
//! tree can be updated atomically together with other databases in the same
//! environment (for example block storage). The root is the node at
//! level `DEPTH`, index 0.
//!
//! A tree can also store only the levels from some `base` up, with the
//! caller keeping the leaves and recomputing the levels below from them
//! (see [`StateTree::open_from`]): the UTXO set does this, storing nothing
//! below subtrees of 256 positions.
//!
//! Database layout: one named LMDB database with integer keys, `DEPTH -
//! level` in the top byte and the index within that level below it,
//! mapping to the 32-byte node digest.

use std::path::Path;
use std::sync::OnceLock;

use heed::byteorder::NativeEndian;
use heed::types::{Bytes, U64};
use heed::{Database, DatabaseFlags, Env, EnvOpenOptions, RoTxn, RwTxn};

use crate::poseidon2::{DIGEST, Fp, compress, compress_all, digest_from_bytes, digest_to_bytes};

/// Tree depth: number of levels between a leaf and the root.
pub const DEPTH: usize = 40;
/// Number of addressable leaves.
pub const CAPACITY: u64 = 1 << DEPTH;
/// A leaf value or node hash.
pub type Digest = [Fp; DIGEST];
/// The value of an empty leaf.
pub const EMPTY: Digest = [Fp::ZERO; DIGEST];

/// Node keys: `DEPTH - level` in the top byte and the index below it, as
/// an LMDB integer key (native byte order, little endian on every platform
/// tabminer runs on), so nodes sort from the root down and then by index.
type NodeKey = U64<NativeEndian>;

/// Errors from tree operations.
#[derive(Debug)]
pub enum Error {
    /// Underlying LMDB failure.
    Heed(heed::Error),
    /// Key is not below [`CAPACITY`].
    KeyOutOfRange(u64),
    /// A stored node could not be decoded as a digest.
    Corrupt { level: u8, index: u64 },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Heed(e) => write!(f, "lmdb error: {e}"),
            Error::KeyOutOfRange(k) => write!(f, "key {k} is not below 2^{DEPTH}"),
            Error::Corrupt { level, index } => {
                write!(f, "corrupt node at level {level} index {index}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Heed(e) => Some(e),
            _ => None,
        }
    }
}

impl From<heed::Error> for Error {
    fn from(e: heed::Error) -> Self {
        Error::Heed(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Default hash of an empty subtree at each level: `defaults[0] == EMPTY`,
/// `defaults[l] == compress(defaults[l-1], defaults[l-1])`.
pub fn default_hashes() -> &'static [Digest; DEPTH + 1] {
    static DEFAULTS: OnceLock<[Digest; DEPTH + 1]> = OnceLock::new();
    DEFAULTS.get_or_init(|| {
        let mut d = [EMPTY; DEPTH + 1];
        for l in 1..=DEPTH {
            d[l] = compress(&d[l - 1], &d[l - 1]);
        }
        d
    })
}

/// Root of a tree with no leaves.
pub fn empty_root() -> Digest {
    default_hashes()[DEPTH]
}

/// Root of the subtree of height `level` whose leaves start at
/// `first = index << level`, from its non-empty leaves `(key, value)`
/// (keys in that range, ascending, distinct).
pub fn subtree_root(level: usize, first: u64, leaves: &[(u64, Digest)]) -> Digest {
    let mut nodes: Vec<(u64, Digest)> = leaves.iter().map(|&(k, v)| (k - first, v)).collect();
    for l in 0..level {
        nodes = parents(l, &nodes);
    }
    nodes.first().map_or(default_hashes()[level], |&(_, v)| v)
}

/// Root of the whole tree from the roots of its subtrees of height `level`
/// at indices `0..roots.len()`; every later subtree is empty.
pub fn root_from_subtrees(level: usize, roots: &[Digest]) -> Digest {
    // The subtree roots are leaves of a tree of height DEPTH - level whose
    // empty leaves are the default subtree root.
    let mut nodes: Vec<(u64, Digest)> = roots.iter().enumerate().map(|(i, r)| (i as u64, *r)).collect();
    for l in level..DEPTH {
        nodes = parents(l, &nodes);
    }
    nodes.first().map_or(empty_root(), |&(_, v)| v)
}

fn node_key(level: usize, index: u64) -> u64 {
    // Lowest levels last: new nodes there, the most numerous, are then
    // appended at the end of the database, which LMDB packs tightly.
    ((DEPTH - level) as u64) << 56 | index
}

/// The parents of the non-empty nodes `nodes` (ascending) at `level`,
/// hashed eight at a time.
fn parents(level: usize, nodes: &[(u64, Digest)]) -> Vec<(u64, Digest)> {
    let default = &default_hashes()[level];
    let mut keys = Vec::with_capacity(nodes.len().div_ceil(2));
    let mut pairs: Vec<(&Digest, &Digest)> = Vec::with_capacity(nodes.len().div_ceil(2));
    let mut i = 0;
    while i < nodes.len() {
        let (k, v) = &nodes[i];
        let (left, right, step) = if k & 1 == 0 {
            match nodes.get(i + 1) {
                Some((k2, v2)) if *k2 == k + 1 => (v, v2, 2),
                _ => (v, default, 1),
            }
        } else {
            (default, v, 1)
        };
        keys.push(k >> 1);
        pairs.push((left, right));
        i += step;
    }
    keys.into_iter().zip(compress_all(&pairs)).collect()
}

/// The root of the subtree of height `level` starting at leaf `first`
/// (as [`subtree_root`]) and the siblings, from the leaves up, of the
/// leaf `key` in it.
pub fn subtree_path(level: usize, first: u64, leaves: &[(u64, Digest)], key: u64) -> (Digest, Vec<Digest>) {
    let mut nodes: Vec<(u64, Digest)> = leaves.iter().map(|&(k, v)| (k - first, v)).collect();
    let mut idx = key - first;
    let mut siblings = Vec::with_capacity(level);
    for l in 0..level {
        let want = idx ^ 1;
        siblings.push(match nodes.binary_search_by_key(&want, |&(k, _)| k) {
            Ok(i) => nodes[i].1,
            Err(_) => default_hashes()[l],
        });
        nodes = parents(l, &nodes);
        idx >>= 1;
    }
    (nodes.first().map_or(default_hashes()[level], |&(_, v)| v), siblings)
}

/// Opens (creating if needed) an LMDB environment at `path` with the given
/// maximum map size in bytes. The map size is an upper bound on the file
/// size, not an allocation; choose it generously.
pub fn open_env(path: &Path, map_size: usize) -> Result<Env> {
    std::fs::create_dir_all(path).map_err(heed::Error::Io)?;
    // SAFETY: heed marks `open` unsafe because opening the same environment
    // twice in one process, or deleting its files while open, is undefined
    // behaviour. Callers must open each path once per process.
    let env = unsafe { EnvOpenOptions::new().map_size(map_size).max_dbs(16).open(path)? };
    Ok(env)
}

/// A Merkle inclusion proof: the sibling hash at every level from the leaf
/// (index 0) up to just below the root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proof {
    pub siblings: [Digest; DEPTH],
}

impl Proof {
    /// Serialized size in bytes.
    pub const SIZE: usize = DEPTH * DIGEST * 4;

    /// Recomputes the root implied by this proof for `(key, value)`.
    pub fn root(&self, key: u64, value: &Digest) -> Digest {
        let mut node = *value;
        let mut idx = key;
        for sibling in &self.siblings {
            node = if idx & 1 == 0 { compress(&node, sibling) } else { compress(sibling, &node) };
            idx >>= 1;
        }
        node
    }

    /// Checks that `(key, value)` is a leaf of the tree with root `root`.
    /// With `value == EMPTY` this is a proof of non-membership.
    pub fn verify(&self, root: &Digest, key: u64, value: &Digest) -> bool {
        key < CAPACITY && self.root(key, value) == *root
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        for s in &self.siblings {
            out.extend_from_slice(&digest_to_bytes(s));
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Proof> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        let mut siblings = [EMPTY; DEPTH];
        for (s, chunk) in siblings.iter_mut().zip(bytes.chunks_exact(DIGEST * 4)) {
            *s = digest_from_bytes(chunk)?;
        }
        Some(Proof { siblings })
    }
}

/// Handle to a sparse Merkle tree stored in one named LMDB database.
///
/// The tree stores the nodes at levels `base` and above; with `base == 0`
/// it is an ordinary tree of leaves. With a higher base the caller keeps
/// the leaves itself and gives the tree the root of each subtree of
/// height `base` ([`StateTree::set`]): the levels below are recomputed
/// from the leaves when needed instead of stored, which is most of a
/// sparse tree's nodes.
#[derive(Clone)]
pub struct StateTree {
    db: Database<NodeKey, Bytes>,
    base: usize,
}

impl StateTree {
    /// Opens the tree of leaves stored under `name` in `env`, creating the
    /// database if it does not exist. The transaction must be committed by
    /// the caller.
    pub fn open(env: &Env, wtxn: &mut RwTxn, name: &str) -> Result<StateTree> {
        StateTree::open_from(env, wtxn, name, 0)
    }

    /// Opens a tree storing levels `base` and above.
    pub fn open_from(env: &Env, wtxn: &mut RwTxn, name: &str, base: usize) -> Result<StateTree> {
        assert!(base <= DEPTH);
        let db = env
            .database_options()
            .types::<NodeKey, Bytes>()
            .name(name)
            .flags(DatabaseFlags::INTEGER_KEY)
            .create(wtxn)?;
        Ok(StateTree { db, base })
    }

    /// The lowest stored level.
    pub fn base(&self) -> usize {
        self.base
    }

    fn check_key(key: u64) -> Result<()> {
        if key < CAPACITY { Ok(()) } else { Err(Error::KeyOutOfRange(key)) }
    }

    /// Reads a stored node (level at least the base), returning the level
    /// default if it is not stored.
    pub fn node(&self, rtxn: &RoTxn, level: usize, index: u64) -> Result<Digest> {
        debug_assert!(level >= self.base);
        match self.db.get(rtxn, &node_key(level, index))? {
            Some(bytes) => digest_from_bytes(bytes).ok_or(Error::Corrupt { level: level as u8, index }),
            None => Ok(default_hashes()[level]),
        }
    }

    /// Writes a node, deleting it instead if it equals the level default.
    fn put_node(&self, wtxn: &mut RwTxn, level: usize, index: u64, value: &Digest) -> Result<()> {
        let key = node_key(level, index);
        if *value == default_hashes()[level] {
            self.db.delete(wtxn, &key)?;
        } else {
            self.db.put(wtxn, &key, &digest_to_bytes(value))?;
        }
        Ok(())
    }

    /// Current root.
    pub fn root(&self, rtxn: &RoTxn) -> Result<Digest> {
        self.node(rtxn, DEPTH, 0)
    }

    /// Sets the node at the base level, `index`, and recomputes the path
    /// to the root. Returns the new root.
    pub fn set(&self, wtxn: &mut RwTxn, index: u64, value: &Digest) -> Result<Digest> {
        if index >= 1 << (DEPTH - self.base) {
            return Err(Error::KeyOutOfRange(index));
        }
        let mut idx = index;
        let mut node = *value;
        self.put_node(wtxn, self.base, idx, &node)?;
        for level in self.base + 1..=DEPTH {
            let sibling = self.node(wtxn, level - 1, idx ^ 1)?;
            node = if idx & 1 == 0 { compress(&node, &sibling) } else { compress(&sibling, &node) };
            idx >>= 1;
            self.put_node(wtxn, level, idx, &node)?;
        }
        Ok(node)
    }

    /// Fills an empty tree from its non-default base-level nodes, ascending
    /// by index, writing every level at once. Returns the root.
    pub fn build(&self, wtxn: &mut RwTxn, nodes: &[(u64, Digest)]) -> Result<Digest> {
        self.build_from(wtxn, self.base, nodes)
    }

    /// Writes the non-default nodes `nodes` (ascending) at `level`, at
    /// least the base, and every level above them. Returns the root.
    pub fn build_from(&self, wtxn: &mut RwTxn, level: usize, nodes: &[(u64, Digest)]) -> Result<Digest> {
        assert!(level >= self.base);
        let mut level_nodes: Vec<(u64, Digest)> = nodes.to_vec();
        for level in level..=DEPTH {
            for (i, v) in &level_nodes {
                self.put_node(wtxn, level, *i, v)?;
            }
            if level == DEPTH {
                break;
            }
            level_nodes = parents(level, &level_nodes);
        }
        self.root(wtxn)
    }

    /// Writes one subtree with its top at `top`: its non-default base-level
    /// nodes `nodes` (ascending, all under one node at `top`) and every
    /// level up to `top`. Returns the subtree's root.
    pub fn write_subtree(&self, wtxn: &mut RwTxn, top: usize, index: u64, nodes: &[(u64, Digest)]) -> Result<Digest> {
        assert!(top >= self.base && top <= DEPTH);
        let mut level_nodes: Vec<(u64, Digest)> = nodes.to_vec();
        for level in self.base..top {
            for (i, v) in &level_nodes {
                self.put_node(wtxn, level, *i, v)?;
            }
            level_nodes = parents(level, &level_nodes);
        }
        let root = level_nodes.first().map_or(default_hashes()[top], |&(_, v)| v);
        self.put_node(wtxn, top, index, &root)?;
        Ok(root)
    }

    /// Deletes every node.
    pub fn clear(&self, wtxn: &mut RwTxn) -> Result<()> {
        Ok(self.db.clear(wtxn)?)
    }

    /// The siblings from the base level up to just below the root, for
    /// the base-level node `index`.
    pub fn upper_siblings(&self, rtxn: &RoTxn, index: u64) -> Result<Vec<Digest>> {
        (self.base..DEPTH).map(|level| self.node(rtxn, level, (index >> (level - self.base)) ^ 1)).collect()
    }

    /// Value of leaf `key`, [`EMPTY`] if unset (a tree of leaves only).
    pub fn get(&self, rtxn: &RoTxn, key: u64) -> Result<Digest> {
        assert_eq!(self.base, 0, "leaves are not stored");
        Self::check_key(key)?;
        self.node(rtxn, 0, key)
    }

    /// Sets leaf `key` to `value` (use [`EMPTY`] to clear it) and recomputes
    /// the path to the root. Returns the new root.
    pub fn update(&self, wtxn: &mut RwTxn, key: u64, value: &Digest) -> Result<Digest> {
        assert_eq!(self.base, 0, "leaves are not stored");
        Self::check_key(key)?;
        self.set(wtxn, key, value)
    }

    /// Clears leaf `key`. Returns the new root.
    pub fn remove(&self, wtxn: &mut RwTxn, key: u64) -> Result<Digest> {
        self.update(wtxn, key, &EMPTY)
    }

    /// Applies several updates in order and returns the final root. Atomic
    /// with respect to the enclosing transaction.
    pub fn apply<I>(&self, wtxn: &mut RwTxn, updates: I) -> Result<Digest>
    where
        I: IntoIterator<Item = (u64, Digest)>,
    {
        for (key, value) in updates {
            self.update(wtxn, key, &value)?;
        }
        self.root(wtxn)
    }

    /// Inclusion (or non-membership) proof for leaf `key`.
    pub fn prove(&self, rtxn: &RoTxn, key: u64) -> Result<Proof> {
        assert_eq!(self.base, 0, "leaves are not stored");
        Self::check_key(key)?;
        let mut siblings = [EMPTY; DEPTH];
        for (s, n) in siblings.iter_mut().zip(self.upper_siblings(rtxn, key)?) {
            *s = n;
        }
        Ok(Proof { siblings })
    }

    /// Number of non-default nodes stored.
    pub fn stored_nodes(&self, rtxn: &RoTxn) -> Result<u64> {
        Ok(self.db.len(rtxn)?)
    }

    /// LMDB statistics of the node database, for measuring storage.
    pub fn db_stat(&self, rtxn: &RoTxn) -> Result<heed::DatabaseStat> {
        Ok(self.db.stat(rtxn)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let p = std::env::temp_dir().join(format!("tabminer-state-tree-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn setup(name: &str) -> (TempDir, Env, StateTree) {
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let tree = StateTree::open(&env, &mut wtxn, "state").unwrap();
        wtxn.commit().unwrap();
        (dir, env, tree)
    }

    fn val(n: u32) -> Digest {
        let mut d = EMPTY;
        d[0] = Fp::new(n);
        d[7] = Fp::new(n ^ 0xabcd);
        d
    }

    #[test]
    fn subtree_roots_compose_to_the_root() {
        let dir = std::env::temp_dir().join(format!("tabminer-subtree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let env = open_env(&dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let tree = StateTree::open(&env, &mut wtxn, "t").unwrap();
        let mut leaves: Vec<(u64, Digest)> = Vec::new();
        for k in [0u64, 1, 2, 5, 17, 18, 31, 32, 63, 100] {
            let v = [Fp::new(k as u32 + 1); DIGEST];
            tree.update(&mut wtxn, k, &v).unwrap();
            leaves.push((k, v));
        }
        let root = tree.root(&wtxn).unwrap();
        for level in [0usize, 1, 4, 5] {
            let span = 1u64 << level;
            let count = (101 + span - 1) / span;
            let roots: Vec<Digest> = (0..count)
                .map(|i| {
                    let part: Vec<(u64, Digest)> = leaves.iter().copied().filter(|(k, _)| k / span == i).collect();
                    subtree_root(level, i * span, &part)
                })
                .collect();
            assert_eq!(root_from_subtrees(level, &roots), root, "level {level}");
        }
        assert_eq!(root_from_subtrees(4, &[]), empty_root());
        assert_eq!(subtree_root(3, 8, &[]), default_hashes()[3]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Independent root computation by recursion over the sparse key set.
    fn reference_root(leaves: &BTreeMap<u64, Digest>, level: usize, index: u64) -> Digest {
        let lo = index << level;
        let hi = lo + ((1u64 << level) - 1);
        if leaves.range(lo..=hi).next().is_none() {
            return default_hashes()[level];
        }
        if level == 0 {
            return leaves[&lo];
        }
        let l = reference_root(leaves, level - 1, 2 * index);
        let r = reference_root(leaves, level - 1, 2 * index + 1);
        compress(&l, &r)
    }

    #[test]
    fn defaults_and_empty_root() {
        let d = default_hashes();
        assert_eq!(d[0], EMPTY);
        assert_eq!(d[1], compress(&EMPTY, &EMPTY));
        assert_eq!(d[DEPTH], empty_root());
        assert_ne!(empty_root(), EMPTY);
        let (_dir, env, tree) = setup("empty");
        let rtxn = env.read_txn().unwrap();
        assert_eq!(tree.root(&rtxn).unwrap(), empty_root());
        assert_eq!(tree.get(&rtxn, 12345).unwrap(), EMPTY);
        assert_eq!(tree.stored_nodes(&rtxn).unwrap(), 0);
        // Non-membership proof against the empty tree.
        let proof = tree.prove(&rtxn, 12345).unwrap();
        assert!(proof.verify(&empty_root(), 12345, &EMPTY));
        assert!(!proof.verify(&empty_root(), 12345, &val(1)));
    }

    #[test]
    fn matches_reference_and_proofs_verify() {
        let (_dir, env, tree) = setup("reference");
        let keys = [0u64, 1, 2, 3, 1 << 20, (1 << 20) + 1, CAPACITY - 1, CAPACITY - 2, 777_777_777];
        let mut leaves = BTreeMap::new();
        let mut wtxn = env.write_txn().unwrap();
        for (i, &k) in keys.iter().enumerate() {
            let v = val(i as u32 + 1);
            let root = tree.update(&mut wtxn, k, &v).unwrap();
            leaves.insert(k, v);
            assert_eq!(root, reference_root(&leaves, DEPTH, 0), "after inserting {k}");
        }
        wtxn.commit().unwrap();

        let rtxn = env.read_txn().unwrap();
        let root = tree.root(&rtxn).unwrap();
        for (&k, v) in &leaves {
            assert_eq!(tree.get(&rtxn, k).unwrap(), *v);
            let proof = tree.prove(&rtxn, k).unwrap();
            assert!(proof.verify(&root, k, v), "proof for {k}");
            assert!(!proof.verify(&root, k, &EMPTY));
            assert!(!proof.verify(&root, k ^ 1, v));
            assert!(!proof.verify(&empty_root(), k, v));
            let back = Proof::from_bytes(&proof.to_bytes()).unwrap();
            assert_eq!(back, proof);
        }
        // Non-membership of a key next to a stored one.
        let proof = tree.prove(&rtxn, 4).unwrap();
        assert!(proof.verify(&root, 4, &EMPTY));
        assert!(Proof::from_bytes(&[0u8; Proof::SIZE - 1]).is_none());
    }

    #[test]
    fn overwrite_and_remove() {
        let (_dir, env, tree) = setup("remove");
        let mut wtxn = env.write_txn().unwrap();
        tree.update(&mut wtxn, 5, &val(1)).unwrap();
        tree.update(&mut wtxn, 6, &val(2)).unwrap();
        let root_two = tree.root(&wtxn).unwrap();
        tree.update(&mut wtxn, 6, &val(3)).unwrap();
        assert_ne!(tree.root(&wtxn).unwrap(), root_two);
        tree.update(&mut wtxn, 6, &val(2)).unwrap();
        assert_eq!(tree.root(&wtxn).unwrap(), root_two);

        let root_one = {
            let mut leaves = BTreeMap::new();
            leaves.insert(5, val(1));
            reference_root(&leaves, DEPTH, 0)
        };
        assert_eq!(tree.remove(&mut wtxn, 6).unwrap(), root_one);
        assert_eq!(tree.get(&wtxn, 6).unwrap(), EMPTY);
        // Only the path of key 5 remains: one node per level.
        assert_eq!(tree.stored_nodes(&wtxn).unwrap(), (DEPTH + 1) as u64);
        assert_eq!(tree.remove(&mut wtxn, 5).unwrap(), empty_root());
        assert_eq!(tree.stored_nodes(&wtxn).unwrap(), 0);
        // Removing an absent key is a no-op.
        assert_eq!(tree.remove(&mut wtxn, 99).unwrap(), empty_root());
        assert_eq!(tree.stored_nodes(&wtxn).unwrap(), 0);
        wtxn.commit().unwrap();
    }

    #[test]
    fn key_range_is_enforced() {
        let (_dir, env, tree) = setup("range");
        let mut wtxn = env.write_txn().unwrap();
        assert!(matches!(tree.update(&mut wtxn, CAPACITY, &val(1)), Err(Error::KeyOutOfRange(_))));
        assert!(matches!(tree.get(&wtxn, u64::MAX), Err(Error::KeyOutOfRange(_))));
        assert!(matches!(tree.prove(&wtxn, CAPACITY), Err(Error::KeyOutOfRange(_))));
        tree.update(&mut wtxn, CAPACITY - 1, &val(1)).unwrap();
        let proof = tree.prove(&wtxn, CAPACITY - 1).unwrap();
        assert!(!proof.verify(&tree.root(&wtxn).unwrap(), CAPACITY, &val(1)));
    }

    #[test]
    fn batch_is_atomic_and_state_persists() {
        let dir = TempDir::new("persist");
        let root_after;
        {
            let env = open_env(&dir.0, 64 << 20).unwrap();
            let mut wtxn = env.write_txn().unwrap();
            let tree = StateTree::open(&env, &mut wtxn, "state").unwrap();
            root_after = tree.apply(&mut wtxn, [(10, val(1)), (11, val(2)), (12, val(3))]).unwrap();
            wtxn.commit().unwrap();

            // An aborted transaction leaves no trace.
            let mut wtxn = env.write_txn().unwrap();
            tree.apply(&mut wtxn, [(13, val(4)), (10, EMPTY)]).unwrap();
            assert_ne!(tree.root(&wtxn).unwrap(), root_after);
            wtxn.abort();
            let rtxn = env.read_txn().unwrap();
            assert_eq!(tree.root(&rtxn).unwrap(), root_after);
        }
        // Reopen from disk.
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let tree = StateTree::open(&env, &mut wtxn, "state").unwrap();
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(tree.root(&rtxn).unwrap(), root_after);
        assert_eq!(tree.get(&rtxn, 11).unwrap(), val(2));
        assert_eq!(tree.get(&rtxn, 13).unwrap(), EMPTY);
        let mut leaves = BTreeMap::new();
        leaves.insert(10, val(1));
        leaves.insert(11, val(2));
        leaves.insert(12, val(3));
        assert_eq!(root_after, reference_root(&leaves, DEPTH, 0));
    }
}
