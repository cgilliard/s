//! The name half of the state tree: a binary trie keyed by the hash of a
//! name, with leaves at variable depth, backed by LMDB.
//!
//! The state tree's root compresses two halves: the left is the depth-39
//! tree of outputs ([`crate::utxo`]), the right is this trie, whose root
//! the [`crate::state_tree::StateTree`] stores as its node at level
//! `DEPTH - 1`, index 1. A name's key is [`KEY_BITS`] bits of the hash of
//! its name ([`key_of`]); the trie's depth `d` corresponds to depth
//! `d + 1` of the state tree, below the bit that chose the half.
//!
//! # Shape
//!
//! The trie is canonical: for a given set of keys there is one shape, so
//! every node computes the same root. A leaf sits at the first depth at
//! which its key's prefix is unique among the keys stored, so a trie of
//! `n` keys has leaves about `log2(n)` deep. Two keys that share a long
//! prefix sit deeper: the internal nodes between the depth where they
//! join the rest and the depth where they part have one empty child. An
//! attacker who wants a name's path longer must register a name whose
//! key shares one more bit of prefix per level, about `2^d` hashes for
//! the `d`-th level, and cannot block the name: a path can grow no deeper
//! than the key is long.
//!
//! Hashing: an internal node is `compress(left, right)` with [`EMPTY`] for
//! an absent child; a leaf is the domain-separated hash of its key and
//! value ([`leaf_hash`]), so a leaf can never be read as an internal node
//! and a path cannot stop early at another name's leaf. The empty trie's
//! root is [`EMPTY_ROOT`], the hash of an empty depth-39 subtree, so a
//! chain without names has the state root it had before names existed.
//!
//! # Proofs
//!
//! A [`NameProof`] is the path from a terminal up to the root: the
//! terminal is the leaf itself (membership), or, for non-membership, the
//! empty slot or the other name's leaf where the key's path ends.
//!
//! # Storage
//!
//! One LMDB database of nodes keyed by depth and prefix (16 bytes), and a
//! count. An internal node stores its hash; a leaf its key, value and
//! hash. Removal exists for undoing a block: consensus never removes a
//! name.

use heed::types::{Bytes, Str, U64};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::poseidon2::{DIGEST, Fp, compress, digest_from_bytes, digest_to_bytes};
use crate::state_tree::{DEPTH, Digest, EMPTY, default_hashes};
use crate::transaction::hash_domain;

/// Bits of a key: four 30-bit limbs of the name's hash.
pub const KEY_BITS: usize = 120;
/// A key's limbs, as the circuit sees them.
pub const KEY_LIMBS: usize = 4;
const LIMB_BITS: usize = 30;
const MASK30: u64 = (1 << LIMB_BITS) - 1;
pub(crate) const DOM_LEAF: u32 = 4;
const PREFIX_BYTES: usize = 15;
const NODE_KEY_BYTES: usize = 1 + PREFIX_BYTES;
const META_COUNT: &str = "count";

const TAG_INTERNAL: u8 = 0;
const TAG_LEAF: u8 = 1;

/// A key: [`KEY_BITS`] bits, the highest first.
pub type Key = u128;

/// The root of a trie with no names: the empty subtree the state tree had
/// there before names.
pub fn empty_root() -> Digest {
    default_hashes()[DEPTH - 1]
}

/// The key of a name's hash: the low 30 bits of its first four elements,
/// the first element highest.
pub fn key_of(hash: &Digest) -> Key {
    let mut key: Key = 0;
    for x in &hash[..KEY_LIMBS] {
        key = key << LIMB_BITS | Key::from(x.to_canonical() as u64 & MASK30);
    }
    key
}

/// A key's limbs, highest first, as field elements.
pub fn key_limbs(key: Key) -> [Fp; KEY_LIMBS] {
    core::array::from_fn(|i| Fp::new(((key >> (LIMB_BITS * (KEY_LIMBS - 1 - i))) as u64 & MASK30) as u32))
}

/// The hash of a leaf holding `value` under `key`.
pub fn leaf_hash(key: Key, value: &Digest) -> Digest {
    let mut input = [Fp::ZERO; KEY_LIMBS + DIGEST];
    input[..KEY_LIMBS].copy_from_slice(&key_limbs(key));
    input[KEY_LIMBS..].copy_from_slice(value);
    hash_domain(DOM_LEAF, &input)
}

/// The direction taken from depth `depth` to `depth + 1`: the key's bit
/// there, `true` for right.
pub fn bit(key: Key, depth: usize) -> bool {
    debug_assert!(depth < KEY_BITS);
    key >> (KEY_BITS - 1 - depth) & 1 == 1
}

/// The first `depth` bits of `key`, the rest zero.
fn prefix(key: Key, depth: usize) -> Key {
    if depth == 0 { 0 } else { key & (!0 << (KEY_BITS - depth)) }
}

/// The depth at which `a` and `b` part: the index of their first
/// differing bit (so both have leaves at that depth plus one).
fn first_difference(a: Key, b: Key) -> usize {
    debug_assert_ne!(a, b);
    (a ^ b).leading_zeros() as usize - (128 - KEY_BITS)
}

fn node_key(depth: usize, prefix: Key) -> [u8; NODE_KEY_BYTES] {
    let mut out = [0u8; NODE_KEY_BYTES];
    out[0] = depth as u8;
    out[1..].copy_from_slice(&prefix.to_be_bytes()[1..]);
    out
}

#[derive(Debug)]
pub enum Error {
    Heed(heed::Error),
    /// The key is already present (insert) or absent (update, remove).
    Present(Key),
    Absent(Key),
    Corrupt(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Heed(e) => write!(f, "lmdb error: {e}"),
            Error::Present(k) => write!(f, "name key {k:030x} is already registered"),
            Error::Absent(k) => write!(f, "name key {k:030x} is not registered"),
            Error::Corrupt(what) => write!(f, "corrupt name trie: {what}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<heed::Error> for Error {
    fn from(e: heed::Error) -> Self {
        Error::Heed(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// A stored node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Node {
    Internal(Digest),
    Leaf { key: Key, value: Digest, hash: Digest },
}

impl Node {
    fn hash(&self) -> Digest {
        match self {
            Node::Internal(h) => *h,
            Node::Leaf { hash, .. } => *hash,
        }
    }

    fn to_bytes(self) -> Vec<u8> {
        match self {
            Node::Internal(h) => {
                let mut v = vec![TAG_INTERNAL];
                v.extend_from_slice(&digest_to_bytes(&h));
                v
            }
            Node::Leaf { key, value, hash } => {
                let mut v = vec![TAG_LEAF];
                v.extend_from_slice(&key.to_be_bytes()[1..]);
                v.extend_from_slice(&digest_to_bytes(&value));
                v.extend_from_slice(&digest_to_bytes(&hash));
                v
            }
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Node> {
        match *bytes.first()? {
            TAG_INTERNAL if bytes.len() == 1 + DIGEST * 4 => Some(Node::Internal(digest_from_bytes(&bytes[1..])?)),
            TAG_LEAF if bytes.len() == 1 + PREFIX_BYTES + 2 * DIGEST * 4 => {
                let mut k = [0u8; 16];
                k[1..].copy_from_slice(&bytes[1..1 + PREFIX_BYTES]);
                let value = digest_from_bytes(&bytes[1 + PREFIX_BYTES..1 + PREFIX_BYTES + DIGEST * 4])?;
                let hash = digest_from_bytes(&bytes[1 + PREFIX_BYTES + DIGEST * 4..])?;
                Some(Node::Leaf { key: Key::from_be_bytes(k), value, hash })
            }
            _ => None,
        }
    }
}

/// What a key's path ends at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    /// An empty slot (non-membership), or the whole trie is empty.
    Empty,
    /// A leaf: the key's own (membership) or another's sharing the prefix
    /// (non-membership).
    Leaf { key: Key, value: Digest },
}

/// The path from a terminal to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameProof {
    pub terminal: Terminal,
    /// Siblings from the terminal's depth up: `siblings[0]` is the sibling
    /// of the terminal, `siblings.last()` the root's other child. The
    /// terminal's depth is their number.
    pub siblings: Vec<Digest>,
}

impl NameProof {
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// The root the proof implies for `key`'s path.
    pub fn root(&self, key: Key) -> Digest {
        let depth = self.depth();
        let mut node = match self.terminal {
            Terminal::Empty if depth == 0 => return empty_root(),
            Terminal::Empty => EMPTY,
            Terminal::Leaf { key, value } => leaf_hash(key, &value),
        };
        for (i, sibling) in self.siblings.iter().enumerate() {
            let d = depth - 1 - i;
            node = if bit(key, d) { compress(sibling, &node) } else { compress(&node, sibling) };
        }
        node
    }

    /// Whether the proof shows `key` holding `value` under `root`.
    pub fn verify_member(&self, root: &Digest, key: Key, value: &Digest) -> bool {
        matches!(self.terminal, Terminal::Leaf { key: k, value: v } if k == key && v == *value)
            && self.depth() <= KEY_BITS
            && self.root(key) == *root
    }

    /// Whether the proof shows `key` absent under `root`: its path ends at
    /// an empty slot, or at another key's leaf whose prefix it shares.
    pub fn verify_absent(&self, root: &Digest, key: Key) -> bool {
        let depth = self.depth();
        let terminal_ok = match self.terminal {
            Terminal::Empty => true,
            Terminal::Leaf { key: k, .. } => k != key && prefix(k, depth) == prefix(key, depth),
        };
        terminal_ok && depth <= KEY_BITS && self.root(key) == *root
    }
}

/// The trie.
#[derive(Clone)]
pub struct NameTrie {
    nodes: Database<Bytes, Bytes>,
    meta: Database<Str, U64<heed::byteorder::LittleEndian>>,
}

impl NameTrie {
    /// Opens the trie stored under `prefix` in `env`, creating its
    /// databases if needed. The transaction must be committed by the caller.
    pub fn open(env: &Env, wtxn: &mut RwTxn, prefix: &str) -> Result<NameTrie> {
        let nodes = env.create_database(wtxn, Some(&format!("{prefix}.nodes")))?;
        let meta = env.create_database(wtxn, Some(&format!("{prefix}.meta")))?;
        Ok(NameTrie { nodes, meta })
    }

    fn node(&self, rtxn: &RoTxn, depth: usize, prefix: Key) -> Result<Option<Node>> {
        match self.nodes.get(rtxn, &node_key(depth, prefix))? {
            None => Ok(None),
            Some(b) => Node::from_bytes(b).map(Some).ok_or(Error::Corrupt("node")),
        }
    }

    fn put(&self, wtxn: &mut RwTxn, depth: usize, prefix: Key, node: Node) -> Result<()> {
        self.nodes.put(wtxn, &node_key(depth, prefix), &node.to_bytes())?;
        Ok(())
    }

    fn delete(&self, wtxn: &mut RwTxn, depth: usize, prefix: Key) -> Result<()> {
        self.nodes.delete(wtxn, &node_key(depth, prefix))?;
        Ok(())
    }

    fn child_hash(&self, rtxn: &RoTxn, depth: usize, prefix: Key) -> Result<Digest> {
        Ok(self.node(rtxn, depth, prefix)?.map_or(EMPTY, |n| n.hash()))
    }

    /// The root: [`empty_root`] with no names.
    pub fn root(&self, rtxn: &RoTxn) -> Result<Digest> {
        Ok(self.node(rtxn, 0, 0)?.map_or_else(empty_root, |n| n.hash()))
    }

    /// Number of names.
    pub fn len(&self, rtxn: &RoTxn) -> Result<u64> {
        Ok(self.meta.get(rtxn, META_COUNT)?.unwrap_or(0))
    }

    pub fn is_empty(&self, rtxn: &RoTxn) -> Result<bool> {
        Ok(self.len(rtxn)? == 0)
    }

    fn add_count(&self, wtxn: &mut RwTxn, delta: i64) -> Result<()> {
        let n = (self.len(wtxn)? as i64 + delta) as u64;
        self.meta.put(wtxn, META_COUNT, &n)?;
        Ok(())
    }

    /// Walks `key`'s path: the depth it ends at and what is there.
    fn walk(&self, rtxn: &RoTxn, key: Key) -> Result<(usize, Option<Node>)> {
        let mut depth = 0;
        loop {
            match self.node(rtxn, depth, prefix(key, depth))? {
                Some(Node::Internal(_)) => depth += 1,
                other => return Ok((depth, other)),
            }
        }
    }

    /// The value under `key`, if present.
    pub fn get(&self, rtxn: &RoTxn, key: Key) -> Result<Option<Digest>> {
        Ok(match self.walk(rtxn, key)?.1 {
            Some(Node::Leaf { key: k, value, .. }) if k == key => Some(value),
            _ => None,
        })
    }

    /// Recomputes the internal nodes on `key`'s path from depth `from`
    /// (exclusive: the node there is already right) up to the root, and
    /// returns the root.
    fn rehash(&self, wtxn: &mut RwTxn, key: Key, from: usize) -> Result<Digest> {
        let mut depth = from;
        while depth > 0 {
            depth -= 1;
            let p = prefix(key, depth);
            let left = self.child_hash(wtxn, depth + 1, p)?;
            let right = self.child_hash(wtxn, depth + 1, p | (1 << (KEY_BITS - 1 - depth)))?;
            self.put(wtxn, depth, p, Node::Internal(compress(&left, &right)))?;
        }
        self.root(wtxn)
    }

    /// Inserts `value` under `key`, which must be absent. Returns the root.
    pub fn insert(&self, wtxn: &mut RwTxn, key: Key, value: &Digest) -> Result<Digest> {
        let hash = leaf_hash(key, value);
        let (depth, found) = self.walk(wtxn, key)?;
        let leaf_depth = match found {
            None => {
                self.put(wtxn, depth, prefix(key, depth), Node::Leaf { key, value: *value, hash })?;
                depth
            }
            Some(Node::Leaf { key: other, .. }) if other == key => return Err(Error::Present(key)),
            Some(other @ Node::Leaf { key: other_key, .. }) => {
                // Both keys share the prefix down to where they part: a
                // chain of internal nodes, then the two leaves.
                let part = first_difference(key, other_key);
                for d in depth..=part {
                    self.put(wtxn, d, prefix(key, d), Node::Internal(EMPTY))?;
                }
                self.put(wtxn, part + 1, prefix(other_key, part + 1), other)?;
                self.put(wtxn, part + 1, prefix(key, part + 1), Node::Leaf { key, value: *value, hash })?;
                part + 1
            }
            Some(Node::Internal(_)) => unreachable!("the walk stops at a leaf or an empty slot"),
        };
        self.add_count(wtxn, 1)?;
        self.rehash(wtxn, key, leaf_depth)
    }

    /// Replaces the value under `key`, which must be present. Returns the
    /// root.
    pub fn update(&self, wtxn: &mut RwTxn, key: Key, value: &Digest) -> Result<Digest> {
        let (depth, found) = self.walk(wtxn, key)?;
        match found {
            Some(Node::Leaf { key: k, .. }) if k == key => {
                self.put(
                    wtxn,
                    depth,
                    prefix(key, depth),
                    Node::Leaf { key, value: *value, hash: leaf_hash(key, value) },
                )?;
                self.rehash(wtxn, key, depth)
            }
            _ => Err(Error::Absent(key)),
        }
    }

    /// Removes `key`, which must be present, restoring the canonical
    /// shape: a leaf left alone under a chain of internal nodes moves up to
    /// the first depth where it has a sibling. Returns the root. For
    /// undoing a block; consensus never removes a name.
    pub fn remove(&self, wtxn: &mut RwTxn, key: Key) -> Result<Digest> {
        let (mut depth, found) = self.walk(wtxn, key)?;
        if !matches!(found, Some(Node::Leaf { key: k, .. }) if k == key) {
            return Err(Error::Absent(key));
        }
        self.delete(wtxn, depth, prefix(key, depth))?;
        self.add_count(wtxn, -1)?;
        if depth > 0 {
            let sibling_prefix = prefix(key, depth) ^ (1 << (KEY_BITS - depth));
            if let Some(leaf @ Node::Leaf { key: other, .. }) = self.node(wtxn, depth, sibling_prefix)? {
                // The sibling leaf climbs while its new sibling is absent.
                self.delete(wtxn, depth, sibling_prefix)?;
                let mut d = depth - 1;
                while d > 0 && self.node(wtxn, d, prefix(other, d) ^ (1 << (KEY_BITS - d)))?.is_none() {
                    self.delete(wtxn, d, prefix(other, d))?;
                    d -= 1;
                }
                self.put(wtxn, d, prefix(other, d), leaf)?;
                depth = d;
            }
        } else {
            return Ok(empty_root());
        }
        // From `depth` up the internal nodes on the key's path still exist
        // (the moved leaf's path is a prefix of the key's).
        self.rehash(wtxn, key, depth)
    }

    /// A membership or non-membership proof for `key`.
    pub fn prove(&self, rtxn: &RoTxn, key: Key) -> Result<NameProof> {
        let (depth, found) = self.walk(rtxn, key)?;
        let terminal = match found {
            None => Terminal::Empty,
            Some(Node::Leaf { key, value, .. }) => Terminal::Leaf { key, value },
            Some(Node::Internal(_)) => unreachable!("the walk stops at a leaf or an empty slot"),
        };
        let mut siblings = Vec::with_capacity(depth);
        for d in (1..=depth).rev() {
            siblings.push(self.child_hash(rtxn, d, prefix(key, d) ^ (1 << (KEY_BITS - d)))?);
        }
        Ok(NameProof { terminal, siblings })
    }

    /// Every `(key, value)` with `lo <= key < hi`, ascending by key.
    pub fn entries_in(&self, rtxn: &RoTxn, lo: Key, hi: Key) -> Result<Vec<(Key, Digest)>> {
        let mut out = Vec::new();
        if lo < hi {
            self.collect(rtxn, 0, 0, lo, hi, &mut out)?;
        }
        Ok(out)
    }

    /// Every `(key, value)`, ascending by key.
    pub fn entries(&self, rtxn: &RoTxn) -> Result<Vec<(Key, Digest)>> {
        self.entries_in(rtxn, 0, Key::MAX)
    }

    fn collect(
        &self,
        rtxn: &RoTxn,
        depth: usize,
        pfx: Key,
        lo: Key,
        hi: Key,
        out: &mut Vec<(Key, Digest)>,
    ) -> Result<()> {
        // The subtree covers keys [pfx, pfx + 2^(KEY_BITS - depth)).
        let span_end = if depth == 0 { Key::MAX } else { pfx + (1 << (KEY_BITS - depth)) - 1 };
        if span_end < lo || pfx >= hi {
            return Ok(());
        }
        match self.node(rtxn, depth, pfx)? {
            None => {}
            Some(Node::Leaf { key, value, .. }) if key >= lo && key < hi => out.push((key, value)),
            Some(Node::Leaf { .. }) => {}
            Some(Node::Internal(_)) => {
                self.collect(rtxn, depth + 1, pfx, lo, hi, out)?;
                self.collect(rtxn, depth + 1, pfx | (1 << (KEY_BITS - 1 - depth)), lo, hi, out)?;
            }
        }
        Ok(())
    }

    /// The node database's statistics.
    pub fn db_stat(&self, rtxn: &RoTxn) -> Result<heed::DatabaseStat> {
        Ok(self.nodes.stat(rtxn)?)
    }

    /// Removes every name.
    pub fn clear(&self, wtxn: &mut RwTxn) -> Result<()> {
        self.nodes.clear(wtxn)?;
        self.meta.clear(wtxn)?;
        Ok(())
    }

    /// Number of stored nodes, for measuring storage.
    pub fn stored_nodes(&self, rtxn: &RoTxn) -> Result<u64> {
        Ok(self.nodes.len(rtxn)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_tree::open_env;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let p = std::env::temp_dir().join(format!("tabminer-name-trie-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn setup(name: &str) -> (TempDir, Env, NameTrie) {
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let trie = NameTrie::open(&env, &mut wtxn, "names").unwrap();
        wtxn.commit().unwrap();
        (dir, env, trie)
    }

    fn val(n: u64) -> Digest {
        let mut d = EMPTY;
        d[0] = Fp::from_u64(n);
        d[7] = Fp::from_u64(n ^ 0xabcd);
        d
    }

    /// The canonical root of a key set, computed from scratch: a leaf at
    /// the first depth where its prefix is unique.
    fn plain_root(entries: &BTreeMap<Key, Digest>) -> Digest {
        fn node(depth: usize, keys: &[(Key, Digest)]) -> Digest {
            match keys {
                [] => EMPTY,
                [(k, v)] => leaf_hash(*k, v),
                _ => {
                    let split = keys.partition_point(|(k, _)| !bit(*k, depth));
                    compress(&node(depth + 1, &keys[..split]), &node(depth + 1, &keys[split..]))
                }
            }
        }
        let keys: Vec<(Key, Digest)> = entries.iter().map(|(k, v)| (*k, *v)).collect();
        if keys.is_empty() { empty_root() } else { node(0, &keys) }
    }

    /// A key sharing the first `bits` bits of `with`, then differing.
    fn colliding(with: Key, bits: usize, tail: u64) -> Key {
        let flip = 1 << (KEY_BITS - 1 - bits);
        (prefix(with, bits) | flip) ^ (Key::from(tail) & (flip - 1))
    }

    #[test]
    fn keys_bits_and_limbs() {
        let mut h = EMPTY;
        h[0] = Fp::new((1 << 30) + 5); // the top bit of an element is dropped
        h[1] = Fp::new(7);
        h[2] = Fp::new(0);
        h[3] = Fp::new(MASK30 as u32);
        h[4] = Fp::new(99); // ignored
        let k = key_of(&h);
        assert_eq!(k, (5u128 << 90) | (7u128 << 60) | MASK30 as u128);
        assert_eq!(key_limbs(k), [Fp::new(5), Fp::new(7), Fp::ZERO, Fp::new(MASK30 as u32)]);
        assert!(!bit(k, 0) && bit(k, 29) && !bit(k, 30) && bit(k, KEY_BITS - 1));
        assert_eq!(prefix(k, 0), 0);
        assert_eq!(prefix(k, 30), 5u128 << 90);
        assert_eq!(first_difference(k, k ^ 1), KEY_BITS - 1);
        assert_eq!(first_difference(k, k ^ (1 << (KEY_BITS - 1))), 0);
        assert_ne!(leaf_hash(k, &val(1)), leaf_hash(k, &val(2)));
        assert_ne!(leaf_hash(k, &val(1)), compress(&key_limbs_digest(k), &val(1)));
    }

    fn key_limbs_digest(k: Key) -> Digest {
        let mut d = EMPTY;
        d[..KEY_LIMBS].copy_from_slice(&key_limbs(k));
        d
    }

    #[test]
    fn matches_the_canonical_shape_through_inserts_updates_and_removals() {
        let (_dir, env, trie) = setup("canonical");
        let mut wtxn = env.write_txn().unwrap();
        let mut plain: BTreeMap<Key, Digest> = BTreeMap::new();
        assert_eq!(trie.root(&wtxn).unwrap(), empty_root());
        let mut rng = 11u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut keys: Vec<Key> = Vec::new();
        for round in 0..400 {
            let r = next() % 10;
            if r < 6 || keys.is_empty() {
                // Insert: a random key, or one colliding with an existing
                // key for many bits, so paths grow deep.
                let key = if keys.len() > 2 && r % 2 == 0 {
                    let with = keys[(next() % keys.len() as u64) as usize];
                    colliding(with, 20 + (next() % 90) as usize, next())
                } else {
                    Key::from(next()) << 56 ^ Key::from(next())
                };
                let key = key & (Key::MAX >> (128 - KEY_BITS));
                if plain.contains_key(&key) {
                    assert!(matches!(trie.insert(&mut wtxn, key, &val(round)), Err(Error::Present(_))));
                    continue;
                }
                let root = trie.insert(&mut wtxn, key, &val(round)).unwrap();
                plain.insert(key, val(round));
                keys.push(key);
                assert_eq!(root, plain_root(&plain), "root after insert {round}");
            } else if r < 8 {
                let key = keys[(next() % keys.len() as u64) as usize];
                let root = trie.update(&mut wtxn, key, &val(1000 + round)).unwrap();
                plain.insert(key, val(1000 + round));
                assert_eq!(root, plain_root(&plain), "root after update {round}");
            } else {
                let key = keys.swap_remove((next() % keys.len() as u64) as usize);
                let root = trie.remove(&mut wtxn, key).unwrap();
                plain.remove(&key);
                assert_eq!(root, plain_root(&plain), "root after removal {round}");
                assert!(matches!(trie.remove(&mut wtxn, key), Err(Error::Absent(_))));
                assert!(matches!(trie.update(&mut wtxn, key, &val(1)), Err(Error::Absent(_))));
            }
            assert_eq!(trie.len(&wtxn).unwrap(), plain.len() as u64);
        }
        // Lookups, proofs and iteration agree with the map.
        let root = trie.root(&wtxn).unwrap();
        for (k, v) in &plain {
            assert_eq!(trie.get(&wtxn, *k).unwrap(), Some(*v));
            let proof = trie.prove(&wtxn, *k).unwrap();
            assert!(proof.verify_member(&root, *k, v));
            assert!(!proof.verify_member(&root, *k, &val(u64::MAX)));
            assert!(!proof.verify_absent(&root, *k));
        }
        for i in 0..50u64 {
            let absent = colliding(keys[i as usize % keys.len()], 10 + (i as usize * 2) % 100, next());
            if plain.contains_key(&absent) {
                continue;
            }
            assert_eq!(trie.get(&wtxn, absent).unwrap(), None);
            let proof = trie.prove(&wtxn, absent).unwrap();
            assert!(proof.verify_absent(&root, absent), "non-membership {i}");
            assert!(!proof.verify_member(&root, absent, &val(1)));
            // The same path does not prove a key with a different prefix absent.
            let other = absent ^ (1 << (KEY_BITS - 1));
            assert!(!proof.verify_absent(&root, other) || proof.depth() == 0);
        }
        let all = trie.entries(&wtxn).unwrap();
        assert_eq!(all, plain.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>());
        let mid = keys[keys.len() / 2];
        let low = trie.entries_in(&wtxn, 0, mid).unwrap();
        let high = trie.entries_in(&wtxn, mid, Key::MAX).unwrap();
        assert_eq!(low.len() + high.len(), all.len());
        assert!(low.iter().all(|(k, _)| *k < mid) && high.iter().all(|(k, _)| *k >= mid));
        // Everything out leaves nothing behind.
        for k in keys {
            trie.remove(&mut wtxn, k).unwrap();
        }
        assert_eq!(trie.root(&wtxn).unwrap(), empty_root());
        assert_eq!(trie.stored_nodes(&wtxn).unwrap(), 0);
        assert!(trie.prove(&wtxn, 5).unwrap().verify_absent(&empty_root(), 5));
    }

    #[test]
    fn depth_follows_shared_prefixes() {
        let (_dir, env, trie) = setup("depth");
        let mut wtxn = env.write_txn().unwrap();
        let a: Key = 0b1010 << (KEY_BITS - 4);
        trie.insert(&mut wtxn, a, &val(1)).unwrap();
        // Alone, a leaf sits at the root.
        assert_eq!(trie.prove(&wtxn, a).unwrap().depth(), 0);
        assert_eq!(trie.root(&wtxn).unwrap(), leaf_hash(a, &val(1)));
        // A key parting at bit 0 puts both at depth 1.
        let b = a ^ (1 << (KEY_BITS - 1));
        trie.insert(&mut wtxn, b, &val(2)).unwrap();
        assert_eq!(trie.prove(&wtxn, a).unwrap().depth(), 1);
        assert_eq!(trie.prove(&wtxn, b).unwrap().depth(), 1);
        // One sharing 80 bits with `a` pushes `a` to depth 81, `b` stays.
        let c = colliding(a, 80, 3);
        trie.insert(&mut wtxn, c, &val(3)).unwrap();
        assert_eq!(trie.prove(&wtxn, a).unwrap().depth(), 81);
        assert_eq!(trie.prove(&wtxn, c).unwrap().depth(), 81);
        assert_eq!(trie.prove(&wtxn, b).unwrap().depth(), 1);
        // The deepest possible: parting at the last bit.
        let d = a ^ 1;
        trie.insert(&mut wtxn, d, &val(4)).unwrap();
        assert_eq!(trie.prove(&wtxn, a).unwrap().depth(), KEY_BITS);
        assert_eq!(trie.prove(&wtxn, d).unwrap().depth(), KEY_BITS);
        let root = trie.root(&wtxn).unwrap();
        for (k, v) in [(a, 1), (b, 2), (c, 3), (d, 4)] {
            assert!(trie.prove(&wtxn, k).unwrap().verify_member(&root, k, &val(v)));
        }
        // A key whose path ends at `c`'s leaf is proven absent by it; one
        // running down `a`'s chain past where `c` parted ends at an empty
        // slot.
        let e = colliding(c, 85, 5);
        let proof = trie.prove(&wtxn, e).unwrap();
        assert!(matches!(proof.terminal, Terminal::Leaf { key, .. } if key == c));
        assert_eq!(proof.depth(), 81);
        assert!(proof.verify_absent(&root, e));
        let f = colliding(a, 90, 5);
        let proof = trie.prove(&wtxn, f).unwrap();
        assert_eq!((proof.terminal, proof.depth()), (Terminal::Empty, 91));
        assert!(proof.verify_absent(&root, f));
        // Removing `d` lifts `a` back to depth 81; removing `c` to depth 1.
        trie.remove(&mut wtxn, d).unwrap();
        assert_eq!(trie.prove(&wtxn, a).unwrap().depth(), 81);
        trie.remove(&mut wtxn, c).unwrap();
        assert_eq!(trie.prove(&wtxn, a).unwrap().depth(), 1);
        trie.remove(&mut wtxn, b).unwrap();
        assert_eq!(trie.prove(&wtxn, a).unwrap().depth(), 0);
        assert_eq!(trie.stored_nodes(&wtxn).unwrap(), 1);
    }

    #[test]
    fn persists_and_aborts_cleanly() {
        let (_dir, env, trie) = setup("persist");
        let mut wtxn = env.write_txn().unwrap();
        let root = trie.insert(&mut wtxn, 7, &val(7)).unwrap();
        wtxn.commit().unwrap();
        let mut wtxn = env.write_txn().unwrap();
        trie.insert(&mut wtxn, 8, &val(8)).unwrap();
        wtxn.abort();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(trie.root(&rtxn).unwrap(), root);
        assert_eq!(trie.len(&rtxn).unwrap(), 1);
        assert_eq!(trie.get(&rtxn, 8).unwrap(), None);
    }
}
