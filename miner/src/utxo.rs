//! The unspent output set: outputs stored in the sparse [`StateTree`] at
//! counter positions.
//!
//! Every output ever created gets the next position from a monotonically
//! increasing counter (positions are never reused), and its leaf, the
//! commitment and memo compressed ([`crate::transaction::leaf`]), is at
//! that position in the tree, so the root covers memos too. Spending an
//! output clears the leaf. Outputs are found by position only: blocks list
//! their inputs' positions, and a transaction input carries its output's
//! position, which nodes check against its commitment ([`UtxoSet::holds`]).
//! Wallets learn their outputs' positions from the blocks that add them.
//!
//! Storage is laid out for a set of hundreds of millions of outputs spread
//! thinly over billions of positions:
//!
//! - `<prefix>.outputs`: the unspent outputs in buckets of consecutive
//!   ones. A bucket's key is the lowest position it covers (8 bytes, big
//!   endian, so byte order is numeric order); it holds the outputs from
//!   there up to the next bucket's key, each a varint, its distance from
//!   the previous position (from the key for the first), then its
//!   commitment and memo (64 bytes). A bucket is at most [`BUCKET_MAX`]
//!   bytes, one LMDB overflow page; full buckets split and emptied ones are
//!   repacked with their neighbours, so pages stay mostly full however
//!   outputs are spent (LMDB's own pages stay about half full under random
//!   deletion).
//! - `<prefix>.tree`: the Merkle tree's nodes from level [`GROUP_LOG`] up
//!   (subtrees of 256 positions). The levels below are recomputed from the
//!   outputs when needed, at most 256 leaves hashed eight at a time, rather
//!   than stored: they are most of a sparse tree's nodes.
//! - `<prefix>.meta`: the counter and the number of unspent outputs.
//!
//! All operations take the caller's transaction so a block can update the
//! set and its own records atomically.

use std::collections::BTreeMap;

use crate::block::BlockOutput;
use crate::poseidon2::digest_from_bytes;
use crate::state_tree::EMPTY;
use crate::transaction::{Memo, leaf};
use heed::byteorder::{BigEndian, LittleEndian};
use heed::types::{Bytes, Str, U64};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::poseidon2::{DIGEST, compress_all, digest_to_bytes};
use crate::state_tree::{self, CAPACITY, Digest, Proof, StateTree, subtree_path, subtree_root, subtree_roots};
use crate::transaction::Commitment;

const COMMITMENT_BYTES: usize = DIGEST * 4;
const META_NEXT_POSITION: &str = "next_position";
const META_COUNT: &str = "count";
/// Height of the subtrees whose roots are the lowest stored tree level.
pub const GROUP_LOG: usize = 8;
const RECORD: usize = 2 * COMMITMENT_BYTES;
/// Largest bucket: one LMDB overflow page, 4096 bytes less its 16-byte
/// header, so a full bucket wastes nothing.
pub const BUCKET_MAX: usize = 4080;
/// A bucket left smaller than this is repacked with its neighbours when
/// that saves a bucket.
const BUCKET_LOW: usize = BUCKET_MAX * 3 / 4;
/// Threads reading ahead for a batch of spends: they wait on the disk
/// rather than compute, so there are more of them than cores.
const PREFETCH_THREADS: usize = 32;

/// An output's commitment and memo, as stored.
type Record = [u8; RECORD];

/// Errors from UTXO set operations.
#[derive(Debug)]
pub enum Error {
    Tree(state_tree::Error),
    Heed(heed::Error),
    /// All `2^DEPTH` positions have been assigned.
    Full,
    /// A stored record could not be decoded, or an output is missing where
    /// it must be.
    CorruptIndex,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Tree(e) => write!(f, "{e}"),
            Error::Heed(e) => write!(f, "lmdb error: {e}"),
            Error::Full => f.write_str("utxo set is full: no positions left"),
            Error::CorruptIndex => f.write_str("corrupt or missing utxo record"),
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

fn record_bytes(commitment: &Commitment, memo: &Memo) -> Record {
    let mut rec = [0u8; RECORD];
    rec[..COMMITMENT_BYTES].copy_from_slice(&digest_to_bytes(commitment));
    rec[COMMITMENT_BYTES..].copy_from_slice(&digest_to_bytes(memo));
    rec
}

fn parse_record(rec: &[u8]) -> Result<(Commitment, Memo)> {
    Ok((
        digest_from_bytes(&rec[..COMMITMENT_BYTES]).ok_or(Error::CorruptIndex)?,
        digest_from_bytes(&rec[COMMITMENT_BYTES..]).ok_or(Error::CorruptIndex)?,
    ))
}

fn varint_len(mut x: u64) -> usize {
    let mut n = 1;
    while x >= 0x80 {
        x >>= 7;
        n += 1;
    }
    n
}

/// A bucket's outputs `(position, record)`, from the bucket's value under
/// `key`.
fn decode_bucket(key: u64, bytes: &[u8]) -> Result<Vec<(u64, Record)>> {
    let mut out = Vec::with_capacity(bytes.len() / (RECORD + 1));
    let (mut prev, mut i) = (key, 0);
    while i < bytes.len() {
        let (mut delta, mut shift) = (0u64, 0);
        loop {
            let b = *bytes.get(i).ok_or(Error::CorruptIndex)?;
            if shift > 56 {
                return Err(Error::CorruptIndex);
            }
            delta |= u64::from(b & 0x7f) << shift;
            i += 1;
            shift += 7;
            if b < 0x80 {
                break;
            }
        }
        if delta == 0 && !out.is_empty() {
            return Err(Error::CorruptIndex);
        }
        let position = prev.checked_add(delta).filter(|&p| p < CAPACITY).ok_or(Error::CorruptIndex)?;
        let rec = bytes.get(i..i + RECORD).ok_or(Error::CorruptIndex)?;
        out.push((position, rec.try_into().unwrap()));
        (prev, i) = (position, i + RECORD);
    }
    if out.is_empty() {
        return Err(Error::CorruptIndex);
    }
    Ok(out)
}

/// Packs `entries` (ascending) into buckets of at most [`BUCKET_MAX`]
/// bytes, each as full as it goes: the first keyed `key` (at most the
/// first position), the others by their first position.
fn pack_buckets(key: u64, entries: &[(u64, Record)]) -> Vec<(u64, Vec<u8>)> {
    let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut prev = key;
    for &(position, ref rec) in entries {
        let fits = out.last().is_some_and(|(_, b)| b.len() + varint_len(position - prev) + RECORD <= BUCKET_MAX);
        if !fits {
            if !out.is_empty() {
                prev = position;
            }
            out.push((prev, Vec::with_capacity(BUCKET_MAX)));
        }
        let bytes = &mut out.last_mut().unwrap().1;
        let mut d = position - prev;
        while d >= 0x80 {
            bytes.push(d as u8 | 0x80);
            d >>= 7;
        }
        bytes.push(d as u8);
        bytes.extend_from_slice(rec);
        prev = position;
    }
    out
}

/// The roots `(group, root)` of the subtrees of 256 positions holding the
/// outputs at `positions` (ascending) with `records`; groups without
/// outputs are left out. The leaves and every level are hashed across
/// groups, eight at a time, with the groups split among threads.
fn group_roots(positions: &[u64], records: &[(Commitment, Memo)]) -> Vec<(u64, Digest)> {
    // Cut into pieces of whole groups, about one per thread.
    let per = positions.len().div_ceil(crate::parallel::threads()).max(1 << GROUP_LOG);
    let mut cuts = vec![0];
    while let Some(&last) = cuts.last()
        && last < positions.len()
    {
        let mut c = (last + per).min(positions.len());
        while c < positions.len() && positions[c] >> GROUP_LOG == positions[c - 1] >> GROUP_LOG {
            c += 1;
        }
        cuts.push(c);
    }
    let pieces = crate::parallel::par_map_min(cuts.len() - 1, 1, |k| {
        let (a, b) = (cuts[k], cuts[k + 1]);
        let pairs: Vec<(&Digest, &Digest)> = records[a..b].iter().map(|(c, m)| (c, m)).collect();
        let leaves: Vec<(u64, Digest)> = positions[a..b].iter().copied().zip(compress_all(&pairs)).collect();
        subtree_roots(GROUP_LOG, leaves)
    });
    pieces.into_iter().flatten().collect()
}

/// The buckets one operation changes, each read once, changed in memory
/// and written back once by [`UtxoSet::write`].
#[derive(Default)]
struct Edit {
    /// Buckets by key: their outputs, ascending (possibly emptied).
    buckets: BTreeMap<u64, Vec<(u64, Record)>>,
    /// Change in the number of unspent outputs.
    count: i64,
}

/// Handle to the UTXO set.
#[derive(Clone)]
pub struct UtxoSet {
    env: Env,
    tree: StateTree,
    outputs: Database<U64<BigEndian>, Bytes>,
    meta: Database<Str, U64<LittleEndian>>,
}

impl UtxoSet {
    /// Opens the set stored under `prefix` in `env`, creating its databases
    /// if needed. The transaction must be committed by the caller.
    pub fn open(env: &Env, wtxn: &mut RwTxn, prefix: &str) -> Result<UtxoSet> {
        let tree = StateTree::open_from(env, wtxn, &format!("{prefix}.tree"), GROUP_LOG)?;
        let outputs = env.create_database(wtxn, Some(&format!("{prefix}.outputs")))?;
        let meta = env.create_database(wtxn, Some(&format!("{prefix}.meta")))?;
        Ok(UtxoSet { env: env.clone(), tree, outputs, meta })
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

    /// Adds an output with an empty memo; returns its position.
    pub fn add(&self, wtxn: &mut RwTxn, commitment: &Commitment) -> Result<u64> {
        self.add_output(wtxn, &BlockOutput { commitment: *commitment, memo: EMPTY })
    }

    /// Adds an output at the next position: its leaf is the commitment and
    /// memo compressed ([`crate::transaction::leaf`]). Returns the position.
    pub fn add_output(&self, wtxn: &mut RwTxn, output: &BlockOutput) -> Result<u64> {
        let position = self.next_position(wtxn)?;
        self.add_outputs(wtxn, std::slice::from_ref(output))?;
        Ok(position)
    }

    /// Adds outputs at the next positions, in order, updating the tree once
    /// for each subtree they fall in.
    pub fn add_outputs(&self, wtxn: &mut RwTxn, outputs: &[BlockOutput]) -> Result<()> {
        let first = self.next_position(wtxn)?;
        let end = first + outputs.len() as u64;
        if end > CAPACITY {
            return Err(Error::Full);
        }
        let mut edit = Edit::default();
        for (i, o) in outputs.iter().enumerate() {
            self.put_record(wtxn, &mut edit, first + i as u64, &o.commitment, &o.memo)?;
        }
        self.write(wtxn, edit)?;
        self.meta.put(wtxn, META_NEXT_POSITION, &end)?;
        if end > first {
            self.refresh_groups(wtxn, (first >> GROUP_LOG..=(end - 1) >> GROUP_LOG).collect())?;
        }
        Ok(())
    }

    /// Spends the unspent outputs at `positions` (a block's inputs, in
    /// order), updating each subtree they fall in once. Returns their
    /// commitments and memos, or the first position with nothing unspent
    /// (also a position given twice): the caller then discards the
    /// transaction.
    #[allow(clippy::type_complexity)]
    pub fn spend_positions(
        &self,
        wtxn: &mut RwTxn,
        positions: &[u64],
    ) -> Result<core::result::Result<Vec<(Commitment, Memo)>, u64>> {
        self.prefetch(positions.iter().map(|p| p >> GROUP_LOG).collect());
        let mut edit = Edit::default();
        let mut spent = Vec::with_capacity(positions.len());
        for &p in positions {
            let Some(rec) = self.remove_record(wtxn, &mut edit, p, None)? else {
                return Ok(Err(p));
            };
            spent.push(rec);
        }
        self.write(wtxn, edit)?;
        self.refresh_groups(wtxn, positions.iter().map(|p| p >> GROUP_LOG).collect())?;
        Ok(Ok(spent))
    }

    /// Restores spent outputs `(position, commitment, memo)`: the inverse
    /// of [`UtxoSet::spend_positions`].
    pub fn restore(&self, wtxn: &mut RwTxn, outputs: &[(u64, Commitment, Memo)]) -> Result<()> {
        self.prefetch(outputs.iter().map(|o| o.0 >> GROUP_LOG).collect());
        let mut edit = Edit::default();
        for (p, c, m) in outputs {
            if *p >= CAPACITY {
                return Err(Error::Full);
            }
            self.put_record(wtxn, &mut edit, *p, c, m)?;
        }
        self.write(wtxn, edit)?;
        self.refresh_groups(wtxn, outputs.iter().map(|o| o.0 >> GROUP_LOG).collect())
    }

    /// Writes an unspent output at `position` without moving the counter.
    pub fn insert_at(&self, wtxn: &mut RwTxn, position: u64, commitment: &Commitment, memo: &Memo) -> Result<()> {
        if position >= CAPACITY {
            return Err(Error::Full);
        }
        let mut edit = Edit::default();
        self.put_record(wtxn, &mut edit, position, commitment, memo)?;
        self.write(wtxn, edit)?;
        self.refresh_group(wtxn, position >> GROUP_LOG)
    }

    /// Fills an empty set from a snapshot: `outputs` ascending by position,
    /// all below `next`, which becomes the counter. Writes each stored tree
    /// node once, so it stays fast for a set of any size.
    pub fn install(&self, wtxn: &mut RwTxn, outputs: &[(u64, Commitment, Memo)], next: u64) -> Result<()> {
        if !self.is_empty(wtxn)? || self.next_position(wtxn)? != 0 || next > CAPACITY {
            return Err(Error::CorruptIndex);
        }
        if outputs.windows(2).any(|w| w[0].0 >= w[1].0) || outputs.last().is_some_and(|o| o.0 >= next) {
            return Err(Error::CorruptIndex);
        }
        self.put_packed(wtxn, outputs)?;
        self.tree.build(wtxn, &Self::roots_of(outputs))?;
        self.meta.put(wtxn, META_NEXT_POSITION, &next)?;
        Ok(())
    }

    /// Stores one part of a snapshot being installed, the subtree of height
    /// `level` at `index`: its unspent outputs (ascending, in the part and
    /// below `next`) and its tree nodes, but nothing above the part.
    /// Returns the part's root. [`UtxoSet::finish_staged`] completes the
    /// tree once every part is in, so a snapshot of any size is installed
    /// a part at a time.
    pub fn stage(
        &self,
        wtxn: &mut RwTxn,
        level: usize,
        index: u64,
        outputs: &[(u64, Commitment, Memo)],
        next: u64,
    ) -> Result<Digest> {
        let (first, end) = (index << level, ((index + 1) << level).min(next));
        if level < GROUP_LOG
            || outputs.windows(2).any(|w| w[0].0 >= w[1].0)
            || outputs.iter().any(|o| o.0 < first || o.0 >= end)
        {
            return Err(Error::CorruptIndex);
        }
        self.put_packed(wtxn, outputs)?;
        Ok(self.tree.write_subtree(wtxn, level, index, &Self::roots_of(outputs))?)
    }

    /// Removes a staged part, the subtree of height `level` at `index`:
    /// its outputs and its tree nodes. Returns the outputs, ascending.
    pub fn unstage(&self, wtxn: &mut RwTxn, level: usize, index: u64) -> Result<Vec<(u64, Commitment, Memo)>> {
        if level < GROUP_LOG {
            return Err(Error::CorruptIndex);
        }
        let (first, end) = (index << level, (index + 1) << level);
        let outputs: Vec<(u64, Commitment, Memo)> =
            self.unspent_in(wtxn, first, end)?.into_iter().map(|(p, (c, m))| (p, c, m)).collect();
        // Staged buckets hold one part's outputs each, keyed within it.
        self.outputs.delete_range(wtxn, &(first..end))?;
        self.add_count(wtxn, -(outputs.len() as i64))?;
        self.tree.clear_subtree(wtxn, level, index)?;
        Ok(outputs)
    }

    /// Completes a staged snapshot: checks that the stored root of every
    /// part matches `roots` (the parts of height `level`, in order), writes
    /// the levels above them and sets the counter to `next`.
    pub fn finish_staged(&self, wtxn: &mut RwTxn, level: usize, roots: &[Digest], next: u64) -> Result<Digest> {
        if roots.len() as u64 != next.div_ceil(1 << level) {
            return Err(Error::CorruptIndex);
        }
        let mut nodes = Vec::new();
        for (p, r) in roots.iter().enumerate() {
            if self.tree.node(wtxn, level, p as u64)? != *r {
                return Err(Error::CorruptIndex);
            }
            if *r != state_tree::default_hashes()[level] {
                nodes.push((p as u64, *r));
            }
        }
        let root = self.tree.build_from(wtxn, level, &nodes)?;
        self.meta.put(wtxn, META_NEXT_POSITION, &next)?;
        Ok(root)
    }

    /// Empties the set.
    pub fn clear(&self, wtxn: &mut RwTxn) -> Result<()> {
        self.tree.clear(wtxn)?;
        self.outputs.clear(wtxn)?;
        self.meta.clear(wtxn)?;
        Ok(())
    }

    /// Sets the next position: for installing a snapshot.
    pub fn set_next_position(&self, wtxn: &mut RwTxn, next: u64) -> Result<()> {
        self.meta.put(wtxn, META_NEXT_POSITION, &next)?;
        Ok(())
    }

    /// Stores `outputs` (ascending, at positions holding nothing, after
    /// every stored bucket's outputs or before the next bucket's key) in
    /// full buckets of their own: for installing a snapshot.
    fn put_packed(&self, wtxn: &mut RwTxn, outputs: &[(u64, Commitment, Memo)]) -> Result<()> {
        let Some(&(first, _, _)) = outputs.first() else {
            return Ok(());
        };
        let entries: Vec<(u64, Record)> = outputs.iter().map(|(p, c, m)| (*p, record_bytes(c, m))).collect();
        for (key, bytes) in pack_buckets(first, &entries) {
            self.outputs.put(wtxn, &key, &bytes)?;
        }
        self.add_count(wtxn, outputs.len() as i64)
    }

    fn add_count(&self, wtxn: &mut RwTxn, delta: i64) -> Result<()> {
        let count = self.len(wtxn)?.checked_add_signed(delta).ok_or(Error::CorruptIndex)?;
        self.meta.put(wtxn, META_COUNT, &count)?;
        Ok(())
    }

    /// Key of the stored bucket covering `position`: the greatest at most
    /// `position`.
    fn bucket_key(&self, rtxn: &RoTxn, position: u64) -> Result<Option<u64>> {
        Ok(self.outputs.rev_range(rtxn, &(..=position))?.next().transpose()?.map(|(k, _)| k))
    }

    /// The outputs of the stored bucket `key`.
    fn bucket(&self, rtxn: &RoTxn, key: u64) -> Result<Vec<(u64, Record)>> {
        decode_bucket(key, self.outputs.get(rtxn, &key)?.ok_or(Error::CorruptIndex)?)
    }

    /// The bucket in `edit` covering `position`, read from the database the
    /// first time; a new one keyed `position` if none does.
    fn load<'e>(&self, rtxn: &RoTxn, edit: &'e mut Edit, position: u64) -> Result<&'e mut Vec<(u64, Record)>> {
        let stored = self.bucket_key(rtxn, position)?;
        let loaded = edit.buckets.range(..=position).next_back().map(|(k, _)| *k);
        let key = match (stored, loaded) {
            (Some(s), Some(l)) => s.max(l),
            (s, l) => s.or(l).unwrap_or(position),
        };
        Ok(match edit.buckets.entry(key) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(if stored == Some(key) { self.bucket(rtxn, key)? } else { Vec::new() })
            }
        })
    }

    /// Stores an output's record in `edit`, replacing any at `position`;
    /// the tree is not updated.
    fn put_record(
        &self,
        wtxn: &mut RwTxn,
        edit: &mut Edit,
        position: u64,
        commitment: &Commitment,
        memo: &Memo,
    ) -> Result<()> {
        let rec = record_bytes(commitment, memo);
        let bucket = self.load(wtxn, edit, position)?;
        match bucket.binary_search_by_key(&position, |e| e.0) {
            Ok(i) => bucket[i].1 = rec,
            Err(i) => {
                bucket.insert(i, (position, rec));
                edit.count += 1;
            }
        }
        Ok(())
    }

    /// Removes the output at `position` in `edit`, if there is one and, when
    /// given, its commitment is `commitment`; the tree is not updated.
    /// Returns its commitment and memo.
    fn remove_record(
        &self,
        wtxn: &mut RwTxn,
        edit: &mut Edit,
        position: u64,
        commitment: Option<&Commitment>,
    ) -> Result<Option<(Commitment, Memo)>> {
        let bucket = self.load(wtxn, edit, position)?;
        let Ok(i) = bucket.binary_search_by_key(&position, |e| e.0) else {
            return Ok(None);
        };
        let (c, m) = parse_record(&bucket[i].1)?;
        if commitment.is_some_and(|x| *x != c) {
            return Ok(None);
        }
        bucket.remove(i);
        edit.count -= 1;
        Ok(Some((c, m)))
    }

    /// Writes back the buckets `edit` changed: full ones split, emptied
    /// ones deleted, and small ones repacked with their neighbours when
    /// that saves a bucket.
    fn write(&self, wtxn: &mut RwTxn, edit: Edit) -> Result<()> {
        let mut small = Vec::new();
        for (key, entries) in edit.buckets {
            let packed = pack_buckets(key, &entries);
            if packed.is_empty() {
                self.outputs.delete(wtxn, &key)?;
            }
            for (k, bytes) in packed {
                if bytes.len() < BUCKET_LOW {
                    small.push(k);
                }
                self.outputs.put(wtxn, &k, &bytes)?;
            }
        }
        for key in small {
            self.repack(wtxn, key)?;
        }
        self.add_count(wtxn, edit.count)
    }

    /// Repacks the bucket `key` (if still stored) with the buckets either
    /// side of it when they fit in fewer.
    fn repack(&self, wtxn: &mut RwTxn, key: u64) -> Result<()> {
        if self.outputs.get(wtxn, &key)?.is_none() {
            return Ok(());
        }
        let mut keys = Vec::with_capacity(3);
        if let Some(prev) = key.checked_sub(1).map(|k| self.bucket_key(wtxn, k)).transpose()?.flatten() {
            keys.push(prev);
        }
        keys.push(key);
        if let Some(item) = self.outputs.range(wtxn, &(key + 1..))?.next() {
            keys.push(item?.0);
        }
        if keys.len() < 2 {
            return Ok(());
        }
        let mut entries = Vec::new();
        for &k in &keys {
            entries.extend(self.bucket(wtxn, k)?);
        }
        let packed = pack_buckets(keys[0], &entries);
        if packed.len() < keys.len() {
            for &k in &keys {
                self.outputs.delete(wtxn, &k)?;
            }
            for (k, bytes) in packed {
                self.outputs.put(wtxn, &k, &bytes)?;
            }
        }
        Ok(())
    }

    /// Reads what changing the subtrees `groups` will read (their buckets
    /// and the tree nodes beside their paths) from other threads, many
    /// reads at once, before the write transaction does: a set larger than
    /// memory then comes off the disk in parallel instead of a page at a
    /// time. It only warms the page cache; errors are left for the real
    /// reads to report.
    fn prefetch(&self, mut groups: Vec<u64>) {
        groups.sort_unstable();
        groups.dedup();
        if groups.len() < 2 * PREFETCH_THREADS {
            return;
        }
        let per = groups.len().div_ceil(PREFETCH_THREADS);
        std::thread::scope(|s| {
            for chunk in groups.chunks(per) {
                s.spawn(move || {
                    let Ok(rtxn) = self.env.read_txn() else {
                        return;
                    };
                    for &g in chunk {
                        let _ = self.scan(&rtxn, g << GROUP_LOG, (g + 1) << GROUP_LOG, |_, _| Ok(()));
                        let _ = self.tree.upper_siblings(&rtxn, g);
                    }
                });
            }
        });
    }

    /// Calls `f` with each unspent output at positions `first..end`,
    /// ascending.
    fn scan(&self, rtxn: &RoTxn, first: u64, end: u64, mut f: impl FnMut(u64, &Record) -> Result<()>) -> Result<()> {
        if end <= first {
            return Ok(());
        }
        let start = self.bucket_key(rtxn, first)?.unwrap_or(first);
        for item in self.outputs.range(rtxn, &(start..end))? {
            let (key, bytes) = item?;
            for (p, rec) in decode_bucket(key, bytes)? {
                if p >= end {
                    break;
                }
                if p >= first {
                    f(p, &rec)?;
                }
            }
        }
        Ok(())
    }

    /// The roots of the groups holding `outputs` (ascending by position).
    fn roots_of(outputs: &[(u64, Commitment, Memo)]) -> Vec<(u64, Digest)> {
        let positions: Vec<u64> = outputs.iter().map(|o| o.0).collect();
        let records: Vec<(Commitment, Memo)> = outputs.iter().map(|o| (o.1, o.2)).collect();
        group_roots(&positions, &records)
    }

    /// Appends the positions and records of the unspent outputs in the
    /// subtree of 256 positions `group`, ascending.
    fn group_records(
        &self,
        rtxn: &RoTxn,
        group: u64,
        positions: &mut Vec<u64>,
        records: &mut Vec<(Commitment, Memo)>,
    ) -> Result<()> {
        self.scan(rtxn, group << GROUP_LOG, (group + 1) << GROUP_LOG, |p, rec| {
            positions.push(p);
            records.push(parse_record(rec)?);
            Ok(())
        })
    }

    /// The leaves of the subtree of 256 positions `group`, ascending.
    pub(crate) fn group_leaves(&self, rtxn: &RoTxn, group: u64) -> Result<Vec<(u64, Digest)>> {
        let (mut positions, mut records) = (Vec::new(), Vec::new());
        self.group_records(rtxn, group, &mut positions, &mut records)?;
        // Leaves are the commitment and memo compressed, hashed eight at
        // a time.
        let pairs: Vec<(&Digest, &Digest)> = records.iter().map(|(c, m)| (c, m)).collect();
        Ok(positions.into_iter().zip(compress_all(&pairs)).collect())
    }

    /// Recomputes the stored roots of the subtrees `groups` (any order,
    /// repeats allowed) and everything above them, once: the outputs are
    /// read first, then hashed together ([`group_roots`]).
    fn refresh_groups(&self, wtxn: &mut RwTxn, mut groups: Vec<u64>) -> Result<()> {
        groups.sort_unstable();
        groups.dedup();
        let (mut positions, mut records) = (Vec::new(), Vec::new());
        for &g in &groups {
            self.group_records(wtxn, g, &mut positions, &mut records)?;
        }
        // Groups left with no outputs go back to the empty subtree's root.
        let mut found = group_roots(&positions, &records).into_iter().peekable();
        let empty = state_tree::default_hashes()[GROUP_LOG];
        let roots: Vec<(u64, Digest)> = groups
            .into_iter()
            .map(|g| match found.next_if(|r| r.0 == g) {
                Some(r) => r,
                None => (g, empty),
            })
            .collect();
        self.tree.set_many(wtxn, &roots)?;
        Ok(())
    }

    /// Recomputes the stored root of subtree `group` and the path above it.
    fn refresh_group(&self, wtxn: &mut RwTxn, group: u64) -> Result<()> {
        let leaves = self.group_leaves(wtxn, group)?;
        self.tree.set(wtxn, group, &subtree_root(GROUP_LOG, group << GROUP_LOG, &leaves))?;
        Ok(())
    }

    /// Commitment and memo of the unspent output at `position`.
    pub fn output_at(&self, rtxn: &RoTxn, position: u64) -> Result<Option<(Commitment, Memo)>> {
        self.record(rtxn, position)
    }

    /// Whether the unspent output at `position` has this commitment.
    pub fn holds(&self, rtxn: &RoTxn, position: u64, commitment: &Commitment) -> Result<bool> {
        Ok(self.record(rtxn, position)?.is_some_and(|(c, _)| c == *commitment))
    }

    /// Spends the output with this commitment at exactly `position`.
    /// Returns `false` if no such unspent output exists.
    pub fn spend_at(&self, wtxn: &mut RwTxn, commitment: &Commitment, position: u64) -> Result<bool> {
        let mut edit = Edit::default();
        if self.remove_record(wtxn, &mut edit, position, Some(commitment))?.is_none() {
            return Ok(false);
        }
        self.write(wtxn, edit)?;
        self.refresh_group(wtxn, position >> GROUP_LOG)?;
        Ok(true)
    }

    /// Restores a spent output and its memo: the inverse of
    /// [`UtxoSet::spend_at`].
    pub fn unspend(&self, wtxn: &mut RwTxn, commitment: &Commitment, memo: &Memo, position: u64) -> Result<()> {
        self.insert_at(wtxn, position, commitment, memo)
    }

    fn record(&self, rtxn: &RoTxn, position: u64) -> Result<Option<(Commitment, Memo)>> {
        let Some(key) = self.bucket_key(rtxn, position)? else {
            return Ok(None);
        };
        let bucket = self.bucket(rtxn, key)?;
        match bucket.binary_search_by_key(&position, |e| e.0) {
            Ok(i) => parse_record(&bucket[i].1).map(Some),
            Err(_) => Ok(None),
        }
    }

    /// The memo of the unspent output at `position` (empty if none).
    pub fn memo(&self, rtxn: &RoTxn, position: u64) -> Result<Memo> {
        Ok(self.record(rtxn, position)?.map_or(EMPTY, |(_, m)| m))
    }

    /// Every unspent output's non-empty memo with its position, in
    /// position order.
    pub fn memos(&self, rtxn: &RoTxn) -> Result<Vec<(u64, Memo)>> {
        let mut out = Vec::new();
        for (position, (_, memo)) in self.unspent(rtxn)? {
            if memo != EMPTY {
                out.push((position, memo));
            }
        }
        Ok(out)
    }

    /// Every unspent output, position order: commitment and memo.
    pub fn unspent(&self, rtxn: &RoTxn) -> Result<Vec<(u64, (Commitment, Memo))>> {
        self.unspent_in(rtxn, 0, CAPACITY)
    }

    /// The unspent outputs at positions `first..end`, ascending.
    pub fn unspent_in(&self, rtxn: &RoTxn, first: u64, end: u64) -> Result<Vec<(u64, (Commitment, Memo))>> {
        let mut out = Vec::new();
        self.scan(rtxn, first, end, |p, rec| {
            out.push((p, parse_record(rec)?));
            Ok(())
        })?;
        Ok(out)
    }

    /// Removes the outputs appended from `first` on, which must be the
    /// last ones added and still unspent, with `commitments` their
    /// commitments in order; the next position becomes `first`.
    pub fn truncate(&self, wtxn: &mut RwTxn, first: u64, commitments: &[Commitment]) -> Result<()> {
        let end = first + commitments.len() as u64;
        if self.next_position(wtxn)? != end {
            return Err(Error::CorruptIndex);
        }
        let mut edit = Edit::default();
        for (i, c) in commitments.iter().enumerate().rev() {
            if self.remove_record(wtxn, &mut edit, first + i as u64, Some(c))?.is_none() {
                return Err(Error::CorruptIndex);
            }
        }
        self.write(wtxn, edit)?;
        if end > first {
            self.refresh_groups(wtxn, (first >> GROUP_LOG..=(end - 1) >> GROUP_LOG).collect())?;
        }
        self.meta.put(wtxn, META_NEXT_POSITION, &first)?;
        Ok(())
    }

    /// Commitment of the unspent output at `position`, or the empty digest
    /// if spent or never assigned.
    pub fn get(&self, rtxn: &RoTxn, position: u64) -> Result<Digest> {
        Ok(self.record(rtxn, position)?.map_or(EMPTY, |(c, _)| c))
    }

    /// The tree leaf at `position`: commitment and memo compressed, or the
    /// empty digest.
    pub fn leaf_at(&self, rtxn: &RoTxn, position: u64) -> Result<Digest> {
        Ok(self.record(rtxn, position)?.map_or(EMPTY, |(c, m)| leaf(&c, &m)))
    }

    /// Root of the stored subtree of height `level` (at least
    /// [`GROUP_LOG`]) at `index`.
    pub fn subtree(&self, rtxn: &RoTxn, level: usize, index: u64) -> Result<Digest> {
        Ok(self.tree.node(rtxn, level, index)?)
    }

    /// Merkle proof for the leaf at `position`.
    pub fn prove(&self, rtxn: &RoTxn, position: u64) -> Result<Proof> {
        if position >= CAPACITY {
            return Err(state_tree::Error::KeyOutOfRange(position).into());
        }
        let group = position >> GROUP_LOG;
        let leaves = self.group_leaves(rtxn, group)?;
        let (_, low) = subtree_path(GROUP_LOG, group << GROUP_LOG, &leaves, position);
        let mut siblings = [EMPTY; state_tree::DEPTH];
        for (s, n) in siblings.iter_mut().zip(low.into_iter().chain(self.tree.upper_siblings(rtxn, group)?)) {
            *s = n;
        }
        Ok(Proof { siblings })
    }

    /// Number of unspent outputs.
    pub fn len(&self, rtxn: &RoTxn) -> Result<u64> {
        Ok(self.meta.get(rtxn, META_COUNT)?.unwrap_or(0))
    }

    pub fn is_empty(&self, rtxn: &RoTxn) -> Result<bool> {
        Ok(self.len(rtxn)? == 0)
    }

    /// Disk use of each database in bytes (pages times page size) with its
    /// entry count: for measuring storage.
    pub fn storage(&self, rtxn: &RoTxn) -> Result<Vec<(&'static str, u64, usize)>> {
        let size =
            |s: heed::DatabaseStat| (s.branch_pages + s.leaf_pages + s.overflow_pages) as u64 * s.page_size as u64;
        let t = self.tree.db_stat(rtxn)?;
        let o = self.outputs.stat(rtxn)?;
        Ok(vec![("tree", size(t), t.entries), ("outputs", size(o), o.entries)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_tree::{EMPTY, empty_root, open_env};
    use crate::transaction::{Key, Output};
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
            assert_eq!(set.add(&mut wtxn, &o.commitment).unwrap(), i as u64);
        }
        wtxn.commit().unwrap();

        let rtxn = env.read_txn().unwrap();
        assert_eq!(set.next_position(&rtxn).unwrap(), 3);
        assert_eq!(set.len(&rtxn).unwrap(), 3);
        for (i, o) in outs.iter().enumerate() {
            assert_eq!(set.get(&rtxn, i as u64).unwrap(), o.commitment);
            assert!(set.holds(&rtxn, i as u64, &o.commitment).unwrap());
            assert!(!set.holds(&rtxn, (i as u64 + 1) % 3, &o.commitment).unwrap());
            let proof = set.prove(&rtxn, i as u64).unwrap();
            assert!(proof.verify(
                &set.root(&rtxn).unwrap(),
                i as u64,
                &crate::transaction::leaf(&o.commitment, &EMPTY)
            ));
        }
        assert!(!set.holds(&rtxn, 3, &Output::new(&a, 99).commitment).unwrap());
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
        let r = tree2
            .apply(
                &mut w,
                outs.iter().enumerate().map(|(i, o)| (i as u64, crate::transaction::leaf(&o.commitment, &EMPTY))),
            )
            .unwrap();
        assert_eq!(r, set.root(&rtxn).unwrap());
    }

    #[test]
    fn duplicates_are_spent_by_position() {
        let (_dir, env, set) = setup("spend");
        let a = pk(3);
        let dup = Output::new(&a, 10);
        let other = Output::new(&a, 11);
        let mut wtxn = env.write_txn().unwrap();
        set.add(&mut wtxn, &dup.commitment).unwrap(); // 0
        set.add(&mut wtxn, &other.commitment).unwrap(); // 1
        set.add(&mut wtxn, &dup.commitment).unwrap(); // 2
        let root_three = set.root(&wtxn).unwrap();
        assert!(set.holds(&wtxn, 0, &dup.commitment).unwrap() && set.holds(&wtxn, 2, &dup.commitment).unwrap());

        assert!(set.spend_at(&mut wtxn, &dup.commitment, 0).unwrap());
        assert_eq!(set.get(&wtxn, 0).unwrap(), EMPTY);
        assert_eq!(set.get(&wtxn, 2).unwrap(), dup.commitment);
        assert!(!set.holds(&wtxn, 0, &dup.commitment).unwrap());
        assert_ne!(set.root(&wtxn).unwrap(), root_three);
        assert_eq!(set.len(&wtxn).unwrap(), 2);
        // Positions are never reused.
        assert_eq!(set.next_position(&wtxn).unwrap(), 3);

        assert!(set.spend_at(&mut wtxn, &dup.commitment, 2).unwrap());
        assert!(!set.spend_at(&mut wtxn, &dup.commitment, 2).unwrap());
        assert!(!set.holds(&wtxn, 2, &dup.commitment).unwrap());
        assert!(!set.spend_at(&mut wtxn, &other.commitment, 0).unwrap());
        assert!(set.spend_at(&mut wtxn, &other.commitment, 1).unwrap());
        assert!(set.is_empty(&wtxn).unwrap());
        assert_eq!(set.root(&wtxn).unwrap(), empty_root());
        assert!(set.storage(&wtxn).unwrap().iter().all(|&(_, _, entries)| entries == 0));
        // Non-membership proof for a spent position.
        let proof = set.prove(&wtxn, 0).unwrap();
        assert!(proof.verify(&set.root(&wtxn).unwrap(), 0, &EMPTY));
        wtxn.commit().unwrap();
    }

    #[test]
    fn counter_and_outputs_persist_and_abort_cleanly() {
        let dir = TempDir::new("persist");
        let o = Output::new(&pk(4), 5);
        let root;
        {
            let env = open_env(&dir.0, 64 << 20).unwrap();
            let mut wtxn = env.write_txn().unwrap();
            let set = UtxoSet::open(&env, &mut wtxn, "utxo").unwrap();
            set.add(&mut wtxn, &o.commitment).unwrap();
            set.add(&mut wtxn, &o.commitment).unwrap();
            root = set.root(&wtxn).unwrap();
            wtxn.commit().unwrap();

            let mut wtxn = env.write_txn().unwrap();
            assert!(set.spend_at(&mut wtxn, &o.commitment, 0).unwrap());
            set.add(&mut wtxn, &o.commitment).unwrap();
            wtxn.abort();
        }
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let set = UtxoSet::open(&env, &mut wtxn, "utxo").unwrap();
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(set.root(&rtxn).unwrap(), root);
        assert_eq!(set.next_position(&rtxn).unwrap(), 2);
        assert!(set.holds(&rtxn, 0, &o.commitment).unwrap() && set.holds(&rtxn, 1, &o.commitment).unwrap());
        assert_eq!(set.len(&rtxn).unwrap(), 2);
    }

    /// The compact layout gives the same roots and proofs as a plain tree
    /// of every leaf, through adds, spends, restores, truncation and a
    /// one-pass install.
    #[test]
    fn matches_a_plain_tree() {
        let (_dir, env, set) = setup("plain");
        let mut wtxn = env.write_txn().unwrap();
        let plain = StateTree::open(&env, &mut wtxn, "plain").unwrap();
        let mut rng = 7u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let digest = |x: u64| {
            let mut d = EMPTY;
            d[0] = crate::poseidon2::Fp::new((x % 1000) as u32 + 1);
            d[3] = crate::poseidon2::Fp::new((x >> 20) as u32 % 1000);
            d
        };
        let mut live: Vec<(u64, Commitment, Memo)> = Vec::new();
        for round in 0..60 {
            // Append a run, sometimes long enough to span several groups.
            let n = 1 + next() % if round % 7 == 0 { 150 } else { 9 };
            let first = set.next_position(&wtxn).unwrap();
            let outs: Vec<BlockOutput> =
                (0..n).map(|_| BlockOutput { commitment: digest(next() % 40), memo: digest(next()) }).collect();
            set.add_outputs(&mut wtxn, &outs).unwrap();
            for (i, o) in outs.iter().enumerate() {
                let p = first + i as u64;
                plain.update(&mut wtxn, p, &leaf(&o.commitment, &o.memo)).unwrap();
                live.push((p, o.commitment, o.memo));
            }
            // Spend a few at random.
            for _ in 0..next() % 6 {
                if live.is_empty() {
                    break;
                }
                let (p, c, m) = live.swap_remove((next() % live.len() as u64) as usize);
                assert!(set.spend_at(&mut wtxn, &c, p).unwrap());
                plain.remove(&mut wtxn, p).unwrap();
                if next() % 4 == 0 {
                    set.unspend(&mut wtxn, &c, &m, p).unwrap();
                    plain.update(&mut wtxn, p, &leaf(&c, &m)).unwrap();
                    live.push((p, c, m));
                }
            }
            // A block's worth of spends at once, sometimes restored at once.
            if round % 3 == 1 && live.len() > 8 {
                let mut batch: Vec<(u64, Commitment, Memo)> = Vec::new();
                for _ in 0..1 + next() % 8 {
                    batch.push(live.swap_remove((next() % live.len() as u64) as usize));
                }
                let positions: Vec<u64> = batch.iter().map(|o| o.0).collect();
                let spent = set.spend_positions(&mut wtxn, &positions).unwrap().unwrap();
                assert_eq!(spent, batch.iter().map(|o| (o.1, o.2)).collect::<Vec<_>>());
                for p in &positions {
                    plain.remove(&mut wtxn, *p).unwrap();
                }
                // Spending one again fails.
                assert_eq!(set.spend_positions(&mut wtxn, &positions[..1]).unwrap(), Err(positions[0]));
                if next() % 2 == 0 {
                    set.restore(&mut wtxn, &batch).unwrap();
                    for (p, c, m) in &batch {
                        plain.update(&mut wtxn, *p, &leaf(c, m)).unwrap();
                    }
                    live.extend(batch);
                }
            }
            // Sometimes take back the last run, as disconnecting a block does.
            if round % 5 == 4 && live.iter().filter(|o| o.0 >= first).count() as u64 == n {
                let cs: Vec<Commitment> = outs.iter().map(|o| o.commitment).collect();
                set.truncate(&mut wtxn, first, &cs).unwrap();
                for p in first..first + n {
                    plain.remove(&mut wtxn, p).unwrap();
                }
                live.retain(|o| o.0 < first);
            }
            let root = set.root(&wtxn).unwrap();
            assert_eq!(root, plain.root(&wtxn).unwrap(), "round {round}");
            for _ in 0..4 {
                let p = next() % (set.next_position(&wtxn).unwrap() + 70);
                let proof = set.prove(&wtxn, p).unwrap();
                assert_eq!(proof, plain.prove(&wtxn, p).unwrap(), "proof of {p}");
                assert!(proof.verify(&root, p, &set.leaf_at(&wtxn, p).unwrap()));
            }
            for (p, c, _) in &live {
                assert!(set.holds(&wtxn, *p, c).unwrap());
            }
        }
        // A fresh set installed in one pass from the live outputs matches.
        live.sort_unstable_by_key(|o| o.0);
        let fresh = UtxoSet::open(&env, &mut wtxn, "fresh").unwrap();
        let counter = set.next_position(&wtxn).unwrap();
        fresh.install(&mut wtxn, &live, counter).unwrap();
        assert_eq!(fresh.root(&wtxn).unwrap(), set.root(&wtxn).unwrap());
        assert_eq!(fresh.unspent(&wtxn).unwrap(), set.unspent(&wtxn).unwrap());
        assert_eq!(fresh.len(&wtxn).unwrap(), live.len() as u64);
    }

    /// Measures disk use per unspent output and projects it to a Bitcoin
    /// sized set. `TABMINER_SCALE_N` unspent outputs (default 1,000,000)
    /// are spread at random over twenty times as many positions, as when
    /// one output in twenty ever created is still unspent, added a block's
    /// worth (`TABMINER_SCALE_BLOCK`, default 2,000) per transaction.
    #[test]
    #[ignore = "slow: storage measurement"]
    fn storage_per_unspent_output() {
        let var = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
        let n = var("TABMINER_SCALE_N", 1_000_000);
        let per_txn = var("TABMINER_SCALE_BLOCK", 2_000);
        let spread = 20u64;
        let dir = TempDir::new("scale");
        let env = open_env(&dir.0, 1 << 40).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let set = UtxoSet::open(&env, &mut wtxn, "utxo").unwrap();
        wtxn.commit().unwrap();
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            rng = rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = rng;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let mut random_digest = || {
            let mut d = EMPTY;
            for x in d.iter_mut() {
                *x = crate::poseidon2::Fp::new((next() % crate::poseidon2::P as u64) as u32);
            }
            d
        };
        let start = std::time::Instant::now();
        let (mut added, mut position) = (0u64, 0u64);
        let mut gaps = 0x2545_f491_4f6c_dd1du64;
        while added < n {
            let mut wtxn = env.write_txn().unwrap();
            for _ in 0..per_txn.min(n - added) {
                gaps ^= gaps << 13;
                gaps ^= gaps >> 7;
                gaps ^= gaps << 17;
                position += 1 + gaps % (2 * spread - 1);
                let (c, m) = (random_digest(), random_digest());
                set.insert_at(&mut wtxn, position, &c, &m).unwrap();
                added += 1;
            }
            set.set_next_position(&mut wtxn, position + 1).unwrap();
            wtxn.commit().unwrap();
        }
        let secs = start.elapsed().as_secs_f64();
        let rtxn = env.read_txn().unwrap();
        eprintln!("{n} unspent outputs over {position} positions, {:.0} µs each", secs * 1e6 / n as f64);
        let mut in_dbs = 0;
        for (name, bytes, entries) in set.storage(&rtxn).unwrap() {
            in_dbs += bytes;
            eprintln!(
                "  {name:8} {:>8.1} MB  {:>10} entries  {:>6.1} B/output",
                bytes as f64 / 1e6,
                entries,
                bytes as f64 / n as f64
            );
        }
        let file = env.real_disk_size().unwrap();
        let per = in_dbs as f64 / n as f64;
        eprintln!(
            "  in use   {:>8.1} MB, {per:.1} B/output: 170M outputs take {:.1} GB",
            in_dbs as f64 / 1e6,
            per * 170e6 / 1e9
        );
        eprintln!("  file     {:>8.1} MB with a 1 TiB map (the rest is free pages LMDB reuses)", file as f64 / 1e6);
    }

    /// Times a block's worth of work where it costs most: a fully dense
    /// region (every recent output unspent), 4,000 spends at random, 4,000
    /// new outputs and a proof for each spend.
    #[test]
    #[ignore = "slow: timing"]
    fn dense_update_cost() {
        let dir = TempDir::new("dense");
        let env = open_env(&dir.0, 1 << 34).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let set = UtxoSet::open(&env, &mut wtxn, "utxo").unwrap();
        let mut x = 0x1234_5678_9abc_def1u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let digest = |n: &mut dyn FnMut() -> u64| {
            let mut d = EMPTY;
            for e in d.iter_mut() {
                *e = crate::poseidon2::Fp::new((n() % crate::poseidon2::P as u64) as u32);
            }
            d
        };
        let total = 200_000u64;
        let outs: Vec<BlockOutput> =
            (0..total).map(|_| BlockOutput { commitment: digest(&mut next), memo: digest(&mut next) }).collect();
        set.add_outputs(&mut wtxn, &outs).unwrap();
        wtxn.commit().unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let picks: Vec<u64> =
            (0..4000).map(|_| next() % total).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        let t = std::time::Instant::now();
        for &p in &picks {
            let _ = set.prove(&wtxn, p).unwrap();
        }
        let prove = t.elapsed();
        let t = std::time::Instant::now();
        for &p in &picks {
            assert!(set.spend_at(&mut wtxn, &outs[p as usize].commitment, p).unwrap());
        }
        let spend = t.elapsed();
        let new: Vec<BlockOutput> =
            (0..4000).map(|_| BlockOutput { commitment: digest(&mut next), memo: digest(&mut next) }).collect();
        let t = std::time::Instant::now();
        set.add_outputs(&mut wtxn, &new).unwrap();
        let add = t.elapsed();
        // The same spends as a block applies them: at once.
        let back: Vec<(u64, Commitment, Memo)> =
            picks.iter().map(|&p| (p, outs[p as usize].commitment, outs[p as usize].memo)).collect();
        let t = std::time::Instant::now();
        set.restore(&mut wtxn, &back).unwrap();
        let restore = t.elapsed();
        let t = std::time::Instant::now();
        set.spend_positions(&mut wtxn, &picks).unwrap().unwrap();
        let batch = t.elapsed();
        eprintln!(
            "  as a block: {} spends at once {:.2} s, restored at once {:.2} s",
            picks.len(),
            batch.as_secs_f64(),
            restore.as_secs_f64()
        );
        eprintln!(
            "subtrees of {} positions: {} spends {:.2} s ({:.0} µs each), 4000 adds {:.3} s, {} proofs {:.2} s ({:.0} µs each)",
            1 << GROUP_LOG,
            picks.len(),
            spend.as_secs_f64(),
            spend.as_secs_f64() * 1e6 / picks.len() as f64,
            add.as_secs_f64(),
            picks.len(),
            prove.as_secs_f64(),
            prove.as_secs_f64() * 1e6 / picks.len() as f64
        );
    }

    /// Installs a snapshot of `TABMINER_SCALE_N` unspent outputs (default
    /// 4,000,000, one position in twenty) part by part, as a fast-syncing
    /// node does, and reports time and the most heap memory used.
    #[test]
    #[ignore = "slow: measurement"]
    fn staged_install_at_scale() {
        fn rss_anon_kb() -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("RssAnon:"))
                        .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
                })
                .unwrap_or(0)
        }
        let n: u64 = std::env::var("TABMINER_SCALE_N").ok().and_then(|v| v.parse().ok()).unwrap_or(4_000_000);
        let level = crate::chain::SNAPSHOT_PART_LOG;
        let next = n * 20;
        let parts = next.div_ceil(1 << level);
        let dir = TempDir::new("staged");
        let env = open_env(&dir.0, 1 << 40).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let set = UtxoSet::open(&env, &mut wtxn, "utxo").unwrap();
        wtxn.commit().unwrap();
        let mut x = 0x0bad_cafe_dead_beefu64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let base = rss_anon_kb();
        let mut peak = base;
        let start = std::time::Instant::now();
        let mut roots = Vec::with_capacity(parts as usize);
        let mut count = 0u64;
        for p in 0..parts {
            let first = p << level;
            let end = ((p + 1) << level).min(next);
            let mut outputs = Vec::new();
            for pos in first..end {
                if rnd() % 20 == 0 {
                    let mut c = EMPTY;
                    let mut m = EMPTY;
                    for e in c.iter_mut().chain(m.iter_mut()) {
                        *e = crate::poseidon2::Fp::new((rnd() % crate::poseidon2::P as u64) as u32);
                    }
                    outputs.push((pos, c, m));
                }
            }
            count += outputs.len() as u64;
            let mut wtxn = env.write_txn().unwrap();
            roots.push(set.stage(&mut wtxn, level, p, &outputs, next).unwrap());
            wtxn.commit().unwrap();
            peak = peak.max(rss_anon_kb());
        }
        let mut wtxn = env.write_txn().unwrap();
        let root = set.finish_staged(&mut wtxn, level, &roots, next).unwrap();
        wtxn.commit().unwrap();
        peak = peak.max(rss_anon_kb());
        let secs = start.elapsed().as_secs_f64();
        assert_eq!(root, state_tree::root_from_subtrees(level, &roots));
        eprintln!(
            "{count} outputs in {parts} parts: {secs:.1} s ({:.1} µs each, 170M in {:.0} min); heap grew at most {:.1} MB",
            secs * 1e6 / count as f64,
            secs / count as f64 * 170e6 / 60.0,
            (peak - base) as f64 / 1e3
        );
    }

    /// Time to apply one full block (`TABMINER_BLOCK_SPEND` random spends,
    /// 20,000, and `TABMINER_BLOCK_ADD` outputs, 25,000) to a set of
    /// `TABMINER_BLOCK_UNSPENT` unspent outputs (1,000,000), every fifth
    /// position, phase by phase. The set is installed a snapshot part at a
    /// time, so any size fits in memory. With `TABMINER_BLOCK_DIR` it is
    /// kept there and built only once; each run then spends outputs earlier
    /// runs left alone (up to 64 runs), so a run can follow dropping the
    /// file from the page cache to measure a set larger than memory.
    #[test]
    #[ignore = "slow: timing measurement"]
    fn full_block_cost() {
        let var = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
        let (spend, add, unspent) = (
            var("TABMINER_BLOCK_SPEND", 20_000),
            var("TABMINER_BLOCK_ADD", 25_000),
            var("TABMINER_BLOCK_UNSPENT", 1_000_000),
        );
        let (_temp, path) = match std::env::var("TABMINER_BLOCK_DIR") {
            Ok(d) => (None, PathBuf::from(d)),
            Err(_) => {
                let t = TempDir::new("fullblock");
                let p = t.0.clone();
                (Some(t), p)
            }
        };
        let env = open_env(&path, 1 << 40).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let set = UtxoSet::open(&env, &mut wtxn, "utxo").unwrap();
        wtxn.commit().unwrap();
        let rng = |mut x: u64| {
            move || {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x
            }
        };
        let digest = |next: &mut dyn FnMut() -> u64| -> Digest {
            core::array::from_fn(|_| crate::poseidon2::Fp::new((next() % crate::poseidon2::P as u64) as u32))
        };
        let span = unspent * 5;
        if set.next_position(&env.read_txn().unwrap()).unwrap() == 0 {
            let start = std::time::Instant::now();
            let level = crate::chain::SNAPSHOT_PART_LOG;
            let parts = span.div_ceil(1 << level);
            let mut next = rng(0x0bad_cafe_1234_5679);
            let mut roots = Vec::with_capacity(parts as usize);
            let mut wtxn = env.write_txn().unwrap();
            for part in 0..parts {
                let outputs: Vec<(u64, Commitment, Memo)> = ((part << level)..((part + 1) << level).min(span))
                    .filter(|p| p % 5 == 0)
                    .map(|p| (p, digest(&mut next), digest(&mut next)))
                    .collect();
                roots.push(set.stage(&mut wtxn, level, part, &outputs, span).unwrap());
                if part % 256 == 255 {
                    wtxn.commit().unwrap();
                    wtxn = env.write_txn().unwrap();
                    if part % 8192 == 8191 {
                        eprintln!(
                            "  built {:.0}% in {:.0} s",
                            (part + 1) as f64 * 100.0 / parts as f64,
                            start.elapsed().as_secs_f64()
                        );
                    }
                }
            }
            set.finish_staged(&mut wtxn, level, &roots, span).unwrap();
            wtxn.commit().unwrap();
            eprintln!("built {unspent} unspent outputs in {:.0} s", start.elapsed().as_secs_f64());
        }
        if std::env::var("TABMINER_BLOCK_WARM").is_ok() {
            // What a running node keeps cached because every block uses it:
            // the tree and the buckets' index pages (walking the keys does
            // not read the buckets' own pages).
            let t = std::time::Instant::now();
            let rtxn = env.read_txn().unwrap();
            let nodes = set.tree.stored_nodes(&rtxn).unwrap();
            let mut sum = 0u64;
            for item in set.tree.iter_values(&rtxn) {
                sum = sum.wrapping_add(item[0].to_canonical() as u64);
            }
            let buckets = set.outputs.iter(&rtxn).unwrap().map(|i| i.unwrap().0).fold(0u64, u64::wrapping_add);
            eprintln!(
                "warmed {nodes} tree nodes and the bucket index in {:.1} s ({sum} {buckets})",
                t.elapsed().as_secs_f64()
            );
        }
        let rtxn = env.read_txn().unwrap();
        let made = set.next_position(&rtxn).unwrap();
        let mut run = 0u64;
        while set.output_at(&rtxn, 5 * run).unwrap().is_none() {
            run += 1;
        }
        drop(rtxn);
        // This run spends outputs 5k with k = run mod 64.
        let mut next = rng(0x1357_9bdf_2468_ace1 ^ run);
        let mut chosen = std::collections::BTreeSet::from([5 * run]);
        while (chosen.len() as u64) < spend.min(unspent / 64) {
            chosen.insert(5 * (64 * (next() % (unspent / 64)) + run));
        }
        let mut picks: Vec<u64> = chosen.into_iter().collect();
        picks.sort_by_key(|p| p.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let new: Vec<BlockOutput> =
            (0..add).map(|_| BlockOutput { commitment: digest(&mut next), memo: digest(&mut next) }).collect();
        let total = std::time::Instant::now();
        let mut wtxn = env.write_txn().unwrap();
        let t = std::time::Instant::now();
        set.spend_positions(&mut wtxn, &picks).unwrap().unwrap();
        let spent = t.elapsed();
        let t = std::time::Instant::now();
        set.add_outputs(&mut wtxn, &new).unwrap();
        let added = t.elapsed();
        let t = std::time::Instant::now();
        wtxn.commit().unwrap();
        let commit = t.elapsed();
        eprintln!(
            "full block (run {run}, {made} positions): {} spends {:.3} s, {add} outputs {:.3} s, commit {:.3} s, total {:.3} s",
            picks.len(),
            spent.as_secs_f64(),
            added.as_secs_f64(),
            commit.as_secs_f64(),
            total.elapsed().as_secs_f64()
        );
    }

    /// Every stored bucket is within [`BUCKET_MAX`], not empty, keyed at
    /// most its first position and below the next bucket's key, and the
    /// count matches.
    fn check_buckets(set: &UtxoSet, rtxn: &RoTxn) {
        let mut prev_end = 0u64;
        let mut count = 0u64;
        for item in set.outputs.iter(rtxn).unwrap() {
            let (key, bytes) = item.unwrap();
            assert!(bytes.len() <= BUCKET_MAX, "bucket {key} has {} bytes", bytes.len());
            let entries = decode_bucket(key, bytes).unwrap();
            assert!(key >= prev_end, "bucket {key} overlaps the one before");
            assert!(entries.windows(2).all(|w| w[0].0 < w[1].0));
            prev_end = entries.last().unwrap().0 + 1;
            count += entries.len() as u64;
        }
        assert_eq!(set.len(rtxn).unwrap(), count);
    }

    #[test]
    fn buckets_pack_and_decode() {
        let rec = |i: u64| -> Record { core::array::from_fn(|j| (i as usize * 31 + j) as u8) };
        for gap in [1u64, 3, 127, 128, 20_000, 1 << 30] {
            let entries: Vec<(u64, Record)> = (0..500).map(|i| (7 + i * gap, rec(i))).collect();
            let packed = pack_buckets(5, &entries);
            assert_eq!(packed[0].0, 5);
            let mut back = Vec::new();
            for (i, (k, bytes)) in packed.iter().enumerate() {
                assert!(bytes.len() <= BUCKET_MAX);
                // All but the last are as full as they go.
                if i + 1 < packed.len() {
                    assert!(bytes.len() + RECORD + 10 > BUCKET_MAX);
                }
                back.extend(decode_bucket(*k, bytes).unwrap());
            }
            assert_eq!(back, entries);
        }
        assert!(decode_bucket(0, &[]).is_err());
        assert!(decode_bucket(0, &[0x80]).is_err());
        assert!(decode_bucket(0, &[0; RECORD]).is_err());
    }

    /// Random adds, spends, restores and truncations keep the buckets
    /// well formed, full enough, and their contents equal to a plain map.
    #[test]
    fn buckets_follow_a_plain_map() {
        let dir = TempDir::new("buckets");
        let env = open_env(&dir.0, 1 << 30).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let set = UtxoSet::open(&env, &mut wtxn, "utxo").unwrap();
        let mut x = 0x0123_4567_89ab_cdefu64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut model: BTreeMap<u64, (Commitment, Memo)> = BTreeMap::new();
        for round in 0..60 {
            let d = |n: u64| -> Digest {
                core::array::from_fn(|i| crate::poseidon2::Fp::new((n as u32 + i as u32) % 1000))
            };
            let first = set.next_position(&wtxn).unwrap();
            let outs: Vec<BlockOutput> =
                (0..1 + next() % 400).map(|i| BlockOutput { commitment: d(first + i), memo: d(round) }).collect();
            set.add_outputs(&mut wtxn, &outs).unwrap();
            for (i, o) in outs.iter().enumerate() {
                model.insert(first + i as u64, (o.commitment, o.memo));
            }
            let live: Vec<u64> = model.keys().copied().collect();
            let mut picks: Vec<u64> = (0..next() % (live.len() as u64 * 3 / 4 + 1))
                .map(|_| live[(next() % live.len() as u64) as usize])
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            // Spent in a scrambled order, as a block's inputs come.
            picks.sort_by_key(|p| p.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let spent = set.spend_positions(&mut wtxn, &picks).unwrap().unwrap();
            for p in &picks {
                model.remove(p);
            }
            if round % 3 == 0 {
                // Put a few back, as a disconnected block does.
                let back: Vec<(u64, Commitment, Memo)> =
                    picks.iter().zip(&spent).take(50).map(|(p, (c, m))| (*p, *c, *m)).collect();
                set.restore(&mut wtxn, &back).unwrap();
                for (p, c, m) in back {
                    model.insert(p, (c, m));
                }
            }
            if round % 7 == 0 {
                // Undo the last outputs added, those still unspent.
                let end = set.next_position(&wtxn).unwrap();
                if outs.iter().enumerate().all(|(i, _)| model.contains_key(&(first + i as u64))) {
                    let cs: Vec<Commitment> = outs.iter().map(|o| o.commitment).collect();
                    set.truncate(&mut wtxn, first, &cs).unwrap();
                    for p in first..end {
                        model.remove(&p);
                    }
                }
            }
            check_buckets(&set, &wtxn);
            let got: BTreeMap<u64, (Commitment, Memo)> = set.unspent(&wtxn).unwrap().into_iter().collect();
            assert_eq!(got, model, "round {round}");
            let leaves: Vec<(u64, Digest)> = model.iter().map(|(p, (c, m))| (*p, leaf(c, m))).collect();
            assert_eq!(set.root(&wtxn).unwrap(), subtree_root(state_tree::DEPTH, 0, &leaves), "round {round}");
        }
        // Spends thin the buckets; repacking keeps them reasonably full.
        let stored = set.outputs.len(&wtxn).unwrap();
        let bytes: usize = set.outputs.iter(&wtxn).unwrap().map(|i| i.unwrap().1.len()).sum();
        assert!(
            bytes as f64 > stored.saturating_sub(1) as f64 * BUCKET_LOW as f64 * 0.5,
            "{stored} buckets, {bytes} bytes"
        );
    }

    /// Storage after block-sized churn, as the large-block simulation
    /// makes: blocks of `TABMINER_CHURN_ADD` new outputs (default 25,000)
    /// and `TABMINER_CHURN_SPEND` spends (default 20,000) picked uniformly
    /// from the unspent ones, for `TABMINER_CHURN_BLOCKS` blocks (250).
    #[test]
    #[ignore = "slow: storage measurement"]
    fn storage_under_churn() {
        let var = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
        let (add, spend, blocks) =
            (var("TABMINER_CHURN_ADD", 25_000), var("TABMINER_CHURN_SPEND", 20_000), var("TABMINER_CHURN_BLOCKS", 250));
        let dir = TempDir::new("churn");
        let env = open_env(&dir.0, 1 << 40).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let set = UtxoSet::open(&env, &mut wtxn, "utxo").unwrap();
        wtxn.commit().unwrap();
        let mut x = 0x5151_7272_9393_b4b4u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut live: Vec<u64> = Vec::new();
        let start = std::time::Instant::now();
        for _ in 0..blocks {
            let mut wtxn = env.write_txn().unwrap();
            let mut picks = Vec::new();
            for _ in 0..spend.min(live.len() as u64) {
                picks.push(live.swap_remove((next() % live.len() as u64) as usize));
            }
            set.spend_positions(&mut wtxn, &picks).unwrap().unwrap();
            let first = set.next_position(&wtxn).unwrap();
            let outs: Vec<BlockOutput> = (0..add)
                .map(|_| {
                    let mut d = || -> Digest {
                        core::array::from_fn(|_| {
                            crate::poseidon2::Fp::new((next() % crate::poseidon2::P as u64) as u32)
                        })
                    };
                    BlockOutput { commitment: d(), memo: d() }
                })
                .collect();
            set.add_outputs(&mut wtxn, &outs).unwrap();
            live.extend(first..first + add);
            wtxn.commit().unwrap();
        }
        let rtxn = env.read_txn().unwrap();
        let n = live.len() as u64;
        let made = set.next_position(&rtxn).unwrap();
        eprintln!(
            "buckets: {n} unspent of {made} ({:.1}%), {blocks} blocks in {:.1} s",
            n as f64 * 100.0 / made as f64,
            start.elapsed().as_secs_f64()
        );
        let mut total = 0;
        for (name, bytes, entries) in set.storage(&rtxn).unwrap() {
            total += bytes;
            eprintln!(
                "  {name:8} {:>8.1} MB  {entries:>10} entries  {:>6.1} B/output",
                bytes as f64 / 1e6,
                bytes as f64 / n as f64
            );
        }
        eprintln!("  total    {:>8.1} MB, {:.1} B/output", total as f64 / 1e6, total as f64 / n as f64);
    }

    /// Block-sized batches of adds and random spends, emptying most
    /// subtrees, keep the stored tree equal to the root of the outputs the
    /// test itself knows to be unspent.
    #[test]
    fn large_batches_keep_the_tree_right() {
        let (_dir, env, set) = setup("batches");
        let mut x = 0x0123_4567_89ab_cdefu64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut live: std::collections::BTreeMap<u64, Digest> = Default::default();
        for block in 0..12 {
            let mut wtxn = env.write_txn().unwrap();
            let mut picks = Vec::new();
            let keys: Vec<u64> = live.keys().copied().collect();
            for _ in 0..keys.len() * 19 / 20 {
                let p = keys[(next() % keys.len() as u64) as usize];
                if live.remove(&p).is_some() {
                    picks.push(p);
                }
            }
            set.spend_positions(&mut wtxn, &picks).unwrap().unwrap();
            let first = set.next_position(&wtxn).unwrap();
            let outs: Vec<BlockOutput> = (0..2500u64)
                .map(|i| {
                    let mut d = EMPTY;
                    d[0] = crate::poseidon2::Fp::new((first + i) as u32 + 1);
                    d[1] = crate::poseidon2::Fp::new((next() % 1000) as u32);
                    BlockOutput { commitment: d, memo: EMPTY }
                })
                .collect();
            set.add_outputs(&mut wtxn, &outs).unwrap();
            for (i, o) in outs.iter().enumerate() {
                live.insert(first + i as u64, leaf(&o.commitment, &o.memo));
            }
            let leaves: Vec<(u64, Digest)> = live.iter().map(|(p, l)| (*p, *l)).collect();
            assert_eq!(set.root(&wtxn).unwrap(), subtree_root(state_tree::DEPTH, 0, &leaves), "block {block}");
            assert_eq!(set.len(&wtxn).unwrap(), live.len() as u64);
            wtxn.commit().unwrap();
        }
    }

    /// Range scans follow the keys' values, not their bytes: chunk 1562
    /// (bytes 1a 06 ...) is not inside chunks 16 to 31 (bytes 10 to 1f).
    #[test]
    fn range_scans_follow_value_order() {
        let (_dir, env, set) = setup("ranges");
        let mut wtxn = env.write_txn().unwrap();
        let c = |n: u32| {
            let mut d = EMPTY;
            d[0] = crate::poseidon2::Fp::new(n);
            d
        };
        set.insert_at(&mut wtxn, 3, &c(1), &EMPTY).unwrap();
        set.insert_at(&mut wtxn, 1562 * 16 + 9, &c(2), &EMPTY).unwrap();
        set.insert_at(&mut wtxn, 300 * 16, &c(3), &EMPTY).unwrap();
        assert!(set.group_leaves(&wtxn, 1).unwrap().is_empty());
        assert!(set.unspent_in(&wtxn, 256, 512).unwrap().is_empty());
        let all: Vec<u64> = set.unspent(&wtxn).unwrap().iter().map(|o| o.0).collect();
        assert_eq!(all, vec![3, 300 * 16, 1562 * 16 + 9]);
        let leaves: Vec<(u64, Digest)> =
            [(3, c(1)), (300 * 16, c(3)), (1562 * 16 + 9, c(2))].iter().map(|&(p, d)| (p, leaf(&d, &EMPTY))).collect();
        assert_eq!(set.root(&wtxn).unwrap(), subtree_root(state_tree::DEPTH, 0, &leaves));
    }
}
