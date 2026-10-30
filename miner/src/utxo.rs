//! The unspent output set: outputs stored in the sparse [`StateTree`] at
//! counter positions, with a lookup from commitment to position.
//!
//! Every output ever created gets the next position from a monotonically
//! increasing counter (positions are never reused), and its leaf, the
//! commitment and memo compressed ([`crate::transaction::leaf`]), is at
//! that position in the tree, so the root covers memos too. Spending an
//! output clears the leaf. Because a transaction input identifies the
//! output it spends only by its commitment, an index from commitment to
//! positions is kept alongside. Two outputs with the same key and amount
//! have the same commitment; they occupy distinct positions and
//! [`UtxoSet::spend`] consumes the lowest one first.
//!
//! Storage is laid out for a set of hundreds of millions of outputs spread
//! thinly over billions of positions, at about 130 bytes each:
//!
//! - `<prefix>.chunks`: the unspent outputs, sixteen positions to an
//!   entry. The integer key is the position over 16; the value is a 16-bit
//!   little-endian bitmap of the occupied positions followed by each one's
//!   commitment and memo (64 bytes), in position order.
//! - `<prefix>.tree`: the Merkle tree's nodes from level [`GROUP_LOG`] up
//!   (subtrees of 256 positions). The levels below are recomputed from the
//!   chunks when needed, at most 256 leaves hashed eight at a time, rather
//!   than stored: they are most of a sparse tree's nodes.
//! - `<prefix>.index`: the first 8 bytes of each unspent output's
//!   commitment followed by its position (5 bytes, little endian), no
//!   value. A lookup checks the candidates' full commitments in the chunks.
//! - `<prefix>.meta`: the counter.
//!
//! All operations take the caller's transaction so a block can update the
//! set and its own records atomically.

use crate::block::BlockOutput;
use crate::poseidon2::digest_from_bytes;
use crate::state_tree::EMPTY;
use crate::transaction::{Memo, leaf};
use heed::byteorder::{LittleEndian, NativeEndian};
use heed::types::{Bytes, Str, U64, Unit};
use heed::{Database, DatabaseFlags, Env, RoTxn, RwTxn};

use crate::poseidon2::{DIGEST, compress_all, digest_to_bytes};
use crate::state_tree::{self, CAPACITY, Digest, Proof, StateTree, subtree_path, subtree_root};
use crate::transaction::Commitment;

const COMMITMENT_BYTES: usize = DIGEST * 4;
/// Bytes of the commitment kept in the index.
const INDEX_PREFIX: usize = 8;
const INDEX_KEY_LEN: usize = INDEX_PREFIX + 5;
const META_NEXT_POSITION: &str = "next_position";
/// Positions per chunk: 16, so a full chunk (2 + 16 * 64 bytes) still fits
/// in an LMDB page.
pub const CHUNK_LOG: usize = 4;
/// Height of the subtrees whose roots are the lowest stored tree level.
pub const GROUP_LOG: usize = 8;
const RECORD: usize = 2 * COMMITMENT_BYTES;

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
    k[..INDEX_PREFIX].copy_from_slice(&digest_to_bytes(commitment)[..INDEX_PREFIX]);
    k[INDEX_PREFIX..].copy_from_slice(&position.to_le_bytes()[..5]);
    k
}

/// A chunk's value: the bitmap and the records of its occupied positions.
struct Chunk {
    bits: u16,
    records: Vec<[u8; RECORD]>,
}

impl Chunk {
    fn parse(bytes: &[u8]) -> Result<Chunk> {
        let (bits, rest) = bytes.split_at_checked(2).ok_or(Error::CorruptIndex)?;
        let bits = u16::from_le_bytes(bits.try_into().unwrap());
        if rest.len() != bits.count_ones() as usize * RECORD {
            return Err(Error::CorruptIndex);
        }
        Ok(Chunk { bits, records: rest.chunks_exact(RECORD).map(|r| r.try_into().unwrap()).collect() })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.records.len() * RECORD);
        out.extend_from_slice(&self.bits.to_le_bytes());
        for r in &self.records {
            out.extend_from_slice(r);
        }
        out
    }

    /// Index into `records` of `slot`, and whether it is occupied.
    fn find(&self, slot: u32) -> (usize, bool) {
        ((self.bits & ((1u16 << slot) - 1)).count_ones() as usize, self.bits >> slot & 1 == 1)
    }
}

fn record_bytes(commitment: &Commitment, memo: &Memo) -> [u8; RECORD] {
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

/// Handle to the UTXO set.
#[derive(Clone)]
pub struct UtxoSet {
    tree: StateTree,
    index: Database<Bytes, Unit>,
    chunks: Database<U64<NativeEndian>, Bytes>,
    meta: Database<Str, U64<LittleEndian>>,
}

impl UtxoSet {
    /// Opens the set stored under `prefix` in `env`, creating its databases
    /// if needed. The transaction must be committed by the caller.
    pub fn open(env: &Env, wtxn: &mut RwTxn, prefix: &str) -> Result<UtxoSet> {
        let tree = StateTree::open_from(env, wtxn, &format!("{prefix}.tree"), GROUP_LOG)?;
        let index = env.create_database(wtxn, Some(&format!("{prefix}.index")))?;
        let chunks = env
            .database_options()
            .types::<U64<NativeEndian>, Bytes>()
            .name(&format!("{prefix}.chunks"))
            .flags(DatabaseFlags::INTEGER_KEY)
            .create(wtxn)?;
        let meta = env.create_database(wtxn, Some(&format!("{prefix}.meta")))?;
        Ok(UtxoSet { tree, index, chunks, meta })
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
        for (i, o) in outputs.iter().enumerate() {
            self.put_record(wtxn, first + i as u64, &o.commitment, &o.memo)?;
        }
        self.meta.put(wtxn, META_NEXT_POSITION, &end)?;
        if end > first {
            for g in first >> GROUP_LOG..=(end - 1) >> GROUP_LOG {
                self.refresh_group(wtxn, g)?;
            }
        }
        Ok(())
    }

    /// Writes an unspent output at `position` without moving the counter.
    pub fn insert_at(&self, wtxn: &mut RwTxn, position: u64, commitment: &Commitment, memo: &Memo) -> Result<()> {
        if position >= CAPACITY {
            return Err(Error::Full);
        }
        self.put_record(wtxn, position, commitment, memo)?;
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
        let mut groups: Vec<(u64, Digest)> = Vec::new();
        let mut i = 0;
        while i < outputs.len() {
            let g = outputs[i].0 >> GROUP_LOG;
            let mut leaves = Vec::new();
            while i < outputs.len() && outputs[i].0 >> GROUP_LOG == g {
                let (pos, c, m) = &outputs[i];
                self.put_record(wtxn, *pos, c, m)?;
                leaves.push((*pos, leaf(c, m)));
                i += 1;
            }
            groups.push((g, subtree_root(GROUP_LOG, g << GROUP_LOG, &leaves)));
        }
        self.tree.build(wtxn, &groups)?;
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
        let mut groups: Vec<(u64, Digest)> = Vec::new();
        let mut i = 0;
        while i < outputs.len() {
            let g = outputs[i].0 >> GROUP_LOG;
            let start = i;
            while i < outputs.len() && outputs[i].0 >> GROUP_LOG == g {
                let (pos, c, m) = &outputs[i];
                self.put_record(wtxn, *pos, c, m)?;
                i += 1;
            }
            let pairs: Vec<(&Digest, &Digest)> = outputs[start..i].iter().map(|(_, c, m)| (c, m)).collect();
            let leaves: Vec<(u64, Digest)> = outputs[start..i].iter().map(|o| o.0).zip(compress_all(&pairs)).collect();
            groups.push((g, subtree_root(GROUP_LOG, g << GROUP_LOG, &leaves)));
        }
        Ok(self.tree.write_subtree(wtxn, level, index, &groups)?)
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
        self.index.clear(wtxn)?;
        self.chunks.clear(wtxn)?;
        self.meta.clear(wtxn)?;
        Ok(())
    }

    /// Sets the next position: for installing a snapshot.
    pub fn set_next_position(&self, wtxn: &mut RwTxn, next: u64) -> Result<()> {
        self.meta.put(wtxn, META_NEXT_POSITION, &next)?;
        Ok(())
    }

    fn chunk(&self, rtxn: &RoTxn, chunk: u64) -> Result<Chunk> {
        match self.chunks.get(rtxn, &chunk)? {
            Some(b) => Chunk::parse(b),
            None => Ok(Chunk { bits: 0, records: Vec::new() }),
        }
    }

    fn put_chunk(&self, wtxn: &mut RwTxn, key: u64, chunk: &Chunk) -> Result<()> {
        if chunk.bits == 0 {
            self.chunks.delete(wtxn, &key)?;
        } else {
            self.chunks.put(wtxn, &key, &chunk.to_bytes())?;
        }
        Ok(())
    }

    /// Stores an output's record and index entry; the tree is not updated.
    fn put_record(&self, wtxn: &mut RwTxn, position: u64, commitment: &Commitment, memo: &Memo) -> Result<()> {
        let key = position >> CHUNK_LOG;
        let mut chunk = self.chunk(wtxn, key)?;
        let (i, occupied) = chunk.find((position & ((1 << CHUNK_LOG) - 1)) as u32);
        let rec = record_bytes(commitment, memo);
        if occupied {
            let (old, _) = parse_record(&chunk.records[i])?;
            self.index.delete(wtxn, &index_key(&old, position))?;
            chunk.records[i] = rec;
        } else {
            chunk.bits |= 1 << (position & ((1 << CHUNK_LOG) - 1));
            chunk.records.insert(i, rec);
        }
        self.put_chunk(wtxn, key, &chunk)?;
        self.index.put(wtxn, &index_key(commitment, position), &())?;
        Ok(())
    }

    /// Removes the output at `position` if its commitment is `commitment`;
    /// the tree is not updated. Returns whether it was there.
    fn remove_record(&self, wtxn: &mut RwTxn, position: u64, commitment: &Commitment) -> Result<bool> {
        let key = position >> CHUNK_LOG;
        let mut chunk = self.chunk(wtxn, key)?;
        let slot = (position & ((1 << CHUNK_LOG) - 1)) as u32;
        let (i, occupied) = chunk.find(slot);
        if !occupied || parse_record(&chunk.records[i])?.0 != *commitment {
            return Ok(false);
        }
        chunk.bits &= !(1 << slot);
        chunk.records.remove(i);
        self.put_chunk(wtxn, key, &chunk)?;
        if !self.index.delete(wtxn, &index_key(commitment, position))? {
            return Err(Error::CorruptIndex);
        }
        Ok(true)
    }

    /// The leaves of the subtree of 256 positions `group`, ascending.
    fn group_leaves(&self, rtxn: &RoTxn, group: u64) -> Result<Vec<(u64, Digest)>> {
        let per = 1u64 << (GROUP_LOG - CHUNK_LOG);
        let mut positions = Vec::new();
        let mut records = Vec::new();
        for item in self.chunks.range(rtxn, &(group * per..=group * per + per - 1))? {
            let (key, bytes) = item?;
            let chunk = Chunk::parse(bytes)?;
            let mut r = chunk.records.iter();
            for slot in 0..1u64 << CHUNK_LOG {
                if chunk.bits >> slot & 1 == 1 {
                    positions.push((key << CHUNK_LOG) + slot);
                    records.push(parse_record(r.next().unwrap())?);
                }
            }
        }
        // Leaves are the commitment and memo compressed, hashed eight at
        // a time.
        let pairs: Vec<(&Digest, &Digest)> = records.iter().map(|(c, m)| (c, m)).collect();
        Ok(positions.into_iter().zip(compress_all(&pairs)).collect())
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

    /// Positions of all unspent outputs with this commitment, ascending.
    pub fn positions(&self, rtxn: &RoTxn, commitment: &Commitment) -> Result<Vec<u64>> {
        let prefix = &digest_to_bytes(commitment)[..INDEX_PREFIX];
        let mut candidates = Vec::new();
        for item in self.index.prefix_iter(rtxn, prefix)? {
            let (key, ()) = item?;
            if key.len() != INDEX_KEY_LEN {
                return Err(Error::CorruptIndex);
            }
            let mut p = [0u8; 8];
            p[..5].copy_from_slice(&key[INDEX_PREFIX..]);
            candidates.push(u64::from_le_bytes(p));
        }
        let mut out = Vec::new();
        for p in candidates {
            if self.record(rtxn, p)?.is_some_and(|(c, _)| c == *commitment) {
                out.push(p);
            }
        }
        // Keys are little endian, so LMDB's order is not numeric.
        out.sort_unstable();
        Ok(out)
    }

    /// Whether at least one unspent output has this commitment.
    pub fn contains(&self, rtxn: &RoTxn, commitment: &Commitment) -> Result<bool> {
        Ok(!self.positions(rtxn, commitment)?.is_empty())
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
        if !self.remove_record(wtxn, position, commitment)? {
            return Ok(false);
        }
        self.refresh_group(wtxn, position >> GROUP_LOG)?;
        Ok(true)
    }

    /// Restores a spent output and its memo: the inverse of
    /// [`UtxoSet::spend_at`].
    pub fn unspend(&self, wtxn: &mut RwTxn, commitment: &Commitment, memo: &Memo, position: u64) -> Result<()> {
        self.insert_at(wtxn, position, commitment, memo)
    }

    fn record(&self, rtxn: &RoTxn, position: u64) -> Result<Option<(Commitment, Memo)>> {
        let Some(bytes) = self.chunks.get(rtxn, &(position >> CHUNK_LOG))? else {
            return Ok(None);
        };
        let chunk = Chunk::parse(bytes)?;
        let (i, occupied) = chunk.find((position & ((1 << CHUNK_LOG) - 1)) as u32);
        if !occupied {
            return Ok(None);
        }
        parse_record(&chunk.records[i]).map(Some)
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
        if end <= first {
            return Ok(out);
        }
        for item in self.chunks.range(rtxn, &(first >> CHUNK_LOG..=(end - 1) >> CHUNK_LOG))? {
            let (key, bytes) = item?;
            let chunk = Chunk::parse(bytes)?;
            let mut r = chunk.records.iter();
            for slot in 0..1u64 << CHUNK_LOG {
                if chunk.bits >> slot & 1 == 1 {
                    let rec = parse_record(r.next().unwrap())?;
                    let pos = (key << CHUNK_LOG) + slot;
                    if (first..end).contains(&pos) {
                        out.push((pos, rec));
                    }
                }
            }
        }
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
        for (i, c) in commitments.iter().enumerate().rev() {
            if !self.remove_record(wtxn, first + i as u64, c)? {
                return Err(Error::CorruptIndex);
            }
        }
        if end > first {
            for g in first >> GROUP_LOG..=(end - 1) >> GROUP_LOG {
                self.refresh_group(wtxn, g)?;
            }
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
        Ok(self.index.len(rtxn)?)
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
        let i = self.index.stat(rtxn)?;
        let c = self.chunks.stat(rtxn)?;
        Ok(vec![("tree", size(t), t.entries), ("index", size(i), i.entries), ("chunks", size(c), c.entries)])
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
            assert_eq!(set.positions(&rtxn, &o.commitment).unwrap(), vec![i as u64]);
            assert!(set.contains(&rtxn, &o.commitment).unwrap());
            let proof = set.prove(&rtxn, i as u64).unwrap();
            assert!(proof.verify(
                &set.root(&rtxn).unwrap(),
                i as u64,
                &crate::transaction::leaf(&o.commitment, &EMPTY)
            ));
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
        let r = tree2
            .apply(
                &mut w,
                outs.iter().enumerate().map(|(i, o)| (i as u64, crate::transaction::leaf(&o.commitment, &EMPTY))),
            )
            .unwrap();
        assert_eq!(r, set.root(&rtxn).unwrap());
    }

    #[test]
    fn spend_removes_lowest_duplicate_first() {
        let (_dir, env, set) = setup("spend");
        let a = pk(3);
        let dup = Output::new(&a, 10);
        let other = Output::new(&a, 11);
        let mut wtxn = env.write_txn().unwrap();
        set.add(&mut wtxn, &dup.commitment).unwrap(); // 0
        set.add(&mut wtxn, &other.commitment).unwrap(); // 1
        set.add(&mut wtxn, &dup.commitment).unwrap(); // 2
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
        assert!(set.storage(&wtxn).unwrap().iter().all(|&(_, _, entries)| entries == 0));
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
            set.add(&mut wtxn, &o.commitment).unwrap();
            set.add(&mut wtxn, &o.commitment).unwrap();
            root = set.root(&wtxn).unwrap();
            wtxn.commit().unwrap();

            let mut wtxn = env.write_txn().unwrap();
            set.spend(&mut wtxn, &o.commitment).unwrap();
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
        assert_eq!(set.positions(&rtxn, &o.commitment).unwrap(), vec![0, 1]);
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
                assert!(set.positions(&wtxn, c).unwrap().contains(p));
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
        let mut digest = |n: &mut dyn FnMut() -> u64| {
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
}
