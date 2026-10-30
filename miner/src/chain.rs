//! Chain state, block validation and fork choice.
//!
//! A [`Chain`] owns an LMDB environment holding the UTXO set
//! ([`crate::utxo::UtxoSet`]), every valid header and body by block id with
//! its cumulative work, the main-chain index by height, undo records for the
//! blocks on the main chain, and the tip. Blocks are applied with
//! [`Chain::apply_block`], which validates and commits in one transaction so
//! the UTXO set and the block index never disagree.
//!
//! # Fork choice
//!
//! The main chain is the known branch with the most cumulative work, each
//! block counting `2^256 / (target + 1)` as Bitcoin does. A block whose
//! parent is known is stored whatever branch it extends, once its header
//! rules hold (2 to 4 below). If its branch then has more work than the tip,
//! the main chain is reorganized: the blocks after the fork point are
//! disconnected newest first, restoring the outputs they spent and removing
//! the ones they appended, and the new branch is connected oldest first
//! with the full state rules (5 to 7). All of that is one transaction, so a
//! branch with an invalid block leaves the old main chain in place; the bad
//! block and its stored descendants are then marked invalid. A block whose
//! parent is unknown is refused with [`ChainError::UnknownParent`] so the
//! caller can fetch the parent first.
//!
//! # Rules checked
//!
//! 1. The parent is a known valid block and `height` is its height plus one.
//! 2. `timestamp` is greater than the median of the last eleven block
//!    timestamps on its branch and at most two hours ahead of the caller's
//!    clock.
//! 3. The proof of work meets the ASERT target derived from the parent, via
//!    the cheap mix pre-check and then the full evaluation from the text.
//! 4. The body is well formed (distinct, in-range inputs), within the size
//!    limits, and the header commits to it.
//! 5. Every input position holds an unspent output.
//! 6. The validity proof is accepted by the configured [`ProofVerifier`].
//! 7. After spending the inputs and appending the outputs, the UTXO root
//!    equals `state_root`.
//!
//! Genesis is installed with [`Chain::init_genesis`] and is not subject to
//! proof-of-work or timestamp checks; its id anchors everything after it.
//! Mainnet's is [`ChainParams::genesis`], a fixed empty block.
//!
//! What a node cannot check here is balance: no amount is on chain, only
//! commitments. That, the signatures and the commitment preimages are the
//! proof's job.

use std::collections::HashMap;
use std::path::Path;

use heed::byteorder::LittleEndian;
use heed::types::{Bytes, Str, U32};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::aggregate::AggregatorParams;
use crate::block::{Block, Body, BodyError, HEADER_SIZE, Header};
use crate::difficulty::{Asert, U256};
use crate::poseidon2::digest_from_bytes;
use crate::pow::{Digest, PowParams, SeedText, Target};
use crate::state_tree::{EMPTY, empty_root, open_env};
use crate::transaction::{Commitment, Memo};
use crate::utxo::{self, UtxoSet};

/// Base units per coin.
pub const COIN: u64 = 100_000_000;
/// Blocks per year at the ten-minute target: 144 a day.
pub const BLOCKS_PER_YEAR: u32 = 144 * 365;

/// Mainnet emission: 1500 coins a block for 3.5 years, 500 for 3.5 years,
/// then 7 for 1000 years, 735,840,000 coins in all; then the chain ends.
pub const MAINNET_EMISSION: &[(u32, u64)] = &[
    (BLOCKS_PER_YEAR * 7 / 2, 1500 * COIN),
    (BLOCKS_PER_YEAR * 7 / 2, 500 * COIN),
    (BLOCKS_PER_YEAR * 1000, 7 * COIN),
];

/// Consensus parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainParams {
    pub pow: PowParams,
    /// Timestamp of the genesis block, an empty block (see
    /// [`ChainParams::genesis`]).
    pub genesis_timestamp: u64,
    /// The genesis header's nonce: on mainnet, the hash of the latest
    /// Bitcoin block when genesis was made, so the chain provably did not
    /// exist before it.
    pub genesis_nonce: [u8; 32],
    /// Target of the block after genesis; the ASERT anchor.
    pub genesis_target: U256,
    /// Easiest permitted target.
    pub max_target: U256,
    /// Largest serialized block, header and body (input positions,
    /// outputs and proof), in bytes. The only limit on a block's contents.
    pub max_block_size: usize,
    /// Seconds a timestamp may lead the local clock.
    pub max_future_drift: u64,
    /// Number of past blocks whose median timestamp bounds the next.
    pub median_time_window: usize,
    /// The emission schedule: consecutive eras of `(blocks, subsidy per
    /// block in base units)`, starting at height 1 (genesis pays nothing).
    /// The chain ends with the last era: a block above
    /// [`ChainParams::final_height`] is invalid.
    pub emission: &'static [(u32, u64)],
    /// Parameters of the block validity proof.
    pub aggregator: AggregatorParams,
}

impl ChainParams {
    pub const MAINNET: ChainParams = ChainParams {
        pow: PowParams::MAINNET,
        genesis_timestamp: crate::genesis::TIMESTAMP,
        genesis_nonce: crate::genesis::BITCOIN_HASH,
        genesis_target: U256(crate::genesis::TARGET),
        max_target: U256([u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 8]), // 2^248 - 1
        max_block_size: 2 << 20,
        max_future_drift: 2 * 3600,
        median_time_window: 11,
        emission: MAINNET_EMISSION,
        aggregator: AggregatorParams::MAINNET,
    };

    /// Subsidy paid by the block at `height`: zero for genesis and above
    /// the final height.
    pub fn subsidy(&self, height: u32) -> u64 {
        if height == 0 {
            return 0;
        }
        let mut first = 1u64;
        for &(blocks, subsidy) in self.emission {
            if (height as u64) < first + blocks as u64 {
                return subsidy;
            }
            first += blocks as u64;
        }
        0
    }

    /// Height of the last block the chain can have.
    pub fn final_height(&self) -> u32 {
        self.emission.iter().map(|&(blocks, _)| blocks as u64).sum::<u64>().min(u32::MAX as u64) as u32
    }

    /// Every coin the schedule creates, in base units.
    pub fn total_supply(&self) -> u128 {
        self.emission.iter().map(|&(blocks, subsidy)| blocks as u128 * subsidy as u128).sum()
    }

    /// The genesis block: empty, at `genesis_timestamp`, over the empty
    /// state tree, with `genesis_nonce` as its nonce (proof of work is not
    /// checked on genesis). Every node of a network must start from the
    /// same one.
    pub fn genesis(&self) -> Block {
        let body = Body { inputs: vec![], outputs: vec![], proof: vec![] };
        let header = Header {
            prev_hash: EMPTY,
            height: 0,
            timestamp: self.genesis_timestamp,
            body_commitment: body.commitment(),
            state_root: empty_root(),
            mix: EMPTY,
            nonce: self.genesis_nonce,
        };
        Block { header, body }
    }

    /// Work a block mined at `target` adds to its chain: `2^256 / (target +
    /// 1)`, computed as `(!target / (target + 1)) + 1`.
    pub fn block_work(target: U256) -> U256 {
        let t1 = target.saturating_add(U256::ONE);
        target.not().div(t1).saturating_add(U256::ONE)
    }
}

/// Statement a block's proof must attest to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockStatement<'a> {
    pub height: u32,
    pub prev_state_root: Digest,
    pub new_state_root: Digest,
    /// Position of the first output appended by this block.
    pub first_output_position: u64,
    /// Subsidy the block may create.
    pub subsidy: u64,
    pub body: &'a Body,
}

/// Verifies a block's validity proof. The real implementation is the STARK
/// verifier for the block circuit.
pub trait ProofVerifier {
    fn verify(&self, statement: &BlockStatement<'_>, proof: &[u8]) -> bool;
}

/// Accepts every proof. For development and tests only; a node using this
/// trusts block producers completely.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAllProofs;

impl ProofVerifier for AcceptAllProofs {
    fn verify(&self, _: &BlockStatement<'_>, _: &[u8]) -> bool {
        true
    }
}

#[derive(Debug)]
pub enum ChainError {
    Heed(heed::Error),
    Utxo(utxo::Error),
    Body(BodyError),
    NoGenesis,
    AlreadyInitialized,
    /// The stored genesis is not the one the parameters name.
    WrongGenesis,
    /// `prev_hash` is not a known block.
    UnknownParent(Digest),
    /// The parent was found invalid.
    InvalidParent,
    /// The block is above the schedule's final height: the chain has ended.
    ChainEnded,
    /// A block of the branch has no body yet (fast sync stores headers
    /// alone).
    MissingBody,
    /// A reorganization would go below the fast-sync snapshot.
    BelowSnapshot,
    /// A reorganization would go deeper than the undo records kept.
    BeyondUndo,
    /// A snapshot does not match its block's state root or proof.
    BadSnapshot,
    /// The block was found invalid before.
    KnownInvalid,
    BadHeight {
        expected: u32,
        got: u32,
    },
    TimestampTooOld {
        median: u64,
        got: u64,
    },
    TimestampTooNew {
        limit: u64,
        got: u64,
    },
    BadProofOfWork,
    BadBodyCommitment,
    /// The serialized block exceeds `max_block_size` bytes.
    TooLarge(usize),
    /// Input position holds no unspent output.
    UnknownInput(u64),
    BadProof,
    StateRootMismatch {
        expected: Digest,
        got: Digest,
    },
    /// A stored record could not be decoded.
    Corrupt(&'static str),
    /// The data directory was written by an incompatible version.
    OldFormat,
}

impl ChainError {
    /// Whether the error is a consensus failure of the block itself, so
    /// that it is remembered as invalid by id. Not: a missing parent, a
    /// storage problem, a timestamp ahead of the caller's clock (the block
    /// may be fine later), or a body the header does not commit to (the
    /// header may be fine with its real body).
    pub fn is_invalid_block(&self) -> bool {
        !matches!(
            self,
            ChainError::Heed(_)
                | ChainError::Utxo(_)
                | ChainError::NoGenesis
                | ChainError::AlreadyInitialized
                | ChainError::WrongGenesis
                | ChainError::UnknownParent(_)
                | ChainError::TimestampTooNew { .. }
                | ChainError::BadBodyCommitment
                | ChainError::Corrupt(_)
                | ChainError::OldFormat
                | ChainError::MissingBody
                | ChainError::BelowSnapshot
                | ChainError::BeyondUndo
                | ChainError::BadSnapshot
        )
    }
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainError::Heed(e) => write!(f, "lmdb error: {e}"),
            ChainError::Utxo(e) => write!(f, "{e}"),
            ChainError::Body(e) => write!(f, "{e}"),
            ChainError::NoGenesis => f.write_str("chain has no genesis block"),
            ChainError::AlreadyInitialized => f.write_str("chain already has a genesis block"),
            ChainError::WrongGenesis => f.write_str("stored genesis differs from the network's"),
            ChainError::UnknownParent(_) => f.write_str("parent block is unknown"),
            ChainError::InvalidParent => f.write_str("parent block is invalid"),
            ChainError::ChainEnded => f.write_str("the chain has reached its final block"),
            ChainError::MissingBody => f.write_str("a block of the branch has no body yet"),
            ChainError::BelowSnapshot => f.write_str("cannot reorganize below the fast-sync snapshot"),
            ChainError::BeyondUndo => f.write_str("cannot reorganize deeper than the undo records kept"),
            ChainError::BadSnapshot => f.write_str("snapshot does not match its block"),
            ChainError::KnownInvalid => f.write_str("block is known to be invalid"),
            ChainError::BadHeight { expected, got } => {
                write!(f, "height {got}, expected {expected}")
            }
            ChainError::TimestampTooOld { median, got } => {
                write!(f, "timestamp {got} not after median time past {median}")
            }
            ChainError::TimestampTooNew { limit, got } => {
                write!(f, "timestamp {got} exceeds limit {limit}")
            }
            ChainError::BadProofOfWork => f.write_str("proof of work does not meet the target"),
            ChainError::BadBodyCommitment => f.write_str("header does not commit to the body"),
            ChainError::TooLarge(n) => write!(f, "block of {n} bytes exceeds the size limit"),
            ChainError::UnknownInput(p) => write!(f, "input position {p} is not an unspent output"),
            ChainError::BadProof => f.write_str("validity proof rejected"),
            ChainError::StateRootMismatch { .. } => f.write_str("state root does not match the applied body"),
            ChainError::Corrupt(what) => write!(f, "corrupt chain record: {what}"),
            ChainError::OldFormat => {
                f.write_str("chain database is from an older format; delete the chain directory and resync")
            }
        }
    }
}

impl std::error::Error for ChainError {}

impl From<heed::Error> for ChainError {
    fn from(e: heed::Error) -> Self {
        ChainError::Heed(e)
    }
}

impl From<utxo::Error> for ChainError {
    fn from(e: utxo::Error) -> Self {
        ChainError::Utxo(e)
    }
}

impl From<BodyError> for ChainError {
    fn from(e: BodyError) -> Self {
        ChainError::Body(e)
    }
}

pub type Result<T> = core::result::Result<T, ChainError>;

/// What [`Chain::apply_block`] did with a valid block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The block was already stored.
    Known,
    /// Stored on a branch with no more work than the main chain.
    Side,
    /// The block is the new tip, extending the previous one.
    Extended,
    /// The block is the new tip of a branch that replaced `unwound` blocks
    /// of the main chain above `fork_height`.
    Reorganized { fork_height: u32, unwound: u32 },
}

const META_TIP: &str = "tip";
/// Most-work header known, which may be ahead of the tip.
const META_BEST_HEADER: &str = "best_header";
/// Height of the snapshot a fast sync started from: no block at or below
/// it can be disconnected (its undo record does not exist).
const META_FLOOR: &str = "floor";
/// The output counter after the snapshot block.
const META_FLOOR_NEXT: &str = "floor_next";
/// Positions per snapshot part (a subtree of the state tree).
pub const SNAPSHOT_PART_LOG: usize = 14;
// Part roots are read from the stored tree, which starts at this level.
const _: () = assert!(SNAPSHOT_PART_LOG >= crate::utxo::GROUP_LOG);
const META_FORMAT: &str = "format";
/// Version of the on-disk layout: 5 keeps unspent outputs in chunks and
/// the state tree from subtrees of 64 positions up.
const FORMAT: u8 = 5;

/// Status byte of a stored block, after its work in the index.
const STATUS_HEADER_VALID: u8 = 0;
const STATUS_VALID: u8 = 1;
const STATUS_INVALID: u8 = 2;
/// A header checked on its own (proof of work, difficulty, timestamps),
/// stored without its body during a fast sync.
const STATUS_HEADER_ONLY: u8 = 3;

/// A stored header with its index record.
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub header: Header,
    /// Cumulative work of the chain ending at this block.
    pub work: U256,
    /// Whether the block has been connected (its state rules checked).
    pub validated: bool,
    pub invalid: bool,
    /// Stored as a header alone (fast sync), its body not yet seen.
    pub header_only: bool,
}

/// What disconnecting a block needs: the commitments and memos its inputs
/// held, in input order, and where its outputs started.
struct Undo {
    first_output_position: u64,
    spent: Vec<(Commitment, Memo)>,
}

impl Undo {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 64 * self.spent.len());
        out.extend_from_slice(&self.first_output_position.to_le_bytes());
        for (c, m) in &self.spent {
            out.extend_from_slice(&digest_bytes(c));
            out.extend_from_slice(&digest_bytes(m));
        }
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Undo> {
        let (first, rest) = bytes.split_at_checked(8)?;
        if rest.len() % 64 != 0 {
            return None;
        }
        let spent = rest
            .chunks_exact(64)
            .map(|c| Some((digest_from_bytes(&c[..32])?, digest_from_bytes(&c[32..])?)))
            .collect::<Option<Vec<_>>>()?;
        Some(Undo { first_output_position: u64::from_le_bytes(first.try_into().unwrap()), spent })
    }
}

/// Persistent chain state.
pub struct Chain<V: ProofVerifier> {
    env: Env,
    params: ChainParams,
    seed: SeedText,
    verifier: V,
    utxo: UtxoSet,
    headers: Database<Bytes, Bytes>,
    bodies: Database<Bytes, Bytes>,
    /// Block id to its work (32 bytes, little endian) and status byte.
    index: Database<Bytes, Bytes>,
    undo: Database<Bytes, Bytes>,
    by_height: Database<U32<LittleEndian>, Bytes>,
    meta: Database<Str, Bytes>,
    /// Undo records kept, counting back from the tip; `None` keeps all.
    max_undo: Option<u32>,
}

/// Default undo window: a week of blocks.
pub const DEFAULT_MAX_UNDO: u32 = 144 * 7;

fn digest_bytes(d: &Digest) -> [u8; 32] {
    crate::poseidon2::digest_to_bytes(d)
}

fn work_bytes(w: U256) -> [u8; 32] {
    w.to_le_bytes()
}

fn work_from_bytes(b: &[u8]) -> Option<U256> {
    Some(U256::from_le_bytes(b.try_into().ok()?))
}

impl<V: ProofVerifier> Chain<V> {
    /// Opens or creates the chain database at `path`. `seed` must be built
    /// with `params.pow`.
    pub fn open(path: &Path, map_size: usize, params: ChainParams, seed: SeedText, verifier: V) -> Result<Self> {
        let env = open_env(path, map_size).map_err(|e| match e {
            crate::state_tree::Error::Heed(h) => ChainError::Heed(h),
            other => ChainError::Utxo(utxo::Error::Tree(other)),
        })?;
        let mut wtxn = env.write_txn()?;
        let utxo = UtxoSet::open(&env, &mut wtxn, "utxo")?;
        let headers = env.create_database(&mut wtxn, Some("headers"))?;
        let bodies = env.create_database(&mut wtxn, Some("bodies"))?;
        let index = env.create_database(&mut wtxn, Some("index"))?;
        let undo = env.create_database(&mut wtxn, Some("undo"))?;
        let by_height = env.create_database(&mut wtxn, Some("by_height"))?;
        let meta: Database<Str, Bytes> = env.create_database(&mut wtxn, Some("meta"))?;
        match meta.get(&wtxn, META_FORMAT)? {
            Some([FORMAT]) => {}
            Some(_) => return Err(ChainError::OldFormat),
            None if meta.get(&wtxn, META_TIP)?.is_some() => return Err(ChainError::OldFormat),
            None => meta.put(&mut wtxn, META_FORMAT, &[FORMAT])?,
        }
        wtxn.commit()?;
        Ok(Chain {
            env,
            params,
            seed,
            verifier,
            utxo,
            headers,
            bodies,
            index,
            undo,
            by_height,
            meta,
            max_undo: Some(DEFAULT_MAX_UNDO),
        })
    }

    /// Keeps undo records and bodies for the last `blocks` main-chain blocks
    /// (`None` keeps them all, an archive). Older blocks keep only their
    /// headers; reorganizations deeper than that are refused, and
    /// snapshots are served only for blocks within it.
    pub fn with_max_undo(mut self, blocks: Option<u32>) -> Self {
        self.max_undo = blocks;
        self
    }

    /// Deletes undo records and bodies outside the window: those of blocks
    /// at least `max_undo` below the tip. Returns how many undo records
    /// went.
    pub fn prune_undo(&self) -> Result<usize> {
        let Some(keep) = self.max_undo else {
            return Ok(0);
        };
        let mut wtxn = self.env.write_txn()?;
        let tip = self.tip_in(&wtxn)?.ok_or(ChainError::NoGenesis)?;
        let mut n = 0;
        let mut h = tip.height.saturating_sub(keep);
        while h > 0 {
            let Some(header) = self.header_at_in(&wtxn, h)? else {
                break;
            };
            if !self.undo.delete(&mut wtxn, &digest_bytes(&header.hash()))? {
                // Everything below was pruned before.
                break;
            }
            n += 1;
            h -= 1;
        }
        if tip.height > keep {
            self.prune_bodies(&mut wtxn, tip.height - keep)?;
        }
        wtxn.commit()?;
        Ok(n)
    }

    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    pub fn verifier(&self) -> &V {
        &self.verifier
    }

    pub fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    pub fn env(&self) -> &Env {
        &self.env
    }

    fn tip_in(&self, rtxn: &RoTxn) -> Result<Option<Header>> {
        match self.meta.get(rtxn, META_TIP)? {
            None => Ok(None),
            Some(hash) => {
                let bytes = self.headers.get(rtxn, hash)?.ok_or(ChainError::Corrupt("tip header missing"))?;
                Header::from_bytes(bytes).map(Some).ok_or(ChainError::Corrupt("tip header"))
            }
        }
    }

    /// The current tip header, if genesis has been installed.
    pub fn tip(&self) -> Result<Option<Header>> {
        let rtxn = self.env.read_txn()?;
        self.tip_in(&rtxn)
    }

    /// Cumulative work of the main chain, zero before genesis.
    pub fn tip_work(&self) -> Result<U256> {
        let rtxn = self.env.read_txn()?;
        match self.tip_in(&rtxn)? {
            None => Ok(U256::ZERO),
            Some(tip) => Ok(self.entry_in(&rtxn, &tip.hash())?.ok_or(ChainError::Corrupt("tip index"))?.work),
        }
    }

    /// Main-chain header at `height`.
    pub fn header_at(&self, height: u32) -> Result<Option<Header>> {
        let rtxn = self.env.read_txn()?;
        self.header_at_in(&rtxn, height)
    }

    fn header_at_in(&self, rtxn: &RoTxn, height: u32) -> Result<Option<Header>> {
        match self.by_height.get(rtxn, &height)? {
            None => Ok(None),
            Some(hash) => self.header_by_hash_in(rtxn, hash),
        }
    }

    fn header_by_hash_in(&self, rtxn: &RoTxn, hash: &[u8]) -> Result<Option<Header>> {
        match self.headers.get(rtxn, hash)? {
            None => Ok(None),
            Some(bytes) => Header::from_bytes(bytes).map(Some).ok_or(ChainError::Corrupt("header")),
        }
    }

    pub fn header_by_hash(&self, hash: &Digest) -> Result<Option<Header>> {
        let rtxn = self.env.read_txn()?;
        self.header_by_hash_in(&rtxn, &digest_bytes(hash))
    }

    fn body_by_hash_in(&self, rtxn: &RoTxn, hash: &[u8]) -> Result<Option<Body>> {
        match self.bodies.get(rtxn, hash)? {
            None => Ok(None),
            Some(bytes) => Body::from_bytes(bytes).map(Some).map_err(|_| ChainError::Corrupt("body")),
        }
    }

    pub fn body_by_hash(&self, hash: &Digest) -> Result<Option<Body>> {
        let rtxn = self.env.read_txn()?;
        self.body_by_hash_in(&rtxn, &digest_bytes(hash))
    }

    /// A stored valid block, header and body, by id.
    pub fn block_by_hash(&self, hash: &Digest) -> Result<Option<Block>> {
        let rtxn = self.env.read_txn()?;
        let id = digest_bytes(hash);
        match (self.header_by_hash_in(&rtxn, &id)?, self.body_by_hash_in(&rtxn, &id)?) {
            (Some(header), Some(body)) => Ok(Some(Block { header, body })),
            _ => Ok(None),
        }
    }

    fn entry_in(&self, rtxn: &RoTxn, hash: &Digest) -> Result<Option<Entry>> {
        let id = digest_bytes(hash);
        let Some(header) = self.header_by_hash_in(rtxn, &id)? else {
            return Ok(None);
        };
        let rec = self.index.get(rtxn, &id)?.ok_or(ChainError::Corrupt("index record missing"))?;
        if rec.len() != 33 {
            return Err(ChainError::Corrupt("index record"));
        }
        let work = work_from_bytes(&rec[..32]).ok_or(ChainError::Corrupt("work"))?;
        let status = rec[32];
        Ok(Some(Entry {
            header,
            work,
            validated: status == STATUS_VALID,
            invalid: status == STATUS_INVALID,
            header_only: status == STATUS_HEADER_ONLY,
        }))
    }

    /// The stored header, work and status of a block id.
    pub fn entry(&self, hash: &Digest) -> Result<Option<Entry>> {
        let rtxn = self.env.read_txn()?;
        self.entry_in(&rtxn, hash)
    }

    fn put_index(&self, wtxn: &mut RwTxn, id: &[u8; 32], work: U256, status: u8) -> Result<()> {
        let mut rec = [0u8; 33];
        rec[..32].copy_from_slice(&work_bytes(work));
        rec[32] = status;
        self.index.put(wtxn, id, &rec)?;
        Ok(())
    }

    /// Whether `hash` is on the main chain.
    fn is_main_in(&self, rtxn: &RoTxn, header: &Header) -> Result<bool> {
        Ok(self.by_height.get(rtxn, &header.height)? == Some(&digest_bytes(&header.hash())[..]))
    }

    /// Current UTXO root.
    pub fn state_root(&self) -> Result<Digest> {
        let rtxn = self.env.read_txn()?;
        Ok(self.utxo.root(&rtxn)?)
    }

    /// Median timestamp of the `median_time_window` blocks ending at `tip`,
    /// along `tip`'s own branch.
    fn median_time_past(&self, rtxn: &RoTxn, tip: &Header) -> Result<u64> {
        let mut times = Vec::with_capacity(self.params.median_time_window);
        let mut header = *tip;
        loop {
            times.push(header.timestamp);
            if times.len() == self.params.median_time_window || header.height == 0 {
                break;
            }
            header = self
                .header_by_hash_in(rtxn, &digest_bytes(&header.prev_hash))?
                .ok_or(ChainError::Corrupt("missing ancestor header"))?;
        }
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }

    /// ASERT schedule anchored at genesis.
    fn asert(&self, genesis: &Header) -> Asert {
        Asert::from_genesis(genesis.timestamp as i64, self.params.genesis_target, self.params.max_target)
    }

    fn target_after(&self, rtxn: &RoTxn, parent: &Header) -> Result<Target> {
        let genesis = self.header_at_in(rtxn, 0)?.ok_or(ChainError::NoGenesis)?;
        Ok(self.asert(&genesis).next_target(parent.height as u64, parent.timestamp as i64).into())
    }

    /// Target the block after `parent` must meet.
    pub fn expected_target(&self, parent: &Header) -> Result<Target> {
        let rtxn = self.env.read_txn()?;
        self.target_after(&rtxn, parent)
    }

    /// Installs the genesis block. Its header must have height 0 and a zero
    /// previous hash, and its state root must match its outputs applied to
    /// an empty tree. Proof of work and timestamp are not checked.
    pub fn init_genesis(&self, block: &Block) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        if self.meta.get(&wtxn, META_TIP)?.is_some() {
            return Err(ChainError::AlreadyInitialized);
        }
        if block.header.height != 0 {
            return Err(ChainError::BadHeight { expected: 0, got: block.header.height });
        }
        if block.header.prev_hash != EMPTY {
            return Err(ChainError::UnknownParent(block.header.prev_hash));
        }
        if !block.body.inputs.is_empty() {
            return Err(ChainError::UnknownInput(block.body.inputs[0]));
        }
        self.check_body(&block.header, &block.body)?;
        let (root, _) = self.apply_body(&mut wtxn, &block.body)?;
        if root != block.header.state_root {
            return Err(ChainError::StateRootMismatch { expected: root, got: block.header.state_root });
        }
        let id = digest_bytes(&block.header.hash());
        self.headers.put(&mut wtxn, &id, &block.header.to_bytes())?;
        self.bodies.put(&mut wtxn, &id, &block.body.to_bytes())?;
        self.put_index(&mut wtxn, &id, U256::ZERO, STATUS_VALID)?;
        self.undo.put(&mut wtxn, &id, &Undo { first_output_position: 0, spent: vec![] }.to_bytes())?;
        self.by_height.put(&mut wtxn, &0, &id)?;
        self.meta.put(&mut wtxn, META_TIP, &id)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Installs `params.genesis()` if the chain is empty, and checks that
    /// an existing chain starts from it.
    pub fn init_or_check_genesis(&self) -> Result<()> {
        let expected = self.params.genesis();
        match self.header_at(0)? {
            None => self.init_genesis(&expected),
            Some(h) if h == expected.header => Ok(()),
            Some(_) => Err(ChainError::WrongGenesis),
        }
    }

    /// The commitment is checked first: the other failures condemn the
    /// header, and only hold for the body it commits to.
    fn check_body(&self, header: &Header, body: &Body) -> Result<()> {
        if header.body_commitment != body.commitment() {
            return Err(ChainError::BadBodyCommitment);
        }
        body.validate()?;
        let size = HEADER_SIZE + body.size();
        if size > self.params.max_block_size {
            return Err(ChainError::TooLarge(size));
        }
        Ok(())
    }

    /// Spends the inputs and appends the outputs; returns the new root and
    /// the commitments the inputs held.
    fn apply_body(&self, wtxn: &mut RwTxn, body: &Body) -> Result<(Digest, Vec<(Commitment, Memo)>)> {
        let mut spent = Vec::with_capacity(body.inputs.len());
        for &pos in &body.inputs {
            let commitment = self.utxo.get(wtxn, pos)?;
            let memo = self.utxo.memo(wtxn, pos)?;
            if commitment == EMPTY || !self.utxo.spend_at(wtxn, &commitment, pos)? {
                return Err(ChainError::UnknownInput(pos));
            }
            spent.push((commitment, memo));
        }
        self.utxo.add_outputs(wtxn, &body.outputs)?;
        Ok((self.utxo.root(wtxn)?, spent))
    }

    /// Header rules (1 to 4) of a block whose parent is `parent`: returns
    /// the block's cumulative work.
    fn check_header(&self, rtxn: &RoTxn, block: &Block, parent: &Entry, now: u64) -> Result<U256> {
        let work = self.check_header_rules(rtxn, &block.header, parent, now)?;
        self.check_body(&block.header, &block.body)?;
        Ok(work)
    }

    /// The header rules alone (1 to 3): returns the header's cumulative work.
    fn check_header_rules(&self, rtxn: &RoTxn, header: &Header, parent: &Entry, now: u64) -> Result<U256> {
        if parent.invalid {
            return Err(ChainError::InvalidParent);
        }
        let expected_height = parent
            .header
            .height
            .checked_add(1)
            .ok_or(ChainError::BadHeight { expected: u32::MAX, got: header.height })?;
        if header.height != expected_height {
            return Err(ChainError::BadHeight { expected: expected_height, got: header.height });
        }
        if header.height > self.params.final_height() {
            return Err(ChainError::ChainEnded);
        }
        let median = self.median_time_past(rtxn, &parent.header)?;
        if header.timestamp <= median {
            return Err(ChainError::TimestampTooOld { median, got: header.timestamp });
        }
        let limit = now.saturating_add(self.params.max_future_drift);
        if header.timestamp > limit {
            return Err(ChainError::TimestampTooNew { limit, got: header.timestamp });
        }
        let target = self.target_after(rtxn, &parent.header)?;
        if !header.quick_pow_check(&target) || !header.verify_pow(&self.seed, &target) {
            return Err(ChainError::BadProofOfWork);
        }
        Ok(parent.work.saturating_add(ChainParams::block_work(target.into())))
    }

    /// Validates `block` and, if it passes every rule, stores it; if its
    /// branch then has the most work, makes it the tip, reorganizing the
    /// main chain if needed. `now` is the caller's clock in unix seconds.
    pub fn apply_block(&self, block: &Block, now: u64) -> Result<Applied> {
        let result = self.apply_block_inner(block, now);
        if let Err(e) = &result
            && e.is_invalid_block()
        {
            // Remember the verdict so the block is not validated again.
            let mut wtxn = self.env.write_txn()?;
            let id = digest_bytes(&block.header.hash());
            if self.headers.get(&wtxn, &id)?.is_none() {
                self.headers.put(&mut wtxn, &id, &block.header.to_bytes())?;
            }
            self.put_index(&mut wtxn, &id, U256::ZERO, STATUS_INVALID)?;
            wtxn.commit()?;
        }
        result
    }

    fn apply_block_inner(&self, block: &Block, now: u64) -> Result<Applied> {
        let header = &block.header;
        let mut wtxn = self.env.write_txn()?;
        let tip = self.tip_in(&wtxn)?.ok_or(ChainError::NoGenesis)?;
        let tip_entry = self.entry_in(&wtxn, &tip.hash())?.ok_or(ChainError::Corrupt("tip index"))?;
        let hash = header.hash();
        let id = digest_bytes(&hash);
        if let Some(e) = self.entry_in(&wtxn, &hash)?
            && !e.header_only
        {
            return if e.invalid { Err(ChainError::KnownInvalid) } else { Ok(Applied::Known) };
        }
        let parent = self.entry_in(&wtxn, &header.prev_hash)?.ok_or(ChainError::UnknownParent(header.prev_hash))?;
        let work = self.check_header(&wtxn, block, &parent, now)?;

        self.headers.put(&mut wtxn, &id, &header.to_bytes())?;
        self.bodies.put(&mut wtxn, &id, &block.body.to_bytes())?;
        self.put_index(&mut wtxn, &id, work, STATUS_HEADER_VALID)?;
        if work <= tip_entry.work {
            wtxn.commit()?;
            return Ok(Applied::Side);
        }

        // The branch from the main chain to the block, oldest first.
        let mut branch = vec![*header];
        let mut cur = parent;
        while !self.is_main_in(&wtxn, &cur.header)? {
            branch.push(cur.header);
            cur = self.entry_in(&wtxn, &cur.header.prev_hash)?.ok_or(ChainError::Corrupt("branch parent missing"))?;
        }
        branch.reverse();
        let fork_height = cur.header.height;
        let unwound = tip.height - fork_height;
        for h in (fork_height + 1..=tip.height).rev() {
            self.disconnect(&mut wtxn, h)?;
        }
        for (i, h) in branch.iter().enumerate() {
            let body = if i + 1 == branch.len() {
                block.body.clone()
            } else {
                self.body_by_hash_in(&wtxn, &digest_bytes(&h.hash()))?.ok_or(ChainError::MissingBody)?
            };
            if let Err(e) = self.connect(&mut wtxn, h, &body) {
                drop(wtxn);
                if e.is_invalid_block() {
                    // The failed block and everything stored after it on
                    // this branch can never connect.
                    let mut wtxn = self.env.write_txn()?;
                    for bad in &branch[i..] {
                        let bad_id = digest_bytes(&bad.hash());
                        if self.headers.get(&wtxn, &bad_id)?.is_some() {
                            self.put_index(&mut wtxn, &bad_id, U256::ZERO, STATUS_INVALID)?;
                            self.bodies.delete(&mut wtxn, &bad_id)?;
                        }
                    }
                    wtxn.commit()?;
                }
                return Err(e);
            }
        }
        wtxn.commit()?;
        Ok(if unwound == 0 { Applied::Extended } else { Applied::Reorganized { fork_height, unwound } })
    }

    /// Connects a stored header-valid block on top of the tip, which must be
    /// its parent: state rules 5 to 7.
    fn connect(&self, wtxn: &mut RwTxn, header: &Header, body: &Body) -> Result<()> {
        let id = digest_bytes(&header.hash());
        let prev_state_root = self.utxo.root(wtxn)?;
        let first_output_position = self.utxo.next_position(wtxn)?;
        let (new_root, spent) = self.apply_body(wtxn, body)?;
        if new_root != header.state_root {
            return Err(ChainError::StateRootMismatch { expected: new_root, got: header.state_root });
        }
        let statement = BlockStatement {
            height: header.height,
            prev_state_root,
            new_state_root: new_root,
            first_output_position,
            subsidy: self.params.subsidy(header.height),
            body,
        };
        if !self.verifier.verify(&statement, &body.proof) {
            return Err(ChainError::BadProof);
        }
        let work = self.entry_in(wtxn, &header.hash())?.ok_or(ChainError::Corrupt("connecting unknown block"))?.work;
        self.put_index(wtxn, &id, work, STATUS_VALID)?;
        self.undo.put(wtxn, &id, &Undo { first_output_position, spent }.to_bytes())?;
        self.by_height.put(wtxn, &header.height, &id)?;
        self.meta.put(wtxn, META_TIP, &id)?;
        // The block leaving the undo window keeps only its header.
        if let Some(keep) = self.max_undo
            && header.height > keep
            && let Some(old) = self.header_at_in(wtxn, header.height - keep)?
        {
            self.undo.delete(wtxn, &digest_bytes(&old.hash()))?;
            self.prune_bodies(wtxn, header.height - keep)?;
        }
        Ok(())
    }

    /// Deletes the bodies of every block at or below `height` but genesis,
    /// on the main chain or not: no reorganization can reach them, and the
    /// chain proof of every later block covers them. Returns how many went.
    fn prune_bodies(&self, wtxn: &mut RwTxn, height: u32) -> Result<usize> {
        let mut old = Vec::new();
        for item in self.bodies.iter(wtxn)? {
            let (id, _) = item?;
            if let Some(h) = self.header_by_hash_in(wtxn, id)?
                && (1..=height).contains(&h.height)
            {
                old.push(id.to_vec());
            }
        }
        for id in &old {
            self.bodies.delete(wtxn, id)?;
        }
        Ok(old.len())
    }

    /// Disconnects the main-chain block at `height`, the tip, restoring the
    /// outputs it spent and removing the ones it appended.
    fn disconnect(&self, wtxn: &mut RwTxn, height: u32) -> Result<()> {
        if self.floor_in(wtxn)?.is_some_and(|f| height <= f) {
            return Err(ChainError::BelowSnapshot);
        }
        let header = self.header_at_in(wtxn, height)?.ok_or(ChainError::Corrupt("disconnecting missing height"))?;
        let id = digest_bytes(&header.hash());
        let undo = match self.undo.get(wtxn, &id)? {
            Some(b) => Undo::from_bytes(b).ok_or(ChainError::Corrupt("undo record"))?,
            None if self.max_undo.is_some() => return Err(ChainError::BeyondUndo),
            None => return Err(ChainError::Corrupt("undo record")),
        };
        let body = self.body_by_hash_in(wtxn, &id)?.ok_or(ChainError::Corrupt("body of main-chain block"))?;
        if undo.spent.len() != body.inputs.len() {
            return Err(ChainError::Corrupt("undo record length"));
        }
        let commitments: Vec<Commitment> = body.outputs.iter().map(|o| o.commitment).collect();
        self.utxo.truncate(wtxn, undo.first_output_position, &commitments)?;
        for (&pos, (c, m)) in body.inputs.iter().zip(&undo.spent) {
            self.utxo.unspend(wtxn, c, m, pos)?;
        }
        let parent = self
            .header_by_hash_in(wtxn, &digest_bytes(&header.prev_hash))?
            .ok_or(ChainError::Corrupt("parent of main-chain block"))?;
        if self.utxo.root(wtxn)? != parent.state_root {
            return Err(ChainError::Corrupt("state root after disconnect"));
        }
        self.by_height.delete(wtxn, &height)?;
        self.meta.put(wtxn, META_TIP, &digest_bytes(&header.prev_hash))?;
        Ok(())
    }

    fn floor_in(&self, rtxn: &RoTxn) -> Result<Option<u32>> {
        match self.meta.get(rtxn, META_FLOOR)? {
            None => Ok(None),
            Some(b) => Ok(Some(u32::from_le_bytes(b.try_into().map_err(|_| ChainError::Corrupt("floor"))?))),
        }
    }

    /// Height of the snapshot this chain was fast-synced from, if any.
    pub fn floor(&self) -> Result<Option<u32>> {
        let rtxn = self.env.read_txn()?;
        self.floor_in(&rtxn)
    }

    /// Checks a header against its stored parent (proof of work,
    /// difficulty, timestamps) and stores it without a body, for a fast
    /// sync. Returns whether it was new.
    pub fn accept_header(&self, header: &Header, now: u64) -> Result<bool> {
        let mut wtxn = self.env.write_txn()?;
        let id = digest_bytes(&header.hash());
        if let Some(e) = self.entry_in(&wtxn, &header.hash())? {
            return if e.invalid { Err(ChainError::KnownInvalid) } else { Ok(false) };
        }
        let parent = self.entry_in(&wtxn, &header.prev_hash)?.ok_or(ChainError::UnknownParent(header.prev_hash))?;
        let work = match self.check_header_rules(&wtxn, header, &parent, now) {
            Ok(w) => w,
            Err(e) => {
                drop(wtxn);
                return Err(e);
            }
        };
        self.headers.put(&mut wtxn, &id, &header.to_bytes())?;
        self.put_index(&mut wtxn, &id, work, STATUS_HEADER_ONLY)?;
        let best = self.best_header_in(&wtxn)?;
        if work > self.entry_in(&wtxn, &best.hash())?.map_or(U256::ZERO, |e| e.work) {
            self.meta.put(&mut wtxn, META_BEST_HEADER, &id)?;
        }
        wtxn.commit()?;
        Ok(true)
    }

    fn best_header_in(&self, rtxn: &RoTxn) -> Result<Header> {
        let tip = self.tip_in(rtxn)?.ok_or(ChainError::NoGenesis)?;
        let Some(id) = self.meta.get(rtxn, META_BEST_HEADER)? else {
            return Ok(tip);
        };
        let best = self.header_by_hash_in(rtxn, id)?.ok_or(ChainError::Corrupt("best header"))?;
        let w = |h: &Header| -> Result<U256> { Ok(self.entry_in(rtxn, &h.hash())?.map_or(U256::ZERO, |e| e.work)) };
        Ok(if w(&best)? > w(&tip)? { best } else { tip })
    }

    /// The most-work header known: the tip, or a header stored ahead of it.
    pub fn best_header(&self) -> Result<Header> {
        let rtxn = self.env.read_txn()?;
        self.best_header_in(&rtxn)
    }

    /// Cumulative work of [`Chain::best_header`].
    pub fn best_header_work(&self) -> Result<U256> {
        let rtxn = self.env.read_txn()?;
        let best = self.best_header_in(&rtxn)?;
        Ok(self.entry_in(&rtxn, &best.hash())?.map_or(U256::ZERO, |e| e.work))
    }

    /// The ancestor at `height` of the stored header `from`.
    pub fn ancestor(&self, from: &Header, height: u32) -> Result<Option<Header>> {
        let rtxn = self.env.read_txn()?;
        if height > from.height {
            return Ok(None);
        }
        let mut h = *from;
        while h.height > height {
            match self.header_by_hash_in(&rtxn, &digest_bytes(&h.prev_hash))? {
                Some(p) => h = p,
                None => return Ok(None),
            }
        }
        Ok(Some(h))
    }

    /// A block locator from the best header: it, then the main chain's.
    pub fn header_locator(&self) -> Result<Vec<Digest>> {
        let best = self.best_header()?;
        let mut loc = self.locator()?;
        if loc.first() != Some(&best.hash()) {
            loc.insert(0, best.hash());
        }
        loc.truncate(32);
        Ok(loc)
    }

    /// Checks that `block`, whose header is stored, is valid with the given
    /// output counter after it (from a snapshot manifest): body rules and
    /// its proof, which covers every block before it. The statement's
    /// previous state root comes from the stored parent header.
    pub fn verify_snapshot_block(&self, block: &Block, next_position: u64) -> Result<()> {
        let rtxn = self.env.read_txn()?;
        if block.header.height == 0 {
            return Err(ChainError::BadSnapshot);
        }
        self.entry_in(&rtxn, &block.header.hash())?.ok_or(ChainError::UnknownParent(block.header.hash()))?;
        let parent = self
            .header_by_hash_in(&rtxn, &digest_bytes(&block.header.prev_hash))?
            .ok_or(ChainError::UnknownParent(block.header.prev_hash))?;
        self.check_body(&block.header, &block.body)?;
        let first = next_position.checked_sub(block.body.outputs.len() as u64).ok_or(ChainError::BadSnapshot)?;
        let statement = BlockStatement {
            height: block.header.height,
            prev_state_root: parent.state_root,
            new_state_root: block.header.state_root,
            first_output_position: first,
            subsidy: self.params.subsidy(block.header.height),
            body: &block.body,
        };
        if !self.verifier.verify(&statement, &block.body.proof) {
            return Err(ChainError::BadProof);
        }
        Ok(())
    }

    /// Installs a verified snapshot: the unspent outputs after `block`
    /// (stored as a header, verified with [`Chain::verify_snapshot_block`])
    /// and the output counter. The chain must hold genesis alone. Every
    /// ancestor becomes part of the main chain without its body; `block`
    /// is the new tip and the floor below which nothing reorganizes.
    pub fn install_snapshot(
        &self,
        block: &Block,
        outputs: &[(u64, Commitment, Memo)],
        next_position: u64,
    ) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let tip = self.tip_in(&wtxn)?.ok_or(ChainError::NoGenesis)?;
        if tip.height != 0 || self.utxo.next_position(&wtxn)? != 0 {
            return Err(ChainError::AlreadyInitialized);
        }
        let header = block.header;
        let entry = self.entry_in(&wtxn, &header.hash())?.ok_or(ChainError::UnknownParent(header.hash()))?;
        self.check_body(&header, &block.body)?;
        if outputs.windows(2).any(|w| w[0].0 >= w[1].0) || outputs.last().is_some_and(|o| o.0 >= next_position) {
            return Err(ChainError::BadSnapshot);
        }
        self.utxo.install(&mut wtxn, outputs, next_position)?;
        if self.utxo.root(&wtxn)? != header.state_root {
            return Err(ChainError::BadSnapshot);
        }
        // The main chain up to the snapshot: proven by its block's proof.
        let mut h = header;
        loop {
            let id = digest_bytes(&h.hash());
            let e = self.entry_in(&wtxn, &h.hash())?.ok_or(ChainError::Corrupt("snapshot ancestor"))?;
            self.put_index(&mut wtxn, &id, e.work, STATUS_VALID)?;
            self.by_height.put(&mut wtxn, &h.height, &id)?;
            if h.height == 0 {
                break;
            }
            h = self
                .header_by_hash_in(&wtxn, &digest_bytes(&h.prev_hash))?
                .ok_or(ChainError::Corrupt("snapshot ancestor header"))?;
        }
        let id = digest_bytes(&header.hash());
        self.bodies.put(&mut wtxn, &id, &block.body.to_bytes())?;
        self.put_index(&mut wtxn, &id, entry.work, STATUS_VALID)?;
        self.meta.put(&mut wtxn, META_TIP, &id)?;
        self.meta.put(&mut wtxn, META_FLOOR, &header.height.to_le_bytes())?;
        self.meta.put(&mut wtxn, META_FLOOR_NEXT, &next_position.to_le_bytes())?;
        wtxn.commit()?;
        Ok(())
    }

    /// The state after the main-chain block `id`: its output counter and
    /// the outputs spent since, to restore (position to commitment and
    /// memo). `None` if the block is not on the main chain or older than
    /// this node's undo records.
    #[allow(clippy::type_complexity)]
    fn state_after(&self, rtxn: &RoTxn, id: &Digest) -> Result<Option<(u64, HashMap<u64, (Commitment, Memo)>)>> {
        let Some(header) = self.header_by_hash_in(rtxn, &digest_bytes(id))? else {
            return Ok(None);
        };
        if !self.is_main_in(rtxn, &header)? || header.height == 0 {
            return Ok(None);
        }
        let key = digest_bytes(id);
        let next = match self.undo.get(rtxn, &key)?.and_then(Undo::from_bytes) {
            Some(u) => {
                let body = self.body_by_hash_in(rtxn, &key)?.ok_or(ChainError::Corrupt("main-chain body"))?;
                u.first_output_position + body.outputs.len() as u64
            }
            None if self.floor_in(rtxn)? == Some(header.height) => {
                let b = self.meta.get(rtxn, META_FLOOR_NEXT)?.ok_or(ChainError::Corrupt("floor counter"))?;
                u64::from_le_bytes(b.try_into().map_err(|_| ChainError::Corrupt("floor counter"))?)
            }
            None => return Ok(None),
        };
        let tip = self.tip_in(rtxn)?.ok_or(ChainError::NoGenesis)?;
        let mut restored = HashMap::new();
        for h in header.height + 1..=tip.height {
            let hd = self.header_at_in(rtxn, h)?.ok_or(ChainError::Corrupt("main-chain header"))?;
            let k = digest_bytes(&hd.hash());
            let body = self.body_by_hash_in(rtxn, &k)?.ok_or(ChainError::Corrupt("main-chain body"))?;
            let undo = self.undo.get(rtxn, &k)?.and_then(Undo::from_bytes).ok_or(ChainError::Corrupt("undo record"))?;
            for (&pos, spent) in body.inputs.iter().zip(&undo.spent) {
                if pos < next {
                    restored.insert(pos, *spent);
                }
            }
        }
        Ok(Some((next, restored)))
    }

    /// The unspent outputs in snapshot part `part` of the state after the
    /// main-chain block `id`: positions `part << SNAPSHOT_PART_LOG` and on.
    #[allow(clippy::type_complexity)]
    fn snapshot_part_in(
        &self,
        rtxn: &RoTxn,
        next: u64,
        restored: &HashMap<u64, (Commitment, Memo)>,
        part: u64,
    ) -> Result<Vec<(u64, Commitment, Memo)>> {
        let first = part << SNAPSHOT_PART_LOG;
        let end = (first + (1 << SNAPSHOT_PART_LOG)).min(next);
        let mut out: Vec<(u64, Commitment, Memo)> =
            self.utxo.unspent_in(rtxn, first, end)?.into_iter().map(|(p, (c, m))| (p, c, m)).collect();
        let before = out.len();
        out.extend(restored.iter().filter(|(p, _)| (first..end).contains(*p)).map(|(p, (c, m))| (*p, *c, *m)));
        if out.len() > before {
            out.sort_unstable_by_key(|o| o.0);
        }
        Ok(out)
    }

    /// A snapshot manifest of the state after the main-chain block `id`:
    /// the output counter and the root of every part's subtree.
    pub fn snapshot_manifest(&self, id: &Digest) -> Result<Option<(u64, Vec<Digest>)>> {
        let rtxn = self.env.read_txn()?;
        let Some((next, restored)) = self.state_after(&rtxn, id)? else {
            return Ok(None);
        };
        let parts = next.div_ceil(1 << SNAPSHOT_PART_LOG);
        // Parts wholly below the counter that nothing since has spent from
        // are as stored now; only the others are recomputed.
        let touched: std::collections::HashSet<u64> = restored.keys().map(|p| p >> SNAPSHOT_PART_LOG).collect();
        let mut roots = Vec::with_capacity(parts as usize);
        for p in 0..parts {
            if !touched.contains(&p) && (p + 1) << SNAPSHOT_PART_LOG <= next {
                roots.push(self.utxo.subtree(&rtxn, SNAPSHOT_PART_LOG, p)?);
                continue;
            }
            let leaves: Vec<(u64, Digest)> = self
                .snapshot_part_in(&rtxn, next, &restored, p)?
                .iter()
                .map(|(pos, c, m)| (*pos, crate::transaction::leaf(c, m)))
                .collect();
            roots.push(crate::state_tree::subtree_root(SNAPSHOT_PART_LOG, p << SNAPSHOT_PART_LOG, &leaves));
        }
        Ok(Some((next, roots)))
    }

    /// Part `part` of the snapshot after the main-chain block `id`.
    #[allow(clippy::type_complexity)]
    pub fn snapshot_part(&self, id: &Digest, part: u64) -> Result<Option<Vec<(u64, Commitment, Memo)>>> {
        let rtxn = self.env.read_txn()?;
        let Some((next, restored)) = self.state_after(&rtxn, id)? else {
            return Ok(None);
        };
        if part >= next.div_ceil(1 << SNAPSHOT_PART_LOG) {
            return Ok(None);
        }
        Ok(Some(self.snapshot_part_in(&rtxn, next, &restored, part)?))
    }

    /// The proof statement and proof of the main-chain block at `height`
    /// (at least 1): what the next block's chain proof builds on.
    pub fn proof_statement(&self, height: u32) -> Result<Option<(crate::aggregate::Statement, Vec<u8>)>> {
        let rtxn = self.env.read_txn()?;
        let (Some(header), Some(parent)) =
            (self.header_at_in(&rtxn, height)?, self.header_at_in(&rtxn, height.saturating_sub(1))?)
        else {
            return Ok(None);
        };
        if height == 0 {
            return Ok(None);
        }
        let id = digest_bytes(&header.hash());
        let body = self.body_by_hash_in(&rtxn, &id)?.ok_or(ChainError::Corrupt("main-chain body"))?;
        let undo = self.undo.get(&rtxn, &id)?.and_then(Undo::from_bytes).ok_or(ChainError::Corrupt("undo record"))?;
        let statement = crate::aggregate::Statement::from_block(&BlockStatement {
            height,
            prev_state_root: parent.state_root,
            new_state_root: header.state_root,
            first_output_position: undo.first_output_position,
            subsidy: self.params.subsidy(height),
            body: &body,
        });
        Ok(Some((statement, body.proof)))
    }

    /// Block ids locating the main chain for a peer: the tip and its
    /// ancestors at exponentially growing distances, then genesis.
    pub fn locator(&self) -> Result<Vec<Digest>> {
        let rtxn = self.env.read_txn()?;
        let Some(tip) = self.tip_in(&rtxn)? else {
            return Ok(vec![]);
        };
        let mut out = Vec::new();
        let mut step = 1u32;
        let mut h = tip.height;
        loop {
            let header = self.header_at_in(&rtxn, h)?.ok_or(ChainError::Corrupt("main-chain header"))?;
            out.push(header.hash());
            if h == 0 {
                break;
            }
            if out.len() > 10 {
                step = step.saturating_mul(2);
            }
            h = h.saturating_sub(step);
        }
        Ok(out)
    }

    /// Up to `max` main-chain headers after the first id of `locator` that
    /// is on the main chain, oldest first. Without a match, headers after
    /// genesis.
    pub fn headers_after(&self, locator: &[Digest], max: usize) -> Result<Vec<Header>> {
        let rtxn = self.env.read_txn()?;
        let Some(tip) = self.tip_in(&rtxn)? else {
            return Ok(vec![]);
        };
        let mut from = 0u32;
        for hash in locator {
            if let Some(h) = self.header_by_hash_in(&rtxn, &digest_bytes(hash))?
                && self.is_main_in(&rtxn, &h)?
            {
                from = h.height;
                break;
            }
        }
        let mut out = Vec::new();
        let mut h = from;
        while out.len() < max && h < tip.height {
            h += 1;
            out.push(self.header_at_in(&rtxn, h)?.ok_or(ChainError::Corrupt("main-chain header"))?);
        }
        Ok(out)
    }

    /// State root that applying `body` on top of the tip would produce,
    /// without committing. Used to fill a block template.
    pub fn preview_state_root(&self, body: &Body) -> Result<Digest> {
        let mut wtxn = self.env.write_txn()?;
        let (root, _) = self.apply_body(&mut wtxn, body)?;
        wtxn.abort();
        Ok(root)
    }

    /// A header extending the tip for `body` at `timestamp`, with mix and
    /// nonce zeroed, ready to be mined against [`Chain::expected_target`].
    pub fn template(&self, body: &Body, timestamp: u64) -> Result<Header> {
        let tip = self.tip()?.ok_or(ChainError::NoGenesis)?;
        Ok(Header {
            prev_hash: tip.hash(),
            height: tip.height + 1,
            timestamp,
            body_commitment: body.commitment(),
            state_root: self.preview_state_root(body)?,
            mix: EMPTY,
            nonce: [0u8; 32],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::{self, Dataset, nonce_from_u64};
    use crate::transaction::{Key, Output};
    use crate::xmss::PublicKey;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("tabminer-chain-{}-{name}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn mainnet_segments_cover_the_largest_block() {
        // Inputs cost the most rows per byte (1237 for 5), so the block that
        // needs the most segments is all inputs, with no proof bytes.
        let p = ChainParams::MAINNET;
        let n = (p.max_block_size - HEADER_SIZE - 12) / crate::block::POSITION_SIZE;
        let segments = crate::block_air::pack(1, |_| (n, 0), p.aggregator.segment_rows()).len();
        assert!(segments <= p.aggregator.max_segments, "{n} inputs need {segments} segments");
        println!("{n} inputs: {segments} of {} segments", p.aggregator.max_segments);
    }

    const POW: PowParams = PowParams { log_dataset_items: 8, parents: 32, accesses: 64 };
    const GENESIS_TIME: u64 = 1_700_000_000;

    fn params() -> ChainParams {
        ChainParams {
            pow: POW,
            genesis_timestamp: GENESIS_TIME,
            genesis_nonce: [0u8; 32],
            // Easy: 2^240, about 2^8 hashes per block.
            genesis_target: U256([0, 0, 0, 1 << 48]),
            max_target: ChainParams::MAINNET.max_target,
            // Four outputs and a short proof.
            max_block_size: HEADER_SIZE + 12 + 4 * crate::block::BLOCK_OUTPUT_SIZE + 31,
            max_future_drift: 7200,
            median_time_window: 11,
            emission: &[(10, 50), (10, 25), (5, 12)],
            aggregator: AggregatorParams::MAINNET,
        }
    }

    fn seed() -> SeedText {
        let text: Vec<u8> = (0..20_000u32).map(|i| (i * 31 % 253) as u8).collect();
        SeedText::from_bytes(POW, text)
    }

    fn pk(tag: u8) -> PublicKey {
        let mut s = [0u8; 32];
        s[0] = tag;
        Key::generate(&s).public_key()
    }

    struct Fixture {
        _dir: TempDir,
        chain: Chain<AcceptAllProofs>,
        dataset: Dataset,
    }

    fn open(name: &str) -> Fixture {
        let dir = TempDir::new(name);
        let seed = seed();
        let dataset = Dataset::generate(&seed);
        let chain = Chain::open(&dir.0, 64 << 20, params(), seed, AcceptAllProofs).unwrap();
        Fixture { _dir: dir, chain, dataset }
    }

    fn genesis_block(outputs: Vec<Output>) -> Block {
        let body = Body { inputs: vec![], outputs: outputs.iter().map(|o| o.block_output()).collect(), proof: vec![] };
        // State root: compute via a throwaway chain.
        let dir = TempDir::new("genesis-scratch");
        let scratch = Chain::open(&dir.0, 64 << 20, params(), seed(), AcceptAllProofs).unwrap();
        let state_root = scratch.preview_state_root(&body).unwrap();
        let header = Header {
            prev_hash: EMPTY,
            height: 0,
            timestamp: GENESIS_TIME,
            body_commitment: body.commitment(),
            state_root,
            mix: EMPTY,
            nonce: [0u8; 32],
        };
        Block { header, body }
    }

    /// Mines `header` (nonce and mix are overwritten) against the tip's target.
    fn solve(f: &Fixture, mut header: Header) -> Header {
        let tip = f.chain.tip().unwrap().unwrap();
        let target = f.chain.expected_target(&tip).unwrap();
        let (nonce, out) =
            pow::mine(&f.dataset, &header.pow_hash(), &target, (0..1_000_000).map(nonce_from_u64)).unwrap();
        header.nonce = nonce;
        header.mix = out.mix;
        header
    }

    fn mine(f: &Fixture, body: Body, timestamp: u64) -> Block {
        let header = f.chain.template(&body, timestamp).unwrap();
        Block { header: solve(f, header), body }
    }

    /// Like `mine` but with a caller-supplied state root, for bodies the
    /// chain would refuse to preview.
    fn mine_with_root(f: &Fixture, body: Body, timestamp: u64, state_root: Digest) -> Block {
        let tip = f.chain.tip().unwrap().unwrap();
        let header = Header {
            prev_hash: tip.hash(),
            height: tip.height + 1,
            timestamp,
            body_commitment: body.commitment(),
            state_root,
            mix: EMPTY,
            nonce: [0u8; 32],
        };
        Block { header: solve(f, header), body }
    }

    #[test]
    fn genesis_then_blocks() {
        let f = open("basic");
        assert!(f.chain.tip().unwrap().is_none());
        assert!(matches!(f.chain.apply_block(&genesis_block(vec![]), GENESIS_TIME), Err(ChainError::NoGenesis)));

        let a = pk(1);
        let b = pk(2);
        let genesis = genesis_block(vec![Output::new(&a, 100), Output::new(&a, 50)]);
        f.chain.init_genesis(&genesis).unwrap();
        assert!(matches!(f.chain.init_genesis(&genesis), Err(ChainError::AlreadyInitialized)));
        let tip = f.chain.tip().unwrap().unwrap();
        assert_eq!(tip, genesis.header);
        assert_eq!(f.chain.state_root().unwrap(), genesis.header.state_root);
        assert_eq!(f.chain.header_at(0).unwrap(), Some(genesis.header));
        assert_eq!(f.chain.body_by_hash(&genesis.header.hash()).unwrap(), Some(genesis.body.clone()));

        // Block 1 spends position 0 and creates two outputs (3 and 4 would be
        // positions 2 and 3).
        let body1 = Body {
            inputs: vec![0],
            outputs: vec![Output::new(&b, 60).block_output(), Output::new(&a, 40).block_output()],
            proof: vec![9],
        };
        let block1 = mine(&f, body1, GENESIS_TIME + 600);
        f.chain.apply_block(&block1, GENESIS_TIME + 700).unwrap();
        assert_eq!(f.chain.tip().unwrap().unwrap().height, 1);
        {
            let rtxn = f.chain.env().read_txn().unwrap();
            assert_eq!(f.chain.utxo().get(&rtxn, 0).unwrap(), EMPTY);
            assert_eq!(f.chain.utxo().get(&rtxn, 2).unwrap(), Output::new(&b, 60).commitment);
            assert_eq!(f.chain.utxo().next_position(&rtxn).unwrap(), 4);
            assert_eq!(f.chain.utxo().len(&rtxn).unwrap(), 3);
        }

        // Block 2 spends positions 1 and 2, with a reward-only style output.
        let body2 = Body { inputs: vec![1, 2], outputs: vec![Output::new(&b, 200).block_output()], proof: vec![] };
        let block2 = mine(&f, body2, GENESIS_TIME + 1200);
        f.chain.apply_block(&block2, GENESIS_TIME + 1300).unwrap();
        assert_eq!(f.chain.tip().unwrap().unwrap().height, 2);
        assert_eq!(f.chain.header_at(2).unwrap(), Some(block2.header));
        assert_eq!(f.chain.header_by_hash(&block1.header.hash()).unwrap(), Some(block1.header));

        // Spending an already spent position fails and leaves state intact.
        let root_before = f.chain.state_root().unwrap();
        let bad = mine_with_root(
            &f,
            Body { inputs: vec![0], outputs: vec![], proof: vec![] },
            GENESIS_TIME + 1800,
            root_before,
        );
        assert!(matches!(f.chain.template(&bad.body, GENESIS_TIME + 1800), Err(ChainError::UnknownInput(0))));
        assert!(matches!(f.chain.apply_block(&bad, GENESIS_TIME + 1900), Err(ChainError::UnknownInput(0))));
        assert_eq!(f.chain.state_root().unwrap(), root_before);
        assert_eq!(f.chain.tip().unwrap().unwrap().height, 2);
    }

    #[test]
    fn subsidy_schedule() {
        let p = params();
        assert_eq!(p.subsidy(0), 0);
        assert_eq!((p.subsidy(1), p.subsidy(10)), (50, 50));
        assert_eq!((p.subsidy(11), p.subsidy(20)), (25, 25));
        assert_eq!((p.subsidy(21), p.subsidy(25)), (12, 12));
        assert_eq!(p.subsidy(26), 0);
        assert_eq!(p.final_height(), 25);
        let m = ChainParams::MAINNET;
        let era = 144 * 365 * 7 / 2;
        assert_eq!(era, 183_960);
        assert_eq!(m.subsidy(0), 0);
        assert_eq!((m.subsidy(1), m.subsidy(era)), (1500 * COIN, 1500 * COIN));
        assert_eq!((m.subsidy(era + 1), m.subsidy(2 * era)), (500 * COIN, 500 * COIN));
        assert_eq!(m.subsidy(2 * era + 1), 7 * COIN);
        assert_eq!(m.final_height(), 2 * era + 144 * 365 * 1000);
        assert_eq!(m.final_height(), 52_927_920);
        assert_eq!(m.subsidy(m.final_height()), 7 * COIN);
        assert_eq!(m.subsidy(m.final_height() + 1), 0);
        assert_eq!(m.total_supply(), 735_840_000 * COIN as u128);
    }

    #[test]
    fn rejects_invalid_headers() {
        let f = open("invalid");
        let a = pk(3);
        f.chain.init_genesis(&genesis_block(vec![Output::new(&a, 1)])).unwrap();
        let body = Body { inputs: vec![], outputs: vec![Output::new(&a, 7).block_output()], proof: vec![] };
        let good = mine(&f, body.clone(), GENESIS_TIME + 600);
        let now = GENESIS_TIME + 700;

        let mut b = good.clone();
        b.header.prev_hash = EMPTY;
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::UnknownParent(_))));
        let mut b = good.clone();
        b.header.height = 2;
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::BadHeight { expected: 1, got: 2 })));
        let mut b = good.clone();
        b.header.timestamp = GENESIS_TIME;
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::TimestampTooOld { .. })));
        assert!(matches!(
            f.chain.apply_block(&good, GENESIS_TIME + 600 - 7201),
            Err(ChainError::TimestampTooNew { .. })
        ));
        let mut b = good.clone();
        b.header.nonce[5] ^= 1;
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::BadProofOfWork)));
        let mut b = good.clone();
        b.header.mix[0] += crate::poseidon2::Fp::ONE;
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::BadProofOfWork)));
        // Changing the body breaks the commitment (PoW is over the commitment,
        // so re-mine with a mismatched commitment to isolate the check).
        let mut b = good.clone();
        b.body.proof.push(1);
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::BadBodyCommitment)));
        // Wrong state root.
        let mut wrong = good.body.clone();
        wrong.outputs.push(Output::new(&a, 8).block_output());
        let b = mine_with_root(&f, wrong, GENESIS_TIME + 600, good.header.state_root);
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::StateRootMismatch { .. })));
        // Too large.
        let many = Body { inputs: vec![], outputs: vec![Output::new(&a, 1).block_output(); 5], proof: vec![] };
        let b = mine(&f, many, GENESIS_TIME + 600);
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::TooLarge(504))));

        // The good block still applies afterwards.
        f.chain.apply_block(&good, now).unwrap();
        assert_eq!(f.chain.tip().unwrap().unwrap().height, 1);
    }

    #[test]
    fn median_time_past_and_retarget() {
        let f = open("mtp");
        let a = pk(4);
        f.chain.init_genesis(&genesis_block(vec![])).unwrap();
        // Blocks with alternating fast/slow spacing; timestamps need not be
        // monotone, only above the median of the last eleven.
        let mut t = GENESIS_TIME;
        let times = [600u64, 30, 2000, 10, 1500, 600, 5, 900, 700, 600, 600, 300];
        for (i, dt) in times.iter().enumerate() {
            t += dt;
            let body =
                Body { inputs: vec![], outputs: vec![Output::new(&a, i as u64 + 1).block_output()], proof: vec![] };
            let block = mine(&f, body, t);
            f.chain.apply_block(&block, t + 10).unwrap();
        }
        let tip = f.chain.tip().unwrap().unwrap();
        assert_eq!(tip.height, times.len() as u32);
        // A timestamp below the median of the last eleven is rejected even if
        // it is above the parent's.
        let rtxn = f.chain.env().read_txn().unwrap();
        let median = f.chain.median_time_past(&rtxn, &tip).unwrap();
        drop(rtxn);
        assert!(median < tip.timestamp);
        let body = Body { inputs: vec![], outputs: vec![], proof: vec![] };
        let late = mine(&f, body.clone(), median);
        assert!(matches!(f.chain.apply_block(&late, tip.timestamp + 10), Err(ChainError::TimestampTooOld { .. })));
        let ok = mine(&f, body, median + 1);
        f.chain.apply_block(&ok, tip.timestamp + 10).unwrap();

        // Retarget: blocks arriving faster than schedule tighten the target.
        let genesis = f.chain.header_at(0).unwrap().unwrap();
        let on_time = Header { height: 10, timestamp: GENESIS_TIME + 6000, ..genesis };
        let fast = Header { height: 10, timestamp: GENESIS_TIME + 3000, ..genesis };
        let slow = Header { height: 10, timestamp: GENESIS_TIME + 9000, ..genesis };
        let t_on: U256 = f.chain.expected_target(&on_time).unwrap().into();
        let t_fast: U256 = f.chain.expected_target(&fast).unwrap().into();
        let t_slow: U256 = f.chain.expected_target(&slow).unwrap().into();
        assert_eq!(t_on, params().genesis_target);
        assert!(t_fast < t_on);
        assert!(t_slow > t_on);
    }

    #[test]
    fn rejected_proof_blocks_nothing_else() {
        struct RejectAll;
        impl ProofVerifier for RejectAll {
            fn verify(&self, s: &BlockStatement<'_>, proof: &[u8]) -> bool {
                // Accept only genesis-free blocks carrying the magic byte, and
                // check the statement is coherent.
                assert_eq!(s.body.inputs.len(), 0);
                assert_ne!(s.prev_state_root, s.new_state_root);
                proof == [42]
            }
        }
        let dir = TempDir::new("proof");
        let seed = seed();
        let dataset = Dataset::generate(&seed);
        let chain = Chain::open(&dir.0, 64 << 20, params(), seed, RejectAll).unwrap();
        let a = pk(5);
        chain.init_genesis(&genesis_block(vec![])).unwrap();
        let tip = chain.tip().unwrap().unwrap();
        let target = chain.expected_target(&tip).unwrap();
        let make = |proof: Vec<u8>| {
            let body = Body { inputs: vec![], outputs: vec![Output::new(&a, 3).block_output()], proof };
            let mut header = chain.template(&body, GENESIS_TIME + 600).unwrap();
            let (nonce, out) =
                pow::mine(&dataset, &header.pow_hash(), &target, (0..1_000_000).map(nonce_from_u64)).unwrap();
            header.nonce = nonce;
            header.mix = out.mix;
            Block { header, body }
        };
        let bad = make(vec![41]);
        assert!(matches!(chain.apply_block(&bad, GENESIS_TIME + 700), Err(ChainError::BadProof)));
        assert_eq!(chain.tip().unwrap().unwrap().height, 0);
        assert_eq!(chain.state_root().unwrap(), tip.state_root);
        let good = make(vec![42]);
        chain.apply_block(&good, GENESIS_TIME + 700).unwrap();
        assert_eq!(chain.tip().unwrap().unwrap().height, 1);
    }

    #[test]
    fn state_persists_across_reopen() {
        let dir = TempDir::new("reopen");
        let a = pk(6);
        let (tip, root) = {
            let seed = seed();
            let dataset = Dataset::generate(&seed);
            let chain = Chain::open(&dir.0, 64 << 20, params(), seed, AcceptAllProofs).unwrap();
            chain.init_genesis(&genesis_block(vec![Output::new(&a, 1)])).unwrap();
            let f = Fixture { _dir: TempDir(PathBuf::new()), chain, dataset };
            let block = mine(
                &f,
                Body { inputs: vec![0], outputs: vec![Output::new(&a, 2).block_output()], proof: vec![] },
                GENESIS_TIME + 600,
            );
            f.chain.apply_block(&block, GENESIS_TIME + 700).unwrap();
            (f.chain.tip().unwrap().unwrap(), f.chain.state_root().unwrap())
        };
        let chain = Chain::open(&dir.0, 64 << 20, params(), seed(), AcceptAllProofs).unwrap();
        assert_eq!(chain.tip().unwrap(), Some(tip));
        assert_eq!(chain.state_root().unwrap(), root);
        assert_eq!(chain.header_at(1).unwrap(), Some(tip));
        let rtxn = chain.env().read_txn().unwrap();
        assert_eq!(chain.utxo().next_position(&rtxn).unwrap(), 2);
    }

    /// Mines a block on `f`'s tip with `body` and `timestamp`.
    fn mine_outputs(f: &Fixture, outputs: &[Output], timestamp: u64) -> Block {
        let body = Body { inputs: vec![], outputs: outputs.iter().map(|o| o.block_output()).collect(), proof: vec![] };
        mine(f, body, timestamp)
    }

    /// Measures what each block costs once it has left the undo window:
    /// its header, index record and height entry. Bodies (here with a
    /// 205 KB proof each, as on mainnet) are kept only inside the window.
    #[test]
    #[ignore = "slow: storage measurement"]
    fn storage_per_block() {
        let blocks: u64 = std::env::var("TABMINER_SCALE_BLOCKS").ok().and_then(|v| v.parse().ok()).unwrap_or(3000);
        let window = 100u32;
        let dir = TempDir::new("scale-blocks");
        let seed = seed();
        let dataset = Dataset::generate(&seed);
        let params = ChainParams {
            max_block_size: ChainParams::MAINNET.max_block_size,
            emission: ChainParams::MAINNET.emission,
            ..params()
        };
        let chain = Chain::open(&dir.0, 1 << 30, params, seed, AcceptAllProofs).unwrap().with_max_undo(Some(window));
        let f = Fixture { _dir: dir, chain, dataset };
        f.chain.init_genesis(&genesis_block(vec![])).unwrap();
        let k = pk(9);
        let mut t = GENESIS_TIME;
        for i in 1..=blocks {
            t += 600;
            let body =
                Body { inputs: vec![], outputs: vec![Output::new(&k, i).block_output()], proof: vec![7; 205_000] };
            let block = mine(&f, body, t);
            f.chain.apply_block(&block, t + 1).unwrap();
        }
        let rtxn = f.chain.env().read_txn().unwrap();
        let size =
            |s: heed::DatabaseStat| (s.branch_pages + s.leaf_pages + s.overflow_pages) as u64 * s.page_size as u64;
        let per_block: u64 = [
            size(f.chain.headers.stat(&rtxn).unwrap()),
            size(f.chain.index.stat(&rtxn).unwrap()),
            size(f.chain.by_height.stat(&rtxn).unwrap()),
        ]
        .iter()
        .sum();
        let bodies = f.chain.bodies.stat(&rtxn).unwrap();
        let per = per_block as f64 / (blocks + 1) as f64;
        eprintln!("{blocks} blocks, window {window}");
        eprintln!(
            "  headers, index, heights: {:.1} B/block: {:.1} MB a year, {:.2} GB a century",
            per,
            per * BLOCKS_PER_YEAR as f64 / 1e6,
            per * BLOCKS_PER_YEAR as f64 * 100.0 / 1e9
        );
        eprintln!(
            "  bodies: {} kept, {:.1} MB ({:.0} KB each)",
            bodies.entries,
            size(bodies) as f64 / 1e6,
            size(bodies) as f64 / bodies.entries as f64 / 1e3
        );
        assert!(bodies.entries as u32 <= window + 1);
        eprintln!("  file {:.1} MB", f.chain.env().real_disk_size().unwrap() as f64 / 1e6);
    }

    #[test]
    fn block_work_and_u256() {
        use crate::difficulty::U256;
        assert_eq!(ChainParams::block_work(U256::MAX.shift_right(8)), U256::from_u64(256));
        assert_eq!(ChainParams::block_work(U256::ZERO), U256::MAX);
        assert_eq!(U256::from_u64(100).div(U256::from_u64(7)), U256::from_u64(14));
        assert_eq!(U256::MAX.div(U256::MAX), U256::ONE);
        assert_eq!(U256::MAX.saturating_add(U256::ONE), U256::MAX);
        assert_eq!(U256::ONE.checked_sub(U256::from_u64(2)), None);
        assert_eq!(U256::from_u64(5).checked_sub(U256::from_u64(2)), Some(U256::from_u64(3)));
        assert!(!U256::MAX.not().bit(3));
    }

    #[test]
    fn side_chains_and_reorgs() {
        // Two chains from one genesis: `a` mines a short branch, `b` a longer
        // one; `a` learns `b`'s blocks and switches.
        let a = open("reorg-a");
        let b = open("reorg-b");
        let k = pk(7);
        let genesis = genesis_block(vec![Output::new(&k, 1), Output::new(&k, 2)]);
        a.chain.init_genesis(&genesis).unwrap();
        b.chain.init_genesis(&genesis).unwrap();
        let g = genesis.header.hash();

        // a: A1 spends position 0 and adds two outputs.
        let a1 = mine(
            &a,
            Body {
                inputs: vec![0],
                outputs: vec![Output::new(&k, 10).block_output(), Output::new(&k, 11).block_output()],
                proof: vec![1],
            },
            GENESIS_TIME + 600,
        );
        assert_eq!(a.chain.apply_block(&a1, GENESIS_TIME + 700).unwrap(), Applied::Extended);
        let a_root = a.chain.state_root().unwrap();
        let a_work = a.chain.tip_work().unwrap();
        assert!(a_work > crate::difficulty::U256::ZERO);

        // b: B1 spends position 1, B2 spends B1's output.
        let b1 = mine(
            &b,
            Body { inputs: vec![1], outputs: vec![Output::new(&k, 20).block_output()], proof: vec![2] },
            GENESIS_TIME + 650,
        );
        b.chain.apply_block(&b1, GENESIS_TIME + 700).unwrap();
        let b2 = mine(
            &b,
            Body { inputs: vec![2], outputs: vec![Output::new(&k, 21).block_output()], proof: vec![3] },
            GENESIS_TIME + 1250,
        );
        b.chain.apply_block(&b2, GENESIS_TIME + 1300).unwrap();
        let b_root = b.chain.state_root().unwrap();

        // B1 alone has the same work as A1: it is stored as a side block.
        assert_eq!(a.chain.apply_block(&b1, GENESIS_TIME + 1300).unwrap(), Applied::Side);
        assert_eq!(a.chain.apply_block(&b1, GENESIS_TIME + 1300).unwrap(), Applied::Known);
        assert_eq!(a.chain.tip().unwrap().unwrap(), a1.header);
        assert_eq!(a.chain.state_root().unwrap(), a_root);
        let e = a.chain.entry(&b1.header.hash()).unwrap().unwrap();
        assert!(!e.validated && !e.invalid && e.work == a_work);
        assert_eq!(a.chain.block_by_hash(&b1.header.hash()).unwrap(), Some(b1.clone()));

        // A block on an unknown parent is refused and not stored.
        let mut orphan = b2.clone();
        orphan.header.prev_hash = Output::new(&k, 99).commitment;
        assert!(matches!(a.chain.apply_block(&orphan, GENESIS_TIME + 1300), Err(ChainError::UnknownParent(_))));
        assert!(a.chain.entry(&orphan.header.hash()).unwrap().is_none());

        // B2 makes b's branch heavier: reorg from genesis, unwinding A1.
        assert_eq!(
            a.chain.apply_block(&b2, GENESIS_TIME + 1300).unwrap(),
            Applied::Reorganized { fork_height: 0, unwound: 1 }
        );
        assert_eq!(a.chain.tip().unwrap().unwrap(), b2.header);
        assert_eq!(a.chain.state_root().unwrap(), b_root);
        assert_eq!(a.chain.header_at(1).unwrap(), Some(b1.header));
        assert_eq!(a.chain.header_at(2).unwrap(), Some(b2.header));
        assert_eq!(a.chain.tip_work().unwrap(), b.chain.tip_work().unwrap());
        {
            let rtxn = a.chain.env().read_txn().unwrap();
            let u = a.chain.utxo();
            // Position 0 (spent by A1) is back; 1 and 2 are spent by b.
            assert_eq!(u.get(&rtxn, 0).unwrap(), Output::new(&k, 1).commitment);
            assert_eq!(u.get(&rtxn, 1).unwrap(), EMPTY);
            assert_eq!(u.get(&rtxn, 2).unwrap(), EMPTY);
            assert_eq!(u.get(&rtxn, 3).unwrap(), Output::new(&k, 21).commitment);
            assert_eq!(u.next_position(&rtxn).unwrap(), 4);
            assert_eq!(u.len(&rtxn).unwrap(), 2);
        }
        // A1 is still stored, validated, off the main chain.
        let e = a.chain.entry(&a1.header.hash()).unwrap().unwrap();
        assert!(e.validated && !e.invalid);
        assert_eq!(a.chain.header_by_hash(&a1.header.hash()).unwrap(), Some(a1.header));

        // Locators and header serving.
        let loc = a.chain.locator().unwrap();
        assert_eq!(loc, vec![b2.header.hash(), b1.header.hash(), g]);
        assert_eq!(a.chain.headers_after(&[a1.header.hash(), g], 10).unwrap(), vec![b1.header, b2.header]);
        assert_eq!(a.chain.headers_after(&[b1.header.hash()], 10).unwrap(), vec![b2.header]);
        assert_eq!(a.chain.headers_after(&[b2.header.hash()], 10).unwrap(), Vec::<Header>::new());
        assert_eq!(a.chain.headers_after(&[], 1).unwrap(), vec![b1.header]);

        // Back to a's branch: A2 on top of A1 already outweighs B2 (b's
        // blocks came 50 s late, so ASERT eased B2's target), and A3 extends.
        let a2 = {
            // Mine on a's old branch using chain `c`, a mirror of a's branch.
            let c = open("reorg-c");
            c.chain.init_genesis(&genesis).unwrap();
            c.chain.apply_block(&a1, GENESIS_TIME + 700).unwrap();
            let a2 = mine_outputs(&c, &[Output::new(&k, 30)], GENESIS_TIME + 1300);
            c.chain.apply_block(&a2, GENESIS_TIME + 1400).unwrap();
            let a3 = mine_outputs(&c, &[Output::new(&k, 31)], GENESIS_TIME + 1900);
            c.chain.apply_block(&a3, GENESIS_TIME + 2000).unwrap();
            (a2, a3, c.chain.state_root().unwrap())
        };
        let (a2, a3, c_root) = a2;
        assert_eq!(
            a.chain.apply_block(&a2, GENESIS_TIME + 2000).unwrap(),
            Applied::Reorganized { fork_height: 0, unwound: 2 }
        );
        assert_eq!(a.chain.apply_block(&a3, GENESIS_TIME + 2000).unwrap(), Applied::Extended);
        assert_eq!(a.chain.tip().unwrap().unwrap(), a3.header);
        assert_eq!(a.chain.state_root().unwrap(), c_root);
        assert_eq!(a.chain.header_at(1).unwrap(), Some(a1.header));
        assert_eq!(a.chain.header_at(2).unwrap(), Some(a2.header));
        assert_eq!(a.chain.header_at(3).unwrap(), Some(a3.header));
        assert!(!a.chain.entry(&b2.header.hash()).unwrap().unwrap().invalid);
    }

    #[test]
    fn invalid_branch_leaves_main_chain() {
        let a = open("badbranch-a");
        let b = open("badbranch-b");
        let k = pk(8);
        let genesis = genesis_block(vec![Output::new(&k, 1)]);
        a.chain.init_genesis(&genesis).unwrap();
        b.chain.init_genesis(&genesis).unwrap();
        let a1 = mine_outputs(&a, &[Output::new(&k, 5)], GENESIS_TIME + 600);
        a.chain.apply_block(&a1, GENESIS_TIME + 700).unwrap();
        let root = a.chain.state_root().unwrap();

        // b's branch: B1 fine, B2 claims a wrong state root (header rules
        // pass, so a stores it as a side block; connecting it fails).
        let b1 = mine_outputs(&b, &[Output::new(&k, 6)], GENESIS_TIME + 650);
        b.chain.apply_block(&b1, GENESIS_TIME + 700).unwrap();
        let bad_body = Body { inputs: vec![], outputs: vec![Output::new(&k, 7).block_output()], proof: vec![] };
        let b2 = mine_with_root(&b, bad_body, GENESIS_TIME + 1250, b1.header.state_root);
        assert_eq!(a.chain.apply_block(&b1, GENESIS_TIME + 1300).unwrap(), Applied::Side);
        assert!(matches!(a.chain.apply_block(&b2, GENESIS_TIME + 1300), Err(ChainError::StateRootMismatch { .. })));
        assert_eq!(a.chain.tip().unwrap().unwrap(), a1.header);
        assert_eq!(a.chain.state_root().unwrap(), root);
        assert_eq!(a.chain.header_at(1).unwrap(), Some(a1.header));
        // B2 is remembered as invalid, B1 stays a valid side block.
        assert!(a.chain.entry(&b2.header.hash()).unwrap().unwrap().invalid);
        assert!(matches!(a.chain.apply_block(&b2, GENESIS_TIME + 1300), Err(ChainError::KnownInvalid)));
        let e = a.chain.entry(&b1.header.hash()).unwrap().unwrap();
        assert!(!e.invalid);
        // A child of the invalid block is refused.
        let b3 = {
            let c = open("badbranch-c");
            c.chain.init_genesis(&genesis).unwrap();
            c.chain.apply_block(&b1, GENESIS_TIME + 700).unwrap();
            let h = Header { prev_hash: b2.header.hash(), height: 2, ..b2.header };
            let _ = h;
            // Build B3 with prev_hash = B2 by hand on top of c's tip target.
            let body = Body { inputs: vec![], outputs: vec![], proof: vec![] };
            let header = Header {
                prev_hash: b2.header.hash(),
                height: 3,
                timestamp: GENESIS_TIME + 1900,
                body_commitment: body.commitment(),
                state_root: b1.header.state_root,
                mix: EMPTY,
                nonce: [0u8; 32],
            };
            Block { header: solve(&c, header), body }
        };
        assert!(matches!(a.chain.apply_block(&b3, GENESIS_TIME + 2000), Err(ChainError::InvalidParent)));
    }

    #[test]
    fn fast_sync_from_a_snapshot() {
        let a = open("fast-a");
        let k = pk(11);
        a.chain.init_genesis(&genesis_block(vec![])).unwrap();
        // Twelve blocks: each adds two outputs (with memos) and, from block
        // 3 on, spends one made two blocks earlier, some after block 8.
        let mut t = GENESIS_TIME;
        let mut blocks = Vec::new();
        for h in 1..=12u64 {
            t += 600;
            let memo = |i: u64| core::array::from_fn(|j| crate::poseidon2::Fp::new((h * 10 + i) as u32 + j as u32));
            let outs = (0..2)
                .map(|i| Output::with_memo(&crate::transaction::pubkey_hash(&k), h * 10 + i, memo(i)).block_output())
                .collect();
            let inputs = if h >= 3 { vec![(h - 3) * 2] } else { vec![] };
            let block = mine(&a, Body { inputs, outputs: outs, proof: vec![] }, t);
            a.chain.apply_block(&block, t + 1).unwrap();
            blocks.push(block);
        }
        let s8 = blocks[7].header;
        let (next, roots) = a.chain.snapshot_manifest(&s8.hash()).unwrap().unwrap();
        assert_eq!(next, 16);
        assert_eq!(crate::state_tree::root_from_subtrees(SNAPSHOT_PART_LOG, &roots), s8.state_root);
        let part = a.chain.snapshot_part(&s8.hash(), 0).unwrap().unwrap();
        // 16 outputs made, positions 0..=10 spent by blocks 3..8 at even
        // positions, so 10 unspent after block 8; later spends are restored.
        assert_eq!(part.len(), 10);
        assert!(a.chain.snapshot_part(&s8.hash(), 1).unwrap().is_none());
        assert!(a.chain.snapshot_manifest(&blocks[0].header.prev_hash).unwrap().is_none());

        // b: headers first, then the snapshot, then the tail.
        let b = open("fast-b");
        b.chain.init_genesis(&genesis_block(vec![])).unwrap();
        assert!(matches!(b.chain.accept_header(&blocks[1].header, t), Err(ChainError::UnknownParent(_))));
        for block in &blocks {
            assert!(b.chain.accept_header(&block.header, t + 1).unwrap());
        }
        assert!(!b.chain.accept_header(&blocks[3].header, t + 1).unwrap());
        assert_eq!(b.chain.best_header().unwrap(), blocks[11].header);
        assert_eq!(b.chain.tip().unwrap().unwrap().height, 0);
        assert_eq!(b.chain.ancestor(&blocks[11].header, 8).unwrap(), Some(s8));
        let mut bad_header = blocks[11].header;
        bad_header.nonce[0] ^= 1;
        assert!(b.chain.accept_header(&bad_header, t + 1).is_err());
        // A block arriving now cannot connect: its ancestors have no bodies.
        assert!(matches!(b.chain.apply_block(&blocks[11], t + 1), Err(ChainError::MissingBody)));

        b.chain.verify_snapshot_block(&blocks[7], next).unwrap();
        let mut forged = part.clone();
        forged[0].1[0] += crate::poseidon2::Fp::ONE;
        assert!(matches!(b.chain.install_snapshot(&blocks[7], &forged, next), Err(ChainError::BadSnapshot)));
        b.chain.install_snapshot(&blocks[7], &part, next).unwrap();
        assert_eq!(b.chain.tip().unwrap().unwrap(), s8);
        assert_eq!(b.chain.state_root().unwrap(), s8.state_root);
        assert_eq!(b.chain.floor().unwrap(), Some(8));
        assert_eq!(b.chain.header_at(3).unwrap(), Some(blocks[2].header));
        for block in &blocks[8..] {
            assert_eq!(b.chain.apply_block(block, t + 1).unwrap(), Applied::Extended);
        }
        assert_eq!(b.chain.tip().unwrap().unwrap(), blocks[11].header);
        assert_eq!(b.chain.state_root().unwrap(), a.chain.state_root().unwrap());
        // b now serves snapshots from its floor on, the same as a's.
        assert_eq!(b.chain.snapshot_manifest(&s8.hash()).unwrap(), Some((next, roots)));
        assert_eq!(b.chain.snapshot_part(&s8.hash(), 0).unwrap(), Some(part));
        // A memo survived: the wallet's scan reads them from here.
        let rtxn = b.chain.env().read_txn().unwrap();
        assert!(b.chain.utxo().memos(&rtxn).unwrap().len() >= 10);
        drop(rtxn);
        // Nothing reorganizes below the floor: a heavier branch from block 5
        // is stored but refused.
        let fork_root = blocks[4].header;
        let mut fork = Vec::new();
        let mut parent = fork_root;
        let c = open("fast-c");
        c.chain.init_genesis(&genesis_block(vec![])).unwrap();
        for block in &blocks[..5] {
            c.chain.apply_block(block, t + 1).unwrap();
        }
        let mut tc = parent.timestamp;
        for _ in 0..9 {
            tc += 60;
            let block = mine(&c, Body { inputs: vec![], outputs: vec![], proof: vec![] }, tc);
            c.chain.apply_block(&block, tc + 1).unwrap();
            parent = block.header;
            fork.push(block);
        }
        let _ = parent;
        let mut refused = false;
        for block in &fork {
            match b.chain.apply_block(block, tc + 1) {
                Ok(_) => {}
                Err(ChainError::BelowSnapshot | ChainError::MissingBody | ChainError::UnknownParent(_)) => {
                    refused = true
                }
                Err(e) => panic!("{e}"),
            }
        }
        assert!(refused || b.chain.tip().unwrap().unwrap() == blocks[11].header);
        assert_eq!(b.chain.state_root().unwrap(), a.chain.state_root().unwrap());
    }

    #[test]
    fn undo_records_are_pruned_beyond_the_window() {
        let mut f = open("undo");
        f.chain = f.chain.with_max_undo(Some(3));
        let k = pk(12);
        f.chain.init_genesis(&genesis_block(vec![])).unwrap();
        let mut t = GENESIS_TIME;
        let mut blocks = Vec::new();
        for i in 1..=6u64 {
            t += 600;
            let block = mine_outputs(&f, &[Output::new(&k, i)], t);
            f.chain.apply_block(&block, t + 1).unwrap();
            blocks.push(block);
        }
        // Heights 4 to 6 keep undo records: snapshots after them are served,
        // after 3 or below not.
        let undo = |h: usize| {
            let rtxn = f.chain.env().read_txn().unwrap();
            f.chain.undo.get(&rtxn, &digest_bytes(&blocks[h - 1].header.hash())).unwrap().is_some()
        };
        assert_eq!((1..=6).map(undo).collect::<Vec<_>>(), [false, false, false, true, true, true]);
        // Bodies go with them: blocks 1 to 3 keep only their headers.
        let body = |h: usize| f.chain.body_by_hash(&blocks[h - 1].header.hash()).unwrap().is_some();
        assert_eq!((1..=6).map(body).collect::<Vec<_>>(), [false, false, false, true, true, true]);
        assert!(f.chain.entry(&blocks[0].header.hash()).unwrap().unwrap().validated);
        assert!(f.chain.snapshot_manifest(&blocks[2].header.hash()).unwrap().is_none());
        assert!(f.chain.snapshot_manifest(&blocks[3].header.hash()).unwrap().is_some());
        // A heavier branch from block 2 would unwind block 3: refused.
        let g = open("undo-fork");
        g.chain.init_genesis(&genesis_block(vec![])).unwrap();
        for b in &blocks[..2] {
            g.chain.apply_block(b, t + 1).unwrap();
        }
        let mut tg = blocks[1].header.timestamp;
        let mut refused = false;
        for _ in 0..8 {
            tg += 30;
            let b = mine_outputs(&g, &[], tg);
            g.chain.apply_block(&b, tg + 1).unwrap();
            match f.chain.apply_block(&b, tg + 1) {
                Ok(_) => {}
                Err(ChainError::BeyondUndo | ChainError::UnknownParent(_)) => refused = true,
                Err(e) => panic!("{e}"),
            }
        }
        assert!(refused);
        assert_eq!(f.chain.tip().unwrap().unwrap(), blocks[5].header);
        // A shallow reorganization within the window still works.
        let h = open("undo-shallow");
        h.chain.init_genesis(&genesis_block(vec![])).unwrap();
        for b in &blocks[..5] {
            h.chain.apply_block(b, t + 1).unwrap();
        }
        let mut th = blocks[4].header.timestamp;
        let mut last = None;
        for _ in 0..3 {
            th += 30;
            let b = mine_outputs(&h, &[], th);
            h.chain.apply_block(&b, th + 1).unwrap();
            last = Some(f.chain.apply_block(&b, th + 1).unwrap());
        }
        assert!(matches!(last, Some(Applied::Reorganized { fork_height: 5, unwound: 1 }) | Some(Applied::Extended)));
        // No body is left at or below the window, side branches included.
        let tip = f.chain.tip().unwrap().unwrap().height;
        let rtxn = f.chain.env().read_txn().unwrap();
        for item in f.chain.bodies.iter(&rtxn).unwrap() {
            let (id, _) = item.unwrap();
            let h = f.chain.header_by_hash_in(&rtxn, id).unwrap().unwrap().height;
            assert!(h == 0 || h > tip - 3, "body at height {h} with the tip at {tip}");
        }
        drop(rtxn);
        // Pruning by hand clears a backlog left by a larger window.
        let wide = open("undo-wide");
        let wide_chain = Chain::open(&wide._dir.0.join("c"), 64 << 20, params(), seed(), AcceptAllProofs)
            .unwrap()
            .with_max_undo(None);
        wide_chain.init_genesis(&genesis_block(vec![])).unwrap();
        for b in &blocks {
            wide_chain.apply_block(b, t + 1).unwrap();
        }
        let wide_chain = wide_chain.with_max_undo(Some(2));
        assert_eq!(wide_chain.prune_undo().unwrap(), 4);
        assert_eq!(wide_chain.prune_undo().unwrap(), 0);
    }

    #[test]
    fn mainnet_genesis_matches_the_generated_file() {
        let g = ChainParams::MAINNET.genesis().header;
        let id: String = crate::poseidon2::digest_to_bytes(&g.hash()).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(id, crate::genesis::ID, "src/genesis.rs is out of date: regenerate it with tools/genesis.rs");
        assert_eq!(g.timestamp, crate::genesis::TIMESTAMP);
        let hex: String = g.nonce.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, crate::genesis::BITCOIN_HASH_HEX);
        assert!(crate::genesis::BITCOIN_TIME <= g.timestamp, "the Bitcoin block must come first");
    }

    #[test]
    fn mainnet_genesis_is_fixed() {
        let p = ChainParams::MAINNET;
        let g = p.genesis();
        assert_eq!(g.header.height, 0);
        assert_eq!(g.header.state_root, empty_root());
        assert_eq!(g.header.hash(), p.genesis().header.hash());
        let dir = TempDir::new("mainnet-genesis");
        let chain =
            Chain::open(&dir.0, 64 << 20, p, SeedText::from_bytes(p.pow, vec![0u8; 20_000]), AcceptAllProofs).unwrap();
        chain.init_or_check_genesis().unwrap();
        chain.init_or_check_genesis().unwrap();
        assert_eq!(chain.tip().unwrap(), Some(g.header));
        let other = Chain::open(&TempDir::new("other-genesis").0, 64 << 20, params(), seed(), AcceptAllProofs).unwrap();
        other.init_genesis(&genesis_block(vec![Output::new(&pk(9), 1)])).unwrap();
        assert!(matches!(other.init_or_check_genesis(), Err(ChainError::WrongGenesis)));
    }
}
