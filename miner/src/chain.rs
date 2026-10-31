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

use std::path::Path;
use std::sync::Mutex;

use heed::byteorder::{BigEndian, LittleEndian};
use heed::types::{Bytes, Str, U32, U64};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::aggregate::AggregatorParams;
use crate::block::{Block, BlockOutput, Body, BodyError, HEADER_SIZE, Header};
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
    /// Snapshots of the state are taken after every block at a multiple of
    /// this height, and only those are served for fast sync.
    pub snapshot_interval: u32,
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
        snapshot_interval: 144,
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
    /// A snapshot is being installed; blocks wait until it is done.
    SnapshotInProgress,
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
                | ChainError::SnapshotInProgress
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
            ChainError::SnapshotInProgress => f.write_str("a snapshot is being installed"),
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
/// Set while a snapshot is being installed part by part; a node that
/// stops midway clears the partial state when it next opens.
const META_STAGING: &str = "staging";
/// The output counter after the snapshot block.
const META_FLOOR_NEXT: &str = "floor_next";
/// Positions per snapshot part (a subtree of the state tree).
pub const SNAPSHOT_PART_LOG: usize = 14;
// Part roots are read from the stored tree, which starts at this level.
const _: () = assert!(SNAPSHOT_PART_LOG >= crate::utxo::GROUP_LOG);
const META_FORMAT: &str = "format";
/// Version of the on-disk layout: 8 keeps unspent outputs in packed
/// buckets with no index by commitment, and the state tree from subtrees
/// of 256 positions up; 9 keeps the outputs spent within the undo window
/// once, by position, for reorganizations and snapshots alike.
const FORMAT: u8 = 9;

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

/// What disconnecting a block needs besides its body and the outputs it
/// spent (kept by position in the spent log): where its outputs started
/// and how many it made.
struct Undo {
    first_output_position: u64,
    outputs: u32,
}

impl Undo {
    fn to_bytes(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[..8].copy_from_slice(&self.first_output_position.to_le_bytes());
        out[8..].copy_from_slice(&self.outputs.to_le_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Undo> {
        let bytes: &[u8; 12] = bytes.try_into().ok()?;
        Some(Undo {
            first_output_position: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            outputs: u32::from_le_bytes(bytes[8..].try_into().unwrap()),
        })
    }
}

/// A spent-log entry: the height of the block spending the output, then
/// its commitment and memo.
const SPENT_ENTRY: usize = 4 + 64;

fn spent_entry(height: u32, commitment: &Commitment, memo: &Memo) -> [u8; SPENT_ENTRY] {
    let mut value = [0u8; SPENT_ENTRY];
    value[..4].copy_from_slice(&height.to_le_bytes());
    value[4..36].copy_from_slice(&digest_bytes(commitment));
    value[36..].copy_from_slice(&digest_bytes(memo));
    value
}

fn read_spent_entry(value: &[u8]) -> Option<(u32, Commitment, Memo)> {
    if value.len() != SPENT_ENTRY {
        return None;
    }
    let height = u32::from_le_bytes(value[..4].try_into().unwrap());
    Some((height, digest_from_bytes(&value[4..36])?, digest_from_bytes(&value[36..])?))
}

/// A staged snapshot part to carry forward: see
/// [`Chain::carry_snapshot_parts`].
#[derive(Clone, Debug)]
pub struct CarriedPart {
    pub index: u64,
    /// Positions in the part spent since, ascending.
    pub spent: Vec<u64>,
    /// Its root in the later manifest; `None` clears it.
    pub root: Option<Digest>,
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
    /// Snapshot manifest of the main-chain block at each multiple of
    /// [`ChainParams::snapshot_interval`] within the undo window: its id,
    /// the output counter and the root of every part.
    snapshots: Database<U32<BigEndian>, Bytes>,
    /// Every output spent by a main-chain block within the undo window, by
    /// position: the spending block's height, the commitment and memo.
    /// Disconnecting a block restores its inputs from here, and a snapshot's
    /// part is the outputs unspent now in its range plus those spent since.
    spent: Database<U64<BigEndian>, Bytes>,
    /// The best header's branch above the main chain, oldest first, as
    /// [`Chain::missing_bodies`] last saw it: extended as headers arrive
    /// rather than walked again.
    branch: Mutex<Vec<Header>>,
    /// The full proof-of-work dataset, once loaded or generated: checks a
    /// header in microseconds instead of tens of milliseconds from the
    /// seed text.
    dataset: std::sync::RwLock<Option<std::sync::Arc<crate::pow::Dataset>>>,
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
        let snapshots = env.create_database(&mut wtxn, Some("snapshots"))?;
        let spent = env.create_database(&mut wtxn, Some("spent"))?;
        match meta.get(&wtxn, META_FORMAT)? {
            Some([FORMAT]) => {}
            Some(_) => return Err(ChainError::OldFormat),
            None if meta.get(&wtxn, META_TIP)?.is_some() => return Err(ChainError::OldFormat),
            None => meta.put(&mut wtxn, META_FORMAT, &[FORMAT])?,
        }
        wtxn.commit()?;
        let chain = Chain {
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
            snapshots,
            spent,
            branch: Mutex::new(Vec::new()),
            dataset: std::sync::RwLock::new(None),
        };
        // A snapshot install interrupted by a stop: start over cleanly.
        chain.abort_snapshot()?;
        Ok(chain)
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
            self.forget_spends(&mut wtxn, &header)?;
            n += 1;
            h -= 1;
        }
        if tip.height > keep {
            self.prune_bodies(&mut wtxn, tip.height - keep)?;
        }
        self.prune_snapshots(&mut wtxn, tip.height)?;
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

    /// The main-chain block at `height`: its id, the position its first
    /// output took and its outputs. `None` past the tip, or once its body
    /// and undo record are pruned.
    pub fn main_outputs(&self, height: u32) -> Result<Option<(Digest, u64, Vec<BlockOutput>)>> {
        let rtxn = self.env.read_txn()?;
        let Some(header) = self.header_at_in(&rtxn, height)? else {
            return Ok(None);
        };
        let id = digest_bytes(&header.hash());
        let (Some(body), Some(undo)) = (self.body_by_hash_in(&rtxn, &id)?, self.undo.get(&rtxn, &id)?) else {
            return Ok(None);
        };
        let undo = Undo::from_bytes(undo).ok_or(ChainError::Corrupt("undo record"))?;
        Ok(Some((header.hash(), undo.first_output_position, body.outputs)))
    }

    /// A stored block's serialization, as [`Block::to_bytes`] gives it,
    /// copied out without decoding: for serving.
    pub fn block_bytes(&self, hash: &Digest) -> Result<Option<Vec<u8>>> {
        let rtxn = self.env.read_txn()?;
        let id = digest_bytes(hash);
        match (self.headers.get(&rtxn, &id)?, self.bodies.get(&rtxn, &id)?) {
            (Some(header), Some(body)) => Ok(Some([header, body].concat())),
            _ => Ok(None),
        }
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
        self.undo.put(&mut wtxn, &id, &Undo { first_output_position: 0, outputs: 0 }.to_bytes())?;
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
        let spent = self.utxo.spend_positions(wtxn, &body.inputs)?.map_err(ChainError::UnknownInput)?;
        self.utxo.add_outputs(wtxn, &body.outputs)?;
        Ok((self.utxo.root(wtxn)?, spent))
    }

    /// Uses the full proof-of-work dataset for header checks from now on.
    pub fn set_dataset(&self, dataset: std::sync::Arc<crate::pow::Dataset>) {
        *self.dataset.write().unwrap() = Some(dataset);
    }

    /// Whether `header`'s proof of work meets `target`, from the dataset if
    /// loaded, else from the seed text.
    fn pow_ok(&self, header: &Header, target: &Target) -> bool {
        if !header.quick_pow_check(target) {
            return false;
        }
        match self.dataset.read().unwrap().as_deref() {
            Some(d) => header.verify_pow(d, target),
            None => header.verify_pow(&self.seed, target),
        }
    }

    /// Header rules (1 to 4) of a block whose parent is `parent`: returns
    /// the block's cumulative work. `pow` is the proof-of-work verdict if
    /// already known.
    fn check_header(&self, rtxn: &RoTxn, block: &Block, parent: &Entry, now: u64, pow: Option<bool>) -> Result<U256> {
        let work = self.check_header_rules(rtxn, &block.header, parent, now, pow)?;
        self.check_body(&block.header, &block.body)?;
        Ok(work)
    }

    /// The header rules alone (1 to 3): returns the header's cumulative
    /// work. `pow` is the proof-of-work verdict if already known.
    fn check_header_rules(
        &self,
        rtxn: &RoTxn,
        header: &Header,
        parent: &Entry,
        now: u64,
        pow: Option<bool>,
    ) -> Result<U256> {
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
        if !pow.unwrap_or_else(|| self.pow_ok(header, &target)) {
            return Err(ChainError::BadProofOfWork);
        }
        Ok(parent.work.saturating_add(ChainParams::block_work(target.into())))
    }

    /// Validates `block` and, if it passes every rule, stores it; if its
    /// branch then has the most work, makes it the tip, reorganizing the
    /// main chain if needed. `now` is the caller's clock in unix seconds.
    pub fn apply_block(&self, block: &Block, now: u64) -> Result<Applied> {
        if self.staging()? {
            return Err(ChainError::SnapshotInProgress);
        }
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
        let known = self.entry_in(&wtxn, &hash)?;
        if let Some(e) = known
            && !e.header_only
        {
            return if e.invalid { Err(ChainError::KnownInvalid) } else { Ok(Applied::Known) };
        }
        let parent = self.entry_in(&wtxn, &header.prev_hash)?.ok_or(ChainError::UnknownParent(header.prev_hash))?;
        // A header stored alone had its proof of work checked then.
        let pow = known.map(|_| true);
        let work = self.check_header(&wtxn, block, &parent, now, pow)?;

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
        for (p, (c, m)) in body.inputs.iter().zip(spent) {
            self.spent.put(wtxn, p, &spent_entry(header.height, &c, &m))?;
        }
        let outputs = body.outputs.len() as u32;
        self.undo.put(wtxn, &id, &Undo { first_output_position, outputs }.to_bytes())?;
        self.by_height.put(wtxn, &header.height, &id)?;
        self.meta.put(wtxn, META_TIP, &id)?;
        if header.height.is_multiple_of(self.params.snapshot_interval) {
            self.take_snapshot(wtxn, header)?;
        }
        // The block leaving the undo window keeps only its header.
        if let Some(keep) = self.max_undo
            && header.height > keep
            && let Some(old) = self.header_at_in(wtxn, header.height - keep)?
        {
            self.undo.delete(wtxn, &digest_bytes(&old.hash()))?;
            self.forget_spends(wtxn, &old)?;
            self.prune_bodies(wtxn, header.height - keep)?;
        }
        self.prune_snapshots(wtxn, header.height)?;
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
        let mut spent = Vec::with_capacity(body.inputs.len());
        for &p in &body.inputs {
            let entry = self.spent.get(wtxn, &p)?.and_then(read_spent_entry);
            match entry {
                Some((h, c, m)) if h == height => spent.push((p, c, m)),
                _ => return Err(ChainError::Corrupt("spent log")),
            }
        }
        let commitments: Vec<Commitment> = body.outputs.iter().map(|o| o.commitment).collect();
        self.utxo.truncate(wtxn, undo.first_output_position, &commitments)?;
        self.utxo.restore(wtxn, &spent)?;
        for (p, _, _) in &spent {
            self.spent.delete(wtxn, p)?;
        }
        self.snapshots.delete(wtxn, &height)?;
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

    /// The lowest height from which this node holds the body of every
    /// main-chain block up to its tip: 1 for an archive or young chain,
    /// higher once old bodies are pruned or below a fast-sync snapshot, and
    /// the tip's height plus one if it holds none but genesis. Peers
    /// advertise it, so bodies are only asked of nodes that have them.
    pub fn oldest_body(&self) -> Result<u32> {
        let rtxn = self.env.read_txn()?;
        let Some(tip) = self.tip_in(&rtxn)? else {
            return Ok(1);
        };
        let has = |h: u32| -> Result<bool> {
            Ok(match self.by_height.get(&rtxn, &h)? {
                Some(id) => self.bodies.get(&rtxn, id)?.is_some(),
                None => false,
            })
        };
        // The bodies held run up to the tip: search for where they start.
        let (mut lo, mut hi) = (1, tip.height + 1);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if has(mid)? {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        Ok(lo)
    }

    /// Height of the snapshot this chain was fast-synced from, if any.
    pub fn floor(&self) -> Result<Option<u32>> {
        let rtxn = self.env.read_txn()?;
        self.floor_in(&rtxn)
    }

    /// Checks a header against its stored parent (proof of work,
    /// difficulty, timestamps) and stores it without a body, so that its
    /// block can be fetched once its branch has the most work. Returns
    /// whether it was new. A known header can still become the best one,
    /// after a branch above an invalid block was dropped.
    pub fn accept_header(&self, header: &Header, now: u64) -> Result<bool> {
        match self.accept_headers(std::slice::from_ref(header), now) {
            (_, Some(e)) => Err(e),
            (new, None) => Ok(new == 1),
        }
    }

    /// [`Chain::accept_header`] for a run of headers, each the parent of
    /// the next or with a stored parent: their proofs of work are checked
    /// in parallel, then the rest in order, all stored in one transaction.
    /// Returns how many were new and the error that stopped the run, if
    /// any; the headers before it are kept.
    pub fn accept_headers(&self, headers: &[Header], now: u64) -> (usize, Option<ChainError>) {
        match self.accept_headers_inner(headers, now) {
            Ok(r) => r,
            Err(e) => (0, Some(e)),
        }
    }

    fn accept_headers_inner(&self, headers: &[Header], now: u64) -> Result<(usize, Option<ChainError>)> {
        // The target of each, from its parent: the previous header of the
        // run or a stored one. Proofs of work are then checked at once.
        let (targets, known): (Vec<Option<Target>>, Vec<bool>) = {
            let rtxn = self.env.read_txn()?;
            let mut out = Vec::with_capacity(headers.len());
            let mut known = Vec::with_capacity(headers.len());
            for (i, h) in headers.iter().enumerate() {
                known.push(self.headers.get(&rtxn, &digest_bytes(&h.hash()))?.is_some());
                let parent = match i.checked_sub(1).map(|j| headers[j]).filter(|p| p.hash() == h.prev_hash) {
                    Some(p) => Some(p),
                    None => self.header_by_hash_in(&rtxn, &digest_bytes(&h.prev_hash))?,
                };
                out.push(match parent {
                    Some(p) => Some(self.target_after(&rtxn, &p)?),
                    None => None,
                });
            }
            (out, known)
        };
        let dataset = self.dataset.read().unwrap().clone();
        let seed = &self.seed;
        let pow: Vec<bool> = crate::parallel::par_map_min(headers.len(), 1, |i| {
            let (h, Some(t)) = (&headers[i], targets[i]) else { return false };
            known[i]
                || (h.quick_pow_check(&t)
                    && match dataset.as_deref() {
                        Some(d) => h.verify_pow(d, &t),
                        None => h.verify_pow(seed, &t),
                    })
        });
        let mut wtxn = self.env.write_txn()?;
        let mut new = 0;
        let mut stop = None;
        for (h, ok) in headers.iter().zip(&pow) {
            let id = digest_bytes(&h.hash());
            let work = match self.entry_in(&wtxn, &h.hash())? {
                Some(e) if e.invalid => {
                    stop = Some(ChainError::KnownInvalid);
                    break;
                }
                Some(e) => e.work,
                None => {
                    let Some(parent) = self.entry_in(&wtxn, &h.prev_hash)? else {
                        stop = Some(ChainError::UnknownParent(h.prev_hash));
                        break;
                    };
                    match self.check_header_rules(&wtxn, h, &parent, now, Some(*ok)) {
                        Ok(w) => {
                            self.headers.put(&mut wtxn, &id, &h.to_bytes())?;
                            self.put_index(&mut wtxn, &id, w, STATUS_HEADER_ONLY)?;
                            new += 1;
                            w
                        }
                        Err(e) => {
                            stop = Some(e);
                            break;
                        }
                    }
                }
            };
            let best = self.best_header_in(&wtxn)?;
            if work > self.entry_in(&wtxn, &best.hash())?.map_or(U256::ZERO, |e| e.work) {
                self.meta.put(&mut wtxn, META_BEST_HEADER, &id)?;
            }
        }
        wtxn.commit()?;
        Ok((new, stop))
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

    /// The first `max` blocks, oldest first, whose bodies are still needed
    /// to reach the best header: those on its branch above the main chain
    /// that are stored as headers alone. If the branch runs through an
    /// invalid block, it is dropped as the best header (the tip is the best
    /// again until a peer offers another) and nothing is returned.
    ///
    /// The branch is kept between calls: blocks joining the main chain
    /// leave its front and new headers join its end, so a call costs about
    /// what changed, not the branch's length.
    pub fn missing_bodies(&self, max: usize) -> Result<Vec<Header>> {
        let rtxn = self.env.read_txn()?;
        let best = self.best_header_in(&rtxn)?;
        let mut branch = self.branch.lock().unwrap();
        let joined = branch.iter().take_while(|h| self.is_main_in(&rtxn, h).unwrap_or(false)).count();
        branch.drain(..joined);
        // Still a branch off the main chain, ending where the best was?
        let rooted = match branch.first() {
            Some(first) => {
                let parent = self.header_by_hash_in(&rtxn, &digest_bytes(&first.prev_hash))?;
                parent.is_some_and(|p| self.is_main_in(&rtxn, &p).unwrap_or(false))
            }
            None => true,
        };
        if !rooted {
            branch.clear();
        }
        let end = branch.last().map(|h| h.hash());
        let mut fresh = Vec::new();
        let mut h = best;
        while Some(h.hash()) != end && !self.is_main_in(&rtxn, &h)? {
            fresh.push(h);
            h = self
                .header_by_hash_in(&rtxn, &digest_bytes(&h.prev_hash))?
                .ok_or(ChainError::Corrupt("best branch parent"))?;
        }
        if Some(h.hash()) != end {
            // The best header left the cached branch: start again from it.
            branch.clear();
        }
        branch.extend(fresh.into_iter().rev());
        let mut out = Vec::new();
        for h in branch.iter() {
            if out.len() == max {
                break;
            }
            let e = self.entry_in(&rtxn, &h.hash())?.ok_or(ChainError::Corrupt("best branch header"))?;
            if e.invalid {
                branch.clear();
                drop(rtxn);
                let mut wtxn = self.env.write_txn()?;
                self.meta.delete(&mut wtxn, META_BEST_HEADER)?;
                wtxn.commit()?;
                return Ok(vec![]);
            }
            if e.header_only {
                out.push(*h);
            }
        }
        Ok(out)
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
        if outputs.windows(2).any(|w| w[0].0 >= w[1].0) || outputs.last().is_some_and(|o| o.0 >= next_position) {
            return Err(ChainError::BadSnapshot);
        }
        self.begin_snapshot()?;
        let result = (|| {
            let parts = next_position.div_ceil(1 << SNAPSHOT_PART_LOG);
            let mut roots = Vec::with_capacity(parts as usize);
            let mut rest = outputs;
            for p in 0..parts {
                let n = rest.iter().take_while(|o| o.0 >> SNAPSHOT_PART_LOG == p).count();
                roots.push(self.stage_snapshot_part(p, &rest[..n], next_position, None)?);
                rest = &rest[n..];
            }
            self.finish_snapshot(block, &roots, next_position)
        })();
        if result.is_err() {
            self.abort_snapshot()?;
        }
        result
    }

    fn staging_in(&self, rtxn: &RoTxn) -> Result<bool> {
        Ok(self.meta.get(rtxn, META_STAGING)?.is_some())
    }

    /// Disk use of every database: name, bytes in pages and entries, the
    /// unspent outputs' parts first. And the file's size.
    #[allow(clippy::type_complexity)]
    pub fn storage(&self) -> Result<(Vec<(&'static str, u64, usize)>, u64)> {
        let rtxn = self.env.read_txn()?;
        let size =
            |s: heed::DatabaseStat| (s.branch_pages + s.leaf_pages + s.overflow_pages) as u64 * s.page_size as u64;
        let mut rows = self.utxo.storage(&rtxn)?;
        for (name, stat) in [
            ("headers", self.headers.stat(&rtxn)?),
            ("block index", self.index.stat(&rtxn)?),
            ("heights", self.by_height.stat(&rtxn)?),
            ("bodies", self.bodies.stat(&rtxn)?),
            ("undo", self.undo.stat(&rtxn)?),
            ("snapshots", self.snapshots.stat(&rtxn)?),
            ("spent outputs", self.spent.stat(&rtxn)?),
        ] {
            rows.push((name, size(stat), stat.entries));
        }
        Ok((rows, self.env.real_disk_size()?))
    }

    /// Whether a snapshot is being installed.
    pub fn staging(&self) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        self.staging_in(&rtxn)
    }

    /// Starts installing a snapshot a part at a time: the chain must be at
    /// genesis. Blocks are refused until it is finished or aborted.
    pub fn begin_snapshot(&self) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let tip = self.tip_in(&wtxn)?.ok_or(ChainError::NoGenesis)?;
        if tip.height != 0 || self.floor_in(&wtxn)?.is_some() {
            return Err(ChainError::AlreadyInitialized);
        }
        self.utxo.clear(&mut wtxn)?;
        self.meta.put(&mut wtxn, META_STAGING, &[1])?;
        wtxn.commit()?;
        Ok(())
    }

    /// Stores snapshot part `part`: its unspent outputs, ascending, all in
    /// the part and below `next_position`. Returns the part's root; with
    /// `expected` (the manifest's), a part with another root is refused
    /// and nothing stored. Each part is its own transaction, so memory
    /// stays bounded by one part.
    pub fn stage_snapshot_part(
        &self,
        part: u64,
        outputs: &[(u64, Commitment, Memo)],
        next_position: u64,
        expected: Option<&Digest>,
    ) -> Result<Digest> {
        let mut wtxn = self.env.write_txn()?;
        if !self.staging_in(&wtxn)? {
            return Err(ChainError::BadSnapshot);
        }
        let root = self
            .utxo
            .stage(&mut wtxn, SNAPSHOT_PART_LOG, part, outputs, next_position)
            .map_err(|_| ChainError::BadSnapshot)?;
        if expected.is_some_and(|e| *e != root) {
            return Err(ChainError::BadSnapshot);
        }
        wtxn.commit()?;
        Ok(root)
    }

    /// Carries staged parts forward to a later snapshot, whose counter is
    /// `next_position`: each part loses the outputs spent since, and must
    /// then have the later manifest's root. Parts that do not, or that are
    /// given no root, are cleared, to be fetched again. Returns, for each
    /// part, whether it was carried. One transaction for them all.
    pub fn carry_snapshot_parts(&self, parts: &[CarriedPart], next_position: u64) -> Result<Vec<bool>> {
        let mut wtxn = self.env.write_txn()?;
        if !self.staging_in(&wtxn)? {
            return Err(ChainError::BadSnapshot);
        }
        let mut carried = Vec::with_capacity(parts.len());
        for part in parts {
            // Untouched parts keep their root: only check it.
            if part.spent.is_empty()
                && let Some(root) = &part.root
                && self.utxo.subtree(&wtxn, SNAPSHOT_PART_LOG, part.index)? == *root
            {
                carried.push(true);
                continue;
            }
            let mut outputs = self.utxo.unstage(&mut wtxn, SNAPSHOT_PART_LOG, part.index)?;
            let Some(root) = &part.root else {
                carried.push(false);
                continue;
            };
            outputs.retain(|o| part.spent.binary_search(&o.0).is_err());
            let leaves: Vec<(u64, Digest)> =
                outputs.iter().map(|(p, c, m)| (*p, crate::transaction::leaf(c, m))).collect();
            let first = part.index << SNAPSHOT_PART_LOG;
            if crate::state_tree::subtree_root(SNAPSHOT_PART_LOG, first, &leaves) != *root {
                carried.push(false);
                continue;
            }
            self.utxo
                .stage(&mut wtxn, SNAPSHOT_PART_LOG, part.index, &outputs, next_position)
                .map_err(|_| ChainError::BadSnapshot)?;
            carried.push(true);
        }
        wtxn.commit()?;
        Ok(carried)
    }

    /// Clears a partly installed snapshot, if any.
    pub fn abort_snapshot(&self) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        if self.staging_in(&wtxn)? {
            self.utxo.clear(&mut wtxn)?;
            self.meta.delete(&mut wtxn, META_STAGING)?;
            wtxn.commit()?;
        }
        Ok(())
    }

    /// Completes a snapshot whose every part is staged: `roots` are the
    /// manifest's part roots and `next_position` its counter. The state
    /// must reach `block`'s state root (whose chain proof the caller has
    /// verified); `block` becomes the tip and the floor below which
    /// nothing reorganizes.
    pub fn finish_snapshot(&self, block: &Block, roots: &[Digest], next_position: u64) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        if !self.staging_in(&wtxn)? {
            return Err(ChainError::BadSnapshot);
        }
        let tip = self.tip_in(&wtxn)?.ok_or(ChainError::NoGenesis)?;
        if tip.height != 0 {
            return Err(ChainError::AlreadyInitialized);
        }
        let header = block.header;
        let entry = self.entry_in(&wtxn, &header.hash())?.ok_or(ChainError::UnknownParent(header.hash()))?;
        self.check_body(&header, &block.body)?;
        self.utxo
            .finish_staged(&mut wtxn, SNAPSHOT_PART_LOG, roots, next_position)
            .map_err(|_| ChainError::BadSnapshot)?;
        if self.utxo.root(&wtxn)? != header.state_root {
            return Err(ChainError::BadSnapshot);
        }
        self.meta.delete(&mut wtxn, META_STAGING)?;
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
        if header.height.is_multiple_of(self.params.snapshot_interval) {
            self.put_snapshot(&mut wtxn, &header, next_position, roots)?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Drops the spent-log entries of the main-chain block `header`,
    /// leaving the undo window: its inputs, read from its body before that
    /// goes too. A block without a body (the floor of a fast sync) spent
    /// nothing that was logged.
    fn forget_spends(&self, wtxn: &mut RwTxn, header: &Header) -> Result<()> {
        let Some(body) = self.body_by_hash_in(wtxn, &digest_bytes(&header.hash()))? else {
            return Ok(());
        };
        for p in &body.inputs {
            if self.spent.get(wtxn, p)?.and_then(read_spent_entry).is_some_and(|(h, _, _)| h == header.height) {
                self.spent.delete(wtxn, p)?;
            }
        }
        Ok(())
    }

    /// Drops the manifests that can no longer be served, with the tip at
    /// `tip`: a part needs the outputs spent by every block after its
    /// snapshot, and those leave the spent log with the undo window. An
    /// archive (no window) keeps them all, as its status promises.
    fn prune_snapshots(&self, wtxn: &mut RwTxn, tip: u32) -> Result<()> {
        let Some(keep) = self.max_undo else {
            return Ok(());
        };
        let Some(oldest) = tip.checked_sub(keep) else {
            return Ok(());
        };
        let stale: Vec<u32> =
            self.snapshots.range(wtxn, &(..oldest))?.map(|e| e.map(|(h, _)| h)).collect::<heed::Result<_>>()?;
        for h in stale {
            self.snapshots.delete(wtxn, &h)?;
        }
        Ok(())
    }

    /// Takes the snapshot after `header`, just connected: the roots of its
    /// parts are read from the state tree as it stands.
    fn take_snapshot(&self, wtxn: &mut RwTxn, header: &Header) -> Result<()> {
        let next = self.utxo.next_position(wtxn)?;
        let parts = next.div_ceil(1 << SNAPSHOT_PART_LOG);
        let roots =
            (0..parts).map(|p| self.utxo.subtree(wtxn, SNAPSHOT_PART_LOG, p)).collect::<utxo::Result<Vec<_>>>()?;
        self.put_snapshot(wtxn, header, next, &roots)
    }

    /// Stores a snapshot manifest.
    fn put_snapshot(&self, wtxn: &mut RwTxn, header: &Header, next: u64, roots: &[Digest]) -> Result<()> {
        let mut value = Vec::with_capacity(40 + 32 * roots.len());
        value.extend_from_slice(&digest_bytes(&header.hash()));
        value.extend_from_slice(&next.to_le_bytes());
        for r in roots {
            value.extend_from_slice(&digest_bytes(r));
        }
        self.snapshots.put(wtxn, &header.height, &value)?;
        Ok(())
    }

    /// The kept snapshot after the main-chain block `id`: its height,
    /// output counter and part roots.
    fn snapshot_in(&self, rtxn: &RoTxn, id: &Digest) -> Result<Option<(u32, u64, Vec<Digest>)>> {
        let Some(header) = self.header_by_hash_in(rtxn, &digest_bytes(id))? else {
            return Ok(None);
        };
        let Some(value) = self.snapshots.get(rtxn, &header.height)? else {
            return Ok(None);
        };
        if value.len() < 40 || value[..32] != digest_bytes(id) || (value.len() - 40) % 32 != 0 {
            return Ok(None);
        }
        let next = u64::from_le_bytes(value[32..40].try_into().unwrap());
        let roots = value[40..]
            .chunks_exact(32)
            .map(digest_from_bytes)
            .collect::<Option<Vec<_>>>()
            .ok_or(ChainError::Corrupt("snapshot root"))?;
        Ok(Some((header.height, next, roots)))
    }

    /// A snapshot manifest of the state after the main-chain block `id`:
    /// the output counter and the root of every part's subtree. `None`
    /// unless a snapshot was taken after that block and is still kept.
    pub fn snapshot_manifest(&self, id: &Digest) -> Result<Option<(u64, Vec<Digest>)>> {
        let rtxn = self.env.read_txn()?;
        Ok(self.snapshot_in(&rtxn, id)?.map(|(_, next, roots)| (next, roots)))
    }

    /// The unspent outputs in part `part` of the snapshot after the
    /// main-chain block `id` (positions `part << SNAPSHOT_PART_LOG` and on,
    /// below its counter): those unspent now, with those spent since.
    #[allow(clippy::type_complexity)]
    pub fn snapshot_part(&self, id: &Digest, part: u64) -> Result<Option<Vec<(u64, Commitment, Memo)>>> {
        let rtxn = self.env.read_txn()?;
        let Some((height, next, roots)) = self.snapshot_in(&rtxn, id)? else {
            return Ok(None);
        };
        if part >= roots.len() as u64 {
            return Ok(None);
        }
        let first = part << SNAPSHOT_PART_LOG;
        let end = (first + (1 << SNAPSHOT_PART_LOG)).min(next);
        let mut out: Vec<(u64, Commitment, Memo)> =
            self.utxo.unspent_in(&rtxn, first, end)?.into_iter().map(|(p, (c, m))| (p, c, m)).collect();
        let before = out.len();
        for e in self.spent.range(&rtxn, &(first..end))? {
            let (p, v) = e?;
            let (spent_at, c, m) = read_spent_entry(v).ok_or(ChainError::Corrupt("spent log"))?;
            if spent_at > height {
                out.push((p, c, m));
            }
        }
        if out.len() > before {
            out.sort_unstable_by_key(|o| o.0);
        }
        Ok(Some(out))
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

    /// Up to `max` main-chain headers from `height` on.
    pub fn headers_from(&self, height: u32, max: usize) -> Result<Vec<Header>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        let mut h = height;
        while out.len() < max {
            match self.header_at_in(&rtxn, h)? {
                Some(header) => out.push(header),
                None => break,
            }
            h += 1;
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
            snapshot_interval: 4,
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

    /// Checks the snapshot manifests a real data directory would serve:
    /// `TABMINER_DEBUG_CHAIN` names a copy of a chain database (it is
    /// written to), `TABMINER_DEBUG_HEIGHT` the block.
    #[test]
    #[ignore = "debugging a data directory"]
    fn manifest_of_a_data_directory() {
        let Ok(path) = std::env::var("TABMINER_DEBUG_CHAIN") else {
            return;
        };
        let height: u32 = std::env::var("TABMINER_DEBUG_HEIGHT").unwrap().parse().unwrap();
        let p = ChainParams::MAINNET;
        let chain = Chain::open(Path::new(&path), 1 << 40, p, SeedText::new(p.pow), AcceptAllProofs).unwrap();
        let header = chain.header_at(height).unwrap().unwrap();
        let (next, roots) = chain.snapshot_manifest(&header.hash()).unwrap().unwrap();
        let ok = crate::state_tree::root_from_subtrees(SNAPSHOT_PART_LOG, &roots) == header.state_root;
        eprintln!("block {height}: {next} positions, {} parts, composes to the state root: {ok}", roots.len());
        let mut bad = 0;
        for (i, r) in roots.iter().enumerate().filter(|_| std::env::var("TABMINER_DEBUG_TIP_ONLY").is_err()) {
            let part = chain.snapshot_part(&header.hash(), i as u64).unwrap().unwrap();
            let leaves: Vec<(u64, Digest)> =
                part.iter().map(|(pos, c, m)| (*pos, crate::transaction::leaf(c, m))).collect();
            let full = crate::state_tree::subtree_root(SNAPSHOT_PART_LOG, (i as u64) << SNAPSHOT_PART_LOG, &leaves);
            if full != *r {
                bad += 1;
                if bad <= 5 {
                    eprintln!("  part {i}: manifest root differs from the part's outputs ({} outputs)", part.len());
                }
            }
        }
        eprintln!("{bad} parts differ");
        // The tip's own state, recomputed from its outputs.
        let tip = chain.tip().unwrap().unwrap();
        let rtxn = chain.env().read_txn().unwrap();
        let all = chain.utxo().unspent(&rtxn).unwrap();
        let leaves: Vec<(u64, Digest)> =
            all.iter().map(|(pos, (c, m))| (*pos, crate::transaction::leaf(c, m))).collect();
        let tip_next = chain.utxo().next_position(&rtxn).unwrap();
        let parts: Vec<Digest> = (0..tip_next.div_ceil(1 << SNAPSHOT_PART_LOG))
            .map(|i| {
                let lo = i << SNAPSHOT_PART_LOG;
                let hi = lo + (1 << SNAPSHOT_PART_LOG);
                let these: Vec<(u64, Digest)> = leaves.iter().copied().filter(|(p, _)| (lo..hi).contains(p)).collect();
                crate::state_tree::subtree_root(SNAPSHOT_PART_LOG, lo, &these)
            })
            .collect();
        eprintln!(
            "tip {}: stored root matches its outputs: {}; matches its header: {}",
            tip.height,
            crate::state_tree::root_from_subtrees(SNAPSHOT_PART_LOG, &parts) == chain.utxo().root(&rtxn).unwrap(),
            chain.utxo().root(&rtxn).unwrap() == tip.state_root
        );
        let stored_bad = (0..parts.len())
            .filter(|&i| chain.utxo().subtree(&rtxn, SNAPSHOT_PART_LOG, i as u64).unwrap() != parts[i])
            .count();
        eprintln!("{stored_bad} stored part roots differ from their outputs");
        // Down to the stored subtrees of 256 positions.
        let groups = tip_next.div_ceil(1 << crate::utxo::GROUP_LOG);
        let mut wrong = Vec::new();
        for g in 0..groups {
            let leaves = chain.utxo().group_leaves(&rtxn, g).unwrap();
            let want = crate::state_tree::subtree_root(crate::utxo::GROUP_LOG, g << crate::utxo::GROUP_LOG, &leaves);
            if chain.utxo().subtree(&rtxn, crate::utxo::GROUP_LOG, g).unwrap() != want {
                wrong.push((g, leaves.len()));
            }
        }
        eprintln!(
            "{} of {groups} stored subtree roots differ; first: {:?}",
            wrong.len(),
            &wrong[..wrong.len().min(12)]
        );
        for &(g, _) in wrong.iter().take(3) {
            let leaves = chain.utxo().group_leaves(&rtxn, g).unwrap();
            let stored = chain.utxo().subtree(&rtxn, crate::utxo::GROUP_LOG, g).unwrap();
            let d = crate::state_tree::default_hashes();
            // Which subset of the leaves gives the stored root?
            let n = leaves.len();
            let mut explains = None;
            for mask in 0u32..(1 << n.min(12)) {
                let sub: Vec<(u64, Digest)> = (0..n).filter(|i| mask >> i & 1 == 1).map(|i| leaves[i]).collect();
                if crate::state_tree::subtree_root(crate::utxo::GROUP_LOG, g << crate::utxo::GROUP_LOG, &sub) == stored
                {
                    explains = Some(sub.iter().map(|l| l.0).collect::<Vec<_>>());
                    break;
                }
            }
            eprintln!(
                "  group {g}: leaves at {:?}; stored root is default: {}; stored root is these leaves: {:?}",
                leaves.iter().map(|l| l.0).collect::<Vec<_>>(),
                stored == d[crate::utxo::GROUP_LOG],
                explains
            );
        }
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
    fn snapshots_are_kept_and_served_through_spends_and_reorganizations() {
        // Twenty blocks of three outputs each, from block 3 on spending two
        // earlier ones; snapshots after every fourth block, kept for the
        // undo window of nine blocks.
        let k = pk(13);
        let mut f = open("snap-f");
        f.chain = f.chain.with_max_undo(Some(9));
        f.chain.init_genesis(&genesis_block(vec![])).unwrap();
        let mut unspent: Vec<u64> = Vec::new();
        let mut next = 0u64;
        let mut lcg = 7u64;
        let mut t = GENESIS_TIME;
        let mut blocks = Vec::new();
        let mut build = |chain_f: &Fixture, h: u64, unspent: &mut Vec<u64>, next: &mut u64, tag: u64, t: &mut u64| {
            let mut inputs = Vec::new();
            if h >= 3 {
                for _ in 0..2 {
                    lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    inputs.push(unspent.swap_remove((lcg >> 33) as usize % unspent.len()));
                }
            }
            let outputs = (0..3).map(|i| Output::new(&k, h * 100 + i + tag).block_output()).collect();
            unspent.extend(*next..*next + 3);
            *next += 3;
            *t += 600;
            mine(chain_f, Body { inputs, outputs, proof: vec![] }, *t)
        };
        for h in 1..=20u64 {
            let block = build(&f, h, &mut unspent, &mut next, 0, &mut t);
            f.chain.apply_block(&block, t + 1).unwrap();
            blocks.push(block);
        }
        let check = |chain: &Chain<AcceptAllProofs>, header: &Header| {
            let (n, roots) = chain.snapshot_manifest(&header.hash()).unwrap().unwrap();
            assert_eq!(crate::state_tree::root_from_subtrees(SNAPSHOT_PART_LOG, &roots), header.state_root);
            for (i, r) in roots.iter().enumerate() {
                let part = chain.snapshot_part(&header.hash(), i as u64).unwrap().unwrap();
                assert!(part.iter().all(|o| o.0 < n));
                let leaves: Vec<(u64, Digest)> =
                    part.iter().map(|(p, c, m)| (*p, crate::transaction::leaf(c, m))).collect();
                assert_eq!(
                    crate::state_tree::subtree_root(SNAPSHOT_PART_LOG, (i as u64) << SNAPSHOT_PART_LOG, &leaves),
                    *r
                );
            }
            (n, roots)
        };
        let kept = |chain: &Chain<AcceptAllProofs>, blocks: &[Block]| {
            (1..=blocks.len())
                .filter(|&h| chain.snapshot_manifest(&blocks[h - 1].header.hash()).unwrap().is_some())
                .collect::<Vec<_>>()
        };
        assert_eq!(kept(&f.chain, &blocks), [12, 16, 20]);
        for h in [12, 16, 20] {
            check(&f.chain, &blocks[h - 1].header);
        }
        // The spent log holds the spends of the blocks in the window, 12 to
        // 20, and nothing older.
        let spent_heights = |chain: &Chain<AcceptAllProofs>| {
            let rtxn = chain.env().read_txn().unwrap();
            let mut heights: Vec<u32> =
                chain.spent.iter(&rtxn).unwrap().map(|e| read_spent_entry(e.unwrap().1).unwrap().0).collect();
            heights.sort_unstable();
            heights
        };
        assert_eq!(spent_heights(&f.chain), (12..=20).flat_map(|h| [h, h]).collect::<Vec<_>>());
        // g shares blocks 1 to 16, then outgrows f with its own 17 to 21.
        let g = open("snap-g");
        g.chain.init_genesis(&genesis_block(vec![])).unwrap();
        for b in &blocks[..16] {
            g.chain.apply_block(b, t + 1).unwrap();
        }
        let mut g_unspent: Vec<u64> = Vec::new();
        let mut g_next = 0u64;
        // Rebuild the unspent set as of block 16 by replaying its bodies.
        for b in &blocks[..16] {
            g_unspent.retain(|p| !b.body.inputs.contains(p));
            g_unspent.extend(g_next..g_next + b.body.outputs.len() as u64);
            g_next += b.body.outputs.len() as u64;
        }
        t = blocks[15].header.timestamp;
        let mut fork = Vec::new();
        for h in 17..=21u64 {
            let block = build(&g, h, &mut g_unspent, &mut g_next, 50, &mut t);
            g.chain.apply_block(&block, t + 1).unwrap();
            fork.push(block);
        }
        for b in &fork {
            f.chain.apply_block(b, t + 1).unwrap();
        }
        assert_eq!(f.chain.tip().unwrap(), g.chain.tip().unwrap());
        // f's block 20 went with the reorganization; the new 20 replaced it.
        assert!(f.chain.snapshot_manifest(&blocks[19].header.hash()).unwrap().is_none());
        let both: Vec<Block> = blocks[..16].iter().chain(fork.iter()).cloned().collect();
        assert_eq!(kept(&f.chain, &both), [12, 16, 20]);
        assert_eq!(spent_heights(&f.chain), (13..=21).flat_map(|h| [h, h]).collect::<Vec<_>>());
        for h in [12, 16, 20] {
            let header = both[h - 1].header;
            assert_eq!(check(&f.chain, &header), check(&g.chain, &header));
        }
    }

    #[test]
    fn staged_parts_are_carried_to_a_later_snapshot() {
        // Blocks 1 to 3 make 20,000 outputs each: parts 0 to 2 full, part
        // 3 begun. Blocks 4 to 8 make one each and spend in parts 0 and 2.
        let big = || ChainParams { max_block_size: ChainParams::MAINNET.max_block_size, ..params() };
        let make = |name: &str| {
            let dir = TempDir::new(name);
            let seed = seed();
            let dataset = Dataset::generate(&seed);
            let chain = Chain::open(&dir.0, 1 << 30, big(), seed, AcceptAllProofs).unwrap();
            chain.init_genesis(&genesis_block(vec![])).unwrap();
            Fixture { _dir: dir, chain, dataset }
        };
        let a = make("carry-a");
        let k = pk(14);
        let mut t = GENESIS_TIME;
        let mut blocks = Vec::new();
        for h in 1..=8u64 {
            t += 600;
            let n = if h <= 3 { 20_000 } else { 1 };
            let outputs = (0..n).map(|i| Output::new(&k, h * 100_000 + i).block_output()).collect();
            let inputs = match h {
                4 => vec![1, 33_000],
                5 => vec![2, 40_000],
                6 => vec![3],
                7 => vec![34_000, 35_000],
                _ => vec![],
            };
            let block = mine(&a, Body { inputs, outputs, proof: vec![] }, t);
            a.chain.apply_block(&block, t + 1).unwrap();
            blocks.push(block);
        }
        let (s4, s8) = (blocks[3].header, blocks[7].header);
        let (next4, roots4) = a.chain.snapshot_manifest(&s4.hash()).unwrap().unwrap();
        let (next8, roots8) = a.chain.snapshot_manifest(&s8.hash()).unwrap().unwrap();
        assert_eq!((next4, roots4.len(), next8, roots8.len()), (60_001, 4, 60_005, 4));

        // b stages the snapshot after block 4, then moves to block 8's.
        let b = make("carry-b");
        for block in &blocks {
            b.chain.accept_header(&block.header, t + 1).unwrap();
        }
        b.chain.begin_snapshot().unwrap();
        for (i, root) in roots4.iter().enumerate() {
            let part = a.chain.snapshot_part(&s4.hash(), i as u64).unwrap().unwrap();
            b.chain.stage_snapshot_part(i as u64, &part, next4, Some(root)).unwrap();
        }
        let mut spent: Vec<u64> = blocks[4..8].iter().flat_map(|b| b.body.inputs.clone()).collect();
        spent.sort_unstable();
        let in_part = |i: u64| -> Vec<u64> { spent.iter().copied().filter(|p| p >> SNAPSHOT_PART_LOG == i).collect() };
        let parts = [
            // Spends carried away.
            CarriedPart { index: 0, spent: in_part(0), root: Some(roots8[0]) },
            // Untouched.
            CarriedPart { index: 1, spent: in_part(1), root: Some(roots8[1]) },
            // A spend missed (a lying body would do this): cleared.
            CarriedPart { index: 2, spent: vec![34_000], root: Some(roots8[2]) },
            // Begun at block 4, grown since: cleared.
            CarriedPart { index: 3, spent: in_part(3), root: None },
        ];
        assert!(in_part(1).is_empty());
        assert_eq!(b.chain.carry_snapshot_parts(&parts, next8).unwrap(), [true, true, false, false]);
        // The cleared parts are fetched at block 8 and the install completes.
        for i in [2u64, 3] {
            let part = a.chain.snapshot_part(&s8.hash(), i).unwrap().unwrap();
            b.chain.stage_snapshot_part(i, &part, next8, Some(&roots8[i as usize])).unwrap();
        }
        b.chain.finish_snapshot(&blocks[7], &roots8, next8).unwrap();
        let rtxn = b.chain.env().read_txn().unwrap();
        assert_eq!(b.chain.utxo().root(&rtxn).unwrap(), s8.state_root);
        assert_eq!(b.chain.utxo().len(&rtxn).unwrap(), a.chain.utxo().len(&a.chain.env().read_txn().unwrap()).unwrap());
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
        assert!(!b.chain.staging().unwrap());
        // Part by part, as a node does: blocks wait meanwhile, and finishing
        // with a part missing is refused.
        b.chain.begin_snapshot().unwrap();
        assert!(matches!(b.chain.apply_block(&blocks[8], t + 1), Err(ChainError::SnapshotInProgress)));
        assert!(matches!(b.chain.finish_snapshot(&blocks[7], &roots, next), Err(ChainError::BadSnapshot)));
        let mut wrong = roots[0];
        wrong[0] += crate::poseidon2::Fp::ONE;
        assert!(matches!(b.chain.stage_snapshot_part(0, &part, next, Some(&wrong)), Err(ChainError::BadSnapshot)));
        assert_eq!(b.chain.stage_snapshot_part(0, &part, next, Some(&roots[0])).unwrap(), roots[0]);
        b.chain.finish_snapshot(&blocks[7], &roots, next).unwrap();
        assert!(!b.chain.staging().unwrap());
        assert_eq!(b.chain.utxo().len(&b.chain.env().read_txn().unwrap()).unwrap(), 10);
        // An install interrupted by a stop is cleared when the chain reopens.
        let Fixture { _dir: d_dir, chain: d, dataset: _ } = open("fast-d");
        d.init_genesis(&genesis_block(vec![])).unwrap();
        for block in &blocks {
            d.accept_header(&block.header, t + 1).unwrap();
        }
        d.begin_snapshot().unwrap();
        d.stage_snapshot_part(0, &part, next, None).unwrap();
        drop(d);
        let d = Chain::open(&d_dir.0, 64 << 20, params(), seed(), AcceptAllProofs).unwrap();
        assert!(!d.staging().unwrap());
        assert!(d.utxo().is_empty(&d.env().read_txn().unwrap()).unwrap());
        d.install_snapshot(&blocks[7], &part, next).unwrap();
        assert_eq!(d.state_root().unwrap(), s8.state_root);
        drop(d);
        // A second install on b is refused: its chain is past genesis.
        assert!(matches!(b.chain.install_snapshot(&blocks[7], &part, next), Err(ChainError::AlreadyInitialized)));
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
    fn missing_bodies_follow_the_best_branch() {
        let a = open("missing-a");
        a.chain.init_genesis(&genesis_block(vec![])).unwrap();
        let k = pk(3);
        let mut t = GENESIS_TIME;
        let mut blocks = Vec::new();
        for i in 1..=8u64 {
            t += 600;
            let block = mine_outputs(&a, &[Output::new(&k, i)], t);
            a.chain.apply_block(&block, t + 1).unwrap();
            blocks.push(block);
        }
        let b = open("missing-b");
        b.chain.init_genesis(&genesis_block(vec![])).unwrap();
        let heights = |n: usize| b.chain.missing_bodies(n).unwrap().iter().map(|h| h.height).collect::<Vec<_>>();
        assert!(heights(4).is_empty());
        for block in &blocks[..5] {
            assert!(b.chain.accept_header(&block.header, t + 1).unwrap());
        }
        assert_eq!(heights(4), [1, 2, 3, 4]);
        // Connected blocks leave the front, new headers join the end.
        for block in &blocks[..2] {
            b.chain.apply_block(block, t + 1).unwrap();
        }
        assert_eq!(heights(4), [3, 4, 5]);
        for block in &blocks[5..] {
            b.chain.accept_header(&block.header, t + 1).unwrap();
        }
        assert_eq!(heights(10), [3, 4, 5, 6, 7, 8]);
        for block in &blocks[2..] {
            b.chain.apply_block(block, t + 1).unwrap();
        }
        assert!(heights(4).is_empty());
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
        // Heights 4 to 6 keep undo records and their spends: snapshots from
        // height 3 on can be served, older ones not.
        let undo = |h: usize| {
            let rtxn = f.chain.env().read_txn().unwrap();
            f.chain.undo.get(&rtxn, &digest_bytes(&blocks[h - 1].header.hash())).unwrap().is_some()
        };
        assert_eq!((1..=6).map(undo).collect::<Vec<_>>(), [false, false, false, true, true, true]);
        // Bodies go with them: blocks 1 to 3 keep only their headers.
        let body = |h: usize| f.chain.body_by_hash(&blocks[h - 1].header.hash()).unwrap().is_some();
        assert_eq!((1..=6).map(body).collect::<Vec<_>>(), [false, false, false, true, true, true]);
        assert_eq!(f.chain.oldest_body().unwrap(), 4);
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
