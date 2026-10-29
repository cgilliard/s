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

use heed::byteorder::BigEndian;
use heed::types::{Bytes, Str, U32};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::aggregate::AggregatorParams;
use crate::block::{Block, Body, BodyError, HEADER_SIZE, Header};
use crate::difficulty::{Asert, U256};
use crate::poseidon2::digest_from_bytes;
use crate::pow::{Digest, PowParams, SeedText, Target};
use crate::state_tree::{EMPTY, empty_root, open_env};
use crate::transaction::Commitment;
use crate::utxo::{self, UtxoSet};

/// Consensus parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainParams {
    pub pow: PowParams,
    /// Timestamp of the genesis block, an empty block (see
    /// [`ChainParams::genesis`]).
    pub genesis_timestamp: u64,
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
    /// Block subsidy at height 0, in base units.
    pub initial_subsidy: u64,
    /// Blocks between halvings of the subsidy.
    pub halving_interval: u32,
    /// Parameters of the block validity proof.
    pub aggregator: AggregatorParams,
}

impl ChainParams {
    pub const MAINNET: ChainParams = ChainParams {
        pow: PowParams::MAINNET,
        genesis_timestamp: 1_767_225_600,         // 2026-01-01T00:00:00Z
        genesis_target: U256([0, 0, 0, 1 << 40]), // 2^232: about 2^16 hashes per block to start
        max_target: U256([u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 8]), // 2^248 - 1
        max_block_size: 2 << 20,
        max_future_drift: 2 * 3600,
        median_time_window: 11,
        initial_subsidy: 50 * 100_000_000,
        halving_interval: 210_000,
        aggregator: AggregatorParams::MAINNET,
    };

    /// Subsidy paid by the block at `height`.
    pub fn subsidy(&self, height: u32) -> u64 {
        let halvings = height / self.halving_interval;
        if halvings >= 64 { 0 } else { self.initial_subsidy >> halvings }
    }

    /// The genesis block: empty, at `genesis_timestamp`, over the empty
    /// state tree. Every node of a network must start from the same one.
    pub fn genesis(&self) -> Block {
        let body = Body { inputs: vec![], outputs: vec![], proof: vec![] };
        let header = Header {
            prev_hash: EMPTY,
            height: 0,
            timestamp: self.genesis_timestamp,
            body_commitment: body.commitment(),
            state_root: empty_root(),
            mix: EMPTY,
            nonce: [0u8; 32],
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

/// Status byte of a stored block, after its work in the index.
const STATUS_HEADER_VALID: u8 = 0;
const STATUS_VALID: u8 = 1;
const STATUS_INVALID: u8 = 2;

/// A stored header with its index record.
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub header: Header,
    /// Cumulative work of the chain ending at this block.
    pub work: U256,
    /// Whether the block has been connected (its state rules checked).
    pub validated: bool,
    pub invalid: bool,
}

/// What disconnecting a block needs: the commitments its inputs held, in
/// input order, and where its outputs started.
struct Undo {
    first_output_position: u64,
    spent: Vec<Commitment>,
}

impl Undo {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 * self.spent.len());
        out.extend_from_slice(&self.first_output_position.to_le_bytes());
        for c in &self.spent {
            out.extend_from_slice(&digest_bytes(c));
        }
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Undo> {
        let (first, rest) = bytes.split_at_checked(8)?;
        if rest.len() % 32 != 0 {
            return None;
        }
        let spent = rest.chunks_exact(32).map(digest_from_bytes).collect::<Option<Vec<_>>>()?;
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
    by_height: Database<U32<BigEndian>, Bytes>,
    meta: Database<Str, Bytes>,
}

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
        let meta = env.create_database(&mut wtxn, Some("meta"))?;
        wtxn.commit()?;
        Ok(Chain { env, params, seed, verifier, utxo, headers, bodies, index, undo, by_height, meta })
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
        Ok(Some(Entry { header, work, validated: status == STATUS_VALID, invalid: status == STATUS_INVALID }))
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
    fn apply_body(&self, wtxn: &mut RwTxn, body: &Body) -> Result<(Digest, Vec<Commitment>)> {
        let mut spent = Vec::with_capacity(body.inputs.len());
        for &pos in &body.inputs {
            let commitment = self.utxo.get(wtxn, pos)?;
            if commitment == EMPTY || !self.utxo.spend_at(wtxn, &commitment, pos)? {
                return Err(ChainError::UnknownInput(pos));
            }
            spent.push(commitment);
        }
        for out in &body.outputs {
            self.utxo.add(wtxn, out)?;
        }
        Ok((self.utxo.root(wtxn)?, spent))
    }

    /// Header rules (1 to 4) of a block whose parent is `parent`: returns
    /// the block's cumulative work.
    fn check_header(&self, rtxn: &RoTxn, block: &Block, parent: &Entry, now: u64) -> Result<U256> {
        let header = &block.header;
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
        self.check_body(header, &block.body)?;
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
        if let Some(e) = self.entry_in(&wtxn, &hash)? {
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
                self.body_by_hash_in(&wtxn, &digest_bytes(&h.hash()))?.ok_or(ChainError::Corrupt("branch body"))?
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
        Ok(())
    }

    /// Disconnects the main-chain block at `height`, the tip, restoring the
    /// outputs it spent and removing the ones it appended.
    fn disconnect(&self, wtxn: &mut RwTxn, height: u32) -> Result<()> {
        let header = self.header_at_in(wtxn, height)?.ok_or(ChainError::Corrupt("disconnecting missing height"))?;
        let id = digest_bytes(&header.hash());
        let body = self.body_by_hash_in(wtxn, &id)?.ok_or(ChainError::Corrupt("body of main-chain block"))?;
        let undo = self.undo.get(wtxn, &id)?.and_then(Undo::from_bytes).ok_or(ChainError::Corrupt("undo record"))?;
        if undo.spent.len() != body.inputs.len() {
            return Err(ChainError::Corrupt("undo record length"));
        }
        self.utxo.truncate(wtxn, undo.first_output_position, &body.outputs)?;
        for (&pos, c) in body.inputs.iter().zip(&undo.spent) {
            self.utxo.unspend(wtxn, c, pos)?;
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
            // Easy: 2^240, about 2^8 hashes per block.
            genesis_target: U256([0, 0, 0, 1 << 48]),
            max_target: ChainParams::MAINNET.max_target,
            // Four outputs and a short proof.
            max_block_size: HEADER_SIZE + 12 + 4 * crate::block::COMMITMENT_SIZE + 31,
            max_future_drift: 7200,
            median_time_window: 11,
            initial_subsidy: 50,
            halving_interval: 10,
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
        let body = Body { inputs: vec![], outputs: outputs.iter().map(|o| o.commitment).collect(), proof: vec![] };
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
            outputs: vec![Output::new(&b, 60).commitment, Output::new(&a, 40).commitment],
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
        let body2 = Body { inputs: vec![1, 2], outputs: vec![Output::new(&b, 200).commitment], proof: vec![] };
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
        assert_eq!(p.subsidy(0), 50);
        assert_eq!(p.subsidy(9), 50);
        assert_eq!(p.subsidy(10), 25);
        assert_eq!(p.subsidy(25), 12);
        assert_eq!(p.subsidy(10 * 70), 0);
        assert_eq!(ChainParams::MAINNET.subsidy(0), 5_000_000_000);
        assert_eq!(ChainParams::MAINNET.subsidy(210_000), 2_500_000_000);
    }

    #[test]
    fn rejects_invalid_headers() {
        let f = open("invalid");
        let a = pk(3);
        f.chain.init_genesis(&genesis_block(vec![Output::new(&a, 1)])).unwrap();
        let body = Body { inputs: vec![], outputs: vec![Output::new(&a, 7).commitment], proof: vec![] };
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
        wrong.outputs.push(Output::new(&a, 8).commitment);
        let b = mine_with_root(&f, wrong, GENESIS_TIME + 600, good.header.state_root);
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::StateRootMismatch { .. })));
        // Too large.
        let many = Body { inputs: vec![], outputs: vec![Output::new(&a, 1).commitment; 5], proof: vec![] };
        let b = mine(&f, many, GENESIS_TIME + 600);
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::TooLarge(344))));

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
            let body = Body { inputs: vec![], outputs: vec![Output::new(&a, i as u64 + 1).commitment], proof: vec![] };
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
            let body = Body { inputs: vec![], outputs: vec![Output::new(&a, 3).commitment], proof };
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
                Body { inputs: vec![0], outputs: vec![Output::new(&a, 2).commitment], proof: vec![] },
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
        let body = Body { inputs: vec![], outputs: outputs.iter().map(|o| o.commitment).collect(), proof: vec![] };
        mine(f, body, timestamp)
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
                outputs: vec![Output::new(&k, 10).commitment, Output::new(&k, 11).commitment],
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
            Body { inputs: vec![1], outputs: vec![Output::new(&k, 20).commitment], proof: vec![2] },
            GENESIS_TIME + 650,
        );
        b.chain.apply_block(&b1, GENESIS_TIME + 700).unwrap();
        let b2 = mine(
            &b,
            Body { inputs: vec![2], outputs: vec![Output::new(&k, 21).commitment], proof: vec![3] },
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
        let bad_body = Body { inputs: vec![], outputs: vec![Output::new(&k, 7).commitment], proof: vec![] };
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
