//! Chain state and block validation.
//!
//! A [`Chain`] owns an LMDB environment holding the UTXO set
//! ([`crate::utxo::UtxoSet`]), every accepted header and body by block id,
//! the main-chain index by height, and the tip. Blocks are applied with
//! [`Chain::apply_block`], which validates and commits in one transaction so
//! the UTXO set and the block index never disagree.
//!
//! # Rules checked
//!
//! 1. The block extends the tip: `prev_hash` is the tip id and `height` is
//!    the tip height plus one. Forks are not handled yet; a block that does
//!    not extend the tip is rejected.
//! 2. `timestamp` is greater than the median of the last eleven block
//!    timestamps and at most two hours ahead of the caller's clock.
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
//!
//! What a node cannot check here is balance: input amounts are not on chain.
//! That, the signatures, and the commitment preimages are the proof's job.

use std::path::Path;

use heed::byteorder::BigEndian;
use heed::types::{Bytes, Str, U32};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::aggregate::AggregatorParams;
use crate::block::{Block, Body, BodyError, Header};
use crate::difficulty::{Asert, U256};
use crate::pow::{Digest, PowParams, SeedText, Target};
use crate::state_tree::{EMPTY, open_env};
use crate::utxo::{self, UtxoSet};

/// Consensus parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainParams {
    pub pow: PowParams,
    /// Target of the block after genesis; the ASERT anchor.
    pub genesis_target: U256,
    /// Easiest permitted target.
    pub max_target: U256,
    pub max_inputs: usize,
    pub max_outputs: usize,
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
        genesis_target: U256([0, 0, 0, 1 << 40]), // 2^232: about 2^16 hashes per block to start
        max_target: U256([u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 8]), // 2^248 - 1
        max_inputs: 1024,
        max_outputs: 1024,
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
    /// `prev_hash` is not the tip.
    NotOnTip,
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
    TooManyInputs(usize),
    TooManyOutputs(usize),
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

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainError::Heed(e) => write!(f, "lmdb error: {e}"),
            ChainError::Utxo(e) => write!(f, "{e}"),
            ChainError::Body(e) => write!(f, "{e}"),
            ChainError::NoGenesis => f.write_str("chain has no genesis block"),
            ChainError::AlreadyInitialized => f.write_str("chain already has a genesis block"),
            ChainError::NotOnTip => f.write_str("block does not extend the tip"),
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
            ChainError::TooManyInputs(n) => write!(f, "{n} inputs exceeds the block limit"),
            ChainError::TooManyOutputs(n) => write!(f, "{n} outputs exceeds the block limit"),
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

const META_TIP: &str = "tip";

/// Persistent chain state.
pub struct Chain<V: ProofVerifier> {
    env: Env,
    params: ChainParams,
    seed: SeedText,
    verifier: V,
    utxo: UtxoSet,
    headers: Database<Bytes, Bytes>,
    bodies: Database<Bytes, Bytes>,
    by_height: Database<U32<BigEndian>, Bytes>,
    meta: Database<Str, Bytes>,
}

fn digest_bytes(d: &Digest) -> [u8; 32] {
    crate::poseidon2::digest_to_bytes(d)
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
        let by_height = env.create_database(&mut wtxn, Some("by_height"))?;
        let meta = env.create_database(&mut wtxn, Some("meta"))?;
        wtxn.commit()?;
        Ok(Chain { env, params, seed, verifier, utxo, headers, bodies, by_height, meta })
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

    pub fn body_by_hash(&self, hash: &Digest) -> Result<Option<Body>> {
        let rtxn = self.env.read_txn()?;
        match self.bodies.get(&rtxn, &digest_bytes(hash))? {
            None => Ok(None),
            Some(bytes) => Body::from_bytes(bytes).map(Some).map_err(|_| ChainError::Corrupt("body")),
        }
    }

    /// Current UTXO root.
    pub fn state_root(&self) -> Result<Digest> {
        let rtxn = self.env.read_txn()?;
        Ok(self.utxo.root(&rtxn)?)
    }

    /// Median timestamp of the `median_time_window` blocks ending at `tip`.
    fn median_time_past(&self, rtxn: &RoTxn, tip: &Header) -> Result<u64> {
        let mut times = Vec::with_capacity(self.params.median_time_window);
        let mut h = tip.height;
        loop {
            let header = self.header_at_in(rtxn, h)?.ok_or(ChainError::Corrupt("missing main-chain header"))?;
            times.push(header.timestamp);
            if times.len() == self.params.median_time_window || h == 0 {
                break;
            }
            h -= 1;
        }
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }

    /// ASERT schedule anchored at genesis.
    fn asert(&self, genesis: &Header) -> Asert {
        Asert::from_genesis(genesis.timestamp as i64, self.params.genesis_target, self.params.max_target)
    }

    /// Target the block after `parent` must meet.
    pub fn expected_target(&self, parent: &Header) -> Result<Target> {
        let rtxn = self.env.read_txn()?;
        let genesis = self.header_at_in(&rtxn, 0)?.ok_or(ChainError::NoGenesis)?;
        Ok(self.asert(&genesis).next_target(parent.height as u64, parent.timestamp as i64).into())
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
            return Err(ChainError::NotOnTip);
        }
        if !block.body.inputs.is_empty() {
            return Err(ChainError::UnknownInput(block.body.inputs[0]));
        }
        self.check_body(&block.header, &block.body)?;
        let root = self.apply_body(&mut wtxn, &block.body)?;
        if root != block.header.state_root {
            return Err(ChainError::StateRootMismatch { expected: root, got: block.header.state_root });
        }
        self.store(&mut wtxn, block)?;
        wtxn.commit()?;
        Ok(())
    }

    fn check_body(&self, header: &Header, body: &Body) -> Result<()> {
        body.validate()?;
        if body.inputs.len() > self.params.max_inputs {
            return Err(ChainError::TooManyInputs(body.inputs.len()));
        }
        if body.outputs.len() > self.params.max_outputs {
            return Err(ChainError::TooManyOutputs(body.outputs.len()));
        }
        if header.body_commitment != body.commitment() {
            return Err(ChainError::BadBodyCommitment);
        }
        Ok(())
    }

    /// Spends the inputs and appends the outputs; returns the new root.
    fn apply_body(&self, wtxn: &mut RwTxn, body: &Body) -> Result<Digest> {
        for &pos in &body.inputs {
            let commitment = self.utxo.get(wtxn, pos)?;
            if commitment == EMPTY || !self.utxo.spend_at(wtxn, &commitment, pos)? {
                return Err(ChainError::UnknownInput(pos));
            }
        }
        for out in &body.outputs {
            self.utxo.add(wtxn, out)?;
        }
        Ok(self.utxo.root(wtxn)?)
    }

    fn store(&self, wtxn: &mut RwTxn, block: &Block) -> Result<()> {
        let id = digest_bytes(&block.header.hash());
        self.headers.put(wtxn, &id, &block.header.to_bytes())?;
        self.bodies.put(wtxn, &id, &block.body.to_bytes())?;
        self.by_height.put(wtxn, &block.header.height, &id)?;
        self.meta.put(wtxn, META_TIP, &id)?;
        Ok(())
    }

    /// Validates `block` against the tip and `now` (unix seconds) and, if it
    /// passes every rule, commits it as the new tip.
    pub fn apply_block(&self, block: &Block, now: u64) -> Result<()> {
        let header = &block.header;
        let mut wtxn = self.env.write_txn()?;
        let tip = self.tip_in(&wtxn)?.ok_or(ChainError::NoGenesis)?;
        let genesis = self.header_at_in(&wtxn, 0)?.ok_or(ChainError::NoGenesis)?;

        // 1. Linkage.
        if header.prev_hash != tip.hash() {
            return Err(ChainError::NotOnTip);
        }
        let expected_height =
            tip.height.checked_add(1).ok_or(ChainError::BadHeight { expected: u32::MAX, got: header.height })?;
        if header.height != expected_height {
            return Err(ChainError::BadHeight { expected: expected_height, got: header.height });
        }

        // 2. Timestamp.
        let median = self.median_time_past(&wtxn, &tip)?;
        if header.timestamp <= median {
            return Err(ChainError::TimestampTooOld { median, got: header.timestamp });
        }
        let limit = now.saturating_add(self.params.max_future_drift);
        if header.timestamp > limit {
            return Err(ChainError::TimestampTooNew { limit, got: header.timestamp });
        }

        // 3. Proof of work: cheap pre-check first, then the full evaluation.
        let target: Target = self.asert(&genesis).next_target(tip.height as u64, tip.timestamp as i64).into();
        if !header.quick_pow_check(&target) || !header.verify_pow(&self.seed, &target) {
            return Err(ChainError::BadProofOfWork);
        }

        // 4. Body.
        self.check_body(header, &block.body)?;

        // 5-7. State transition and proof.
        let prev_state_root = self.utxo.root(&wtxn)?;
        let first_output_position = self.utxo.next_position(&wtxn)?;
        let new_root = self.apply_body(&mut wtxn, &block.body)?;
        if new_root != header.state_root {
            return Err(ChainError::StateRootMismatch { expected: new_root, got: header.state_root });
        }
        let statement = BlockStatement {
            height: header.height,
            prev_state_root,
            new_state_root: new_root,
            first_output_position,
            subsidy: self.params.subsidy(header.height),
            body: &block.body,
        };
        if !self.verifier.verify(&statement, &block.body.proof) {
            return Err(ChainError::BadProof);
        }

        self.store(&mut wtxn, block)?;
        wtxn.commit()?;
        Ok(())
    }

    /// State root that applying `body` on top of the tip would produce,
    /// without committing. Used to fill a block template.
    pub fn preview_state_root(&self, body: &Body) -> Result<Digest> {
        let mut wtxn = self.env.write_txn()?;
        let root = self.apply_body(&mut wtxn, body)?;
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

    const POW: PowParams = PowParams { log_dataset_items: 8, parents: 32, accesses: 64 };
    const GENESIS_TIME: u64 = 1_700_000_000;

    fn params() -> ChainParams {
        ChainParams {
            pow: POW,
            // Easy: 2^240, about 2^8 hashes per block.
            genesis_target: U256([0, 0, 0, 1 << 48]),
            max_target: ChainParams::MAINNET.max_target,
            max_inputs: 4,
            max_outputs: 4,
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
        let body = Body { inputs: vec![], outputs, proof: vec![] };
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
        let body1 = Body { inputs: vec![0], outputs: vec![Output::new(&b, 60), Output::new(&a, 40)], proof: vec![9] };
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
        let body2 = Body { inputs: vec![1, 2], outputs: vec![Output::new(&b, 200)], proof: vec![] };
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
        let body = Body { inputs: vec![], outputs: vec![Output::new(&a, 7)], proof: vec![] };
        let good = mine(&f, body.clone(), GENESIS_TIME + 600);
        let now = GENESIS_TIME + 700;

        let mut b = good.clone();
        b.header.prev_hash = EMPTY;
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::NotOnTip)));
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
        wrong.outputs.push(Output::new(&a, 8));
        let b = mine_with_root(&f, wrong, GENESIS_TIME + 600, good.header.state_root);
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::StateRootMismatch { .. })));
        // Too many outputs.
        let many = Body { inputs: vec![], outputs: vec![Output::new(&a, 1); 5], proof: vec![] };
        let b = mine(&f, many, GENESIS_TIME + 600);
        assert!(matches!(f.chain.apply_block(&b, now), Err(ChainError::TooManyOutputs(5))));

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
            let body = Body { inputs: vec![], outputs: vec![Output::new(&a, i as u64 + 1)], proof: vec![] };
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
            let body = Body { inputs: vec![], outputs: vec![Output::new(&a, 3)], proof };
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
                Body { inputs: vec![0], outputs: vec![Output::new(&a, 2)], proof: vec![] },
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
}
