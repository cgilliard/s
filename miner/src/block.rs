//! Block format: a proof-of-work header over a body of input positions,
//! outputs and a validity proof.
//!
//! # Header, 204 bytes
//!
//! | field           | bytes | meaning                                        |
//! |-----------------|-------|------------------------------------------------|
//! | prev_hash       | 32    | [`Header::hash`] of the previous block         |
//! | height          | 4     | genesis is 0                                   |
//! | timestamp       | 8     | unix seconds                                   |
//! | body_commitment | 32    | [`Body::commitment`]                           |
//! | state_root      | 32    | UTXO tree root after applying this block       |
//! | aux             | 32    | the miner's own bytes, any value; zero here    |
//! | mix             | 32    | proof-of-work mix digest                       |
//! | nonce           | 32    | proof-of-work nonce                            |
//!
//! [`Header::pow_hash`] covers the first six fields and seeds the proof of
//! work together with the nonce. [`Header::hash`] covers everything and is
//! the block id. The difficulty target is not stored; it follows from the
//! parent header through [`crate::difficulty::Asert`].
//!
//! # Body
//!
//! 1. Inputs: positions in the state tree of the outputs being spent, five
//!    bytes each (little endian, below 2^39), in transaction order and
//!    without repeats.
//! 2. Outputs: a commitment (32 bytes), a memo (20) and an amount (8,
//!    public: `docs/AMOUNTS.md`), in the order they are appended to the
//!    state tree. The memo is opaque to consensus (its owner's wallet uses
//!    it for recovery); the proof binds it, and the amount, to the
//!    transaction that created the output, and the amount to the one the
//!    output's commitment hides.
//! 3. Name operations, in order (see [`crate::names::BlockNameOp`]), at
//!    most the cap of each kind. A commit occupies the counter position
//!    after the block's outputs, in operation order; a reveal names the
//!    position of the commit it spends.
//! 4. Swept commits: positions, five bytes each. The positions spent by
//!    inputs, reveals and sweeps are all distinct; at most [`MAX_SWEEPS`]
//!    sweeps.
//! 5. The validity proof.
//!
//! Keys, input amounts, signatures, salts and transaction boundaries are
//! not on chain; the proof attests to them. Output amounts are, so every
//! node checks the supply outside the proof.
//!
//! The body commitment hashes all five.

use crate::names::{BlockNameOp, MAX_SWEEPS, OpKind, count_ops};
use crate::poseidon2::{DIGEST, Fp, digest_from_bytes, digest_to_bytes};
use crate::pow::{self, Digest, ItemSource, Nonce, PowOutput, Target, pack_bytes};
use crate::state_tree::OUTPUT_CAPACITY;
use crate::transaction::{Commitment, Memo, hash_domain};

pub const HEADER_SIZE: usize = 32 + 4 + 8 + 32 + 32 + 32 + 32 + 32;
pub const POSITION_SIZE: usize = 5;
pub const COMMITMENT_SIZE: usize = 4 * DIGEST;
/// Serialized size of a block output: commitment, memo and amount.
pub const BLOCK_OUTPUT_SIZE: usize = COMMITMENT_SIZE + crate::transaction::MEMO_BYTES + 8;

/// An output as a block lists it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlockOutput {
    pub commitment: Commitment,
    pub memo: Memo,
    /// Public (`docs/AMOUNTS.md`): every node sums these to check the
    /// supply, and the proof binds it to the amount the commitment hides.
    pub amount: u64,
}

impl BlockOutput {
    /// Its memo slot: the memo and the amount, as leaves and sponges take it.
    pub fn slot(&self) -> Digest {
        crate::transaction::memo_slot(&self.memo, self.amount)
    }
}

impl From<Commitment> for BlockOutput {
    /// An output with an empty memo and amount zero.
    fn from(commitment: Commitment) -> BlockOutput {
        BlockOutput { commitment, memo: crate::transaction::EMPTY_MEMO, amount: 0 }
    }
}

const DOM_POW_HASH: u32 = 0x10;
const DOM_BLOCK_ID: u32 = 0x11;
const DOM_BODY: u32 = 0x12;
const DOM_PROOF: u32 = 0x13;
const MASK30: u64 = (1 << 30) - 1;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Header {
    pub prev_hash: Digest,
    pub height: u32,
    pub timestamp: u64,
    pub body_commitment: Digest,
    pub state_root: Digest,
    /// Auxiliary bytes for the miner's own use, any value: under the
    /// proof of work, unread by consensus.
    pub aux: [u8; 32],
    pub mix: Digest,
    pub nonce: Nonce,
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        let mut w = Writer(&mut out, 0);
        w.put(&digest_to_bytes(&self.prev_hash));
        w.put(&self.height.to_le_bytes());
        w.put(&self.timestamp.to_le_bytes());
        w.put(&digest_to_bytes(&self.body_commitment));
        w.put(&digest_to_bytes(&self.state_root));
        w.put(&self.aux);
        w.put(&digest_to_bytes(&self.mix));
        w.put(&self.nonce);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Header> {
        if bytes.len() != HEADER_SIZE {
            return None;
        }
        let mut r = Reader(bytes);
        Some(Header {
            prev_hash: r.digest()?,
            height: u32::from_le_bytes(r.take(4)?.try_into().unwrap()),
            timestamp: u64::from_le_bytes(r.take(8)?.try_into().unwrap()),
            body_commitment: r.digest()?,
            state_root: r.digest()?,
            aux: r.take(32)?.try_into().unwrap(),
            mix: r.digest()?,
            nonce: r.take(32)?.try_into().unwrap(),
        })
    }

    /// Hash of the fields under proof of work: everything but mix and nonce.
    pub fn pow_hash(&self) -> Digest {
        let mut v = Vec::with_capacity(3 * DIGEST + 15);
        v.extend_from_slice(&self.prev_hash);
        v.push(Fp::from_u32(self.height));
        v.push(Fp::new((self.timestamp & MASK30) as u32));
        v.push(Fp::new(((self.timestamp >> 30) & MASK30) as u32));
        v.push(Fp::new((self.timestamp >> 60) as u32));
        v.extend_from_slice(&self.body_commitment);
        v.extend_from_slice(&self.state_root);
        v.extend(pack_bytes(&self.aux));
        hash_domain(DOM_POW_HASH, &v)
    }

    /// Block id: hash of the whole header including the proof of work.
    pub fn hash(&self) -> Digest {
        let mut v = Vec::with_capacity(2 * DIGEST + 11);
        v.extend_from_slice(&self.pow_hash());
        v.extend_from_slice(&self.mix);
        v.extend(pack_bytes(&self.nonce));
        hash_domain(DOM_BLOCK_ID, &v)
    }

    /// Evaluates the proof of work for this header's nonce.
    pub fn pow_output<S: ItemSource>(&self, source: &S) -> PowOutput {
        pow::hashimoto(source, &self.pow_hash(), &self.nonce)
    }

    /// Cheap pre-check from the claimed mix: two permutations. A header that
    /// fails this is invalid; one that passes still needs [`Header::verify_pow`].
    pub fn quick_pow_check(&self, target: &Target) -> bool {
        target.is_met_by(&pow::result_from_mix(&self.pow_hash(), &self.nonce, &self.mix))
    }

    /// Full proof-of-work check from the seed text: the mix must be the true
    /// mix and the result must meet the target.
    pub fn verify_pow<S: pow::ItemSource>(&self, source: &S, target: &Target) -> bool {
        self.quick_pow_check(target) && pow::verify(source, &self.pow_hash(), &self.nonce, &self.mix, target)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyError {
    /// The same position is spent twice.
    DuplicateInput(u64),
    /// An input position is not below the tree capacity.
    InputOutOfRange(u64),
    /// More operations of a kind than its cap.
    TooMany(OpKind),
    /// A reveal or update with a malformed name.
    BadName,
    /// A position spent by a reveal or a sweep is repeated or also spent.
    DuplicateSpend(u64),
    /// A position spent by a reveal or a sweep is not below the tree capacity.
    SpendOutOfRange(u64),
    Malformed,
}

impl core::fmt::Display for BodyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BodyError::DuplicateInput(p) => write!(f, "input position {p} appears twice"),
            BodyError::InputOutOfRange(p) => write!(f, "input position {p} exceeds the state tree"),
            BodyError::TooMany(k) => write!(f, "more than {} {} operations", k.cap(), k.name()),
            BodyError::BadName => f.write_str("a name operation has a malformed name"),
            BodyError::DuplicateSpend(p) => write!(f, "position {p} is spent twice"),
            BodyError::SpendOutOfRange(p) => write!(f, "spent position {p} exceeds the state tree"),
            BodyError::Malformed => f.write_str("malformed block body"),
        }
    }
}

impl std::error::Error for BodyError {}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Body {
    /// State tree positions being spent, in transaction order, no repeats.
    pub inputs: Vec<u64>,
    /// The new outputs, in tree order.
    pub outputs: Vec<BlockOutput>,
    /// Name operations, in order.
    pub ops: Vec<BlockNameOp>,
    /// Positions of the commits swept, in order.
    pub sweeps: Vec<u64>,
    /// Validity proof.
    pub proof: Vec<u8>,
}

impl Body {
    /// Checks that inputs and sweeps are in range and distinct, names well
    /// formed and operation counts within the caps.
    pub fn validate(&self) -> Result<(), BodyError> {
        let mut seen = std::collections::HashSet::with_capacity(self.inputs.len() + self.sweeps.len());
        for &p in &self.inputs {
            if p >= OUTPUT_CAPACITY {
                return Err(BodyError::InputOutOfRange(p));
            }
            if !seen.insert(p) {
                return Err(BodyError::DuplicateInput(p));
            }
        }
        for p in self.ops.iter().filter_map(BlockNameOp::spends).chain(self.sweeps.iter().copied()) {
            if p >= OUTPUT_CAPACITY {
                return Err(BodyError::SpendOutOfRange(p));
            }
            if !seen.insert(p) {
                return Err(BodyError::DuplicateSpend(p));
            }
        }
        let kinds = self.ops.iter().map(BlockNameOp::kind).chain(self.sweeps.iter().map(|_| OpKind::Sweep));
        count_ops(kinds).map_err(BodyError::TooMany)?;
        if !self.ops.iter().all(BlockNameOp::is_well_formed) {
            return Err(BodyError::BadName);
        }
        Ok(())
    }

    /// The digests of the name operations, in order. Panics on a malformed
    /// name; [`validate`](Body::validate) first.
    pub fn op_digests(&self) -> Vec<Digest> {
        self.ops.iter().map(|op| op.digest().expect("validated body")).collect()
    }

    /// The counter positions the commits take: after the outputs, in order.
    pub fn commit_positions(&self, first_output: u64) -> Vec<u64> {
        let first = first_output + self.outputs.len() as u64;
        (0..self.commits() as u64).map(|i| first + i).collect()
    }

    /// How many commits the block makes.
    pub fn commits(&self) -> usize {
        self.ops.iter().filter(|op| op.kind() == OpKind::Commit).count()
    }

    /// Every position the block spends: inputs, then the commits its
    /// reveals and sweeps consume.
    pub fn spent_positions(&self) -> impl Iterator<Item = u64> + '_ {
        self.inputs
            .iter()
            .copied()
            .chain(self.ops.iter().filter_map(BlockNameOp::spends))
            .chain(self.sweeps.iter().copied())
    }

    /// Serialized size of the name section's items (operations and swept
    /// positions), without the counts.
    pub fn names_size(&self) -> usize {
        self.ops.iter().map(BlockNameOp::size).sum::<usize>() + self.sweeps.len() * POSITION_SIZE
    }

    /// Hash of the proof bytes, length bound.
    pub fn proof_hash(&self) -> Digest {
        let mut v = Vec::with_capacity(1 + self.proof.len().div_ceil(3));
        v.push(Fp::from_u64(self.proof.len() as u64));
        v.extend(pack_bytes(&self.proof));
        hash_domain(DOM_PROOF, &v)
    }

    /// Commitment to inputs, outputs, name operations (by digest, plus the
    /// positions reveals spend), sweeps and proof.
    pub fn commitment(&self) -> Digest {
        let positions = |v: &mut Vec<Fp>, ps: &[u64]| {
            v.push(Fp::from_u64(ps.len() as u64));
            for &p in ps {
                v.push(Fp::new((p & MASK30) as u32));
                v.push(Fp::new((p >> 30) as u32));
            }
        };
        let mut v = Vec::with_capacity(
            4 + 2 * (self.inputs.len() + self.sweeps.len()) + DIGEST * (2 * self.outputs.len() + self.ops.len() + 1),
        );
        positions(&mut v, &self.inputs);
        v.push(Fp::from_u64(self.outputs.len() as u64));
        for o in &self.outputs {
            v.extend_from_slice(&o.commitment);
            v.extend_from_slice(&o.slot());
        }
        v.push(Fp::from_u64(self.ops.len() as u64));
        for op in &self.ops {
            v.extend_from_slice(&op.digest().unwrap_or([Fp::ZERO; DIGEST]));
        }
        // The digests leave out the positions reveals spend.
        let spends: Vec<u64> = self.ops.iter().filter_map(BlockNameOp::spends).collect();
        positions(&mut v, &spends);
        positions(&mut v, &self.sweeps);
        v.extend_from_slice(&self.proof_hash());
        hash_domain(DOM_BODY, &v)
    }

    pub fn size(&self) -> usize {
        Self::size_of(self.inputs.len(), self.outputs.len(), self.names_size(), self.proof.len())
    }

    /// The serialized size of a body with these counts, a name section of
    /// `names` bytes ([`names_size`](Body::names_size)) and a proof of
    /// `proof` bytes: what a block builder checks against the size limit.
    pub fn size_of(inputs: usize, outputs: usize, names: usize, proof: usize) -> usize {
        20 + inputs * POSITION_SIZE + outputs * BLOCK_OUTPUT_SIZE + names + proof
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for &p in &self.inputs {
            out.extend_from_slice(&p.to_le_bytes()[..POSITION_SIZE]);
        }
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            out.extend_from_slice(&digest_to_bytes(&o.commitment));
            out.extend_from_slice(&crate::transaction::memo_to_bytes(&o.memo));
            out.extend_from_slice(&o.amount.to_le_bytes());
        }
        out.extend_from_slice(&(self.ops.len() as u32).to_le_bytes());
        for op in &self.ops {
            out.extend_from_slice(&op.to_bytes());
        }
        out.extend_from_slice(&(self.sweeps.len() as u32).to_le_bytes());
        for &p in &self.sweeps {
            out.extend_from_slice(&p.to_le_bytes()[..POSITION_SIZE]);
        }
        out.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.proof);
        out
    }

    /// Parses and validates a body; the whole slice must be consumed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Body, BodyError> {
        let (body, rest) = Self::parse(bytes)?;
        if !rest.is_empty() {
            return Err(BodyError::Malformed);
        }
        Ok(body)
    }

    fn parse(bytes: &[u8]) -> Result<(Body, &[u8]), BodyError> {
        let mut r = Reader(bytes);
        let inputs = r.positions().ok_or(BodyError::Malformed)?;
        let n_out = r.u32().ok_or(BodyError::Malformed)? as usize;
        let mut outputs = Vec::with_capacity(n_out.min(bytes.len() / BLOCK_OUTPUT_SIZE));
        for _ in 0..n_out {
            let c = r.take(COMMITMENT_SIZE).ok_or(BodyError::Malformed)?;
            let m = r.take(crate::transaction::MEMO_BYTES).ok_or(BodyError::Malformed)?;
            let a = r.u64().ok_or(BodyError::Malformed)?;
            outputs.push(BlockOutput {
                commitment: digest_from_bytes(c).ok_or(BodyError::Malformed)?,
                memo: crate::transaction::memo_from_bytes(m).ok_or(BodyError::Malformed)?,
                amount: a,
            });
        }
        let n_ops = r.u32().ok_or(BodyError::Malformed)? as usize;
        let mut ops = Vec::with_capacity(n_ops.min(MAX_SWEEPS * 2));
        for _ in 0..n_ops {
            let (op, rest) = BlockNameOp::parse(r.0).ok_or(BodyError::Malformed)?;
            ops.push(op);
            r.0 = rest;
        }
        let sweeps = r.positions().ok_or(BodyError::Malformed)?;
        let n_proof = r.u32().ok_or(BodyError::Malformed)? as usize;
        let proof = r.take(n_proof).ok_or(BodyError::Malformed)?.to_vec();
        let body = Body { inputs, outputs, ops, sweeps, proof };
        body.validate()?;
        Ok((body, r.0))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    pub header: Header,
    pub body: Body,
}

impl Block {
    /// Whether the header commits to this body.
    pub fn body_commitment_matches(&self) -> bool {
        self.header.body_commitment == self.body.commitment()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.body.size());
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.body.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Block, BodyError> {
        if bytes.len() < HEADER_SIZE {
            return Err(BodyError::Malformed);
        }
        let header = Header::from_bytes(&bytes[..HEADER_SIZE]).ok_or(BodyError::Malformed)?;
        let body = Body::from_bytes(&bytes[HEADER_SIZE..])?;
        Ok(Block { header, body })
    }
}

struct Writer<'a>(&'a mut [u8], usize);

impl Writer<'_> {
    fn put(&mut self, b: &[u8]) {
        self.0[self.1..self.1 + b.len()].copy_from_slice(b);
        self.1 += b.len();
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn digest(&mut self) -> Option<Digest> {
        digest_from_bytes(self.take(32)?)
    }

    /// A count and that many five-byte positions.
    fn positions(&mut self) -> Option<Vec<u64>> {
        let n = self.u32()? as usize;
        let mut out = Vec::with_capacity(n.min(self.0.len() / POSITION_SIZE));
        for _ in 0..n {
            let mut buf = [0u8; 8];
            buf[..POSITION_SIZE].copy_from_slice(self.take(POSITION_SIZE)?);
            out.push(u64::from_le_bytes(buf));
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::{Dataset, PowParams, SeedText, nonce_from_u64};
    use crate::transaction::{Key, Output};

    fn d(n: u32) -> Digest {
        core::array::from_fn(|i| Fp::new(n + i as u32))
    }

    fn header() -> Header {
        Header {
            prev_hash: d(1),
            height: 7,
            timestamp: 1_700_000_000,
            body_commitment: d(100),
            state_root: d(200),
            aux: [9u8; 32],
            mix: d(300),
            nonce: nonce_from_u64(42),
        }
    }

    fn outputs() -> Vec<BlockOutput> {
        let mut seed = [0u8; 32];
        seed[0] = 9;
        let pk = Key::generate(&seed).public_key();
        let memo = core::array::from_fn(|i| Fp::new(1000 + i as u32));
        let with_memo = Output::with_memo(&crate::transaction::pubkey_hash(&pk), u64::MAX, memo);
        vec![Output::new(&pk, 5).block_output(), with_memo.block_output()]
    }

    #[test]
    fn header_roundtrip_and_hashes() {
        let h = header();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), 204);
        assert_eq!(HEADER_SIZE, 204);
        assert_eq!(Header::from_bytes(&bytes), Some(h));
        // The aux bytes are under the proof of work.
        let other = Header { aux: [10u8; 32], ..h };
        assert_ne!(other.pow_hash(), h.pow_hash());
        assert_ne!(other.hash(), h.hash());
        assert!(Header::from_bytes(&bytes[1..]).is_none());
        let mut bad = bytes;
        bad[..4].copy_from_slice(&0x7800_0001u32.to_le_bytes());
        assert!(Header::from_bytes(&bad).is_none());

        // pow_hash ignores mix and nonce; hash does not.
        let mut h2 = h;
        h2.mix = d(999);
        h2.nonce = nonce_from_u64(1);
        assert_eq!(h2.pow_hash(), h.pow_hash());
        assert_ne!(h2.hash(), h.hash());
        for f in [
            |x: &mut Header| x.prev_hash = d(2),
            |x: &mut Header| x.height += 1,
            |x: &mut Header| x.timestamp += 1,
            |x: &mut Header| x.timestamp += 1 << 40,
            |x: &mut Header| x.body_commitment = d(2),
            |x: &mut Header| x.state_root = d(2),
        ] {
            let mut x = h;
            f(&mut x);
            assert_ne!(x.pow_hash(), h.pow_hash());
        }
    }

    fn record(name: &str, n: u32) -> crate::names::Record {
        crate::names::Record::new(name.as_bytes(), d(n), d(n + 1), d(n + 2)).unwrap()
    }

    fn ops() -> Vec<BlockNameOp> {
        vec![
            BlockNameOp::Commit { commit: d(10), memo: crate::transaction::memo5(d(11)) },
            BlockNameOp::Reveal { record: record("alice", 20), commit: 12 },
            BlockNameOp::Update(record("bob_99", 30)),
            BlockNameOp::Commit { commit: d(12), memo: crate::transaction::memo5(d(13)) },
        ]
    }

    #[test]
    fn body_canonical_form() {
        let outs = outputs();
        let ok = Body {
            inputs: vec![5, 1, 0, OUTPUT_CAPACITY - 1],
            outputs: outs.clone(),
            proof: vec![1, 2, 3],
            ..Default::default()
        };
        assert_eq!(ok.validate(), Ok(()));
        let dup = Body { inputs: vec![1, 7, 1], ..ok.clone() };
        assert_eq!(dup.validate(), Err(BodyError::DuplicateInput(1)));
        let big = Body { inputs: vec![OUTPUT_CAPACITY], ..ok.clone() };
        assert_eq!(big.validate(), Err(BodyError::InputOutOfRange(OUTPUT_CAPACITY)));
        assert_eq!(Body::default().validate(), Ok(()));

        let bytes = ok.to_bytes();
        assert_eq!(bytes.len(), ok.size());
        assert_eq!(bytes.len(), 20 + 4 * 5 + 2 * 60 + 3);
        assert_eq!(Body::from_bytes(&bytes), Ok(ok.clone()));
        assert_eq!(Body::from_bytes(&dup.to_bytes()), Err(BodyError::DuplicateInput(1)));
        assert_eq!(Body::from_bytes(&bytes[..bytes.len() - 1]), Err(BodyError::Malformed));
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(Body::from_bytes(&extra), Err(BodyError::Malformed));
        // Five-byte positions survive the top bits.
        let top = Body { inputs: vec![OUTPUT_CAPACITY - 1], sweeps: vec![OUTPUT_CAPACITY - 2], ..Default::default() };
        let back = Body::from_bytes(&top.to_bytes()).unwrap();
        assert_eq!((back.inputs, back.sweeps), (vec![OUTPUT_CAPACITY - 1], vec![OUTPUT_CAPACITY - 2]));
    }

    #[test]
    fn name_section() {
        let ok = Body { inputs: vec![3], outputs: outputs(), ops: ops(), sweeps: vec![7, 8], proof: vec![1] };
        assert_eq!(ok.validate(), Ok(()));
        let bytes = ok.to_bytes();
        assert_eq!(bytes.len(), ok.size());
        assert_eq!(ok.names_size(), 2 * 53 + (98 + 5 + 5) + (98 + 6) + 2 * 5);
        assert_eq!(bytes.len(), 20 + 5 + 2 * 60 + ok.names_size() + 1);
        assert_eq!(Body::from_bytes(&bytes), Ok(ok.clone()));
        assert_eq!(Body::from_bytes(&bytes[..bytes.len() - 1]), Err(BodyError::Malformed));
        assert_eq!(ok.op_digests().len(), 4);
        assert_eq!(ok.op_digests(), ops().iter().map(|o| o.digest().unwrap()).collect::<Vec<_>>());
        // Commits take the positions after the outputs, in order.
        assert_eq!(ok.commit_positions(100), vec![102, 103]);
        assert_eq!(Body::default().commit_positions(5), Vec::<u64>::new());

        // The commitment covers every part of the section.
        let c = ok.commitment();
        let mut b = ok.clone();
        b.ops.swap(0, 3);
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        b.ops[1] = BlockNameOp::Update(record("alice", 20));
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        if let BlockNameOp::Reveal { commit, .. } = &mut b.ops[1] {
            *commit = 9;
        }
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        b.ops.pop();
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        b.sweeps[0] = 9;
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        b.sweeps.pop();
        assert_ne!(b.commitment(), c);
        let mut b = ok.clone();
        if let BlockNameOp::Reveal { record, .. } = &mut b.ops[1] {
            record.memo = d(0);
        }
        assert_ne!(b.commitment(), c);

        // Validation: sweeps distinct and apart from inputs, in range; caps; names.
        let bad = Body { sweeps: vec![1, 1], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::DuplicateSpend(1)));
        let bad = Body { inputs: vec![4], sweeps: vec![4], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::DuplicateSpend(4)));
        let bad = Body { ops: ops(), sweeps: vec![12], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::DuplicateSpend(12)));
        let bad = Body { sweeps: vec![OUTPUT_CAPACITY], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::SpendOutOfRange(OUTPUT_CAPACITY)));
        assert_eq!(ok.spent_positions().collect::<Vec<_>>(), vec![3, 12, 7, 8]);
        let bad = Body { sweeps: (0..MAX_SWEEPS as u64 + 1).collect(), ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::TooMany(OpKind::Sweep)));
        assert_eq!(Body::from_bytes(&bad.to_bytes()), Err(BodyError::TooMany(OpKind::Sweep)));
        let full = Body { sweeps: (0..MAX_SWEEPS as u64).collect(), ..Default::default() };
        assert_eq!(full.validate(), Ok(()));
        let reveal = |i: u64| BlockNameOp::Reveal { record: record("a", 1), commit: 100 + i };
        let bad = Body { ops: (0..crate::names::MAX_REVEALS as u64 + 1).map(reveal).collect(), ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::TooMany(OpKind::Reveal)));
        let bad = Body {
            ops: vec![BlockNameOp::Update(record("a", 1)); crate::names::MAX_UPDATES + 1],
            ..Default::default()
        };
        assert_eq!(bad.validate(), Err(BodyError::TooMany(OpKind::Update)));
        let bad = Body { ops: vec![ops()[0].clone(); crate::names::MAX_COMMITS + 1], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::TooMany(OpKind::Commit)));
        let at_caps = Body {
            ops: [
                (0..crate::names::MAX_REVEALS as u64).map(reveal).collect(),
                vec![BlockNameOp::Update(record("a", 1)); crate::names::MAX_UPDATES],
                vec![ops()[0].clone(); crate::names::MAX_COMMITS],
            ]
            .concat(),
            ..Default::default()
        };
        assert_eq!(at_caps.validate(), Ok(()));
        let malformed = crate::names::Record { name: b"A".to_vec(), owner: d(1), value: d(2), memo: d(3) };
        let bad = Body { ops: vec![BlockNameOp::Reveal { record: malformed, commit: 0 }], ..Default::default() };
        assert_eq!(bad.validate(), Err(BodyError::BadName));
        assert_eq!(Body::from_bytes(&bad.to_bytes()), Err(BodyError::Malformed));
    }

    #[test]
    fn body_commitment_covers_everything() {
        let outs = outputs();
        let base = Body { inputs: vec![3, 9], outputs: outs.clone(), proof: vec![7; 100], ..Default::default() };
        let c = base.commitment();
        assert_eq!(c, base.clone().commitment());
        let mut b = base.clone();
        b.inputs[0] = 4;
        assert_ne!(b.commitment(), c);
        let mut b = base.clone();
        b.inputs.push(10);
        assert_ne!(b.commitment(), c);
        let mut b = base.clone();
        b.outputs[0].commitment[0] += Fp::ONE;
        assert_ne!(b.commitment(), c);
        let mut b = base.clone();
        b.outputs.swap(0, 1);
        assert_ne!(b.commitment(), c);
        let mut b = base.clone();
        b.proof[50] ^= 1;
        assert_ne!(b.commitment(), c);
        let mut b = base.clone();
        b.proof.push(0);
        assert_ne!(b.commitment(), c);
        assert_ne!(Body::default().commitment(), [Fp::ZERO; DIGEST]);
    }

    #[test]
    fn block_roundtrip() {
        let body = Body { inputs: vec![1, 2], outputs: outputs(), ops: ops(), sweeps: vec![6], proof: vec![0xab; 10] };
        let mut h = header();
        h.body_commitment = body.commitment();
        let block = Block { header: h, body };
        assert!(block.body_commitment_matches());
        let bytes = block.to_bytes();
        assert_eq!(Block::from_bytes(&bytes), Ok(block.clone()));
        assert_eq!(Block::from_bytes(&bytes[..100]), Err(BodyError::Malformed));
        let mut other = block.clone();
        other.body.proof[0] ^= 1;
        assert!(!other.body_commitment_matches());
    }

    #[test]
    fn header_proof_of_work() {
        let params = PowParams { log_dataset_items: 8, parents: 64, accesses: 64 };
        let text: Vec<u8> = (0..20_000u32).map(|i| (i * 31 % 253) as u8).collect();
        let seed = SeedText::from_bytes(params, text);
        let dataset = Dataset::generate(&seed);
        let target = Target::from_leading_zero_bits(5);
        let mut h = header();
        let (nonce, out) = pow::mine(&dataset, &h.pow_hash(), &target, (0..5000).map(nonce_from_u64)).unwrap();
        h.nonce = nonce;
        h.mix = out.mix;
        assert_eq!(h.pow_output(&dataset), out);
        assert!(h.quick_pow_check(&target));
        assert!(h.verify_pow(&seed, &target));
        // A forged mix that passes the quick check still fails the full check.
        let mut forged = h;
        forged.mix = d(1);
        let mut n = 0u64;
        while !forged.quick_pow_check(&target) {
            n += 1;
            forged.nonce = nonce_from_u64(1_000_000 + n);
        }
        assert!(!forged.verify_pow(&seed, &target));
        let mut harder = h;
        harder.height += 1;
        assert!(!harder.verify_pow(&seed, &target) || harder.pow_output(&dataset).mix != h.mix);
    }
}
