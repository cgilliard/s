//! Block format: a proof-of-work header over a body of input positions,
//! outputs and a validity proof.
//!
//! # Header, 172 bytes
//!
//! | field           | bytes | meaning                                        |
//! |-----------------|-------|------------------------------------------------|
//! | prev_hash       | 32    | [`Header::hash`] of the previous block         |
//! | height          | 4     | genesis is 0                                   |
//! | timestamp       | 8     | unix seconds                                   |
//! | body_commitment | 32    | [`Body::commitment`]                           |
//! | state_root      | 32    | UTXO tree root after applying this block       |
//! | mix             | 32    | proof-of-work mix digest                       |
//! | nonce           | 32    | proof-of-work nonce                            |
//!
//! [`Header::pow_hash`] covers the first five fields and seeds the proof of
//! work together with the nonce. [`Header::hash`] covers everything and is
//! the block id. The difficulty target is not stored; it follows from the
//! parent header through [`crate::difficulty::Asert`].
//!
//! # Body
//!
//! 1. Inputs: positions in the state tree of the outputs being spent, five
//!    bytes each (little endian, below 2^40), in transaction order and
//!    without repeats.
//! 2. Outputs: a commitment and a memo, 32 bytes each, in the order they
//!    are appended to the state tree. The memo is opaque to consensus (its
//!    owner's wallet uses it for recovery); the proof binds it to the
//!    transaction that created the output.
//! 3. The validity proof.
//!
//! Keys, amounts, signatures and transaction boundaries are not on chain;
//! the proof attests to them and reveals nothing else about them.
//!
//! The body commitment hashes all three.

use crate::poseidon2::{DIGEST, Fp, digest_from_bytes, digest_to_bytes};
use crate::pow::{self, Digest, ItemSource, Nonce, PowOutput, SeedText, Target, pack_bytes};
use crate::state_tree::CAPACITY;
use crate::transaction::{Commitment, Memo, hash_domain};

pub const HEADER_SIZE: usize = 32 + 4 + 8 + 32 + 32 + 32 + 32;
pub const POSITION_SIZE: usize = 5;
pub const COMMITMENT_SIZE: usize = 4 * DIGEST;
/// Serialized size of a block output: commitment and memo.
pub const BLOCK_OUTPUT_SIZE: usize = 2 * COMMITMENT_SIZE;

/// An output as a block lists it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlockOutput {
    pub commitment: Commitment,
    pub memo: Memo,
}

impl From<Commitment> for BlockOutput {
    /// An output with an empty memo.
    fn from(commitment: Commitment) -> BlockOutput {
        BlockOutput { commitment, memo: [Fp::ZERO; DIGEST] }
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
            mix: r.digest()?,
            nonce: r.take(32)?.try_into().unwrap(),
        })
    }

    /// Hash of the fields under proof of work: everything but mix and nonce.
    pub fn pow_hash(&self) -> Digest {
        let mut v = Vec::with_capacity(3 * DIGEST + 4);
        v.extend_from_slice(&self.prev_hash);
        v.push(Fp::from_u32(self.height));
        v.push(Fp::new((self.timestamp & MASK30) as u32));
        v.push(Fp::new(((self.timestamp >> 30) & MASK30) as u32));
        v.push(Fp::new((self.timestamp >> 60) as u32));
        v.extend_from_slice(&self.body_commitment);
        v.extend_from_slice(&self.state_root);
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
    pub fn verify_pow(&self, seed: &SeedText, target: &Target) -> bool {
        self.quick_pow_check(target) && pow::verify(seed, &self.pow_hash(), &self.nonce, &self.mix, target)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyError {
    /// The same position is spent twice.
    DuplicateInput(u64),
    /// An input position is not below the tree capacity.
    InputOutOfRange(u64),
    Malformed,
}

impl core::fmt::Display for BodyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BodyError::DuplicateInput(p) => write!(f, "input position {p} appears twice"),
            BodyError::InputOutOfRange(p) => write!(f, "input position {p} exceeds the state tree"),
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
    /// Validity proof.
    pub proof: Vec<u8>,
}

impl Body {
    /// Checks that inputs are in range and distinct.
    pub fn validate(&self) -> Result<(), BodyError> {
        let mut seen = std::collections::HashSet::with_capacity(self.inputs.len());
        for &p in &self.inputs {
            if p >= CAPACITY {
                return Err(BodyError::InputOutOfRange(p));
            }
            if !seen.insert(p) {
                return Err(BodyError::DuplicateInput(p));
            }
        }
        Ok(())
    }

    /// Hash of the proof bytes, length bound.
    pub fn proof_hash(&self) -> Digest {
        let mut v = Vec::with_capacity(1 + self.proof.len().div_ceil(3));
        v.push(Fp::from_u64(self.proof.len() as u64));
        v.extend(pack_bytes(&self.proof));
        hash_domain(DOM_PROOF, &v)
    }

    /// Commitment to inputs, outputs and proof.
    pub fn commitment(&self) -> Digest {
        let mut v = Vec::with_capacity(2 + 2 * self.inputs.len() + 2 * DIGEST * self.outputs.len() + DIGEST);
        v.push(Fp::from_u64(self.inputs.len() as u64));
        for &p in &self.inputs {
            v.push(Fp::new((p & MASK30) as u32));
            v.push(Fp::new((p >> 30) as u32));
        }
        v.push(Fp::from_u64(self.outputs.len() as u64));
        for o in &self.outputs {
            v.extend_from_slice(&o.commitment);
            v.extend_from_slice(&o.memo);
        }
        v.extend_from_slice(&self.proof_hash());
        hash_domain(DOM_BODY, &v)
    }

    pub fn size(&self) -> usize {
        12 + self.inputs.len() * POSITION_SIZE + self.outputs.len() * BLOCK_OUTPUT_SIZE + self.proof.len()
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
            out.extend_from_slice(&digest_to_bytes(&o.memo));
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
        let n_in = r.u32().ok_or(BodyError::Malformed)? as usize;
        let mut inputs = Vec::with_capacity(n_in.min(bytes.len() / POSITION_SIZE));
        for _ in 0..n_in {
            let b = r.take(POSITION_SIZE).ok_or(BodyError::Malformed)?;
            let mut buf = [0u8; 8];
            buf[..POSITION_SIZE].copy_from_slice(b);
            inputs.push(u64::from_le_bytes(buf));
        }
        let n_out = r.u32().ok_or(BodyError::Malformed)? as usize;
        let mut outputs = Vec::with_capacity(n_out.min(bytes.len() / BLOCK_OUTPUT_SIZE));
        for _ in 0..n_out {
            let c = r.take(COMMITMENT_SIZE).ok_or(BodyError::Malformed)?;
            let m = r.take(COMMITMENT_SIZE).ok_or(BodyError::Malformed)?;
            outputs.push(BlockOutput {
                commitment: digest_from_bytes(c).ok_or(BodyError::Malformed)?,
                memo: digest_from_bytes(m).ok_or(BodyError::Malformed)?,
            });
        }
        let n_proof = r.u32().ok_or(BodyError::Malformed)? as usize;
        let proof = r.take(n_proof).ok_or(BodyError::Malformed)?.to_vec();
        let body = Body { inputs, outputs, proof };
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

    fn digest(&mut self) -> Option<Digest> {
        digest_from_bytes(self.take(32)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::{Dataset, PowParams, nonce_from_u64};
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
        assert_eq!(bytes.len(), 172);
        assert_eq!(HEADER_SIZE, 172);
        assert_eq!(Header::from_bytes(&bytes), Some(h));
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

    #[test]
    fn body_canonical_form() {
        let outs = outputs();
        let ok = Body { inputs: vec![5, 1, 0, CAPACITY - 1], outputs: outs.clone(), proof: vec![1, 2, 3] };
        assert_eq!(ok.validate(), Ok(()));
        let dup = Body { inputs: vec![1, 7, 1], ..ok.clone() };
        assert_eq!(dup.validate(), Err(BodyError::DuplicateInput(1)));
        let big = Body { inputs: vec![CAPACITY], ..ok.clone() };
        assert_eq!(big.validate(), Err(BodyError::InputOutOfRange(CAPACITY)));
        assert_eq!(Body::default().validate(), Ok(()));

        let bytes = ok.to_bytes();
        assert_eq!(bytes.len(), ok.size());
        assert_eq!(bytes.len(), 12 + 4 * 5 + 2 * 64 + 3);
        assert_eq!(Body::from_bytes(&bytes), Ok(ok.clone()));
        assert_eq!(Body::from_bytes(&dup.to_bytes()), Err(BodyError::DuplicateInput(1)));
        assert_eq!(Body::from_bytes(&bytes[..bytes.len() - 1]), Err(BodyError::Malformed));
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(Body::from_bytes(&extra), Err(BodyError::Malformed));
        // Five-byte positions survive the top bits.
        let top = Body { inputs: vec![CAPACITY - 1], outputs: vec![], proof: vec![] };
        assert_eq!(Body::from_bytes(&top.to_bytes()).unwrap().inputs, vec![CAPACITY - 1]);
    }

    #[test]
    fn body_commitment_covers_everything() {
        let outs = outputs();
        let base = Body { inputs: vec![3, 9], outputs: outs.clone(), proof: vec![7; 100] };
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
        let body = Body { inputs: vec![1, 2], outputs: outputs(), proof: vec![0xab; 10] };
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
