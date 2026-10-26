//! Block aggregation: one proof per block, built as a tree.
//!
//! Segment proofs (see [`crate::block_proof`]) are verified by node
//! programs for [`crate::vm_air`]. A node verifies up to `fan_in` children,
//! each either a segment proof or the machine proof of another node, checks
//! that the children chain, and outputs a digest of the combined span
//! record: the same 92 values a segment exports (state roots, list sponges
//! and output positions in and out, amount limb sums). The root node
//! additionally binds the span to the block statement: the chain starts at
//! the block's previous state, ends at the body's lists and new state, and
//! the amounts balance against the subsidy, so its output digest is the
//! statement digest.
//!
//! The tree shape is a function of the segment count and
//! [`AggregatorParams`] alone, and every node program embeds its children's
//! program digests, so a node knows the root digest to expect for each
//! segment count without seeing a proof ([`plan`]).
//!
//! Encoding of a block proof: `u32` segment count, then the root's machine
//! proof.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::block_air::{
    BlockAir, LIMBS, NUM_PUBLIC as SEGMENT_PUBLIC, PUB_ISP_IN, PUB_ISP_OUT, PUB_OSP_IN, PUB_OSP_OUT, PUB_POS_IN,
    PUB_POS_OUT, PUB_ROOT_IN, PUB_ROOT_OUT, PUB_SUM_IN, PUB_SUM_OUT, ROWS_PER_OUTPUT, SegmentPublic, SegmentWitness,
    initial_inputs_state, initial_outputs_state, inputs_state, limbs16, outputs_state,
};
use crate::block_proof::{DOM_SEGMENT_PROOF, SegmentProof, prove_segment_padded};
use crate::chain::{BlockStatement, ProofVerifier};
use crate::challenger::Challenger;
use crate::codec::{Reader, Writer};
use crate::ext::Fp4;
use crate::merkle::Digest;
use crate::poseidon2::{DIGEST, Fp, P, WIDTH};
use crate::recursion::{Compiler, dummy_proof};
use crate::stark::{self, StarkConfig};
use crate::vm_air::{Addr, NUM_PUBLIC as VM_PUBLIC, PUB_OUTPUT, VmAir};

/// Transcript domain separator for node (aggregate) proofs.
const DOM_AGGREGATE_PROOF: u32 = 0x31;
const MASK30: u64 = (1 << 30) - 1;

fn outer_transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_AGGREGATE_PROOF));
    c
}

/// Consensus parameters of the aggregator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregatorParams {
    /// STARK configuration of the segment proofs.
    pub segment: StarkConfig,
    /// Every segment trace has exactly `2^segment_log_n` rows.
    pub segment_log_n: usize,
    /// Largest segment count a block may use.
    pub max_segments: usize,
    /// Largest number of children a node verifies.
    pub fan_in: usize,
    /// STARK configuration of the node (machine) proofs.
    pub outer: StarkConfig,
}

impl AggregatorParams {
    pub const MAINNET: AggregatorParams = AggregatorParams {
        segment: StarkConfig { log_blowup: 2, num_queries: 50 },
        segment_log_n: 15,
        max_segments: 16,
        fan_in: 4,
        outer: StarkConfig { log_blowup: 2, num_queries: 50 },
    };

    /// Rows available to transactions in one segment.
    pub fn segment_rows(&self) -> usize {
        1 << self.segment_log_n
    }
}

/// Values the root's output digest commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub prev_state_root: [Fp; DIGEST],
    pub new_state_root: [Fp; DIGEST],
    /// Inputs sponge state after the block's input positions.
    pub inputs_state: [Fp; WIDTH],
    /// Outputs sponge state after the block's outputs.
    pub outputs_state: [Fp; WIDTH],
    pub first_output_position: u64,
    pub end_output_position: u64,
    pub subsidy: u64,
}

/// Scalars in the statement encoding.
pub const STATEMENT_LEN: usize = 2 * DIGEST + 2 * WIDTH + 4 + LIMBS;
const ST_PREV: usize = 0;
const ST_NEW: usize = DIGEST;
const ST_ISP: usize = 2 * DIGEST;
const ST_OSP: usize = ST_ISP + WIDTH;
const ST_POS_IN: usize = ST_OSP + WIDTH;
const ST_POS_OUT: usize = ST_POS_IN + 2;
const ST_SUBSIDY: usize = ST_POS_OUT + 2;

impl Statement {
    pub fn from_block(s: &BlockStatement<'_>) -> Statement {
        Statement {
            prev_state_root: s.prev_state_root,
            new_state_root: s.new_state_root,
            inputs_state: inputs_state(&s.body.inputs),
            outputs_state: outputs_state(&s.body.outputs),
            first_output_position: s.first_output_position,
            end_output_position: s.first_output_position + s.body.outputs.len() as u64,
            subsidy: s.subsidy,
        }
    }

    fn zero() -> Statement {
        Statement {
            prev_state_root: [Fp::ZERO; DIGEST],
            new_state_root: [Fp::ZERO; DIGEST],
            inputs_state: [Fp::ZERO; WIDTH],
            outputs_state: [Fp::ZERO; WIDTH],
            first_output_position: 0,
            end_output_position: 0,
            subsidy: 0,
        }
    }

    pub fn to_values(&self) -> Vec<Fp> {
        let mut v = Vec::with_capacity(STATEMENT_LEN);
        v.extend_from_slice(&self.prev_state_root);
        v.extend_from_slice(&self.new_state_root);
        v.extend_from_slice(&self.inputs_state);
        v.extend_from_slice(&self.outputs_state);
        for p in [self.first_output_position, self.end_output_position] {
            v.push(Fp::new((p & MASK30) as u32));
            v.push(Fp::new((p >> 30) as u32));
        }
        v.extend_from_slice(&limbs16(self.subsidy));
        debug_assert_eq!(v.len(), STATEMENT_LEN);
        v
    }

    /// Output digest of the root program for this statement.
    pub fn digest(&self) -> [Fp; DIGEST] {
        crate::poseidon2::hash(&self.to_values())
    }
}

/// Digest of a span record, the output of an inner node.
pub fn record_digest(record: &SegmentPublic) -> [Fp; DIGEST] {
    crate::poseidon2::hash(&record.to_values())
}

/// The span covered by consecutive records: first in, last out, summed
/// limbs.
pub fn combine_records(records: &[SegmentPublic]) -> SegmentPublic {
    let (first, last) = (&records[0], &records[records.len() - 1]);
    let mut out = SegmentPublic {
        root_in: first.root_in,
        root_out: last.root_out,
        isp_in: first.isp_in,
        isp_out: last.isp_out,
        osp_in: first.osp_in,
        osp_out: last.osp_out,
        pos_in: first.pos_in,
        pos_out: last.pos_out,
        sum_in: [0; LIMBS],
        sum_out: [0; LIMBS],
    };
    for r in records {
        for j in 0..LIMBS {
            out.sum_in[j] += r.sum_in[j];
            out.sum_out[j] += r.sum_out[j];
        }
    }
    out
}

/// A proven node: its span record and machine proof, with the program it
/// ran.
#[derive(Clone, Debug)]
pub struct NodeProof {
    pub record: SegmentPublic,
    pub digest: Digest,
    pub proof: stark::Proof,
}

/// A child of a node program.
pub enum Child<'a> {
    Segment(&'a SegmentProof),
    Node(&'a NodeProof),
}

impl Child<'_> {
    fn record(&self) -> SegmentPublic {
        match self {
            Child::Segment(s) => s.public,
            Child::Node(n) => n.record,
        }
    }
}

/// What a node program outputs.
pub enum Output<'a> {
    /// The digest of the combined span record (inner nodes).
    Record,
    /// The digest of the block statement, after binding the span to it
    /// (the root).
    Statement(&'a Statement),
}

/// Builds a node program over `children`, along with the witness.
pub fn compile_node(params: &AggregatorParams, children: &[Child<'_>], output: Output<'_>) -> Compiler {
    let k = children.len();
    assert!(k >= 1 && k <= params.fan_in, "child count {k} out of range");
    let mut c = Compiler::new();
    let at = |base: Addr, field: usize| base + field as Addr;

    // Each child: its record as inputs, then its proof.
    let seg_prefix = [Fp::new(DOM_SEGMENT_PROOF)];
    let node_prefix = [Fp::new(DOM_AGGREGATE_PROOF)];
    let mut recs: Vec<Addr> = Vec::with_capacity(k);
    for child in children {
        let rec = c.scalar_inputs(&child.record().to_values());
        match child {
            Child::Segment(sp) => {
                assert_eq!(sp.proof.log_n, params.segment_log_n, "segment proof has the wrong height");
                c.verify_stark(&BlockAir, &params.segment, &seg_prefix, None, rec, SEGMENT_PUBLIC, &sp.proof);
            }
            Child::Node(np) => {
                // The child's public values are its program digest, pinned
                // to a constant, and its output digest, which must be the
                // hash of the record.
                let public = VmAir::public_values(&np.digest, &record_digest(&np.record));
                let pubv = c.scalar_inputs(&public);
                for (i, d) in np.digest.iter().enumerate() {
                    c.assert_scalar(pubv + i as Addr, *d);
                }
                c.hash_scalars(rec, SEGMENT_PUBLIC);
                let out = c.squeeze_digest();
                c.assert_block(at(pubv, PUB_OUTPUT), out, DIGEST);
                c.verify_stark(&VmAir, &params.outer, &node_prefix, Some(pubv), pubv, VM_PUBLIC, &np.proof);
            }
        }
        recs.push(rec);
    }

    // Chaining between consecutive children.
    for w in recs.windows(2) {
        let (a, b) = (w[0], w[1]);
        c.assert_block(at(a, PUB_ROOT_OUT), at(b, PUB_ROOT_IN), DIGEST);
        c.assert_block(at(a, PUB_ISP_OUT), at(b, PUB_ISP_IN), WIDTH);
        c.assert_block(at(a, PUB_OSP_OUT), at(b, PUB_OSP_IN), WIDTH);
        c.assert_block(at(a, PUB_POS_OUT), at(b, PUB_POS_IN), 2);
    }
    let (first, last) = (recs[0], recs[k - 1]);

    match output {
        Output::Record => {
            // Combined record: copies of the boundary fields, summed limbs.
            let padded = SEGMENT_PUBLIC.div_ceil(8) * 8;
            let out = c.prog.alloc(padded as u32);
            let copy = |c: &mut Compiler, src: Addr, dst: usize, n: usize| {
                for i in 0..n {
                    let v = c.val(src + i as Addr);
                    c.prog.muladd_to(src + i as Addr, 1, 0, at(out, dst + i));
                    c.set_word(at(out, dst + i), v);
                }
            };
            copy(&mut c, at(first, PUB_ROOT_IN), PUB_ROOT_IN, DIGEST);
            copy(&mut c, at(last, PUB_ROOT_OUT), PUB_ROOT_OUT, DIGEST);
            copy(&mut c, at(first, PUB_ISP_IN), PUB_ISP_IN, WIDTH);
            copy(&mut c, at(last, PUB_ISP_OUT), PUB_ISP_OUT, WIDTH);
            copy(&mut c, at(first, PUB_OSP_IN), PUB_OSP_IN, WIDTH);
            copy(&mut c, at(last, PUB_OSP_OUT), PUB_OSP_OUT, WIDTH);
            copy(&mut c, at(first, PUB_POS_IN), PUB_POS_IN, 2);
            copy(&mut c, at(last, PUB_POS_OUT), PUB_POS_OUT, 2);
            for field in [PUB_SUM_IN, PUB_SUM_OUT] {
                for j in 0..LIMBS {
                    let mut acc = 0;
                    for &r in &recs {
                        acc = c.add(acc, at(r, field + j));
                    }
                    let v = c.val(acc);
                    c.prog.muladd_to(acc, 1, 0, at(out, field + j));
                    c.set_word(at(out, field + j), v);
                }
            }
            for i in SEGMENT_PUBLIC..padded {
                c.prog.muladd_to(0, 1, 0, at(out, i));
                c.set_word(at(out, i), Fp4::ZERO);
            }
            c.hash_scalars(out, SEGMENT_PUBLIC);
            c.assert_public();
        }
        Output::Statement(statement) => {
            let st = c.scalar_inputs(&statement.to_values());
            // The span starts at the block's previous state and the fixed
            // initial list states, and ends at the statement's.
            c.assert_block(at(first, PUB_ROOT_IN), at(st, ST_PREV), DIGEST);
            for (i, v) in initial_inputs_state().iter().enumerate() {
                c.assert_scalar(at(first, PUB_ISP_IN + i), *v);
            }
            for (i, v) in initial_outputs_state().iter().enumerate() {
                c.assert_scalar(at(first, PUB_OSP_IN + i), *v);
            }
            c.assert_block(at(first, PUB_POS_IN), at(st, ST_POS_IN), 2);
            c.assert_block(at(last, PUB_ROOT_OUT), at(st, ST_NEW), DIGEST);
            c.assert_block(at(last, PUB_ISP_OUT), at(st, ST_ISP), WIDTH);
            c.assert_block(at(last, PUB_OSP_OUT), at(st, ST_OSP), WIDTH);
            c.assert_block(at(last, PUB_POS_OUT), at(st, ST_POS_OUT), 2);

            // Balance: sum over children of (out - in) minus the subsidy is
            // zero as an integer. Each limb difference is small, so the
            // carries between 16-bit limbs are hinted and range checked, and
            // the final carry is zero.
            //
            // Bounds: a segment's limb sums are honest integers below
            // `items * 2^16` where `items` is at most the rows divided by
            // the rows per output, and a record sums at most `max_segments`
            // of them, so the limb differences sum to `|s| < items * 2^16`
            // with `items = max_segments * outputs + 1` (the subsidy). An
            // honest carry satisfies `|c| <= items`, so carries are range
            // checked to `(-2^b, 2^b)` with `items < 2^b`. The identity
            // `s + c_prev - c * 2^16` is then below
            // `items * 2^16 + 2^b + 2^(b + 16)` in magnitude, which must stay
            // below `p` for field equality to imply integer equality.
            let items = params.max_segments * (params.segment_rows() / ROWS_PER_OUTPUT) + 1;
            let b = (usize::BITS - items.leading_zeros()) as u64;
            let bound = ((items as u64) << 16) + (1 << b) + (1 << (b + 16));
            assert!(bound < P as u64, "amount sums could wrap the field for these parameters");
            let carry_offset = 1u32 << b;
            let carry_bits = b as usize + 1;
            let two16 = c.scalar(Fp::new(1 << 16));
            let mut carry: Option<Addr> = None;
            for j in 0..LIMBS {
                let mut d = c.neg(at(st, ST_SUBSIDY + j));
                for &r in &recs {
                    d = c.add(d, at(r, PUB_SUM_OUT + j));
                    d = c.sub(d, at(r, PUB_SUM_IN + j));
                }
                if let Some(cp) = carry {
                    d = c.add(d, cp);
                }
                if j + 1 == LIMBS {
                    c.assert_eq(d, 0);
                    break;
                }
                // d == carry * 2^16, carry in (-offset, offset).
                let dv = signed(c.val(d).0[0]);
                let cv = dv.div_euclid(1 << 16);
                let hint = c.input(Fp4::from_base(Fp::new((cv + carry_offset as i64).max(0) as u32)));
                let off = c.scalar(Fp::new(carry_offset));
                let cj = c.sub(hint, off);
                let back = c.muladd(cj, two16, 0);
                c.assert_eq(back, d);
                c.assert_bits_zero_from(hint, carry_bits);
                carry = Some(cj);
            }

            c.hash_scalars(st, STATEMENT_LEN);
            c.assert_public();
        }
    }
    c
}

/// Signed value of a field element, assuming it is small in magnitude.
fn signed(x: Fp) -> i64 {
    let v = x.to_canonical() as i64;
    if v > (P as i64) / 2 { v - P as i64 } else { v }
}

// ---------------------------------------------------------------------------
// Tree planning
// ---------------------------------------------------------------------------

/// The shape of a node: its children (a child with no children of its own
/// is a segment proof), the segments under it, and the program digest and
/// height a node of this shape has.
#[derive(Clone, Debug)]
pub struct Shape {
    pub children: Vec<Shape>,
    /// Segments under this node.
    pub segments: usize,
    pub digest: Digest,
    pub log_n: usize,
}

impl Shape {
    pub fn is_segment(&self) -> bool {
        self.children.is_empty()
    }
}

/// Splits `k > fan_in` segments into balanced groups: as many as `fan_in`
/// allows for parallelism, but where possible at least two segments each,
/// since a node over one segment only adds a level. Always at least two
/// groups, so every group is smaller than `k`.
fn split(k: usize, fan_in: usize) -> Vec<usize> {
    debug_assert!(k > fan_in && fan_in >= 2);
    let groups = (k / 2).clamp(2, fan_in);
    let (base, extra) = (k / groups, k % groups);
    (0..groups).map(|g| base + usize::from(g < extra)).collect()
}

/// Plans the tree for `k` segments and computes every node's program
/// digest by compiling it against zero-filled proofs of the right shapes.
pub fn plan(params: &AggregatorParams, k: usize) -> Shape {
    assert!(k >= 1 && k <= params.max_segments, "segment count {k} out of range");
    let mut memo: HashMap<Vec<usize>, Shape> = HashMap::new();
    plan_node(params, k, true, &mut memo)
}

fn plan_node(params: &AggregatorParams, k: usize, root: bool, memo: &mut HashMap<Vec<usize>, Shape>) -> Shape {
    if k == 1 && !root {
        return Shape { children: vec![], segments: 1, digest: [Fp::ZERO; DIGEST], log_n: params.segment_log_n };
    }
    let sizes = if k <= params.fan_in { vec![1; k] } else { split(k, params.fan_in) };
    let key: Vec<usize> = std::iter::once(usize::from(root)).chain(sizes.iter().copied()).collect();
    if let Some(s) = memo.get(&key) {
        return s.clone();
    }
    let children: Vec<Shape> = sizes.iter().map(|&n| plan_node(params, n, false, memo)).collect();
    let segment_dummy = SegmentProof {
        public: SegmentPublic::from_values(&vec![Fp::ZERO; SEGMENT_PUBLIC]).unwrap(),
        proof: dummy_proof(&BlockAir, &params.segment, params.segment_log_n, SEGMENT_PUBLIC),
    };
    let node_dummies: Vec<NodeProof> = children
        .iter()
        .filter(|c| !c.is_segment())
        .map(|c| NodeProof {
            record: segment_dummy.public,
            digest: c.digest,
            proof: dummy_proof(&VmAir, &params.outer, c.log_n, VM_PUBLIC),
        })
        .collect();
    let mut nd = node_dummies.iter();
    let child_refs: Vec<Child<'_>> = children
        .iter()
        .map(|c| if c.is_segment() { Child::Segment(&segment_dummy) } else { Child::Node(nd.next().unwrap()) })
        .collect();
    let zero = Statement::zero();
    let output = if root { Output::Statement(&zero) } else { Output::Record };
    let prog = compile_node(params, &child_refs, output).prog;
    let shape = Shape {
        children,
        segments: k,
        digest: prog.digest(params.outer.log_blowup),
        log_n: prog.height().trailing_zeros() as usize,
    };
    memo.insert(key, shape.clone());
    shape
}

// ---------------------------------------------------------------------------
// Proving and verifying
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateError {
    Malformed,
    /// Segment count is zero or above the maximum.
    BadSegmentCount(usize),
    /// The machine proof does not verify against the expected program and
    /// statement digests.
    Rejected,
}

/// Proves one node of the tree over `segments[..shape.segments]`.
fn prove_node(params: &AggregatorParams, shape: &Shape, segments: &[SegmentProof], output: Output<'_>) -> NodeProof {
    let mut nodes: Vec<Option<NodeProof>> = Vec::with_capacity(shape.children.len());
    let mut at = 0;
    for child in &shape.children {
        let slice = &segments[at..at + child.segments];
        at += child.segments;
        nodes.push(if child.is_segment() { None } else { Some(prove_node(params, child, slice, Output::Record)) });
    }
    let mut at = 0;
    let children: Vec<Child<'_>> = shape
        .children
        .iter()
        .zip(&nodes)
        .map(|(child, node)| {
            let seg = &segments[at];
            at += child.segments;
            match node {
                Some(n) => Child::Node(n),
                None => Child::Segment(seg),
            }
        })
        .collect();
    let records: Vec<SegmentPublic> = children.iter().map(|c| c.record()).collect();
    let record = combine_records(&records);
    let out_digest = match &output {
        Output::Record => record_digest(&record),
        Output::Statement(s) => s.digest(),
    };
    let c = compile_node(params, &children, output);
    let trace = VmAir::generate_trace(&c.prog, &c.inputs).expect("node program rejects its own witness");
    let pre = c.prog.preprocess(params.outer.log_blowup);
    assert_eq!(pre.root(), shape.digest, "node program differs from the planned shape");
    let public = VmAir::public_values(&pre.root(), &out_digest);
    let proof = stark::prove_with(&params.outer, &VmAir, &trace, Some(&pre), &public, &mut outer_transcript());
    NodeProof { record, digest: shape.digest, proof }
}

/// Proves a block: segments in parallel, then the tree. The segments must
/// each fit `params.segment_log_n` rows.
pub fn prove_block(params: &AggregatorParams, statement: &Statement, segments: &[SegmentWitness]) -> Vec<u8> {
    let proofs: Vec<SegmentProof> = std::thread::scope(|s| {
        let handles: Vec<_> = segments
            .iter()
            .map(|w| s.spawn(move || prove_segment_padded(&params.segment, w, params.segment_log_n)))
            .collect();
        handles.into_iter().map(|h| h.join().expect("segment prover panicked")).collect()
    });
    let shape = plan(params, proofs.len());
    let root = prove_node(params, &shape, &proofs, Output::Statement(statement));
    let bytes = root.proof.to_bytes();
    let mut w = Writer::with_capacity(bytes.len() + 4);
    w.u32(proofs.len() as u32);
    w.0.extend_from_slice(&bytes);
    w.finish()
}

/// Verifies an encoded block proof against a statement. `root_digest`
/// gives the planned root program digest for a segment count.
pub fn verify_block(
    params: &AggregatorParams,
    root_digest: &dyn Fn(usize) -> Digest,
    statement: &Statement,
    proof: &[u8],
) -> Result<(), AggregateError> {
    let mut r = Reader(proof);
    let k = r.u32().ok_or(AggregateError::Malformed)? as usize;
    if k == 0 || k > params.max_segments {
        return Err(AggregateError::BadSegmentCount(k));
    }
    let proof = stark::Proof::from_bytes(r.0).ok_or(AggregateError::Malformed)?;
    let digest = root_digest(k);
    let public = VmAir::public_values(&digest, &statement.digest());
    stark::verify_with(&params.outer, &VmAir, Some(&digest), &public, &proof, &mut outer_transcript())
        .map_err(|_| AggregateError::Rejected)
}

/// Verifies block proofs with the aggregator, caching root digests per
/// segment count.
pub struct AggregateVerifier {
    pub params: AggregatorParams,
    digests: Mutex<HashMap<usize, Digest>>,
}

impl AggregateVerifier {
    pub fn new(params: AggregatorParams) -> AggregateVerifier {
        AggregateVerifier { params, digests: Mutex::new(HashMap::new()) }
    }

    pub fn digest(&self, k: usize) -> Digest {
        if let Some(d) = self.digests.lock().unwrap().get(&k) {
            return *d;
        }
        let d = plan(&self.params, k).digest;
        self.digests.lock().unwrap().insert(k, d);
        d
    }

    pub fn verify_statement(&self, statement: &Statement, proof: &[u8]) -> Result<(), AggregateError> {
        verify_block(&self.params, &|k| self.digest(k), statement, proof)
    }
}

impl ProofVerifier for AggregateVerifier {
    fn verify(&self, s: &BlockStatement<'_>, proof: &[u8]) -> bool {
        self.verify_statement(&Statement::from_block(s), proof).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Body;
    use crate::block_proof::prove_segment_padded;
    use crate::state_tree::open_env;
    use crate::transaction::{Key, Output as TxOutput, Sig, Transaction, UnsignedTransaction};
    use crate::utxo::UtxoSet;
    use crate::vm_air::ExecError;
    use crate::xmss::PublicKey;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let p = std::env::temp_dir().join(format!("tabminer-aggregate-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn key(tag: u8) -> Key {
        let mut s = [0u8; 32];
        s[0] = tag;
        Key::generate(&s)
    }

    /// Reward-only transactions: tiny segments (one output each).
    fn reward(pk: &PublicKey, amount: u64) -> Transaction {
        UnsignedTransaction::new(vec![], vec![TxOutput::new(pk, amount)]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap()
    }

    /// Small parameters: 128-row segments hold one output-only transaction,
    /// nodes take two children.
    const SMALL: AggregatorParams = AggregatorParams {
        segment: StarkConfig { log_blowup: 1, num_queries: 4 },
        segment_log_n: 7,
        max_segments: 4,
        fan_in: 2,
        outer: StarkConfig { log_blowup: 1, num_queries: 4 },
    };

    struct Setup {
        _dir: TempDir,
        segments: Vec<SegmentWitness>,
        statement: Statement,
        proofs: Vec<SegmentProof>,
    }

    fn setup(name: &str, amounts: &[u64], subsidy: u64) -> Setup {
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 16 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let miner = key(9).public_key();
        let txs: Vec<Transaction> = amounts.iter().map(|a| reward(&miner, *a)).collect();
        let prev_root = utxo.root(&wtxn).unwrap();
        let segments = SegmentWitness::collect_by_rows(&utxo, &mut wtxn, &txs, SMALL.segment_rows()).unwrap();
        let new_root = utxo.root(&wtxn).unwrap();
        wtxn.abort();
        assert_eq!(segments.len(), amounts.len());
        let body = Body { inputs: vec![], outputs: segments.iter().flat_map(|s| s.outputs()).collect(), proof: vec![] };
        let statement = Statement::from_block(&BlockStatement {
            height: 1,
            prev_state_root: prev_root,
            new_state_root: new_root,
            first_output_position: 0,
            subsidy,
            body: &body,
        });
        let proofs: Vec<SegmentProof> =
            segments.iter().map(|w| prove_segment_padded(&SMALL.segment, w, SMALL.segment_log_n)).collect();
        Setup { _dir: dir, segments, statement, proofs }
    }

    fn seg_children(proofs: &[SegmentProof]) -> Vec<Child<'_>> {
        proofs.iter().map(Child::Segment).collect()
    }

    #[test]
    fn root_program_accepts_and_rejects() {
        let s = setup("program", &[30, 25], 55);
        // Each segment proof verifies natively.
        for sp in &s.proofs {
            let tr = &mut crate::block_proof::transcript();
            assert_eq!(stark::verify(&SMALL.segment, &BlockAir, &sp.public.to_values(), &sp.proof, tr), Ok(()));
        }
        let c = compile_node(&SMALL, &seg_children(&s.proofs), Output::Statement(&s.statement));
        let exec = match VmAir::execute(&c.prog, &c.inputs) {
            Ok(e) => e,
            Err(ExecError::AssertionFailed(i)) => panic!("root rejected at {i}: {:?}", c.prog.instrs[i]),
            Err(e) => panic!("{e:?}"),
        };
        assert_eq!(exec.output_digest, Some(s.statement.digest()));
        println!(
            "root over 2 segments of 2^{}: {} instructions, {} inputs",
            SMALL.segment_log_n,
            c.prog.instrs.len(),
            c.inputs.len()
        );
        let shape = plan(&SMALL, 2);
        assert_eq!(shape.digest, c.prog.digest(SMALL.outer.log_blowup));
        assert!(shape.children.iter().all(|c| c.is_segment()));
        assert_ne!(plan(&SMALL, 1).digest, shape.digest);

        let rejects = |st: &Statement, proofs: &[SegmentProof]| {
            let c = compile_node(&SMALL, &seg_children(proofs), Output::Statement(st));
            matches!(VmAir::execute(&c.prog, &c.inputs), Err(ExecError::AssertionFailed(_)))
        };
        // Unbalanced.
        let mut poor = s.statement.clone();
        poor.subsidy = 54;
        assert!(rejects(&poor, &s.proofs));
        let mut rich = s.statement.clone();
        rich.subsidy = 56;
        assert!(rejects(&rich, &s.proofs));
        // A balance that only holds modulo 2^16 in the low limb.
        let mut wrapped = s.statement.clone();
        wrapped.subsidy = 55 + (1 << 16);
        assert!(rejects(&wrapped, &s.proofs));
        // Broken chain: segments swapped.
        let swapped = vec![s.proofs[1].clone(), s.proofs[0].clone()];
        assert!(rejects(&s.statement, &swapped));
        // Wrong end state.
        let mut moved = s.statement.clone();
        moved.end_output_position = 3;
        assert!(rejects(&moved, &s.proofs));
        let mut other_root = s.statement.clone();
        other_root.new_state_root[0] += Fp::ONE;
        assert!(rejects(&other_root, &s.proofs));
        // A segment proof for different public values.
        let mut forged = s.proofs.clone();
        forged[1].public.sum_out[0] += 1;
        let mut richer = s.statement.clone();
        richer.subsidy = 56;
        assert!(rejects(&richer, &forged));
        // Segment proofs swapped under their public values.
        let mut cross = s.proofs.clone();
        cross[1].proof = s.proofs[0].proof.clone();
        assert!(rejects(&s.statement, &cross));
    }

    #[test]
    fn inner_node_program_outputs_record() {
        let s = setup("record", &[30, 25], 55);
        let c = compile_node(&SMALL, &seg_children(&s.proofs), Output::Record);
        let exec = VmAir::execute(&c.prog, &c.inputs).expect("valid node");
        let records: Vec<SegmentPublic> = s.proofs.iter().map(|p| p.public).collect();
        assert_eq!(exec.output_digest, Some(record_digest(&combine_records(&records))));
    }

    #[test]
    fn tree_plans() {
        assert_eq!(split(10, 4), vec![3, 3, 2, 2]);
        assert_eq!(split(5, 4), vec![3, 2]);
        assert_eq!(split(16, 4), vec![4, 4, 4, 4]);
        assert_eq!(split(17, 4), vec![5, 4, 4, 4]);
        assert_eq!(split(3, 2), vec![2, 1]);
    }

    #[test]
    fn aggregator_size() {
        for (name, params) in [
            ("mainnet", AggregatorParams::MAINNET),
            ("2^13 segments", AggregatorParams { segment_log_n: 13, ..AggregatorParams::MAINNET }),
            (
                "2^13 segments, rate 1/8, 34 queries",
                AggregatorParams {
                    segment: StarkConfig { log_blowup: 3, num_queries: 34 },
                    segment_log_n: 13,
                    ..AggregatorParams::MAINNET
                },
            ),
        ] {
            let dummy = dummy_proof(&BlockAir, &params.segment, params.segment_log_n, SEGMENT_PUBLIC);
            let public = SegmentPublic::from_values(&vec![Fp::ZERO; SEGMENT_PUBLIC]).unwrap();
            let seg = SegmentProof { public, proof: dummy };
            let zero = Statement::zero();
            let c = compile_node(&params, &[Child::Segment(&seg)], Output::Statement(&zero));
            let mut hist = std::collections::BTreeMap::new();
            for ins in &c.prog.instrs {
                let name = format!("{ins:?}");
                *hist.entry(name.split([' ', '{']).next().unwrap().to_string()).or_insert(0usize) += 1;
            }
            println!("  {hist:?}");
            let rows = c.prog.num_rows();
            println!(
                "{name}: one segment = {} instructions, {} inputs, {} machine rows (2^{}), segment proof {} bytes",
                c.prog.instrs.len(),
                c.inputs.len(),
                rows,
                rows.next_power_of_two().trailing_zeros(),
                seg.proof.to_bytes().len()
            );
        }
        // A node verifying one node proof of the mainnet root's height.
        let params = AggregatorParams::MAINNET;
        let seg = SegmentProof {
            public: SegmentPublic::from_values(&vec![Fp::ZERO; SEGMENT_PUBLIC]).unwrap(),
            proof: dummy_proof(&BlockAir, &params.segment, params.segment_log_n, SEGMENT_PUBLIC),
        };
        let zero = Statement::zero();
        let leaf = compile_node(&params, &[Child::Segment(&seg)], Output::Statement(&zero)).prog;
        let np = NodeProof {
            record: seg.public,
            digest: [Fp::ZERO; DIGEST],
            proof: dummy_proof(&VmAir, &params.outer, leaf.height().trailing_zeros() as usize, VM_PUBLIC),
        };
        let c = compile_node(&params, &[Child::Node(&np)], Output::Record);
        println!(
            "mainnet: one node child of 2^{} rows = {} instructions, {} inputs, node proof {} bytes",
            leaf.height().trailing_zeros(),
            c.prog.instrs.len(),
            c.inputs.len(),
            np.proof.to_bytes().len()
        );
    }

    #[test]
    #[ignore = "proves an aggregate; run with --release"]
    fn aggregate_proof_roundtrip() {
        let s = setup("roundtrip", &[30, 25], 55);
        let t = std::time::Instant::now();
        let proof = prove_block(&SMALL, &s.statement, &s.segments);
        println!("aggregate of 2 segments: {} bytes in {:?}", proof.len(), t.elapsed());
        let v = AggregateVerifier::new(SMALL);
        let t = std::time::Instant::now();
        assert_eq!(v.verify_statement(&s.statement, &proof), Ok(()));
        println!("verify: {:?}", t.elapsed());
        let mut poor = s.statement.clone();
        poor.subsidy = 54;
        assert_eq!(v.verify_statement(&poor, &proof), Err(AggregateError::Rejected));
        let mut bad = proof.clone();
        bad[0] = 3;
        assert_eq!(v.verify_statement(&s.statement, &bad), Err(AggregateError::Rejected));
        bad[0] = 0;
        assert_eq!(v.verify_statement(&s.statement, &bad), Err(AggregateError::BadSegmentCount(0)));
        assert_eq!(v.verify_statement(&s.statement, &proof[..100]), Err(AggregateError::Malformed));
    }

    #[test]
    #[ignore = "proves a two-level tree; run with --release"]
    fn aggregate_tree_roundtrip() {
        // Three segments with fan-in two: leaves of 2 and 1 segments, then
        // the root verifies one node proof and one segment proof.
        let s = setup("tree", &[30, 25, 10], 65);
        let shape = plan(&SMALL, 3);
        assert_eq!(shape.children.len(), 2);
        assert_eq!(shape.children[0].segments, 2);
        assert!(!shape.children[0].is_segment());
        assert!(shape.children[1].is_segment());
        let t = std::time::Instant::now();
        let proof = prove_block(&SMALL, &s.statement, &s.segments);
        println!("tree aggregate of 3 segments: {} bytes in {:?}", proof.len(), t.elapsed());
        let v = AggregateVerifier::new(SMALL);
        assert_eq!(v.verify_statement(&s.statement, &proof), Ok(()));
        let mut poor = s.statement.clone();
        poor.subsidy = 64;
        assert_eq!(v.verify_statement(&poor, &proof), Err(AggregateError::Rejected));
    }
}
