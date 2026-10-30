//! Block aggregation: one proof per block, built as a tree.
//!
//! Segment proofs (see [`crate::block_proof`]) are verified by node
//! programs for [`crate::vm_air`]. A node verifies up to `fan_in` children,
//! each either a segment proof or the machine proof of another node, checks
//! that the children chain, and outputs the digest of the combined span
//! record (the values a segment exports: state roots, list sponges, output
//! positions, amount sums and open-transaction carries in and out, with the
//! sums normalized) followed by its tree digest. The root node instead
//! binds the span to the block statement: the chain starts at the block's
//! previous state, ends at the body's lists and new state, no transaction
//! is open at either end, and the amounts balance against the subsidy; it
//! outputs the digest of the statement and its tree digest.
//!
//! A node verifies a child node's proof under whatever program digest the
//! child's public values give, and commits to it in its tree digest
//! ([`tree_digest`]): one descriptor per child, a tag for a segment and the
//! program and tree digests for a node. The tree digest at the top thus
//! pins every program in the tree, and a node program depends only on its
//! children's kinds and table heights, of which there are few (35 types
//! cover every segment count on mainnet). [`plan`] lays out the tree for a
//! segment count and computes its digests, compiling each program type
//! once ([`PlanCache`]); after that, planning any count is hashing.
//!
//! The root's proof is itself verified by one more program, the wrap
//! ([`compile_wrap`]), proven at a lower rate with fewer queries: a much
//! smaller proof for a fixed extra proving cost, the same for every block.
//!
//! Last, a chain program verifies the wrap together with the previous
//! block's chain proof (see "Chain proofs" below), so each block's proof
//! shows the whole chain up to it valid. That chain proof is what a block
//! carries. A node can therefore check any one block's proof and know
//! every block before it valid, which is what fast sync uses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::block_air::{
    BlockAir, CARRY_LEN, LIMBS, NUM_PUBLIC as SEGMENT_PUBLIC, PUB_CARRY_IN, PUB_CARRY_OUT, PUB_ISP_IN, PUB_ISP_OUT,
    PUB_OSP_IN, PUB_OSP_OUT, PUB_POS_IN, PUB_POS_OUT, PUB_ROOT_IN, PUB_ROOT_OUT, PUB_SUM_IN, PUB_SUM_OUT,
    ROWS_PER_OUTPUT, SegmentPublic, SegmentWitness, initial_inputs_state, initial_outputs_state, inputs_state, limbs16,
    limbs16_wide, outputs_state,
};
use crate::block_proof::{DOM_SEGMENT_PROOF, SegmentProof, prove_segment_padded};
use crate::chain::{BlockStatement, ProofVerifier};
use crate::challenger::Challenger;
use crate::codec::{Reader, Writer};
use crate::ext::Fp4;
use crate::hash_table::HashTableAir;
use crate::merkle::Digest;
use crate::poseidon2::{DIGEST, Fp, P, WIDTH};
use crate::recursion::{Compiler, dummy_proof};
use crate::stark::{self, Preprocessed, StarkConfig};
use crate::vm_air::{Addr, NUM_PUBLIC as VM_PUBLIC, PUB_OUTPUT, Program, VmAir};

/// Transcript domain separator for node (aggregate) proofs.
const DOM_AGGREGATE_PROOF: u32 = 0x31;
/// Transcript domain separator for the wrap proof.
const DOM_WRAP_PROOF: u32 = 0x32;
const MASK30: u64 = (1 << 30) - 1;

fn outer_transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_AGGREGATE_PROOF));
    c
}

fn wrap_transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_WRAP_PROOF));
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
    /// STARK configuration of the wrap proof, the one a block carries.
    pub wrap: StarkConfig,
}

impl AggregatorParams {
    /// 120 bits of conjectured security for every proof (see SECURITY.md):
    /// each Fiat-Shamir round has an error below 2^-121.
    ///
    /// - The queries give `log_blowup` bits each, plus 16 bits of grinding
    ///   (about 35 ms). That is 124 bits for segments and nodes (rate 1/4,
    ///   54 queries) and 126 for the wrap (rate 1/32, 22 queries), or 122
    ///   and 124 at the list-decoding capacity radius left by the 2025
    ///   counterexamples to the proximity-gap conjectures. The field caps
    ///   the ethSTARK figure at 122.6.
    /// - Every challenge before the queries is ground to 121 bits
    ///   (`commit_bits`). The challenges come from a field of about 2^123.6,
    ///   so each one's degree term costs that many bits less. The lookup
    ///   challenges need the most: 24 bits on a node and 22 on the wrap,
    ///   about 8 s and 2 s. The DEEP batching uses independent
    ///   coefficients (`stark::Deep`), so it needs 15 to 20 bits rather
    ///   than the 25 to 30 that powers of one challenge would.
    ///
    /// Segments and nodes are both at rate 1/4. Segments at rate 1/8 prove
    /// twice as slowly but are cheaper to verify, and nodes at 1/8 would
    /// double their proving time for little gain. A full block's root
    /// verifies four children in up to 2^19 rows, and the wrap over it
    /// takes 2^17.
    ///
    /// The wrap is at rate 1/32 and is the published proof, so it is zero
    /// knowledge: nothing about the block's transactions, amounts or keys
    /// can be learned from it. The proofs below it are witnesses of the
    /// wrap and never leave the prover.
    pub const MAINNET: AggregatorParams = AggregatorParams {
        segment: StarkConfig { log_blowup: 2, num_queries: 54, pow_bits: 16, zk: false, commit_bits: 121 },
        segment_log_n: 15,
        max_segments: 1 << 14,
        fan_in: 4,
        outer: StarkConfig { log_blowup: 2, num_queries: 54, pow_bits: 16, zk: false, commit_bits: 121 },
        wrap: StarkConfig { log_blowup: 5, num_queries: 22, pow_bits: 16, zk: true, commit_bits: 121 },
    };

    /// Rate 1/8 at the same security, for comparisons.
    #[cfg(test)]
    const EIGHTH: StarkConfig = StarkConfig { log_blowup: 3, num_queries: 28, pow_bits: 16, zk: false, commit_bits: 0 };

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
    /// Output digest of a root whose tree digest is `tree`, and of the
    /// wrap (see [`wrap_tree`]).
    pub fn output(&self, tree: &Digest) -> Digest {
        let mut v = self.to_values();
        v.extend_from_slice(tree);
        crate::poseidon2::hash(&v)
    }
}

/// Descriptor tag of a segment child.
const SEGMENT_TAG: u32 = 0x41;
/// Scalars per child descriptor.
const DESCRIPTOR: usize = 2 * DIGEST;

/// Tree digest of a node: the hash of one descriptor per child, a segment
/// `[SEGMENT_TAG, 0, ..]` and a node its program digest and tree digest
/// (`Some((digest, tree))`). It commits to every program below the node,
/// which the node itself takes from its children's proofs unchecked.
pub fn tree_digest(children: &[Option<(Digest, Digest)>]) -> Digest {
    let mut v = Vec::with_capacity(DESCRIPTOR * children.len());
    for ch in children {
        match ch {
            None => {
                v.push(Fp::new(SEGMENT_TAG));
                v.extend_from_slice(&[Fp::ZERO; DESCRIPTOR - 1]);
            }
            Some((digest, tree)) => {
                v.extend_from_slice(digest);
                v.extend_from_slice(tree);
            }
        }
    }
    crate::poseidon2::hash(&v)
}

/// The wrap's tree digest: that of a node with the root as its one child.
pub fn wrap_tree(root_digest: &Digest, root_tree: &Digest) -> Digest {
    tree_digest(&[Some((*root_digest, *root_tree))])
}

/// Output digest of an inner node: its record and tree digest.
pub fn node_output(record: &SegmentPublic, tree: &Digest) -> Digest {
    let mut v = record.to_values();
    v.extend_from_slice(tree);
    crate::poseidon2::hash(&v)
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
        carry_in: first.carry_in,
        carry_out: last.carry_out,
    };
    // Sums are normalized to 16-bit limbs, as the node program does.
    let normal = |f: fn(&SegmentPublic) -> &[u32; LIMBS]| -> [u32; LIMBS] {
        let total: u128 = records.iter().map(|r| SegmentPublic::total(f(r))).sum();
        limbs16_wide(total).map(|x| x.to_canonical())
    };
    out.sum_in = normal(|r| &r.sum_in);
    out.sum_out = normal(|r| &r.sum_out);
    out
}

/// Bits of a carry when normalizing limb sums. A segment's limb sums are
/// honest integers below `2^25` (fewer than `2^9` items of 16 bits), a
/// node's are normalized, and a node sums at most `fan_in` records plus
/// the subsidy, so a limb sum with its incoming carry stays well below
/// `2^30` and its carry below `2^14`. Both sides of `s + c_in = r + 2^16
/// c` then stay below `p`, so the field identity is an integer one.
const CARRY_BITS: usize = 14;

/// Normalizes limb sums to 16-bit limbs with hinted, range-checked
/// carries; the top limb must fit 16 bits on its own, so the value is
/// below `2^96`. A normalized form is unique, so two of them are equal
/// exactly when the integers are.
fn normalize(c: &mut Compiler, sums: &[Addr; LIMBS]) -> [Addr; LIMBS] {
    let two16 = c.scalar(Fp::new(1 << 16));
    let mut out = [0; LIMBS];
    let mut carry: Option<Addr> = None;
    for j in 0..LIMBS {
        let d = match carry {
            Some(cp) => c.add(sums[j], cp),
            None => sums[j],
        };
        if j + 1 == LIMBS {
            c.assert_bits_zero_from(d, 16);
            out[j] = d;
            break;
        }
        let v = c.val(d).0[0].to_canonical();
        let r = c.input(Fp4::from_base(Fp::new(v & 0xffff)));
        let cj = c.input(Fp4::from_base(Fp::new(v >> 16)));
        c.assert_bits_zero_from(r, 16);
        c.assert_bits_zero_from(cj, CARRY_BITS);
        let back = c.muladd(cj, two16, r);
        c.assert_eq(back, d);
        out[j] = r;
        carry = Some(cj);
    }
    out
}

/// Limb sums of field `field` over `recs`, plus `extra` limbs if given.
fn sum_limbs(c: &mut Compiler, recs: &[Addr], field: usize, extra: Option<Addr>) -> [Addr; LIMBS] {
    core::array::from_fn(|j| {
        let mut acc = extra.map_or(0, |e| e + j as Addr);
        for &r in recs {
            acc = c.add(acc, r + (field + j) as Addr);
        }
        acc
    })
}

/// A proven node: its span record and machine proof, with the program it
/// ran.
#[derive(Clone, Debug)]
pub struct NodeProof {
    pub record: SegmentPublic,
    /// Program digest.
    pub digest: Digest,
    /// Tree digest: the programs below.
    pub tree: Digest,
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

/// What a node program outputs, along with its tree digest.
pub enum Output<'a> {
    /// The combined span record (inner nodes).
    Record,
    /// The block statement, after binding the span to it (the root).
    Statement(&'a Statement),
}

/// Copies `words` into a fresh block, zero padded to a multiple of eight,
/// for hashing.
fn concat(c: &mut Compiler, words: &[Addr]) -> Addr {
    let padded = words.len().div_ceil(8).max(1) * 8;
    let base = c.prog.alloc(padded as u32);
    for i in 0..padded {
        let src = words.get(i).copied().unwrap_or(0);
        let v = c.val(src);
        c.prog.muladd_to(src, 1, 0, base + i as Addr);
        c.set_word(base + i as Addr, v);
    }
    base
}

/// Builds a node program over `children`, along with the witness.
pub fn compile_node(params: &AggregatorParams, children: &[Child<'_>], output: Output<'_>) -> Compiler {
    let k = children.len();
    assert!(k >= 1 && k <= params.fan_in, "child count {k} out of range");
    // The bound behind CARRY_BITS: a limb sum over the children (each at
    // most a segment's items of 16 bits), the subsidy and a carry.
    let items = (params.segment_rows() / ROWS_PER_OUTPUT + 1) as u64;
    let limb_sum = ((params.fan_in as u64 * items + 1) << 16) + (1 << CARRY_BITS);
    assert!(limb_sum >> 16 < 1 << CARRY_BITS && (1u64 << (16 + CARRY_BITS)) + limb_sum < P as u64);
    let mut c = Compiler::new();
    let at = |base: Addr, field: usize| base + field as Addr;

    // Each child: its record as inputs, then its proof; and its
    // descriptor for the tree digest.
    let seg_prefix = [Fp::new(DOM_SEGMENT_PROOF)];
    let mut recs: Vec<Addr> = Vec::with_capacity(k);
    let mut descriptors: Vec<Addr> = Vec::with_capacity(k * DESCRIPTOR);
    for child in children {
        match child {
            Child::Segment(sp) => {
                let rec = c.scalar_inputs(&child.record().to_values());
                assert_eq!(sp.proof.tables[0].log_n, params.segment_log_n, "segment proof has the wrong height");
                c.verify_stark(&[(&BlockAir, None)], &params.segment, &seg_prefix, rec, SEGMENT_PUBLIC, &sp.proof);
                let tag = c.scalar(Fp::new(SEGMENT_TAG));
                descriptors.push(tag);
                descriptors.extend([0; DESCRIPTOR - 1]);
                recs.push(rec);
            }
            Child::Node(np) => {
                let (rec, pubv) = verify_node_child(&mut c, params, np, |c, np| {
                    let mut v = np.record.to_values();
                    v.extend_from_slice(&np.tree);
                    let rec = c.scalar_inputs(&v);
                    (rec, SEGMENT_PUBLIC + DIGEST, node_output(&np.record, &np.tree))
                });
                descriptors.extend((0..DIGEST as Addr).map(|i| pubv + i));
                descriptors.extend((0..DIGEST).map(|i| at(rec, SEGMENT_PUBLIC + i)));
                recs.push(rec);
            }
        }
    }
    let block = concat(&mut c, &descriptors);
    c.hash_scalars(block, descriptors.len());
    let tree = c.squeeze_digest();

    // Chaining between consecutive children.
    for w in recs.windows(2) {
        let (a, b) = (w[0], w[1]);
        c.assert_block(at(a, PUB_ROOT_OUT), at(b, PUB_ROOT_IN), DIGEST);
        c.assert_block(at(a, PUB_ISP_OUT), at(b, PUB_ISP_IN), WIDTH);
        c.assert_block(at(a, PUB_OSP_OUT), at(b, PUB_OSP_IN), WIDTH);
        c.assert_block(at(a, PUB_POS_OUT), at(b, PUB_POS_IN), 2);
        c.assert_block(at(a, PUB_CARRY_OUT), at(b, PUB_CARRY_IN), CARRY_LEN);
    }
    let (first, last) = (recs[0], recs[k - 1]);

    match output {
        Output::Record => {
            // Combined record: copies of the boundary fields, summed limbs;
            // then the tree digest.
            let padded = (SEGMENT_PUBLIC + DIGEST).div_ceil(8) * 8;
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
            copy(&mut c, at(first, PUB_CARRY_IN), PUB_CARRY_IN, CARRY_LEN);
            copy(&mut c, at(last, PUB_CARRY_OUT), PUB_CARRY_OUT, CARRY_LEN);
            for field in [PUB_SUM_IN, PUB_SUM_OUT] {
                let sums = sum_limbs(&mut c, &recs, field, None);
                let limbs = normalize(&mut c, &sums);
                for (j, &l) in limbs.iter().enumerate() {
                    let v = c.val(l);
                    c.prog.muladd_to(l, 1, 0, at(out, field + j));
                    c.set_word(at(out, field + j), v);
                }
            }
            for i in 0..DIGEST {
                let v = c.val(tree + i as Addr);
                c.prog.muladd_to(tree + i as Addr, 1, 0, at(out, SEGMENT_PUBLIC + i));
                c.set_word(at(out, SEGMENT_PUBLIC + i), v);
            }
            for i in SEGMENT_PUBLIC + DIGEST..padded {
                c.prog.muladd_to(0, 1, 0, at(out, i));
                c.set_word(at(out, i), Fp4::ZERO);
            }
            c.hash_scalars(out, SEGMENT_PUBLIC + DIGEST);
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
            // No transaction is open at either end.
            for i in 0..CARRY_LEN {
                c.assert_eq(at(first, PUB_CARRY_IN + i), 0);
                c.assert_eq(at(last, PUB_CARRY_OUT + i), 0);
            }

            // Balance: the inputs plus the subsidy equal the outputs, as
            // integers: both normalized, then compared limb by limb.
            let ins = sum_limbs(&mut c, &recs, PUB_SUM_IN, Some(at(st, ST_SUBSIDY)));
            let outs = sum_limbs(&mut c, &recs, PUB_SUM_OUT, None);
            let (ins, outs) = (normalize(&mut c, &ins), normalize(&mut c, &outs));
            for (a, b) in ins.iter().zip(&outs) {
                c.assert_eq(*a, *b);
            }

            let words: Vec<Addr> =
                (0..STATEMENT_LEN).map(|i| at(st, i)).chain((0..DIGEST).map(|i| tree + i as Addr)).collect();
            let block = concat(&mut c, &words);
            c.hash_scalars(block, words.len());
            c.assert_public();
        }
    }
    c
}

/// Verifies a node child's machine proof under the program digest its
/// public values claim, which the caller commits to in a tree digest.
/// `inputs` lays out the values the child's output digest covers and
/// returns their address, length and the expected digest. Returns that
/// address and the child's public values.
fn verify_node_child(
    c: &mut Compiler,
    params: &AggregatorParams,
    np: &NodeProof,
    inputs: impl FnOnce(&mut Compiler, &NodeProof) -> (Addr, usize, Digest),
) -> (Addr, Addr) {
    let (base, len, output) = inputs(c, np);
    let pubv = c.scalar_inputs(&VmAir::public_values(&np.digest, &output));
    c.hash_scalars(base, len);
    let out = c.squeeze_digest();
    c.assert_block(pubv + PUB_OUTPUT as Addr, out, DIGEST);
    let tables: [(&dyn stark::DynAir, Option<Addr>); 2] = [(&VmAir, Some(pubv)), (&HashTableAir, None)];
    let node_prefix = [Fp::new(DOM_AGGREGATE_PROOF)];
    c.verify_stark(&tables, &params.outer, &node_prefix, pubv, VM_PUBLIC, &np.proof);
    (base, pubv)
}

/// Builds the wrap program: verifies the root's machine proof (at
/// `params.outer`) and outputs the statement with the wrap's tree digest
/// ([`wrap_tree`]), so the block's proof can be a single proof at the
/// lower rate of `params.wrap`. Like every node, it depends only on the
/// root's table heights.
pub fn compile_wrap(params: &AggregatorParams, root: &NodeProof, statement: &Statement) -> Compiler {
    let mut c = Compiler::new();
    let (st, pubv) = verify_node_child(&mut c, params, root, |c, root| {
        let mut v = statement.to_values();
        v.extend_from_slice(&root.tree);
        (c.scalar_inputs(&v), STATEMENT_LEN + DIGEST, statement.output(&root.tree))
    });
    let words: Vec<Addr> =
        (0..DIGEST as Addr).map(|i| pubv + i).chain((0..DIGEST).map(|i| st + (STATEMENT_LEN + i) as Addr)).collect();
    let block = concat(&mut c, &words);
    c.hash_scalars(block, DESCRIPTOR);
    let tree = c.squeeze_digest();
    let words: Vec<Addr> =
        (0..STATEMENT_LEN).map(|i| st + i as Addr).chain((0..DIGEST).map(|i| tree + i as Addr)).collect();
    let block = concat(&mut c, &words);
    c.hash_scalars(block, words.len());
    c.assert_public();
    c.prog.reserve(params.wrap.blind_rows());
    c
}

// ---------------------------------------------------------------------------
// Tree planning
// ---------------------------------------------------------------------------

/// The shape of a node: its children (a child with no children of its own
/// is a segment proof), the segments under it, and the program digest and
/// table heights a node of this shape has.
#[derive(Clone, Debug)]
pub struct Shape {
    pub children: Vec<Shape>,
    /// Segments under this node.
    pub segments: usize,
    pub digest: Digest,
    pub log_n: usize,
    /// Log height of the node's hash table.
    pub hash_log_n: usize,
    /// Tree digest: the programs below ([`tree_digest`]).
    pub tree: Digest,
    /// The wrap program over this node, for the root.
    pub wrap: Option<Wrap>,
}

/// Program digest and table heights of the wrap over a root, and its tree
/// digest ([`wrap_tree`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wrap {
    pub digest: Digest,
    pub log_n: usize,
    pub hash_log_n: usize,
    pub tree: Digest,
}

impl Shape {
    pub fn is_segment(&self) -> bool {
        self.children.is_empty()
    }
}

/// Splits `k > fan_in` segments into full subtrees of `u` segments, `u`
/// the largest power of `fan_in` below `k`, and the remainder. Full
/// subtrees of a size have one shape whatever `k` is, so planning a new
/// segment count only plans the remainder's path. At most `fan_in`
/// groups, at least two, each smaller than `k`.
fn split(k: usize, fan_in: usize) -> Vec<usize> {
    debug_assert!(k > fan_in && fan_in >= 2);
    let mut u = 1;
    while u * fan_in < k {
        u *= fan_in;
    }
    let mut groups = vec![u; k / u];
    if !k.is_multiple_of(u) {
        groups.push(k % u);
    }
    groups
}

/// What a node program depends on: whether it is the root, and per child
/// whether it is a segment (`None`) or a node with the given table heights.
type NodeType = (bool, Vec<Option<(usize, usize)>>);

/// Program digest and table heights of a compiled program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Compiled {
    digest: Digest,
    log_n: usize,
    hash_log_n: usize,
}

impl Compiled {
    fn of(prog: &Program, log_blowup: usize) -> Compiled {
        Compiled {
            digest: prog.digest(log_blowup),
            log_n: prog.height().trailing_zeros() as usize,
            hash_log_n: VmAir::hash_height(prog).trailing_zeros() as usize,
        }
    }
}

/// Node and wrap programs compiled so far, by type. There are few types
/// (child kinds and heights), so a cache warmed by a few plans makes
/// planning any segment count a matter of hashing.
#[derive(Default)]
pub struct PlanCache {
    nodes: HashMap<NodeType, Compiled>,
    wraps: HashMap<(usize, usize), Compiled>,
}

impl PlanCache {
    pub fn new() -> PlanCache {
        PlanCache::default()
    }

    /// Programs compiled so far.
    pub fn len(&self) -> usize {
        self.nodes.len() + self.wraps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Plans the tree for `k` segments: its shape, every node's program digest
/// and heights, and the tree digests.
pub fn plan(params: &AggregatorParams, k: usize) -> Shape {
    plan_with(params, k, &mut PlanCache::new())
}

/// As [`plan`], compiling only the program types `cache` lacks.
pub fn plan_with(params: &AggregatorParams, k: usize, cache: &mut PlanCache) -> Shape {
    assert!(k >= 1 && k <= params.max_segments, "segment count {k} out of range");
    let mut root = plan_node(params, k, true, cache);
    let wrap = *cache.wraps.entry((root.log_n, root.hash_log_n)).or_insert_with(|| {
        let dummy = NodeProof {
            record: dummy_record(),
            digest: [Fp::ZERO; DIGEST],
            tree: [Fp::ZERO; DIGEST],
            proof: dummy_proof(&[(&VmAir, root.log_n), (&HashTableAir, root.hash_log_n)], &params.outer, VM_PUBLIC),
        };
        Compiled::of(&compile_wrap(params, &dummy, &Statement::zero()).prog, params.wrap.log_blowup)
    });
    root.wrap = Some(Wrap {
        digest: wrap.digest,
        log_n: wrap.log_n,
        hash_log_n: wrap.hash_log_n,
        tree: wrap_tree(&root.digest, &root.tree),
    });
    root
}

fn dummy_record() -> SegmentPublic {
    SegmentPublic::from_values(&vec![Fp::ZERO; SEGMENT_PUBLIC]).unwrap()
}

fn plan_node(params: &AggregatorParams, k: usize, root: bool, cache: &mut PlanCache) -> Shape {
    if k == 1 && !root {
        return Shape {
            children: vec![],
            segments: 1,
            digest: [Fp::ZERO; DIGEST],
            log_n: params.segment_log_n,
            hash_log_n: 0,
            tree: [Fp::ZERO; DIGEST],
            wrap: None,
        };
    }
    let sizes = if k <= params.fan_in { vec![1; k] } else { split(k, params.fan_in) };
    // Equal sizes plan equally; full subtrees repeat.
    let mut children: Vec<Shape> = Vec::with_capacity(sizes.len());
    for (i, &n) in sizes.iter().enumerate() {
        let shape = match sizes[..i].iter().position(|&m| m == n) {
            Some(j) => children[j].clone(),
            None => plan_node(params, n, false, cache),
        };
        children.push(shape);
    }
    let kinds: Vec<Option<(usize, usize)>> =
        children.iter().map(|c| (!c.is_segment()).then_some((c.log_n, c.hash_log_n))).collect();
    let compiled = *cache.nodes.entry((root, kinds.clone())).or_insert_with(|| {
        let segment_dummy = SegmentProof {
            public: dummy_record(),
            proof: dummy_proof(&[(&BlockAir, params.segment_log_n)], &params.segment, SEGMENT_PUBLIC),
        };
        let node_dummies: Vec<NodeProof> = kinds
            .iter()
            .flatten()
            .map(|&(log_n, hash_log_n)| NodeProof {
                record: dummy_record(),
                digest: [Fp::ZERO; DIGEST],
                tree: [Fp::ZERO; DIGEST],
                proof: dummy_proof(&[(&VmAir, log_n), (&HashTableAir, hash_log_n)], &params.outer, VM_PUBLIC),
            })
            .collect();
        let mut nd = node_dummies.iter();
        let child_refs: Vec<Child<'_>> = kinds
            .iter()
            .map(|kind| if kind.is_none() { Child::Segment(&segment_dummy) } else { Child::Node(nd.next().unwrap()) })
            .collect();
        let zero = Statement::zero();
        let output = if root { Output::Statement(&zero) } else { Output::Record };
        Compiled::of(&compile_node(params, &child_refs, output).prog, params.outer.log_blowup)
    });
    let descriptors: Vec<Option<(Digest, Digest)>> =
        children.iter().map(|c| (!c.is_segment()).then_some((c.digest, c.tree))).collect();
    Shape {
        segments: k,
        digest: compiled.digest,
        log_n: compiled.log_n,
        hash_log_n: compiled.hash_log_n,
        tree: tree_digest(&descriptors),
        wrap: None,
        children,
    }
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

/// A step of [`prove_block_with`], reported as it completes.
#[derive(Clone, Copy, Debug)]
pub enum Progress {
    /// Segment `index` of `count` is proven.
    Segment { index: usize, count: usize, elapsed: std::time::Duration },
    /// A node over `segments` segments is proven; `root` for the last one.
    Node { segments: usize, log_n: usize, hash_log_n: usize, root: bool, elapsed: std::time::Duration },
    /// The wrap over the root is proven.
    Wrap { log_n: usize, hash_log_n: usize, elapsed: std::time::Duration },
    /// The chain step over the wrap and the previous block's proof.
    Chain { elapsed: std::time::Duration },
}

/// Recently used committed programs, most recent last. A program type's
/// table is the same in every block, and committing it costs about as much
/// as a trace column set, so the last few are kept (a few hundred MB each).
static PROGRAMS: Mutex<Vec<(Digest, Arc<Preprocessed>)>> = Mutex::new(Vec::new());
const CACHED_PROGRAMS: usize = 4;

/// The commitment to `prog` at `log_blowup`, whose digest the plan says is
/// `digest`; from the cache when it was committed recently.
fn committed_program(prog: &Program, config: &StarkConfig, digest: &Digest) -> Arc<Preprocessed> {
    {
        let mut cache = PROGRAMS.lock().unwrap();
        if let Some(i) = cache.iter().position(|(d, _)| d == digest) {
            let entry = cache.remove(i);
            let pre = entry.1.clone();
            cache.push(entry);
            debug_assert_eq!(pre.table().values, prog.table().values, "program differs from the planned shape");
            return pre;
        }
    }
    let pre = Arc::new(prog.preprocess(config));
    assert_eq!(pre.root(), *digest, "program differs from the planned shape");
    let mut cache = PROGRAMS.lock().unwrap();
    cache.push((*digest, pre.clone()));
    if cache.len() > CACHED_PROGRAMS {
        cache.remove(0);
    }
    pre
}

/// Proves one node of the tree over `segments[..shape.segments]`; `None`
/// if `cancel` fired.
fn prove_node(
    params: &AggregatorParams,
    shape: &Shape,
    segments: &[SegmentProof],
    output: Output<'_>,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: stark::Cancel<'_>,
) -> Option<NodeProof> {
    let mut nodes: Vec<Option<NodeProof>> = Vec::with_capacity(shape.children.len());
    let mut at = 0;
    for child in &shape.children {
        let slice = &segments[at..at + child.segments];
        at += child.segments;
        nodes.push(if child.is_segment() {
            None
        } else {
            Some(prove_node(params, child, slice, Output::Record, progress, cancel)?)
        });
    }
    if cancel() {
        return None;
    }
    let t = std::time::Instant::now();
    let root = matches!(output, Output::Statement(_));
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
        Output::Record => node_output(&record, &shape.tree),
        Output::Statement(s) => s.output(&shape.tree),
    };
    let c = compile_node(params, &children, output);
    let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).expect("node program rejects its own witness");
    let pre = committed_program(&c.prog, &params.outer, &shape.digest);
    let public = VmAir::public_values(&pre.root(), &out_digest);
    let tables = VmAir::tables(&trace, &hashes, &pre);
    let proof = stark::try_prove_tables(&params.outer, &tables, &public, &mut outer_transcript(), Some(cancel)).ok()?;
    progress(Progress::Node {
        segments: shape.segments,
        log_n: shape.log_n,
        hash_log_n: shape.hash_log_n,
        root,
        elapsed: t.elapsed(),
    });
    Some(NodeProof { record, digest: shape.digest, tree: shape.tree, proof })
}

/// Proves a block: segments in parallel, then the tree. The segments must
/// each fit `params.segment_log_n` rows.
pub fn prove_block(params: &AggregatorParams, statement: &Statement, segments: &[SegmentWitness]) -> Vec<u8> {
    prove_block_with(params, &plan(params, segments.len()), statement, segments, segments.len(), &|_| {})
}

/// As [`prove_block`], with the tree `shape` already planned for
/// `segments.len()`, at most `jobs` segment provers at a time (each is
/// itself parallel, and a mainnet segment prover holds about a gigabyte),
/// and `progress` called after every segment and node.
pub fn prove_block_with(
    params: &AggregatorParams,
    shape: &Shape,
    statement: &Statement,
    segments: &[SegmentWitness],
    jobs: usize,
    progress: &(dyn Fn(Progress) + Sync),
) -> Vec<u8> {
    prove_block_cancellable(params, shape, statement, segments, jobs, progress, &|| false).expect("no cancellation")
}

/// As [`prove_block_with`], giving up with `None` once `cancel` returns
/// `true`: before each segment and node, and between the phases of each
/// proof.
pub fn prove_block_cancellable(
    params: &AggregatorParams,
    shape: &Shape,
    statement: &Statement,
    segments: &[SegmentWitness],
    jobs: usize,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: stark::Cancel<'_>,
) -> Option<Vec<u8>> {
    let proof = prove_wrap(params, shape, statement, segments, jobs, progress, cancel)?;
    let bytes = proof.to_bytes();
    let mut w = Writer::with_capacity(bytes.len() + 4);
    w.u32(segments.len() as u32);
    w.0.extend_from_slice(&bytes);
    Some(w.finish())
}

/// The wrap proof of a block: segments, the tree, then the wrap, as
/// [`prove_block_cancellable`] encodes it.
pub fn prove_wrap(
    params: &AggregatorParams,
    shape: &Shape,
    statement: &Statement,
    segments: &[SegmentWitness],
    jobs: usize,
    progress: &(dyn Fn(Progress) + Sync),
    cancel: stark::Cancel<'_>,
) -> Option<stark::Proof> {
    assert_eq!(shape.segments, segments.len(), "shape planned for a different segment count");
    let count = segments.len();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done: Vec<Mutex<Option<SegmentProof>>> = (0..count).map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..jobs.clamp(1, count.max(1)) {
            s.spawn(|| {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if index >= count || cancel() {
                        break;
                    }
                    let t = std::time::Instant::now();
                    let p = prove_segment_padded(&params.segment, &segments[index], params.segment_log_n);
                    progress(Progress::Segment { index, count, elapsed: t.elapsed() });
                    *done[index].lock().unwrap() = Some(p);
                }
            });
        }
    });
    if cancel() {
        return None;
    }
    let proofs: Vec<SegmentProof> = done.into_iter().map(|m| m.into_inner().unwrap().unwrap()).collect();
    let root = prove_node(params, shape, &proofs, Output::Statement(statement), progress, cancel)?;
    let wrap = shape.wrap.expect("shape is a planned root");
    let t = std::time::Instant::now();
    let c = compile_wrap(params, &root, statement);
    let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).expect("wrap program rejects its own witness");
    let pre = committed_program(&c.prog, &params.wrap, &wrap.digest);
    let public = VmAir::public_values(&pre.root(), &statement.output(&wrap.tree));
    let tables = VmAir::tables(&trace, &hashes, &pre);
    let proof = stark::try_prove_tables(&params.wrap, &tables, &public, &mut wrap_transcript(), Some(cancel)).ok()?;
    progress(Progress::Wrap { log_n: wrap.log_n, hash_log_n: wrap.hash_log_n, elapsed: t.elapsed() });
    Some(proof)
}

// ---------------------------------------------------------------------------
// Chain proofs
// ---------------------------------------------------------------------------
//
// A chain proof shows that a block and every block before it are valid. The
// chain program verifies the block's wrap proof, under a wrap program and
// tree digest that the plan allows for some segment count (a membership
// path in the Merkle tree of all of them), checks the block's subsidy
// against the emission schedule for its height, and links to the previous
// block's chain proof: the same state root and output position, one less
// height. Height 1 uses a base program that instead starts from the empty
// state. Every chain proof outputs
//
//     H(height || statement || step program digest || plan root)
//
// and a step verifies its predecessor under the step digest it outputs (or
// the base digest at height 2), so a valid proof at height h covers the
// whole chain up to h. The verifier supplies the step digest and the plan
// root it expects, which pins every program involved.

/// Transcript domain separator for chain proofs.
const DOM_CHAIN_PROOF: u32 = 0x33;

fn chain_transcript() -> Challenger {
    let mut c = Challenger::new();
    c.observe(Fp::new(DOM_CHAIN_PROOF));
    c
}

/// The allowed wraps: one leaf `H(wrap digest || wrap tree)` per segment
/// count `1..=max_segments`, padded with empty leaves to a power of two.
pub fn plan_leaves(params: &AggregatorParams, cache: &mut PlanCache) -> Vec<Digest> {
    let mut leaves: Vec<Digest> = (1..=params.max_segments)
        .map(|k| {
            let w = plan_with(params, k, cache).wrap.expect("planned root");
            let mut v = w.digest.to_vec();
            v.extend_from_slice(&w.tree);
            crate::poseidon2::hash(&v)
        })
        .collect();
    leaves.resize(params.max_segments.next_power_of_two(), [Fp::ZERO; DIGEST]);
    leaves
}

/// Output digest of a chain proof.
pub fn chain_output(height: u32, statement: &Statement, step: &Digest, plan_root: &Digest) -> Digest {
    let mut v = Vec::with_capacity(1 + STATEMENT_LEN + 2 * DIGEST);
    v.push(Fp::new(height));
    v.extend(statement.to_values());
    v.extend_from_slice(step);
    v.extend_from_slice(plan_root);
    crate::poseidon2::hash(&v)
}

/// The previous block's chain proof, for a step.
pub struct PrevChain<'a> {
    pub height: u32,
    pub statement: &'a Statement,
    pub proof: &'a stark::Proof,
}

/// Everything a chain program needs about one block.
pub struct ChainWitness<'a> {
    pub height: u32,
    pub statement: &'a Statement,
    pub wrap: Wrap,
    pub wrap_proof: &'a stark::Proof,
    /// Membership path of the wrap's leaf, and its index.
    pub path: Vec<Digest>,
    pub index: usize,
    /// `None` for the base program (height 1).
    pub prev: Option<PrevChain<'a>>,
}

/// The fixed context of the chain programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSetup {
    pub plan_root: Digest,
    /// Height of the plan tree.
    pub plan_depth: usize,
    pub base: Digest,
    pub step: Digest,
    /// Table heights every chain proof has.
    pub log_n: usize,
    pub hash_log_n: usize,
}

/// Builds a chain program: the base when `w.prev` is `None`, else a step.
/// `self_step` is the step digest the output commits to (an input, not
/// part of the program); `pad_to` pads to common heights.
#[allow(clippy::too_many_arguments)]
fn compile_chain(
    params: &AggregatorParams,
    emission: &[(u32, u64)],
    plan_root: &Digest,
    base_digest: &Digest,
    self_step: &Digest,
    w: &ChainWitness<'_>,
    pad_to: Option<(usize, usize)>,
) -> Compiler {
    let mut c = Compiler::new();
    let at = |base: Addr, field: usize| base + field as Addr;
    let st = c.scalar_inputs(&w.statement.to_values());
    let h = c.input(Fp4::from_base(Fp::new(w.height)));
    let dself = c.scalar_inputs(self_step);

    // The wrap is an allowed one: its leaf is in the plan tree.
    let mut pair_values = w.wrap.digest.to_vec();
    pair_values.extend_from_slice(&w.wrap.tree);
    let pair = c.scalar_inputs(&pair_values);
    let idx = c.input(Fp4::from_base(Fp::new(w.index as u32)));
    let bits = c.prog.decompose(idx);
    for k in 0..8 {
        let v = w.index as u32;
        c.set_word(bits + k as Addr, Fp4(core::array::from_fn(|j| Fp::new((v >> (4 * k + j)) & 1))));
    }
    let root = c.merkle_root(pair, 2 * DIGEST, &w.path, bits);
    for (i, v) in plan_root.iter().enumerate() {
        c.assert_scalar(root + i as Addr, *v);
    }

    // The wrap proof, for this block's statement.
    let words: Vec<Addr> =
        (0..STATEMENT_LEN).map(|i| at(st, i)).chain((0..DIGEST).map(|i| at(pair, DIGEST + i))).collect();
    let block = concat(&mut c, &words);
    c.hash_scalars(block, words.len());
    let wrap_out = c.squeeze_digest();
    let expected = w.statement.output(&w.wrap.tree);
    let pubv = c.scalar_inputs(&VmAir::public_values(&w.wrap.digest, &expected));
    c.assert_block(pubv, pair, DIGEST);
    c.assert_block(at(pubv, PUB_OUTPUT), wrap_out, DIGEST);
    let tables: [(&dyn stark::DynAir, Option<Addr>); 2] = [(&VmAir, Some(pubv)), (&HashTableAir, None)];
    c.verify_stark(&tables, &params.wrap, &[Fp::new(DOM_WRAP_PROOF)], pubv, VM_PUBLIC, w.wrap_proof);

    // The subsidy is the schedule's for the height: for each era boundary
    // a hinted bit says whether the height is within it, checked by a
    // range check on the difference either way.
    let mut sels: Vec<Addr> = Vec::with_capacity(emission.len());
    let mut end = 0u64;
    let mut prev_bit: Addr = 0;
    for (i, &(blocks, _)) in emission.iter().enumerate() {
        end += blocks as u64;
        let t = c.scalar(Fp::new(end as u32));
        let bit = if i + 1 == emission.len() {
            // Every height is within the last era: the chain ends there.
            let d = c.sub(t, h);
            c.assert_bits_zero_from(d, 30);
            1
        } else {
            let within = (w.height as u64) <= end;
            let b = c.input(Fp4::from_base(Fp::new(within as u32)));
            let bb = c.mul(b, b);
            c.assert_eq(bb, b);
            let below = c.sub(t, h);
            let above = c.sub(h, t);
            let above = c.sub(above, 1);
            let x = c.sub(below, above);
            let d = c.muladd(b, x, above);
            c.assert_bits_zero_from(d, 30);
            b
        };
        sels.push(c.sub(bit, prev_bit));
        prev_bit = bit;
    }
    for j in 0..LIMBS {
        let mut acc: Addr = 0;
        for (sel, &(_, subsidy)) in sels.iter().zip(emission) {
            let l = c.scalar(limbs16(subsidy)[j]);
            acc = c.muladd(*sel, l, acc);
        }
        c.assert_eq(acc, at(st, ST_SUBSIDY + j));
    }
    // Heights start at 1.
    let h0 = c.sub(h, 1);
    c.assert_bits_zero_from(h0, 30);

    match &w.prev {
        None => {
            // Height 1 starts from the empty state.
            c.assert_scalar(h, Fp::ONE);
            for (i, v) in crate::state_tree::empty_root().iter().enumerate() {
                c.assert_scalar(at(st, ST_PREV + i), *v);
            }
            c.assert_eq(at(st, ST_POS_IN), 0);
            c.assert_eq(at(st, ST_POS_IN + 1), 0);
        }
        Some(prev) => {
            let pst = c.scalar_inputs(&prev.statement.to_values());
            let ph = c.input(Fp4::from_base(Fp::new(prev.height)));
            let next = c.add(ph, 1);
            c.assert_eq(next, h);
            c.assert_block(at(pst, ST_NEW), at(st, ST_PREV), DIGEST);
            c.assert_block(at(pst, ST_POS_OUT), at(st, ST_POS_IN), 2);
            // The predecessor's program: the base at height 2, else the
            // step this proof itself claims.
            let two = c.scalar(Fp::new(2));
            let e = c.sub(h, two);
            let b = c.input(Fp4::from_base(Fp::new((w.height == 2) as u32)));
            let bb = c.mul(b, b);
            c.assert_eq(bb, b);
            let eb = c.mul(e, b);
            c.assert_eq(eb, 0);
            let inv_v = if w.height == 2 { Fp::ZERO } else { (Fp::new(w.height) - Fp::new(2)).inverse().unwrap() };
            let inv = c.input(Fp4::from_base(inv_v));
            let ei = c.mul(e, inv);
            let one_minus_b = c.sub(1, b);
            c.assert_eq(ei, one_minus_b);
            let mut digest_words = Vec::with_capacity(DIGEST);
            for (i, v) in base_digest.iter().enumerate() {
                let bd = c.scalar(*v);
                let diff = c.sub(bd, dself + i as Addr);
                digest_words.push(c.muladd(b, diff, dself + i as Addr));
            }
            let prev_digest: Digest = core::array::from_fn(|i| c.val(digest_words[i]).0[0]);
            // Its output: its statement, this proof's step digest, the plan.
            let mut words: Vec<Addr> = vec![ph];
            words.extend((0..STATEMENT_LEN).map(|i| at(pst, i)));
            words.extend((0..DIGEST).map(|i| dself + i as Addr));
            let plan_words: Vec<Addr> = plan_root.iter().map(|v| c.scalar(*v)).collect();
            words.extend(plan_words);
            let block = concat(&mut c, &words);
            c.hash_scalars(block, words.len());
            let prev_out = c.squeeze_digest();
            let expected = chain_output(prev.height, prev.statement, self_step, plan_root);
            let ppub = c.scalar_inputs(&VmAir::public_values(&prev_digest, &expected));
            for (i, dw) in digest_words.iter().enumerate() {
                c.assert_eq(ppub + i as Addr, *dw);
            }
            c.assert_block(at(ppub, PUB_OUTPUT), prev_out, DIGEST);
            let tables: [(&dyn stark::DynAir, Option<Addr>); 2] = [(&VmAir, Some(ppub)), (&HashTableAir, None)];
            c.verify_stark(&tables, &params.wrap, &[Fp::new(DOM_CHAIN_PROOF)], ppub, VM_PUBLIC, prev.proof);
        }
    }

    // Output, after padding to the common heights if asked: the padding
    // leaves room for the output hash, which must come last.
    let mut words: Vec<Addr> = vec![h];
    words.extend((0..STATEMENT_LEN).map(|i| at(st, i)));
    words.extend((0..DIGEST).map(|i| dself + i as Addr));
    let plan_words: Vec<Addr> = plan_root.iter().map(|v| c.scalar(*v)).collect();
    words.extend(plan_words);
    let block = concat(&mut c, &words);
    let blind = params.wrap.blind_rows();
    let final_hashes = words.len().div_ceil(8);
    if let Some((log_n, hash_log_n)) = pad_to {
        c.prog.reserve(blind + final_hashes);
        let zero = concat(&mut c, &[]);
        while VmAir::hash_height(&c.prog) < 1 << hash_log_n {
            c.hash_scalars(zero, 8);
        }
        c.prog.reserve(blind + final_hashes + 1);
        while c.prog.height() < 1 << log_n {
            c.add(0, 0);
        }
    }
    c.hash_scalars(block, words.len());
    c.prog.reserve(blind);
    c.assert_public();
    if let Some((log_n, hash_log_n)) = pad_to {
        assert_eq!(c.prog.height(), 1 << log_n, "chain program does not match its padding");
        assert_eq!(VmAir::hash_height(&c.prog), 1 << hash_log_n, "chain program does not match its hash padding");
    }
    c
}

/// Heights of every wrap proof (the same for every segment count).
fn wrap_heights(params: &AggregatorParams, cache: &mut PlanCache) -> (usize, usize) {
    let w = plan_with(params, 1, cache).wrap.expect("planned root");
    (w.log_n, w.hash_log_n)
}

/// Compiles the chain programs for `plan_root` (the root of
/// [`plan_leaves`]) and finds their common heights.
pub fn chain_setup(
    params: &AggregatorParams,
    emission: &[(u32, u64)],
    plan_root: &Digest,
    plan_depth: usize,
    cache: &mut PlanCache,
) -> ChainSetup {
    let (wn, wh) = wrap_heights(params, cache);
    let wrap_dummy = dummy_proof(&[(&VmAir, wn), (&HashTableAir, wh)], &params.wrap, VM_PUBLIC);
    let zero = Statement::zero();
    let wrap = Wrap { digest: [Fp::ZERO; DIGEST], log_n: wn, hash_log_n: wh, tree: [Fp::ZERO; DIGEST] };
    let path = vec![[Fp::ZERO; DIGEST]; plan_depth];
    let zd = [Fp::ZERO; DIGEST];
    fn witness<'a>(
        height: u32,
        statement: &'a Statement,
        wrap: Wrap,
        wrap_proof: &'a stark::Proof,
        path: &[Digest],
        prev: Option<PrevChain<'a>>,
    ) -> ChainWitness<'a> {
        ChainWitness { height, statement, wrap, wrap_proof, path: path.to_vec(), index: 0, prev }
    }
    let heights = |c: &Compiler| {
        (c.prog.height().trailing_zeros() as usize, VmAir::hash_height(&c.prog).trailing_zeros() as usize)
    };
    let base =
        compile_chain(params, emission, plan_root, &zd, &zd, &witness(1, &zero, wrap, &wrap_dummy, &path, None), None);
    // The step verifies a proof of its own heights: find the fixed point,
    // with room for the padding's bookkeeping.
    let (bn, bh) = heights(&base);
    let mut guess = (bn.max(wn), bh.max(wh));
    loop {
        let prev = dummy_proof(&[(&VmAir, guess.0), (&HashTableAir, guess.1)], &params.wrap, VM_PUBLIC);
        let w =
            witness(3, &zero, wrap, &wrap_dummy, &path, Some(PrevChain { height: 2, statement: &zero, proof: &prev }));
        let step = compile_chain(params, emission, plan_root, &zd, &zd, &w, None);
        let (sn, sh) = heights(&step);
        let room = step.prog.num_rows() + 64 < 1 << guess.0;
        if sn <= guess.0 && sh <= guess.1 && room {
            break;
        }
        guess = (if room { guess.0.max(sn) } else { guess.0 + 1 }, guess.1.max(sh));
    }
    let pad = Some(guess);
    let base =
        compile_chain(params, emission, plan_root, &zd, &zd, &witness(1, &zero, wrap, &wrap_dummy, &path, None), pad);
    let base_digest = base.prog.digest(params.wrap.log_blowup);
    let prev = dummy_proof(&[(&VmAir, guess.0), (&HashTableAir, guess.1)], &params.wrap, VM_PUBLIC);
    let w = witness(3, &zero, wrap, &wrap_dummy, &path, Some(PrevChain { height: 2, statement: &zero, proof: &prev }));
    let step = compile_chain(params, emission, plan_root, &base_digest, &zd, &w, pad);
    ChainSetup {
        plan_root: *plan_root,
        plan_depth,
        base: base_digest,
        step: step.prog.digest(params.wrap.log_blowup),
        log_n: guess.0,
        hash_log_n: guess.1,
    }
}

/// Proves a chain step (or the base, without `w.prev`).
pub fn prove_chain(
    params: &AggregatorParams,
    emission: &[(u32, u64)],
    setup: &ChainSetup,
    w: &ChainWitness<'_>,
    cancel: stark::Cancel<'_>,
) -> Option<stark::Proof> {
    let pad = Some((setup.log_n, setup.hash_log_n));
    let c = compile_chain(params, emission, &setup.plan_root, &setup.base, &setup.step, w, pad);
    let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).expect("chain program rejects its own witness");
    let digest = if w.prev.is_none() { setup.base } else { setup.step };
    let pre = committed_program(&c.prog, &params.wrap, &digest);
    let public = VmAir::public_values(&digest, &chain_output(w.height, w.statement, &setup.step, &setup.plan_root));
    let tables = VmAir::tables(&trace, &hashes, &pre);
    stark::try_prove_tables(&params.wrap, &tables, &public, &mut chain_transcript(), Some(cancel)).ok()
}

/// Verifies that `proof` shows the block at `height` with `statement`, and
/// every block before it, valid.
pub fn verify_chain(
    params: &AggregatorParams,
    setup: &ChainSetup,
    height: u32,
    statement: &Statement,
    proof: &stark::Proof,
) -> Result<(), AggregateError> {
    if height == 0 {
        return Err(AggregateError::Rejected);
    }
    let digest = if height == 1 { setup.base } else { setup.step };
    let public = VmAir::public_values(&digest, &chain_output(height, statement, &setup.step, &setup.plan_root));
    stark::verify_tables(&params.wrap, &VmAir::specs(&digest), &public, proof, &mut chain_transcript())
        .map_err(|_| AggregateError::Rejected)
}

/// Verifies an encoded block proof against a statement. `wrap` gives the
/// planned wrap for a segment count: the program digest the proof is
/// checked against and the tree digest its output commits to.
pub fn verify_block(
    params: &AggregatorParams,
    wrap: &dyn Fn(usize) -> Wrap,
    statement: &Statement,
    proof: &[u8],
) -> Result<(), AggregateError> {
    let mut r = Reader(proof);
    let k = r.u32().ok_or(AggregateError::Malformed)? as usize;
    if k == 0 || k > params.max_segments {
        return Err(AggregateError::BadSegmentCount(k));
    }
    let proof = stark::Proof::from_bytes(r.0).ok_or(AggregateError::Malformed)?;
    let wrap = wrap(k);
    let public = VmAir::public_values(&wrap.digest, &statement.output(&wrap.tree));
    stark::verify_tables(&params.wrap, &VmAir::specs(&wrap.digest), &public, &proof, &mut wrap_transcript())
        .map_err(|_| AggregateError::Rejected)
}

/// Mainnet's chain-proof setup: the root of the allowed wraps and the
/// chain programs, fixed by the circuits. Regenerate with the ignored test
/// `aggregate::tests::mainnet_chain_constants` after any circuit change.
pub const MAINNET_CHAIN: Option<ChainSetupConst> = Some(ChainSetupConst {
    plan_root: [1247916242, 1882446428, 1447144151, 450301831, 14159551, 1862179341, 1350039139, 828987825],
    plan_depth: 14,
    base: [151172052, 115859863, 671589279, 335580281, 702886413, 65863969, 1550395963, 788797239],
    step: [565762766, 1416504455, 1537457357, 1679329851, 1406711078, 1166448519, 168982398, 537990819],
    log_n: 17,
    hash_log_n: 15,
});

/// [`ChainSetup`] as plain integers, for a constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSetupConst {
    pub plan_root: [u32; DIGEST],
    pub plan_depth: usize,
    pub base: [u32; DIGEST],
    pub step: [u32; DIGEST],
    pub log_n: usize,
    pub hash_log_n: usize,
}

impl ChainSetupConst {
    fn setup(&self) -> ChainSetup {
        let d = |x: &[u32; DIGEST]| x.map(Fp::new);
        ChainSetup {
            plan_root: d(&self.plan_root),
            plan_depth: self.plan_depth,
            base: d(&self.base),
            step: d(&self.step),
            log_n: self.log_n,
            hash_log_n: self.hash_log_n,
        }
    }
}

/// Verifies block proofs: each a chain proof covering the block and every
/// block before it. Also proves them, for a miner.
pub struct AggregateVerifier {
    pub params: AggregatorParams,
    pub emission: &'static [(u32, u64)],
    /// Compiled program types, and the planned wrap by segment count.
    plans: Mutex<(PlanCache, HashMap<usize, Wrap>)>,
    setup: std::sync::OnceLock<ChainSetup>,
    tree: std::sync::OnceLock<crate::merkle::MerkleTree>,
    /// Debugging only: accept every proof without checking it.
    unchecked: bool,
}

impl AggregateVerifier {
    pub fn new(params: AggregatorParams, emission: &'static [(u32, u64)]) -> AggregateVerifier {
        AggregateVerifier {
            params,
            emission,
            plans: Mutex::new((PlanCache::new(), HashMap::new())),
            setup: std::sync::OnceLock::new(),
            tree: std::sync::OnceLock::new(),
            unchecked: false,
        }
    }

    /// Debugging only: a verifier that accepts every block proof unchecked,
    /// so blocks too large to prove in reasonable time can be simulated.
    /// Such a node can be fed any block.
    pub fn unchecked(mut self) -> AggregateVerifier {
        self.unchecked = true;
        self
    }

    /// Whether proofs go unchecked.
    pub fn is_unchecked(&self) -> bool {
        self.unchecked
    }

    /// The planned tree for `k` segments. Program types compiled for
    /// earlier counts are reused, so once warm this only hashes.
    pub fn shape(&self, k: usize) -> Shape {
        let mut plans = self.plans.lock().unwrap();
        let s = plan_with(&self.params, k, &mut plans.0);
        plans.1.insert(k, s.wrap.expect("planned root"));
        s
    }

    /// The planned wrap a `k`-segment block proof is checked against.
    pub fn wrap(&self, k: usize) -> Wrap {
        if let Some(w) = self.plans.lock().unwrap().1.get(&k) {
            return *w;
        }
        self.shape(k).wrap.expect("planned root")
    }

    /// Mainnet's setup from its constants; otherwise computed, which plans
    /// every segment count.
    fn is_mainnet(&self) -> bool {
        self.params == AggregatorParams::MAINNET && self.emission == crate::chain::MAINNET_EMISSION
    }

    /// The tree of allowed wraps, which proving needs (computed once:
    /// about a minute on mainnet). `leaves` may give it precomputed, as
    /// from [`AggregateVerifier::plan_leaves_bytes`]; they are checked.
    pub fn plan_tree(&self, leaves: Option<Vec<Digest>>) -> &crate::merkle::MerkleTree {
        self.tree.get_or_init(|| {
            if let Some(leaves) = leaves {
                let t = crate::merkle::MerkleTree::from_leaf_hashes(leaves);
                if self.setup.get().is_none_or(|s| s.plan_root == t.root())
                    && self.const_root().is_none_or(|r| r == t.root())
                {
                    return t;
                }
            }
            let mut plans = self.plans.lock().unwrap();
            crate::merkle::MerkleTree::from_leaf_hashes(plan_leaves(&self.params, &mut plans.0))
        })
    }

    fn const_root(&self) -> Option<Digest> {
        self.is_mainnet().then_some(MAINNET_CHAIN).flatten().map(|c| c.setup().plan_root)
    }

    /// The chain-proof setup.
    pub fn setup(&self) -> &ChainSetup {
        self.setup.get_or_init(|| {
            if let Some(c) = self.is_mainnet().then_some(MAINNET_CHAIN).flatten() {
                return c.setup();
            }
            let tree = self.plan_tree(None);
            let (root, depth) = (tree.root(), tree.height());
            let mut plans = self.plans.lock().unwrap();
            chain_setup(&self.params, self.emission, &root, depth, &mut plans.0)
        })
    }

    /// The plan tree's leaves as bytes, to save and reload with
    /// [`AggregateVerifier::plan_tree`].
    pub fn plan_leaves_bytes(&self) -> Vec<u8> {
        let tree = self.plan_tree(None);
        let mut w = Writer::default();
        for i in 0..tree.len() {
            w.digest(&tree.leaf(i));
        }
        w.finish()
    }

    /// Verifies a block proof: the chain proof of the block at `height`.
    pub fn verify_chain_proof(&self, height: u32, statement: &Statement, proof: &[u8]) -> Result<(), AggregateError> {
        let proof = stark::Proof::from_bytes(proof).ok_or(AggregateError::Malformed)?;
        verify_chain(&self.params, self.setup(), height, statement, &proof)
    }

    /// Verifies a wrap encoding (segment count and wrap proof), as
    /// [`prove_block_cancellable`] makes.
    pub fn verify_statement(&self, statement: &Statement, proof: &[u8]) -> Result<(), AggregateError> {
        verify_block(&self.params, &|k| self.wrap(k), statement, proof)
    }

    /// Proves the block at `height`: its segments, tree and wrap, then the
    /// chain step on `prev` (the previous block's height, statement and
    /// proof; `None` at height 1). Returns the block proof.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_block(
        &self,
        height: u32,
        statement: &Statement,
        segments: &[SegmentWitness],
        prev: Option<(u32, &Statement, &[u8])>,
        jobs: usize,
        progress: &(dyn Fn(Progress) + Sync),
        cancel: stark::Cancel<'_>,
    ) -> Option<Vec<u8>> {
        let shape = self.shape(segments.len());
        let wrap_proof = prove_wrap(&self.params, &shape, statement, segments, jobs, progress, cancel)?;
        let prev_proof = match prev {
            Some((_, _, bytes)) => Some(stark::Proof::from_bytes(bytes).expect("the previous block's proof decodes")),
            None => None,
        };
        let setup = *self.setup();
        let tree = self.plan_tree(None);
        let index = segments.len() - 1;
        let w = ChainWitness {
            height,
            statement,
            wrap: shape.wrap.expect("planned root"),
            wrap_proof: &wrap_proof,
            path: tree.open(index),
            index,
            prev: prev.zip(prev_proof.as_ref()).map(|((h, st, _), proof)| PrevChain {
                height: h,
                statement: st,
                proof,
            }),
        };
        let t = std::time::Instant::now();
        let proof = prove_chain(&self.params, self.emission, &setup, &w, cancel)?;
        progress(Progress::Chain { elapsed: t.elapsed() });
        Some(proof.to_bytes())
    }
}

impl ProofVerifier for AggregateVerifier {
    fn verify(&self, s: &BlockStatement<'_>, proof: &[u8]) -> bool {
        self.unchecked || self.verify_chain_proof(s.height, &Statement::from_block(s), proof).is_ok()
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
        segment: StarkConfig { log_blowup: 1, num_queries: 4, pow_bits: 3, zk: false, commit_bits: 110 },
        segment_log_n: 7,
        max_segments: 16,
        fan_in: 2,
        outer: StarkConfig { log_blowup: 2, num_queries: 4, pow_bits: 5, zk: false, commit_bits: 112 },
        wrap: StarkConfig { log_blowup: 3, num_queries: 4, pow_bits: 4, zk: true, commit_bits: 112 },
    };

    struct Setup {
        _dir: TempDir,
        segments: Vec<SegmentWitness>,
        statement: Statement,
        proofs: Vec<SegmentProof>,
    }

    fn setup(name: &str, amounts: &[u64], subsidy: u64) -> Setup {
        let miner = key(9).public_key();
        let s = setup_txs(name, &amounts.iter().map(|a| reward(&miner, *a)).collect::<Vec<_>>(), subsidy);
        assert_eq!(s.segments.len(), amounts.len());
        s
    }

    /// `txs` packed into SMALL segments, proven.
    fn setup_txs(name: &str, txs: &[Transaction], subsidy: u64) -> Setup {
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 16 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let prev_root = utxo.root(&wtxn).unwrap();
        let segments = SegmentWitness::collect_by_rows(&utxo, &mut wtxn, txs, SMALL.segment_rows()).unwrap();
        let new_root = utxo.root(&wtxn).unwrap();
        wtxn.abort();
        let body =
            Body { inputs: vec![], outputs: segments.iter().flat_map(|s| s.block_outputs()).collect(), proof: vec![] };
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

    /// One reward transaction with three outputs: in 128-row segments it
    /// spans three.
    fn spanning_setup(name: &str) -> Setup {
        let miner = key(9).public_key();
        let outs = [10, 20, 25].map(|a| TxOutput::new(&miner, a)).to_vec();
        let tx = UnsignedTransaction::new(vec![], outs).sign(|_, _, _| Err::<Sig, ()>(())).unwrap();
        setup_txs(name, &[tx], 55)
    }

    #[test]
    fn nodes_chain_open_transactions() {
        let s = spanning_setup("span");
        assert_eq!(s.proofs.len(), 3);
        let (p0, p1, p2) = (&s.proofs[0].public, &s.proofs[1].public, &s.proofs[2].public);
        assert!(p0.carry_out.open && p1.carry_out.open && !p2.carry_out.open);
        assert_eq!((p0.carry_out, p1.carry_out), (p1.carry_in, p2.carry_in));
        // A node over the first two segments chains them and exports the
        // open transaction.
        let c = compile_node(&SMALL, &seg_children(&s.proofs[..2]), Output::Record);
        let exec = VmAir::execute(&c.prog, &c.inputs).expect("node accepts chained open transactions");
        let record = combine_records(&[*p0, *p1]);
        assert!(record.carry_out.open && !record.carry_in.open);
        assert_eq!(exec.output_digest, Some(node_output(&record, &tree_digest(&[None, None]))));
        // Out of order, the carries do not chain (nor do the roots).
        let c = compile_node(&SMALL, &seg_children(&[s.proofs[1].clone(), s.proofs[0].clone()]), Output::Record);
        assert!(matches!(VmAir::execute(&c.prog, &c.inputs), Err(ExecError::AssertionFailed(_))));
        // A block that ends with the transaction still open is rejected by
        // the root, though everything else about it is consistent.
        let short = Statement {
            new_state_root: p1.root_out,
            outputs_state: p1.osp_out,
            end_output_position: p1.pos_out,
            subsidy: 30,
            ..s.statement.clone()
        };
        let c = compile_node(&SMALL, &seg_children(&s.proofs[..2]), Output::Statement(&short));
        assert!(matches!(VmAir::execute(&c.prog, &c.inputs), Err(ExecError::AssertionFailed(_))));
    }

    #[test]
    fn proving_can_be_cancelled() {
        let s = setup("cancel", &[30, 25], 55);
        let shape = plan(&SMALL, 2);
        let quiet = |_: Progress| {};
        // At once: no segment is proven.
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let now = || {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            true
        };
        assert!(prove_block_cancellable(&SMALL, &shape, &s.statement, &s.segments, 2, &quiet, &now).is_none());
        assert!(calls.load(std::sync::atomic::Ordering::Relaxed) >= 1);
        // Part way: after the segments, during the node's phases.
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let later = || calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= 6;
        assert!(prove_block_cancellable(&SMALL, &shape, &s.statement, &s.segments, 2, &quiet, &later).is_none());
        // Never: a proof as from `prove_block_with`.
        let proof = prove_block_cancellable(&SMALL, &shape, &s.statement, &s.segments, 2, &quiet, &|| false).unwrap();
        assert_eq!(AggregateVerifier::new(SMALL, &[(10, 55)]).verify_statement(&s.statement, &proof), Ok(()));
    }

    #[test]
    #[ignore = "proves two blocks and their chain proofs; run with --release"]
    fn chain_proofs_cover_history() {
        let dir = TempDir::new("chain");
        let env = open_env(&dir.0, 16 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let miner = key(9).public_key();
        // Two consecutive blocks on one UTXO set, 55 each.
        let mut block = |txs: Vec<Transaction>, height: u32| {
            let prev_root = utxo.root(&wtxn).unwrap();
            let first = utxo.next_position(&wtxn).unwrap();
            let segments = SegmentWitness::collect_by_rows(&utxo, &mut wtxn, &txs, SMALL.segment_rows()).unwrap();
            let body = Body {
                inputs: vec![],
                outputs: segments.iter().flat_map(|s| s.block_outputs()).collect(),
                proof: vec![],
            };
            let statement = Statement::from_block(&BlockStatement {
                height,
                prev_state_root: prev_root,
                new_state_root: utxo.root(&wtxn).unwrap(),
                first_output_position: first,
                subsidy: 55,
                body: &body,
            });
            (segments, statement)
        };
        let (seg1, st1) = block(vec![reward(&miner, 30), reward(&miner, 25)], 1);
        let (seg2, st2) = block(vec![reward(&miner, 55)], 2);
        wtxn.abort();

        let mut cache = PlanCache::new();
        let tree = crate::merkle::MerkleTree::from_leaf_hashes(plan_leaves(&SMALL, &mut cache));
        let emission = [(10u32, 55u64)];
        let t = std::time::Instant::now();
        let setup = chain_setup(&SMALL, &emission, &tree.root(), tree.height(), &mut cache);
        println!("chain setup in {:?}: 2^{}/2^{}", t.elapsed(), setup.log_n, setup.hash_log_n);
        let wrap_of = |segs: &[SegmentWitness], st: &Statement| {
            let shape = plan_with(&SMALL, segs.len(), &mut PlanCache::new());
            let proof = prove_wrap(&SMALL, &shape, st, segs, 2, &|_| {}, &|| false).unwrap();
            (shape.wrap.unwrap(), proof, segs.len() - 1)
        };
        let (w1, p1, i1) = wrap_of(&seg1, &st1);
        let (w2, p2, i2) = wrap_of(&seg2, &st2);
        let witness = |height, st, wrap, proof, index, prev| ChainWitness {
            height,
            statement: st,
            wrap,
            wrap_proof: proof,
            path: tree.open(index),
            index,
            prev,
        };
        let t = std::time::Instant::now();
        let c1 = prove_chain(&SMALL, &emission, &setup, &witness(1, &st1, w1, &p1, i1, None), &|| false).unwrap();
        println!("base proof in {:?}", t.elapsed());
        assert_eq!(verify_chain(&SMALL, &setup, 1, &st1, &c1), Ok(()));
        let prev = PrevChain { height: 1, statement: &st1, proof: &c1 };
        let t = std::time::Instant::now();
        let c2 = prove_chain(&SMALL, &emission, &setup, &witness(2, &st2, w2, &p2, i2, Some(prev)), &|| false).unwrap();
        println!("step proof in {:?}, {} bytes", t.elapsed(), c2.to_bytes().len());
        assert_eq!(verify_chain(&SMALL, &setup, 2, &st2, &c2), Ok(()));
        // Wrong height, statement or proof.
        assert!(verify_chain(&SMALL, &setup, 3, &st2, &c2).is_err());
        assert!(verify_chain(&SMALL, &setup, 2, &st1, &c2).is_err());
        assert!(verify_chain(&SMALL, &setup, 2, &st2, &c1).is_err());
        let mut other = st2.clone();
        other.end_output_position += 1;
        assert!(verify_chain(&SMALL, &setup, 2, &other, &c2).is_err());
        // The schedule is enforced: with block 2 due 7, its 55 is refused.
        let strict = [(1u32, 55u64), (9, 7)];
        let bad = std::panic::catch_unwind(|| {
            let prev = PrevChain { height: 1, statement: &st1, proof: &c1 };
            let w = witness(2, &st2, w2, &p2, i2, Some(prev));
            compile_chain(&SMALL, &strict, &setup.plan_root, &setup.base, &setup.step, &w, None)
        });
        if let Ok(c) = bad {
            assert!(VmAir::execute(&c.prog, &c.inputs).is_err());
        }
        // A wrap that is not in the plan is refused.
        let mut fake = w2;
        fake.tree[0] += Fp::ONE;
        let prev = PrevChain { height: 1, statement: &st1, proof: &c1 };
        let w = witness(2, &st2, fake, &p2, i2, Some(prev));
        let c = compile_chain(&SMALL, &emission, &setup.plan_root, &setup.base, &setup.step, &w, None);
        assert!(VmAir::execute(&c.prog, &c.inputs).is_err());
    }

    #[test]
    #[ignore = "proves a four-level tree; run with --release"]
    fn deep_tree_roundtrip() {
        // Nine segments at fan-in two: a full subtree of eight and one
        // segment, with an open transaction crossing two boundaries.
        let miner = key(9).public_key();
        let mut txs: Vec<Transaction> = (0..6).map(|i| reward(&miner, 1 + i)).collect();
        let outs = [5, 6, 7].map(|a| TxOutput::new(&miner, a)).to_vec();
        txs.push(UnsignedTransaction::new(vec![], outs).sign(|_, _, _| Err::<Sig, ()>(())).unwrap());
        let s = setup_txs("deep", &txs, 21 + 18);
        assert_eq!(s.segments.len(), 9);
        let shape = plan(&SMALL, 9);
        assert_eq!(shape.children.iter().map(|c| c.segments).collect::<Vec<_>>(), vec![8, 1]);
        let t = std::time::Instant::now();
        let proof = prove_block(&SMALL, &s.statement, &s.segments);
        println!("9 segments, 4 levels: {} bytes in {:?}", proof.len(), t.elapsed());
        let v = AggregateVerifier::new(SMALL, &[(10, 55)]);
        assert_eq!(v.verify_statement(&s.statement, &proof), Ok(()));
        let mut poor = s.statement.clone();
        poor.subsidy -= 1;
        assert_eq!(v.verify_statement(&poor, &proof), Err(AggregateError::Rejected));
    }

    #[test]
    #[ignore = "proves an aggregate; run with --release"]
    fn spanning_transaction_roundtrip() {
        let s = spanning_setup("span-roundtrip");
        let proof = prove_block(&SMALL, &s.statement, &s.segments);
        let v = AggregateVerifier::new(SMALL, &[(10, 55)]);
        assert_eq!(v.verify_statement(&s.statement, &proof), Ok(()));
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
        assert_eq!(exec.output_digest, Some(s.statement.output(&tree_digest(&[None, None]))));
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
        assert_eq!(exec.output_digest, Some(node_output(&combine_records(&records), &tree_digest(&[None, None]))));
    }

    #[test]
    #[ignore = "plans mainnet trees; run with --release"]
    fn mainnet_plans() {
        fn show(s: &Shape) -> String {
            if s.is_segment() {
                return "s".into();
            }
            let kids: Vec<String> = s.children.iter().map(show).collect();
            format!("2^{}/2^{}[{}]", s.log_n, s.hash_log_n, kids.join(" "))
        }
        let eighth = AggregatorParams { segment: AggregatorParams::EIGHTH, ..AggregatorParams::MAINNET };
        for (name, params) in [("mainnet", AggregatorParams::MAINNET), ("segments at rate 1/8", eighth)] {
            println!("{name}:");
            for k in [1, 2, 4, 5, 8, 12, 16] {
                println!("{k:2} segments: {}", show(&plan(&params, k)));
            }
            let mut cache = PlanCache::new();
            for k in [1000, 9999, 1 << 14, 1001, 12345, 3, 77] {
                let t = std::time::Instant::now();
                let fresh = plan(&params, k);
                let alone = t.elapsed();
                let t = std::time::Instant::now();
                let s = plan_with(&params, k, &mut cache);
                assert_eq!(s.wrap, fresh.wrap);
                println!(
                    "{k} segments: root 2^{}/2^{}, planned in {alone:?}, {:?} after the counts before ({} types)",
                    s.log_n,
                    s.hash_log_n,
                    t.elapsed(),
                    cache.len()
                );
            }
        }
    }

    #[test]
    fn tree_plans() {
        assert_eq!(split(10, 4), vec![4, 4, 2]);
        assert_eq!(split(5, 4), vec![4, 1]);
        assert_eq!(split(16, 4), vec![4, 4, 4, 4]);
        assert_eq!(split(17, 4), vec![16, 1]);
        assert_eq!(split(63, 4), vec![16, 16, 16, 15]);
        assert_eq!(split(3, 2), vec![2, 1]);
        for k in 5..300 {
            let g = split(k, 4);
            assert!(g.len() >= 2 && g.len() <= 4 && g.iter().sum::<usize>() == k && g.iter().all(|&n| n < k));
        }
    }

    #[test]
    fn aggregator_size() {
        for (name, params) in [
            ("mainnet", AggregatorParams::MAINNET),
            (
                "segments at rate 1/8, 28 queries",
                AggregatorParams { segment: AggregatorParams::EIGHTH, ..AggregatorParams::MAINNET },
            ),
            ("2^13 segments", AggregatorParams { segment_log_n: 13, ..AggregatorParams::MAINNET }),
        ] {
            let dummy = dummy_proof(&[(&BlockAir, params.segment_log_n)], &params.segment, SEGMENT_PUBLIC);
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
        // A node verifying one node proof of the mainnet root's height, with
        // the outer proofs at rate 1/4 and at rate 1/8.
        for (name, outer) in [
            ("rate 1/4, 42 queries", AggregatorParams::MAINNET.outer),
            ("rate 1/8, 28 queries", AggregatorParams::EIGHTH),
        ] {
            let params = AggregatorParams { outer, ..AggregatorParams::MAINNET };
            let seg = SegmentProof {
                public: SegmentPublic::from_values(&vec![Fp::ZERO; SEGMENT_PUBLIC]).unwrap(),
                proof: dummy_proof(&[(&BlockAir, params.segment_log_n)], &params.segment, SEGMENT_PUBLIC),
            };
            let zero = Statement::zero();
            let leaf = compile_node(&params, &[Child::Segment(&seg)], Output::Statement(&zero)).prog;
            let np = NodeProof {
                record: seg.public,
                digest: [Fp::ZERO; DIGEST],
                tree: [Fp::ZERO; DIGEST],
                proof: dummy_proof(
                    &[
                        (&VmAir, leaf.height().trailing_zeros() as usize),
                        (&HashTableAir, VmAir::hash_height(&leaf).trailing_zeros() as usize),
                    ],
                    &params.outer,
                    VM_PUBLIC,
                ),
            };
            let c = compile_node(&params, &[Child::Node(&np)], Output::Record);
            println!(
                "mainnet node child, {name}: 2^{} rows = {} instructions, {} inputs, node proof {} bytes",
                leaf.height().trailing_zeros(),
                c.prog.instrs.len(),
                c.inputs.len(),
                np.proof.to_bytes().len()
            );
        }
    }

    #[test]
    #[ignore = "proves an aggregate; run with --release"]
    fn aggregate_proof_roundtrip() {
        let s = setup("roundtrip", &[30, 25], 55);
        let t = std::time::Instant::now();
        let proof = prove_block(&SMALL, &s.statement, &s.segments);
        println!("aggregate of 2 segments: {} bytes in {:?}", proof.len(), t.elapsed());
        let v = AggregateVerifier::new(SMALL, &[(10, 55)]);
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
        let v = AggregateVerifier::new(SMALL, &[(10, 55)]);
        assert_eq!(v.verify_statement(&s.statement, &proof), Ok(()));
        let mut poor = s.statement.clone();
        poor.subsidy = 64;
        assert_eq!(v.verify_statement(&poor, &proof), Err(AggregateError::Rejected));
    }

    #[test]
    #[ignore = "proves a mainnet segment and a node over it; run with --release"]
    fn mainnet_node_timing() {
        let s = setup("node-timing", &[30], 30);
        let params = AggregatorParams::MAINNET;
        let seg = prove_segment_padded(&params.segment, &s.segments[0], params.segment_log_n);
        let c = compile_node(&params, &[Child::Segment(&seg)], Output::Record);
        let out = node_output(&combine_records(&[seg.public]), &tree_digest(&[None]));
        for _ in 0..2 {
            let t = std::time::Instant::now();
            let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).unwrap();
            let pre = c.prog.preprocess(&params.outer);
            eprintln!("  trace + program: {:?}", t.elapsed());
            let public = VmAir::public_values(&pre.root(), &out);
            let tables = VmAir::tables(&trace, &hashes, &pre);
            let proof = stark::prove_tables(&params.outer, &tables, &public, &mut outer_transcript());
            println!(
                "node 2^{} + 2^{} hashes: {:?}, {} bytes",
                trace.height().trailing_zeros(),
                hashes.height().trailing_zeros(),
                t.elapsed(),
                proof.to_bytes().len()
            );
        }
    }

    /// Mainnet-sized output-only block of `segments` full segments under
    /// `params`: the witnesses and the statement.
    fn full_segments(name: &str, params: &AggregatorParams, segments: usize) -> (Vec<SegmentWitness>, Statement) {
        let miner = key(9).public_key();
        let per = params.segment_rows() / crate::block_air::tx_rows(&reward(&miner, 1));
        let txs: Vec<Transaction> = (0..segments * per).map(|i| reward(&miner, 1 + i as u64)).collect();
        let subsidy: u64 = (1..=txs.len() as u64).sum();
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 256 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let prev_root = utxo.root(&wtxn).unwrap();
        let w = SegmentWitness::collect_by_rows(&utxo, &mut wtxn, &txs, params.segment_rows()).unwrap();
        let new_root = utxo.root(&wtxn).unwrap();
        wtxn.abort();
        assert_eq!(w.len(), segments);
        let body = Body { inputs: vec![], outputs: w.iter().flat_map(|s| s.block_outputs()).collect(), proof: vec![] };
        let statement = Statement::from_block(&BlockStatement {
            height: 1,
            prev_state_root: prev_root,
            new_state_root: new_root,
            first_output_position: 0,
            subsidy,
            body: &body,
        });
        (w, statement)
    }

    /// Computes mainnet's chain-proof constants ([`MAINNET_CHAIN`]) and
    /// checks the source has them; prints them when it does not.
    #[test]
    #[ignore = "plans every mainnet segment count (about a minute); run with --release"]
    fn mainnet_chain_constants() {
        let params = AggregatorParams::MAINNET;
        let mut cache = PlanCache::new();
        let tree = crate::merkle::MerkleTree::from_leaf_hashes(plan_leaves(&params, &mut cache));
        let s = chain_setup(&params, crate::chain::MAINNET_EMISSION, &tree.root(), tree.height(), &mut cache);
        let u = |d: &Digest| d.map(|x| x.to_canonical());
        let c = ChainSetupConst {
            plan_root: u(&s.plan_root),
            plan_depth: s.plan_depth,
            base: u(&s.base),
            step: u(&s.step),
            log_n: s.log_n,
            hash_log_n: s.hash_log_n,
        };
        println!("pub const MAINNET_CHAIN: Option<ChainSetupConst> = Some({c:?});");
        assert_eq!(MAINNET_CHAIN, Some(c), "update MAINNET_CHAIN to the line printed above");
    }

    /// Chain proofs at mainnet parameters (with the plan cut to 16 segment
    /// counts, which only shortens a Merkle path): two one-segment blocks,
    /// their wraps, the base proof and a step.
    #[test]
    #[ignore = "proves mainnet blocks and chain proofs; run with --release"]
    fn mainnet_chain_timing() {
        let params = AggregatorParams { max_segments: 16, ..AggregatorParams::MAINNET };
        let miner = key(9).public_key();
        let per = params.segment_rows() / crate::block_air::tx_rows(&reward(&miner, 1));
        let dir = TempDir::new("mainnet-chain");
        let env = open_env(&dir.0, 256 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let subsidy: u64 = (1..=per as u64).sum();
        let mut block = |height: u32| {
            let txs: Vec<Transaction> = (0..per).map(|i| reward(&miner, 1 + i as u64)).collect();
            let prev_root = utxo.root(&wtxn).unwrap();
            let first = utxo.next_position(&wtxn).unwrap();
            let w = SegmentWitness::collect_by_rows(&utxo, &mut wtxn, &txs, params.segment_rows()).unwrap();
            let body =
                Body { inputs: vec![], outputs: w.iter().flat_map(|s| s.block_outputs()).collect(), proof: vec![] };
            let st = Statement::from_block(&BlockStatement {
                height,
                prev_state_root: prev_root,
                new_state_root: utxo.root(&wtxn).unwrap(),
                first_output_position: first,
                subsidy,
                body: &body,
            });
            (w, st)
        };
        let (seg1, st1) = block(1);
        let (seg2, st2) = block(2);
        wtxn.abort();
        let mut cache = PlanCache::new();
        let t = std::time::Instant::now();
        let tree = crate::merkle::MerkleTree::from_leaf_hashes(plan_leaves(&params, &mut cache));
        let emission = [(10u32, subsidy)];
        let setup = chain_setup(&params, &emission, &tree.root(), tree.height(), &mut cache);
        println!(
            "plan and chain setup in {:?}: chain proofs 2^{} + 2^{} rows",
            t.elapsed(),
            setup.log_n,
            setup.hash_log_n
        );
        let wrap_of = |segs: &[SegmentWitness], st: &Statement, cache: &mut PlanCache| {
            let shape = plan_with(&params, segs.len(), cache);
            let t = std::time::Instant::now();
            let proof = prove_wrap(&params, &shape, st, segs, 2, &|_| {}, &|| false).unwrap();
            println!("block proven to its wrap in {:?}", t.elapsed());
            (shape.wrap.unwrap(), proof)
        };
        let (w1, p1) = wrap_of(&seg1, &st1, &mut cache);
        let (w2, p2) = wrap_of(&seg2, &st2, &mut cache);
        let t = std::time::Instant::now();
        let base = ChainWitness {
            height: 1,
            statement: &st1,
            wrap: w1,
            wrap_proof: &p1,
            path: tree.open(0),
            index: 0,
            prev: None,
        };
        let c1 = prove_chain(&params, &emission, &setup, &base, &|| false).unwrap();
        println!("base chain proof in {:?}", t.elapsed());
        let t = std::time::Instant::now();
        let step = ChainWitness {
            height: 2,
            statement: &st2,
            wrap: w2,
            wrap_proof: &p2,
            path: tree.open(0),
            index: 0,
            prev: Some(PrevChain { height: 1, statement: &st1, proof: &c1 }),
        };
        let c2 = prove_chain(&params, &emission, &setup, &step, &|| false).unwrap();
        println!("step chain proof in {:?}, {} bytes", t.elapsed(), c2.to_bytes().len());
        let t = std::time::Instant::now();
        assert_eq!(verify_chain(&params, &setup, 2, &st2, &c2), Ok(()));
        println!("verified in {:?}; wrap proof was {} bytes", t.elapsed(), p2.to_bytes().len());
    }

    /// Candidate security levels: table heights over the segment counts,
    /// and blocks of one and sixteen full segments proven and verified.
    /// `SEC` picks configurations by name (all by default).
    #[test]
    #[ignore = "proves mainnet blocks under several parameter sets; run with --release"]
    fn security_configs() {
        let m = AggregatorParams::MAINNET;
        let cfg = |q: usize, pow: usize| StarkConfig { num_queries: q, pow_bits: pow, commit_bits: 0, ..m.segment };
        let wrap = |q: usize, pow: usize| StarkConfig { num_queries: q, pow_bits: pow, commit_bits: 0, ..m.wrap };
        let all = [
            ("mainnet", m),
            // Mainnet without the commit-phase grinding: its cost by difference.
            ("plain", AggregatorParams { segment: cfg(54, 16), outer: cfg(54, 16), wrap: wrap(22, 16), ..m }),
            ("112", AggregatorParams { segment: cfg(50, 16), outer: cfg(50, 16), wrap: wrap(20, 16), ..m }),
            ("old", AggregatorParams { segment: cfg(42, 16), outer: cfg(42, 16), wrap: wrap(16, 20), ..m }),
        ];
        let pick = std::env::var("SEC").ok();
        for (name, params) in all {
            if pick.as_ref().is_some_and(|p| !p.split(',').any(|x| x == name)) {
                continue;
            }
            let bits = |c: &StarkConfig| c.num_queries * c.log_blowup + c.pow_bits;
            println!(
                "== {name}: segments/nodes {}+{} ({} bits), wrap {}x{}+{} ({} bits)",
                params.outer.num_queries,
                params.outer.pow_bits,
                bits(&params.outer),
                params.wrap.num_queries,
                params.wrap.log_blowup,
                params.wrap.pow_bits,
                bits(&params.wrap)
            );
            let mut cache = PlanCache::new();
            for k in [1, 16, 64, 1 << 14] {
                let s = plan_with(&params, k, &mut cache);
                let w = s.wrap.unwrap();
                println!(
                    "  {k} segments: root 2^{}/2^{}, wrap 2^{}/2^{}",
                    s.log_n, s.hash_log_n, w.log_n, w.hash_log_n
                );
            }
            for k in [1, 16] {
                let (segments, statement) = full_segments(name, &params, k);
                let shape = plan_with(&params, k, &mut cache);
                let t = std::time::Instant::now();
                let times = Mutex::new(Vec::new());
                let proof = prove_block_with(&params, &shape, &statement, &segments, 2, &|p| {
                    times.lock().unwrap().push(format!("{p:?}"));
                });
                let elapsed = t.elapsed();
                let wrap_line = times.lock().unwrap().iter().rev().find(|l| l.starts_with("Wrap")).cloned();
                let t = std::time::Instant::now();
                let w = shape.wrap.unwrap();
                let ok = verify_block(&params, &|_| w, &statement, &proof);
                println!(
                    "  block of {k}: proven in {elapsed:.1?}, {} bytes, verified {:?} in {:.1?}; {}",
                    proof.len(),
                    ok,
                    t.elapsed(),
                    wrap_line.unwrap_or_default()
                );
            }
        }
    }

    /// The numbers the soundness analysis needs, per table of each proof.
    #[test]
    #[ignore = "prints the parameters of the soundness analysis"]
    fn soundness_parameters() {
        use crate::block_air::{BlockAir, NUM_PUBLIC as BLOCK_PUBLIC};
        use crate::stark::{DynAir, evaluate, shape};
        fn table(name: &str, air: &dyn DynAir, num_public: usize) {
            let public = vec![Fp::ZERO; num_public];
            let (constraints, terms) = shape(air, &public);
            let zeros = vec![Fp::ZERO; air.air_width()];
            let pre = vec![Fp::ZERO; air.air_preprocessed_width()];
            let (_, t) = evaluate(air, &zeros, &zeros, (&pre, &pre), &public, (Fp::ZERO, Fp::ZERO, Fp::ZERO));
            let max_len = t.iter().map(|t| t.values.len()).max().unwrap_or(0);
            let lens: usize = t.iter().map(|t| t.values.len()).sum();
            println!(
                "{name}: width {} pre {} degree {} constraints {constraints} terms {terms} (tuple lengths sum {lens}, max {max_len}) group {}",
                air.air_width(),
                air.air_preprocessed_width(),
                air.air_degree(),
                air.air_lookup_group()
            );
        }
        table("segment BlockAir", &BlockAir, BLOCK_PUBLIC);
        table("machine VmAir", &VmAir, crate::vm_air::NUM_PUBLIC);
        table("hash HashTableAir", &crate::hash_table::HashTableAir, crate::vm_air::NUM_PUBLIC);
        let m = AggregatorParams::MAINNET;
        for k in [1, 16] {
            let s = plan(&m, k);
            let w = s.wrap.unwrap();
            println!("{k} segments: root 2^{}/2^{}, wrap 2^{}/2^{}", s.log_n, s.hash_log_n, w.log_n, w.hash_log_n);
        }
        // The grinding of the largest proof of each kind.
        let full = plan(&m, 16);
        let wrap = full.wrap.unwrap();
        let hash = crate::hash_table::HashTableAir;
        type Kind<'a> = (&'a str, StarkConfig, Vec<(&'a dyn DynAir, usize)>, usize);
        let kinds: [Kind<'_>; 3] = [
            ("segment", m.segment, vec![(&BlockAir, m.segment_log_n)], BLOCK_PUBLIC),
            ("node", m.outer, vec![(&VmAir, full.log_n), (&hash, full.hash_log_n)], crate::vm_air::NUM_PUBLIC),
            ("wrap", m.wrap, vec![(&VmAir, wrap.log_n), (&hash, wrap.hash_log_n)], crate::vm_air::NUM_PUBLIC),
        ];
        for (name, config, tables, num_public) in kinds {
            let g = crate::stark::grinding_of(&config, &tables, &vec![Fp::ZERO; num_public]);
            let mut sizes: Vec<usize> = tables.iter().map(|t| t.1 + config.log_blowup).collect();
            sizes.dedup();
            let fri = config.fri();
            let mut log_m = sizes[0];
            let folds: Vec<usize> = crate::fri::round_log_arities(&fri, &sizes)
                .iter()
                .map(|&la| {
                    let b = crate::fri::fold_grinding(&fri, la, log_m);
                    log_m -= la;
                    b
                })
                .collect();
            println!("{name} grinding: {g:?}, folds {folds:?}");
        }
    }

    #[test]
    fn wrap_program_accepts_and_rejects() {
        let s = setup("wrap", &[30, 25], 55);
        let shape = plan(&SMALL, 2);
        let root = prove_node(&SMALL, &shape, &s.proofs, Output::Statement(&s.statement), &|_| {}, &|| false).unwrap();
        let c = compile_wrap(&SMALL, &root, &s.statement);
        let exec = VmAir::execute(&c.prog, &c.inputs).expect("wrap accepts the root proof");
        let wrap = shape.wrap.unwrap();
        assert_eq!(wrap.tree, wrap_tree(&shape.digest, &tree_digest(&[None, None])));
        assert_eq!(exec.output_digest, Some(s.statement.output(&wrap.tree)));
        assert_eq!(c.prog.digest(SMALL.wrap.log_blowup), wrap.digest);
        let rejects = |c: Compiler| matches!(VmAir::execute(&c.prog, &c.inputs), Err(ExecError::AssertionFailed(_)));
        // Another statement, another root program, another tree, a
        // corrupted proof.
        let mut poor = s.statement.clone();
        poor.subsidy = 54;
        assert!(rejects(compile_wrap(&SMALL, &root, &poor)));
        let mut other = root.clone();
        other.digest[0] += Fp::ONE;
        assert!(rejects(compile_wrap(&SMALL, &other, &s.statement)));
        let mut other = root.clone();
        other.tree[0] += Fp::ONE;
        assert!(rejects(compile_wrap(&SMALL, &other, &s.statement)));
        let mut bad = root.clone();
        bad.proof.openings[1][0].trace_row[3] += Fp::ONE;
        assert!(rejects(compile_wrap(&SMALL, &bad, &s.statement)));
        // Proof-of-work witnesses before the batching challenge and the
        // first fold are checked too.
        let hash = crate::hash_table::HashTableAir;
        let g = crate::stark::grinding_of(
            &SMALL.outer,
            &[(&VmAir, shape.log_n), (&hash, shape.hash_log_n)],
            &[Fp::ZERO; crate::vm_air::NUM_PUBLIC],
        );
        assert!(g.beta > 0, "{g:?}");
        let mut bad = root.clone();
        bad.proof.grinding[3] += Fp::ONE;
        assert!(rejects(compile_wrap(&SMALL, &bad, &s.statement)));
        let mut bad = root.clone();
        bad.proof.fri.fold_witnesses[0] += Fp::ONE;
        assert!(rejects(compile_wrap(&SMALL, &bad, &s.statement)));
    }

    #[test]
    #[ignore = "proves a mainnet root and wraps it; run with --release"]
    fn mainnet_wrap_timing() {
        let s = setup("wrap-timing", &[30], 30);
        let params = AggregatorParams::MAINNET;
        let seg = prove_segment_padded(&params.segment, &s.segments[0], params.segment_log_n);
        let shape = plan(&params, 1);
        let root = prove_node(&params, &shape, &[seg], Output::Statement(&s.statement), &|_| {}, &|| false).unwrap();
        let configs: Vec<StarkConfig> = match std::env::var("WRAP") {
            Ok(v) => {
                let n: Vec<usize> = v.split(',').map(|x| x.parse().unwrap()).collect();
                vec![StarkConfig {
                    log_blowup: n[0],
                    num_queries: n[1],
                    pow_bits: n[2],
                    zk: n.get(3) == Some(&1),
                    commit_bits: 0,
                }]
            }
            Err(_) => vec![
                StarkConfig { log_blowup: 4, num_queries: 21, pow_bits: 16, zk: false, commit_bits: 0 },
                StarkConfig { log_blowup: 5, num_queries: 17, pow_bits: 16, zk: false, commit_bits: 0 },
                StarkConfig { log_blowup: 6, num_queries: 14, pow_bits: 16, zk: false, commit_bits: 0 },
            ],
        };
        for wrap in configs {
            let mut c = compile_wrap(&params, &root, &s.statement);
            c.prog.reserve(wrap.blind_rows());
            let t = std::time::Instant::now();
            let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).unwrap();
            let pre = c.prog.preprocess(&wrap);
            let public = VmAir::public_values(&pre.root(), &s.statement.output(&shape.wrap.unwrap().tree));
            let tables = VmAir::tables(&trace, &hashes, &pre);
            let proof = stark::prove_tables(&wrap, &tables, &public, &mut outer_transcript());
            let elapsed = t.elapsed();
            let t = std::time::Instant::now();
            let ok = stark::verify_tables(&wrap, &VmAir::specs(&pre.root()), &public, &proof, &mut outer_transcript());
            println!(
                "wrap at rate 1/{}, {} queries: 2^{} + 2^{} hashes, {} instructions; proven in {elapsed:?}, {} bytes; verify {:?} {:?}",
                1 << wrap.log_blowup,
                wrap.num_queries,
                trace.height().trailing_zeros(),
                hashes.height().trailing_zeros(),
                c.prog.instrs.len(),
                proof.to_bytes().len(),
                ok,
                t.elapsed()
            );
        }
    }

    #[test]
    #[ignore = "proves mainnet-sized segments and nodes; run with --release"]
    fn mainnet_rate_timing() {
        let s = setup("rates", &[30], 30);
        let quarter = AggregatorParams::MAINNET.outer;
        let eighth = AggregatorParams::EIGHTH;
        for (name, segment, outer) in [
            ("segments 1/4, nodes 1/4", quarter, quarter),
            ("segments 1/8, nodes 1/4", eighth, quarter),
            ("segments 1/8, nodes 1/8", eighth, eighth),
        ] {
            let params = AggregatorParams { segment, outer, ..AggregatorParams::MAINNET };
            let t = std::time::Instant::now();
            let seg = prove_segment_padded(&params.segment, &s.segments[0], params.segment_log_n);
            let seg_time = t.elapsed();
            let c = compile_node(&params, &[Child::Segment(&seg)], Output::Record);
            let t = std::time::Instant::now();
            let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).unwrap();
            let pre = c.prog.preprocess(&params.outer);
            let out = node_output(&combine_records(&[seg.public]), &tree_digest(&[None]));
            let public = VmAir::public_values(&pre.root(), &out);
            let tables = VmAir::tables(&trace, &hashes, &pre);
            let proof = stark::prove_tables(&params.outer, &tables, &public, &mut outer_transcript());
            let node_time = t.elapsed();
            println!(
                "{name}: segment 2^{} in {seg_time:?} ({} bytes); node over it 2^{} + 2^{} hashes in {node_time:?} ({} bytes)",
                params.segment_log_n,
                seg.proof.to_bytes().len(),
                c.prog.height().trailing_zeros(),
                hashes.height().trailing_zeros(),
                proof.to_bytes().len()
            );
        }
    }
}
