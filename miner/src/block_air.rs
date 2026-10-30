//! The segment circuit: proves that a run of transactions is valid and
//! correctly transforms the UTXO tree, with a chainable public interface so
//! a block can be split into segments proven in parallel.
//!
//! # Statement
//!
//! Public values (150 elements):
//!
//! ```text
//! root_in[8] root_out[8]            UTXO root before and after
//! isp_in[16] isp_out[16]            inputs sponge state before and after
//! osp_in[16] osp_out[16]            outputs sponge state before and after
//! pos_in(2) pos_out(2)              next output position before and after
//! sum_in[6] sum_out[6]              16-bit limb sums of input and output amounts
//! carry_in[27] carry_out[27]        transaction open across the boundary:
//!                                   open, message[8], body sponge[16],
//!                                   inputs left, outputs left (all zero
//!                                   when closed)
//! ```
//!
//! Segments chain by matching one segment's `*_out` to the next segment's
//! `*_in`. The aggregator checks that the first segment starts from the
//! block's previous root, the initial sponge states, the block's first
//! output position and no open transaction, that the last segment ends at
//! the new root, at sponge states equal to the block's input and output
//! lists and with no open transaction, and that the summed balances plus
//! the subsidy equal zero as integers.
//!
//! A transaction may span segments: a segment can end after any item of a
//! transaction, exporting the transaction's state as `carry_out`, and the
//! next segment then begins with a `resume` row that takes it back from
//! `carry_in` and continues with the next item. The message, body sponge
//! and item counters are the only state that crosses: everything else is
//! per item, and amounts are summed per segment.
//!
//! Within a segment, for every input the prover shows an XMSS signature by
//! the revealed key over the body hash of its transaction, derives the
//! commitment `H(H(key) || amount)`, compresses it with the output's memo
//! (a witness) into the tree leaf, proves that leaf sits at the input's
//! position in the current tree, and clears it. For every output it
//! derives the commitment `H(key_hash || amount)` from a witness key hash
//! and appends its leaf, commitment and memo compressed, at the next
//! position. Positions are absorbed
//! into the inputs sponge, and output commitments and memos (never amounts)
//! into the outputs sponge. A memo is a free witness, also absorbed into
//! the body, so the signatures cover it. Per transaction, the body sponge is rebuilt from the
//! same registers the signatures and commitments use and must equal the
//! signed message.
//!
//! # Schedule
//!
//! ```text
//! tx_start | resume                         body sponge header; counters n_in, n_out
//!   per input:  [xmss rows] pkh0 pkh1 cm0 cm1 ileaf ilist old/new x 40 body_in0 body_in1
//!   per output: ocm0 ocm1 oleaf olist olist2 body_out0 body_out1 body_out2 old/new x 40
//! tx_end                                    body digest == signed message
//! ... more transactions ... done rows
//! ```
//!
//! A `resume` row may only be the first; the last transaction may stop
//! after any item (straight into the done rows), leaving it open.
//!
//! Row types are one-hot; the order is enforced by transition constraints,
//! with the next phase after a transaction start or an item end chosen by
//! zero tests on the remaining-item counters. The XMSS and tree fragments
//! follow [`crate::xmss_air`] and [`crate::smt_air`] with their public
//! checks replaced by register plumbing.

use crate::block::BlockOutput;
use crate::field::Field;
use crate::hash_machine::{
    COL_ABSORB, COL_ACC, COL_CHAIN, COL_COMPRESS, COL_DATA, COL_DIR, COL_LOAD, COL_PASS, COL_START, HashTraceBuilder,
    NUM_COLS as HM_COLS, eval_hash_machine,
};
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH, permute};
use crate::poseidon2_air::{COL_INPUT, COL_OUTPUT};
use crate::stark::{Air, Builder, Trace};
use crate::state_tree::{DEPTH, EMPTY};
use crate::transaction::{
    Commitment, DOM_BODY, DOM_COMMITMENT, DOM_PUBKEY, Memo, Output, Sig, TREE_HEIGHT, Transaction, amount_fps,
};
use crate::utxo::{self, UtxoSet};
use crate::xmss::{
    CHAINS, CSUM_CHAINS, DIGITS_PER_ELEMENT, DOM_MSG, DOM_TREE, DOM_WOTS_CHAIN, DOM_WOTS_PK, Digest, MSG_CHAINS,
    PUB_SEED_LEN, PublicKey, W, digits,
};

pub const HEIGHT: usize = TREE_HEIGHT;
const STEPS: usize = W - 1;
const ELEMENTS: usize = DIGEST + 1;
const BITS: usize = 31;
const AMOUNT_BITS: usize = 64;
/// 16-bit limbs of amount sums: four hold an amount, six any sum of a
/// block's amounts (fewer than `2^32` of them).
pub const LIMBS: usize = 6;
const MASK30: u64 = (1 << 30) - 1;
const DOM_INPUTS: u32 = 0x21;
const DOM_OUTPUTS: u32 = 0x22;

// ---- row types ----
pub const T_TX_START: usize = HM_COLS;
pub const T_TX_END: usize = HM_COLS + 1;
pub const T_MSG_START: usize = HM_COLS + 2;
pub const T_MSG_ABS: usize = HM_COLS + 3;
pub const T_LOAD: usize = HM_COLS + 4;
pub const T_STEP: usize = HM_COLS + 5;
pub const T_LEAF: usize = HM_COLS + 6;
pub const T_TREE_START: usize = HM_COLS + 7;
pub const T_TREE_ABS: usize = HM_COLS + 8;
pub const T_PKH0: usize = HM_COLS + 9;
pub const T_PKH1: usize = HM_COLS + 10;
pub const T_CM0: usize = HM_COLS + 11;
pub const T_CM1: usize = HM_COLS + 12;
pub const T_ILIST: usize = HM_COLS + 13;
pub const T_OLD: usize = HM_COLS + 14;
pub const T_NEW: usize = HM_COLS + 15;
pub const T_BODY_IN0: usize = HM_COLS + 16;
pub const T_BODY_IN1: usize = HM_COLS + 17;
pub const T_OCM0: usize = HM_COLS + 18;
pub const T_OCM1: usize = HM_COLS + 19;
pub const T_OLIST: usize = HM_COLS + 20;
pub const T_BODY_OUT0: usize = HM_COLS + 21;
pub const T_BODY_OUT1: usize = HM_COLS + 22;
pub const T_DONE: usize = HM_COLS + 23;
pub const T_RESUME: usize = HM_COLS + 24;
pub const T_OLIST2: usize = HM_COLS + 25;
pub const T_BODY_OUT2: usize = HM_COLS + 26;
pub const T_ILEAF: usize = HM_COLS + 27;
pub const T_OLEAF: usize = HM_COLS + 28;
const NUM_TYPES: usize = 29;
// ---- xmss counters ----
pub const C_MC: usize = HM_COLS + NUM_TYPES;
pub const C_ACTIVE: usize = C_MC + 1;
pub const C_REM: usize = C_ACTIVE + 1;
pub const C_REM_INV: usize = C_REM + 1;
pub const C_SSEL: usize = C_REM_INV + 1;
pub const C_KSEL: usize = C_SSEL + STEPS;
pub const C_ESEL: usize = C_KSEL + DIGITS_PER_ELEMENT;
pub const C_LAST: usize = C_ESEL + ELEMENTS;
pub const C_LSEL: usize = C_LAST + 1;
pub const C_BITS: usize = C_LSEL + HEIGHT;
pub const C_T3: usize = C_BITS + BITS;
pub const C_D: usize = C_T3 + 1;
pub const C_CSUM: usize = C_D + 1;
// ---- xmss registers ----
pub const R_PUB_SEED: usize = C_CSUM + 1;
pub const R_IDX: usize = R_PUB_SEED + PUB_SEED_LEN;
pub const R_M: usize = R_IDX + HEIGHT;
pub const R_SP: usize = R_M + DIGEST;
pub const R_NODE: usize = R_SP + WIDTH;
pub const R_SIB: usize = R_NODE + DIGEST;
// ---- tree update ----
pub const C_LEVEL: usize = R_SIB + DIGEST;
pub const C_LEVEL_INV: usize = C_LEVEL + 1;
pub const C_IS_LAST: usize = C_LEVEL_INV + 1;
pub const C_SMT_END: usize = C_IS_LAST + 1;
pub const R_PBITS: usize = C_SMT_END + 1;
pub const R_ROOT: usize = R_PBITS + DEPTH;
pub const R_OLD: usize = R_ROOT + DIGEST;
pub const R_NEW: usize = R_OLD + DIGEST;
// ---- block registers ----
pub const R_IS_OUT: usize = R_NEW + DIGEST;
pub const C_OUT_END: usize = R_IS_OUT + 1;
pub const R_MSG: usize = C_OUT_END + 1;
pub const R_BSP: usize = R_MSG + DIGEST;
pub const R_ISP: usize = R_BSP + WIDTH;
pub const R_OSP: usize = R_ISP + WIDTH;
pub const R_PKROOT: usize = R_OSP + WIDTH;
pub const R_OCM: usize = R_PKROOT + DIGEST;
pub const R_ABITS: usize = R_OCM + DIGEST;
pub const R_SUM_IN: usize = R_ABITS + AMOUNT_BITS;
pub const R_SUM_OUT: usize = R_SUM_IN + LIMBS;
pub const R_OPOS_LO: usize = R_SUM_OUT + LIMBS;
pub const R_OPOS_HI: usize = R_OPOS_LO + 1;
pub const C_WRAP: usize = R_OPOS_HI + 1;
pub const C_WRAP_INV: usize = C_WRAP + 1;
pub const R_IN_LEFT: usize = C_WRAP_INV + 1;
pub const R_OUT_LEFT: usize = R_IN_LEFT + 1;
pub const C_IN_ZERO: usize = R_OUT_LEFT + 1;
pub const C_IN_INV: usize = C_IN_ZERO + 1;
pub const C_OUT_ZERO: usize = C_IN_INV + 1;
pub const C_OUT_INV: usize = C_OUT_ZERO + 1;
pub const C_GO_OUT: usize = C_OUT_INV + 1;
pub const C_GO_END: usize = C_GO_OUT + 1;
/// One while a transaction is open: from its start (or resume) until the
/// row after its end.
pub const R_OPEN: usize = C_GO_END + 1;
/// The current item's memo, set entering its first row.
pub const R_MEMO: usize = R_OPEN + 1;
/// The current output's tree leaf, set after its leaf row.
pub const R_LEAF: usize = R_MEMO + DIGEST;
pub const NUM_COLS: usize = R_LEAF + DIGEST;

// ---- public values ----
pub const PUB_ROOT_IN: usize = 0;
pub const PUB_ROOT_OUT: usize = DIGEST;
pub const PUB_ISP_IN: usize = 2 * DIGEST;
pub const PUB_ISP_OUT: usize = PUB_ISP_IN + WIDTH;
pub const PUB_OSP_IN: usize = PUB_ISP_OUT + WIDTH;
pub const PUB_OSP_OUT: usize = PUB_OSP_IN + WIDTH;
pub const PUB_POS_IN: usize = PUB_OSP_OUT + WIDTH; // lo, hi
pub const PUB_POS_OUT: usize = PUB_POS_IN + 2;
pub const PUB_SUM_IN: usize = PUB_POS_OUT + 2;
pub const PUB_SUM_OUT: usize = PUB_SUM_IN + LIMBS;
pub const PUB_CARRY_IN: usize = PUB_SUM_OUT + LIMBS;
pub const PUB_CARRY_OUT: usize = PUB_CARRY_IN + CARRY_LEN;
pub const NUM_PUBLIC: usize = PUB_CARRY_OUT + CARRY_LEN;

/// Layout of a carry: open flag, message, body sponge, items left.
pub const CARRY_OPEN: usize = 0;
pub const CARRY_MSG: usize = 1;
pub const CARRY_BSP: usize = CARRY_MSG + DIGEST;
pub const CARRY_IN_LEFT: usize = CARRY_BSP + WIDTH;
pub const CARRY_OUT_LEFT: usize = CARRY_IN_LEFT + 1;
pub const CARRY_LEN: usize = CARRY_OUT_LEFT + 1;

/// Rows of one input (signature plus commitment, tree update and body).
pub const ROWS_PER_INPUT: usize = 3 + CHAINS * (2 + STEPS) + 2 * HEIGHT + 5 + 1 + 2 * DEPTH + 2;
/// Rows of one output.
pub const ROWS_PER_OUTPUT: usize = 8 + 2 * DEPTH;

/// Body elements per input and per output (see
/// `crate::transaction::body_elements`).
const BODY_PER_INPUT: u32 = 16;
const BODY_PER_OUTPUT: u32 = 24;

/// Body sponge state after a transaction's header block.
pub fn body_init(n_in: u32, n_out: u32) -> [Fp; WIDTH] {
    let mut input = [Fp::ZERO; WIDTH];
    input[0] = Fp::new(n_in);
    input[1] = Fp::new(n_out);
    input[RATE..].copy_from_slice(&cap_const::<Fp>(DOM_BODY, 8 + BODY_PER_INPUT * n_in + BODY_PER_OUTPUT * n_out));
    permute(input)
}

fn absorb_block(state: &mut [Fp; WIDTH], block: &[Fp]) {
    for (s, x) in state.iter_mut().zip(block) {
        *s = s.add(x);
    }
    *state = permute(*state);
}

/// Absorbs one input (key root, then seed and amount) into a body sponge.
pub fn body_absorb_input(state: &mut [Fp; WIDTH], pubkey: &PublicKey, amount: u64) {
    absorb_block(state, &pubkey.root);
    let mut blk = [Fp::ZERO; RATE];
    blk[..PUB_SEED_LEN].copy_from_slice(&pubkey.pub_seed);
    blk[PUB_SEED_LEN..PUB_SEED_LEN + 3].copy_from_slice(&amount_fps(amount));
    absorb_block(state, &blk);
}

/// Absorbs one output (commitment, then amount) into a body sponge.
pub fn body_absorb_output(state: &mut [Fp; WIDTH], output: &Output) {
    absorb_block(state, &output.commitment);
    absorb_block(state, &amt_block(output.amount));
    absorb_block(state, &output.memo);
}

fn pow2<F: Field>(k: usize) -> F {
    F::from_u32(1 << k)
}

fn cap_const<F: Field>(domain: u32, len: u32) -> [F; RATE] {
    let mut c = [F::ZERO; RATE];
    c[0] = F::from_u32(domain);
    c[1] = F::from_u32(len);
    c
}

/// Initial state of the inputs sponge.
pub fn initial_inputs_state() -> [Fp; WIDTH] {
    let mut state = [Fp::ZERO; WIDTH];
    state[RATE] = Fp::new(DOM_INPUTS);
    state
}

/// Initial state of the outputs sponge.
pub fn initial_outputs_state() -> [Fp; WIDTH] {
    let mut state = [Fp::ZERO; WIDTH];
    state[RATE] = Fp::new(DOM_OUTPUTS);
    state
}

/// Absorbs one input position into the inputs sponge.
pub fn absorb_position(state: &mut [Fp; WIDTH], position: u64) {
    state[0] = state[0].add(&Fp::new((position & MASK30) as u32));
    state[1] = state[1].add(&Fp::new((position >> 30) as u32));
    *state = permute(*state);
}

/// Absorbs one output's commitment, then its memo, into the outputs
/// sponge. Amounts stay off chain.
pub fn absorb_output(state: &mut [Fp; WIDTH], commitment: &Commitment, memo: &Memo) {
    absorb_block(state, commitment);
    absorb_block(state, memo);
}

/// Inputs sponge state after absorbing all of a block's positions.
pub fn inputs_state(positions: &[u64]) -> [Fp; WIDTH] {
    let mut state = initial_inputs_state();
    for &p in positions {
        absorb_position(&mut state, p);
    }
    state
}

/// Outputs sponge state after absorbing all of a block's outputs.
pub fn outputs_state(outputs: &[BlockOutput]) -> [Fp; WIDTH] {
    let mut state = initial_outputs_state();
    for o in outputs {
        absorb_output(&mut state, &o.commitment, &o.memo);
    }
    state
}

/// Splits a `u64` into four 16-bit limbs, least significant first.
pub fn limbs16(v: u64) -> [Fp; LIMBS] {
    limbs16_wide(v as u128)
}

/// As [`limbs16`] for a sum below `2^96`.
pub fn limbs16_wide(v: u128) -> [Fp; LIMBS] {
    assert!(v >> (16 * LIMBS) == 0, "sum out of range");
    core::array::from_fn(|j| Fp::new(((v >> (16 * j)) & 0xffff) as u32))
}

// ---------------------------------------------------------------------------
// Constraints
// ---------------------------------------------------------------------------

pub struct BlockAir;

impl Air for BlockAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    #[allow(clippy::needless_range_loop)]
    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        eval_hash_machine(b);
        let l = b.local();
        let n = b.next();
        let public = b.public();
        let one = F::ONE;
        let pubv = |i: usize| -> F { public[i] };

        // ---------------- row types ----------------
        b.mark("row types");
        let types: [F; NUM_TYPES] = core::array::from_fn(|i| l[T_TX_START + i]);
        for t in types {
            b.assert_zero(t * t - t);
        }
        b.assert_eq(types.iter().fold(F::ZERO, |a, t| a + *t), one);
        let tx_start = l[T_TX_START];
        let tx_end = l[T_TX_END];
        let msg_start = l[T_MSG_START];
        let msg_abs = l[T_MSG_ABS];
        let load = l[T_LOAD];
        let step = l[T_STEP];
        let leaf = l[T_LEAF];
        let tree_start = l[T_TREE_START];
        let tree_abs = l[T_TREE_ABS];
        let pkh0 = l[T_PKH0];
        let pkh1 = l[T_PKH1];
        let cm0 = l[T_CM0];
        let cm1 = l[T_CM1];
        let ilist = l[T_ILIST];
        let old_t = l[T_OLD];
        let new_t = l[T_NEW];
        let body_in0 = l[T_BODY_IN0];
        let body_in1 = l[T_BODY_IN1];
        let ocm0 = l[T_OCM0];
        let ocm1 = l[T_OCM1];
        let olist = l[T_OLIST];
        let body_out0 = l[T_BODY_OUT0];
        let body_out1 = l[T_BODY_OUT1];
        let olist2 = l[T_OLIST2];
        let body_out2 = l[T_BODY_OUT2];
        let ileaf = l[T_ILEAF];
        let oleaf = l[T_OLEAF];
        let done = l[T_DONE];
        let resume = l[T_RESUME];
        let active = l[C_ACTIVE];
        b.assert_zero(active * active - active);
        b.assert_zero(active * (one - step));

        // machine op mapping
        b.assert_eq(
            l[COL_START],
            tx_start
                + msg_start
                + leaf
                + tree_start
                + pkh0
                + cm0
                + ilist
                + old_t
                + new_t
                + body_in0
                + ocm0
                + olist
                + body_out0
                + ileaf
                + oleaf,
        );
        b.assert_eq(l[COL_ABSORB], msg_abs + tree_abs + pkh1 + cm1 + body_in1 + ocm1 + olist2 + body_out1 + body_out2);
        b.assert_eq(l[COL_LOAD], load);
        b.assert_eq(l[COL_CHAIN], step * active);
        b.assert_eq(l[COL_PASS], step * (one - active) + tx_end + done + resume);
        b.assert_zero(l[COL_COMPRESS]);
        b.when_first_row(one - tx_start - resume);
        b.when_last_row(one - done);

        // ---------------- counters and gadgets ----------------
        b.mark("counters");
        let ssel: [F; STEPS] = core::array::from_fn(|i| l[C_SSEL + i]);
        let ksel: [F; DIGITS_PER_ELEMENT] = core::array::from_fn(|i| l[C_KSEL + i]);
        let esel: [F; ELEMENTS] = core::array::from_fn(|i| l[C_ESEL + i]);
        let lsel: [F; HEIGHT] = core::array::from_fn(|i| l[C_LSEL + i]);
        for v in ssel.iter().chain(&ksel).chain(&esel).chain(&lsel) {
            b.assert_zero(*v * *v - *v);
        }
        b.assert_eq(ssel.iter().fold(F::ZERO, |a, v| a + *v), step);
        b.assert_eq(ksel.iter().fold(F::ZERO, |a, v| a + *v), one);
        b.assert_eq(esel.iter().fold(F::ZERO, |a, v| a + *v), one);
        b.assert_eq(lsel.iter().fold(F::ZERO, |a, v| a + *v), tree_start + tree_abs);
        let mc = l[C_MC];
        b.assert_zero(mc * mc - mc);
        b.assert_zero(mc * (one - msg_abs));
        let last = l[C_LAST];
        b.assert_eq(last, esel[ELEMENTS - 1] * ksel[CSUM_CHAINS - 1]);
        for (i, k) in ksel.iter().enumerate() {
            b.assert_zero(msg_start * (*k - if i == DIGITS_PER_ELEMENT - 1 { one } else { F::ZERO }));
        }
        for (e, v) in esel.iter().enumerate() {
            b.assert_zero(msg_start * (*v - if e == ELEMENTS - 1 { one } else { F::ZERO }));
        }
        // tree-update level gadget
        let level = l[C_LEVEL];
        let is_last = l[C_IS_LAST];
        let last_level = F::from_u32((DEPTH - 1) as u32);
        b.assert_zero(is_last * is_last - is_last);
        b.assert_zero(is_last * (level - last_level));
        b.assert_eq((level - last_level) * l[C_LEVEL_INV], one - is_last);
        let smt_end = l[C_SMT_END];
        b.assert_eq(smt_end, new_t * is_last);
        let is_out = l[R_IS_OUT];
        b.assert_zero(is_out * is_out - is_out);
        let out_end = l[C_OUT_END];
        b.assert_eq(out_end, smt_end * is_out);
        // remaining-item counters and zero tests
        let in_left = l[R_IN_LEFT];
        let out_left = l[R_OUT_LEFT];
        let in_zero = l[C_IN_ZERO];
        let out_zero = l[C_OUT_ZERO];
        b.assert_zero(in_zero * in_zero - in_zero);
        b.assert_zero(out_zero * out_zero - out_zero);
        b.assert_eq(in_left * l[C_IN_INV], one - in_zero);
        b.assert_zero(in_zero * in_left);
        b.assert_eq(out_left * l[C_OUT_INV], one - out_zero);
        b.assert_zero(out_zero * out_left);
        let go_out = l[C_GO_OUT];
        let go_end = l[C_GO_END];
        b.assert_eq(go_out, in_zero * (one - out_zero));
        b.assert_eq(go_end, in_zero * out_zero);

        // ---------------- schedule ----------------
        b.mark("schedule");
        let nt = |t: usize| n[t];
        // dispatch after tx_start, after an input (body_in1), after an output (out_end)
        // (and after a resume); or into the done rows, leaving the
        // transaction open.
        let disp = tx_start + body_in1 + out_end + resume;
        b.when_transition(disp * (one - in_zero) * (one - nt(T_MSG_START) - nt(T_DONE)));
        b.when_transition(disp * go_out * (one - nt(T_OCM0) - nt(T_DONE)));
        b.when_transition(disp * go_end * (one - nt(T_TX_END) - nt(T_DONE)));
        // A resume is only ever the first row.
        b.when_transition(nt(T_RESUME));
        b.when_first_row(resume - pubv(PUB_CARRY_IN + CARRY_OPEN));
        // open: one from a start or resume until the row after the end
        let open = l[R_OPEN];
        b.assert_zero(open * open - open);
        b.when_first_row(one - open);
        b.when_transition(tx_end * (n[R_OPEN] - nt(T_TX_START)));
        b.when_transition(nt(T_TX_START) * (one - n[R_OPEN]));
        b.when_transition((one - tx_end - nt(T_TX_START)) * (n[R_OPEN] - open));
        b.when_last_row(open - pubv(PUB_CARRY_OUT + CARRY_OPEN));
        b.when_transition(tx_end * (one - nt(T_TX_START) - nt(T_DONE)));
        b.when_transition(done * (one - nt(T_DONE)));
        // xmss
        b.when_transition(msg_start * (one - nt(T_MSG_ABS)));
        b.when_transition(msg_start * n[C_MC]);
        b.when_transition(msg_abs * (one - mc) * (one - nt(T_MSG_ABS)));
        b.when_transition(msg_abs * (one - mc) * (one - n[C_MC]));
        b.when_transition(msg_abs * mc * (one - nt(T_LOAD)));
        b.when_transition(load * (one - nt(T_STEP)));
        b.when_transition(load * (one - n[C_SSEL]));
        let s_last = ssel[STEPS - 1];
        b.when_transition(step * (one - s_last) * (one - nt(T_STEP)));
        for i in 1..STEPS {
            b.when_transition(step * (n[C_SSEL + i] - ssel[i - 1]));
        }
        b.when_transition(step * s_last * (one - nt(T_LEAF)));
        b.when_transition(leaf * (nt(T_LOAD) - (one - last)));
        b.when_transition(leaf * (nt(T_TREE_START) - last));
        b.when_transition(leaf * last * (one - n[C_LSEL]));
        b.when_transition(tree_start * (one - nt(T_TREE_ABS)));
        for i in 0..HEIGHT {
            b.when_transition(tree_start * (n[C_LSEL + i] - lsel[i]));
        }
        let l_last = lsel[HEIGHT - 1];
        b.when_transition(tree_abs * (one - l_last) * (one - nt(T_TREE_START)));
        for i in 1..HEIGHT {
            b.when_transition(tree_abs * (n[C_LSEL + i] - lsel[i - 1]));
        }
        b.when_transition(tree_abs * l_last * (one - nt(T_PKH0)));
        // input tail
        b.when_transition(pkh0 * (one - nt(T_PKH1)));
        b.when_transition(pkh1 * (one - nt(T_CM0)));
        b.when_transition(cm0 * (one - nt(T_CM1)));
        b.when_transition(cm1 * (one - nt(T_ILEAF)));
        b.when_transition(ileaf * (one - nt(T_ILIST)));
        b.when_transition(ilist * (one - nt(T_OLD)));
        b.when_transition(ilist * n[C_LEVEL]);
        b.when_transition(old_t * (one - nt(T_NEW)));
        b.when_transition(old_t * (n[C_LEVEL] - level));
        b.when_transition(new_t * (one - is_last) * (one - nt(T_OLD)));
        b.when_transition(new_t * (one - is_last) * (n[C_LEVEL] - level - one));
        b.when_transition(smt_end * (one - is_out) * (one - nt(T_BODY_IN0)));
        b.when_transition(body_in0 * (one - nt(T_BODY_IN1)));
        // output
        b.when_transition(ocm0 * (one - nt(T_OCM1)));
        b.when_transition(ocm1 * (one - nt(T_OLEAF)));
        b.when_transition(oleaf * (one - nt(T_OLIST)));
        b.when_transition(olist * (one - nt(T_OLIST2)));
        b.when_transition(olist2 * (one - nt(T_BODY_OUT0)));
        b.when_transition(body_out0 * (one - nt(T_BODY_OUT1)));
        b.when_transition(body_out1 * (one - nt(T_BODY_OUT2)));
        b.when_transition(body_out2 * (one - nt(T_OLD)));
        b.when_transition(body_out2 * n[C_LEVEL]);
        // is_out: 1 from ocm0 until the output ends, 0 on inputs and tx start
        b.assert_zero(ocm0 * (one - is_out));
        b.assert_zero(msg_start * is_out);
        b.assert_zero(tx_start * is_out);
        b.when_transition((one - nt(T_OCM0) - nt(T_MSG_START) - nt(T_TX_START)) * (n[R_IS_OUT] - is_out));
        // item counters
        b.when_transition(nt(T_MSG_START) * (n[R_IN_LEFT] - in_left + one));
        b.when_transition((one - nt(T_MSG_START) - nt(T_TX_START)) * (n[R_IN_LEFT] - in_left));
        b.when_transition(nt(T_OCM0) * (n[R_OUT_LEFT] - out_left + one));
        b.when_transition((one - nt(T_OCM0) - nt(T_TX_START)) * (n[R_OUT_LEFT] - out_left));
        b.assert_zero(tx_end * in_left);
        b.assert_zero(tx_end * out_left);
        // Carries: the open transaction's state on the resume row and at
        // the end (carried there through the done rows), zero when closed.
        let carried = |c: usize| -> F {
            match c {
                CARRY_IN_LEFT => in_left,
                CARRY_OUT_LEFT => out_left,
                c if c < CARRY_BSP => l[R_MSG + c - CARRY_MSG],
                c => l[R_BSP + c - CARRY_BSP],
            }
        };
        for c in CARRY_MSG..CARRY_LEN {
            b.when_first_row(resume * carried(c) - pubv(PUB_CARRY_IN + c));
            b.when_last_row(open * carried(c) - pubv(PUB_CARRY_OUT + c));
        }

        // ---------------- xmss: digit selectors rotate on load rows ----------------
        b.mark("digit selectors");
        for i in 0..DIGITS_PER_ELEMENT {
            let prev = ksel[(i + DIGITS_PER_ELEMENT - 1) % DIGITS_PER_ELEMENT];
            b.when_transition(nt(T_LOAD) * (n[C_KSEL + i] - prev));
            b.when_transition((one - nt(T_LOAD) - nt(T_MSG_START)) * (n[C_KSEL + i] - ksel[i]));
        }
        let wrap_k = ksel[DIGITS_PER_ELEMENT - 1];
        for e in 0..ELEMENTS {
            let prev = esel[(e + ELEMENTS - 1) % ELEMENTS];
            b.when_transition(nt(T_LOAD) * (n[C_ESEL + e] - (esel[e] + wrap_k * (prev - esel[e]))));
            b.when_transition((one - nt(T_LOAD) - nt(T_MSG_START)) * (n[C_ESEL + e] - esel[e]));
        }

        // ---------------- registers: key, index, amount bits ----------------
        b.mark("key/index/amount registers");
        let pub_seed: [F; PUB_SEED_LEN] = core::array::from_fn(|i| l[R_PUB_SEED + i]);
        for i in 0..PUB_SEED_LEN {
            b.when_transition((one - nt(T_MSG_START)) * (n[R_PUB_SEED + i] - pub_seed[i]));
        }
        let idx_bits: [F; HEIGHT] = core::array::from_fn(|i| l[R_IDX + i]);
        let mut idx = F::ZERO;
        for (i, bit) in idx_bits.iter().enumerate() {
            b.assert_zero(*bit * *bit - *bit);
            b.when_transition((one - nt(T_MSG_START)) * (n[R_IDX + i] - *bit));
            idx += *bit * pow2::<F>(i);
        }
        let abits: [F; AMOUNT_BITS] = core::array::from_fn(|i| l[R_ABITS + i]);
        let (mut amt_lo, mut amt_mid, mut amt_hi) = (F::ZERO, F::ZERO, F::ZERO);
        let mut l16 = [F::ZERO; LIMBS];
        for (i, bit) in abits.iter().enumerate() {
            b.assert_zero(*bit * *bit - *bit);
            b.when_transition((one - nt(T_MSG_START) - nt(T_OCM0)) * (n[R_ABITS + i] - *bit));
            if i < 30 {
                amt_lo += *bit * pow2::<F>(i);
            } else if i < 60 {
                amt_mid += *bit * pow2::<F>(i - 30);
            } else {
                amt_hi += *bit * pow2::<F>(i - 60);
            }
            l16[i / 16] += *bit * pow2::<F>(i % 16);
        }
        let msg: [F; DIGEST] = core::array::from_fn(|i| l[R_MSG + i]);
        for i in 0..DIGEST {
            b.when_transition((one - nt(T_TX_START)) * (n[R_MSG + i] - msg[i]));
            b.when_transition((one - nt(T_OCM0)) * (n[R_OCM + i] - l[R_OCM + i]));
            b.when_transition((one - nt(T_OCM0) - nt(T_MSG_START)) * (n[R_MEMO + i] - l[R_MEMO + i]));
            // Leaves: the commitment just hashed and the memo, compressed.
            b.when_transition(nt(T_ILEAF) * (n[COL_INPUT + i] - l[COL_ACC + i]));
            b.assert_zero(ileaf * (l[COL_INPUT + RATE + i] - l[R_MEMO + i]));
            b.assert_zero(oleaf * (l[COL_INPUT + i] - l[R_OCM + i]));
            b.assert_zero(oleaf * (l[COL_INPUT + RATE + i] - l[R_MEMO + i]));
            b.when_transition(oleaf * (n[R_LEAF + i] - l[COL_ACC + i]));
            b.when_transition((one - oleaf) * (n[R_LEAF + i] - l[R_LEAF + i]));
            b.assert_zero((olist2 + body_out2) * (l[COL_DATA + i] - l[R_MEMO + i]));
            // pkroot: set entering pkh0 from the tree root, else copied
            b.when_transition(nt(T_PKH0) * (n[R_PKROOT + i] - l[COL_ACC + i]));
            b.when_transition((one - nt(T_PKH0)) * (n[R_PKROOT + i] - l[R_PKROOT + i]));
        }

        // ---------------- xmss: bits, digit, checksum ----------------
        b.mark("xmss digits");
        let bits: [F; BITS] = core::array::from_fn(|i| l[C_BITS + i]);
        let mut value = F::ZERO;
        let mut low27 = F::ZERO;
        let mut high12 = F::ZERO;
        for (i, bit) in bits.iter().enumerate() {
            b.assert_zero(*bit * *bit - *bit);
            value += *bit * pow2::<F>(i);
            if i < 27 {
                low27 += *bit * pow2::<F>(i);
            }
            if i >= 12 {
                high12 += *bit;
            }
        }
        let t3 = l[C_T3];
        b.assert_eq(t3, bits[30] * bits[29] * bits[28]);
        b.assert_zero(t3 * bits[27] * low27);
        let mut elem = F::ZERO;
        for e in 0..DIGEST {
            elem += esel[e] * l[R_M + e];
        }
        elem += esel[DIGEST] * l[C_CSUM];
        b.assert_zero(load * (value - elem));
        b.assert_zero(esel[DIGEST] * high12);
        let mut d = F::ZERO;
        for k in 0..DIGITS_PER_ELEMENT {
            let mut nib = F::ZERO;
            let width = if k == DIGITS_PER_ELEMENT - 1 { 3 } else { 4 };
            for j in 0..width {
                nib += bits[4 * k + j] * pow2::<F>(j);
            }
            d += ksel[k] * nib;
        }
        let dcol = l[C_D];
        b.assert_eq(dcol, d);
        let fifteen = F::from_u32((W - 1) as u32);
        // Accumulates after each message chain's load row; resets to zero
        // entering a new signature.
        b.when_transition(
            n[C_CSUM] - l[C_CSUM] - load * (one - esel[DIGEST]) * (fifteen - dcol) + nt(T_MSG_START) * l[C_CSUM],
        );
        b.assert_zero(msg_start * l[C_CSUM]);
        // chain control
        b.mark("chain control");
        let rem = l[C_REM];
        b.assert_zero(load * (rem - dcol));
        b.when_transition(load * (n[C_REM] - rem));
        b.assert_zero(step * active * rem);
        b.assert_zero(step * ((one - active) - rem * l[C_REM_INV]));
        b.when_transition(step * (n[C_REM] - rem + (one - active)));
        let mut chain_idx = F::ZERO;
        for (e, v) in esel.iter().enumerate() {
            chain_idx += *v * F::from_u32((e * DIGITS_PER_ELEMENT) as u32);
        }
        for (k, v) in ksel.iter().enumerate() {
            chain_idx += *v * F::from_u32(k as u32);
        }
        let mut step_idx = F::ZERO;
        for (i, v) in ssel.iter().enumerate() {
            step_idx += *v * F::from_u32(i as u32);
        }
        let chain_cap = [
            pub_seed[0],
            pub_seed[1],
            pub_seed[2],
            pub_seed[3],
            F::from_u32(DOM_WOTS_CHAIN),
            idx,
            F::ZERO,
            chain_idx + step_idx * F::from_u32(1 << 16),
        ];
        for (j, c) in chain_cap.iter().enumerate() {
            b.assert_zero(step * active * (l[COL_DATA + j] - *c));
        }
        // message digest sponge (message from the register)
        b.mark("message sponge");
        let msg_cap = [pub_seed[0], pub_seed[1], pub_seed[2], pub_seed[3], F::from_u32(DOM_MSG), idx, F::ZERO, F::ZERO];
        for (j, c) in msg_cap.iter().enumerate() {
            b.assert_zero(msg_start * (l[COL_INPUT + RATE + j] - *c));
        }
        let block0: [F; RATE] = core::array::from_fn(|i| if i == 0 { F::from_u32(DIGEST as u32) } else { msg[i - 1] });
        let block1: [F; RATE] = core::array::from_fn(|i| if i == 0 { msg[DIGEST - 1] } else { F::ZERO });
        for i in 0..RATE {
            b.assert_zero(msg_abs * (l[COL_DATA + i] - ((one - mc) * block0[i] + mc * block1[i])));
        }
        for i in 0..DIGEST {
            b.when_transition(msg_abs * mc * (n[R_M + i] - l[COL_ACC + i]));
            b.when_transition((one - msg_abs * mc) * (n[R_M + i] - l[R_M + i]));
        }
        // leaf sponge
        b.mark("leaf sponge");
        let sp_init: [F; WIDTH] = core::array::from_fn(|j| match j {
            j if j < RATE => F::ZERO,
            j if j < RATE + PUB_SEED_LEN => pub_seed[j - RATE],
            j if j == RATE + PUB_SEED_LEN => F::from_u32(DOM_WOTS_PK),
            j if j == RATE + PUB_SEED_LEN + 1 => idx,
            _ => F::ZERO,
        });
        for j in 0..WIDTH {
            b.assert_zero(msg_start * (l[R_SP + j] - sp_init[j]));
            b.when_transition(leaf * (n[R_SP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - leaf - nt(T_MSG_START)) * (n[R_SP + j] - l[R_SP + j]));
        }
        for i in 0..RATE {
            b.when_transition(nt(T_LEAF) * (n[COL_INPUT + i] - n[R_SP + i] - l[COL_ACC + i]));
            b.when_transition(nt(T_LEAF) * (n[COL_INPUT + RATE + i] - n[R_SP + RATE + i]));
        }
        // xmss tree levels
        b.mark("xmss tree");
        let dir = l[COL_DIR];
        let mut dir_want = F::ZERO;
        let mut pos = F::ZERO;
        let mut level_plus_one = F::ZERO;
        for (lv, sel) in lsel.iter().enumerate() {
            dir_want += *sel * idx_bits[lv];
            let mut p = pow2::<F>(HEIGHT - 1 - lv);
            for (i, bit) in idx_bits.iter().enumerate().skip(lv + 1) {
                p += *bit * pow2::<F>(i - lv - 1);
            }
            pos += *sel * p;
            level_plus_one += *sel * F::from_u32((lv + 1) as u32);
        }
        b.assert_zero(tree_start * (dir - dir_want));
        b.when_transition(tree_start * (n[COL_DIR] - dir));
        for i in 0..DIGEST {
            b.when_transition(nt(T_TREE_START) * (n[R_NODE + i] - l[COL_ACC + i]));
            b.when_transition((one - nt(T_TREE_START)) * (n[R_NODE + i] - l[R_NODE + i]));
            b.when_transition(tree_start * (n[R_SIB + i] - l[R_SIB + i]));
            let node = l[R_NODE + i];
            let sib = l[R_SIB + i];
            b.assert_zero(tree_start * (l[COL_INPUT + i] - ((one - dir) * node + dir * sib)));
            b.assert_zero(tree_abs * (l[COL_DATA + i] - ((one - dir) * sib + dir * node)));
        }
        let tree_cap =
            [pub_seed[0], pub_seed[1], pub_seed[2], pub_seed[3], F::from_u32(DOM_TREE), pos, F::ZERO, level_plus_one];
        for (j, c) in tree_cap.iter().enumerate() {
            b.assert_zero(tree_start * (l[COL_INPUT + RATE + j] - *c));
        }

        // ---------------- key hash and commitment ----------------
        b.mark("key hash / commitment / amounts");
        let cap_pk = cap_const::<F>(DOM_PUBKEY, (DIGEST + PUB_SEED_LEN) as u32);
        let cap_cm = cap_const::<F>(DOM_COMMITMENT, (DIGEST + 3) as u32);
        for i in 0..RATE {
            b.when_transition(nt(T_PKH0) * (n[COL_INPUT + i] - l[COL_ACC + i]));
            b.when_transition(nt(T_CM0) * (n[COL_INPUT + i] - l[COL_ACC + i]));
            b.assert_zero(pkh0 * (l[COL_INPUT + RATE + i] - cap_pk[i]));
            b.assert_zero(cm0 * (l[COL_INPUT + RATE + i] - cap_cm[i]));
            // An output's commitment is H(key_hash || amount) with the key
            // hash a free witness, so the amount summed is the one it hides.
            b.assert_zero(ocm0 * (l[COL_INPUT + RATE + i] - cap_cm[i]));
            b.assert_zero(ocm1 * (l[COL_ACC + i] - l[R_OCM + i]));
            let pkh1_data = if i < PUB_SEED_LEN { pub_seed[i] } else { F::ZERO };
            b.assert_zero(pkh1 * (l[COL_DATA + i] - pkh1_data));
            let amt_block = [amt_lo, amt_mid, amt_hi, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO];
            b.assert_zero(cm1 * (l[COL_DATA + i] - amt_block[i]));
            b.assert_zero(ocm1 * (l[COL_DATA + i] - amt_block[i]));
            b.assert_zero(body_out1 * (l[COL_DATA + i] - amt_block[i]));
            let body_in1_data = [pub_seed[0], pub_seed[1], pub_seed[2], pub_seed[3], amt_lo, amt_mid, amt_hi, F::ZERO];
            b.assert_zero(body_in1 * (l[COL_DATA + i] - body_in1_data[i]));
        }
        // amount sums: zero at the start of the segment, exported at the end
        for j in 0..LIMBS {
            b.when_transition(n[R_SUM_IN + j] - l[R_SUM_IN + j] - cm1 * l16[j]);
            b.when_transition(n[R_SUM_OUT + j] - l[R_SUM_OUT + j] - olist * l16[j]);
            b.when_first_row(l[R_SUM_IN + j]);
            b.when_first_row(l[R_SUM_OUT + j]);
            b.when_last_row(l[R_SUM_IN + j] - pubv(PUB_SUM_IN + j));
            b.when_last_row(l[R_SUM_OUT + j] - pubv(PUB_SUM_OUT + j));
        }

        // ---------------- tree update registers ----------------
        b.mark("tree update");
        let pbits: [F; DEPTH] = core::array::from_fn(|i| l[R_PBITS + i]);
        let (mut pos_lo, mut pos_hi) = (F::ZERO, F::ZERO);
        let (mut npos_lo, mut npos_hi) = (F::ZERO, F::ZERO);
        for (i, bit) in pbits.iter().enumerate() {
            b.assert_zero(*bit * *bit - *bit);
            if i < 30 {
                pos_lo += *bit * pow2::<F>(i);
                npos_lo += n[R_PBITS + i] * pow2::<F>(i);
            } else {
                pos_hi += *bit * pow2::<F>(i - 30);
                npos_hi += n[R_PBITS + i] * pow2::<F>(i - 30);
            }
            let shifted = if i + 1 < DEPTH { pbits[i + 1] } else { F::ZERO };
            b.when_transition(new_t * (one - is_last) * (n[R_PBITS + i] - shifted));
            b.when_transition((one - new_t - nt(T_ILIST) - body_out2) * (n[R_PBITS + i] - *bit));
        }
        // output position: decomposed into the path bits entering the insert
        b.when_transition(body_out2 * (npos_lo - l[R_OPOS_LO]));
        b.when_transition(body_out2 * (npos_hi - l[R_OPOS_HI]));
        let wrap = l[C_WRAP];
        let lo_max = F::from_u32((1u32 << 30) - 1);
        b.assert_zero(wrap * wrap - wrap);
        b.assert_zero(wrap * (l[R_OPOS_LO] - lo_max));
        b.assert_eq((l[R_OPOS_LO] - lo_max) * l[C_WRAP_INV], one - wrap);
        b.when_transition(out_end * (n[R_OPOS_LO] - (one - wrap) * (l[R_OPOS_LO] + one)));
        b.when_transition(out_end * (n[R_OPOS_HI] - l[R_OPOS_HI] - wrap));
        b.when_transition((one - out_end) * (n[R_OPOS_LO] - l[R_OPOS_LO]));
        b.when_transition((one - out_end) * (n[R_OPOS_HI] - l[R_OPOS_HI]));
        b.when_first_row(l[R_OPOS_LO] - pubv(PUB_POS_IN));
        b.when_first_row(l[R_OPOS_HI] - pubv(PUB_POS_IN + 1));
        b.when_last_row(l[R_OPOS_LO] - pubv(PUB_POS_OUT));
        b.when_last_row(l[R_OPOS_HI] - pubv(PUB_POS_OUT + 1));
        b.assert_zero(old_t * (dir - pbits[0]));
        b.when_transition(old_t * (n[COL_DIR] - dir));
        for i in 0..DIGEST {
            let (o, nw, sib, root, acc, out) =
                (l[R_OLD + i], l[R_NEW + i], l[R_SIB + i], l[R_ROOT + i], l[COL_ACC + i], l[COL_OUTPUT + i]);
            // old: commitment entering ilist, zero entering an output insert, output after old rows
            b.when_transition(nt(T_ILIST) * (n[R_OLD + i] - acc));
            b.when_transition(body_out2 * n[R_OLD + i]);
            b.when_transition(old_t * (n[R_OLD + i] - out));
            b.when_transition((one - old_t - nt(T_ILIST) - body_out2 - smt_end) * (n[R_OLD + i] - o));
            // new: zero on ilist, the output commitment entering an insert, output after new rows
            b.assert_zero(ilist * nw);
            b.when_transition(body_out2 * (n[R_NEW + i] - l[R_LEAF + i]));
            b.when_transition(new_t * (one - is_last) * (n[R_NEW + i] - out));
            b.when_transition((one - new_t - body_out2 - nt(T_ILIST)) * (n[R_NEW + i] - nw));
            // sibling: witness on old rows, copied to the new row
            b.when_transition(old_t * (n[R_SIB + i] - sib));
            // root
            b.assert_zero(old_t * is_last * (acc - root));
            b.when_transition(smt_end * (n[R_ROOT + i] - acc));
            b.when_transition((one - smt_end) * (n[R_ROOT + i] - root));
            b.when_first_row(root - pubv(PUB_ROOT_IN + i));
            b.when_last_row(root - pubv(PUB_ROOT_OUT + i));
            // compress inputs
            let inp_lo = l[COL_INPUT + i];
            let inp_hi = l[COL_INPUT + RATE + i];
            b.assert_zero(old_t * (inp_lo - ((one - dir) * o + dir * sib)));
            b.assert_zero(old_t * (inp_hi - ((one - dir) * sib + dir * o)));
            b.assert_zero(new_t * (inp_lo - ((one - dir) * nw + dir * sib)));
            b.assert_zero(new_t * (inp_hi - ((one - dir) * sib + dir * nw)));
        }

        // ---------------- register sponges: body, inputs, outputs ----------------
        b.mark("register sponges");
        let body_len = F::from_u32(8) + in_left * F::from_u32(BODY_PER_INPUT) + out_left * F::from_u32(BODY_PER_OUTPUT);
        let bsp_rows = tx_start + body_in0 + body_in1 + body_out0 + body_out1 + body_out2;
        let osp_rows = olist + olist2;
        for j in 0..WIDTH {
            b.when_transition(bsp_rows * (n[R_BSP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - bsp_rows) * (n[R_BSP + j] - l[R_BSP + j]));
            b.when_transition(ilist * (n[R_ISP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - ilist) * (n[R_ISP + j] - l[R_ISP + j]));
            b.when_transition(osp_rows * (n[R_OSP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - osp_rows) * (n[R_OSP + j] - l[R_OSP + j]));
            b.when_first_row(l[R_ISP + j] - pubv(PUB_ISP_IN + j));
            b.when_first_row(l[R_OSP + j] - pubv(PUB_OSP_IN + j));
            b.when_last_row(l[R_ISP + j] - pubv(PUB_ISP_OUT + j));
            b.when_last_row(l[R_OSP + j] - pubv(PUB_OSP_OUT + j));
        }
        for i in 0..RATE {
            // tx_start: body header block with the body capacity
            let header = if i == 0 {
                in_left
            } else if i == 1 {
                out_left
            } else {
                F::ZERO
            };
            b.assert_zero(tx_start * (l[COL_INPUT + i] - header));
            let cap_body = [F::from_u32(DOM_BODY), body_len, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO];
            b.assert_zero(tx_start * (l[COL_INPUT + RATE + i] - cap_body[i]));
            // body_in0 / body_out0 / olist0 / ilist: start rows continuing a register sponge
            b.assert_zero(body_in0 * (l[COL_INPUT + i] - l[R_BSP + i] - l[R_PKROOT + i]));
            b.assert_zero(body_in0 * (l[COL_INPUT + RATE + i] - l[R_BSP + RATE + i]));
            b.assert_zero(body_out0 * (l[COL_INPUT + i] - l[R_BSP + i] - l[R_OCM + i]));
            b.assert_zero(body_out0 * (l[COL_INPUT + RATE + i] - l[R_BSP + RATE + i]));
            b.assert_zero(olist * (l[COL_INPUT + i] - l[R_OSP + i] - l[R_OCM + i]));
            b.assert_zero(olist * (l[COL_INPUT + RATE + i] - l[R_OSP + RATE + i]));
            let ilist_block = if i == 0 {
                pos_lo
            } else if i == 1 {
                pos_hi
            } else {
                F::ZERO
            };
            b.assert_zero(ilist * (l[COL_INPUT + i] - l[R_ISP + i] - ilist_block));
            b.assert_zero(ilist * (l[COL_INPUT + RATE + i] - l[R_ISP + RATE + i]));
            // tx_end: body digest equals the signed message
            b.assert_zero(tx_end * (l[R_BSP + i] - msg[i]));
        }
    }
}

// ---------------------------------------------------------------------------
// Witness
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputWitness {
    pub pubkey: PublicKey,
    pub amount: u64,
    /// Memo of the output being spent, part of its leaf.
    pub memo: Memo,
    pub signature: Sig,
    pub position: u64,
    pub siblings: [Digest; DEPTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputWitness {
    pub output: Output,
    pub siblings: [Digest; DEPTH],
}

/// The part of one transaction that a segment proves: some of its items,
/// in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxWitness {
    pub inputs: Vec<InputWitness>,
    pub outputs: Vec<OutputWitness>,
    /// The transaction body hash, which every input signed.
    pub message: Digest,
    /// Inputs and outputs of the transaction from this part on: all of
    /// them when the part starts the transaction.
    pub in_left: u32,
    pub out_left: u32,
    /// The body sponge state when this part resumes a transaction begun in
    /// an earlier segment; `None` when it starts the transaction.
    pub resume: Option<[Fp; WIDTH]>,
    /// Whether the transaction ends in this part.
    pub ends: bool,
}

impl TxWitness {
    /// Trace rows of this part: a start or resume row, the items, and the
    /// end row if it ends here.
    pub fn num_rows(&self) -> usize {
        1 + self.inputs.len() * ROWS_PER_INPUT + self.outputs.len() * ROWS_PER_OUTPUT + usize::from(self.ends)
    }
}

/// A transaction left open across a segment boundary: its signed message,
/// body sponge state and items still to come. [`Carry::CLOSED`] when none
/// is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Carry {
    pub open: bool,
    pub msg: Digest,
    pub bsp: [Fp; WIDTH],
    pub in_left: u32,
    pub out_left: u32,
}

impl Carry {
    pub const CLOSED: Carry =
        Carry { open: false, msg: [Fp::ZERO; DIGEST], bsp: [Fp::ZERO; WIDTH], in_left: 0, out_left: 0 };

    fn push_values(&self, v: &mut Vec<Fp>) {
        v.push(Fp::new(self.open as u32));
        v.extend_from_slice(&self.msg);
        v.extend_from_slice(&self.bsp);
        v.push(Fp::new(self.in_left));
        v.push(Fp::new(self.out_left));
    }

    /// Parses a carry; a closed one must be all zero.
    fn from_values(v: &[Fp]) -> Option<Carry> {
        let open = match v[CARRY_OPEN].to_canonical() {
            0 => false,
            1 => true,
            _ => return None,
        };
        let c = Carry {
            open,
            msg: v[CARRY_MSG..CARRY_MSG + DIGEST].try_into().unwrap(),
            bsp: v[CARRY_BSP..CARRY_BSP + WIDTH].try_into().unwrap(),
            in_left: v[CARRY_IN_LEFT].to_canonical(),
            out_left: v[CARRY_OUT_LEFT].to_canonical(),
        };
        (open || c == Carry::CLOSED).then_some(c)
    }
}

/// Boundary values of a segment: its public statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentPublic {
    pub root_in: Digest,
    pub root_out: Digest,
    pub isp_in: [Fp; WIDTH],
    pub isp_out: [Fp; WIDTH],
    pub osp_in: [Fp; WIDTH],
    pub osp_out: [Fp; WIDTH],
    pub pos_in: u64,
    pub pos_out: u64,
    pub sum_in: [u32; LIMBS],
    pub sum_out: [u32; LIMBS],
    pub carry_in: Carry,
    pub carry_out: Carry,
}

impl SegmentPublic {
    pub fn to_values(&self) -> Vec<Fp> {
        let mut v = Vec::with_capacity(NUM_PUBLIC);
        v.extend_from_slice(&self.root_in);
        v.extend_from_slice(&self.root_out);
        v.extend_from_slice(&self.isp_in);
        v.extend_from_slice(&self.isp_out);
        v.extend_from_slice(&self.osp_in);
        v.extend_from_slice(&self.osp_out);
        for p in [self.pos_in, self.pos_out] {
            v.push(Fp::new((p & MASK30) as u32));
            v.push(Fp::new((p >> 30) as u32));
        }
        v.extend(self.sum_in.iter().map(|x| Fp::new(*x)));
        v.extend(self.sum_out.iter().map(|x| Fp::new(*x)));
        self.carry_in.push_values(&mut v);
        self.carry_out.push_values(&mut v);
        v
    }

    /// Parses values written by [`SegmentPublic::to_values`]. Positions must
    /// decode to less than `2^40` and limb sums must be in range.
    pub fn from_values(v: &[Fp]) -> Option<SegmentPublic> {
        if v.len() != NUM_PUBLIC {
            return None;
        }
        let digest = |at: usize| -> Digest { v[at..at + DIGEST].try_into().unwrap() };
        let state = |at: usize| -> [Fp; WIDTH] { v[at..at + WIDTH].try_into().unwrap() };
        let pos = |at: usize| -> Option<u64> {
            let (lo, hi) = (v[at].to_canonical() as u64, v[at + 1].to_canonical() as u64);
            if lo >= 1 << 30 || hi >= 1 << 10 { None } else { Some(lo | hi << 30) }
        };
        let sums = |at: usize| -> [u32; LIMBS] { core::array::from_fn(|j| v[at + j].to_canonical()) };
        Some(SegmentPublic {
            root_in: digest(PUB_ROOT_IN),
            root_out: digest(PUB_ROOT_OUT),
            isp_in: state(PUB_ISP_IN),
            isp_out: state(PUB_ISP_OUT),
            osp_in: state(PUB_OSP_IN),
            osp_out: state(PUB_OSP_OUT),
            pos_in: pos(PUB_POS_IN)?,
            pos_out: pos(PUB_POS_OUT)?,
            sum_in: sums(PUB_SUM_IN),
            sum_out: sums(PUB_SUM_OUT),
            carry_in: Carry::from_values(&v[PUB_CARRY_IN..PUB_CARRY_IN + CARRY_LEN])?,
            carry_out: Carry::from_values(&v[PUB_CARRY_OUT..PUB_CARRY_OUT + CARRY_LEN])?,
        })
    }

    /// Integer value of a limb-sum vector.
    pub fn total(limbs: &[u32; LIMBS]) -> u128 {
        limbs.iter().enumerate().map(|(j, l)| (*l as u128) << (16 * j)).sum()
    }
}

/// Everything needed to prove one segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentWitness {
    pub root_in: Digest,
    pub isp_in: [Fp; WIDTH],
    pub osp_in: [Fp; WIDTH],
    pub pos_in: u64,
    pub txs: Vec<TxWitness>,
}

/// A run of one transaction's items, `start..end` in input-then-output
/// order, placed in a segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Part {
    pub tx: usize,
    pub start: usize,
    pub end: usize,
}

/// Trace rows of item `k` of a transaction with `n_in` inputs.
fn item_rows(k: usize, n_in: usize) -> usize {
    if k < n_in { ROWS_PER_INPUT } else { ROWS_PER_OUTPUT }
}

/// Packs transactions into segments of `max_rows` trace rows (one kept
/// for padding), greedily and splitting a transaction between items when
/// it does not fit what is left of a segment. Each segment lists its
/// parts in order. `items(t)` gives transaction `t`'s input and output
/// counts.
pub fn pack(num_txs: usize, items: impl Fn(usize) -> (usize, usize), max_rows: usize) -> Vec<Vec<Part>> {
    let cap = max_rows - 1;
    let mut segments = Vec::new();
    let mut cur: Vec<Part> = Vec::new();
    let mut rows = 0;
    for tx in 0..num_txs {
        let (n_in, n_out) = items(tx);
        let n = n_in + n_out;
        // Rows item k needs, with the end row after the last item.
        let cost = |k: usize| item_rows(k, n_in) + usize::from(k + 1 == n);
        let mut k = 0;
        loop {
            // A part needs its start (or resume) row and its first item,
            // or the end row for an empty transaction.
            let first = if k < n { cost(k) } else { 1 };
            assert!(first < cap, "an item does not fit a segment of {max_rows} rows");
            if rows + 1 + first > cap {
                segments.push(std::mem::take(&mut cur));
                rows = 0;
            }
            let start = k;
            rows += 1;
            while k < n && rows + cost(k) <= cap {
                rows += item_rows(k, n_in);
                k += 1;
            }
            cur.push(Part { tx, start, end: k });
            if k == n {
                rows += 1;
                break;
            }
            segments.push(std::mem::take(&mut cur));
            rows = 0;
        }
    }
    if !cur.is_empty() {
        segments.push(cur);
    }
    segments
}

impl SegmentWitness {
    /// Applies `txs` to the UTXO set inside `wtxn`, splitting them into
    /// segments of at most `txs_per_segment` whole transactions and
    /// recording the sibling paths each update needs. The caller decides
    /// whether to commit or abort the transaction. Signatures are not
    /// checked here.
    pub fn collect(
        utxo: &UtxoSet,
        wtxn: &mut heed::RwTxn,
        txs: &[Transaction],
        txs_per_segment: usize,
    ) -> utxo::Result<Vec<SegmentWitness>> {
        assert!(txs_per_segment > 0);
        let parts: Vec<Part> = txs
            .iter()
            .enumerate()
            .map(|(t, tx)| Part { tx: t, start: 0, end: tx.inputs.len() + tx.outputs.len() })
            .collect();
        Self::collect_parts(utxo, wtxn, txs, parts.chunks(txs_per_segment).map(|c| c.to_vec()).collect())
    }

    /// As [`SegmentWitness::collect`], packed by [`pack`] into segments of
    /// `max_rows` rows, transactions split between segments where needed.
    pub fn collect_by_rows(
        utxo: &UtxoSet,
        wtxn: &mut heed::RwTxn,
        txs: &[Transaction],
        max_rows: usize,
    ) -> utxo::Result<Vec<SegmentWitness>> {
        let plan = pack(txs.len(), |t| (txs[t].inputs.len(), txs[t].outputs.len()), max_rows);
        Self::collect_parts(utxo, wtxn, txs, plan)
    }

    /// Applies the parts of `txs` in order, one segment per entry of
    /// `segments`. A transaction's parts must be consecutive and cover its
    /// items in order.
    pub fn collect_parts(
        utxo: &UtxoSet,
        wtxn: &mut heed::RwTxn,
        txs: &[Transaction],
        segments: Vec<Vec<Part>>,
    ) -> utxo::Result<Vec<SegmentWitness>> {
        let mut isp = initial_inputs_state();
        let mut osp = initial_outputs_state();
        let mut bsp = [Fp::ZERO; WIDTH];
        let mut out_segments = Vec::with_capacity(segments.len());
        for parts in segments {
            let root_in = utxo.root(wtxn)?;
            let pos_in = utxo.next_position(wtxn)?;
            let (isp_in, osp_in) = (isp, osp);
            let mut out = Vec::with_capacity(parts.len());
            for part in parts {
                let tx = &txs[part.tx];
                let (n_in, n_out) = (tx.inputs.len(), tx.outputs.len());
                assert!(part.start <= part.end && part.end <= n_in + n_out, "part out of range");
                let resume = if part.start == 0 {
                    bsp = body_init(n_in as u32, n_out as u32);
                    None
                } else {
                    Some(bsp)
                };
                let mut inputs = Vec::new();
                let mut outputs = Vec::new();
                for k in part.start..part.end {
                    if k < n_in {
                        let inp = &tx.inputs[k];
                        let (commitment, position) = (inp.commitment(), inp.position);
                        let memo = utxo.memo(wtxn, position)?;
                        if !utxo.spend_at(wtxn, &commitment, position)? {
                            return Err(utxo::Error::CorruptIndex);
                        }
                        // Siblings are unchanged by the removal, so read them after it.
                        let proof = utxo.prove(wtxn, position)?;
                        absorb_position(&mut isp, position);
                        body_absorb_input(&mut bsp, &inp.pubkey, inp.amount);
                        inputs.push(InputWitness {
                            pubkey: inp.pubkey,
                            amount: inp.amount,
                            memo,
                            signature: inp.signature.clone(),
                            position,
                            siblings: proof.siblings,
                        });
                    } else {
                        let o = &tx.outputs[k - n_in];
                        let position = utxo.next_position(wtxn)?;
                        let proof = utxo.prove(wtxn, position)?;
                        utxo.add_output(wtxn, &o.block_output())?;
                        absorb_output(&mut osp, &o.commitment, &o.memo);
                        body_absorb_output(&mut bsp, o);
                        outputs.push(OutputWitness { output: *o, siblings: proof.siblings });
                    }
                }
                out.push(TxWitness {
                    inputs,
                    outputs,
                    message: tx.body_hash(),
                    in_left: n_in.saturating_sub(part.start) as u32,
                    out_left: (n_out - part.start.saturating_sub(n_in)) as u32,
                    resume,
                    ends: part.end == n_in + n_out,
                });
            }
            out_segments.push(SegmentWitness { root_in, isp_in, osp_in, pos_in, txs: out });
        }
        Ok(out_segments)
    }

    pub fn positions(&self) -> Vec<u64> {
        self.txs.iter().flat_map(|t| t.inputs.iter().map(|i| i.position)).collect()
    }

    pub fn outputs(&self) -> Vec<Output> {
        self.txs.iter().flat_map(|t| t.outputs.iter().map(|o| o.output)).collect()
    }

    /// The segment's output commitments, as they appear in the block.
    pub fn commitments(&self) -> Vec<Commitment> {
        self.txs.iter().flat_map(|t| t.outputs.iter().map(|o| o.output.commitment)).collect()
    }

    /// The outputs as a block lists them: commitment and memo.
    pub fn block_outputs(&self) -> Vec<BlockOutput> {
        self.txs.iter().flat_map(|t| t.outputs.iter().map(|o| o.output.block_output())).collect()
    }

    /// Trace rows before padding; a trace needs at least one more.
    pub fn num_rows(&self) -> usize {
        self.txs.iter().map(TxWitness::num_rows).sum()
    }
}

/// Trace rows a transaction occupies in a segment.
pub fn tx_rows(tx: &Transaction) -> usize {
    2 + tx.inputs.len() * ROWS_PER_INPUT + tx.outputs.len() * ROWS_PER_OUTPUT
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Regs {
    pub_seed: [Fp; PUB_SEED_LEN],
    idx_bits: [Fp; HEIGHT],
    m: Digest,
    sp: [Fp; WIDTH],
    node: Digest,
    sib: Digest,
    csum: u32,
    ksel: usize,
    esel: usize,
    rem: u32,
    level: u32,
    pbits: [Fp; DEPTH],
    root: Digest,
    old: Digest,
    new: Digest,
    is_out: bool,
    msg: Digest,
    bsp: [Fp; WIDTH],
    isp: [Fp; WIDTH],
    osp: [Fp; WIDTH],
    pkroot: Digest,
    ocm: Digest,
    amount: u64,
    sum_in: [u32; LIMBS],
    sum_out: [u32; LIMBS],
    opos: u64,
    in_left: u32,
    out_left: u32,
    open: bool,
    memo: Memo,
    leaf: Digest,
}

impl Regs {
    fn write(&self, row: &mut [Fp]) {
        row[R_PUB_SEED..R_PUB_SEED + PUB_SEED_LEN].copy_from_slice(&self.pub_seed);
        row[R_IDX..R_IDX + HEIGHT].copy_from_slice(&self.idx_bits);
        row[R_M..R_M + DIGEST].copy_from_slice(&self.m);
        row[R_SP..R_SP + WIDTH].copy_from_slice(&self.sp);
        row[R_NODE..R_NODE + DIGEST].copy_from_slice(&self.node);
        row[R_SIB..R_SIB + DIGEST].copy_from_slice(&self.sib);
        row[C_CSUM] = Fp::new(self.csum);
        row[C_KSEL + self.ksel] = Fp::ONE;
        row[C_ESEL + self.esel] = Fp::ONE;
        row[C_LAST] = Fp::new((self.esel == ELEMENTS - 1 && self.ksel == CSUM_CHAINS - 1) as u32);
        row[C_REM] = Fp::new(self.rem);
        row[C_LEVEL] = Fp::new(self.level);
        let diff = Fp::new(self.level) - Fp::new((DEPTH - 1) as u32);
        let is_last = diff.is_zero();
        row[C_IS_LAST] = Fp::new(is_last as u32);
        row[C_LEVEL_INV] = if is_last { Fp::ZERO } else { diff.inverse().unwrap() };
        row[C_SMT_END] = Fp::new((is_last && row[T_NEW] == Fp::ONE) as u32);
        row[R_PBITS..R_PBITS + DEPTH].copy_from_slice(&self.pbits);
        row[R_ROOT..R_ROOT + DIGEST].copy_from_slice(&self.root);
        row[R_OLD..R_OLD + DIGEST].copy_from_slice(&self.old);
        row[R_NEW..R_NEW + DIGEST].copy_from_slice(&self.new);
        row[R_IS_OUT] = Fp::new(self.is_out as u32);
        row[C_OUT_END] = Fp::new((row[C_SMT_END] == Fp::ONE && self.is_out) as u32);
        row[R_MSG..R_MSG + DIGEST].copy_from_slice(&self.msg);
        row[R_BSP..R_BSP + WIDTH].copy_from_slice(&self.bsp);
        row[R_ISP..R_ISP + WIDTH].copy_from_slice(&self.isp);
        row[R_OSP..R_OSP + WIDTH].copy_from_slice(&self.osp);
        row[R_PKROOT..R_PKROOT + DIGEST].copy_from_slice(&self.pkroot);
        row[R_OCM..R_OCM + DIGEST].copy_from_slice(&self.ocm);
        for i in 0..AMOUNT_BITS {
            row[R_ABITS + i] = Fp::new(((self.amount >> i) & 1) as u32);
        }
        for j in 0..LIMBS {
            row[R_SUM_IN + j] = Fp::new(self.sum_in[j]);
            row[R_SUM_OUT + j] = Fp::new(self.sum_out[j]);
        }
        let lo = (self.opos & MASK30) as u32;
        row[R_OPOS_LO] = Fp::new(lo);
        row[R_OPOS_HI] = Fp::new((self.opos >> 30) as u32);
        let diff = Fp::new(lo) - Fp::new((1 << 30) - 1);
        let wrap = diff.is_zero();
        row[C_WRAP] = Fp::new(wrap as u32);
        row[C_WRAP_INV] = if wrap { Fp::ZERO } else { diff.inverse().unwrap() };
        row[R_IN_LEFT] = Fp::new(self.in_left);
        row[R_OUT_LEFT] = Fp::new(self.out_left);
        let in_zero = self.in_left == 0;
        let out_zero = self.out_left == 0;
        row[C_IN_ZERO] = Fp::new(in_zero as u32);
        row[C_IN_INV] = if in_zero { Fp::ZERO } else { Fp::new(self.in_left).inverse().unwrap() };
        row[C_OUT_ZERO] = Fp::new(out_zero as u32);
        row[C_OUT_INV] = if out_zero { Fp::ZERO } else { Fp::new(self.out_left).inverse().unwrap() };
        row[C_GO_OUT] = Fp::new((in_zero && !out_zero) as u32);
        row[C_GO_END] = Fp::new((in_zero && out_zero) as u32);
        row[R_OPEN] = Fp::new(self.open as u32);
        row[R_MEMO..R_MEMO + DIGEST].copy_from_slice(&self.memo);
        row[R_LEAF..R_LEAF + DIGEST].copy_from_slice(&self.leaf);
    }
}

fn cap(pub_seed: &[Fp; PUB_SEED_LEN], domain: u32, index: u64, extra: u32) -> [Fp; DIGEST] {
    let mut c = [Fp::ZERO; DIGEST];
    c[..PUB_SEED_LEN].copy_from_slice(pub_seed);
    c[PUB_SEED_LEN] = Fp::new(domain);
    c[PUB_SEED_LEN + 1] = Fp::new((index & MASK30) as u32);
    c[PUB_SEED_LEN + 2] = Fp::new((index >> 30) as u32);
    c[PUB_SEED_LEN + 3] = Fp::new(extra);
    c
}

fn write_bits(row: &mut [Fp], value: u32) {
    for i in 0..BITS {
        row[C_BITS + i] = Fp::new((value >> i) & 1);
    }
    row[C_T3] = Fp::new(((value >> 28) & 7 == 7) as u32);
}

fn compress_input(node: &Digest, sib: &Digest, right: bool) -> [Fp; WIDTH] {
    let mut input = [Fp::ZERO; WIDTH];
    let (a, c) = if right { (sib, node) } else { (node, sib) };
    input[..DIGEST].copy_from_slice(a);
    input[DIGEST..].copy_from_slice(c);
    input
}

fn amt_block(amount: u64) -> [Fp; RATE] {
    let mut blk = [Fp::ZERO; RATE];
    blk[..3].copy_from_slice(&amount_fps(amount));
    blk
}

struct Gen {
    b: HashTraceBuilder,
    regs: Regs,
}

impl Gen {
    /// Pushes a register-sponge start row: `input = sp + [block, 0]`.
    fn sponge_start(&mut self, sp: [Fp; WIDTH], block: [Fp; RATE], ty: usize) -> [Fp; WIDTH] {
        let mut input = sp;
        for (s, x) in input.iter_mut().zip(&block) {
            *s = s.add(x);
        }
        self.b.start(input);
        let row = self.b.last_row_mut();
        row[ty] = Fp::ONE;
        self.regs.write(row);
        self.b.state()
    }

    /// A leaf row: the commitment and the memo register compressed.
    fn leaf_row(&mut self, commitment: Digest, ty: usize) -> Digest {
        let mut input = [Fp::ZERO; WIDTH];
        input[..DIGEST].copy_from_slice(&commitment);
        input[DIGEST..].copy_from_slice(&self.regs.memo);
        self.b.start(input);
        let row = self.b.last_row_mut();
        row[ty] = Fp::ONE;
        self.regs.write(row);
        let leaf = self.b.acc();
        debug_assert_eq!(leaf, crate::transaction::leaf(&commitment, &self.regs.memo));
        leaf
    }

    fn absorb(&mut self, block: [Fp; RATE], ty: usize) -> [Fp; WIDTH] {
        self.b.absorb(block);
        let row = self.b.last_row_mut();
        row[ty] = Fp::ONE;
        self.regs.write(row);
        self.b.state()
    }

    fn smt_update(&mut self, position: u64, siblings: &[Digest; DEPTH]) {
        // Caller has set regs.old / regs.new / regs.pbits / regs.level = 0.
        let mut old_node = self.regs.old;
        let mut new_node = self.regs.new;
        for (level, sib) in siblings.iter().enumerate() {
            let right = (position >> level) & 1 == 1;
            self.regs.level = level as u32;
            self.regs.sib = *sib;
            self.b.start(compress_input(&old_node, &self.regs.sib, right));
            {
                let row = self.b.last_row_mut();
                row[T_OLD] = Fp::ONE;
                row[COL_DIR] = Fp::new(right as u32);
                self.regs.write(row);
            }
            old_node = self.b.acc();
            self.regs.old = old_node;
            self.b.start(compress_input(&new_node, &self.regs.sib, right));
            {
                let row = self.b.last_row_mut();
                row[T_NEW] = Fp::ONE;
                row[COL_DIR] = Fp::new(right as u32);
                self.regs.write(row);
            }
            new_node = self.b.acc();
            if level + 1 < DEPTH {
                self.regs.new = new_node;
                for i in 0..DEPTH - 1 {
                    self.regs.pbits[i] = self.regs.pbits[i + 1];
                }
                self.regs.pbits[DEPTH - 1] = Fp::ZERO;
            }
        }
        assert_eq!(old_node, self.regs.root, "old path does not reach the current root");
        self.regs.root = new_node;
    }

    fn input(&mut self, w: &InputWitness) {
        let ps = w.pubkey.pub_seed;
        let idx = w.signature.index;
        assert!(idx < 1 << HEIGHT);
        let r = &mut self.regs;
        r.pub_seed = ps;
        r.memo = w.memo;
        r.idx_bits = core::array::from_fn(|i| Fp::new(((idx >> i) & 1) as u32));
        r.amount = w.amount;
        r.is_out = false;
        r.in_left -= 1;
        r.csum = 0;
        r.ksel = DIGITS_PER_ELEMENT - 1;
        r.esel = ELEMENTS - 1;
        r.sp = [Fp::ZERO; WIDTH];
        r.sp[RATE..].copy_from_slice(&cap(&ps, DOM_WOTS_PK, idx, 0));
        let msg = r.msg;

        // message digest sponge
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&w.signature.randomizer);
        input[RATE..].copy_from_slice(&cap(&ps, DOM_MSG, idx, 0));
        self.b.start(input);
        {
            let row = self.b.last_row_mut();
            row[T_MSG_START] = Fp::ONE;
            self.regs.write(row);
        }
        let mut block0 = [Fp::ZERO; RATE];
        block0[0] = Fp::from_u32(DIGEST as u32);
        block0[1..].copy_from_slice(&msg[..RATE - 1]);
        self.absorb(block0, T_MSG_ABS);
        let mut block1 = [Fp::ZERO; RATE];
        block1[0] = msg[DIGEST - 1];
        self.b.absorb(block1);
        {
            let row = self.b.last_row_mut();
            row[T_MSG_ABS] = Fp::ONE;
            row[C_MC] = Fp::ONE;
            self.regs.write(row);
        }
        let m = self.b.acc();
        self.regs.m = m;
        let digs = digits(&m);

        for (c, &digit) in digs.iter().enumerate() {
            let wrap = self.regs.ksel == DIGITS_PER_ELEMENT - 1;
            self.regs.ksel = (self.regs.ksel + 1) % DIGITS_PER_ELEMENT;
            if wrap {
                self.regs.esel = (self.regs.esel + 1) % ELEMENTS;
            }
            let d = digit as u32;
            self.regs.rem = d;
            self.b.load(w.signature.wots[c]);
            {
                let elem = if self.regs.esel < DIGEST { m[self.regs.esel].to_canonical() } else { self.regs.csum };
                let row = self.b.last_row_mut();
                row[T_LOAD] = Fp::ONE;
                write_bits(row, elem);
                row[C_D] = Fp::new(d);
                self.regs.write(row);
            }
            if c < MSG_CHAINS {
                self.regs.csum += (W as u32 - 1) - d;
            }
            for step in 0..STEPS {
                let active = self.regs.rem == 0;
                if active {
                    self.b.chain(cap(&ps, DOM_WOTS_CHAIN, idx, c as u32 | (step as u32) << 16));
                } else {
                    self.b.pass();
                }
                {
                    let rem = self.regs.rem;
                    let row = self.b.last_row_mut();
                    row[T_STEP] = Fp::ONE;
                    row[C_SSEL + step] = Fp::ONE;
                    row[C_ACTIVE] = Fp::new(active as u32);
                    row[C_REM_INV] = if active { Fp::ZERO } else { Fp::new(rem).inverse().unwrap() };
                    self.regs.write(row);
                }
                if !active {
                    self.regs.rem -= 1;
                }
            }
            let end = self.b.acc();
            let sp = self.regs.sp;
            let out = self.sponge_start(sp, end, T_LEAF);
            self.regs.sp = out;
        }

        // xmss tree levels
        let mut pos = (1u64 << HEIGHT) + idx;
        for level in 0..HEIGHT {
            let right = pos & 1 == 1;
            pos >>= 1;
            self.regs.node = self.b.acc();
            self.regs.sib = w.signature.auth_path[level];
            let (left_v, right_v) =
                if right { (self.regs.sib, self.regs.node) } else { (self.regs.node, self.regs.sib) };
            let mut input = [Fp::ZERO; WIDTH];
            input[..RATE].copy_from_slice(&left_v);
            input[RATE..].copy_from_slice(&cap(&ps, DOM_TREE, pos, (level + 1) as u32));
            self.b.start(input);
            {
                let row = self.b.last_row_mut();
                row[T_TREE_START] = Fp::ONE;
                row[C_LSEL + level] = Fp::ONE;
                row[COL_DIR] = Fp::new(right as u32);
                self.regs.write(row);
            }
            self.b.absorb(right_v);
            {
                let row = self.b.last_row_mut();
                row[T_TREE_ABS] = Fp::ONE;
                row[C_LSEL + level] = Fp::ONE;
                row[COL_DIR] = Fp::new(right as u32);
                self.regs.write(row);
            }
        }
        let root = self.b.acc();
        assert_eq!(root, w.pubkey.root, "signature does not verify under the given key");
        self.regs.pkroot = root;

        // key hash and commitment
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&root);
        input[RATE..].copy_from_slice(&cap_const::<Fp>(DOM_PUBKEY, (DIGEST + PUB_SEED_LEN) as u32));
        self.b.start(input);
        {
            let row = self.b.last_row_mut();
            row[T_PKH0] = Fp::ONE;
            self.regs.write(row);
        }
        let mut seed_block = [Fp::ZERO; RATE];
        seed_block[..PUB_SEED_LEN].copy_from_slice(&ps);
        self.absorb(seed_block, T_PKH1);
        let pkh = self.b.acc();
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&pkh);
        input[RATE..].copy_from_slice(&cap_const::<Fp>(DOM_COMMITMENT, (DIGEST + 3) as u32));
        self.b.start(input);
        {
            let row = self.b.last_row_mut();
            row[T_CM0] = Fp::ONE;
            self.regs.write(row);
        }
        self.absorb(amt_block(w.amount), T_CM1);
        let commitment = self.b.acc();
        for (acc, limb) in self.regs.sum_in.iter_mut().zip(limbs16(w.amount)) {
            *acc += limb.to_canonical();
        }
        let leaf = self.leaf_row(commitment, T_ILEAF);

        // inputs list row, then the removal
        self.regs.old = leaf;
        self.regs.new = EMPTY;
        self.regs.level = 0;
        self.regs.pbits = core::array::from_fn(|i| Fp::new(((w.position >> i) & 1) as u32));
        let mut blk = [Fp::ZERO; RATE];
        blk[0] = Fp::new((w.position & MASK30) as u32);
        blk[1] = Fp::new((w.position >> 30) as u32);
        let isp = self.regs.isp;
        let out = self.sponge_start(isp, blk, T_ILIST);
        self.regs.isp = out;
        self.smt_update(w.position, &w.siblings);

        // body rows
        let bsp = self.regs.bsp;
        let out = self.sponge_start(bsp, root, T_BODY_IN0);
        self.regs.bsp = out;
        let mut blk = [Fp::ZERO; RATE];
        blk[..PUB_SEED_LEN].copy_from_slice(&ps);
        blk[PUB_SEED_LEN..PUB_SEED_LEN + 3].copy_from_slice(&amount_fps(w.amount));
        let out = self.absorb(blk, T_BODY_IN1);
        self.regs.bsp = out;
    }

    fn output(&mut self, w: &OutputWitness) {
        let o = &w.output;
        let r = &mut self.regs;
        r.ocm = o.commitment;
        r.memo = o.memo;
        r.amount = o.amount;
        r.is_out = true;
        r.out_left -= 1;
        let osp = r.osp;
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&o.key_hash);
        input[RATE..].copy_from_slice(&cap_const::<Fp>(DOM_COMMITMENT, (DIGEST + 3) as u32));
        self.b.start(input);
        {
            let row = self.b.last_row_mut();
            row[T_OCM0] = Fp::ONE;
            self.regs.write(row);
        }
        self.absorb(amt_block(o.amount), T_OCM1);
        assert_eq!(self.b.acc(), o.commitment, "output commitment does not match its key hash and amount");
        let leaf = self.leaf_row(o.commitment, T_OLEAF);
        self.regs.leaf = leaf;
        let out = self.sponge_start(osp, o.commitment, T_OLIST);
        self.regs.osp = out;
        // The amount sum advances on the row after olist.
        for (acc, limb) in self.regs.sum_out.iter_mut().zip(limbs16(o.amount)) {
            *acc += limb.to_canonical();
        }
        let out = self.absorb(o.memo, T_OLIST2);
        self.regs.osp = out;
        let bsp = self.regs.bsp;
        let out = self.sponge_start(bsp, o.commitment, T_BODY_OUT0);
        self.regs.bsp = out;
        let out = self.absorb(amt_block(o.amount), T_BODY_OUT1);
        self.regs.bsp = out;
        let out = self.absorb(o.memo, T_BODY_OUT2);
        self.regs.bsp = out;
        let position = self.regs.opos;
        self.regs.old = EMPTY;
        self.regs.new = self.regs.leaf;
        self.regs.level = 0;
        self.regs.pbits = core::array::from_fn(|i| Fp::new(((position >> i) & 1) as u32));
        self.smt_update(position, &w.siblings);
        self.regs.opos += 1;
    }
}

impl BlockAir {
    /// Builds the trace for segment `w`; returns it with the segment's
    /// public statement. Panics if the witness is inconsistent (a signature
    /// that does not verify, a missing leaf, or a mismatched message).
    pub fn generate_trace(w: &SegmentWitness) -> (Trace, SegmentPublic) {
        Self::generate_trace_with(w, 2)
    }

    /// Trace padded to exactly `2^log_n` rows; panics if the segment needs
    /// more.
    pub fn generate_trace_padded(w: &SegmentWitness, log_n: usize) -> (Trace, SegmentPublic) {
        assert!(w.num_rows() < 1 << log_n, "segment of {} rows does not fit 2^{log_n}", w.num_rows());
        Self::generate_trace_with(w, 1 << log_n)
    }

    fn generate_trace_with(w: &SegmentWitness, min_rows: usize) -> (Trace, SegmentPublic) {
        assert!(!w.txs.is_empty(), "a segment needs at least one transaction");
        let regs = Regs {
            pub_seed: [Fp::ZERO; PUB_SEED_LEN],
            idx_bits: [Fp::ZERO; HEIGHT],
            m: EMPTY,
            sp: [Fp::ZERO; WIDTH],
            node: EMPTY,
            sib: EMPTY,
            csum: 0,
            ksel: 0,
            esel: 0,
            rem: 0,
            level: 0,
            pbits: [Fp::ZERO; DEPTH],
            root: w.root_in,
            old: EMPTY,
            new: EMPTY,
            is_out: false,
            msg: EMPTY,
            bsp: [Fp::ZERO; WIDTH],
            isp: w.isp_in,
            osp: w.osp_in,
            pkroot: EMPTY,
            ocm: EMPTY,
            amount: 0,
            sum_in: [0; LIMBS],
            sum_out: [0; LIMBS],
            opos: w.pos_in,
            in_left: 0,
            out_left: 0,
            open: false,
            memo: EMPTY,
            leaf: EMPTY,
        };
        let mut g = Gen { b: HashTraceBuilder::new(NUM_COLS), regs };
        let mut carry_in = Carry::CLOSED;
        let mut carry_out = Carry::CLOSED;
        let parts = w.txs.len();
        for (p, tx) in w.txs.iter().enumerate() {
            let (n_in, n_out) = (tx.inputs.len() as u32, tx.outputs.len() as u32);
            assert!(n_in <= tx.in_left && n_out <= tx.out_left, "more items than the transaction has left");
            assert!(n_out == 0 || n_in == tx.in_left, "outputs before the last input");
            assert!(!tx.ends || (n_in, n_out) == (tx.in_left, tx.out_left), "a part that ends has every item left");
            g.regs.msg = tx.message;
            g.regs.in_left = tx.in_left;
            g.regs.out_left = tx.out_left;
            g.regs.is_out = false;
            g.regs.open = true;
            match tx.resume {
                None => {
                    let mut input = [Fp::ZERO; WIDTH];
                    input[0] = Fp::new(tx.in_left);
                    input[1] = Fp::new(tx.out_left);
                    input[RATE..].copy_from_slice(&cap_const::<Fp>(
                        DOM_BODY,
                        8 + BODY_PER_INPUT * tx.in_left + BODY_PER_OUTPUT * tx.out_left,
                    ));
                    g.b.start(input);
                    let row = g.b.last_row_mut();
                    row[T_TX_START] = Fp::ONE;
                    g.regs.write(row);
                    g.regs.bsp = g.b.state();
                }
                Some(bsp) => {
                    assert_eq!(p, 0, "only a segment's first part may resume a transaction");
                    g.regs.bsp = bsp;
                    g.b.pass();
                    let row = g.b.last_row_mut();
                    row[T_RESUME] = Fp::ONE;
                    g.regs.write(row);
                    carry_in = Carry { open: true, msg: tx.message, bsp, in_left: tx.in_left, out_left: tx.out_left };
                }
            }
            for inp in &tx.inputs {
                g.input(inp);
            }
            for out in &tx.outputs {
                g.output(out);
            }
            if tx.ends {
                assert_eq!(&g.regs.bsp[..DIGEST], &tx.message[..], "body digest does not match the signed message");
                g.b.pass();
                let row = g.b.last_row_mut();
                row[T_TX_END] = Fp::ONE;
                g.regs.write(row);
                g.regs.open = false;
            } else {
                assert_eq!(p + 1, parts, "only a segment's last part may leave a transaction open");
                let r = &g.regs;
                carry_out = Carry { open: true, msg: r.msg, bsp: r.bsp, in_left: r.in_left, out_left: r.out_left };
            }
        }
        let public = SegmentPublic {
            root_in: w.root_in,
            root_out: g.regs.root,
            isp_in: w.isp_in,
            isp_out: g.regs.isp,
            osp_in: w.osp_in,
            osp_out: g.regs.osp,
            pos_in: w.pos_in,
            pos_out: g.regs.opos,
            sum_in: g.regs.sum_in,
            sum_out: g.regs.sum_out,
            carry_in,
            carry_out,
        };
        let n = (g.b.len() + 1).max(min_rows).next_power_of_two();
        while g.b.len() < n {
            g.b.pass();
            let row = g.b.last_row_mut();
            row[T_DONE] = Fp::ONE;
            g.regs.write(row);
        }
        (g.b.finish(), public)
    }
}

/// Commitment type re-export for callers.
pub type Leaf = Commitment;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::stark::{StarkConfig, check_constraints, measure_degree, prove, verify};
    use crate::state_tree::open_env;
    use crate::transaction::{Key, UnsignedTransaction};
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let p = std::env::temp_dir().join(format!("tabminer-block-air-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
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

    /// A UTXO set with three outputs, then three transactions spending them,
    /// split into segments of `per_segment` transactions. Returns the
    /// segments, the final root, the positions and the outputs.
    fn scenario(name: &str, per_segment: usize) -> (Vec<SegmentWitness>, Digest, Vec<u64>, Vec<Output>) {
        scenario_with(name, |utxo, wtxn, txs| SegmentWitness::collect(utxo, wtxn, txs, per_segment).unwrap())
    }

    fn scenario_with(
        name: &str,
        split: impl FnOnce(&UtxoSet, &mut heed::RwTxn, &[Transaction]) -> Vec<SegmentWitness>,
    ) -> (Vec<SegmentWitness>, Digest, Vec<u64>, Vec<Output>) {
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let mut a = key(1);
        let mut bk = key(2);
        let c = key(3).public_key();
        let miner = key(4).public_key();
        utxo.add(&mut wtxn, &Output::new(&a.public_key(), 100).commitment).unwrap();
        utxo.add(&mut wtxn, &Output::new(&bk.public_key(), 50).commitment).unwrap();
        utxo.add(&mut wtxn, &Output::new(&a.public_key(), 30).commitment).unwrap();

        let mut tx1 = UnsignedTransaction::new(
            vec![(a.public_key(), 100), (bk.public_key(), 50)],
            vec![Output::new(&c, 120), Output::new(&a.public_key(), 25)],
        )
        .sign(|i, _, m| if i == 0 { a.sign(m) } else { bk.sign(m) })
        .unwrap();
        tx1.set_positions(&[0, 1]);
        let reward =
            UnsignedTransaction::new(vec![], vec![Output::new(&miner, 55)]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap();
        let mut tx3 = UnsignedTransaction::new(vec![(a.public_key(), 30)], vec![Output::new(&bk.public_key(), 30)])
            .sign_with(&mut a)
            .unwrap();
        tx3.set_positions(&[2]);
        assert!(tx1.verify_signatures() && tx3.verify_signatures());
        let txs = [tx1, reward, tx3];
        let positions = vec![0, 1, 2];
        let outputs: Vec<Output> = txs.iter().flat_map(|t| t.outputs.clone()).collect();

        let segments = split(&utxo, &mut wtxn, &txs);
        let new_root = utxo.root(&wtxn).unwrap();
        wtxn.abort();
        (segments, new_root, positions, outputs)
    }

    #[test]
    fn layout_and_degree() {
        assert_eq!(measure_degree(&BlockAir, NUM_PUBLIC), 3);
        assert_eq!(ROWS_PER_INPUT, 1150 + 5 + 1 + 80 + 2);
        assert_eq!(ROWS_PER_OUTPUT, 88);
        assert_eq!(NUM_PUBLIC, 96 + 2 * 27);
    }

    #[test]
    fn segments_satisfy_constraints_and_chain() {
        let (segments, expected_root, positions, outputs) = scenario("ok", 2);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].txs.len(), 2);
        assert_eq!(segments[0].num_rows(), 2 * 2 + 2 * ROWS_PER_INPUT + 3 * ROWS_PER_OUTPUT);
        let mut publics = Vec::new();
        for (k, seg) in segments.iter().enumerate() {
            let (trace, public) = BlockAir::generate_trace(seg);
            let values = public.to_values();
            assert_eq!(SegmentPublic::from_values(&values), Some(public));
            assert_eq!(check_constraints(&BlockAir, &trace, &values), Ok(()), "segment {k}");
            // Every public value matters.
            for i in [
                PUB_ROOT_IN,
                PUB_ROOT_OUT + 3,
                PUB_ISP_IN + 9,
                PUB_ISP_OUT,
                PUB_OSP_IN + 15,
                PUB_OSP_OUT + 2,
                PUB_POS_IN,
                PUB_POS_OUT,
                PUB_SUM_IN + 1,
                PUB_SUM_OUT,
            ] {
                let mut bad = values.clone();
                bad[i] += Fp::ONE;
                assert!(check_constraints(&BlockAir, &trace, &bad).is_err(), "segment {k} public {i}");
            }
            publics.push(public);
        }
        // Chaining and block-level binding.
        assert_eq!(publics[0].root_out, publics[1].root_in);
        assert_eq!(publics[0].isp_out, publics[1].isp_in);
        assert_eq!(publics[0].osp_out, publics[1].osp_in);
        assert_eq!(publics[0].pos_out, publics[1].pos_in);
        assert_eq!(publics[0].isp_in, initial_inputs_state());
        assert_eq!(publics[0].osp_in, initial_outputs_state());
        assert_eq!(publics[0].pos_in, 3);
        assert_eq!(publics[1].pos_out, 7);
        assert_eq!(publics[1].root_out, expected_root);
        assert_eq!(publics[1].isp_out, inputs_state(&positions));
        assert_eq!(publics[1].osp_out, outputs_state(&outputs.iter().map(|o| o.block_output()).collect::<Vec<_>>()));
        let total_in: u128 = publics.iter().map(|p| SegmentPublic::total(&p.sum_in)).sum();
        let total_out: u128 = publics.iter().map(|p| SegmentPublic::total(&p.sum_out)).sum();
        assert_eq!(total_in, 180);
        assert_eq!(total_out, 230);
        assert_eq!(total_in + 50, total_out);
        // The same transactions as one segment give the same endpoints.
        let (single, root1, _, _) = scenario("single", 10);
        assert_eq!(single.len(), 1);
        let (_, p) = BlockAir::generate_trace(&single[0]);
        assert_eq!(p.root_out, root1);
        assert_eq!(p.isp_out, publics[1].isp_out);
        assert_eq!(p.osp_out, publics[1].osp_out);
        assert_eq!(SegmentPublic::total(&p.sum_out), 230);
    }

    #[test]
    fn transactions_span_segments() {
        // The first transaction (two inputs, two outputs) is split after
        // its first input and after its first output.
        let plan = vec![
            vec![Part { tx: 0, start: 0, end: 1 }],
            vec![Part { tx: 0, start: 1, end: 3 }],
            vec![Part { tx: 0, start: 3, end: 4 }, Part { tx: 1, start: 0, end: 1 }, Part { tx: 2, start: 0, end: 2 }],
        ];
        let (segments, expected_root, positions, outputs) =
            scenario_with("span", |utxo, wtxn, txs| SegmentWitness::collect_parts(utxo, wtxn, txs, plan).unwrap());
        assert_eq!(segments.len(), 3);
        let mut publics = Vec::new();
        let mut traces = Vec::new();
        for (k, seg) in segments.iter().enumerate() {
            let (trace, public) = BlockAir::generate_trace(seg);
            let values = public.to_values();
            assert_eq!(SegmentPublic::from_values(&values), Some(public));
            assert_eq!(check_constraints(&BlockAir, &trace, &values), Ok(()), "segment {k}");
            publics.push(public);
            traces.push(trace);
        }
        let (c01, c12) = (publics[0].carry_out, publics[1].carry_out);
        assert_eq!(publics[0].carry_in, Carry::CLOSED);
        assert!(c01.open && c12.open);
        assert_eq!((c01.in_left, c01.out_left), (1, 2));
        assert_eq!((c12.in_left, c12.out_left), (0, 1));
        assert_eq!(publics[1].carry_in, c01);
        assert_eq!(publics[2].carry_in, c12);
        assert_eq!(publics[2].carry_out, Carry::CLOSED);
        for w in publics.windows(2) {
            assert_eq!((w[0].root_out, w[0].isp_out, w[0].osp_out), (w[1].root_in, w[1].isp_in, w[1].osp_in));
            assert_eq!(w[0].pos_out, w[1].pos_in);
        }
        assert_eq!(publics[2].root_out, expected_root);
        assert_eq!(publics[2].isp_out, inputs_state(&positions));
        assert_eq!(publics[2].osp_out, outputs_state(&outputs.iter().map(|o| o.block_output()).collect::<Vec<_>>()));
        let total = |f: fn(&SegmentPublic) -> &[u32; LIMBS]| -> u128 {
            publics.iter().map(|p| SegmentPublic::total(f(p))).sum()
        };
        assert_eq!(total(|p| &p.sum_in) + 50, total(|p| &p.sum_out));

        // Every carry value matters, on both sides.
        let mid = &traces[1];
        let values = publics[1].to_values();
        for c in [CARRY_OPEN, CARRY_MSG + 2, CARRY_BSP + 11, CARRY_IN_LEFT, CARRY_OUT_LEFT] {
            for at in [PUB_CARRY_IN, PUB_CARRY_OUT] {
                let mut bad = values.clone();
                bad[at + c] += Fp::ONE;
                assert!(check_constraints(&BlockAir, mid, &bad).is_err(), "carry {at} + {c}");
            }
        }
        // Claiming the open transaction closed.
        let mut bad = values.clone();
        bad[PUB_CARRY_OUT..PUB_CARRY_OUT + CARRY_LEN].fill(Fp::ZERO);
        assert!(check_constraints(&BlockAir, mid, &bad).is_err());
        // A resume row turned into a start: its header is not the carry.
        let mut bad = mid.clone();
        bad.values[T_RESUME] = Fp::ZERO;
        bad.values[T_TX_START] = Fp::ONE;
        assert!(check_constraints(&BlockAir, &bad, &values).is_err());
        // A transaction cannot be resumed with a different message: the
        // signatures then fail (the witness refuses to build).
        let mut forged = segments[1].clone();
        forged.txs[0].message[0] += Fp::ONE;
        assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&forged)).is_err());
    }

    #[test]
    fn packing_splits_between_items() {
        let items = |t: usize| [(0, 1), (3, 2), (1, 2), (0, 5)][t];
        let max_rows = 2048;
        let plan = pack(4, items, max_rows);
        // Parts cover every item once, in order.
        let mut next = [0usize; 4];
        let mut last_tx = 0;
        for seg in &plan {
            let mut rows = 0;
            for p in seg {
                assert!(p.tx >= last_tx);
                last_tx = p.tx;
                assert_eq!(p.start, next[p.tx]);
                next[p.tx] = p.end;
                let (n_in, n_out) = items(p.tx);
                rows += 1 + (p.start..p.end).map(|k| item_rows(k, n_in)).sum::<usize>();
                rows += usize::from(p.end == n_in + n_out);
            }
            assert!(rows < max_rows, "{rows}");
        }
        assert_eq!(next, [1, 5, 3, 5]);
        // A segment holds one input: the second transaction's three are
        // spread over three segments, its outputs joining the last.
        assert_eq!(plan[0], vec![Part { tx: 0, start: 0, end: 1 }, Part { tx: 1, start: 0, end: 1 }]);
        assert_eq!(plan[1], vec![Part { tx: 1, start: 1, end: 2 }]);
        assert_eq!(plan[2][0], Part { tx: 1, start: 2, end: 5 });
    }

    #[test]
    fn forged_segments_fail() {
        let (segments, _, _, _) = scenario("forge", 10);
        let w = &segments[0];
        // Claiming a larger input amount changes the commitment, so the old
        // path misses the root.
        let mut greedy = w.clone();
        greedy.txs[0].inputs[0].amount += 1;
        assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&greedy)).is_err());
        // An output whose commitment hides more than the amount counted.
        let mut inflated = w.clone();
        let o = &mut inflated.txs[0].outputs[0].output;
        o.commitment = crate::transaction::key_commitment(&o.key_hash, o.amount + 1_000_000);
        assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&inflated)).is_err());
        // A wrong message means the signature chains do not reach the key.
        let mut wrong_msg = w.clone();
        wrong_msg.txs[2].message[0] += Fp::ONE;
        assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&wrong_msg)).is_err());
        // Hand-patched traces: an output amount inflated after the fact.
        let (trace, public) = BlockAir::generate_trace(w);
        let values = public.to_values();
        let width = NUM_COLS;
        let mut bad = trace.clone();
        let r = (0..trace.height()).find(|&r| trace.values[r * width + T_BODY_OUT1] == Fp::ONE).unwrap();
        bad.values[r * width + COL_DATA] += Fp::ONE;
        assert!(check_constraints(&BlockAir, &bad, &values).is_err());
        // The amount hashed into an output's commitment differs from its bits.
        let mut bad = trace.clone();
        let r = (0..trace.height()).find(|&r| trace.values[r * width + T_OCM1] == Fp::ONE).unwrap();
        bad.values[r * width + COL_DATA] += Fp::ONE;
        assert!(check_constraints(&BlockAir, &bad, &values).is_err());
        // Memos: the one listed and the one signed must both be the
        // register's, and the register cannot change within an output.
        for ty in [T_OLIST2, T_BODY_OUT2] {
            let mut bad = trace.clone();
            let r = (0..trace.height()).find(|&r| trace.values[r * width + ty] == Fp::ONE).unwrap();
            bad.values[r * width + COL_DATA + 3] += Fp::ONE;
            assert!(check_constraints(&BlockAir, &bad, &values).is_err(), "row type {ty}");
        }
        let mut bad = trace.clone();
        let r = (0..trace.height()).find(|&r| trace.values[r * width + T_BODY_OUT1] == Fp::ONE).unwrap();
        bad.values[r * width + R_MEMO] += Fp::ONE;
        assert!(check_constraints(&BlockAir, &bad, &values).is_err());
        // Leaves: the memo compressed into each leaf must be the register's,
        // and the leaf inserted must be the one computed.
        for ty in [T_ILEAF, T_OLEAF] {
            let mut bad = trace.clone();
            let r = (0..trace.height()).find(|&r| trace.values[r * width + ty] == Fp::ONE).unwrap();
            bad.values[r * width + COL_INPUT + RATE + 2] += Fp::ONE;
            assert!(check_constraints(&BlockAir, &bad, &values).is_err(), "leaf row type {ty}");
        }
        let mut bad = trace.clone();
        let r = (0..trace.height()).find(|&r| trace.values[r * width + T_BODY_OUT2] == Fp::ONE).unwrap();
        bad.values[r * width + R_LEAF] += Fp::ONE;
        assert!(check_constraints(&BlockAir, &bad, &values).is_err());
        // Spending with the wrong memo misses the leaf, so the path misses
        // the root.
        let mut wrong_memo = w.clone();
        wrong_memo.txs[0].inputs[0].memo[1] += Fp::ONE;
        assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&wrong_memo)).is_err());
        // A memo changed after signing breaks the body digest.
        let mut swapped = w.clone();
        swapped.txs[0].outputs[0].output.memo[0] += Fp::ONE;
        assert!(std::panic::catch_unwind(|| BlockAir::generate_trace(&swapped)).is_err());
        // And the listed outputs differ with the memo.
        let o = w.txs[0].outputs[0].output;
        let mut other = o.block_output();
        other.memo[0] += Fp::ONE;
        assert_ne!(outputs_state(&[o.block_output()]), outputs_state(&[other]));
        // A done row inserted before the last transaction ends.
        let mut bad = trace.clone();
        let r = (0..trace.height()).rev().find(|&r| trace.values[r * width + T_TX_END] == Fp::ONE).unwrap();
        bad.values[r * width + T_TX_END] = Fp::ZERO;
        bad.values[r * width + T_DONE] = Fp::ONE;
        assert!(check_constraints(&BlockAir, &bad, &values).is_err());
    }

    #[test]
    #[ignore = "slow in debug builds; run with --release"]
    fn prove_and_verify_block() {
        let config = StarkConfig { log_blowup: 1, num_queries: 20, pow_bits: 0, zk: false, commit_bits: 0 };
        let (segments, _, _, _) = scenario("prove", 10);
        let (trace, public) = BlockAir::generate_trace(&segments[0]);
        let public = public.to_values();
        let tr = || {
            let mut c = Challenger::new();
            c.observe(Fp::new(0xe5));
            c
        };
        let t = std::time::Instant::now();
        let proof = prove(&config, &BlockAir, &trace, &public, &mut tr());
        println!("block proof ({} rows x {} cols): {:?}", trace.height(), NUM_COLS, t.elapsed());
        let t = std::time::Instant::now();
        assert_eq!(verify(&config, &BlockAir, &public, &proof, &mut tr()), Ok(()));
        println!("verify: {:?}", t.elapsed());
        let mut bad = public.clone();
        bad[PUB_SUM_OUT] += Fp::ONE;
        assert!(verify(&config, &BlockAir, &bad, &proof, &mut tr()).is_err());
    }
}
