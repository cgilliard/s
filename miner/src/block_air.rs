//! The segment circuit: proves that a run of transactions is valid and
//! correctly transforms the UTXO tree, with a chainable public interface so
//! a block can be split into segments proven in parallel.
//!
//! # Statement
//!
//! Public values (184 elements):
//!
//! ```text
//! root_in[8] root_out[8]            UTXO root before and after
//! isp_in[16] isp_out[16]            inputs sponge state before and after
//! osp_in[16] osp_out[16]            outputs sponge state before and after
//! nsp_in[16] nsp_out[16]            name operations sponge state before and after
//! pos_in(2) pos_out(2)              next output position before and after
//! sum_in[6] sum_out[6]              16-bit limb sums of input and output amounts
//! carry_in[28] carry_out[28]        transaction open across the boundary:
//!                                   open, message[8], body sponge[16],
//!                                   inputs, outputs and operations left
//!                                   (all zero when closed)
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
//! slot (a witness) into the tree leaf, proves that leaf sits at the
//! input's position in the current tree, and clears it. For every output
//! it derives the commitment `H(key_hash || amount)` from a witness key
//! hash and appends its leaf, commitment and memo slot compressed, at the
//! next position. Positions are absorbed into the inputs sponge, and
//! output commitments and memo slots into the outputs sponge. A memo slot
//! ([`crate::transaction::memo_slot`]) is the memo's five elements, free,
//! and the amount's three limbs, constrained to be the amount the
//! commitment hides: so the amount the block lists (public, through the
//! outputs sponge) and the amount a spent leaf holds are the amounts the
//! commitments and the sums use (`docs/AMOUNTS.md`). The slot is also
//! absorbed into the body, so the signatures cover it. Per transaction, the body sponge is rebuilt from the
//! same registers the signatures and commitments use and must equal the
//! signed message.
//!
//! A transaction's name operations (see [`crate::names`]) come after its
//! outputs as digests: each is a free witness absorbed into the body, so
//! the signatures cover it, and into the operations sponge, which the
//! block's name segment must reproduce (see `crate::name_air`). The
//! segment applies no operation itself.
//!
//! # Schedule
//!
//! ```text
//! tx_start | resume                         body sponge header; counters n_in, n_out
//!   per input:  [xmss rows] pkh0 pkh1 cm0 cm1 ileaf ileaf2 ilist old/new x 40 body_in0 body_in1
//!   policy:     pstart cvs lhdr [conditions] pp0..pp3 ([xmss rows] pkh0 pkh1 psig)* pend
//!               cm0 cm1 ileaf ileaf2 ilist old/new x 40 body_in0 body_in1
//!   per output: ocm0 ocm1 oleaf oleaf2 olist olist2 body_out0 body_out1 body_out2 old/new x 40
//!               [cvc cvm] [rb0 rb1 rb2]        covered outputs, and the run's end
//!   per op:     op_body op_list
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
use crate::policy::{Cond, CondWitness, LEAF_CONDS, POLICY_DEPTH, PolicyInput};
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH, permute};
use crate::poseidon2_air::{COL_INPUT, COL_OUTPUT};
use crate::stark::{Air, Builder, Trace};
use crate::state_tree::{DEPTH, EMPTY};
use crate::transaction::{
    Commitment, DOM_BODY, DOM_COMMITMENT, DOM_PUBKEY, MEMO_LEN, Output, Sig, Transaction, amount_fps,
};
use crate::utxo::{self, UtxoSet};
use crate::xmss::{Digest, PUB_SEED_LEN, PublicKey};
use crate::xmss_fragment::{self, Cols as XCols, Types as XTypes};

const AMOUNT_BITS: usize = 64;
/// 16-bit limbs of amount sums: four hold an amount, six any sum of a
/// block's amounts (fewer than `2^32` of them).
pub const LIMBS: usize = 6;
const MASK30: u64 = (1 << 30) - 1;
const DOM_INPUTS: u32 = 0x21;
const DOM_OUTPUTS: u32 = 0x22;
const DOM_NAME_OPS: u32 = 0x23;
const DOM_SWEEPS: u32 = 0x24;

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
pub const T_OP_BODY: usize = HM_COLS + 29;
pub const T_OP_LIST: usize = HM_COLS + 30;
/// The second leaf row: the first's digest compressed with the creation
/// height (see [`crate::transaction::leaf`]).
pub const T_ILEAF2: usize = HM_COLS + 31;
pub const T_OLEAF2: usize = HM_COLS + 32;
// ---- policy input rows (see `docs/ELTOO.md` and `crate::policy`) ----
/// Pass row loading the policy input's registers.
pub const T_PSTART: usize = HM_COLS + 33;
/// Covered-run sponge start: `[count, 0, …]`.
pub const T_CVS: usize = HM_COLS + 34;
/// Leaf sponge start: the header block.
pub const T_LHDR: usize = HM_COLS + 35;
/// Threshold header block `[mode, m, n, 0, …]`.
pub const T_THR: usize = HM_COLS + 36;
/// Threshold channel block.
pub const T_CHAN: usize = HM_COLS + 37;
/// One listed key hash.
pub const T_KEY: usize = HM_COLS + 38;
/// A selected key, absorbed into the keys sponge after its `key` row.
pub const T_KSEL: usize = HM_COLS + 39;
/// The hash lock's preimage hashed (its own permutation).
pub const T_HL: usize = HM_COLS + 40;
/// The hash lock block, equal to the preimage's hash.
pub const T_HASH: usize = HM_COLS + 41;
pub const T_AFTER: usize = HM_COLS + 42;
pub const T_OLDER: usize = HM_COLS + 43;
pub const T_STATE: usize = HM_COLS + 44;
/// The covenant block: the covered digest.
pub const T_OUTS: usize = HM_COLS + 45;
/// The policy tree path, one row per level.
pub const T_PP0: usize = HM_COLS + 46;
pub const T_PP1: usize = HM_COLS + 47;
pub const T_PP2: usize = HM_COLS + 48;
pub const T_PP3: usize = HM_COLS + 49;
/// A signer's key hash absorbed into the signers sponge.
pub const T_PSIG: usize = HM_COLS + 50;
/// Pass row ending the signatures: signers and selected keys agree.
pub const T_PEND: usize = HM_COLS + 51;
/// A covered output's commitment, then memo, into the covered sponge.
pub const T_CVC: usize = HM_COLS + 52;
pub const T_CVM: usize = HM_COLS + 53;
/// The rebindable message over the channel, state and covered digest.
pub const T_RB0: usize = HM_COLS + 54;
pub const T_RB1: usize = HM_COLS + 55;
pub const T_RB2: usize = HM_COLS + 56;
const NUM_TYPES: usize = 57;
// ---- xmss fragment ----
pub const XCOLS: XCols = XCols::new(HM_COLS + NUM_TYPES);
pub const XTYPES: XTypes = XTypes {
    msg_start: T_MSG_START,
    msg_abs: T_MSG_ABS,
    load: T_LOAD,
    step: T_STEP,
    leaf: T_LEAF,
    tree_start: T_TREE_START,
    tree_abs: T_TREE_ABS,
};
/// The fragment's sibling register, shared with the tree update.
pub const R_SIB: usize = XCOLS.sib(0);
// ---- tree update ----
pub const C_LEVEL: usize = XCOLS.base + xmss_fragment::LEN;
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
/// The current name operation's digest, set entering its first row.
pub const R_OPD: usize = R_LEAF + DIGEST;
/// The name operations sponge.
pub const R_NSP: usize = R_OPD + DIGEST;
pub const R_OPS_LEFT: usize = R_NSP + WIDTH;
pub const C_OPS_ZERO: usize = R_OPS_LEFT + 1;
pub const C_OPS_INV: usize = C_OPS_ZERO + 1;
pub const C_GO_OPS: usize = C_OPS_INV + 1;
// ---- policy input registers ----
/// One from the policy input's start row to the transaction's end.
pub const R_POL: usize = C_GO_OPS + 1;
/// One over the policy input's own rows (start to its `body_in1`).
pub const R_PIN: usize = R_POL + 1;
/// Policy inputs left: 0 or 1, from the transaction header.
pub const R_POL_LEFT: usize = R_PIN + 1;
/// `in_zero` and no policy input left: outputs may follow.
pub const C_IN_DONE: usize = R_POL_LEFT + 1;
/// Dispatch rows, with the covered-run detours folded in.
pub const C_DISP: usize = C_IN_DONE + 1;
/// The spending transaction's state number.
pub const R_PSTATE: usize = C_DISP + 1;
/// Outputs before the covered run, and covered outputs left.
pub const R_CVB: usize = R_PSTATE + 1;
pub const R_CVN: usize = R_CVB + 1;
pub const C_CVB_ZERO: usize = R_CVN + 1;
pub const C_CVB_INV: usize = C_CVB_ZERO + 1;
pub const C_CVN_ZERO: usize = C_CVB_INV + 1;
pub const C_CVN_INV: usize = C_CVN_ZERO + 1;
/// The current output is in the covered run.
pub const R_INRUN: usize = C_CVN_INV + 1;
/// The spent output's creation height.
pub const R_CREATED: usize = R_INRUN + 1;
/// The message the signature fragment verifies: the body hash, or the
/// rebindable message for a rebindable threshold.
pub const R_SMSG: usize = R_CREATED + 1;
/// The rebindable message the policy input's signatures are over.
pub const R_RMSG: usize = R_SMSG + DIGEST;
/// The leaf's index in the policy tree, as bits.
pub const R_PIDX: usize = R_RMSG + DIGEST;
/// The leaf's element count, and blocks absorbed so far.
pub const R_LLEN: usize = R_PIDX + POLICY_DEPTH;
pub const R_LCNT: usize = R_LLEN + 1;
/// The leaf sponge.
pub const R_LSP: usize = R_LCNT + 1;
/// Conditions left, and the tags of the next conditions (the current
/// first, shifted as conditions start).
pub const R_NC: usize = R_LSP + WIDTH;
pub const C_NC_ZERO: usize = R_NC + 1;
pub const C_NC_INV: usize = C_NC_ZERO + 1;
pub const R_TAG: usize = C_NC_INV + 1;
/// Threshold: `m`, keys left to list, signatures left, and whether one
/// was seen.
pub const R_M: usize = R_TAG + LEAF_CONDS;
pub const C_M_INV: usize = R_M + 1;
pub const R_KREM: usize = C_M_INV + 1;
pub const C_KLAST: usize = R_KREM + 1;
pub const C_KLAST_INV: usize = C_KLAST + 1;
pub const R_SREM: usize = C_KLAST_INV + 1;
pub const C_SREM_ZERO: usize = R_SREM + 1;
pub const C_SREM_INV: usize = C_SREM_ZERO + 1;
pub const R_HADTHR: usize = C_SREM_INV + 1;
/// Rebindable mode, and the channel.
pub const R_REBIND: usize = R_HADTHR + 1;
pub const R_CHAN: usize = R_REBIND + 1;
/// A covenant was listed, with its covered digest; the covered run must
/// end; it did.
pub const R_HASCOV: usize = R_CHAN + DIGEST;
pub const R_NEEDRUN: usize = R_HASCOV + 1;
pub const R_RUNDONE: usize = R_NEEDRUN + 1;
pub const R_COV: usize = R_RUNDONE + 1;
/// The policy root, from the path.
pub const R_PROOT: usize = R_COV + DIGEST;
/// The selected keys and the signers sponges.
pub const R_KSP: usize = R_PROOT + DIGEST;
pub const R_SSP: usize = R_KSP + WIDTH;
/// The covered-run sponge.
pub const R_CSP: usize = R_SSP + WIDTH;
/// The end of a condition (a next-row dependent flag).
pub const C_CEND: usize = R_CSP + WIDTH;
/// Plain inputs done and a policy input left.
pub const C_GO_POL: usize = C_CEND + 1;
pub const NUM_COLS: usize = C_GO_POL + 1;

// ---- public values ----
pub const PUB_ROOT_IN: usize = 0;
pub const PUB_ROOT_OUT: usize = DIGEST;
pub const PUB_ISP_IN: usize = 2 * DIGEST;
pub const PUB_ISP_OUT: usize = PUB_ISP_IN + WIDTH;
pub const PUB_OSP_IN: usize = PUB_ISP_OUT + WIDTH;
pub const PUB_OSP_OUT: usize = PUB_OSP_IN + WIDTH;
pub const PUB_NSP_IN: usize = PUB_OSP_OUT + WIDTH;
pub const PUB_NSP_OUT: usize = PUB_NSP_IN + WIDTH;
pub const PUB_POS_IN: usize = PUB_NSP_OUT + WIDTH; // lo, hi
pub const PUB_POS_OUT: usize = PUB_POS_IN + 2;
pub const PUB_SUM_IN: usize = PUB_POS_OUT + 2;
pub const PUB_SUM_OUT: usize = PUB_SUM_IN + LIMBS;
pub const PUB_CARRY_IN: usize = PUB_SUM_OUT + LIMBS;
pub const PUB_CARRY_OUT: usize = PUB_CARRY_IN + CARRY_LEN;
/// The block's height: the creation height of every output.
pub const PUB_HEIGHT: usize = PUB_CARRY_OUT + CARRY_LEN;
pub const NUM_PUBLIC: usize = PUB_HEIGHT + 1;

/// Layout of a carry: open flag, message, body sponge, items left.
pub const CARRY_OPEN: usize = 0;
pub const CARRY_MSG: usize = 1;
pub const CARRY_BSP: usize = CARRY_MSG + DIGEST;
pub const CARRY_IN_LEFT: usize = CARRY_BSP + WIDTH;
pub const CARRY_OUT_LEFT: usize = CARRY_IN_LEFT + 1;
pub const CARRY_OPS_LEFT: usize = CARRY_OUT_LEFT + 1;
pub const CARRY_LEN: usize = CARRY_OPS_LEFT + 1;

/// Rows of one input (signature plus commitment, tree update and body).
/// Rows of an input whose key has `height`: its signature, key hash,
/// commitment, leaf and list rows, the removal, and the body rows.
pub const fn input_rows(height: usize) -> usize {
    xmss_fragment::rows(height) + 6 + 1 + 2 * DEPTH + 2
}
/// Rows of an input by the tallest key.
pub const ROWS_PER_INPUT: usize = input_rows(crate::xmss::MAX_HEIGHT);
/// Rows of one output.
pub const ROWS_PER_OUTPUT: usize = 9 + 2 * DEPTH;
/// Extra rows of an output in a policy input's covered run.
pub const ROWS_PER_COVERED: usize = 2;
/// Rows ending a covered run: the rebindable message.
pub const ROWS_RUN_END: usize = 3;
/// Rows of one name operation.
pub const ROWS_PER_OP: usize = 2;

/// Rows of a policy input: its start and covered-sponge rows, the leaf
/// header, the conditions, the path, the signatures (each a fragment, the
/// key hash and a signers row), the end row, then the commitment, leaf,
/// list, removal and body rows as a plain input has.
pub fn policy_rows(p: &PolicyInput) -> usize {
    let conds: usize = p
        .leaf
        .conds
        .iter()
        .map(|c| match c {
            Cond::Thresh { m, keys, .. } => 2 + keys.len() + *m as usize,
            Cond::Hash(_) => 2,
            _ => 1,
        })
        .sum();
    let sigs: usize = p
        .witness
        .iter()
        .filter_map(|w| match w {
            CondWitness::Signatures(s) => {
                Some(s.iter().map(|s| xmss_fragment::rows(s.pubkey.height()) + 3).sum::<usize>())
            }
            _ => None,
        })
        .sum();
    3 + conds + POLICY_DEPTH + sigs + 1 + 6 + 1 + 2 * DEPTH + 2
}

/// Rows of each item of `tx`, in item order (plain inputs, the policy
/// input, outputs, operations), and whether the transaction must stay
/// whole in one segment (it has a policy input: the covered run and the
/// policy's registers are not carried between segments).
pub fn item_rows_of(tx: &Transaction) -> (Vec<usize>, bool) {
    let mut rows: Vec<usize> = tx.inputs.iter().map(|i| input_rows(i.pubkey.height())).collect();
    let (mut start, mut count) = (usize::MAX, 0);
    if let Some(p) = tx.policy_inputs.first() {
        rows.push(policy_rows(p));
        start = p.covered.0 as usize;
        count = p.covered.1 as usize;
    }
    for j in 0..tx.outputs.len() {
        let covered = j >= start && j < start + count;
        let last = covered && j + 1 == start + count;
        rows.push(ROWS_PER_OUTPUT + usize::from(covered) * ROWS_PER_COVERED + usize::from(last) * ROWS_RUN_END);
    }
    rows.extend(std::iter::repeat_n(ROWS_PER_OP, tx.ops.len()));
    (rows, !tx.policy_inputs.is_empty())
}

/// Body elements per input, output and operation (see
/// `crate::transaction::body_elements`).
const BODY_PER_INPUT: u32 = 16;
const BODY_PER_OUTPUT: u32 = 24;
const BODY_PER_OP: u32 = 8;

/// Body sponge state after a transaction's header block.
pub fn body_init(n_in: u32, n_out: u32, n_ops: u32, n_policy: u32) -> [Fp; WIDTH] {
    let mut input = [Fp::ZERO; WIDTH];
    input[0] = Fp::new(n_in);
    input[1] = Fp::new(n_out);
    input[2] = Fp::new(n_ops);
    input[3] = Fp::new(n_policy);
    let len = 8 + BODY_PER_INPUT * (n_in + n_policy) + BODY_PER_OUTPUT * n_out + BODY_PER_OP * n_ops;
    input[RATE..].copy_from_slice(&cap_const::<Fp>(DOM_BODY, len));
    permute(input)
}

/// Absorbs one policy input (its policy root, then the amount with the
/// policy marker) into a body sponge.
pub fn body_absorb_policy(state: &mut [Fp; WIDTH], policy: &Digest, amount: u64) {
    absorb_block(state, policy);
    let mut blk = [Fp::ZERO; RATE];
    blk[PUB_SEED_LEN..PUB_SEED_LEN + 3].copy_from_slice(&amount_fps(amount));
    blk[RATE - 1] = Fp::ONE;
    absorb_block(state, &blk);
}

/// Absorbs one name operation's digest into a body sponge.
pub fn body_absorb_op(state: &mut [Fp; WIDTH], digest: &Digest) {
    absorb_block(state, digest);
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
    absorb_block(state, &output.slot());
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

/// Initial state of the name operations sponge.
pub fn initial_names_state() -> [Fp; WIDTH] {
    let mut state = [Fp::ZERO; WIDTH];
    state[RATE] = Fp::new(DOM_NAME_OPS);
    state
}

/// Absorbs one operation digest into the name operations sponge.
pub fn absorb_op(state: &mut [Fp; WIDTH], digest: &Digest) {
    absorb_block(state, digest);
}

/// Name operations sponge state after absorbing all of a block's
/// operation digests, in order.
pub fn names_state(digests: &[Digest]) -> [Fp; WIDTH] {
    let mut state = initial_names_state();
    for d in digests {
        absorb_op(&mut state, d);
    }
    state
}

/// Initial state of the sweeps sponge: the positions of the commits a
/// block's name segment sweeps.
pub fn initial_sweeps_state() -> [Fp; WIDTH] {
    let mut state = [Fp::ZERO; WIDTH];
    state[RATE] = Fp::new(DOM_SWEEPS);
    state
}

/// Absorbs one swept position into the sweeps sponge, as
/// [`absorb_position`] does for the inputs sponge.
pub fn absorb_sweep(state: &mut [Fp; WIDTH], position: u64) {
    absorb_position(state, position);
}

/// Sweeps sponge state after absorbing all of a block's swept positions.
pub fn sweeps_state(positions: &[u64]) -> [Fp; WIDTH] {
    let mut state = initial_sweeps_state();
    for &p in positions {
        absorb_sweep(&mut state, p);
    }
    state
}

/// Absorbs one input position into the inputs sponge.
pub fn absorb_position(state: &mut [Fp; WIDTH], position: u64) {
    state[0] = state[0].add(&Fp::new((position & MASK30) as u32));
    state[1] = state[1].add(&Fp::new((position >> 30) as u32));
    *state = permute(*state);
}

/// Absorbs one output's commitment, then its memo slot (memo and public
/// amount), into the outputs sponge.
pub fn absorb_output(state: &mut [Fp; WIDTH], commitment: &Commitment, slot: &Digest) {
    absorb_block(state, commitment);
    absorb_block(state, slot);
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
        absorb_output(&mut state, &o.commitment, &o.slot());
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
        let ileaf2 = l[T_ILEAF2];
        let oleaf2 = l[T_OLEAF2];
        let (pstart, cvs, lhdr, thr, chan, key, ksel) =
            (l[T_PSTART], l[T_CVS], l[T_LHDR], l[T_THR], l[T_CHAN], l[T_KEY], l[T_KSEL]);
        let (hl, hash_t, after, older, state_t, outs) =
            (l[T_HL], l[T_HASH], l[T_AFTER], l[T_OLDER], l[T_STATE], l[T_OUTS]);
        let (pp0, pp1, pp2, pp3, psig, pend) = (l[T_PP0], l[T_PP1], l[T_PP2], l[T_PP3], l[T_PSIG], l[T_PEND]);
        let (cvc, cvm, rb0, rb1, rb2) = (l[T_CVC], l[T_CVM], l[T_RB0], l[T_RB1], l[T_RB2]);
        let (pol, pin, pol_left, inrun) = (l[R_POL], l[R_PIN], l[R_POL_LEFT], l[R_INRUN]);
        let (pstate, cvb, cvn, created) = (l[R_PSTATE], l[R_CVB], l[R_CVN], l[R_CREATED]);
        let (cvb_zero, cvn_zero, nc_zero, srem_zero) = (l[C_CVB_ZERO], l[C_CVN_ZERO], l[C_NC_ZERO], l[C_SREM_ZERO]);
        let (nc, m_reg, krem, klast, srem, hadthr) = (l[R_NC], l[R_M], l[R_KREM], l[C_KLAST], l[R_SREM], l[R_HADTHR]);
        let (rebind, hascov, needrun, rundone, cend) =
            (l[R_REBIND], l[R_HASCOV], l[R_NEEDRUN], l[R_RUNDONE], l[C_CEND]);
        // Leaf-sponge absorb rows: a block added to the leaf sponge register.
        let labs = thr + chan + key + hash_t + after + older + state_t + outs;
        let labs_next =
            |n: &[F]| n[T_THR] + n[T_CHAN] + n[T_KEY] + n[T_HASH] + n[T_AFTER] + n[T_OLDER] + n[T_STATE] + n[T_OUTS];
        let op_body = l[T_OP_BODY];
        let op_list = l[T_OP_LIST];
        let done = l[T_DONE];
        let resume = l[T_RESUME];
        let active = l[XCOLS.active()];
        let msg: [F; DIGEST] = core::array::from_fn(|i| l[R_MSG + i]);
        let smsg: [F; DIGEST] = core::array::from_fn(|i| l[R_SMSG + i]);
        xmss_fragment::eval(b, &XCOLS, &XTYPES, &smsg, n[T_PKH0]);

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
                + oleaf
                + ileaf2
                + oleaf2
                + op_body
                + op_list
                + cvs
                + lhdr
                + labs
                + ksel
                + hl
                + pp0
                + pp1
                + pp2
                + pp3
                + psig
                + cvc
                + cvm
                + rb0,
        );
        b.assert_eq(
            l[COL_ABSORB],
            msg_abs + tree_abs + pkh1 + cm1 + body_in1 + ocm1 + olist2 + body_out1 + body_out2 + rb1 + rb2,
        );
        b.assert_eq(l[COL_LOAD], load);
        b.assert_eq(l[COL_CHAIN], step * active);
        b.assert_eq(l[COL_PASS], step * (one - active) + tx_end + done + resume + pstart + pend);
        b.assert_zero(l[COL_COMPRESS]);
        b.when_first_row(one - tx_start - resume);
        b.when_last_row(one - done);

        // ---------------- counters and gadgets ----------------
        b.mark("counters");
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
        let ops_left = l[R_OPS_LEFT];
        let ops_zero = l[C_OPS_ZERO];
        b.assert_zero(ops_zero * ops_zero - ops_zero);
        b.assert_eq(ops_left * l[C_OPS_INV], one - ops_zero);
        b.assert_zero(ops_zero * ops_left);
        let go_out = l[C_GO_OUT];
        let go_ops = l[C_GO_OPS];
        let go_end = l[C_GO_END];
        let in_done = l[C_IN_DONE];
        b.assert_eq(in_done, in_zero * (one - pol_left));
        b.assert_eq(go_out, in_done * (one - out_zero));
        b.assert_eq(go_ops, in_done * out_zero * (one - ops_zero));
        b.assert_eq(go_end, in_done * out_zero * ops_zero);

        // ---------------- schedule ----------------
        b.mark("schedule");
        let nt = |t: usize| n[t];
        // dispatch after tx_start, after an input (body_in1), after an
        // output (out_end), after an operation (op_list) and after a
        // resume; or into the done rows, leaving the transaction open.
        // A covered output continues into its covered rows, and the run's
        // end into the rebindable message rows, before dispatching.
        let disp = l[C_DISP];
        b.assert_eq(
            disp,
            tx_start + body_in1 + out_end * (one - inrun) + op_list + resume + rb2 + cvm * (one - cvn_zero),
        );
        b.when_transition(disp * (one - in_zero) * (one - nt(T_MSG_START) - nt(T_DONE)));
        let go_pol = l[C_GO_POL];
        b.assert_eq(go_pol, in_zero * pol_left);
        b.when_transition(disp * go_pol * (one - nt(T_PSTART) - nt(T_DONE)));
        b.when_transition(disp * go_out * (one - nt(T_OCM0) - nt(T_DONE)));
        b.when_transition(disp * go_ops * (one - nt(T_OP_BODY) - nt(T_DONE)));
        b.when_transition(disp * go_end * (one - nt(T_TX_END) - nt(T_DONE)));
        // operation
        b.when_transition(op_body * (one - nt(T_OP_LIST)));
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
        // input tail (the signature rows are the fragment's)
        b.when_transition(pkh0 * (one - nt(T_PKH1)));
        b.when_transition(pkh1 * (one - pin) * (one - nt(T_CM0)));
        b.when_transition(pkh1 * pin * (one - nt(T_PSIG)));
        b.when_transition(cm0 * (one - nt(T_CM1)));
        b.when_transition(cm1 * (one - nt(T_ILEAF)));
        b.when_transition(ileaf * (one - nt(T_ILEAF2)));
        b.when_transition(ileaf2 * (one - nt(T_ILIST)));
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
        b.when_transition(oleaf * (one - nt(T_OLEAF2)));
        b.when_transition(oleaf2 * (one - nt(T_OLIST)));
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
        b.when_transition(nt(T_MSG_START) * (one - n[R_PIN]) * (n[R_IN_LEFT] - in_left + one));
        b.when_transition((one - nt(T_MSG_START) * (one - n[R_PIN]) - nt(T_TX_START)) * (n[R_IN_LEFT] - in_left));
        b.when_transition(nt(T_OCM0) * (n[R_OUT_LEFT] - out_left + one));
        b.when_transition((one - nt(T_OCM0) - nt(T_TX_START)) * (n[R_OUT_LEFT] - out_left));
        b.when_transition(nt(T_OP_BODY) * (n[R_OPS_LEFT] - ops_left + one));
        b.when_transition((one - nt(T_OP_BODY) - nt(T_TX_START)) * (n[R_OPS_LEFT] - ops_left));
        b.assert_zero(tx_end * in_left);
        b.assert_zero(tx_end * out_left);
        b.assert_zero(tx_end * ops_left);
        b.assert_zero(tx_end * pol_left);
        // Carries: the open transaction's state on the resume row and at
        // the end (carried there through the done rows), zero when closed.
        let carried = |c: usize| -> F {
            match c {
                CARRY_IN_LEFT => in_left,
                CARRY_OUT_LEFT => out_left,
                CARRY_OPS_LEFT => ops_left,
                c if c < CARRY_BSP => l[R_MSG + c - CARRY_MSG],
                c => l[R_BSP + c - CARRY_BSP],
            }
        };
        for c in CARRY_MSG..CARRY_LEN {
            b.when_first_row(resume * carried(c) - pubv(PUB_CARRY_IN + c));
            b.when_last_row(open * carried(c) - pubv(PUB_CARRY_OUT + c));
        }

        // ---------------- registers: amount bits ----------------
        b.mark("amount registers");
        let pub_seed: [F; PUB_SEED_LEN] = core::array::from_fn(|i| l[XCOLS.pub_seed(i)]);
        let abits: [F; AMOUNT_BITS] = core::array::from_fn(|i| l[R_ABITS + i]);
        let (mut amt_lo, mut amt_mid, mut amt_hi) = (F::ZERO, F::ZERO, F::ZERO);
        let mut l16 = [F::ZERO; LIMBS];
        for (i, bit) in abits.iter().enumerate() {
            b.assert_zero(*bit * *bit - *bit);
            b.when_transition(
                (one - nt(T_MSG_START) * (one - n[R_PIN]) - nt(T_OCM0) - nt(T_PSTART)) * (n[R_ABITS + i] - *bit),
            );
            if i < 30 {
                amt_lo += *bit * pow2::<F>(i);
            } else if i < 60 {
                amt_mid += *bit * pow2::<F>(i - 30);
            } else {
                amt_hi += *bit * pow2::<F>(i - 60);
            }
            l16[i / 16] += *bit * pow2::<F>(i % 16);
        }
        b.assert_zero(oleaf2 * (l[COL_INPUT + RATE] - pubv(PUB_HEIGHT)));
        for i in 0..DIGEST {
            b.when_transition((one - nt(T_TX_START)) * (n[R_MSG + i] - msg[i]));
            b.when_transition((one - nt(T_OCM0)) * (n[R_OCM + i] - l[R_OCM + i]));
            b.when_transition(
                (one - nt(T_OCM0) - nt(T_MSG_START) * (one - n[R_PIN]) - nt(T_PSTART))
                    * (n[R_MEMO + i] - l[R_MEMO + i]),
            );
            // Leaves: the commitment just hashed and the memo, compressed,
            // then that digest compressed with the creation height: the
            // block's (public) for an output, a witness for an input, which
            // the tree path authenticates.
            b.when_transition(nt(T_ILEAF) * (n[COL_INPUT + i] - l[COL_ACC + i]));
            b.assert_zero(ileaf * (l[COL_INPUT + RATE + i] - l[R_MEMO + i]));
            b.assert_zero(oleaf * (l[COL_INPUT + i] - l[R_OCM + i]));
            b.assert_zero(oleaf * (l[COL_INPUT + RATE + i] - l[R_MEMO + i]));
            b.when_transition((nt(T_ILEAF2) + nt(T_OLEAF2)) * (n[COL_INPUT + i] - l[COL_ACC + i]));
            if i > 0 {
                b.assert_zero((ileaf2 + oleaf2) * l[COL_INPUT + RATE + i]);
            }
            b.when_transition(oleaf2 * (n[R_LEAF + i] - l[COL_ACC + i]));
            b.when_transition((one - oleaf2) * (n[R_LEAF + i] - l[R_LEAF + i]));
            // The operation digest is a witness entering its first row.
            b.when_transition((one - nt(T_OP_BODY)) * (n[R_OPD + i] - l[R_OPD + i]));
            b.assert_zero((olist2 + body_out2) * (l[COL_DATA + i] - l[R_MEMO + i]));
            // pkroot: set entering pkh0 from the tree root, else copied
            b.when_transition(nt(T_PKH0) * (n[R_PKROOT + i] - l[COL_ACC + i]));
            b.when_transition((one - nt(T_PKH0)) * (n[R_PKROOT + i] - l[R_PKROOT + i]));
        }

        // ---------------- key hash and commitment ----------------
        b.mark("key hash / commitment / amounts");
        let cap_pk = cap_const::<F>(DOM_PUBKEY, (DIGEST + PUB_SEED_LEN + 1) as u32);
        let cap_cm = cap_const::<F>(DOM_COMMITMENT, (DIGEST + 3) as u32);
        for i in 0..RATE {
            b.when_transition(nt(T_PKH0) * (n[COL_INPUT + i] - l[COL_ACC + i]));
            b.when_transition(nt(T_CM0) * (one - n[R_PIN]) * (n[COL_INPUT + i] - l[COL_ACC + i]));
            b.when_transition(nt(T_CM0) * n[R_PIN] * (n[COL_INPUT + i] - n[R_PROOT + i]));
            b.assert_zero(pkh0 * (l[COL_INPUT + RATE + i] - cap_pk[i]));
            b.assert_zero(cm0 * (l[COL_INPUT + RATE + i] - cap_cm[i]));
            // An output's commitment is H(key_hash || amount) with the key
            // hash a free witness, so the amount summed is the one it hides.
            b.assert_zero(ocm0 * (l[COL_INPUT + RATE + i] - cap_cm[i]));
            b.assert_zero(ocm1 * (l[COL_ACC + i] - l[R_OCM + i]));
            // The key hash covers the tree height: the fragment's for now.
            let pkh1_data = match i {
                _ if i < PUB_SEED_LEN => pub_seed[i],
                PUB_SEED_LEN => xmss_fragment::height_value(l, &XCOLS),
                _ => F::ZERO,
            };
            b.assert_zero(pkh1 * (l[COL_DATA + i] - pkh1_data));
            let amt_block = [amt_lo, amt_mid, amt_hi, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO];
            b.assert_zero(cm1 * (l[COL_DATA + i] - amt_block[i]));
            b.assert_zero(ocm1 * (l[COL_DATA + i] - amt_block[i]));
            b.assert_zero(body_out1 * (l[COL_DATA + i] - amt_block[i]));
            let body_in1_data = [pub_seed[0], pub_seed[1], pub_seed[2], pub_seed[3], amt_lo, amt_mid, amt_hi, F::ZERO];
            let body_pol_data = [F::ZERO, F::ZERO, F::ZERO, F::ZERO, amt_lo, amt_mid, amt_hi, one];
            b.assert_zero(body_in1 * (l[COL_DATA + i] - ((one - pin) * body_in1_data[i] + pin * body_pol_data[i])));
        }
        // The memo slot's last three elements are the amount's limbs: the
        // amount a spent leaf holds and a block lists is the one the
        // commitment hides and the sums count.
        let limbs3 = [amt_lo, amt_mid, amt_hi];
        for (k, limb) in limbs3.iter().enumerate() {
            b.assert_zero((cm1 + ocm1) * (l[R_MEMO + MEMO_LEN + k] - *limb));
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
        let dir = l[COL_DIR];
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

        // ---------------- policy input ----------------
        b.mark("policy input");
        let height = pubv(PUB_HEIGHT);
        let hold = |b: &mut Builder<'_, F>, reg: usize, len: usize, except: F| {
            for i in 0..len {
                b.when_transition((one - except) * (n[reg + i] - l[reg + i]));
            }
        };
        let zero_at_start = |b: &mut Builder<'_, F>, reg: usize, len: usize| {
            for i in 0..len {
                b.when_transition(nt(T_TX_START) * n[reg + i]);
            }
        };
        let is_bool = |b: &mut Builder<'_, F>, v: F| b.assert_zero(v * v - v);
        for v in
            [pol, pin, pol_left, inrun, cvb_zero, cvn_zero, nc_zero, srem_zero, klast, hadthr, rebind, hascov, rundone]
        {
            is_bool(b, v);
        }
        // Zero tests.
        b.assert_eq(cvb * l[C_CVB_INV], one - cvb_zero);
        b.assert_zero(cvb_zero * cvb);
        b.assert_eq(cvn * l[C_CVN_INV], one - cvn_zero);
        b.assert_zero(cvn_zero * cvn);
        b.assert_eq(nc * l[C_NC_INV], one - nc_zero);
        b.assert_zero(nc_zero * nc);
        b.assert_eq(srem * l[C_SREM_INV], one - srem_zero);
        b.assert_zero(srem_zero * srem);
        b.assert_eq(krem * l[C_KLAST_INV], one - klast);
        b.assert_zero(klast * krem);
        // Flags: `pol` from the start to the transaction's end, `pin` to the
        // input's last body row; one policy input at most, never split
        // between segments.
        b.when_first_row(pol);
        b.when_first_row(pin);
        b.when_first_row(resume * pol_left);
        b.when_last_row(open * pol);
        b.when_last_row(open * pol_left);
        b.when_transition(nt(T_PSTART) * (n[R_POL] - one));
        b.when_transition(tx_end * n[R_POL]);
        b.when_transition((one - nt(T_PSTART) - tx_end) * (n[R_POL] - pol));
        b.when_transition(nt(T_PSTART) * (n[R_PIN] - one));
        b.when_transition(body_in1 * n[R_PIN]);
        b.when_transition((one - nt(T_PSTART) - body_in1) * (n[R_PIN] - pin));
        b.when_transition(nt(T_PSTART) * (n[R_POL_LEFT] - pol_left + one));
        b.when_transition((one - nt(T_TX_START) - nt(T_PSTART)) * (n[R_POL_LEFT] - pol_left));
        // Registers the start row loads, held until the next policy input.
        for (reg, len) in
            [(R_PSTATE, 1), (R_CREATED, 1), (R_RMSG, DIGEST), (R_PIDX, POLICY_DEPTH), (R_LLEN, 1), (R_CHAN, DIGEST)]
        {
            hold(b, reg, len, nt(T_PSTART));
        }
        for i in 0..POLICY_DEPTH {
            is_bool(b, l[R_PIDX + i]);
        }
        // The signing message: the body hash outside a policy input and for
        // body-mode thresholds, the rebindable message otherwise.
        hold(b, R_SMSG, DIGEST, nt(T_TX_START) + nt(T_PSTART) + body_in1);
        // (`rebind` is only ever set within a policy input.)
        for i in 0..DIGEST {
            b.assert_zero((one - pin) * (smsg[i] - msg[i]));
            b.assert_zero(msg_abs * (one - rebind) * (smsg[i] - msg[i]));
            b.assert_zero(msg_abs * rebind * (smsg[i] - l[R_RMSG + i]));
        }
        // A rebindable signature's leaf index is the state number.
        let idx = (0..crate::xmss::MAX_HEIGHT).fold(F::ZERO, |a, i| a + l[XCOLS.idx(i)] * pow2::<F>(i));
        b.assert_zero(msg_start * rebind * (idx - pstate));
        // The covered run: counters loaded at the start, zero for a
        // transaction without a policy input, moving as outputs begin.
        for reg in [R_CVB, R_CVN] {
            hold(b, reg, 1, nt(T_PSTART) + nt(T_TX_START) + nt(T_OCM0));
        }
        zero_at_start(b, R_CVB, 1);
        zero_at_start(b, R_CVN, 1);
        b.when_transition(nt(T_OCM0) * (n[R_INRUN] - cvb_zero * (one - cvn_zero)));
        b.when_transition(nt(T_OCM0) * (n[R_CVB] - cvb + (one - cvb_zero)));
        b.when_transition(nt(T_OCM0) * (n[R_CVN] - cvn + n[R_INRUN]));
        hold(b, R_INRUN, 1, nt(T_OCM0) + nt(T_TX_START));
        zero_at_start(b, R_INRUN, 1);
        // Threshold, covenant and run flags: free entering their rows, zero
        // for a fresh transaction.
        for reg in [R_REBIND, R_M, R_HADTHR, R_HASCOV, R_RUNDONE] {
            zero_at_start(b, reg, 1);
        }
        hold(b, R_REBIND, 1, nt(T_THR) + nt(T_TX_START));
        hold(b, R_M, 1, nt(T_THR) + nt(T_TX_START));
        hold(b, R_KREM, 1, nt(T_THR) + nt(T_KEY));
        hold(b, R_SREM, 1, nt(T_THR) + nt(T_PSIG) + nt(T_TX_START));
        zero_at_start(b, R_SREM, 1);
        hold(b, R_HADTHR, 1, nt(T_THR) + nt(T_TX_START));
        b.when_transition(nt(T_THR) * (n[R_HADTHR] - one));
        b.when_transition(nt(T_THR) * hadthr);
        hold(b, R_HASCOV, 1, nt(T_OUTS) + nt(T_TX_START));
        b.when_transition(nt(T_OUTS) * (n[R_HASCOV] - one));
        b.when_transition(nt(T_OUTS) * hascov);
        hold(b, R_COV, DIGEST, nt(T_OUTS));
        hold(b, R_RUNDONE, 1, rb2 + nt(T_TX_START));
        b.when_transition(rb2 * (n[R_RUNDONE] - one));
        b.assert_eq(needrun, rebind + hascov - rebind * hascov);
        b.assert_zero(tx_end * needrun * (one - rundone));
        // Sponges: leaf, selected keys, signers, covered run.
        for j in 0..WIDTH {
            b.when_transition((lhdr + labs) * (n[R_LSP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - lhdr - labs) * (n[R_LSP + j] - l[R_LSP + j]));
            b.when_transition(ksel * (n[R_KSP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - ksel - nt(T_THR)) * (n[R_KSP + j] - l[R_KSP + j]));
            b.when_transition(psig * (n[R_SSP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - psig - nt(T_THR)) * (n[R_SSP + j] - l[R_SSP + j]));
            b.when_transition((cvs + cvc + cvm) * (n[R_CSP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - cvs - cvc - cvm) * (n[R_CSP + j] - l[R_CSP + j]));
        }
        // Leaf: header, element count, conditions left and their tags.
        hold(b, R_LCNT, 1, nt(T_LHDR) + labs_next(n));
        b.when_transition(nt(T_LHDR) * (n[R_LCNT] - one));
        b.when_transition(labs_next(n) * (n[R_LCNT] - l[R_LCNT] - one));
        b.when_transition(nt(T_PP0) * (l[R_LCNT] * F::from_u32(DIGEST as u32) - l[R_LLEN]));
        let cstart_next = nt(T_THR) + nt(T_HL) + nt(T_AFTER) + nt(T_OLDER) + nt(T_STATE) + nt(T_OUTS);
        hold(b, R_NC, 1, cstart_next + nt(T_LHDR));
        b.when_transition(cstart_next * (n[R_NC] - nc + one));
        for k in 0..LEAF_CONDS {
            let next_tag = if k + 1 < LEAF_CONDS { l[R_TAG + k + 1] } else { F::ZERO };
            b.when_transition(cstart_next * (n[R_TAG + k] - next_tag));
            b.when_transition((one - cstart_next - nt(T_LHDR)) * (n[R_TAG + k] - l[R_TAG + k]));
            b.assert_zero(lhdr * (l[COL_INPUT + 1 + k] - l[R_TAG + k]));
        }
        b.assert_zero(lhdr * (l[COL_INPUT] - nc));
        for i in 1 + LEAF_CONDS..RATE {
            b.assert_zero(lhdr * l[COL_INPUT + i]);
        }
        let cap_leaf = [
            F::from_u32(crate::policy::DOM_POLICY_LEAF),
            l[R_LLEN],
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ];
        let cap_hl = cap_const::<F>(crate::policy::DOM_HASHLOCK, DIGEST as u32);
        let cap_cv = [
            F::from_u32(crate::policy::DOM_COVERED),
            F::from_u32(8) + cvn * F::from_u32(16),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ];
        let cap_rb = cap_const::<F>(crate::policy::DOM_REBIND, (2 * DIGEST + 1) as u32);
        let cap_signers = [
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::from_u32(crate::policy::DOM_SIGNERS),
            m_reg * F::from_u32(DIGEST as u32),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ];
        // The end of a condition: dispatch to the next or to the path.
        b.when_transition(
            cend - (lhdr + hash_t + after + older + state_t + outs + ksel * klast + key * klast * (one - nt(T_KSEL))),
        );
        b.when_last_row(cend);
        b.when_transition(cend * nc_zero * (one - nt(T_PP0)));
        b.when_transition(cend * (one - nc_zero) * (one - cstart_next));
        let tag_next = nt(T_THR)
            + nt(T_HL) * F::from_u32(2)
            + nt(T_AFTER) * F::from_u32(3)
            + nt(T_OLDER) * F::from_u32(4)
            + nt(T_STATE) * F::from_u32(5)
            + nt(T_OUTS) * F::from_u32(6);
        b.when_transition(cend * (one - nc_zero) * (l[R_TAG] - tag_next));
        // Schedule within the policy input.
        b.when_transition(pstart * (one - nt(T_CVS)));
        b.when_transition(cvs * (one - nt(T_LHDR)));
        b.when_transition(thr * (one - nt(T_CHAN)));
        b.when_transition(chan * (one - nt(T_KEY)));
        b.when_transition(key * (one - klast) * (one - nt(T_KEY) - nt(T_KSEL)));
        b.when_transition(ksel * (one - klast) * (one - nt(T_KEY)));
        b.when_transition(nt(T_KSEL) * (one - key));
        b.when_transition(hl * (one - nt(T_HASH)));
        b.when_transition(nt(T_HASH) * (one - hl));
        b.when_transition(pp0 * (one - nt(T_PP1)));
        b.when_transition(pp1 * (one - nt(T_PP2)));
        b.when_transition(pp2 * (one - nt(T_PP3)));
        b.when_transition(pp3 * (one - srem_zero) * (one - nt(T_MSG_START)));
        b.when_transition(pp3 * srem_zero * (one - nt(T_PEND)));
        b.when_transition(psig * (one - srem_zero) * (one - nt(T_MSG_START)));
        b.when_transition(psig * srem_zero * (one - nt(T_PEND)));
        b.when_transition(nt(T_PSIG) * (one - pkh1));
        b.when_transition(pend * (one - nt(T_CM0)));
        b.when_transition(out_end * inrun * (one - nt(T_CVC)));
        b.when_transition(cvc * (one - nt(T_CVM)));
        b.when_transition(cvm * cvn_zero * (one - nt(T_RB0)));
        b.when_transition(rb0 * (one - nt(T_RB1)));
        b.when_transition(rb1 * (one - nt(T_RB2)));
        // Counters moved by rows.
        b.when_transition(nt(T_KEY) * (n[R_KREM] - krem + one));
        b.when_transition(nt(T_PSIG) * (n[R_SREM] - srem + one));
        // Policy root after the path; checks at the end of the signatures.
        hold(b, R_PROOT, DIGEST, pp3);
        b.assert_zero(pend * srem);
        for j in 0..WIDTH {
            b.assert_zero(pend * (l[R_KSP + j] - l[R_SSP + j]));
            b.assert_zero(thr * (l[R_KSP + j] - cap_signers[j]));
            b.assert_zero(thr * (l[R_SSP + j] - cap_signers[j]));
        }
        b.assert_zero(thr * (m_reg * l[C_M_INV] - one));
        b.assert_zero(thr * (srem - m_reg));
        b.assert_zero(ileaf2 * pin * (l[COL_INPUT + RATE] - created));
        b.assert_zero(rb2 * hascov * cvn);
        let bits_v = xmss_fragment::bits_value(l, &XCOLS);
        for i in 0..RATE {
            let blk = l[COL_INPUT + i] - l[R_LSP + i];
            // Leaf rows continue the leaf sponge; the header starts it.
            b.assert_zero(labs * (l[COL_INPUT + RATE + i] - l[R_LSP + RATE + i]));
            b.assert_zero(lhdr * (l[COL_INPUT + RATE + i] - cap_leaf[i]));
            // Threshold header: mode, m, n.
            let thr_word = match i {
                0 => rebind,
                1 => m_reg,
                2 => krem,
                _ => F::ZERO,
            };
            b.assert_zero(thr * (blk - thr_word));
            // Channel: the register's, zero in body mode.
            b.assert_zero(chan * (blk - l[R_CHAN + i]));
            b.assert_zero(chan * (one - rebind) * blk);
            // A selected key: the key row's block, into the keys sponge.
            b.when_transition(nt(T_KSEL) * (n[COL_INPUT + i] - n[R_KSP + i] - blk));
            b.assert_zero(ksel * (l[COL_INPUT + RATE + i] - l[R_KSP + RATE + i]));
            // Hash lock: the preimage's hash is the block.
            b.assert_zero(hl * (l[COL_INPUT + RATE + i] - cap_hl[i]));
            b.when_transition(nt(T_HASH) * (n[COL_INPUT + i] - n[R_LSP + i] - l[COL_ACC + i]));
            // Timelocks and state: one word, non-negative differences.
            let word = after + older + state_t;
            if i == 0 {
                b.assert_zero(after * (bits_v - (height - blk)));
                b.assert_zero(older * (bits_v - (height - created - blk)));
                b.assert_zero(state_t * (bits_v - (pstate - blk - one)));
            } else {
                b.assert_zero(word * blk);
            }
            // Covenant: the covered digest the register holds.
            b.assert_zero(outs * (blk - l[R_COV + i]));
            // Signers: the key hash just computed, into the signers sponge.
            b.when_transition(nt(T_PSIG) * (n[COL_INPUT + i] - n[R_SSP + i] - l[COL_ACC + i]));
            b.assert_zero(psig * (l[COL_INPUT + RATE + i] - l[R_SSP + RATE + i]));
            // Policy path: compress the node with its sibling by the index
            // bit, starting from the leaf sponge's digest (the last leaf row
            // may be followed by a selected key's row).
            for (k, pp_next) in [nt(T_PP0), nt(T_PP1), nt(T_PP2), nt(T_PP3)].into_iter().enumerate() {
                let bit = n[R_PIDX + k];
                let node = if k == 0 { n[R_LSP + i] } else { l[COL_ACC + i] };
                b.when_transition(pp_next * (n[COL_INPUT + i] - ((one - bit) * node + bit * n[R_SIB + i])));
                b.when_transition(pp_next * (n[COL_INPUT + RATE + i] - (bit * node + (one - bit) * n[R_SIB + i])));
            }
            b.when_transition(pp3 * (n[R_PROOT + i] - l[COL_ACC + i]));
            // Covered run: its count, then each covered output's commitment and memo.
            let cvs_word = if i == 0 { cvn } else { F::ZERO };
            b.assert_zero(cvs * (l[COL_INPUT + i] - cvs_word));
            b.assert_zero(cvs * (l[COL_INPUT + RATE + i] - cap_cv[i]));
            b.assert_zero(cvc * (l[COL_INPUT + i] - l[R_CSP + i] - l[R_OCM + i]));
            b.assert_zero(cvc * (l[COL_INPUT + RATE + i] - l[R_CSP + RATE + i]));
            b.assert_zero(cvm * (l[COL_INPUT + i] - l[R_CSP + i] - l[R_MEMO + i]));
            b.assert_zero(cvm * (l[COL_INPUT + RATE + i] - l[R_CSP + RATE + i]));
            // The rebindable message: channel, state and the covered digest.
            b.assert_zero(rb0 * (l[COL_INPUT + i] - l[R_CHAN + i]));
            b.assert_zero(rb0 * (l[COL_INPUT + RATE + i] - cap_rb[i]));
            let rb1_word = if i == 0 { pstate } else { l[R_CSP + i - 1] };
            b.assert_zero(rb1 * (l[COL_DATA + i] - rb1_word));
            let rb2_word = if i == 0 { l[R_CSP + RATE - 1] } else { F::ZERO };
            b.assert_zero(rb2 * (l[COL_DATA + i] - rb2_word));
            b.assert_zero(rb2 * rebind * (l[COL_ACC + i] - l[R_RMSG + i]));
            b.assert_zero(rb2 * hascov * (l[R_CSP + i] - l[R_COV + i]));
        }
        // ---------------- register sponges: body, inputs, outputs, operations ----------------
        b.mark("register sponges");
        let body_len = F::from_u32(8)
            + (in_left + pol_left) * F::from_u32(BODY_PER_INPUT)
            + out_left * F::from_u32(BODY_PER_OUTPUT)
            + ops_left * F::from_u32(BODY_PER_OP);
        let bsp_rows = tx_start + body_in0 + body_in1 + body_out0 + body_out1 + body_out2 + op_body;
        let osp_rows = olist + olist2;
        for j in 0..WIDTH {
            b.when_transition(bsp_rows * (n[R_BSP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - bsp_rows) * (n[R_BSP + j] - l[R_BSP + j]));
            b.when_transition(ilist * (n[R_ISP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - ilist) * (n[R_ISP + j] - l[R_ISP + j]));
            b.when_transition(osp_rows * (n[R_OSP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - osp_rows) * (n[R_OSP + j] - l[R_OSP + j]));
            b.when_transition(op_list * (n[R_NSP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - op_list) * (n[R_NSP + j] - l[R_NSP + j]));
            b.when_first_row(l[R_ISP + j] - pubv(PUB_ISP_IN + j));
            b.when_first_row(l[R_OSP + j] - pubv(PUB_OSP_IN + j));
            b.when_first_row(l[R_NSP + j] - pubv(PUB_NSP_IN + j));
            b.when_last_row(l[R_ISP + j] - pubv(PUB_ISP_OUT + j));
            b.when_last_row(l[R_OSP + j] - pubv(PUB_OSP_OUT + j));
            b.when_last_row(l[R_NSP + j] - pubv(PUB_NSP_OUT + j));
        }
        for i in 0..RATE {
            // tx_start: body header block with the body capacity
            let header = match i {
                0 => in_left,
                1 => out_left,
                2 => ops_left,
                3 => pol_left,
                _ => F::ZERO,
            };
            b.assert_zero(tx_start * (l[COL_INPUT + i] - header));
            let cap_body = [F::from_u32(DOM_BODY), body_len, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO];
            b.assert_zero(tx_start * (l[COL_INPUT + RATE + i] - cap_body[i]));
            // body_in0 / body_out0 / olist0 / ilist: start rows continuing a register sponge
            b.assert_zero(
                body_in0 * (l[COL_INPUT + i] - l[R_BSP + i] - ((one - pin) * l[R_PKROOT + i] + pin * l[R_PROOT + i])),
            );
            b.assert_zero(body_in0 * (l[COL_INPUT + RATE + i] - l[R_BSP + RATE + i]));
            b.assert_zero(body_out0 * (l[COL_INPUT + i] - l[R_BSP + i] - l[R_OCM + i]));
            b.assert_zero(body_out0 * (l[COL_INPUT + RATE + i] - l[R_BSP + RATE + i]));
            b.assert_zero(olist * (l[COL_INPUT + i] - l[R_OSP + i] - l[R_OCM + i]));
            b.assert_zero(olist * (l[COL_INPUT + RATE + i] - l[R_OSP + RATE + i]));
            // operations: the digest into the body, then into the operations sponge
            b.assert_zero(op_body * (l[COL_INPUT + i] - l[R_BSP + i] - l[R_OPD + i]));
            b.assert_zero(op_body * (l[COL_INPUT + RATE + i] - l[R_BSP + RATE + i]));
            b.assert_zero(op_list * (l[COL_INPUT + i] - l[R_NSP + i] - l[R_OPD + i]));
            b.assert_zero(op_list * (l[COL_INPUT + RATE + i] - l[R_NSP + RATE + i]));
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
    /// Memo slot (memo and amount) of the output being spent, part of its
    /// leaf.
    pub memo: Digest,
    /// Creation height of the output being spent, part of its leaf.
    pub height: u32,
    pub signature: Sig,
    pub position: u64,
    pub siblings: [Digest; DEPTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputWitness {
    pub output: Output,
    pub siblings: [Digest; DEPTH],
}

/// A policy input (see [`crate::policy`]) with what the prover reads from
/// the state: the spent output's memo and creation height, its tree path,
/// and the rebindable message its signatures are over (zero when none).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyWitness {
    pub input: PolicyInput,
    /// The spent output's memo slot.
    pub memo: Digest,
    pub created: u32,
    pub siblings: [Digest; DEPTH],
    pub rmsg: Digest,
}

impl PolicyWitness {
    /// The threshold's mode: rebindable with its channel, if the leaf has
    /// a threshold in that mode.
    fn rebind_channel(&self) -> Option<Digest> {
        self.input.leaf.conds.iter().find_map(|c| match c {
            Cond::Thresh { mode: crate::policy::Mode::Rebindable { channel }, .. } => Some(*channel),
            _ => None,
        })
    }
}

/// The part of one transaction that a segment proves: some of its items,
/// in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxWitness {
    pub inputs: Vec<InputWitness>,
    /// The policy input, in a part that holds the whole transaction.
    pub policy: Option<PolicyWitness>,
    pub outputs: Vec<OutputWitness>,
    /// Digests of the name operations in this part.
    pub ops: Vec<Digest>,
    /// The transaction body hash, which every input signed.
    pub message: Digest,
    /// Inputs, outputs and operations of the transaction from this part
    /// on: all of them when the part starts the transaction.
    pub in_left: u32,
    pub out_left: u32,
    pub ops_left: u32,
    /// Policy inputs of the transaction from this part on: 0 or 1.
    pub pol_left: u32,
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
        let (start, count) =
            self.policy.as_ref().map_or((usize::MAX, 0), |p| (p.input.covered.0 as usize, p.input.covered.1 as usize));
        let outputs: usize = (0..self.outputs.len())
            .map(|j| {
                let covered = j >= start && j < start + count;
                let last = covered && j + 1 == start + count;
                ROWS_PER_OUTPUT + usize::from(covered) * ROWS_PER_COVERED + usize::from(last) * ROWS_RUN_END
            })
            .sum();
        1 + self.inputs.iter().map(|i| input_rows(i.pubkey.height())).sum::<usize>()
            + self.policy.as_ref().map_or(0, |p| policy_rows(&p.input))
            + outputs
            + self.ops.len() * ROWS_PER_OP
            + usize::from(self.ends)
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
    pub ops_left: u32,
}

impl Carry {
    pub const CLOSED: Carry =
        Carry { open: false, msg: [Fp::ZERO; DIGEST], bsp: [Fp::ZERO; WIDTH], in_left: 0, out_left: 0, ops_left: 0 };

    fn push_values(&self, v: &mut Vec<Fp>) {
        v.push(Fp::new(self.open as u32));
        v.extend_from_slice(&self.msg);
        v.extend_from_slice(&self.bsp);
        v.push(Fp::new(self.in_left));
        v.push(Fp::new(self.out_left));
        v.push(Fp::new(self.ops_left));
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
            ops_left: v[CARRY_OPS_LEFT].to_canonical(),
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
    pub nsp_in: [Fp; WIDTH],
    pub nsp_out: [Fp; WIDTH],
    pub pos_in: u64,
    pub pos_out: u64,
    pub sum_in: [u32; LIMBS],
    pub sum_out: [u32; LIMBS],
    pub carry_in: Carry,
    pub carry_out: Carry,
    pub height: u32,
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
        v.extend_from_slice(&self.nsp_in);
        v.extend_from_slice(&self.nsp_out);
        for p in [self.pos_in, self.pos_out] {
            v.push(Fp::new((p & MASK30) as u32));
            v.push(Fp::new((p >> 30) as u32));
        }
        v.extend(self.sum_in.iter().map(|x| Fp::new(*x)));
        v.extend(self.sum_out.iter().map(|x| Fp::new(*x)));
        self.carry_in.push_values(&mut v);
        self.carry_out.push_values(&mut v);
        v.push(Fp::new(self.height));
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
            nsp_in: state(PUB_NSP_IN),
            nsp_out: state(PUB_NSP_OUT),
            pos_in: pos(PUB_POS_IN)?,
            pos_out: pos(PUB_POS_OUT)?,
            sum_in: sums(PUB_SUM_IN),
            sum_out: sums(PUB_SUM_OUT),
            carry_in: Carry::from_values(&v[PUB_CARRY_IN..PUB_CARRY_IN + CARRY_LEN])?,
            carry_out: Carry::from_values(&v[PUB_CARRY_OUT..PUB_CARRY_OUT + CARRY_LEN])?,
            height: v[PUB_HEIGHT].to_canonical(),
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
    /// The block's height: the creation height of its outputs.
    pub height: u32,
    pub root_in: Digest,
    pub isp_in: [Fp; WIDTH],
    pub osp_in: [Fp; WIDTH],
    pub nsp_in: [Fp; WIDTH],
    pub pos_in: u64,
    pub txs: Vec<TxWitness>,
}

/// A run of one transaction's items, `start..end` in input, output then
/// operation order, placed in a segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Part {
    pub tx: usize,
    pub start: usize,
    pub end: usize,
}

/// Packs transactions into segments of `max_rows` trace rows (one kept
/// for padding), greedily and splitting a transaction between items when
/// it does not fit what is left of a segment. Each segment lists its
/// parts in order. `items(t)` gives the rows of each of transaction `t`'s
/// items ([`item_rows_of`]) and whether it must stay whole.
pub fn pack(num_txs: usize, items: impl Fn(usize) -> (Vec<usize>, bool), max_rows: usize) -> Vec<Vec<Part>> {
    let cap = max_rows - 1;
    let mut segments = Vec::new();
    let mut cur: Vec<Part> = Vec::new();
    let mut rows = 0;
    for tx in 0..num_txs {
        let (item_rows, whole) = items(tx);
        let n = item_rows.len();
        if whole {
            let total = 2 + item_rows.iter().sum::<usize>();
            assert!(total <= cap, "a transaction with a policy input does not fit a segment of {max_rows} rows");
            if rows + total > cap {
                segments.push(std::mem::take(&mut cur));
                rows = 0;
            }
            cur.push(Part { tx, start: 0, end: n });
            rows += total;
            continue;
        }
        // Rows item k needs, with the end row after the last item.
        let cost = |k: usize| item_rows[k] + usize::from(k + 1 == n);
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
                rows += item_rows[k];
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
        height: u32,
    ) -> utxo::Result<Vec<SegmentWitness>> {
        assert!(txs_per_segment > 0);
        let parts: Vec<Part> = txs
            .iter()
            .enumerate()
            .map(|(t, tx)| Part {
                tx: t,
                start: 0,
                end: tx.inputs.len() + tx.policy_inputs.len() + tx.outputs.len() + tx.ops.len(),
            })
            .collect();
        Self::collect_parts(utxo, wtxn, txs, parts.chunks(txs_per_segment).map(|c| c.to_vec()).collect(), height)
    }

    /// As [`SegmentWitness::collect`], packed by [`pack`] into segments of
    /// `max_rows` rows, transactions split between segments where needed.
    pub fn collect_by_rows(
        utxo: &UtxoSet,
        wtxn: &mut heed::RwTxn,
        txs: &[Transaction],
        max_rows: usize,
        height: u32,
    ) -> utxo::Result<Vec<SegmentWitness>> {
        let plan = pack(txs.len(), |t| item_rows_of(&txs[t]), max_rows);
        Self::collect_parts(utxo, wtxn, txs, plan, height)
    }

    /// Applies the parts of `txs` in order, one segment per entry of
    /// `segments`. A transaction's parts must be consecutive and cover its
    /// items in order.
    pub fn collect_parts(
        utxo: &UtxoSet,
        wtxn: &mut heed::RwTxn,
        txs: &[Transaction],
        segments: Vec<Vec<Part>>,
        height: u32,
    ) -> utxo::Result<Vec<SegmentWitness>> {
        let mut isp = initial_inputs_state();
        let mut osp = initial_outputs_state();
        let mut nsp = initial_names_state();
        let mut bsp = [Fp::ZERO; WIDTH];
        let mut out_segments = Vec::with_capacity(segments.len());
        for parts in segments {
            let root_in = utxo.root(wtxn)?;
            let pos_in = utxo.next_position(wtxn)?;
            let (isp_in, osp_in, nsp_in) = (isp, osp, nsp);
            let mut out = Vec::with_capacity(parts.len());
            for part in parts {
                let tx = &txs[part.tx];
                assert!(tx.policy_inputs.len() <= 1, "one policy input per transaction");
                let (n_in, n_pol, n_out, n_ops) =
                    (tx.inputs.len(), tx.policy_inputs.len(), tx.outputs.len(), tx.ops.len());
                assert!(part.start <= part.end && part.end <= n_in + n_pol + n_out + n_ops, "part out of range");
                assert!(
                    n_pol == 0 || (part.start == 0 && part.end == n_in + n_pol + n_out + n_ops),
                    "a policy spend stays whole"
                );
                let resume = if part.start == 0 {
                    bsp = body_init(n_in as u32, n_out as u32, n_ops as u32, n_pol as u32);
                    None
                } else {
                    Some(bsp)
                };
                let mut inputs = Vec::new();
                let mut policy = None;
                let mut outputs = Vec::new();
                let mut ops = Vec::new();
                for k in part.start..part.end {
                    if k >= n_in && k < n_in + n_pol {
                        let p = &tx.policy_inputs[k - n_in];
                        let (c, memo, created) = utxo.output_at(wtxn, p.position)?.ok_or(utxo::Error::CorruptIndex)?;
                        if c != p.commitment() || !utxo.spend_at(wtxn, &c, p.position)? {
                            return Err(utxo::Error::CorruptIndex);
                        }
                        let proof = utxo.prove(wtxn, p.position)?;
                        absorb_position(&mut isp, p.position);
                        body_absorb_policy(&mut bsp, &p.policy(), p.amount);
                        let covered = p.covered_outputs(&tx.outputs).unwrap_or_default();
                        let mut w =
                            PolicyWitness { input: p.clone(), memo, created, siblings: proof.siblings, rmsg: EMPTY };
                        if let Some(channel) = w.rebind_channel() {
                            w.rmsg = crate::policy::rebind_message(&channel, p.state, &covered);
                        }
                        policy = Some(w);
                        continue;
                    }
                    let k = if k > n_in { k - n_pol } else { k };
                    if k < n_in {
                        let inp = &tx.inputs[k];
                        let (commitment, position) = (inp.commitment(), inp.position);
                        let stored = utxo.output_at(wtxn, position)?;
                        let (memo, created) = match stored {
                            Some((_, memo, created)) => (memo, created),
                            // Tests: a lenient generator (`stark::lenient`)
                            // goes on with what a cheater would claim.
                            None if crate::stark::lenient() => (EMPTY, 0),
                            None => return Err(utxo::Error::CorruptIndex),
                        };
                        if !utxo.spend_at(wtxn, &commitment, position)? {
                            if !crate::stark::lenient() {
                                return Err(utxo::Error::CorruptIndex);
                            }
                            // The claimed output is not there: clear what is.
                            if let Some((c, ..)) = stored {
                                utxo.spend_at(wtxn, &c, position)?;
                            }
                        }
                        // Siblings are unchanged by the removal, so read them after it.
                        let proof = utxo.prove(wtxn, position)?;
                        absorb_position(&mut isp, position);
                        body_absorb_input(&mut bsp, &inp.pubkey, inp.amount);
                        inputs.push(InputWitness {
                            pubkey: inp.pubkey,
                            amount: inp.amount,
                            memo,
                            height: created,
                            signature: inp.signature.clone(),
                            position,
                            siblings: proof.siblings,
                        });
                    } else if k < n_in + n_out {
                        let o = &tx.outputs[k - n_in];
                        let position = utxo.next_position(wtxn)?;
                        let proof = utxo.prove(wtxn, position)?;
                        utxo.add_output(wtxn, &o.block_output(), height)?;
                        absorb_output(&mut osp, &o.commitment, &o.slot());
                        body_absorb_output(&mut bsp, o);
                        outputs.push(OutputWitness { output: *o, siblings: proof.siblings });
                    } else {
                        let digest = tx.ops[k - n_in - n_out].digest().expect("a well-formed operation");
                        absorb_op(&mut nsp, &digest);
                        body_absorb_op(&mut bsp, &digest);
                        ops.push(digest);
                    }
                }
                out.push(TxWitness {
                    inputs,
                    policy,
                    outputs,
                    ops,
                    message: tx.body_hash(),
                    in_left: n_in.saturating_sub(part.start) as u32,
                    out_left: n_out.saturating_sub(part.start.saturating_sub(n_in + n_pol)) as u32,
                    ops_left: (n_ops - part.start.saturating_sub(n_in + n_pol + n_out)) as u32,
                    pol_left: n_pol.saturating_sub(part.start.saturating_sub(n_in)) as u32,
                    resume,
                    ends: part.end == n_in + n_pol + n_out + n_ops,
                });
            }
            out_segments.push(SegmentWitness { height, root_in, isp_in, osp_in, nsp_in, pos_in, txs: out });
        }
        Ok(out_segments)
    }

    pub fn positions(&self) -> Vec<u64> {
        self.txs
            .iter()
            .flat_map(|t| t.inputs.iter().map(|i| i.position).chain(t.policy.iter().map(|p| p.input.position)))
            .collect()
    }

    pub fn outputs(&self) -> Vec<Output> {
        self.txs.iter().flat_map(|t| t.outputs.iter().map(|o| o.output)).collect()
    }

    /// The segment's output commitments, as they appear in the block.
    pub fn commitments(&self) -> Vec<Commitment> {
        self.txs.iter().flat_map(|t| t.outputs.iter().map(|o| o.output.commitment)).collect()
    }

    /// The outputs as a block lists them: commitment, memo and amount.
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
    2 + item_rows_of(tx).0.iter().sum::<usize>()
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Regs {
    xmss: xmss_fragment::Regs,
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
    /// The current item's memo slot.
    memo: Digest,
    leaf: Digest,
    opd: Digest,
    nsp: [Fp; WIDTH],
    ops_left: u32,
    // policy input
    pol: bool,
    pin: bool,
    pol_left: u32,
    pstate: u32,
    cvb: u32,
    cvn: u32,
    inrun: bool,
    created: u32,
    smsg: Digest,
    rmsg: Digest,
    pidx: usize,
    llen: u32,
    lcnt: u32,
    lsp: [Fp; WIDTH],
    nc: u32,
    tags: [u32; LEAF_CONDS],
    m: u32,
    krem: u32,
    srem: u32,
    hadthr: bool,
    rebind: bool,
    chan: Digest,
    hascov: bool,
    rundone: bool,
    cov: Digest,
    proot: Digest,
    ksp: [Fp; WIDTH],
    ssp: [Fp; WIDTH],
    csp: [Fp; WIDTH],
}

impl Regs {
    /// Clears the policy registers a transaction start resets; the rest
    /// hold their last values until the rows that set them.
    fn reset_policy(&mut self) {
        self.pol = false;
        self.pin = false;
        self.pol_left = 0;
        self.cvb = 0;
        self.cvn = 0;
        self.inrun = false;
        self.rebind = false;
        self.m = 0;
        self.srem = 0;
        self.hadthr = false;
        self.hascov = false;
        self.rundone = false;
    }

    fn write(&self, row: &mut [Fp]) {
        self.xmss.write(row, &XCOLS);
        self.write_rest(row);
    }

    /// Everything but the signature fragment's registers.
    fn write_rest(&self, row: &mut [Fp]) {
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
        let ops_zero = self.ops_left == 0;
        row[R_OPS_LEFT] = Fp::new(self.ops_left);
        row[C_OPS_ZERO] = Fp::new(ops_zero as u32);
        row[C_OPS_INV] = if ops_zero { Fp::ZERO } else { Fp::new(self.ops_left).inverse().unwrap() };
        let in_done = in_zero && self.pol_left == 0;
        row[C_GO_OUT] = Fp::new((in_done && !out_zero) as u32);
        row[C_GO_OPS] = Fp::new((in_done && out_zero && !ops_zero) as u32);
        row[C_GO_END] = Fp::new((in_done && out_zero && ops_zero) as u32);
        row[R_OPEN] = Fp::new(self.open as u32);
        row[R_MEMO..R_MEMO + DIGEST].copy_from_slice(&self.memo);
        row[R_LEAF..R_LEAF + DIGEST].copy_from_slice(&self.leaf);
        row[R_OPD..R_OPD + DIGEST].copy_from_slice(&self.opd);
        row[R_NSP..R_NSP + WIDTH].copy_from_slice(&self.nsp);
        // policy input
        let zero_test = |row: &mut [Fp], v: u32, zero_col: usize, inv_col: usize| {
            row[zero_col] = Fp::new((v == 0) as u32);
            row[inv_col] = if v == 0 { Fp::ZERO } else { Fp::new(v).inverse().unwrap() };
        };
        row[R_POL] = Fp::new(self.pol as u32);
        row[R_PIN] = Fp::new(self.pin as u32);
        row[R_POL_LEFT] = Fp::new(self.pol_left);
        row[C_IN_DONE] = Fp::new((in_zero && self.pol_left == 0) as u32);
        row[C_GO_POL] = Fp::new((in_zero && self.pol_left != 0) as u32);
        row[R_PSTATE] = Fp::new(self.pstate);
        row[R_CVB] = Fp::new(self.cvb);
        row[R_CVN] = Fp::new(self.cvn);
        zero_test(row, self.cvb, C_CVB_ZERO, C_CVB_INV);
        zero_test(row, self.cvn, C_CVN_ZERO, C_CVN_INV);
        row[R_INRUN] = Fp::new(self.inrun as u32);
        row[R_CREATED] = Fp::new(self.created);
        row[R_SMSG..R_SMSG + DIGEST].copy_from_slice(&self.smsg);
        row[R_RMSG..R_RMSG + DIGEST].copy_from_slice(&self.rmsg);
        for i in 0..POLICY_DEPTH {
            row[R_PIDX + i] = Fp::new(((self.pidx >> i) & 1) as u32);
        }
        row[R_LLEN] = Fp::new(self.llen);
        row[R_LCNT] = Fp::new(self.lcnt);
        row[R_LSP..R_LSP + WIDTH].copy_from_slice(&self.lsp);
        row[R_NC] = Fp::new(self.nc);
        zero_test(row, self.nc, C_NC_ZERO, C_NC_INV);
        for k in 0..LEAF_CONDS {
            row[R_TAG + k] = Fp::new(self.tags[k]);
        }
        row[R_M] = Fp::new(self.m);
        row[C_M_INV] = if self.m == 0 { Fp::ZERO } else { Fp::new(self.m).inverse().unwrap() };
        row[R_KREM] = Fp::new(self.krem);
        zero_test(row, self.krem, C_KLAST, C_KLAST_INV);
        row[R_SREM] = Fp::new(self.srem);
        zero_test(row, self.srem, C_SREM_ZERO, C_SREM_INV);
        row[R_HADTHR] = Fp::new(self.hadthr as u32);
        row[R_REBIND] = Fp::new(self.rebind as u32);
        row[R_CHAN..R_CHAN + DIGEST].copy_from_slice(&self.chan);
        row[R_HASCOV] = Fp::new(self.hascov as u32);
        row[R_NEEDRUN] = Fp::new((self.rebind || self.hascov) as u32);
        row[R_RUNDONE] = Fp::new(self.rundone as u32);
        row[R_COV..R_COV + DIGEST].copy_from_slice(&self.cov);
        row[R_PROOT..R_PROOT + DIGEST].copy_from_slice(&self.proot);
        row[R_KSP..R_KSP + WIDTH].copy_from_slice(&self.ksp);
        row[R_SSP..R_SSP + WIDTH].copy_from_slice(&self.ssp);
        row[R_CSP..R_CSP + WIDTH].copy_from_slice(&self.csp);
        // Dispatch rows: a covered output and the run's end detour first.
        let out_end = row[C_OUT_END] == Fp::ONE;
        let disp = row[T_TX_START] == Fp::ONE
            || row[T_BODY_IN1] == Fp::ONE
            || (out_end && !self.inrun)
            || row[T_OP_LIST] == Fp::ONE
            || row[T_RESUME] == Fp::ONE
            || row[T_RB2] == Fp::ONE
            || (row[T_CVM] == Fp::ONE && self.cvn != 0);
        row[C_DISP] = Fp::new(disp as u32);
        // Condition ends that do not depend on the next row; a key row's is
        // set by the generator.
        let cend = [T_LHDR, T_HASH, T_AFTER, T_OLDER, T_STATE, T_OUTS].iter().any(|&t| row[t] == Fp::ONE)
            || (row[T_KSEL] == Fp::ONE && self.krem == 0);
        row[C_CEND] = Fp::new(cend as u32);
    }
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
    /// The block's height: every output's creation height.
    height: u32,
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

    /// The leaf rows: the commitment and the memo register compressed
    /// (`ty`), then that compressed with the creation height (`ty2`).
    fn leaf_rows(&mut self, commitment: Digest, height: u32, ty: usize, ty2: usize) -> Digest {
        let mut input = [Fp::ZERO; WIDTH];
        input[..DIGEST].copy_from_slice(&commitment);
        input[DIGEST..].copy_from_slice(&self.regs.memo);
        self.b.start(input);
        let row = self.b.last_row_mut();
        row[ty] = Fp::ONE;
        self.regs.write(row);
        let inner = self.b.acc();
        let mut input = [Fp::ZERO; WIDTH];
        input[..DIGEST].copy_from_slice(&inner);
        input[DIGEST..].copy_from_slice(&crate::transaction::height_digest(height));
        self.b.start(input);
        let row = self.b.last_row_mut();
        row[ty2] = Fp::ONE;
        self.regs.write(row);
        let leaf = self.b.acc();
        debug_assert_eq!(leaf, crate::transaction::leaf(&commitment, &self.regs.memo, height));
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
            self.regs.xmss.sib = *sib;
            self.b.start(compress_input(&old_node, &self.regs.xmss.sib, right));
            {
                let row = self.b.last_row_mut();
                row[T_OLD] = Fp::ONE;
                row[COL_DIR] = Fp::new(right as u32);
                self.regs.write(row);
            }
            old_node = self.b.acc();
            self.regs.old = old_node;
            self.b.start(compress_input(&new_node, &self.regs.xmss.sib, right));
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
        crate::stark::refuse(old_node == self.regs.root, "old path does not reach the current root");
        self.regs.root = new_node;
    }

    fn input(&mut self, w: &InputWitness) {
        let ps = w.pubkey.pub_seed;
        let r = &mut self.regs;
        r.memo = w.memo;
        r.amount = w.amount;
        r.is_out = false;
        r.in_left -= 1;
        let msg = r.smsg;

        // the signature
        let mut xr = self.regs.xmss.clone();
        let regs = &self.regs;
        let root = xmss_fragment::generate(
            &mut self.b,
            &mut xr,
            &XCOLS,
            &XTYPES,
            &msg,
            &w.signature,
            &w.pubkey,
            &mut |row, _| regs.write_rest(row),
        );
        self.regs.xmss = xr;
        self.regs.pkroot = root;

        // key hash and commitment
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&root);
        input[RATE..].copy_from_slice(&cap_const::<Fp>(DOM_PUBKEY, (DIGEST + PUB_SEED_LEN + 1) as u32));
        self.b.start(input);
        {
            let row = self.b.last_row_mut();
            row[T_PKH0] = Fp::ONE;
            self.regs.write(row);
        }
        let mut seed_block = [Fp::ZERO; RATE];
        seed_block[..PUB_SEED_LEN].copy_from_slice(&ps);
        seed_block[PUB_SEED_LEN] = Fp::new(w.pubkey.height as u32);
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
        let leaf = self.leaf_rows(commitment, w.height, T_ILEAF, T_ILEAF2);

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

    /// A leaf-sponge row: `block` added to the leaf sponge register.
    fn leaf_absorb(&mut self, block: [Fp; RATE], ty: usize) {
        let lsp = self.regs.lsp;
        self.regs.lcnt += 1;
        let out = self.sponge_start(lsp, block, ty);
        self.regs.lsp = out;
    }

    /// The key hash rows after a signature: the fragment's root hashed with
    /// the public seed and tree height. Returns the key hash.
    fn key_hash_rows(&mut self, root: Digest, pk: &PublicKey) -> Digest {
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&root);
        input[RATE..].copy_from_slice(&cap_const::<Fp>(DOM_PUBKEY, (DIGEST + PUB_SEED_LEN + 1) as u32));
        self.b.start(input);
        {
            let row = self.b.last_row_mut();
            row[T_PKH0] = Fp::ONE;
            self.regs.write(row);
        }
        let mut seed_block = [Fp::ZERO; RATE];
        seed_block[..PUB_SEED_LEN].copy_from_slice(&pk.pub_seed);
        seed_block[PUB_SEED_LEN] = Fp::new(pk.height as u32);
        self.absorb(seed_block, T_PKH1);
        self.b.acc()
    }

    /// One signature's rows: the fragment, then the key hash rows.
    fn signature_rows(&mut self, sig: &Sig, pk: &PublicKey) -> Digest {
        let msg = self.regs.smsg;
        let mut xr = self.regs.xmss.clone();
        let regs = &self.regs;
        let root = xmss_fragment::generate(&mut self.b, &mut xr, &XCOLS, &XTYPES, &msg, sig, pk, &mut |row, _| {
            regs.write_rest(row)
        });
        self.regs.xmss = xr;
        self.regs.pkroot = root;
        self.key_hash_rows(root, pk)
    }

    fn policy(&mut self, w: &PolicyWitness) {
        let p = &w.input;
        let blocks = p.leaf.blocks();
        let channel = w.rebind_channel();
        let height = self.height;
        {
            let r = &mut self.regs;
            r.pol = true;
            r.pin = true;
            r.pol_left -= 1;
            r.memo = w.memo;
            r.amount = p.amount;
            r.is_out = false;
            r.pstate = p.state;
            r.cvb = p.covered.0 as u32;
            r.cvn = p.covered.1 as u32;
            r.created = w.created;
            r.rmsg = w.rmsg;
            r.pidx = p.index as usize;
            r.llen = (blocks.len() * DIGEST) as u32;
            r.chan = channel.unwrap_or(EMPTY);
            r.smsg = if channel.is_some() { w.rmsg } else { r.msg };
        }
        // start
        self.b.pass();
        {
            let row = self.b.last_row_mut();
            row[T_PSTART] = Fp::ONE;
            self.regs.write(row);
        }
        // the covered-run sponge: the count block
        let cvn = self.regs.cvn;
        let mut input = [Fp::ZERO; WIDTH];
        input[0] = Fp::new(cvn);
        input[RATE..].copy_from_slice(&cap_const::<Fp>(crate::policy::DOM_COVERED, 8 + 16 * cvn));
        self.b.start(input);
        {
            let row = self.b.last_row_mut();
            row[T_CVS] = Fp::ONE;
            self.regs.write(row);
        }
        self.regs.csp = self.b.state();
        // the leaf header
        let header = blocks[0];
        {
            let r = &mut self.regs;
            r.nc = p.leaf.conds.len() as u32;
            for k in 0..LEAF_CONDS {
                r.tags[k] = header[1 + k].to_canonical();
            }
            r.lcnt = 1;
        }
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&header);
        input[RATE..].copy_from_slice(&cap_const::<Fp>(crate::policy::DOM_POLICY_LEAF, self.regs.llen));
        self.b.start(input);
        {
            let row = self.b.last_row_mut();
            row[T_LHDR] = Fp::ONE;
            self.regs.write(row);
        }
        self.regs.lsp = self.b.state();
        // the conditions
        let mut bi = 1;
        for (cond, wit) in p.leaf.conds.iter().zip(&p.witness) {
            {
                let r = &mut self.regs;
                r.nc -= 1;
                for k in 0..LEAF_CONDS - 1 {
                    r.tags[k] = r.tags[k + 1];
                }
                r.tags[LEAF_CONDS - 1] = 0;
            }
            match (cond, wit) {
                (Cond::Thresh { mode, m, keys }, CondWitness::Signatures(signers)) => {
                    let n = keys.len() as u32;
                    {
                        let r = &mut self.regs;
                        r.rebind = matches!(mode, crate::policy::Mode::Rebindable { .. });
                        r.m = *m as u32;
                        r.krem = n;
                        r.srem = *m as u32;
                        r.hadthr = true;
                        let mut init = [Fp::ZERO; WIDTH];
                        init[RATE..]
                            .copy_from_slice(&cap_const::<Fp>(crate::policy::DOM_SIGNERS, *m as u32 * DIGEST as u32));
                        r.ksp = init;
                        r.ssp = init;
                    }
                    self.leaf_absorb(blocks[bi], T_THR);
                    bi += 1;
                    self.leaf_absorb(blocks[bi], T_CHAN);
                    bi += 1;
                    for j in 0..keys.len() {
                        let selected = signers.iter().any(|s| s.key as usize == j);
                        self.regs.krem -= 1;
                        self.leaf_absorb(blocks[bi], T_KEY);
                        {
                            let last = self.regs.krem == 0;
                            let row = self.b.last_row_mut();
                            row[C_CEND] = Fp::new((last && !selected) as u32);
                        }
                        if selected {
                            let ksp = self.regs.ksp;
                            let out = self.sponge_start(ksp, blocks[bi], T_KSEL);
                            self.regs.ksp = out;
                        }
                        bi += 1;
                    }
                }
                (Cond::Hash(_), CondWitness::Preimage(preimage)) => {
                    let mut input = [Fp::ZERO; WIDTH];
                    input[..RATE].copy_from_slice(preimage);
                    input[RATE..].copy_from_slice(&cap_const::<Fp>(crate::policy::DOM_HASHLOCK, DIGEST as u32));
                    self.b.start(input);
                    {
                        let row = self.b.last_row_mut();
                        row[T_HL] = Fp::ONE;
                        self.regs.write(row);
                    }
                    crate::stark::refuse(self.b.acc() == blocks[bi], "preimage does not open the hash lock");
                    self.leaf_absorb(blocks[bi], T_HASH);
                    bi += 1;
                }
                (Cond::After(v), CondWitness::None)
                | (Cond::Older(v), CondWitness::None)
                | (Cond::State(v), CondWitness::None) => {
                    let (ty, value) = match cond {
                        Cond::After(_) => (T_AFTER, height as i64 - *v as i64),
                        Cond::Older(_) => (T_OLDER, height as i64 - self.regs.created as i64 - *v as i64),
                        _ => (T_STATE, self.regs.pstate as i64 - *v as i64 - 1),
                    };
                    crate::stark::refuse((0..1 << 31).contains(&value), "a policy condition's lock has not passed");
                    self.leaf_absorb(blocks[bi], ty);
                    bi += 1;
                    let ksel = self.regs.xmss.ksel;
                    let row = self.b.last_row_mut();
                    xmss_fragment::write_bits(row, &XCOLS, value as u32, ksel);
                }
                (Cond::Outputs(list), CondWitness::None) => {
                    self.regs.cov = crate::policy::covered_digest(list);
                    self.regs.hascov = true;
                    self.leaf_absorb(blocks[bi], T_OUTS);
                    bi += 1;
                }
                _ => panic!("a policy witness does not fit its condition"),
            }
        }
        assert_eq!(bi, blocks.len());
        assert_eq!(self.regs.lcnt as usize * DIGEST, self.regs.llen as usize);
        // the path to the policy root, from the leaf sponge's digest
        let mut node: Digest = self.regs.lsp[..DIGEST].try_into().unwrap();
        debug_assert_eq!(node, p.leaf.hash(), "leaf sponge");
        for (k, ty) in [T_PP0, T_PP1, T_PP2, T_PP3].into_iter().enumerate() {
            let right = (p.index as usize >> k) & 1 == 1;
            let sib = p.siblings[k];
            self.regs.xmss.sib = sib;
            self.b.start(compress_input(&node, &sib, right));
            {
                let row = self.b.last_row_mut();
                row[ty] = Fp::ONE;
                self.regs.write(row);
            }
            node = self.b.acc();
        }
        self.regs.proot = node;
        crate::stark::refuse(node == p.policy(), "policy path does not reach the policy");
        // the signatures, each into the signers sponge
        for wit in &p.witness {
            let CondWitness::Signatures(signers) = wit else { continue };
            for signer in signers {
                let pkh = self.signature_rows(&signer.signature, &signer.pubkey);
                self.regs.srem -= 1;
                let ssp = self.regs.ssp;
                let out = self.sponge_start(ssp, pkh, T_PSIG);
                self.regs.ssp = out;
            }
        }
        crate::stark::refuse(self.regs.ksp == self.regs.ssp, "signers are not the selected keys");
        self.b.pass();
        {
            let row = self.b.last_row_mut();
            row[T_PEND] = Fp::ONE;
            self.regs.write(row);
        }
        // the commitment from the policy root and amount
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&node);
        input[RATE..].copy_from_slice(&cap_const::<Fp>(DOM_COMMITMENT, (DIGEST + 3) as u32));
        self.b.start(input);
        {
            let row = self.b.last_row_mut();
            row[T_CM0] = Fp::ONE;
            self.regs.write(row);
        }
        self.absorb(amt_block(p.amount), T_CM1);
        let commitment = self.b.acc();
        crate::stark::refuse(commitment == p.commitment(), "policy input commitment");
        for (acc, limb) in self.regs.sum_in.iter_mut().zip(limbs16(p.amount)) {
            *acc += limb.to_canonical();
        }
        let leaf = self.leaf_rows(commitment, w.created, T_ILEAF, T_ILEAF2);
        self.regs.old = leaf;
        self.regs.new = EMPTY;
        self.regs.level = 0;
        self.regs.pbits = core::array::from_fn(|i| Fp::new(((p.position >> i) & 1) as u32));
        let mut blk = [Fp::ZERO; RATE];
        blk[0] = Fp::new((p.position & MASK30) as u32);
        blk[1] = Fp::new((p.position >> 30) as u32);
        let isp = self.regs.isp;
        let out = self.sponge_start(isp, blk, T_ILIST);
        self.regs.isp = out;
        self.smt_update(p.position, &w.siblings);
        // body: the policy root, then the amount with the policy marker
        let bsp = self.regs.bsp;
        let out = self.sponge_start(bsp, node, T_BODY_IN0);
        self.regs.bsp = out;
        let mut blk = [Fp::ZERO; RATE];
        blk[PUB_SEED_LEN..PUB_SEED_LEN + 3].copy_from_slice(&amount_fps(p.amount));
        blk[RATE - 1] = Fp::ONE;
        let out = self.absorb(blk, T_BODY_IN1);
        self.regs.bsp = out;
        self.regs.pin = false;
        self.regs.smsg = self.regs.msg;
    }

    /// The covered-run rows after an output in the run, and the run's end.
    fn covered_rows(&mut self) {
        if !self.regs.inrun {
            return;
        }
        let csp = self.regs.csp;
        let out = self.sponge_start(csp, self.regs.ocm, T_CVC);
        self.regs.csp = out;
        let csp = self.regs.csp;
        let out = self.sponge_start(csp, self.regs.memo, T_CVM);
        self.regs.csp = out;
        if self.regs.cvn != 0 {
            return;
        }
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&self.regs.chan);
        input[RATE..].copy_from_slice(&cap_const::<Fp>(crate::policy::DOM_REBIND, (2 * DIGEST + 1) as u32));
        self.b.start(input);
        {
            let row = self.b.last_row_mut();
            row[T_RB0] = Fp::ONE;
            self.regs.write(row);
        }
        let mut blk = [Fp::ZERO; RATE];
        blk[0] = Fp::new(self.regs.pstate);
        blk[1..].copy_from_slice(&self.regs.csp[..RATE - 1]);
        self.absorb(blk, T_RB1);
        let mut blk = [Fp::ZERO; RATE];
        blk[0] = self.regs.csp[RATE - 1];
        self.absorb(blk, T_RB2);
        if self.regs.rebind {
            crate::stark::refuse(
                self.b.acc() == self.regs.rmsg,
                "rebindable message does not match the covered outputs",
            );
        }
        if self.regs.hascov {
            crate::stark::refuse(
                self.regs.csp[..DIGEST] == self.regs.cov[..],
                "covered outputs are not the covenant's",
            );
        }
        self.regs.rundone = true;
    }

    fn output(&mut self, w: &OutputWitness) {
        let o = &w.output;
        let r = &mut self.regs;
        if r.cvb > 0 {
            r.cvb -= 1;
            r.inrun = false;
        } else if r.cvn > 0 {
            r.cvn -= 1;
            r.inrun = true;
        } else {
            r.inrun = false;
        }
        r.ocm = o.commitment;
        r.memo = o.slot();
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
        crate::stark::refuse(self.b.acc() == o.commitment, "output commitment does not match its key hash and amount");
        let leaf = self.leaf_rows(o.commitment, self.height, T_OLEAF, T_OLEAF2);
        self.regs.leaf = leaf;
        let out = self.sponge_start(osp, o.commitment, T_OLIST);
        self.regs.osp = out;
        // The amount sum advances on the row after olist.
        for (acc, limb) in self.regs.sum_out.iter_mut().zip(limbs16(o.amount)) {
            *acc += limb.to_canonical();
        }
        let out = self.absorb(o.slot(), T_OLIST2);
        self.regs.osp = out;
        let bsp = self.regs.bsp;
        let out = self.sponge_start(bsp, o.commitment, T_BODY_OUT0);
        self.regs.bsp = out;
        let out = self.absorb(amt_block(o.amount), T_BODY_OUT1);
        self.regs.bsp = out;
        let out = self.absorb(o.slot(), T_BODY_OUT2);
        self.regs.bsp = out;
        let position = self.regs.opos;
        self.regs.old = EMPTY;
        self.regs.new = self.regs.leaf;
        self.regs.level = 0;
        self.regs.pbits = core::array::from_fn(|i| Fp::new(((position >> i) & 1) as u32));
        self.smt_update(position, &w.siblings);
        self.regs.opos += 1;
        self.covered_rows();
    }

    /// A name operation: its digest into the body, then into the
    /// operations sponge.
    fn op(&mut self, digest: &Digest) {
        self.regs.opd = *digest;
        self.regs.ops_left -= 1;
        let bsp = self.regs.bsp;
        let out = self.sponge_start(bsp, *digest, T_OP_BODY);
        self.regs.bsp = out;
        let nsp = self.regs.nsp;
        let out = self.sponge_start(nsp, *digest, T_OP_LIST);
        self.regs.nsp = out;
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
            xmss: xmss_fragment::Regs::default(),
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
            opd: EMPTY,
            nsp: w.nsp_in,
            ops_left: 0,
            pol: false,
            pin: false,
            pol_left: 0,
            pstate: 0,
            cvb: 0,
            cvn: 0,
            inrun: false,
            created: 0,
            smsg: w.txs.first().map_or(EMPTY, |t| t.message),
            rmsg: EMPTY,
            pidx: 0,
            llen: 0,
            lcnt: 0,
            lsp: [Fp::ZERO; WIDTH],
            nc: 0,
            tags: [0; LEAF_CONDS],
            m: 0,
            krem: 0,
            srem: 0,
            hadthr: false,
            rebind: false,
            chan: EMPTY,
            hascov: false,
            rundone: false,
            cov: EMPTY,
            proot: EMPTY,
            ksp: [Fp::ZERO; WIDTH],
            ssp: [Fp::ZERO; WIDTH],
            csp: [Fp::ZERO; WIDTH],
        };
        let mut g = Gen { b: HashTraceBuilder::new(NUM_COLS), regs, height: w.height };
        let mut carry_in = Carry::CLOSED;
        let mut carry_out = Carry::CLOSED;
        let parts = w.txs.len();
        for (p, tx) in w.txs.iter().enumerate() {
            let (n_in, n_out, n_ops) = (tx.inputs.len() as u32, tx.outputs.len() as u32, tx.ops.len() as u32);
            crate::stark::refuse(
                n_in <= tx.in_left && n_out <= tx.out_left && n_ops <= tx.ops_left,
                "more items than the transaction has left",
            );
            crate::stark::refuse(n_out == 0 || n_in == tx.in_left, "outputs before the last input");
            crate::stark::refuse(
                tx.pol_left == 0 || tx.policy.is_some() || n_out == 0,
                "outputs before the policy input",
            );
            crate::stark::refuse(
                n_ops == 0 || (n_in == tx.in_left && n_out == tx.out_left),
                "operations before the last output",
            );
            crate::stark::refuse(
                !tx.ends || (n_in, n_out, n_ops) == (tx.in_left, tx.out_left, tx.ops_left),
                "a part that ends has every item left",
            );
            crate::stark::refuse(
                tx.pol_left <= 1 && (tx.policy.is_some() == (tx.pol_left == 1)),
                "one policy input, whole",
            );
            crate::stark::refuse(
                tx.policy.is_none() || (tx.resume.is_none() && tx.ends),
                "a policy spend is never split",
            );
            g.regs.msg = tx.message;
            g.regs.in_left = tx.in_left;
            g.regs.out_left = tx.out_left;
            g.regs.ops_left = tx.ops_left;
            g.regs.is_out = false;
            g.regs.open = true;
            g.regs.reset_policy();
            g.regs.pol_left = tx.pol_left;
            g.regs.smsg = tx.message;
            match tx.resume {
                None => {
                    let mut input = [Fp::ZERO; WIDTH];
                    input[0] = Fp::new(tx.in_left);
                    input[1] = Fp::new(tx.out_left);
                    input[2] = Fp::new(tx.ops_left);
                    input[3] = Fp::new(tx.pol_left);
                    input[RATE..].copy_from_slice(&cap_const::<Fp>(
                        DOM_BODY,
                        8 + BODY_PER_INPUT * (tx.in_left + tx.pol_left)
                            + BODY_PER_OUTPUT * tx.out_left
                            + BODY_PER_OP * tx.ops_left,
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
                    carry_in = Carry {
                        open: true,
                        msg: tx.message,
                        bsp,
                        in_left: tx.in_left,
                        out_left: tx.out_left,
                        ops_left: tx.ops_left,
                    };
                }
            }
            for inp in &tx.inputs {
                g.input(inp);
            }
            if let Some(p) = &tx.policy {
                g.policy(p);
            }
            for out in &tx.outputs {
                g.output(out);
            }
            for op in &tx.ops {
                g.op(op);
            }
            if tx.ends {
                crate::stark::refuse(
                    g.regs.bsp[..DIGEST] == tx.message[..],
                    "body digest does not match the signed message",
                );
                g.b.pass();
                let row = g.b.last_row_mut();
                row[T_TX_END] = Fp::ONE;
                g.regs.write(row);
                g.regs.open = false;
                g.regs.pol = false;
            } else {
                assert_eq!(p + 1, parts, "only a segment's last part may leave a transaction open");
                let r = &g.regs;
                carry_out = Carry {
                    open: true,
                    msg: r.msg,
                    bsp: r.bsp,
                    in_left: r.in_left,
                    out_left: r.out_left,
                    ops_left: r.ops_left,
                };
            }
        }
        let public = SegmentPublic {
            height: w.height,
            root_in: w.root_in,
            root_out: g.regs.root,
            isp_in: w.isp_in,
            isp_out: g.regs.isp,
            osp_in: w.osp_in,
            osp_out: g.regs.osp,
            nsp_in: w.nsp_in,
            nsp_out: g.regs.nsp,
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
        scenario_with(name, |utxo, wtxn, txs| SegmentWitness::collect(utxo, wtxn, txs, per_segment, 1).unwrap())
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
        utxo.add_output(&mut wtxn, &Output::new(&a.public_key(), 100).block_output(), 0).unwrap();
        utxo.add_output(&mut wtxn, &Output::new(&bk.public_key(), 50).block_output(), 0).unwrap();
        utxo.add_output(&mut wtxn, &Output::new(&a.public_key(), 30).block_output(), 0).unwrap();

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

    /// Policy spends: 2-of-3 multisig, an HTLC claim, an eltoo update with
    /// rebindable signatures and a covenant settlement, each a whole
    /// transaction in a segment, satisfy the constraints; a tampered state
    /// number does not.
    #[test]
    fn policy_spends_satisfy_constraints() {
        let (txs, segments) = policy_segments();
        assert_eq!(segments.len(), 4);
        for (k, seg) in segments.iter().enumerate() {
            assert_eq!(seg.num_rows(), tx_rows(&txs[k]), "rows of transaction {k}");
            let (trace, public) = BlockAir::generate_trace(seg);
            assert_eq!(check_constraints(&BlockAir, &trace, &public.to_values()), Ok(()), "transaction {k}");
            // Tampering with the state number breaks the update's rows.
            if k == 2 {
                let mut bad = trace.clone();
                let width = bad.width;
                for r in 0..bad.height() {
                    if bad.values[r * width + R_PSTATE] == Fp::new(4) {
                        bad.values[r * width + R_PSTATE] = Fp::new(5);
                    }
                }
                assert!(check_constraints(&BlockAir, &bad, &public.to_values()).is_err());
            }
        }
        assert_eq!(txs[2].weight(), 2);
        assert_eq!(txs[3].weight(), 0);
    }

    /// What becomes of a witness that breaks a rule when the generator
    /// writes its trace anyway, as a cheating prover's would.
    #[derive(Debug, PartialEq)]
    enum Cheat {
        /// The constraints reject the trace: the rule holds in the circuit.
        Rejected,
        /// The constraints accept it: a soundness bug.
        Accepted,
        /// The generator cannot write a trace for it at all.
        NoTrace(String),
    }

    fn cheat(w: &SegmentWitness) -> Cheat {
        crate::stark::LENIENT.with(|l| l.set(true));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| BlockAir::generate_trace(w)));
        crate::stark::LENIENT.with(|l| l.set(false));
        match r {
            Err(e) => Cheat::NoTrace(
                e.downcast_ref::<String>()
                    .cloned()
                    .or(e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default(),
            ),
            Ok((trace, public)) => match check_constraints(&BlockAir, &trace, &public.to_values()) {
                Err(_) => Cheat::Rejected,
                Ok(()) => Cheat::Accepted,
            },
        }
    }

    /// A segment spending one output of `policy` (created at height 0,
    /// amount 1000, memo `m`) by the transaction `spend` builds from the
    /// input, at `height`.
    fn policy_spend(
        name: &str,
        policy: &crate::policy::Policy,
        height: u32,
        spend: impl FnOnce(crate::policy::PolicyInput) -> Transaction,
    ) -> SegmentWitness {
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let mut memo = EMPTY;
        memo[0] = Fp::new(42);
        let o = Output::with_memo(&policy.root(), 1000, crate::transaction::memo5(memo));
        utxo.add_output(&mut wtxn, &o.block_output(), 0).unwrap();
        let tx = spend(policy.spend(0, 1000, 0));
        let mut segments = SegmentWitness::collect(&utxo, &mut wtxn, std::slice::from_ref(&tx), 1, height).unwrap();
        wtxn.abort();
        segments.remove(0)
    }

    /// Step 2 of the circuit review (`docs/HARDENING.md`): each rule the
    /// witness generator enforces, broken by a witness the generator then
    /// writes anyway (as a cheating prover's would), must be rejected by
    /// the constraints themselves.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
    fn broken_rules_are_rejected_by_the_constraints() {
        use crate::policy::{Cond, CondWitness, Leaf, Mode, Policy, Signer, hash_lock};
        use crate::transaction::pubkey_hash;
        let mut verdicts: Vec<(&str, Cheat)> = Vec::new();
        // The plain spends' forgeries.
        let (segments, ..) = scenario("attack", 10);
        let w = &segments[0];
        let mut greedy = w.clone();
        greedy.txs[0].inputs[0].amount += 1;
        verdicts.push(("an input claiming more than its output holds", cheat(&greedy)));
        let mut inflated = w.clone();
        let o = &mut inflated.txs[0].outputs[0].output;
        o.commitment = crate::transaction::key_commitment(&o.key_hash, o.amount + 1_000_000);
        verdicts.push(("an output hiding more than it counts", cheat(&inflated)));
        let mut wrong_msg = w.clone();
        wrong_msg.txs[2].message[0] += Fp::ONE;
        verdicts.push(("a signature over another message", cheat(&wrong_msg)));
        let mut wrong_memo = w.clone();
        wrong_memo.txs[0].inputs[0].memo[1] += Fp::ONE;
        verdicts.push(("an input with another memo than its leaf's", cheat(&wrong_memo)));
        let mut swapped = w.clone();
        swapped.txs[0].outputs[0].output.memo[0] += Fp::ONE;
        verdicts.push(("an output memo changed after signing", cheat(&swapped)));

        // Policy spends.
        let k = |t: u8| key(t);
        let pkh = |t: u8| pubkey_hash(&k(t).public_key());
        let dest = k(9).public_key();
        let signed = |input: crate::policy::PolicyInput, sign: &dyn Fn(&Digest) -> CondWitness| {
            let mut input = input;
            let body = UnsignedTransaction::new(vec![], vec![Output::new(&dest, 1000)])
                .with_policy_inputs(vec![input.clone()])
                .body_hash();
            let last = input.witness.len() - 1;
            input.witness[last] = sign(&body);
            UnsignedTransaction::new(vec![], vec![Output::new(&dest, 1000)])
                .with_policy_inputs(vec![input])
                .sign(|_, _, _| Err::<Sig, ()>(()))
                .unwrap()
        };
        let sig = |t: u8, key_index: u8, body: &Digest| {
            let mut sk = k(t);
            Signer { key: key_index, pubkey: sk.public_key(), signature: sk.sign(body).unwrap() }
        };
        let multisig = Policy::new(vec![Leaf::new(vec![Cond::Thresh {
            mode: Mode::Body,
            m: 2,
            keys: vec![pkh(1), pkh(2), pkh(3)],
        }])]);
        // Honest first: the helper's segment holds.
        let honest = policy_spend("honest-multisig", &multisig, 10, |i| {
            signed(i, &|b| CondWitness::Signatures(vec![sig(1, 0, b), sig(3, 2, b)]))
        });
        assert_eq!(cheat(&honest), Cheat::Accepted, "an honest 2-of-3");
        let outsider = policy_spend("outsider", &multisig, 10, |i| {
            signed(i, &|b| CondWitness::Signatures(vec![sig(1, 0, b), sig(7, 1, b)]))
        });
        verdicts.push(("a 2-of-3 with a signer whose key is not the policy's", cheat(&outsider)));
        let twice = policy_spend("twice", &multisig, 10, |i| {
            signed(i, &|b| CondWitness::Signatures(vec![sig(1, 0, b), sig(1, 0, b)]))
        });
        verdicts.push(("a 2-of-3 with one signer counted twice", cheat(&twice)));
        let mut pre = EMPTY;
        pre[0] = Fp::new(77);
        let htlc = Policy::new(vec![Leaf::new(vec![
            Cond::Hash(hash_lock(&pre)),
            Cond::Thresh { mode: Mode::Body, m: 1, keys: vec![pkh(2)] },
        ])]);
        let wrong_pre = policy_spend("preimage", &htlc, 10, |mut i| {
            let mut other = pre;
            other[0] += Fp::ONE;
            i.witness[0] = CondWitness::Preimage(other);
            signed(i, &|b| CondWitness::Signatures(vec![sig(2, 0, b)]))
        });
        verdicts.push(("an HTLC claimed with the wrong preimage", cheat(&wrong_pre)));
        let refund = Policy::new(vec![Leaf::new(vec![
            Cond::After(100),
            Cond::Thresh { mode: Mode::Body, m: 1, keys: vec![pkh(1)] },
        ])]);
        let early = policy_spend("after", &refund, 50, |i| signed(i, &|b| CondWitness::Signatures(vec![sig(1, 0, b)])));
        verdicts.push(("a refund before its height (After 100 at 50)", cheat(&early)));
        let relative = Policy::new(vec![Leaf::new(vec![
            Cond::Older(144),
            Cond::Thresh { mode: Mode::Body, m: 1, keys: vec![pkh(1)] },
        ])]);
        let young =
            policy_spend("older", &relative, 100, |i| signed(i, &|b| CondWitness::Signatures(vec![sig(1, 0, b)])));
        verdicts.push(("a spend before its delay (Older 144, 100 blocks old)", cheat(&young)));

        // Covenant: a settlement paying other outputs than the covenant's.
        let mut m1 = EMPTY;
        m1[0] = Fp::new(101);
        let to = |t: u8, amount: u64| Output::with_memo(&pkh(t), amount, crate::transaction::memo5(EMPTY));
        let settle_to = [Output::with_memo(&pkh(1), 600, crate::transaction::memo5(m1)), to(2, 400)];
        let covered: Vec<(Commitment, Digest)> = settle_to.iter().map(|o| (o.commitment, o.slot())).collect();
        let covenant = Policy::new(vec![Leaf::new(vec![Cond::Outputs(covered)])]);
        let pay = |outs: Vec<Output>| {
            move |mut i: crate::policy::PolicyInput| {
                i.covered = (0, outs.len() as u8);
                UnsignedTransaction::new(vec![], outs.clone())
                    .with_policy_inputs(vec![i])
                    .sign(|_, _, _| Err::<Sig, ()>(()))
                    .unwrap()
            }
        };
        let honest_settle = policy_spend("covenant-ok", &covenant, 10, pay(settle_to.to_vec()));
        assert_eq!(cheat(&honest_settle), Cheat::Accepted, "an honest settlement");
        let other = [to(1, 400), to(2, 600)];
        let robbed = policy_spend("covenant", &covenant, 10, pay(other.to_vec()));
        verdicts.push(("a settlement paying other outputs than the covenant's", cheat(&robbed)));
        // Eltoo: an update to a state no newer than the current one.
        let channel = {
            let mut c = EMPTY;
            c[0] = Fp::new(5);
            c
        };
        let state = Policy::new(vec![Leaf::new(vec![
            Cond::Thresh { mode: Mode::Rebindable { channel }, m: 2, keys: vec![pkh(1), pkh(2)] },
            Cond::State(3),
        ])]);
        let state_root = state.root();
        let update = |to: u32| {
            move |mut i: crate::policy::PolicyInput| {
                let new_state = Output::with_memo(&state_root, 1000, crate::transaction::memo5(EMPTY));
                i.state = to;
                i.covered = (0, 1);
                let msg = crate::policy::rebind_message(&channel, to, &[(new_state.commitment, new_state.slot())]);
                let signer = |t: u8, key_index: u8| {
                    let mut sk = key(t);
                    sk.set_next_index(u64::from(to));
                    Signer { key: key_index, pubkey: sk.public_key(), signature: sk.sign(&msg).unwrap() }
                };
                i.witness[0] = CondWitness::Signatures(vec![signer(1, 0), signer(2, 1)]);
                UnsignedTransaction::new(vec![], vec![new_state])
                    .with_policy_inputs(vec![i])
                    .sign(|_, _, _| Err::<Sig, ()>(()))
                    .unwrap()
            }
        };
        let newer = policy_spend("eltoo-ok", &state, 10, update(4));
        assert_eq!(cheat(&newer), Cheat::Accepted, "an honest update to state 4");
        let stale = policy_spend("eltoo", &state, 10, update(3));
        verdicts.push(("an eltoo update to a state no newer (3 over 3)", cheat(&stale)));

        // A segment resuming a transaction with one input fewer left than
        // the previous segment carried out, checked against the honest
        // public values: the carry is bound to the resume row.
        let plan = vec![
            vec![Part { tx: 0, start: 0, end: 1 }],
            vec![Part { tx: 0, start: 1, end: 3 }],
            vec![Part { tx: 0, start: 3, end: 4 }, Part { tx: 1, start: 0, end: 1 }, Part { tx: 2, start: 0, end: 2 }],
        ];
        let (span, ..) = scenario_with("attack-span", |utxo, wtxn, txs| {
            SegmentWitness::collect_parts(utxo, wtxn, txs, plan, 1).unwrap()
        });
        let (_, honest_public) = BlockAir::generate_trace(&span[1]);
        let mut short = span[1].clone();
        short.txs[0].inputs.clear();
        short.txs[0].in_left -= 1;
        crate::stark::LENIENT.with(|l| l.set(true));
        let forged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| BlockAir::generate_trace(&short)));
        crate::stark::LENIENT.with(|l| l.set(false));
        verdicts.push((
            "a resumed transaction skipping an input, under the honest statement",
            match forged {
                Err(e) => Cheat::NoTrace(e.downcast_ref::<String>().cloned().unwrap_or_default()),
                Ok((trace, _)) => match check_constraints(&BlockAir, &trace, &honest_public.to_values()) {
                    Err(_) => Cheat::Rejected,
                    Ok(()) => Cheat::Accepted,
                },
            },
        ));
        // The same input spent twice in one segment (its path stale).
        let mut double = w.clone();
        let again = double.txs[2].clone();
        double.txs.push(again);
        verdicts.push(("an input spent twice in one segment", cheat(&double)));
        // An output inserted over an occupied position.
        let mut occupied = w.clone();
        occupied.pos_in = 2;
        verdicts.push(("outputs inserted from an occupied position", cheat(&occupied)));

        // Name operations a transaction carries: the digest absorbed into
        // the body (signed) and the operations list (the name segment's)
        // is one; changed or dropped after signing, the body breaks.
        let with_ops = name_ops_segment("attack-ops");
        assert_eq!(cheat(&with_ops), Cheat::Accepted, "an honest spend carrying name operations");
        let mut changed = with_ops.clone();
        changed.txs[0].ops[1][0] += Fp::ONE;
        verdicts.push(("a name operation changed after signing", cheat(&changed)));
        let mut dropped = with_ops.clone();
        dropped.txs[0].ops.pop();
        dropped.txs[0].ops_left -= 1;
        verdicts.push(("a name operation dropped from a signed transaction", cheat(&dropped)));

        let failures: Vec<String> =
            verdicts.iter().filter(|(_, v)| *v != Cheat::Rejected).map(|(what, v)| format!("{what}: {v:?}")).collect();
        for (what, v) in &verdicts {
            eprintln!("{what}: {v:?}");
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// Step 3 of the circuit review (`docs/HARDENING.md`): the circuit
    /// against the chain's own rules on random blocks. A valid block, its
    /// transactions packed into segments of a random size (so they often
    /// split), must give segments that hold, chain, and end where the
    /// native set does: root, input and output lists, position and sums. A
    /// block one random change makes invalid by the chain's checks must be
    /// rejected by the constraints, its trace written by the lenient
    /// generator (or refused already when the witness is collected).
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn the_circuit_agrees_with_the_chain_on_random_blocks() {
        use crate::test_util::Rng;
        // A fixed seed, or another for a wider search (TABMINER_DIFF_SEED).
        let seed = std::env::var("TABMINER_DIFF_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed_b10c);
        let mut rng = Rng::new(seed);
        let mut pick = |n: u64| (rng.next_u64() % n.max(1)) as usize;
        let dir = TempDir::new("differential");
        let env = open_env(&dir.0, 256 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "circuit").unwrap();
        let native = UtxoSet::open(&env, &mut wtxn, "native").unwrap();
        // A fresh key per output, by counter.
        let mut next_key = 0u64;
        let mut fresh = || {
            next_key += 1;
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&next_key.to_le_bytes());
            seed[8] = 0xd1;
            Key::generate(&seed)
        };
        // Unspent: position, key, amount.
        let mut unspent: Vec<(u64, Key, u64)> = Vec::new();
        for _ in 0..24 {
            let k = fresh();
            let amount = 1000 + pick(9000) as u64;
            let o = Output::new(&k.public_key(), amount).block_output();
            let p = utxo.add_output(&mut wtxn, &o, 0).unwrap();
            native.add_output(&mut wtxn, &o, 0).unwrap();
            unspent.push((p, k, amount));
        }
        let (mut valid, mut rejected, mut inconclusive) = (0, 0, 0);
        for round in 0..40u32 {
            let height = 1 + round;
            let broken = round % 2 == 1;
            // A random block of valid transactions.
            let mut txs: Vec<Transaction> = Vec::new();
            let mut spent_now: Vec<(u64, Key, u64)> = Vec::new();
            let mut made: Vec<(Key, u64)> = Vec::new();
            for _ in 0..1 + pick(3) {
                if unspent.len() < 2 {
                    break;
                }
                let mut ins: Vec<(u64, Key, u64)> = Vec::new();
                for _ in 0..1 + pick(2) {
                    let i = pick(unspent.len() as u64);
                    ins.push(unspent.remove(i));
                }
                let total: u64 = ins.iter().map(|i| i.2).sum();
                let fee = pick(10) as u64;
                let n_out = 1 + pick(3);
                let mut outs: Vec<(Key, u64)> = Vec::new();
                let mut left = total - fee;
                for j in 0..n_out {
                    let a = if j + 1 == n_out { left } else { 1 + pick(left / 2) as u64 };
                    left -= a;
                    outs.push((fresh(), a));
                }
                let outputs: Vec<Output> = outs.iter().map(|(k, a)| Output::new(&k.public_key(), *a)).collect();
                let inputs: Vec<(crate::xmss::PublicKey, u64)> =
                    ins.iter().map(|(_, k, a)| (k.public_key(), *a)).collect();
                let mut keys: Vec<Key> = ins.iter().map(|i| i.1.clone()).collect();
                let mut tx = UnsignedTransaction::new(inputs, outputs).sign(|i, _, m| keys[i].sign(m)).unwrap();
                tx.set_positions(&ins.iter().map(|i| i.0).collect::<Vec<_>>());
                txs.push(tx);
                spent_now.extend(ins);
                made.extend(outs);
            }
            if txs.is_empty() {
                break;
            }
            // One change the chain rejects, in a random transaction.
            let mut what = "";
            if broken {
                let t = pick(txs.len() as u64);
                let tx = &mut txs[t];
                match pick(5) {
                    0 => {
                        // Signed by a key that does not own the output.
                        let mut stranger = fresh();
                        let mut un = tx.unsigned();
                        un = UnsignedTransaction::new(
                            un.inputs
                                .iter()
                                .enumerate()
                                .map(|(i, x)| if i == 0 { (stranger.public_key(), x.1) } else { *x })
                                .collect(),
                            un.outputs.clone(),
                        );
                        let positions = tx.spent_positions();
                        let mut owners: Vec<Key> =
                            spent_now.iter().filter(|s| positions.contains(&s.0)).map(|s| s.1.clone()).collect();
                        let signed = un.sign(|i, _, m| if i == 0 { stranger.sign(m) } else { owners[i].sign(m) });
                        let Ok(mut forged) = signed else {
                            unspent.append(&mut spent_now);
                            continue;
                        };
                        forged.set_positions(&positions);
                        *tx = forged;
                        what = "signed by a stranger";
                    }
                    1 => {
                        // An input pointing at another unspent output.
                        let Some(other) = unspent.first() else {
                            unspent.append(&mut spent_now);
                            continue;
                        };
                        let mut ps = tx.spent_positions();
                        ps[0] = other.0;
                        tx.set_positions(&ps);
                        what = "another output's position";
                    }
                    2 => {
                        // An input claiming more than its output holds.
                        tx.inputs[0].amount += 1;
                        what = "an input claiming more";
                    }
                    3 => {
                        // An output changed after signing.
                        let o = &mut tx.outputs[0];
                        *o = Output::new(&fresh().public_key(), o.amount);
                        what = "an output changed after signing";
                    }
                    _ => {
                        // The same output spent by two transactions.
                        let first = txs[0].clone();
                        txs.push(first);
                        what = "an output spent twice";
                    }
                }
            }
            // The chain's verdict: signatures, inputs held, no double spend.
            let native_ok = {
                let mut seen = std::collections::HashSet::new();
                txs.iter().all(|tx| {
                    tx.verify_signatures()
                        && tx
                            .spent_positions()
                            .iter()
                            .zip(tx.spent_commitments())
                            .all(|(p, c)| seen.insert(*p) && native.holds(&wtxn, *p, &c).unwrap())
                })
            };
            assert_eq!(native_ok, !broken, "round {round}: the chain's verdict on {what:?}");
            let max_rows = [2048, 4096, 8192][pick(3)];
            let positions: Vec<u64> = txs.iter().flat_map(|t| t.spent_positions()).collect();
            let block_outputs: Vec<BlockOutput> =
                txs.iter().flat_map(|t| t.outputs.iter().map(|o| o.block_output())).collect();
            let root_in = utxo.root(&wtxn).unwrap();
            let pos_in = utxo.next_position(&wtxn).unwrap();
            let mut nested = env.nested_write_txn(&mut wtxn).unwrap();
            // A broken block's witness is collected as a cheater would.
            crate::stark::LENIENT.with(|l| l.set(broken));
            let collected = SegmentWitness::collect_by_rows(&utxo, &mut nested, &txs, max_rows, height);
            crate::stark::LENIENT.with(|l| l.set(false));
            if broken {
                nested.abort();
                // Nothing was spent: the inputs are still there.
                unspent.append(&mut spent_now);
                let Ok(segments) = collected else {
                    inconclusive += 1;
                    continue;
                };
                // Some segment's trace must fail.
                if segments.iter().any(|w| cheat(w) != Cheat::Accepted) {
                    rejected += 1;
                } else {
                    panic!("round {round}: {what} accepted by every segment");
                }
                continue;
            }
            let segments = collected.unwrap();
            let root_out = utxo.root(&nested).unwrap();
            nested.commit().unwrap();
            // The native block.
            native.spend_positions(&mut wtxn, &positions).unwrap().unwrap();
            native.add_outputs(&mut wtxn, &block_outputs, height).unwrap();
            assert_eq!(native.root(&wtxn).unwrap(), root_out, "round {round}: roots");
            let publics: Vec<SegmentPublic> = segments
                .iter()
                .map(|w| {
                    let (trace, public) = BlockAir::generate_trace(w);
                    assert_eq!(check_constraints(&BlockAir, &trace, &public.to_values()), Ok(()), "round {round}");
                    public
                })
                .collect();
            for p in publics.windows(2) {
                assert_eq!(
                    (p[0].root_out, p[0].isp_out, p[0].osp_out, p[0].pos_out, p[0].carry_out),
                    (p[1].root_in, p[1].isp_in, p[1].osp_in, p[1].pos_in, p[1].carry_in),
                    "round {round}: segments chain"
                );
            }
            let (first, last) = (&publics[0], &publics[publics.len() - 1]);
            assert_eq!((first.root_in, first.pos_in, first.carry_in), (root_in, pos_in, Carry::CLOSED));
            assert_eq!(last.root_out, native.root(&wtxn).unwrap());
            assert_eq!(last.isp_out, inputs_state(&positions), "round {round}: inputs list");
            assert_eq!(last.osp_out, outputs_state(&block_outputs), "round {round}: outputs list");
            assert_eq!(last.pos_out, native.next_position(&wtxn).unwrap());
            assert_eq!(last.carry_out, Carry::CLOSED);
            let sum = |f: fn(&SegmentPublic) -> &[u32; LIMBS]| {
                publics.iter().map(|p| SegmentPublic::total(f(p))).sum::<u128>()
            };
            let ins: u128 = spent_now.iter().map(|s| s.2 as u128).sum();
            let outs: u128 = made.iter().map(|m| m.1 as u128).sum();
            assert_eq!((sum(|p| &p.sum_in), sum(|p| &p.sum_out)), (ins, outs), "round {round}: sums");
            // The new outputs join the unspent set.
            for (i, (k, a)) in made.into_iter().enumerate() {
                unspent.push((pos_in + i as u64, k, a));
            }
            valid += 1;
        }
        eprintln!(
            "{valid} valid blocks agreed; {rejected} broken ones rejected, {inconclusive} refused when collected"
        );
        assert!(valid >= 15 && rejected >= 8, "too few rounds ran: {valid} valid, {rejected} rejected");
    }

    /// A segment of one transaction spending an output to another and
    /// carrying two name commits.
    fn name_ops_segment(name: &str) -> SegmentWitness {
        use crate::names::NameOp;
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let mut a = key(1);
        utxo.add_output(&mut wtxn, &Output::new(&a.public_key(), 100).block_output(), 0).unwrap();
        let d = |x: u32| {
            let mut v = EMPTY;
            v[0] = Fp::new(x);
            v
        };
        let ops = vec![
            NameOp::Commit { commit: d(7), memo: crate::transaction::memo5(d(8)) },
            NameOp::Commit { commit: d(9), memo: crate::transaction::memo5(d(10)) },
        ];
        let mut tx = UnsignedTransaction::with_ops(
            vec![(a.public_key(), 100)],
            vec![Output::new(&key(2).public_key(), 99)],
            ops,
        )
        .sign_with(&mut a)
        .unwrap();
        tx.set_positions(&[0]);
        let mut segments = SegmentWitness::collect(&utxo, &mut wtxn, std::slice::from_ref(&tx), 1, 1).unwrap();
        wtxn.abort();
        segments.remove(0)
    }

    /// One random change to a field inside a segment's witness (not its
    /// boundary: root, position, list states and height in, which the
    /// aggregation pins), described. `None` if the witness has no such
    /// field to change this time.
    fn mutate_segment(w: &mut SegmentWitness, rng: &mut crate::test_util::Rng) -> Option<String> {
        let mut r = |n: usize| (rng.next_u64() % n.max(1) as u64) as usize;
        let nz = |v: usize| Fp::new(1 + (v as u32) % (crate::poseidon2::P - 1));
        let t = r(w.txs.len());
        let k = r(1 << 20);
        let tx = &mut w.txs[t];
        let (ni, no) = (tx.inputs.len(), tx.outputs.len());
        let i = r(ni.max(1));
        let o = r(no.max(1));
        let d = r(DIGEST);
        let delta = nz(k);
        Some(match r(22) {
            0 if ni > 0 => {
                tx.inputs[i].amount = tx.inputs[i].amount.wrapping_add(1 + (k % 3) as u64);
                format!("tx {t} input {i} amount")
            }
            1 if ni > 0 => {
                tx.inputs[i].memo[d] += delta;
                format!("tx {t} input {i} memo[{d}]")
            }
            2 if ni > 0 => {
                tx.inputs[i].position ^= 1 << (k % 6);
                format!("tx {t} input {i} position")
            }
            3 if ni > 0 => {
                let l = k % DEPTH;
                tx.inputs[i].siblings[l][d] += delta;
                format!("tx {t} input {i} sibling {l}")
            }
            4 if ni > 0 => {
                let c = k % tx.inputs[i].signature.wots.len();
                tx.inputs[i].signature.wots[c][d] += delta;
                format!("tx {t} input {i} signature chain {c}")
            }
            5 if ni > 0 && !tx.inputs[i].signature.auth_path.is_empty() => {
                let l = k % tx.inputs[i].signature.auth_path.len();
                tx.inputs[i].signature.auth_path[l][d] += delta;
                format!("tx {t} input {i} signature path {l}")
            }
            6 if ni > 0 => {
                tx.inputs[i].signature.randomizer[d] += delta;
                format!("tx {t} input {i} signature randomizer")
            }
            7 if ni > 0 => {
                tx.inputs[i].signature.index ^= 1;
                format!("tx {t} input {i} signature index")
            }
            8 if ni > 0 => {
                tx.inputs[i].pubkey.root[d] += delta;
                format!("tx {t} input {i} key root")
            }
            9 if ni > 0 => {
                let j = k % tx.inputs[i].pubkey.pub_seed.len();
                tx.inputs[i].pubkey.pub_seed[j] += delta;
                format!("tx {t} input {i} key seed")
            }
            10 if ni > 0 => {
                tx.inputs[i].height ^= 1 << (k % 4);
                format!("tx {t} input {i} creation height")
            }
            11 if no > 0 => {
                tx.outputs[o].output.amount = tx.outputs[o].output.amount.wrapping_add(1 + (k % 3) as u64);
                format!("tx {t} output {o} amount")
            }
            12 if no > 0 => {
                let j = k % tx.outputs[o].output.memo.len();
                tx.outputs[o].output.memo[j] += delta;
                format!("tx {t} output {o} memo[{j}]")
            }
            13 if no > 0 => {
                tx.outputs[o].output.commitment[d] += delta;
                format!("tx {t} output {o} commitment")
            }
            14 if no > 0 => {
                tx.outputs[o].output.key_hash[d] += delta;
                format!("tx {t} output {o} key hash")
            }
            15 if no > 0 => {
                let l = k % DEPTH;
                tx.outputs[o].siblings[l][d] += delta;
                format!("tx {t} output {o} sibling {l}")
            }
            16 => {
                tx.message[d] += delta;
                format!("tx {t} message")
            }
            17 if !tx.ops.is_empty() => {
                let j = k % tx.ops.len();
                tx.ops[j][d] += delta;
                format!("tx {t} operation {j}")
            }
            18 => {
                match k % 3 {
                    0 => tx.in_left = tx.in_left.wrapping_add(1),
                    1 => tx.out_left = tx.out_left.wrapping_add(1),
                    _ => tx.ops_left = tx.ops_left.wrapping_add(1),
                }
                format!("tx {t} items left")
            }
            19 if ni > 1 => {
                tx.inputs.swap(0, 1);
                format!("tx {t} inputs swapped")
            }
            20 if no > 1 => {
                tx.outputs.swap(0, 1);
                format!("tx {t} outputs swapped")
            }
            21 if tx.policy.is_some() => {
                let p = tx.policy.as_mut().unwrap();
                match k % 4 {
                    0 => p.input.amount = p.input.amount.wrapping_add(1),
                    1 => p.input.state = p.input.state.wrapping_add(1),
                    2 => p.memo[d] += delta,
                    _ => p.created ^= 1,
                }
                format!("tx {t} policy input")
            }
            _ => return None,
        })
    }

    /// A chain of segments (one block) rebuilt from `from` on, as a cheating
    /// prover would: each later segment starts where the one before it
    /// ended (root, lists, position) and takes over its open transaction
    /// (message, body, items left), its trace written leniently. The
    /// segments' public values, or why the chain fails: `Err(true)` when a
    /// constraint rejects a segment, `Err(false)` when one has no trace.
    fn rebuild_chain(
        chain: &mut [SegmentWitness],
        from: usize,
        before: &[SegmentPublic],
    ) -> Result<Vec<SegmentPublic>, bool> {
        let mut publics: Vec<SegmentPublic> = before[..from].to_vec();
        for k in from..chain.len() {
            if k > from {
                let prev = publics[k - 1];
                let w = &mut chain[k];
                (w.root_in, w.isp_in, w.osp_in, w.nsp_in, w.pos_in) =
                    (prev.root_out, prev.isp_out, prev.osp_out, prev.nsp_out, prev.pos_out);
                if prev.carry_out.open {
                    let c = prev.carry_out;
                    let tx = &mut w.txs[0];
                    (tx.message, tx.resume, tx.in_left, tx.out_left, tx.ops_left) =
                        (c.msg, Some(c.bsp), c.in_left, c.out_left, c.ops_left);
                }
            }
            crate::stark::LENIENT.with(|l| l.set(true));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| BlockAir::generate_trace(&chain[k])));
            crate::stark::LENIENT.with(|l| l.set(false));
            let (trace, public) = r.map_err(|_| false)?;
            check_constraints(&BlockAir, &trace, &public.to_values()).map_err(|_| true)?;
            publics.push(public);
        }
        Ok(publics)
    }

    /// Fuzzes the block circuit's witnesses: 1 to 4 random changes inside
    /// one segment (`mutate_segment`) of a block, the block's later
    /// segments rebuilt to follow it (`rebuild_chain`), traces written
    /// leniently. A block every segment of which holds, whose start, lists,
    /// closed ends and height are the honest block's, but which ends
    /// elsewhere (root, position, sums) is a bug: the same body with another
    /// outcome. Other lists are another body (the node checks the block's
    /// own); the same outcome is counted as an equivalent witness.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
    fn fuzz_segment_witnesses() {
        let (iters, seed) = crate::stark::fuzz_params(150, 0xf022_b10c);
        let mut rng = crate::test_util::Rng::new(seed);
        let (plain, ..) = scenario("fuzz-plain", 3);
        let plan = vec![
            vec![Part { tx: 0, start: 0, end: 1 }],
            vec![Part { tx: 0, start: 1, end: 3 }],
            vec![Part { tx: 0, start: 3, end: 4 }, Part { tx: 1, start: 0, end: 1 }, Part { tx: 2, start: 0, end: 2 }],
        ];
        let (span, ..) = scenario_with("fuzz-span", |utxo, wtxn, txs| {
            SegmentWitness::collect_parts(utxo, wtxn, txs, plan, 1).unwrap()
        });
        let (_, policy) = policy_segments();
        // Blocks: the plain one, the spanning one, each policy spend, the
        // spend carrying name operations.
        let mut blocks: Vec<Vec<SegmentWitness>> = vec![plain, span];
        blocks.extend(policy.into_iter().map(|w| vec![w]));
        blocks.push(vec![name_ops_segment("fuzz-ops")]);
        let honest: Vec<Vec<SegmentPublic>> =
            blocks.iter().map(|b| b.iter().map(|w| BlockAir::generate_trace(w).1).collect()).collect();
        let pinned = |p: &[SegmentPublic]| {
            let (f, l) = (&p[0], &p[p.len() - 1]);
            (
                f.root_in,
                f.isp_in,
                f.osp_in,
                f.nsp_in,
                f.pos_in,
                f.carry_in,
                l.isp_out,
                l.osp_out,
                l.nsp_out,
                l.carry_out,
                f.height,
            )
        };
        let outcome = |p: &[SegmentPublic]| {
            let sum =
                |f: fn(&SegmentPublic) -> &[u32; LIMBS]| p.iter().map(|x| SegmentPublic::total(f(x))).sum::<u128>();
            (p[p.len() - 1].root_out, p[p.len() - 1].pos_out, sum(|x| &x.sum_in), sum(|x| &x.sum_out))
        };
        let (mut rejected, mut no_trace, mut other, mut bugs) = (0, 0, 0, Vec::new());
        let mut same: Vec<String> = Vec::new();
        // The lenient generator panics on witnesses it cannot write: quiet.
        let quiet = crate::test_util::Quiet::new();
        let mut n = 0;
        while n < iters {
            let b = (rng.next_u64() % blocks.len() as u64) as usize;
            let k = (rng.next_u64() % blocks[b].len() as u64) as usize;
            let mut chain = blocks[b].clone();
            let mut what = Vec::new();
            for _ in 0..1 + rng.next_u64() % 4 {
                if let Some(m) = mutate_segment(&mut chain[k], &mut rng) {
                    what.push(m);
                }
            }
            if what.is_empty() {
                continue;
            }
            n += 1;
            let at = format!("block {b} segment {k}: {}", what.join(", "));
            match rebuild_chain(&mut chain, k, &honest[b]) {
                Err(true) => rejected += 1,
                Err(false) => no_trace += 1,
                Ok(p) if pinned(&p) != pinned(&honest[b]) => other += 1,
                Ok(p) if outcome(&p) == outcome(&honest[b]) => same.push(at),
                Ok(_) => bugs.push(at),
            }
        }
        drop(quiet);
        eprintln!(
            "{iters} mutants: {rejected} rejected, {} equivalent, {other} another body, {no_trace} without a trace, {} another outcome",
            same.len(),
            bugs.len()
        );
        for e in &same {
            eprintln!("  equivalent: {e}");
        }
        assert!(bugs.is_empty(), "the same body with another outcome (seed {seed}):\n{}", bugs.join("\n"));
    }

    /// The four policy spends of [`policy_spends_satisfy_constraints`]
    /// (multisig, HTLC claim, eltoo update, covenant settlement), one
    /// segment each.
    fn policy_segments() -> (Vec<Transaction>, Vec<SegmentWitness>) {
        use crate::policy::{Cond, CondWitness, Leaf, Mode, Policy, Signer, covered_digest, hash_lock, rebind_message};
        use crate::transaction::pubkey_hash;
        let dir = TempDir::new("policy");
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let (mut a, mut bk, mut c) = (key(1), key(2), key(3));
        let keys: Vec<Digest> = [&a, &bk, &c].iter().map(|k| pubkey_hash(&k.public_key())).collect();
        let dest = key(4).public_key();
        let height = 200;
        let d = |x: u32| {
            let mut v = EMPTY;
            v[0] = Fp::new(x);
            v
        };
        let memo = |x: u32| d(100 + x);

        // Outputs: a 2-of-3, an HTLC, an eltoo state (settling to a and b).
        let multisig = Policy::new(vec![Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 2, keys: keys.clone() }])]);
        let preimage = d(77);
        let htlc = Policy::new(vec![
            Leaf::new(vec![
                Cond::Hash(hash_lock(&preimage)),
                Cond::Thresh { mode: Mode::Body, m: 1, keys: keys[1..2].to_vec() },
            ]),
            Leaf::new(vec![Cond::After(100), Cond::Thresh { mode: Mode::Body, m: 1, keys: keys[..1].to_vec() }]),
        ]);
        let channel = d(5);
        let settle_outputs = [
            Output::with_memo(&keys[0], 600, crate::transaction::memo5(memo(1))),
            Output::with_memo(&keys[1], 400, crate::transaction::memo5(memo(2))),
        ];
        let settle: Vec<(Commitment, Digest)> = settle_outputs.iter().map(|o| (o.commitment, o.slot())).collect();
        let state = Policy::new(vec![
            Leaf::new(vec![
                Cond::Thresh { mode: Mode::Rebindable { channel }, m: 2, keys: keys[..2].to_vec() },
                Cond::State(3),
            ]),
            Leaf::new(vec![Cond::Older(144), Cond::Outputs(settle.clone())]),
        ]);
        let outs = [
            (multisig.root(), 1000u64, memo(10)),
            (htlc.root(), 500, memo(11)),
            (state.root(), 1000, memo(12)),
            (state.root(), 1000, memo(13)),
        ];
        for (policy, amount, m) in &outs {
            let o = Output::with_memo(policy, *amount, crate::transaction::memo5(*m));
            utxo.add_output(&mut wtxn, &o.block_output(), 0).unwrap();
        }

        // 2-of-3 in body mode: a and c sign the body hash.
        let mut spend = multisig.spend(0, 1000, 0);
        let unsigned =
            UnsignedTransaction::new(vec![], vec![Output::new(&dest, 1000)]).with_policy_inputs(vec![spend.clone()]);
        let body = unsigned.body_hash();
        spend.witness[0] = CondWitness::Signatures(vec![
            Signer { key: 0, pubkey: a.public_key(), signature: a.sign(&body).unwrap() },
            Signer { key: 2, pubkey: c.public_key(), signature: c.sign(&body).unwrap() },
        ]);
        let tx_multisig = UnsignedTransaction::new(vec![], vec![Output::new(&dest, 1000)])
            .with_policy_inputs(vec![spend])
            .sign(|_, _, _| Err::<Sig, ()>(()))
            .unwrap();
        assert_eq!(tx_multisig.body_hash(), body);

        // HTLC claim: the preimage and b's signature.
        let mut claim = htlc.spend(0, 500, 1);
        let unsigned =
            UnsignedTransaction::new(vec![], vec![Output::new(&dest, 500)]).with_policy_inputs(vec![claim.clone()]);
        let body = unsigned.body_hash();
        claim.witness[0] = CondWitness::Preimage(preimage);
        claim.witness[1] = CondWitness::Signatures(vec![Signer {
            key: 0,
            pubkey: bk.public_key(),
            signature: bk.sign(&body).unwrap(),
        }]);
        let tx_claim = UnsignedTransaction::new(vec![], vec![Output::new(&dest, 500)])
            .with_policy_inputs(vec![claim])
            .sign(|_, _, _| Err::<Sig, ()>(()))
            .unwrap();

        // Eltoo update to state 4: a and b sign the rebindable message with
        // leaf 4, over the new state output as the covered run.
        let new_state = Output::with_memo(&state.root(), 1000, crate::transaction::memo5(memo(14)));
        let mut update = state.spend(0, 1000, 2);
        update.state = 4;
        update.covered = (0, 1);
        let msg = rebind_message(&channel, 4, &[(new_state.commitment, new_state.slot())]);
        let mut a4 = key(1);
        a4.set_next_index(4);
        let mut b4 = key(2);
        b4.set_next_index(4);
        update.witness[0] = CondWitness::Signatures(vec![
            Signer { key: 0, pubkey: a4.public_key(), signature: a4.sign(&msg).unwrap() },
            Signer { key: 1, pubkey: b4.public_key(), signature: b4.sign(&msg).unwrap() },
        ]);
        let tx_update = UnsignedTransaction::new(vec![], vec![new_state])
            .with_policy_inputs(vec![update])
            .sign(|_, _, _| Err::<Sig, ()>(()))
            .unwrap();

        // Settlement of the other state output: no signature, the covered
        // run is the covenant's, after the delay (created at 0, height 200).
        let mut settlement = state.spend(1, 1000, 3);
        settlement.covered = (1, 2);
        let tx_settle = UnsignedTransaction::new(
            vec![],
            vec![Output::new(&dest, 7), settle_outputs[0], settle_outputs[1], Output::new(&dest, 9)],
        )
        .with_policy_inputs(vec![settlement])
        .sign(|_, _, _| Err::<Sig, ()>(()))
        .unwrap();
        assert_eq!(covered_digest(&settle), covered_digest(&settle));

        let txs = [tx_multisig, tx_claim, tx_update, tx_settle];
        for tx in &txs {
            let created = |_| Some(0);
            assert_eq!(tx.check_policy_inputs(height, created), Ok(()), "node-side check");
        }
        let segments = SegmentWitness::collect(&utxo, &mut wtxn, &txs, 1, height).unwrap();
        wtxn.abort();
        (txs.to_vec(), segments)
    }

    /// The block circuit's columns by name: each column is named after the
    /// constant at or below it, with an offset (for the audit's report).
    fn column_name(c: usize) -> String {
        let named: &[(&str, usize)] = &[
            ("T_TX_START", T_TX_START),
            ("T_TX_END", T_TX_END),
            ("T_MSG_START", T_MSG_START),
            ("T_MSG_ABS", T_MSG_ABS),
            ("T_LOAD", T_LOAD),
            ("T_STEP", T_STEP),
            ("T_LEAF", T_LEAF),
            ("T_TREE_START", T_TREE_START),
            ("T_TREE_ABS", T_TREE_ABS),
            ("T_PKH0", T_PKH0),
            ("T_PKH1", T_PKH1),
            ("T_CM0", T_CM0),
            ("T_CM1", T_CM1),
            ("T_ILIST", T_ILIST),
            ("T_OLD", T_OLD),
            ("T_NEW", T_NEW),
            ("T_BODY_IN0", T_BODY_IN0),
            ("T_BODY_IN1", T_BODY_IN1),
            ("T_OCM0", T_OCM0),
            ("T_OCM1", T_OCM1),
            ("T_OLIST", T_OLIST),
            ("T_BODY_OUT0", T_BODY_OUT0),
            ("T_BODY_OUT1", T_BODY_OUT1),
            ("T_DONE", T_DONE),
            ("T_RESUME", T_RESUME),
            ("T_OLIST2", T_OLIST2),
            ("T_BODY_OUT2", T_BODY_OUT2),
            ("T_ILEAF", T_ILEAF),
            ("T_OLEAF", T_OLEAF),
            ("T_OP_BODY", T_OP_BODY),
            ("T_OP_LIST", T_OP_LIST),
            ("T_ILEAF2", T_ILEAF2),
            ("T_OLEAF2", T_OLEAF2),
            ("T_PSTART", T_PSTART),
            ("T_CVS", T_CVS),
            ("T_LHDR", T_LHDR),
            ("T_THR", T_THR),
            ("T_CHAN", T_CHAN),
            ("T_KEY", T_KEY),
            ("T_KSEL", T_KSEL),
            ("T_HL", T_HL),
            ("T_HASH", T_HASH),
            ("T_AFTER", T_AFTER),
            ("T_OLDER", T_OLDER),
            ("T_STATE", T_STATE),
            ("T_OUTS", T_OUTS),
            ("T_PP0", T_PP0),
            ("T_PP1", T_PP1),
            ("T_PP2", T_PP2),
            ("T_PP3", T_PP3),
            ("T_PSIG", T_PSIG),
            ("T_PEND", T_PEND),
            ("T_CVC", T_CVC),
            ("T_CVM", T_CVM),
            ("T_RB0", T_RB0),
            ("T_RB1", T_RB1),
            ("T_RB2", T_RB2),
            ("R_SIB", R_SIB),
            ("C_LEVEL", C_LEVEL),
            ("C_LEVEL_INV", C_LEVEL_INV),
            ("C_IS_LAST", C_IS_LAST),
            ("C_SMT_END", C_SMT_END),
            ("R_PBITS", R_PBITS),
            ("R_ROOT", R_ROOT),
            ("R_OLD", R_OLD),
            ("R_NEW", R_NEW),
            ("R_IS_OUT", R_IS_OUT),
            ("C_OUT_END", C_OUT_END),
            ("R_MSG", R_MSG),
            ("R_BSP", R_BSP),
            ("R_ISP", R_ISP),
            ("R_OSP", R_OSP),
            ("R_PKROOT", R_PKROOT),
            ("R_OCM", R_OCM),
            ("R_ABITS", R_ABITS),
            ("R_SUM_IN", R_SUM_IN),
            ("R_SUM_OUT", R_SUM_OUT),
            ("R_OPOS_LO", R_OPOS_LO),
            ("R_OPOS_HI", R_OPOS_HI),
            ("C_WRAP", C_WRAP),
            ("C_WRAP_INV", C_WRAP_INV),
            ("R_IN_LEFT", R_IN_LEFT),
            ("R_OUT_LEFT", R_OUT_LEFT),
            ("C_IN_ZERO", C_IN_ZERO),
            ("C_IN_INV", C_IN_INV),
            ("C_OUT_ZERO", C_OUT_ZERO),
            ("C_OUT_INV", C_OUT_INV),
            ("C_GO_OUT", C_GO_OUT),
            ("C_GO_END", C_GO_END),
            ("R_OPEN", R_OPEN),
            ("R_MEMO", R_MEMO),
            ("R_LEAF", R_LEAF),
            ("R_OPD", R_OPD),
            ("R_NSP", R_NSP),
            ("R_OPS_LEFT", R_OPS_LEFT),
            ("C_OPS_ZERO", C_OPS_ZERO),
            ("C_OPS_INV", C_OPS_INV),
            ("C_GO_OPS", C_GO_OPS),
            ("R_POL", R_POL),
            ("R_PIN", R_PIN),
            ("R_POL_LEFT", R_POL_LEFT),
            ("C_IN_DONE", C_IN_DONE),
            ("C_DISP", C_DISP),
            ("R_PSTATE", R_PSTATE),
            ("R_CVB", R_CVB),
            ("R_CVN", R_CVN),
            ("C_CVB_ZERO", C_CVB_ZERO),
            ("C_CVB_INV", C_CVB_INV),
            ("C_CVN_ZERO", C_CVN_ZERO),
            ("C_CVN_INV", C_CVN_INV),
            ("R_INRUN", R_INRUN),
            ("R_CREATED", R_CREATED),
            ("R_SMSG", R_SMSG),
            ("R_RMSG", R_RMSG),
            ("R_PIDX", R_PIDX),
            ("R_LLEN", R_LLEN),
            ("R_LCNT", R_LCNT),
            ("R_LSP", R_LSP),
            ("R_NC", R_NC),
            ("C_NC_ZERO", C_NC_ZERO),
            ("C_NC_INV", C_NC_INV),
            ("R_TAG", R_TAG),
            ("R_M", R_M),
            ("C_M_INV", C_M_INV),
            ("R_KREM", R_KREM),
            ("C_KLAST", C_KLAST),
            ("C_KLAST_INV", C_KLAST_INV),
            ("R_SREM", R_SREM),
            ("C_SREM_ZERO", C_SREM_ZERO),
            ("C_SREM_INV", C_SREM_INV),
            ("R_HADTHR", R_HADTHR),
            ("R_REBIND", R_REBIND),
            ("R_CHAN", R_CHAN),
            ("R_HASCOV", R_HASCOV),
            ("R_NEEDRUN", R_NEEDRUN),
            ("R_RUNDONE", R_RUNDONE),
            ("R_COV", R_COV),
            ("R_PROOT", R_PROOT),
            ("R_KSP", R_KSP),
            ("R_SSP", R_SSP),
            ("R_CSP", R_CSP),
            ("C_CEND", C_CEND),
            ("C_GO_POL", C_GO_POL),
            ("hm::COL_START", crate::hash_machine::COL_START),
            ("hm::COL_ABSORB", crate::hash_machine::COL_ABSORB),
            ("hm::COL_CHAIN", crate::hash_machine::COL_CHAIN),
            ("hm::COL_COMPRESS", crate::hash_machine::COL_COMPRESS),
            ("hm::COL_PASS", crate::hash_machine::COL_PASS),
            ("hm::COL_LOAD", crate::hash_machine::COL_LOAD),
            ("hm::COL_DIR", crate::hash_machine::COL_DIR),
            ("hm::COL_DATA", crate::hash_machine::COL_DATA),
            ("hm::COL_ACC", crate::hash_machine::COL_ACC),
            ("perm", 0),
            ("x::mc", XCOLS.mc()),
            ("x::active", XCOLS.active()),
            ("x::rem", XCOLS.rem()),
            ("x::rem_inv", XCOLS.rem_inv()),
            ("x::last", XCOLS.last()),
            ("x::tlast", XCOLS.tlast()),
            ("x::t3", XCOLS.t3()),
            ("x::d", XCOLS.d()),
            ("x::csum", XCOLS.csum()),
            ("x::ssel", XCOLS.ssel(0)),
            ("x::ksel", XCOLS.ksel(0)),
            ("x::esel", XCOLS.esel(0)),
            ("x::lsel", XCOLS.lsel(0)),
            ("x::hsel", XCOLS.hsel(0)),
            ("x::bits", XCOLS.bits(0)),
            ("x::pub_seed", XCOLS.pub_seed(0)),
            ("x::idx", XCOLS.idx(0)),
            ("x::m", XCOLS.m(0)),
            ("x::sp", XCOLS.sp(0)),
            ("x::node", XCOLS.node(0)),
            ("x::sib", XCOLS.sib(0)),
        ];
        let (name, at) = named.iter().filter(|(_, v)| *v <= c).max_by_key(|(_, v)| *v).unwrap();
        if *at == c { name.to_string() } else { format!("{name}+{}", c - at) }
    }

    /// Runs `f` over `items` in chunks on every core and gathers what it
    /// returns.
    fn on_cores<T: Sync, R: Send>(items: &[T], f: impl Fn(&[T]) -> Vec<R> + Sync) -> Vec<R> {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let chunk = items.len().div_ceil(threads).max(1);
        std::thread::scope(|s| {
            let handles: Vec<_> = items.chunks(chunk).map(|c| s.spawn(|| f(c))).collect();
            handles.into_iter().flat_map(|h| h.join().unwrap()).collect()
        })
    }

    /// The soundness audit of one segment (`stark::freedom_audit` and
    /// `stark::run_audit`): every way its rows' cells can move together
    /// unseen, but the two kinds the design allows, as lines naming the
    /// segment, row and cells. Allowed: a hash permutation on a row whose
    /// permutation is not used (`pass`, `load`), and a value with its
    /// zero-test inverse (pinned by the product, so only to first order).
    fn audit_segment(name: &str, seg: &SegmentWitness) -> Vec<String> {
        use crate::hash_machine::{COL_LOAD, COL_PASS};
        let (trace, public) = BlockAir::generate_trace(seg);
        let public = public.to_values();
        let types: Vec<usize> =
            (0..NUM_COLS).filter(|&c| column_name(c).starts_with("T_") && !column_name(c).contains('+')).collect();
        let row_type = |r: usize| types.iter().copied().find(|&c| trace.row(r)[c] == Fp::ONE);
        // Rows: all of a rare type, eight spread over a common one.
        let mut of_type: std::collections::BTreeMap<Option<usize>, Vec<usize>> = Default::default();
        for r in 0..trace.height() {
            of_type.entry(row_type(r)).or_default().push(r);
        }
        let mut rows = Vec::new();
        for list in of_type.values() {
            if list.len() <= 8 {
                rows.extend(list);
            } else {
                rows.extend((0..8).map(|k| list[k * (list.len() - 1) / 7]));
            }
        }
        let perm = crate::poseidon2_air::NUM_COLS;
        let zero_pair = |a: usize, b: usize| {
            let (na, nb) = (column_name(a), column_name(b));
            nb == format!("{na}_INV") || (na == "x::rem" && nb == "x::rem_inv")
        };
        let mut problems: Vec<String> =
            on_cores(&rows, |chunk| crate::stark::freedom_audit(&BlockAir, &trace, None, &public, chunk))
                .into_iter()
                .filter(|f| {
                    let unused_perm = f.cells.iter().all(|(c, _)| *c < perm)
                        && (trace.row(f.row)[COL_PASS] == Fp::ONE || trace.row(f.row)[COL_LOAD] == Fp::ONE);
                    let inverse = !f.exact && f.cells.len() == 2 && zero_pair(f.cells[0].0, f.cells[1].0);
                    !(unused_perm || inverse)
                })
                .map(|f| {
                    let cells: Vec<String> = f.cells.iter().map(|(c, _)| column_name(*c)).collect();
                    format!(
                        "{name} row {} {}: {} freedom: {}",
                        f.row,
                        row_type(f.row).map_or("(none)".into(), column_name),
                        if f.exact { "exact" } else { "first-order" },
                        cells.join(" ")
                    )
                })
                .collect();
        // Runs of one type, two rows or more, every column.
        let mut runs = Vec::new();
        let mut start = 0;
        for r in 1..=trace.height() {
            if r == trace.height() || row_type(r) != row_type(start) {
                if r - start >= 2 {
                    runs.extend((0..NUM_COLS).map(|c| (c, start, r)));
                }
                start = r;
            }
        }
        let shifted = on_cores(&runs, |chunk| crate::stark::run_audit(&BlockAir, &trace, None, &public, chunk));
        for (col, first, end) in shifted {
            // A column nothing reads in the run can shift freely; one read
            // there and still unseen is a carried register unpinned. On the
            // done rows (padding) registers left over from the last item
            // are carried to the end and read by nothing: the shift was
            // checked against the last row's public values and every
            // lookup, so the statement does not change.
            if row_type(first) == Some(T_DONE) {
                continue;
            }
            if (first..end).any(|r| crate::stark::cell_read(&BlockAir, &trace, None, &public, r, col)) {
                problems.push(format!(
                    "{name} rows {first}..{end} {}: {} shifts unseen",
                    row_type(first).map_or("(none)".into(), column_name),
                    column_name(col)
                ));
            }
        }
        problems
    }

    /// The soundness audit of the block circuit over the transaction
    /// shapes the tests build: plain spends and a reward in one segment, a
    /// transaction split over three segments (resume rows, carries), and
    /// the four policy spends. No row may have a freedom the design does
    /// not allow, nor any run a register that shifts unseen.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn the_block_circuit_has_no_unintended_freedom() {
        let mut problems = Vec::new();
        let (plain, ..) = scenario("audit-plain", 3);
        let plan = vec![
            vec![Part { tx: 0, start: 0, end: 1 }],
            vec![Part { tx: 0, start: 1, end: 3 }],
            vec![Part { tx: 0, start: 3, end: 4 }, Part { tx: 1, start: 0, end: 1 }, Part { tx: 2, start: 0, end: 2 }],
        ];
        let (spanning, ..) = scenario_with("audit-span", |utxo, wtxn, txs| {
            SegmentWitness::collect_parts(utxo, wtxn, txs, plan, 1).unwrap()
        });
        let (_, policy) = policy_segments();
        let ops = vec![name_ops_segment("audit-ops")];
        let shapes = [("plain", plain), ("span", spanning), ("policy", policy), ("ops", ops)];
        for (shape, segments) in &shapes {
            for (k, seg) in segments.iter().enumerate() {
                let t = std::time::Instant::now();
                let found = audit_segment(&format!("{shape} segment {k}"), seg);
                eprintln!("{shape} segment {k}: {} problems in {:.0} s", found.len(), t.elapsed().as_secs_f64());
                problems.extend(found);
            }
        }
        assert!(problems.is_empty(), "{} problems:\n{}", problems.len(), problems.join("\n"));
    }

    /// The hash permutation of each load and step row of a spend, replaced
    /// by an honest permutation of another input: every active chain step
    /// notices (a signature chain is linked step to step), and no pass or
    /// load row does, whose permutation the hash machine does not use.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn a_replaced_permutation_is_caught_where_it_is_used() {
        let dir = TempDir::new("audit-perm");
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let mut k = Key::generate_with_height(&[9; 32], 4);
        let dest = key(3).public_key();
        utxo.add_output(&mut wtxn, &Output::new(&k.public_key(), 70).block_output(), 0).unwrap();
        let mut tx = UnsignedTransaction::new(vec![(k.public_key(), 70)], vec![Output::new(&dest, 70)])
            .sign(|_, _, m| k.sign(m))
            .unwrap();
        tx.set_positions(&[0]);
        let segments = SegmentWitness::collect(&utxo, &mut wtxn, std::slice::from_ref(&tx), 1, 1).unwrap();
        wtxn.abort();
        let (trace, public) = BlockAir::generate_trace(&segments[0]);
        let public = public.to_values();
        let perm_cols = crate::poseidon2_air::NUM_COLS;
        let other =
            crate::poseidon2_air::Poseidon2Air::generate_trace(&[core::array::from_fn(|i| Fp::new(77 + i as u32))]);
        let mut by_kind = std::collections::BTreeMap::<String, (usize, usize)>::new();
        for r in 0..trace.height() {
            let kind = if trace.row(r)[T_LOAD] == Fp::ONE {
                "T_LOAD"
            } else if trace.row(r)[T_STEP] == Fp::ONE {
                if trace.row(r)[XCOLS.active()] == Fp::ONE { "T_STEP active" } else { "T_STEP pass" }
            } else {
                continue;
            };
            let mut bad = trace.clone();
            bad.values[r * bad.width..r * bad.width + perm_cols].copy_from_slice(&other.row(0)[..perm_cols]);
            let caught = check_constraints(&BlockAir, &bad, &public).is_err();
            let e = by_kind.entry(kind.to_string()).or_default();
            e.0 += 1;
            if !caught {
                e.1 += 1;
            }
        }
        let active = by_kind["T_STEP active"];
        assert!(active.0 > 0 && active.1 == 0, "active steps that miss a replaced permutation: {by_kind:?}");
        let (pass, load) = (by_kind["T_STEP pass"], by_kind["T_LOAD"]);
        assert_eq!((pass.1, load.1), (pass.0, load.0), "unused permutations seen: {by_kind:?}");
    }

    /// Keys of any height up to the maximum verify; the fragment stops at
    /// the key's last level and the rows count accordingly.
    #[test]
    fn keys_of_other_heights_verify() {
        let dir = TempDir::new("heights");
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let mut tall = Key::generate_with_height(&[9; 32], 10);
        let mut short = Key::generate_with_height(&[8; 32], 1);
        // The tall key signs from a high leaf: the index bits above a
        // plain key's height are in use.
        tall.set_next_index(1000);
        let dest = key(3).public_key();
        utxo.add_output(&mut wtxn, &Output::new(&tall.public_key(), 70).block_output(), 0).unwrap();
        utxo.add_output(&mut wtxn, &Output::new(&short.public_key(), 30).block_output(), 0).unwrap();
        let mut tx = UnsignedTransaction::new(
            vec![(tall.public_key(), 70), (short.public_key(), 30)],
            vec![Output::new(&dest, 100)],
        )
        .sign(|i, _, m| if i == 0 { tall.sign(m) } else { short.sign(m) })
        .unwrap();
        tx.set_positions(&[0, 1]);
        assert!(tx.verify_signatures());
        assert_eq!(tx.inputs[0].signature.height(), 10);
        assert_eq!(tx.inputs[1].signature.height(), 1);
        let segments = SegmentWitness::collect(&utxo, &mut wtxn, std::slice::from_ref(&tx), 1, 1).unwrap();
        wtxn.abort();
        assert_eq!(segments[0].num_rows(), 2 + input_rows(10) + input_rows(1) + ROWS_PER_OUTPUT);
        let (trace, public) = BlockAir::generate_trace(&segments[0]);
        assert_eq!(trace.height(), segments[0].num_rows().next_power_of_two());
        assert_eq!(check_constraints(&BlockAir, &trace, &public.to_values()), Ok(()));
    }

    /// An output whose state leaf holds another amount than its
    /// commitment hides cannot be spent: the amount the supply check
    /// counted is the one the proof's sums use (`docs/AMOUNTS.md`).
    #[test]
    fn the_amount_in_the_leaf_is_the_committed_one() {
        let dir = TempDir::new("leaf-amount");
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut a = key(1);
        let dest = key(3).public_key();
        let spend = |recorded: u64, a: &mut Key| {
            let mut wtxn = env.write_txn().unwrap();
            let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
            let mut listed = Output::new(&a.public_key(), 100).block_output();
            listed.amount = recorded;
            utxo.add_output(&mut wtxn, &listed, 0).unwrap();
            let mut tx = UnsignedTransaction::new(vec![(a.public_key(), 100)], vec![Output::new(&dest, 100)])
                .sign_with(a)
                .unwrap();
            tx.set_positions(&[0]);
            let segments = SegmentWitness::collect(&utxo, &mut wtxn, std::slice::from_ref(&tx), 1, 1).unwrap();
            wtxn.abort();
            let (trace, public) = BlockAir::generate_trace(&segments[0]);
            check_constraints(&BlockAir, &trace, &public.to_values())
        };
        assert_eq!(spend(100, &mut a), Ok(()));
        // The leaf (so the state root) says 1, the commitment 100.
        let err = spend(1, &mut a).unwrap_err();
        assert_eq!(err.2, "key hash / commitment / amounts");
    }

    #[test]
    fn layout_and_degree() {
        assert_eq!(measure_degree(&BlockAir, NUM_PUBLIC), 3);
        assert_eq!(input_rows(4), 1150 + 6 + 1 + 80 + 2);
        assert_eq!(ROWS_PER_INPUT, 1182 + 6 + 1 + 80 + 2);
        assert_eq!(ROWS_PER_OUTPUT, 89);
        assert_eq!(NUM_PUBLIC, 128 + 2 * 28 + 1);
    }

    #[test]
    fn segments_satisfy_constraints_and_chain() {
        let (segments, expected_root, positions, outputs) = scenario("ok", 2);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].txs.len(), 2);
        assert_eq!(segments[0].num_rows(), 2 * 2 + 2 * input_rows(4) + 3 * ROWS_PER_OUTPUT);
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
            scenario_with("span", |utxo, wtxn, txs| SegmentWitness::collect_parts(utxo, wtxn, txs, plan, 1).unwrap());
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
        // Inputs by keys of 4, 20 and 16 levels; the last transaction stays
        // whole.
        let items = |t: usize| {
            let (heights, n_out, n_ops, whole): (&[usize], usize, usize, bool) = [
                (&[][..], 1, 0, false),
                (&[4, 20, 16][..], 2, 1, false),
                (&[4][..], 2, 0, false),
                (&[][..], 5, 3, true),
            ][t];
            let mut rows: Vec<usize> = heights.iter().map(|&h| input_rows(h)).collect();
            rows.extend(std::iter::repeat_n(ROWS_PER_OUTPUT, n_out));
            rows.extend(std::iter::repeat_n(ROWS_PER_OP, n_ops));
            (rows, whole)
        };
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
                let (item_rows, whole) = items(p.tx);
                assert!(!whole || (p.start == 0 && p.end == item_rows.len()));
                rows += 1 + item_rows[p.start..p.end].iter().sum::<usize>();
                rows += usize::from(p.end == item_rows.len());
            }
            assert!(rows < max_rows, "{rows}");
        }
        assert_eq!(next, [1, 6, 3, 8]);
        // A segment holds one input: the second transaction's three are
        // spread over three segments, its outputs joining the last.
        assert_eq!(plan[0], vec![Part { tx: 0, start: 0, end: 1 }, Part { tx: 1, start: 0, end: 1 }]);
        assert_eq!(plan[1], vec![Part { tx: 1, start: 1, end: 2 }]);
        assert_eq!(plan[2][0], Part { tx: 1, start: 2, end: 6 });
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
    #[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
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
        // The verifier, fuzzed: mutants of the proof's bytes are refused.
        let (iters, seed) = crate::stark::fuzz_params(200, 0xf022_b1);
        let verifies = |p: &crate::stark::Proof| verify(&config, &BlockAir, &public, p, &mut tr()).is_ok();
        let fuzz = crate::stark::fuzz_proof(&proof, iters, seed, verifies);
        eprintln!("{fuzz:?}");
        assert!(fuzz.accepted.is_empty() && fuzz.panicked.is_empty(), "seed {seed}: {fuzz:?}");
        let mut bad = public.clone();
        bad[PUB_SUM_OUT] += Fp::ONE;
        assert!(verify(&config, &BlockAir, &bad, &proof, &mut tr()).is_err());
    }
}
