//! The name segment circuit: proves that a block's name operations and
//! sweeps are valid and correctly transform the state tree (see
//! `docs/NAMES.md`).
//!
//! # Statement
//!
//! Public values (57 elements):
//!
//! ```text
//! root_in[8] root_out[8]     state root before and after the operations
//! pos_in(2) pos_out(2)       next output position before and after (commits take positions)
//! nsp[16]                    name operations sponge after the operations, from its initial state
//! ssp[16]                    sweeps sponge after the swept positions, from its initial state
//! height                     the block's height
//! counts[4]                  commits, reveals, updates, sweeps
//! ```
//!
//! The aggregator chains `root_in` and `pos_in` from the last transaction
//! segment, checks `nsp` against the transaction segments' operations
//! sponge (so every operation applied here was signed by a transaction's
//! inputs, in this order, and none was skipped), checks `ssp` against the
//! block body's swept positions, the height against the block's and the
//! counts against the caps.
//!
//! # Operations
//!
//! Each operation starts with an `op` row that loads its kind and the
//! witnesses that are not computed in the circuit, then:
//!
//! ```text
//! commit:  cleaf(2) leafc leafc2 pload walk(40) term opd(3) nlist
//! sweep:   cleaf(2) leafc leafc2 win pload walk(40) term slist
//! reveal:  name(4) key(4) rec2(4) rec(4) tleaf(2) tleaf2(2) tload walk(1+d) term [split..]
//!          commit(3) cleaf(2) leafc leafc2 win win2 pload walk(40) term opd(2) nlist
//! update:  name(4) key(4) rec2(4) rec(4) tleaf(2) tleaf2(2) tload walk(1+d) term
//!          umsg [xmss signature] pkh0 pkh1 opd(2) nlist
//! ```
//!
//! `name` hashes the name's 32 elements, checking each is a charset value
//! or zero padding; `key` decomposes the hash into the 120 key bits; `rec`
//! and `rec2` hash the new and current (or colliding) record; `tleaf` and
//! `tleaf2` their trie leaves. `commit` recomputes the commit from the name
//! hash, a witness salt and the owner, `cleaf` binds it to the commit's
//! height and `leafc` to its memo, giving the output leaf the commit
//! occupies. `win` and `win2` check the reveal window (or, for a sweep,
//! expiry) with the block height.
//!
//! A walk verifies a path from the state root down to a terminal node, top
//! down, two rows a level: an `old` row shows the current node is the hash
//! of a witness child and sibling in the direction of the current key bit,
//! a `new` row shows the new node is the hash of a new child and the same
//! sibling. The directions come from a shift register of 120 key bits (or
//! 40 position bits), consumed one a level; a trie walk's first level is
//! the state root's, where the direction is right and the sibling is the
//! outputs' root. The `term` row then checks the two terminals by the kind
//! of walk: an output walk inserts a commit leaf into an empty slot or
//! removes it; a trie walk for an update finds the current leaf and
//! replaces it; a trie walk for a reveal finds an empty slot (the empty
//! trie at depth zero) and places the leaf, or finds another name's leaf
//! and continues with `split` rows that build the chain of nodes down to
//! the first bit where the two keys differ, checked against a second shift
//! register of the other key's bits.
//!
//! The update's owner signs the hash of the new record's leaf value; the
//! signature is verified by [`crate::xmss_fragment`] and the key's hash
//! must be the current owner, which must differ from the new one.
//!
//! `opd` hashes the operation's digest as the block lists it and `nlist`
//! absorbs it into the operations sponge; `slist` absorbs a swept position
//! into the sweeps sponge.

use crate::block_air::{absorb_op, absorb_sweep, initial_names_state, initial_sweeps_state};
use crate::field::Field;
use crate::hash_machine::{
    COL_ABSORB, COL_ACC, COL_CHAIN, COL_COMPRESS, COL_DATA, COL_DIR, COL_LOAD, COL_PASS, COL_START, HashTraceBuilder,
    NUM_COLS as HM_COLS, eval_hash_machine,
};
use crate::name_trie::{self, KEY_BITS, Key, Terminal, bit, empty_root, key_of, leaf_hash};
use crate::names::{
    self, BlockNameOp, Commit, MAX_REVEAL, MIN_REVEAL, NAME_MAX, NameOp, NameSet, Record, commit_hash, commit_leaf,
    name_hash,
};
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH, compress};
use crate::poseidon2_air::{COL_INPUT, COL_OUTPUT};
use crate::stark::{Air, Builder, Trace};
use crate::state_tree::{DEPTH, Digest, EMPTY};
use crate::transaction::memo_slot;
use crate::transaction::{DOM_PUBKEY, Sig};
use crate::utxo::UtxoSet;
use crate::xmss::{PUB_SEED_LEN, PublicKey};
use crate::xmss_fragment::{self, Cols as XCols, Types as XTypes, bits_value};

/// A commit's memo from its slot (the memo, then amount zero's limbs).
fn memo_of(slot: &Digest) -> crate::transaction::Memo {
    slot[..crate::transaction::MEMO_LEN].try_into().unwrap()
}

/// Every name segment trace has this many rows.
pub const NAME_LOG_ROWS: usize = 15;

const MASK30: u64 = (1 << 30) - 1;
/// Bits of a charset element: values 0 to 37 fit six.
const CHAR_BITS: usize = 6;

// ---- row types ----
pub const T_OP: usize = HM_COLS;
pub const T_NAME: usize = HM_COLS + 1;
pub const T_KEY: usize = HM_COLS + 2;
pub const T_REC2: usize = HM_COLS + 3;
pub const T_REC: usize = HM_COLS + 4;
pub const T_TLEAF: usize = HM_COLS + 5;
pub const T_TLEAF2: usize = HM_COLS + 6;
pub const T_TLOAD: usize = HM_COLS + 7;
pub const T_WOLD: usize = HM_COLS + 8;
pub const T_WNEW: usize = HM_COLS + 9;
pub const T_TERM: usize = HM_COLS + 10;
pub const T_SPLIT: usize = HM_COLS + 11;
pub const T_UMSG: usize = HM_COLS + 12;
pub const T_MSG_START: usize = HM_COLS + 13;
pub const T_MSG_ABS: usize = HM_COLS + 14;
pub const T_LOAD: usize = HM_COLS + 15;
pub const T_STEP: usize = HM_COLS + 16;
pub const T_LEAF: usize = HM_COLS + 17;
pub const T_TREE_START: usize = HM_COLS + 18;
pub const T_TREE_ABS: usize = HM_COLS + 19;
pub const T_PKH0: usize = HM_COLS + 20;
pub const T_PKH1: usize = HM_COLS + 21;
pub const T_COMMIT: usize = HM_COLS + 22;
pub const T_CLEAF: usize = HM_COLS + 23;
pub const T_LEAFC: usize = HM_COLS + 24;
pub const T_WIN: usize = HM_COLS + 25;
pub const T_WIN2: usize = HM_COLS + 26;
pub const T_PLOAD: usize = HM_COLS + 27;
pub const T_OPD: usize = HM_COLS + 28;
pub const T_NLIST: usize = HM_COLS + 29;
pub const T_SLIST: usize = HM_COLS + 30;
pub const T_DONE: usize = HM_COLS + 31;
/// The commit output's second leaf row: `leafc`'s digest compressed with
/// the commit's height, its creation height ([`crate::transaction::leaf`]).
pub const T_LEAFC2: usize = HM_COLS + 32;
const NUM_TYPES: usize = 33;

/// Row types and their lengths (rows per phase); `T_OPD` is 2 or 3.
const PHASES: [(usize, usize); 9] = [
    (T_NAME, 4),
    (T_KEY, 4),
    (T_REC2, 4),
    (T_REC, 4),
    (T_COMMIT, 3),
    (T_CLEAF, 2),
    (T_TLEAF, 2),
    (T_TLEAF2, 2),
    (T_OPD, 3),
];
const IDX: usize = 4;

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
/// The walk's sibling register, shared with the signature fragment.
pub const R_SIB: usize = XCOLS.sib(0);
const BASE: usize = XCOLS.base + xmss_fragment::LEN;

// ---- counters and gadgets ----
/// One-hot row index within a phase.
pub const C_IDX: usize = BASE;
/// One-hot operation kind: commit, reveal, update, sweep.
pub const R_KIND: usize = C_IDX + IDX;
pub const KIND_COMMIT: usize = 0;
pub const KIND_REVEAL: usize = 1;
pub const KIND_UPDATE: usize = 2;
pub const KIND_SWEEP: usize = 3;
/// One-hot walk kind.
pub const R_WK: usize = R_KIND + 4;
pub const WK_COMMIT: usize = 0;
pub const WK_RDEL: usize = 1;
pub const WK_SWEEP: usize = 2;
pub const WK_REMPTY: usize = 3;
pub const WK_RSPLIT: usize = 4;
pub const WK_UPDATE: usize = 5;
const WKS: usize = 6;
pub const R_CNT: usize = R_WK + WKS;
/// One on the last row of a phase.
pub const C_EXIT: usize = R_CNT + 4;
pub const R_LEVEL: usize = C_EXIT + 1;
pub const C_LVL_INV: usize = R_LEVEL + 1;
pub const C_LVL0: usize = C_LVL_INV + 1;
pub const R_WLEN: usize = C_LVL0 + 1;
pub const C_LAST_INV: usize = R_WLEN + 1;
pub const C_IS_LAST: usize = C_LAST_INV + 1;
pub const C_W1_INV: usize = C_IS_LAST + 1;
pub const C_W1: usize = C_W1_INV + 1;
/// The first level of a trie walk.
pub const C_TOP: usize = C_W1 + 1;
/// The last split row: the two keys' current bits differ.
pub const C_LS: usize = C_TOP + 1;
/// A commit's list row: the position counter advances.
pub const C_ADV: usize = C_LS + 1;
pub const C_WRAP: usize = C_ADV + 1;
pub const C_WRAP_INV: usize = C_WRAP + 1;
pub const C_NEQ_SEL: usize = C_WRAP_INV + 1;
pub const C_NEQ_D: usize = C_NEQ_SEL + DIGEST;
pub const C_NEQ_INV: usize = C_NEQ_D + 1;
// ---- registers ----
pub const R_ROOT: usize = C_NEQ_INV + 1;
pub const R_ONODE: usize = R_ROOT + DIGEST;
pub const R_NNODE: usize = R_ONODE + DIGEST;
pub const R_KB: usize = R_NNODE + DIGEST;
pub const R_KB2: usize = R_KB + KEY_BITS;
pub const R_NAMEH: usize = R_KB2 + KEY_BITS;
pub const R_OWNER: usize = R_NAMEH + DIGEST;
pub const R_OWNER2: usize = R_OWNER + DIGEST;
pub const R_VAL: usize = R_OWNER2 + DIGEST;
pub const R_VAL2: usize = R_VAL + DIGEST;
pub const R_LEAF: usize = R_VAL2 + DIGEST;
pub const R_OLEAF: usize = R_LEAF + DIGEST;
pub const R_C: usize = R_OLEAF + DIGEST;
pub const R_CMEMO: usize = R_C + DIGEST;
pub const R_CH: usize = R_CMEMO + DIGEST;
pub const R_CLEAF: usize = R_CH + 1;
pub const R_MSG: usize = R_CLEAF + DIGEST;
pub const R_OPX: usize = R_MSG + DIGEST;
pub const R_NSP: usize = R_OPX + DIGEST;
pub const R_SSP: usize = R_NSP + WIDTH;
pub const R_POS_LO: usize = R_SSP + WIDTH;
pub const R_POS_HI: usize = R_POS_LO + 1;
pub const R_WPOS_LO: usize = R_POS_HI + 1;
pub const R_WPOS_HI: usize = R_WPOS_LO + 1;
// ---- charset ----
pub const C_CB: usize = R_WPOS_HI + 1;
pub const C_LIVE: usize = C_CB + RATE * CHAR_BITS;
pub const C_LIVE_INV: usize = C_LIVE + RATE;
pub const NUM_COLS: usize = C_LIVE_INV + RATE;

// ---- public values ----
pub const PUB_ROOT_IN: usize = 0;
pub const PUB_ROOT_OUT: usize = DIGEST;
pub const PUB_POS_IN: usize = 2 * DIGEST;
pub const PUB_POS_OUT: usize = PUB_POS_IN + 2;
pub const PUB_NSP: usize = PUB_POS_OUT + 2;
pub const PUB_SSP: usize = PUB_NSP + WIDTH;
pub const PUB_HEIGHT: usize = PUB_SSP + WIDTH;
pub const PUB_COUNTS: usize = PUB_HEIGHT + 1;
pub const NUM_PUBLIC: usize = PUB_COUNTS + 4;

fn pow2<F: Field>(k: usize) -> F {
    F::from_u32(1 << k)
}

fn cap_const<F: Field>(domain: u32, len: u32) -> [F; RATE] {
    let mut c = [F::ZERO; RATE];
    c[0] = F::from_u32(domain);
    c[1] = F::from_u32(len);
    c
}

// ---------------------------------------------------------------------------
// Constraints
// ---------------------------------------------------------------------------

pub struct NameAir;

impl Air for NameAir {
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
        let nt = |t: usize| -> F { n[t] };
        let height = pubv(PUB_HEIGHT);

        // ---------------- row types ----------------
        b.mark("row types");
        let types: [F; NUM_TYPES] = core::array::from_fn(|i| l[T_OP + i]);
        for t in types {
            b.assert_zero(t * t - t);
        }
        b.assert_eq(types.iter().fold(F::ZERO, |a, t| a + *t), one);
        let ty = |t: usize| -> F { l[t] };
        let (op, name, key, rec2, rec) = (ty(T_OP), ty(T_NAME), ty(T_KEY), ty(T_REC2), ty(T_REC));
        let (tleaf, tleaf2, tload, wold, wnew) = (ty(T_TLEAF), ty(T_TLEAF2), ty(T_TLOAD), ty(T_WOLD), ty(T_WNEW));
        let (term, split, umsg, pkh0, pkh1) = (ty(T_TERM), ty(T_SPLIT), ty(T_UMSG), ty(T_PKH0), ty(T_PKH1));
        let (commit_t, cleaf, leafc, win, win2) = (ty(T_COMMIT), ty(T_CLEAF), ty(T_LEAFC), ty(T_WIN), ty(T_WIN2));
        let leafc2 = ty(T_LEAFC2);
        let (pload, opd, nlist, slist, done) = (ty(T_PLOAD), ty(T_OPD), ty(T_NLIST), ty(T_SLIST), ty(T_DONE));
        let (msg_start, msg_abs, load, step) = (ty(T_MSG_START), ty(T_MSG_ABS), ty(T_LOAD), ty(T_STEP));
        let (xleaf, tree_start, tree_abs) = (ty(T_LEAF), ty(T_TREE_START), ty(T_TREE_ABS));
        let active = l[XCOLS.active()];
        let idx: [F; IDX] = core::array::from_fn(|i| l[C_IDX + i]);
        for v in idx {
            b.assert_zero(v * v - v);
        }
        b.assert_eq(idx.iter().fold(F::ZERO, |a, v| a + *v), one);
        let kind: [F; 4] = core::array::from_fn(|i| l[R_KIND + i]);
        for v in kind {
            b.assert_zero(v * v - v);
        }
        b.assert_eq(kind.iter().fold(F::ZERO, |a, v| a + *v), one);
        let (is_commit, is_reveal, is_update, is_sweep) =
            (kind[KIND_COMMIT], kind[KIND_REVEAL], kind[KIND_UPDATE], kind[KIND_SWEEP]);
        let wk: [F; WKS] = core::array::from_fn(|i| l[R_WK + i]);
        for v in wk {
            b.assert_zero(v * v - v);
        }
        b.assert_eq(wk.iter().fold(F::ZERO, |a, v| a + *v), one);
        let trie = wk[WK_REMPTY] + wk[WK_RSPLIT] + wk[WK_UPDATE];

        // The signature fragment, over the update message register.
        let msg: [F; DIGEST] = core::array::from_fn(|i| l[R_MSG + i]);
        xmss_fragment::eval(b, &XCOLS, &XTYPES, &msg, nt(T_PKH0));

        // machine op mapping
        let multi_start = (name + rec2 + rec + commit_t + cleaf + tleaf + tleaf2 + opd) * idx[0];
        let multi_absorb = (name + rec2 + rec + commit_t + opd) * (one - idx[0]) + (cleaf + tleaf + tleaf2) * idx[1];
        b.assert_eq(
            l[COL_START],
            multi_start
                + leafc
                + leafc2
                + umsg
                + wold
                + wnew
                + split
                + nlist
                + slist
                + pkh0
                + msg_start
                + xleaf
                + tree_start,
        );
        b.assert_eq(l[COL_ABSORB], multi_absorb + pkh1 + msg_abs + tree_abs);
        b.assert_eq(l[COL_LOAD], load);
        b.assert_eq(l[COL_CHAIN], step * active);
        b.assert_eq(l[COL_PASS], op + key + win + win2 + pload + tload + term + done + step * (one - active));
        b.assert_zero(l[COL_COMPRESS]);
        b.when_first_row(one - op - done);
        b.when_first_row(one - idx[0]);
        b.when_last_row(one - done);

        // ---------------- phase index ----------------
        b.mark("phase index");
        // The last row of a phase: single-row types, the last index of a
        // multi-row type, and the operation digest's kind-dependent end.
        let singles = op
            + tload
            + wold
            + wnew
            + term
            + split
            + umsg
            + leafc
            + leafc2
            + win
            + win2
            + pload
            + nlist
            + slist
            + done
            + pkh0
            + pkh1
            + msg_start
            + msg_abs
            + load
            + step
            + xleaf
            + tree_start
            + tree_abs;
        let mut phase_last = singles;
        for (t, len) in PHASES {
            if t == T_OPD {
                phase_last += opd * (idx[2] + idx[1] * (one - is_commit));
            } else {
                phase_last += ty(t) * idx[len - 1];
            }
        }
        let exit = l[C_EXIT];
        b.assert_eq(exit, phase_last);
        b.when_transition(n[C_IDX] - exit);
        for i in 1..IDX {
            let mut from = F::ZERO;
            for (t, len) in PHASES {
                if t == T_OPD {
                    if i == 1 {
                        from += opd * idx[0];
                    } else if i == 2 {
                        from += opd * idx[1] * is_commit;
                    }
                } else if len > i {
                    from += ty(t) * idx[i - 1];
                }
            }
            b.when_transition(n[C_IDX + i] - from);
        }

        // ---------------- gadgets ----------------
        b.mark("gadgets");
        let level = l[R_LEVEL];
        let lvl0 = l[C_LVL0];
        b.assert_zero(lvl0 * lvl0 - lvl0);
        b.assert_eq(level * l[C_LVL_INV], one - lvl0);
        b.assert_zero(lvl0 * level);
        let wlen = l[R_WLEN];
        let is_last = l[C_IS_LAST];
        let to_end = level + one - wlen;
        b.assert_zero(is_last * is_last - is_last);
        b.assert_eq(to_end * l[C_LAST_INV], one - is_last);
        b.assert_zero(is_last * to_end);
        let w1 = l[C_W1];
        b.assert_zero(w1 * w1 - w1);
        b.assert_eq((wlen - one) * l[C_W1_INV], one - w1);
        b.assert_zero(w1 * (wlen - one));
        let top = l[C_TOP];
        b.assert_eq(top, trie * lvl0);
        let kb: [F; KEY_BITS] = core::array::from_fn(|i| l[R_KB + i]);
        let kb2: [F; KEY_BITS] = core::array::from_fn(|i| l[R_KB2 + i]);
        for i in 0..KEY_BITS {
            b.assert_zero(kb[i] * kb[i] - kb[i]);
            b.assert_zero(kb2[i] * kb2[i] - kb2[i]);
        }
        let ls = l[C_LS];
        b.assert_eq(ls, kb[0] + kb2[0] - kb[0] * kb2[0] * F::from_u32(2));
        let adv = l[C_ADV];
        b.assert_eq(adv, nlist * is_commit);
        let wrap = l[C_WRAP];
        let lo_max = F::from_u32((1u32 << 30) - 1);
        b.assert_zero(wrap * wrap - wrap);
        b.assert_zero(wrap * (l[R_POS_LO] - lo_max));
        b.assert_eq((l[R_POS_LO] - lo_max) * l[C_WRAP_INV], one - wrap);
        // Owner inequality: a selected component of the difference is
        // invertible on an update message row.
        let sel: [F; DIGEST] = core::array::from_fn(|i| l[C_NEQ_SEL + i]);
        let mut d = F::ZERO;
        for i in 0..DIGEST {
            b.assert_zero(sel[i] * sel[i] - sel[i]);
            d += sel[i] * (l[R_OWNER + i] - l[R_OWNER2 + i]);
        }
        b.assert_eq(sel.iter().fold(F::ZERO, |a, v| a + *v), one);
        b.assert_eq(l[C_NEQ_D], d);
        b.assert_zero(umsg * (l[C_NEQ_D] * l[C_NEQ_INV] - one));

        // ---------------- schedule ----------------
        b.mark("schedule");
        // After the op row: by kind.
        b.when_transition(op * (is_reveal + is_update) * (one - nt(T_NAME)));
        b.when_transition(op * (is_commit + is_sweep) * (one - nt(T_CLEAF)));
        // Multi-row phases: stay until the exit, then the fixed successor.
        let follow = |b: &mut Builder<'_, F>, t: usize, next: usize| {
            b.when_transition(ty(t) * (one - exit) * (one - nt(t)));
            b.when_transition(ty(t) * exit * (one - nt(next)));
        };
        follow(b, T_NAME, T_KEY);
        follow(b, T_KEY, T_REC2);
        follow(b, T_REC2, T_REC);
        follow(b, T_REC, T_TLEAF);
        follow(b, T_TLEAF, T_TLEAF2);
        follow(b, T_TLEAF2, T_TLOAD);
        follow(b, T_COMMIT, T_CLEAF);
        follow(b, T_CLEAF, T_LEAFC);
        follow(b, T_OPD, T_NLIST);
        // Walks.
        b.when_transition((pload + tload) * (one - nt(T_WOLD)));
        b.when_transition(wold * (one - nt(T_WNEW)));
        b.when_transition(wnew * (one - is_last) * (one - nt(T_WOLD)));
        b.when_transition(wnew * is_last * (one - nt(T_TERM)));
        b.when_transition(term * (wk[WK_COMMIT] + wk[WK_RDEL]) * (one - nt(T_OPD)));
        b.when_transition(term * wk[WK_SWEEP] * (one - nt(T_SLIST)));
        b.when_transition(term * wk[WK_REMPTY] * (one - nt(T_COMMIT)));
        b.when_transition(term * wk[WK_RSPLIT] * (one - nt(T_SPLIT)));
        b.when_transition(term * wk[WK_UPDATE] * (one - nt(T_UMSG)));
        b.when_transition(split * (one - ls) * (one - nt(T_SPLIT)));
        b.when_transition(split * ls * (one - nt(T_COMMIT)));
        // Update signature.
        b.when_transition(umsg * (one - nt(T_MSG_START)));
        b.when_transition(pkh0 * (one - nt(T_PKH1)));
        b.when_transition(pkh1 * (one - nt(T_OPD)));
        // Commit leaf and window.
        b.when_transition(leafc * (one - nt(T_LEAFC2)));
        b.when_transition(leafc2 * is_commit * (one - nt(T_PLOAD)));
        b.when_transition(leafc2 * (is_reveal + is_sweep) * (one - nt(T_WIN)));
        b.when_transition(win * is_sweep * (one - nt(T_PLOAD)));
        b.when_transition(win * is_reveal * (one - nt(T_WIN2)));
        b.when_transition(win2 * (one - nt(T_PLOAD)));
        // End of an operation.
        b.when_transition((nlist + slist) * (one - nt(T_OP) - nt(T_DONE)));
        b.when_transition(done * (one - nt(T_DONE)));

        // ---------------- kinds, walk kinds, counts ----------------
        b.mark("kinds and counts");
        for k in 0..4 {
            b.when_transition((one - nt(T_OP)) * (n[R_KIND + k] - kind[k]));
            b.when_transition(op * (n[R_CNT + k] - l[R_CNT + k] - kind[k]));
            b.when_transition((one - op) * (n[R_CNT + k] - l[R_CNT + k]));
            b.when_first_row(l[R_CNT + k]);
            b.when_last_row(l[R_CNT + k] - pubv(PUB_COUNTS + k));
        }
        for k in 0..WKS {
            b.when_transition((one - pload - tload) * (n[R_WK + k] - wk[k]));
        }
        b.when_transition(pload * (n[R_WK + WK_COMMIT] - is_commit));
        b.when_transition(pload * (n[R_WK + WK_RDEL] - is_reveal));
        b.when_transition(pload * (n[R_WK + WK_SWEEP] - is_sweep));
        b.when_transition(pload * (n[R_WK + WK_REMPTY] + n[R_WK + WK_RSPLIT] + n[R_WK + WK_UPDATE]));
        b.when_transition(tload * (n[R_WK + WK_UPDATE] - is_update));
        b.when_transition(tload * (n[R_WK + WK_REMPTY] + n[R_WK + WK_RSPLIT] - is_reveal));
        b.when_transition(tload * (n[R_WK + WK_COMMIT] + n[R_WK + WK_RDEL] + n[R_WK + WK_SWEEP]));

        // ---------------- op-level registers ----------------
        b.mark("op registers");
        // Free entering an op row, else fixed (or set where computed).
        let fixed = |b: &mut Builder<'_, F>, at: usize, len: usize, except: F| {
            for i in 0..len {
                b.when_transition((one - nt(T_OP) - except) * (n[at + i] - l[at + i]));
            }
        };
        fixed(b, R_OWNER, DIGEST, F::ZERO);
        fixed(b, R_OWNER2, DIGEST, F::ZERO);
        fixed(b, R_CMEMO, DIGEST, F::ZERO);
        fixed(b, R_CH, 1, F::ZERO);
        fixed(b, R_WPOS_LO, 2, F::ZERO);
        fixed(b, R_KB2, KEY_BITS, wnew + split);
        fixed(b, R_C, DIGEST, commit_t * idx[2]);
        fixed(b, R_VAL2, DIGEST, rec2 * idx[IDX - 1]);
        // A commit is made at this height, at the next position.
        b.assert_zero(op * is_commit * (l[R_CH] - height));
        b.assert_zero(op * is_commit * (l[R_WPOS_LO] - l[R_POS_LO]));
        b.assert_zero(op * is_commit * (l[R_WPOS_HI] - l[R_POS_HI]));
        // Computed registers: set after the phase that computes them.
        let computed = |b: &mut Builder<'_, F>, at: usize, when: F| {
            for i in 0..DIGEST {
                b.when_transition(when * (n[at + i] - l[COL_ACC + i]));
                b.when_transition((one - when) * (n[at + i] - l[at + i]));
            }
        };
        computed(b, R_NAMEH, name * idx[IDX - 1]);
        computed(b, R_VAL, rec * idx[IDX - 1]);
        computed(b, R_LEAF, tleaf * idx[1]);
        computed(b, R_OLEAF, tleaf2 * idx[1]);
        computed(b, R_CLEAF, leafc2);
        computed(b, R_MSG, umsg);
        for i in 0..DIGEST {
            b.when_transition(commit_t * idx[2] * (n[R_C + i] - l[COL_ACC + i]));
            b.when_transition(rec2 * idx[IDX - 1] * (n[R_VAL2 + i] - l[COL_ACC + i]));
            // The digest the operation hashes: the commit, or the record
            // leaf value.
            b.when_transition(term * (wk[WK_COMMIT]) * (n[R_OPX + i] - l[R_C + i]));
            b.when_transition(term * (wk[WK_RDEL]) * (n[R_OPX + i] - l[R_VAL + i]));
            b.when_transition(pkh1 * (n[R_OPX + i] - l[R_VAL + i]));
            b.when_transition((one - term - pkh1) * (n[R_OPX + i] - l[R_OPX + i]));
        }

        // ---------------- hashing phases ----------------
        b.mark("hashing phases");
        let data: [F; RATE] = core::array::from_fn(|i| l[COL_DATA + i]);
        let inp: [F; WIDTH] = core::array::from_fn(|i| l[COL_INPUT + i]);
        let nameh: [F; DIGEST] = core::array::from_fn(|i| l[R_NAMEH + i]);
        // A phase's start row: block zero in the rate, the capacity constant.
        let start_cap = |b: &mut Builder<'_, F>, t: F, cap: [F; RATE]| {
            for j in 0..RATE {
                b.assert_zero(t * (inp[RATE + j] - cap[j]));
            }
        };
        let block_is = |b: &mut Builder<'_, F>, t: F, first: bool, block: [F; RATE]| {
            for i in 0..RATE {
                let have = if first { inp[i] } else { data[i] };
                b.assert_zero(t * (have - block[i]));
            }
        };
        let digest_block = |at: usize| -> [F; RATE] { core::array::from_fn(|i| l[at + i]) };
        // name: the 32 elements, charset checked (data mirrors the input on
        // the start row so every row's elements are in `data`).
        start_cap(b, name * idx[0], cap_const(names::DOM_NAME, NAME_MAX as u32));
        block_is(b, name * idx[0], true, data);
        for i in 0..RATE {
            let mut v = F::ZERO;
            let cb: [F; CHAR_BITS] = core::array::from_fn(|k| l[C_CB + CHAR_BITS * i + k]);
            for (k, bit) in cb.iter().enumerate() {
                b.assert_zero(*bit * *bit - *bit);
                v += *bit * pow2::<F>(k);
            }
            b.assert_zero(name * (v - data[i]));
            // Below 38: not (bit5 and (bit4 or bit3 or (bit2 and bit1))).
            b.assert_zero(cb[5] * (cb[4] + cb[3] + cb[2] * cb[1]));
            let live = l[C_LIVE + i];
            b.assert_zero(live * live - live);
            b.assert_zero(name * (one - live) * data[i]);
            b.assert_zero(name * (data[i] * l[C_LIVE_INV + i] - live));
            if i + 1 < RATE {
                b.assert_zero(name * l[C_LIVE + i + 1] * (one - live));
            }
        }
        b.assert_zero(name * idx[0] * (one - l[C_LIVE]));
        b.when_transition(nt(T_NAME) * n[C_LIVE] * (one - l[C_LIVE + RATE - 1]));
        // key: element i of the name hash decomposed canonically; its low
        // 30 bits become key bits 30i.. (most significant first).
        let bits_v = bits_value(l, &XCOLS);
        let mut elem = F::ZERO;
        for i in 0..IDX {
            elem += idx[i] * nameh[i];
        }
        b.assert_zero(key * (bits_v - elem));
        // rec, rec2: name hash, owner, value, memo.
        let rec_cap = cap_const(names::DOM_RECORD, 4 * DIGEST as u32);
        start_cap(b, rec * idx[0], rec_cap);
        start_cap(b, rec2 * idx[0], rec_cap);
        block_is(b, rec * idx[0], true, nameh);
        block_is(b, rec * idx[1], false, digest_block(R_OWNER));
        block_is(b, rec2 * idx[1], false, digest_block(R_OWNER2));
        // tleaf, tleaf2: the key's four limbs and the record leaf value.
        let limbs = |kb: &[F; KEY_BITS]| -> [F; 4] {
            core::array::from_fn(|i| (0..30).fold(F::ZERO, |a, m| a + kb[30 * i + m] * pow2::<F>(29 - m)))
        };
        let leaf_cap = cap_const(name_trie::DOM_LEAF, 12);
        for (t, kbits, val) in [(tleaf, limbs(&kb), R_VAL), (tleaf2, limbs(&kb2), R_VAL2)] {
            start_cap(b, t * idx[0], leaf_cap);
            let block0: [F; RATE] = core::array::from_fn(|i| if i < 4 { kbits[i] } else { l[val + i - 4] });
            let block1: [F; RATE] = core::array::from_fn(|i| if i < 4 { l[val + 4 + i] } else { F::ZERO });
            block_is(b, t * idx[0], true, block0);
            block_is(b, t * idx[1], false, block1);
        }
        // umsg: the update message over the new record leaf value.
        start_cap(b, umsg, cap_const(names::DOM_UPDATE, DIGEST as u32));
        block_is(b, umsg, true, digest_block(R_VAL));
        // pkh0, pkh1: the signer's key hash is the current owner.
        for i in 0..RATE {
            b.when_transition(nt(T_PKH0) * (n[COL_INPUT + i] - l[COL_ACC + i]));
            let seed = match i {
                _ if i < PUB_SEED_LEN => l[XCOLS.pub_seed(i)],
                PUB_SEED_LEN => xmss_fragment::height_value(l, &XCOLS),
                _ => F::ZERO,
            };
            b.assert_zero(pkh1 * (data[i] - seed));
            b.assert_zero(pkh1 * (l[COL_ACC + i] - l[R_OWNER2 + i]));
        }
        start_cap(b, pkh0, cap_const(DOM_PUBKEY, (DIGEST + PUB_SEED_LEN + 1) as u32));
        // commit: name hash, salt (free), owner.
        start_cap(b, commit_t * idx[0], cap_const(names::DOM_COMMIT, 3 * DIGEST as u32));
        block_is(b, commit_t * idx[0], true, nameh);
        block_is(b, commit_t * idx[2], false, digest_block(R_OWNER));
        // cleaf: the commit and its height; leafc: compressed with the memo.
        start_cap(b, cleaf * idx[0], cap_const(names::DOM_COMMIT_LEAF, DIGEST as u32 + 1));
        block_is(b, cleaf * idx[0], true, digest_block(R_C));
        let ch_block: [F; RATE] = core::array::from_fn(|i| if i == 0 { l[R_CH] } else { F::ZERO });
        block_is(b, cleaf * idx[1], false, ch_block);
        // leafc2: that digest compressed with the commit's height, the
        // output's creation height.
        for i in 0..RATE {
            b.when_transition((nt(T_LEAFC) + nt(T_LEAFC2)) * (n[COL_INPUT + i] - l[COL_ACC + i]));
            b.assert_zero(leafc * (inp[RATE + i] - l[R_CMEMO + i]));
            b.assert_zero(leafc2 * (inp[RATE + i] - if i == 0 { l[R_CH] } else { F::ZERO }));
        }
        // win, win2: the commit's age against the window (or past it).
        let min = F::from_u32(MIN_REVEAL);
        let span = F::from_u32(MAX_REVEAL + 1 - MIN_REVEAL);
        b.assert_zero(win * (bits_v - (height - l[R_CH] - min - is_sweep * span)));
        b.assert_zero(win2 * (bits_v - (l[R_CH] + F::from_u32(MAX_REVEAL) - height)));
        // opd: the operation digest as the block lists it.
        let opd_len = F::from_u32(2 * DIGEST as u32) + is_commit * F::from_u32(DIGEST as u32);
        let tag = is_commit * F::from_u32(names::TAG_COMMIT as u32)
            + is_reveal * F::from_u32(names::TAG_REVEAL as u32)
            + is_update * F::from_u32(names::TAG_UPDATE as u32);
        let opd_cap: [F; RATE] = core::array::from_fn(|j| match j {
            0 => F::from_u32(names::DOM_OP),
            1 => opd_len,
            _ => F::ZERO,
        });
        start_cap(b, opd * idx[0], opd_cap);
        let tag_block: [F; RATE] = core::array::from_fn(|i| if i == 0 { tag } else { F::ZERO });
        block_is(b, opd * idx[0], true, tag_block);
        block_is(b, opd * idx[1], false, digest_block(R_OPX));
        block_is(b, opd * idx[2], false, digest_block(R_CMEMO));
        // nlist, slist: register sponges.
        for i in 0..RATE {
            b.when_transition(nt(T_NLIST) * (n[COL_INPUT + i] - n[R_NSP + i] - l[COL_ACC + i]));
            b.assert_zero(nlist * (inp[RATE + i] - l[R_NSP + RATE + i]));
            let pos_part = match i {
                0 => l[R_WPOS_LO],
                1 => l[R_WPOS_HI],
                _ => F::ZERO,
            };
            b.assert_zero(slist * (inp[i] - l[R_SSP + i] - pos_part));
            b.assert_zero(slist * (inp[RATE + i] - l[R_SSP + RATE + i]));
        }
        for j in 0..WIDTH {
            b.when_transition(nlist * (n[R_NSP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - nlist) * (n[R_NSP + j] - l[R_NSP + j]));
            b.when_transition(slist * (n[R_SSP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - slist) * (n[R_SSP + j] - l[R_SSP + j]));
            b.when_first_row(l[R_NSP + j] - initial_names_state()[j].into());
            b.when_first_row(l[R_SSP + j] - initial_sweeps_state()[j].into());
            b.when_last_row(l[R_NSP + j] - pubv(PUB_NSP + j));
            b.when_last_row(l[R_SSP + j] - pubv(PUB_SSP + j));
        }
        // The position counter advances after a commit's list row.
        b.when_transition(adv * (n[R_POS_LO] - (one - wrap) * (l[R_POS_LO] + one)));
        b.when_transition(adv * (n[R_POS_HI] - l[R_POS_HI] - wrap));
        b.when_transition((one - adv) * (n[R_POS_LO] - l[R_POS_LO]));
        b.when_transition((one - adv) * (n[R_POS_HI] - l[R_POS_HI]));
        b.when_first_row(l[R_POS_LO] - pubv(PUB_POS_IN));
        b.when_first_row(l[R_POS_HI] - pubv(PUB_POS_IN + 1));
        b.when_last_row(l[R_POS_LO] - pubv(PUB_POS_OUT));
        b.when_last_row(l[R_POS_HI] - pubv(PUB_POS_OUT + 1));

        // ---------------- walks ----------------
        b.mark("walks");
        let dir = l[COL_DIR];
        let walk_load = pload + tload;
        // Loading: the old node is the root, the root becomes the new one
        // (a witness), the level is zero; an output walk is 40 levels over
        // the position's bits, a trie walk as long as the witness says.
        b.when_transition(walk_load * (n[R_LEVEL]));
        b.when_transition(pload * (n[R_WLEN] - F::from_u32(DEPTH as u32)));
        // One constraint per 30-bit limb: 40 bits in one sum would exceed
        // the field, and two bit patterns could meet the same position.
        let (mut pos_lo, mut pos_hi) = (F::ZERO, F::ZERO);
        for m in 0..DEPTH {
            let k = DEPTH - 1 - m;
            if k < 30 {
                pos_lo += n[R_KB + m] * pow2::<F>(k);
            } else {
                pos_hi += n[R_KB + m] * pow2::<F>(k - 30);
            }
        }
        b.when_transition(pload * (pos_lo - l[R_WPOS_LO]));
        b.when_transition(pload * (pos_hi - l[R_WPOS_HI]));
        // An update finds its own key: the second register holds the same.
        for i in 0..KEY_BITS {
            b.assert_zero(tload * is_update * (kb[i] - kb2[i]));
        }
        // Level and length registers.
        b.when_transition(wold * (n[R_LEVEL] - level));
        b.when_transition((wnew + split) * (n[R_LEVEL] - level - one));
        b.when_transition((one - walk_load - wold - wnew - split) * (n[R_LEVEL] - level));
        b.when_transition((one - walk_load) * (n[R_WLEN] - wlen));
        // Directions: the current key bit, or right at a trie walk's top.
        let dir_want = kb[0] + top * (one - kb[0]);
        b.assert_zero(wold * (dir - dir_want));
        b.when_transition(wold * (n[COL_DIR] - dir));
        b.assert_zero(split * (dir - kb[0]));
        // Key bits: loaded on key rows (slot by index), free on an output
        // walk load, shifted by a level (not the trie's top), else fixed.
        for m in 0..KEY_BITS {
            let slot = m / 30;
            let bit = l[XCOLS.bits(29 - m % 30)];
            let loaded = idx[slot] * bit + (one - idx[slot]) * kb[m];
            b.when_transition(key * (n[R_KB + m] - loaded));
            let shifted = if m + 1 < KEY_BITS { kb[m + 1] } else { F::ZERO };
            let shifted2 = if m + 1 < KEY_BITS { kb2[m + 1] } else { F::ZERO };
            b.when_transition(wnew * (one - top) * (n[R_KB + m] - shifted));
            b.when_transition(wnew * top * (n[R_KB + m] - kb[m]));
            b.when_transition(split * (n[R_KB + m] - shifted));
            b.when_transition((one - key - pload - wnew - split) * (n[R_KB + m] - kb[m]));
            b.when_transition(wnew * (one - top) * (n[R_KB2 + m] - shifted2));
            b.when_transition(wnew * top * (n[R_KB2 + m] - kb2[m]));
            b.when_transition(split * (n[R_KB2 + m] - shifted2));
        }
        // Nodes: the child half and sibling half of this row's input.
        for i in 0..DIGEST {
            let (lo, hi) = (inp[i], inp[RATE + i]);
            let child = (one - dir) * lo + dir * hi;
            let sibling = (one - dir) * hi + dir * lo;
            let (onode, nnode, sib, root, out) =
                (l[R_ONODE + i], l[R_NNODE + i], l[R_SIB + i], l[R_ROOT + i], l[COL_OUTPUT + i]);
            // old rows: this node hashes from the child and a witness sibling
            b.assert_zero(wold * (out - onode));
            b.assert_zero(wold * (sib - sibling));
            b.when_transition(wold * (n[R_ONODE + i] - child));
            b.when_transition(walk_load * (n[R_ONODE + i] - root));
            b.when_transition((one - wold - walk_load) * (n[R_ONODE + i] - onode));
            // new rows: the new node hashes from the new child and the same sibling
            b.assert_zero(wnew * (out - nnode));
            b.assert_zero(wnew * (sibling - sib));
            b.when_transition(wnew * (n[R_NNODE + i] - child));
            // split rows: the chain down to the differing bit, empty
            // siblings until the other leaf
            b.assert_zero(split * (out - nnode));
            b.assert_zero(split * (sib - sibling));
            b.assert_zero(split * (one - ls) * sib);
            b.assert_zero(split * ls * (sib - l[R_OLEAF + i]));
            b.when_transition(split * (n[R_NNODE + i] - child));
            b.when_transition(split * ls * (n[R_NNODE + i] - l[R_LEAF + i]));
            b.when_transition((one - wnew - split - walk_load) * (n[R_NNODE + i] - nnode));
            // the root: replaced by the new root entering a walk
            b.when_transition(walk_load * (n[R_ROOT + i] - n[R_NNODE + i]));
            b.when_transition((one - walk_load) * (n[R_ROOT + i] - root));
            b.when_first_row(root - pubv(PUB_ROOT_IN + i));
            b.when_last_row(root - pubv(PUB_ROOT_OUT + i));
            // terminals
            let er: F = empty_root()[i].into();
            b.assert_zero(term * wk[WK_COMMIT] * onode);
            b.assert_zero(term * wk[WK_COMMIT] * (nnode - l[R_CLEAF + i]));
            b.assert_zero(term * (wk[WK_RDEL] + wk[WK_SWEEP]) * (onode - l[R_CLEAF + i]));
            b.assert_zero(term * (wk[WK_RDEL] + wk[WK_SWEEP]) * nnode);
            b.assert_zero(term * wk[WK_REMPTY] * (onode - w1 * er));
            b.assert_zero(term * wk[WK_REMPTY] * (nnode - l[R_LEAF + i]));
            b.assert_zero(term * (wk[WK_RSPLIT] + wk[WK_UPDATE]) * (onode - l[R_OLEAF + i]));
            b.assert_zero(term * wk[WK_UPDATE] * (nnode - l[R_LEAF + i]));
        }
    }
}

// ---------------------------------------------------------------------------
// Witness
// ---------------------------------------------------------------------------

/// A path in the output half: siblings from the leaf up, as
/// [`crate::state_tree::Proof`] gives them.
pub type OutputPath = [Digest; DEPTH];

/// A path in the trie, as [`NameSet::prove`] gives it, with the outputs'
/// root the trie root is hashed with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriePath {
    pub left: Digest,
    pub proof: name_trie::NameProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpWitness {
    Commit {
        commit: Digest,
        memo: Digest,
        /// Path of the position the commit takes (the next one).
        path: OutputPath,
    },
    Reveal {
        record: Record,
        salt: Digest,
        /// The colliding leaf's record, when the path ends at one.
        other: Option<Record>,
        trie: TriePath,
        commit_height: u32,
        commit_memo: Digest,
        commit_position: u64,
        /// Path of the commit's position, after the registration.
        path: OutputPath,
    },
    Update {
        old: Record,
        new: Record,
        pubkey: PublicKey,
        signature: Sig,
        trie: TriePath,
    },
    Sweep {
        commit: Digest,
        memo: Digest,
        height: u32,
        position: u64,
        path: OutputPath,
    },
}

/// Rows of an output walk with its load and terminal rows.
const OUTPUT_WALK_ROWS: usize = 1 + 2 * DEPTH + 1;

impl OpWitness {
    pub fn kind(&self) -> names::OpKind {
        match self {
            OpWitness::Commit { .. } => names::OpKind::Commit,
            OpWitness::Reveal { .. } => names::OpKind::Reveal,
            OpWitness::Update { .. } => names::OpKind::Update,
            OpWitness::Sweep { .. } => names::OpKind::Sweep,
        }
    }

    /// Trace rows this operation takes.
    pub fn rows(&self) -> usize {
        let trie_walk = |t: &TriePath| 1 + 2 * (1 + t.proof.depth()) + 1;
        match self {
            OpWitness::Commit { .. } => 1 + 2 + 2 + OUTPUT_WALK_ROWS + 3 + 1,
            OpWitness::Sweep { .. } => 1 + 2 + 2 + 1 + OUTPUT_WALK_ROWS + 1,
            OpWitness::Reveal { record, trie, .. } => {
                let split = match trie.proof.terminal {
                    Terminal::Empty => 0,
                    Terminal::Leaf { key, .. } => {
                        let k = record.key().expect("a well-formed name");
                        first_difference(k, key) + 1 - trie.proof.depth()
                    }
                };
                1 + 4 * 4 + 2 * 2 + trie_walk(trie) + split + 3 + 2 + 2 + 2 + OUTPUT_WALK_ROWS + 2 + 1
            }
            OpWitness::Update { trie, pubkey, .. } => {
                1 + 4 * 4 + 2 * 2 + trie_walk(trie) + 1 + xmss_fragment::rows(pubkey.height()) + 2 + 2 + 1
            }
        }
    }
}

/// The first bit at which two keys differ (they must differ).
fn first_difference(a: Key, b: Key) -> usize {
    (a ^ b).leading_zeros() as usize - (128 - KEY_BITS)
}

/// Everything needed to prove one block's name segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameWitness {
    pub root_in: Digest,
    pub pos_in: u64,
    pub height: u32,
    pub ops: Vec<OpWitness>,
}

pub use crate::names::ApplyError;

impl NameWitness {
    /// Applies a block's name operations and sweeps to the UTXO set and
    /// the registry inside `wtxn`, in order, recording what the circuit
    /// needs. The caller commits or aborts the transaction. Checks every
    /// rule the circuit enforces, so a block whose witness collects is one
    /// the circuit accepts.
    pub fn collect(
        utxo: &UtxoSet,
        names: &NameSet,
        wtxn: &mut heed::RwTxn,
        height: u32,
        ops: &[NameOp],
        sweeps: &[u64],
    ) -> Result<NameWitness, ApplyError> {
        let kinds = ops.iter().map(NameOp::kind).chain(sweeps.iter().map(|_| names::OpKind::Sweep));
        names::count_ops(kinds).map_err(ApplyError::TooMany)?;
        let root_in = utxo.root(wtxn)?;
        let pos_in = utxo.next_position(wtxn)?;
        let mut out = Vec::with_capacity(ops.len() + sweeps.len());
        for op in ops {
            out.push(match op {
                NameOp::Commit { commit, memo } => {
                    let position = utxo.next_position(wtxn)?;
                    let path = utxo.prove(wtxn, position)?.siblings;
                    let leaf = commit_leaf(commit, height);
                    utxo.add_output(
                        wtxn,
                        &crate::block::BlockOutput { commitment: leaf, memo: *memo, amount: 0 },
                        height,
                    )?;
                    names.add_commit(wtxn, position, Commit { hash: *commit, height })?;
                    OpWitness::Commit { commit: *commit, memo: memo_slot(memo, 0), path }
                }
                NameOp::Reveal { record, salt, commit: position } => {
                    let elements = record.elements().ok_or(ApplyError::BadName)?;
                    let nh = name_hash(&elements);
                    let key = key_of(&nh);
                    let c = commit_hash(&nh, salt, &record.owner);
                    let position = *position;
                    let commit = names.commit_at(wtxn, position)?.ok_or(ApplyError::NoCommit)?;
                    if commit.hash != c {
                        return Err(ApplyError::NoCommit);
                    }
                    if !names::in_window(height, commit.height) {
                        return Err(ApplyError::Window(commit.height));
                    }
                    let proof = names.prove(wtxn, &record.name)?;
                    let other = match proof.terminal {
                        Terminal::Empty => None,
                        Terminal::Leaf { key: k, .. } if k == key => return Err(ApplyError::Registered),
                        Terminal::Leaf { key: k, .. } => {
                            Some(names.record(wtxn, k)?.ok_or(names::Error::Corrupt("record missing for a leaf"))?)
                        }
                    };
                    let left = utxo.output_root(wtxn)?;
                    let root = names.register(wtxn, record)?;
                    utxo.set_name_root(wtxn, &root)?;
                    let commit_memo = utxo.slot(wtxn, position)?;
                    if !utxo.spend_at(wtxn, &commit_leaf(&c, commit.height), position)? {
                        return Err(ApplyError::NoCommit);
                    }
                    names.remove_commit(wtxn, position)?;
                    let path = utxo.prove(wtxn, position)?.siblings;
                    OpWitness::Reveal {
                        record: record.clone(),
                        salt: *salt,
                        other,
                        trie: TriePath { left, proof },
                        commit_height: commit.height,
                        commit_memo,
                        commit_position: position,
                        path,
                    }
                }
                NameOp::Update { record, pubkey, signature } => {
                    let old = names.lookup(wtxn, &record.name)?.ok_or(ApplyError::NotRegistered)?;
                    if !op.verify_owner(&old.owner) {
                        return Err(ApplyError::BadOwner);
                    }
                    let proof = names.prove(wtxn, &record.name)?;
                    let left = utxo.output_root(wtxn)?;
                    let (_, root) = names.update(wtxn, record)?;
                    utxo.set_name_root(wtxn, &root)?;
                    OpWitness::Update {
                        old,
                        new: record.clone(),
                        pubkey: *pubkey,
                        signature: signature.clone(),
                        trie: TriePath { left, proof },
                    }
                }
            });
        }
        for &position in sweeps {
            let commit = names.commit_at(wtxn, position)?.ok_or(ApplyError::NoCommit)?;
            if !names::expired(height, commit.height) {
                return Err(ApplyError::NotExpired(commit.height));
            }
            let memo = utxo.slot(wtxn, position)?;
            if !utxo.spend_at(wtxn, &commit_leaf(&commit.hash, commit.height), position)? {
                return Err(ApplyError::NoCommit);
            }
            names.remove_commit(wtxn, position)?;
            let path = utxo.prove(wtxn, position)?.siblings;
            out.push(OpWitness::Sweep { commit: commit.hash, memo, height: commit.height, position, path });
        }
        Ok(NameWitness { root_in, pos_in, height, ops: out })
    }

    /// Trace rows before padding.
    pub fn num_rows(&self) -> usize {
        self.ops.iter().map(OpWitness::rows).sum()
    }

    /// The operation digests, in order, as the block lists them.
    pub fn op_digests(&self) -> Vec<Digest> {
        self.ops
            .iter()
            .filter_map(|op| match op {
                OpWitness::Commit { commit, memo, .. } => {
                    BlockNameOp::Commit { commit: *commit, memo: memo_of(memo) }.digest()
                }
                OpWitness::Reveal { record, commit_position, .. } => {
                    BlockNameOp::Reveal { record: record.clone(), commit: *commit_position }.digest()
                }
                OpWitness::Update { new, .. } => BlockNameOp::Update(new.clone()).digest(),
                OpWitness::Sweep { .. } => None,
            })
            .collect()
    }

    /// The operations as the block lists them, in order.
    pub fn block_ops(&self) -> Vec<BlockNameOp> {
        self.ops
            .iter()
            .filter_map(|op| match op {
                OpWitness::Commit { commit, memo, .. } => {
                    Some(BlockNameOp::Commit { commit: *commit, memo: memo_of(memo) })
                }
                OpWitness::Reveal { record, commit_position, .. } => {
                    Some(BlockNameOp::Reveal { record: record.clone(), commit: *commit_position })
                }
                OpWitness::Update { new, .. } => Some(BlockNameOp::Update(new.clone())),
                OpWitness::Sweep { .. } => None,
            })
            .collect()
    }

    /// An empty witness for a block without name operations, continuing
    /// from where `segments` end (or from `self` when there are none).
    pub fn with_segments(mut self, segments: &[crate::block_air::SegmentWitness]) -> NameWitness {
        if let Some(last) = segments.last() {
            let (_, public) = crate::block_air::BlockAir::generate_trace(last);
            self.root_in = public.root_out;
            self.pos_in = public.pos_out;
        }
        self
    }

    /// The swept positions, in order.
    pub fn sweeps(&self) -> Vec<u64> {
        self.ops
            .iter()
            .filter_map(|op| match op {
                OpWitness::Sweep { position, .. } => Some(*position),
                _ => None,
            })
            .collect()
    }
}

/// Boundary values of a name segment: its public statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamePublic {
    pub root_in: Digest,
    pub root_out: Digest,
    pub pos_in: u64,
    pub pos_out: u64,
    pub nsp: [Fp; WIDTH],
    pub ssp: [Fp; WIDTH],
    pub height: u32,
    /// Commits, reveals, updates, sweeps.
    pub counts: [u32; 4],
}

impl NamePublic {
    pub fn to_values(&self) -> Vec<Fp> {
        let mut v = Vec::with_capacity(NUM_PUBLIC);
        v.extend_from_slice(&self.root_in);
        v.extend_from_slice(&self.root_out);
        for p in [self.pos_in, self.pos_out] {
            v.push(Fp::new((p & MASK30) as u32));
            v.push(Fp::new((p >> 30) as u32));
        }
        v.extend_from_slice(&self.nsp);
        v.extend_from_slice(&self.ssp);
        v.push(Fp::new(self.height));
        v.extend(self.counts.iter().map(|c| Fp::new(*c)));
        v
    }

    /// Parses values written by [`NamePublic::to_values`].
    pub fn from_values(v: &[Fp]) -> Option<NamePublic> {
        if v.len() != NUM_PUBLIC {
            return None;
        }
        let digest = |at: usize| -> Digest { v[at..at + DIGEST].try_into().unwrap() };
        let state = |at: usize| -> [Fp; WIDTH] { v[at..at + WIDTH].try_into().unwrap() };
        let pos = |at: usize| -> Option<u64> {
            let (lo, hi) = (v[at].to_canonical() as u64, v[at + 1].to_canonical() as u64);
            if lo >= 1 << 30 || hi >= 1 << 10 { None } else { Some(lo | hi << 30) }
        };
        Some(NamePublic {
            root_in: digest(PUB_ROOT_IN),
            root_out: digest(PUB_ROOT_OUT),
            pos_in: pos(PUB_POS_IN)?,
            pos_out: pos(PUB_POS_OUT)?,
            nsp: state(PUB_NSP),
            ssp: state(PUB_SSP),
            height: v[PUB_HEIGHT].to_canonical(),
            counts: core::array::from_fn(|k| v[PUB_COUNTS + k].to_canonical()),
        })
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Regs {
    xmss: xmss_fragment::Regs,
    kind: usize,
    wk: usize,
    cnt: [u32; 4],
    level: u32,
    wlen: u32,
    root: Digest,
    onode: Digest,
    nnode: Digest,
    kb: [bool; KEY_BITS],
    kb2: [bool; KEY_BITS],
    nameh: Digest,
    owner: Digest,
    owner2: Digest,
    val: Digest,
    val2: Digest,
    leaf: Digest,
    oleaf: Digest,
    c: Digest,
    cmemo: Digest,
    ch: u32,
    cleaf: Digest,
    msg: Digest,
    opx: Digest,
    nsp: [Fp; WIDTH],
    ssp: [Fp; WIDTH],
    pos: u64,
    wpos: u64,
}

fn inv_or_zero(x: Fp) -> Fp {
    x.inverse().unwrap_or(Fp::ZERO)
}

impl Regs {
    fn write(&self, row: &mut [Fp]) {
        self.xmss.write(row, &XCOLS);
        self.write_rest(row);
    }

    /// Everything but the signature fragment's registers.
    fn write_rest(&self, row: &mut [Fp]) {
        row[R_KIND + self.kind] = Fp::ONE;
        row[R_WK + self.wk] = Fp::ONE;
        for k in 0..4 {
            row[R_CNT + k] = Fp::new(self.cnt[k]);
        }
        let level = Fp::new(self.level);
        row[R_LEVEL] = level;
        let lvl0 = level.is_zero();
        row[C_LVL0] = Fp::new(lvl0 as u32);
        row[C_LVL_INV] = inv_or_zero(level);
        let wlen = Fp::new(self.wlen);
        row[R_WLEN] = wlen;
        let to_end = level + Fp::ONE - wlen;
        row[C_IS_LAST] = Fp::new(to_end.is_zero() as u32);
        row[C_LAST_INV] = inv_or_zero(to_end);
        let w1 = wlen - Fp::ONE;
        row[C_W1] = Fp::new(w1.is_zero() as u32);
        row[C_W1_INV] = inv_or_zero(w1);
        let trie = matches!(self.wk, WK_REMPTY | WK_RSPLIT | WK_UPDATE);
        row[C_TOP] = Fp::new((trie && lvl0) as u32);
        row[C_LS] = Fp::new((self.kb[0] ^ self.kb2[0]) as u32);
        let lo = Fp::new((self.pos & MASK30) as u32);
        let diff = lo - Fp::new((1 << 30) - 1);
        row[C_WRAP] = Fp::new(diff.is_zero() as u32);
        row[C_WRAP_INV] = inv_or_zero(diff);
        let sel = (0..DIGEST).find(|&i| self.owner[i] != self.owner2[i]).unwrap_or(0);
        row[C_NEQ_SEL + sel] = Fp::ONE;
        let d = self.owner[sel] - self.owner2[sel];
        row[C_NEQ_D] = d;
        row[C_NEQ_INV] = inv_or_zero(d);
        row[R_ROOT..R_ROOT + DIGEST].copy_from_slice(&self.root);
        row[R_ONODE..R_ONODE + DIGEST].copy_from_slice(&self.onode);
        row[R_NNODE..R_NNODE + DIGEST].copy_from_slice(&self.nnode);
        for m in 0..KEY_BITS {
            row[R_KB + m] = Fp::new(self.kb[m] as u32);
            row[R_KB2 + m] = Fp::new(self.kb2[m] as u32);
        }
        row[R_NAMEH..R_NAMEH + DIGEST].copy_from_slice(&self.nameh);
        row[R_OWNER..R_OWNER + DIGEST].copy_from_slice(&self.owner);
        row[R_OWNER2..R_OWNER2 + DIGEST].copy_from_slice(&self.owner2);
        row[R_VAL..R_VAL + DIGEST].copy_from_slice(&self.val);
        row[R_VAL2..R_VAL2 + DIGEST].copy_from_slice(&self.val2);
        row[R_LEAF..R_LEAF + DIGEST].copy_from_slice(&self.leaf);
        row[R_OLEAF..R_OLEAF + DIGEST].copy_from_slice(&self.oleaf);
        row[R_C..R_C + DIGEST].copy_from_slice(&self.c);
        row[R_CMEMO..R_CMEMO + DIGEST].copy_from_slice(&self.cmemo);
        row[R_CH] = Fp::new(self.ch);
        row[R_CLEAF..R_CLEAF + DIGEST].copy_from_slice(&self.cleaf);
        row[R_MSG..R_MSG + DIGEST].copy_from_slice(&self.msg);
        row[R_OPX..R_OPX + DIGEST].copy_from_slice(&self.opx);
        row[R_NSP..R_NSP + WIDTH].copy_from_slice(&self.nsp);
        row[R_SSP..R_SSP + WIDTH].copy_from_slice(&self.ssp);
        row[R_POS_LO] = lo;
        row[R_POS_HI] = Fp::new((self.pos >> 30) as u32);
        row[R_WPOS_LO] = Fp::new((self.wpos & MASK30) as u32);
        row[R_WPOS_HI] = Fp::new((self.wpos >> 30) as u32);
        // Charset columns are filled on name rows; elsewhere every element
        // counts as live so a following name row's first element may be.
        for i in 0..RATE {
            row[C_LIVE + i] = Fp::ONE;
        }
    }
}

/// Key bits, most significant first.
fn key_bits(key: Key) -> [bool; KEY_BITS] {
    core::array::from_fn(|m| bit(key, m))
}

/// Position bits, most significant of 40 first, in a key-bit register.
fn position_bits(position: u64) -> [bool; KEY_BITS] {
    core::array::from_fn(|m| m < DEPTH && (position >> (DEPTH - 1 - m)) & 1 == 1)
}

fn ordered(child: &Digest, sibling: &Digest, right: bool) -> [Fp; WIDTH] {
    let mut input = [Fp::ZERO; WIDTH];
    let (a, c) = if right { (sibling, child) } else { (child, sibling) };
    input[..DIGEST].copy_from_slice(a);
    input[DIGEST..].copy_from_slice(c);
    input
}

/// A walk's levels, top down: direction and sibling.
struct Levels {
    dirs: Vec<bool>,
    sibs: Vec<Digest>,
}

impl Levels {
    fn output(position: u64, path: &OutputPath) -> Levels {
        Levels {
            dirs: (0..DEPTH).map(|lv| (position >> (DEPTH - 1 - lv)) & 1 == 1).collect(),
            sibs: path.iter().rev().copied().collect(),
        }
    }

    fn trie(key: Key, t: &TriePath) -> Levels {
        let d = t.proof.depth();
        let mut dirs = vec![true];
        let mut sibs = vec![t.left];
        for depth in 0..d {
            dirs.push(bit(key, depth));
            sibs.push(t.proof.siblings[d - 1 - depth]);
        }
        Levels { dirs, sibs }
    }

    /// The nodes from the terminal up to the root: `nodes[0]` is the root.
    fn nodes(&self, terminal: &Digest) -> Vec<Digest> {
        let n = self.dirs.len();
        let mut nodes = vec![*terminal; n + 1];
        for lv in (0..n).rev() {
            let (child, sib) = (nodes[lv + 1], self.sibs[lv]);
            nodes[lv] = if self.dirs[lv] { compress(&sib, &child) } else { compress(&child, &sib) };
        }
        nodes
    }
}

struct Gen {
    b: HashTraceBuilder,
    r: Regs,
    height: u32,
}

impl Gen {
    fn finish(&mut self, ty: usize, idx: usize) {
        let row = self.b.last_row_mut();
        row[ty] = Fp::ONE;
        row[C_IDX + idx] = Fp::ONE;
        self.r.write(row);
        let exit = match ty {
            T_OPD => idx == if self.r.kind == KIND_COMMIT { 2 } else { 1 },
            t => PHASES.iter().find(|(p, _)| *p == t).is_none_or(|(_, len)| idx == len - 1),
        };
        row[C_EXIT] = Fp::new(exit as u32);
        row[C_ADV] = Fp::new((ty == T_NLIST && self.r.kind == KIND_COMMIT) as u32);
    }

    fn pass(&mut self, ty: usize) {
        self.b.pass();
        self.finish(ty, 0);
    }

    /// Starts a domain hash with `block0`.
    fn start(&mut self, ty: usize, domain: u32, len: u32, block0: [Fp; RATE]) {
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&block0);
        input[RATE..].copy_from_slice(&cap_const::<Fp>(domain, len));
        self.b.start(input);
        self.finish(ty, 0);
    }

    fn absorb(&mut self, ty: usize, idx: usize, block: [Fp; RATE]) {
        self.b.absorb(block);
        self.finish(ty, idx);
    }

    /// A record hash: `H(DOM_RECORD, name hash, owner, value, memo)`.
    fn record(&mut self, ty: usize, nameh: &Digest, r: &Record) -> Digest {
        self.start(ty, names::DOM_RECORD, 4 * DIGEST as u32, *nameh);
        self.absorb(ty, 1, r.owner);
        self.absorb(ty, 2, r.value);
        self.absorb(ty, 3, r.memo);
        self.b.acc()
    }

    /// A trie leaf hash from a bit register and a record leaf value.
    fn trie_leaf(&mut self, ty: usize, bits: &[bool; KEY_BITS], value: &Digest) -> Digest {
        let mut block0 = [Fp::ZERO; RATE];
        for i in 0..4 {
            let limb = (0..30).fold(0u32, |a, m| a | (bits[30 * i + m] as u32) << (29 - m));
            block0[i] = Fp::new(limb);
        }
        block0[4..].copy_from_slice(&value[..4]);
        let mut block1 = [Fp::ZERO; RATE];
        block1[..4].copy_from_slice(&value[4..]);
        self.start(ty, name_trie::DOM_LEAF, 12, block0);
        self.absorb(ty, 1, block1);
        self.b.acc()
    }

    /// The commit leaf rows: `cleaf(2)`, `leafc`, `leafc2`.
    fn commit_leaf_rows(&mut self) {
        self.start(T_CLEAF, names::DOM_COMMIT_LEAF, DIGEST as u32 + 1, self.r.c);
        let mut block1 = [Fp::ZERO; RATE];
        block1[0] = Fp::new(self.r.ch);
        self.absorb(T_CLEAF, 1, block1);
        let mut input = [Fp::ZERO; WIDTH];
        input[..DIGEST].copy_from_slice(&self.b.acc());
        input[DIGEST..].copy_from_slice(&self.r.cmemo);
        self.b.start(input);
        self.finish(T_LEAFC, 0);
        let mut input = [Fp::ZERO; WIDTH];
        input[..DIGEST].copy_from_slice(&self.b.acc());
        input[DIGEST..].copy_from_slice(&crate::transaction::height_digest(self.r.ch));
        self.b.start(input);
        self.finish(T_LEAFC2, 0);
        self.r.cleaf = self.b.acc();
        debug_assert_eq!(
            self.r.cleaf,
            crate::transaction::leaf(&commit_leaf(&self.r.c, self.r.ch), &self.r.cmemo, self.r.ch)
        );
    }

    /// A window (or expiry) row: `value` must be non-negative.
    fn window_row(&mut self, ty: usize, value: i64) {
        assert!((0..1 << 31).contains(&value), "commit age out of range");
        self.b.pass();
        let row = self.b.last_row_mut();
        xmss_fragment::write_bits(row, &XCOLS, value as u32, self.r.xmss.ksel);
        self.finish(ty, 0);
    }

    /// The name rows: four blocks of elements with their charset columns.
    fn name_rows(&mut self, elements: &[Fp; NAME_MAX]) -> Digest {
        for k in 0..4 {
            let block: [Fp; RATE] = elements[RATE * k..RATE * (k + 1)].try_into().unwrap();
            if k == 0 {
                let mut input = [Fp::ZERO; WIDTH];
                input[..RATE].copy_from_slice(&block);
                input[RATE..].copy_from_slice(&cap_const::<Fp>(names::DOM_NAME, NAME_MAX as u32));
                self.b.start(input);
                self.b.last_row_mut()[COL_DATA..COL_DATA + RATE].copy_from_slice(&block);
            } else {
                self.b.absorb(block);
            }
            self.finish(T_NAME, k);
            let row = self.b.last_row_mut();
            for i in 0..RATE {
                let v = block[i].to_canonical();
                assert!(v <= names::CHAR_MAX, "name element out of range");
                for bit in 0..CHAR_BITS {
                    row[C_CB + CHAR_BITS * i + bit] = Fp::new((v >> bit) & 1);
                }
                row[C_LIVE + i] = Fp::new((v != 0) as u32);
                row[C_LIVE_INV + i] = inv_or_zero(block[i]);
            }
        }
        self.b.acc()
    }

    /// The key rows: the name hash's elements into the key register.
    fn key_rows(&mut self, nameh: &Digest) {
        let key = key_of(nameh);
        let bits = key_bits(key);
        for i in 0..4 {
            self.b.pass();
            let row = self.b.last_row_mut();
            xmss_fragment::write_bits(row, &XCOLS, nameh[i].to_canonical(), self.r.xmss.ksel);
            self.finish(T_KEY, i);
            self.r.kb[30 * i..30 * (i + 1)].copy_from_slice(&bits[30 * i..30 * (i + 1)]);
        }
    }

    /// A walk: the load row, the levels, the terminal row. `wk` is the
    /// walk kind the rows after the load carry.
    fn walk(&mut self, load: usize, wk: usize, levels: &Levels, old_terminal: &Digest, new_terminal: &Digest) {
        self.pass_then(|_| {}, load, wk, levels, old_terminal, new_terminal);
    }

    fn shift_keys(&mut self) {
        self.r.kb.copy_within(1.., 0);
        self.r.kb[KEY_BITS - 1] = false;
        self.r.kb2.copy_within(1.., 0);
        self.r.kb2[KEY_BITS - 1] = false;
    }

    /// An output walk at `position` from the current root.
    fn output_walk(&mut self, position: u64, path: &OutputPath, old_terminal: &Digest, new_terminal: &Digest) {
        let wk = match self.r.kind {
            KIND_COMMIT => WK_COMMIT,
            KIND_REVEAL => WK_RDEL,
            _ => WK_SWEEP,
        };
        let levels = Levels::output(position, path);
        // The position bits load with the walk; the load row still shows
        // the register as it was.
        let saved = self.r.kb;
        self.r.kb = position_bits(position);
        let bits = self.r.kb;
        self.r.kb = saved;
        self.pass_then(|g| g.r.kb = bits, T_PLOAD, wk, &levels, old_terminal, new_terminal);
    }

    /// As [`Gen::walk`], applying `after_load` to the registers after the
    /// load row is written.
    fn pass_then(
        &mut self,
        after_load: impl FnOnce(&mut Gen),
        load: usize,
        wk: usize,
        levels: &Levels,
        old_terminal: &Digest,
        new_terminal: &Digest,
    ) {
        let old = levels.nodes(old_terminal);
        let new = levels.nodes(new_terminal);
        assert_eq!(old[0], self.r.root, "old path does not reach the current root");
        self.pass(load);
        after_load(self);
        self.r.wk = wk;
        self.r.level = 0;
        self.r.wlen = levels.dirs.len() as u32;
        self.r.onode = old[0];
        self.r.nnode = new[0];
        self.r.root = new[0];
        for lv in 0..levels.dirs.len() {
            let (right, sib) = (levels.dirs[lv], levels.sibs[lv]);
            self.r.xmss.sib = sib;
            self.b.start(ordered(&old[lv + 1], &sib, right));
            self.b.last_row_mut()[COL_DIR] = Fp::new(right as u32);
            self.finish(T_WOLD, 0);
            self.r.onode = old[lv + 1];
            self.b.start(ordered(&new[lv + 1], &sib, right));
            self.b.last_row_mut()[COL_DIR] = Fp::new(right as u32);
            self.finish(T_WNEW, 0);
            self.r.nnode = new[lv + 1];
            self.r.level += 1;
            let top = load == T_TLOAD && lv == 0;
            if !top {
                self.shift_keys();
            }
        }
        self.pass(T_TERM);
    }

    /// The operation digest rows and the list row.
    fn digest_rows(&mut self, op: &BlockNameOp) {
        let kind = self.r.kind;
        let is_commit = kind == KIND_COMMIT;
        let len = if is_commit { 3 * DIGEST } else { 2 * DIGEST } as u32;
        let tag = match kind {
            KIND_COMMIT => names::TAG_COMMIT,
            KIND_REVEAL => names::TAG_REVEAL,
            _ => names::TAG_UPDATE,
        };
        let mut block0 = [Fp::ZERO; RATE];
        block0[0] = Fp::new(tag as u32);
        self.start(T_OPD, names::DOM_OP, len, block0);
        self.absorb(T_OPD, 1, self.r.opx);
        if is_commit {
            self.absorb(T_OPD, 2, self.r.cmemo);
        }
        let digest = self.b.acc();
        assert_eq!(Some(digest), op.digest(), "operation digest does not match the block's");
        let mut input = self.r.nsp;
        for (s, x) in input.iter_mut().zip(&digest) {
            *s = s.add(x);
        }
        self.b.start(input);
        self.finish(T_NLIST, 0);
        self.r.nsp = self.b.state();
        if is_commit {
            self.r.pos += 1;
        }
    }

    fn op(&mut self, w: &OpWitness) {
        let height = self.height;
        match w {
            OpWitness::Commit { commit, memo, path } => {
                let r = &mut self.r;
                r.kind = KIND_COMMIT;
                r.c = *commit;
                r.cmemo = *memo;
                r.ch = height;
                r.wpos = r.pos;
                self.pass(T_OP);
                self.r.cnt[KIND_COMMIT] += 1;
                self.commit_leaf_rows();
                let (position, cleaf) = (self.r.wpos, self.r.cleaf);
                self.output_walk(position, path, &EMPTY, &cleaf);
                self.r.opx = self.r.c;
                self.digest_rows(&BlockNameOp::Commit { commit: *commit, memo: memo_of(memo) });
            }
            OpWitness::Sweep { commit, memo, height: ch, position, path } => {
                let r = &mut self.r;
                r.kind = KIND_SWEEP;
                r.c = *commit;
                r.cmemo = *memo;
                r.ch = *ch;
                r.wpos = *position;
                self.pass(T_OP);
                self.r.cnt[KIND_SWEEP] += 1;
                self.commit_leaf_rows();
                self.window_row(T_WIN, height as i64 - *ch as i64 - MAX_REVEAL as i64 - 1);
                let cleaf = self.r.cleaf;
                self.output_walk(*position, path, &cleaf, &EMPTY);
                let mut input = self.r.ssp;
                input[0] = input[0].add(&Fp::new((*position & MASK30) as u32));
                input[1] = input[1].add(&Fp::new((*position >> 30) as u32));
                self.b.start(input);
                self.finish(T_SLIST, 0);
                self.r.ssp = self.b.state();
            }
            OpWitness::Reveal { record, salt, other, trie, commit_height, commit_memo, commit_position, path } => {
                let elements = record.elements().expect("a well-formed name");
                let nh = name_hash(&elements);
                let key = key_of(&nh);
                let (other_key, other_value) = match trie.proof.terminal {
                    Terminal::Leaf { key, value } => (key, value),
                    Terminal::Empty => (0, EMPTY),
                };
                let other_rec =
                    other.clone().unwrap_or(Record { name: vec![], owner: EMPTY, value: EMPTY, memo: EMPTY });
                let r = &mut self.r;
                r.kind = KIND_REVEAL;
                r.owner = record.owner;
                r.owner2 = other_rec.owner;
                r.cmemo = *commit_memo;
                r.ch = *commit_height;
                r.wpos = *commit_position;
                r.kb2 = key_bits(other_key);
                r.val2 = other_value;
                self.pass(T_OP);
                self.r.cnt[KIND_REVEAL] += 1;
                self.r.nameh = self.name_rows(&elements);
                debug_assert_eq!(self.r.nameh, nh);
                self.key_rows(&nh);
                // rec2: the colliding record (garbage for an empty terminal)
                let other_nh = other.as_ref().map(|o| name_hash(&o.elements().unwrap())).unwrap_or(EMPTY);
                self.r.val2 = self.record(T_REC2, &other_nh, &other_rec);
                if other.is_some() {
                    assert_eq!(self.r.val2, other_value, "colliding record does not match its leaf");
                }
                self.r.val = self.record(T_REC, &nh, record);
                let (kb, kb2, val, val2) = (self.r.kb, self.r.kb2, self.r.val, self.r.val2);
                self.r.leaf = self.trie_leaf(T_TLEAF, &kb, &val);
                debug_assert_eq!(self.r.leaf, leaf_hash(key, &val));
                self.r.oleaf = self.trie_leaf(T_TLEAF2, &kb2, &val2);
                // the trie walk
                let d = trie.proof.depth();
                let levels = Levels::trie(key, trie);
                let new_leaf = self.r.leaf;
                let (wk, old_terminal, new_terminal, split) = match trie.proof.terminal {
                    Terminal::Empty => {
                        let old = if d == 0 { empty_root() } else { EMPTY };
                        (WK_REMPTY, old, new_leaf, None)
                    }
                    Terminal::Leaf { .. } => {
                        let old_leaf = self.r.oleaf;
                        let j = first_difference(key, other_key);
                        assert!(j >= d, "the colliding key shares the prefix");
                        // chain[t] for t in d..=j
                        let mut chain = vec![EMPTY; j - d + 1];
                        chain[j - d] =
                            if bit(key, j) { compress(&old_leaf, &new_leaf) } else { compress(&new_leaf, &old_leaf) };
                        for t in (d..j).rev() {
                            let child = chain[t + 1 - d];
                            chain[t - d] =
                                if bit(key, t) { compress(&EMPTY, &child) } else { compress(&child, &EMPTY) };
                        }
                        (WK_RSPLIT, old_leaf, chain[0], Some(chain))
                    }
                };
                self.walk(T_TLOAD, wk, &levels, &old_terminal, &new_terminal);
                if let Some(chain) = split {
                    let j = d + chain.len() - 1;
                    for t in d..=j {
                        let right = bit(key, t);
                        let (child, sib) = if t < j { (chain[t + 1 - d], EMPTY) } else { (new_leaf, self.r.oleaf) };
                        self.r.xmss.sib = sib;
                        self.b.start(ordered(&child, &sib, right));
                        self.b.last_row_mut()[COL_DIR] = Fp::new(right as u32);
                        self.finish(T_SPLIT, 0);
                        self.r.nnode = child;
                        self.r.level += 1;
                        self.shift_keys();
                    }
                }
                // the commit
                self.start(T_COMMIT, names::DOM_COMMIT, 3 * DIGEST as u32, nh);
                self.absorb(T_COMMIT, 1, *salt);
                self.absorb(T_COMMIT, 2, record.owner);
                self.r.c = self.b.acc();
                debug_assert_eq!(self.r.c, commit_hash(&nh, salt, &record.owner));
                self.commit_leaf_rows();
                self.window_row(T_WIN, height as i64 - *commit_height as i64 - MIN_REVEAL as i64);
                self.window_row(T_WIN2, *commit_height as i64 + MAX_REVEAL as i64 - height as i64);
                let cleaf = self.r.cleaf;
                self.output_walk(*commit_position, path, &cleaf, &EMPTY);
                self.r.opx = self.r.val;
                self.digest_rows(&BlockNameOp::Reveal { record: record.clone(), commit: *commit_position });
            }
            OpWitness::Update { old, new, pubkey, signature, trie } => {
                let elements = new.elements().expect("a well-formed name");
                let nh = name_hash(&elements);
                let key = key_of(&nh);
                assert_eq!(old.name, new.name, "an update keeps the name");
                let r = &mut self.r;
                r.kind = KIND_UPDATE;
                r.owner = new.owner;
                r.owner2 = old.owner;
                r.kb2 = key_bits(key);
                self.pass(T_OP);
                self.r.cnt[KIND_UPDATE] += 1;
                self.r.nameh = self.name_rows(&elements);
                self.key_rows(&nh);
                self.r.val2 = self.record(T_REC2, &nh, old);
                self.r.val = self.record(T_REC, &nh, new);
                let (kb, kb2, val, val2) = (self.r.kb, self.r.kb2, self.r.val, self.r.val2);
                self.r.leaf = self.trie_leaf(T_TLEAF, &kb, &val);
                self.r.oleaf = self.trie_leaf(T_TLEAF2, &kb2, &val2);
                match trie.proof.terminal {
                    Terminal::Leaf { key: k, value } if k == key && value == val2 => {}
                    _ => panic!("update of a name whose leaf is not the current record"),
                }
                let levels = Levels::trie(key, trie);
                let (old_leaf, new_leaf) = (self.r.oleaf, self.r.leaf);
                self.walk(T_TLOAD, WK_UPDATE, &levels, &old_leaf, &new_leaf);
                // the owner's signature over the update message
                self.start(T_UMSG, names::DOM_UPDATE, DIGEST as u32, val);
                self.r.msg = self.b.acc();
                debug_assert_eq!(Some(self.r.msg), names::update_message(new));
                let msg = self.r.msg;
                let mut xr = self.r.xmss.clone();
                let regs = &self.r;
                let root = xmss_fragment::generate(
                    &mut self.b,
                    &mut xr,
                    &XCOLS,
                    &XTYPES,
                    &msg,
                    signature,
                    pubkey,
                    &mut |row, _| {
                        regs.write_rest(row);
                        row[C_IDX] = Fp::ONE;
                        row[C_EXIT] = Fp::ONE;
                    },
                );
                self.r.xmss = xr;
                let mut input = [Fp::ZERO; WIDTH];
                input[..RATE].copy_from_slice(&root);
                input[RATE..].copy_from_slice(&cap_const::<Fp>(DOM_PUBKEY, (DIGEST + PUB_SEED_LEN + 1) as u32));
                self.b.start(input);
                self.finish(T_PKH0, 0);
                let mut seed_block = [Fp::ZERO; RATE];
                seed_block[..PUB_SEED_LEN].copy_from_slice(&pubkey.pub_seed);
                seed_block[PUB_SEED_LEN] = Fp::new(pubkey.height as u32);
                self.absorb(T_PKH1, 0, seed_block);
                assert_eq!(self.b.acc(), old.owner, "the signer is not the current owner");
                assert_ne!(new.owner, old.owner, "an update must change the owner");
                self.r.opx = self.r.val;
                self.digest_rows(&BlockNameOp::Update(new.clone()));
            }
        }
    }
}

impl NameAir {
    /// Builds the trace for `w`; returns it with the segment's public
    /// statement. Panics if the witness is inconsistent.
    pub fn generate_trace(w: &NameWitness) -> (Trace, NamePublic) {
        Self::generate_trace_with(w, 2)
    }

    /// Trace padded to exactly `2^log_n` rows; panics if the witness needs
    /// more.
    pub fn generate_trace_padded(w: &NameWitness, log_n: usize) -> (Trace, NamePublic) {
        assert!(w.num_rows() < 1 << log_n, "name segment of {} rows does not fit 2^{log_n}", w.num_rows());
        Self::generate_trace_with(w, 1 << log_n)
    }

    fn generate_trace_with(w: &NameWitness, min_rows: usize) -> (Trace, NamePublic) {
        let regs = Regs {
            xmss: xmss_fragment::Regs::default(),
            kind: KIND_COMMIT,
            wk: WK_COMMIT,
            cnt: [0; 4],
            level: 0,
            wlen: 0,
            root: w.root_in,
            onode: EMPTY,
            nnode: EMPTY,
            kb: [false; KEY_BITS],
            kb2: [false; KEY_BITS],
            nameh: EMPTY,
            owner: EMPTY,
            owner2: EMPTY,
            val: EMPTY,
            val2: EMPTY,
            leaf: EMPTY,
            oleaf: EMPTY,
            c: EMPTY,
            cmemo: EMPTY,
            ch: 0,
            cleaf: EMPTY,
            msg: EMPTY,
            opx: EMPTY,
            nsp: initial_names_state(),
            ssp: initial_sweeps_state(),
            pos: w.pos_in,
            wpos: 0,
        };
        let mut g = Gen { b: HashTraceBuilder::new(NUM_COLS), r: regs, height: w.height };
        for op in &w.ops {
            g.op(op);
        }
        let public = NamePublic {
            root_in: w.root_in,
            root_out: g.r.root,
            pos_in: w.pos_in,
            pos_out: g.r.pos,
            nsp: g.r.nsp,
            ssp: g.r.ssp,
            height: w.height,
            counts: g.r.cnt,
        };
        let n = (g.b.len() + 1).max(min_rows).next_power_of_two();
        while g.b.len() < n {
            g.pass(T_DONE);
        }
        (g.b.finish(), public)
    }
}

/// Native check of what the segment exports for a block: the operations
/// sponge over the digests and the sweeps sponge over the positions.
pub fn expected_states(digests: &[Digest], sweeps: &[u64]) -> ([Fp; WIDTH], [Fp; WIDTH]) {
    let mut nsp = initial_names_state();
    for d in digests {
        absorb_op(&mut nsp, d);
    }
    let mut ssp = initial_sweeps_state();
    for &p in sweeps {
        absorb_sweep(&mut ssp, p);
    }
    (nsp, ssp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_air::{names_state, sweeps_state};
    use crate::stark::{check_constraints, measure_degree};
    use crate::state_tree::open_env;
    use crate::transaction::{Key as OwnerKey, pubkey_hash};
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let p = std::env::temp_dir().join(format!("tabminer-name-air-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn d(n: u32) -> Digest {
        core::array::from_fn(|i| Fp::new(n * 1000 + i as u32 * 7 + 1))
    }

    fn owner_key(tag: u8) -> OwnerKey {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        seed[1] = 0xaa;
        OwnerKey::generate(&seed)
    }

    /// A name whose key shares its first bits with `with`'s, found by
    /// trying suffixes.
    fn colliding_name(with: &[u8], bits: usize) -> Vec<u8> {
        let k = names::name_key(with).unwrap();
        for i in 0u32.. {
            let name = format!("x{i}").into_bytes();
            let k2 = names::name_key(&name).unwrap();
            if k2 != k && first_difference(k, k2) >= bits {
                return name;
            }
        }
        unreachable!()
    }

    struct World {
        _dir: TempDir,
        env: heed::Env,
        utxo: UtxoSet,
        names: NameSet,
    }

    fn world(name: &str) -> World {
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 256 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let names = NameSet::open(&env, &mut wtxn, "n").unwrap();
        // A few outputs so positions are not trivial.
        for i in 0..5 {
            utxo.add(&mut wtxn, &d(100 + i)).unwrap();
        }
        wtxn.commit().unwrap();
        World { _dir: dir, env, utxo, names }
    }

    /// Applies a block's name section, checks the segment's constraints
    /// and that its exports match the block, and returns the public values.
    fn block(w: &World, height: u32, ops: &[NameOp], sweeps: &[u64]) -> NamePublic {
        let mut wtxn = w.env.write_txn().unwrap();
        let witness = NameWitness::collect(&w.utxo, &w.names, &mut wtxn, height, ops, sweeps).unwrap();
        let root_out = w.utxo.root(&wtxn).unwrap();
        let pos_out = w.utxo.next_position(&wtxn).unwrap();
        wtxn.commit().unwrap();
        let (trace, public) = NameAir::generate_trace(&witness);
        assert_eq!(witness.num_rows(), trace.height() - (trace.height() - witness.num_rows()));
        let values = public.to_values();
        assert_eq!(NamePublic::from_values(&values), Some(public));
        assert_eq!(check_constraints(&NameAir, &trace, &values), Ok(()), "height {height}");
        assert_eq!(public.root_out, root_out);
        assert_eq!(public.pos_out, pos_out);
        let digests: Vec<Digest> = ops.iter().map(|o| o.digest().unwrap()).collect();
        assert_eq!(public.nsp, names_state(&digests));
        assert_eq!(public.ssp, sweeps_state(sweeps));
        assert_eq!(witness.op_digests(), digests);
        assert_eq!(witness.sweeps(), sweeps);
        // Every public value matters (the height only once an operation
        // uses it).
        for i in [
            PUB_ROOT_IN,
            PUB_ROOT_OUT + 2,
            PUB_POS_IN,
            PUB_POS_OUT,
            PUB_NSP + 3,
            PUB_SSP + 9,
            PUB_HEIGHT,
            PUB_COUNTS + 1,
        ] {
            if i == PUB_HEIGHT && ops.is_empty() {
                continue;
            }
            let mut bad = values.clone();
            bad[i] += Fp::ONE;
            assert!(check_constraints(&NameAir, &trace, &bad).is_err(), "public {i} at height {height}");
        }
        public
    }

    #[test]
    fn layout_and_degree() {
        assert_eq!(measure_degree(&NameAir, NUM_PUBLIC), 3);
        assert_eq!(NUM_PUBLIC, 57);
        println!("name segment: {NUM_COLS} columns");
    }

    #[test]
    fn empty_segment_keeps_the_state() {
        let w = world("empty");
        let p = block(&w, 7, &[], &[]);
        assert_eq!(p.root_in, p.root_out);
        assert_eq!(p.counts, [0; 4]);
    }

    #[test]
    fn commits_reveals_updates_and_sweeps() {
        let w = world("all");
        let mut k1 = owner_key(1);
        let o1 = pubkey_hash(&k1.public_key());
        let k2 = owner_key(2);
        let o2 = pubkey_hash(&k2.public_key());
        let mut k3 = owner_key(3);
        let o3 = pubkey_hash(&k3.public_key());
        let alice = Record::new(b"alice", o1, d(11), d(12)).unwrap();
        let bob_name = colliding_name(b"alice", 3);
        let bob = Record::new(&bob_name, o2, d(21), d(22)).unwrap();
        let carol = Record::new(b"carol_9", o3, d(31), d(32)).unwrap();
        let salt = |n: u32| d(500 + n);
        let commit_of = |r: &Record, s: &Digest| commit_hash(&name_hash(&r.elements().unwrap()), s, &r.owner);

        // Block 10: three commits.
        let commits = vec![
            NameOp::Commit { commit: commit_of(&alice, &salt(1)), memo: crate::transaction::memo5(d(41)) },
            NameOp::Commit { commit: commit_of(&bob, &salt(2)), memo: crate::transaction::memo5(d(42)) },
            NameOp::Commit { commit: commit_of(&carol, &salt(3)), memo: crate::transaction::memo5(d(43)) },
        ];
        let p = block(&w, 10, &commits, &[]);
        assert_eq!(p.counts, [3, 0, 0, 0]);
        assert_eq!((p.pos_in, p.pos_out), (5, 8));

        // Block 22: reveal alice (empty trie) and bob (a split under
        // alice's leaf: the keys share at least three bits).
        let reveals = vec![
            NameOp::Reveal { record: alice.clone(), salt: salt(1), commit: 5 },
            NameOp::Reveal { record: bob.clone(), salt: salt(2), commit: 6 },
        ];
        let p = block(&w, 22, &reveals, &[]);
        assert_eq!(p.counts, [0, 2, 0, 0]);
        assert_eq!((p.pos_in, p.pos_out), (8, 8));
        {
            let rtxn = w.env.read_txn().unwrap();
            assert_eq!(w.names.lookup(&rtxn, b"alice").unwrap(), Some(alice.clone()));
            assert_eq!(w.names.lookup(&rtxn, &bob_name).unwrap(), Some(bob.clone()));
            assert_eq!(w.names.len(&rtxn).unwrap(), 2);
            assert!(w.names.prove(&rtxn, &bob_name).unwrap().depth() >= 4);
            // The commits are gone from the UTXO set; carol's remains.
            assert!(w.utxo.output_at(&rtxn, 5).unwrap().is_none());
            assert!(w.utxo.output_at(&rtxn, 6).unwrap().is_none());
            assert!(w.utxo.output_at(&rtxn, 7).unwrap().is_some());
        }

        // Block 23: alice rotates her key, a commit in the same block.
        let mut k4 = owner_key(4);
        let o4 = pubkey_hash(&k4.public_key());
        let alice2 = Record::new(b"alice", o4, d(13), d(14)).unwrap();
        let update = NameOp::update(alice2.clone(), &mut k1).unwrap();
        let ops = vec![update, NameOp::Commit { commit: d(77), memo: crate::transaction::memo5(d(78)) }];
        let p = block(&w, 23, &ops, &[]);
        assert_eq!(p.counts, [1, 0, 1, 0]);
        assert_eq!((p.pos_in, p.pos_out), (8, 9));
        {
            let rtxn = w.env.read_txn().unwrap();
            assert_eq!(w.names.lookup(&rtxn, b"alice").unwrap(), Some(alice2.clone()));
        }

        // Block 300: carol's commit (height 10) has expired: sweep it, and
        // alice transfers to k3's hash... wait, that is an update by k4.
        let alice3 = Record::new(b"alice", o3, d(15), d(16)).unwrap();
        let transfer = NameOp::update(alice3.clone(), &mut k4).unwrap();
        let p = block(&w, 300, &[transfer], &[7]);
        assert_eq!(p.counts, [0, 0, 1, 1]);
        {
            let rtxn = w.env.read_txn().unwrap();
            assert!(w.utxo.output_at(&rtxn, 7).unwrap().is_none());
            assert!(w.names.commit_at(&rtxn, 7).unwrap().is_none());
            assert_eq!(w.names.lookup(&rtxn, b"alice").unwrap(), Some(alice3.clone()));
        }

        // Block 301: carol's reveal now fails (no commit); a reveal of a
        // registered name fails; an update by a stale key fails; a sweep
        // of a live commit fails; an update keeping the owner fails.
        let mut wtxn = w.env.write_txn().unwrap();
        let fail = |wtxn: &mut heed::RwTxn, ops: &[NameOp], sweeps: &[u64]| {
            NameWitness::collect(&w.utxo, &w.names, wtxn, 301, ops, sweeps).expect_err("rejected")
        };
        assert!(matches!(
            fail(&mut wtxn, &[NameOp::Reveal { record: carol.clone(), salt: salt(3), commit: 7 }], &[]),
            ApplyError::NoCommit
        ));
        assert!(matches!(
            fail(&mut wtxn, &[NameOp::Reveal { record: alice.clone(), salt: salt(1), commit: 5 }], &[]),
            ApplyError::NoCommit
        ));
        let stale = NameOp::update(Record::new(b"alice", o2, d(1), d(2)).unwrap(), &mut k1).unwrap();
        assert!(matches!(fail(&mut wtxn, &[stale], &[]), ApplyError::BadOwner));
        let same = NameOp::update(Record::new(b"alice", o3, d(1), d(2)).unwrap(), &mut k3).unwrap();
        assert!(matches!(fail(&mut wtxn, &[same], &[]), ApplyError::BadOwner));
        assert!(matches!(fail(&mut wtxn, &[], &[8]), ApplyError::NotExpired(23)));
        assert!(matches!(fail(&mut wtxn, &[], &[3]), ApplyError::NoCommit));
        let unknown = NameOp::update(Record::new(b"nobody", o2, d(1), d(2)).unwrap(), &mut k3).unwrap();
        assert!(matches!(fail(&mut wtxn, &[unknown], &[]), ApplyError::NotRegistered));
        // A commit revealed too early or too late.
        let late = Record::new(b"late", o2, d(1), d(2)).unwrap();
        let ops = [NameOp::Commit { commit: commit_of(&late, &salt(9)), memo: crate::transaction::memo5(d(1)) }];
        NameWitness::collect(&w.utxo, &w.names, &mut wtxn, 301, &ops, &[]).unwrap();
        let reveal = [NameOp::Reveal { record: late.clone(), salt: salt(9), commit: 9 }];
        assert!(matches!(
            NameWitness::collect(&w.utxo, &w.names, &mut wtxn, 301 + MIN_REVEAL - 1, &reveal, &[]).err().unwrap(),
            ApplyError::Window(301)
        ));
        assert!(matches!(
            NameWitness::collect(&w.utxo, &w.names, &mut wtxn, 301 + MAX_REVEAL + 1, &reveal, &[]).err().unwrap(),
            ApplyError::Window(301)
        ));
        NameWitness::collect(&w.utxo, &w.names, &mut wtxn, 301 + MAX_REVEAL, &reveal, &[]).unwrap();
        // Re-registering a revealed name: the trie has it.
        let again = [NameOp::Commit { commit: commit_of(&late, &salt(10)), memo: crate::transaction::memo5(d(1)) }];
        NameWitness::collect(&w.utxo, &w.names, &mut wtxn, 600, &again, &[]).unwrap();
        let reveal = [NameOp::Reveal { record: late.clone(), salt: salt(10), commit: 10 }];
        assert!(matches!(
            NameWitness::collect(&w.utxo, &w.names, &mut wtxn, 620, &reveal, &[]).err().unwrap(),
            ApplyError::Registered
        ));
        wtxn.abort();
        // Beyond the caps.
        let mut wtxn = w.env.write_txn().unwrap();
        let many: Vec<NameOp> = (0..names::MAX_COMMITS as u32 + 1)
            .map(|i| NameOp::Commit { commit: d(900 + i), memo: crate::transaction::memo5(d(1)) })
            .collect();
        assert!(matches!(fail(&mut wtxn, &many, &[]), ApplyError::TooMany(names::OpKind::Commit)));
        wtxn.abort();
        let _ = (k2, o1);
    }

    /// The name segment at mainnet parameters: an empty one (every block
    /// pays this) and one with every kind of operation, proven and
    /// verified.
    #[test]
    #[ignore = "proves mainnet name segments; run with --release"]
    fn mainnet_name_segment_timing() {
        use crate::aggregate::AggregatorParams;
        use crate::block_proof::{name_transcript, prove_name_padded};
        let params = AggregatorParams::MAINNET;
        let w = world("timing");
        let mut k1 = owner_key(1);
        let o1 = pubkey_hash(&k1.public_key());
        let o2 = pubkey_hash(&owner_key(2).public_key());
        let alice = Record::new(b"alice", o1, d(11), d(12)).unwrap();
        let salt = d(500);
        let c = commit_hash(&name_hash(&alice.elements().unwrap()), &salt, &o1);
        let empty = NameWitness {
            root_in: w.utxo.root(&w.env.read_txn().unwrap()).unwrap(),
            pos_in: 5,
            height: 1,
            ops: vec![],
        };
        block(
            &w,
            1,
            &[
                NameOp::Commit { commit: c, memo: crate::transaction::memo5(d(1)) },
                NameOp::Commit { commit: d(2), memo: crate::transaction::memo5(d(3)) },
            ],
            &[],
        );
        block(&w, 13, &[NameOp::Reveal { record: alice.clone(), salt, commit: 5 }], &[]);
        let alice2 = Record::new(b"alice", o2, d(13), d(14)).unwrap();
        let ops = [
            NameOp::update(alice2, &mut k1).unwrap(),
            NameOp::Commit { commit: d(4), memo: crate::transaction::memo5(d(5)) },
        ];
        let mut wtxn = w.env.write_txn().unwrap();
        let full = NameWitness::collect(&w.utxo, &w.names, &mut wtxn, 400, &ops, &[6]).unwrap();
        wtxn.abort();
        for (name, witness) in [("empty", &empty), ("update, commit and sweep", &full)] {
            let t = std::time::Instant::now();
            let p = prove_name_padded(&params.segment, witness, params.name_log_n);
            let proved = t.elapsed();
            let t = std::time::Instant::now();
            let ok = crate::stark::verify(
                &params.segment,
                &NameAir,
                &p.public.to_values(),
                &p.proof,
                &mut name_transcript(),
            );
            println!(
                "name segment ({name}, {} rows used of 2^{}): proven in {proved:?}, {} bytes, verified {ok:?} in {:?}",
                witness.num_rows(),
                params.name_log_n,
                p.proof.to_bytes().len(),
                t.elapsed()
            );
            assert_eq!(ok, Ok(()));
        }
    }

    #[test]
    fn forged_traces_fail() {
        let w = world("forge");
        let k1 = owner_key(1);
        let o1 = pubkey_hash(&k1.public_key());
        let alice = Record::new(b"alice", o1, d(11), d(12)).unwrap();
        let c = commit_hash(&name_hash(&alice.elements().unwrap()), &d(5), &o1);
        block(&w, 10, &[NameOp::Commit { commit: c, memo: crate::transaction::memo5(d(41)) }], &[]);
        let mut wtxn = w.env.write_txn().unwrap();
        let ops = [NameOp::Reveal { record: alice.clone(), salt: d(5), commit: 5 }];
        let witness = NameWitness::collect(&w.utxo, &w.names, &mut wtxn, 30, &ops, &[]).unwrap();
        wtxn.abort();
        let (trace, public) = NameAir::generate_trace(&witness);
        let values = public.to_values();
        assert_eq!(check_constraints(&NameAir, &trace, &values), Ok(()));
        let width = NUM_COLS;
        let find = |ty: usize, nth: usize| {
            (0..trace.height()).filter(|&r| trace.values[r * width + ty] == Fp::ONE).nth(nth).unwrap()
        };
        // A name element out of the charset (38) on the first name row.
        let mut bad = trace.clone();
        let r = find(T_NAME, 0);
        bad.values[r * width + COL_DATA + 1] = Fp::new(38);
        bad.values[r * width + COL_INPUT + 1] = Fp::new(38);
        for bit in 0..CHAR_BITS {
            bad.values[r * width + C_CB + CHAR_BITS + bit] = Fp::new((38 >> bit) & 1);
        }
        assert!(check_constraints(&NameAir, &bad, &values).is_err());
        // Padding before the end of the name: zero then a letter.
        let mut bad = trace.clone();
        bad.values[r * width + C_LIVE + 2] = Fp::ZERO;
        bad.values[r * width + C_LIVE_INV + 2] = Fp::ZERO;
        assert!(check_constraints(&NameAir, &bad, &values).is_err());
        // A wrong key bit.
        let mut bad = trace.clone();
        let r = find(T_TLOAD, 0) + 1;
        let v = &mut bad.values[r * width + R_KB + 5];
        *v = Fp::ONE - *v;
        assert!(check_constraints(&NameAir, &bad, &values).is_err());
        // The window: pretend the commit is one block younger.
        let mut bad = trace.clone();
        let r = find(T_WIN, 0);
        for rr in 0..trace.height() {
            if trace.values[rr * width + T_WIN] == Fp::ONE || trace.values[rr * width + T_WIN2] == Fp::ONE {
                let _ = rr;
            }
        }
        bad.values[r * width + R_CH] += Fp::ONE;
        assert!(check_constraints(&NameAir, &bad, &values).is_err());
        // A different owner in the record than in the commit.
        let mut bad = trace.clone();
        let r = find(T_COMMIT, 2);
        bad.values[r * width + COL_DATA] += Fp::ONE;
        assert!(check_constraints(&NameAir, &bad, &values).is_err());
        // Claiming a count that is not the operations'.
        let mut bad = values.clone();
        bad[PUB_COUNTS + 1] = Fp::new(2);
        assert!(check_constraints(&NameAir, &trace, &bad).is_err());
        // The witness generator refuses a reveal to a name already there,
        // and a wrong salt (its commit is not found).
        let mut wtxn = w.env.write_txn().unwrap();
        let wrong = [NameOp::Reveal { record: alice.clone(), salt: d(6), commit: 5 }];
        // And the right salt at the wrong position.
        let moved = [NameOp::Reveal { record: alice.clone(), salt: d(5), commit: 6 }];
        assert!(matches!(
            NameWitness::collect(&w.utxo, &w.names, &mut wtxn, 30, &moved, &[]).err().unwrap(),
            ApplyError::NoCommit
        ));
        assert!(matches!(
            NameWitness::collect(&w.utxo, &w.names, &mut wtxn, 30, &wrong, &[]).err().unwrap(),
            ApplyError::NoCommit
        ));
        wtxn.abort();
    }
}
