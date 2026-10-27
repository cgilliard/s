//! XMSS signature verification as an AIR on the hash machine.
//!
//! One signature occupies a fixed schedule of rows, each one hash machine
//! permutation (or a pass/load row), in this order:
//!
//! ```text
//! msg_start, msg_abs(0), msg_abs(1)                 message digest sponge (3 rows)
//! for each of the 67 chains:
//!     load                                          digest := signature value
//!     step x 15                                     pass while digits remain, then chain steps
//!     leaf                                          absorb the chain end into the leaf sponge
//! for each of the 4 tree levels:
//!     tree_start, tree_abs                          th(DOM_TREE, pos, level, left || right)
//! done ...                                          padding
//! ```
//!
//! Row types are one-hot flags and the sequence is enforced by transition
//! constraints driven by small one-hot counters (step within chain, digit
//! within element, element, tree level). The digit of a chain is read from a
//! canonical 31-bit decomposition of the selected digest element on the
//! chain's load row; the checksum accumulates as chains are processed and is
//! itself the ninth "element" for the last three chains. Registers carried
//! across rows hold the public seed, the leaf index bits, the message
//! digest, the leaf sponge state, the saved node and sibling for tree
//! levels, and the remaining pass count of the current chain.
//!
//! Public values: `root[8] | pub_seed[4] | msg[8]`. Witness: the signature
//! (index, randomizer, 67 chain values, 4 siblings).

use crate::field::Field;
use crate::hash_machine::{
    COL_ABSORB, COL_ACC, COL_CHAIN, COL_COMPRESS, COL_DATA, COL_DIR, COL_LOAD, COL_PASS, COL_START, HashTraceBuilder,
    NUM_COLS as HM_COLS, eval_hash_machine,
};
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH};
use crate::poseidon2_air::{COL_INPUT, COL_OUTPUT};
use crate::stark::{Air, Builder, Trace};
use crate::transaction::TREE_HEIGHT;
use crate::xmss::{
    CHAINS, CSUM_CHAINS, DIGITS_PER_ELEMENT, DOM_MSG, DOM_TREE, DOM_WOTS_CHAIN, DOM_WOTS_PK, Digest, MSG_CHAINS,
    PUB_SEED_LEN, PublicKey, Signature, W, digits,
};

pub const HEIGHT: usize = TREE_HEIGHT;
const STEPS: usize = W - 1;
const ELEMENTS: usize = DIGEST + 1; // digest elements plus the checksum
const BITS: usize = 31;

// Row type flags.
pub const T_MSG_START: usize = HM_COLS;
pub const T_MSG_ABS: usize = HM_COLS + 1;
pub const T_LOAD: usize = HM_COLS + 2;
pub const T_STEP: usize = HM_COLS + 3;
pub const T_LEAF: usize = HM_COLS + 4;
pub const T_TREE_START: usize = HM_COLS + 5;
pub const T_TREE_ABS: usize = HM_COLS + 6;
pub const T_DONE: usize = HM_COLS + 7;
const NUM_TYPES: usize = 8;
// Counters and flags.
pub const C_MC: usize = HM_COLS + NUM_TYPES;
pub const C_ACTIVE: usize = C_MC + 1;
pub const C_REM: usize = C_ACTIVE + 1;
pub const C_REM_INV: usize = C_REM + 1;
pub const C_SSEL: usize = C_REM_INV + 1; // [STEPS]
pub const C_KSEL: usize = C_SSEL + STEPS; // [DIGITS_PER_ELEMENT]
pub const C_ESEL: usize = C_KSEL + DIGITS_PER_ELEMENT; // [ELEMENTS]
pub const C_LAST: usize = C_ESEL + ELEMENTS;
pub const C_LSEL: usize = C_LAST + 1; // [HEIGHT]
pub const C_BITS: usize = C_LSEL + HEIGHT; // [BITS]
pub const C_T3: usize = C_BITS + BITS;
pub const C_D: usize = C_T3 + 1;
pub const C_CSUM: usize = C_D + 1;
// Registers.
pub const R_PUB_SEED: usize = C_CSUM + 1; // [PUB_SEED_LEN]
pub const R_IDX: usize = R_PUB_SEED + PUB_SEED_LEN; // [HEIGHT] bits
pub const R_M: usize = R_IDX + HEIGHT; // [DIGEST]
pub const R_SP: usize = R_M + DIGEST; // [WIDTH]
pub const R_NODE: usize = R_SP + WIDTH; // [DIGEST]
pub const R_SIB: usize = R_NODE + DIGEST; // [DIGEST]
pub const NUM_COLS: usize = R_SIB + DIGEST;

pub const PUB_ROOT: usize = 0;
pub const PUB_SEED: usize = DIGEST;
pub const PUB_MSG: usize = DIGEST + PUB_SEED_LEN;
pub const NUM_PUBLIC: usize = PUB_MSG + DIGEST;

/// Rows used by one signature before padding.
pub const ROWS_PER_SIGNATURE: usize = 3 + CHAINS * (2 + STEPS) + 2 * HEIGHT;

fn pow2<F: Field>(k: usize) -> F {
    F::from_u32(1 << k)
}

/// The XMSS verification AIR.
pub struct XmssAir;

impl Air for XmssAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        eval_hash_machine(b);
        let l = b.local();
        let n = b.next();
        let public = b.public();
        let one = F::ONE;
        let pubv = |i: usize| -> F { public[i] };

        // --- row types and machine op consistency ---
        let types: [F; NUM_TYPES] = core::array::from_fn(|i| l[T_MSG_START + i]);
        let (msg_start, msg_abs, load, step, leaf, tree_start, tree_abs, done) =
            (types[0], types[1], types[2], types[3], types[4], types[5], types[6], types[7]);
        for t in types {
            b.assert_zero(t * t - t);
        }
        b.assert_eq(types.iter().fold(F::ZERO, |a, t| a + *t), one);
        let active = l[C_ACTIVE];
        b.assert_zero(active * active - active);
        b.assert_zero(active * (one - step));
        b.assert_eq(l[COL_START], msg_start + leaf + tree_start);
        b.assert_eq(l[COL_ABSORB], msg_abs + tree_abs);
        b.assert_eq(l[COL_LOAD], load);
        b.assert_eq(l[COL_CHAIN], step * active);
        b.assert_eq(l[COL_PASS], step * (one - active) + done);
        b.assert_zero(l[COL_COMPRESS]);
        b.when_first_row(one - msg_start);
        b.when_last_row(one - done);

        // --- one-hot counters ---
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
        // Initial counter state on the first row: digit 7 of the "ninth
        // element", so the first rotation lands on element 0, digit 0.
        for (i, k) in ksel.iter().enumerate() {
            b.assert_zero(msg_start * (*k - if i == DIGITS_PER_ELEMENT - 1 { one } else { F::ZERO }));
        }
        for (e, v) in esel.iter().enumerate() {
            b.assert_zero(msg_start * (*v - if e == ELEMENTS - 1 { one } else { F::ZERO }));
        }

        // --- schedule (transitions) ---
        let (n_msg_abs, n_load, n_step, n_leaf, n_tree_start, n_tree_abs, n_done) =
            (n[T_MSG_ABS], n[T_LOAD], n[T_STEP], n[T_LEAF], n[T_TREE_START], n[T_TREE_ABS], n[T_DONE]);
        b.when_transition(msg_start * (one - n_msg_abs));
        b.when_transition(msg_start * n[C_MC]);
        b.when_transition(msg_abs * (one - mc) * (one - n_msg_abs));
        b.when_transition(msg_abs * (one - mc) * (one - n[C_MC]));
        b.when_transition(msg_abs * mc * (one - n_load));
        b.when_transition(load * (one - n_step));
        b.when_transition(load * (one - n[C_SSEL]));
        let s_last = ssel[STEPS - 1];
        b.when_transition(step * (one - s_last) * (one - n_step));
        for i in 1..STEPS {
            b.when_transition(step * (n[C_SSEL + i] - ssel[i - 1]));
        }
        b.when_transition(step * s_last * (one - n_leaf));
        b.when_transition(leaf * (n_load - (one - last)));
        b.when_transition(leaf * (n_tree_start - last));
        b.when_transition(leaf * last * (one - n[C_LSEL]));
        b.when_transition(tree_start * (one - n_tree_abs));
        for i in 0..HEIGHT {
            b.when_transition(tree_start * (n[C_LSEL + i] - lsel[i]));
        }
        let l_last = lsel[HEIGHT - 1];
        b.when_transition(tree_abs * (one - l_last) * (one - n_tree_start));
        for i in 1..HEIGHT {
            b.when_transition(tree_abs * (n[C_LSEL + i] - lsel[i - 1]));
        }
        b.when_transition(tree_abs * l_last * (one - n_done));
        b.when_transition(done * (one - n_done));

        // --- digit selectors rotate on load rows ---
        for i in 0..DIGITS_PER_ELEMENT {
            let prev = ksel[(i + DIGITS_PER_ELEMENT - 1) % DIGITS_PER_ELEMENT];
            b.when_transition(n_load * (n[C_KSEL + i] - prev));
            b.when_transition((one - n_load) * (n[C_KSEL + i] - ksel[i]));
        }
        let wrap = ksel[DIGITS_PER_ELEMENT - 1];
        for e in 0..ELEMENTS {
            let prev = esel[(e + ELEMENTS - 1) % ELEMENTS];
            b.when_transition(n_load * (n[C_ESEL + e] - (esel[e] + wrap * (prev - esel[e]))));
            b.when_transition((one - n_load) * (n[C_ESEL + e] - esel[e]));
        }

        // --- registers: public seed and index bits are constant ---
        for i in 0..PUB_SEED_LEN {
            b.when_transition(n[R_PUB_SEED + i] - l[R_PUB_SEED + i]);
            b.when_first_row(l[R_PUB_SEED + i] - pubv(PUB_SEED + i));
        }
        let idx_bits: [F; HEIGHT] = core::array::from_fn(|i| l[R_IDX + i]);
        let mut idx = F::ZERO;
        for (i, bit) in idx_bits.iter().enumerate() {
            b.assert_zero(*bit * *bit - *bit);
            b.when_transition(n[R_IDX + i] - *bit);
            idx += *bit * pow2::<F>(i);
        }
        let pub_seed: [F; PUB_SEED_LEN] = core::array::from_fn(|i| l[R_PUB_SEED + i]);

        // --- bits, digit, checksum ---
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
        // Canonical: a value with bits 27..31 all set must have low27 == 0 (p - 1).
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
        b.when_transition(n[C_CSUM] - l[C_CSUM] - load * (one - esel[DIGEST]) * (fifteen - dcol));
        b.assert_zero(msg_start * l[C_CSUM]);

        // --- chain control ---
        let rem = l[C_REM];
        b.assert_zero(load * (rem - dcol));
        b.when_transition(load * (n[C_REM] - rem));
        b.assert_zero(step * active * rem);
        // Inactive step rows need rem != 0: rem * rem_inv == 1 - active.
        b.assert_zero(step * ((one - active) - rem * l[C_REM_INV]));
        b.when_transition(step * (n[C_REM] - rem + (one - active)));

        // chain index and step from the one-hot counters
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

        // --- message digest sponge ---
        let msg_cap = [pub_seed[0], pub_seed[1], pub_seed[2], pub_seed[3], F::from_u32(DOM_MSG), idx, F::ZERO, F::ZERO];
        for (j, c) in msg_cap.iter().enumerate() {
            b.assert_zero(msg_start * (l[COL_INPUT + RATE + j] - *c));
        }
        let block0: [F; RATE] =
            core::array::from_fn(|i| if i == 0 { F::from_u32(DIGEST as u32) } else { pubv(PUB_MSG + i - 1) });
        let block1: [F; RATE] = core::array::from_fn(|i| if i == 0 { pubv(PUB_MSG + DIGEST - 1) } else { F::ZERO });
        for i in 0..RATE {
            b.assert_zero(msg_abs * (l[COL_DATA + i] - ((one - mc) * block0[i] + mc * block1[i])));
        }
        for i in 0..DIGEST {
            b.when_transition(msg_abs * mc * (n[R_M + i] - l[COL_ACC + i]));
            b.when_transition((one - msg_abs * mc) * (n[R_M + i] - l[R_M + i]));
        }

        // --- leaf sponge ---
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
            b.when_transition((one - leaf) * (n[R_SP + j] - l[R_SP + j]));
        }
        for i in 0..RATE {
            b.when_transition(n_leaf * (n[COL_INPUT + i] - n[R_SP + i] - l[COL_ACC + i]));
            b.when_transition(n_leaf * (n[COL_INPUT + RATE + i] - n[R_SP + RATE + i]));
        }

        // --- tree levels ---
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
            b.when_transition(n_tree_start * (n[R_NODE + i] - l[COL_ACC + i]));
            b.when_transition((one - n_tree_start) * (n[R_NODE + i] - l[R_NODE + i]));
            b.when_transition(tree_start * (n[R_SIB + i] - l[R_SIB + i]));
            let node = l[R_NODE + i];
            let sib = l[R_SIB + i];
            b.assert_zero(tree_start * (l[COL_INPUT + i] - ((one - dir) * node + dir * sib)));
            b.assert_zero(tree_abs * (l[COL_DATA + i] - ((one - dir) * sib + dir * node)));
            b.assert_zero(tree_abs * l_last * (l[COL_ACC + i] - pubv(PUB_ROOT + i)));
        }
        let tree_cap =
            [pub_seed[0], pub_seed[1], pub_seed[2], pub_seed[3], F::from_u32(DOM_TREE), pos, F::ZERO, level_plus_one];
        for (j, c) in tree_cap.iter().enumerate() {
            b.assert_zero(tree_start * (l[COL_INPUT + RATE + j] - *c));
        }
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Regs {
    pub_seed: [Fp; PUB_SEED_LEN],
    idx_bits: [Fp; HEIGHT],
    m: [Fp; DIGEST],
    sp: [Fp; WIDTH],
    node: [Fp; DIGEST],
    sib: [Fp; DIGEST],
    csum: u32,
    ksel: usize,
    esel: usize,
    rem: u32,
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
        row[C_LAST] = if self.esel == ELEMENTS - 1 && self.ksel == CSUM_CHAINS - 1 { Fp::ONE } else { Fp::ZERO };
        row[C_REM] = Fp::new(self.rem);
    }
}

fn cap(pub_seed: &[Fp; PUB_SEED_LEN], domain: u32, index: u64, extra: u32) -> [Fp; DIGEST] {
    let mut c = [Fp::ZERO; DIGEST];
    c[..PUB_SEED_LEN].copy_from_slice(pub_seed);
    c[PUB_SEED_LEN] = Fp::new(domain);
    c[PUB_SEED_LEN + 1] = Fp::new((index & ((1 << 30) - 1)) as u32);
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

impl XmssAir {
    /// Builds the trace for verifying `sig` on `msg` under `pk`. The trace is
    /// valid only for a genuine signature; an invalid one yields a trace
    /// that fails the constraints (or a panic on malformed input).
    pub fn generate_trace(pk: &PublicKey, msg: &[Fp; DIGEST], sig: &Signature<HEIGHT>) -> Trace {
        assert!(sig.index < 1 << HEIGHT);
        let mut b = HashTraceBuilder::new(NUM_COLS);
        let ps = pk.pub_seed;
        let idx = sig.index;
        let mut regs = Regs {
            pub_seed: ps,
            idx_bits: core::array::from_fn(|i| Fp::new(((idx >> i) & 1) as u32)),
            m: [Fp::ZERO; DIGEST],
            sp: {
                let mut sp = [Fp::ZERO; WIDTH];
                sp[RATE..].copy_from_slice(&cap(&ps, DOM_WOTS_PK, idx, 0));
                sp
            },
            node: [Fp::ZERO; DIGEST],
            sib: [Fp::ZERO; DIGEST],
            csum: 0,
            ksel: DIGITS_PER_ELEMENT - 1,
            esel: ELEMENTS - 1,
            rem: 0,
        };

        // Message digest sponge.
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&sig.randomizer);
        input[RATE..].copy_from_slice(&cap(&ps, DOM_MSG, idx, 0));
        b.start(input);
        {
            let row = b.last_row_mut();
            row[T_MSG_START] = Fp::ONE;
            regs.write(row);
        }
        let mut block0 = [Fp::ZERO; RATE];
        block0[0] = Fp::from_u32(DIGEST as u32);
        block0[1..].copy_from_slice(&msg[..RATE - 1]);
        b.absorb(block0);
        {
            let row = b.last_row_mut();
            row[T_MSG_ABS] = Fp::ONE;
            regs.write(row);
        }
        let mut block1 = [Fp::ZERO; RATE];
        block1[0] = msg[DIGEST - 1];
        b.absorb(block1);
        {
            let row = b.last_row_mut();
            row[T_MSG_ABS] = Fp::ONE;
            row[C_MC] = Fp::ONE;
            regs.write(row);
        }
        let m = b.acc();
        regs.m = m;
        let digs = digits(&m);

        // Chains.
        for (c, &digit) in digs.iter().enumerate() {
            // Rotate selectors into this chain.
            let wrap = regs.ksel == DIGITS_PER_ELEMENT - 1;
            regs.ksel = (regs.ksel + 1) % DIGITS_PER_ELEMENT;
            if wrap {
                regs.esel = (regs.esel + 1) % ELEMENTS;
            }
            let d = digit as u32;
            regs.rem = d;
            b.load(sig.wots[c]);
            {
                let elem = if regs.esel < DIGEST { m[regs.esel].to_canonical() } else { regs.csum };
                let row = b.last_row_mut();
                row[T_LOAD] = Fp::ONE;
                write_bits(row, elem);
                row[C_D] = Fp::new(d);
                regs.write(row);
            }
            if c < MSG_CHAINS {
                regs.csum += (W as u32 - 1) - d;
            }
            for step in 0..STEPS {
                let active = regs.rem == 0;
                if active {
                    b.chain(cap(&ps, DOM_WOTS_CHAIN, idx, c as u32 | (step as u32) << 16));
                } else {
                    b.pass();
                }
                {
                    let row = b.last_row_mut();
                    row[T_STEP] = Fp::ONE;
                    row[C_SSEL + step] = Fp::ONE;
                    row[C_ACTIVE] = Fp::new(active as u32);
                    row[C_REM_INV] = if active { Fp::ZERO } else { Fp::new(regs.rem).inverse().unwrap() };
                    regs.write(row);
                }
                if !active {
                    regs.rem -= 1;
                }
            }
            // Leaf sponge absorbs the chain end.
            let end = b.acc();
            let mut input = regs.sp;
            for (s, x) in input.iter_mut().zip(&end) {
                *s = s.add(x);
            }
            b.start(input);
            {
                let row = b.last_row_mut();
                row[T_LEAF] = Fp::ONE;
                regs.write(row);
            }
            regs.sp = b.state();
        }

        // Tree levels.
        let mut pos = (1u64 << HEIGHT) + idx;
        for level in 0..HEIGHT {
            let right = pos & 1 == 1;
            pos >>= 1;
            regs.node = b.acc();
            regs.sib = sig.auth_path[level];
            let (left_v, right_v) = if right { (regs.sib, regs.node) } else { (regs.node, regs.sib) };
            let mut input = [Fp::ZERO; WIDTH];
            input[..RATE].copy_from_slice(&left_v);
            input[RATE..].copy_from_slice(&cap(&ps, DOM_TREE, pos, (level + 1) as u32));
            b.start(input);
            {
                let row = b.last_row_mut();
                row[T_TREE_START] = Fp::ONE;
                row[C_LSEL + level] = Fp::ONE;
                row[COL_DIR] = Fp::new(right as u32);
                regs.write(row);
            }
            b.absorb(right_v);
            {
                let row = b.last_row_mut();
                row[T_TREE_ABS] = Fp::ONE;
                row[C_LSEL + level] = Fp::ONE;
                row[COL_DIR] = Fp::new(right as u32);
                regs.write(row);
            }
        }
        debug_assert_eq!(b.len(), ROWS_PER_SIGNATURE);

        // Done rows up to a power of two.
        let n = b.len().next_power_of_two();
        while b.len() < n {
            b.pass();
            let row = b.last_row_mut();
            row[T_DONE] = Fp::ONE;
            regs.write(row);
        }
        b.finish()
    }

    /// Public values for `pk` and `msg`.
    pub fn public_values(pk: &PublicKey, msg: &[Fp; DIGEST]) -> Vec<Fp> {
        let mut v = Vec::with_capacity(NUM_PUBLIC);
        v.extend_from_slice(&pk.root);
        v.extend_from_slice(&pk.pub_seed);
        v.extend_from_slice(msg);
        v
    }
}

/// Digest type re-export for callers.
pub type Msg = Digest;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::stark::{StarkConfig, check_constraints, prove, verify};
    use crate::xmss::SecretKey;

    fn key(tag: u8) -> SecretKey<HEIGHT> {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        SecretKey::generate(&seed)
    }

    fn msg(tag: u32) -> [Fp; DIGEST] {
        core::array::from_fn(|i| Fp::new(tag.wrapping_mul(i as u32 + 7) % crate::poseidon2::P))
    }

    #[test]
    fn layout() {
        assert_eq!(crate::stark::measure_degree(&XmssAir, NUM_PUBLIC), 3);
        assert_eq!(ROWS_PER_SIGNATURE, 3 + 67 * 17 + 8);
        const { assert!(ROWS_PER_SIGNATURE <= 2048) };
        assert_eq!(NUM_PUBLIC, 20);
        const { assert!(NUM_COLS < 500) };
    }

    #[test]
    fn genuine_signatures_satisfy_constraints() {
        let mut sk = key(1);
        let pk = sk.public_key();
        // Several leaves, including the last, with different messages.
        for (i, tag) in [1u32, 2, 0xffff_ffff].iter().enumerate() {
            while sk.next_index() < [0u64, 7, 15][i] {
                sk.sign(&msg(99)).unwrap();
            }
            let m = msg(*tag);
            let sig = sk.sign(&m).unwrap();
            assert!(pk.verify(&m, &sig));
            let trace = XmssAir::generate_trace(&pk, &m, &sig);
            assert_eq!(trace.height(), 2048);
            let public = XmssAir::public_values(&pk, &m);
            assert_eq!(check_constraints(&XmssAir, &trace, &public), Ok(()), "leaf {}", sig.index);

            // Wrong public root or message fails.
            let mut bad = public.clone();
            bad[PUB_ROOT] += Fp::ONE;
            assert!(check_constraints(&XmssAir, &trace, &bad).is_err());
            let mut bad = public.clone();
            bad[PUB_MSG + 3] += Fp::ONE;
            assert!(check_constraints(&XmssAir, &trace, &bad).is_err());
        }
    }

    #[test]
    fn forged_witness_fails_constraints() {
        let mut sk = key(2);
        let pk = sk.public_key();
        let m = msg(5);
        let sig = sk.sign(&m).unwrap();
        let trace = XmssAir::generate_trace(&pk, &m, &sig);
        let public = XmssAir::public_values(&pk, &m);
        let w = NUM_COLS;

        // Tamper a chain value on its load row (data and acc together).
        let load_row = 3 + 10 * 17;
        let mut bad = trace.clone();
        bad.values[load_row * w + COL_DATA] += Fp::ONE;
        bad.values[load_row * w + COL_ACC] += Fp::ONE;
        assert!(check_constraints(&XmssAir, &bad, &public).is_err());

        // Claim a different digit (skip one chain step) on a chain.
        let mut bad = trace.clone();
        bad.values[load_row * w + C_D] += Fp::ONE;
        assert!(check_constraints(&XmssAir, &bad, &public).is_err());

        // Flip an index bit everywhere: tweaks and tree path change.
        let mut bad = trace.clone();
        for r in 0..trace.height() {
            let v = &mut bad.values[r * w + R_IDX];
            *v = Fp::ONE - *v;
        }
        assert!(check_constraints(&XmssAir, &bad, &public).is_err());

        // Stop early: turn the last tree row into a done row.
        let mut bad = trace.clone();
        let last_tree = ROWS_PER_SIGNATURE - 1;
        bad.values[last_tree * w + T_TREE_ABS] = Fp::ZERO;
        bad.values[last_tree * w + T_DONE] = Fp::ONE;
        assert!(check_constraints(&XmssAir, &bad, &public).is_err());

        // A signature from another key on the same message.
        let mut other = key(3);
        let sig2 = other.sign(&m).unwrap();
        let trace2 = XmssAir::generate_trace(&other.public_key(), &m, &sig2);
        assert!(check_constraints(&XmssAir, &trace2, &public).is_err());
        assert_eq!(check_constraints(&XmssAir, &trace2, &XmssAir::public_values(&other.public_key(), &m)), Ok(()));
    }

    #[test]
    #[ignore = "slow in debug builds; run with --release"]
    fn prove_and_verify_signature() {
        let config = StarkConfig { log_blowup: 1, num_queries: 20, pow_bits: 0 };
        let mut sk = key(4);
        let pk = sk.public_key();
        let m = msg(11);
        let sig = sk.sign(&m).unwrap();
        let trace = XmssAir::generate_trace(&pk, &m, &sig);
        let public = XmssAir::public_values(&pk, &m);
        let tr = || {
            let mut c = Challenger::new();
            c.observe(Fp::new(0xc3));
            c
        };
        let proof = prove(&config, &XmssAir, &trace, &public, &mut tr());
        assert_eq!(verify(&config, &XmssAir, &public, &proof, &mut tr()), Ok(()));
        let mut bad = public.clone();
        bad[PUB_MSG] += Fp::ONE;
        assert!(verify(&config, &XmssAir, &bad, &proof, &mut tr()).is_err());
    }
}
