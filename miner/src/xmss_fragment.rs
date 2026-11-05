//! XMSS signature verification as a fragment of a hash-machine circuit.
//!
//! A circuit built on [`crate::hash_machine`] that needs to verify XMSS
//! signatures (the transaction segments for their inputs, the name
//! segment for record updates) places this fragment's columns at a base
//! of its choosing ([`Cols`]), gives it seven row types ([`Types`]) and
//! calls [`eval`] from its own `eval` with the message register to sign.
//! The fragment then owns the schedule from a `msg_start` row to the last
//! `tree_abs` row, after which the enclosing circuit must continue with the
//! row type it names (`exit`), finding the key's root in the machine's
//! digest and the key's public seed in [`Cols::pub_seed`].
//!
//! The enclosing circuit maps the row types onto the machine: `msg_start`,
//! `leaf` and `tree_start` are `start` rows, `msg_abs` and `tree_abs` are
//! `absorb` rows, `load` is a `load` row, and `step` is `chain` while the
//! fragment's `active` flag is set and `pass` otherwise. Entering
//! `msg_start`, the public seed, the leaf index bits and the message are
//! free witnesses; the fragment keeps the first two fixed until the next
//! signature.
//!
//! Rows per signature: three message rows, then per chain a load row,
//! `W - 1` step rows and a leaf row, then two rows per tree level of the
//! key's height, 1 to [`MAX_HEIGHT`]: [`rows`]. The height is a one-hot
//! register ([`Cols::hsel`]) set entering `msg_start` with the rest of the
//! key, so the enclosing circuit hashes it into the key hash
//! ([`height_value`]).
//!
//! The 31-bit decomposition columns ([`Cols::bits`]) are constrained to a
//! canonical field element on every row and bound to a value only on load
//! rows, so an enclosing circuit may use them for its own range checks on
//! other rows through [`bits_value`].

use crate::field::Field;
use crate::hash_machine::{COL_ACC, COL_DATA, COL_DIR, HashTraceBuilder};
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH};
use crate::poseidon2_air::{COL_INPUT, COL_OUTPUT};
use crate::stark::Builder;
use crate::transaction::Sig;
use crate::xmss::{
    CHAINS, CSUM_CHAINS, DIGITS_PER_ELEMENT, DOM_MSG, DOM_TREE, DOM_WOTS_CHAIN, DOM_WOTS_PK, Digest, MAX_HEIGHT,
    MSG_CHAINS, PUB_SEED_LEN, PublicKey, W, digits,
};
pub const STEPS: usize = W - 1;
/// Message digest elements plus the checksum.
pub const ELEMENTS: usize = DIGEST + 1;
/// Bits of a field element.
pub const BITS: usize = 31;
const MASK30: u64 = (1 << 30) - 1;

/// Rows of one signature by a key of `height`.
pub const fn rows(height: usize) -> usize {
    3 + CHAINS * (2 + STEPS) + 2 * height
}
/// Rows of one signature by the tallest key.
pub const ROWS: usize = rows(MAX_HEIGHT);

// Column offsets from the base.
const MC: usize = 0;
const ACTIVE: usize = 1;
const REM: usize = 2;
const REM_INV: usize = 3;
const SSEL: usize = 4;
const KSEL: usize = SSEL + STEPS;
const ESEL: usize = KSEL + DIGITS_PER_ELEMENT;
const LAST: usize = ESEL + ELEMENTS;
const LSEL: usize = LAST + 1;
const HSEL: usize = LSEL + MAX_HEIGHT;
const TLAST: usize = HSEL + MAX_HEIGHT;
const BITS_AT: usize = TLAST + 1;
const T3: usize = BITS_AT + BITS;
const D: usize = T3 + 1;
const CSUM: usize = D + 1;
const PUB_SEED: usize = CSUM + 1;
const IDX: usize = PUB_SEED + PUB_SEED_LEN;
const M: usize = IDX + MAX_HEIGHT;
const SP: usize = M + DIGEST;
const NODE: usize = SP + WIDTH;
const SIB: usize = NODE + DIGEST;
/// Columns the fragment uses.
pub const LEN: usize = SIB + DIGEST;

/// Where the fragment's columns sit in the enclosing trace.
#[derive(Clone, Copy, Debug)]
pub struct Cols {
    pub base: usize,
}

impl Cols {
    pub const fn new(base: usize) -> Cols {
        Cols { base }
    }

    /// Second message block flag (the message takes two absorb rows).
    pub const fn mc(&self) -> usize {
        self.base + MC
    }
    /// One on step rows that perform a chain step (not a pass).
    pub const fn active(&self) -> usize {
        self.base + ACTIVE
    }
    /// Steps left in the current chain.
    pub const fn rem(&self) -> usize {
        self.base + REM
    }
    pub const fn rem_inv(&self) -> usize {
        self.base + REM_INV
    }
    /// One-hot step index, `0..STEPS`.
    pub const fn ssel(&self, i: usize) -> usize {
        self.base + SSEL + i
    }
    /// One-hot digit index within an element.
    pub const fn ksel(&self, i: usize) -> usize {
        self.base + KSEL + i
    }
    /// One-hot element index (the checksum last).
    pub const fn esel(&self, i: usize) -> usize {
        self.base + ESEL + i
    }
    /// One on the last chain's rows.
    pub const fn last(&self) -> usize {
        self.base + LAST
    }
    /// One-hot tree level on tree rows.
    pub const fn lsel(&self, i: usize) -> usize {
        self.base + LSEL + i
    }
    /// One-hot tree height of the key: `hsel(k)` for height `k + 1`.
    pub const fn hsel(&self, k: usize) -> usize {
        self.base + HSEL + k
    }
    /// One on the tree rows of the key's last level.
    pub const fn tlast(&self) -> usize {
        self.base + TLAST
    }
    /// 31-bit decomposition, least significant first.
    pub const fn bits(&self, i: usize) -> usize {
        self.base + BITS_AT + i
    }
    pub const fn t3(&self) -> usize {
        self.base + T3
    }
    /// The current digit.
    pub const fn d(&self) -> usize {
        self.base + D
    }
    /// Running checksum.
    pub const fn csum(&self) -> usize {
        self.base + CSUM
    }
    /// The key's public seed.
    pub const fn pub_seed(&self, i: usize) -> usize {
        self.base + PUB_SEED + i
    }
    /// Leaf index bits.
    pub const fn idx(&self, i: usize) -> usize {
        self.base + IDX + i
    }
    /// The randomized message digest.
    pub const fn m(&self, i: usize) -> usize {
        self.base + M + i
    }
    /// The leaf (WOTS public key) sponge.
    pub const fn sp(&self, j: usize) -> usize {
        self.base + SP + j
    }
    /// Current tree node.
    pub const fn node(&self, i: usize) -> usize {
        self.base + NODE + i
    }
    /// Tree sibling; only constrained on tree rows, so an enclosing circuit
    /// may share it.
    pub const fn sib(&self, i: usize) -> usize {
        self.base + SIB + i
    }
}

/// The enclosing circuit's row-type columns for the fragment's rows.
#[derive(Clone, Copy, Debug)]
pub struct Types {
    pub msg_start: usize,
    pub msg_abs: usize,
    pub load: usize,
    pub step: usize,
    pub leaf: usize,
    pub tree_start: usize,
    pub tree_abs: usize,
}

fn pow2<F: Field>(k: usize) -> F {
    F::from_u32(1 << k)
}

/// The value the decomposition columns hold on a row.
pub fn bits_value<F: Field>(row: &[F], c: &Cols) -> F {
    (0..BITS).fold(F::ZERO, |acc, i| acc + row[c.bits(i)] * pow2::<F>(i))
}

/// The key's tree height as a value, from the one-hot register.
pub fn height_value<F: Field>(row: &[F], c: &Cols) -> F {
    (0..MAX_HEIGHT).fold(F::ZERO, |acc, k| acc + row[c.hsel(k)] * F::from_u32((k + 1) as u32))
}

/// Emits the fragment's constraints. `msg` is the message register (eight
/// columns of the enclosing circuit) a signature is over; `exit` is the
/// next-row expression that must hold after the last tree row.
#[allow(clippy::needless_range_loop)]
pub fn eval<F: Field>(b: &mut Builder<'_, F>, c: &Cols, t: &Types, msg: &[F; DIGEST], exit: F) {
    let l = b.local();
    let n = b.next();
    let one = F::ONE;
    let nt = |ty: usize| n[ty];
    let msg_start = l[t.msg_start];
    let msg_abs = l[t.msg_abs];
    let load = l[t.load];
    let step = l[t.step];
    let leaf = l[t.leaf];
    let tree_start = l[t.tree_start];
    let tree_abs = l[t.tree_abs];
    let active = l[c.active()];
    b.assert_zero(active * active - active);
    b.assert_zero(active * (one - step));

    // ---------------- counters and gadgets ----------------
    b.mark("xmss counters");
    let ssel: [F; STEPS] = core::array::from_fn(|i| l[c.ssel(i)]);
    let ksel: [F; DIGITS_PER_ELEMENT] = core::array::from_fn(|i| l[c.ksel(i)]);
    let esel: [F; ELEMENTS] = core::array::from_fn(|i| l[c.esel(i)]);
    let lsel: [F; MAX_HEIGHT] = core::array::from_fn(|i| l[c.lsel(i)]);
    let hsel: [F; MAX_HEIGHT] = core::array::from_fn(|k| l[c.hsel(k)]);
    for v in ssel.iter().chain(&ksel).chain(&esel).chain(&lsel).chain(&hsel) {
        b.assert_zero(*v * *v - *v);
    }
    b.assert_eq(ssel.iter().fold(F::ZERO, |a, v| a + *v), step);
    b.assert_eq(ksel.iter().fold(F::ZERO, |a, v| a + *v), one);
    b.assert_eq(esel.iter().fold(F::ZERO, |a, v| a + *v), one);
    b.assert_eq(lsel.iter().fold(F::ZERO, |a, v| a + *v), tree_start + tree_abs);
    b.assert_eq(hsel.iter().fold(F::ZERO, |a, v| a + *v), one);
    // The height is part of the key: fixed until the next signature.
    for k in 0..MAX_HEIGHT {
        b.when_transition((one - nt(t.msg_start)) * (n[c.hsel(k)] - hsel[k]));
    }
    // The last tree level is the key's height less one.
    let tlast = l[c.tlast()];
    b.assert_eq(tlast, (0..MAX_HEIGHT).fold(F::ZERO, |a, lv| a + lsel[lv] * hsel[lv]));
    let mc = l[c.mc()];
    b.assert_zero(mc * mc - mc);
    b.assert_zero(mc * (one - msg_abs));
    let last = l[c.last()];
    b.assert_eq(last, esel[ELEMENTS - 1] * ksel[CSUM_CHAINS - 1]);
    for (i, k) in ksel.iter().enumerate() {
        b.assert_zero(msg_start * (*k - if i == DIGITS_PER_ELEMENT - 1 { one } else { F::ZERO }));
    }
    for (e, v) in esel.iter().enumerate() {
        b.assert_zero(msg_start * (*v - if e == ELEMENTS - 1 { one } else { F::ZERO }));
    }

    // ---------------- schedule ----------------
    b.mark("xmss schedule");
    b.when_transition(msg_start * (one - nt(t.msg_abs)));
    b.when_transition(msg_start * n[c.mc()]);
    b.when_transition(msg_abs * (one - mc) * (one - nt(t.msg_abs)));
    b.when_transition(msg_abs * (one - mc) * (one - n[c.mc()]));
    b.when_transition(msg_abs * mc * (one - nt(t.load)));
    b.when_transition(load * (one - nt(t.step)));
    b.when_transition(load * (one - n[c.ssel(0)]));
    let s_last = ssel[STEPS - 1];
    b.when_transition(step * (one - s_last) * (one - nt(t.step)));
    for i in 1..STEPS {
        b.when_transition(step * (n[c.ssel(i)] - ssel[i - 1]));
    }
    b.when_transition(step * s_last * (one - nt(t.leaf)));
    b.when_transition(leaf * (nt(t.load) - (one - last)));
    b.when_transition(leaf * (nt(t.tree_start) - last));
    b.when_transition(leaf * last * (one - n[c.lsel(0)]));
    b.when_transition(tree_start * (one - nt(t.tree_abs)));
    for i in 0..MAX_HEIGHT {
        b.when_transition(tree_start * (n[c.lsel(i)] - lsel[i]));
    }
    b.when_transition(tree_abs * (one - tlast) * (one - nt(t.tree_start)));
    for i in 1..MAX_HEIGHT {
        b.when_transition(tree_abs * (one - tlast) * (n[c.lsel(i)] - lsel[i - 1]));
    }
    b.when_transition(tree_abs * tlast * (one - exit));

    // ---------------- digit selectors rotate on load rows ----------------
    b.mark("xmss digit selectors");
    for i in 0..DIGITS_PER_ELEMENT {
        let prev = ksel[(i + DIGITS_PER_ELEMENT - 1) % DIGITS_PER_ELEMENT];
        b.when_transition(nt(t.load) * (n[c.ksel(i)] - prev));
        b.when_transition((one - nt(t.load) - nt(t.msg_start)) * (n[c.ksel(i)] - ksel[i]));
    }
    let wrap_k = ksel[DIGITS_PER_ELEMENT - 1];
    for e in 0..ELEMENTS {
        let prev = esel[(e + ELEMENTS - 1) % ELEMENTS];
        b.when_transition(nt(t.load) * (n[c.esel(e)] - (esel[e] + wrap_k * (prev - esel[e]))));
        b.when_transition((one - nt(t.load) - nt(t.msg_start)) * (n[c.esel(e)] - esel[e]));
    }

    // ---------------- key registers ----------------
    b.mark("xmss key registers");
    let pub_seed: [F; PUB_SEED_LEN] = core::array::from_fn(|i| l[c.pub_seed(i)]);
    for i in 0..PUB_SEED_LEN {
        b.when_transition((one - nt(t.msg_start)) * (n[c.pub_seed(i)] - pub_seed[i]));
    }
    let idx_bits: [F; MAX_HEIGHT] = core::array::from_fn(|i| l[c.idx(i)]);
    let mut idx = F::ZERO;
    for (i, bit) in idx_bits.iter().enumerate() {
        b.assert_zero(*bit * *bit - *bit);
        b.when_transition((one - nt(t.msg_start)) * (n[c.idx(i)] - *bit));
        idx += *bit * pow2::<F>(i);
        // Bits at or above the height are zero: the index is below 2^height.
        let above = (0..i).fold(F::ZERO, |a, k| a + hsel[k]);
        b.assert_zero(*bit * above);
    }
    let height = height_value(l, c);

    // ---------------- bits, digit, checksum ----------------
    b.mark("xmss digits");
    let bits: [F; BITS] = core::array::from_fn(|i| l[c.bits(i)]);
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
    let t3 = l[c.t3()];
    b.assert_eq(t3, bits[30] * bits[29] * bits[28]);
    b.assert_zero(t3 * bits[27] * low27);
    let mut elem = F::ZERO;
    for e in 0..DIGEST {
        elem += esel[e] * l[c.m(e)];
    }
    elem += esel[DIGEST] * l[c.csum()];
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
    let dcol = l[c.d()];
    b.assert_eq(dcol, d);
    let fifteen = F::from_u32((W - 1) as u32);
    // Accumulates after each message chain's load row; resets to zero
    // entering a new signature.
    b.when_transition(
        n[c.csum()] - l[c.csum()] - load * (one - esel[DIGEST]) * (fifteen - dcol) + nt(t.msg_start) * l[c.csum()],
    );
    b.assert_zero(msg_start * l[c.csum()]);

    // ---------------- chain control ----------------
    b.mark("xmss chain control");
    let rem = l[c.rem()];
    b.assert_zero(load * (rem - dcol));
    b.when_transition(load * (n[c.rem()] - rem));
    b.assert_zero(step * active * rem);
    b.assert_zero(step * ((one - active) - rem * l[c.rem_inv()]));
    b.when_transition(step * (n[c.rem()] - rem + (one - active)));
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
    for (j, cc) in chain_cap.iter().enumerate() {
        b.assert_zero(step * active * (l[COL_DATA + j] - *cc));
    }

    // ---------------- message sponge ----------------
    b.mark("xmss message sponge");
    let msg_cap = [pub_seed[0], pub_seed[1], pub_seed[2], pub_seed[3], F::from_u32(DOM_MSG), idx, F::ZERO, F::ZERO];
    for (j, cc) in msg_cap.iter().enumerate() {
        b.assert_zero(msg_start * (l[COL_INPUT + RATE + j] - *cc));
    }
    let block0: [F; RATE] = core::array::from_fn(|i| if i == 0 { F::from_u32(DIGEST as u32) } else { msg[i - 1] });
    let block1: [F; RATE] = core::array::from_fn(|i| if i == 0 { msg[DIGEST - 1] } else { F::ZERO });
    for i in 0..RATE {
        b.assert_zero(msg_abs * (l[COL_DATA + i] - ((one - mc) * block0[i] + mc * block1[i])));
    }
    for i in 0..DIGEST {
        b.when_transition(msg_abs * mc * (n[c.m(i)] - l[COL_ACC + i]));
        b.when_transition((one - msg_abs * mc) * (n[c.m(i)] - l[c.m(i)]));
    }

    // ---------------- leaf sponge ----------------
    b.mark("xmss leaf sponge");
    let sp_init: [F; WIDTH] = core::array::from_fn(|j| match j {
        j if j < RATE => F::ZERO,
        j if j < RATE + PUB_SEED_LEN => pub_seed[j - RATE],
        j if j == RATE + PUB_SEED_LEN => F::from_u32(DOM_WOTS_PK),
        j if j == RATE + PUB_SEED_LEN + 1 => idx,
        _ => F::ZERO,
    });
    for j in 0..WIDTH {
        b.assert_zero(msg_start * (l[c.sp(j)] - sp_init[j]));
        b.when_transition(leaf * (n[c.sp(j)] - l[COL_OUTPUT + j]));
        b.when_transition((one - leaf - nt(t.msg_start)) * (n[c.sp(j)] - l[c.sp(j)]));
    }
    for i in 0..RATE {
        b.when_transition(nt(t.leaf) * (n[COL_INPUT + i] - n[c.sp(i)] - l[COL_ACC + i]));
        b.when_transition(nt(t.leaf) * (n[COL_INPUT + RATE + i] - n[c.sp(RATE + i)]));
    }

    // ---------------- tree levels ----------------
    b.mark("xmss tree");
    let dir = l[COL_DIR];
    let mut dir_want = F::ZERO;
    let mut pos = F::ZERO;
    let mut level_plus_one = F::ZERO;
    for (lv, sel) in lsel.iter().enumerate() {
        dir_want += *sel * idx_bits[lv];
        // The node's index at the level above: the leaf index's higher bits.
        let mut p = F::ZERO;
        for (i, bit) in idx_bits.iter().enumerate().skip(lv + 1) {
            p += *bit * pow2::<F>(i - lv - 1);
        }
        pos += *sel * p;
        level_plus_one += *sel * F::from_u32((lv + 1) as u32);
    }
    b.assert_zero(tree_start * (dir - dir_want));
    b.when_transition(tree_start * (n[COL_DIR] - dir));
    for i in 0..DIGEST {
        b.when_transition(nt(t.tree_start) * (n[c.node(i)] - l[COL_ACC + i]));
        b.when_transition((one - nt(t.tree_start)) * (n[c.node(i)] - l[c.node(i)]));
        b.when_transition(tree_start * (n[c.sib(i)] - l[c.sib(i)]));
        let node = l[c.node(i)];
        let sib = l[c.sib(i)];
        b.assert_zero(tree_start * (l[COL_INPUT + i] - ((one - dir) * node + dir * sib)));
        b.assert_zero(tree_abs * (l[COL_DATA + i] - ((one - dir) * sib + dir * node)));
    }
    let tree_cap =
        [pub_seed[0], pub_seed[1], pub_seed[2], pub_seed[3], F::from_u32(DOM_TREE), pos, height, level_plus_one];
    for (j, cc) in tree_cap.iter().enumerate() {
        b.assert_zero(tree_start * (l[COL_INPUT + RATE + j] - *cc));
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

/// The fragment's register state, written to every row.
#[derive(Clone, Debug)]
pub struct Regs {
    pub pub_seed: [Fp; PUB_SEED_LEN],
    pub idx_bits: [Fp; MAX_HEIGHT],
    /// The key's tree height, 1 to `MAX_HEIGHT` (0 before any signature).
    pub height: usize,
    pub m: Digest,
    pub sp: [Fp; WIDTH],
    pub node: Digest,
    pub sib: Digest,
    pub csum: u32,
    pub ksel: usize,
    pub esel: usize,
    pub rem: u32,
}

impl Default for Regs {
    fn default() -> Regs {
        Regs {
            pub_seed: [Fp::ZERO; PUB_SEED_LEN],
            idx_bits: [Fp::ZERO; MAX_HEIGHT],
            height: 1,
            m: [Fp::ZERO; DIGEST],
            sp: [Fp::ZERO; WIDTH],
            node: [Fp::ZERO; DIGEST],
            sib: [Fp::ZERO; DIGEST],
            csum: 0,
            ksel: 0,
            esel: 0,
            rem: 0,
        }
    }
}

impl Regs {
    pub fn write(&self, row: &mut [Fp], c: &Cols) {
        row[c.pub_seed(0)..c.pub_seed(PUB_SEED_LEN)].copy_from_slice(&self.pub_seed);
        row[c.idx(0)..c.idx(MAX_HEIGHT)].copy_from_slice(&self.idx_bits);
        row[c.hsel(self.height - 1)] = Fp::ONE;
        row[c.m(0)..c.m(DIGEST)].copy_from_slice(&self.m);
        row[c.sp(0)..c.sp(WIDTH)].copy_from_slice(&self.sp);
        row[c.node(0)..c.node(DIGEST)].copy_from_slice(&self.node);
        row[c.sib(0)..c.sib(DIGEST)].copy_from_slice(&self.sib);
        row[c.csum()] = Fp::new(self.csum);
        row[c.ksel(self.ksel)] = Fp::ONE;
        row[c.esel(self.esel)] = Fp::ONE;
        row[c.last()] = Fp::new((self.esel == ELEMENTS - 1 && self.ksel == CSUM_CHAINS - 1) as u32);
        row[c.rem()] = Fp::new(self.rem);
    }
}

/// Writes the 31-bit decomposition of `value`, its top-digit flag and the
/// digit column, which must hold the digit the row's digit index (`ksel`)
/// selects.
pub fn write_bits(row: &mut [Fp], c: &Cols, value: u32, ksel: usize) {
    for i in 0..BITS {
        row[c.bits(i)] = Fp::new((value >> i) & 1);
    }
    row[c.t3()] = Fp::new(((value >> 28) & 7 == 7) as u32);
    let width = if ksel == DIGITS_PER_ELEMENT - 1 { 3 } else { 4 };
    row[c.d()] = Fp::new((value >> (4 * ksel)) & ((1 << width) - 1));
}

/// The tweakable capacity of the XMSS sponge.
pub fn cap(pub_seed: &[Fp; PUB_SEED_LEN], domain: u32, index: u64, extra: u32) -> [Fp; DIGEST] {
    let mut c = [Fp::ZERO; DIGEST];
    c[..PUB_SEED_LEN].copy_from_slice(pub_seed);
    c[PUB_SEED_LEN] = Fp::new(domain);
    c[PUB_SEED_LEN + 1] = Fp::new((index & MASK30) as u32);
    c[PUB_SEED_LEN + 2] = Fp::new((index >> 30) as u32);
    c[PUB_SEED_LEN + 3] = Fp::new(extra);
    c
}

/// Pushes the rows verifying `sig` on `msg` under `pk`, from the message
/// rows to the last tree row. `finish` is called on every row after the
/// fragment has filled its own columns, with the register state the row
/// carries, so the enclosing circuit can write its registers. Returns the
/// key root reached, which must be `pk.root`.
#[allow(clippy::too_many_arguments)]
pub fn generate(
    b: &mut HashTraceBuilder,
    regs: &mut Regs,
    c: &Cols,
    t: &Types,
    msg: &Digest,
    sig: &Sig,
    pk: &PublicKey,
    finish: &mut dyn FnMut(&mut [Fp], &Regs),
) -> Digest {
    let ps = pk.pub_seed;
    let idx = sig.index;
    let h = pk.height();
    assert!((1..=MAX_HEIGHT).contains(&h) && sig.height() == h, "signature and key heights differ");
    assert!(idx < 1 << h);
    regs.pub_seed = ps;
    regs.height = h;
    regs.idx_bits = core::array::from_fn(|i| Fp::new(((idx >> i) & 1) as u32));
    regs.csum = 0;
    regs.ksel = DIGITS_PER_ELEMENT - 1;
    regs.esel = ELEMENTS - 1;
    regs.sp = [Fp::ZERO; WIDTH];
    regs.sp[RATE..].copy_from_slice(&cap(&ps, DOM_WOTS_PK, idx, 0));

    // message digest sponge
    let mut input = [Fp::ZERO; WIDTH];
    input[..RATE].copy_from_slice(&sig.randomizer);
    input[RATE..].copy_from_slice(&cap(&ps, DOM_MSG, idx, 0));
    b.start(input);
    {
        let row = b.last_row_mut();
        row[t.msg_start] = Fp::ONE;
        regs.write(row, c);
        finish(row, regs);
    }
    let mut block0 = [Fp::ZERO; RATE];
    block0[0] = Fp::from_u32(DIGEST as u32);
    block0[1..].copy_from_slice(&msg[..RATE - 1]);
    b.absorb(block0);
    {
        let row = b.last_row_mut();
        row[t.msg_abs] = Fp::ONE;
        regs.write(row, c);
        finish(row, regs);
    }
    let mut block1 = [Fp::ZERO; RATE];
    block1[0] = msg[DIGEST - 1];
    b.absorb(block1);
    {
        let row = b.last_row_mut();
        row[t.msg_abs] = Fp::ONE;
        row[c.mc()] = Fp::ONE;
        regs.write(row, c);
        finish(row, regs);
    }
    let m = b.acc();
    regs.m = m;
    let digs = digits(&m);

    for (ch, &digit) in digs.iter().enumerate() {
        let wrap = regs.ksel == DIGITS_PER_ELEMENT - 1;
        regs.ksel = (regs.ksel + 1) % DIGITS_PER_ELEMENT;
        if wrap {
            regs.esel = (regs.esel + 1) % ELEMENTS;
        }
        let d = digit as u32;
        regs.rem = d;
        b.load(sig.wots[ch]);
        {
            let elem = if regs.esel < DIGEST { m[regs.esel].to_canonical() } else { regs.csum };
            let row = b.last_row_mut();
            row[t.load] = Fp::ONE;
            write_bits(row, c, elem, regs.ksel);
            debug_assert_eq!(row[c.d()], Fp::new(d));
            regs.write(row, c);
            finish(row, regs);
        }
        if ch < MSG_CHAINS {
            regs.csum += (W as u32 - 1) - d;
        }
        for step in 0..STEPS {
            let active = regs.rem == 0;
            if active {
                b.chain(cap(&ps, DOM_WOTS_CHAIN, idx, ch as u32 | (step as u32) << 16));
            } else {
                b.pass();
            }
            {
                let rem = regs.rem;
                let row = b.last_row_mut();
                row[t.step] = Fp::ONE;
                row[c.ssel(step)] = Fp::ONE;
                row[c.active()] = Fp::new(active as u32);
                row[c.rem_inv()] = if active { Fp::ZERO } else { Fp::new(rem).inverse().unwrap() };
                regs.write(row, c);
                finish(row, regs);
            }
            if !active {
                regs.rem -= 1;
            }
        }
        let end = b.acc();
        let mut input = regs.sp;
        for (s, x) in input.iter_mut().zip(&end) {
            *s = s.add(x);
        }
        b.start(input);
        {
            let row = b.last_row_mut();
            row[t.leaf] = Fp::ONE;
            regs.write(row, c);
            finish(row, regs);
        }
        regs.sp = b.state();
    }

    // tree levels
    let mut index = idx;
    for level in 0..h {
        let right = index & 1 == 1;
        index >>= 1;
        regs.node = b.acc();
        regs.sib = sig.auth_path[level];
        let (left_v, right_v) = if right { (regs.sib, regs.node) } else { (regs.node, regs.sib) };
        let mut input = [Fp::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&left_v);
        input[RATE..].copy_from_slice(&cap(&ps, DOM_TREE, (h as u64) << 30 | index, (level + 1) as u32));
        b.start(input);
        {
            let row = b.last_row_mut();
            row[t.tree_start] = Fp::ONE;
            row[c.lsel(level)] = Fp::ONE;
            row[c.tlast()] = Fp::new((level + 1 == h) as u32);
            row[COL_DIR] = Fp::new(right as u32);
            regs.write(row, c);
            finish(row, regs);
        }
        b.absorb(right_v);
        {
            let row = b.last_row_mut();
            row[t.tree_abs] = Fp::ONE;
            row[c.lsel(level)] = Fp::ONE;
            row[c.tlast()] = Fp::new((level + 1 == h) as u32);
            row[COL_DIR] = Fp::new(right as u32);
            regs.write(row, c);
            finish(row, regs);
        }
    }
    let root = b.acc();
    crate::stark::refuse(root == pk.root, "signature does not verify under the given key");
    root
}
