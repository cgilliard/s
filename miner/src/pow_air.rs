//! The work segment: a header's proof of work, proven (docs/NODE.md, the
//! work in the chain proof). Each block's root verifies its parent's
//! (`aggregate::Output::Statement`), against the block statement's
//! `parent_work`.
//!
//! One proof of four tables shows that `hashimoto` (see [`crate::pow`]),
//! its items computed from the seed file, gives the mix it gives:
//!
//! - **perm**: the hash machine ([`crate::hash_machine`]), one permutation a
//!   row. Three seed rows (a start with the header hash and `DOM_SEED`,
//!   then the nonce's two blocks absorbed), then for each dataset item a
//!   start `[index, DOM_ITEM]` and exactly `parents` absorbs of windows (a
//!   counter). On each absorb, the window's index
//!   `w = (out0 + out1 * 2^31) mod N`, from the previous permutation's
//!   output, is proven in 10-bit limbs (both outputs shown canonical, the
//!   quotient and remainder decomposed, the carries ranged, `w < N`), and
//!   the window it absorbs is looked up in the text table. An item's final
//!   output is offered under its index.
//! - **text**: the windows of the seed file at 24-byte boundaries
//!   (`N` = 53,795, a table of 2^16 rows), a preprocessed table
//!   `[w, eight packed elements]` committed once, and how often each is
//!   read.
//! - **mix**: hashimoto's accesses: each row derives a pair's index from
//!   the mix (the low 19 bits of a canonical value), takes its two items
//!   from perm and folds them in (`fnv`), and reads one window directly: its
//!   index from a second canonical value ([`crate::pow::direct_window`]: the
//!   low `L` bits, less `N` once if they are `N` or more, `w < N` in limbs),
//!   looked up in the text table and added to the mix.
//! - **range**: 0 to 1023, for the limbs.
//!
//! The public values are the header's `pow_hash` (8 elements), its nonce
//! (11) and its `mix` (8): the mix after the 64 accesses, folded to eight
//! elements, must be the header's. That the result from the mix meets the
//! target is left to the native check (`Header::quick_pow_check`, two
//! permutations): the proof supplies the expensive fact, that the `mix` is
//! the true one.

use crate::field::Field;
use crate::hash_machine::{
    COL_ABSORB, COL_CHAIN, COL_COMPRESS, COL_DATA, COL_LOAD, COL_START, HashTraceBuilder, NUM_COLS as HM_COLS,
    eval_hash_machine,
};
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH};
use crate::poseidon2_air::{COL_INPUT, COL_OUTPUT};
use crate::stark::{Air, Builder, Trace};

const LIMB: u32 = 1 << 10;
const TAG_ITEM: u32 = 1;
const TAG_SEED: u32 = 2;
const TAG_RANGE: u32 = 3;
const TAG_TEXT: u32 = 4;
const DOM_ITEM: u32 = 0x5041;
const DOM_SEED: u32 = 0x5042;
const FNV_PRIME: u32 = 0x0100_0193;
const WINDOW: usize = 3 * RATE;
/// `p - 2^30 - 1`: the largest low 30 bits of a canonical element whose
/// bit 30 is set.
const CANON_LOW: u32 = 0x3800_0000;
const MIX_WORDS: usize = 2 * WIDTH;
/// The public values: `pow_hash`, the nonce's 11 elements, the `mix`.
pub const PUB_HASH: usize = 0;
pub const PUB_NONCE: usize = DIGEST;
pub const PUB_MIX: usize = PUB_NONCE + 11;
pub const NUM_PUBLIC: usize = PUB_MIX + DIGEST;
/// The work segment's transcript domain (the other proofs': 0x30 to 0x34).
pub const DOM_WORK_PROOF: u32 = 0x35;

/// How the windows are laid out: window `w` is the 24 bytes from
/// `w * stride` (the last no later than a window's length before the
/// text's end), for `w < n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Windows {
    pub stride: usize,
    pub n: usize,
}

impl Windows {
    /// At 24-byte boundaries, the last ending at the text's end: the proof
    /// of work ([`crate::pow::SeedText::windows`]).
    pub fn aligned(text_len: usize) -> Windows {
        Windows { stride: WINDOW, n: text_len.div_ceil(WINDOW) }
    }

    fn limbs(v: u32) -> [u32; 3] {
        [v % LIMB, (v / LIMB) % LIMB, v / (LIMB * LIMB)]
    }
}

/// Packs 24 bytes three to an element, little-endian.
fn pack_window(window: &[u8]) -> [Fp; RATE] {
    core::array::from_fn(|k| {
        let c = &window[3 * k..3 * k + 3];
        Fp::new(c[0] as u32 | (c[1] as u32) << 8 | (c[2] as u32) << 16)
    })
}

fn fnv(a: Fp, b: Fp) -> Fp {
    a.mul(&Fp::new(FNV_PRIME)).add(&b)
}

// ---------------------------------------------------------------------------
// perm: the permutations
// ---------------------------------------------------------------------------

const P_S0: usize = HM_COLS;
const P_S1: usize = P_S0 + 1;
const P_S2: usize = P_S0 + 2;
const P_IS: usize = P_S0 + 3;
const P_IA: usize = P_S0 + 4;
const P_LAST: usize = P_S0 + 5;
const P_K: usize = P_S0 + 6;
const P_CUR: usize = P_S0 + 7;
const P_PA0: usize = P_S0 + 8;
const P_PA1: usize = P_S0 + 9;
const P_A: usize = P_S0 + 10; // a0..a3
const P_B: usize = P_A + 4; // b0..b3
const P_DA: usize = P_B + 4; // 3
const P_DB: usize = P_DA + 3; // 3
const P_Q: usize = P_DB + 3; // 5
const P_W: usize = P_Q + 5; // 3
const P_D: usize = P_W + 3; // 3
const P_E: usize = P_D + 3; // 2
const P_C: usize = P_E + 2; // 6 low limbs of the carries
const P_CH: usize = P_C + 6; // 6 x 4 high bits
pub const PERM_COLS: usize = P_CH + 24;
const CARRY_BIAS: i64 = 1 << 13;

/// The perm table's AIR for windows numbered below `n` and `parents`
/// absorbs an item (the proof of work has 256; 254 fits 2^15 rows).
pub struct PermAir {
    pub windows: Windows,
    pub parents: usize,
}

impl PermAir {
    /// The limbs every row ranges.
    fn range_cols() -> impl Iterator<Item = usize> {
        (P_A..P_A + 3)
            .chain(P_B..P_B + 3)
            .chain(P_DA..P_DA + 3)
            .chain(P_DB..P_DB + 3)
            .chain(P_Q..P_Q + 5)
            .chain(P_W..P_W + 3)
            .chain(P_D..P_D + 3)
            .chain(P_C..P_C + 6)
    }
}

fn lin<F: Field>(l: &[F], at: usize, n: usize) -> F {
    (0..n).rev().fold(F::ZERO, |acc, i| acc.scale(Fp::new(LIMB)) + l[at + i])
}

impl Air for PermAir {
    fn width(&self) -> usize {
        PERM_COLS
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn lookup_group(&self) -> usize {
        2
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        eval_hash_machine(b);
        let l = b.local();
        let n = b.next();
        let p = b.public();
        let one = F::ONE;
        let c = |v: u32| F::from_u32(v);
        b.mark("pow flags");
        let (s0, s1, s2, is, ia, last) = (l[P_S0], l[P_S1], l[P_S2], l[P_IS], l[P_IA], l[P_LAST]);
        for f in [s0, s1, s2, is, ia, last] {
            b.assert_zero(f * f - f);
        }
        b.assert_zero(l[COL_CHAIN]);
        b.assert_zero(l[COL_COMPRESS]);
        b.assert_zero(l[COL_LOAD]);
        b.assert_eq(l[COL_START], s0 + is);
        b.assert_eq(l[COL_ABSORB], s1 + s2 + ia);
        // The seed: rows 0, 1, 2.
        b.when_first_row(s0 - one);
        b.when_transition(n[P_S0]);
        b.when_transition(n[P_S1] - s0);
        b.when_transition(n[P_S2] - s1);
        b.mark("pow seed");
        for k in 0..DIGEST {
            b.assert_zero(s0 * (l[COL_INPUT + k] - p[k]));
        }
        b.assert_zero(s0 * (l[COL_INPUT + DIGEST] - c(DOM_SEED)));
        for k in DIGEST + 1..WIDTH {
            b.assert_zero(s0 * l[COL_INPUT + k]);
        }
        for k in 0..RATE {
            b.assert_zero(s1 * (l[COL_DATA + k] - p[DIGEST + k]));
            let block2 = if k < 3 { p[DIGEST + RATE + k] } else { F::ZERO };
            b.assert_zero(s2 * (l[COL_DATA + k] - block2));
        }
        // An item: a start, then exactly 256 absorbs.
        b.mark("pow items");
        b.assert_zero(is * (l[COL_INPUT] - l[P_CUR]));
        b.assert_zero(is * (l[COL_INPUT + 1] - c(DOM_ITEM)));
        for k in 2..WIDTH {
            b.assert_zero(is * l[COL_INPUT + k]);
        }
        b.assert_zero(is * l[P_K]);
        let it = is + ia;
        b.when_transition(n[P_IA] * (one - it));
        b.when_transition(n[P_IA] * (n[P_K] - l[P_K] - one));
        b.when_transition(n[P_IA] * (n[P_CUR] - l[P_CUR]));
        b.when_transition(n[P_IA] * last);
        b.assert_zero(last * (l[P_K] - c(self.parents as u32)));
        b.assert_zero(last * (one - ia));
        b.when_transition(it * (one - last) * (one - n[P_IA]));
        b.when_last_row(it - last);
        b.when_transition(n[P_IA] * (n[P_PA0] - l[COL_OUTPUT]));
        b.when_transition(n[P_IA] * (n[P_PA1] - l[COL_OUTPUT + 1]));
        // The window: w = (pa0 + pa1 * 2^31) mod N, in 10-bit limbs.
        b.mark("pow window");
        for x in [P_A + 3, P_B + 3, P_E, P_E + 1] {
            b.assert_zero(l[x] * l[x] - l[x]);
        }
        for k in 0..24 {
            let h = l[P_CH + k];
            b.assert_zero(h * h - h);
        }
        b.assert_zero(ia * (l[P_PA0] - lin(l, P_A, 4)));
        b.assert_zero(ia * (l[P_PA1] - lin(l, P_B, 4)));
        // Canonical: with bit 30 set, the low 30 bits at most CANON_LOW.
        b.assert_zero(ia * (lin(l, P_DA, 3) - l[P_A + 3] * (c(CANON_LOW) - lin(l, P_A, 3))));
        b.assert_zero(ia * (lin(l, P_DB, 3) - l[P_B + 3] * (c(CANON_LOW) - lin(l, P_B, 3))));
        let nl = Windows::limbs(self.windows.n as u32);
        let r = [
            l[P_A],
            l[P_A + 1],
            l[P_A + 2],
            l[P_A + 3] + l[P_B].scale(Fp::new(2)),
            l[P_B + 1].scale(Fp::new(2)),
            l[P_B + 2].scale(Fp::new(2)),
            l[P_B + 3].scale(Fp::new(2)),
        ];
        let carry = |k: usize| -> F {
            let hi = (0..4).fold(F::ZERO, |acc, j| acc + l[P_CH + 4 * k + j].scale(Fp::new(1 << j)));
            l[P_C + k] + hi.scale(Fp::new(LIMB)) - c(CARRY_BIAS as u32)
        };
        let mut prev = F::ZERO;
        for k in 0..7 {
            let mut ck = if k < 3 { l[P_W + k] } else { F::ZERO };
            for (j, nj) in nl.iter().enumerate() {
                if k >= j && k - j < 5 {
                    ck += l[P_Q + k - j].scale(Fp::new(*nj));
                }
            }
            let out = if k < 6 { carry(k).scale(Fp::new(LIMB)) } else { F::ZERO };
            b.assert_zero(ia * (ck - r[k] + prev - out));
            if k < 6 {
                prev = carry(k);
            }
        }
        // w < N: w + d = N - 1.
        let m = Windows::limbs(self.windows.n as u32 - 1);
        b.assert_zero(ia * (l[P_W] + l[P_D] - c(m[0]) - l[P_E].scale(Fp::new(LIMB))));
        b.assert_zero(ia * (l[P_W + 1] + l[P_D + 1] + l[P_E] - c(m[1]) - l[P_E + 1].scale(Fp::new(LIMB))));
        b.assert_zero(ia * (l[P_W + 2] + l[P_D + 2] + l[P_E + 1] - c(m[2])));
        // The buses.
        let w = lin(l, P_W, 3);
        let mut text = vec![c(TAG_TEXT), w];
        text.extend((0..RATE).map(|k| l[COL_DATA + k]));
        b.lookup(true, ia, &text);
        let mut item = vec![c(TAG_ITEM), l[P_CUR]];
        item.extend((0..WIDTH).map(|k| l[COL_OUTPUT + k]));
        b.lookup(true, last, &item);
        let mut seed = vec![c(TAG_SEED)];
        seed.extend((0..WIDTH).map(|k| l[COL_OUTPUT + k]));
        b.lookup(true, s2, &seed);
        for x in Self::range_cols() {
            b.lookup(true, one, &[c(TAG_RANGE), l[x]]);
        }
    }
}

// ---------------------------------------------------------------------------
// text, range, mix
// ---------------------------------------------------------------------------

/// The windows: preprocessed `[w, packed[8]]`, and the reads of each.
pub struct TextAir;

impl Air for TextAir {
    fn width(&self) -> usize {
        1
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn preprocessed_width(&self) -> usize {
        1 + RATE
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let pre = b.preprocessed();
        let m = b.local()[0];
        let mut v = vec![F::from_u32(TAG_TEXT)];
        v.extend_from_slice(&pre[..1 + RATE]);
        b.lookup(false, m, &v);
    }
}

/// 0 to 1023, and how often each is ranged.
pub struct RangeAir;

impl Air for RangeAir {
    fn width(&self) -> usize {
        2
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let l = b.local();
        let n = b.next();
        b.when_first_row(l[0]);
        b.when_transition(n[0] - l[0] - F::ONE);
        b.lookup(false, l[1], &[F::from_u32(TAG_RANGE), l[0]]);
    }
}

const M_FIRST: usize = 0;
const M_I: usize = 1;
const M_IB: usize = 2; // 7 bits of I
const M_SEED0: usize = M_IB + 7;
const M_MIX: usize = M_SEED0 + 1; // 32
const M_OH: usize = M_MIX + MIX_WORDS; // 32
const M_SB: usize = M_OH + MIX_WORDS; // 31 bits of sel
const M_T: usize = M_SB + 31; // 3 helpers
const M_A: usize = M_T + 3; // 16
const M_BB: usize = M_A + WIDTH; // 16
const M_FIN: usize = M_BB + WIDTH; // the row after the last access
const M_SEED1: usize = M_FIN + 1;
const M_SB2: usize = M_SEED1 + 1; // 31 bits of the direct read's selector
const M_T2: usize = M_SB2 + 31; // 3 helpers
const M_WF: usize = M_T2 + 3; // the low bits were N or more
const M_WL: usize = M_WF + 1; // 2 limbs of its window
const M_WD: usize = M_WL + 2; // 2 limbs of N - 1 - w
const M_X: usize = M_WD + 2; // the window, 8 packed elements
pub const MIX_COLS: usize = M_X + RATE;
const MIX_ROWS: usize = 128;

/// hashimoto's accesses, one a row (64 active rows of 128).
pub struct MixAir {
    /// The dataset's pairs of items: `2^log_pairs` (`2^19` on mainnet).
    pub log_pairs: u32,
    /// The seed file's windows, `N`: at most 2^20.
    pub windows: usize,
}

/// A canonical value's 31 bits, from `bits`: binary, summing to `v`, and
/// with bits 30 to 27 all set the rest zero (`t`, three helpers).
fn canonical_bits<F: Field>(b: &mut Builder<'_, F>, v: F, bits: &[F], t: &[F]) {
    for x in bits {
        b.assert_zero(*x * *x - *x);
    }
    b.assert_eq(v, (0..31).fold(F::ZERO, |acc, k| acc + bits[k].scale(Fp::from_u32(1 << k))));
    b.assert_eq(t[0], bits[30] * bits[29]);
    b.assert_eq(t[1], bits[28] * bits[27]);
    b.assert_eq(t[2], t[0] * t[1]);
    b.assert_zero(t[2] * (0..27).fold(F::ZERO, |acc, k| acc + bits[k]));
}

impl Air for MixAir {
    fn width(&self) -> usize {
        MIX_COLS
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn lookup_group(&self) -> usize {
        2
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let l = b.local();
        let n = b.next();
        let one = F::ONE;
        let c = |v: u32| F::from_u32(v);
        b.when_first_row(l[M_FIRST] - one);
        b.when_transition(n[M_FIRST]);
        b.when_first_row(l[M_I]);
        b.when_transition(n[M_I] - l[M_I] - one);
        for k in 0..7 {
            let x = l[M_IB + k];
            b.assert_zero(x * x - x);
        }
        b.assert_eq(l[M_I], (0..7).fold(F::ZERO, |acc, k| acc + l[M_IB + k].scale(Fp::new(1 << k))));
        let act = one - l[M_IB + 6];
        // The seed fills both halves of the first mix; seed0 is kept.
        for k in 0..WIDTH {
            b.when_first_row(l[M_MIX + WIDTH + k] - l[M_MIX + k]);
        }
        b.when_first_row(l[M_SEED0] - l[M_MIX]);
        b.when_transition(n[M_SEED0] - l[M_SEED0]);
        // mix[i % 32] by a rotating one-hot.
        b.when_first_row(l[M_OH] - one);
        for k in 1..MIX_WORDS {
            b.when_first_row(l[M_OH + k]);
        }
        for k in 0..MIX_WORDS {
            b.when_transition(n[M_OH + (k + 1) % MIX_WORDS] - l[M_OH + k]);
        }
        let picked = (0..MIX_WORDS).fold(F::ZERO, |acc, k| acc + l[M_OH + k] * l[M_MIX + k]);
        let sel = (l[M_I] + l[M_SEED0]).scale(Fp::new(FNV_PRIME)) + picked;
        // sel in bits, canonical: bits 30..27 all set leave the rest zero.
        canonical_bits(b, sel, &l[M_SB..M_SB + 31], &l[M_T..M_T + 3]);
        let idx = (0..self.log_pairs as usize).fold(F::ZERO, |acc, k| acc + l[M_SB + k].scale(Fp::new(2 << k)));
        // The direct read: sel2 = fnv(i + seed1, mix[(i + 16) % 32]) in bits,
        // canonical; its low L bits, less N once if they are N or more, are
        // the window: 0 <= w < N in limbs.
        b.when_first_row(l[M_SEED1] - l[M_MIX + 1]);
        b.when_transition(n[M_SEED1] - l[M_SEED1]);
        let picked2 = (0..MIX_WORDS).fold(F::ZERO, |acc, k| acc + l[M_OH + k] * l[M_MIX + (k + WIDTH) % MIX_WORDS]);
        let sel2 = (l[M_I] + l[M_SEED1]).scale(Fp::new(FNV_PRIME)) + picked2;
        canonical_bits(b, sel2, &l[M_SB2..M_SB2 + 31], &l[M_T2..M_T2 + 3]);
        let bits = (self.windows as u32).next_power_of_two().trailing_zeros() as usize;
        let low = (0..bits).fold(F::ZERO, |acc, k| acc + l[M_SB2 + k].scale(Fp::new(1 << k)));
        let wf = l[M_WF];
        b.assert_zero(wf * wf - wf);
        let w = l[M_WL] + l[M_WL + 1].scale(Fp::new(LIMB));
        b.assert_eq(w, low - wf.scale(Fp::new(self.windows as u32)));
        b.assert_eq(l[M_WD] + l[M_WD + 1].scale(Fp::new(LIMB)), c(self.windows as u32 - 1) - w);
        // The two items folded in, and the window added.
        for k in 0..MIX_WORDS {
            let d = if k < WIDTH { l[M_A + k] } else { l[M_BB + k - WIDTH] };
            let x = l[M_X + k % RATE];
            b.when_transition(
                n[M_MIX + k] - l[M_MIX + k] - act * (l[M_MIX + k].scale(Fp::new(FNV_PRIME - 1)) + d + x),
            );
        }
        // The row after the 64th access holds the final mix: folded to eight
        // elements (fnv is linear), the header's.
        b.when_first_row(l[M_FIN]);
        b.when_transition(n[M_FIN] - (n[M_IB + 6] - l[M_IB + 6]));
        let p = b.public();
        let f = Fp::new(FNV_PRIME);
        for k in 0..DIGEST {
            let w = &l[M_MIX + 4 * k..M_MIX + 4 * k + 4];
            let folded = ((w[0].scale(f) + w[1]).scale(f) + w[2]).scale(f) + w[3];
            b.assert_zero(l[M_FIN] * (folded - p[PUB_MIX + k]));
        }
        let mut seed = vec![c(TAG_SEED)];
        seed.extend((0..WIDTH).map(|k| l[M_MIX + k]));
        b.lookup(false, l[M_FIRST], &seed);
        let mut a = vec![c(TAG_ITEM), idx];
        a.extend((0..WIDTH).map(|k| l[M_A + k]));
        b.lookup(false, act, &a);
        let mut bb = vec![c(TAG_ITEM), idx + one];
        bb.extend((0..WIDTH).map(|k| l[M_BB + k]));
        b.lookup(false, act, &bb);
        let mut text = vec![c(TAG_TEXT), w];
        text.extend((0..RATE).map(|k| l[M_X + k]));
        b.lookup(true, act, &text);
        for x in Self::range_cols() {
            b.lookup(true, act, &[c(TAG_RANGE), l[x]]);
        }
    }
}

impl MixAir {
    /// The limbs an active row ranges.
    fn range_cols() -> [usize; 4] {
        [M_WL, M_WL + 1, M_WD, M_WD + 1]
    }
}

// ---------------------------------------------------------------------------
// The witness
// ---------------------------------------------------------------------------

/// The four traces of one header's proof of work, the text's preprocessed
/// table, the public values and the folded mix.
pub struct PowWitness {
    pub text_pre: Trace,
    pub text: Trace,
    pub perm: Trace,
    pub range: Trace,
    pub mix: Trace,
    pub public: Vec<Fp>,
    pub mix_out: [Fp; MIX_WORDS],
}

/// What a proof of work's circuit depends on: the text's window layout, the
/// absorbs an item and the dataset's size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkShape {
    pub windows: Windows,
    pub parents: usize,
    /// `2^log_pairs` pairs of items.
    pub log_pairs: u32,
}

impl WorkShape {
    /// The proof of work's, for `seed` (aligned windows).
    pub fn of(seed: &crate::pow::SeedText) -> WorkShape {
        let params = crate::pow::ItemSource::params(seed);
        WorkShape {
            windows: Windows::aligned(seed.text().len()),
            parents: params.parents,
            log_pairs: params.log_dataset_items - 1,
        }
    }

    pub fn perm_air(&self) -> PermAir {
        PermAir { windows: self.windows, parents: self.parents }
    }

    pub fn mix_air(&self) -> MixAir {
        assert!(self.windows.n <= 1 << 20, "the direct read's window is ranged in two limbs");
        MixAir { log_pairs: self.log_pairs, windows: self.windows.n }
    }
}

/// A way to cheat, for the attack tests: the witness generator, made
/// lenient, writes the trace as a cheating prover would, everything after
/// the cheat computed from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cheat {
    None,
    /// Absorbs the next window while showing the true index.
    OtherWindow,
    /// Shows the next index (and absorbs its window) with the true quotient.
    OtherIndex,
    /// Absorbs the true window with an element changed.
    OtherText,
    /// An item of one parent too few, or too many.
    FewerParents,
    MoreParents,
    /// The first access's first item computed for another index.
    OtherItem,
    /// The first access picks another pair than its selector's bits.
    OtherPair,
    /// An output decomposed as itself plus p, where that fits 31 bits.
    NonCanonical,
    /// A window index past N (and so a padding row's zeros), the quotient one
    /// less.
    BeyondN,
    /// Another mix claimed, or another header hash.
    WrongMix,
    WrongHash,
    /// The first access adds the next window while showing the true index.
    OtherDirect,
    /// A direct read whose low bits are N or more taken unreduced, the
    /// table's padding row (zeros) read.
    DirectUnreduced,
}

/// hashimoto's mix, its items computed from the seed file, with `parents`
/// absorbs an item and windows laid out as `windows`, and the traces that
/// prove it.
pub fn witness(text: &[u8], shape: WorkShape, header_hash: &[Fp; DIGEST], nonce: &[u8; 32]) -> PowWitness {
    witness_cheating(text, shape, header_hash, nonce, Cheat::None)
}

/// [`witness`], cheating as `cheat` says (tests, with the generator lenient).
pub fn witness_cheating(
    text: &[u8],
    shape: WorkShape,
    header_hash: &[Fp; DIGEST],
    nonce: &[u8; 32],
    cheat: Cheat,
) -> PowWitness {
    use crate::stark::refuse;
    let (windows, parents) = (shape.windows, shape.parents);
    let n_text = windows.n.next_power_of_two();
    let window = |w: usize| {
        let at = (w * windows.stride).min(text.len() - WINDOW);
        pack_window(&text[at..at + WINDOW])
    };
    let mut reads = vec![0u32; n_text];
    let mut ranged = vec![0u32; LIMB as usize];
    let mut perm = HashTraceBuilder::new(PERM_COLS);

    // The seed.
    let packed: Vec<Fp> = nonce
        .chunks(3)
        .map(|ch| Fp::new(ch.iter().enumerate().fold(0u32, |a, (i, x)| a | (*x as u32) << (8 * i))))
        .collect();
    let mut input = [Fp::ZERO; WIDTH];
    input[..DIGEST].copy_from_slice(header_hash);
    input[DIGEST] = Fp::new(DOM_SEED);
    perm.start(input);
    perm.last_row_mut()[P_S0] = Fp::ONE;
    for (j, block) in packed.chunks(RATE).enumerate() {
        let mut data = [Fp::ZERO; RATE];
        data[..block.len()].copy_from_slice(block);
        perm.absorb(data);
        perm.last_row_mut()[if j == 0 { P_S1 } else { P_S2 }] = Fp::ONE;
    }
    let seed = perm.state();

    // An item, its rows appended; `first` for the first access's first item,
    // where the cheats happen.
    let mut cheated = false;
    let mut item = |index: u32, first: bool, perm: &mut HashTraceBuilder, reads: &mut Vec<u32>| -> [Fp; WIDTH] {
        let index = if first && cheat == Cheat::OtherItem { index + 2 } else { index };
        let parents = match (first, cheat) {
            (true, Cheat::FewerParents) => parents - 1,
            (true, Cheat::MoreParents) => parents + 1,
            _ => parents,
        };
        let mut input = [Fp::ZERO; WIDTH];
        input[0] = Fp::from_u32(index);
        input[1] = Fp::new(DOM_ITEM);
        perm.start(input);
        {
            let row = perm.last_row_mut();
            row[P_IS] = Fp::ONE;
            row[P_CUR] = Fp::from_u32(index);
        }
        for k in 1..=parents {
            let st = perm.state();
            let (mut a, bv) = (st[0].to_canonical(), st[1].to_canonical());
            let here = first && !cheated && k >= 10;
            if here && cheat == Cheat::NonCanonical && (a as u64) + (crate::poseidon2::P as u64) < 1 << 31 {
                a += crate::poseidon2::P;
                cheated = true;
            }
            let r = a as u64 | (bv as u64) << 31;
            let mut w = (r % windows.n as u64) as u32;
            let mut q = r / windows.n as u64;
            let mut data = window(w as usize);
            let n_text = windows.n.next_power_of_two() as u32;
            if here {
                match cheat {
                    Cheat::OtherWindow => {
                        data = window((w as usize + 1) % windows.n);
                        cheated = true;
                    }
                    Cheat::OtherIndex => {
                        w = (w + 1) % windows.n as u32;
                        data = window(w as usize);
                        cheated = true;
                    }
                    Cheat::OtherText => {
                        data[0] = data[0].add(&Fp::ONE);
                        cheated = true;
                    }
                    Cheat::BeyondN if w + (windows.n as u32) < n_text && q > 0 => {
                        w += windows.n as u32;
                        q -= 1;
                        data = [Fp::ZERO; RATE];
                        cheated = true;
                    }
                    _ => {}
                }
            }
            refuse(a < crate::poseidon2::P, "the output is canonical");
            refuse((w as usize) < windows.n, "the window is in the text");
            perm.absorb(data);
            reads[w as usize] += 1;
            let row = perm.last_row_mut();
            row[P_IA] = Fp::ONE;
            row[P_K] = Fp::from_u32(k as u32);
            row[P_CUR] = Fp::from_u32(index);
            row[P_PA0] = st[0];
            row[P_PA1] = st[1];
            let limbs4 = |v: u32| [v % LIMB, (v >> 10) % LIMB, (v >> 20) % LIMB, v >> 30];
            let (al, bl) = (limbs4(a), limbs4(bv));
            for j in 0..4 {
                row[P_A + j] = Fp::new(al[j]);
                row[P_B + j] = Fp::new(bl[j]);
            }
            let diff = |l: [u32; 4]| if l[3] == 1 { CANON_LOW - (l[0] + l[1] * LIMB + l[2] * LIMB * LIMB) } else { 0 };
            for (at, d) in [(P_DA, diff(al)), (P_DB, diff(bl))] {
                for (j, x) in Windows::limbs(d).iter().enumerate() {
                    row[at + j] = Fp::new(*x);
                }
            }
            for j in 0..5 {
                row[P_Q + j] = Fp::new(((q >> (10 * j)) % LIMB as u64) as u32);
            }
            let wl = Windows::limbs(w);
            let m = Windows::limbs(windows.n as u32 - 1);
            let dl = Windows::limbs((windows.n as u32 - 1).wrapping_sub(w) & ((1 << 30) - 1));
            for j in 0..3 {
                row[P_W + j] = Fp::new(wl[j]);
                row[P_D + j] = Fp::new(dl[j]);
            }
            let e0 = (wl[0] as i64 + dl[0] as i64 - m[0] as i64).div_euclid(LIMB as i64);
            let e1 = (wl[1] as i64 + dl[1] as i64 + e0 - m[1] as i64).div_euclid(LIMB as i64);
            row[P_E] = Fp::from_u32(e0 as u32 & 1);
            row[P_E + 1] = Fp::from_u32(e1 as u32 & 1);
            let nl = Windows::limbs(windows.n as u32);
            let ql: Vec<i64> = (0..5).map(|j| ((q >> (10 * j)) % LIMB as u64) as i64).collect();
            let rl = [al[0], al[1], al[2], al[3] + 2 * bl[0], 2 * bl[1], 2 * bl[2], 2 * bl[3]];
            let mut prev = 0i64;
            for kk in 0..7 {
                let mut ck = if kk < 3 { wl[kk] as i64 } else { 0 };
                for (j, nj) in nl.iter().enumerate() {
                    if kk >= j && kk - j < 5 {
                        ck += ql[kk - j] * *nj as i64;
                    }
                }
                let v = ck - rl[kk] as i64 + prev;
                if kk < 6 {
                    refuse(v % LIMB as i64 == 0, "the limbs carry whole");
                    let carry = v.div_euclid(LIMB as i64);
                    let biased = ((carry + CARRY_BIAS) as u32) & ((1 << 14) - 1);
                    row[P_C + kk] = Fp::new(biased % LIMB);
                    for j in 0..4 {
                        row[P_CH + 4 * kk + j] = Fp::new((biased >> (10 + j)) & 1);
                    }
                    prev = carry;
                } else {
                    refuse(v == 0, "the last limb balances");
                }
            }
            if k == parents {
                row[P_LAST] = Fp::ONE;
            }
        }
        perm.state()
    };

    // The accesses, and the mix table beside them.
    let pairs = 1u32 << shape.log_pairs;
    let low_mask = (windows.n as u32).next_power_of_two() - 1;
    let mut unreduced = false;
    let mut mixv = [Fp::ZERO; MIX_WORDS];
    mixv[..WIDTH].copy_from_slice(&seed);
    mixv[WIDTH..].copy_from_slice(&seed);
    let mut mix_rows = vec![Fp::ZERO; MIX_ROWS * MIX_COLS];
    for i in 0..MIX_ROWS {
        let row = &mut mix_rows[i * MIX_COLS..(i + 1) * MIX_COLS];
        row[M_FIRST] = if i == 0 { Fp::ONE } else { Fp::ZERO };
        row[M_I] = Fp::from_u32(i as u32);
        for k in 0..7 {
            row[M_IB + k] = Fp::new((i as u32 >> k) & 1);
        }
        row[M_SEED0] = seed[0];
        row[M_MIX..M_MIX + MIX_WORDS].copy_from_slice(&mixv);
        row[M_OH + i % MIX_WORDS] = Fp::ONE;
        let sel = fnv(Fp::from_u32(i as u32).add(&seed[0]), mixv[i % MIX_WORDS]);
        let sv = sel.to_canonical();
        for k in 0..31 {
            row[M_SB + k] = Fp::new((sv >> k) & 1);
        }
        let sv = if i == 0 && cheat == Cheat::OtherPair { sv ^ 2 } else { sv };
        let bit = |k: usize| (sv >> k) & 1;
        row[M_T] = Fp::new(bit(30) * bit(29));
        row[M_T + 1] = Fp::new(bit(28) * bit(27));
        row[M_T + 2] = Fp::new(bit(30) * bit(29) * bit(28) * bit(27));
        row[M_FIN] = if i == 64 { Fp::ONE } else { Fp::ZERO };
        // The direct read.
        row[M_SEED1] = seed[1];
        let sel2 = fnv(Fp::from_u32(i as u32).add(&seed[1]), mixv[(i + WIDTH) % MIX_WORDS]);
        let s2 = sel2.to_canonical();
        for k in 0..31 {
            row[M_SB2 + k] = Fp::new((s2 >> k) & 1);
        }
        let bit2 = |k: usize| (s2 >> k) & 1;
        row[M_T2] = Fp::new(bit2(30) * bit2(29));
        row[M_T2 + 1] = Fp::new(bit2(28) * bit2(27));
        row[M_T2 + 2] = Fp::new(bit2(30) * bit2(29) * bit2(28) * bit2(27));
        let low = s2 & low_mask;
        let mut wrapped = low >= windows.n as u32;
        let mut wd = crate::pow::direct_window(s2, windows.n) as u32;
        let mut x = window(wd as usize);
        if i < 64 {
            if i == 0 && cheat == Cheat::OtherDirect {
                x = window((wd as usize + 1) % windows.n);
            }
            if wrapped && !unreduced && cheat == Cheat::DirectUnreduced {
                unreduced = true;
                wrapped = false;
                wd = low;
                x = [Fp::ZERO; RATE];
            }
        }
        row[M_WF] = Fp::new(wrapped as u32);
        let d = (windows.n as u32 - 1).wrapping_sub(wd) & ((1 << 20) - 1);
        for (at, v) in [(M_WL, wd), (M_WD, d)] {
            row[at] = Fp::new(v % LIMB);
            row[at + 1] = Fp::new(v / LIMB);
        }
        row[M_X..M_X + RATE].copy_from_slice(&x);
        if i < 64 {
            refuse((wd as usize) < windows.n, "the direct read is in the file");
            reads[wd as usize] += 1;
            for col in MixAir::range_cols() {
                if let Some(c) = ranged.get_mut(row[col].to_canonical() as usize) {
                    *c += 1;
                }
            }
            let idx = (sv % pairs) * 2;
            let a = item(idx, i == 0, &mut perm, &mut reads);
            let bv = item(idx + 1, false, &mut perm, &mut reads);
            row[M_A..M_A + WIDTH].copy_from_slice(&a);
            row[M_BB..M_BB + WIDTH].copy_from_slice(&bv);
            for (k, (m, d)) in mixv.iter_mut().zip(a.iter().chain(&bv)).enumerate() {
                *m = fnv(*m, *d).add(&x[k % RATE]);
            }
        }
    }

    // Pass rows to a power of two; every row's limbs ranged.
    let perm_trace = perm.finish();
    for i in 0..perm_trace.height() {
        let row = perm_trace.row(i);
        for x in PermAir::range_cols() {
            // A limb out of range (only a cheat's) has no row to count on:
            // its lookup goes unanswered.
            if let Some(c) = ranged.get_mut(row[x].to_canonical() as usize) {
                *c += 1;
            }
        }
    }

    let mut pre = vec![Fp::ZERO; n_text * (1 + RATE)];
    let mut text_main = vec![Fp::ZERO; n_text];
    for w in 0..n_text {
        pre[w * (1 + RATE)] = Fp::from_u32(w as u32);
        if w < windows.n {
            pre[w * (1 + RATE) + 1..(w + 1) * (1 + RATE)].copy_from_slice(&window(w));
        }
        text_main[w] = Fp::new(reads[w]);
    }
    let mut range = vec![Fp::ZERO; 2 * LIMB as usize];
    for v in 0..LIMB as usize {
        range[2 * v] = Fp::new(v as u32);
        range[2 * v + 1] = Fp::new(ranged[v]);
    }
    let mut public = header_hash.to_vec();
    if cheat == Cheat::WrongHash {
        public[0] = public[0].add(&Fp::ONE);
    }
    public.extend_from_slice(&packed);
    let mut folded = fold_mix(&mixv);
    if cheat == Cheat::WrongMix {
        folded[0] = folded[0].add(&Fp::ONE);
    }
    public.extend_from_slice(&folded);
    PowWitness {
        text_pre: Trace::new(pre, 1 + RATE),
        text: Trace::new(text_main, 1),
        perm: perm_trace,
        range: Trace::new(range, 2),
        mix: Trace::new(mix_rows, MIX_COLS),
        public,
        mix_out: mixv,
    }
}

/// hashimoto's fold of the 32-element mix to the header's eight.
pub fn fold_mix(mix: &[Fp; MIX_WORDS]) -> [Fp; DIGEST] {
    core::array::from_fn(|k| {
        let w = &mix[4 * k..4 * k + 4];
        fnv(fnv(fnv(w[0], w[1]), w[2]), w[3])
    })
}

/// The public values of a header's work: its `pow_hash`, nonce and `mix`.
pub fn public_values(pow_hash: &[Fp; DIGEST], nonce: &[u8; 32], mix: &[Fp; DIGEST]) -> Vec<Fp> {
    let mut v = pow_hash.to_vec();
    v.extend(nonce.chunks(3).map(|ch| Fp::new(ch.iter().enumerate().fold(0u32, |a, (i, x)| a | (*x as u32) << (8 * i)))));
    v.extend_from_slice(mix);
    v
}

// ---------------------------------------------------------------------------
// The work segment
// ---------------------------------------------------------------------------

/// The text's window table, committed once, and the shape of the proof of
/// work it serves.
pub struct WorkSetup {
    pub shape: WorkShape,
    /// Log heights of the four tables, which a recursive verifier's
    /// program depends on: the same for every header.
    pub log_heights: [usize; 4],
    seed: crate::pow::SeedText,
    pre: crate::stark::Preprocessed,
}

impl WorkSetup {
    /// Commits the windows of `seed`'s text at `config` (0.3 s on the
    /// development laptop).
    pub fn new(seed: &crate::pow::SeedText, config: &crate::stark::StarkConfig) -> WorkSetup {
        let shape = WorkShape::of(seed);
        let windows = shape.windows;
        let n_text = windows.n.next_power_of_two();
        let mut pre = vec![Fp::ZERO; n_text * (1 + RATE)];
        for w in 0..n_text {
            pre[w * (1 + RATE)] = Fp::from_u32(w as u32);
            if w < windows.n {
                let at = seed.window_offset(w);
                pre[w * (1 + RATE) + 1..(w + 1) * (1 + RATE)].copy_from_slice(&pack_window(&seed.text()[at..at + WINDOW]));
            }
        }
        let table = Trace::new(pre, 1 + RATE);
        let pre = crate::stark::Preprocessed::new(&table, config.log_blowup, config.quotient_stride(TextAir.max_constraint_degree()));
        let w = witness(seed.text(), shape, &[Fp::ZERO; DIGEST], &[0; 32]);
        let log_heights = [&w.text, &w.perm, &w.range, &w.mix].map(|t| t.height().trailing_zeros() as usize);
        WorkSetup { shape, log_heights, seed: seed.clone(), pre }
    }

    /// The root of the committed window table, which a verifier needs.
    pub fn root(&self) -> crate::merkle::Digest {
        self.pre.root()
    }

    /// What a verifier needs of it.
    pub fn verifier(&self) -> WorkVerifier {
        WorkVerifier { root: self.root(), shape: self.shape }
    }
}

/// What verifying a header's work needs: the window table's root and the
/// proof of work's shape.
#[derive(Clone, Copy, Debug)]
pub struct WorkVerifier {
    pub root: crate::merkle::Digest,
    pub shape: WorkShape,
}

/// A header's work, as the work segment proves it: its `pow_hash`, nonce
/// and the true hashimoto `mix` of the two. A block's statement carries its
/// parent's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Work {
    pub pow_hash: [Fp; DIGEST],
    pub nonce: [u8; 32],
    pub mix: [Fp; DIGEST],
}

impl Work {
    pub const ZERO: Work = Work { pow_hash: [Fp::ZERO; DIGEST], nonce: [0; 32], mix: [Fp::ZERO; DIGEST] };

    /// A header's, as it claims it (its `mix` checked by the proof of work).
    pub fn of_header(h: &crate::block::Header) -> Work {
        Work { pow_hash: h.pow_hash(), nonce: h.nonce, mix: h.mix }
    }

    /// A header's, its mix computed (genesis, whose `mix` field is empty):
    /// from the seed file, a few tens of milliseconds.
    pub fn computed(seed: &crate::pow::SeedText, h: &crate::block::Header) -> Work {
        let pow_hash = h.pow_hash();
        Work { pow_hash, nonce: h.nonce, mix: crate::pow::hashimoto(seed, &pow_hash, &h.nonce).mix }
    }

    /// The work segment's public values.
    pub fn to_values(&self) -> Vec<Fp> {
        public_values(&self.pow_hash, &self.nonce, &self.mix)
    }
}

/// A proven [`Work`].
#[derive(Clone, Debug)]
pub struct WorkProof {
    pub work: Work,
    pub proof: crate::stark::Proof,
}

/// The work setup for proofs at `config` of the proof of work `pow`:
/// committed once per process (0.3 s and about 50 MB on mainnet), then
/// shared.
pub fn work_setup(config: &crate::stark::StarkConfig, pow: crate::pow::PowParams) -> &'static WorkSetup {
    type Setups = std::sync::Mutex<Vec<(crate::stark::StarkConfig, crate::pow::PowParams, &'static WorkSetup)>>;
    static SETUPS: Setups = std::sync::Mutex::new(Vec::new());
    let mut setups = SETUPS.lock().unwrap();
    if let Some((_, _, s)) = setups.iter().find(|(c, p, _)| c == config && *p == pow) {
        return s;
    }
    let s: &'static WorkSetup = Box::leak(Box::new(WorkSetup::new(&crate::pow::SeedText::new(pow), config)));
    setups.push((*config, pow, s));
    s
}

/// The seed text of `pow`, for tests (decompressed once).
#[cfg(test)]
pub(crate) fn test_seed(pow: crate::pow::PowParams) -> &'static crate::pow::SeedText {
    static SEEDS: std::sync::Mutex<Vec<(crate::pow::PowParams, &'static crate::pow::SeedText)>> =
        std::sync::Mutex::new(Vec::new());
    let mut seeds = SEEDS.lock().unwrap();
    if let Some((_, s)) = seeds.iter().find(|(p, _)| *p == pow) {
        return s;
    }
    let s: &'static crate::pow::SeedText = Box::leak(Box::new(crate::pow::SeedText::new(pow)));
    seeds.push((pow, s));
    s
}

/// A header for tests on `prev_hash` at `height` with `state_root`, its mix
/// hashimoto's under `pow` (its target not met: the chain proof checks the
/// mix, not the target), and its work.
#[cfg(test)]
pub(crate) fn test_header(
    prev_hash: [Fp; DIGEST],
    height: u32,
    state_root: [Fp; DIGEST],
    pow: crate::pow::PowParams,
) -> (crate::block::Header, Work) {
    let mut header = crate::block::Header {
        prev_hash,
        height,
        timestamp: 1_793_000_000 + 600 * height as u64,
        body_commitment: core::array::from_fn(|k| Fp::new(100 * height + k as u32)),
        state_root,
        aux: [height as u8; 32],
        mix: [Fp::ZERO; DIGEST],
        nonce: [7u8.wrapping_add(height as u8); 32],
    };
    let work = Work::computed(test_seed(pow), &header);
    header.mix = work.mix;
    (header, work)
}

/// The test chains' genesis: a header at height 0, its `mix` empty.
#[cfg(test)]
pub(crate) fn test_genesis_header() -> crate::block::Header {
    crate::block::Header { mix: [Fp::ZERO; DIGEST], ..test_header([Fp::ZERO; DIGEST], 0, [Fp::ZERO; DIGEST], crate::pow::PowParams::DEV).0 }
}

/// The test genesis's work under `pow`: its true mix.
#[cfg(test)]
pub(crate) fn test_work(pow: crate::pow::PowParams) -> Work {
    Work::computed(test_seed(pow), &test_genesis_header())
}

fn work_transcript() -> crate::challenger::Challenger {
    let mut c = crate::challenger::Challenger::new();
    c.observe(Fp::new(DOM_WORK_PROOF));
    c
}

/// Proves a header's work: that `hashimoto(pow_hash, nonce)`, its items
/// computed from the seed file, gives the `mix` returned.
pub fn prove_work(
    setup: &WorkSetup,
    config: &crate::stark::StarkConfig,
    pow_hash: &[Fp; DIGEST],
    nonce: &[u8; 32],
) -> (crate::stark::Proof, [Fp; DIGEST]) {
    use crate::stark::TableInput;
    let w = witness(setup.seed.text(), setup.shape, pow_hash, nonce);
    let (perm, mix) = (setup.shape.perm_air(), setup.shape.mix_air());
    let inputs = [
        TableInput { air: &TextAir, trace: &w.text, pre: Some(&setup.pre) },
        TableInput { air: &perm, trace: &w.perm, pre: None },
        TableInput { air: &RangeAir, trace: &w.range, pre: None },
        TableInput { air: &mix, trace: &w.mix, pre: None },
    ];
    let proof = crate::stark::prove_tables(config, &inputs, &w.public, &mut work_transcript());
    (proof, fold_mix(&w.mix_out))
}

/// Verifies a proof of [`prove_work`] for a header's `pow_hash`, nonce and
/// `mix`, against the window table's root.
pub fn verify_work(
    verifier: &WorkVerifier,
    config: &crate::stark::StarkConfig,
    pow_hash: &[Fp; DIGEST],
    nonce: &[u8; 32],
    mix: &[Fp; DIGEST],
    proof: &crate::stark::Proof,
) -> Result<(), crate::stark::VerifyError> {
    use crate::stark::TableSpec;
    let (perm, mix_air) = (verifier.shape.perm_air(), verifier.shape.mix_air());
    let specs = [
        TableSpec { air: &TextAir, pre_root: Some(&verifier.root) },
        TableSpec { air: &perm, pre_root: None },
        TableSpec { air: &RangeAir, pre_root: None },
        TableSpec { air: &mix_air, pre_root: None },
    ];
    crate::stark::verify_tables(config, &specs, &public_values(pow_hash, nonce, mix), proof, &mut work_transcript())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::{self, PowParams, SeedText};
    use crate::stark::{self, DynAir, Preprocessed, StarkConfig, TableInput, TableSpec};

    const SEGMENT: StarkConfig =
        StarkConfig { log_blowup: 2, num_queries: 54, pow_bits: 16, zk: false, commit_bits: 121 };

    fn header() -> ([Fp; DIGEST], [u8; 32]) {
        (core::array::from_fn(|k| Fp::new(1000 + k as u32 * 7)), core::array::from_fn(|k| (k * 13) as u8))
    }

    fn transcript() -> crate::challenger::Challenger {
        let mut c = crate::challenger::Challenger::new();
        c.observe(Fp::new(0x7077));
        c
    }

    /// The witness's mix is hashimoto's.
    #[test]
    #[ignore = "slow: the seed text and 128 items"]
    fn mix_matches_hashimoto() {
        let seed = SeedText::new(PowParams::MAINNET);
        let (hh, nonce) = header();
        let w = witness(seed.text(), WorkShape::of(&seed), &hh, &nonce);
        let want = pow::hashimoto(&seed, &hh, &nonce);
        assert_eq!(fold_mix(&w.mix_out), want.mix);
        assert_eq!(w.public, public_values(&hh, &nonce, &want.mix));
    }

    fn tables<'a>(
        w: &'a PowWitness,
        perm: &'a PermAir,
        mix: &'a MixAir,
    ) -> Vec<(&'a dyn DynAir, &'a Trace, Option<&'a Trace>)> {
        vec![
            (&TextAir, &w.text, Some(&w.text_pre)),
            (perm, &w.perm, None),
            (&RangeAir, &w.range, None),
            (mix, &w.mix, None),
        ]
    }

    /// Every constraint holds and the buses balance.
    #[test]
    #[ignore = "slow: the seed file and 128 items"]
    fn constraints_hold() {
        let seed = SeedText::new(PowParams::MAINNET);
        let (hh, nonce) = header();
        let shape = WorkShape::of(&seed);
        let w = witness(seed.text(), shape, &hh, &nonce);
        assert_eq!(stark::check_tables(&tables(&w, &shape.perm_air(), &shape.mix_air()), &w.public), Ok(()));
    }

    /// Each way of cheating, written as a cheating prover would (the
    /// generator lenient, all after the cheat computed from it), is refused
    /// by the constraints or the buses.
    #[test]
    #[ignore = "slow: the seed text and 128 items, for each cheat"]
    fn attacks() {
        let seed = SeedText::new(PowParams::MAINNET);
        let (hh, nonce) = header();
        let shape = WorkShape::of(&seed);
        let (perm, mix) = (shape.perm_air(), shape.mix_air());
        let honest = witness(seed.text(), shape, &hh, &nonce);
        assert_eq!(stark::check_tables(&tables(&honest, &perm, &mix), &honest.public), Ok(()));
        for cheat in [
            Cheat::OtherWindow,
            Cheat::OtherIndex,
            Cheat::OtherText,
            Cheat::FewerParents,
            Cheat::MoreParents,
            Cheat::OtherItem,
            Cheat::OtherPair,
            Cheat::NonCanonical,
            Cheat::BeyondN,
            Cheat::WrongMix,
            Cheat::WrongHash,
            Cheat::OtherDirect,
            Cheat::DirectUnreduced,
        ] {
            crate::stark::LENIENT.with(|l| l.set(true));
            let w = witness_cheating(seed.text(), shape, &hh, &nonce, cheat);
            crate::stark::LENIENT.with(|l| l.set(false));
            assert!(stark::check_tables(&tables(&w, &perm, &mix), &w.public).is_err(), "{cheat:?} accepted");
        }
    }

    /// A real header's work: proven, and verified only against its own
    /// `pow_hash`, nonce and `mix`, and the window table's root.
    #[test]
    #[ignore = "slow: proves a header's work"]
    fn proves_a_real_header() {
        use crate::block::Header;
        let seed = SeedText::new(PowParams::MAINNET);
        let mut header = Header {
            prev_hash: core::array::from_fn(|k| Fp::new(11 + k as u32)),
            height: 7,
            timestamp: 1_793_400_000,
            body_commitment: core::array::from_fn(|k| Fp::new(500 + k as u32)),
            state_root: core::array::from_fn(|k| Fp::new(900 + k as u32)),
            aux: [0; 32],
            mix: [Fp::ZERO; DIGEST],
            nonce: crate::pow::nonce_from_u64(42),
        };
        let pow_hash = header.pow_hash();
        header.mix = pow::hashimoto(&seed, &pow_hash, &header.nonce).mix;
        let setup = WorkSetup::new(&seed, &SEGMENT);
        let (proof, mix) = prove_work(&setup, &SEGMENT, &pow_hash, &header.nonce);
        assert_eq!(mix, header.mix);
        let check = |root: &crate::merkle::Digest, h: &[Fp; DIGEST], n: &[u8; 32], m: &[Fp; DIGEST]| {
            let v = WorkVerifier { root: *root, ..setup.verifier() };
            verify_work(&v, &SEGMENT, h, n, m, &proof).is_ok()
        };
        assert!(check(&setup.root(), &pow_hash, &header.nonce, &header.mix));
        let mut wrong_mix = header.mix;
        wrong_mix[3] = wrong_mix[3].add(&Fp::ONE);
        assert!(!check(&setup.root(), &pow_hash, &header.nonce, &wrong_mix), "another mix");
        assert!(!check(&setup.root(), &pow_hash, &crate::pow::nonce_from_u64(43), &header.mix), "another nonce");
        let mut other = header;
        other.timestamp += 1;
        assert!(!check(&setup.root(), &other.pow_hash(), &header.nonce, &header.mix), "another header");
        let mut root = setup.root();
        root[0] = root[0].add(&Fp::ONE);
        assert!(!check(&root, &pow_hash, &header.nonce, &header.mix), "another text");
    }

    /// The work segment verified inside a machine program, as a block's
    /// root would: the program's height, and that it accepts.
    #[test]
    #[ignore = "slow: proves a header's work and compiles its verifier"]
    fn folds() {
        use crate::recursion::Compiler;
        use crate::vm_air::VmAir;
        let seed = SeedText::new(PowParams::MAINNET);
        let (hh, nonce) = header();
        let setup = WorkSetup::new(&seed, &SEGMENT);
        let (proof, mix) = prove_work(&setup, &SEGMENT, &hh, &nonce);
        let t = std::time::Instant::now();
        let mut c = Compiler::new();
        let public = public_values(&hh, &nonce, &mix);
        let pubv = c.scalar_inputs(&public);
        let root = c.scalar_inputs(&setup.root());
        for (i, v) in setup.root().iter().enumerate() {
            c.assert_scalar(root + i as u32, *v);
        }
        let (perm, mix_air) = (setup.shape.perm_air(), setup.shape.mix_air());
        let tables: [(&dyn DynAir, Option<u32>); 4] = [(&TextAir, Some(root)), (&perm, None), (&RangeAir, None), (&mix_air, None)];
        c.verify_stark(&tables, &SEGMENT, &[Fp::new(DOM_WORK_PROOF)], pubv, NUM_PUBLIC, &proof);
        eprintln!("compiled in {:.2?}: {} rows (2^{}), hash rows 2^{}", t.elapsed(), c.prog.instrs.len(), c.prog.height().trailing_zeros(), VmAir::hash_height(&c.prog).trailing_zeros());
        VmAir::execute(&c.prog, &c.inputs).expect("the verifier program accepts");
    }

    /// Proving and verifying one header's proof of work at the mainnet
    /// segment configuration.
    /// `cargo test --release --lib pow_air::tests::cost -- --ignored --nocapture`
    #[test]
    #[ignore = "slow: measures proving"]
    fn cost() {
        let seed = SeedText::new(PowParams::MAINNET);
        let (hh, nonce) = header();
        let shape = WorkShape::of(&seed);
        let (perm, mix) = (shape.perm_air(), shape.mix_air());
        let t = std::time::Instant::now();
        let w = witness(seed.text(), shape, &hh, &nonce);
        let built = t.elapsed();
        let t = std::time::Instant::now();
        let pre = Preprocessed::new(&w.text_pre, SEGMENT.log_blowup, SEGMENT.quotient_stride(TextAir.max_constraint_degree()));
        let commit = t.elapsed();
        let inputs = [
            TableInput { air: &TextAir, trace: &w.text, pre: Some(&pre) },
            TableInput { air: &perm, trace: &w.perm, pre: None },
            TableInput { air: &RangeAir, trace: &w.range, pre: None },
            TableInput { air: &mix, trace: &w.mix, pre: None },
        ];
        let t = std::time::Instant::now();
        let proof = stark::prove_tables(&SEGMENT, &inputs, &w.public, &mut transcript());
        let proved = t.elapsed();
        let root = pre.root();
        let specs = [
            TableSpec { air: &TextAir, pre_root: Some(&root) },
            TableSpec { air: &perm, pre_root: None },
            TableSpec { air: &RangeAir, pre_root: None },
            TableSpec { air: &mix, pre_root: None },
        ];
        let t = std::time::Instant::now();
        let ok = stark::verify_tables(&SEGMENT, &specs, &w.public, &proof, &mut transcript());
        let verified = t.elapsed();
        assert_eq!(ok, Ok(()));
        println!(
            "parents {}: text 2^{} perm 2^{} ({} cols) mix {} cols | witness {built:.2?}, text commit (once) {commit:.2?}, prove {proved:.2?}, {} KB, verify {verified:.2?}",
            shape.parents,
            w.text.height().trailing_zeros(),
            w.perm.height().trailing_zeros(),
            PERM_COLS,
            MIX_COLS,
            proof.to_bytes().len() / 1024,
        );
    }
}
