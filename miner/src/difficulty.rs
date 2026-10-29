//! Difficulty: 256-bit targets, Bitcoin's compact encoding, and the
//! Bitcoin Cash ASERT retargeting algorithm (`aserti3-2d`).
//!
//! ASERT sets the next target directly from how far the chain is ahead of or
//! behind its ideal schedule, measured against a fixed anchor block:
//!
//! ```text
//! next_target = anchor_target * 2^((time_delta - ideal_block_time * (height_delta + 1)) / half_life)
//! ```
//!
//! with `time_delta` and `height_delta` taken from the block being evaluated
//! (the parent of the block whose target is wanted) relative to the anchor.
//! The exponent is fixed point with 16 fractional bits and the fractional
//! power of two is a cubic approximation, exactly as specified, so results
//! match the reference test vectors bit for bit.
//!
//! This chain anchors at genesis. The specification requires the anchor's
//! parent timestamp; genesis has no parent, so the anchor parent time is
//! defined as the genesis timestamp minus one block interval, which puts
//! genesis exactly on schedule.

use crate::pow::Target;

/// Ideal spacing between blocks, in seconds.
pub const IDEAL_BLOCK_TIME: i64 = 600;
/// ASERT half-life: two days.
pub const HALF_LIFE: i64 = 2 * 24 * 3600;
const RADIX_BITS: u32 = 16;

/// Little-endian 256-bit unsigned integer.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    pub const fn from_u64(v: u64) -> U256 {
        U256([v, 0, 0, 0])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (chunk, limb) in out.chunks_exact_mut(8).zip(self.0) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    pub fn from_le_bytes(b: &[u8; 32]) -> U256 {
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(b.chunks_exact(8)) {
            *limb = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        U256(limbs)
    }

    /// Number of significant bits.
    pub fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + 64 - self.0[i].leading_zeros();
            }
        }
        0
    }

    #[allow(clippy::needless_range_loop)]
    pub fn shift_left(self, n: u32) -> U256 {
        if n >= 256 {
            return U256::ZERO;
        }
        let (words, bits) = ((n / 64) as usize, n % 64);
        let mut out = [0u64; 4];
        for i in (words..4).rev() {
            let lo = self.0[i - words] << bits;
            let hi = if bits > 0 && i > words { self.0[i - words - 1] >> (64 - bits) } else { 0 };
            out[i] = lo | hi;
        }
        U256(out)
    }

    #[allow(clippy::needless_range_loop)]
    pub fn shift_right(self, n: u32) -> U256 {
        if n >= 256 {
            return U256::ZERO;
        }
        let (words, bits) = ((n / 64) as usize, n % 64);
        let mut out = [0u64; 4];
        for i in 0..4 - words {
            let lo = self.0[i + words] >> bits;
            let hi = if bits > 0 && i + words + 1 < 4 { self.0[i + words + 1] << (64 - bits) } else { 0 };
            out[i] = lo | hi;
        }
        U256(out)
    }

    pub fn saturating_add(self, other: U256) -> U256 {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s, c1) = self.0[i].overflowing_add(other.0[i]);
            let (s, c2) = s.overflowing_add(carry);
            out[i] = s;
            carry = u64::from(c1) + u64::from(c2);
        }
        if carry > 0 { U256::MAX } else { U256(out) }
    }

    /// `self - other`, which must not go negative.
    pub fn checked_sub(self, other: U256) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            out[i] = d;
            borrow = u64::from(b1) + u64::from(b2);
        }
        if borrow > 0 { None } else { Some(U256(out)) }
    }

    pub fn not(self) -> U256 {
        U256(self.0.map(|l| !l))
    }

    pub fn bit(&self, i: u32) -> bool {
        (self.0[(i / 64) as usize] >> (i % 64)) & 1 == 1
    }

    /// `self / divisor` by long division; `divisor` must be nonzero.
    pub fn div(self, divisor: U256) -> U256 {
        assert!(!divisor.is_zero(), "division by zero");
        let mut quotient = U256::ZERO;
        let mut rem = U256::ZERO;
        for i in (0..256).rev() {
            rem = rem.shift_left(1);
            if self.bit(i) {
                rem.0[0] |= 1;
            }
            if rem >= divisor {
                rem = rem.checked_sub(divisor).unwrap();
                quotient.0[(i / 64) as usize] |= 1 << (i % 64);
            }
        }
        quotient
    }

    /// `self * m` as five limbs (no overflow possible).
    fn mul_u64_wide(self, m: u64) -> [u64; 5] {
        let mut out = [0u64; 5];
        let mut carry = 0u128;
        for (o, limb) in out.iter_mut().zip(self.0) {
            let t = limb as u128 * m as u128 + carry;
            *o = t as u64;
            carry = t >> 64;
        }
        out[4] = carry as u64;
        out
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                core::cmp::Ordering::Equal => continue,
                o => return o,
            }
        }
        core::cmp::Ordering::Equal
    }
}

impl From<Target> for U256 {
    fn from(t: Target) -> U256 {
        U256::from_le_bytes(&t.0)
    }
}

impl From<U256> for Target {
    fn from(v: U256) -> Target {
        Target(v.to_le_bytes())
    }
}

/// Decodes Bitcoin's compact `nBits` form. Negative or zero encodings give
/// zero; the result is not clamped.
pub fn compact_to_target(bits: u32) -> U256 {
    let size = bits >> 24;
    let mut word = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || word == 0 {
        return U256::ZERO;
    }
    if size <= 3 {
        word >>= 8 * (3 - size);
        U256::from_u64(word as u64)
    } else {
        let shift = 8 * (size - 3);
        if shift >= 256 || U256::from_u64(word as u64).bits() + shift > 256 {
            // Does not fit: caller should treat as invalid; return MAX so it
            // exceeds any limit.
            return U256::MAX;
        }
        U256::from_u64(word as u64).shift_left(shift)
    }
}

/// Encodes a target in compact form, as Bitcoin does.
pub fn target_to_compact(target: U256) -> u32 {
    let mut size = target.bits().div_ceil(8);
    let mut compact: u64 =
        if size <= 3 { target.0[0] << (8 * (3 - size)) } else { target.shift_right(8 * (size - 3)).0[0] };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    (compact as u32) | (size << 24)
}

/// Fixed parameters of an ASERT schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Asert {
    pub anchor_height: u64,
    /// Timestamp of the anchor block's parent (virtual for genesis).
    pub anchor_parent_time: i64,
    pub anchor_target: U256,
    /// Easiest permitted target.
    pub max_target: U256,
    pub half_life: i64,
    pub ideal_block_time: i64,
}

impl Asert {
    /// Schedule anchored at a genesis block with the given timestamp and
    /// target, using mainnet constants.
    pub fn from_genesis(genesis_time: i64, genesis_target: U256, max_target: U256) -> Asert {
        Asert {
            anchor_height: 0,
            anchor_parent_time: genesis_time - IDEAL_BLOCK_TIME,
            anchor_target: genesis_target,
            max_target,
            half_life: HALF_LIFE,
            ideal_block_time: IDEAL_BLOCK_TIME,
        }
    }

    /// Target of the block following the evaluation block at
    /// `(eval_height, eval_time)`. `eval_height` must not be below the anchor.
    pub fn next_target(&self, eval_height: u64, eval_time: i64) -> U256 {
        assert!(eval_height >= self.anchor_height, "evaluation block precedes anchor");
        let time_delta = eval_time as i128 - self.anchor_parent_time as i128;
        let height_delta = (eval_height - self.anchor_height) as i128;
        let radix: i128 = 1 << RADIX_BITS;
        // Truncating division, per the specification.
        let exponent =
            ((time_delta - self.ideal_block_time as i128 * (height_delta + 1)) * radix) / self.half_life as i128;
        let num_shifts = exponent >> RADIX_BITS; // arithmetic shift == floor division
        let frac = exponent - (num_shifts << RADIX_BITS);
        debug_assert!((0..radix).contains(&frac));
        let factor: i128 =
            ((195_766_423_245_049 * frac + 971_821_376 * frac * frac + 5127 * frac * frac * frac + (1i128 << 47))
                >> 48)
                + 65536;
        let product = self.anchor_target.mul_u64_wide(factor as u64);

        // next = product * 2^(num_shifts - 16)
        let shift = num_shifts - RADIX_BITS as i128;
        let next = if shift <= 0 {
            let s = (-shift).min(320) as u32;
            shr320(product, s)
        } else {
            let s = shift.min(512) as u32;
            if product.iter().all(|&l| l == 0) {
                Some(U256::ZERO)
            } else if bits320(product) + s > 256 {
                None
            } else {
                Some(U256([product[0], product[1], product[2], product[3]]).shift_left(s))
            }
        };
        match next {
            None => self.max_target,
            Some(t) if t.is_zero() => U256::ONE,
            Some(t) if t > self.max_target => self.max_target,
            Some(t) => t,
        }
    }
}

fn bits320(v: [u64; 5]) -> u32 {
    for i in (0..5).rev() {
        if v[i] != 0 {
            return 64 * i as u32 + 64 - v[i].leading_zeros();
        }
    }
    0
}

/// Shifts a five-limb value right; `None` if the result exceeds 256 bits.
fn shr320(v: [u64; 5], n: u32) -> Option<U256> {
    let mut out = [0u64; 5];
    if n < 320 {
        let (words, bits) = ((n / 64) as usize, n % 64);
        for i in 0..5 - words {
            let lo = v[i + words] >> bits;
            let hi = if bits > 0 && i + words + 1 < 5 { v[i + words + 1] << (64 - bits) } else { 0 };
            out[i] = lo | hi;
        }
    }
    if out[4] != 0 { None } else { Some(U256([out[0], out[1], out[2], out[3]])) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_BITS: u32 = 0x1d00_ffff;

    #[test]
    fn u256_basics() {
        let a = U256::from_u64(0x1234);
        assert_eq!(a.shift_left(8).0[0], 0x123400);
        assert_eq!(a.shift_left(64).0[1], 0x1234);
        assert_eq!(a.shift_left(64).shift_right(64), a);
        assert_eq!(a.shift_left(200).shift_right(200), a);
        assert_eq!(U256::ONE.shift_left(255).bits(), 256);
        assert_eq!(a.shift_left(255), U256::ZERO); // only bit 0 would survive, and it is clear
        assert_eq!(a.bits(), 13);
        assert_eq!(U256::ZERO.bits(), 0);
        assert!(U256::MAX > a);
        assert_eq!(U256::from_le_bytes(&a.shift_left(100).to_le_bytes()), a.shift_left(100));
        let t: Target = a.into();
        assert_eq!(U256::from(t), a);
    }

    #[test]
    fn compact_roundtrip() {
        for bits in [MAX_BITS, 0x1a2b_3c4d, 0x0101_0000, 0x1802_aee8, 0x0312_3456, 0x0212_3400, 0x0112_0000] {
            let t = compact_to_target(bits);
            assert_eq!(target_to_compact(t), bits, "{bits:#x}");
        }
        assert_eq!(compact_to_target(MAX_BITS), U256::from_u64(0xffff).shift_left(8 * 26));
        assert_eq!(target_to_compact(U256::ONE), 0x0101_0000);
        assert_eq!(target_to_compact(U256::from_u64(0x80)), 0x0200_8000);
        assert_eq!(compact_to_target(0x0180_0000), U256::ZERO);
        // Non-canonical encodings decode to the same target as their canonical form.
        assert_eq!(compact_to_target(0x0300_1234), compact_to_target(0x0212_3400));
    }

    struct Run {
        anchor_height: u64,
        anchor_parent_time: i64,
        anchor_bits: u32,
        rows: Vec<(u64, i64, u32)>,
    }

    fn parse_run(text: &str) -> Run {
        let field = |key: &str| -> &str {
            let line = text.lines().find(|l| l.contains(key)).unwrap();
            line.split(':').nth(1).unwrap().trim()
        };
        let anchor_bits = u32::from_str_radix(field("anchor nBits").trim_start_matches("0x"), 16).unwrap();
        let rows = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let p: Vec<&str> = l.split_whitespace().collect();
                (
                    p[1].parse().unwrap(),
                    p[2].parse().unwrap(),
                    u32::from_str_radix(p[3].trim_start_matches("0x"), 16).unwrap(),
                )
            })
            .collect();
        Run {
            anchor_height: field("anchor height").parse().unwrap(),
            anchor_parent_time: field("anchor parent time").parse().unwrap(),
            anchor_bits,
            rows,
        }
    }

    #[test]
    fn matches_bitcoin_cash_test_vectors() {
        let runs = [
            include_str!("../testdata/asert/run01"),
            include_str!("../testdata/asert/run02"),
            include_str!("../testdata/asert/run03"),
            include_str!("../testdata/asert/run04"),
            include_str!("../testdata/asert/run05"),
            include_str!("../testdata/asert/run06"),
            include_str!("../testdata/asert/run07"),
            include_str!("../testdata/asert/run08"),
            include_str!("../testdata/asert/run09"),
            include_str!("../testdata/asert/run10"),
            include_str!("../testdata/asert/run11"),
            include_str!("../testdata/asert/run12"),
        ];
        let mut checked = 0;
        for (i, text) in runs.iter().enumerate() {
            let run = parse_run(text);
            let asert = Asert {
                anchor_height: run.anchor_height,
                anchor_parent_time: run.anchor_parent_time,
                anchor_target: compact_to_target(run.anchor_bits),
                max_target: compact_to_target(MAX_BITS),
                half_life: HALF_LIFE,
                ideal_block_time: IDEAL_BLOCK_TIME,
            };
            for (height, time, want) in &run.rows {
                let got = target_to_compact(asert.next_target(*height, *time));
                assert_eq!(got, *want, "run{:02} height {height} time {time}: got {got:#x} want {want:#x}", i + 1);
                checked += 1;
            }
        }
        assert!(checked > 13_000, "only {checked} rows checked");
    }

    #[test]
    fn genesis_anchor_keeps_schedule() {
        let genesis_time = 1_700_000_000;
        let target = compact_to_target(0x1802_aee8);
        let asert = Asert::from_genesis(genesis_time, target, compact_to_target(MAX_BITS));
        // Exactly on schedule: constant target.
        for h in 0..10u64 {
            assert_eq!(asert.next_target(h, genesis_time + h as i64 * IDEAL_BLOCK_TIME), target, "height {h}");
        }
        // One half-life late doubles the target; one early halves it.
        assert_eq!(asert.next_target(0, genesis_time + HALF_LIFE), target.shift_left(1));
        assert_eq!(asert.next_target(0, genesis_time - HALF_LIFE), target.shift_right(1));
        // Faster blocks tighten, slower loosen.
        assert!(asert.next_target(1, genesis_time + 100) < target);
        assert!(asert.next_target(1, genesis_time + 5000) > target);
        // Clamps.
        assert_eq!(asert.next_target(0, genesis_time + 100 * HALF_LIFE), asert.max_target);
        assert_eq!(asert.next_target(0, genesis_time - 300 * HALF_LIFE), U256::ONE);
    }
}
