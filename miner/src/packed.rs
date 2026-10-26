//! Eight BabyBear elements in one AVX2 register, in Montgomery form.
//!
//! Products use the Montgomery reduction with `p^-1` rather than `-p^-1`:
//! for `x = a b < p^2` and `q = x p^-1 mod 2^32`, `x - q p` is divisible by
//! `2^32` and its high half lies in `(-p, p)`; adding `p` when negative is
//! an unsigned min of `d` and `d + p`. Results are canonical and equal the
//! scalar [`crate::poseidon2::Fp`] operations bit for bit.
//!
//! Only compiled when AVX2 is enabled at build time (see
//! `.cargo/config.toml`); callers keep a portable path for other targets.

use core::arch::x86_64::*;

use crate::poseidon2::{Fp, P};

pub type V = __m256i;

/// `p^-1 mod 2^32`.
const P_INV: u32 = 0x8800_0001;
const _: () = assert!(P.wrapping_mul(P_INV) == 1);

#[inline(always)]
pub fn splat(x: u32) -> V {
    unsafe { _mm256_set1_epi32(x as i32) }
}

#[inline(always)]
pub fn splat_fp(x: Fp) -> V {
    splat(x.to_mont())
}

/// Loads eight raw Montgomery words.
#[inline(always)]
pub fn load(x: &[u32; 8]) -> V {
    // SAFETY: eight u32s are 32 bytes; unaligned loads have no alignment
    // requirement.
    unsafe { _mm256_loadu_si256(x.as_ptr() as *const V) }
}

#[inline(always)]
pub fn store(x: &mut [u32; 8], v: V) {
    // SAFETY: as in `load`.
    unsafe { _mm256_storeu_si256(x.as_mut_ptr() as *mut V, v) }
}

/// Loads eight consecutive elements.
#[inline(always)]
pub fn load_fp(x: &[Fp]) -> V {
    assert!(x.len() >= 8);
    // SAFETY: `Fp` is a transparent `u32` and the slice holds eight.
    unsafe { _mm256_loadu_si256(x.as_ptr() as *const V) }
}

#[inline(always)]
pub fn store_fp(x: &mut [Fp], v: V) {
    assert!(x.len() >= 8);
    // SAFETY: as in `load_fp`.
    unsafe { _mm256_storeu_si256(x.as_mut_ptr() as *mut V, v) }
}

#[inline(always)]
pub fn add(a: V, b: V) -> V {
    unsafe {
        let t = _mm256_add_epi32(a, b);
        _mm256_min_epu32(t, _mm256_sub_epi32(t, splat(P)))
    }
}

#[inline(always)]
pub fn sub(a: V, b: V) -> V {
    unsafe {
        let t = _mm256_sub_epi32(a, b);
        _mm256_min_epu32(t, _mm256_add_epi32(t, splat(P)))
    }
}

#[inline(always)]
pub fn mul(a: V, b: V) -> V {
    unsafe {
        let p = splat(P);
        let p_inv = splat(P_INV);
        let a_odd = _mm256_srli_epi64(a, 32);
        let b_odd = _mm256_srli_epi64(b, 32);
        let x_evn = _mm256_mul_epu32(a, b);
        let x_odd = _mm256_mul_epu32(a_odd, b_odd);
        let q_evn = _mm256_mul_epu32(x_evn, p_inv);
        let q_odd = _mm256_mul_epu32(x_odd, p_inv);
        let d_evn = _mm256_sub_epi64(x_evn, _mm256_mul_epu32(q_evn, p));
        let d_odd = _mm256_sub_epi64(x_odd, _mm256_mul_epu32(q_odd, p));
        // High halves: even lanes from d_evn shifted down, odd in place.
        let d = _mm256_blend_epi32(_mm256_srli_epi64(d_evn, 32), d_odd, 0b1010_1010);
        _mm256_min_epu32(d, _mm256_add_epi32(d, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_scalar() {
        let mut x = 0x9e37_79b9u32;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            Fp::from_mont(x % P)
        };
        for _ in 0..2000 {
            let mut a: [Fp; 8] = core::array::from_fn(|_| next());
            let b: [Fp; 8] = core::array::from_fn(|_| next());
            a[0] = Fp::ZERO;
            a[1] = Fp::from_mont(P - 1);
            let (va, vb) = (load_fp(&a), load_fp(&b));
            for (op, f) in [
                (add(va, vb), (|x: Fp, y: Fp| x.add(&y)) as fn(Fp, Fp) -> Fp),
                (sub(va, vb), |x, y| x.sub(&y)),
                (mul(va, vb), |x, y| x.mul(&y)),
            ] {
                let mut out = [Fp::ZERO; 8];
                store_fp(&mut out, op);
                for l in 0..8 {
                    assert_eq!(out[l], f(a[l], b[l]));
                }
            }
        }
    }
}
