//! Number-theoretic transform over BabyBear and its two-adic cosets.
//!
//! BabyBear has `p - 1 = 15 * 2^27`, so multiplicative subgroups of every
//! power-of-two order up to `2^27` exist. [`ntt`] evaluates a polynomial given
//! by coefficients on the subgroup of order `n` (natural order in, natural
//! order out); [`intt`] interpolates. The coset variants work on `shift * H`.
//! Extension field versions apply the transform to each of the four base
//! coordinates, which is valid because the transform is `Fp`-linear.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::ext::{DEGREE, Fp4};
use crate::poseidon2::Fp;

/// Largest `k` such that a subgroup of order `2^k` exists.
pub const TWO_ADICITY: usize = 27;

/// Generator of the subgroup of order `2^27` (`31^15`, as in Plonky3).
pub const TWO_ADIC_GENERATOR: Fp = Fp::new(440_564_289);

/// Multiplicative generator of the whole field, used as the default coset
/// shift so that `shift * H` is disjoint from `H`.
pub const MULTIPLICATIVE_GENERATOR: Fp = Fp::new(31);

const INV_2: Fp = Fp::new(1_006_632_961);

/// A primitive root of unity of order `2^log_n`.
pub fn root_of_unity(log_n: usize) -> Fp {
    assert!(log_n <= TWO_ADICITY, "no subgroup of order 2^{log_n}");
    TWO_ADIC_GENERATOR.pow(1u64 << (TWO_ADICITY - log_n))
}

pub fn log2_strict(n: usize) -> usize {
    assert!(n.is_power_of_two(), "{n} is not a power of two");
    n.trailing_zeros() as usize
}

/// Reorders `v` so that index `i` moves to the bit reversal of `i`.
pub fn bit_reverse_permute<T>(v: &mut [T]) {
    let n = v.len();
    if n <= 2 {
        return;
    }
    let bits = log2_strict(n);
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS as usize - bits);
        if i < j {
            v.swap(i, j);
        }
    }
}

/// Cached tables of powers: twiddles per stage for a transform, and
/// successive powers of a coset shift. Keyed by the base element and the
/// size, shared across threads.
fn cached_powers(key: (u32, usize), build: impl FnOnce() -> Vec<Fp>) -> Arc<Vec<Fp>> {
    type Cache = Mutex<HashMap<(u32, usize), Arc<Vec<Fp>>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(t) = cache.lock().unwrap().get(&key) {
        return t.clone();
    }
    let t = Arc::new(build());
    cache.lock().unwrap().entry(key).or_insert(t).clone()
}

/// `base^0, base^1, ..., base^(n-1)`.
pub fn power_table(base: Fp, n: usize) -> Arc<Vec<Fp>> {
    cached_powers((base.to_canonical(), n), || {
        let mut v = Vec::with_capacity(n);
        let mut p = Fp::ONE;
        for _ in 0..n {
            v.push(p);
            p = p.mul(&base);
        }
        v
    })
}

/// Twiddles for all stages of a size-`n` transform with `root`, stage by
/// stage (lengths 1, 2, 4, ..., n/2), concatenated.
fn twiddle_table(root: Fp, n: usize) -> Arc<Vec<Fp>> {
    cached_powers((root.to_canonical(), n), || {
        let log_n = log2_strict(n);
        let mut v = Vec::with_capacity(n);
        for stage in 1..=log_n {
            let w_len = root.pow(1u64 << (log_n - stage));
            let half = 1usize << (stage - 1);
            let mut w = Fp::ONE;
            for _ in 0..half {
                v.push(w);
                w = w.mul(&w_len);
            }
        }
        v
    })
}

/// In-place radix-2 transform with the given root of unity of order `n`.
fn transform(v: &mut [Fp], root: Fp) {
    let n = v.len();
    if n <= 1 {
        return;
    }
    let table = twiddle_table(root, n);
    bit_reverse_permute(v);
    let mut len = 2;
    let mut offset = 0;
    while len <= n {
        let half = len / 2;
        let twiddles = &table[offset..offset + half];
        for start in (0..n).step_by(len) {
            let (lo, hi) = v[start..start + len].split_at_mut(half);
            butterflies(lo, hi, twiddles);
        }
        offset += half;
        len <<= 1;
    }
}

/// `(a, b) <- (a + w b, a - w b)` elementwise.
#[inline]
fn butterflies(lo: &mut [Fp], hi: &mut [Fp], twiddles: &[Fp]) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    if lo.len() >= 8 {
        use crate::packed::{add, load_fp, mul, store_fp, sub};
        for ((a, b), w) in lo.chunks_exact_mut(8).zip(hi.chunks_exact_mut(8)).zip(twiddles.chunks_exact(8)) {
            let (va, t) = (load_fp(a), mul(load_fp(b), load_fp(w)));
            store_fp(a, add(va, t));
            store_fp(b, sub(va, t));
        }
        return;
    }
    for ((a, b), w) in lo.iter_mut().zip(hi.iter_mut()).zip(twiddles) {
        let t = b.mul(w);
        *b = a.sub(&t);
        *a = a.add(&t);
    }
}

/// `v[i] *= s[i]`.
#[inline]
fn scale(v: &mut [Fp], s: &[Fp]) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        use crate::packed::{load_fp, mul, store_fp};
        let whole = v.len() / 8 * 8;
        let (head, tail) = v.split_at_mut(whole);
        for (x, c) in head.chunks_exact_mut(8).zip(s.chunks_exact(8)) {
            store_fp(x, mul(load_fp(x), load_fp(c)));
        }
        for (x, c) in tail.iter_mut().zip(&s[whole..]) {
            *x = x.mul(c);
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    for (x, c) in v.iter_mut().zip(s) {
        *x = x.mul(c);
    }
}

/// `v[i] *= c`.
#[inline]
fn scale_const(v: &mut [Fp], c: Fp) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        use crate::packed::{load_fp, mul, splat_fp, store_fp};
        let vc = splat_fp(c);
        let whole = v.len() / 8 * 8;
        let (head, tail) = v.split_at_mut(whole);
        for x in head.chunks_exact_mut(8) {
            store_fp(x, mul(load_fp(x), vc));
        }
        for x in tail {
            *x = x.mul(&c);
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    for x in v.iter_mut() {
        *x = x.mul(&c);
    }
}

/// Coefficients to evaluations on `H`.
pub fn ntt(v: &mut [Fp]) {
    let root = root_of_unity(log2_strict(v.len()));
    transform(v, root);
}

/// Evaluations on `H` to coefficients.
pub fn intt(v: &mut [Fp]) {
    let n = v.len();
    if n <= 1 {
        return;
    }
    let root = root_of_unity(log2_strict(n)).inverse().unwrap();
    transform(v, root);
    let inv_n = Fp::new(n as u32).inverse().unwrap();
    scale_const(v, inv_n);
}

/// Coefficients to evaluations on the coset `shift * H`.
pub fn coset_ntt(v: &mut [Fp], shift: Fp) {
    let pows = power_table(shift, v.len());
    scale(v, &pows);
    ntt(v);
}

/// Evaluations on `shift * H` to coefficients.
pub fn coset_intt(v: &mut [Fp], shift: Fp) {
    intt(v);
    let inv = shift.inverse().expect("shift must be non-zero");
    let pows = power_table(inv, v.len());
    scale(v, &pows);
}

fn map_components(v: &mut [Fp4], f: impl Fn(&mut [Fp])) {
    let mut col = vec![Fp::ZERO; v.len()];
    for k in 0..DEGREE {
        for (c, x) in col.iter_mut().zip(v.iter()) {
            *c = x.0[k];
        }
        f(&mut col);
        for (x, c) in v.iter_mut().zip(&col) {
            x.0[k] = *c;
        }
    }
}

/// [`coset_ntt`] for extension field polynomials.
pub fn coset_ntt_ext(v: &mut [Fp4], shift: Fp) {
    map_components(v, |c| coset_ntt(c, shift));
}

/// [`coset_intt`] for extension field evaluations.
pub fn coset_intt_ext(v: &mut [Fp4], shift: Fp) {
    map_components(v, |c| coset_intt(c, shift));
}

/// Evaluates the polynomial with coefficients `coeffs` at `x` (Horner).
pub fn eval_poly(coeffs: &[Fp], x: Fp) -> Fp {
    coeffs.iter().rev().fold(Fp::ZERO, |acc, c| acc.mul(&x).add(c))
}

/// Evaluates an extension polynomial at an extension point.
pub fn eval_poly_ext(coeffs: &[Fp4], x: Fp4) -> Fp4 {
    coeffs.iter().rev().fold(Fp4::ZERO, |acc, c| acc.mul(&x).add(c))
}

/// `1/2`, used by FRI folding.
pub const fn inv_two() -> Fp {
    INV_2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::Rng;

    #[test]
    fn roots_have_exact_order() {
        assert_eq!(TWO_ADIC_GENERATOR, MULTIPLICATIVE_GENERATOR.pow(15));
        for log_n in 0..=TWO_ADICITY {
            let w = root_of_unity(log_n);
            assert_eq!(w.pow(1u64 << log_n), Fp::ONE, "order 2^{log_n}");
            if log_n > 0 {
                assert_eq!(w.pow(1u64 << (log_n - 1)), -Fp::ONE);
            }
        }
        assert_eq!(INV_2 + INV_2, Fp::ONE);
    }

    #[test]
    fn bit_reversal() {
        let mut v: Vec<u32> = (0..8).collect();
        bit_reverse_permute(&mut v);
        assert_eq!(v, vec![0, 4, 2, 6, 1, 5, 3, 7]);
        let mut v: Vec<u32> = (0..2).collect();
        bit_reverse_permute(&mut v);
        assert_eq!(v, vec![0, 1]);
    }

    #[test]
    fn matches_naive_evaluation() {
        let mut rng = Rng::new(10);
        for log_n in 0..=6 {
            let n = 1 << log_n;
            let coeffs: Vec<Fp> = (0..n).map(|_| rng.fp()).collect();
            let shift = MULTIPLICATIVE_GENERATOR;
            let w = root_of_unity(log_n);
            let mut evals = coeffs.clone();
            coset_ntt(&mut evals, shift);
            for (i, e) in evals.iter().enumerate() {
                let x = shift.mul(&w.pow(i as u64));
                assert_eq!(*e, eval_poly(&coeffs, x), "n={n} i={i}");
            }
            coset_intt(&mut evals, shift);
            assert_eq!(evals, coeffs);

            let mut plain = coeffs.clone();
            ntt(&mut plain);
            for (i, e) in plain.iter().enumerate() {
                assert_eq!(*e, eval_poly(&coeffs, w.pow(i as u64)));
            }
            intt(&mut plain);
            assert_eq!(plain, coeffs);
        }
    }

    #[test]
    fn extension_transform_roundtrip() {
        let mut rng = Rng::new(11);
        let coeffs: Vec<Fp4> = (0..16).map(|_| rng.fp4()).collect();
        let shift = Fp::new(7);
        let w = root_of_unity(4);
        let mut evals = coeffs.clone();
        coset_ntt_ext(&mut evals, shift);
        for (i, e) in evals.iter().enumerate() {
            let x = Fp4::from_base(shift.mul(&w.pow(i as u64)));
            assert_eq!(*e, eval_poly_ext(&coeffs, x));
        }
        coset_intt_ext(&mut evals, shift);
        assert_eq!(evals, coeffs);
    }
}
