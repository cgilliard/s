//! FRI low-degree test over `Fp4` codewords on BabyBear cosets.
//!
//! The prover holds the evaluations of a polynomial `f` of degree below
//! `n / 2^log_blowup` on the coset `shift * H` of size `n`. In each round it
//! commits to the current codeword, receives a challenge `beta` from the
//! transcript and folds
//!
//! ```text
//! f'(x^2) = (f(x) + f(-x)) / 2 + beta * (f(x) - f(-x)) / (2x)
//! ```
//!
//! halving both the domain and the degree bound. Rounds fold by four where
//! they can: two binary folds in one round, the first with `beta` and the
//! second with `beta^2`, which is the same as
//! `f'(x^4) = f0(x^4) + beta f1(x^4) + beta^2 f2(x^4) + beta^3 f3(x^4)` for
//! `f(X) = sum_k X^k f_k(X^4)`. When `log_n - log_blowup` is odd the last
//! round folds by two. Once the degree bound reaches one the codeword must
//! be constant; that constant is sent in the clear. The verifier then checks
//! `num_queries` random positions: for each, it walks the rounds, verifying
//! Merkle openings and recomputing the fold.
//!
//! In a round of arity `a` on a domain of size `m`, leaf `i < m/a` holds
//! `c[i + k m/a]` for `k < a`: the values at `x, w x, .., w^(a-1) x` with
//! `w` a primitive `a`-th root of unity. The fold of leaf `i` lands at index
//! `i` of the next codeword, which lives in leaf `i mod m/(a a')` at
//! position `i / (m/(a a'))`. One opening per round therefore suffices.
//!
//! Several codewords of different sizes can be tested together: each
//! smaller one, evaluated on the coset `shift^(n/m) * H_m` that the folded
//! codeword reaches at size `m`, is added to the folded codeword at the
//! start of the round of that size. The round arities are chosen so that
//! every input size starts a round.
//!
//! Queries are sampled as indices into the full input domain. For every
//! query the verifier asks the enclosing protocol for the input values at
//! that index (index `i mod m` for an input of size `m`), which it must
//! compute from its own openings (in a STARK, the DEEP combination of the
//! trace and quotient rows there), and checks them against the committed
//! codewords.

use crate::challenger::Challenger;
use crate::codec::{Reader, Writer};
use crate::ext::{DEGREE, Fp4};
use crate::merkle::{Digest, MerkleTree, verify as merkle_verify};
use crate::ntt::{inv_two, log2_strict, root_of_unity};
use crate::parallel::{par_chunks_mut, par_map};
use crate::poseidon2::Fp;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FriConfig {
    /// Rate is `2^-log_blowup`; the degree bound is `n >> log_blowup`.
    pub log_blowup: usize,
    /// Number of query positions checked by the verifier.
    pub num_queries: usize,
}

/// One round of a query: the opened leaf (as many values as the round's
/// arity) and its Merkle path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryStep {
    pub values: Vec<Fp4>,
    pub path: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriProof {
    /// Merkle roots of the codewords of each round, first round first.
    pub commitments: Vec<Digest>,
    /// The constant final codeword.
    pub final_value: Fp4,
    /// `num_queries` queries, each with one step per round.
    pub queries: Vec<Vec<QueryStep>>,
}

impl FriProof {
    pub fn write(&self, w: &mut Writer) {
        w.digest_vec(&self.commitments);
        w.fp4(&self.final_value);
        w.u32(self.queries.len() as u32);
        for q in &self.queries {
            w.u32(q.len() as u32);
            for step in q {
                w.u32(step.values.len() as u32);
                for v in &step.values {
                    w.fp4(v);
                }
                w.digest_vec(&step.path);
            }
        }
    }

    pub fn read(r: &mut Reader) -> Option<FriProof> {
        let commitments = r.digest_vec()?;
        let final_value = r.fp4()?;
        let nq = r.len(1)?;
        let mut queries = Vec::with_capacity(nq);
        for _ in 0..nq {
            let ns = r.len(32)?;
            let mut steps = Vec::with_capacity(ns);
            for _ in 0..ns {
                let nv = r.len(16)?;
                let values = (0..nv).map(|_| r.fp4()).collect::<Option<Vec<_>>>()?;
                let path = r.digest_vec()?;
                steps.push(QueryStep { values, path });
            }
            queries.push(steps);
        }
        Some(FriProof { commitments, final_value, queries })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FriError {
    /// Number of commitments or queries does not match the parameters.
    Shape,
    InvalidOpening {
        query: usize,
        round: usize,
    },
    FoldMismatch {
        query: usize,
        round: usize,
    },
    FinalMismatch {
        query: usize,
    },
}

impl core::fmt::Display for FriError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FriError::Shape => f.write_str("fri proof has the wrong shape"),
            FriError::InvalidOpening { query, round } => {
                write!(f, "fri query {query} round {round}: invalid merkle opening")
            }
            FriError::FoldMismatch { query, round } => {
                write!(f, "fri query {query} round {round}: fold does not match opened value")
            }
            FriError::FinalMismatch { query } => {
                write!(f, "fri query {query}: last fold does not match final value")
            }
        }
    }
}

impl std::error::Error for FriError {}

/// The scalars of a leaf, as hashed into the Merkle tree.
pub(crate) fn leaf_row(values: &[Fp4]) -> Vec<Fp> {
    values.iter().flat_map(|v| v.0).collect()
}

/// `f'(x^2)` from `a = f(x)`, `b = f(-x)` and `x_inv = 1/x`.
#[inline]
fn fold(a: Fp4, b: Fp4, x_inv: Fp, beta: Fp4) -> Fp4 {
    let even = a.add(&b).mul_base(&inv_two());
    let odd = a.sub(&b).mul_base(&inv_two().mul(&x_inv));
    even.add(&beta.mul(&odd))
}

/// Folds one opened leaf: `values[k]` is the codeword at `w^k x` for `w` a
/// primitive root of unity of order `values.len()` (two or four), with
/// `x_inv = 1/x` and `w_inv = 1/w`.
#[inline]
pub(crate) fn fold_leaf(values: &[Fp4], x_inv: Fp, w_inv: Fp, beta: Fp4) -> Fp4 {
    match values.len() {
        2 => fold(values[0], values[1], x_inv, beta),
        4 => {
            // Pairs at (x, -x) and (w x, -w x), then the pair (x^2, -x^2).
            let g0 = fold(values[0], values[2], x_inv, beta);
            let g1 = fold(values[1], values[3], x_inv.mul(&w_inv), beta);
            fold(g0, g1, x_inv.square(), beta.mul(&beta))
        }
        n => panic!("unsupported fri arity {n}"),
    }
}

/// Log2 of the arity of each folding round for input codewords of sizes
/// `2^log_sizes[g]` (strictly decreasing): between consecutive sizes, and
/// from the last one down to the blowup, fours and then a two if the bit
/// count is odd.
pub fn round_log_arities(config: &FriConfig, log_sizes: &[usize]) -> Vec<usize> {
    assert!(!log_sizes.is_empty(), "no codewords");
    let mut v = Vec::new();
    let mut cur = log_sizes[0];
    for &stop in log_sizes[1..].iter().chain([&config.log_blowup]) {
        assert!(stop < cur, "codeword sizes must decrease and exceed the blowup");
        let bits = cur - stop;
        v.extend(std::iter::repeat_n(2, bits / 2));
        if bits % 2 == 1 {
            v.push(1);
        }
        cur = stop;
    }
    v
}

/// Number of folding rounds for input codewords of sizes `2^log_sizes[g]`.
pub fn num_rounds(config: &FriConfig, log_sizes: &[usize]) -> usize {
    round_log_arities(config, log_sizes).len()
}

/// For every input after the first, the round at whose start it is added.
pub fn injection_rounds(config: &FriConfig, log_sizes: &[usize]) -> Vec<usize> {
    let mut out = Vec::with_capacity(log_sizes.len() - 1);
    let mut log_m = log_sizes[0];
    for (r, la) in round_log_arities(config, log_sizes).into_iter().enumerate() {
        if out.len() + 1 < log_sizes.len() && log_sizes[out.len() + 1] == log_m {
            out.push(r);
        }
        log_m -= la;
    }
    debug_assert_eq!(out.len() + 1, log_sizes.len());
    out
}

/// Proves that each of `inputs` (strictly decreasing sizes) has degree
/// below its length `>> log_blowup`, where `inputs[0]` holds evaluations on
/// `shift * H` and an input of size `m` evaluations on `shift^(n/m) * H_m`.
/// The caller's transcript must be in the same state the verifier's will
/// be. Also returns the sampled query indices into the largest domain, so
/// the caller can open its own commitments at the same positions.
pub fn prove(
    config: &FriConfig,
    challenger: &mut Challenger,
    shift: Fp,
    inputs: Vec<Vec<Fp4>>,
) -> (FriProof, Vec<usize>) {
    let log_sizes: Vec<usize> = inputs.iter().map(|c| log2_strict(c.len())).collect();
    let log_n = log_sizes[0];
    let arities = round_log_arities(config, &log_sizes);
    let rounds = arities.len();
    assert!(log_n <= 27, "domain too large for query sampling");
    let mut inputs = inputs.into_iter();
    let codeword = inputs.next().unwrap();
    let mut pending = inputs.peekable();

    let mut trees: Vec<MerkleTree> = Vec::with_capacity(rounds);
    let mut codewords: Vec<Vec<Fp4>> = Vec::with_capacity(rounds);
    let mut commitments = Vec::with_capacity(rounds);
    let mut cur = codeword;
    let mut shift_r = shift;
    let mut omega_inv = root_of_unity(log_n).inverse().unwrap();

    for &la in &arities {
        if let Some(extra) = pending.next_if(|c| c.len() == cur.len()) {
            par_chunks_mut(&mut cur, 1 << 12, |c, chunk| {
                for (k, v) in chunk.iter_mut().enumerate() {
                    *v += extra[(c << 12) + k];
                }
            });
        }
        let arity = 1usize << la;
        let leaves = cur.len() >> la;
        let leaf = |i: usize| -> Vec<Fp4> { (0..arity).map(|k| cur[i + k * leaves]).collect() };
        let flat: Vec<Fp> = par_map(leaves, |i| leaf_row(&leaf(i))).into_iter().flatten().collect();
        let tree = MerkleTree::from_flat(&flat, arity * DEGREE);
        challenger.observe_digest(&tree.root());
        let beta = challenger.sample_ext();

        // x_i = shift_r * omega^i, so 1/x_i = shift_r^-1 * omega^-i; the
        // leaf's root of unity is omega^leaves.
        let w_inv = omega_inv.pow(leaves as u64);
        let shift_inv = shift_r.inverse().unwrap();
        let x_invs = {
            let mut v = Vec::with_capacity(leaves);
            let mut p = shift_inv;
            for _ in 0..leaves {
                v.push(p);
                p = p.mul(&omega_inv);
            }
            v
        };
        let next: Vec<Fp4> = par_map(leaves, |i| fold_leaf(&leaf(i), x_invs[i], w_inv, beta));

        commitments.push(tree.root());
        trees.push(tree);
        codewords.push(cur);
        cur = next;
        for _ in 0..la {
            shift_r = shift_r.square();
            omega_inv = omega_inv.square();
        }
    }

    debug_assert!(pending.next().is_none());
    // For an honest prover the final codeword is constant. A dishonest one
    // may send anything here; the query phase is what catches it.
    let final_value = cur[0];
    challenger.observe_ext(&final_value);

    let mut queries = Vec::with_capacity(config.num_queries);
    let mut indices = Vec::with_capacity(config.num_queries);
    for _ in 0..config.num_queries {
        let mut index = challenger.sample_bits(log_n);
        indices.push(index);
        let mut steps = Vec::with_capacity(rounds);
        for ((tree, cw), &la) in trees.iter().zip(&codewords).zip(&arities) {
            let leaves = cw.len() >> la;
            index %= leaves;
            let values = (0..1usize << la).map(|k| cw[index + k * leaves]).collect();
            steps.push(QueryStep { values, path: tree.open(index) });
        }
        queries.push(steps);
    }

    (FriProof { commitments, final_value, queries }, indices)
}

/// Verifies a proof for input codewords of sizes `2^log_sizes[g]` (see
/// [`prove`]). For each query, `open(query, index)` must return the input
/// values at `index` (an index into the largest domain; the input of size
/// `m` is read at `index mod m`), one per input, computed independently of
/// the proof's FRI part.
pub fn verify<E: From<FriError>>(
    config: &FriConfig,
    challenger: &mut Challenger,
    shift: Fp,
    log_sizes: &[usize],
    proof: &FriProof,
    mut open: impl FnMut(usize, usize) -> Result<Vec<Fp4>, E>,
) -> Result<(), E> {
    let log_n = log_sizes[0];
    let arities = round_log_arities(config, log_sizes);
    let rounds = arities.len();
    let inject = injection_rounds(config, log_sizes);
    if proof.commitments.len() != rounds || proof.queries.len() != config.num_queries {
        return Err(FriError::Shape.into());
    }
    let mut betas = Vec::with_capacity(rounds);
    for root in &proof.commitments {
        challenger.observe_digest(root);
        betas.push(challenger.sample_ext());
    }
    challenger.observe_ext(&proof.final_value);

    // Per-round domain parameters: round r lives on shift_r * H with
    // `round_log_sizes[r]` points; `w_invs[r]` inverts its leaf root of unity.
    let mut shift_invs = Vec::with_capacity(rounds);
    let mut omega_invs = Vec::with_capacity(rounds);
    let mut w_invs = Vec::with_capacity(rounds);
    let mut round_log_sizes = Vec::with_capacity(rounds);
    let mut s_inv = shift.inverse().expect("non-zero shift");
    let mut w_inv = root_of_unity(log_n).inverse().unwrap();
    let mut log_m = log_n;
    for &la in &arities {
        shift_invs.push(s_inv);
        omega_invs.push(w_inv);
        w_invs.push(w_inv.pow(1u64 << (log_m - la)));
        round_log_sizes.push(log_m);
        for _ in 0..la {
            s_inv = s_inv.square();
            w_inv = w_inv.square();
        }
        log_m -= la;
    }

    for (q, steps) in proof.queries.iter().enumerate() {
        if steps.len() != rounds {
            return Err(FriError::Shape.into());
        }
        let mut index = challenger.sample_bits(log_n);
        let values = open(q, index)?;
        if values.len() != log_sizes.len() {
            return Err(FriError::Shape.into());
        }
        let mut folded = values[0];
        for (r, step) in steps.iter().enumerate() {
            let la = arities[r];
            if step.values.len() != 1 << la {
                return Err(FriError::Shape.into());
            }
            if let Some(g) = inject.iter().position(|&ir| ir == r) {
                folded += values[g + 1];
            }
            let log_leaves = round_log_sizes[r] - la;
            let leaves = 1usize << log_leaves;
            let pos = index / leaves;
            index %= leaves;
            if !merkle_verify(&proof.commitments[r], log_leaves, index, &leaf_row(&step.values), &step.path) {
                return Err(FriError::InvalidOpening { query: q, round: r }.into());
            }
            if step.values[pos] != folded {
                return Err(FriError::FoldMismatch { query: q, round: r }.into());
            }
            let x_inv = shift_invs[r].mul(&omega_invs[r].pow(index as u64));
            folded = fold_leaf(&step.values, x_inv, w_invs[r], betas[r]);
        }
        if folded != proof.final_value {
            return Err(FriError::FinalMismatch { query: q }.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntt::{MULTIPLICATIVE_GENERATOR, coset_ntt_ext};
    use crate::test_util::Rng;

    const CONFIG: FriConfig = FriConfig { log_blowup: 3, num_queries: 20 };

    fn transcript() -> Challenger {
        let mut c = Challenger::new();
        c.observe(Fp::new(0xf21));
        c
    }

    /// Evaluations on `shift * H` of a random polynomial with `degree_bound`
    /// coefficients, padded to a domain of size `2^log_n`.
    fn low_degree_codeword(rng: &mut Rng, log_n: usize, degree_bound: usize, shift: Fp) -> Vec<Fp4> {
        let mut v = vec![Fp4::ZERO; 1 << log_n];
        for c in v.iter_mut().take(degree_bound) {
            *c = rng.fp4();
        }
        coset_ntt_ext(&mut v, shift);
        v
    }

    /// Verifies against the true input codewords, checking that the
    /// queried indices are the ones the prover opened.
    fn check(log_sizes: &[usize], shift: Fp, proof: &FriProof, inputs: &[Vec<Fp4>]) -> Result<Vec<usize>, FriError> {
        let mut seen = Vec::new();
        verify(&CONFIG, &mut transcript(), shift, log_sizes, proof, |_, index| {
            seen.push(index);
            Ok::<_, FriError>(inputs.iter().map(|c| c[index % c.len()]).collect())
        })?;
        Ok(seen)
    }

    #[test]
    fn accepts_low_degree_codewords() {
        let mut rng = Rng::new(30);
        for log_n in [4, 7, 10] {
            let bound = 1 << (log_n - CONFIG.log_blowup);
            let shift = MULTIPLICATIVE_GENERATOR;
            let cw = low_degree_codeword(&mut rng, log_n, bound, shift);
            let (proof, indices) = prove(&CONFIG, &mut transcript(), shift, vec![cw.clone()]);
            assert_eq!(proof.commitments.len(), (log_n - CONFIG.log_blowup).div_ceil(2));
            assert_eq!(proof.queries.len(), CONFIG.num_queries);
            assert_eq!(check(&[log_n], shift, &proof, &[cw]), Ok(indices));
            // Also with a smaller polynomial than the bound, and no shift.
            let cw = low_degree_codeword(&mut rng, log_n, bound / 2, Fp::ONE);
            let (proof, _) = prove(&CONFIG, &mut transcript(), Fp::ONE, vec![cw.clone()]);
            assert!(check(&[log_n], Fp::ONE, &proof, &[cw]).is_ok());
        }
    }

    #[test]
    fn round_schedules() {
        assert_eq!(round_log_arities(&CONFIG, &[10]), vec![2, 2, 2, 1]);
        assert_eq!(round_log_arities(&CONFIG, &[10, 7, 6]), vec![2, 1, 1, 2, 1]);
        assert_eq!(injection_rounds(&CONFIG, &[10, 7, 6]), vec![2, 3]);
        assert_eq!(injection_rounds(&CONFIG, &[10]), Vec::<usize>::new());
    }

    #[test]
    fn injected_codewords() {
        let mut rng = Rng::new(36);
        let shift = MULTIPLICATIVE_GENERATOR;
        for sizes in [vec![10, 7], vec![11, 9, 5], vec![8, 7]] {
            let n = sizes[0];
            let inputs: Vec<Vec<Fp4>> = sizes
                .iter()
                .map(|&l| {
                    let s = shift.pow(1u64 << (n - l));
                    low_degree_codeword(&mut rng, l, 1 << (l - CONFIG.log_blowup), s)
                })
                .collect();
            let (proof, indices) = prove(&CONFIG, &mut transcript(), shift, inputs.clone());
            assert_eq!(proof.commitments.len(), round_log_arities(&CONFIG, &sizes).len());
            assert_eq!(check(&sizes, shift, &proof, &inputs), Ok(indices));
            // A smaller input above its degree bound is caught.
            let mut bad = inputs.clone();
            let l = sizes[1];
            let s = shift.pow(1u64 << (n - l));
            bad[1] = low_degree_codeword(&mut rng, l, (1 << (l - CONFIG.log_blowup)) + 1, s);
            let (proof, _) = prove(&CONFIG, &mut transcript(), shift, bad.clone());
            assert!(check(&sizes, shift, &proof, &bad).is_err());
            // Values that differ from the committed smaller input are caught.
            let (proof, _) = prove(&CONFIG, &mut transcript(), shift, inputs.clone());
            let mut other = inputs.clone();
            other[1].iter_mut().for_each(|v| *v += Fp4::ONE);
            assert!(check(&sizes, shift, &proof, &other).is_err());
        }
    }

    #[test]
    fn rejects_degree_just_above_bound() {
        let mut rng = Rng::new(31);
        let log_n = 8;
        let bound = 1 << (log_n - CONFIG.log_blowup);
        let shift = MULTIPLICATIVE_GENERATOR;
        let cw = low_degree_codeword(&mut rng, log_n, bound + 1, shift);
        let (proof, _) = prove(&CONFIG, &mut transcript(), shift, vec![cw.clone()]);
        assert!(check(&[log_n], shift, &proof, &[cw]).is_err());
    }

    #[test]
    fn rejects_random_codeword() {
        let mut rng = Rng::new(32);
        let log_n = 8;
        let cw: Vec<Fp4> = (0..1 << log_n).map(|_| rng.fp4()).collect();
        let (proof, _) = prove(&CONFIG, &mut transcript(), Fp::ONE, vec![cw.clone()]);
        assert!(check(&[log_n], Fp::ONE, &proof, &[cw]).is_err());
    }

    #[test]
    fn rejects_tampering_and_mismatched_parameters() {
        let mut rng = Rng::new(33);
        let log_n = 8;
        let bound = 1 << (log_n - CONFIG.log_blowup);
        let shift = MULTIPLICATIVE_GENERATOR;
        let cw = low_degree_codeword(&mut rng, log_n, bound, shift);
        let (proof, _) = prove(&CONFIG, &mut transcript(), shift, vec![cw.clone()]);
        let inputs = [cw.clone()];
        assert!(check(&[log_n], shift, &proof, &inputs).is_ok());
        let open = |_: usize, i: usize| Ok::<_, FriError>(vec![cw[i % cw.len()]]);

        // Different transcript prefix.
        assert!(verify(&CONFIG, &mut Challenger::new(), shift, &[log_n], &proof, open).is_err());
        // Wrong shift or size.
        assert!(check(&[log_n], Fp::new(3), &proof, &inputs).is_err());
        // One size up has the same round count with arity four (5 and 6
        // folding bits), so it fails at the openings; two up changes shape.
        assert!(check(&[log_n + 1], shift, &proof, &inputs).is_err());
        assert_eq!(check(&[log_n + 2], shift, &proof, &inputs).unwrap_err(), FriError::Shape);
        let fewer = FriConfig { num_queries: 19, ..CONFIG };
        assert_eq!(verify(&fewer, &mut transcript(), shift, &[log_n], &proof, open).unwrap_err(), FriError::Shape);
        // An input value that differs from the committed codeword.
        let wrong = |_: usize, i: usize| Ok::<_, FriError>(vec![cw[i] + Fp4::ONE]);
        assert_eq!(
            verify(&CONFIG, &mut transcript(), shift, &[log_n], &proof, wrong).unwrap_err(),
            FriError::FoldMismatch { query: 0, round: 0 }
        );

        let mut p = proof.clone();
        p.final_value += Fp4::ONE;
        assert!(check(&[log_n], shift, &p, &inputs).is_err());
        let mut p = proof.clone();
        p.queries[3][1].values[0] += Fp4::ONE;
        assert_eq!(check(&[log_n], shift, &p, &inputs).unwrap_err(), FriError::InvalidOpening { query: 3, round: 1 });
        let mut p = proof.clone();
        p.commitments[0][0] += Fp::ONE;
        assert!(check(&[log_n], shift, &p, &inputs).is_err());
        let mut p = proof.clone();
        p.queries[0].pop();
        assert_eq!(check(&[log_n], shift, &p, &inputs).unwrap_err(), FriError::Shape);
    }

    #[test]
    fn fold_matches_polynomial_split() {
        // f(x) = e(x^2) + x o(x^2); fold with beta gives e(x^2) + beta o(x^2).
        let mut rng = Rng::new(34);
        let e: Vec<Fp4> = (0..4).map(|_| rng.fp4()).collect();
        let o: Vec<Fp4> = (0..4).map(|_| rng.fp4()).collect();
        let x = rng.fp();
        let beta = rng.fp4();
        let x2 = Fp4::from_base(x.square());
        let ev = crate::ntt::eval_poly_ext;
        let f = |p: Fp| ev(&e, Fp4::from_base(p.square())) + ev(&o, Fp4::from_base(p.square())) * p;
        let got = fold(f(x), f(-x), x.inverse().unwrap(), beta);
        assert_eq!(got, ev(&e, x2) + beta * ev(&o, x2));
    }

    #[test]
    fn fold_by_four_matches_polynomial_split() {
        let mut rng = Rng::new(35);
        let parts: Vec<Vec<Fp4>> = (0..4).map(|_| (0..3).map(|_| rng.fp4()).collect()).collect();
        let x = rng.fp();
        let beta = rng.fp4();
        let ev = crate::ntt::eval_poly_ext;
        // f(X) = sum_k X^k f_k(X^4).
        let f = |p: Fp| {
            let p4 = Fp4::from_base(p.square().square());
            let mut acc = Fp4::ZERO;
            let mut pk = Fp::ONE;
            for part in &parts {
                acc += ev(part, p4) * pk;
                pk = pk.mul(&p);
            }
            acc
        };
        let w = root_of_unity(2);
        let values: Vec<Fp4> = (0..4).map(|k| f(x.mul(&w.pow(k)))).collect();
        let got = fold_leaf(&values, x.inverse().unwrap(), w.inverse().unwrap(), beta);
        let x4 = Fp4::from_base(x.square().square());
        let mut want = Fp4::ZERO;
        let mut bk = Fp4::ONE;
        for part in &parts {
            want += ev(part, x4) * bk;
            bk *= beta;
        }
        assert_eq!(got, want);
    }
}
