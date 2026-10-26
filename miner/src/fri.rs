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
//! Queries are sampled as indices into the full input domain. The verifier
//! returns, for every query, the input value the prover committed to at that
//! index; the enclosing protocol must check it against its own openings (in
//! a STARK, the trace and quotient rows at that index). Used standalone, the
//! proof only shows that the *committed* input codeword is low degree.

use crate::challenger::Challenger;
use crate::codec::{Reader, Writer};
use crate::ext::{DEGREE, Fp4};
use crate::merkle::{Digest, MerkleTree, verify as merkle_verify};
use crate::ntt::{inv_two, log2_strict, root_of_unity};
use crate::parallel::par_map;
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

/// Log2 of the arity of each folding round for a codeword of size
/// `2^log_n`: fours, then a final two if the round count is odd.
pub fn round_log_arities(config: &FriConfig, log_n: usize) -> Vec<usize> {
    assert!(log_n > config.log_blowup, "codeword must be larger than the blowup");
    let bits = log_n - config.log_blowup;
    let mut v = vec![2; bits / 2];
    if bits % 2 == 1 {
        v.push(1);
    }
    v
}

/// Number of folding rounds for a codeword of size `2^log_n`.
pub fn num_rounds(config: &FriConfig, log_n: usize) -> usize {
    round_log_arities(config, log_n).len()
}

/// Proves that `codeword`, the evaluations of `f` on `shift * H`, has
/// degree below `codeword.len() >> log_blowup`. The caller's transcript
/// must be in the same state the verifier's will be. Also returns the
/// sampled query indices into the input domain, so the caller can open its
/// own commitments at the same positions.
pub fn prove(config: &FriConfig, challenger: &mut Challenger, shift: Fp, codeword: Vec<Fp4>) -> (FriProof, Vec<usize>) {
    let log_n = log2_strict(codeword.len());
    let arities = round_log_arities(config, log_n);
    let rounds = arities.len();
    assert!(log_n <= 27, "domain too large for query sampling");

    let mut trees: Vec<MerkleTree> = Vec::with_capacity(rounds);
    let mut codewords: Vec<Vec<Fp4>> = Vec::with_capacity(rounds);
    let mut commitments = Vec::with_capacity(rounds);
    let mut cur = codeword;
    let mut shift_r = shift;
    let mut omega_inv = root_of_unity(log_n).inverse().unwrap();

    for &la in &arities {
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

/// Verifies a proof for a codeword of size `2^log_n` on `shift * H`.
///
/// On success returns, per query, the sampled input-domain index and the
/// input value the prover committed to there. Callers that know the input
/// independently must check those values.
pub fn verify(
    config: &FriConfig,
    challenger: &mut Challenger,
    shift: Fp,
    log_n: usize,
    proof: &FriProof,
) -> Result<Vec<(usize, Fp4)>, FriError> {
    let arities = round_log_arities(config, log_n);
    let rounds = arities.len();
    if proof.commitments.len() != rounds || proof.queries.len() != config.num_queries {
        return Err(FriError::Shape);
    }
    let mut betas = Vec::with_capacity(rounds);
    for root in &proof.commitments {
        challenger.observe_digest(root);
        betas.push(challenger.sample_ext());
    }
    challenger.observe_ext(&proof.final_value);

    // Per-round domain parameters: round r lives on shift_r * H with
    // `log_sizes[r]` points; `w_invs[r]` inverts its leaf root of unity.
    let mut shift_invs = Vec::with_capacity(rounds);
    let mut omega_invs = Vec::with_capacity(rounds);
    let mut w_invs = Vec::with_capacity(rounds);
    let mut log_sizes = Vec::with_capacity(rounds);
    let mut s_inv = shift.inverse().expect("non-zero shift");
    let mut w_inv = root_of_unity(log_n).inverse().unwrap();
    let mut log_m = log_n;
    for &la in &arities {
        shift_invs.push(s_inv);
        omega_invs.push(w_inv);
        w_invs.push(w_inv.pow(1u64 << (log_m - la)));
        log_sizes.push(log_m);
        for _ in 0..la {
            s_inv = s_inv.square();
            w_inv = w_inv.square();
        }
        log_m -= la;
    }

    let mut inputs = Vec::with_capacity(config.num_queries);
    for (q, steps) in proof.queries.iter().enumerate() {
        if steps.len() != rounds {
            return Err(FriError::Shape);
        }
        let mut index = challenger.sample_bits(log_n);
        let query_index = index;
        let mut folded: Option<Fp4> = None;
        for (r, step) in steps.iter().enumerate() {
            let la = arities[r];
            if step.values.len() != 1 << la {
                return Err(FriError::Shape);
            }
            let log_leaves = log_sizes[r] - la;
            let leaves = 1usize << log_leaves;
            let pos = index / leaves;
            index %= leaves;
            if !merkle_verify(&proof.commitments[r], log_leaves, index, &leaf_row(&step.values), &step.path) {
                return Err(FriError::InvalidOpening { query: q, round: r });
            }
            match folded {
                Some(f) => {
                    if step.values[pos] != f {
                        return Err(FriError::FoldMismatch { query: q, round: r });
                    }
                }
                None => inputs.push((query_index, step.values[pos])),
            }
            let x_inv = shift_invs[r].mul(&omega_invs[r].pow(index as u64));
            folded = Some(fold_leaf(&step.values, x_inv, w_invs[r], betas[r]));
        }
        if folded != Some(proof.final_value) {
            return Err(FriError::FinalMismatch { query: q });
        }
    }
    Ok(inputs)
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

    #[test]
    fn accepts_low_degree_codewords() {
        let mut rng = Rng::new(30);
        for log_n in [4, 7, 10] {
            let bound = 1 << (log_n - CONFIG.log_blowup);
            let shift = MULTIPLICATIVE_GENERATOR;
            let cw = low_degree_codeword(&mut rng, log_n, bound, shift);
            let (proof, indices) = prove(&CONFIG, &mut transcript(), shift, cw.clone());
            assert_eq!(proof.commitments.len(), (log_n - CONFIG.log_blowup).div_ceil(2));
            assert_eq!(proof.queries.len(), CONFIG.num_queries);
            let inputs = verify(&CONFIG, &mut transcript(), shift, log_n, &proof).unwrap();
            assert_eq!(inputs.len(), CONFIG.num_queries);
            for (q, (index, value)) in inputs.iter().enumerate() {
                assert_eq!(*index, indices[q]);
                assert_eq!(*value, cw[*index], "log_n={log_n} query {q}");
            }
            // Also with a smaller polynomial than the bound, and no shift.
            let cw = low_degree_codeword(&mut rng, log_n, bound / 2, Fp::ONE);
            let (proof, _) = prove(&CONFIG, &mut transcript(), Fp::ONE, cw);
            assert!(verify(&CONFIG, &mut transcript(), Fp::ONE, log_n, &proof).is_ok());
        }
    }

    #[test]
    fn rejects_degree_just_above_bound() {
        let mut rng = Rng::new(31);
        let log_n = 8;
        let bound = 1 << (log_n - CONFIG.log_blowup);
        let shift = MULTIPLICATIVE_GENERATOR;
        let cw = low_degree_codeword(&mut rng, log_n, bound + 1, shift);
        let (proof, _) = prove(&CONFIG, &mut transcript(), shift, cw);
        assert!(verify(&CONFIG, &mut transcript(), shift, log_n, &proof).is_err());
    }

    #[test]
    fn rejects_random_codeword() {
        let mut rng = Rng::new(32);
        let log_n = 8;
        let cw: Vec<Fp4> = (0..1 << log_n).map(|_| rng.fp4()).collect();
        let (proof, _) = prove(&CONFIG, &mut transcript(), Fp::ONE, cw);
        assert!(verify(&CONFIG, &mut transcript(), Fp::ONE, log_n, &proof).is_err());
    }

    #[test]
    fn rejects_tampering_and_mismatched_parameters() {
        let mut rng = Rng::new(33);
        let log_n = 8;
        let bound = 1 << (log_n - CONFIG.log_blowup);
        let shift = MULTIPLICATIVE_GENERATOR;
        let cw = low_degree_codeword(&mut rng, log_n, bound, shift);
        let (proof, _) = prove(&CONFIG, &mut transcript(), shift, cw);
        assert!(verify(&CONFIG, &mut transcript(), shift, log_n, &proof).is_ok());

        // Different transcript prefix.
        assert!(verify(&CONFIG, &mut Challenger::new(), shift, log_n, &proof).is_err());
        // Wrong shift or size.
        assert!(verify(&CONFIG, &mut transcript(), Fp::new(3), log_n, &proof).is_err());
        // One size up has the same round count with arity four (5 and 6
        // folding bits), so it fails at the openings; two up changes shape.
        assert!(verify(&CONFIG, &mut transcript(), shift, log_n + 1, &proof).is_err());
        assert_eq!(verify(&CONFIG, &mut transcript(), shift, log_n + 2, &proof).unwrap_err(), FriError::Shape);
        let fewer = FriConfig { num_queries: 19, ..CONFIG };
        assert_eq!(verify(&fewer, &mut transcript(), shift, log_n, &proof).unwrap_err(), FriError::Shape);

        let mut p = proof.clone();
        p.final_value += Fp4::ONE;
        assert!(verify(&CONFIG, &mut transcript(), shift, log_n, &p).is_err());
        let mut p = proof.clone();
        p.queries[3][1].values[0] += Fp4::ONE;
        assert_eq!(
            verify(&CONFIG, &mut transcript(), shift, log_n, &p).unwrap_err(),
            FriError::InvalidOpening { query: 3, round: 1 }
        );
        let mut p = proof.clone();
        p.commitments[0][0] += Fp::ONE;
        assert!(verify(&CONFIG, &mut transcript(), shift, log_n, &p).is_err());
        let mut p = proof.clone();
        p.queries[0].pop();
        assert_eq!(verify(&CONFIG, &mut transcript(), shift, log_n, &p).unwrap_err(), FriError::Shape);
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
