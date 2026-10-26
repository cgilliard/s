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
//! halving both the domain and the degree bound. After `log_n - log_blowup`
//! rounds the codeword must be constant; that constant is sent in the clear.
//! The verifier then checks `num_queries` random positions: for each, it
//! walks the rounds, verifying Merkle openings and recomputing the fold.
//!
//! Leaves store the pair `(f(x), f(-x))`: for a domain of size `m` indexed by
//! `i`, leaf `i < m/2` holds `(c[i], c[i + m/2])`. The fold of leaf `i` lands
//! at index `i` of the next codeword, which lives in leaf `i mod m/4` at
//! position `i / (m/4)`. One opening per round therefore suffices.
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

/// One round of a query: the opened leaf pair and its Merkle path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryStep {
    pub pair: [Fp4; 2],
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
                w.fp4(&step.pair[0]);
                w.fp4(&step.pair[1]);
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
                let pair = [r.fp4()?, r.fp4()?];
                let path = r.digest_vec()?;
                steps.push(QueryStep { pair, path });
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

pub(crate) fn pair_row(pair: &[Fp4; 2]) -> [Fp; 2 * DEGREE] {
    let mut row = [Fp::ZERO; 2 * DEGREE];
    row[..DEGREE].copy_from_slice(&pair[0].0);
    row[DEGREE..].copy_from_slice(&pair[1].0);
    row
}

/// `f'(x^2)` from `a = f(x)`, `b = f(-x)` and `x_inv = 1/x`.
#[inline]
fn fold(a: Fp4, b: Fp4, x_inv: Fp, beta: Fp4) -> Fp4 {
    let even = a.add(&b).mul_base(&inv_two());
    let odd = a.sub(&b).mul_base(&inv_two().mul(&x_inv));
    even.add(&beta.mul(&odd))
}

/// Number of folding rounds for a codeword of size `2^log_n`.
pub fn num_rounds(config: &FriConfig, log_n: usize) -> usize {
    assert!(log_n > config.log_blowup, "codeword must be larger than the blowup");
    log_n - config.log_blowup
}

/// Proves that `codeword`, the evaluations of `f` on `shift * H`, has
/// degree below `codeword.len() >> log_blowup`. The caller's transcript
/// must be in the same state the verifier's will be. Also returns the
/// sampled query indices into the input domain, so the caller can open its
/// own commitments at the same positions.
pub fn prove(config: &FriConfig, challenger: &mut Challenger, shift: Fp, codeword: Vec<Fp4>) -> (FriProof, Vec<usize>) {
    let log_n = log2_strict(codeword.len());
    let rounds = num_rounds(config, log_n);
    assert!(log_n <= 27, "domain too large for query sampling");

    let mut trees: Vec<MerkleTree> = Vec::with_capacity(rounds);
    let mut codewords: Vec<Vec<Fp4>> = Vec::with_capacity(rounds);
    let mut commitments = Vec::with_capacity(rounds);
    let mut cur = codeword;
    let mut shift_r = shift;
    let mut omega_inv = root_of_unity(log_n).inverse().unwrap();

    for _ in 0..rounds {
        let half = cur.len() / 2;
        let flat: Vec<Fp> = par_map(half, |i| pair_row(&[cur[i], cur[i + half]])).into_iter().flatten().collect();
        let tree = MerkleTree::from_flat(&flat, 2 * DEGREE);
        challenger.observe_digest(&tree.root());
        let beta = challenger.sample_ext();

        // x_i = shift_r * omega^i, so 1/x_i = shift_r^-1 * omega^-i.
        let shift_inv = shift_r.inverse().unwrap();
        let omega_inv_pows = {
            let mut v = Vec::with_capacity(half);
            let mut p = shift_inv;
            for _ in 0..half {
                v.push(p);
                p = p.mul(&omega_inv);
            }
            v
        };
        let next: Vec<Fp4> = par_map(half, |i| fold(cur[i], cur[i + half], omega_inv_pows[i], beta));

        commitments.push(tree.root());
        trees.push(tree);
        codewords.push(cur);
        cur = next;
        shift_r = shift_r.square();
        omega_inv = omega_inv.square();
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
        for (tree, cw) in trees.iter().zip(&codewords) {
            let half = cw.len() / 2;
            index %= half;
            steps.push(QueryStep { pair: [cw[index], cw[index + half]], path: tree.open(index) });
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
    let rounds = num_rounds(config, log_n);
    if proof.commitments.len() != rounds || proof.queries.len() != config.num_queries {
        return Err(FriError::Shape);
    }
    let mut betas = Vec::with_capacity(rounds);
    for root in &proof.commitments {
        challenger.observe_digest(root);
        betas.push(challenger.sample_ext());
    }
    challenger.observe_ext(&proof.final_value);

    // Per-round domain parameters: round r lives on shift^(2^r) * H_{log_n - r}.
    let mut shift_invs = Vec::with_capacity(rounds);
    let mut omega_invs = Vec::with_capacity(rounds);
    let mut s_inv = shift.inverse().expect("non-zero shift");
    let mut w_inv = root_of_unity(log_n).inverse().unwrap();
    for _ in 0..rounds {
        shift_invs.push(s_inv);
        omega_invs.push(w_inv);
        s_inv = s_inv.square();
        w_inv = w_inv.square();
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
            let log_half = log_n - 1 - r;
            let half = 1usize << log_half;
            let prev_index = index;
            index %= half;
            if !merkle_verify(&proof.commitments[r], log_half, index, &pair_row(&step.pair), &step.path) {
                return Err(FriError::InvalidOpening { query: q, round: r });
            }
            let pos = prev_index / half;
            match folded {
                Some(f) => {
                    if step.pair[pos] != f {
                        return Err(FriError::FoldMismatch { query: q, round: r });
                    }
                }
                None => inputs.push((query_index, step.pair[pos])),
            }
            let x_inv = shift_invs[r].mul(&omega_invs[r].pow(index as u64));
            folded = Some(fold(step.pair[0], step.pair[1], x_inv, betas[r]));
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
            assert_eq!(proof.commitments.len(), log_n - CONFIG.log_blowup);
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
        assert_eq!(verify(&CONFIG, &mut transcript(), shift, log_n + 1, &proof).unwrap_err(), FriError::Shape);
        let fewer = FriConfig { num_queries: 19, ..CONFIG };
        assert_eq!(verify(&fewer, &mut transcript(), shift, log_n, &proof).unwrap_err(), FriError::Shape);

        let mut p = proof.clone();
        p.final_value += Fp4::ONE;
        assert!(verify(&CONFIG, &mut transcript(), shift, log_n, &p).is_err());
        let mut p = proof.clone();
        p.queries[3][1].pair[0] += Fp4::ONE;
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
}
