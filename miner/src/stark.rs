//! A univariate STARK: AIR constraints over an execution trace, proved with
//! Merkle-committed low-degree extensions, a DEEP out-of-domain opening and
//! the FRI low-degree test from [`crate::fri`], with an optional LogUp
//! lookup argument for multiset relations between rows.
//!
//! # Protocol
//!
//! Let the trace have `n = 2^log_n` rows (the domain `H` with generator `g`)
//! and `w` columns, and let `N = n * 2^log_blowup` be the size of the
//! evaluation coset `D = shift * H_N`.
//!
//! 1. The prover interpolates each column over `H`, evaluates it on `D` and
//!    commits to the `N x w` matrix.
//! 2. If the AIR declares lookup terms, the verifier samples `gamma, delta`
//!    and the prover builds the auxiliary trace: for every group of
//!    [`Air::lookup_group`] terms the sum of their signed fractions
//!    `multiplicity / (gamma + sum delta^(k+1) v_k)`, and one running sum of
//!    those columns. It commits to it as a second matrix (extension columns
//!    stored as four base columns each).
//! 3. The verifier samples `alpha`. On every point of `D` the prover
//!    evaluates the AIR constraints and the lookup constraints (one per
//!    group with its denominators cleared, the running-sum transition, and
//!    its values at both ends), combines them as
//!    `C = sum alpha^k c_k`, and divides by `Z_H(x) = x^n - 1`. The
//!    quotient is split into chunks of degree below `n` and committed.
//! 4. The verifier samples `zeta`. The prover opens every trace and
//!    auxiliary column at `zeta` and `g * zeta`, and every chunk at
//!    `zeta_q = zeta^(2^log_quotient)`. The verifier samples `beta`.
//! 5. Both sides form the DEEP combination over all openings; the prover
//!    runs FRI on its evaluations over `D` and opens the committed rows at
//!    every FRI query index.
//!
//! The verifier checks the constraint identity `Q(zeta) Z_H(zeta) = C(zeta)`
//! from the openings, runs the FRI verifier, and recomputes the DEEP value
//! at each queried index from the opened rows.
//!
//! Selectors: `is_first_row = Z_H / (x - 1)`, `is_last_row = Z_H / (x - g^-1)`
//! and `is_transition = x - g^-1`. The first two have degree `n - 1` and
//! count as a column when sizing the quotient; the transition selector has
//! degree one and is absorbed by the slack in the bound. The proof is not
//! zero-knowledge.
//!
//! # Lookups
//!
//! An AIR calls [`Builder::lookup`] with a direction, a multiplicity and a
//! tuple of values. The sum over all rows of `+m / denom` for sends and
//! `-m / denom` for receives must vanish, which (with random challenges)
//! means the multiset of sent tuples, with multiplicities, equals the
//! multiset of received tuples. Lookup terms must not use the row
//! selectors, only columns and constants.
//!
//! A group of terms with denominators `d_i` and signed multiplicities
//! `m_i` has one column `h` and the constraint
//! `h * prod d_i = sum_i m_i prod_(j != i) d_j`, of degree
//! `1 + sum deg d_i`. Larger groups mean fewer columns for a higher
//! constraint degree. The constraint only fixes `h` when no denominator
//! vanishes, which holds except with negligible probability over `gamma`.

use crate::challenger::Challenger;
use crate::codec::{Reader, Writer};
use crate::ext::{DEGREE, Fp4};
use crate::field::{Deg, Field, batch_inverse};
use crate::fri::{self, FriConfig, FriError, FriProof, QueryStep, leaf_row};
use crate::merkle::{Digest, MerkleTree, verify as merkle_verify};
use crate::ntt::{
    MULTIPLICATIVE_GENERATOR, coset_intt_ext, coset_ntt, coset_ntt_ext, intt, log2_strict, root_of_unity,
};
use crate::parallel::{par_chunks_mut, par_map, par_map_min, par_map_with};
use crate::poseidon2::{Fp, zeroed_vec};
use crate::recursion::Expr;

// ---------------------------------------------------------------------------
// AIR interface
// ---------------------------------------------------------------------------

/// One lookup term: `multiplicity / (gamma + sum delta^(k+1) values[k])`,
/// added for sends and subtracted for receives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupTerm<F> {
    pub send: bool,
    pub multiplicity: F,
    pub values: Vec<F>,
}

/// Output buffers of a [`Builder`], kept between rows so that evaluating
/// an AIR on many rows does not allocate per row.
pub(crate) struct Scratch<F> {
    constraints: Vec<F>,
    /// Lookup terms; only the first `num_lookups` are current, the rest
    /// keep their value buffers for reuse.
    lookups: Vec<LookupTerm<F>>,
    num_lookups: usize,
    marks: Vec<(usize, &'static str)>,
}

impl<F> Default for Scratch<F> {
    fn default() -> Self {
        Scratch { constraints: Vec::new(), lookups: Vec::new(), num_lookups: 0, marks: Vec::new() }
    }
}

impl<F> Scratch<F> {
    pub(crate) fn constraints(&self) -> &[F] {
        &self.constraints
    }

    pub(crate) fn terms(&self) -> &[LookupTerm<F>] {
        &self.lookups[..self.num_lookups]
    }
}

/// Collects constraint evaluations and lookup terms for one row pair.
pub struct Builder<'a, F: Field> {
    local: &'a [F],
    next: &'a [F],
    pre_local: &'a [F],
    pre_next: &'a [F],
    public: &'a [F],
    is_first_row: F,
    is_last_row: F,
    is_transition: F,
    out: Scratch<F>,
}

impl<'a, F: Field> Builder<'a, F> {
    pub(crate) fn new(local: &'a [F], next: &'a [F], pre: (&'a [F], &'a [F]), public: &'a [F], sel: (F, F, F)) -> Self {
        Self::with_scratch(local, next, pre, public, sel, Scratch::default())
    }

    /// A builder writing into reused buffers, which it clears.
    fn with_scratch(
        local: &'a [F],
        next: &'a [F],
        pre: (&'a [F], &'a [F]),
        public: &'a [F],
        sel: (F, F, F),
        mut out: Scratch<F>,
    ) -> Self {
        out.constraints.clear();
        out.num_lookups = 0;
        out.marks.clear();
        Builder {
            local,
            next,
            pre_local: pre.0,
            pre_next: pre.1,
            public,
            is_first_row: sel.0,
            is_last_row: sel.1,
            is_transition: sel.2,
            out,
        }
    }

    /// Labels the constraints emitted from here on, for diagnostics from
    /// [`check_constraints`]. Has no effect on proving.
    pub fn mark(&mut self, label: &'static str) {
        self.out.marks.push((self.out.constraints.len(), label));
    }

    pub fn local(&self) -> &'a [F] {
        self.local
    }

    pub fn next(&self) -> &'a [F] {
        self.next
    }

    /// Preprocessed columns of this row (see [`Air::preprocessed_width`]).
    pub fn preprocessed(&self) -> &'a [F] {
        self.pre_local
    }

    /// Preprocessed columns of the next row.
    pub fn preprocessed_next(&self) -> &'a [F] {
        self.pre_next
    }

    /// Public values, embedded in the evaluation field.
    pub fn public(&self) -> &'a [F] {
        self.public
    }

    /// Constraints and lookup terms collected so far (for compilers).
    pub(crate) fn into_parts(self) -> (Vec<F>, Vec<LookupTerm<F>>) {
        let mut out = self.out;
        out.lookups.truncate(out.num_lookups);
        (out.constraints, out.lookups)
    }

    /// Requires `c == 0` on every row.
    pub fn assert_zero(&mut self, c: F) {
        self.out.constraints.push(c);
    }

    pub fn assert_eq(&mut self, a: F, b: F) {
        self.assert_zero(a - b);
    }

    /// Requires `c == 0` on the first row only (adds one to the degree).
    pub fn when_first_row(&mut self, c: F) {
        let s = self.is_first_row;
        self.assert_zero(s * c);
    }

    /// Requires `c == 0` on the last row only (adds one to the degree).
    pub fn when_last_row(&mut self, c: F) {
        let s = self.is_last_row;
        self.assert_zero(s * c);
    }

    /// Requires `c == 0` on every row but the last, where `next` wraps
    /// around. The selector is `x - g^-1`, degree one in `x`, so unlike the
    /// row selectors it does not add to the constraint degree count.
    pub fn when_transition(&mut self, c: F) {
        let s = self.is_transition;
        self.assert_zero(s * c);
    }

    /// Declares a lookup term. `send` adds `multiplicity / denom` to the
    /// running sum, a receive subtracts it. Values and multiplicity must be
    /// built from columns and constants only.
    pub fn lookup(&mut self, send: bool, multiplicity: F, values: &[F]) {
        let out = &mut self.out;
        if out.num_lookups < out.lookups.len() {
            let term = &mut out.lookups[out.num_lookups];
            term.send = send;
            term.multiplicity = multiplicity;
            term.values.clear();
            term.values.extend_from_slice(values);
        } else {
            out.lookups.push(LookupTerm { send, multiplicity, values: values.to_vec() });
        }
        out.num_lookups += 1;
    }
}

/// An algebraic intermediate representation: constraints over consecutive
/// trace rows. `eval` must be the same polynomial map for both field types.
pub trait Air: Sync {
    /// Number of trace columns.
    fn width(&self) -> usize;

    /// Maximum total degree of any constraint, counting each column as one
    /// and each of `when_first_row` / `when_last_row` as one;
    /// `when_transition` is free. Lookup terms add one to the degree of
    /// their multiplicity and values (two for the multiplicity). Must be at
    /// least one.
    fn max_constraint_degree(&self) -> usize;

    /// Number of preprocessed columns: a fixed table, committed once and
    /// known to the verifier by its root, that constraints may read through
    /// [`Builder::preprocessed`]. Zero by default.
    fn preprocessed_width(&self) -> usize {
        0
    }

    /// Lookup terms summed per auxiliary column, in declaration order. A
    /// group's constraint has degree one plus the degrees of its
    /// denominators, which must fit [`Air::max_constraint_degree`].
    fn lookup_group(&self) -> usize {
        1
    }

    fn eval<F: Field>(&self, builder: &mut Builder<'_, F>);
}

/// An [`Air`] behind a trait object, so that the tables of one proof can
/// have different AIR types. Implemented for every `Air`.
pub trait DynAir: Sync {
    fn air_width(&self) -> usize;
    fn air_degree(&self) -> usize;
    fn air_preprocessed_width(&self) -> usize;
    fn air_lookup_group(&self) -> usize;
    fn eval_fp(&self, b: &mut Builder<'_, Fp>);
    fn eval_fp4(&self, b: &mut Builder<'_, Fp4>);
    fn eval_deg(&self, b: &mut Builder<'_, Deg>);
    fn eval_expr(&self, b: &mut Builder<'_, Expr>);
}

impl<A: Air> DynAir for A {
    fn air_width(&self) -> usize {
        self.width()
    }
    fn air_degree(&self) -> usize {
        self.max_constraint_degree()
    }
    fn air_preprocessed_width(&self) -> usize {
        self.preprocessed_width()
    }
    fn air_lookup_group(&self) -> usize {
        self.lookup_group().max(1)
    }
    fn eval_fp(&self, b: &mut Builder<'_, Fp>) {
        self.eval(b)
    }
    fn eval_fp4(&self, b: &mut Builder<'_, Fp4>) {
        self.eval(b)
    }
    fn eval_deg(&self, b: &mut Builder<'_, Deg>) {
        self.eval(b)
    }
    fn eval_expr(&self, b: &mut Builder<'_, Expr>) {
        self.eval(b)
    }
}

/// Fields a [`DynAir`] can be evaluated over.
pub trait EvalField: Field {
    fn eval_air(air: &dyn DynAir, b: &mut Builder<'_, Self>);
}

impl EvalField for Fp {
    fn eval_air(air: &dyn DynAir, b: &mut Builder<'_, Fp>) {
        air.eval_fp(b)
    }
}

impl EvalField for Fp4 {
    fn eval_air(air: &dyn DynAir, b: &mut Builder<'_, Fp4>) {
        air.eval_fp4(b)
    }
}

impl EvalField for Deg {
    fn eval_air(air: &dyn DynAir, b: &mut Builder<'_, Deg>) {
        air.eval_deg(b)
    }
}

impl EvalField for Expr {
    fn eval_air(air: &dyn DynAir, b: &mut Builder<'_, Expr>) {
        air.eval_expr(b)
    }
}

/// Row-major trace matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    pub values: Vec<Fp>,
    pub width: usize,
}

impl Trace {
    pub fn new(values: Vec<Fp>, width: usize) -> Trace {
        assert!(width > 0 && values.len().is_multiple_of(width));
        let t = Trace { values, width };
        assert!(t.height().is_power_of_two() && t.height() >= 2, "trace height must be a power of two >= 2");
        t
    }

    pub fn height(&self) -> usize {
        self.values.len() / self.width
    }

    pub fn row(&self, i: usize) -> &[Fp] {
        &self.values[i * self.width..(i + 1) * self.width]
    }

    pub fn column(&self, k: usize) -> Vec<Fp> {
        (0..self.height()).map(|i| self.values[i * self.width + k]).collect()
    }
}

// ---------------------------------------------------------------------------
// Configuration and proof
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StarkConfig {
    /// Evaluation domain is `2^log_blowup` times the trace height. Must be at
    /// least `log2_ceil(max_constraint_degree - 1)`.
    pub log_blowup: usize,
    pub num_queries: usize,
    /// Proof-of-work bits ground before the FRI queries are sampled; each
    /// bit adds one bit of security against a prover trying many
    /// transcripts.
    pub pow_bits: usize,
}

impl StarkConfig {
    pub(crate) fn fri(&self) -> FriConfig {
        FriConfig { log_blowup: self.log_blowup, num_queries: self.num_queries, pow_bits: self.pow_bits }
    }
}

/// Openings of one table's committed matrices at one queried index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryOpening {
    pub trace_row: Vec<Fp>,
    pub trace_path: Vec<Digest>,
    pub aux_row: Vec<Fp>,
    pub aux_path: Vec<Digest>,
    pub pre_row: Vec<Fp>,
    pub pre_path: Vec<Digest>,
    pub quotient_row: Vec<Fp>,
    pub quotient_path: Vec<Digest>,
}

/// The part of a proof that belongs to one table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableProof {
    pub log_n: usize,
    pub trace_root: Digest,
    /// Present when the AIR declares lookups.
    pub aux_root: Option<Digest>,
    /// The table's total of its lookup terms (zero without lookups). The
    /// totals of all tables must add up to zero.
    pub lookup_sum: Fp4,
    pub quotient_root: Digest,
    pub trace_at_zeta: Vec<Fp4>,
    pub trace_at_zeta_next: Vec<Fp4>,
    /// Auxiliary base columns at zeta (four per extension column).
    pub aux_at_zeta: Vec<Fp4>,
    pub aux_at_zeta_next: Vec<Fp4>,
    /// Preprocessed columns at zeta (empty without preprocessed columns).
    pub pre_at_zeta: Vec<Fp4>,
    pub pre_at_zeta_next: Vec<Fp4>,
    pub quotient_at_zeta_q: Vec<Fp4>,
}

impl TableProof {
    /// The out-of-domain openings, in transcript order.
    pub fn opened(&self) -> [&Vec<Fp4>; 7] {
        [
            &self.trace_at_zeta,
            &self.trace_at_zeta_next,
            &self.aux_at_zeta,
            &self.aux_at_zeta_next,
            &self.pre_at_zeta,
            &self.pre_at_zeta_next,
            &self.quotient_at_zeta_q,
        ]
    }

    fn write(&self, w: &mut Writer) {
        w.u32(self.log_n as u32);
        w.digest(&self.trace_root);
        match &self.aux_root {
            Some(r) => {
                w.u32(1);
                w.digest(r);
                w.fp4(&self.lookup_sum);
            }
            None => w.u32(0),
        }
        w.digest(&self.quotient_root);
        for v in self.opened() {
            w.fp4_vec(v);
        }
    }

    fn read(r: &mut Reader) -> Option<TableProof> {
        let log_n = r.u32()? as usize;
        let trace_root = r.digest()?;
        let (aux_root, lookup_sum) = match r.u32()? {
            0 => (None, Fp4::ZERO),
            1 => (Some(r.digest()?), r.fp4()?),
            _ => return None,
        };
        Some(TableProof {
            log_n,
            trace_root,
            aux_root,
            lookup_sum,
            quotient_root: r.digest()?,
            trace_at_zeta: r.fp4_vec()?,
            trace_at_zeta_next: r.fp4_vec()?,
            aux_at_zeta: r.fp4_vec()?,
            aux_at_zeta_next: r.fp4_vec()?,
            pre_at_zeta: r.fp4_vec()?,
            pre_at_zeta_next: r.fp4_vec()?,
            quotient_at_zeta_q: r.fp4_vec()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// One part per table, tallest table first.
    pub tables: Vec<TableProof>,
    pub fri: FriProof,
    /// For every FRI query, one opening per table.
    pub openings: Vec<Vec<QueryOpening>>,
    /// The sampled query indices into the largest domain. The verifier
    /// samples them itself and rejects a proof that disagrees; the encoding
    /// needs them to rebuild the Merkle paths it leaves out.
    pub query_indices: Vec<usize>,
}

impl Proof {
    /// Every Merkle tree the proof opens, as its height and, per query,
    /// the opened leaf's hash and path: per table its trace, auxiliary,
    /// preprocessed and quotient trees, then the FRI rounds. An absent tree
    /// has height zero. A query's leaf in a tree of height `h` is its index
    /// modulo `2^h`.
    #[allow(clippy::type_complexity)]
    fn trees(&self) -> Vec<(usize, Vec<(Digest, &[Digest])>)> {
        let nq = self.openings.len();
        let mut out = Vec::new();
        for t in 0..self.tables.len() {
            for k in 0..4 {
                let per_q: Vec<(Digest, &[Digest])> = (0..nq)
                    .map(|q| {
                        let o = &self.openings[q][t];
                        let (row, path) = match k {
                            0 => (&o.trace_row, &o.trace_path),
                            1 => (&o.aux_row, &o.aux_path),
                            2 => (&o.pre_row, &o.pre_path),
                            _ => (&o.quotient_row, &o.quotient_path),
                        };
                        (
                            if row.is_empty() {
                                [Fp::ZERO; crate::poseidon2::DIGEST]
                            } else {
                                crate::merkle::hash_row(row)
                            },
                            &path[..],
                        )
                    })
                    .collect();
                out.push((per_q.first().map_or(0, |p| p.1.len()), per_q));
            }
        }
        let rounds = self.fri.queries.first().map_or(0, |q| q.len());
        for r in 0..rounds {
            let per_q: Vec<(Digest, &[Digest])> = self
                .fri
                .queries
                .iter()
                .map(|q| (crate::merkle::hash_row(&leaf_row(&q[r].values)), &q[r].path[..]))
                .collect();
            out.push((per_q.first().map_or(0, |p| p.1.len()), per_q));
        }
        out
    }

    /// Encodes the proof. Merkle paths are batched per tree: a sibling
    /// that another opening determines, or that an earlier query already
    /// sent, is left out (see [`crate::merkle::compress_paths`]).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(1 << 16);
        w.u32(self.tables.len() as u32);
        for t in &self.tables {
            t.write(&mut w);
        }
        let nq = self.openings.len();
        assert_eq!(self.query_indices.len(), nq, "one index per query");
        assert_eq!(self.fri.queries.len(), nq, "one fri query per opening");
        let rounds = self.fri.queries.first().map_or(0, |q| q.len());
        assert!(self.fri.queries.iter().all(|q| q.len() == rounds), "fri queries of one shape");
        w.digest_vec(&self.fri.commitments);
        w.fp4(&self.fri.final_value);
        w.fp(&self.fri.pow_witness);
        w.u32(nq as u32);
        w.u32(rounds as u32);
        for (q, steps) in self.fri.queries.iter().enumerate() {
            w.u32(self.query_indices[q] as u32);
            for step in steps {
                w.fp4_vec(&step.values);
            }
            for o in &self.openings[q] {
                w.fp_vec(&o.trace_row);
                w.fp_vec(&o.aux_row);
                w.fp_vec(&o.pre_row);
                w.fp_vec(&o.quotient_row);
            }
        }
        let trees = self.trees();
        for (height, per_q) in &trees {
            assert!(per_q.iter().all(|p| p.1.len() == *height), "paths of one tree have one length");
            w.u32(*height as u32);
        }
        for (height, per_q) in &trees {
            let leaves: Vec<Digest> = per_q.iter().map(|p| p.0).collect();
            let paths: Vec<&[Digest]> = per_q.iter().map(|p| p.1).collect();
            for d in crate::merkle::compress_paths(*height, &self.query_indices, &leaves, &paths) {
                w.digest(&d);
            }
        }
        w.finish()
    }

    /// Parses a proof; the whole slice must be consumed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Proof> {
        let mut r = Reader(bytes);
        let nt = r.len(64)?;
        if nt == 0 {
            return None;
        }
        let tables = (0..nt).map(|_| TableProof::read(&mut r)).collect::<Option<Vec<_>>>()?;
        let commitments = r.digest_vec()?;
        let final_value = r.fp4()?;
        let pow_witness = r.fp()?;
        let nq = r.len(4)?;
        let rounds = r.len(0)?;
        if rounds > 32 {
            return None;
        }
        let mut query_indices = Vec::with_capacity(nq);
        let mut fri_queries = Vec::with_capacity(nq);
        let mut openings = Vec::with_capacity(nq);
        for _ in 0..nq {
            query_indices.push(r.u32()? as usize);
            let steps = (0..rounds)
                .map(|_| Some(QueryStep { values: r.fp4_vec()?, path: Vec::new() }))
                .collect::<Option<Vec<_>>>()?;
            fri_queries.push(steps);
            let mut per_table = Vec::with_capacity(nt);
            for _ in 0..nt {
                per_table.push(QueryOpening {
                    trace_row: r.fp_vec()?,
                    trace_path: Vec::new(),
                    aux_row: r.fp_vec()?,
                    aux_path: Vec::new(),
                    pre_row: r.fp_vec()?,
                    pre_path: Vec::new(),
                    quotient_row: r.fp_vec()?,
                    quotient_path: Vec::new(),
                });
            }
            openings.push(per_table);
        }
        let mut proof = Proof {
            tables,
            fri: FriProof { commitments, final_value, pow_witness, queries: fri_queries },
            openings,
            query_indices,
        };
        let num_trees = 4 * nt + rounds;
        let mut heights = Vec::with_capacity(num_trees);
        for _ in 0..num_trees {
            let h = r.u32()? as usize;
            if h > 32 {
                return None;
            }
            heights.push(h);
        }
        let mut all_paths: Vec<Vec<Vec<Digest>>> = Vec::with_capacity(num_trees);
        for (tree, (_, per_q)) in proof.trees().into_iter().enumerate() {
            let leaves: Vec<Digest> = per_q.iter().map(|p| p.0).collect();
            all_paths.push(crate::merkle::expand_paths(heights[tree], &proof.query_indices, &leaves, || r.digest())?);
        }
        if !r.is_empty() {
            return None;
        }
        let mut it = all_paths.into_iter();
        for t in 0..nt {
            for k in 0..4 {
                for (q, path) in it.next().unwrap().into_iter().enumerate() {
                    let o = &mut proof.openings[q][t];
                    *match k {
                        0 => &mut o.trace_path,
                        1 => &mut o.aux_path,
                        2 => &mut o.pre_path,
                        _ => &mut o.quotient_path,
                    } = path;
                }
            }
        }
        for rd in 0..rounds {
            for (q, path) in it.next().unwrap().into_iter().enumerate() {
                proof.fri.queries[q][rd].path = path;
            }
        }
        Some(proof)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    Shape,
    ConstraintIdentity,
    /// The tables' lookup totals do not cancel.
    LookupSum,
    Fri(FriError),
    InvalidTraceOpening {
        query: usize,
    },
    InvalidAuxOpening {
        query: usize,
    },
    InvalidPreprocessedOpening {
        query: usize,
    },
    InvalidQuotientOpening {
        query: usize,
    },
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::Shape => f.write_str("stark proof has the wrong shape"),
            VerifyError::ConstraintIdentity => f.write_str("constraints do not hold at the out-of-domain point"),
            VerifyError::LookupSum => f.write_str("lookup totals of the tables do not cancel"),
            VerifyError::Fri(e) => write!(f, "{e}"),
            VerifyError::InvalidTraceOpening { query } => {
                write!(f, "query {query}: invalid trace opening")
            }
            VerifyError::InvalidAuxOpening { query } => {
                write!(f, "query {query}: invalid auxiliary opening")
            }
            VerifyError::InvalidPreprocessedOpening { query } => {
                write!(f, "query {query}: invalid preprocessed opening")
            }
            VerifyError::InvalidQuotientOpening { query } => {
                write!(f, "query {query}: invalid quotient opening")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<FriError> for VerifyError {
    fn from(e: FriError) -> Self {
        VerifyError::Fri(e)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// `log2_ceil(max(d - 1, 1))`: number of quotient chunks is `2^this`.
pub fn log_quotient_degree(max_constraint_degree: usize) -> usize {
    let q = max_constraint_degree.saturating_sub(1).max(1);
    (usize::BITS - (q - 1).leading_zeros()) as usize
}

/// Lookup challenges, with the powers of `delta` that denominators use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupChallenges {
    pub gamma: Fp4,
    pub delta: Fp4,
    /// `delta^1 .. delta^DELTA_POWERS`.
    delta_powers: Vec<Fp4>,
}

const DELTA_POWERS: usize = 32;

impl LookupChallenges {
    pub fn new(gamma: Fp4, delta: Fp4) -> LookupChallenges {
        let delta_powers = powers(delta, DELTA_POWERS + 1)[1..].to_vec();
        LookupChallenges { gamma, delta, delta_powers }
    }

    fn sample(ch: &mut Challenger) -> LookupChallenges {
        let gamma = ch.sample_ext();
        let delta = ch.sample_ext();
        LookupChallenges::new(gamma, delta)
    }

    /// `gamma + sum delta^(k+1) values[k]`.
    fn denominator<F: Field>(&self, values: &[F]) -> Fp4 {
        let mut acc = self.gamma;
        for (v, pow) in values.iter().zip(&self.delta_powers) {
            acc += v.mul_ext(*pow);
        }
        if values.len() > DELTA_POWERS {
            let mut pow = self.delta_powers[DELTA_POWERS - 1];
            for v in &values[DELTA_POWERS..] {
                pow *= self.delta;
                acc += v.mul_ext(pow);
            }
        }
        acc
    }
}

/// Evaluates the AIR at one row pair.
pub(crate) fn evaluate<F: EvalField>(
    air: &dyn DynAir,
    local: &[F],
    next: &[F],
    pre: (&[F], &[F]),
    public: &[F],
    sel: (F, F, F),
) -> (Vec<F>, Vec<LookupTerm<F>>) {
    let mut b = Builder::new(local, next, pre, public, sel);
    F::eval_air(air, &mut b);
    b.into_parts()
}

/// Evaluates the AIR at one row pair into reused buffers.
pub(crate) fn evaluate_into<F: EvalField>(
    air: &dyn DynAir,
    local: &[F],
    next: &[F],
    pre: (&[F], &[F]),
    public: &[F],
    sel: (F, F, F),
    scratch: &mut Scratch<F>,
) {
    let mut b = Builder::with_scratch(local, next, pre, public, sel, std::mem::take(scratch));
    F::eval_air(air, &mut b);
    *scratch = b.out;
}

/// Auxiliary extension columns for `terms` lookup terms summed `group` at
/// a time: one per group and the running sum.
pub(crate) fn lookup_columns(terms: usize, group: usize) -> usize {
    if terms == 0 { 0 } else { terms.div_ceil(group) + 1 }
}

/// Number of lookup constraints for `terms` lookup terms in groups of
/// `group`: one per group plus the running-sum transition and its two
/// boundary checks.
pub(crate) fn num_lookup_constraints(terms: usize, group: usize) -> usize {
    if terms == 0 { 0 } else { terms.div_ceil(group) + 3 }
}

/// Counts constraints and lookup terms an AIR emits (on an all-zero row pair).
pub(crate) fn shape(air: &dyn DynAir, public: &[Fp]) -> (usize, usize) {
    let zeros = vec![Fp::ZERO; air.air_width()];
    let pre = vec![Fp::ZERO; air.air_preprocessed_width()];
    let (c, t) = evaluate(air, &zeros, &zeros, (&pre, &pre), public, (Fp::ZERO, Fp::ZERO, Fp::ZERO));
    (c.len(), t.len())
}

/// Lookup settings of a table for [`combine`]: challenges, the table's
/// lookup total and the group size.
#[derive(Clone, Copy)]
struct LookupArgs<'a> {
    ch: &'a LookupChallenges,
    total: Fp4,
    group: usize,
}

/// Combines main constraints and lookup constraints with powers of alpha.
/// The lookup constraints, in order: one per group of terms
/// (`h * prod d_i - sum m_i prod_(j != i) d_j`), the running-sum transition,
/// the running sum starting at zero, and the last row reaching the table's
/// lookup `total`. `aux_local`/`aux_next` are the extension values: the
/// group sums then the running sum.
fn combine<F: Field>(
    constraints: &[F],
    terms: &[LookupTerm<F>],
    aux_local: &[Fp4],
    aux_next: &[Fp4],
    sel: (Fp4, Fp4, Fp4),
    lookup: Option<LookupArgs<'_>>,
    alpha_powers: &[Fp4],
) -> Fp4 {
    let mut acc = Fp4::ZERO;
    for (c, a) in constraints.iter().zip(alpha_powers) {
        acc += c.mul_ext(*a);
    }
    if let Some(LookupArgs { ch, total, group }) = lookup {
        let a = &alpha_powers[constraints.len()..];
        let groups = terms.len().div_ceil(group);
        let mut contrib = Fp4::ZERO;
        for (j, members) in terms.chunks(group).enumerate() {
            // Running numerator and denominator of the group's fractions.
            let (mut num, mut den) = (Fp4::ZERO, Fp4::ONE);
            for term in members {
                let d = ch.denominator(&term.values);
                let m = term.multiplicity.mul_ext(Fp4::ONE);
                num = num * d + if term.send { m * den } else { -(m * den) };
                den *= d;
            }
            let h = aux_local[j];
            acc += (h * den - num) * a[j];
            contrib += h;
        }
        let s = aux_local[groups];
        let s_next = aux_next[groups];
        acc += sel.2 * (s_next - s - contrib) * a[groups];
        acc += sel.0 * s * a[groups + 1];
        acc += sel.1 * (s + contrib - total) * a[groups + 2];
    }
    acc
}

pub(crate) fn powers(base: Fp4, count: usize) -> Vec<Fp4> {
    let mut out = Vec::with_capacity(count);
    let mut acc = Fp4::ONE;
    for _ in 0..count {
        out.push(acc);
        acc *= base;
    }
    out
}

/// Horner evaluation of extension coefficients at an extension point.
fn eval_ext_poly_at(coeffs: &[Fp4], x: Fp4) -> Fp4 {
    coeffs.iter().rev().fold(Fp4::ZERO, |acc, c| acc * x + *c)
}

fn ext_row(values: &[Fp4]) -> Vec<Fp> {
    values.iter().flat_map(|v| v.0).collect()
}

fn ext_from_row(row: &[Fp]) -> Vec<Fp4> {
    row.chunks_exact(DEGREE).map(|c| Fp4([c[0], c[1], c[2], c[3]])).collect()
}

/// Reconstructs extension column values from their four base-column
/// openings: `c0 + c1 X + c2 X^2 + c3 X^3`.
fn ext_from_base_openings(opened: &[Fp4]) -> Vec<Fp4> {
    opened
        .chunks_exact(DEGREE)
        .map(|c| {
            let mut acc = c[DEGREE - 1];
            for k in (0..DEGREE - 1).rev() {
                acc = acc * Fp4::X + c[k];
            }
            acc
        })
        .collect()
}

/// The coset `shift * H` of the `2^log_n`-th roots of unity, in order.
fn coset_points(shift: Fp, log_n: usize) -> Vec<Fp> {
    let omega = root_of_unity(log_n);
    let mut v = Vec::with_capacity(1 << log_n);
    let mut x = shift;
    for _ in 0..1usize << log_n {
        v.push(x);
        x = x.mul(&omega);
    }
    v
}

/// Coset of the evaluation domain of a table whose domain has `2^log_m`
/// points, in a proof whose largest domain has `2^log_big`: the coset the
/// FRI folding of the largest domain reaches at that size.
fn table_shift(log_big: usize, log_m: usize) -> Fp {
    MULTIPLICATIVE_GENERATOR.pow(1u64 << (log_big - log_m))
}

/// Out-of-domain openings: trace at zeta and g zeta, aux at zeta and g zeta,
/// quotient chunks at zeta_q.
/// DEEP combination `sum_k beta^k (row_k - opened_k) / (x - point_k)`,
/// arranged so each row costs base-times-extension products only: the
/// opened values are folded into constants once, and the openings at `g
/// zeta` reuse the row sum at `zeta` scaled by a power of `beta`.
/// Beta power offsets: trace at zeta, trace at g zeta, aux at both,
/// preprocessed at both, then the quotient chunks. Later tables continue
/// the powers: their combination is scaled by `beta^offset`, the number of
/// openings of the tables before them.
struct Deep {
    w: usize,
    aux_w: usize,
    pre_w: usize,
    beta_powers: Vec<Fp4>,
    beta_w: Fp4,
    beta_aux: Fp4,
    beta_pre: Fp4,
    c_tz: Fp4,
    c_tzn: Fp4,
    c_az: Fp4,
    c_azn: Fp4,
    c_pz: Fp4,
    c_pzn: Fp4,
    c_q: Fp4,
}

impl Deep {
    fn new(beta: Fp4, t: &TableProof) -> Deep {
        let [t_z, t_zn, a_z, a_zn, p_z, p_zn, q_zq] = t.opened();
        let (w, aux_w, pre_w, chunks) = (t_z.len(), a_z.len(), p_z.len(), q_zq.len());
        let beta_powers = powers(beta, 2 * w + 2 * aux_w + 2 * pre_w + chunks);
        let dot = |from: usize, vals: &[Fp4]| -> Fp4 {
            vals.iter().zip(&beta_powers[from..]).fold(Fp4::ZERO, |acc, (v, b)| acc + *v * *b)
        };
        Deep {
            w,
            aux_w,
            pre_w,
            c_tz: dot(0, t_z),
            c_tzn: dot(w, t_zn),
            c_az: dot(2 * w, a_z),
            c_azn: dot(2 * w + aux_w, a_zn),
            c_pz: dot(2 * w + 2 * aux_w, p_z),
            c_pzn: dot(2 * w + 2 * aux_w + pre_w, p_zn),
            c_q: dot(2 * w + 2 * aux_w + 2 * pre_w, q_zq),
            beta_w: beta.exp(w as u64),
            beta_aux: beta.exp(aux_w as u64),
            beta_pre: beta.exp(pre_w as u64),
            beta_powers,
        }
    }

    /// Number of openings this table contributes.
    fn len(&self) -> usize {
        self.beta_powers.len()
    }

    fn value(&self, rows: Rows<'_>, inv_z: Fp4, inv_zn: Fp4, inv_q: Fp4) -> Fp4 {
        let (trace_row, aux_row, pre_row, quotient_row) = rows;
        let (w, aux_w, pre_w) = (self.w, self.aux_w, self.pre_w);
        let bp = &self.beta_powers;
        let base_dot =
            |row: &[Fp], from: usize| row.iter().zip(&bp[from..]).fold(Fp4::ZERO, |acc, (v, b)| acc + b.mul_base(v));
        let s_t = base_dot(trace_row, 0);
        let s_a = base_dot(aux_row, 2 * w);
        let s_p = base_dot(pre_row, 2 * w + 2 * aux_w);
        let q_from = 2 * w + 2 * aux_w + 2 * pre_w;
        let s_q = quotient_row.iter().zip(&bp[q_from..]).fold(Fp4::ZERO, |acc, (v, b)| acc + *v * *b);
        (s_t - self.c_tz + s_a - self.c_az + s_p - self.c_pz) * inv_z
            + (self.beta_w * s_t - self.c_tzn + self.beta_aux * s_a - self.c_azn + self.beta_pre * s_p - self.c_pzn)
                * inv_zn
            + (s_q - self.c_q) * inv_q
    }
}

type Rows<'a> = (&'a [Fp], &'a [Fp], &'a [Fp], &'a [Fp4]);

/// A committed fixed table: the low-degree extension and Merkle tree of
/// preprocessed columns, built once and reused across proofs.
pub struct Preprocessed {
    pub width: usize,
    pub log_n: usize,
    pub log_blowup: usize,
    table: Trace,
    coeffs: Vec<Vec<Fp>>,
    lde: Vec<Fp>,
    tree: MerkleTree,
}

impl Preprocessed {
    pub fn new(table: &Trace, log_blowup: usize) -> Preprocessed {
        let w = table.width;
        let log_n = log2_strict(table.height());
        let big_n = table.height() << log_blowup;
        let mut lde = zeroed_vec(big_n * w);
        let ext: Vec<(Vec<Fp>, Vec<Fp>)> =
            par_map_min(w, 1, |k| lde_column(table.column(k), big_n, MULTIPLICATIVE_GENERATOR));
        let (coeffs, evals): (Vec<Vec<Fp>>, Vec<Vec<Fp>>) = ext.into_iter().unzip();
        scatter_columns(&mut lde, w, 0, &evals);
        let tree = MerkleTree::from_flat(&lde, w);
        Preprocessed { width: w, log_n, log_blowup, table: table.clone(), coeffs, lde, tree }
    }

    pub fn root(&self) -> Digest {
        self.tree.root()
    }

    fn row(&self, i: usize) -> &[Fp] {
        &self.lde[i * self.width..(i + 1) * self.width]
    }
}

/// Evaluates base-coefficient polynomials at `x`, sharing a table of powers.
fn eval_base_polys_at(polys: &[Vec<Fp>], x: Fp4) -> Vec<Fp4> {
    let n = polys.first().map_or(0, |p| p.len());
    let xp = powers(x, n);
    par_map_min(polys.len(), 1, |k| polys[k].iter().zip(&xp).fold(Fp4::ZERO, |acc, (c, p)| acc + p.mul_base(c)))
}

/// Binds the table heights and public values.
fn observe_setup(challenger: &mut Challenger, log_ns: &[usize], public: &[Fp]) {
    for log_n in log_ns {
        challenger.observe(Fp::from_u32(*log_n as u32));
    }
    challenger.observe(Fp::from_u32(public.len() as u32));
    challenger.observe_slice(public);
}

/// Evaluates every constraint on every row pair of `trace` with the
/// selectors as plain 0/1 flags and reports the first violation as
/// `(row, constraint index, section label)`, the label being the last
/// [`Builder::mark`] before the constraint. Also checks that the lookup
/// terms cancel, reporting `(usize::MAX, 0, "lookup sum")` if they do not.
/// A debugging aid for AIR authors; the prover does not need it.
pub fn check_constraints<A: Air>(air: &A, trace: &Trace, public: &[Fp]) -> Result<(), (usize, usize, &'static str)> {
    check_constraints_with(air, trace, None, public)
}

/// [`check_constraints`] with a preprocessed table of the trace's height.
pub fn check_constraints_with<A: Air>(
    air: &A,
    trace: &Trace,
    pre: Option<&Trace>,
    public: &[Fp],
) -> Result<(), (usize, usize, &'static str)> {
    check_tables(&[(air, trace, pre)], public).map_err(|(_, e)| e)
}

/// [`check_constraints`] over several tables whose lookup terms must cancel
/// together. Errors carry the index of the offending table.
#[allow(clippy::type_complexity)]
pub fn check_tables(
    tables: &[(&dyn DynAir, &Trace, Option<&Trace>)],
    public: &[Fp],
) -> Result<(), (usize, (usize, usize, &'static str))> {
    let ch = LookupChallenges::new(Fp4::from_u32(0x1234_5678), Fp4([Fp::new(3), Fp::new(5), Fp::new(7), Fp::new(11)]));
    let mut sum = Fp4::ZERO;
    for (t, (air, trace, pre)) in tables.iter().enumerate() {
        let n = trace.height();
        let empty: Vec<Fp> = Vec::new();
        let pre_row = |i: usize| -> &[Fp] { pre.map_or(&empty[..], |p| p.row(i)) };
        for i in 0..n {
            let next = (i + 1) % n;
            let sel = (
                if i == 0 { Fp::ONE } else { Fp::ZERO },
                if i == n - 1 { Fp::ONE } else { Fp::ZERO },
                if i == n - 1 { Fp::ZERO } else { Fp::ONE },
            );
            let mut b = Builder::new(trace.row(i), trace.row(next), (pre_row(i), pre_row(next)), public, sel);
            air.eval_fp(&mut b);
            if let Some(k) = b.out.constraints.iter().position(|c| *c != Fp::ZERO) {
                let label = b.out.marks.iter().rev().find(|(at, _)| *at <= k).map(|(_, l)| *l).unwrap_or("");
                return Err((t, (i, k, label)));
            }
            for term in b.out.terms() {
                let d = ch.denominator(&term.values);
                let Some(inv) = d.inverse() else {
                    return Err((t, (i, 0, "lookup denominator zero")));
                };
                let c = term.multiplicity.mul_ext(inv);
                if term.send { sum += c } else { sum -= c }
            }
        }
    }
    if sum != Fp4::ZERO {
        return Err((tables.len() - 1, (usize::MAX, 0, "lookup sum")));
    }
    Ok(())
}

/// Upper bound on the degree of the AIR's constraints, measured by
/// evaluating it over [`Deg`] with every column at degree one, the row
/// selectors at degree one and the transition selector at degree zero.
/// A group of lookup terms counts as `1 + sum deg d_i`, and as
/// `deg m_i + sum_(j != i) deg d_j` for each member, where a denominator
/// has the largest degree of its values. Must not exceed
/// `air.max_constraint_degree()`.
pub fn measure_degree<A: Air>(air: &A, num_public: usize) -> usize {
    measure_degree_dyn(air, num_public)
}

fn measure_degree_dyn(air: &dyn DynAir, num_public: usize) -> usize {
    let cols = vec![Deg(1); air.air_width()];
    let pre = vec![Deg(1); air.air_preprocessed_width()];
    let public = vec![Deg(0); num_public];
    let (constraints, terms) = evaluate(air, &cols, &cols, (&pre, &pre), &public, (Deg(1), Deg(1), Deg(0)));
    let mut max = constraints.iter().map(|d| d.0 as usize).max().unwrap_or(0);
    for members in terms.chunks(air.air_lookup_group()) {
        let d: Vec<usize> = members.iter().map(|t| t.values.iter().map(|d| d.0 as usize).max().unwrap_or(0)).collect();
        let sum: usize = d.iter().sum();
        max = max.max(1 + sum);
        for (t, dt) in members.iter().zip(&d) {
            max = max.max(t.multiplicity.0 as usize + sum - dt);
        }
    }
    max
}

/// Builds the auxiliary trace (row-major extension values: group sums
/// then the running sum) for `trace` under the given challenges, and
/// returns it with the table's lookup total.
fn build_aux(
    air: &dyn DynAir,
    trace: &Trace,
    pre: Option<&Preprocessed>,
    public: &[Fp],
    ch: &LookupChallenges,
    terms: usize,
) -> (Vec<Fp4>, Fp4) {
    let n = trace.height();
    let empty: Vec<Fp> = Vec::new();
    let pre_row = |i: usize| -> &[Fp] { pre.map_or(&empty[..], |p| p.table.row(i)) };
    let group = air.air_lookup_group();
    let groups = terms.div_ceil(group);
    let width = groups + 1;
    let mut aux = vec![Fp4::ZERO; n * width];
    // Denominators and signed multiplicities of every term, row by row.
    const ROWS: usize = 256;
    let mut dm = vec![(Fp4::ZERO, Fp::ZERO); n * terms];
    par_chunks_mut(&mut dm, ROWS * terms, |c, chunk| {
        let mut scratch = Scratch::default();
        for (r, out) in chunk.chunks_exact_mut(terms).enumerate() {
            let i = c * ROWS + r;
            evaluate_into(
                air,
                trace.row(i),
                trace.row((i + 1) % n),
                (pre_row(i), pre_row((i + 1) % n)),
                public,
                (Fp::ZERO, Fp::ZERO, Fp::ZERO),
                &mut scratch,
            );
            assert_eq!(scratch.terms().len(), terms, "lookup term count varies between rows");
            for (o, t) in out.iter_mut().zip(scratch.terms()) {
                *o = (ch.denominator(&t.values), if t.send { t.multiplicity } else { -t.multiplicity });
            }
        }
    });
    let (denoms, mults): (Vec<Fp4>, Vec<Fp>) = dm.into_iter().unzip();
    let invs = par_batch_inverse(&denoms);
    // Group sums, and each row's contribution in the running-sum column,
    // which the prefix sums then replace.
    par_chunks_mut(&mut aux, ROWS * width, |c, chunk| {
        for (r, row) in chunk.chunks_exact_mut(width).enumerate() {
            let i = c * ROWS + r;
            let mut contrib = Fp4::ZERO;
            for k in 0..terms {
                let f = invs[i * terms + k].mul_base(&mults[i * terms + k]);
                row[k / group] += f;
                contrib += f;
            }
            row[groups] = contrib;
        }
    });
    let mut sum = Fp4::ZERO;
    for row in aux.chunks_exact_mut(width) {
        let contrib = row[groups];
        row[groups] = sum;
        sum += contrib;
    }
    (aux, sum)
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// Batch inversion in parallel chunks.
fn par_batch_inverse<F: Field + Send + Sync>(xs: &[F]) -> Vec<F> {
    const CHUNK: usize = 1 << 14;
    par_map_min(xs.len().div_ceil(CHUNK), 1, |c| batch_inverse(&xs[c * CHUNK..((c + 1) * CHUNK).min(xs.len())]))
        .into_iter()
        .flatten()
        .collect()
}

/// Phase timer, active when `TABMINER_TIMING` is set.
struct Timer {
    on: bool,
    last: std::time::Instant,
}

impl Timer {
    fn new() -> Timer {
        Timer { on: std::env::var_os("TABMINER_TIMING").is_some(), last: std::time::Instant::now() }
    }

    fn lap(&mut self, what: &str) {
        if self.on {
            eprintln!("  {what}: {:?}", self.last.elapsed());
            self.last = std::time::Instant::now();
        }
    }
}

/// Transposes column evaluations (each `big_n` long) into row-major `lde`
/// (rows of `w`), columns `first..first + cols.len()`.
fn scatter_columns(lde: &mut [Fp], w: usize, first: usize, cols: &[Vec<Fp>]) {
    const ROWS: usize = 256;
    par_chunks_mut(lde, ROWS * w, |c, rows| {
        for (r, row) in rows.chunks_exact_mut(w).enumerate() {
            let i = c * ROWS + r;
            for (k, col) in cols.iter().enumerate() {
                row[first + k] = col[i];
            }
        }
    });
}

/// Interpolates a base column over `H` and evaluates it on the coset of
/// size `big_n`; returns the coefficients and the evaluations.
fn lde_column(col: Vec<Fp>, big_n: usize, shift: Fp) -> (Vec<Fp>, Vec<Fp>) {
    let mut c = col;
    intt(&mut c);
    let mut e = c.clone();
    e.resize(big_n, Fp::ZERO);
    coset_ntt(&mut e, shift);
    (c, e)
}

/// A committed matrix: column coefficients, row-major evaluations on the
/// coset, and the Merkle tree over the rows.
struct Committed {
    width: usize,
    coeffs: Vec<Vec<Fp>>,
    rows: Vec<Fp>,
    tree: MerkleTree,
}

impl Committed {
    /// Extends the `width` columns `column(k)` to `big_n` points on the
    /// coset `shift * H` and commits to the rows. Columns are extended in
    /// parallel batches (bounding memory) and scattered into the row-major
    /// table.
    fn new(width: usize, big_n: usize, shift: Fp, column: impl Fn(usize) -> Vec<Fp> + Sync) -> Committed {
        let mut coeffs: Vec<Vec<Fp>> = Vec::with_capacity(width);
        let mut rows = zeroed_vec(big_n * width);
        let batch = crate::parallel::threads() * 4;
        for first in (0..width).step_by(batch) {
            let cols = (first + batch).min(width) - first;
            let ext: Vec<(Vec<Fp>, Vec<Fp>)> = par_map_min(cols, 1, |k| lde_column(column(first + k), big_n, shift));
            let (c, e): (Vec<Vec<Fp>>, Vec<Vec<Fp>>) = ext.into_iter().unzip();
            scatter_columns(&mut rows, width, first, &e);
            coeffs.extend(c);
        }
        let tree = MerkleTree::from_flat(&rows, width);
        Committed { width, coeffs, rows, tree }
    }

    fn row(&self, i: usize) -> &[Fp] {
        &self.rows[i * self.width..(i + 1) * self.width]
    }
}

/// One table of a proof: its AIR, trace, and the committed preprocessed
/// table when the AIR has preprocessed columns (it must have the trace's
/// height and the config's blowup).
#[derive(Clone, Copy)]
pub struct TableInput<'a> {
    pub air: &'a dyn DynAir,
    pub trace: &'a Trace,
    pub pre: Option<&'a Preprocessed>,
}

/// The prover's state for one table.
struct TableState<'a> {
    input: TableInput<'a>,
    log_n: usize,
    /// Evaluation coset of the table.
    shift: Fp,
    num_constraints: usize,
    num_terms: usize,
    trace: Committed,
    /// Auxiliary columns, their extension values per row, and the lookup
    /// total.
    aux: Option<(Committed, Vec<Fp4>, Fp4)>,
}

impl TableState<'_> {
    fn big_n(&self, log_blowup: usize) -> usize {
        1 << (self.log_n + log_blowup)
    }

    fn aux_ext_w(&self) -> usize {
        lookup_columns(self.num_terms, self.input.air.air_lookup_group())
    }

    fn pre_row(&self, i: usize) -> &[Fp] {
        self.input.pre.map_or(&[], |p| p.row(i))
    }

    fn aux_row(&self, i: usize) -> &[Fp] {
        self.aux.as_ref().map_or(&[], |(c, _, _)| c.row(i))
    }
}

/// The committed quotient of one table.
struct Quotient {
    coeffs: Vec<Vec<Fp4>>,
    /// Chunk values per point, `chunks` per row.
    lde: Vec<Fp4>,
    rows: Vec<Fp>,
    tree: MerkleTree,
    chunks: usize,
}

/// Evaluates the combined constraints of a table on its coset, divides by
/// the vanishing polynomial, splits the quotient into chunks and commits.
fn commit_quotient(
    t: &TableState<'_>,
    log_blowup: usize,
    public: &[Fp],
    lookup: Option<&LookupChallenges>,
    alpha_powers: &[Fp4],
    timer: &mut Timer,
) -> Quotient {
    let air = t.input.air;
    let n = 1usize << t.log_n;
    let big_n = t.big_n(log_blowup);
    let w = t.trace.width;
    let aux_ext_w = t.aux_ext_w();
    let num_chunks = 1usize << log_quotient_degree(air.air_degree());
    let shift = t.shift;
    let g_inv = root_of_unity(t.log_n).inverse().unwrap();
    let xs = coset_points(shift, t.log_n + log_blowup);
    let period = 1usize << log_blowup;
    let z_h: Vec<Fp> = (0..period).map(|i| xs[i].pow(n as u64).sub(&Fp::ONE)).collect();
    let z_h_inv = batch_inverse(&z_h);
    let denoms: Vec<Fp> = xs.iter().flat_map(|x| [x.sub(&Fp::ONE), x.sub(&g_inv)]).collect();
    let denom_inv = batch_inverse(&denoms);
    let empty: [Fp4; 0] = [];
    let (aux_lde, total): (&[Fp4], Fp4) = t.aux.as_ref().map_or((&empty, Fp4::ZERO), |(_, l, s)| (&l[..], *s));
    let group = air.air_lookup_group();
    let lookup = lookup.filter(|_| t.num_terms > 0).map(|ch| LookupArgs { ch, total, group });
    let lde = &t.trace.rows;

    let mut quotient: Vec<Fp4> = par_map_with(big_n, Scratch::default, |scratch, i| {
        let zh = z_h[i % period];
        let first = zh.mul(&denom_inv[2 * i]);
        let last = zh.mul(&denom_inv[2 * i + 1]);
        let transition = xs[i].sub(&g_inv);
        let next_i = (i + period) % big_n;
        evaluate_into(
            air,
            &lde[i * w..(i + 1) * w],
            &lde[next_i * w..(next_i + 1) * w],
            (t.pre_row(i), t.pre_row(next_i)),
            public,
            (first, last, transition),
            scratch,
        );
        let (constraints, terms) = (scratch.constraints(), scratch.terms());
        let (aux_l, aux_n): (&[Fp4], &[Fp4]) = if aux_ext_w > 0 {
            (&aux_lde[i * aux_ext_w..(i + 1) * aux_ext_w], &aux_lde[next_i * aux_ext_w..(next_i + 1) * aux_ext_w])
        } else {
            (&empty, &empty)
        };
        let sel_ext = (Fp4::from_base(first), Fp4::from_base(last), Fp4::from_base(transition));
        let c = combine(constraints, terms, aux_l, aux_n, sel_ext, lookup, alpha_powers);
        c.mul_base(&z_h_inv[i % period])
    });
    timer.lap("quotient eval");

    // Chunks: Q(x) = sum_j x^j Q_j(x^(2^log_q)).
    coset_intt_ext(&mut quotient, shift);
    let chunks: Vec<(Vec<Fp4>, Vec<Fp4>)> = par_map_min(num_chunks, 1, |j| {
        let c: Vec<Fp4> = quotient.iter().skip(j).step_by(num_chunks).copied().collect();
        let mut e = c.clone();
        e.resize(big_n, Fp4::ZERO);
        coset_ntt_ext(&mut e, shift);
        (c, e)
    });
    let (coeffs, chunk_evals): (Vec<Vec<Fp4>>, Vec<Vec<Fp4>>) = chunks.into_iter().unzip();
    let mut chunk_lde = vec![Fp4::ZERO; big_n * num_chunks];
    par_chunks_mut(&mut chunk_lde, 1 << 12, |c, part| {
        for (r, v) in part.iter_mut().enumerate() {
            let at = (c << 12) + r;
            *v = chunk_evals[at % num_chunks][at / num_chunks];
        }
    });
    drop(chunk_evals);
    let rows: Vec<Fp> = ext_row(&chunk_lde);
    timer.lap("quotient lde");
    let tree = MerkleTree::from_flat(&rows, num_chunks * DEGREE);
    timer.lap("quotient commit");
    Quotient { coeffs, lde: chunk_lde, rows, tree, chunks: num_chunks }
}

pub fn prove<A: Air>(
    config: &StarkConfig,
    air: &A,
    trace: &Trace,
    public: &[Fp],
    challenger: &mut Challenger,
) -> Proof {
    assert_eq!(air.preprocessed_width(), 0, "this air needs a preprocessed table: use prove_with");
    prove_with(config, air, trace, None, public, challenger)
}

/// [`prove`] with a preprocessed table (required when the AIR declares
/// preprocessed columns; it must have the trace's height and the config's
/// blowup).
pub fn prove_with<A: Air>(
    config: &StarkConfig,
    air: &A,
    trace: &Trace,
    pre: Option<&Preprocessed>,
    public: &[Fp],
    challenger: &mut Challenger,
) -> Proof {
    prove_tables(config, &[TableInput { air, trace, pre }], public, challenger)
}

/// Proves several tables at once, tallest first. The tables share the
/// public values, the lookup challenges (their lookup terms must cancel
/// together, so tables can exchange messages) and one FRI proof, into
/// which the DEEP combination of a smaller table enters at its size. Only
/// tables of the tallest height may have preprocessed columns.
pub fn prove_tables(
    config: &StarkConfig,
    tables: &[TableInput<'_>],
    public: &[Fp],
    challenger: &mut Challenger,
) -> Proof {
    assert!(!tables.is_empty(), "no tables");
    let log_blowup = config.log_blowup;
    let log_ns: Vec<usize> = tables.iter().map(|t| log2_strict(t.trace.height())).collect();
    assert!(log_ns.windows(2).all(|w| w[0] >= w[1]), "tables must be ordered by height, tallest first");
    let log_big = log_ns[0] + log_blowup;
    for (t, &log_n) in tables.iter().zip(&log_ns) {
        let air = t.air;
        assert_eq!(t.trace.width, air.air_width(), "trace width does not match air");
        assert_eq!(t.pre.map_or(0, |p| p.width), air.air_preprocessed_width(), "preprocessed width does not match air");
        if let Some(p) = t.pre {
            assert_eq!(p.log_n, log_n, "preprocessed table height does not match trace");
            assert_eq!(p.log_blowup, log_blowup, "preprocessed table blowup does not match config");
            assert_eq!(log_n, log_ns[0], "only the tallest tables may have preprocessed columns");
        }
        debug_assert!(
            measure_degree_dyn(air, public.len()) <= air.air_degree(),
            "air constraints exceed the declared degree"
        );
        let log_q = log_quotient_degree(air.air_degree());
        assert!(log_blowup >= log_q, "log_blowup must be at least {log_q} for this air");
    }

    observe_setup(challenger, &log_ns, public);
    for t in tables {
        if let Some(p) = t.pre {
            challenger.observe_digest(&p.root());
        }
    }
    let mut timer = Timer::new();

    // 1. Trace LDEs and commitments.
    let mut states: Vec<TableState<'_>> = tables
        .iter()
        .zip(&log_ns)
        .map(|(input, &log_n)| {
            let shift = table_shift(log_big, log_n + log_blowup);
            let (num_constraints, num_terms) = shape(input.air, public);
            let trace = Committed::new(input.trace.width, 1 << (log_n + log_blowup), shift, |k| input.trace.column(k));
            challenger.observe_digest(&trace.tree.root());
            TableState { input: *input, log_n, shift, num_constraints, num_terms, trace, aux: None }
        })
        .collect();
    timer.lap("trace commit");

    // 2. Lookup challenges and auxiliary traces.
    let mut lookup_ch = None;
    if states.iter().any(|t| t.num_terms > 0) {
        let ch = LookupChallenges::sample(challenger);
        for t in states.iter_mut().filter(|t| t.num_terms > 0) {
            let (aux, total) = build_aux(t.input.air, t.input.trace, t.input.pre, public, &ch, t.num_terms);
            timer.lap("aux build");
            let ext_w = t.aux_ext_w();
            let n = 1usize << t.log_n;
            let committed = Committed::new(ext_w * DEGREE, t.big_n(log_blowup), t.shift, |j| {
                let (e, k) = (j / DEGREE, j % DEGREE);
                (0..n).map(|i| aux[i * ext_w + e].0[k]).collect()
            });
            let aux_lde = ext_from_row(&committed.rows);
            challenger.observe_digest(&committed.tree.root());
            challenger.observe_ext(&total);
            t.aux = Some((committed, aux_lde, total));
            timer.lap("aux commit");
        }
        debug_assert!(
            states.iter().filter_map(|t| t.aux.as_ref()).fold(Fp4::ZERO, |a, (_, _, s)| a + *s).is_zero(),
            "lookup terms do not cancel: the traces violate a multiset relation"
        );
        lookup_ch = Some(ch);
    }

    // 3. Constraint combinations and quotients.
    let alpha = challenger.sample_ext();
    let quotients: Vec<Quotient> = states
        .iter()
        .map(|t| {
            let alpha_powers =
                powers(alpha, t.num_constraints + num_lookup_constraints(t.num_terms, t.input.air.air_lookup_group()));
            let q = commit_quotient(t, log_blowup, public, lookup_ch.as_ref(), &alpha_powers, &mut timer);
            challenger.observe_digest(&q.tree.root());
            q
        })
        .collect();

    // 4. Out-of-domain openings.
    let zeta = challenger.sample_ext();
    let no_coeffs: Vec<Vec<Fp>> = Vec::new();
    let parts: Vec<TableProof> = states
        .iter()
        .zip(&quotients)
        .map(|(t, q)| {
            let zeta_next = zeta.mul_base(&root_of_unity(t.log_n));
            let zeta_q = zeta.exp(q.chunks as u64);
            let aux_coeffs = t.aux.as_ref().map_or(&no_coeffs, |(c, _, _)| &c.coeffs);
            let pre_coeffs = t.input.pre.map_or(&no_coeffs, |p| &p.coeffs);
            let part = TableProof {
                log_n: t.log_n,
                trace_root: t.trace.tree.root(),
                aux_root: t.aux.as_ref().map(|(c, _, _)| c.tree.root()),
                lookup_sum: t.aux.as_ref().map_or(Fp4::ZERO, |(_, _, s)| *s),
                quotient_root: q.tree.root(),
                trace_at_zeta: eval_base_polys_at(&t.trace.coeffs, zeta),
                trace_at_zeta_next: eval_base_polys_at(&t.trace.coeffs, zeta_next),
                aux_at_zeta: eval_base_polys_at(aux_coeffs, zeta),
                aux_at_zeta_next: eval_base_polys_at(aux_coeffs, zeta_next),
                pre_at_zeta: eval_base_polys_at(pre_coeffs, zeta),
                pre_at_zeta_next: eval_base_polys_at(pre_coeffs, zeta_next),
                quotient_at_zeta_q: q.coeffs.iter().map(|c| eval_ext_poly_at(c, zeta_q)).collect(),
            };
            for v in part.opened().into_iter().flatten() {
                challenger.observe_ext(v);
            }
            part
        })
        .collect();
    timer.lap("openings");

    // 5. DEEP combinations, summed per domain size, and FRI.
    let beta = challenger.sample_ext();
    let mut inputs: Vec<Vec<Fp4>> = Vec::new();
    let mut input_log_sizes: Vec<usize> = Vec::new();
    let mut offset = 0usize;
    for ((t, q), part) in states.iter().zip(&quotients).zip(&parts) {
        let deep = Deep::new(beta, part);
        let scale = beta.exp(offset as u64);
        offset += deep.len();
        let log_m = t.log_n + log_blowup;
        let zeta_next = zeta.mul_base(&root_of_unity(t.log_n));
        let zeta_q = zeta.exp(q.chunks as u64);
        let xs = coset_points(t.shift, log_m);
        let mut denoms: Vec<Fp4> = Vec::with_capacity(3 * xs.len());
        for x in &xs {
            let xe = Fp4::from_base(*x);
            denoms.push(xe - zeta);
            denoms.push(xe - zeta_next);
            denoms.push(xe - zeta_q);
        }
        let inv = par_batch_inverse(&denoms);
        let c = q.chunks;
        let reduced: Vec<Fp4> = par_map(xs.len(), |i| {
            let rows = (t.trace.row(i), t.aux_row(i), t.pre_row(i), &q.lde[i * c..(i + 1) * c]);
            scale * deep.value(rows, inv[3 * i], inv[3 * i + 1], inv[3 * i + 2])
        });
        if input_log_sizes.last() == Some(&log_m) {
            let last = inputs.last_mut().unwrap();
            for (a, b) in last.iter_mut().zip(&reduced) {
                *a += *b;
            }
        } else {
            inputs.push(reduced);
            input_log_sizes.push(log_m);
        }
    }
    timer.lap("deep");
    let (fri_proof, indices) = fri::prove(&config.fri(), challenger, MULTIPLICATIVE_GENERATOR, inputs);
    timer.lap("fri");

    let openings = indices
        .iter()
        .map(|&index| {
            states
                .iter()
                .zip(&quotients)
                .map(|(t, q)| {
                    let i = index % t.big_n(log_blowup);
                    let qw = q.chunks * DEGREE;
                    QueryOpening {
                        trace_row: t.trace.row(i).to_vec(),
                        trace_path: t.trace.tree.open(i),
                        aux_row: t.aux_row(i).to_vec(),
                        aux_path: t.aux.as_ref().map(|(c, _, _)| c.tree.open(i)).unwrap_or_default(),
                        pre_row: t.pre_row(i).to_vec(),
                        pre_path: t.input.pre.map(|p| p.tree.open(i)).unwrap_or_default(),
                        quotient_row: q.rows[i * qw..(i + 1) * qw].to_vec(),
                        quotient_path: q.tree.open(i),
                    }
                })
                .collect()
        })
        .collect();

    Proof { tables: parts, fri: fri_proof, openings, query_indices: indices }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

pub fn verify<A: Air>(
    config: &StarkConfig,
    air: &A,
    public: &[Fp],
    proof: &Proof,
    challenger: &mut Challenger,
) -> Result<(), VerifyError> {
    verify_with(config, air, None, public, proof, challenger)
}

/// [`verify`] against a preprocessed table known by its root.
pub fn verify_with<A: Air>(
    config: &StarkConfig,
    air: &A,
    pre_root: Option<&Digest>,
    public: &[Fp],
    proof: &Proof,
    challenger: &mut Challenger,
) -> Result<(), VerifyError> {
    verify_tables(config, &[TableSpec { air, pre_root }], public, proof, challenger)
}

/// One table a verifier expects: its AIR and, when the AIR has
/// preprocessed columns, the root of the committed table.
#[derive(Clone, Copy)]
pub struct TableSpec<'a> {
    pub air: &'a dyn DynAir,
    pub pre_root: Option<&'a Digest>,
}

/// Shape of one table, derived from its AIR and checked against the proof.
struct TableShape {
    w: usize,
    aux_w: usize,
    pre_w: usize,
    chunks: usize,
    num_constraints: usize,
    num_terms: usize,
    group: usize,
}

/// Verifies a proof of [`prove_tables`] for the given tables, in order.
pub fn verify_tables(
    config: &StarkConfig,
    specs: &[TableSpec<'_>],
    public: &[Fp],
    proof: &Proof,
    challenger: &mut Challenger,
) -> Result<(), VerifyError> {
    let log_blowup = config.log_blowup;
    if specs.is_empty() || proof.tables.len() != specs.len() || proof.openings.len() != config.num_queries {
        return Err(VerifyError::Shape);
    }
    let log_ns: Vec<usize> = proof.tables.iter().map(|t| t.log_n).collect();
    if log_ns.windows(2).any(|w| w[0] < w[1]) {
        return Err(VerifyError::Shape);
    }
    let mut shapes = Vec::with_capacity(specs.len());
    for (spec, t) in specs.iter().zip(&proof.tables) {
        let air = spec.air;
        let log_q = log_quotient_degree(air.air_degree());
        let (num_constraints, num_terms) = shape(air, public);
        let group = air.air_lookup_group();
        let aux_w = lookup_columns(num_terms, group) * DEGREE;
        let s = TableShape {
            w: air.air_width(),
            aux_w,
            pre_w: air.air_preprocessed_width(),
            chunks: 1 << log_q,
            num_constraints,
            num_terms,
            group,
        };
        if t.log_n == 0
            || t.log_n + log_blowup > 27
            || log_blowup < log_q
            || t.trace_at_zeta.len() != s.w
            || t.trace_at_zeta_next.len() != s.w
            || t.aux_at_zeta.len() != s.aux_w
            || t.aux_at_zeta_next.len() != s.aux_w
            || t.aux_root.is_some() != (num_terms > 0)
            || (t.aux_root.is_none() && !t.lookup_sum.is_zero())
            || spec.pre_root.is_some() != (s.pre_w > 0)
            || (s.pre_w > 0 && t.log_n != log_ns[0])
            || t.pre_at_zeta.len() != s.pre_w
            || t.pre_at_zeta_next.len() != s.pre_w
            || t.quotient_at_zeta_q.len() != s.chunks
        {
            return Err(VerifyError::Shape);
        }
        shapes.push(s);
    }
    let log_big = log_ns[0] + log_blowup;

    observe_setup(challenger, &log_ns, public);
    for spec in specs {
        if let Some(root) = spec.pre_root {
            challenger.observe_digest(root);
        }
    }
    for t in &proof.tables {
        challenger.observe_digest(&t.trace_root);
    }
    let lookup_ch = if proof.tables.iter().any(|t| t.aux_root.is_some()) {
        let ch = LookupChallenges::sample(challenger);
        for t in &proof.tables {
            if let Some(root) = &t.aux_root {
                challenger.observe_digest(root);
                challenger.observe_ext(&t.lookup_sum);
            }
        }
        Some(ch)
    } else {
        None
    };
    if !proof.tables.iter().fold(Fp4::ZERO, |a, t| a + t.lookup_sum).is_zero() {
        return Err(VerifyError::LookupSum);
    }
    let alpha = challenger.sample_ext();
    for t in &proof.tables {
        challenger.observe_digest(&t.quotient_root);
    }
    let zeta = challenger.sample_ext();
    for t in &proof.tables {
        for v in t.opened().into_iter().flatten() {
            challenger.observe_ext(v);
        }
    }
    let beta = challenger.sample_ext();

    // Constraint identity of every table at zeta.
    let public_ext: Vec<Fp4> = public.iter().map(|x| Fp4::from_base(*x)).collect();
    for ((spec, t), s) in specs.iter().zip(&proof.tables).zip(&shapes) {
        let g_inv = root_of_unity(t.log_n).inverse().unwrap();
        let z_h = zeta.exp(1u64 << t.log_n) - Fp4::ONE;
        let first = z_h * (zeta - Fp4::ONE).inv().ok_or(VerifyError::ConstraintIdentity)?;
        let last = z_h * (zeta - Fp4::from_base(g_inv)).inv().ok_or(VerifyError::ConstraintIdentity)?;
        let transition = zeta - Fp4::from_base(g_inv);
        let (constraints, terms) = evaluate(
            spec.air,
            &t.trace_at_zeta,
            &t.trace_at_zeta_next,
            (&t.pre_at_zeta, &t.pre_at_zeta_next),
            &public_ext,
            (first, last, transition),
        );
        let aux_l = ext_from_base_openings(&t.aux_at_zeta);
        let aux_n = ext_from_base_openings(&t.aux_at_zeta_next);
        let alpha_powers = powers(alpha, s.num_constraints + num_lookup_constraints(s.num_terms, s.group));
        let lookup = lookup_ch.as_ref().filter(|_| s.num_terms > 0).map(|ch| LookupArgs {
            ch,
            total: t.lookup_sum,
            group: s.group,
        });
        let c_zeta = combine(&constraints, &terms, &aux_l, &aux_n, (first, last, transition), lookup, &alpha_powers);
        let mut q_zeta = Fp4::ZERO;
        let mut zeta_pow = Fp4::ONE;
        for q in &t.quotient_at_zeta_q {
            q_zeta += *q * zeta_pow;
            zeta_pow *= zeta;
        }
        if q_zeta * z_h != c_zeta {
            return Err(VerifyError::ConstraintIdentity);
        }
    }

    // FRI over the DEEP combinations recomputed from the opened rows.
    let mut offset = 0usize;
    let deeps: Vec<(Deep, Fp4)> = proof
        .tables
        .iter()
        .map(|t| {
            let d = Deep::new(beta, t);
            let scale = beta.exp(offset as u64);
            offset += d.len();
            (d, scale)
        })
        .collect();
    let mut log_sizes: Vec<usize> = log_ns.iter().map(|l| l + log_blowup).collect();
    log_sizes.dedup();
    if proof.query_indices.len() != config.num_queries {
        return Err(VerifyError::Shape);
    }
    let open = |q: usize, index: usize| -> Result<Vec<Fp4>, VerifyError> {
        let openings = &proof.openings[q];
        if openings.len() != specs.len() || proof.query_indices[q] != index {
            return Err(VerifyError::Shape);
        }
        let mut values: Vec<Fp4> = Vec::with_capacity(log_sizes.len());
        let mut last_size = None;
        for ((((spec, t), s), opening), (deep, scale)) in
            specs.iter().zip(&proof.tables).zip(&shapes).zip(openings).zip(&deeps)
        {
            if opening.trace_row.len() != s.w
                || opening.aux_row.len() != s.aux_w
                || opening.pre_row.len() != s.pre_w
                || opening.quotient_row.len() != s.chunks * DEGREE
            {
                return Err(VerifyError::Shape);
            }
            let log_m = t.log_n + log_blowup;
            let i = index % (1 << log_m);
            if !merkle_verify(&t.trace_root, log_m, i, &opening.trace_row, &opening.trace_path) {
                return Err(VerifyError::InvalidTraceOpening { query: q });
            }
            if let Some(root) = &t.aux_root
                && !merkle_verify(root, log_m, i, &opening.aux_row, &opening.aux_path)
            {
                return Err(VerifyError::InvalidAuxOpening { query: q });
            }
            if let Some(root) = spec.pre_root
                && !merkle_verify(root, log_m, i, &opening.pre_row, &opening.pre_path)
            {
                return Err(VerifyError::InvalidPreprocessedOpening { query: q });
            }
            if !merkle_verify(&t.quotient_root, log_m, i, &opening.quotient_row, &opening.quotient_path) {
                return Err(VerifyError::InvalidQuotientOpening { query: q });
            }
            let shift = table_shift(log_big, log_m);
            let x = Fp4::from_base(shift.mul(&root_of_unity(log_m).pow(i as u64)));
            let zeta_next = zeta.mul_base(&root_of_unity(t.log_n));
            let zeta_q = zeta.exp(s.chunks as u64);
            let inv = batch_inverse(&[x - zeta, x - zeta_next, x - zeta_q]);
            let rows = (&opening.trace_row[..], &opening.aux_row[..], &opening.pre_row[..]);
            let quotient = ext_from_row(&opening.quotient_row);
            let v = *scale * deep.value((rows.0, rows.1, rows.2, &quotient), inv[0], inv[1], inv[2]);
            if last_size == Some(log_m) {
                *values.last_mut().unwrap() += v;
            } else {
                values.push(v);
                last_size = Some(log_m);
            }
        }
        Ok(values)
    };
    fri::verify(&config.fri(), challenger, MULTIPLICATIVE_GENERATOR, &log_sizes, &proof.fri, open)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fibonacci: columns (a, b); next = (b, a + b); a_0 = 0, b_0 = 1;
    /// last b equals the public value. Max degree 2 (selector + column).
    struct Fibonacci;

    impl Air for Fibonacci {
        fn width(&self) -> usize {
            2
        }
        fn max_constraint_degree(&self) -> usize {
            2
        }
        fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
            let (a0, b0) = (b.local()[0], b.local()[1]);
            let (a1, b1) = (b.next()[0], b.next()[1]);
            let out: F = b.public()[0];
            b.when_first_row(a0);
            b.when_first_row(b0 - F::ONE);
            b.when_transition(a1 - b0);
            b.when_transition(b1 - a0 - b0);
            b.when_last_row(b0 - out);
        }
    }

    fn fib_trace(log_n: usize) -> (Trace, Vec<Fp>) {
        let n = 1 << log_n;
        let mut values = Vec::with_capacity(2 * n);
        let (mut a, mut b) = (Fp::ZERO, Fp::ONE);
        for _ in 0..n {
            values.push(a);
            values.push(b);
            let c = a + b;
            a = b;
            b = c;
        }
        let last_b = values[2 * n - 1];
        (Trace::new(values, 2), vec![last_b])
    }

    /// x_{i+1} = x_i^2 + k with x_0 public; degree 3 with the selector, so
    /// the quotient is split into two chunks.
    struct Squaring {
        k: Fp,
    }

    impl Air for Squaring {
        fn width(&self) -> usize {
            1
        }
        fn max_constraint_degree(&self) -> usize {
            3
        }
        fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
            let x0 = b.local()[0];
            let x1 = b.next()[0];
            let start: F = b.public()[0];
            let k: F = self.k.into();
            b.when_first_row(x0 - start);
            b.when_transition(x1 - x0 * x0 - k);
        }
    }

    fn squaring_trace(air: &Squaring, log_n: usize, start: Fp) -> Trace {
        let mut values = Vec::with_capacity(1 << log_n);
        let mut x = start;
        for _ in 0..1 << log_n {
            values.push(x);
            x = x * x + air.k;
        }
        Trace::new(values, 1)
    }

    const CONFIG: StarkConfig = StarkConfig { log_blowup: 2, num_queries: 16, pow_bits: 0 };

    fn transcript() -> Challenger {
        let mut c = Challenger::new();
        c.observe(Fp::new(77));
        c
    }

    #[test]
    fn measured_degrees() {
        assert_eq!(measure_degree(&Fibonacci, 1), 2);
        assert_eq!(measure_degree(&Squaring { k: Fp::ONE }, 1), 2); // declared 3 is a safe over-estimate
    }

    #[test]
    fn quotient_degree_sizing() {
        assert_eq!(log_quotient_degree(1), 0);
        assert_eq!(log_quotient_degree(2), 0);
        assert_eq!(log_quotient_degree(3), 1);
        assert_eq!(log_quotient_degree(4), 2);
        assert_eq!(log_quotient_degree(5), 2);
        assert_eq!(log_quotient_degree(9), 3);
    }

    #[test]
    fn fibonacci_roundtrip() {
        for log_n in [1, 3, 6] {
            let (trace, public) = fib_trace(log_n);
            let proof = prove(&CONFIG, &Fibonacci, &trace, &public, &mut transcript());
            assert_eq!(proof.tables[0].log_n, log_n);
            assert_eq!(proof.tables[0].quotient_at_zeta_q.len(), 1);
            assert_eq!(verify(&CONFIG, &Fibonacci, &public, &proof, &mut transcript()), Ok(()), "log_n={log_n}");
            // Wrong public value fails the constraint identity.
            let bad = vec![public[0] + Fp::ONE];
            assert_eq!(
                verify(&CONFIG, &Fibonacci, &bad, &proof, &mut transcript()),
                Err(VerifyError::ConstraintIdentity)
            );
        }
    }

    #[test]
    fn squaring_with_two_quotient_chunks() {
        let air = Squaring { k: Fp::new(5) };
        let start = Fp::new(3);
        let trace = squaring_trace(&air, 5, start);
        let proof = prove(&CONFIG, &air, &trace, &[start], &mut transcript());
        assert_eq!(proof.tables[0].quotient_at_zeta_q.len(), 2);
        assert_eq!(verify(&CONFIG, &air, &[start], &proof, &mut transcript()), Ok(()));
        assert!(verify(&CONFIG, &air, &[start + Fp::ONE], &proof, &mut transcript()).is_err());
        let other = Squaring { k: Fp::new(6) };
        assert!(verify(&CONFIG, &other, &[start], &proof, &mut transcript()).is_err());
    }

    #[test]
    fn invalid_trace_is_rejected() {
        // A trace violating a transition constraint in one row.
        let (mut trace, public) = fib_trace(5);
        trace.values[2 * 7 + 1] += Fp::ONE;
        let proof = prove(&CONFIG, &Fibonacci, &trace, &public, &mut transcript());
        assert!(verify(&CONFIG, &Fibonacci, &public, &proof, &mut transcript()).is_err());
        // A consistent trace with the wrong boundary.
        let (trace, public) = fib_trace(4);
        let mut shifted = trace.values.clone();
        shifted.rotate_left(2);
        let proof = prove(&CONFIG, &Fibonacci, &Trace::new(shifted, 2), &public, &mut transcript());
        assert!(verify(&CONFIG, &Fibonacci, &public, &proof, &mut transcript()).is_err());
    }

    #[test]
    fn proof_bytes_roundtrip() {
        let (trace, public) = fib_trace(4);
        let proof = prove(&CONFIG, &Fibonacci, &trace, &public, &mut transcript());
        let bytes = proof.to_bytes();
        let back = Proof::from_bytes(&bytes).unwrap();
        assert_eq!(back, proof);
        assert_eq!(verify(&CONFIG, &Fibonacci, &public, &back, &mut transcript()), Ok(()));
        // A proof claiming other query indices is rejected, though it
        // decodes.
        let mut moved = proof.clone();
        moved.query_indices[0] ^= 1;
        assert_eq!(verify(&CONFIG, &Fibonacci, &public, &moved, &mut transcript()), Err(VerifyError::Shape));
        assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Proof::from_bytes(&extra).is_none());
    }

    #[test]
    fn tampered_proofs_are_rejected() {
        let (trace, public) = fib_trace(4);
        let proof = prove(&CONFIG, &Fibonacci, &trace, &public, &mut transcript());
        assert_eq!(verify(&CONFIG, &Fibonacci, &public, &proof, &mut transcript()), Ok(()));

        assert!(verify(&CONFIG, &Fibonacci, &public, &proof, &mut Challenger::new()).is_err());
        let mut p = proof.clone();
        p.tables[0].trace_at_zeta[0] += Fp4::ONE;
        assert!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()).is_err());
        let mut p = proof.clone();
        p.openings[2][0].trace_row[1] += Fp::ONE;
        assert_eq!(
            verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()),
            Err(VerifyError::InvalidTraceOpening { query: 2 })
        );
        let mut p = proof.clone();
        p.openings[5][0].quotient_row[0] += Fp::ONE;
        assert_eq!(
            verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()),
            Err(VerifyError::InvalidQuotientOpening { query: 5 })
        );
        let mut p = proof.clone();
        p.openings.pop();
        assert_eq!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()), Err(VerifyError::Shape));
        let mut p = proof.clone();
        p.tables[0].trace_root[0] += Fp::ONE;
        assert!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()).is_err());
        let mut p = proof.clone();
        p.fri.final_value += Fp4::ONE;
        assert!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()).is_err());
        let mut p = proof.clone();
        p.tables[0].log_n = 5;
        assert!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()).is_err());
    }

    /// Read-only memory: write rows publish `(addr, value)` with a
    /// multiplicity, read rows consume one copy. Columns:
    /// `[mult, is_read, addr, value]`.
    struct RomAir;

    impl Air for RomAir {
        fn width(&self) -> usize {
            4
        }
        fn max_constraint_degree(&self) -> usize {
            3
        }
        fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
            let (mult, is_read, addr, value) = (b.local()[0], b.local()[1], b.local()[2], b.local()[3]);
            b.assert_zero(is_read * is_read - is_read);
            b.assert_zero(mult * is_read);
            b.lookup(true, mult, &[addr, value]);
            b.lookup(false, is_read, &[addr, value]);
        }
    }

    fn rom_trace(rows: &[[u32; 4]]) -> Trace {
        let n = rows.len().max(2).next_power_of_two();
        let mut values = Vec::with_capacity(4 * n);
        for r in rows {
            values.extend(r.iter().map(|v| Fp::new(*v)));
        }
        values.resize(4 * n, Fp::ZERO);
        Trace::new(values, 4)
    }

    #[test]
    fn rom_lookup_roundtrip() {
        assert_eq!(measure_degree(&RomAir, 0), 2);
        let good = rom_trace(&[
            [2, 0, 1, 10], // write (1, 10) twice
            [1, 0, 2, 20], // write (2, 20) once
            [0, 1, 1, 10],
            [0, 1, 2, 20],
            [0, 1, 1, 10],
        ]);
        assert_eq!(check_constraints(&RomAir, &good, &[]), Ok(()));
        let proof = prove(&CONFIG, &RomAir, &good, &[], &mut transcript());
        assert!(proof.tables[0].aux_root.is_some());
        assert_eq!(proof.tables[0].aux_at_zeta.len(), 3 * 4);
        assert_eq!(verify(&CONFIG, &RomAir, &[], &proof, &mut transcript()), Ok(()));
        let back = Proof::from_bytes(&proof.to_bytes()).unwrap();
        assert_eq!(back, proof);

        // Reading a value that was never written.
        let bad = rom_trace(&[[1, 0, 1, 10], [0, 1, 1, 11]]);
        assert_eq!(check_constraints(&RomAir, &bad, &[]), Err((usize::MAX, 0, "lookup sum")));
        // Multiplicity too small for the reads.
        let bad2 = rom_trace(&[[1, 0, 1, 10], [0, 1, 1, 10], [0, 1, 1, 10]]);
        assert!(check_constraints(&RomAir, &bad2, &[]).is_err());
        // A dishonest prover's proof for an unsatisfied relation fails: the
        // running sum cannot end at zero. (Aux generation asserts in debug;
        // emulate by proving a trace whose sum is non-zero in release only.)
        if !cfg!(debug_assertions) {
            let proof = prove(&CONFIG, &RomAir, &bad, &[], &mut transcript());
            assert!(verify(&CONFIG, &RomAir, &[], &proof, &mut transcript()).is_err());
        }
        // Tampering with the auxiliary opening is caught.
        let mut p = proof.clone();
        p.tables[0].aux_at_zeta[0] += Fp4::ONE;
        assert!(verify(&CONFIG, &RomAir, &[], &p, &mut transcript()).is_err());
        let mut p = proof.clone();
        p.openings[0][0].aux_row[0] += Fp::ONE;
        assert_eq!(
            verify(&CONFIG, &RomAir, &[], &p, &mut transcript()),
            Err(VerifyError::InvalidAuxOpening { query: 0 })
        );
    }

    /// [`RomAir`] with its two lookup terms summed in one column.
    struct PairedRom;

    impl Air for PairedRom {
        fn width(&self) -> usize {
            4
        }
        fn max_constraint_degree(&self) -> usize {
            3
        }
        fn lookup_group(&self) -> usize {
            2
        }
        fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
            RomAir.eval(b)
        }
    }

    #[test]
    fn paired_lookup_terms() {
        assert_eq!(measure_degree(&PairedRom, 0), 3);
        let good = rom_trace(&[[2, 0, 1, 10], [1, 0, 2, 20], [0, 1, 1, 10], [0, 1, 2, 20], [0, 1, 1, 10]]);
        let proof = prove(&CONFIG, &PairedRom, &good, &[], &mut transcript());
        // One group column and the running sum.
        assert_eq!(proof.tables[0].aux_at_zeta.len(), 2 * 4);
        assert_eq!(verify(&CONFIG, &PairedRom, &[], &proof, &mut transcript()), Ok(()));
        // The unpaired verifier expects a different shape.
        assert!(verify(&CONFIG, &RomAir, &[], &proof, &mut transcript()).is_err());
        let mut p = proof.clone();
        p.tables[0].aux_at_zeta[0] += Fp4::ONE;
        assert!(verify(&CONFIG, &PairedRom, &[], &p, &mut transcript()).is_err());
        if !cfg!(debug_assertions) {
            let bad = rom_trace(&[[1, 0, 1, 10], [0, 1, 1, 11]]);
            let proof = prove(&CONFIG, &PairedRom, &bad, &[], &mut transcript());
            assert!(verify(&CONFIG, &PairedRom, &[], &proof, &mut transcript()).is_err());
        }
    }

    /// Sends its single column, once per row.
    struct Sender;

    impl Air for Sender {
        fn width(&self) -> usize {
            1
        }
        fn max_constraint_degree(&self) -> usize {
            2
        }
        fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
            b.lookup(true, F::ONE, &[b.local()[0]]);
        }
    }

    /// Receives `value` with multiplicity `mult`, and runs a Fibonacci
    /// sequence over `(a, b)` so that its own row structure is checked.
    /// Columns: `[value, mult, a, b]`.
    struct Receiver;

    impl Air for Receiver {
        fn width(&self) -> usize {
            4
        }
        fn max_constraint_degree(&self) -> usize {
            3
        }
        fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
            let l = b.local();
            let n = b.next();
            b.lookup(false, l[1], &[l[0]]);
            b.when_first_row(l[2]);
            b.when_first_row(l[3] - F::ONE);
            b.when_transition(n[2] - l[3]);
            b.when_transition(n[3] - l[2] - l[3]);
        }
    }

    /// A 16-row and a 4-row sender and a 4-row receiver of their values.
    fn exchange(mults: [u32; 4]) -> (Trace, Trace, Trace) {
        let tall = Trace::new((0..16).map(|i| Fp::new(10 + i % 4)).collect(), 1);
        let short = Trace::new((0..4).map(|i| Fp::new(10 + i)).collect(), 1);
        let (mut a, mut b) = (Fp::ZERO, Fp::ONE);
        let mut values = Vec::new();
        for (i, m) in mults.iter().enumerate() {
            values.extend([Fp::new(10 + i as u32), Fp::new(*m), a, b]);
            let c = a + b;
            a = b;
            b = c;
        }
        (tall, short, Trace::new(values, 4))
    }

    #[test]
    fn tables_of_different_heights() {
        let (tall, short, recv) = exchange([5; 4]);
        let tables = [
            TableInput { air: &Sender, trace: &tall, pre: None },
            TableInput { air: &Sender, trace: &short, pre: None },
            TableInput { air: &Receiver, trace: &recv, pre: None },
        ];
        let specs = [
            TableSpec { air: &Sender, pre_root: None },
            TableSpec { air: &Sender, pre_root: None },
            TableSpec { air: &Receiver, pre_root: None },
        ];
        let checks: Vec<(&dyn DynAir, &Trace, Option<&Trace>)> =
            vec![(&Sender, &tall, None), (&Sender, &short, None), (&Receiver, &recv, None)];
        assert_eq!(check_tables(&checks, &[]), Ok(()));
        let proof = prove_tables(&CONFIG, &tables, &[], &mut transcript());
        assert_eq!(proof.tables.iter().map(|t| t.log_n).collect::<Vec<_>>(), vec![4, 2, 2]);
        assert_eq!(verify_tables(&CONFIG, &specs, &[], &proof, &mut transcript()), Ok(()));
        let back = Proof::from_bytes(&proof.to_bytes()).unwrap();
        assert_eq!(back, proof);

        // Tables in another order, or one missing.
        let swapped = [specs[0], specs[2], specs[1]];
        assert!(verify_tables(&CONFIG, &swapped, &[], &proof, &mut transcript()).is_err());
        assert_eq!(verify_tables(&CONFIG, &specs[..2], &[], &proof, &mut transcript()), Err(VerifyError::Shape));
        // Openings of a smaller table are checked.
        let mut p = proof.clone();
        p.openings[3][2].trace_row[2] += Fp::ONE;
        assert_eq!(
            verify_tables(&CONFIG, &specs, &[], &p, &mut transcript()),
            Err(VerifyError::InvalidTraceOpening { query: 3 })
        );
        let mut p = proof.clone();
        p.tables[2].trace_at_zeta_next[3] += Fp4::ONE;
        assert!(verify_tables(&CONFIG, &specs, &[], &p, &mut transcript()).is_err());
        // Moving lookup weight between tables keeps the total but breaks
        // the last-row constraint of both.
        let mut p = proof.clone();
        p.tables[0].lookup_sum += Fp4::ONE;
        p.tables[2].lookup_sum -= Fp4::ONE;
        assert!(verify_tables(&CONFIG, &specs, &[], &p, &mut transcript()).is_err());
        let mut p = proof.clone();
        p.tables[1].lookup_sum += Fp4::ONE;
        assert_eq!(verify_tables(&CONFIG, &specs, &[], &p, &mut transcript()), Err(VerifyError::LookupSum));

        // Messages that do not balance.
        let (tall, short, recv) = exchange([5, 5, 4, 5]);
        let checks: Vec<(&dyn DynAir, &Trace, Option<&Trace>)> =
            vec![(&Sender, &tall, None), (&Sender, &short, None), (&Receiver, &recv, None)];
        assert_eq!(check_tables(&checks, &[]), Err((2, (usize::MAX, 0, "lookup sum"))));
        if !cfg!(debug_assertions) {
            let tables = [
                TableInput { air: &Sender, trace: &tall, pre: None },
                TableInput { air: &Sender, trace: &short, pre: None },
                TableInput { air: &Receiver, trace: &recv, pre: None },
            ];
            let proof = prove_tables(&CONFIG, &tables, &[], &mut transcript());
            assert_eq!(verify_tables(&CONFIG, &specs, &[], &proof, &mut transcript()), Err(VerifyError::LookupSum));
        }
    }

    /// Two columns that must be permutations of each other.
    struct PermAir;

    impl Air for PermAir {
        fn width(&self) -> usize {
            2
        }
        fn max_constraint_degree(&self) -> usize {
            2
        }
        fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
            b.lookup(true, F::ONE, &[b.local()[0]]);
            b.lookup(false, F::ONE, &[b.local()[1]]);
        }
    }

    #[test]
    fn permutation_lookup() {
        let a = [5u32, 3, 9, 1, 7, 7, 2, 0];
        let bperm = [7u32, 1, 0, 9, 3, 2, 7, 5];
        let values: Vec<Fp> = a.iter().zip(&bperm).flat_map(|(x, y)| [Fp::new(*x), Fp::new(*y)]).collect();
        let trace = Trace::new(values, 2);
        assert_eq!(check_constraints(&PermAir, &trace, &[]), Ok(()));
        let proof = prove(&CONFIG, &PermAir, &trace, &[], &mut transcript());
        assert_eq!(verify(&CONFIG, &PermAir, &[], &proof, &mut transcript()), Ok(()));
        let mut bad = trace.clone();
        bad.values[3] = Fp::new(4);
        assert!(check_constraints(&PermAir, &bad, &[]).is_err());
    }
}
