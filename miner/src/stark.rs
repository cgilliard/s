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
//!    and the prover builds the auxiliary trace: for every term an inverse
//!    of `gamma + sum delta^(k+1) v_k` and one running sum of the signed
//!    `multiplicity * inverse` contributions. It commits to it as a second
//!    matrix (extension columns stored as four base columns each).
//! 3. The verifier samples `alpha`. On every point of `D` the prover
//!    evaluates the AIR constraints and the lookup constraints (inverse
//!    checks, running-sum transition, zero at both ends), combines them as
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

use crate::challenger::Challenger;
use crate::codec::{Reader, Writer};
use crate::ext::{DEGREE, Fp4};
use crate::field::{Deg, Field, batch_inverse};
use crate::fri::{self, FriConfig, FriError, FriProof};
use crate::merkle::{Digest, MerkleTree, verify as merkle_verify};
use crate::ntt::{
    MULTIPLICATIVE_GENERATOR, coset_intt_ext, coset_ntt, coset_ntt_ext, intt, log2_strict, root_of_unity,
};
use crate::parallel::{par_chunks_mut, par_map, par_map_min};
use crate::poseidon2::Fp;

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
    constraints: Vec<F>,
    lookups: Vec<LookupTerm<F>>,
    marks: Vec<(usize, &'static str)>,
}

impl<'a, F: Field> Builder<'a, F> {
    pub(crate) fn new(local: &'a [F], next: &'a [F], pre: (&'a [F], &'a [F]), public: &'a [F], sel: (F, F, F)) -> Self {
        Builder {
            local,
            next,
            pre_local: pre.0,
            pre_next: pre.1,
            public,
            is_first_row: sel.0,
            is_last_row: sel.1,
            is_transition: sel.2,
            constraints: Vec::new(),
            lookups: Vec::new(),
            marks: Vec::new(),
        }
    }

    /// Labels the constraints emitted from here on, for diagnostics from
    /// [`check_constraints`]. Has no effect on proving.
    pub fn mark(&mut self, label: &'static str) {
        self.marks.push((self.constraints.len(), label));
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
        (self.constraints, self.lookups)
    }

    /// Requires `c == 0` on every row.
    pub fn assert_zero(&mut self, c: F) {
        self.constraints.push(c);
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
        self.lookups.push(LookupTerm { send, multiplicity, values: values.to_vec() });
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

    fn eval<F: Field>(&self, builder: &mut Builder<'_, F>);
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
}

impl StarkConfig {
    fn fri(&self) -> FriConfig {
        FriConfig { log_blowup: self.log_blowup, num_queries: self.num_queries }
    }
}

/// Openings of the committed matrices at one queried domain index.
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub log_n: usize,
    pub trace_root: Digest,
    /// Present when the AIR declares lookups.
    pub aux_root: Option<Digest>,
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
    pub fri: FriProof,
    pub openings: Vec<QueryOpening>,
}

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(1 << 16);
        w.u32(self.log_n as u32);
        w.digest(&self.trace_root);
        match &self.aux_root {
            Some(r) => {
                w.u32(1);
                w.digest(r);
            }
            None => w.u32(0),
        }
        w.digest(&self.quotient_root);
        w.fp4_vec(&self.trace_at_zeta);
        w.fp4_vec(&self.trace_at_zeta_next);
        w.fp4_vec(&self.aux_at_zeta);
        w.fp4_vec(&self.aux_at_zeta_next);
        w.fp4_vec(&self.pre_at_zeta);
        w.fp4_vec(&self.pre_at_zeta_next);
        w.fp4_vec(&self.quotient_at_zeta_q);
        self.fri.write(&mut w);
        w.u32(self.openings.len() as u32);
        for o in &self.openings {
            w.fp_vec(&o.trace_row);
            w.digest_vec(&o.trace_path);
            w.fp_vec(&o.aux_row);
            w.digest_vec(&o.aux_path);
            w.fp_vec(&o.pre_row);
            w.digest_vec(&o.pre_path);
            w.fp_vec(&o.quotient_row);
            w.digest_vec(&o.quotient_path);
        }
        w.finish()
    }

    /// Parses a proof; the whole slice must be consumed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Proof> {
        let mut r = Reader(bytes);
        let log_n = r.u32()? as usize;
        let trace_root = r.digest()?;
        let aux_root = match r.u32()? {
            0 => None,
            1 => Some(r.digest()?),
            _ => return None,
        };
        let quotient_root = r.digest()?;
        let trace_at_zeta = r.fp4_vec()?;
        let trace_at_zeta_next = r.fp4_vec()?;
        let aux_at_zeta = r.fp4_vec()?;
        let aux_at_zeta_next = r.fp4_vec()?;
        let pre_at_zeta = r.fp4_vec()?;
        let pre_at_zeta_next = r.fp4_vec()?;
        let quotient_at_zeta_q = r.fp4_vec()?;
        let fri = FriProof::read(&mut r)?;
        let n = r.len(4)?;
        let mut openings = Vec::with_capacity(n);
        for _ in 0..n {
            openings.push(QueryOpening {
                trace_row: r.fp_vec()?,
                trace_path: r.digest_vec()?,
                aux_row: r.fp_vec()?,
                aux_path: r.digest_vec()?,
                pre_row: r.fp_vec()?,
                pre_path: r.digest_vec()?,
                quotient_row: r.fp_vec()?,
                quotient_path: r.digest_vec()?,
            });
        }
        if !r.is_empty() {
            return None;
        }
        Some(Proof {
            log_n,
            trace_root,
            aux_root,
            quotient_root,
            trace_at_zeta,
            trace_at_zeta_next,
            aux_at_zeta,
            aux_at_zeta_next,
            pre_at_zeta,
            pre_at_zeta_next,
            quotient_at_zeta_q,
            fri,
            openings,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    Shape,
    ConstraintIdentity,
    Fri(FriError),
    InvalidTraceOpening { query: usize },
    InvalidAuxOpening { query: usize },
    InvalidPreprocessedOpening { query: usize },
    InvalidQuotientOpening { query: usize },
    DeepMismatch { query: usize },
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::Shape => f.write_str("stark proof has the wrong shape"),
            VerifyError::ConstraintIdentity => f.write_str("constraints do not hold at the out-of-domain point"),
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
            VerifyError::DeepMismatch { query } => {
                write!(f, "query {query}: deep value does not match fri input")
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

/// Lookup challenges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LookupChallenges {
    pub gamma: Fp4,
    pub delta: Fp4,
}

impl LookupChallenges {
    fn sample(ch: &mut Challenger) -> LookupChallenges {
        LookupChallenges { gamma: ch.sample_ext(), delta: ch.sample_ext() }
    }

    /// `gamma + sum delta^(k+1) values[k]`.
    fn denominator<F: Field>(&self, values: &[F]) -> Fp4 {
        let mut acc = self.gamma;
        let mut pow = self.delta;
        for v in values {
            acc += v.mul_ext(pow);
            pow *= self.delta;
        }
        acc
    }
}

/// Evaluates the AIR at one row pair.
pub(crate) fn evaluate<F: Field, A: Air>(
    air: &A,
    local: &[F],
    next: &[F],
    pre: (&[F], &[F]),
    public: &[F],
    sel: (F, F, F),
) -> (Vec<F>, Vec<LookupTerm<F>>) {
    let mut b = Builder::new(local, next, pre, public, sel);
    air.eval(&mut b);
    (b.constraints, b.lookups)
}

/// Number of lookup constraints for `terms` lookup terms: one inverse check
/// per term plus the running-sum transition and its two boundary checks.
pub(crate) fn num_lookup_constraints(terms: usize) -> usize {
    if terms == 0 { 0 } else { terms + 3 }
}

/// Counts constraints and lookup terms an AIR emits (on an all-zero row pair).
pub(crate) fn shape<A: Air>(air: &A, public: &[Fp]) -> (usize, usize) {
    let zeros = vec![Fp::ZERO; air.width()];
    let pre = vec![Fp::ZERO; air.preprocessed_width()];
    let (c, t) = evaluate(air, &zeros, &zeros, (&pre, &pre), public, (Fp::ZERO, Fp::ZERO, Fp::ZERO));
    (c.len(), t.len())
}

/// Lookup constraints for one row, in order: inverse checks, running-sum
/// transition, first-row zero, last-row zero. `aux_local`/`aux_next` are the
/// extension values: inverses then the running sum.
fn lookup_constraints<F: Field>(
    ch: &LookupChallenges,
    terms: &[LookupTerm<F>],
    aux_local: &[Fp4],
    aux_next: &[Fp4],
    sel: (Fp4, Fp4, Fp4),
) -> Vec<Fp4> {
    let t = terms.len();
    let mut out = Vec::with_capacity(t + 3);
    let mut contrib = Fp4::ZERO;
    for (k, term) in terms.iter().enumerate() {
        let inv = aux_local[k];
        out.push(inv * ch.denominator(&term.values) - Fp4::ONE);
        let c = term.multiplicity.mul_ext(inv);
        if term.send { contrib += c } else { contrib -= c }
    }
    let s = aux_local[t];
    let s_next = aux_next[t];
    out.push(sel.2 * (s_next - s - contrib));
    out.push(sel.0 * s);
    out.push(sel.1 * (s + contrib));
    out
}

/// Combines main constraints and lookup constraints with powers of alpha.
fn combine<F: Field>(
    constraints: &[F],
    terms: &[LookupTerm<F>],
    aux_local: &[Fp4],
    aux_next: &[Fp4],
    sel_ext: (Fp4, Fp4, Fp4),
    ch: Option<&LookupChallenges>,
    alpha_powers: &[Fp4],
) -> Fp4 {
    let mut acc = Fp4::ZERO;
    let mut powers = alpha_powers.iter();
    for c in constraints {
        acc += c.mul_ext(*powers.next().expect("alpha powers"));
    }
    if let Some(ch) = ch {
        for c in lookup_constraints(ch, terms, aux_local, aux_next, sel_ext) {
            acc += c * *powers.next().expect("alpha powers");
        }
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

/// Out-of-domain openings: trace at zeta and g zeta, aux at zeta and g zeta,
/// quotient chunks at zeta_q.
/// DEEP combination `sum_k beta^k (row_k - opened_k) / (x - point_k)`,
/// arranged so each row costs base-times-extension products only: the
/// opened values are folded into constants once, and the openings at `g
/// zeta` reuse the row sum at `zeta` scaled by a power of `beta`.
/// Beta power offsets: trace at zeta, trace at g zeta, aux at both,
/// preprocessed at both, then the quotient chunks.
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
    fn new(beta: Fp4, openings: Openings<'_>) -> Deep {
        let (t_z, t_zn, a_z, a_zn, p_z, p_zn, q_zq) = openings;
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

type Openings<'a> = (&'a [Fp4], &'a [Fp4], &'a [Fp4], &'a [Fp4], &'a [Fp4], &'a [Fp4], &'a [Fp4]);
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
        let mut lde = vec![Fp::ZERO; big_n * w];
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

fn observe_setup(challenger: &mut Challenger, log_n: usize, public: &[Fp]) {
    challenger.observe(Fp::from_u32(log_n as u32));
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
    let n = trace.height();
    let empty: Vec<Fp> = Vec::new();
    let pre_row = |i: usize| -> &[Fp] { pre.map_or(&empty[..], |p| p.row(i)) };
    let ch = LookupChallenges {
        gamma: Fp4::from_u32(0x1234_5678),
        delta: Fp4([Fp::new(3), Fp::new(5), Fp::new(7), Fp::new(11)]),
    };
    let mut sum = Fp4::ZERO;
    for i in 0..n {
        let next = (i + 1) % n;
        let sel = (
            if i == 0 { Fp::ONE } else { Fp::ZERO },
            if i == n - 1 { Fp::ONE } else { Fp::ZERO },
            if i == n - 1 { Fp::ZERO } else { Fp::ONE },
        );
        let mut b = Builder::new(trace.row(i), trace.row(next), (pre_row(i), pre_row(next)), public, sel);
        air.eval(&mut b);
        if let Some(k) = b.constraints.iter().position(|c| *c != Fp::ZERO) {
            let label = b.marks.iter().rev().find(|(at, _)| *at <= k).map(|(_, l)| *l).unwrap_or("");
            return Err((i, k, label));
        }
        for term in &b.lookups {
            let d = ch.denominator(&term.values);
            let Some(inv) = d.inverse() else {
                return Err((i, 0, "lookup denominator zero"));
            };
            let c = term.multiplicity.mul_ext(inv);
            if term.send { sum += c } else { sum -= c }
        }
    }
    if sum != Fp4::ZERO {
        return Err((usize::MAX, 0, "lookup sum"));
    }
    Ok(())
}

/// Upper bound on the degree of the AIR's constraints, measured by
/// evaluating it over [`Deg`] with every column at degree one, the row
/// selectors at degree one and the transition selector at degree zero.
/// Lookup terms count as degree `max(values) + 1` and `multiplicity + 2`.
/// Must not exceed `air.max_constraint_degree()`.
pub fn measure_degree<A: Air>(air: &A, num_public: usize) -> usize {
    let cols = vec![Deg(1); air.width()];
    let pre = vec![Deg(1); air.preprocessed_width()];
    let public = vec![Deg(0); num_public];
    let (constraints, terms) = evaluate(air, &cols, &cols, (&pre, &pre), &public, (Deg(1), Deg(1), Deg(0)));
    let mut max = constraints.iter().map(|d| d.0 as usize).max().unwrap_or(0);
    for t in &terms {
        let v = t.values.iter().map(|d| d.0 as usize).max().unwrap_or(0);
        max = max.max(v + 1).max(t.multiplicity.0 as usize + 2);
    }
    max
}

/// Builds the auxiliary trace (row-major extension values: inverses then
/// the running sum) for `trace` under the given challenges.
fn build_aux<A: Air>(
    air: &A,
    trace: &Trace,
    pre: Option<&Preprocessed>,
    public: &[Fp],
    ch: &LookupChallenges,
    terms: usize,
) -> Vec<Fp4> {
    let n = trace.height();
    let empty: Vec<Fp> = Vec::new();
    let pre_row = |i: usize| -> &[Fp] { pre.map_or(&empty[..], |p| p.table.row(i)) };
    let width = terms + 1;
    let mut aux = vec![Fp4::ZERO; n * width];
    let rows: Vec<(Vec<Fp4>, Vec<Fp4>)> = par_map(n, |i| {
        let (_, row_terms) = evaluate(
            air,
            trace.row(i),
            trace.row((i + 1) % n),
            (pre_row(i), pre_row((i + 1) % n)),
            public,
            (Fp::ZERO, Fp::ZERO, Fp::ZERO),
        );
        assert_eq!(row_terms.len(), terms, "lookup term count varies between rows");
        let denoms: Vec<Fp4> = row_terms.iter().map(|t| ch.denominator(&t.values)).collect();
        let mults: Vec<Fp4> = row_terms
            .iter()
            .map(|t| if t.send { Fp4::from_base(t.multiplicity) } else { -Fp4::from_base(t.multiplicity) })
            .collect();
        (denoms, mults)
    });
    let mut denoms = Vec::with_capacity(n * terms);
    let mut mults = Vec::with_capacity(n * terms);
    for (d, m) in rows {
        denoms.extend(d);
        mults.extend(m);
    }
    let invs = par_batch_inverse(&denoms);
    let mut sum = Fp4::ZERO;
    for i in 0..n {
        aux[i * width + terms] = sum;
        for k in 0..terms {
            let inv = invs[i * terms + k];
            aux[i * width + k] = inv;
            sum += mults[i * terms + k] * inv;
        }
    }
    debug_assert!(sum.is_zero(), "lookup terms do not cancel: trace violates a multiset relation");
    aux
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// Interpolates a base column over `H` and evaluates it on the coset of
/// size `big_n`; returns the coefficients and the evaluations.
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

fn lde_column(col: Vec<Fp>, big_n: usize, shift: Fp) -> (Vec<Fp>, Vec<Fp>) {
    let mut c = col;
    intt(&mut c);
    let mut e = c.clone();
    e.resize(big_n, Fp::ZERO);
    coset_ntt(&mut e, shift);
    (c, e)
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
    assert_eq!(trace.width, air.width(), "trace width does not match air");
    let pre_w = air.preprocessed_width();
    assert_eq!(pre.map_or(0, |p| p.width), pre_w, "preprocessed width does not match air");
    if let Some(p) = pre {
        assert_eq!(p.log_n, log2_strict(trace.height()), "preprocessed table height does not match trace");
        assert_eq!(p.log_blowup, config.log_blowup, "preprocessed table blowup does not match config");
    }
    let empty: Vec<Fp> = Vec::new();
    let pre_row = |i: usize| -> &[Fp] { pre.map_or(&empty[..], |p| p.row(i)) };
    debug_assert!(
        measure_degree(air, public.len()) <= air.max_constraint_degree(),
        "air constraints exceed the declared degree"
    );
    let n = trace.height();
    let log_n = log2_strict(n);
    let log_blowup = config.log_blowup;
    let log_q = log_quotient_degree(air.max_constraint_degree());
    assert!(log_blowup >= log_q, "log_blowup must be at least {log_q} for this air");
    let big_n = n << log_blowup;
    let log_big_n = log_n + log_blowup;
    let shift = MULTIPLICATIVE_GENERATOR;
    let w = air.width();
    let num_chunks = 1usize << log_q;
    let (num_constraints, num_terms) = shape(air, public);
    let aux_ext_w = if num_terms > 0 { num_terms + 1 } else { 0 };
    let aux_w = aux_ext_w * DEGREE;

    observe_setup(challenger, log_n, public);
    if let Some(p) = pre {
        challenger.observe_digest(&p.root());
    }
    let mut timer = Timer::new();

    // 1. Trace LDE and commitment. Columns are extended in parallel batches
    // (bounding memory) and scattered into the row-major evaluation table.
    let mut coeffs: Vec<Vec<Fp>> = Vec::with_capacity(w);
    let mut lde = vec![Fp::ZERO; big_n * w];
    let batch = crate::parallel::threads() * 4;
    for first in (0..w).step_by(batch) {
        let cols = (first + batch).min(w) - first;
        let ext: Vec<(Vec<Fp>, Vec<Fp>)> = par_map_min(cols, 1, |k| lde_column(trace.column(first + k), big_n, shift));
        let (c, e): (Vec<Vec<Fp>>, Vec<Vec<Fp>>) = ext.into_iter().unzip();
        scatter_columns(&mut lde, w, first, &e);
        coeffs.extend(c);
    }
    timer.lap("trace lde");
    let trace_tree = MerkleTree::from_flat(&lde, w);
    challenger.observe_digest(&trace_tree.root());
    timer.lap("trace commit");

    // 2. Lookup challenges and auxiliary trace.
    let mut lookup_ch = None;
    let mut aux_coeffs: Vec<Vec<Fp>> = Vec::new();
    let mut aux_lde: Vec<Fp4> = Vec::new(); // big_n x aux_ext_w
    let mut aux_rows: Vec<Fp> = Vec::new(); // big_n x aux_w
    let mut aux_tree = None;
    if num_terms > 0 {
        let ch = LookupChallenges::sample(challenger);
        let aux = build_aux(air, trace, pre, public, &ch, num_terms);
        timer.lap("aux build");
        aux_rows = vec![Fp::ZERO; big_n * aux_w];
        for first in (0..aux_w).step_by(batch) {
            let cols = (first + batch).min(aux_w) - first;
            let ext: Vec<(Vec<Fp>, Vec<Fp>)> = par_map_min(cols, 1, |j| {
                let (e, k) = ((first + j) / DEGREE, (first + j) % DEGREE);
                let col: Vec<Fp> = (0..n).map(|i| aux[i * aux_ext_w + e].0[k]).collect();
                lde_column(col, big_n, shift)
            });
            let (c, e): (Vec<Vec<Fp>>, Vec<Vec<Fp>>) = ext.into_iter().unzip();
            scatter_columns(&mut aux_rows, aux_w, first, &e);
            aux_coeffs.extend(c);
        }
        aux_lde = par_map(big_n, |i| {
            let row = &aux_rows[i * aux_w..(i + 1) * aux_w];
            (0..aux_ext_w).map(|e| Fp4(core::array::from_fn(|k| row[e * DEGREE + k]))).collect::<Vec<Fp4>>()
        })
        .into_iter()
        .flatten()
        .collect();
        timer.lap("aux lde");
        let tree = MerkleTree::from_flat(&aux_rows, aux_w);
        challenger.observe_digest(&tree.root());
        timer.lap("aux commit");
        aux_tree = Some(tree);
        lookup_ch = Some(ch);
    }

    // 3. Constraint combination and quotient.
    let alpha = challenger.sample_ext();
    let alpha_powers = powers(alpha, num_constraints + num_lookup_constraints(num_terms));
    let g = root_of_unity(log_n);
    let g_inv = g.inverse().unwrap();
    let omega = root_of_unity(log_big_n);
    let xs: Vec<Fp> = {
        let mut v = Vec::with_capacity(big_n);
        let mut x = shift;
        for _ in 0..big_n {
            v.push(x);
            x = x.mul(&omega);
        }
        v
    };
    let period = 1usize << log_blowup;
    let z_h: Vec<Fp> = (0..period).map(|i| xs[i].pow(n as u64).sub(&Fp::ONE)).collect();
    let z_h_inv = batch_inverse(&z_h);
    let denoms: Vec<Fp> = xs.iter().flat_map(|x| [x.sub(&Fp::ONE), x.sub(&g_inv)]).collect();
    let denom_inv = batch_inverse(&denoms);
    let empty: [Fp4; 0] = [];

    let mut quotient: Vec<Fp4> = par_map(big_n, |i| {
        let zh = z_h[i % period];
        let first = zh.mul(&denom_inv[2 * i]);
        let last = zh.mul(&denom_inv[2 * i + 1]);
        let transition = xs[i].sub(&g_inv);
        let next_i = (i + period) % big_n;
        let (constraints, terms) = evaluate(
            air,
            &lde[i * w..(i + 1) * w],
            &lde[next_i * w..(next_i + 1) * w],
            (pre_row(i), pre_row(next_i)),
            public,
            (first, last, transition),
        );
        let (aux_l, aux_n): (&[Fp4], &[Fp4]) = if aux_ext_w > 0 {
            (&aux_lde[i * aux_ext_w..(i + 1) * aux_ext_w], &aux_lde[next_i * aux_ext_w..(next_i + 1) * aux_ext_w])
        } else {
            (&empty, &empty)
        };
        let sel_ext = (Fp4::from_base(first), Fp4::from_base(last), Fp4::from_base(transition));
        let c = combine(&constraints, &terms, aux_l, aux_n, sel_ext, lookup_ch.as_ref(), &alpha_powers);
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
    let (chunk_coeffs, chunk_evals): (Vec<Vec<Fp4>>, Vec<Vec<Fp4>>) = chunks.into_iter().unzip();
    let chunk_lde: Vec<Fp4> = par_map(big_n, |i| (0..num_chunks).map(|j| chunk_evals[j][i]).collect::<Vec<Fp4>>())
        .into_iter()
        .flatten()
        .collect();
    drop(chunk_evals);
    let chunk_rows: Vec<Fp> = ext_row(&chunk_lde);
    timer.lap("quotient lde");
    let quotient_tree = MerkleTree::from_flat(&chunk_rows, num_chunks * DEGREE);
    challenger.observe_digest(&quotient_tree.root());
    timer.lap("quotient commit");

    // 4. Out-of-domain openings.
    let zeta = challenger.sample_ext();
    let zeta_next = zeta.mul_base(&g);
    let zeta_q = zeta.exp(num_chunks as u64);
    let trace_at_zeta = eval_base_polys_at(&coeffs, zeta);
    let trace_at_zeta_next = eval_base_polys_at(&coeffs, zeta_next);
    let aux_at_zeta = eval_base_polys_at(&aux_coeffs, zeta);
    let aux_at_zeta_next = eval_base_polys_at(&aux_coeffs, zeta_next);
    let no_coeffs: Vec<Vec<Fp>> = Vec::new();
    let pre_coeffs = pre.map_or(&no_coeffs, |p| &p.coeffs);
    let pre_at_zeta = eval_base_polys_at(pre_coeffs, zeta);
    let pre_at_zeta_next = eval_base_polys_at(pre_coeffs, zeta_next);
    let quotient_at_zeta_q: Vec<Fp4> = chunk_coeffs.iter().map(|c| eval_ext_poly_at(c, zeta_q)).collect();
    for v in trace_at_zeta
        .iter()
        .chain(&trace_at_zeta_next)
        .chain(&aux_at_zeta)
        .chain(&aux_at_zeta_next)
        .chain(&pre_at_zeta)
        .chain(&pre_at_zeta_next)
        .chain(&quotient_at_zeta_q)
    {
        challenger.observe_ext(v);
    }
    timer.lap("openings");

    // 5. DEEP combination and FRI.
    let beta = challenger.sample_ext();
    let deep = Deep::new(
        beta,
        (
            &trace_at_zeta,
            &trace_at_zeta_next,
            &aux_at_zeta,
            &aux_at_zeta_next,
            &pre_at_zeta,
            &pre_at_zeta_next,
            &quotient_at_zeta_q,
        ),
    );
    let mut denoms_ext: Vec<Fp4> = Vec::with_capacity(3 * big_n);
    for x in &xs {
        let xe = Fp4::from_base(*x);
        denoms_ext.push(xe - zeta);
        denoms_ext.push(xe - zeta_next);
        denoms_ext.push(xe - zeta_q);
    }
    let inv = par_batch_inverse(&denoms_ext);
    let reduced: Vec<Fp4> = par_map(big_n, |i| {
        deep.value(
            (
                &lde[i * w..(i + 1) * w],
                &aux_rows[i * aux_w..(i + 1) * aux_w],
                pre_row(i),
                &chunk_lde[i * num_chunks..(i + 1) * num_chunks],
            ),
            inv[3 * i],
            inv[3 * i + 1],
            inv[3 * i + 2],
        )
    });
    timer.lap("deep");
    let (fri_proof, indices) = fri::prove(&config.fri(), challenger, shift, reduced);
    timer.lap("fri");

    let openings = indices
        .iter()
        .map(|&i| QueryOpening {
            trace_row: lde[i * w..(i + 1) * w].to_vec(),
            trace_path: trace_tree.open(i),
            aux_row: aux_rows[i * aux_w..(i + 1) * aux_w].to_vec(),
            aux_path: aux_tree.as_ref().map(|t| t.open(i)).unwrap_or_default(),
            pre_row: pre_row(i).to_vec(),
            pre_path: pre.map(|p| p.tree.open(i)).unwrap_or_default(),
            quotient_row: chunk_rows[i * num_chunks * DEGREE..(i + 1) * num_chunks * DEGREE].to_vec(),
            quotient_path: quotient_tree.open(i),
        })
        .collect();

    Proof {
        log_n,
        trace_root: trace_tree.root(),
        aux_root: aux_tree.map(|t| t.root()),
        quotient_root: quotient_tree.root(),
        trace_at_zeta,
        trace_at_zeta_next,
        aux_at_zeta,
        aux_at_zeta_next,
        pre_at_zeta,
        pre_at_zeta_next,
        quotient_at_zeta_q,
        fri: fri_proof,
        openings,
    }
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
    let w = air.width();
    let pre_w = air.preprocessed_width();
    let log_n = proof.log_n;
    let log_blowup = config.log_blowup;
    let log_q = log_quotient_degree(air.max_constraint_degree());
    let num_chunks = 1usize << log_q;
    let (num_constraints, num_terms) = shape(air, public);
    let aux_ext_w = if num_terms > 0 { num_terms + 1 } else { 0 };
    let aux_w = aux_ext_w * DEGREE;
    if log_n == 0 || log_n + log_blowup > 27 || log_blowup < log_q {
        return Err(VerifyError::Shape);
    }
    let n = 1usize << log_n;
    let log_big_n = log_n + log_blowup;
    let shift = MULTIPLICATIVE_GENERATOR;
    if proof.trace_at_zeta.len() != w
        || proof.trace_at_zeta_next.len() != w
        || proof.aux_at_zeta.len() != aux_w
        || proof.aux_at_zeta_next.len() != aux_w
        || proof.aux_root.is_some() != (num_terms > 0)
        || pre_root.is_some() != (pre_w > 0)
        || proof.pre_at_zeta.len() != pre_w
        || proof.pre_at_zeta_next.len() != pre_w
        || proof.quotient_at_zeta_q.len() != num_chunks
        || proof.openings.len() != config.num_queries
    {
        return Err(VerifyError::Shape);
    }

    observe_setup(challenger, log_n, public);
    if let Some(root) = pre_root {
        challenger.observe_digest(root);
    }
    challenger.observe_digest(&proof.trace_root);
    let lookup_ch = match &proof.aux_root {
        Some(root) => {
            let ch = LookupChallenges::sample(challenger);
            challenger.observe_digest(root);
            Some(ch)
        }
        None => None,
    };
    let alpha = challenger.sample_ext();
    let alpha_powers = powers(alpha, num_constraints + num_lookup_constraints(num_terms));
    challenger.observe_digest(&proof.quotient_root);
    let zeta = challenger.sample_ext();
    for v in proof
        .trace_at_zeta
        .iter()
        .chain(&proof.trace_at_zeta_next)
        .chain(&proof.aux_at_zeta)
        .chain(&proof.aux_at_zeta_next)
        .chain(&proof.pre_at_zeta)
        .chain(&proof.pre_at_zeta_next)
        .chain(&proof.quotient_at_zeta_q)
    {
        challenger.observe_ext(v);
    }
    let beta = challenger.sample_ext();
    let deep = Deep::new(
        beta,
        (
            &proof.trace_at_zeta,
            &proof.trace_at_zeta_next,
            &proof.aux_at_zeta,
            &proof.aux_at_zeta_next,
            &proof.pre_at_zeta,
            &proof.pre_at_zeta_next,
            &proof.quotient_at_zeta_q,
        ),
    );

    // Constraint identity at zeta.
    let g = root_of_unity(log_n);
    let g_inv = g.inverse().unwrap();
    let zeta_next = zeta.mul_base(&g);
    let zeta_q = zeta.exp(num_chunks as u64);
    let z_h = zeta.exp(n as u64) - Fp4::ONE;
    let first = z_h * (zeta - Fp4::ONE).inv().ok_or(VerifyError::ConstraintIdentity)?;
    let last = z_h * (zeta - Fp4::from_base(g_inv)).inv().ok_or(VerifyError::ConstraintIdentity)?;
    let transition = zeta - Fp4::from_base(g_inv);
    let public_ext: Vec<Fp4> = public.iter().map(|x| Fp4::from_base(*x)).collect();
    let (constraints, terms) = evaluate(
        air,
        &proof.trace_at_zeta,
        &proof.trace_at_zeta_next,
        (&proof.pre_at_zeta, &proof.pre_at_zeta_next),
        &public_ext,
        (first, last, transition),
    );
    let aux_l = ext_from_base_openings(&proof.aux_at_zeta);
    let aux_n = ext_from_base_openings(&proof.aux_at_zeta_next);
    let c_zeta =
        combine(&constraints, &terms, &aux_l, &aux_n, (first, last, transition), lookup_ch.as_ref(), &alpha_powers);
    let mut q_zeta = Fp4::ZERO;
    let mut zeta_pow = Fp4::ONE;
    for q in &proof.quotient_at_zeta_q {
        q_zeta += *q * zeta_pow;
        zeta_pow *= zeta;
    }
    if q_zeta * z_h != c_zeta {
        return Err(VerifyError::ConstraintIdentity);
    }

    // FRI, then consistency of its input with the opened rows.
    let inputs = fri::verify(&config.fri(), challenger, shift, log_big_n, &proof.fri)?;
    let omega = root_of_unity(log_big_n);
    for (q, ((index, claimed), opening)) in inputs.iter().zip(&proof.openings).enumerate() {
        if opening.trace_row.len() != w
            || opening.aux_row.len() != aux_w
            || opening.pre_row.len() != pre_w
            || opening.quotient_row.len() != num_chunks * DEGREE
        {
            return Err(VerifyError::Shape);
        }
        if !merkle_verify(&proof.trace_root, log_big_n, *index, &opening.trace_row, &opening.trace_path) {
            return Err(VerifyError::InvalidTraceOpening { query: q });
        }
        if let Some(root) = &proof.aux_root
            && !merkle_verify(root, log_big_n, *index, &opening.aux_row, &opening.aux_path)
        {
            return Err(VerifyError::InvalidAuxOpening { query: q });
        }
        if let Some(root) = pre_root
            && !merkle_verify(root, log_big_n, *index, &opening.pre_row, &opening.pre_path)
        {
            return Err(VerifyError::InvalidPreprocessedOpening { query: q });
        }
        if !merkle_verify(&proof.quotient_root, log_big_n, *index, &opening.quotient_row, &opening.quotient_path) {
            return Err(VerifyError::InvalidQuotientOpening { query: q });
        }
        let x = Fp4::from_base(shift.mul(&omega.pow(*index as u64)));
        let inv = batch_inverse(&[x - zeta, x - zeta_next, x - zeta_q]);
        let value = deep.value(
            (&opening.trace_row, &opening.aux_row, &opening.pre_row, &ext_from_row(&opening.quotient_row)),
            inv[0],
            inv[1],
            inv[2],
        );
        if value != *claimed {
            return Err(VerifyError::DeepMismatch { query: q });
        }
    }
    Ok(())
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

    const CONFIG: StarkConfig = StarkConfig { log_blowup: 2, num_queries: 16 };

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
            assert_eq!(proof.log_n, log_n);
            assert_eq!(proof.quotient_at_zeta_q.len(), 1);
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
        assert_eq!(proof.quotient_at_zeta_q.len(), 2);
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
        p.trace_at_zeta[0] += Fp4::ONE;
        assert!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()).is_err());
        let mut p = proof.clone();
        p.openings[2].trace_row[1] += Fp::ONE;
        assert_eq!(
            verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()),
            Err(VerifyError::InvalidTraceOpening { query: 2 })
        );
        let mut p = proof.clone();
        p.openings[5].quotient_row[0] += Fp::ONE;
        assert_eq!(
            verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()),
            Err(VerifyError::InvalidQuotientOpening { query: 5 })
        );
        let mut p = proof.clone();
        p.openings.pop();
        assert_eq!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()), Err(VerifyError::Shape));
        let mut p = proof.clone();
        p.trace_root[0] += Fp::ONE;
        assert!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()).is_err());
        let mut p = proof.clone();
        p.fri.final_value += Fp4::ONE;
        assert!(verify(&CONFIG, &Fibonacci, &public, &p, &mut transcript()).is_err());
        let mut p = proof.clone();
        p.log_n = 5;
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
        assert_eq!(measure_degree(&RomAir, 0), 3);
        let good = rom_trace(&[
            [2, 0, 1, 10], // write (1, 10) twice
            [1, 0, 2, 20], // write (2, 20) once
            [0, 1, 1, 10],
            [0, 1, 2, 20],
            [0, 1, 1, 10],
        ]);
        assert_eq!(check_constraints(&RomAir, &good, &[]), Ok(()));
        let proof = prove(&CONFIG, &RomAir, &good, &[], &mut transcript());
        assert!(proof.aux_root.is_some());
        assert_eq!(proof.aux_at_zeta.len(), 3 * 4);
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
        p.aux_at_zeta[0] += Fp4::ONE;
        assert!(verify(&CONFIG, &RomAir, &[], &p, &mut transcript()).is_err());
        let mut p = proof.clone();
        p.openings[0].aux_row[0] += Fp::ONE;
        assert_eq!(
            verify(&CONFIG, &RomAir, &[], &p, &mut transcript()),
            Err(VerifyError::InvalidAuxOpening { query: 0 })
        );
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
