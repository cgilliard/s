//! Recursive verification: compiles the STARK verifier for an inner AIR into
//! a program for [`crate::vm_air`], computing the witness alongside.
//!
//! [`Compiler`] mirrors `stark::verify` step by step. Every value the
//! verifier touches lives in the machine's memory: proof data enters as
//! inputs, transcript samples come from squeezed sponge state, and all
//! arithmetic is fused multiply-adds. The inner AIR's constraints are
//! compiled by running its `eval` over [`Expr`], a field whose operations
//! emit instructions, so any AIR can be verified without hand-written
//! circuits. Divisions use prover-supplied inverse hints checked by a
//! multiplication.
//!
//! The program depends only on the inner AIR, the STARK configuration, the
//! trace height and the number of public values, not on the proof, so a
//! verifier computes its digest from a zero-filled proof of the right shape
//! ([`dummy_proof`]). The output digest commits to the inner public values.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::ext::{DEGREE, Fp4};
use crate::field::Field;
use crate::fri::{FriProof, QueryStep, injection_rounds, leaf_row, round_log_arities};
use crate::merkle::Digest;
use crate::ntt::{MULTIPLICATIVE_GENERATOR, inv_two, root_of_unity};
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH, compress, permute};
use crate::stark::{
    Air, Builder, DynAir, LookupTerm, Proof, QueryOpening, StarkConfig, TableProof, log_quotient_degree,
    lookup_columns, num_lookup_constraints, shape,
};
use crate::vm_air::{Addr, Program};

/// Address of a memory word, usable as a field inside an AIR's `eval`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Expr(pub Addr);

const A_ZERO: Addr = 0;
const A_ONE: Addr = 1;
const A_MINUS_ONE: Addr = 2;
const A_X: Addr = 3;

thread_local! {
    static CTX: RefCell<Option<Compiler>> = const { RefCell::new(None) };
}

fn with_ctx<R>(f: impl FnOnce(&mut Compiler) -> R) -> R {
    CTX.with(|c| f(c.borrow_mut().as_mut().expect("Expr used outside of a compilation context")))
}

macro_rules! expr_binop {
    ($tr:ident, $m:ident, $tra:ident, $ma:ident, $body:expr) => {
        impl core::ops::$tr for Expr {
            type Output = Expr;
            fn $m(self, rhs: Expr) -> Expr {
                let f: fn(&mut Compiler, Addr, Addr) -> Addr = $body;
                Expr(with_ctx(|c| f(c, self.0, rhs.0)))
            }
        }
        impl core::ops::$tra for Expr {
            fn $ma(&mut self, rhs: Expr) {
                *self = core::ops::$tr::$m(*self, rhs);
            }
        }
    };
}
expr_binop!(Add, add, AddAssign, add_assign, |c, a, b| c.add(a, b));
expr_binop!(Sub, sub, SubAssign, sub_assign, |c, a, b| c.sub(a, b));
expr_binop!(Mul, mul, MulAssign, mul_assign, |c, a, b| c.mul(a, b));

impl core::ops::Neg for Expr {
    type Output = Expr;
    fn neg(self) -> Expr {
        Expr(with_ctx(|c| c.neg(self.0)))
    }
}

impl From<Fp> for Expr {
    fn from(x: Fp) -> Expr {
        Expr(with_ctx(|c| c.constant(Fp4::from_base(x))))
    }
}

impl Field for Expr {
    const ZERO: Expr = Expr(A_ZERO);
    const ONE: Expr = Expr(A_ONE);

    fn scale(self, b: Fp) -> Expr {
        Expr(with_ctx(|c| {
            let k = c.constant(Fp4::from_base(b));
            c.mul(self.0, k)
        }))
    }

    fn mul_ext(self, _: Fp4) -> Fp4 {
        unreachable!("mul_ext is not used inside AIR evaluation")
    }

    fn inv(self) -> Option<Expr> {
        Some(Expr(with_ctx(|c| c.inverse(self.0))))
    }
}

/// Replay of the Fiat-Shamir challenger inside the program.
///
/// The machine has one sponge register, shared with Merkle hashing, so the
/// transcript may only be permuted while no other hashing has happened
/// since its last permutation; `state` records what the register must hold.
struct Transcript {
    pending: Vec<Addr>,
    started: bool,
    squeezed: Option<Addr>,
    pos: usize,
    state: Option<[Fp; WIDTH]>,
}

/// Emits a verifier program while computing every value natively.
pub struct Compiler {
    pub prog: Program,
    pub inputs: Vec<Fp4>,
    mem: Vec<Fp4>,
    consts: HashMap<[u32; DEGREE], Addr>,
    sponge: Option<[Fp; WIDTH]>,
    digest: [Fp; DIGEST],
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    pub fn new() -> Compiler {
        let mut c = Compiler {
            prog: Program::new(),
            inputs: Vec::new(),
            mem: Vec::new(),
            consts: HashMap::new(),
            sponge: None,
            digest: [Fp::ZERO; DIGEST],
        };
        assert_eq!(c.constant(Fp4::ZERO), A_ZERO);
        assert_eq!(c.constant(Fp4::ONE), A_ONE);
        assert_eq!(c.constant(-Fp4::ONE), A_MINUS_ONE);
        assert_eq!(c.constant(Fp4::X), A_X);
        c
    }

    fn set(&mut self, addr: Addr, v: Fp4) {
        let a = addr as usize;
        if a >= self.mem.len() {
            self.mem.resize(a + 1, Fp4::ZERO);
        }
        self.mem[a] = v;
    }

    /// Records the native value of a word written by an instruction the
    /// caller emitted directly on `prog`.
    pub fn set_word(&mut self, addr: Addr, v: Fp4) {
        self.set(addr, v);
    }

    /// Native value of a word.
    pub fn val(&self, addr: Addr) -> Fp4 {
        self.mem.get(addr as usize).copied().unwrap_or(Fp4::ZERO)
    }

    pub fn constant(&mut self, v: Fp4) -> Addr {
        let key = v.0.map(|x| x.to_canonical());
        if let Some(&a) = self.consts.get(&key) {
            return a;
        }
        let a = self.prog.constant(v);
        self.set(a, v);
        self.consts.insert(key, a);
        a
    }

    pub fn scalar(&mut self, v: Fp) -> Addr {
        self.constant(Fp4::from_base(v))
    }

    pub fn input(&mut self, v: Fp4) -> Addr {
        let a = self.prog.input();
        self.inputs.push(v);
        self.set(a, v);
        a
    }

    /// Scalars as inputs at consecutive addresses, zero padded to a
    /// multiple of eight.
    pub fn scalar_inputs(&mut self, values: &[Fp]) -> Addr {
        let blocks = values.len().div_ceil(RATE).max(1);
        let base = self.prog.alloc((blocks * RATE) as u32);
        for b in 0..blocks {
            let out = base + (b * RATE) as Addr;
            self.prog.input8_at(out);
            for k in 0..RATE {
                let v = Fp4::from_base(values.get(b * RATE + k).copied().unwrap_or(Fp::ZERO));
                self.inputs.push(v);
                self.set(out + k as Addr, v);
            }
        }
        for k in values.len()..blocks * RATE {
            self.prog.assert_eq(base + k as Addr, A_ZERO);
        }
        base
    }

    pub fn word_inputs(&mut self, values: &[Fp4]) -> Vec<Addr> {
        values.iter().map(|v| self.input(*v)).collect()
    }

    pub fn muladd(&mut self, a: Addr, b: Addr, d: Addr) -> Addr {
        let out = self.prog.muladd(a, b, d);
        let v = self.val(a) * self.val(b) + self.val(d);
        self.set(out, v);
        out
    }

    pub fn mul(&mut self, a: Addr, b: Addr) -> Addr {
        self.muladd(a, b, A_ZERO)
    }

    pub fn add(&mut self, a: Addr, b: Addr) -> Addr {
        self.muladd(a, A_ONE, b)
    }

    pub fn sub(&mut self, a: Addr, b: Addr) -> Addr {
        self.muladd(b, A_MINUS_ONE, a)
    }

    pub fn neg(&mut self, a: Addr) -> Addr {
        self.muladd(a, A_MINUS_ONE, A_ZERO)
    }

    /// Inverse via a hint: the prover supplies `a^-1`, the program checks
    /// `a * hint == 1`.
    pub fn inverse(&mut self, a: Addr) -> Addr {
        let hint = self.val(a).inverse().unwrap_or(Fp4::ZERO);
        let h = self.input(hint);
        let prod = self.mul(a, h);
        self.prog.assert_eq(prod, A_ONE);
        h
    }

    pub fn assert_eq(&mut self, a: Addr, b: Addr) {
        self.prog.assert_eq(a, b);
    }

    pub fn component(&mut self, word: Addr, c: u8) -> Addr {
        let out = self.prog.component(word, c);
        self.set(out, Fp4::from_base(self.val(word).0[c as usize]));
        out
    }

    /// Copies words into a fresh block of eight, zero padded.
    fn block_of(&mut self, words: &[Addr]) -> Addr {
        assert!(words.len() <= RATE);
        let base = self.prog.alloc(RATE as u32);
        for i in 0..RATE {
            let src = words.get(i).copied().unwrap_or(A_ZERO);
            self.prog.muladd_to(src, A_ONE, A_ZERO, base + i as Addr);
            self.set(base + i as Addr, self.val(src));
        }
        base
    }

    /// `((s3 X + s2) X + s1) X + s0`.
    fn word_from_scalars(&mut self, s: [Addr; DEGREE]) -> Addr {
        let mut acc = s[3];
        for k in (0..3).rev() {
            acc = self.muladd(acc, A_X, s[k]);
        }
        acc
    }

    /// An empty compiler used to swap `self` into the thread-local context.
    fn shell() -> Compiler {
        Compiler {
            prog: Program::new(),
            inputs: Vec::new(),
            mem: Vec::new(),
            consts: HashMap::new(),
            sponge: None,
            digest: [Fp::ZERO; DIGEST],
        }
    }

    /// Asserts that the scalar at `a` equals the constant `v`.
    pub fn assert_scalar(&mut self, a: Addr, v: Fp) {
        let k = self.scalar(v);
        self.prog.assert_eq(a, k);
    }

    /// Asserts that `n` consecutive words at `a` and `b` are equal.
    pub fn assert_block(&mut self, a: Addr, b: Addr, n: usize) {
        for i in 0..n as Addr {
            self.prog.assert_eq(a + i, b + i);
        }
    }

    /// Hashes `len` scalars at `base` (zero padded to blocks of eight) as
    /// `poseidon2::hash`, leaving the digest in the sponge.
    pub fn hash_scalars(&mut self, base: Addr, len: usize) {
        self.sponge_start(base, Fp::from_u32(len as u32));
        for k in 1..len.div_ceil(RATE).max(1) {
            self.absorb(base + (k * RATE) as Addr);
        }
    }

    /// Asserts that the scalar at `a` is below `2^n` by decomposing it and
    /// requiring bits `n..31` to be zero.
    pub fn assert_bits_zero_from(&mut self, a: Addr, n: usize) {
        assert!(n <= 31);
        let bits = self.prog.decompose(a);
        let v = self.val(a).0[0].to_canonical();
        for k in 0..8 {
            self.set(bits + k as Addr, Fp4(core::array::from_fn(|c| Fp::new((v >> (4 * k + c)) & 1))));
        }
        let mut i = n;
        while i < 31 {
            if i.is_multiple_of(4) && i + 4 <= 31 {
                // A whole word of four bits at once.
                self.prog.assert_eq(bits + (i / 4) as Addr, A_ZERO);
                i += 4;
            } else {
                let b = self.bit(bits, i);
                self.prog.assert_eq(b, A_ZERO);
                i += 1;
            }
        }
    }

    /// Writes the current digest to eight fresh words.
    pub fn squeeze_digest(&mut self) -> Addr {
        self.squeeze()
    }

    /// Emits `AssertPublic`: the current digest is the program's output.
    pub fn assert_public(&mut self) {
        self.prog.assert_public();
    }

    // ---- hashing ----

    fn sponge_start(&mut self, block: Addr, cap0: Fp) {
        self.prog.sponge_start(block, cap0);
        let mut input = [Fp::ZERO; WIDTH];
        for (i, x) in input.iter_mut().enumerate().take(RATE) {
            *x = self.val(block + i as Addr).0[0];
        }
        input[RATE] = cap0;
        let st = permute(input);
        self.digest.copy_from_slice(&st[..DIGEST]);
        self.sponge = Some(st);
    }

    fn absorb(&mut self, block: Addr) {
        self.prog.absorb(block);
        let mut st = self.sponge.expect("absorb without a sponge");
        for (i, x) in st.iter_mut().enumerate().take(RATE) {
            *x = x.add(&self.val(block + i as Addr).0[0]);
        }
        let st = permute(st);
        self.digest.copy_from_slice(&st[..DIGEST]);
        self.sponge = Some(st);
    }

    /// One Merkle level: compresses the digest register with the sibling
    /// `sib` (witness to the instruction), on the side given by bit `level`
    /// of `bits`.
    fn compress_in_step(&mut self, sib: &Digest, bits: Addr, level: usize) {
        self.prog.compress_in(bits + (level / 4) as Addr, (level % 4) as u8);
        self.inputs.extend(sib.iter().map(|x| Fp4::from_base(*x)));
        let right = self.val(bits + (level / 4) as Addr).0[level % 4] == Fp::ONE;
        let d = self.digest;
        self.digest = if right { compress(sib, &d) } else { compress(&d, sib) };
        self.sponge = None;
    }

    fn squeeze(&mut self) -> Addr {
        let out = self.prog.squeeze();
        for i in 0..DIGEST {
            self.set(out + i as Addr, Fp4::from_base(self.digest[i]));
        }
        out
    }

    /// Hashes `len` scalars at `row` (padded block) as `poseidon2::hash`,
    /// walks the Merkle path with directions from `bits`, and returns the
    /// root digest's address.
    fn merkle_root(&mut self, row: Addr, len: usize, path: &[Digest], bits: Addr) -> Addr {
        self.sponge_start(row, Fp::from_u32(len as u32));
        let blocks = len.div_ceil(RATE).max(1);
        for k in 1..blocks {
            self.absorb(row + (k * RATE) as Addr);
        }
        for (level, sib) in path.iter().enumerate() {
            self.compress_in_step(sib, bits, level);
        }
        self.squeeze()
    }

    fn assert_digest(&mut self, a: Addr, b: Addr) {
        for i in 0..DIGEST as Addr {
            self.prog.assert_eq(a + i, b + i);
        }
    }

    // ---- transcript ----

    fn transcript(&self) -> Transcript {
        Transcript { pending: Vec::new(), started: false, squeezed: None, pos: 0, state: None }
    }

    /// Permutes the transcript with `words` (at most eight) added to the rate.
    fn transcript_permute(&mut self, t: &mut Transcript, words: &[Addr]) {
        let block = self.block_of(words);
        self.transcript_absorb(t, block);
    }

    /// Absorbs an existing block of eight words into the transcript.
    fn transcript_absorb(&mut self, t: &mut Transcript, block: Addr) {
        if t.started {
            assert_eq!(self.sponge, t.state, "transcript sponge was clobbered by other hashing");
            self.absorb(block);
        } else {
            self.sponge_start(block, Fp::ZERO);
            t.started = true;
        }
        t.state = self.sponge;
    }

    fn flush(&mut self, t: &mut Transcript) {
        let words = std::mem::take(&mut t.pending);
        self.transcript_permute(t, &words);
    }

    fn observe(&mut self, t: &mut Transcript, scalar: Addr) {
        t.squeezed = None;
        t.pending.push(scalar);
        if t.pending.len() == RATE {
            self.flush(t);
        }
    }

    fn observe_word(&mut self, t: &mut Transcript, word: Addr) {
        for c in 0..DEGREE as u8 {
            let s = self.component(word, c);
            self.observe(t, s);
        }
    }

    fn observe_block(&mut self, t: &mut Transcript, base: Addr, n: usize) {
        let mut i = 0;
        // Whole blocks absorb in place when nothing is pending.
        while t.pending.is_empty() && n - i >= RATE {
            t.squeezed = None;
            self.transcript_absorb(t, base + i as Addr);
            i += RATE;
        }
        for k in i..n {
            self.observe(t, base + k as Addr);
        }
    }

    fn sample(&mut self, t: &mut Transcript) -> Addr {
        if !t.pending.is_empty() {
            self.flush(t);
            t.squeezed = Some(self.squeeze());
            t.pos = 0;
        } else if t.squeezed.is_none() || t.pos == RATE {
            // Permute with no new input: absorb a zero block.
            self.transcript_permute(t, &[]);
            t.squeezed = Some(self.squeeze());
            t.pos = 0;
        }
        let a = t.squeezed.unwrap() + t.pos as Addr;
        t.pos += 1;
        a
    }

    fn sample_word(&mut self, t: &mut Transcript) -> Addr {
        let s = [self.sample(t), self.sample(t), self.sample(t), self.sample(t)];
        self.word_from_scalars(s)
    }

    /// Samples a scalar and decomposes it; returns the bits block.
    fn sample_bits(&mut self, t: &mut Transcript) -> Addr {
        let s = self.sample(t);
        let bits = self.prog.decompose(s);
        let v = self.val(s).0[0].to_canonical();
        for k in 0..8 {
            self.set(bits + k as Addr, Fp4(core::array::from_fn(|c| Fp::new((v >> (4 * k + c)) & 1))));
        }
        bits
    }

    /// Observes the proof-of-work witness and checks that the next sample's
    /// low `pow_bits` bits are zero, as [`crate::fri::check_pow`].
    fn check_pow(&mut self, t: &mut Transcript, witness: Fp, pow_bits: usize) {
        assert!(pow_bits <= 27);
        let w = self.input(Fp4::from_base(witness));
        self.observe(t, w);
        let bits = self.sample_bits(t);
        // Whole words of four bits, then single bits.
        for k in 0..pow_bits / 4 {
            self.assert_eq(bits + k as Addr, A_ZERO);
        }
        for i in pow_bits / 4 * 4..pow_bits {
            let b = self.bit(bits, i);
            self.assert_eq(b, A_ZERO);
        }
    }

    fn bit(&mut self, bits: Addr, i: usize) -> Addr {
        self.component(bits + (i / 4) as Addr, (i % 4) as u8)
    }

    /// `base * prod_i (1 + bit_(start + i) (c_i - 1))` for constants `c_i`.
    fn power_from_bits(&mut self, base: Fp, bits: Addr, start: usize, cs: &[Fp]) -> Addr {
        let base = self.scalar(base);
        self.power_from_bits_at(base, bits, start, cs)
    }

    /// As [`Self::power_from_bits`] with `base` a word in memory.
    fn power_from_bits_at(&mut self, base: Addr, bits: Addr, start: usize, cs: &[Fp]) -> Addr {
        let mut acc = base;
        for (i, ci) in cs.iter().enumerate() {
            let b = self.bit(bits, start + i);
            let k = self.scalar(*ci - Fp::ONE);
            let t = self.muladd(b, k, A_ONE);
            acc = self.mul(acc, t);
        }
        acc
    }
}

/// Builds the verifier program for a proof of `air` with `public` values,
/// along with the witness for this particular proof. The output digest is
/// the hash of the public values. For AIRs with preprocessed columns or
/// proofs over several tables use [`Compiler::verify_stark`] directly.
pub fn compile_verifier<A: Air>(air: &A, config: &StarkConfig, public: &[Fp], proof: &Proof) -> Compiler {
    let mut c = Compiler::new();
    let pub_base = c.scalar_inputs(public);
    c.verify_stark(&[(air, None)], config, &[], pub_base, public.len(), proof);
    c.hash_scalars(pub_base, public.len());
    c.assert_public();
    c
}

/// Shape of one table of a proof, from its AIR.
struct TableShape {
    log_n: usize,
    w: usize,
    aux_w: usize,
    pre_w: usize,
    chunks: usize,
    log_q: usize,
    num_constraints: usize,
    num_terms: usize,
    group: usize,
}

impl Compiler {
    /// Verifies `proof` inside the program. `tables` lists the AIR of each
    /// table, tallest first, with the address of the digest of its
    /// preprocessed table when it has one. The inner public values are the
    /// `num_public` scalars at `pub_base` (zero padded to a multiple of
    /// eight); `prefix` holds scalars the transcript observed before
    /// anything else (domain separators).
    pub fn verify_stark(
        &mut self,
        tables: &[(&dyn DynAir, Option<Addr>)],
        config: &StarkConfig,
        prefix: &[Fp],
        pub_base: Addr,
        num_public: usize,
        proof: &Proof,
    ) {
        let public: Vec<Fp> = (0..num_public).map(|i| self.val(pub_base + i as Addr).0[0]).collect();
        let public = &public[..];
        let c = self;
        assert_eq!(proof.tables.len(), tables.len(), "proof has the wrong number of tables");
        assert_eq!(proof.openings.len(), config.num_queries);
        let log_blowup = config.log_blowup;
        let shapes: Vec<TableShape> = tables
            .iter()
            .zip(&proof.tables)
            .map(|((air, pre_root), tp)| {
                let pre_w = air.air_preprocessed_width();
                assert_eq!(
                    pre_root.is_some(),
                    pre_w > 0,
                    "preprocessed root must be given exactly when the air has one"
                );
                let log_q = log_quotient_degree(air.air_degree());
                let (num_constraints, num_terms) = shape(*air, public);
                let group = air.air_lookup_group();
                let s = TableShape {
                    log_n: tp.log_n,
                    w: air.air_width(),
                    aux_w: lookup_columns(num_terms, group) * DEGREE,
                    pre_w,
                    chunks: 1 << log_q,
                    log_q,
                    num_constraints,
                    num_terms,
                    group,
                };
                assert_eq!(tp.trace_at_zeta.len(), s.w);
                assert_eq!(tp.aux_at_zeta.len(), s.aux_w);
                assert_eq!(tp.pre_at_zeta.len(), s.pre_w);
                assert_eq!(tp.quotient_at_zeta_q.len(), s.chunks);
                s
            })
            .collect();
        let log_ns: Vec<usize> = shapes.iter().map(|s| s.log_n).collect();
        assert!(log_ns.windows(2).all(|w| w[0] >= w[1]), "tables must be ordered by height");
        let log_big_n = log_ns[0] + log_blowup;
        let shift = MULTIPLICATIVE_GENERATOR;

        // ---- inputs: commitments and lookup totals ----
        let trace_roots: Vec<Addr> = proof.tables.iter().map(|tp| c.scalar_inputs(&tp.trace_root)).collect();
        let aux: Vec<Option<(Addr, Addr)>> =
            proof.tables.iter().map(|tp| tp.aux_root.map(|r| (c.scalar_inputs(&r), c.input(tp.lookup_sum)))).collect();
        let quotient_roots: Vec<Addr> = proof.tables.iter().map(|tp| c.scalar_inputs(&tp.quotient_root)).collect();

        // ---- transcript up to zeta ----
        let mut t = c.transcript();
        for p in prefix {
            let p = c.scalar(*p);
            c.observe(&mut t, p);
        }
        for log_n in &log_ns {
            let s = c.scalar(Fp::from_u32(*log_n as u32));
            c.observe(&mut t, s);
        }
        let npub_s = c.scalar(Fp::from_u32(public.len() as u32));
        c.observe(&mut t, npub_s);
        c.observe_block(&mut t, pub_base, public.len());
        for (_, pre_root) in tables {
            if let Some(root) = pre_root {
                c.observe_block(&mut t, *root, DIGEST);
            }
        }
        for root in &trace_roots {
            c.observe_block(&mut t, *root, DIGEST);
        }
        let lookup = if aux.iter().any(Option::is_some) {
            let gamma = c.sample_word(&mut t);
            let delta = c.sample_word(&mut t);
            let mut total = A_ZERO;
            for (root, sum) in aux.iter().flatten() {
                c.observe_block(&mut t, *root, DIGEST);
                c.observe_word(&mut t, *sum);
                total = c.add(total, *sum);
            }
            // The tables' lookup totals cancel.
            c.assert_eq(total, A_ZERO);
            Some((gamma, delta))
        } else {
            None
        };
        let alpha = c.sample_word(&mut t);
        for root in &quotient_roots {
            c.observe_block(&mut t, *root, DIGEST);
        }
        let zeta = c.sample_word(&mut t);

        // ---- openings ----
        // Loaded as scalars eight per row, observed in place, and packed
        // into words: per table, the seven groups of `TableProof::opened`.
        let scalars: Vec<Fp> = proof
            .tables
            .iter()
            .flat_map(|tp| tp.opened().into_iter().flat_map(|g| g.iter().flat_map(|v| v.0)))
            .collect();
        let base = c.scalar_inputs(&scalars);
        c.observe_block(&mut t, base, scalars.len());
        let mut next = 0usize;
        let mut opened: Vec<Vec<Vec<Addr>>> = Vec::with_capacity(tables.len());
        for tp in &proof.tables {
            let mut groups = Vec::with_capacity(7);
            for g in tp.opened() {
                let mut words = Vec::with_capacity(g.len());
                for _ in 0..g.len() {
                    let at = base + (next * DEGREE) as Addr;
                    next += 1;
                    words.push(c.word_from_scalars(core::array::from_fn(|k| at + k as Addr)));
                }
                groups.push(words);
            }
            opened.push(groups);
        }
        let beta = c.sample_word(&mut t);

        // ---- constraint identity of every table at zeta ----
        // `zeta_pows[k] = zeta^(2^k)`.
        let max_log = log_ns[0].max(shapes.iter().map(|s| s.log_q).max().unwrap());
        let mut zeta_pows = vec![zeta];
        for k in 0..max_log {
            let z = zeta_pows[k];
            zeta_pows.push(c.mul(z, z));
        }
        let d1 = c.sub(zeta, A_ONE);
        let d1_inv = c.inverse(d1);
        let mut zeta_nexts = Vec::with_capacity(tables.len());
        for (i, ((air, _), s)) in tables.iter().zip(&shapes).enumerate() {
            let [trace_z, trace_zn, aux_z, aux_zn, pre_z, pre_zn, quot_zq] = &opened[i][..] else { unreachable!() };
            let g = root_of_unity(s.log_n);
            let g_s = c.scalar(g);
            let g_inv_s = c.scalar(g.inverse().unwrap());
            zeta_nexts.push(c.mul(zeta, g_s));
            let z_h = c.sub(zeta_pows[s.log_n], A_ONE);
            let first = c.mul(z_h, d1_inv);
            let d2 = c.sub(zeta, g_inv_s);
            let d2_inv = c.inverse(d2);
            let last = c.mul(z_h, d2_inv);
            let transition = d2;

            // Compile the inner constraints over Expr.
            let local: Vec<Expr> = trace_z.iter().map(|a| Expr(*a)).collect();
            let next: Vec<Expr> = trace_zn.iter().map(|a| Expr(*a)).collect();
            let pre_l: Vec<Expr> = pre_z.iter().map(|a| Expr(*a)).collect();
            let pre_n: Vec<Expr> = pre_zn.iter().map(|a| Expr(*a)).collect();
            let pub_exprs: Vec<Expr> = (0..public.len()).map(|i| Expr(pub_base + i as Addr)).collect();
            let owned = std::mem::replace(c, Compiler::shell());
            CTX.with(|cell| *cell.borrow_mut() = Some(owned));
            let (constraints, terms) = {
                let mut b = Builder::new(
                    &local,
                    &next,
                    (&pre_l, &pre_n),
                    &pub_exprs,
                    (Expr(first), Expr(last), Expr(transition)),
                );
                air.eval_expr(&mut b);
                b.into_parts()
            };
            *c = CTX.with(|cell| cell.borrow_mut().take().unwrap());
            assert_eq!(constraints.len(), s.num_constraints);
            assert_eq!(terms.len(), s.num_terms);

            // Lookup constraints over addresses.
            let mut all: Vec<Addr> = constraints.iter().map(|e| e.0).collect();
            if s.num_terms > 0 {
                let (gamma, delta) = lookup.unwrap();
                let total = aux[i].unwrap().1;
                let aux_l = reconstruct_ext(c, aux_z);
                let aux_n = reconstruct_ext(c, aux_zn);
                let sel = (first, last, transition);
                let lk = LookupAddrs { gamma, delta, total, group: s.group };
                all.extend(lookup_constraints_addr(c, lk, &terms, &aux_l, &aux_n, sel));
            }
            assert_eq!(all.len(), s.num_constraints + num_lookup_constraints(s.num_terms, s.group));
            let mut acc = A_ZERO;
            let mut alpha_pow = A_ONE;
            for (k, cst) in all.iter().enumerate() {
                acc = c.muladd(*cst, alpha_pow, acc);
                if k + 1 < all.len() {
                    alpha_pow = c.mul(alpha_pow, alpha);
                }
            }
            let mut q_zeta = A_ZERO;
            let mut zeta_pow = A_ONE;
            for (j, q) in quot_zq.iter().enumerate() {
                q_zeta = c.muladd(*q, zeta_pow, q_zeta);
                if j + 1 < quot_zq.len() {
                    zeta_pow = c.mul(zeta_pow, zeta);
                }
            }
            let lhs = c.mul(q_zeta, z_h);
            c.assert_eq(lhs, acc);
        }

        // ---- FRI commitments ----
        let fri = &proof.fri;
        let mut log_sizes: Vec<usize> = log_ns.iter().map(|l| l + log_blowup).collect();
        log_sizes.dedup();
        let arities = round_log_arities(&config.fri(), &log_sizes);
        let inject = injection_rounds(&config.fri(), &log_sizes);
        let rounds = arities.len();
        assert_eq!(fri.commitments.len(), rounds);
        let mut fri_roots = Vec::with_capacity(rounds);
        let mut fri_betas = Vec::with_capacity(rounds);
        for root in &fri.commitments {
            let r = c.scalar_inputs(root);
            c.observe_block(&mut t, r, DIGEST);
            fri_betas.push(c.sample_word(&mut t));
            fri_roots.push(r);
        }
        let final_value = c.input(fri.final_value);
        c.observe_word(&mut t, final_value);
        if config.pow_bits > 0 {
            c.check_pow(&mut t, fri.pow_witness, config.pow_bits);
        }

        // Query indices are sampled before any Merkle hashing: the native
        // verifier observes nothing between queries, and the machine's sponge
        // register is shared with the Merkle work below.
        let query_bits: Vec<Addr> = (0..config.num_queries).map(|_| c.sample_bits(&mut t)).collect();

        // ---- per-proof constants ----
        // `omega_pows[k] = omega^(2^k)` and likewise for the inverse.
        let omega_big = root_of_unity(log_big_n);
        let squarings = |mut p: Fp| -> Vec<Fp> {
            let mut v = Vec::with_capacity(log_big_n);
            for _ in 0..log_big_n {
                v.push(p);
                p = p.square();
            }
            v
        };
        let omega_pows = squarings(omega_big);
        let omega_inv_pows = squarings(omega_big.inverse().unwrap());
        let shift_inv = shift.inverse().unwrap();
        let inv2 = c.scalar(inv_two());
        // Inverse of the primitive fourth root of unity, for four-way folds.
        let iota_inv = c.scalar(omega_inv_pows[log_big_n - 2]);
        let fri_betas_sq: Vec<Addr> = fri_betas.iter().map(|&b| c.mul(b, b)).collect();
        // Powers of beta in one block of consecutive words, so dot products
        // can read them eight at a time (see `stark::Deep` for the layout,
        // the same for every table up to the table's scale).
        let layout = |s: &TableShape| 2 * s.w + 2 * s.aux_w + 2 * s.pre_w + s.chunks;
        let beta_count = shapes.iter().map(layout).max().unwrap();
        let beta_base = c.powers_block(beta, beta_count + RATE);
        let bp = |k: usize| beta_base + k as Addr;
        let dot = |c: &mut Compiler, from: usize, vals: &[Addr]| -> Addr {
            let mut acc = A_ZERO;
            for (k, v) in vals.iter().enumerate() {
                acc = c.muladd(*v, bp(from + k), acc);
            }
            acc
        };
        struct DeepConsts {
            c_tz: Addr,
            c_tzn: Addr,
            c_az: Addr,
            c_azn: Addr,
            c_pz: Addr,
            c_pzn: Addr,
            c_q: Addr,
            /// `beta^offset`, absent for the first table.
            scale: Option<Addr>,
        }
        let mut offset = 0usize;
        let mut deep = Vec::with_capacity(tables.len());
        for (i, s) in shapes.iter().enumerate() {
            let [trace_z, trace_zn, aux_z, aux_zn, pre_z, pre_zn, quot_zq] = &opened[i][..] else { unreachable!() };
            let (off_a, off_p, off_q) = (2 * s.w, 2 * s.w + 2 * s.aux_w, 2 * s.w + 2 * s.aux_w + 2 * s.pre_w);
            let scale = (offset > 0).then(|| c.pow_const(beta, offset as u64));
            offset += layout(s);
            deep.push(DeepConsts {
                c_tz: dot(c, 0, trace_z),
                c_tzn: dot(c, s.w, trace_zn),
                c_az: dot(c, off_a, aux_z),
                c_azn: dot(c, off_a + s.aux_w, aux_zn),
                c_pz: dot(c, off_p, pre_z),
                c_pzn: dot(c, off_p + s.pre_w, pre_zn),
                c_q: dot(c, off_q, quot_zq),
                scale,
            });
        }

        for (q, steps) in fri.queries.iter().enumerate() {
            assert_eq!(steps.len(), rounds);
            let bits = query_bits[q];
            // In each round the queried point is the leaf's base point
            // `x_r` times `w^pos`, with `pos` the index bits just above the
            // leaf index. Round 0 gets `1/x_0` from the low index bits;
            // later rounds raise the previous base point to the previous
            // arity, which gives the queried point, and divide out `w^pos`.
            let log_leaves0 = log_big_n - arities[0];
            let mut x_inv = c.power_from_bits(shift_inv, bits, 0, &omega_inv_pows[..log_leaves0]);
            let x_abs = c.inverse(x_inv);
            let x = c.power_from_bits_at(x_abs, bits, log_leaves0, &omega_pows[log_leaves0..]);

            // DEEP values from the opened rows, summed per domain size: each
            // row is loaded eight scalars at a time while accumulating its
            // beta-weighted sum. A table of a smaller domain is opened at
            // the index's low bits, at the point `x^(2^k)`.
            let mut values: Vec<Addr> = Vec::with_capacity(log_sizes.len());
            let mut last_size = None;
            let mut x_t = x;
            let mut log_x = log_big_n;
            for (i, s) in shapes.iter().enumerate() {
                let opening: &QueryOpening = &proof.openings[q][i];
                let log_m = s.log_n + log_blowup;
                while log_x > log_m {
                    x_t = c.mul(x_t, x_t);
                    log_x -= 1;
                }
                let (off_a, off_p, off_q) = (2 * s.w, 2 * s.w + 2 * s.aux_w, 2 * s.w + 2 * s.aux_w + 2 * s.pre_w);
                let (trace_row, s_t) = c.row_inputs_dot(&opening.trace_row, bp(0));
                let root = c.merkle_root(trace_row, s.w, &opening.trace_path, bits);
                c.assert_digest(root, trace_roots[i]);
                let s_a = if s.aux_w > 0 {
                    let (row, sum) = c.row_inputs_dot(&opening.aux_row, bp(off_a));
                    let root = c.merkle_root(row, s.aux_w, &opening.aux_path, bits);
                    c.assert_digest(root, aux[i].unwrap().0);
                    sum
                } else {
                    A_ZERO
                };
                let s_p = if s.pre_w > 0 {
                    let (row, sum) = c.row_inputs_dot(&opening.pre_row, bp(off_p));
                    let root = c.merkle_root(row, s.pre_w, &opening.pre_path, bits);
                    c.assert_digest(root, tables[i].1.unwrap());
                    sum
                } else {
                    A_ZERO
                };
                let quot_row = c.scalar_inputs(&opening.quotient_row);
                let root = c.merkle_root(quot_row, s.chunks * DEGREE, &opening.quotient_path, bits);
                c.assert_digest(root, quotient_roots[i]);
                let mut s_q = A_ZERO;
                for j in 0..s.chunks {
                    let sc: [Addr; DEGREE] = core::array::from_fn(|k| quot_row + (j * DEGREE + k) as Addr);
                    let word = c.word_from_scalars(sc);
                    s_q = c.muladd(word, bp(off_q + j), s_q);
                }

                let d = &deep[i];
                let dz = c.sub(x_t, zeta);
                let inv_z = c.inverse(dz);
                let dzn = c.sub(x_t, zeta_nexts[i]);
                let inv_zn = c.inverse(dzn);
                let dzq = c.sub(x_t, zeta_pows[s.log_q]);
                let inv_zq = c.inverse(dzq);
                // value = (s_t - c_tz + s_a - c_az + s_p - c_pz) / (x - zeta)
                //       + (beta^w s_t - c_tzn + beta^aux_w s_a - c_azn + beta^pre_w s_p - c_pzn) / (x - g zeta)
                //       + (s_q - c_q) / (x - zeta_q)
                let at_z = c.sub(s_t, d.c_tz);
                let at_z = c.add(at_z, s_a);
                let at_z = c.sub(at_z, d.c_az);
                let at_z = c.add(at_z, s_p);
                let at_z = c.sub(at_z, d.c_pz);
                let at_zn = c.muladd(bp(s.w), s_t, A_ZERO);
                let at_zn = c.sub(at_zn, d.c_tzn);
                let at_zn = c.muladd(bp(s.aux_w), s_a, at_zn);
                let at_zn = c.sub(at_zn, d.c_azn);
                let at_zn = c.muladd(bp(s.pre_w), s_p, at_zn);
                let at_zn = c.sub(at_zn, d.c_pzn);
                let at_q = c.sub(s_q, d.c_q);
                let value = c.mul(at_z, inv_z);
                let value = c.muladd(at_zn, inv_zn, value);
                let value = c.muladd(at_q, inv_zq, value);
                let value = match d.scale {
                    Some(k) => c.mul(value, k),
                    None => value,
                };
                if last_size == Some(log_m) {
                    let prev = values.pop().unwrap();
                    values.push(c.add(prev, value));
                } else {
                    values.push(value);
                    last_size = Some(log_m);
                }
            }

            let mut expected = values[0];
            let mut log_m = log_big_n;
            for (r, step) in steps.iter().enumerate() {
                let la = arities[r];
                let log_leaves = log_m - la;
                if let Some(g) = inject.iter().position(|&ir| ir == r) {
                    expected = c.add(expected, values[g + 1]);
                }
                if r > 0 {
                    // Queried point inverse times `w^pos`, where `w` has
                    // order `2^la` and its `2^j`-th power is
                    // `omega^(2^(log_big_n - la + j))`.
                    x_inv = c.power_from_bits_at(x_inv, bits, log_leaves, &omega_pows[log_big_n - la..]);
                }
                // Merkle opening of the leaf, loaded as its scalars.
                assert_eq!(step.values.len(), 1 << la);
                let row = c.scalar_inputs(&leaf_row(&step.values));
                let v: Vec<Addr> = (0..1usize << la)
                    .map(|j| c.word_from_scalars(core::array::from_fn(|k| row + (j * DEGREE + k) as Addr)))
                    .collect();
                assert_eq!(step.path.len(), log_leaves);
                let root = c.merkle_root(row, DEGREE << la, &step.path, bits);
                c.assert_digest(root, fri_roots[r]);
                // The value at the queried position.
                let b0 = c.bit(bits, log_leaves);
                let pick = |c: &mut Compiler, lo: Addr, hi: Addr, b: Addr| {
                    let diff = c.sub(hi, lo);
                    c.muladd(b, diff, lo)
                };
                let at_pos = if la == 1 {
                    pick(c, v[0], v[1], b0)
                } else {
                    let b1 = c.bit(bits, log_leaves + 1);
                    let s0 = pick(c, v[0], v[1], b0);
                    let s1 = pick(c, v[2], v[3], b0);
                    pick(c, s0, s1, b1)
                };
                c.assert_eq(at_pos, expected);
                // Fold, and the next round's queried point inverse.
                let fold2 = |c: &mut Compiler, a: Addr, b: Addr, xi: Addr, beta: Addr| {
                    let sum = c.add(a, b);
                    let even = c.mul(sum, inv2);
                    let dsub = c.sub(a, b);
                    let half_d = c.mul(dsub, inv2);
                    let odd = c.mul(half_d, xi);
                    c.muladd(beta, odd, even)
                };
                if la == 1 {
                    expected = fold2(c, v[0], v[1], x_inv, fri_betas[r]);
                    x_inv = c.mul(x_inv, x_inv);
                } else {
                    let g0 = fold2(c, v[0], v[2], x_inv, fri_betas[r]);
                    let xi1 = c.mul(x_inv, iota_inv);
                    let g1 = fold2(c, v[1], v[3], xi1, fri_betas[r]);
                    let x_sq = c.mul(x_inv, x_inv);
                    expected = fold2(c, g0, g1, x_sq, fri_betas_sq[r]);
                    x_inv = c.mul(x_sq, x_sq);
                }
                log_m = log_leaves;
            }
            c.assert_eq(expected, final_value);
        }
    }

    /// `base^e` by square and multiply.
    fn pow_const(&mut self, base: Addr, e: u64) -> Addr {
        let mut acc = A_ONE;
        for i in (0..u64::BITS - e.leading_zeros()).rev() {
            acc = self.mul(acc, acc);
            if (e >> i) & 1 == 1 {
                acc = self.mul(acc, base);
            }
        }
        acc
    }
    /// `base^0 .. base^(count-1)` at `count` consecutive fresh addresses,
    /// zero padded to a multiple of eight.
    fn powers_block(&mut self, base: Addr, count: usize) -> Addr {
        let padded = count.div_ceil(RATE) * RATE;
        let block = self.prog.alloc(padded as u32);
        self.prog.muladd_to(A_ONE, A_ONE, A_ZERO, block);
        self.set(block, Fp4::ONE);
        for k in 1..count {
            let prev = block + (k - 1) as Addr;
            self.prog.muladd_to(prev, base, A_ZERO, block + k as Addr);
            let v = self.val(prev) * self.val(base);
            self.set(block + k as Addr, v);
        }
        for k in count..padded {
            self.prog.muladd_to(A_ZERO, A_ONE, A_ZERO, block + k as Addr);
            self.set(block + k as Addr, Fp4::ZERO);
        }
        block
    }

    /// Loads `values` as scalar inputs at consecutive addresses (zero
    /// padded to blocks of eight, pads asserted zero) while accumulating
    /// `sum_k values[k] * mem[pows + k]`. Returns the base address and the
    /// accumulator.
    fn row_inputs_dot(&mut self, values: &[Fp], pows: Addr) -> (Addr, Addr) {
        let blocks = values.len().div_ceil(RATE).max(1);
        let base = self.prog.alloc((blocks * RATE) as u32);
        let mut acc = A_ZERO;
        for b in 0..blocks {
            let out = base + (b * RATE) as Addr;
            let pw = pows + (b * RATE) as Addr;
            let acc_out = self.prog.input_dot_at(out, pw, acc);
            let mut sum = self.val(acc);
            for k in 0..RATE {
                let v = values.get(b * RATE + k).copied().unwrap_or(Fp::ZERO);
                let v4 = Fp4::from_base(v);
                self.inputs.push(v4);
                self.set(out + k as Addr, v4);
                sum += v4 * self.val(pw + k as Addr);
            }
            self.set(acc_out, sum);
            acc = acc_out;
        }
        for k in values.len()..blocks * RATE {
            self.prog.assert_eq(base + k as Addr, A_ZERO);
        }
        (base, acc)
    }
}

/// Extension values from base-column openings: `o0 + o1 X + o2 X^2 + o3 X^3`.
fn reconstruct_ext(c: &mut Compiler, opened: &[Addr]) -> Vec<Addr> {
    opened
        .chunks_exact(DEGREE)
        .map(|o| {
            let mut acc = o[DEGREE - 1];
            for k in (0..DEGREE - 1).rev() {
                acc = c.muladd(acc, A_X, o[k]);
            }
            acc
        })
        .collect()
}

/// Lookup challenges, total and group size of a table, as addresses.
#[derive(Clone, Copy)]
struct LookupAddrs {
    gamma: Addr,
    delta: Addr,
    total: Addr,
    group: usize,
}

/// Lookup constraints over addresses, mirroring `stark::combine`.
fn lookup_constraints_addr(
    c: &mut Compiler,
    lk: LookupAddrs,
    terms: &[LookupTerm<Expr>],
    aux_l: &[Addr],
    aux_n: &[Addr],
    sel: (Addr, Addr, Addr),
) -> Vec<Addr> {
    let groups = terms.len().div_ceil(lk.group);
    let mut out = Vec::with_capacity(groups + 3);
    // delta^1 .. delta^max_values, shared by every denominator.
    let longest = terms.iter().map(|t| t.values.len()).max().unwrap_or(0);
    let mut delta_pows = Vec::with_capacity(longest);
    for i in 0..longest {
        delta_pows.push(if i == 0 { lk.delta } else { c.mul(delta_pows[i - 1], lk.delta) });
    }
    let mut contrib = A_ZERO;
    for (j, members) in terms.chunks(lk.group).enumerate() {
        let (mut num, mut den) = (A_ZERO, A_ONE);
        for (k, term) in members.iter().enumerate() {
            let mut d = lk.gamma;
            for (v, pow) in term.values.iter().zip(&delta_pows) {
                d = c.muladd(v.0, *pow, d);
            }
            let m = term.multiplicity.0;
            // num = num * d +- m * den, den = den * d; the first member
            // starts from num = 0, den = 1.
            let m_den = if k == 0 { m } else { c.mul(m, den) };
            let scaled = if k == 0 { A_ZERO } else { c.mul(num, d) };
            num = if term.send { c.add(scaled, m_den) } else { c.sub(scaled, m_den) };
            den = if k == 0 { d } else { c.mul(den, d) };
        }
        let h = aux_l[j];
        let hd = c.mul(h, den);
        out.push(c.sub(hd, num));
        contrib = c.add(contrib, h);
    }
    let s = aux_l[groups];
    let s_next = aux_n[groups];
    let d = c.sub(s_next, s);
    let d = c.sub(d, contrib);
    out.push(c.mul(sel.2, d));
    out.push(c.mul(sel.0, s));
    let e = c.add(s, contrib);
    let e = c.sub(e, lk.total);
    out.push(c.mul(sel.1, e));
    out
}

/// A zero-filled proof of the shape `prove_tables` produces for tables
/// with the given AIRs and heights (tallest first), used to compile the
/// verifier program without a real proof.
pub fn dummy_proof(tables: &[(&dyn DynAir, usize)], config: &StarkConfig, num_public: usize) -> Proof {
    let z = [Fp::ZERO; DIGEST];
    let log_blowup = config.log_blowup;
    let shapes: Vec<(usize, usize, usize, usize, usize)> = tables
        .iter()
        .map(|(air, log_n)| {
            let (_, num_terms) = shape(*air, &vec![Fp::ZERO; num_public]);
            let aux_w = lookup_columns(num_terms, air.air_lookup_group()) * DEGREE;
            let chunks = 1usize << log_quotient_degree(air.air_degree());
            (*log_n, air.air_width(), aux_w, air.air_preprocessed_width(), chunks)
        })
        .collect();
    let parts = shapes
        .iter()
        .map(|&(log_n, w, aux_w, pre_w, chunks)| TableProof {
            log_n,
            trace_root: z,
            aux_root: (aux_w > 0).then_some(z),
            lookup_sum: Fp4::ZERO,
            quotient_root: z,
            trace_at_zeta: vec![Fp4::ZERO; w],
            trace_at_zeta_next: vec![Fp4::ZERO; w],
            aux_at_zeta: vec![Fp4::ZERO; aux_w],
            aux_at_zeta_next: vec![Fp4::ZERO; aux_w],
            pre_at_zeta: vec![Fp4::ZERO; pre_w],
            pre_at_zeta_next: vec![Fp4::ZERO; pre_w],
            quotient_at_zeta_q: vec![Fp4::ZERO; chunks],
        })
        .collect();
    let opening: Vec<QueryOpening> = shapes
        .iter()
        .map(|&(log_n, w, aux_w, pre_w, chunks)| {
            let log_m = log_n + log_blowup;
            QueryOpening {
                trace_row: vec![Fp::ZERO; w],
                trace_path: vec![z; log_m],
                aux_row: vec![Fp::ZERO; aux_w],
                aux_path: if aux_w > 0 { vec![z; log_m] } else { vec![] },
                pre_row: vec![Fp::ZERO; pre_w],
                pre_path: if pre_w > 0 { vec![z; log_m] } else { vec![] },
                quotient_row: vec![Fp::ZERO; chunks * DEGREE],
                quotient_path: vec![z; log_m],
            }
        })
        .collect();
    let mut log_sizes: Vec<usize> = shapes.iter().map(|s| s.0 + log_blowup).collect();
    log_sizes.dedup();
    let arities = round_log_arities(&config.fri(), &log_sizes);
    let steps: Vec<QueryStep> = arities
        .iter()
        .scan(log_sizes[0], |log_m, &la| {
            *log_m -= la;
            Some(QueryStep { values: vec![Fp4::ZERO; 1 << la], path: vec![z; *log_m] })
        })
        .collect();
    Proof {
        tables: parts,
        fri: FriProof {
            commitments: vec![z; arities.len()],
            final_value: Fp4::ZERO,
            pow_witness: Fp::ZERO,
            queries: vec![steps; config.num_queries],
        },
        openings: vec![opening; config.num_queries],
    }
}

/// Digest the output of a verifier program commits to: the inner public
/// values hashed with `poseidon2::hash`.
pub fn output_digest(public: &[Fp]) -> [Fp; DIGEST] {
    crate::poseidon2::hash(public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::hash_table::HashTableAir;
    use crate::stark::{Trace, check_tables, prove, prove_tables, verify, verify_tables};
    use crate::vm_air::{ExecError, VmAir};

    /// Checks the machine and hash table traces of a verifier program.
    fn check_program(c: &Compiler, public: &[Fp]) {
        let (vm, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).unwrap();
        let vm_public = VmAir::public_values(&c.prog.digest(1), &output_digest(public));
        let table = c.prog.table();
        assert_eq!(check_tables(&[(&VmAir, &vm, Some(&table)), (&HashTableAir, &hashes, None)], &vm_public), Ok(()));
        println!("verifier trace: {} rows, {} hash rows", vm.height(), hashes.height());
    }

    /// Fibonacci inner AIR (as in the STARK tests).
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
            let out = b.public()[0];
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

    /// Inner AIR with a lookup: column 1 is a permutation of column 0.
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

    const INNER: StarkConfig = StarkConfig { log_blowup: 2, num_queries: 8, pow_bits: 6 };

    fn inner_tr() -> Challenger {
        let mut c = Challenger::new();
        c.observe(Fp::new(0x77));
        c
    }

    fn outer_tr() -> Challenger {
        let mut c = Challenger::new();
        c.observe(Fp::new(0x88));
        c
    }

    #[test]
    fn verifier_program_accepts_fibonacci_proof() {
        let (trace, public) = fib_trace(3);
        let proof = prove(&INNER, &Fibonacci, &trace, &public, &mut inner_tr());
        assert_eq!(verify(&INNER, &Fibonacci, &public, &proof, &mut inner_tr()), Ok(()));
        // Note: the inner transcript here has a prefix (0x77) the compiled
        // verifier does not replay; compile against a proof made with the
        // default transcript instead.
        let proof = prove(&INNER, &Fibonacci, &trace, &public, &mut Challenger::new());
        assert_eq!(verify(&INNER, &Fibonacci, &public, &proof, &mut Challenger::new()), Ok(()));

        let c = compile_verifier(&Fibonacci, &INNER, &public, &proof);
        let exec = VmAir::execute(&c.prog, &c.inputs).expect("verifier program accepts a valid proof");
        assert_eq!(exec.output_digest, Some(output_digest(&public)));
        println!("fibonacci verifier: {} instructions, {} inputs", c.prog.instrs.len(), c.inputs.len());

        // The program digest is independent of the proof's values.
        let dummy = dummy_proof(&[(&Fibonacci, 3)], &INNER, 1);
        let c2 = compile_verifier(&Fibonacci, &INNER, &[Fp::ZERO], &dummy);
        assert_eq!(c2.prog.digest(1), c.prog.digest(1));
        assert_eq!(c2.prog.instrs.len(), c.prog.instrs.len());

        // A corrupted proof is rejected by the program.
        let mut bad = proof.clone();
        bad.tables[0].trace_at_zeta[0] += Fp4::ONE;
        let cb = compile_verifier(&Fibonacci, &INNER, &public, &bad);
        assert!(matches!(VmAir::execute(&cb.prog, &cb.inputs), Err(ExecError::AssertionFailed(_))));
        let mut bad = proof.clone();
        bad.openings[2][0].trace_row[1] += Fp::ONE;
        let cb = compile_verifier(&Fibonacci, &INNER, &public, &bad);
        assert!(matches!(VmAir::execute(&cb.prog, &cb.inputs), Err(ExecError::AssertionFailed(_))));
        let mut bad = proof.clone();
        bad.fri.final_value += Fp4::ONE;
        let cb = compile_verifier(&Fibonacci, &INNER, &public, &bad);
        assert!(matches!(VmAir::execute(&cb.prog, &cb.inputs), Err(ExecError::AssertionFailed(_))));
        // A proof-of-work witness that misses the target.
        let mut bad = proof.clone();
        bad.fri.pow_witness += Fp::ONE;
        if verify(&INNER, &Fibonacci, &public, &bad, &mut Challenger::new()).is_ok() {
            bad.fri.pow_witness += Fp::ONE;
        }
        let cb = compile_verifier(&Fibonacci, &INNER, &public, &bad);
        assert!(matches!(VmAir::execute(&cb.prog, &cb.inputs), Err(ExecError::AssertionFailed(_))));
        // Wrong public value.
        let cb = compile_verifier(&Fibonacci, &INNER, &[public[0] + Fp::ONE], &proof);
        assert!(matches!(VmAir::execute(&cb.prog, &cb.inputs), Err(ExecError::AssertionFailed(_))));

        // The verifier trace satisfies the machine's constraints.
        check_program(&c, &public);
    }

    #[test]
    fn verifier_program_handles_lookups() {
        let a = [5u32, 3, 9, 1, 7, 7, 2, 0];
        let bperm = [7u32, 1, 0, 9, 3, 2, 7, 5];
        let values: Vec<Fp> = a.iter().zip(&bperm).flat_map(|(x, y)| [Fp::new(*x), Fp::new(*y)]).collect();
        let trace = Trace::new(values, 2);
        let proof = prove(&INNER, &PermAir, &trace, &[], &mut Challenger::new());
        assert_eq!(verify(&INNER, &PermAir, &[], &proof, &mut Challenger::new()), Ok(()));
        let c = compile_verifier(&PermAir, &INNER, &[], &proof);
        let exec = VmAir::execute(&c.prog, &c.inputs).expect("accepts");
        assert_eq!(exec.output_digest, Some(output_digest(&[])));
        let mut bad = proof.clone();
        bad.tables[0].aux_at_zeta[1] += Fp4::ONE;
        let cb = compile_verifier(&PermAir, &INNER, &[], &bad);
        assert!(VmAir::execute(&cb.prog, &cb.inputs).is_err());
        check_program(&c, &[]);
    }

    /// Sends its column once per row.
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

    /// Receives `col0` with multiplicity `col1`; `col2` doubles each row.
    struct Receiver;

    impl Air for Receiver {
        fn width(&self) -> usize {
            3
        }
        fn max_constraint_degree(&self) -> usize {
            3
        }
        fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
            let (l, n) = (b.local(), b.next());
            b.lookup(false, l[1], &[l[0]]);
            b.when_first_row(l[2] - F::ONE);
            b.when_transition(n[2] - l[2] - l[2]);
        }
    }

    #[test]
    fn verifier_program_handles_several_tables() {
        use crate::stark::{TableInput, TableSpec};
        let tall = Trace::new((0..32).map(|i| Fp::new(3 + i % 4)).collect(), 1);
        let recv = Trace::new((0..4u32).flat_map(|i| [Fp::new(3 + i), Fp::new(8), Fp::new(1 << i)]).collect(), 3);
        let tables = [
            TableInput { air: &Sender, trace: &tall, pre: None },
            TableInput { air: &Receiver, trace: &recv, pre: None },
        ];
        let proof = prove_tables(&INNER, &tables, &[], &mut Challenger::new());
        let specs = [TableSpec { air: &Sender, pre_root: None }, TableSpec { air: &Receiver, pre_root: None }];
        assert_eq!(verify_tables(&INNER, &specs, &[], &proof, &mut Challenger::new()), Ok(()));

        let compile = |proof: &Proof| {
            let mut c = Compiler::new();
            let pub_base = c.scalar_inputs(&[]);
            c.verify_stark(&[(&Sender, None), (&Receiver, None)], &INNER, &[], pub_base, 0, proof);
            c.hash_scalars(pub_base, 0);
            c.assert_public();
            c
        };
        let c = compile(&proof);
        let exec = VmAir::execute(&c.prog, &c.inputs).expect("accepts");
        assert_eq!(exec.output_digest, Some(output_digest(&[])));
        let dummy = dummy_proof(&[(&Sender, 5), (&Receiver, 2)], &INNER, 0);
        assert_eq!(compile(&dummy).prog.digest(1), c.prog.digest(1));

        let mut bad = proof.clone();
        bad.openings[1][1].trace_row[2] += Fp::ONE;
        let cb = compile(&bad);
        assert!(VmAir::execute(&cb.prog, &cb.inputs).is_err());
        let mut bad = proof.clone();
        bad.tables[1].trace_at_zeta[2] += Fp4::ONE;
        let cb = compile(&bad);
        assert!(VmAir::execute(&cb.prog, &cb.inputs).is_err());
        let mut bad = proof.clone();
        bad.tables[0].lookup_sum += Fp4::ONE;
        let cb = compile(&bad);
        assert!(VmAir::execute(&cb.prog, &cb.inputs).is_err());

        check_program(&c, &[]);
    }

    #[test]
    #[ignore = "proves a proof of a proof; run with --release"]
    fn recursive_proof_roundtrip() {
        let (trace, public) = fib_trace(3);
        let proof = prove(&INNER, &Fibonacci, &trace, &public, &mut Challenger::new());
        let c = compile_verifier(&Fibonacci, &INNER, &public, &proof);
        let (vm_trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).unwrap();
        let outer = StarkConfig { log_blowup: 2, num_queries: 20, pow_bits: 0 };
        let pre = c.prog.preprocess(outer.log_blowup);
        let vm_public = VmAir::public_values(&pre.root(), &output_digest(&public));
        let t = std::time::Instant::now();
        let tables = VmAir::tables(&vm_trace, &hashes, &pre);
        let outer_proof = prove_tables(&outer, &tables, &vm_public, &mut outer_tr());
        println!(
            "outer proof over {} rows and {} hash rows: {:?}, {} bytes",
            vm_trace.height(),
            hashes.height(),
            t.elapsed(),
            outer_proof.to_bytes().len()
        );
        let root = pre.root();
        assert_eq!(verify_tables(&outer, &VmAir::specs(&root), &vm_public, &outer_proof, &mut outer_tr()), Ok(()));
        let mut bad = vm_public.clone();
        bad[0] += Fp::ONE;
        assert!(verify_tables(&outer, &VmAir::specs(&root), &bad, &outer_proof, &mut outer_tr()).is_err());
    }
}
