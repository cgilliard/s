//! A straight-line machine for verifier programs: Fp4 arithmetic, hashing
//! and a write-once memory, as an AIR on the hash machine with lookups.
//!
//! A program is a list of instructions executed one per row in order. Every
//! value lives in a write-once memory of `Fp4` words addressed by small
//! integers: an instruction reads its operands by address and writes its
//! result to a fresh address. Reads and writes are tied together by a LogUp
//! lookup (writes send `(addr, word)` with the number of reads as
//! multiplicity, reads receive), so a value produced on one row can be used
//! on any later row without register plumbing. Blocks of eight consecutive
//! addresses hold sponge blocks, digests and squeezed state.
//!
//! The program itself is a preprocessed table (see
//! [`crate::stark::Preprocessed`]): row `pc` holds the opcode flags and
//! fields of instruction `pc`, padded with `done` rows. Its commitment is
//! the program digest, public value 0..8, which a verifier computes from
//! the program and checks the proof against; the execution rows carry no
//! instruction columns of their own.
//!
//! | instruction      | fields                       | effect                                            |
//! |------------------|------------------------------|---------------------------------------------------|
//! | `Const`          | imm[4], out                  | mem[out] = imm                                    |
//! | `Input`          | out                          | mem[out] = witness                                |
//! | `Input8`         | out                          | mem[out+k] = witness, k < 8                       |
//! | `InputDot`       | out, pows, acc, acc_out      | as `Input8`, and mem[acc_out] = mem[acc] + sum_k mem[out+k] mem[pows+k] |
//! | `MulAdd`         | a, b, d, out                 | mem[out] = mem[a] * mem[b] + mem[d]               |
//! | `AssertEq`       | a, b                         | mem[a] == mem[b]                                  |
//! | `Decompose`      | a, out                       | mem[out+k] = bits 4k..4k+4 of the scalar mem[a]   |
//! | `Select`         | src, comp[4], out            | mem[out] = (mem[src].comp, 0, 0, 0)               |
//! | `SpongeStart`    | data, cap0                   | state = [mem[data..+8] scalars | cap0, 0, ...]    |
//! | `Absorb`         | data                         | add mem[data..+8] into the rate, permute          |
//! | `Compress`       | sib, dir, comp[4]            | Merkle step with sibling block and direction bit  |
//! | `Squeeze`        | out                          | mem[out+k] = (rate[k], 0, 0, 0)                   |
//! | `AssertPublic`   |                              | digest == public value 8..16                      |
//!
//! Scalars are words whose last three components are zero; the hashing
//! instructions enforce that on what they read. Public values: the program
//! digest (8) and the output digest (8).

use crate::ext::{DEGREE, Fp4};
use crate::field::Field;
use crate::hash_machine::{
    COL_ABSORB, COL_ACC, COL_CHAIN, COL_COMPRESS, COL_DATA, COL_DIR, COL_LOAD, COL_PASS, COL_START, HashTraceBuilder,
    NUM_COLS as HM_COLS, eval_hash_machine,
};
use crate::merkle::Digest;
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH, permute};
use crate::poseidon2_air::COL_INPUT;
use crate::stark::{Air, Builder, Preprocessed, Trace};

pub type Addr = u32;

const FIELDS: usize = 6;
const READS: usize = 9;
const WRITES: usize = 9;
const BITS: usize = 31;
const W_EXT: Fp = Fp::new(11);

// ---- preprocessed columns (opcode order) ----
pub const P_CONST: usize = 0;
pub const P_INPUT: usize = 1;
pub const P_INPUT8: usize = 2;
pub const P_DOT: usize = 3;
pub const P_MULADD: usize = 4;
pub const P_ASSERT_EQ: usize = 5;
pub const P_DECOMP: usize = 6;
pub const P_SELECT: usize = 7;
pub const P_SSTART: usize = 8;
pub const P_ABSORB: usize = 9;
pub const P_COMPRESS: usize = 10;
pub const P_SQUEEZE: usize = 11;
pub const P_ASSERT_PUB: usize = 12;
pub const NUM_OPS: usize = 13;
pub const P_DONE: usize = NUM_OPS;
pub const P_F: usize = P_DONE + 1; // [FIELDS]
pub const PRE_WIDTH: usize = P_F + FIELDS;

// ---- main columns ----
pub const C_READ: usize = HM_COLS; // [READS][4]
pub const C_WRITE: usize = C_READ + READS * DEGREE; // [WRITES][4]
pub const C_MULT: usize = C_WRITE + WRITES * DEGREE; // [WRITES]
pub const C_BITS: usize = C_MULT + WRITES; // [BITS]
pub const C_T3: usize = C_BITS + BITS;
/// Running sponge state, so absorbs may be separated by other instructions.
pub const R_SP: usize = C_T3 + 1; // [WIDTH]
pub const NUM_COLS: usize = R_SP + WIDTH;

pub const PUB_PROGRAM: usize = 0;
pub const PUB_OUTPUT: usize = DIGEST;
pub const NUM_PUBLIC: usize = 2 * DIGEST;

fn pow2<F: Field>(k: usize) -> F {
    F::from_u32(1 << k)
}

/// `Fp4` multiplication on components over any field.
pub fn ext_mul<F: Field>(a: &[F; DEGREE], b: &[F; DEGREE]) -> [F; DEGREE] {
    let w: F = W_EXT.into();
    [
        a[0] * b[0] + w * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
        a[0] * b[1] + a[1] * b[0] + w * (a[2] * b[3] + a[3] * b[2]),
        a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w * (a[3] * b[3]),
        a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
    ]
}

// ---------------------------------------------------------------------------
// Instructions and programs
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instr {
    Const { imm: Fp4, out: Addr },
    Input { out: Addr },
    Input8 { out: Addr },
    InputDot { out: Addr, pows: Addr, acc: Addr, acc_out: Addr },
    MulAdd { a: Addr, b: Addr, d: Addr, out: Addr },
    AssertEq { a: Addr, b: Addr },
    Decompose { a: Addr, out: Addr },
    Select { src: Addr, comp: u8, out: Addr },
    SpongeStart { data: Addr, cap0: Fp },
    Absorb { data: Addr },
    Compress { sib: Addr, dir: Addr, comp: u8 },
    Squeeze { out: Addr },
    AssertPublic,
}

impl Instr {
    fn opcode(&self) -> usize {
        match self {
            Instr::Const { .. } => P_CONST,
            Instr::Input { .. } => P_INPUT,
            Instr::Input8 { .. } => P_INPUT8,
            Instr::InputDot { .. } => P_DOT,
            Instr::MulAdd { .. } => P_MULADD,
            Instr::AssertEq { .. } => P_ASSERT_EQ,
            Instr::Decompose { .. } => P_DECOMP,
            Instr::Select { .. } => P_SELECT,
            Instr::SpongeStart { .. } => P_SSTART,
            Instr::Absorb { .. } => P_ABSORB,
            Instr::Compress { .. } => P_COMPRESS,
            Instr::Squeeze { .. } => P_SQUEEZE,
            Instr::AssertPublic => P_ASSERT_PUB,
        }
    }

    /// Witness values this instruction consumes.
    fn num_inputs(&self) -> usize {
        match self {
            Instr::Input { .. } => 1,
            Instr::Input8 { .. } | Instr::InputDot { .. } => 8,
            _ => 0,
        }
    }

    fn fields(&self) -> [Fp; FIELDS] {
        let a = |x: Addr| Fp::new(x);
        let onehot = |c: u8, f: &mut [Fp; FIELDS], at: usize| f[at + c as usize] = Fp::ONE;
        let mut f = [Fp::ZERO; FIELDS];
        match *self {
            Instr::Const { imm, out } => {
                f[..4].copy_from_slice(&imm.0);
                f[4] = a(out);
            }
            Instr::Input { out } | Instr::Input8 { out } => f[0] = a(out),
            Instr::InputDot { out, pows, acc, acc_out } => {
                f[0] = a(out);
                f[1] = a(pows);
                f[2] = a(acc);
                f[3] = a(acc_out);
            }
            Instr::MulAdd { a: x, b, d, out } => {
                f[0] = a(x);
                f[1] = a(b);
                f[2] = a(d);
                f[3] = a(out);
            }
            Instr::AssertEq { a: x, b } => {
                f[0] = a(x);
                f[1] = a(b);
            }
            Instr::Decompose { a: x, out } => {
                f[0] = a(x);
                f[1] = a(out);
            }
            Instr::Select { src, comp, out } => {
                f[0] = a(src);
                onehot(comp, &mut f, 1);
                f[5] = a(out);
            }
            Instr::SpongeStart { data, cap0 } => {
                f[0] = a(data);
                f[1] = cap0;
            }
            Instr::Absorb { data } => f[0] = a(data),
            Instr::Compress { sib, dir, comp } => {
                f[0] = a(sib);
                f[1] = a(dir);
                onehot(comp, &mut f, 2);
            }
            Instr::Squeeze { out } => f[0] = a(out),
            Instr::AssertPublic => {}
        }
        f
    }

    /// The preprocessed row of this instruction.
    fn pre_row(&self) -> [Fp; PRE_WIDTH] {
        let mut row = [Fp::ZERO; PRE_WIDTH];
        row[self.opcode()] = Fp::ONE;
        row[P_F..].copy_from_slice(&self.fields());
        row
    }
}

/// A program under construction, with an address allocator.
#[derive(Clone, Debug, Default)]
pub struct Program {
    pub instrs: Vec<Instr>,
    next_addr: Addr,
    num_inputs: usize,
}

impl Program {
    pub fn new() -> Program {
        Program::default()
    }

    /// Reserves `n` consecutive fresh addresses.
    pub fn alloc(&mut self, n: u32) -> Addr {
        let a = self.next_addr;
        self.next_addr += n;
        a
    }

    pub fn num_inputs(&self) -> usize {
        self.num_inputs
    }

    fn push(&mut self, ins: Instr) {
        self.num_inputs += ins.num_inputs();
        self.instrs.push(ins);
    }

    pub fn constant(&mut self, v: Fp4) -> Addr {
        let out = self.alloc(1);
        self.push(Instr::Const { imm: v, out });
        out
    }

    pub fn scalar(&mut self, v: Fp) -> Addr {
        self.constant(Fp4::from_base(v))
    }

    /// Next witness value, at a fresh address.
    pub fn input(&mut self) -> Addr {
        let out = self.alloc(1);
        self.input_at(out)
    }

    /// Next witness value, at a caller-chosen address.
    pub fn input_at(&mut self, out: Addr) -> Addr {
        self.push(Instr::Input { out });
        out
    }

    /// Eight witness values at eight fresh consecutive addresses, one row.
    pub fn input8(&mut self) -> Addr {
        let out = self.alloc(8);
        self.input8_at(out)
    }

    /// Eight witness values at `out..out + 8`, one row.
    pub fn input8_at(&mut self, out: Addr) -> Addr {
        self.push(Instr::Input8 { out });
        out
    }

    /// Eight witness values at eight fresh addresses, and their dot product
    /// with the eight words at `pows` added to `acc`. Returns `(out,
    /// acc_out)`.
    pub fn input_dot(&mut self, pows: Addr, acc: Addr) -> (Addr, Addr) {
        let out = self.alloc(8);
        let acc_out = self.input_dot_at(out, pows, acc);
        (out, acc_out)
    }

    /// As [`Program::input_dot`] with the values written at `out..out + 8`.
    pub fn input_dot_at(&mut self, out: Addr, pows: Addr, acc: Addr) -> Addr {
        let acc_out = self.alloc(1);
        self.push(Instr::InputDot { out, pows, acc, acc_out });
        acc_out
    }

    /// `n` witness values at consecutive addresses.
    pub fn inputs(&mut self, n: u32) -> Addr {
        let base = self.alloc(n);
        for k in 0..n {
            self.input_at(base + k);
        }
        base
    }

    pub fn muladd_to(&mut self, a: Addr, b: Addr, d: Addr, out: Addr) -> Addr {
        self.push(Instr::MulAdd { a, b, d, out });
        out
    }

    pub fn muladd(&mut self, a: Addr, b: Addr, d: Addr) -> Addr {
        let out = self.alloc(1);
        self.muladd_to(a, b, d, out)
    }

    pub fn assert_eq(&mut self, a: Addr, b: Addr) {
        self.push(Instr::AssertEq { a, b });
    }

    /// Eight words holding the 31 bits of the scalar at `a`, four per word.
    pub fn decompose(&mut self, a: Addr) -> Addr {
        let out = self.alloc(8);
        self.push(Instr::Decompose { a, out });
        out
    }

    /// Component `comp` of the word at `src`, as a scalar word.
    pub fn component(&mut self, src: Addr, comp: u8) -> Addr {
        let out = self.alloc(1);
        self.push(Instr::Select { src, comp, out });
        out
    }

    /// Bit `i` (0..31) of a decomposition at `bits`, as a scalar word.
    pub fn bit(&mut self, bits: Addr, i: usize) -> Addr {
        self.component(bits + (i / 4) as Addr, (i % 4) as u8)
    }

    /// Starts a sponge with the eight scalars at `data` and capacity
    /// `[cap0, 0, ...]`.
    pub fn sponge_start(&mut self, data: Addr, cap0: Fp) {
        self.push(Instr::SpongeStart { data, cap0 });
    }

    pub fn absorb(&mut self, data: Addr) {
        self.push(Instr::Absorb { data });
    }

    /// Merkle step with the sibling digest at `sib` and direction bit
    /// component `comp` of the word at `dir`.
    pub fn compress(&mut self, sib: Addr, dir: Addr, comp: u8) {
        self.push(Instr::Compress { sib, dir, comp });
    }

    /// Writes the current digest (rate) to eight fresh words.
    pub fn squeeze(&mut self) -> Addr {
        let out = self.alloc(8);
        self.push(Instr::Squeeze { out });
        out
    }

    pub fn assert_public(&mut self) {
        self.push(Instr::AssertPublic);
    }

    /// Rows a trace for this program needs before padding.
    pub fn num_rows(&self) -> usize {
        self.instrs.len()
    }

    /// Trace height: the instruction count rounded up to a power of two.
    pub fn height(&self) -> usize {
        self.instrs.len().max(2).next_power_of_two()
    }

    /// The preprocessed table: one row per instruction, then `done` rows.
    pub fn table(&self) -> Trace {
        let n = self.height();
        let mut values = Vec::with_capacity(n * PRE_WIDTH);
        for ins in &self.instrs {
            values.extend_from_slice(&ins.pre_row());
        }
        let mut done = [Fp::ZERO; PRE_WIDTH];
        done[P_DONE] = Fp::ONE;
        for _ in self.instrs.len()..n {
            values.extend_from_slice(&done);
        }
        Trace::new(values, PRE_WIDTH)
    }

    /// The committed program for proofs at `log_blowup`.
    pub fn preprocess(&self, log_blowup: usize) -> Preprocessed {
        Preprocessed::new(&self.table(), log_blowup)
    }

    /// The program digest: root of the committed table.
    pub fn digest(&self, log_blowup: usize) -> Digest {
        self.preprocess(log_blowup).root()
    }
}

// ---------------------------------------------------------------------------
// Constraints
// ---------------------------------------------------------------------------

pub struct VmAir;

impl Air for VmAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn preprocessed_width(&self) -> usize {
        PRE_WIDTH
    }

    #[allow(clippy::needless_range_loop)]
    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        eval_hash_machine(b);
        let l = b.local();
        let n = b.next();
        let p = b.preprocessed();
        let public = b.public();
        let one = F::ONE;
        let zero = F::ZERO;

        // ---- instruction flags (from the committed program) ----
        b.mark("row types");
        let t_const = p[P_CONST];
        let t_input = p[P_INPUT];
        let t_input8 = p[P_INPUT8];
        let t_dot = p[P_DOT];
        let t_muladd = p[P_MULADD];
        let t_assert = p[P_ASSERT_EQ];
        let t_decomp = p[P_DECOMP];
        let t_select = p[P_SELECT];
        let t_sstart = p[P_SSTART];
        let t_absorb = p[P_ABSORB];
        let t_compress = p[P_COMPRESS];
        let t_squeeze = p[P_SQUEEZE];
        let t_apub = p[P_ASSERT_PUB];
        let f: [F; FIELDS] = core::array::from_fn(|i| p[P_F + i]);
        // machine op mapping: absorbs continue the running sponge register,
        // so they are machine starts with a constrained input.
        b.assert_eq(l[COL_START], t_sstart + t_absorb);
        b.assert_zero(l[COL_ABSORB]);
        b.assert_eq(l[COL_COMPRESS], t_compress);
        b.assert_eq(l[COL_PASS], one - t_sstart - t_absorb - t_compress);
        b.assert_zero(l[COL_LOAD]);
        b.assert_zero(l[COL_CHAIN]);
        // sponge register: output after a start/absorb, copied otherwise
        let sp_rows = t_sstart + t_absorb;
        for j in 0..WIDTH {
            b.when_transition(sp_rows * (n[R_SP + j] - l[crate::poseidon2_air::COL_OUTPUT + j]));
            b.when_transition((one - sp_rows) * (n[R_SP + j] - l[R_SP + j]));
        }
        for i in 0..DIGEST {
            b.assert_zero(t_apub * (l[COL_ACC + i] - public[PUB_OUTPUT + i]));
        }

        let read = |k: usize, c: usize| l[C_READ + k * DEGREE + c];
        let rv = |k: usize| -> [F; DEGREE] { core::array::from_fn(|c| read(k, c)) };
        let write = |k: usize, c: usize| l[C_WRITE + k * DEGREE + c];
        let wv = |k: usize| -> [F; DEGREE] { core::array::from_fn(|c| write(k, c)) };

        // ---- memory reads ----
        b.mark("reads");
        let block_ops = t_absorb + t_sstart + t_compress;
        for k in 0..READS {
            let (used, addr) = if k < 8 {
                let single = match k {
                    0 => t_muladd + t_assert + t_select + t_decomp,
                    1 => t_muladd + t_assert,
                    2 => t_muladd,
                    _ => zero,
                };
                let single_addr = match k {
                    0 => f[0],
                    1 => f[1],
                    2 => f[2],
                    _ => zero,
                };
                let kf = F::from_u32(k as u32);
                (single + block_ops + t_dot, single * single_addr + block_ops * (f[0] + kf) + t_dot * (f[1] + kf))
            } else {
                (t_compress + t_dot, t_compress * f[1] + t_dot * f[2])
            };
            let values = [addr, read(k, 0), read(k, 1), read(k, 2), read(k, 3)];
            b.lookup(false, used, &values);
        }
        // Hashing instructions read scalars.
        for k in 0..8 {
            for c in 1..DEGREE {
                b.assert_zero(block_ops * read(k, c));
            }
            b.assert_zero(t_absorb * (l[COL_INPUT + k] - l[R_SP + k] - read(k, 0)));
            b.assert_zero(t_absorb * (l[COL_INPUT + RATE + k] - l[R_SP + RATE + k]));
            b.assert_zero(t_compress * (l[COL_DATA + k] - read(k, 0)));
            b.assert_zero(t_sstart * (l[COL_INPUT + k] - read(k, 0)));
        }
        let cap0 = f[1];
        b.assert_zero(t_sstart * (l[COL_INPUT + RATE] - cap0));
        for i in 1..RATE {
            b.assert_zero(t_sstart * l[COL_INPUT + RATE + i]);
        }
        // Compress direction: component `comp` of the dir word.
        let mut dir = zero;
        for c in 0..DEGREE {
            dir += f[2 + c] * read(8, c);
        }
        b.assert_zero(t_compress * (l[COL_DIR] - dir));
        b.assert_zero((one - t_compress) * l[COL_DIR]);
        // AssertEq
        for c in 0..DEGREE {
            b.assert_zero(t_assert * (read(0, c) - read(1, c)));
        }

        // ---- memory writes ----
        b.mark("writes");
        let multi = t_decomp + t_squeeze + t_input8 + t_dot;
        let multi_base = t_decomp * f[1] + (t_squeeze + t_input8 + t_dot) * f[0];
        let single_w = t_const + t_input + t_muladd + t_select;
        let single_addr = t_const * f[4] + t_input * f[0] + t_muladd * f[3] + t_select * f[5];
        let prod = ext_mul(&rv(0), &rv(1));
        let bits: [F; BITS] = core::array::from_fn(|i| l[C_BITS + i]);
        // InputDot: acc_out = acc + sum_k in_k * pow_k.
        let mut dot: [F; DEGREE] = rv(8);
        for k in 0..8 {
            let t = ext_mul(&wv(k), &rv(k));
            for c in 0..DEGREE {
                dot[c] += t[c];
            }
        }
        for k in 0..WRITES {
            let kf = F::from_u32(k as u32);
            let (used, addr) = match k {
                0 => (single_w + multi, single_addr + multi_base),
                1..=7 => (multi, multi_base + multi * kf),
                _ => (t_dot, t_dot * f[3]),
            };
            let mult = l[C_MULT + k];
            b.assert_zero(mult * (one - used));
            let values = [addr, write(k, 0), write(k, 1), write(k, 2), write(k, 3)];
            b.lookup(true, mult, &values);
            // value definitions
            for c in 0..DEGREE {
                let w = write(k, c);
                if k == 8 {
                    b.assert_zero(t_dot * (w - dot[c]));
                    continue;
                }
                let bit = bits.get(4 * k + c).copied().unwrap_or(zero);
                b.assert_zero(t_decomp * (w - bit));
                let acc_c = if c == 0 { l[COL_ACC + k] } else { zero };
                b.assert_zero(t_squeeze * (w - acc_c));
                if k == 0 {
                    b.assert_zero(t_const * (w - f[c]));
                    b.assert_zero(t_muladd * (w - prod[c] - read(2, c)));
                    let sel_val = if c == 0 { (0..DEGREE).fold(zero, |a, j| a + f[1 + j] * read(0, j)) } else { zero };
                    b.assert_zero(t_select * (w - sel_val));
                }
            }
        }

        // ---- decomposition ----
        b.mark("decompose");
        let mut value = zero;
        let mut low27 = zero;
        for (i, bit) in bits.iter().enumerate() {
            b.assert_zero(*bit * *bit - *bit);
            value += *bit * pow2::<F>(i);
            if i < 27 {
                low27 += *bit * pow2::<F>(i);
            }
        }
        let t3 = l[C_T3];
        b.assert_eq(t3, bits[30] * bits[29] * bits[28]);
        b.assert_zero(t3 * bits[27] * low27);
        b.assert_zero(t_decomp * (read(0, 0) - value));
        for c in 1..DEGREE {
            b.assert_zero(t_decomp * read(0, c));
        }
    }
}

// ---------------------------------------------------------------------------
// Execution and trace generation
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecError {
    /// An `AssertEq` failed at this instruction index.
    AssertionFailed(usize),
    /// `AssertPublic` found no digest or was given the wrong one.
    PublicMismatch(usize),
    ReadUninitialized {
        pc: usize,
        addr: Addr,
    },
    DoubleWrite {
        pc: usize,
        addr: Addr,
    },
    NotScalar {
        pc: usize,
        addr: Addr,
    },
    NotEnoughInputs,
}

/// Result of running a program natively.
pub struct Execution {
    /// Memory words in address order (`None` where never written).
    pub mem: Vec<Option<Fp4>>,
    /// Digest at the `AssertPublic` instruction, if any.
    pub output_digest: Option<[Fp; DIGEST]>,
    /// Sponge register after the last instruction.
    pub final_sponge: [Fp; WIDTH],
}

struct Machine<'a> {
    inputs: &'a [Fp4],
    next_input: usize,
    mem: Vec<Option<Fp4>>,
    reads: Vec<u32>,
}

impl Machine<'_> {
    fn read(&mut self, pc: usize, addr: Addr) -> Result<Fp4, ExecError> {
        let v = self.mem.get(addr as usize).copied().flatten().ok_or(ExecError::ReadUninitialized { pc, addr })?;
        self.reads[addr as usize] += 1;
        Ok(v)
    }

    fn read_scalar(&mut self, pc: usize, addr: Addr) -> Result<Fp, ExecError> {
        let v = self.read(pc, addr)?;
        if v.0[1..].iter().any(|x| !x.is_zero()) {
            return Err(ExecError::NotScalar { pc, addr });
        }
        Ok(v.0[0])
    }

    fn read_block(&mut self, pc: usize, base: Addr) -> Result<[Fp; RATE], ExecError> {
        let mut out = [Fp::ZERO; RATE];
        for (k, o) in out.iter_mut().enumerate() {
            *o = self.read_scalar(pc, base + k as Addr)?;
        }
        Ok(out)
    }

    fn next_input(&mut self) -> Result<Fp4, ExecError> {
        let v = *self.inputs.get(self.next_input).ok_or(ExecError::NotEnoughInputs)?;
        self.next_input += 1;
        Ok(v)
    }

    fn write(&mut self, pc: usize, addr: Addr, v: Fp4) -> Result<(), ExecError> {
        let a = addr as usize;
        if a >= self.mem.len() {
            self.mem.resize(a + 1, None);
            self.reads.resize(a + 1, 0);
        }
        if self.mem[a].is_some() {
            return Err(ExecError::DoubleWrite { pc, addr });
        }
        self.mem[a] = Some(v);
        Ok(())
    }
}

impl VmAir {
    /// Runs `program` on `inputs`, checking assertions. Used both to compute
    /// witnesses and, inside [`VmAir::generate_trace`], to fill the trace.
    pub fn execute(program: &Program, inputs: &[Fp4]) -> Result<Execution, ExecError> {
        let (exec, _) = Self::run(program, inputs, None)?;
        Ok(exec)
    }

    /// Executes and records rows when `rows` is given.
    fn run(
        program: &Program,
        inputs: &[Fp4],
        mut rows: Option<(&mut HashTraceBuilder, &[u32])>,
    ) -> Result<(Execution, Vec<u32>), ExecError> {
        let mut m = Machine { inputs, next_input: 0, mem: Vec::new(), reads: Vec::new() };
        let mut output_digest = None;
        let mut current_digest = [Fp::ZERO; DIGEST];
        // Value of the sponge register entering the current row.
        let mut sp_reg = [Fp::ZERO; WIDTH];
        // Running sponge state, tracked natively (the trace builder, when
        // present, computes the same values row by row).
        let mut sponge: Option<[Fp; WIDTH]> = None;
        for (pc, ins) in program.instrs.iter().enumerate() {
            // Values this row writes (slot, address, word).
            let mut writes: Vec<(usize, Addr, Fp4)> = Vec::new();
            let mut read_vals: Vec<Fp4> = Vec::new();
            let mut bits_val: Option<u32> = None;
            let mut hash_op: Option<(usize, [Fp; WIDTH])> = None; // (kind, data) kind 0 start 1 absorb 2 compress
            let mut dir_bit = false;
            match *ins {
                Instr::Const { imm, out } => {
                    m.write(pc, out, imm)?;
                    writes.push((0, out, imm));
                }
                Instr::Input { out } => {
                    let v = m.next_input()?;
                    m.write(pc, out, v)?;
                    writes.push((0, out, v));
                }
                Instr::Input8 { out } => {
                    for k in 0..8 {
                        let v = m.next_input()?;
                        m.write(pc, out + k as Addr, v)?;
                        writes.push((k, out + k as Addr, v));
                    }
                }
                Instr::InputDot { out, pows, acc, acc_out } => {
                    let mut vals = [Fp4::ZERO; 8];
                    for v in vals.iter_mut() {
                        *v = m.next_input()?;
                    }
                    let mut sum = Fp4::ZERO;
                    for (k, v) in vals.iter().enumerate() {
                        let pw = m.read(pc, pows + k as Addr)?;
                        read_vals.push(pw);
                        sum += *v * pw;
                    }
                    let a = m.read(pc, acc)?;
                    read_vals.push(a);
                    for (k, v) in vals.iter().enumerate() {
                        m.write(pc, out + k as Addr, *v)?;
                        writes.push((k, out + k as Addr, *v));
                    }
                    m.write(pc, acc_out, a + sum)?;
                    writes.push((8, acc_out, a + sum));
                }
                Instr::MulAdd { a, b, d, out } => {
                    let (x, y, z) = (m.read(pc, a)?, m.read(pc, b)?, m.read(pc, d)?);
                    read_vals.extend([x, y, z]);
                    let v = x * y + z;
                    m.write(pc, out, v)?;
                    writes.push((0, out, v));
                }
                Instr::AssertEq { a, b } => {
                    let (x, y) = (m.read(pc, a)?, m.read(pc, b)?);
                    read_vals.extend([x, y]);
                    if x != y {
                        return Err(ExecError::AssertionFailed(pc));
                    }
                }
                Instr::Decompose { a, out } => {
                    let x = m.read_scalar(pc, a)?;
                    read_vals.push(Fp4::from_base(x));
                    let v = x.to_canonical();
                    bits_val = Some(v);
                    for k in 0..8 {
                        let word = Fp4(core::array::from_fn(|c| Fp::new((v >> (4 * k + c)) & 1)));
                        m.write(pc, out + k as Addr, word)?;
                        writes.push((k, out + k as Addr, word));
                    }
                }
                Instr::Select { src, comp, out } => {
                    let x = m.read(pc, src)?;
                    read_vals.push(x);
                    let v = Fp4::from_base(x.0[comp as usize]);
                    m.write(pc, out, v)?;
                    writes.push((0, out, v));
                }
                Instr::SpongeStart { data, cap0 } => {
                    let block = m.read_block(pc, data)?;
                    read_vals.extend(block.iter().map(|x| Fp4::from_base(*x)));
                    let mut input = [Fp::ZERO; WIDTH];
                    input[..RATE].copy_from_slice(&block);
                    input[RATE] = cap0;
                    hash_op = Some((0, input));
                }
                Instr::Absorb { data } => {
                    let block = m.read_block(pc, data)?;
                    read_vals.extend(block.iter().map(|x| Fp4::from_base(*x)));
                    let mut input = [Fp::ZERO; WIDTH];
                    input[..RATE].copy_from_slice(&block);
                    hash_op = Some((1, input));
                }
                Instr::Compress { sib, dir, comp } => {
                    let block = m.read_block(pc, sib)?;
                    read_vals.extend(block.iter().map(|x| Fp4::from_base(*x)));
                    let d = m.read(pc, dir)?;
                    read_vals.push(d);
                    dir_bit = d.0[comp as usize] == Fp::ONE;
                    let mut input = [Fp::ZERO; WIDTH];
                    input[..RATE].copy_from_slice(&block);
                    hash_op = Some((2, input));
                }
                Instr::Squeeze { out } => {
                    for (k, d) in current_digest.iter().enumerate() {
                        let v = Fp4::from_base(*d);
                        m.write(pc, out + k as Addr, v)?;
                        writes.push((k, out + k as Addr, v));
                    }
                }
                Instr::AssertPublic => {
                    output_digest = Some(current_digest);
                }
            }
            // Advance the native sponge. An absorb's full permutation input is
            // the register state plus the block.
            let mut absorb_input = [Fp::ZERO; WIDTH];
            match hash_op {
                Some((0, input)) => sponge = Some(permute(input)),
                Some((1, input)) => {
                    let mut st = sponge.expect("absorb without a running sponge");
                    for (x, y) in st.iter_mut().zip(&input[..RATE]) {
                        *x = x.add(y);
                    }
                    absorb_input = st;
                    sponge = Some(permute(st));
                }
                Some((2, input)) => {
                    let mut st = [Fp::ZERO; WIDTH];
                    let sib: [Fp; DIGEST] = input[..DIGEST].try_into().unwrap();
                    if dir_bit {
                        st[..DIGEST].copy_from_slice(&sib);
                        st[DIGEST..].copy_from_slice(&current_digest);
                    } else {
                        st[..DIGEST].copy_from_slice(&current_digest);
                        st[DIGEST..].copy_from_slice(&sib);
                    }
                    sponge = Some(permute(st));
                }
                _ => {}
            }
            if hash_op.is_some() {
                current_digest.copy_from_slice(&sponge.unwrap()[..DIGEST]);
            }
            if let Some((ref mut b, counts)) = rows {
                match hash_op {
                    Some((0, input)) => {
                        b.start(input);
                    }
                    Some((1, _)) => {
                        b.start(absorb_input);
                    }
                    Some((2, input)) => {
                        b.compress(input[..RATE].try_into().unwrap(), dir_bit);
                    }
                    _ => {
                        b.pass();
                    }
                }
                debug_assert_eq!(b.acc(), current_digest);
                let row = b.last_row_mut();
                row[R_SP..R_SP + WIDTH].copy_from_slice(&sp_reg);
                for (k, v) in read_vals.iter().enumerate() {
                    row[C_READ + k * DEGREE..C_READ + (k + 1) * DEGREE].copy_from_slice(&v.0);
                }
                for (slot, addr, v) in &writes {
                    row[C_WRITE + slot * DEGREE..C_WRITE + (slot + 1) * DEGREE].copy_from_slice(&v.0);
                    row[C_MULT + slot] = Fp::new(counts[*addr as usize]);
                }
                if let Some(v) = bits_val {
                    for i in 0..BITS {
                        row[C_BITS + i] = Fp::new((v >> i) & 1);
                    }
                    row[C_T3] = Fp::new(((v >> 28) & 7 == 7) as u32);
                }
            }
            if matches!(hash_op, Some((0, _)) | Some((1, _))) {
                sp_reg = sponge.unwrap();
            }
        }
        let reads = m.reads.clone();
        Ok((Execution { mem: m.mem, output_digest, final_sponge: sp_reg }, reads))
    }

    /// Builds the trace for `program` on `inputs`, of height
    /// [`Program::height`].
    pub fn generate_trace(program: &Program, inputs: &[Fp4]) -> Result<Trace, ExecError> {
        // First pass: read counts for the write multiplicities.
        let (_, counts) = Self::run(program, inputs, None)?;
        let mut b = HashTraceBuilder::new(NUM_COLS);
        let (exec, _) = Self::run(program, inputs, Some((&mut b, &counts)))?;
        let sp = exec.final_sponge;
        let n = program.height();
        while b.len() < n {
            b.pass();
            let row = b.last_row_mut();
            row[R_SP..R_SP + WIDTH].copy_from_slice(&sp);
        }
        Ok(b.finish())
    }

    pub fn public_values(program_digest: &Digest, output_digest: &[Fp; DIGEST]) -> Vec<Fp> {
        let mut v = Vec::with_capacity(NUM_PUBLIC);
        v.extend_from_slice(program_digest);
        v.extend_from_slice(output_digest);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::merkle::{MerkleTree, hash_row};
    use crate::poseidon2::hash;
    use crate::stark::{StarkConfig, check_constraints_with, measure_degree, prove_with, verify_with};
    use crate::test_util::Rng;

    fn tr() -> Challenger {
        let mut c = Challenger::new();
        c.observe(Fp::new(0xf6));
        c
    }

    /// Builds a program exercising every instruction. Returns the program,
    /// its inputs, and the expected output digest.
    fn sample_program(rng: &mut Rng) -> (Program, Vec<Fp4>, [Fp; DIGEST]) {
        let mut p = Program::new();
        let mut inputs = Vec::new();
        let one = p.constant(Fp4::ONE);
        let zero = p.constant(Fp4::ZERO);
        // y = x^3 + 7, asserted against a witness.
        let x_val = rng.fp4();
        let x = p.input();
        inputs.push(x_val);
        let x2 = p.muladd(x, x, zero);
        let seven = p.constant(Fp4::from_u32(7));
        let y = p.muladd(x2, x, seven);
        let y_in = p.input();
        inputs.push(x_val * x_val * x_val + Fp4::from_u32(7));
        p.assert_eq(y, y_in);
        // A sponge hash of eight witness scalars (one block input) equals
        // the native hash.
        let block_vals: Vec<Fp> = (0..8).map(|_| rng.fp()).collect();
        let block = p.input8();
        inputs.extend(block_vals.iter().map(|v| Fp4::from_base(*v)));
        p.sponge_start(block, Fp::from_u32(8));
        let digest = p.squeeze();
        let expected = hash(&block_vals);
        for (i, e) in expected.iter().enumerate() {
            let c = p.scalar(*e);
            p.assert_eq(digest + i as Addr, c);
        }
        // A dot product of eight witness words with eight constants.
        let pows = p.alloc(8);
        let pow_vals: Vec<Fp4> = (0..8).map(|_| rng.fp4()).collect();
        for (k, v) in pow_vals.iter().enumerate() {
            let c = p.constant(*v);
            p.muladd_to(c, one, zero, pows + k as Addr);
        }
        let dot_vals: Vec<Fp4> = (0..8).map(|_| rng.fp4()).collect();
        let (dot_in, acc_out) = p.input_dot(pows, y);
        inputs.extend(dot_vals.iter().copied());
        let want =
            dot_vals.iter().zip(&pow_vals).fold(x_val * x_val * x_val + Fp4::from_u32(7), |a, (v, w)| a + *v * *w);
        let want_c = p.constant(want);
        p.assert_eq(acc_out, want_c);
        let d3 = p.constant(dot_vals[3]);
        p.assert_eq(dot_in + 3, d3);
        // Merkle path: leaf = hash([v]) with index bits from a decomposition.
        let rows: Vec<Vec<Fp>> = (0..16).map(|i| vec![Fp::new(100 + i)]).collect();
        let tree = MerkleTree::new(&rows);
        let index = 11usize;
        let idx = p.input();
        inputs.push(Fp4::from_u32(index as u32));
        let bits = p.decompose(idx);
        let leaf_block = p.alloc(8);
        let v = p.scalar(rows[index][0]);
        p.muladd_to(v, one, zero, leaf_block);
        for k in 1..8 {
            p.muladd_to(zero, one, zero, leaf_block + k);
        }
        p.sponge_start(leaf_block, Fp::ONE);
        let leaf = p.squeeze();
        let want_leaf = hash_row(&rows[index]);
        for (i, e) in want_leaf.iter().enumerate() {
            let c = p.scalar(*e);
            p.assert_eq(leaf + i as Addr, c);
        }
        for (level, sib) in tree.open(index).iter().enumerate() {
            let sib_addr = p.input8();
            inputs.extend(sib.iter().map(|v| Fp4::from_base(*v)));
            p.compress(sib_addr, bits + (level / 4) as Addr, (level % 4) as u8);
        }
        let root = p.squeeze();
        for (i, e) in tree.root().iter().enumerate() {
            let c = p.scalar(*e);
            p.assert_eq(root + i as Addr, c);
        }
        // Bit extraction: bit 3 of 11 is 1, bit 2 is 0.
        let b3 = p.bit(bits, 3);
        let b2 = p.bit(bits, 2);
        p.assert_eq(b3, one);
        p.assert_eq(b2, zero);
        // Output digest over y's first component and half the root.
        let out_scalars = p.alloc(8);
        let y0 = p.component(y, 0);
        for i in 0..4 {
            p.muladd_to(y0, one, zero, out_scalars + i);
        }
        for i in 4..8 {
            p.muladd_to(root + (i as Addr - 4), one, zero, out_scalars + i);
        }
        p.sponge_start(out_scalars, Fp::ZERO);
        p.assert_public();
        let exec = VmAir::execute(&p, &inputs).unwrap();
        (p, inputs, exec.output_digest.unwrap())
    }

    #[test]
    fn layout_and_degree() {
        assert_eq!(measure_degree(&VmAir, NUM_PUBLIC), 3);
        const { assert!(NUM_COLS < 500) };
    }

    #[test]
    fn program_executes_and_satisfies_constraints() {
        let mut rng = Rng::new(70);
        let (p, inputs, out) = sample_program(&mut rng);
        assert_eq!(p.num_inputs(), inputs.len());
        let trace = VmAir::generate_trace(&p, &inputs).unwrap();
        assert_eq!(trace.height(), p.height());
        let table = p.table();
        let public = VmAir::public_values(&p.digest(1), &out);
        assert_eq!(check_constraints_with(&VmAir, &trace, Some(&table), &public), Ok(()));
        // Wrong output digest.
        let mut bad = public.clone();
        bad[PUB_OUTPUT + 7] += Fp::ONE;
        assert!(check_constraints_with(&VmAir, &trace, Some(&table), &bad).is_err());
        // A wrong witness fails an assertion natively.
        let mut wrong = inputs.clone();
        wrong[1] += Fp4::ONE;
        assert!(matches!(VmAir::execute(&p, &wrong), Err(ExecError::AssertionFailed(_))));
        // Tampering with a read value breaks the memory relation.
        let width = NUM_COLS;
        let r = p.instrs.iter().position(|i| matches!(i, Instr::MulAdd { .. })).unwrap();
        let mut bad = trace.clone();
        bad.values[r * width + C_READ] += Fp::ONE;
        assert!(check_constraints_with(&VmAir, &bad, Some(&table), &public).is_err());
        // A different program (one changed field) rejects the same trace.
        let mut other = table.clone();
        other.values[r * PRE_WIDTH + P_F] += Fp::ONE;
        assert!(check_constraints_with(&VmAir, &trace, Some(&other), &public).is_err());
        // A dot-product row with a wrong accumulator.
        let r = p.instrs.iter().position(|i| matches!(i, Instr::InputDot { .. })).unwrap();
        let mut bad = trace.clone();
        bad.values[r * width + C_WRITE + 8 * DEGREE] += Fp::ONE;
        assert!(check_constraints_with(&VmAir, &bad, Some(&table), &public).is_err());
    }

    #[test]
    fn prove_and_verify_program() {
        let config = StarkConfig { log_blowup: 1, num_queries: 16 };
        let mut rng = Rng::new(71);
        let (p, inputs, out) = sample_program(&mut rng);
        let trace = VmAir::generate_trace(&p, &inputs).unwrap();
        let pre = p.preprocess(config.log_blowup);
        let public = VmAir::public_values(&pre.root(), &out);
        let proof = prove_with(&config, &VmAir, &trace, Some(&pre), &public, &mut tr());
        assert_eq!(verify_with(&config, &VmAir, Some(&pre.root()), &public, &proof, &mut tr()), Ok(()));
        let mut bad = public.clone();
        bad[PUB_OUTPUT] += Fp::ONE;
        assert!(verify_with(&config, &VmAir, Some(&pre.root()), &bad, &proof, &mut tr()).is_err());
        // Against another program's digest.
        let mut q = p.clone();
        q.assert_eq(0, 0);
        let other = q.digest(config.log_blowup);
        assert_ne!(other, pre.root());
        assert!(verify_with(&config, &VmAir, Some(&other), &public, &proof, &mut tr()).is_err());
    }
}
