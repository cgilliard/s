//! The chain proof's verifier as a fixed program, run by an interpreter.
//!
//! A chain step already verifies the previous block's chain proof inside
//! the machine of [`crate::vm_air`]: [`Compiler::verify_stark`] compiles
//! the STARK verifier into a program that depends only on the proof's
//! shape (the configuration and table heights), never on its values. This
//! module takes that same verifier, compiled once for the chain setup's
//! heights, and runs it on a proof's values. Tabminer and the fam node
//! (`node/src/user/node/`) both verify chain proofs this way, from the
//! same program (`node/data/chainver.bin`, [`ChainVerifier::to_bytes`]), so
//! they accept exactly the same proofs.
//!
//! A proof is accepted when:
//!
//! 1. its bytes decode ([`Proof::from_bytes`]) to a proof of the program's
//!    shape: every count and length as the setup's ([`ChainVerifier::fits`]),
//!    and no proof-of-work witness where nothing is ground;
//! 2. the program accepts the proof's values, in the order it reads them
//!    ([`ChainVerifier::stream`]), every assertion holding; and
//! 3. each query index the proof gives is the one the program sampled.
//!
//! The program's inputs are the proof's values, but for the inverses it
//! asks the prover for (a hint `h` for `a`, then the assertion `a h = 1`):
//! those the interpreter computes itself, as [`Op::Inv`]. That is the one
//! difference from the machine, and it changes nothing: a wrong hint fails
//! the assertion that follows it, and the right one is the only one that
//! passes. Every input that passes is a valid proof by the recursion's own
//! soundness, which the chain proofs already rest on: a step verifies its
//! predecessor with this program.

use std::sync::{Arc, Mutex};

use crate::aggregate::DOM_CHAIN_PROOF;
use crate::ext::{DEGREE, Fp4};
use crate::fri::{fold_grinding, leaf_row, round_log_arities};
use crate::hash_table::HashTableAir;
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH, compress, permute};
use crate::recursion::{Compiler, dummy_proof};
use crate::stark::{DynAir, Proof, StarkConfig, grinding_of};
use crate::vm_air::{Addr, Instr, NUM_PUBLIC, VmAir};

/// One instruction of the verifier: the machine's, with inverse hints
/// computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Const { imm: Fp4, out: Addr },
    /// The next value of the stream, as a word.
    Input { out: Addr },
    /// The next eight values, as eight words.
    Input8 { out: Addr },
    /// The next eight values at `out..out + 8`, and `acc` plus their dot
    /// product with the words at `pows..pows + 8` at `acc_out`.
    InputDot { out: Addr, pows: Addr, acc: Addr, acc_out: Addr },
    MulAdd { a: Addr, b: Addr, d: Addr, out: Addr },
    AssertEq { a: Addr, b: Addr },
    /// The 31 bits of the scalar at `a`, four to a word, in eight words.
    Decompose { a: Addr, out: Addr },
    Select { src: Addr, comp: u8, out: Addr },
    SpongeStart { data: Addr, cap0: Fp },
    Absorb { data: Addr },
    /// A Merkle step whose sibling is the next eight values.
    CompressIn { dir: Addr, comp: u8 },
    Squeeze { out: Addr },
    /// The inverse of the word at `a` (zero for zero), which the machine
    /// takes as an input.
    Inv { a: Addr, out: Addr },
}

impl Op {
    fn code(&self) -> u32 {
        match self {
            Op::Const { .. } => 0,
            Op::Input { .. } => 1,
            Op::Input8 { .. } => 2,
            Op::InputDot { .. } => 3,
            Op::MulAdd { .. } => 4,
            Op::AssertEq { .. } => 5,
            Op::Decompose { .. } => 6,
            Op::Select { .. } => 7,
            Op::SpongeStart { .. } => 8,
            Op::Absorb { .. } => 9,
            Op::CompressIn { .. } => 10,
            Op::Squeeze { .. } => 11,
            Op::Inv { .. } => 12,
        }
    }

    /// The words of its encoding after the code.
    fn fields(&self) -> Vec<u32> {
        let c = |x: &Fp| x.to_canonical();
        match *self {
            Op::Const { imm, out } => vec![c(&imm.0[0]), c(&imm.0[1]), c(&imm.0[2]), c(&imm.0[3]), out],
            Op::Input { out } | Op::Input8 { out } | Op::Squeeze { out } => vec![out],
            Op::InputDot { out, pows, acc, acc_out } => vec![out, pows, acc, acc_out],
            Op::MulAdd { a, b, d, out } => vec![a, b, d, out],
            Op::AssertEq { a, b } => vec![a, b],
            Op::Decompose { a, out } => vec![a, out],
            Op::Select { src, comp, out } => vec![src, comp as u32, out],
            Op::SpongeStart { data, cap0 } => vec![data, c(&cap0)],
            Op::Absorb { data } => vec![data],
            Op::CompressIn { dir, comp } => vec![dir, comp as u32],
            Op::Inv { a, out } => vec![a, out],
        }
    }
}

/// What a chain proof must look like, from a proof of the right shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shape {
    /// Per table: its height, whether it has lookups, and the lengths of
    /// its seven groups of out-of-domain openings
    /// ([`crate::stark::TableProof::opened`]).
    pub tables: Vec<(usize, bool, [usize; 7])>,
    /// Per table, the lengths of its opened rows: trace, auxiliary,
    /// preprocessed and quotient.
    pub rows: Vec<[usize; 4]>,
    /// Per FRI round, the values a query opens (`2^arity`) and the bits
    /// its folding challenge is ground to.
    pub rounds: Vec<(usize, usize)>,
    pub queries: usize,
    /// The heights of the trees, in the order of the encoding: per table
    /// its trace, auxiliary, preprocessed and quotient trees, then the FRI
    /// rounds'.
    pub heights: Vec<usize>,
    /// Bits ground before the lookup challenges, the constraint
    /// combination, the out-of-domain point and the batching challenge,
    /// and before the queries.
    pub grinding: [usize; 5],
}

/// The chain proof's verifier for one configuration and pair of heights.
pub struct ChainVerifier {
    pub ops: Vec<Op>,
    /// Words of memory the program uses.
    pub mem: usize,
    /// Values the program reads from its stream.
    pub stream_len: usize,
    pub shape: Shape,
    /// The bits of each query's sampled index, and how many of them the
    /// index takes.
    pub query_bits: Vec<Addr>,
    pub log_big_n: usize,
}

const MAGIC: u32 = u32::from_le_bytes(*b"CHV1");

impl ChainVerifier {
    /// Compiles the verifier of chain proofs with tables of `2^log_n` and
    /// `2^hash_log_n` rows under `config`.
    pub fn new(config: &StarkConfig, log_n: usize, hash_log_n: usize) -> ChainVerifier {
        let tables_h: [(&dyn DynAir, usize); 2] = [(&VmAir, log_n), (&HashTableAir, hash_log_n)];
        let proof = dummy_proof(&tables_h, config, NUM_PUBLIC);
        let mut c = Compiler::new();
        let pubv = c.scalar_inputs(&[Fp::ZERO; NUM_PUBLIC]);
        let tables: [(&dyn DynAir, Option<Addr>); 2] = [(&VmAir, Some(pubv)), (&HashTableAir, None)];
        c.verify_stark(&tables, config, &[Fp::new(DOM_CHAIN_PROOF)], pubv, NUM_PUBLIC, &proof);

        let mut hints = c.hints.iter().copied().peekable();
        let mut ops = Vec::with_capacity(c.prog.instrs.len());
        for (pc, ins) in c.prog.instrs.iter().enumerate() {
            let hint = hints.next_if(|h| h.0 == pc).map(|h| h.1);
            ops.push(match (*ins, hint) {
                (Instr::Input { out }, Some(a)) => Op::Inv { a, out },
                (_, Some(_)) => panic!("an inverse hint that is not an input"),
                (Instr::Const { imm, out }, None) => Op::Const { imm, out },
                (Instr::Input { out }, None) => Op::Input { out },
                (Instr::Input8 { out }, None) => Op::Input8 { out },
                (Instr::InputDot { out, pows, acc, acc_out }, None) => Op::InputDot { out, pows, acc, acc_out },
                (Instr::MulAdd { a, b, d, out }, None) => Op::MulAdd { a, b, d, out },
                (Instr::AssertEq { a, b }, None) => Op::AssertEq { a, b },
                (Instr::Decompose { a, out }, None) => Op::Decompose { a, out },
                (Instr::Select { src, comp, out }, None) => Op::Select { src, comp, out },
                (Instr::SpongeStart { data, cap0 }, None) => Op::SpongeStart { data, cap0 },
                (Instr::Absorb { data }, None) => Op::Absorb { data },
                (Instr::CompressIn { dir, comp }, None) => Op::CompressIn { dir, comp },
                (Instr::Squeeze { out }, None) => Op::Squeeze { out },
                (other, None) => panic!("the verifier uses {other:?}"),
            });
        }
        assert!(hints.next().is_none());

        let mut log_sizes: Vec<usize> = [log_n, hash_log_n].iter().map(|l| l + config.log_blowup).collect();
        log_sizes.dedup();
        let log_big_n = log_sizes[0];
        let arities = round_log_arities(&config.fri(), &log_sizes);
        let mut log_m = log_big_n;
        let rounds = arities
            .iter()
            .map(|&la| {
                let bits = fold_grinding(&config.fri(), la, log_m);
                log_m -= la;
                (1usize << la, bits)
            })
            .collect();
        let g = grinding_of(config, &tables_h, &[Fp::ZERO; NUM_PUBLIC]);
        let o = &proof.openings[0];
        let mut heights = Vec::new();
        for o in o {
            heights.extend([o.trace_path.len(), o.aux_path.len(), o.pre_path.len(), o.quotient_path.len()]);
        }
        heights.extend(proof.fri.queries[0].iter().map(|s| s.path.len()));
        let shape = Shape {
            tables: proof
                .tables
                .iter()
                .map(|t| (t.log_n, t.aux_root.is_some(), t.opened().map(|g| g.len())))
                .collect(),
            rows: o
                .iter()
                .map(|o| [o.trace_row.len(), o.aux_row.len(), o.pre_row.len(), o.quotient_row.len()])
                .collect(),
            rounds,
            queries: config.num_queries,
            heights,
            grinding: [g.lookup, g.alpha, g.zeta, g.beta, config.pow_bits],
        };
        let mut v = ChainVerifier {
            ops,
            mem: c.prog.alloc(0) as usize,
            stream_len: 0,
            shape,
            query_bits: c.query_bits.clone(),
            log_big_n,
        };
        v.stream_len = v.stream(&[Fp::ZERO; NUM_PUBLIC], &proof).len();
        v.check_program();
        v
    }

    /// Checks that the program writes each word once, reads only words
    /// written, and reads exactly its stream: properties of the program
    /// alone, so the interpreter need not track them.
    fn check_program(&self) {
        let mut written = vec![false; self.mem];
        let mut reads = 0usize;
        let (mut hashed, mut sponge) = (false, false);
        for op in &self.ops {
            reads += match op {
                Op::Input { .. } => 1,
                Op::Input8 { .. } | Op::InputDot { .. } | Op::CompressIn { .. } => RATE,
                _ => 0,
            };
            // As the machine: an absorb continues a sponge (a start or
            // an absorb last), a compress or a squeeze follows some hashing.
            match op {
                Op::SpongeStart { .. } => (hashed, sponge) = (true, true),
                Op::Absorb { .. } => assert!(sponge, "an absorb without a sponge"),
                Op::CompressIn { .. } => {
                    assert!(hashed, "a compress before any hashing");
                    sponge = false
                }
                Op::Squeeze { .. } => assert!(hashed, "a squeeze before any hashing"),
                _ => {}
            }
            if let Op::Select { comp, .. } | Op::CompressIn { comp, .. } = op {
                assert!((*comp as usize) < DEGREE);
            }
            let (r, w) = op_access(op);
            for (a, n) in r {
                assert!((0..n).all(|k| written[a as usize + k]), "a word read before it is written");
            }
            for (a, n) in w {
                for k in 0..n {
                    assert!(!std::mem::replace(&mut written[a as usize + k], true), "a word written twice");
                }
            }
        }
        assert_eq!(reads, self.stream_len, "the stream's length");
        assert!(self.log_big_n <= 31);
        for &b in &self.query_bits {
            assert!(written[b as usize]);
        }
    }

    /// Whether `proof` has this verifier's shape.
    pub fn fits(&self, proof: &Proof) -> bool {
        let s = &self.shape;
        let nq = s.queries;
        let rounds = s.rounds.len();
        let tables_fit = proof.tables.len() == s.tables.len()
            && proof
                .tables
                .iter()
                .zip(&s.tables)
                .all(|(t, &(log_n, aux, lens))| {
                    t.log_n == log_n && t.aux_root.is_some() == aux && t.opened().map(|g| g.len()) == lens
                });
        let fri = &proof.fri;
        let fri_fits = fri.commitments.len() == rounds
            && fri.fold_witnesses.len() == rounds
            && fri.fold_witnesses.iter().zip(&s.rounds).all(|(w, r)| r.1 > 0 || w.is_zero())
            && fri.queries.len() == nq
            && fri.queries.iter().all(|q| {
                q.len() == rounds
                    && q.iter()
                        .zip(&s.rounds)
                        .zip(&s.heights[4 * s.tables.len()..])
                        .all(|((st, r), &h)| st.values.len() == r.0 && st.path.len() == h)
            });
        let openings_fit = proof.openings.len() == nq
            && proof.query_indices.len() == nq
            && proof.openings.iter().all(|per| {
                per.len() == s.tables.len()
                    && per.iter().zip(&s.rows).zip(s.heights.chunks(4)).all(|((o, rows), h)| {
                        [o.trace_row.len(), o.aux_row.len(), o.pre_row.len(), o.quotient_row.len()] == *rows
                            && [o.trace_path.len(), o.aux_path.len(), o.pre_path.len(), o.quotient_path.len()]
                                == h[..4]
                    })
            });
        let g = &s.grinding;
        let ground = proof.grinding.iter().zip(g).all(|(w, &bits)| bits > 0 || w.is_zero())
            && (g[4] > 0 || fri.pow_witness.is_zero());
        tables_fit && fri_fits && openings_fit && ground
    }

    /// The values the program reads, in its order, for a proof that
    /// [`ChainVerifier::fits`] with `public` (the program digest and the
    /// output digest). Scalars come in blocks of eight, zero padded.
    pub fn stream(&self, public: &[Fp], proof: &Proof) -> Vec<Fp4> {
        let mut s: Vec<Fp4> = Vec::with_capacity(self.stream_len);
        let scalars = |s: &mut Vec<Fp4>, v: &[Fp]| {
            let n = v.len().div_ceil(RATE).max(1) * RATE;
            s.extend((0..n).map(|i| Fp4::from_base(v.get(i).copied().unwrap_or(Fp::ZERO))));
        };
        let path = |s: &mut Vec<Fp4>, p: &[[Fp; DIGEST]]| {
            s.extend(p.iter().flatten().map(|x| Fp4::from_base(*x)));
        };
        let g = &self.shape.grinding;
        scalars(&mut s, public);
        for t in &proof.tables {
            scalars(&mut s, &t.trace_root);
        }
        for t in &proof.tables {
            if let Some(r) = &t.aux_root {
                scalars(&mut s, r);
                s.push(t.lookup_sum);
            }
        }
        for t in &proof.tables {
            scalars(&mut s, &t.quotient_root);
        }
        let witness = |s: &mut Vec<Fp4>, bits: usize, w: Fp| {
            if bits > 0 {
                s.push(Fp4::from_base(w));
            }
        };
        if proof.tables.iter().any(|t| t.aux_root.is_some()) {
            witness(&mut s, g[0], proof.grinding[0]);
        }
        witness(&mut s, g[1], proof.grinding[1]);
        witness(&mut s, g[2], proof.grinding[2]);
        let opened: Vec<Fp> =
            proof.tables.iter().flat_map(|t| t.opened().into_iter().flat_map(|g| g.iter().flat_map(|v| v.0))).collect();
        scalars(&mut s, &opened);
        witness(&mut s, g[3], proof.grinding[3]);
        for ((root, w), r) in proof.fri.commitments.iter().zip(&proof.fri.fold_witnesses).zip(&self.shape.rounds) {
            scalars(&mut s, root);
            witness(&mut s, r.1, *w);
        }
        s.push(proof.fri.final_value);
        witness(&mut s, g[4], proof.fri.pow_witness);
        for (q, steps) in proof.fri.queries.iter().enumerate() {
            for (o, rows) in proof.openings[q].iter().zip(&self.shape.rows) {
                scalars(&mut s, &o.trace_row);
                path(&mut s, &o.trace_path);
                if rows[1] > 0 {
                    scalars(&mut s, &o.aux_row);
                    path(&mut s, &o.aux_path);
                }
                if rows[2] > 0 {
                    scalars(&mut s, &o.pre_row);
                    path(&mut s, &o.pre_path);
                }
                scalars(&mut s, &o.quotient_row);
                path(&mut s, &o.quotient_path);
            }
            for st in steps {
                scalars(&mut s, &leaf_row(&st.values));
                path(&mut s, &st.path);
            }
        }
        s
    }

    /// Runs the program on `stream`: whether every assertion holds. Also
    /// returns each query's sampled index.
    pub fn run(&self, stream: &[Fp4]) -> Option<Vec<usize>> {
        if stream.len() != self.stream_len {
            return None;
        }
        let mut mem = vec![Fp4::ZERO; self.mem];
        let mut next = 0usize;
        let mut sponge = [Fp::ZERO; WIDTH];
        let scalar = |mem: &[Fp4], a: Addr| -> Option<Fp> {
            let v = mem[a as usize];
            v.0[1..].iter().all(|x| x.is_zero()).then_some(v.0[0])
        };
        let block = |mem: &[Fp4], a: Addr| -> Option<[Fp; RATE]> {
            let mut b = [Fp::ZERO; RATE];
            for (k, x) in b.iter_mut().enumerate() {
                *x = scalar(mem, a + k as Addr)?;
            }
            Some(b)
        };
        for op in &self.ops {
            match *op {
                Op::Const { imm, out } => mem[out as usize] = imm,
                Op::Input { out } => {
                    mem[out as usize] = stream[next];
                    next += 1;
                }
                Op::Input8 { out } => {
                    for k in 0..RATE {
                        mem[out as usize + k] = stream[next + k];
                    }
                    next += RATE;
                }
                Op::InputDot { out, pows, acc, acc_out } => {
                    let mut sum = mem[acc as usize];
                    for k in 0..RATE {
                        let v = stream[next + k];
                        sum += v * mem[pows as usize + k];
                        mem[out as usize + k] = v;
                    }
                    next += RATE;
                    mem[acc_out as usize] = sum;
                }
                Op::MulAdd { a, b, d, out } => {
                    mem[out as usize] = mem[a as usize] * mem[b as usize] + mem[d as usize];
                }
                Op::AssertEq { a, b } => {
                    if mem[a as usize] != mem[b as usize] {
                        return None;
                    }
                }
                Op::Decompose { a, out } => {
                    let v = scalar(&mem, a)?.to_canonical();
                    for k in 0..8 {
                        mem[out as usize + k] = Fp4(core::array::from_fn(|c| Fp::new((v >> (4 * k + c)) & 1)));
                    }
                }
                Op::Select { src, comp, out } => {
                    mem[out as usize] = Fp4::from_base(mem[src as usize].0[comp as usize]);
                }
                Op::SpongeStart { data, cap0 } => {
                    let mut st = [Fp::ZERO; WIDTH];
                    st[..RATE].copy_from_slice(&block(&mem, data)?);
                    st[RATE] = cap0;
                    sponge = permute(st);
                }
                Op::Absorb { data } => {
                    for (x, y) in sponge.iter_mut().zip(&block(&mem, data)?) {
                        *x = x.add(y);
                    }
                    sponge = permute(sponge);
                }
                Op::CompressIn { dir, comp } => {
                    let mut sib = [Fp::ZERO; DIGEST];
                    for (k, x) in sib.iter_mut().enumerate() {
                        let v = stream[next + k];
                        if v.0[1..].iter().any(|y| !y.is_zero()) {
                            return None;
                        }
                        *x = v.0[0];
                    }
                    next += DIGEST;
                    let d: [Fp; DIGEST] = sponge[..DIGEST].try_into().unwrap();
                    let right = mem[dir as usize].0[comp as usize] == Fp::ONE;
                    let out = if right { compress(&sib, &d) } else { compress(&d, &sib) };
                    sponge = [Fp::ZERO; WIDTH];
                    sponge[..DIGEST].copy_from_slice(&out);
                }
                Op::Squeeze { out } => {
                    for k in 0..DIGEST {
                        mem[out as usize + k] = Fp4::from_base(sponge[k]);
                    }
                }
                Op::Inv { a, out } => mem[out as usize] = mem[a as usize].inverse().unwrap_or(Fp4::ZERO),
            }
        }
        Some(
            self.query_bits
                .iter()
                .map(|&b| {
                    (0..self.log_big_n)
                        .map(|i| (mem[b as usize + i / 4].0[i % 4].to_canonical() as usize) << i)
                        .sum()
                })
                .collect(),
        )
    }

    /// Verifies a chain proof with public values `public`.
    pub fn verify(&self, public: &[Fp], proof: &Proof) -> bool {
        if public.len() != NUM_PUBLIC || !self.fits(proof) {
            return false;
        }
        self.run(&self.stream(public, proof)).is_some_and(|sampled| sampled == proof.query_indices)
    }

    /// The program as the fam node reads it: little-endian words. A
    /// header (the magic `CHV1`, the memory's words, the stream's length,
    /// the number of operations, the public values, `log_big_n`, then the
    /// shape: the queries and each one's bits address; the tables, each
    /// its height, lookups and seven opening lengths, then its four row
    /// lengths; the rounds, each its values and fold grinding; the tree
    /// heights; the five grinding bits), then each operation as its code
    /// and fields ([`Op`], in declaration order; field elements
    /// canonical).
    pub fn to_bytes(&self) -> Vec<u8> {
        let s = &self.shape;
        let mut w: Vec<u32> = vec![
            MAGIC,
            self.mem as u32,
            self.stream_len as u32,
            self.ops.len() as u32,
            NUM_PUBLIC as u32,
            self.log_big_n as u32,
            s.queries as u32,
        ];
        w.extend(self.query_bits.iter().copied());
        w.push(s.tables.len() as u32);
        for ((log_n, aux, lens), rows) in s.tables.iter().zip(&s.rows) {
            w.extend([*log_n as u32, *aux as u32]);
            w.extend(lens.iter().map(|&l| l as u32));
            w.extend(rows.iter().map(|&l| l as u32));
        }
        w.push(s.rounds.len() as u32);
        for (values, bits) in &s.rounds {
            w.extend([*values as u32, *bits as u32]);
        }
        w.extend(s.heights.iter().map(|&h| h as u32));
        w.extend(s.grinding.iter().map(|&g| g as u32));
        for op in &self.ops {
            w.push(op.code());
            w.extend(op.fields());
        }
        w.iter().flat_map(|x| x.to_le_bytes()).collect()
    }
}

/// The words an operation reads and writes, as (address, count).
#[allow(clippy::type_complexity)]
fn op_access(op: &Op) -> (Vec<(Addr, usize)>, Vec<(Addr, usize)>) {
    match *op {
        Op::Const { out, .. } | Op::Input { out } => (vec![], vec![(out, 1)]),
        Op::Input8 { out } => (vec![], vec![(out, RATE)]),
        Op::InputDot { out, pows, acc, acc_out } => (vec![(pows, RATE), (acc, 1)], vec![(out, RATE), (acc_out, 1)]),
        Op::MulAdd { a, b, d, out } => (vec![(a, 1), (b, 1), (d, 1)], vec![(out, 1)]),
        Op::AssertEq { a, b } => (vec![(a, 1), (b, 1)], vec![]),
        Op::Decompose { a, out } => (vec![(a, 1)], vec![(out, 8)]),
        Op::Select { src, out, .. } => (vec![(src, 1)], vec![(out, 1)]),
        Op::SpongeStart { data, .. } | Op::Absorb { data } => (vec![(data, RATE)], vec![]),
        Op::CompressIn { dir, .. } => (vec![(dir, 1)], vec![]),
        Op::Squeeze { out } => (vec![], vec![(out, DIGEST)]),
        Op::Inv { a, out } => (vec![(a, 1)], vec![(out, 1)]),
    }
}

type Key = (StarkConfig, usize, usize);

/// The verifier for `config` and the heights, compiled once.
pub fn chain_verifier(config: &StarkConfig, log_n: usize, hash_log_n: usize) -> Arc<ChainVerifier> {
    static CACHE: Mutex<Vec<(Key, Arc<ChainVerifier>)>> = Mutex::new(Vec::new());
    let key = (*config, log_n, hash_log_n);
    if let Some((_, v)) = CACHE.lock().unwrap().iter().find(|(k, _)| *k == key) {
        return v.clone();
    }
    let v = Arc::new(ChainVerifier::new(config, log_n, hash_log_n));
    CACHE.lock().unwrap().push((key, v.clone()));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::stark::{prove_tables, verify_tables};

    const CONFIG: StarkConfig = StarkConfig { log_blowup: 3, num_queries: 4, pow_bits: 4, zk: true, commit_bits: 112 };

    fn transcript() -> Challenger {
        let mut c = Challenger::new();
        c.observe(Fp::new(DOM_CHAIN_PROOF));
        c
    }

    /// A proof of a small program under the chain proofs' transcript: to
    /// the verifier, a chain proof of its heights.
    fn small_proof(config: &StarkConfig, log_n: usize) -> (Vec<Fp>, Proof) {
        let mut c = Compiler::new();
        let vals: Vec<Fp> = (1..=20).map(Fp::new).collect();
        let b = c.scalar_inputs(&vals);
        let x = c.input(Fp4::from_base(Fp::new(5)));
        let y = c.mul(x, x);
        c.assert_scalar(y, Fp::new(25));
        c.hash_scalars(b, vals.len());
        c.assert_public();
        c.prog.reserve(config.blind_rows());
        c.prog.pad_to(log_n, log_n - 1);
        let (trace, hashes) = VmAir::generate_trace(&c.prog, &c.inputs).unwrap();
        let pre = c.prog.preprocess(config);
        let public = VmAir::public_values(&pre.root(), &crate::poseidon2::hash(&vals));
        let proof = prove_tables(config, &VmAir::tables(&trace, &hashes, &pre), &public, &mut transcript());
        assert_eq!(verify_tables(config, &VmAir::specs(&pre.root()), &public, &proof, &mut transcript()), Ok(()));
        (public, proof)
    }

    fn verifier_for(proof: &Proof) -> Arc<ChainVerifier> {
        chain_verifier(&CONFIG, proof.tables[0].log_n, proof.tables[1].log_n)
    }

    #[test]
    fn accepts_a_proof_and_reads_what_the_compiler_reads() {
        let (public, proof) = small_proof(&CONFIG, 9);
        let v = verifier_for(&proof);
        assert!(v.verify(&public, &proof));
        // The stream is the compiled verifier's witness without its hints,
        // and the program compiled for this proof is the same.
        let mut c = Compiler::new();
        let pubv = c.scalar_inputs(&public);
        let tables: [(&dyn DynAir, Option<Addr>); 2] = [(&VmAir, Some(pubv)), (&HashTableAir, None)];
        c.verify_stark(&tables, &CONFIG, &[Fp::new(DOM_CHAIN_PROOF)], pubv, NUM_PUBLIC, &proof);
        assert_eq!(c.prog.instrs.len(), v.ops.len());
        let mut hint_inputs = std::collections::HashSet::new();
        let mut at = 0usize;
        let mut hints = c.hints.iter().map(|h| h.0).peekable();
        for (pc, ins) in c.prog.instrs.iter().enumerate() {
            if hints.next_if_eq(&pc).is_some() {
                hint_inputs.insert(at);
            }
            at += match ins {
                Instr::Input { .. } => 1,
                Instr::Input8 { .. } | Instr::InputDot { .. } | Instr::CompressIn { .. } => RATE,
                _ => 0,
            };
        }
        let witness: Vec<Fp4> =
            c.inputs.iter().enumerate().filter(|(i, _)| !hint_inputs.contains(i)).map(|(_, x)| *x).collect();
        assert_eq!(witness, v.stream(&public, &proof));
        assert!(VmAir::execute(&c.prog, &c.inputs).is_ok());
        // The encoding: the header's first words, and every operation.
        let bytes = v.to_bytes();
        let word = |i: usize| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
        assert_eq!((word(0), word(1) as usize, word(2) as usize, word(3) as usize), (MAGIC, v.mem, v.stream_len, v.ops.len()));
    }

    #[test]
    fn rejects_what_the_native_verifier_rejects() {
        let (public, proof) = small_proof(&CONFIG, 9);
        let v = verifier_for(&proof);
        let root: [Fp; DIGEST] = public[..DIGEST].try_into().unwrap();
        let (iters, seed) = crate::stark::fuzz_params(300, 0x00c4_a19e);
        let fuzz = crate::stark::fuzz_proof(&proof, iters, seed, |p| v.verify(&public, p));
        assert!(fuzz.accepted.is_empty() && fuzz.panicked.is_empty(), "seed {seed}: {fuzz:?}");
        // Every byte changed, in a sample, decodes to a proof both
        // verifiers reject, or not at all.
        let bytes = proof.to_bytes();
        let step = (bytes.len() / 500).max(1);
        for i in (0..bytes.len()).step_by(step) {
            let mut b = bytes.clone();
            b[i] ^= 1 << (i % 8);
            if let Some(p) = Proof::from_bytes(&b) {
                assert!(!v.verify(&public, &p), "byte {i}");
                assert!(verify_tables(&CONFIG, &VmAir::specs(&root), &public, &p, &mut transcript()).is_err());
            }
        }
        // Other public values; a query index past the domain that names
        // the same leaves; a witness where nothing is ground.
        let mut bad = public.clone();
        bad[DIGEST] += Fp::ONE;
        assert!(!v.verify(&bad, &proof));
        let mut far = proof.clone();
        far.query_indices[0] += 1 << v.log_big_n;
        assert!(!v.verify(&public, &far));
        if let Some(k) = v.shape.grinding.iter().position(|&g| g == 0).filter(|&k| k < 4) {
            let mut w = proof.clone();
            w.grinding[k] = Fp::ONE;
            assert!(!v.verify(&public, &w));
        }
    }

    #[test]
    fn rejects_other_heights() {
        let (public, proof) = small_proof(&CONFIG, 9);
        let (public2, taller) = small_proof(&CONFIG, 10);
        assert_ne!(proof.tables[0].log_n, taller.tables[0].log_n);
        let v = verifier_for(&proof);
        assert!(v.verify(&public, &proof) && verifier_for(&taller).verify(&public2, &taller));
        assert!(!v.verify(&public2, &taller));
    }

    /// The fam node's copy of mainnet's chain-proof verifier.
    const FAM_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/chainver.bin");

    /// The recursive dev network's, for the fam node's sync test.
    const FAM_DEV_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/chainver_dev.bin");

    fn dev_recursive() -> Arc<ChainVerifier> {
        let c = crate::aggregate::DEV_RECURSIVE_CHAIN.unwrap();
        chain_verifier(&crate::aggregate::AggregatorParams::DEV_RECURSIVE.wrap, c.log_n, c.hash_log_n)
    }

    fn mainnet() -> Arc<ChainVerifier> {
        let c = crate::aggregate::MAINNET_CHAIN.unwrap();
        chain_verifier(&crate::aggregate::AggregatorParams::MAINNET.wrap, c.log_n, c.hash_log_n)
    }

    #[test]
    fn fam_verifier_is_current() {
        let file = std::fs::read(FAM_FILE).expect("node/src/user/node/chainver.bin: run write_fam_verifier");
        assert!(file == mainnet().to_bytes(), "chainver.bin is stale: run write_fam_verifier");
        let file = std::fs::read(FAM_DEV_FILE).expect("node/src/user/node/chainver_dev.bin: run write_fam_verifier");
        assert!(file == dev_recursive().to_bytes(), "chainver_dev.bin is stale: run write_fam_verifier");
    }

    /// The fam node's mainnet chain proof (`chainproof.bin`: its public
    /// values, then its bytes), which oscheck's `chainver` verifies there.
    #[test]
    fn fam_chain_proof_verifies() {
        let file = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/chainproof.bin")).unwrap();
        let public: Vec<Fp> =
            file[..4 * NUM_PUBLIC].chunks(4).map(|b| Fp::new(u32::from_le_bytes(b.try_into().unwrap()))).collect();
        let proof = Proof::from_bytes(&file[4 * NUM_PUBLIC..]).unwrap();
        let v = mainnet();
        assert!(v.verify(&public, &proof));
        let mut other = public.clone();
        other[DIGEST] += Fp::ONE;
        assert!(!v.verify(&other, &proof));
    }

    #[test]
    #[ignore = "writes node/src/user/node/chainver.bin and chainver_dev.bin"]
    fn write_fam_verifier() {
        for (v, path) in [(mainnet(), FAM_FILE), (dev_recursive(), FAM_DEV_FILE)] {
            std::fs::write(path, v.to_bytes()).unwrap();
            println!("{path}: {} operations, {} words of memory, a stream of {}", v.ops.len(), v.mem, v.stream_len);
        }
    }
}
