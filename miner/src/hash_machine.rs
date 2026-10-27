//! Hash machine: Poseidon2 permutations linked row to row.
//!
//! Every row is one permutation (the columns of [`Poseidon2Air`]) plus an
//! operation that says how its input is derived from the previous row:
//!
//! | op         | input of this row                                        |
//! |------------|----------------------------------------------------------|
//! | `start`    | free witness                                             |
//! | `absorb`   | previous output with `data` added to the rate            |
//! | `chain`    | previous digest in the rate, `data` as the capacity      |
//! | `compress` | `(digest, data)` or `(data, digest)` by `dir`            |
//! | `pass`     | no permutation is used; the digest is carried unchanged  |
//! | `load`     | no permutation is used; the digest becomes `data`        |
//!
//! The digest `acc` is the first eight output elements of the last non-pass
//! row. `absorb` continues a sponge with the full 16-element state; `chain`
//! and `compress` consume only the digest, which is what WOTS chains, XMSS
//! authentication paths, and the sparse state tree need. `pass` rows let a
//! WOTS chain of variable length occupy a fixed number of rows.
//!
//! Column layout: `perm[NUM_PERM_COLS] | start absorb chain compress pass
//! load | dir | data[8] | acc[8]`. Circuits built on this machine append their own
//! columns after these and add their own constraints.

use crate::field::Field;
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH};
use crate::poseidon2_air::{COL_INPUT, COL_OUTPUT, NUM_COLS as NUM_PERM_COLS, Poseidon2Air};
use crate::stark::{Air, Builder, Trace};

pub const COL_START: usize = NUM_PERM_COLS;
pub const COL_ABSORB: usize = COL_START + 1;
pub const COL_CHAIN: usize = COL_START + 2;
pub const COL_COMPRESS: usize = COL_START + 3;
pub const COL_PASS: usize = COL_START + 4;
pub const COL_LOAD: usize = COL_START + 5;
pub const COL_DIR: usize = COL_START + 6;
pub const COL_DATA: usize = COL_DIR + 1;
pub const COL_ACC: usize = COL_DATA + DIGEST;
pub const NUM_COLS: usize = COL_ACC + DIGEST;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Start,
    Absorb,
    Chain,
    Compress { right: bool },
    Pass,
    Load,
}

/// Emits the hash machine constraints for the columns `local[..NUM_COLS]`
/// and `next[..NUM_COLS]`. Call once from the enclosing AIR's `eval`.
pub fn eval_hash_machine<F: Field>(b: &mut Builder<'_, F>) {
    Poseidon2Air.eval(b);
    let local = b.local();
    let next = b.next();

    let flags =
        [local[COL_START], local[COL_ABSORB], local[COL_CHAIN], local[COL_COMPRESS], local[COL_PASS], local[COL_LOAD]];
    for f in flags {
        b.assert_zero(f * f - f);
    }
    b.assert_eq(flags.iter().fold(F::ZERO, |a, f| a + *f), F::ONE);
    let dir = local[COL_DIR];
    b.assert_zero(dir * dir - dir);
    // No first-row rule: the digest is meaningful only after the first
    // start/load row, and enclosing circuits never consume it before that.

    // acc is the permutation output on active rows, data on load rows.
    let active = F::ONE - local[COL_PASS] - local[COL_LOAD];
    for i in 0..DIGEST {
        b.assert_zero(active * (local[COL_ACC + i] - local[COL_OUTPUT + i]));
        b.assert_zero(local[COL_LOAD] * (local[COL_ACC + i] - local[COL_DATA + i]));
    }

    // Transition: how the next row's input and acc follow from this row.
    let (n_absorb, n_chain, n_compress, n_pass) =
        (next[COL_ABSORB], next[COL_CHAIN], next[COL_COMPRESS], next[COL_PASS]);
    let n_dir = next[COL_DIR];
    for i in 0..RATE {
        let n_in_lo = next[COL_INPUT + i];
        let n_in_hi = next[COL_INPUT + RATE + i];
        let n_data = next[COL_DATA + i];
        let prev_out_lo = local[COL_OUTPUT + i];
        let prev_out_hi = local[COL_OUTPUT + RATE + i];
        let prev_acc = local[COL_ACC + i];

        b.when_transition(n_absorb * (n_in_lo - prev_out_lo - n_data));
        b.when_transition(n_absorb * (n_in_hi - prev_out_hi));

        b.when_transition(n_chain * (n_in_lo - prev_acc));
        b.when_transition(n_chain * (n_in_hi - n_data));

        let left = (F::ONE - n_dir) * prev_acc + n_dir * n_data;
        let right = (F::ONE - n_dir) * n_data + n_dir * prev_acc;
        b.when_transition(n_compress * (n_in_lo - left));
        b.when_transition(n_compress * (n_in_hi - right));

        b.when_transition(n_pass * (next[COL_ACC + i] - prev_acc));
    }
}

/// Builds a hash machine trace row by row, tracking the running state.
pub struct HashTraceBuilder {
    width: usize,
    rows: Vec<Fp>,
    state: [Fp; WIDTH],
    acc: [Fp; DIGEST],
}

impl Default for HashTraceBuilder {
    fn default() -> Self {
        Self::new(NUM_COLS)
    }
}

impl HashTraceBuilder {
    /// `width` is the total row width of the enclosing AIR (at least
    /// `NUM_COLS`); extra columns are left zero for the caller to fill.
    pub fn new(width: usize) -> HashTraceBuilder {
        assert!(width >= NUM_COLS);
        HashTraceBuilder { width, rows: Vec::new(), state: [Fp::ZERO; WIDTH], acc: [Fp::ZERO; DIGEST] }
    }

    pub fn len(&self) -> usize {
        self.rows.len() / self.width
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Current digest (first eight elements of the last active output).
    pub fn acc(&self) -> [Fp; DIGEST] {
        self.acc
    }

    /// Full state after the last row.
    pub fn state(&self) -> [Fp; WIDTH] {
        self.state
    }

    /// Mutable access to the most recent row, for circuit-specific columns.
    pub fn last_row_mut(&mut self) -> &mut [Fp] {
        let w = self.width;
        let n = self.rows.len();
        &mut self.rows[n - w..]
    }

    fn push(&mut self, op: Op, input: [Fp; WIDTH], data: [Fp; DIGEST]) -> usize {
        let idx = self.len();
        let mut row = vec![Fp::ZERO; self.width];
        Poseidon2Air::fill_row(&input, &mut row[..NUM_PERM_COLS]);
        let out = Poseidon2Air::output(&row);
        let flag = match op {
            Op::Start => COL_START,
            Op::Absorb => COL_ABSORB,
            Op::Chain => COL_CHAIN,
            Op::Compress { right } => {
                row[COL_DIR] = if right { Fp::ONE } else { Fp::ZERO };
                COL_COMPRESS
            }
            Op::Pass => COL_PASS,
            Op::Load => COL_LOAD,
        };
        row[flag] = Fp::ONE;
        row[COL_DATA..COL_DATA + DIGEST].copy_from_slice(&data);
        match op {
            Op::Pass => {}
            Op::Load => self.acc = data,
            _ => {
                self.state = out;
                self.acc = out[..DIGEST].try_into().unwrap();
            }
        }
        row[COL_ACC..COL_ACC + DIGEST].copy_from_slice(&self.acc);
        self.rows.extend_from_slice(&row);
        idx
    }

    /// Starts a fresh permutation from `input`.
    pub fn start(&mut self, input: [Fp; WIDTH]) -> usize {
        self.push(Op::Start, input, [Fp::ZERO; DIGEST])
    }

    /// Absorbs `block` into the rate of the running sponge state.
    pub fn absorb(&mut self, block: [Fp; RATE]) -> usize {
        let mut input = self.state;
        for (s, x) in input.iter_mut().zip(&block) {
            *s = s.add(x);
        }
        self.push(Op::Absorb, input, block)
    }

    /// One chain step: permutes `(acc, capacity)`.
    pub fn chain(&mut self, capacity: [Fp; DIGEST]) -> usize {
        let mut input = [Fp::ZERO; WIDTH];
        input[..DIGEST].copy_from_slice(&self.acc);
        input[DIGEST..].copy_from_slice(&capacity);
        self.push(Op::Chain, input, capacity)
    }

    /// Merkle step: permutes `(acc, sibling)` or `(sibling, acc)`.
    pub fn compress(&mut self, sibling: [Fp; DIGEST], right: bool) -> usize {
        let mut input = [Fp::ZERO; WIDTH];
        if right {
            input[..DIGEST].copy_from_slice(&sibling);
            input[DIGEST..].copy_from_slice(&self.acc);
        } else {
            input[..DIGEST].copy_from_slice(&self.acc);
            input[DIGEST..].copy_from_slice(&sibling);
        }
        self.push(Op::Compress { right }, input, sibling)
    }

    /// A row that carries the digest unchanged.
    pub fn pass(&mut self) -> usize {
        self.push(Op::Pass, [Fp::ZERO; WIDTH], [Fp::ZERO; DIGEST])
    }

    /// A row that sets the digest to `digest` without a permutation.
    pub fn load(&mut self, digest: [Fp; DIGEST]) -> usize {
        self.push(Op::Load, [Fp::ZERO; WIDTH], digest)
    }

    /// Pads with pass rows to a power of two (at least two rows) and
    /// returns the trace.
    pub fn finish(mut self) -> Trace {
        let n = self.len().max(2).next_power_of_two();
        while self.len() < n {
            self.pass();
        }
        Trace::new(self.rows, self.width)
    }
}

/// The bare hash machine as an AIR: public values are the final digest.
pub struct HashMachineAir;

impl Air for HashMachineAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        eval_hash_machine(b);
        let local = b.local();
        let public = b.public();
        if public.len() >= DIGEST {
            for i in 0..DIGEST {
                let want: F = public[i];
                b.when_last_row(local[COL_ACC + i] - want);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::merkle::{MerkleTree, hash_row};
    use crate::poseidon2::{compress, hash, permute};
    use crate::stark::{StarkConfig, check_constraints, prove, verify};
    use crate::test_util::Rng;

    fn tr() -> Challenger {
        let mut c = Challenger::new();
        c.observe(Fp::new(0xb2));
        c
    }

    /// Rebuilds `poseidon2::hash` on the machine: capacity holds the length,
    /// blocks are absorbed one per row.
    fn sponge_rows(b: &mut HashTraceBuilder, input: &[Fp]) {
        let mut state = [Fp::ZERO; WIDTH];
        state[RATE] = Fp::from_u64(input.len() as u64);
        let mut blocks = input.chunks(RATE);
        let first = blocks.next().unwrap_or(&[]);
        for (s, x) in state.iter_mut().zip(first) {
            *s = s.add(x);
        }
        b.start(state);
        for chunk in blocks {
            let mut block = [Fp::ZERO; RATE];
            block[..chunk.len()].copy_from_slice(chunk);
            b.absorb(block);
        }
    }

    #[test]
    fn degree() {
        assert_eq!(crate::stark::measure_degree(&HashMachineAir, DIGEST), 3);
    }

    #[test]
    fn sponge_matches_native_hash() {
        let mut rng = Rng::new(60);
        for len in [0usize, 1, 8, 9, 20] {
            let input: Vec<Fp> = (0..len).map(|_| rng.fp()).collect();
            let mut b = HashTraceBuilder::default();
            sponge_rows(&mut b, &input);
            assert_eq!(b.acc(), hash(&input), "len {len}");
            let trace = b.finish();
            assert_eq!(check_constraints(&HashMachineAir, &trace, &hash(&input)), Ok(()));
        }
    }

    #[test]
    fn chain_and_compress_match_native() {
        let mut rng = Rng::new(61);
        let mut b = HashTraceBuilder::default();
        let seed: [Fp; WIDTH] = core::array::from_fn(|_| rng.fp());
        b.start(seed);
        let mut digest: [Fp; DIGEST] = permute(seed)[..DIGEST].try_into().unwrap();
        for _ in 0..5 {
            let cap: [Fp; DIGEST] = core::array::from_fn(|_| rng.fp());
            b.chain(cap);
            let mut s = [Fp::ZERO; WIDTH];
            s[..DIGEST].copy_from_slice(&digest);
            s[DIGEST..].copy_from_slice(&cap);
            digest = permute(s)[..DIGEST].try_into().unwrap();
            assert_eq!(b.acc(), digest);
            b.pass();
            assert_eq!(b.acc(), digest);
        }
        // Load replaces the digest; a chain from it matches the native chain.
        let loaded: [Fp; DIGEST] = core::array::from_fn(|_| rng.fp());
        b.load(loaded);
        assert_eq!(b.acc(), loaded);
        let cap: [Fp; DIGEST] = core::array::from_fn(|_| rng.fp());
        b.chain(cap);
        let mut s = [Fp::ZERO; WIDTH];
        s[..DIGEST].copy_from_slice(&loaded);
        s[DIGEST..].copy_from_slice(&cap);
        assert_eq!(b.acc(), permute(s)[..DIGEST]);
        // Merkle path over a real tree.
        let rows: Vec<Vec<Fp>> = (0..8).map(|i| vec![Fp::new(i)]).collect();
        let tree = MerkleTree::new(&rows);
        let index = 5;
        let path = tree.open(index);
        let mut leaf_state = [Fp::ZERO; WIDTH];
        leaf_state[RATE] = Fp::ONE; // hash of a 1-element row: length 1 in capacity
        leaf_state[0] = rows[index][0];
        b.start(leaf_state);
        assert_eq!(b.acc(), hash_row(&rows[index]));
        let mut i = index;
        for sib in &path {
            b.compress(*sib, i & 1 == 1);
            i >>= 1;
        }
        assert_eq!(b.acc(), tree.root());
        assert_eq!(compress(&path[0], &hash_row(&rows[index])), compress(&path[0], &hash_row(&rows[5])));
        let root = tree.root();
        let trace = b.finish();
        assert_eq!(check_constraints(&HashMachineAir, &trace, &root), Ok(()));

        // Breaking a link is caught: flip the direction of one compress.
        let mut bad = trace.clone();
        let r = trace.height() - 1; // last real row is before padding; find a compress row
        let mut compress_row = None;
        for row in (0..r).rev() {
            if bad.values[row * NUM_COLS + COL_COMPRESS] == Fp::ONE {
                compress_row = Some(row);
                break;
            }
        }
        let row = compress_row.unwrap();
        bad.values[row * NUM_COLS + COL_DIR] = Fp::ONE - bad.values[row * NUM_COLS + COL_DIR];
        assert_eq!(check_constraints(&HashMachineAir, &bad, &root).unwrap_err().0, row - 1);
        // Tampering with the carried digest on a pass row is caught.
        let mut bad = trace.clone();
        let last = trace.height() - 1;
        bad.values[last * NUM_COLS + COL_ACC] += Fp::ONE;
        assert!(check_constraints(&HashMachineAir, &bad, &root).is_err());
    }

    #[test]
    fn prove_and_verify_linked_hashes() {
        let config = StarkConfig { log_blowup: 1, num_queries: 16, pow_bits: 0, zk: false };
        let mut rng = Rng::new(62);
        let input: Vec<Fp> = (0..30).map(|_| rng.fp()).collect();
        let mut b = HashTraceBuilder::default();
        sponge_rows(&mut b, &input);
        let digest = b.acc();
        for _ in 0..3 {
            let cap: [Fp; DIGEST] = core::array::from_fn(|_| rng.fp());
            b.chain(cap);
        }
        let sib: [Fp; DIGEST] = core::array::from_fn(|_| rng.fp());
        b.compress(sib, true);
        let public = b.acc();
        let trace = b.finish();
        assert_ne!(public, digest);
        let proof = prove(&config, &HashMachineAir, &trace, &public, &mut tr());
        assert_eq!(verify(&config, &HashMachineAir, &public, &proof, &mut tr()), Ok(()));
        let mut wrong = public;
        wrong[0] += Fp::ONE;
        assert!(verify(&config, &HashMachineAir, &wrong, &proof, &mut tr()).is_err());

        // A prover that skips a chain link cannot produce a valid proof.
        let mut bad = trace.clone();
        let w = NUM_COLS;
        // Row 5 is a chain row (4 sponge rows then chains); make its input
        // independent of the previous digest by altering the previous acc.
        bad.values[4 * w + COL_ACC + 2] += Fp::ONE;
        assert!(check_constraints(&HashMachineAir, &bad, &public).is_err());
        let proof = prove(&config, &HashMachineAir, &bad, &public, &mut tr());
        assert!(verify(&config, &HashMachineAir, &public, &proof, &mut tr()).is_err());
    }
}
