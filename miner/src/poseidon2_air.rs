//! AIR for the Poseidon2 permutation: one permutation per trace row.
//!
//! Every row holds the 16 input elements, the S-box intermediates of every
//! round, and the 16 output elements. The S-box `x^7` is split into two
//! degree-3 steps with witness columns `x3 = x^3` and `x7 = x3^2 * x`, so the
//! whole AIR has degree 3. Linear layers and round constants are applied to
//! expressions and cost no columns.
//!
//! Column layout, in execution order:
//!
//! ```text
//! input[16] | full rounds 0..4: (x3[16], x7[16]) | partial rounds 0..13: (x3, x7)
//!           | full rounds 4..8: (x3[16], x7[16]) | output[16]
//! ```
//!
//! Rows are independent; linking permutations into sponges, chains and
//! Merkle paths is the job of the circuits built on top of this one.

use crate::field::Field;
use crate::poseidon2::{Fp, INTERNAL_DIAG, RC_EXTERNAL_FINAL, RC_EXTERNAL_INITIAL, RC_INTERNAL, ROUNDS_P, WIDTH};
use crate::stark::{Air, Builder, Trace};

pub const HALF_FULL_ROUNDS: usize = 4;
const FULL_COLS: usize = 2 * WIDTH;

pub const COL_INPUT: usize = 0;
pub const COL_FULL_INITIAL: usize = WIDTH;
pub const COL_PARTIAL: usize = COL_FULL_INITIAL + HALF_FULL_ROUNDS * FULL_COLS;
pub const COL_FULL_FINAL: usize = COL_PARTIAL + 2 * ROUNDS_P;
pub const COL_OUTPUT: usize = COL_FULL_FINAL + HALF_FULL_ROUNDS * FULL_COLS;
pub const NUM_COLS: usize = COL_OUTPUT + WIDTH;

/// `M4 = circ(2, 3, 1, 1)` on each block of four, over any field.
fn matmul_m4<F: Field>(s: &mut [F; WIDTH]) {
    for x in s.chunks_exact_mut(4) {
        let t01 = x[0] + x[1];
        let t23 = x[2] + x[3];
        let t0123 = t01 + t23;
        let t01123 = t0123 + x[1];
        let t01233 = t0123 + x[3];
        x[3] = t01233 + x[0] + x[0];
        x[1] = t01123 + x[2] + x[2];
        x[0] = t01123 + t01;
        x[2] = t01233 + t23;
    }
}

/// External linear layer over any field.
pub fn matmul_external<F: Field>(s: &mut [F; WIDTH]) {
    matmul_m4(s);
    let mut col = [F::ZERO; 4];
    for (i, x) in s.iter().enumerate() {
        col[i % 4] += *x;
    }
    for (i, x) in s.iter_mut().enumerate() {
        *x += col[i % 4];
    }
}

/// Internal linear layer over any field.
pub fn matmul_internal<F: Field>(s: &mut [F; WIDTH]) {
    let mut sum = F::ZERO;
    for x in s.iter() {
        sum += *x;
    }
    for (x, v) in s.iter_mut().zip(&INTERNAL_DIAG) {
        *x = x.scale(*v) + sum;
    }
}

/// Walks the permutation, calling `sbox(round_input) -> round_output` for
/// every S-box application. With the real S-box this is the permutation;
/// the AIR passes a closure that reads witness columns and emits constraints.
fn walk<F: Field>(state: &mut [F; WIDTH], mut sbox: impl FnMut(F) -> F) {
    matmul_external(state);
    for rc in RC_EXTERNAL_INITIAL.iter() {
        for (x, c) in state.iter_mut().zip(rc) {
            *x = sbox(*x + F::from(*c));
        }
        matmul_external(state);
    }
    for rc in RC_INTERNAL.iter() {
        state[0] = sbox(state[0] + F::from(*rc));
        matmul_internal(state);
    }
    for rc in RC_EXTERNAL_FINAL.iter() {
        for (x, c) in state.iter_mut().zip(rc) {
            *x = sbox(*x + F::from(*c));
        }
        matmul_external(state);
    }
}

/// The permutation over any field, through the same code path as the AIR.
pub fn permute_generic<F: Field>(mut state: [F; WIDTH]) -> [F; WIDTH] {
    walk(&mut state, |x| {
        let x3 = x * x * x;
        x3 * x3 * x
    });
    state
}

/// The Poseidon2 permutation AIR.
pub struct Poseidon2Air;

impl Poseidon2Air {
    /// Fills one row for `input`.
    pub fn fill_row(input: &[Fp; WIDTH], row: &mut [Fp]) {
        assert_eq!(row.len(), NUM_COLS);
        row[COL_INPUT..COL_INPUT + WIDTH].copy_from_slice(input);
        let mut state = *input;
        let mut k = 0;
        walk(&mut state, |x| {
            let x3 = x * x * x;
            let x7 = x3 * x3 * x;
            let (c3, c7) = Self::sbox_cols(k);
            row[c3] = x3;
            row[c7] = x7;
            k += 1;
            x7
        });
        row[COL_OUTPUT..COL_OUTPUT + WIDTH].copy_from_slice(&state);
    }

    /// Column indices `(x3, x7)` of the `k`-th S-box in execution order.
    fn sbox_cols(k: usize) -> (usize, usize) {
        let full_initial = HALF_FULL_ROUNDS * WIDTH;
        if k < full_initial {
            let (r, i) = (k / WIDTH, k % WIDTH);
            let base = COL_FULL_INITIAL + r * FULL_COLS;
            (base + i, base + WIDTH + i)
        } else if k < full_initial + ROUNDS_P {
            let p = k - full_initial;
            (COL_PARTIAL + 2 * p, COL_PARTIAL + 2 * p + 1)
        } else {
            let k = k - full_initial - ROUNDS_P;
            let (r, i) = (k / WIDTH, k % WIDTH);
            let base = COL_FULL_FINAL + r * FULL_COLS;
            (base + i, base + WIDTH + i)
        }
    }

    /// Builds a trace with one row per input, padded with zero-input rows to
    /// a power of two of at least two rows.
    pub fn generate_trace(inputs: &[[Fp; WIDTH]]) -> Trace {
        let n = inputs.len().max(2).next_power_of_two();
        let mut values = vec![Fp::ZERO; n * NUM_COLS];
        let zero = [Fp::ZERO; WIDTH];
        for (i, row) in values.chunks_exact_mut(NUM_COLS).enumerate() {
            Self::fill_row(inputs.get(i).unwrap_or(&zero), row);
        }
        Trace::new(values, NUM_COLS)
    }

    /// Output elements of `row`.
    pub fn output(row: &[Fp]) -> [Fp; WIDTH] {
        row[COL_OUTPUT..COL_OUTPUT + WIDTH].try_into().unwrap()
    }
}

impl Air for Poseidon2Air {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        let row = b.local();
        let mut state: [F; WIDTH] = row[COL_INPUT..COL_INPUT + WIDTH].try_into().unwrap();
        let mut k = 0;
        let mut pending = Vec::with_capacity(2 * (2 * HALF_FULL_ROUNDS * WIDTH + ROUNDS_P));
        walk(&mut state, |x| {
            let (c3, c7) = Self::sbox_cols(k);
            let (x3, x7) = (row[c3], row[c7]);
            pending.push(x3 - x * x * x);
            pending.push(x7 - x3 * x3 * x);
            k += 1;
            x7
        });
        for c in pending {
            b.assert_zero(c);
        }
        for (i, s) in state.iter().enumerate() {
            b.assert_eq(row[COL_OUTPUT + i], *s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::ext::Fp4;
    use crate::poseidon2::permute;
    use crate::stark::{StarkConfig, check_constraints, prove, verify};
    use crate::test_util::Rng;

    fn random_state(rng: &mut Rng) -> [Fp; WIDTH] {
        core::array::from_fn(|_| rng.fp())
    }

    #[test]
    fn layout() {
        assert_eq!(crate::stark::measure_degree(&Poseidon2Air, 0), 3);
        assert_eq!(NUM_COLS, 16 + 4 * 32 + 13 * 2 + 4 * 32 + 16);
        let mut seen = std::collections::HashSet::new();
        for k in 0..2 * HALF_FULL_ROUNDS * WIDTH + ROUNDS_P {
            let (a, b) = Poseidon2Air::sbox_cols(k);
            assert!(a >= COL_FULL_INITIAL && b < COL_OUTPUT);
            assert!(seen.insert(a) && seen.insert(b), "column reuse at sbox {k}");
        }
    }

    #[test]
    fn generic_matches_native() {
        let mut rng = Rng::new(50);
        let kat: [Fp; WIDTH] = core::array::from_fn(|i| Fp::new(i as u32));
        assert_eq!(permute_generic(kat), permute(kat));
        for _ in 0..10 {
            let s = random_state(&mut rng);
            assert_eq!(permute_generic(s), permute(s));
            let ext: [Fp4; WIDTH] = s.map(Fp4::from_base);
            assert_eq!(permute_generic(ext), permute(s).map(Fp4::from_base));
        }
    }

    #[test]
    fn trace_rows_are_permutations_and_satisfy_constraints() {
        let mut rng = Rng::new(51);
        let inputs: Vec<[Fp; WIDTH]> = (0..5).map(|_| random_state(&mut rng)).collect();
        let trace = Poseidon2Air::generate_trace(&inputs);
        assert_eq!(trace.height(), 8);
        for (i, input) in inputs.iter().enumerate() {
            assert_eq!(Poseidon2Air::output(trace.row(i)), permute(*input));
        }
        assert_eq!(Poseidon2Air::output(trace.row(7)), permute([Fp::ZERO; WIDTH]));
        assert_eq!(check_constraints(&Poseidon2Air, &trace, &[]), Ok(()));

        let mut bad = trace.clone();
        bad.values[2 * NUM_COLS + COL_OUTPUT + 3] += Fp::ONE;
        assert_eq!(check_constraints(&Poseidon2Air, &bad, &[]).unwrap_err().0, 2);
        let mut bad = trace.clone();
        bad.values[NUM_COLS + COL_PARTIAL + 5] += Fp::ONE;
        assert_eq!(check_constraints(&Poseidon2Air, &bad, &[]).unwrap_err().0, 1);
    }

    #[test]
    fn prove_and_verify_permutations() {
        let config = StarkConfig { log_blowup: 1, num_queries: 16 };
        let mut rng = Rng::new(52);
        let inputs: Vec<[Fp; WIDTH]> = (0..3).map(|_| random_state(&mut rng)).collect();
        let trace = Poseidon2Air::generate_trace(&inputs);
        let tr = || {
            let mut c = Challenger::new();
            c.observe(Fp::new(0xa1));
            c
        };
        let proof = prove(&config, &Poseidon2Air, &trace, &[], &mut tr());
        assert_eq!(proof.tables[0].quotient_at_zeta_q.len(), 2);
        assert_eq!(verify(&config, &Poseidon2Air, &[], &proof, &mut tr()), Ok(()));

        // A trace claiming a wrong output does not verify.
        let mut bad = trace.clone();
        bad.values[COL_OUTPUT] += Fp::ONE;
        let proof = prove(&config, &Poseidon2Air, &bad, &[], &mut tr());
        assert!(verify(&config, &Poseidon2Air, &[], &proof, &mut tr()).is_err());
    }
}
