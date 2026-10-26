//! The hash table of the verifier machine: one Poseidon2 permutation per
//! row, in the order [`crate::vm_air`] performs them.
//!
//! The machine does no hashing itself. Each hashing instruction sends the
//! message `(index, kind, cap, dir, data[8], digest[8])` over the lookup
//! bus, and this table receives it on the row of that index. The table is
//! the hash machine of [`crate::hash_machine`] restricted to three ops,
//! plus a row counter, padded with pass rows:
//!
//! | kind | op       | permutation input                                     |
//! |------|----------|-------------------------------------------------------|
//! | 1    | start    | `data | cap, 0, ..`                                   |
//! | 2    | absorb   | previous output with `data` added to the rate         |
//! | 3    | compress | `(digest, data)`, or `(data, digest)` when `dir`      |
//!
//! and `digest` is the first eight elements of the output. `cap` and `dir`
//! are zero for the ops that do not use them. Indices are distinct and the
//! machine numbers its hashing instructions from zero, so the received rows
//! are the first rows of the table, in the machine's order: an absorb or
//! compress chains to the hashing instruction just before it. The machine
//! therefore only absorbs right after a start or another absorb.
//!
//! Only a small fraction of a verifier program hashes, so this table is
//! several times shorter than the machine's, which is the point: the
//! permutation's 314 columns are paid for once per hash, not once per
//! instruction.

use crate::field::Field;
use crate::hash_machine::{
    COL_ABSORB, COL_ACC, COL_CHAIN, COL_COMPRESS, COL_DATA, COL_DIR, COL_LOAD, COL_START, HashTraceBuilder,
    NUM_COLS as HM_COLS, eval_hash_machine,
};
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH};
use crate::poseidon2_air::COL_INPUT;
use crate::stark::{Air, Builder, Trace};

/// Row number, matched against the machine's count of hashing
/// instructions.
pub const COL_INDEX: usize = HM_COLS;
pub const NUM_COLS: usize = COL_INDEX + 1;

pub const KIND_START: u32 = 1;
pub const KIND_ABSORB: u32 = 2;
pub const KIND_COMPRESS: u32 = 3;

/// Number of values in a bus message.
pub const MESSAGE_LEN: usize = 4 + RATE + DIGEST;

/// Values of one bus message, in order.
pub fn message<F: Field>(index: F, kind: F, cap: F, dir: F, data: [F; RATE], digest: [F; DIGEST]) -> [F; MESSAGE_LEN] {
    let mut m = [F::ZERO; MESSAGE_LEN];
    m[..4].copy_from_slice(&[index, kind, cap, dir]);
    m[4..4 + RATE].copy_from_slice(&data);
    m[4 + RATE..].copy_from_slice(&digest);
    m
}

/// One permutation of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashOp {
    Start { data: [Fp; RATE], cap: Fp },
    Absorb { data: [Fp; RATE] },
    Compress { sibling: [Fp; DIGEST], right: bool },
}

pub struct HashTableAir;

impl Air for HashTableAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn max_constraint_degree(&self) -> usize {
        3
    }

    fn eval<F: Field>(&self, b: &mut Builder<'_, F>) {
        eval_hash_machine(b);
        let l = b.local();
        let n = b.next();
        b.assert_zero(l[COL_CHAIN]);
        b.assert_zero(l[COL_LOAD]);
        // The first row has nothing to chain to.
        b.when_first_row(l[COL_ABSORB] + l[COL_COMPRESS]);
        let start = l[COL_START];
        for k in 0..RATE {
            b.assert_zero(start * (l[COL_INPUT + k] - l[COL_DATA + k]));
        }
        for k in 1..RATE {
            b.assert_zero(start * l[COL_INPUT + RATE + k]);
        }
        b.when_first_row(l[COL_INDEX]);
        b.when_transition(n[COL_INDEX] - l[COL_INDEX] - F::ONE);

        let used = start + l[COL_ABSORB] + l[COL_COMPRESS];
        let kind = start + l[COL_ABSORB].scale(Fp::new(KIND_ABSORB)) + l[COL_COMPRESS].scale(Fp::new(KIND_COMPRESS));
        let cap = start * l[COL_INPUT + RATE];
        let data: [F; RATE] = core::array::from_fn(|k| l[COL_DATA + k]);
        let digest: [F; DIGEST] = core::array::from_fn(|k| l[COL_ACC + k]);
        b.lookup(false, used, &message(l[COL_INDEX], kind, cap, l[COL_DIR], data, digest));
    }
}

impl HashTableAir {
    /// Rows for `ops` in order, padded with pass rows to a power of two.
    pub fn generate_trace(ops: &[HashOp]) -> Trace {
        let n = ops.len().max(2).next_power_of_two();
        let mut b = HashTraceBuilder::new(NUM_COLS);
        for op in ops {
            match *op {
                HashOp::Start { data, cap } => {
                    let mut input = [Fp::ZERO; WIDTH];
                    input[..RATE].copy_from_slice(&data);
                    input[RATE] = cap;
                    b.start(input);
                    b.last_row_mut()[COL_DATA..COL_DATA + RATE].copy_from_slice(&data);
                }
                HashOp::Absorb { data } => {
                    b.absorb(data);
                }
                HashOp::Compress { sibling, right } => {
                    b.compress(sibling, right);
                }
            }
            let i = b.len() - 1;
            b.last_row_mut()[COL_INDEX] = Fp::new(i as u32);
        }
        while b.len() < n {
            b.pass();
            let i = b.len() - 1;
            b.last_row_mut()[COL_INDEX] = Fp::new(i as u32);
        }
        b.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::{compress, hash};
    use crate::stark::{check_constraints, measure_degree};

    #[test]
    fn degree_and_rows() {
        assert_eq!(measure_degree(&HashTableAir, 0), 3);
        let data: [Fp; RATE] = core::array::from_fn(|i| Fp::new(i as u32 + 1));
        let sib: [Fp; DIGEST] = core::array::from_fn(|i| Fp::new(50 + i as u32));
        let ops = [
            HashOp::Start { data, cap: Fp::new(16) },
            HashOp::Absorb { data },
            HashOp::Compress { sibling: sib, right: true },
        ];
        let trace = HashTableAir::generate_trace(&ops);
        assert_eq!(trace.height(), 4);
        // The sponge rows hash 16 values; the compress puts the sibling left.
        let mut sixteen = data.to_vec();
        sixteen.extend(data);
        let d1: [Fp; DIGEST] = trace.row(1)[COL_ACC..COL_ACC + DIGEST].try_into().unwrap();
        assert_eq!(d1, hash(&sixteen));
        assert_eq!(trace.row(2)[COL_ACC..COL_ACC + DIGEST], compress(&sib, &d1));
        assert_eq!(trace.row(3)[COL_INDEX], Fp::new(3));
        // Without the machine's messages the lookup terms do not cancel,
        // but every row constraint holds.
        assert_eq!(check_constraints(&HashTableAir, &trace, &[]), Err((usize::MAX, 0, "lookup sum")));
        let mut bad = trace.clone();
        bad.values[NUM_COLS + COL_INDEX] += Fp::ONE;
        assert_eq!(check_constraints(&HashTableAir, &bad, &[]).unwrap_err().0, 0);
    }
}
