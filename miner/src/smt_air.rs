//! Sparse Merkle tree updates as an AIR on the hash machine.
//!
//! The trace proves a sequence of leaf updates `(pos, old_leaf, new_leaf)`
//! against the depth-40 [`crate::state_tree`]: starting from a public
//! initial root, each update's old path must reach the current root, and
//! the new path's root becomes the current root. A list sponge absorbs
//! every update's position and leaves so the sequence can be bound to a
//! public digest. Public values: `initial_root[8] | final_root[8] |
//! list_hash[8]`.
//!
//! Schedule per update:
//!
//! ```text
//! list(0), list(1), list(2)      absorb pos_lo, pos_hi, old_leaf, new_leaf (18 elements)
//! for level in 0..40:
//!     old                        compress(old_node, sibling) by direction bit
//!     new                        compress(new_node, sibling), same sibling and direction
//! ```
//!
//! followed by another update or `done` rows. Directions come from a shift
//! register of the position bits (bit 0 is the current level's direction and
//! the register shifts after every level), so no level-indexed selection is
//! needed; a numeric level counter with an inverse gadget detects the last
//! level. Spending a position twice fails here: the second update's old leaf
//! is non-empty while the tree holds the empty digest, so its old path
//! cannot reach the root.

use crate::field::Field;
use crate::hash_machine::{
    COL_ABSORB, COL_ACC, COL_CHAIN, COL_COMPRESS, COL_DATA, COL_DIR, COL_LOAD, COL_PASS, COL_START, HashTraceBuilder,
    NUM_COLS as HM_COLS, eval_hash_machine,
};
use crate::poseidon2::{DIGEST, Fp, RATE, WIDTH, permute};
use crate::poseidon2_air::{COL_INPUT, COL_OUTPUT};
use crate::stark::{Air, Builder, Trace};
use crate::state_tree::{DEPTH, Digest, Proof};

const DOM_LIST: u32 = 0x20;
const LIST_ROWS: usize = 3;
const MASK30: u64 = (1 << 30) - 1;

// Row types.
pub const T_LIST: usize = HM_COLS;
pub const T_OLD: usize = HM_COLS + 1;
pub const T_NEW: usize = HM_COLS + 2;
pub const T_DONE: usize = HM_COLS + 3;
// Counters.
pub const C_LC: usize = HM_COLS + 4; // [LIST_ROWS] one-hot
pub const C_LEVEL: usize = C_LC + LIST_ROWS;
pub const C_LEVEL_INV: usize = C_LEVEL + 1;
pub const C_IS_LAST: usize = C_LEVEL_INV + 1;
// Registers.
pub const R_BITS: usize = C_IS_LAST + 1; // [DEPTH]
pub const R_ROOT: usize = R_BITS + DEPTH; // [DIGEST]
pub const R_OLD: usize = R_ROOT + DIGEST; // [DIGEST]
pub const R_NEW: usize = R_OLD + DIGEST; // [DIGEST]
pub const R_SIB: usize = R_NEW + DIGEST; // [DIGEST]
pub const R_SP: usize = R_SIB + DIGEST; // [WIDTH]
pub const NUM_COLS: usize = R_SP + WIDTH;

pub const PUB_INITIAL_ROOT: usize = 0;
pub const PUB_FINAL_ROOT: usize = DIGEST;
pub const PUB_LIST_HASH: usize = 2 * DIGEST;
pub const NUM_PUBLIC: usize = 3 * DIGEST;

/// Rows per update before padding.
pub const ROWS_PER_UPDATE: usize = LIST_ROWS + 2 * DEPTH;

/// One leaf update with the sibling path taken before the update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub position: u64,
    pub old_leaf: Digest,
    pub new_leaf: Digest,
    pub siblings: [Digest; DEPTH],
}

impl Update {
    pub fn new(position: u64, old_leaf: Digest, new_leaf: Digest, proof: &Proof) -> Update {
        Update { position, old_leaf, new_leaf, siblings: proof.siblings }
    }
}

fn pow2<F: Field>(k: usize) -> F {
    F::from_u32(1 << k)
}

fn list_capacity() -> [Fp; RATE] {
    let mut c = [Fp::ZERO; RATE];
    c[0] = Fp::new(DOM_LIST);
    c
}

/// The 18 absorbed elements of an update, in three blocks.
fn list_blocks(u: &Update) -> [[Fp; RATE]; LIST_ROWS] {
    let mut b = [[Fp::ZERO; RATE]; LIST_ROWS];
    b[0][0] = Fp::new((u.position & MASK30) as u32);
    b[0][1] = Fp::new((u.position >> 30) as u32);
    b[0][2..].copy_from_slice(&u.old_leaf[..6]);
    b[1][..2].copy_from_slice(&u.old_leaf[6..]);
    b[1][2..].copy_from_slice(&u.new_leaf[..6]);
    b[2][..2].copy_from_slice(&u.new_leaf[6..]);
    b
}

/// Native computation of the list digest the circuit produces.
pub fn list_hash(updates: &[Update]) -> Digest {
    let mut state = [Fp::ZERO; WIDTH];
    state[RATE..].copy_from_slice(&list_capacity());
    for u in updates {
        for block in list_blocks(u) {
            for (s, x) in state.iter_mut().zip(&block) {
                *s = s.add(x);
            }
            state = permute(state);
        }
    }
    state[..DIGEST].try_into().unwrap()
}

pub struct SmtAir;

impl Air for SmtAir {
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
        let public = b.public();
        let one = F::ONE;
        let pubv = |i: usize| -> F { public[i] };

        // --- row types ---
        let (list, old_t, new_t, done) = (l[T_LIST], l[T_OLD], l[T_NEW], l[T_DONE]);
        for t in [list, old_t, new_t, done] {
            b.assert_zero(t * t - t);
        }
        b.assert_eq(list + old_t + new_t + done, one);
        b.assert_eq(l[COL_START], list + old_t + new_t);
        b.assert_eq(l[COL_PASS], done);
        b.assert_zero(l[COL_ABSORB]);
        b.assert_zero(l[COL_CHAIN]);
        b.assert_zero(l[COL_COMPRESS]);
        b.assert_zero(l[COL_LOAD]);
        let lc: [F; LIST_ROWS] = core::array::from_fn(|i| l[C_LC + i]);
        for v in lc {
            b.assert_zero(v * v - v);
        }
        b.assert_eq(lc[0] + lc[1] + lc[2], list);
        b.when_first_row(one - list);
        b.when_first_row(one - lc[0]);
        b.when_last_row(one - done);

        // --- level counter and last-level gadget ---
        let level = l[C_LEVEL];
        let is_last = l[C_IS_LAST];
        let last_level = F::from_u32((DEPTH - 1) as u32);
        b.assert_zero(is_last * is_last - is_last);
        b.assert_zero(is_last * (level - last_level));
        b.assert_eq((level - last_level) * l[C_LEVEL_INV], one - is_last);
        b.assert_zero(list * level);
        b.when_transition(old_t * (n[C_LEVEL] - level));
        b.when_transition(new_t * (one - is_last) * (n[C_LEVEL] - level - one));

        // --- schedule ---
        let (n_list, n_old, n_new, n_done) = (n[T_LIST], n[T_OLD], n[T_NEW], n[T_DONE]);
        b.when_transition(list * lc[0] * (one - n_list));
        b.when_transition(list * lc[0] * (one - n[C_LC + 1]));
        b.when_transition(list * lc[1] * (one - n_list));
        b.when_transition(list * lc[1] * (one - n[C_LC + 2]));
        b.when_transition(list * lc[2] * (one - n_old));
        b.when_transition(list * lc[2] * n[C_LEVEL]);
        b.when_transition(old_t * (one - n_new));
        b.when_transition(new_t * (one - is_last) * (one - n_old));
        b.when_transition(new_t * is_last * (one - n_list - n_done));
        b.when_transition(new_t * is_last * (n_list - n[C_LC]));
        b.when_transition(done * (one - n_done));

        // --- position bits: shift register ---
        let bits: [F; DEPTH] = core::array::from_fn(|i| l[R_BITS + i]);
        let mut pos_lo = F::ZERO;
        let mut pos_hi = F::ZERO;
        for (i, bit) in bits.iter().enumerate() {
            b.assert_zero(*bit * *bit - *bit);
            if i < 30 {
                pos_lo += *bit * pow2::<F>(i);
            } else {
                pos_hi += *bit * pow2::<F>(i - 30);
            }
            let shifted = if i + 1 < DEPTH { bits[i + 1] } else { F::ZERO };
            b.when_transition(new_t * (one - is_last) * (n[R_BITS + i] - shifted));
            b.when_transition((one - new_t) * (n[R_BITS + i] - *bit));
        }
        let dir = l[COL_DIR];
        b.assert_zero(old_t * (dir - bits[0]));
        b.when_transition(old_t * (n[COL_DIR] - dir));

        // --- registers old, new, sib, root ---
        let end_of_update = new_t * is_last;
        for i in 0..DIGEST {
            let (o, nw, sib, root, acc, out) =
                (l[R_OLD + i], l[R_NEW + i], l[R_SIB + i], l[R_ROOT + i], l[COL_ACC + i], l[COL_OUTPUT + i]);
            // old: becomes this row's output after an old row, free after an update, else copied.
            b.when_transition(old_t * (n[R_OLD + i] - out));
            b.when_transition((one - old_t - end_of_update) * (n[R_OLD + i] - o));
            // new: becomes this row's output after a new row (except the last), free after an update.
            b.when_transition(new_t * (one - is_last) * (n[R_NEW + i] - out));
            b.when_transition((one - new_t) * (n[R_NEW + i] - nw));
            // sibling: witness on old rows, copied to the new row.
            b.when_transition(old_t * (n[R_SIB + i] - sib));
            // root: old path must land on it; new path replaces it.
            b.assert_zero(old_t * is_last * (acc - root));
            b.when_transition(end_of_update * (n[R_ROOT + i] - acc));
            b.when_transition((one - end_of_update) * (n[R_ROOT + i] - root));
            b.when_first_row(root - pubv(PUB_INITIAL_ROOT + i));
            b.when_last_row(root - pubv(PUB_FINAL_ROOT + i));
            // compress inputs
            let inp_lo = l[COL_INPUT + i];
            let inp_hi = l[COL_INPUT + RATE + i];
            b.assert_zero(old_t * (inp_lo - ((one - dir) * o + dir * sib)));
            b.assert_zero(old_t * (inp_hi - ((one - dir) * sib + dir * o)));
            b.assert_zero(new_t * (inp_lo - ((one - dir) * nw + dir * sib)));
            b.assert_zero(new_t * (inp_hi - ((one - dir) * sib + dir * nw)));
        }

        // --- list sponge ---
        let cap = list_capacity();
        for j in 0..WIDTH {
            let init: F = if j < RATE { F::ZERO } else { cap[j - RATE].into() };
            b.when_first_row(l[R_SP + j] - init);
            b.when_transition(list * (n[R_SP + j] - l[COL_OUTPUT + j]));
            b.when_transition((one - list) * (n[R_SP + j] - l[R_SP + j]));
        }
        for i in 0..RATE {
            b.assert_zero(list * (l[COL_INPUT + i] - l[R_SP + i] - l[COL_DATA + i]));
            b.assert_zero(list * (l[COL_INPUT + RATE + i] - l[R_SP + RATE + i]));
            b.when_last_row(l[R_SP + i] - pubv(PUB_LIST_HASH + i));
        }
        // absorbed data binds position and leaves
        let data: [F; RATE] = core::array::from_fn(|i| l[COL_DATA + i]);
        let o: [F; DIGEST] = core::array::from_fn(|i| l[R_OLD + i]);
        let nw: [F; DIGEST] = core::array::from_fn(|i| l[R_NEW + i]);
        let block0 = [pos_lo, pos_hi, o[0], o[1], o[2], o[3], o[4], o[5]];
        let block1 = [o[6], o[7], nw[0], nw[1], nw[2], nw[3], nw[4], nw[5]];
        let block2 = [nw[6], nw[7], F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO];
        for i in 0..RATE {
            b.assert_zero(list * lc[0] * (data[i] - block0[i]));
            b.assert_zero(list * lc[1] * (data[i] - block1[i]));
            b.assert_zero(list * lc[2] * (data[i] - block2[i]));
        }
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

struct Regs {
    bits: [Fp; DEPTH],
    root: Digest,
    old: Digest,
    new: Digest,
    sib: Digest,
    sp: [Fp; WIDTH],
    level: u32,
}

impl Regs {
    fn write(&self, row: &mut [Fp]) {
        row[R_BITS..R_BITS + DEPTH].copy_from_slice(&self.bits);
        row[R_ROOT..R_ROOT + DIGEST].copy_from_slice(&self.root);
        row[R_OLD..R_OLD + DIGEST].copy_from_slice(&self.old);
        row[R_NEW..R_NEW + DIGEST].copy_from_slice(&self.new);
        row[R_SIB..R_SIB + DIGEST].copy_from_slice(&self.sib);
        row[R_SP..R_SP + WIDTH].copy_from_slice(&self.sp);
        row[C_LEVEL] = Fp::new(self.level);
        let diff = Fp::new(self.level) - Fp::new((DEPTH - 1) as u32);
        let is_last = diff.is_zero();
        row[C_IS_LAST] = Fp::new(is_last as u32);
        row[C_LEVEL_INV] = if is_last { Fp::ZERO } else { diff.inverse().unwrap() };
    }
}

fn compress_input(node: &Digest, sib: &Digest, right: bool) -> [Fp; WIDTH] {
    let mut input = [Fp::ZERO; WIDTH];
    let (a, c) = if right { (sib, node) } else { (node, sib) };
    input[..DIGEST].copy_from_slice(a);
    input[DIGEST..].copy_from_slice(c);
    input
}

impl SmtAir {
    /// Builds the trace for `updates` applied in order from `initial_root`.
    /// Returns the trace and the final root.
    pub fn generate_trace(initial_root: Digest, updates: &[Update]) -> (Trace, Digest) {
        let mut b = HashTraceBuilder::new(NUM_COLS);
        let mut regs = Regs {
            bits: [Fp::ZERO; DEPTH],
            root: initial_root,
            old: [Fp::ZERO; DIGEST],
            new: [Fp::ZERO; DIGEST],
            sib: [Fp::ZERO; DIGEST],
            sp: {
                let mut sp = [Fp::ZERO; WIDTH];
                sp[RATE..].copy_from_slice(&list_capacity());
                sp
            },
            level: 0,
        };
        for u in updates {
            assert!(u.position < 1 << DEPTH);
            regs.bits = core::array::from_fn(|i| Fp::new(((u.position >> i) & 1) as u32));
            regs.old = u.old_leaf;
            regs.new = u.new_leaf;
            regs.level = 0;
            for (k, block) in list_blocks(u).iter().enumerate() {
                let mut input = regs.sp;
                for (s, x) in input.iter_mut().zip(block) {
                    *s = s.add(x);
                }
                b.start(input);
                let row = b.last_row_mut();
                row[T_LIST] = Fp::ONE;
                row[C_LC + k] = Fp::ONE;
                row[COL_DATA..COL_DATA + RATE].copy_from_slice(block);
                regs.write(row);
                regs.sp = b.state();
            }
            let mut old_node = u.old_leaf;
            let mut new_node = u.new_leaf;
            for level in 0..DEPTH {
                let right = (u.position >> level) & 1 == 1;
                regs.level = level as u32;
                regs.sib = u.siblings[level];
                b.start(compress_input(&old_node, &regs.sib, right));
                {
                    let row = b.last_row_mut();
                    row[T_OLD] = Fp::ONE;
                    row[COL_DIR] = Fp::new(right as u32);
                    regs.write(row);
                }
                old_node = b.acc();
                regs.old = old_node;
                b.start(compress_input(&new_node, &regs.sib, right));
                {
                    let row = b.last_row_mut();
                    row[T_NEW] = Fp::ONE;
                    row[COL_DIR] = Fp::new(right as u32);
                    regs.write(row);
                }
                new_node = b.acc();
                if level + 1 < DEPTH {
                    regs.new = new_node;
                    // shift the position bits
                    for i in 0..DEPTH - 1 {
                        regs.bits[i] = regs.bits[i + 1];
                    }
                    regs.bits[DEPTH - 1] = Fp::ZERO;
                }
            }
            assert_eq!(old_node, regs.root, "old path does not reach the current root");
            regs.root = new_node;
        }
        let final_root = regs.root;
        let n = b.len().max(2).next_power_of_two();
        while b.len() < n {
            b.pass();
            let row = b.last_row_mut();
            row[T_DONE] = Fp::ONE;
            regs.write(row);
        }
        (b.finish(), final_root)
    }

    pub fn public_values(initial_root: &Digest, final_root: &Digest, updates: &[Update]) -> Vec<Fp> {
        let mut v = Vec::with_capacity(NUM_PUBLIC);
        v.extend_from_slice(initial_root);
        v.extend_from_slice(final_root);
        v.extend_from_slice(&list_hash(updates));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::Challenger;
    use crate::stark::{StarkConfig, check_constraints, measure_degree, prove, verify};
    use crate::state_tree::{EMPTY, StateTree, empty_root, open_env};
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let p = std::env::temp_dir().join(format!("tabminer-smt-air-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn leaf(n: u32) -> Digest {
        core::array::from_fn(|i| Fp::new(n * 31 + i as u32))
    }

    /// Applies updates to a real tree, recording each as an `Update`.
    fn run_updates(name: &str, ops: &[(u64, Digest)]) -> (Digest, Vec<Update>, Digest) {
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let tree = StateTree::open(&env, &mut wtxn, "t").unwrap();
        let initial = tree.root(&wtxn).unwrap();
        let mut updates = Vec::new();
        for &(pos, new_leaf) in ops {
            let old_leaf = tree.get(&wtxn, pos).unwrap();
            let proof = tree.prove(&wtxn, pos).unwrap();
            updates.push(Update::new(pos, old_leaf, new_leaf, &proof));
            tree.update(&mut wtxn, pos, &new_leaf).unwrap();
        }
        let final_root = tree.root(&wtxn).unwrap();
        wtxn.abort();
        (initial, updates, final_root)
    }

    #[test]
    fn layout_and_degree() {
        assert_eq!(measure_degree(&SmtAir, NUM_PUBLIC), 3);
        assert_eq!(ROWS_PER_UPDATE, 83);
        assert_eq!(NUM_PUBLIC, 24);
    }

    #[test]
    fn insert_update_remove_sequence() {
        let ops = [
            (5u64, leaf(1)),          // insert
            ((1 << 40) - 1, leaf(2)), // insert at the top position
            (5, EMPTY),               // remove
            (1 << 20, leaf(3)),       // insert
            (1 << 20, leaf(4)),       // overwrite
        ];
        let (initial, updates, final_root) = run_updates("seq", &ops);
        assert_eq!(initial, empty_root());
        let (trace, root) = SmtAir::generate_trace(initial, &updates);
        assert_eq!(root, final_root);
        assert_eq!(trace.height(), 512);
        let public = SmtAir::public_values(&initial, &final_root, &updates);
        assert_eq!(check_constraints(&SmtAir, &trace, &public), Ok(()));

        let mut bad = public.clone();
        bad[PUB_FINAL_ROOT] += Fp::ONE;
        assert!(check_constraints(&SmtAir, &trace, &bad).is_err());
        let mut bad = public.clone();
        bad[PUB_LIST_HASH + 2] += Fp::ONE;
        assert!(check_constraints(&SmtAir, &trace, &bad).is_err());
        let mut bad = public.clone();
        bad[PUB_INITIAL_ROOT] += Fp::ONE;
        assert!(check_constraints(&SmtAir, &trace, &bad).is_err());

        // The list hash is order sensitive and update sensitive.
        let mut swapped = updates.clone();
        swapped.swap(0, 1);
        assert_ne!(list_hash(&swapped), list_hash(&updates));
        let mut changed = updates.clone();
        changed[3].new_leaf = leaf(9);
        assert_ne!(list_hash(&changed), list_hash(&updates));
    }

    #[test]
    fn empty_sequence_keeps_root() {
        let initial = leaf(7);
        let (trace, root) = SmtAir::generate_trace(initial, &[]);
        assert_eq!(root, initial);
        assert_eq!(trace.height(), 2);
        // No list rows at all: the first row must be a list row, so an empty
        // sequence is not provable. That is intended; a block always has rows.
        let public = SmtAir::public_values(&initial, &initial, &[]);
        assert!(check_constraints(&SmtAir, &trace, &public).is_err());
    }

    #[test]
    fn forged_updates_fail() {
        let (initial, updates, final_root) = run_updates("forge", &[(3, leaf(1)), (4, leaf(2))]);
        let (trace, _) = SmtAir::generate_trace(initial, &updates);
        let public = SmtAir::public_values(&initial, &final_root, &updates);
        assert_eq!(check_constraints(&SmtAir, &trace, &public), Ok(()));
        let w = NUM_COLS;

        // A wrong sibling at some level breaks the old path.
        let mut bad = trace.clone();
        let old_row = LIST_ROWS + 2 * 17;
        bad.values[old_row * w + R_SIB] += Fp::ONE;
        bad.values[(old_row + 1) * w + R_SIB] += Fp::ONE;
        assert!(check_constraints(&SmtAir, &bad, &public).is_err());

        // Claiming a different old leaf (the double-spend shape): the first
        // update says the leaf at 3 is already `leaf(1)`.
        let mut forged = updates.clone();
        forged[0].old_leaf = leaf(1);
        let result = std::panic::catch_unwind(|| SmtAir::generate_trace(initial, &forged));
        assert!(result.is_err(), "generator must refuse an old path that misses the root");

        // Same forgery but patched into the trace by hand: constraints catch it.
        let mut bad = trace.clone();
        for r in 0..LIST_ROWS {
            bad.values[r * w + R_OLD] += Fp::ONE;
        }
        bad.values[LIST_ROWS * w + R_OLD] += Fp::ONE;
        assert!(check_constraints(&SmtAir, &bad, &public).is_err());

        // Changing the position bits without changing the list data.
        let mut bad = trace.clone();
        for r in 0..=LIST_ROWS {
            let v = &mut bad.values[r * w + R_BITS + 1];
            *v = Fp::ONE - *v;
        }
        assert!(check_constraints(&SmtAir, &bad, &public).is_err());

        // Ending early: convert the second update's rows to done rows.
        let mut bad = trace.clone();
        for r in ROWS_PER_UPDATE..2 * ROWS_PER_UPDATE {
            for t in [T_LIST, T_OLD, T_NEW] {
                bad.values[r * w + t] = Fp::ZERO;
            }
            bad.values[r * w + T_DONE] = Fp::ONE;
            bad.values[r * w + COL_START] = Fp::ZERO;
            bad.values[r * w + COL_PASS] = Fp::ONE;
        }
        assert!(check_constraints(&SmtAir, &bad, &public).is_err());
    }

    #[test]
    fn prove_and_verify_updates() {
        let config = StarkConfig { log_blowup: 1, num_queries: 20, pow_bits: 0, zk: false, commit_bits: 0 };
        let (initial, updates, final_root) = run_updates("prove", &[(10, leaf(5)), (11, leaf(6)), (10, EMPTY)]);
        let (trace, _) = SmtAir::generate_trace(initial, &updates);
        assert_eq!(trace.height(), 256);
        let public = SmtAir::public_values(&initial, &final_root, &updates);
        let tr = || {
            let mut c = Challenger::new();
            c.observe(Fp::new(0xd4));
            c
        };
        let proof = prove(&config, &SmtAir, &trace, &public, &mut tr());
        assert_eq!(verify(&config, &SmtAir, &public, &proof, &mut tr()), Ok(()));
        let mut bad = public.clone();
        bad[PUB_FINAL_ROOT + 1] += Fp::ONE;
        assert!(verify(&config, &SmtAir, &bad, &proof, &mut tr()).is_err());
    }
}
