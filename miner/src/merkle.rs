//! Merkle vector commitments over rows of field elements.
//!
//! Each leaf is a row of `Fp` values hashed with the length-binding Poseidon2
//! sponge from [`crate::poseidon2::hash`]; internal nodes use
//! [`crate::poseidon2::compress`]. The number of leaves must be a power of
//! two. Paths list siblings from the leaf level upwards.

use crate::parallel::{par_map, par_map_min};
use crate::poseidon2::{DIGEST, Fp, LANES, compress, compress_batch, hash, hash_batch};

pub type Digest = [Fp; DIGEST];

/// Hash of one leaf row.
pub fn hash_row(row: &[Fp]) -> Digest {
    hash(row)
}

/// A complete binary Merkle tree with all levels kept in memory.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// `levels[0]` are the leaf hashes; the last level holds only the root.
    levels: Vec<Vec<Digest>>,
}

impl MerkleTree {
    /// Builds a tree over `rows`. `rows.len()` must be a non-zero power of two.
    pub fn new(rows: &[Vec<Fp>]) -> MerkleTree {
        Self::from_leaf_hashes(par_map(rows.len(), |i| hash_row(&rows[i])))
    }

    /// Builds a tree over rows given as slices of a flat buffer of equal-size
    /// rows (`row_len` elements each).
    pub fn from_flat(flat: &[Fp], row_len: usize) -> MerkleTree {
        assert!(row_len > 0 && flat.len().is_multiple_of(row_len));
        let n = flat.len() / row_len;
        let row = |i: usize| &flat[i * row_len..(i + 1) * row_len];
        let leaves = if n.is_multiple_of(LANES) {
            par_map_min(n / LANES, 128, |g| hash_batch(core::array::from_fn(|l| row(g * LANES + l))))
                .into_iter()
                .flatten()
                .collect()
        } else {
            par_map(n, |i| hash_row(row(i)))
        };
        Self::from_leaf_hashes(leaves)
    }

    pub fn from_leaf_hashes(leaves: Vec<Digest>) -> MerkleTree {
        assert!(!leaves.is_empty() && leaves.len().is_power_of_two(), "leaf count must be a power of two");
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let pairs = prev.len() / 2;
            let next: Vec<Digest> = if pairs.is_multiple_of(LANES) {
                par_map_min(pairs / LANES, 128, |g| {
                    compress_batch(core::array::from_fn(|l| {
                        let i = g * LANES + l;
                        (&prev[2 * i], &prev[2 * i + 1])
                    }))
                })
                .into_iter()
                .flatten()
                .collect()
            } else {
                par_map(pairs, |i| compress(&prev[2 * i], &prev[2 * i + 1]))
            };
            levels.push(next);
        }
        MerkleTree { levels }
    }

    pub fn root(&self) -> Digest {
        self.levels.last().unwrap()[0]
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Path length, `log2(len)`.
    pub fn height(&self) -> usize {
        self.levels.len() - 1
    }

    /// Sibling hashes for `index`, leaf level first.
    pub fn open(&self, index: usize) -> Vec<Digest> {
        assert!(index < self.len());
        let mut path = Vec::with_capacity(self.height());
        let mut i = index;
        for level in &self.levels[..self.height()] {
            path.push(level[i ^ 1]);
            i >>= 1;
        }
        path
    }
}

/// Recomputes the root from a leaf row and its path.
pub fn root_from_path(index: usize, row: &[Fp], path: &[Digest]) -> Digest {
    let mut node = hash_row(row);
    let mut i = index;
    for sibling in path {
        node = if i & 1 == 0 { compress(&node, sibling) } else { compress(sibling, &node) };
        i >>= 1;
    }
    node
}

/// Checks that `row` is leaf `index` of a tree with `height` levels and the
/// given root.
pub fn verify(root: &Digest, height: usize, index: usize, row: &[Fp], path: &[Digest]) -> bool {
    path.len() == height && index < (1usize << height) && root_from_path(index, row, path) == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::Rng;

    #[test]
    fn open_and_verify_all_leaves() {
        let mut rng = Rng::new(20);
        for log_n in 0..=5 {
            let n = 1 << log_n;
            let rows: Vec<Vec<Fp>> = (0..n).map(|i| (0..(i % 3 + 1)).map(|_| rng.fp()).collect()).collect();
            let tree = MerkleTree::new(&rows);
            assert_eq!(tree.len(), n);
            assert_eq!(tree.height(), log_n);
            for (i, row) in rows.iter().enumerate() {
                let path = tree.open(i);
                assert!(verify(&tree.root(), log_n, i, row, &path), "n={n} i={i}");
                if n > 1 {
                    assert!(!verify(&tree.root(), log_n, i ^ 1, row, &path));
                    let mut bad = path.clone();
                    bad[0][0] += Fp::ONE;
                    assert!(!verify(&tree.root(), log_n, i, row, &bad));
                }
                let mut bad_row = row.clone();
                bad_row[0] += Fp::ONE;
                assert!(!verify(&tree.root(), log_n, i, &bad_row, &path));
                assert!(!verify(&tree.root(), log_n + 1, i, row, &path));
            }
        }
    }

    #[test]
    fn flat_matches_rows() {
        let mut rng = Rng::new(21);
        let flat: Vec<Fp> = (0..32).map(|_| rng.fp()).collect();
        let rows: Vec<Vec<Fp>> = flat.chunks(4).map(|c| c.to_vec()).collect();
        assert_eq!(MerkleTree::from_flat(&flat, 4).root(), MerkleTree::new(&rows).root());
        assert_ne!(MerkleTree::from_flat(&flat, 8).root(), MerkleTree::new(&rows).root());
    }
}
