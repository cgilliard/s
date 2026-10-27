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
        Self::from_leaf_hashes(leaf_hashes(flat, row_len))
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

/// Leaf hashes of the rows of a flat buffer of `row_len`-element rows.
pub fn leaf_hashes(flat: &[Fp], row_len: usize) -> Vec<Digest> {
    assert!(row_len > 0 && flat.len().is_multiple_of(row_len));
    let n = flat.len() / row_len;
    let row = |i: usize| &flat[i * row_len..(i + 1) * row_len];
    if n.is_multiple_of(LANES) {
        par_map_min(n / LANES, 128, |g| hash_batch(core::array::from_fn(|l| row(g * LANES + l))))
            .into_iter()
            .flatten()
            .collect()
    } else {
        par_map(n, |i| hash_row(row(i)))
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

// ---------------------------------------------------------------------------
// Batched openings
// ---------------------------------------------------------------------------

/// Walks the paths of leaves `indices` (with hashes `leaves`) of a tree of
/// `height` levels, level by level, and returns every path. A sibling is
/// asked of `supply(query, level)` only when no opened leaf lies under it
/// and it was not supplied before at that level: the others follow from
/// the openings. Encoder and decoder share this walk, so they agree on
/// which siblings travel.
fn walk_paths(
    height: usize,
    indices: &[usize],
    leaves: &[Digest],
    mut supply: impl FnMut(usize, usize) -> Option<Digest>,
) -> Option<Vec<Vec<Digest>>> {
    use std::collections::HashMap;
    let n = indices.len();
    let mask = if height >= usize::BITS as usize { usize::MAX } else { (1usize << height) - 1 };
    let mut pos: Vec<usize> = indices.iter().map(|i| i & mask).collect();
    let mut nodes: HashMap<usize, Digest> = HashMap::with_capacity(n);
    for (p, leaf) in pos.iter().zip(leaves) {
        nodes.entry(*p).or_insert(*leaf);
    }
    let mut paths = vec![Vec::with_capacity(height); n];
    for level in 0..height {
        let mut sent: HashMap<usize, Digest> = HashMap::new();
        for q in 0..n {
            let sib = pos[q] ^ 1;
            let d = match nodes.get(&sib).or_else(|| sent.get(&sib)) {
                Some(d) => *d,
                None => {
                    let d = supply(q, level)?;
                    sent.insert(sib, d);
                    d
                }
            };
            paths[q].push(d);
        }
        let mut next: HashMap<usize, Digest> = HashMap::with_capacity(n);
        for q in 0..n {
            let own = nodes[&pos[q]];
            next.entry(pos[q] >> 1).or_insert_with(|| {
                let sib = &paths[q][level];
                if pos[q] & 1 == 0 { compress(&own, sib) } else { compress(sib, &own) }
            });
            pos[q] >>= 1;
        }
        nodes = next;
    }
    Some(paths)
}

/// The siblings to send for opening leaves `indices` (hashes `leaves`,
/// paths `paths`) of one tree of `height` levels: those no other opening
/// determines, each once, in walk order. [`expand_paths`] rebuilds the
/// paths from them. For paths that do not belong to one tree the rebuilt
/// paths differ, and fail verification as the originals would.
pub fn compress_paths(height: usize, indices: &[usize], leaves: &[Digest], paths: &[&[Digest]]) -> Vec<Digest> {
    let mut out = Vec::new();
    walk_paths(height, indices, leaves, |q, level| {
        let d = paths[q][level];
        out.push(d);
        Some(d)
    });
    out
}

/// Rebuilds the paths of [`compress_paths`], reading the sent siblings
/// from `next`. `None` if `next` runs out.
pub fn expand_paths(
    height: usize,
    indices: &[usize],
    leaves: &[Digest],
    mut next: impl FnMut() -> Option<Digest>,
) -> Option<Vec<Vec<Digest>>> {
    walk_paths(height, indices, leaves, |_, _| next())
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
    fn batched_paths_roundtrip() {
        let mut rng = Rng::new(22);
        let rows: Vec<Vec<Fp>> = (0..64).map(|_| vec![rng.fp(), rng.fp()]).collect();
        let tree = MerkleTree::new(&rows);
        for indices in [vec![], vec![5], vec![5, 5], vec![4, 5], vec![0, 63, 31, 32, 7, 7, 8], (0..64).collect()] {
            let leaves: Vec<Digest> = indices.iter().map(|&i| hash_row(&rows[i])).collect();
            let paths: Vec<Vec<Digest>> = indices.iter().map(|&i| tree.open(i)).collect();
            let refs: Vec<&[Digest]> = paths.iter().map(|p| &p[..]).collect();
            let sent = compress_paths(6, &indices, &leaves, &refs);
            assert!(sent.len() <= 6 * indices.len());
            if indices.len() == 64 {
                assert!(sent.is_empty(), "all leaves open: nothing to send");
            }
            let mut it = sent.iter().copied();
            assert_eq!(expand_paths(6, &indices, &leaves, || it.next()).unwrap(), paths, "{indices:?}");
            assert!(it.next().is_none());
            if !sent.is_empty() {
                let mut short = sent[..sent.len() - 1].iter().copied();
                assert!(expand_paths(6, &indices, &leaves, || short.next()).is_none());
            }
        }
        // Two openings far apart share only the top: the siblings below it
        // all travel.
        let leaves = [hash_row(&rows[0]), hash_row(&rows[63])];
        let (p0, p63) = (tree.open(0), tree.open(63));
        assert_eq!(compress_paths(6, &[0, 63], &leaves, &[&p0, &p63]).len(), 10);
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
