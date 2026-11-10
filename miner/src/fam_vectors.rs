//! tabminer's values for the fam node (`node/src/user/node/`), written as
//! fam tests, each value from tabminer's own code (or Rust's integers where
//! tabminer uses them):
//! - `arith_vectors.fam` (docs/NODE.md step 1): the 32×32→64 product,
//!   BabyBear and its extension, the wide integers, the remainder of 64
//!   bits by 32, and `fri::log2_x256_ceil`;
//! - `poseidon2_vectors.fam` (step 2): the permutation, `compress`, `hash`,
//!   and Merkle roots from paths, verified and refused;
//! - `difficulty_vectors.fam` (step 4): ASERT's next target, a block's
//!   work, and a proof-of-work result against a target;
//! - `pow_vectors.fam` (step 4): the seed file's windows, dataset items,
//!   hashimoto, a header's hashes and its proof of work, checked and
//!   refused; plain code for a program under the OS, which has the file;
//! - `headers_vectors.fam` (step 4): a dev network's header chain fed to
//!   tabminer's own `Chain::accept_headers` one at a time, each verdict as
//!   it gave it, a heavier branch of fewer blocks taking over, and headers
//!   breaking each rule; plain code for a program under the OS.
//! - `statechain.bin` (step 5): a dev chain of blocks with spends and name
//!   operations, built and connected by tabminer's own `Chain`, with bodies
//!   breaking each state rule and tabminer's verdict on each; and
//!   `statesnap.bin` (step 6), the snapshot after its block 150 as
//!   tabminer serves it: its manifest, output parts and name parts; and
//!   the same chain as `statechain40.bin`, its outputs' positions from
//!   just below 2^32 (FIRST40), crossing it;
//! - `pool.bin` (step 7): transactions offered to tabminer's own
//!   `Mempool` on a dev chain whose outputs pay known keys, each verdict as
//!   it gave it, policy inputs spent through each kind of leaf, blocks
//!   mining some, the pool after each, XMSS signatures of other heights,
//!   verified and refused; and (step 8) proofs of outputs and names
//!   against the tip's state, as tabminer makes them.
//!
//! `write_fam_vectors` writes the files; `fam_vectors_are_current` checks
//! them.

#[cfg(test)]
mod tests {
    use crate::difficulty::U256;
    use crate::ext::Fp4;
    use crate::poseidon2::{Fp, P};
    use std::fmt::Write;

    const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/arith_vectors.fam");
    const P2_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/poseidon2_vectors.fam");
    const POW_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/pow_vectors.fam");
    const STATE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/statechain.bin");
    const SNAP_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/statesnap.bin");
    const STATE40_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/statechain40.bin");
    /// The 40-bit chain's first output position: its outputs, spends,
    /// commits, reveals and sweep cross 2^32 (the fam node's
    /// node/scripts/oscheck.sh gives its state test the same).
    const FIRST40: u64 = (1 << 32) - 24;
    const POOL_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/pool.bin");
    /// The block whose snapshot `statesnap.bin` holds.
    const SNAP_HEIGHT: u32 = 150;
    const HDR_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/headers_vectors.fam");
    const DIFF_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/difficulty_vectors.fam");

    /// splitmix64: the same values every run.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        fn u32(&mut self) -> u32 {
            self.next() as u32
        }
        /// Values below p, edges first.
        fn fp(&mut self, i: usize) -> u32 {
            const EDGES: [u32; 6] = [0, 1, 2, P - 1, P - 2, 1 << 30];
            if i < EDGES.len() { EDGES[i] } else { self.u32() % P }
        }
        /// 256-bit values of every size: some limbs zero, some all ones.
        fn u256(&mut self) -> U256 {
            let bits = (self.next() % 257) as u32;
            let mut v = U256([self.next(), self.next(), self.next(), self.next()]);
            if bits < 256 {
                v = v.shift_right(256 - bits);
            }
            if self.next().is_multiple_of(8) {
                v.0[(self.next() % 4) as usize] = u64::MAX;
            }
            v
        }
    }

    fn lit(v: u32) -> String {
        format!("{v:X} lit")
    }

    /// `words` as fam literals, least significant first.
    fn lits(words: &[u32]) -> String {
        words.iter().map(|w| lit(*w)).collect::<Vec<_>>().join(" ")
    }

    fn w256(v: U256) -> Vec<u32> {
        v.0.iter().flat_map(|l| [*l as u32, (*l >> 32) as u32]).collect()
    }

    fn w64s(v: &[u64]) -> Vec<u32> {
        v.iter().flat_map(|l| [*l as u32, (*l >> 32) as u32]).collect()
    }

    /// `words` stored at buffer `buf` (vx..vw).
    fn store(buf: &str, words: &[u32]) -> String {
        format!("{} {buf} @ {} v!", lits(words), lit(words.len() as u32))
    }

    /// Buffer `got` holds `words`.
    fn expect(got: &str, words: &[u32]) -> String {
        format!("{} vw @ {} v!  {got} @ vw @ {} wcmp 0 lit asrt_eq", lits(words), lit(words.len() as u32), lit(words.len() as u32))
    }

    fn fp4(c: [u32; 4]) -> Fp4 {
        Fp4(c.map(Fp::new))
    }

    fn generate() -> String {
        let mut r = Rng(0x5eed_a817);
        let mut o = String::new();
        o.push_str(
            "\\ arith_vectors.fam — tabminer's values for arith.fam (docs/NODE.md, step 1).\n\
             \\ Written by miner/src/fam_vectors.rs (`cargo test --lib write_fam_vectors\n\
             \\ -- --ignored`); not to be edited.  Run: tools/fam --test\n\
             \\ src/user/node/arith.fam src/user/node/arith_vectors.fam\n\n\
             : vx variable ;  : vy variable ;  : vz variable ;  : vw variable ;\n\
             : vinit  arinit vx @ 0= if 40 lit alloc vx !  40 lit alloc vy !  40 lit alloc vz !  40 lit alloc vw ! then ;\n\
             \\ v! ( x0 .. xn-1 a n -- )  the n values at a, x0 first.\n\
             : v!  begin dup while 1 lit - rot 2 lit pick 2 lit pick w! repeat 2drop ;\n\
             \\ canonical values in and out of the Montgomery words.\n\
             : cadd  tom swap tom f+ fromm ;\n\
             : csub  swap tom swap tom f- fromm ;\n\
             : cmul  tom swap tom fmul fromm ;\n\
             : cneg  tom fneg fromm ;\n\
             : cinv  tom finv fromm ;\n\
             : e4tom   4 lit 0 lit do dup i e4@ tom over i e4! loop drop ;\n\
             : e4from  4 lit 0 lit do dup i e4@ fromm over i e4! loop drop ;\n\n\
             Test {\n",
        );

        // The product.
        o.push_str("\tum_star {\n\t\tvinit\n");
        let edges = [0, 1, 0xffff, 0x10000, 0x7fff_ffff, 0x8000_0000, u32::MAX];
        let mut pairs: Vec<(u32, u32)> = edges.iter().flat_map(|a| edges.iter().map(move |b| (*a, *b))).collect();
        pairs.extend((0..40).map(|_| (r.u32(), r.u32())));
        for (a, b) in pairs {
            let p = a as u64 * b as u64;
            writeln!(o, "\t\t{} {} um* {} asrt_eq {} asrt_eq", lit(a), lit(b), lit((p >> 32) as u32), lit(p as u32)).unwrap();
        }
        o.push_str("\t}\n");

        // BabyBear.
        o.push_str("\tbabybear {\n\t\tvinit\n");
        for i in 0..40 {
            let (a, b) = (r.fp(i), r.fp(i / 6 + (i % 6) * 7));
            let (fa, fb) = (Fp::new(a), Fp::new(b));
            writeln!(o, "\t\t{} {} cadd {} asrt_eq", lit(a), lit(b), lit(fa.add(&fb).to_canonical())).unwrap();
            writeln!(o, "\t\t{} {} csub {} asrt_eq", lit(a), lit(b), lit(fa.sub(&fb).to_canonical())).unwrap();
            writeln!(o, "\t\t{} {} cmul {} asrt_eq", lit(a), lit(b), lit(fa.mul(&fb).to_canonical())).unwrap();
            writeln!(o, "\t\t{} cneg {} asrt_eq", lit(a), lit(fa.neg().to_canonical())).unwrap();
            if let Some(inv) = fa.inverse() {
                writeln!(o, "\t\t{} cinv {} asrt_eq", lit(a), lit(inv.to_canonical())).unwrap();
            }
        }
        o.push_str("\t}\n");

        // The extension.
        o.push_str("\tbabybear4 {\n\t\tvinit\n");
        for i in 0..24 {
            let a = [r.fp(i), r.fp(i + 1), r.fp(i + 2), r.fp(i + 3)];
            let b = [r.fp(i + 5), r.fp(i + 4), r.fp(i + 3), r.fp(i + 2)];
            let (fa, fb) = (fp4(a), fp4(b));
            let canon = |x: Fp4| x.0.map(|c| c.to_canonical());
            writeln!(o, "\t\t{}  {}  vx @ e4tom vy @ e4tom", store("vx", &a), store("vy", &b)).unwrap();
            writeln!(o, "\t\tvx @ vy @ vz @ e4mul vz @ e4from  {}", expect("vz", &canon(fa.mul(&fb)))).unwrap();
            writeln!(o, "\t\tvx @ vy @ vz @ e4+ vz @ e4from  {}", expect("vz", &canon(fa.add(&fb)))).unwrap();
            writeln!(o, "\t\tvx @ vy @ vz @ e4- vz @ e4from  {}", expect("vz", &canon(fa.sub(&fb)))).unwrap();
            if let Some(inv) = fa.inverse() {
                writeln!(o, "\t\tvx @ vz @ e4inv vz @ e4from  {}", expect("vz", &canon(inv))).unwrap();
            }
            // In place: a = a b.
            writeln!(o, "\t\tvx @ vy @ vx @ e4mul vx @ e4from  {}", expect("vx", &canon(fa.mul(&fb)))).unwrap();
        }
        o.push_str("\t}\n");

        // 256-bit integers: add, sub, compare, shifts, bits.
        o.push_str("\twide {\n\t\tvinit\n");
        for _ in 0..24 {
            let (a, b) = (r.u256(), if r.next().is_multiple_of(5) { r.u256().shift_right(64) } else { r.u256() });
            let (wa, wb) = (w256(a), w256(b));
            let mut sum = [0u32; 8];
            let mut carry = 0u64;
            for k in 0..8 {
                let t = wa[k] as u64 + wb[k] as u64 + carry;
                sum[k] = t as u32;
                carry = t >> 32;
            }
            let mut diff = [0u32; 8];
            let mut borrow = 0i64;
            for k in 0..8 {
                let t = wa[k] as i64 - wb[k] as i64 - borrow;
                diff[k] = t as u32;
                borrow = (t < 0) as i64;
            }
            if carry == 1 {
                assert_eq!(a.saturating_add(b), U256::MAX);
            }
            assert_eq!(a.checked_sub(b).is_none(), borrow == 1);
            let cmp = match a.cmp(&b) {
                core::cmp::Ordering::Less => u32::MAX,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => 1,
            };
            writeln!(o, "\t\t{}  {}", store("vx", &wa), store("vy", &wb)).unwrap();
            writeln!(o, "\t\tvx @ vy @ vz @ 8 lit wadd {} asrt_eq  {}", lit(carry as u32), expect("vz", &sum)).unwrap();
            writeln!(o, "\t\tvx @ vy @ vz @ 8 lit wsub {} asrt_eq  {}", lit(borrow as u32), expect("vz", &diff)).unwrap();
            writeln!(o, "\t\tvx @ vy @ 8 lit wcmp {} asrt_eq  vx @ vx @ 8 lit wcmp 0 lit asrt_eq", lit(cmp)).unwrap();
            writeln!(o, "\t\tvx @ 8 lit wbits {} asrt_eq", lit(a.bits())).unwrap();
            let s = (r.next() % 260) as u32;
            writeln!(o, "\t\tvx @ vz @ 8 lit {} wshl  {}", lit(s), expect("vz", &w256(a.shift_left(s)))).unwrap();
            writeln!(o, "\t\tvx @ vz @ 8 lit {} wshr  {}", lit(s), expect("vz", &w256(a.shift_right(s)))).unwrap();
        }
        // Shifting in place, by 0, 1, 31, 32, 33 and 255.
        let a = r.u256();
        for s in [0, 1, 31, 32, 33, 255] {
            writeln!(o, "\t\t{}  vx @ vx @ 8 lit {} wshl  {}", store("vx", &w256(a)), lit(s), expect("vx", &w256(a.shift_left(s)))).unwrap();
            writeln!(o, "\t\t{}  vx @ vx @ 8 lit {} wshr  {}", store("vx", &w256(a)), lit(s), expect("vx", &w256(a.shift_right(s)))).unwrap();
        }
        o.push_str("\t}\n");

        // Products: U256 by 64 bits (difficulty's), 64 by 64.
        o.push_str("\twide_mul {\n\t\tvinit\n");
        for _ in 0..16 {
            let (a, m) = (r.u256(), if r.next().is_multiple_of(4) { r.next() >> 40 } else { r.next() });
            writeln!(o, "\t\t{}  {}", store("vx", &w256(a)), store("vy", &w64s(&[m]))).unwrap();
            writeln!(o, "\t\tvx @ 8 lit vy @ 2 lit vz @ wmul  {}", expect("vz", &w64s(&a.mul_u64_wide(m)))).unwrap();
            let (x, y) = (r.next(), r.next());
            let p = x as u128 * y as u128;
            writeln!(o, "\t\t{}  {}", store("vx", &w64s(&[x])), store("vy", &w64s(&[y]))).unwrap();
            writeln!(o, "\t\tvx @ 2 lit vy @ 2 lit vz @ wmul  {}", expect("vz", &w64s(&[p as u64, (p >> 64) as u64]))).unwrap();
        }
        o.push_str("\t}\n");

        // Division: U256 (difficulty's quotient), and 128 bits with the
        // remainder; 64 bits by a word.
        o.push_str("\twide_div {\n\t\tvinit\n");
        for i in 0..12 {
            let a = r.u256();
            let mut b = if i % 3 == 0 { r.u256().shift_right(128) } else { r.u256() };
            if b == U256::ZERO {
                b = U256::ONE;
            }
            writeln!(o, "\t\t{}  {}", store("vx", &w256(a)), store("vy", &w256(b))).unwrap();
            writeln!(o, "\t\tvx @ vy @ vz @ vw @ 8 lit wdivmod  {}", expect("vz", &w256(a.div(b)))).unwrap();
        }
        for i in 0..12 {
            let a = (r.next() as u128) << 64 | r.next() as u128;
            let b = match i % 3 {
                0 => r.next() as u128 | 1,
                1 => (r.next() as u128) << 64 | r.next() as u128 | 1,
                _ => u128::MAX - (r.next() as u128),
            };
            let (q, m) = (a / b, a % b);
            writeln!(o, "\t\t{}  {}", store("vx", &w64s(&[a as u64, (a >> 64) as u64])), store("vy", &w64s(&[b as u64, (b >> 64) as u64]))).unwrap();
            // The remainder kept at vy, since expect() fills vw.
            writeln!(o, "\t\tvx @ vy @ vz @ vw @ 4 lit wdivmod  vw @ vy @ 4 lit wcopy").unwrap();
            writeln!(o, "\t\t{}  {}", expect("vz", &w64s(&[q as u64, (q >> 64) as u64])), expect("vy", &w64s(&[m as u64, (m >> 64) as u64]))).unwrap();
        }
        for _ in 0..24 {
            let x = r.next() >> (r.next() % 3 * 2);
            let d = match r.next() % 3 {
                0 => r.u32() | 1,
                1 => 180_872,
                _ => 53_795,
            };
            writeln!(o, "\t\t{} {} {} ud% {} asrt_eq", lit(x as u32), lit((x >> 32) as u32), lit(d), lit((x % d as u64) as u32)).unwrap();
        }
        o.push_str("\t}\n");

        // The grinding logarithm.
        o.push_str("\tlog2_x256 {\n\t\tvinit\n");
        let mut xs: Vec<u128> = vec![1, 2, 3, 4, 5, 255, 256, 1 << 62, (1 << 63) - 1, 1 << 63, 1 << 64, u128::MAX];
        xs.extend((0..16).map(|_| ((r.next() as u128) << 64 | r.next() as u128) >> (r.next() % 128)));
        for x in xs {
            let x = x.max(1);
            let want = crate::fri::log2_x256_ceil(x);
            writeln!(o, "\t\t{}  vx @ log2x256 {} asrt_eq", store("vx", &w64s(&[x as u64, (x >> 64) as u64])), lit(want as u32)).unwrap();
        }
        o.push_str("\t}\n}\n");
        o
    }

    /// `words` (canonical) at buffer `buf`, then into Montgomery form.
    fn store_mont(buf: &str, words: &[u32]) -> String {
        format!("{}  {buf} @ {} wtom", store(buf, words), lit(words.len() as u32))
    }

    fn canon(v: &[Fp]) -> Vec<u32> {
        v.iter().map(|x| x.to_canonical()).collect()
    }

    fn generate_poseidon2() -> String {
        use crate::merkle::{MerkleTree, root_from_path};
        use crate::poseidon2::{compress, hash, permute};
        let mut r = Rng(0x5eed_9052);
        let mut o = String::new();
        o.push_str(
            "\\ poseidon2_vectors.fam — tabminer's values for poseidon2.fam (docs/NODE.md,\n\
             \\ step 2).  Written by miner/src/fam_vectors.rs (`cargo test --lib\n\
             \\ write_fam_vectors -- --ignored`); not to be edited.  Run: tools/fam --test\n\
             \\ src/user/node/arith.fam src/user/node/poseidon2.fam src/user/node/poseidon2_vectors.fam\n\n\
             : vx variable ;  : vy variable ;  : vz variable ;  : vw variable ;  : vr variable ;\n\
             : vinit  p2init vx @ 0= if 400 lit alloc vx !  400 lit alloc vy !  400 lit alloc vz !  40 lit alloc vw !  40 lit alloc vr ! then ;\n\
             : v!  begin dup while 1 lit - rot 2 lit pick 2 lit pick w! repeat 2drop ;\n\
             : wtom   0 lit do dup i w@ tom over i w! loop drop ;\n\
             : wfrom  0 lit do dup i w@ fromm over i w! loop drop ;\n\n\
             Test {\n",
        );
        // The permutation.
        o.push_str("\tpermutation {\n\t\tvinit\n");
        let mut states: Vec<[u32; 16]> = vec![[0; 16], core::array::from_fn(|i| i as u32), [P - 1; 16]];
        states.extend((0..8).map(|_| core::array::from_fn(|_| r.u32() % P)));
        for st in states {
            let out = permute(st.map(Fp::new));
            writeln!(o, "\t\t{}  vx @ perm16  vx @ 10 lit wfrom  {}", store_mont("vx", &st), expect("vx", &canon(&out))).unwrap();
        }
        o.push_str("\t}\n");
        // compress and hash.
        o.push_str("\tsponge {\n\t\tvinit\n");
        for _ in 0..6 {
            let a: [u32; 8] = core::array::from_fn(|_| r.u32() % P);
            let b: [u32; 8] = core::array::from_fn(|_| r.u32() % P);
            let c = compress(&a.map(Fp::new), &b.map(Fp::new));
            writeln!(o, "\t\t{}  {}", store_mont("vx", &a), store_mont("vy", &b)).unwrap();
            writeln!(o, "\t\tvx @ vy @ vz @ compress  vz @ 8 lit wfrom  {}", expect("vz", &canon(&c))).unwrap();
            writeln!(o, "\t\tvx @ vy @ vx @ compress  vx @ 8 lit wfrom  {}", expect("vx", &canon(&c))).unwrap();
        }
        for n in [0usize, 1, 2, 7, 8, 9, 15, 16, 17, 23, 24, 25, 40] {
            let x: Vec<u32> = (0..n).map(|_| r.u32() % P).collect();
            let h = hash(&x.iter().map(|v| Fp::new(*v)).collect::<Vec<_>>());
            let put = if n == 0 { String::new() } else { store_mont("vx", &x) };
            writeln!(o, "\t\t{put}  vx @ {} vz @ hash  vz @ 8 lit wfrom  {}", lit(n as u32), expect("vz", &canon(&h))).unwrap();
        }
        o.push_str("\t}\n");
        // Merkle paths: trees of 1, 8 and 32 leaves, rows of 1 to 11.
        o.push_str("\tmerkle {\n\t\tvinit\n");
        for (leaves, width) in [(1usize, 3usize), (8, 5), (32, 1), (16, 11)] {
            let rows: Vec<Vec<Fp>> = (0..leaves).map(|_| (0..width).map(|_| Fp::new(r.u32() % P)).collect()).collect();
            let tree = MerkleTree::new(&rows);
            let root = tree.root();
            let h = tree.height();
            for index in [0, leaves / 2, leaves - 1] {
                let path = tree.open(index);
                assert_eq!(root_from_path(index, &rows[index], &path), root);
                let flat: Vec<u32> = path.iter().flat_map(|d| canon(d)).collect();
                let pathset = if flat.is_empty() { String::new() } else { store_mont("vy", &flat) };
                writeln!(o, "\t\t{}  {pathset}  {}", store_mont("vx", &canon(&rows[index])), store_mont("vr", &canon(&root))).unwrap();
                writeln!(
                    o,
                    "\t\tvx @ {} {} vy @ {} vz @ mroot  vz @ 8 lit wfrom  {}",
                    lit(width as u32), lit(index as u32), lit(h as u32), expect("vz", &canon(&root))
                ).unwrap();
                writeln!(o, "\t\tvr @ vx @ {} {} vy @ {} mverify assert", lit(width as u32), lit(index as u32), lit(h as u32)).unwrap();
                // Refused: another index (same path), a changed element, a
                // height one less, an index past the tree.
                if leaves > 1 {
                    writeln!(o, "\t\tvr @ vx @ {} {} vy @ {} mverify 0= assert", lit(width as u32), lit((index ^ 1) as u32), lit(h as u32)).unwrap();
                    writeln!(o, "\t\tvr @ vx @ {} {} vy @ {} mverify 0= assert", lit(width as u32), lit(index as u32), lit(h as u32 - 1)).unwrap();
                }
                writeln!(o, "\t\tvr @ vx @ {} {} vy @ {} mverify 0= assert", lit(width as u32), lit((leaves + index) as u32), lit(h as u32)).unwrap();
                writeln!(o, "\t\tvx @ 0 lit w@ ONE f+ vx @ 0 lit w!  vr @ vx @ {} {} vy @ {} mverify 0= assert", lit(width as u32), lit(index as u32), lit(h as u32)).unwrap();
            }
        }
        o.push_str("\t}\n}\n");
        o
    }


    fn generate_difficulty() -> String {
        use crate::chain::ChainParams;
        use crate::difficulty::{Asert, Schedule};
        use crate::pow::{Target, digest_to_u248_le};
        let mut r = Rng(0x5eed_d1ff);
        let mut o = String::new();
        o.push_str(
            "\\ difficulty_vectors.fam — tabminer's values for difficulty.fam (docs/NODE.md,\n\
             \\ step 4).  Written by miner/src/fam_vectors.rs (`cargo test --lib\n\
             \\ write_fam_vectors -- --ignored`); not to be edited.  Run: tools/fam --test\n\
             \\ src/user/node/arith.fam src/user/node/difficulty.fam src/user/node/difficulty_vectors.fam\n\n\
             : vx variable ;  : vy variable ;  : vz variable ;  : vw variable ;\n\
             : vinit  arinit dvinit vx @ 0= if 60 lit alloc vx !  60 lit alloc vy !  60 lit alloc vz !  60 lit alloc vw ! then ;\n\
             : v!  begin dup while 1 lit - rot 2 lit pick 2 lit pick w! repeat 2drop ;\n\n\
             Test {\n",
        );
        // Results against targets: around the result's own value.
        o.push_str("\tmeets {\n\t\tvinit\n");
        for i in 0..24 {
            let d: [u32; 8] = core::array::from_fn(|k| if i % 4 == 0 && k < i / 4 { 0 } else { r.u32() % P });
            let df = d.map(Fp::new);
            let v = U256::from_le_bytes(&digest_to_u248_le(&df));
            let t = match i % 3 {
                0 => v,
                1 => v.checked_sub(U256::ONE).unwrap_or(U256::ZERO),
                _ => r.u256(),
            };
            let met = Target::from(t).is_met_by(&df);
            writeln!(o, "\t\t{}  {}  vx @ vy @ meets {} asrt_eq", store("vx", &d), store("vy", &w256(t)), if met { "FFFFFFFF lit" } else { "0 lit" }).unwrap();
        }
        o.push_str("\t}\n");
        // A block's work.
        o.push_str("\tblock_work {\n\t\tvinit\n");
        let mut targets = vec![U256::ZERO, U256::ONE, U256::MAX, U256::MAX.shift_right(8), U256(crate::genesis::TARGET)];
        targets.extend((0..12).map(|_| r.u256()));
        for t in targets {
            let w = ChainParams::block_work(t);
            writeln!(o, "\t\t{}  vx @ vz @ bwork  {}", store("vx", &w256(t)), expect("vz", &w256(w))).unwrap();
        }
        o.push_str("\t}\n");
        // ASERT: mainnet's anchored at genesis, the dev networks' at block
        // 1, and others; blocks on schedule, ahead, behind, and far off.
        o.push_str("\tasert {\n\t\tvinit\n");
        let max = ChainParams::MAINNET.max_target;
        let mut scheds: Vec<Asert> = vec![
            Asert::anchored(0, crate::genesis::TIMESTAMP as i64, U256(crate::genesis::TARGET), max, Schedule::MAINNET),
            Asert::anchored(1, 1_767_300_000, ChainParams::DEV.genesis_target, max, ChainParams::DEV.schedule),
            Asert::anchored(1, 1_767_300_000, ChainParams::DEV_RECURSIVE.genesis_target, max, ChainParams::DEV_RECURSIVE.schedule),
        ];
        for _ in 0..4 {
            let sch = Schedule { block_time: 1 + (r.next() % 900) as i64, half_life: 1 + (r.next() % 300_000) as i64, from_first_block: false };
            scheds.push(Asert::anchored(r.next() % 1000, (r.next() % (1u64 << 40)) as i64, r.u256().shift_right(8), max, sch));
        }
        for a in &scheds {
            let at = a.anchor_parent_time as u64;
            let mut sw = vec![a.anchor_height as u32, at as u32, (at >> 32) as u32, a.half_life as u32, a.ideal_block_time as u32];
            sw.extend(w256(a.anchor_target));
            sw.extend(w256(a.max_target));
            writeln!(o, "\t\t{}", store("vx", &sw)).unwrap();
            for k in 0..14u64 {
                let dh = match k { 0 => 0, 1..=5 => r.next() % 1000, 6..=9 => r.next() % 1_000_000, _ => r.next() % (1 << 31) };
                let eh = a.anchor_height + dh;
                let ideal = a.anchor_parent_time + a.ideal_block_time * (dh as i64 + 1);
                let et: i64 = match k % 7 {
                    0 => ideal,
                    1 => ideal + (r.next() % 100_000) as i64,
                    2 => ideal - (r.next() % 100_000) as i64,
                    3 => ideal + (r.next() % (1 << 40)) as i64,
                    4 => ideal - (r.next() % (1 << 40)) as i64,
                    5 => r.next() as i64,
                    _ => ideal + (r.next() % 2000) as i64 - 1000,
                };
                let t = a.next_target(eh, et);
                writeln!(
                    o,
                    "\t\tvx @ {} {} {} vz @ asert  {}",
                    lit(eh as u32), lit(et as u32), lit((et as u64 >> 32) as u32), expect("vz", &w256(t))
                ).unwrap();
            }
        }
        o.push_str("\t}\n}\n");
        o
    }


    fn generate_pow() -> String {
        use crate::block::Header;
        use crate::pow::{PowParams, SeedText, Target, hashimoto};
        let mut r = Rng(0x5eed_9077);
        let mut o = String::new();
        o.push_str(
            "\\ pow_vectors.fam — tabminer's values for pow.fam (docs/NODE.md, step 4).\n\
             \\ Written by miner/src/fam_vectors.rs (`cargo test --lib write_fam_vectors\n\
             \\ -- --ignored`); not to be edited.  Plain code, for pow_test.fam (a\n\
             \\ program under the OS, after powinit): it counts the checks in vpass\n\
             \\ and vfail.\n\n\
             : vx variable ;  : vy variable ;  : vz variable ;  : vw variable ;  : vpass variable ;  : vfail variable ;\n\
             : vinit  vx @ 0= if 100 lit alloc vx !  100 lit alloc vy !  100 lit alloc vz !  100 lit alloc vw ! then ;\n\
             : v!  begin dup while 1 lit - rot 2 lit pick 2 lit pick w! repeat 2drop ;\n\
             : wfrom  0 lit do dup i w@ fromm over i w! loop drop ;\n\
             : vok  if vpass @ 1 lit + vpass ! else vfail @ 1 lit + vfail !  \"pow_vectors: check \" puts vpass @ vfail @ + u. \" failed\" puts 0A lit putc then ;\n\
             \\ vsame ( n -- )  vz holds the n words vw does.\n\
             : vsame  vz @ vw @ rot wcmp 0= vok ;\n\
             : vexp  vw @ swap v! ;\n\n\
             vinit\n",
        );
        let mainnet = SeedText::new(PowParams::MAINNET);
        let dev = SeedText::new(PowParams::DEV);
        let n = mainnet.windows();
        let vexp = |v: &[u32]| format!("{} {} vexp", lits(v), lit(v.len() as u32));
        // Windows: the first, the last two (overlapping), and others.
        let mut ws = vec![0, 1, 2, n - 2, n - 1];
        ws.extend((0..4).map(|_| (r.next() % n as u64) as usize));
        for w in ws {
            writeln!(o, "{} vz @ window  vz @ 8 lit wfrom  {}  8 lit vsame", lit(w as u32), vexp(&canon(&mainnet.window(w)))).unwrap();
        }
        // Items, the dataset's first and last among them.
        let mut items = vec![0usize, 1, 2, 1023, 1 << 19, (1 << 20) - 1];
        items.extend((0..3).map(|_| (r.next() % (1 << 20)) as usize));
        for i in items {
            writeln!(o, "{} vz @ item  vz @ 10 lit wfrom  {}  10 lit vsame", lit(i as u32), vexp(&canon(&mainnet.calc_dataset_item(i)))).unwrap();
        }
        // Headers: their hashes, a height past p, the largest timestamp.
        let header = |r: &mut Rng, height: u32, timestamp: u64| Header {
            prev_hash: core::array::from_fn(|_| Fp::new(r.u32() % P)),
            height,
            timestamp,
            body_commitment: core::array::from_fn(|_| Fp::new(r.u32() % P)),
            state_root: core::array::from_fn(|_| Fp::new(r.u32() % P)),
            aux: core::array::from_fn(|_| r.u32() as u8),
            mix: core::array::from_fn(|_| Fp::new(r.u32() % P)),
            nonce: core::array::from_fn(|_| r.u32() as u8),
        };
        let words = |h: &Header| -> Vec<u32> {
            h.to_bytes().chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
        };
        let put = |h: &Header| format!("{} vx @ {} v!", lits(&words(h)), lit(51));
        let hs = [header(&mut r, 1, 1_793_322_871), header(&mut r, u32::MAX, u64::MAX), header(&mut r, P, 1 << 60), { let t = r.next(); header(&mut r, 77, t) }];
        for h in &hs {
            writeln!(o, "{}  vx @ hdr-ok vok", put(h)).unwrap();
            writeln!(o, "vx @ vz @ powhash  vz @ 8 lit wfrom  {}  8 lit vsame", vexp(&canon(&h.pow_hash()))).unwrap();
            writeln!(o, "vx @ vz @ blockid  vz @ 8 lit wfrom  {}  8 lit vsame", vexp(&canon(&h.hash()))).unwrap();
        }
        // A digest not canonical.
        let mut w = words(&hs[0]);
        w[36] = P;
        writeln!(o, "{} vx @ {} v!  vx @ hdr-ok 0= vok", lits(&w), lit(51)).unwrap();
        // hashimoto, at the dev networks' items and at mainnet's.
        for (src, items) in [(&dev, 0x400u32), (&dev, 0x400), (&mainnet, 0x100000)] {
            let h = header(&mut r, 5, 1_800_000_000);
            let out = hashimoto(src, &h.pow_hash(), &h.nonce);
            writeln!(o, "{} pwitems !  {}  vx @ vy @ powhash", lit(items), put(&h)).unwrap();
            writeln!(o, "vy @ vx @ AC lit + vz @ vw @ hashmix  vz @ 8 lit wfrom  vw @ 8 lit wfrom  vw @ vy @ 8 lit wcopy").unwrap();
            writeln!(o, "{}  8 lit vsame  vy @ vz @ 8 lit wcopy  {}  8 lit vsame", vexp(&canon(&out.mix)), vexp(&canon(&out.result))).unwrap();
        }
        // A header's proof of work at the dev items: a nonce found for a
        // target one in sixteen meet, its true mix; then refused with
        // another mix, and against a harder target.
        let target = Target::from(U256::MAX.shift_right(12));
        let mut h = header(&mut r, 9, 1_800_000_600);
        let out = loop {
            let out = h.pow_output(&dev);
            if target.is_met_by(&out.result) {
                break out;
            }
            h.nonce[0] = h.nonce[0].wrapping_add(1);
            h.nonce[1] = h.nonce[1].wrapping_add((h.nonce[0] == 0) as u8);
        };
        h.mix = out.mix;
        assert!(h.verify_pow(&dev, &target));
        let tw = w256(target.value());
        writeln!(o, "400 lit pwitems !  {}  {} vy @ 8 lit v!", put(&h), lits(&tw)).unwrap();
        writeln!(o, "vx @ vy @ quickpow vok  vx @ vy @ fullpow vok").unwrap();
        let mut forged = h;
        forged.mix[3] = Fp::new((forged.mix[3].to_canonical() + 1) % P);
        assert!(!forged.verify_pow(&dev, &Target::MAX));
        writeln!(o, "{}  {} vy @ 8 lit v!  vx @ vy @ quickpow vok  vx @ vy @ fullpow 0= vok", put(&forged), lits(&w256(Target::MAX.value()))).unwrap();
        let hard = Target::from(U256::MAX.shift_right(200));
        assert!(!h.quick_pow_check(&hard));
        writeln!(o, "{}  {} vy @ 8 lit v!  vx @ vy @ quickpow 0= vok  vx @ vy @ fullpow 0= vok", put(&h), lits(&w256(hard.value()))).unwrap();
        o.push_str("100000 lit pwitems !\n");
        o
    }


    /// The nonces of [`dev_headers`]: each the least meeting its target,
    /// found once by [`nonce_for`]'s search (which prints the table when
    /// one no longer holds, after a change to the proof of work).
    const DEV_NONCES: [u64; 13] = [457442, 46356, 0, 0, 0, 0, 0, 0, 0, 0, 647779, 58059, 0];

    /// The least nonce from 0 at which `h` meets `target`, its mix set:
    /// `hint` if it is that, else searched (slowly) and reported.
    fn nonce_for(h: &mut crate::block::Header, target: &crate::pow::Target, data: &crate::pow::Dataset, hint: u64, found: &mut Vec<u64>) {
        let meets = |h: &crate::block::Header, n: u64| {
            let mut c = *h;
            c.nonce = crate::pow::nonce_from_u64(n);
            target.is_met_by(&c.pow_output(data).result)
        };
        let least = |h: &crate::block::Header| (0..).find(|&n| meets(h, n)).unwrap();
        let ok = meets(h, hint);
        let n = if ok { hint } else { least(h) };
        found.push(n);
        h.nonce = crate::pow::nonce_from_u64(n);
        h.mix = h.pow_output(data).mix;
    }

    fn dev_dataset() -> &'static crate::pow::Dataset {
        use crate::pow::{Dataset, PowParams, SeedText};
        static D: std::sync::OnceLock<Dataset> = std::sync::OnceLock::new();
        D.get_or_init(|| Dataset::generate(&SeedText::new(PowParams::DEV)))
    }

    /// The dev header chain: genesis, blocks 1 and 2 at genesis's target,
    /// eight blocks 3,000 s behind schedule (at the easiest target), a
    /// branch from block 1 of two blocks on schedule (each at genesis's
    /// target: more work in fewer blocks), and a block 11 on the first
    /// branch.
    fn dev_headers() -> (Vec<crate::block::Header>, Vec<crate::block::Header>, crate::block::Header) {
        use crate::block::Header;
        use crate::chain::ChainParams;
        let p = ChainParams::DEV;
        let data = dev_dataset();
        let g = p.genesis().header;
        let gt: crate::pow::Target = p.genesis_target.into();
        let easy: crate::pow::Target = p.max_target.into();
        let child = |parent: &Header, ts: u64, tag: u8| Header {
            prev_hash: parent.hash(),
            height: parent.height + 1,
            timestamp: ts,
            body_commitment: g.body_commitment,
            state_root: g.state_root,
            aux: [tag; 32],
            mix: [Fp::ZERO; 8],
            nonce: [0; 32],
        };
        let mut found = Vec::new();
        let mut hint = DEV_NONCES.iter().copied();
        let mut main = vec![g];
        let mut h1 = child(&g, g.timestamp + 5, 1);
        nonce_for(&mut h1, &gt, data, hint.next().unwrap(), &mut found);
        main.push(h1);
        let mut h2 = child(&h1, h1.timestamp + 3000, 2);
        nonce_for(&mut h2, &gt, data, hint.next().unwrap(), &mut found);
        main.push(h2);
        for k in 0..8 {
            let prev = *main.last().unwrap();
            let mut h = child(&prev, prev.timestamp + 1, 3 + k);
            nonce_for(&mut h, &easy, data, hint.next().unwrap(), &mut found);
            main.push(h);
        }
        let mut b2 = child(&h1, h1.timestamp + 1, 0x42);
        nonce_for(&mut b2, &gt, data, hint.next().unwrap(), &mut found);
        let mut b3 = child(&b2, b2.timestamp + 1, 0x43);
        nonce_for(&mut b3, &gt, data, hint.next().unwrap(), &mut found);
        let tip = main[10];
        let mut times: Vec<u64> = main[main.len() - 11..].iter().map(|h| h.timestamp).collect();
        times.sort();
        let mut h11 = child(&tip, times[5] + 1, 0x77);
        nonce_for(&mut h11, &easy, data, hint.next().unwrap(), &mut found);
        assert!(found == DEV_NONCES, "fam_vectors: DEV_NONCES no longer hold; set them to {found:?}");
        (main, vec![b2, b3], h11)
    }

    fn generate_headers() -> String {
        use crate::block::Header;
        use crate::chain::{AcceptAllProofs, Chain, ChainError, ChainParams};
        use crate::pow::{PowParams, SeedText};
        let p = ChainParams::DEV;
        let (main, branch, h11) = dev_headers();
        let dir = std::env::temp_dir().join(format!("tabminer-famhdr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let chain = Chain::open(&dir, 64 << 20, p, SeedText::new(PowParams::DEV), AcceptAllProofs).unwrap();
        chain.init_genesis(&p.genesis()).unwrap();
        let tip = main.last().unwrap();
        let now = branch[1].timestamp.max(tip.timestamp) + 60;
        let mut o = String::new();
        o.push_str(
            "\\ headers_vectors.fam — a dev network's header chain for headers.fam\n\
             \\ (docs/NODE.md, step 4), each verdict tabminer's own Chain::accept_headers\n\
             \\ gave it.  Written by miner/src/fam_vectors.rs (`cargo test --lib\n\
             \\ write_fam_vectors -- --ignored`); not to be edited.  Plain code, for\n\
             \\ headers_test.fam (a program under the OS, after powinit): it counts the\n\
             \\ checks in vpass and vfail.\n\n\
             : vx variable ;  : vy variable ;  : vpass variable ;  : vfail variable ;  : vn variable ;\n\
             : vinit  vx @ 0= if 100 lit alloc vx !  100 lit alloc vy ! then ;\n\
             : v!  begin dup while 1 lit - rot 2 lit pick 2 lit pick w! repeat 2drop ;\n\
             : vok  vn @ 1 lit + vn !  if vpass @ 1 lit + vpass ! else vfail @ 1 lit + vfail !  \"headers_vectors: check \" puts vn @ u. \" failed\" puts 0A lit putc then ;\n\
             : vnow variable ;  : vnow2 variable ;\n\
             \\ vh ( code -- )  the header at vx, offered now, gets code.\n\
             : vh  vx @ vnow @ vnow2 @ hacc  dup rot = dup 0= if \"  got \" puts over . 0A lit putc then vok drop ;\n\n\
             vinit\n",
        );
        // The network: ChainParams::DEV.
        let mut pw: Vec<u32> = vec![p.pow.log_dataset_items, p.pow.parents as u32, p.pow.accesses as u32];
        pw.extend(w256(p.genesis_target));
        pw.extend(w256(p.max_target));
        pw.extend([p.max_future_drift as u32, p.median_time_window as u32, p.final_height()]);
        pw.extend([p.schedule.block_time as u32, p.schedule.half_life as u32, p.schedule.from_first_block as u32]);
        assert_eq!(pw.len(), 25);
        let words = |h: &Header| -> Vec<u32> {
            h.to_bytes().chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
        };
        writeln!(o, "{} vy @ {} v!", lits(&pw), lit(pw.len() as u32)).unwrap();
        writeln!(o, "{} vx @ {} v!  vy @ vx @ 100 lit hinit", lits(&words(&main[0])), lit(51)).unwrap();
        writeln!(o, "{} vnow !  {} vnow2 !", lit(now as u32), lit((now >> 32) as u32)).unwrap();
        let code = |r: (usize, Option<ChainError>)| -> i32 {
            match r {
                (1, None) => 0,
                (0, None) => 1,
                (_, Some(ChainError::UnknownParent(_))) => -2,
                (_, Some(ChainError::BadHeight { .. })) => -3,
                (_, Some(ChainError::ChainEnded)) => -4,
                (_, Some(ChainError::TimestampTooOld { .. })) => -5,
                (_, Some(ChainError::TimestampTooNew { .. })) => -6,
                (_, Some(ChainError::BadProofOfWork)) => -7,
                other => panic!("unexpected verdict {other:?}"),
            }
        };
        let feed = |o: &mut String, h: &Header, what: &str| -> i32 {
            let c = code(chain.accept_headers(&[*h], now));
            writeln!(o, "\\ {what}\n{} vx @ {} v!  {} vh", lits(&words(h)), lit(51), lit(c as u32)).unwrap();
            c
        };
        let best = |o: &mut String, chain: &Chain<AcceptAllProofs>, what: &str| {
            let b = chain.best_header().unwrap();
            writeln!(o, "\\ the best header: {what}\n{} vy @ 8 lit v!  hbest hid vy @ 8 lit wcmp 0= vok", lits(&canon(&b.hash()))).unwrap();
            let _ = b;
        };
        for (k, h) in main[1..].iter().enumerate() {
            assert_eq!(feed(&mut o, h, &format!("block {}", k + 1)), 0);
        }
        best(&mut o, &chain, "block 10");
        assert_eq!(feed(&mut o, &main[2], "block 2 again: known"), 1);
        assert_eq!(feed(&mut o, &branch[1], "the branch's second before its first: its parent unknown"), -2);
        assert_eq!(feed(&mut o, &branch[0], "the branch's first"), 0);
        best(&mut o, &chain, "still block 10");
        assert_eq!(feed(&mut o, &branch[1], "the branch's second: more work in fewer blocks"), 0);
        best(&mut o, &chain, "the branch");
        // Headers breaking one rule each, on block 10 (no mining needed:
        // the rules before the proof of work fail first).
        let base = Header {
            prev_hash: tip.hash(),
            height: tip.height + 1,
            timestamp: tip.timestamp + 1,
            body_commitment: tip.body_commitment,
            state_root: tip.state_root,
            aux: [0x77; 32],
            mix: tip.mix,
            nonce: tip.nonce,
        };
        let mut bad = base;
        bad.height += 1;
        assert_eq!(feed(&mut o, &bad, "a wrong height"), -3);
        let median = {
            let mut t: Vec<u64> = main[main.len() - 11..].iter().map(|h| h.timestamp).collect();
            t.sort();
            t[5]
        };
        let mut bad = base;
        bad.timestamp = median;
        assert_eq!(feed(&mut o, &bad, "a timestamp at the median of the last eleven"), -5);
        let mut bad = base;
        bad.timestamp = now + p.max_future_drift + 1;
        assert_eq!(feed(&mut o, &bad, "a timestamp past the clock and its drift"), -6);
        let mut bad = base;
        bad.timestamp = median + 1;
        assert_eq!(feed(&mut o, &bad, "the median plus one, but a mix not the true one (the quick check passes at the easiest target)"), -7);
        let mut hard = base;
        hard.prev_hash = branch[1].hash();
        hard.height = branch[1].height + 1;
        hard.timestamp = branch[1].timestamp + 1;
        assert_eq!(feed(&mut o, &hard, "after the branch, at genesis's target, a nonce not mined"), -7);
        // And a good one, mined: stored, but less work than the branch.
        let good = h11;
        assert_eq!(good.prev_hash, base.prev_hash);
        assert_eq!(feed(&mut o, &good, "block 11, mined"), 0);
        best(&mut o, &chain, "still the branch");
        // A digest not canonical: refused as malformed before any rule.
        let mut w = words(&good);
        w[11] = P;
        writeln!(o, "\\ a digest not canonical\n{} vx @ {} v!  {} vh", lits(&w), lit(51), lit(-1i32 as u32)).unwrap();
        drop(chain);
        let _ = std::fs::remove_dir_all(&dir);
        o
    }


    /// The verdict codes `state.fam` gives: 0 connected; body errors from
    /// -30, the connect rules from -10, the name rules from -20.
    fn state_code(e: &crate::chain::ChainError) -> i32 {
        use crate::block::BodyError;
        use crate::chain::ChainError;
        use crate::names::ApplyError;
        match e {
            ChainError::Body(b) => match b {
                BodyError::DuplicateInput(_) => -30,
                BodyError::InputOutOfRange(_) => -31,
                BodyError::SpendOutOfRange(_) => -32,
                BodyError::DuplicateSpend(_) => -33,
                BodyError::TooMany(_) => -34,
                BodyError::BadName => -35,
                BodyError::Malformed => -10,
            },
            ChainError::BadBodyCommitment => -11,
            ChainError::TooLarge(_) => -12,
            ChainError::UnknownInput(_) => -13,
            ChainError::StateRootMismatch { .. } => -15,
            ChainError::Supply { .. } => -16,
            ChainError::Name(n) => match n {
                ApplyError::TooMany(_) => -20,
                ApplyError::BadName => -21,
                ApplyError::NoCommit => -22,
                ApplyError::Window(_) => -23,
                ApplyError::Registered => -24,
                ApplyError::NotRegistered => -25,
                ApplyError::NotExpired(_) => -26,
                other => panic!("unexpected name verdict {other:?}"),
            },
            other => panic!("unexpected verdict {other:?}"),
        }
    }

    /// The dev chain for step 5, as `statechain.bin`: a count, then per
    /// block its verdict (a signed word), its header (204 bytes), its
    /// body's length and the body, zero padded to a word. Blocks with a
    /// nonzero verdict are refused and leave the chain as it was. Its
    /// outputs' positions from `first` (0; `statechain40.bin`'s FIRST40):
    /// the counter set after genesis, which no root includes.
    fn generate_state(first: u64) -> (Vec<u8>, Vec<u8>) {
        use crate::block::{Block, BlockOutput, Body, Header};
        use crate::chain::{AcceptAllProofs, Chain, ChainParams};
        use crate::names::{BlockNameOp, MAX_REVEAL, MIN_REVEAL, Record};
        use crate::poseidon2::DIGEST;
        type Digest = [Fp; DIGEST];
        use crate::pow::{PowParams, SeedText};
        let p = ChainParams { genesis_target: ChainParams::DEV.max_target, ..ChainParams::DEV };
        let dir = std::env::temp_dir().join(format!("tabminer-famstate-{}-{first}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let chain = Chain::open(&dir, 1 << 30, p, SeedText::new(PowParams::DEV), AcceptAllProofs).unwrap();
        chain.set_dataset(std::sync::Arc::new(dev_dataset().clone()));
        chain.init_genesis(&p.genesis()).unwrap();
        if first > 0 {
            let mut wtxn = chain.env().write_txn().unwrap();
            chain.utxo().set_next_position(&mut wtxn, first).unwrap();
            wtxn.commit().unwrap();
        }
        let data = dev_dataset();
        let mut r = Rng(0x5eed_57a7);
        let digest = |r: &mut Rng| -> Digest { core::array::from_fn(|_| Fp::new(r.u32() % P)) };
        let memo = |r: &mut Rng| -> crate::transaction::Memo { core::array::from_fn(|_| Fp::new(r.u32() % P)) };
        let mut out: Vec<u8> = Vec::new();
        let mut entries = 0u32;
        let mut ts = p.genesis_timestamp;
        let solve = |mut h: Header| -> Header {
            h.mix = h.pow_output(data).mix;
            h
        };
        let write = |out: &mut Vec<u8>, code: i32, b: &Block| {
            out.extend_from_slice(&code.to_le_bytes());
            out.extend_from_slice(&b.header.to_bytes());
            let body = b.body.to_bytes();
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
            out.resize(out.len().div_ceil(4) * 4, 0);
        };
        // A body paying the subsidy and what it spends to its outputs (the
        // first gets it all).
        let pay = |chain: &Chain<AcceptAllProofs>, body: &mut Body| {
            let height = chain.tip().unwrap().unwrap().height + 1;
            let rtxn = chain.env().read_txn().unwrap();
            let spent: u64 = body
                .inputs
                .iter()
                .map(|&q| crate::transaction::slot_parts(&chain.utxo().slot(&rtxn, q).unwrap()).unwrap().1)
                .sum();
            body.outputs[0].amount = spent + p.subsidy(height);
        };
        let names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota_9"];
        let mut commits: Vec<(u32, u64, Digest)> = Vec::new(); // height, position, hash
        let mut records: Vec<Record> = Vec::new();
        let mut unspent: Vec<u64> = Vec::new();
        let connect = |chain: &Chain<AcceptAllProofs>, out: &mut Vec<u8>, body: Body, ts: u64| -> Block {
            let header = solve(chain.template(&body, ts).unwrap());
            let b = Block { header, body };
            chain.apply_block(&b, ts + 60).unwrap();
            write(out, 0, &b);
            b
        };
        // A refused block on the tip: built with the given state root
        // (the tip's own when none), offered, its verdict recorded.
        let refuse = |chain: &Chain<AcceptAllProofs>, out: &mut Vec<u8>, body: Body, ts: u64, root: Option<Digest>, commitment: Option<Digest>| -> i32 {
            let tip = chain.tip().unwrap().unwrap();
            let header = solve(Header {
                prev_hash: tip.hash(),
                height: tip.height + 1,
                timestamp: ts,
                body_commitment: commitment.unwrap_or_else(|| body.commitment()),
                state_root: root.unwrap_or(tip.state_root),
                aux: [0x5a; 32],
                mix: [Fp::ZERO; 8],
                nonce: [0; 32],
            });
            let b = Block { header, body };
            let code = state_code(&chain.apply_block(&b, ts + 60).unwrap_err());
            write(out, code, &b);
            code
        };
        let last = 2 + 8 + MAX_REVEAL + 4;
        for h in 1..=last {
            ts += 10;
            let mut body = Body { outputs: vec![BlockOutput { commitment: digest(&mut r), memo: memo(&mut r), amount: 0 }], ..Default::default() };
            if h % 3 == 0 && unspent.len() > 2 {
                // Spend two of the oldest and make a second output.
                body.inputs = vec![unspent.remove(0), unspent.remove(1)];
                body.outputs.push(BlockOutput { commitment: digest(&mut r), memo: memo(&mut r), amount: 0 });
            }
            let first = chain.utxo().next_position(&chain.env().read_txn().unwrap()).unwrap();
            if (2..=10).contains(&h) {
                let hash = digest(&mut r);
                body.ops.push(BlockNameOp::Commit { commit: hash, memo: memo(&mut r) });
                commits.push((h, first + body.outputs.len() as u64, hash));
            }
            // Reveals: two a block, from the window's start; the commit made
            // at height 3 left for the sweep.
            let due: Vec<usize> = commits
                .iter()
                .enumerate()
                .filter(|(_, c)| c.0 != 3 && h >= c.0 + MIN_REVEAL)
                .map(|(i, _)| i)
                .collect();
            let mut revealed = 0;
            for i in due {
                if revealed == 2 || commits[i].1 == u64::MAX {
                    continue;
                }
                let name = names[records.len()];
                let rec = Record::new(name.as_bytes(), digest(&mut r), digest(&mut r), digest(&mut r)).unwrap();
                body.ops.push(BlockNameOp::Reveal { record: rec.clone(), commit: commits[i].1 });
                commits[i].1 = u64::MAX;
                records.push(rec);
                revealed += 1;
            }
            if h == 40 || h == 41 {
                // Updates of the first names.
                let mut rec = records[(h - 40) as usize].clone();
                rec.owner = digest(&mut r);
                rec.memo = digest(&mut r);
                records[(h - 40) as usize] = rec.clone();
                body.ops.push(BlockNameOp::Update(rec));
            }
            let c3 = commits.iter().find(|c| c.0 == 3).map_or(0, |c| c.1);
            if h == 3 + MAX_REVEAL + 1 {
                body.sweeps.push(c3);
            }
            // Refused bodies, before the block, at chosen heights.
            if h == 20 {
                let mut b = body.clone();
                b.inputs = vec![0];
                assert_eq!(refuse(&chain, &mut out, b, ts, None, None), -13, "a spent input");
                entries += 1;
                let mut b = Body { outputs: body.outputs.clone(), ..Default::default() };
                pay(&chain, &mut b);
                b.outputs[0].amount += 1;
                let root = chain.preview_state_root(&b).unwrap();
                assert_eq!(refuse(&chain, &mut out, b, ts, Some(root), None), -16, "the supply");
                entries += 1;
                let mut b = Body { outputs: body.outputs.clone(), ..Default::default() };
                pay(&chain, &mut b);
                assert_eq!(refuse(&chain, &mut out, b.clone(), ts, Some(digest(&mut r)), None), -15, "a wrong state root");
                entries += 1;
                assert_eq!(refuse(&chain, &mut out, b.clone(), ts, None, Some(digest(&mut r))), -11, "a wrong body commitment");
                entries += 1;
                let mut d = b.clone();
                let spend = unspent[0];
                d.inputs = vec![spend, spend];
                assert_eq!(refuse(&chain, &mut out, d, ts, None, None), -30, "an input twice");
                entries += 1;
                let mut d = b.clone();
                d.ops = vec![BlockNameOp::Update(Record::new(b"nobody", digest(&mut r), digest(&mut r), digest(&mut r)).unwrap())];
                assert_eq!(refuse(&chain, &mut out, d, ts, None, None), -25, "an update of no name");
                entries += 1;
                let mut d = b.clone();
                d.sweeps = vec![c3];
                assert_eq!(refuse(&chain, &mut out, d, ts, None, None), -26, "a sweep in the window");
                entries += 1;
                let mut d = b.clone();
                d.ops = vec![BlockNameOp::Reveal { record: records[0].clone(), commit: c3 }];
                assert_eq!(refuse(&chain, &mut out, d, ts, None, None), -24, "a name registered");
                entries += 1;
                let mut d = b.clone();
                d.ops = vec![BlockNameOp::Reveal {
                    record: Record::new(b"late", digest(&mut r), digest(&mut r), digest(&mut r)).unwrap(),
                    commit: commits.iter().find(|c| c.0 == 10).unwrap().1,
                }];
                assert_eq!(refuse(&chain, &mut out, d, ts, None, None), -23, "a reveal before its window");
                entries += 1;
                let mut d = b.clone();
                d.ops = vec![BlockNameOp::Reveal {
                    record: Record::new(b"nocommit", digest(&mut r), digest(&mut r), digest(&mut r)).unwrap(),
                    commit: 1,
                }];
                assert_eq!(refuse(&chain, &mut out, d, ts, None, None), -22, "a reveal of no commit");
                entries += 1;
            }
            pay(&chain, &mut body);
            let n_out = body.outputs.len() as u64;
            connect(&chain, &mut out, body, ts);
            entries += 1;
            unspent.extend(first..first + n_out);
        }
        // The snapshot after block SNAP_HEIGHT: a height, then the
        // manifest, and each part (outputs, then names), each its length
        // and bytes, word padded (none for the 40-bit chain: see above).
        if first > 0 {
            drop(chain);
            let _ = std::fs::remove_dir_all(&dir);
            let mut file = entries.to_le_bytes().to_vec();
            file.extend_from_slice(&out);
            return (file, vec![]);
        }
        let id = chain.header_at(SNAP_HEIGHT).unwrap().unwrap().hash();
        let m = chain.snapshot_manifest(&id).unwrap().unwrap();
        let mut snap = SNAP_HEIGHT.to_le_bytes().to_vec();
        let put = |snap: &mut Vec<u8>, b: &[u8]| {
            snap.extend_from_slice(&(b.len() as u32).to_le_bytes());
            snap.extend_from_slice(b);
            snap.resize(snap.len().div_ceil(4) * 4, 0);
        };
        put(&mut snap, &crate::net::encode_manifest(&m));
        snap.extend_from_slice(&((m.outputs.len() + m.names.len()) as u32).to_le_bytes());
        for i in 0..m.outputs.len() as u64 {
            let (outs, commits) = chain.snapshot_part(&id, i).unwrap().unwrap();
            put(&mut snap, &crate::net::encode_part(&outs, &commits));
        }
        for j in 0..m.names.len() as u64 {
            put(&mut snap, &crate::net::encode_name_part(&chain.snapshot_name_part(&id, j).unwrap().unwrap()));
        }
        drop(chain);
        let _ = std::fs::remove_dir_all(&dir);
        let mut file = entries.to_le_bytes().to_vec();
        file.extend_from_slice(&out);
        (file, snap)
    }

    /// A verdict of `Mempool::insert` as `pool.bin` gives it: 0, or a
    /// negative code (-1 for bytes that do not decode).
    fn tx_code(r: &Result<crate::xmss::Digest, crate::mempool::Reject>) -> i32 {
        use crate::mempool::{NameReject, Reject};
        match r {
            Ok(_) => 0,
            Err(e) => match e {
                Reject::NoInputs => -2,
                Reject::Malformed => -3,
                Reject::TooLarge(_) => -4,
                Reject::Dust { .. } => -5,
                Reject::NegativeFee => -6,
                Reject::FeeTooLow { .. } => -7,
                Reject::BadSignature => -8,
                Reject::UnknownInput(_) => -9,
                Reject::Known => -10,
                Reject::NameConflict => -11,
                Reject::ReplacementFee { .. } => -12,
                Reject::Full => -13,
                Reject::Name(NameReject::NoCommit) => -14,
                Reject::Name(NameReject::Expired(_)) => -15,
                Reject::Name(NameReject::Registered) => -16,
                Reject::Name(NameReject::NotRegistered) => -17,
                Reject::Name(NameReject::BadOwner) => -18,
                Reject::Policy(_) => -19,
                Reject::TooManyRows(_) => -20,
                Reject::Expired => -21,
                other => panic!("unexpected pool verdict {other:?}"),
            },
        }
    }

    /// The pool test for step 7, `pool.bin`: a count, then entries, each a
    /// kind word and word padded:
    /// - 0, a block: its header (204 bytes), its body's length and the
    ///   body; tabminer connected it (its proof is not checked);
    /// - 1, a transaction offered to the pool for the block after the tip:
    ///   tabminer's verdict (`tx_code`), its id (8 canonical words, zero if
    ///   it does not decode), its length and its bytes;
    /// - 2, the pool after a block: a count and the ids it holds;
    /// - 3, an XMSS signature: the flag tabminer's `verify` gives, the
    ///   message (8 canonical words), the key (49 bytes), the signature's
    ///   length and the signature.
    /// - 4, an output's proof against the tip's state root: its position
    ///   (8 bytes), the 40 siblings (canonical words), leaf first;
    /// - 5, a name's proof against the trie: the name's length and the
    ///   name (32 bytes, zero padded), the terminal (0 empty, or 1, its key
    ///   as 16 bytes and its value), the depth and the siblings from the
    ///   terminal's up.
    fn generate_pool() -> Vec<u8> {
        use crate::block::{Block, Body};
        use crate::chain::{AcceptAllProofs, Chain, ChainParams};
        use crate::mempool::Mempool;
        use crate::names::{BlockNameOp, MIN_REVEAL, NameOp, Record, commit_hash, name_elements, name_hash};
        use crate::poseidon2::{DIGEST, digest_to_bytes};
        use crate::pow::{PowParams, SeedText};
        use crate::transaction::{Key, Output, Transaction, UnsignedTransaction, pubkey_hash};
        type Digest = [Fp; DIGEST];
        let p = ChainParams { genesis_target: ChainParams::DEV.max_target, ..ChainParams::DEV };
        let dir = std::env::temp_dir().join(format!("tabminer-fampool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let chain = Chain::open(&dir, 256 << 20, p, SeedText::new(PowParams::DEV), AcceptAllProofs).unwrap();
        chain.set_dataset(std::sync::Arc::new(dev_dataset().clone()));
        chain.init_genesis(&p.genesis()).unwrap();
        let data = dev_dataset();
        let mut r = Rng(0x9001_7e57);
        let digest = |r: &mut Rng| -> Digest { core::array::from_fn(|_| Fp::new(r.u32() % P)) };
        let memo = |r: &mut Rng| -> crate::transaction::Memo { core::array::from_fn(|_| Fp::new(r.u32() % P)) };
        let key = |tag: u8, height: usize| {
            let mut s = [0u8; 32];
            s[0] = 0x70;
            s[1] = tag;
            Key::generate_with_height(&s, height)
        };
        let mut keys: Vec<Key> = (0..8).map(|i| key(i, crate::transaction::TREE_HEIGHT)).collect();
        let mut o0 = key(100, crate::transaction::TREE_HEIGHT);
        let mut o1 = key(101, crate::transaction::TREE_HEIGHT);
        let (h0, h1) = (pubkey_hash(&o0.public_key()), pubkey_hash(&o1.public_key()));
        let mut out: Vec<u8> = Vec::new();
        let mut entries = 0u32;
        let pad = |out: &mut Vec<u8>| out.resize(out.len().div_ceil(4) * 4, 0);
        let words = |out: &mut Vec<u8>, d: &Digest| out.extend_from_slice(&digest_to_bytes(d));
        let mut ts = p.genesis_timestamp;
        // A block of the reward (to key `to`) and the transactions.
        let block = |out: &mut Vec<u8>, ts: u64, to: &Key, txs: &[&Transaction], ops: Vec<BlockNameOp>, r: &mut Rng| {
            let height = chain.tip().unwrap().unwrap().height + 1;
            let fees: i128 = txs.iter().map(|t| t.balance()).sum();
            let reward = Output::with_memo(&pubkey_hash(&to.public_key()), p.subsidy(height) + fees as u64, memo(r));
            let mut body = Body { outputs: vec![reward.block_output()], ..Default::default() };
            for t in txs {
                body.inputs.extend(t.spent_positions());
                body.outputs.extend(t.outputs.iter().map(Output::block_output));
                body.ops.extend(t.ops.iter().map(NameOp::block_op));
            }
            body.ops.extend(ops);
            let mut header = chain.template(&body, ts).unwrap();
            header.mix = header.pow_output(data).mix;
            let b = Block { header, body };
            chain.apply_block(&b, ts + 60).unwrap();
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&b.header.to_bytes());
            let body = b.body.to_bytes();
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
            pad(out);
        };
        let next = |chain: &Chain<AcceptAllProofs>| chain.utxo().next_position(&chain.env().read_txn().unwrap()).unwrap();
        // Blocks 1 to 16: rewards to the keys in turn (block h's at
        // position `reward[h]`); commits for "second" (owner o1, at 3) and
        // "pooltest" (owner o0, at 2; and owner o1, at 4, left unrevealed);
        // "pooltest" revealed at 15.
        let name = |n: &str| name_hash(&name_elements(n.as_bytes()).unwrap());
        let (s0, s1, s2) = (digest(&mut r), digest(&mut r), digest(&mut r));
        let mut reward = vec![0u64];
        let mut amount = vec![0u64];
        let mut commit_at = std::collections::HashMap::new();
        let pt = Record::new(b"pooltest", h0, digest(&mut r), digest(&mut r)).unwrap();
        for h in 1..=16u32 {
            ts += 10;
            reward.push(next(&chain));
            amount.push(p.subsidy(h));
            let mut ops = vec![];
            let c = match h {
                2 => Some(commit_hash(&name("pooltest"), &s0, &h0)),
                3 => Some(commit_hash(&name("second"), &s1, &h1)),
                4 => Some(commit_hash(&name("pooltest"), &s2, &h1)),
                _ => None,
            };
            if let Some(c) = c {
                ops.push(BlockNameOp::Commit { commit: c, memo: memo(&mut r) });
                commit_at.insert(h, reward[h as usize] + 1);
            }
            if h == 2 + MIN_REVEAL + 1 {
                ops.push(BlockNameOp::Reveal { record: pt.clone(), commit: commit_at[&2] });
            }
            let to = h as usize % 8;
            let k = keys[to].clone();
            block(&mut out, ts, &k, &[], ops, &mut r);
            entries += 1;
        }
        let owner = |h: u32| h as usize % 8;
        let mut pool = Mempool::new(crate::mempool::DEFAULT_CAPACITY);
        let offer = |out: &mut Vec<u8>, pool: &mut Mempool, bytes: &[u8], want: i32| {
            let height = chain.tip().unwrap().unwrap().height + 1;
            let (code, id) = match Transaction::from_bytes(bytes) {
                None => (-1, [Fp::ZERO; DIGEST]),
                Some(tx) => {
                    let id = tx.txid();
                    let rtxn = chain.env().read_txn().unwrap();
                    (tx_code(&pool.insert(tx, chain.utxo(), chain.names(), &rtxn, height)), id)
                }
            };
            assert_eq!(code, want, "pool verdict");
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&code.to_le_bytes());
            words(out, &id);
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
            pad(out);
        };
        let ids = |out: &mut Vec<u8>, pool: &Mempool| {
            let mut v = pool.ids();
            v.sort_by_key(digest_to_bytes);
            out.extend_from_slice(&2u32.to_le_bytes());
            out.extend_from_slice(&(v.len() as u32).to_le_bytes());
            for id in &v {
                words(out, id);
            }
        };
        // A transaction spending (block, amount) rewards, signed by their
        // keys, paying `outs` (key, amount) and the rest less `fee` back to
        // the first's key.
        let make = |keys: &mut [Key], reward: &[u64], spends: &[(u32, u64)], outs: &[(usize, u64)], fee: u64, ops: Vec<NameOp>, r: &mut Rng| -> Transaction {
            let total: u64 = spends.iter().map(|s| s.1).sum();
            let paid: u64 = outs.iter().map(|o| o.1).sum();
            let mut outputs: Vec<Output> =
                outs.iter().map(|&(k, a)| Output::with_memo(&pubkey_hash(&keys[k].public_key()), a, memo(r))).collect();
            if let Some(change) = total.checked_sub(paid + fee).filter(|c| *c > 0) {
                outputs.push(Output::with_memo(&pubkey_hash(&keys[owner(spends[0].0)].public_key()), change, memo(r)));
            }
            let inputs = spends.iter().map(|s| (keys[owner(s.0)].public_key(), s.1)).collect();
            let unsigned = UnsignedTransaction::with_ops(inputs, outputs, ops);
            let mut tx = unsigned.sign::<()>(|i, _, msg| Ok(keys[owner(spends[i].0)].sign(msg).unwrap())).unwrap();
            tx.set_positions(&spends.iter().map(|s| reward[s.0 as usize]).collect::<Vec<_>>());
            tx
        };
        let s = amount[1];
        let coin = 100_000_000u64;
        // T1, again, a replacement short of the fee, one paying it.
        let t1 = make(&mut keys, &reward, &[(1, s)], &[(4, coin)], 100_000, vec![], &mut r);
        offer(&mut out, &mut pool, &t1.to_bytes(), 0);
        offer(&mut out, &mut pool, &t1.to_bytes(), -10);
        let t2 = make(&mut keys, &reward, &[(1, s)], &[(5, coin)], 100_000 + 10, vec![], &mut r);
        offer(&mut out, &mut pool, &t2.to_bytes(), -12);
        let t3 = make(&mut keys, &reward, &[(1, s)], &[(4, coin)], 100_000 + 10 * 2600, vec![], &mut r);
        offer(&mut out, &mut pool, &t3.to_bytes(), 0);
        entries += 4;
        // A changed signature (canonical still), an input elsewhere, an
        // amount not the output's.
        let mut t = make(&mut keys, &reward, &[(2, s)], &[(5, coin)], 100_000, vec![], &mut r);
        t.inputs[0].signature.wots[7][3] = t.inputs[0].signature.wots[7][3].add(&Fp::ONE);
        offer(&mut out, &mut pool, &t.to_bytes(), -8);
        let mut t = make(&mut keys, &reward, &[(2, s)], &[(5, coin)], 100_000, vec![], &mut r);
        t.set_positions(&[reward[3]]);
        offer(&mut out, &mut pool, &t.to_bytes(), -9);
        let t = make(&mut keys, &reward, &[(2, s + 1)], &[(5, coin)], 100_000, vec![], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -9);
        entries += 3;
        // The static rules: outputs above the inputs, a fee below the
        // floor, dust, an output of zero, an input twice, no inputs.
        let t = make(&mut keys, &reward, &[(2, s)], &[(5, s + 1)], 0, vec![], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -6);
        let t = make(&mut keys, &reward, &[(2, s)], &[(5, coin)], 10, vec![], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -7);
        let t = make(&mut keys, &reward, &[(2, s)], &[(5, 100)], 100_000, vec![], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -5);
        let mut t = make(&mut keys, &reward, &[(2, s)], &[(5, coin)], 100_000, vec![], &mut r);
        t.outputs.push(Output::with_memo(&h0, 0, memo(&mut r)));
        offer(&mut out, &mut pool, &t.to_bytes(), -3);
        let t = make(&mut keys, &reward, &[(2, s), (2, s)], &[(5, coin)], 100_000, vec![], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -3);
        let t = Transaction { inputs: vec![], policy_inputs: vec![], outputs: t.outputs.clone(), ops: vec![] };
        offer(&mut out, &mut pool, &t.to_bytes(), -2);
        entries += 6;
        // Bytes that do not decode: cut short, an element not canonical, a
        // key of height zero, a byte left over.
        let good = make(&mut keys, &reward, &[(2, s)], &[(5, coin)], 100_000, vec![], &mut r).to_bytes();
        offer(&mut out, &mut pool, &good[..good.len() - 1], -1);
        let mut b = good.clone();
        b[4 + 49 + 16 + 8 + 100..4 + 49 + 16 + 8 + 104].copy_from_slice(&P.to_le_bytes());
        offer(&mut out, &mut pool, &b, -1);
        let mut b = good.clone();
        b[4 + 48] = 0;
        offer(&mut out, &mut pool, &b, -1);
        let mut b = good.clone();
        b.push(0);
        offer(&mut out, &mut pool, &b, -1);
        entries += 4;
        // Names: "second" revealed; again by another; with the wrong salt;
        // "pooltest", registered, revealed from its other commit.
        let sec = Record::new(b"second", h1, digest(&mut r), digest(&mut r)).unwrap();
        let t15 = make(&mut keys, &reward, &[(2, s)], &[(5, coin)], 200_000, vec![NameOp::Reveal { record: sec.clone(), salt: s1, commit: commit_at[&3] }], &mut r);
        offer(&mut out, &mut pool, &t15.to_bytes(), 0);
        let t = make(&mut keys, &reward, &[(3, s)], &[], 200_000, vec![NameOp::Reveal { record: sec.clone(), salt: s1, commit: commit_at[&3] }], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -11);
        let t = make(&mut keys, &reward, &[(3, s)], &[], 200_000, vec![NameOp::Reveal { record: sec.clone(), salt: s0, commit: commit_at[&3] }], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -14);
        let pt1 = Record { owner: h1, ..pt.clone() };
        let t = make(&mut keys, &reward, &[(3, s)], &[], 200_000, vec![NameOp::Reveal { record: pt1.clone(), salt: s2, commit: commit_at[&4] }], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -16);
        entries += 4;
        // Updates: "pooltest" to o1 by o0; by the wrong key; of no name;
        // keeping the owner; another of "pooltest" while one is pooled.
        let up = NameOp::update(pt1.clone(), &mut o0).unwrap();
        let t19 = make(&mut keys, &reward, &[(3, s)], &[], 200_000, vec![up], &mut r);
        offer(&mut out, &mut pool, &t19.to_bytes(), 0);
        let bad = NameOp::update(Record { value: digest(&mut r), ..pt1.clone() }, &mut o1).unwrap();
        let t = make(&mut keys, &reward, &[(4, s)], &[], 200_000, vec![bad], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -18);
        let none = NameOp::update(Record::new(b"nobody", h1, digest(&mut r), digest(&mut r)).unwrap(), &mut o0).unwrap();
        let t = make(&mut keys, &reward, &[(4, s)], &[], 200_000, vec![none], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -17);
        let same = NameOp::update(Record { value: digest(&mut r), ..pt.clone() }, &mut o0).unwrap();
        let t = make(&mut keys, &reward, &[(4, s)], &[], 200_000, vec![same], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -18);
        let other = NameOp::update(Record { value: digest(&mut r), ..pt1.clone() }, &mut o0).unwrap();
        let t = make(&mut keys, &reward, &[(7, s)], &[], 200_000, vec![other], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -11);
        entries += 5;
        // Two inputs; a commit; two commits.
        let t23 = make(&mut keys, &reward, &[(4, s), (5, s)], &[(6, coin), (7, 2 * coin)], 150_000, vec![], &mut r);
        offer(&mut out, &mut pool, &t23.to_bytes(), 0);
        let commit = |r: &mut Rng| NameOp::Commit { commit: digest(r), memo: memo(r) };
        let t24 = make(&mut keys, &reward, &[(6, s)], &[], 200_000, vec![commit(&mut r)], &mut r);
        offer(&mut out, &mut pool, &t24.to_bytes(), 0);
        let t = make(&mut keys, &reward, &[(7, s)], &[], 200_000, vec![commit(&mut r), commit(&mut r)], &mut r);
        offer(&mut out, &mut pool, &t.to_bytes(), -3);
        entries += 3;
        // Block 17 mines T3, T15 and T23; T19 and T24 stay.
        ts += 10;
        reward.push(next(&chain));
        let k = keys[0].clone();
        block(&mut out, ts, &k, &[&t3, &t15, &t23], vec![], &mut r);
        {
            let rtxn = chain.env().read_txn().unwrap();
            let height = chain.tip().unwrap().unwrap().height + 1;
            let (moved, created) = (std::collections::HashMap::new(), std::collections::HashMap::new());
            pool.revalidate(chain.utxo(), chain.names(), &rtxn, height, &moved, &created).unwrap();
        }
        ids(&mut out, &pool);
        entries += 2;
        // T1's input, spent now; T3's payment, spent; T19 again.
        offer(&mut out, &mut pool, &t1.to_bytes(), -9);
        let paid = t3.outputs[0];
        let mut t29 = {
            let inputs = vec![(keys[4].public_key(), paid.amount)];
            let outputs = vec![Output::with_memo(&h0, paid.amount - 50_000, memo(&mut r))];
            UnsignedTransaction::new(inputs, outputs).sign::<()>(|_, _, msg| Ok(keys[4].sign(msg).unwrap())).unwrap()
        };
        t29.set_positions(&[reward[17] + 1]);
        offer(&mut out, &mut pool, &t29.to_bytes(), 0);
        offer(&mut out, &mut pool, &t19.to_bytes(), -10);
        entries += 3;
        // Block 18 mines the rest.
        ts += 10;
        reward.push(next(&chain));
        block(&mut out, ts, &k, &[&t19, &t24, &t29], vec![], &mut r);
        {
            let rtxn = chain.env().read_txn().unwrap();
            let height = chain.tip().unwrap().unwrap().height + 1;
            let (moved, created) = (std::collections::HashMap::new(), std::collections::HashMap::new());
            pool.revalidate(chain.utxo(), chain.names(), &rtxn, height, &moved, &created).unwrap();
        }
        ids(&mut out, &pool);
        entries += 2;
        // Policy inputs (docs/ELTOO.md): five outputs of one policy made by
        // block 19, spent through each kind of leaf, satisfied and not.
        {
            use crate::policy::{Cond, CondWitness, Leaf, Mode, Policy, Signer, hash_lock, rebind_message};
            let pk: Vec<Key> = (110..113).map(|t| key(t, crate::transaction::TREE_HEIGHT)).collect();
            let ph: Vec<Digest> = pk.iter().map(|k| pubkey_hash(&k.public_key())).collect();
            let pre = digest(&mut r);
            let channel = digest(&mut r);
            let settle_outs = vec![
                Output::with_memo(&ph[0], 4 * coin, memo(&mut r)),
                Output::with_memo(&ph[1], 5 * coin, memo(&mut r)),
            ];
            let settle: Vec<_> = settle_outs.iter().map(|o| (o.commitment, o.slot())).collect();
            let policy = Policy::new(vec![
                Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 2, keys: ph.clone() }]),
                Leaf::new(vec![Cond::Hash(hash_lock(&pre)), Cond::Thresh { mode: Mode::Body, m: 1, keys: ph[1..2].to_vec() }]),
                Leaf::new(vec![Cond::After(100), Cond::Thresh { mode: Mode::Body, m: 1, keys: ph[..1].to_vec() }]),
                Leaf::new(vec![Cond::Thresh { mode: Mode::Rebindable { channel }, m: 2, keys: ph[..2].to_vec() }, Cond::State(3)]),
                Leaf::new(vec![Cond::Older(2), Cond::Outputs(settle.clone())]),
            ]);
            let a = 10 * coin;
            // The funding transaction: keys[0]'s reward of block 8.
            let fund = {
                let mut outputs: Vec<Output> = (0..5).map(|_| policy.output(a, memo(&mut r))).collect();
                outputs.push(Output::with_memo(&h0, s - 5 * a - 300_000, memo(&mut r)));
                let mut t = UnsignedTransaction::new(vec![(keys[0].public_key(), s)], outputs)
                    .sign::<()>(|_, _, msg| Ok(keys[0].sign(msg).unwrap()))
                    .unwrap();
                t.set_positions(&[reward[8]]);
                t
            };
            offer(&mut out, &mut pool, &fund.to_bytes(), 0);
            ts += 10;
            reward.push(next(&chain));
            block(&mut out, ts, &k, &[&fund], vec![], &mut r);
            let at = |i: u64| reward[19] + 1 + i;
            {
                let rtxn = chain.env().read_txn().unwrap();
                let height = chain.tip().unwrap().unwrap().height + 1;
                let (moved, created) = (std::collections::HashMap::new(), std::collections::HashMap::new());
                pool.revalidate(chain.utxo(), chain.names(), &rtxn, height, &moved, &created).unwrap();
            }
            ids(&mut out, &pool);
            entries += 3;
            // A policy spend paying `outs` (key hash, amount), witnessed by
            // `witness`, given the body hash; a plain input of keys[0]'s
            // reward of block 16 too if `plain`.
            let pay = |keys: &mut [Key], p: crate::policy::PolicyInput, outs: Vec<Output>, plain: bool, witness: &mut dyn FnMut(&mut crate::policy::PolicyInput, &Digest)| -> Transaction {
                let mut p = p;
                let inputs = if plain { vec![(keys[0].public_key(), s)] } else { vec![] };
                let mut outs = outs;
                if plain {
                    outs.push(Output::with_memo(&h1, s - 200_000, memo(&mut Rng(7))));
                }
                let body = UnsignedTransaction::new(inputs.clone(), outs.clone()).with_policy_inputs(vec![p.clone()]).body_hash();
                witness(&mut p, &body);
                let mut t = UnsignedTransaction::new(inputs, outs)
                    .with_policy_inputs(vec![p.clone()])
                    .sign::<()>(|_, _, msg| Ok(keys[0].sign(msg).unwrap()))
                    .unwrap();
                let mut pos = if plain { vec![reward[16]] } else { vec![] };
                pos.push(p.position);
                t.set_positions(&pos);
                t
            };
            let signer = |k: &mut Key, key: u8, msg: &Digest| Signer { key, pubkey: k.public_key(), signature: k.sign(msg).unwrap() };
            let k5 = pubkey_hash(&keys[5].public_key());
            let to5 = |amount: u64, r: &mut Rng| vec![Output::with_memo(&k5, amount, memo(r))];
            let mut pk = pk;
            // 2 of 3 in body mode; one signature short.
            let (p0, p1) = (pk[0].clone(), pk[2].clone());
            let mut sk = [p0, p1];
            let ta = pay(&mut keys, policy.spend(0, a, at(0)), to5(a - 100_000, &mut r), false, &mut |p, body| {
                let (x, y) = sk.split_at_mut(1);
                p.witness[0] = CondWitness::Signatures(vec![signer(&mut x[0], 0, body), signer(&mut y[0], 2, body)]);
            });
            offer(&mut out, &mut pool, &ta.to_bytes(), 0);
            let t = pay(&mut keys, policy.spend(0, a, at(1)), to5(a - 100_000, &mut r), false, &mut |p, body| {
                p.witness[0] = CondWitness::Signatures(vec![signer(&mut pk[0], 0, body)]);
            });
            offer(&mut out, &mut pool, &t.to_bytes(), -19);
            // The hash lock with a plain input beside it; a wrong preimage;
            // a time lock not yet open.
            let tc = pay(&mut keys, policy.spend(1, a, at(1)), to5(a - 200_000, &mut r), true, &mut |p, body| {
                p.witness[0] = CondWitness::Preimage(pre);
                p.witness[1] = CondWitness::Signatures(vec![signer(&mut pk[1], 0, body)]);
            });
            offer(&mut out, &mut pool, &tc.to_bytes(), 0);
            let wrong = digest(&mut r);
            let t = pay(&mut keys, policy.spend(1, a, at(2)), to5(a - 200_000, &mut r), false, &mut |p, body| {
                p.witness[0] = CondWitness::Preimage(wrong);
                p.witness[1] = CondWitness::Signatures(vec![signer(&mut pk[1], 0, body)]);
            });
            offer(&mut out, &mut pool, &t.to_bytes(), -19);
            let t = pay(&mut keys, policy.spend(2, a, at(2)), to5(a - 200_000, &mut r), false, &mut |p, body| {
                p.witness[1] = CondWitness::Signatures(vec![signer(&mut pk[0], 0, body)]);
            });
            offer(&mut out, &mut pool, &t.to_bytes(), -19);
            entries += 5;
            // The channel's update: rebindable signatures at the state's
            // leaf over the two outputs covered; then a state not above 3.
            let rebind = |pk: &mut [Key], state: u32, p: &mut crate::policy::PolicyInput, outs: &[Output]| {
                p.state = state;
                p.covered = (0, 2);
                let covered: Vec<_> = outs.iter().map(|o| (o.commitment, o.slot())).collect();
                let msg = rebind_message(&channel, state, &covered);
                let mut x = pk[0].clone();
                x.set_next_index(state as u64);
                let mut y = pk[1].clone();
                y.set_next_index(state as u64);
                p.witness[0] = CondWitness::Signatures(vec![signer(&mut x, 0, &msg), signer(&mut y, 1, &msg)]);
            };
            let two = |r: &mut Rng| {
                vec![Output::with_memo(&k5, 3 * coin, memo(r)), Output::with_memo(&k5, a - 3 * coin - 200_000, memo(r))]
            };
            let outs = two(&mut r);
            let mut sp = policy.spend(3, a, at(3));
            rebind(&mut pk, 4, &mut sp, &outs);
            let tf = pay(&mut keys, sp, outs, false, &mut |_, _| {});
            offer(&mut out, &mut pool, &tf.to_bytes(), 0);
            let outs = two(&mut r);
            let mut sp = policy.spend(3, a, at(2));
            rebind(&mut pk, 3, &mut sp, &outs);
            let t = pay(&mut keys, sp, outs, false, &mut |_, _| {});
            offer(&mut out, &mut pool, &t.to_bytes(), -19);
            // The settlement covenant, before its outputs are old enough;
            // covering outputs that are not there.
            let mut sp = policy.spend(4, a, at(4));
            sp.covered = (0, 2);
            let th = pay(&mut keys, sp, settle_outs.clone(), false, &mut |_, _| {});
            offer(&mut out, &mut pool, &th.to_bytes(), -19);
            let mut sp = policy.spend(4, a, at(2));
            sp.covered = (1, 2);
            let t = pay(&mut keys, sp, settle_outs.clone(), false, &mut |_, _| {});
            offer(&mut out, &mut pool, &t.to_bytes(), -19);
            entries += 4;
            // Two policy inputs; more rows than a segment holds (29
            // signatures, the same one, never checked).
            let mut t = th.clone();
            t.policy_inputs.push(policy.spend(4, a, at(2)));
            offer(&mut out, &mut pool, &t.to_bytes(), -3);
            let many: Vec<Digest> = (0..29).map(|_| digest(&mut r)).collect();
            let big = Policy::new(vec![Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 29, keys: many }])]);
            let mut sp = big.spend(0, a, at(2));
            let one = signer(&mut pk[2], 0, &digest(&mut r));
            sp.witness[0] = CondWitness::Signatures(vec![one; 29]);
            let t = pay(&mut keys, sp, to5(a - 2_000_000, &mut r), false, &mut |_, _| {});
            offer(&mut out, &mut pool, &t.to_bytes(), -20);
            entries += 2;
            // Block 20 mines the three pooled; the covenant then admitted
            // at 21 and mined.
            ts += 10;
            reward.push(next(&chain));
            block(&mut out, ts, &k, &[&ta, &tc, &tf], vec![], &mut r);
            {
                let rtxn = chain.env().read_txn().unwrap();
                let height = chain.tip().unwrap().unwrap().height + 1;
                let (moved, created) = (std::collections::HashMap::new(), std::collections::HashMap::new());
                pool.revalidate(chain.utxo(), chain.names(), &rtxn, height, &moved, &created).unwrap();
            }
            ids(&mut out, &pool);
            offer(&mut out, &mut pool, &th.to_bytes(), 0);
            ts += 10;
            reward.push(next(&chain));
            block(&mut out, ts, &k, &[&th], vec![], &mut r);
            {
                let rtxn = chain.env().read_txn().unwrap();
                let height = chain.tip().unwrap().unwrap().height + 1;
                let (moved, created) = (std::collections::HashMap::new(), std::collections::HashMap::new());
                pool.revalidate(chain.utxo(), chain.names(), &rtxn, height, &moved, &created).unwrap();
            }
            ids(&mut out, &pool);
            entries += 5;
        }
        // XMSS on its own: keys of heights 1, 3 and 6, signed, a message,
        // the randomizer and the index changed.
        for (tag, height) in [(200u8, 1usize), (201, 3), (202, 6)] {
            let mut k = key(tag, height);
            let msg = digest(&mut r);
            let sig = k.sign(&msg).unwrap();
            let sig2 = k.sign(&msg).unwrap();
            let mut cases = vec![(msg, sig.clone()), (digest(&mut r), sig.clone()), (msg, sig2.clone())];
            let mut s = sig.clone();
            s.randomizer[0] = s.randomizer[0].add(&Fp::ONE);
            cases.push((msg, s));
            let mut s = sig2.clone();
            s.index ^= 1;
            cases.push((msg, s));
            let mut s = sig.clone();
            s.auth_path[height - 1][5] = s.auth_path[height - 1][5].add(&Fp::ONE);
            cases.push((msg, s));
            for (m, s) in cases {
                let ok = k.public_key().verify(&m, &s);
                out.extend_from_slice(&3u32.to_le_bytes());
                out.extend_from_slice(&(ok as u32).to_le_bytes());
                words(&mut out, &m);
                out.extend_from_slice(&k.public_key().to_bytes());
                let b = s.to_bytes();
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(&b);
                pad(&mut out);
                entries += 1;
            }
        }
        // Proofs against the tip's state root (docs/NODE.md, step 8):
        // outputs unspent and spent, in groups apart, and one past the
        // counter; names registered and not.
        let made = next(&chain);
        for position in [0, 1, reward[2] + 1, reward[17] + 1, reward[21], made - 1, made, 300] {
            let (_, _, proof) = chain.output_proof(position).unwrap().unwrap();
            out.extend_from_slice(&4u32.to_le_bytes());
            out.extend_from_slice(&position.to_le_bytes());
            for sib in &proof.siblings {
                words(&mut out, sib);
            }
            entries += 1;
        }
        for name in ["pooltest", "second", "alpha", "nobody", "a"] {
            let rtxn = chain.env().read_txn().unwrap();
            let proof = chain.names().prove(&rtxn, name.as_bytes()).unwrap();
            out.extend_from_slice(&5u32.to_le_bytes());
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            let mut n = name.as_bytes().to_vec();
            n.resize(32, 0);
            out.extend_from_slice(&n);
            match proof.terminal {
                crate::name_trie::Terminal::Empty => out.extend_from_slice(&[0u8; 4 + 16 + 32]),
                crate::name_trie::Terminal::Leaf { key, value } => {
                    out.extend_from_slice(&1u32.to_le_bytes());
                    out.extend_from_slice(&key.to_le_bytes());
                    words(&mut out, &value);
                }
            }
            out.extend_from_slice(&(proof.siblings.len() as u32).to_le_bytes());
            for sib in &proof.siblings {
                words(&mut out, sib);
            }
            entries += 1;
        }
        drop(chain);
        let _ = std::fs::remove_dir_all(&dir);
        let mut file = entries.to_le_bytes().to_vec();
        file.extend_from_slice(&out);
        file
    }

    #[test]
    fn fam_vectors_are_current() {
        let file = std::fs::read_to_string(PATH).expect("node/src/user/node/arith_vectors.fam");
        assert!(file == generate(), "the fam node's arithmetic vectors are stale: run write_fam_vectors");
        let file = std::fs::read_to_string(P2_PATH).expect("node/src/user/node/poseidon2_vectors.fam");
        assert!(file == generate_poseidon2(), "the fam node's Poseidon2 vectors are stale: run write_fam_vectors");
        let file = std::fs::read_to_string(DIFF_PATH).expect("node/src/user/node/difficulty_vectors.fam");
        assert!(file == generate_difficulty(), "the fam node's difficulty vectors are stale: run write_fam_vectors");
        let file = std::fs::read_to_string(POW_PATH).expect("node/src/user/node/pow_vectors.fam");
        assert!(file == generate_pow(), "the fam node's proof-of-work vectors are stale: run write_fam_vectors");
        let file = std::fs::read_to_string(HDR_PATH).expect("node/src/user/node/headers_vectors.fam");
        assert!(file == generate_headers(), "the fam node's header vectors are stale: run write_fam_vectors");
        let (state, snap) = generate_state(0);
        let file = std::fs::read(STATE_PATH).expect("node/src/user/node/statechain.bin");
        assert!(file == state, "the fam node's state chain is stale: run write_fam_vectors");
        let file = std::fs::read(SNAP_PATH).expect("node/src/user/node/statesnap.bin");
        assert!(file == snap, "the fam node's snapshot is stale: run write_fam_vectors");
        let (state, _) = generate_state(FIRST40);
        let file = std::fs::read(STATE40_PATH).expect("node/src/user/node/statechain40.bin");
        assert!(file == state, "the fam node's 40-bit state chain is stale: run write_fam_vectors");
        let file = std::fs::read(POOL_PATH).expect("node/src/user/node/pool.bin");
        assert!(file == generate_pool(), "the fam node's pool test is stale: run write_fam_vectors");
    }

    #[test]
    #[ignore = "writes the node's vectors: node/src/user/node/*_vectors.fam"]
    fn write_fam_vectors() {
        std::fs::write(PATH, generate()).unwrap();
        std::fs::write(P2_PATH, generate_poseidon2()).unwrap();
        std::fs::write(DIFF_PATH, generate_difficulty()).unwrap();
        std::fs::write(POW_PATH, generate_pow()).unwrap();
        std::fs::write(HDR_PATH, generate_headers()).unwrap();
        let (state, snap) = generate_state(0);
        std::fs::write(STATE_PATH, state).unwrap();
        std::fs::write(SNAP_PATH, snap).unwrap();
        let (state, _) = generate_state(FIRST40);
        std::fs::write(STATE40_PATH, state).unwrap();
        std::fs::write(POOL_PATH, generate_pool()).unwrap();
    }
}

/// Dumps a dev-recursive chain's blocks for the fam node's tests:
/// `TABMINER_DEV_DATA=DIR TABMINER_DEV_OUT=FILE TABMINER_DEV_BLOCKS=N
/// cargo test --release --features dev --lib dump_dev_chain -- --ignored`,
/// DIR a `--network dev-recursive` node's data directory (it may be
/// running). FILE is a count; the chain's constants (the base program's
/// digest, the step's, the plan root: 24 words); genesis's header; then
/// as `statechain.bin`, per block a zero verdict, its header, its body's
/// length and the body, word padded.
#[cfg(all(test, feature = "dev"))]
mod dump {
    #[test]
    #[ignore = "dumps a dev-recursive chain: set TABMINER_DEV_DATA, TABMINER_DEV_OUT"]
    fn dump_dev_chain() {
        use crate::chain::{AcceptAllProofs, Chain, ChainParams};
        use crate::pow::{PowParams, SeedText};
        let dir = std::env::var("TABMINER_DEV_DATA").expect("TABMINER_DEV_DATA");
        let out = std::env::var("TABMINER_DEV_OUT").expect("TABMINER_DEV_OUT");
        let n: u32 = std::env::var("TABMINER_DEV_BLOCKS").ok().and_then(|v| v.parse().ok()).unwrap_or(u32::MAX);
        let chain = Chain::open(&std::path::Path::new(&dir).join("chain"), 1 << 34, ChainParams::DEV_RECURSIVE, SeedText::new(PowParams::DEV), AcceptAllProofs).unwrap();
        let tip = chain.tip().unwrap().unwrap().height.min(n);
        let mut file = tip.to_le_bytes().to_vec();
        let c = crate::aggregate::DEV_RECURSIVE_CHAIN.unwrap();
        for w in c.base.iter().chain(&c.step).chain(&c.plan_root) {
            file.extend_from_slice(&w.to_le_bytes());
        }
        file.extend_from_slice(&ChainParams::DEV_RECURSIVE.genesis().header.to_bytes());
        for h in 1..=tip {
            let header = chain.header_at(h).unwrap().unwrap();
            let bytes = chain.block_bytes(&header.hash()).unwrap().expect("a body");
            file.extend_from_slice(&0i32.to_le_bytes());
            file.extend_from_slice(&bytes[..crate::block::HEADER_SIZE]);
            let body = &bytes[crate::block::HEADER_SIZE..];
            file.extend_from_slice(&(body.len() as u32).to_le_bytes());
            file.extend_from_slice(body);
            file.resize(file.len().div_ceil(4) * 4, 0);
        }
        std::fs::write(&out, &file).unwrap();
        println!("{tip} blocks, {} bytes", file.len());
    }
}
