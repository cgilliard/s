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
    }

    #[test]
    #[ignore = "writes the node's vectors: node/src/user/node/*_vectors.fam"]
    fn write_fam_vectors() {
        std::fs::write(PATH, generate()).unwrap();
        std::fs::write(P2_PATH, generate_poseidon2()).unwrap();
        std::fs::write(DIFF_PATH, generate_difficulty()).unwrap();
        std::fs::write(POW_PATH, generate_pow()).unwrap();
        std::fs::write(HDR_PATH, generate_headers()).unwrap();
    }
}
