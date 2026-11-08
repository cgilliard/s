//! tabminer's values for the fam node's arithmetic
//! (`node/src/user/node/arith.fam`, docs/NODE.md step 1), written as fam
//! tests to `node/src/user/node/arith_vectors.fam`: the 32×32→64 product,
//! BabyBear and its extension, the wide integers, the remainder of 64 bits
//! by 32, and `fri::log2_x256_ceil`. Each value comes from tabminer's own
//! code (or Rust's integers where tabminer uses them). `write_arith_vectors`
//! writes the file; `arith_vectors_are_current` checks it.

#[cfg(test)]
mod tests {
    use crate::difficulty::U256;
    use crate::ext::Fp4;
    use crate::poseidon2::{Fp, P};
    use std::fmt::Write;

    const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/arith_vectors.fam");

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
             \\ Written by miner/src/fam_vectors.rs (`cargo test --lib write_arith_vectors\n\
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

    #[test]
    fn arith_vectors_are_current() {
        let file = std::fs::read_to_string(PATH).expect("node/src/user/node/arith_vectors.fam");
        assert!(file == generate(), "the fam node's vectors are stale: run write_arith_vectors");
    }

    #[test]
    #[ignore = "writes node/src/user/node/arith_vectors.fam"]
    fn write_arith_vectors() {
        std::fs::write(PATH, generate()).unwrap();
    }
}
