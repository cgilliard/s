pub mod aggregate;
pub mod block;
pub mod block_air;
pub mod block_proof;
pub mod chain;
pub mod challenger;
pub mod codec;
pub mod difficulty;
pub mod ext;
pub mod field;
pub mod fri;
pub mod hash_machine;
pub mod hash_table;
pub mod inflate;
pub mod merkle;
pub mod ntt;
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub mod packed;
pub mod parallel;
pub mod poseidon2;
pub mod poseidon2_air;
pub mod pow;
pub mod recursion;
pub mod smt_air;
pub mod stark;
pub mod state_tree;
pub mod transaction;
pub mod utxo;
pub mod vm_air;
pub mod xmss;
pub mod xmss_air;

#[cfg(test)]
pub(crate) mod test_util {
    use crate::ext::Fp4;
    use crate::poseidon2::Fp;

    /// SplitMix64, for deterministic test data without a dependency.
    pub struct Rng(u64);

    impl Rng {
        pub fn new(seed: u64) -> Rng {
            Rng(seed)
        }

        pub fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        pub fn fp(&mut self) -> Fp {
            Fp::from_u64(self.next_u64())
        }

        pub fn fp4(&mut self) -> Fp4 {
            Fp4([self.fp(), self.fp(), self.fp(), self.fp()])
        }
    }
}
