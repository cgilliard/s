pub mod address;
pub mod aggregate;
pub mod bip39;
pub mod block;
pub mod block_air;
pub mod block_proof;
pub mod chain;
pub mod circuit;
pub mod chacha20poly1305;
pub mod channel;
pub mod chain_verifier;
pub mod challenger;
pub mod codec;
pub mod consensus;
pub mod difficulty;
pub mod ext;
pub mod fam_vectors;
#[cfg(test)]
mod fam_xmss_vectors;
pub mod field;
#[rustfmt::skip]
pub mod genesis;
pub mod fri;
pub mod hash_machine;
pub mod hash_table;
#[cfg(test)]
pub mod inflate;
pub mod keccak;
pub mod log;
pub mod mempool;
pub mod merkle;
pub mod mldsa;
pub mod mlkem;
pub mod name_air;
pub mod name_trie;
pub mod names;
pub mod net;
pub mod node;
pub mod ntt;
pub mod onion;
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub mod packed;
pub mod parallel;
pub mod policy;
pub mod proofs;
pub mod poseidon2;
pub mod poseidon2_air;
pub mod pow;
pub mod pow_air;
pub mod random;
pub mod recursion;
pub mod smt_air;
pub mod stark;
pub mod state_tree;
pub mod subnames;
pub mod transaction;
pub mod utxo;
pub mod vm_air;
pub mod wallet;
pub mod xmss;
pub mod xmss_air;
pub mod xmss_fragment;

#[cfg(test)]
pub(crate) mod test_util {
    use crate::ext::Fp4;
    use crate::poseidon2::Fp;

    thread_local! {
        static QUIET: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Keeps this thread's panics unreported while it lives (a fuzzer
    /// catching the panics it provokes), and only this thread's: the panic
    /// hook is the process's, and tests run in parallel, so swapping it
    /// would hide other tests' failures, and two swaps overlapping could
    /// leave it silent for the rest of the run.
    pub(crate) struct Quiet(bool);

    impl Quiet {
        pub(crate) fn new() -> Quiet {
            static HOOK: std::sync::Once = std::sync::Once::new();
            HOOK.call_once(|| {
                let report = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |info| {
                    if !QUIET.with(|q| q.get()) {
                        report(info)
                    }
                }));
            });
            Quiet(QUIET.with(|q| q.replace(true)))
        }
    }

    impl Drop for Quiet {
        fn drop(&mut self) {
            QUIET.with(|q| q.set(self.0));
        }
    }

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

    /// Fuzzes a decoder of untrusted bytes: `iters` mutants of the valid
    /// `samples` (a bit flipped, bytes overwritten, truncated, extended, a
    /// slice set to 0xff or duplicated, two samples spliced) and random
    /// inputs. `decode` returns `None` when it refuses the bytes, else
    /// their encoding again (or `None` inside for a decoder with no
    /// encoder). It must never panic, and what it decodes must encode back
    /// to the very bytes (one object, one encoding). Returns how many
    /// mutants decoded; panics with every failure.
    pub fn fuzz_decoder(
        name: &str,
        samples: &[Vec<u8>],
        iters: u64,
        decode: impl Fn(&[u8]) -> Option<Option<Vec<u8>>>,
    ) -> usize {
        let (iters, seed) = crate::stark::fuzz_params(iters, 0xdec0de);
        let mut rng = Rng::new(seed);
        for s in samples {
            match decode(s) {
                None => panic!("{name}: a valid sample is refused"),
                Some(Some(again)) => assert_eq!(&again, s, "{name}: a sample encodes to other bytes"),
                Some(None) => {}
            }
        }
        let (mut decoded, mut failures) = (0, Vec::new());
        let quiet = crate::test_util::Quiet::new();
        for n in 0..iters {
            let mut r = |m: usize| (rng.next_u64() % m.max(1) as u64) as usize;
            let si = r(samples.len());
            let mut b = samples[si].clone();
            let (at, len) = (r(b.len().max(1)), 1 + r(64));
            let what = match r(9) {
                0 if !b.is_empty() => {
                    b[at] ^= 1 << r(8);
                    "bit flipped"
                }
                1 if !b.is_empty() => {
                    b[at] = r(256) as u8;
                    "byte set"
                }
                2 => {
                    for i in at..(at + len).min(b.len()) {
                        b[i] = r(256) as u8;
                    }
                    "bytes randomized"
                }
                3 => {
                    b.truncate(at);
                    "truncated"
                }
                4 => {
                    b.extend((0..len).map(|_| r(256) as u8));
                    "extended"
                }
                5 => {
                    for i in at..(at + len).min(b.len()) {
                        b[i] = 0xff;
                    }
                    "bytes set to 0xff"
                }
                6 if !b.is_empty() => {
                    let end = (at + len).min(b.len());
                    let slice = b[at..end].to_vec();
                    b.splice(at..at, slice);
                    "bytes duplicated"
                }
                7 => {
                    let other = &samples[r(samples.len())];
                    let cut = r(other.len().max(1));
                    b.truncate(at);
                    b.extend_from_slice(&other[cut.min(other.len())..]);
                    "spliced"
                }
                _ => {
                    b = (0..r(256)).map(|_| r(256) as u8).collect();
                    "random"
                }
            };
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode(&b))) {
                Err(_) => failures.push(format!("mutant {n} ({what}): panicked")),
                Ok(Some(Some(again))) if again != b => {
                    let at = again.iter().zip(&b).position(|(x, y)| x != y).unwrap_or(again.len().min(b.len()));
                    failures.push(format!(
                        "mutant {n} ({what}) of sample {si}: decodes, but encodes to other bytes \
                         (from byte {at}: {:02x?} read, {:02x?} written; {} bytes read, {} written)",
                        &b[at..(at + 8).min(b.len())],
                        &again[at..(at + 8).min(again.len())],
                        b.len(),
                        again.len()
                    ))
                }
                Ok(Some(_)) => decoded += 1,
                Ok(None) => {}
            }
        }
        drop(quiet);
        assert!(failures.is_empty(), "{name} (seed {seed}): {} failures\n{}", failures.len(), failures.join("\n"));
        decoded
    }
}
