//! Memory-hard proof of work in the style of Ethash, seeded by a text that
//! the chain exists to preserve.
//!
//! The American King James Bible in `resources/akjv.txt.gz` is embedded in
//! the binary and decompressed at startup ([`SeedText`], 4.3 MB). Every
//! dataset item is derived directly from it: starting from a state seeded
//! with the item index, each of [`PowParams::parents`] sequential steps uses
//! the current state to pick a byte offset anywhere in the text, absorbs the
//! [`WINDOW`]-byte slice at that offset and applies the Poseidon2
//! permutation. Because windows start at arbitrary byte offsets, no table
//! smaller than the text reproduces the derivation (hashing every window
//! would take about thirty times more space), and a single verification
//! touches tens of thousands of windows, so a node missing any part of the
//! text fails almost every block. Holding the complete text is therefore a
//! precondition for verifying the chain.
//!
//! Miners expand the text once into a 64 MB [`Dataset`] of 64-byte items.
//! The proof ([`hashimoto`]) seeds a 32-element mix from the header hash and
//! nonce, performs [`PowParams::accesses`] random reads of two adjacent items,
//! folds the mix to 8 elements and hashes it with the seed. Verifiers
//! recompute only the items a proof touches from the text (the light path).
//! A hash costs two permutations with the dataset and about
//! `2 * accesses * parents` without it, a gap no cheaper arithmetic closes,
//! so keeping the table is the economical choice even for custom silicon.
//!
//! All arithmetic is in BabyBear: the Ethash FNV step used in the mixing
//! loop becomes `a * FNV_PRIME + b` in the field, and the hashes are the
//! Poseidon2 permutation. Items are 16 field elements.

use crate::difficulty::U256;
use crate::poseidon2::{DIGEST, Fp, P, RATE, WIDTH, compress, permute_in_place};

pub type Digest = [Fp; DIGEST];
/// One dataset item: 16 field elements, 64 bytes.
pub type Item = [Fp; WIDTH];
/// Proof-of-work nonce: 32 arbitrary bytes.
pub type Nonce = [u8; 32];

/// Compressed seed text, embedded at build time.
pub const SEED_TEXT_GZ: &[u8] = include_bytes!("../../resources/akjv.txt.gz");

/// Size of the decompressed seed text, checked when loading.
pub const SEED_TEXT_LEN: usize = 4_340_917;

/// Bytes of text absorbed per derivation step: one sponge block.
pub const WINDOW: usize = 3 * RATE;

const FNV_PRIME: Fp = Fp::new(0x0100_0193);
const DOM_ITEM: u32 = 0x5041;
const DOM_SEED: u32 = 0x5042;
const MIX_WORDS: usize = 2 * WIDTH;

/// Dataset sizing. The item count is a power of two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowParams {
    pub log_dataset_items: u32,
    /// Sequential permutation steps, each absorbing one text window, per
    /// dataset item.
    pub parents: usize,
    /// Dataset reads (of two adjacent items each) per proof.
    pub accesses: usize,
}

impl PowParams {
    /// 64 MB dataset.
    pub const MAINNET: PowParams = PowParams { log_dataset_items: 20, parents: 256, accesses: 64 };

    pub const fn dataset_items(&self) -> usize {
        1 << self.log_dataset_items
    }

    pub const fn dataset_bytes(&self) -> usize {
        self.dataset_items() * WIDTH * 4
    }
}

/// `a * FNV_PRIME + b`.
#[inline(always)]
fn fnv(a: Fp, b: Fp) -> Fp {
    a.mul(&FNV_PRIME).add(&b)
}

/// Decompresses the embedded seed text.
pub fn seed_text() -> Vec<u8> {
    let out = crate::inflate::gunzip(SEED_TEXT_GZ).expect("embedded seed text is valid gzip");
    assert_eq!(out.len(), SEED_TEXT_LEN, "embedded seed text has unexpected length");
    out
}

/// Packs bytes three per element, little-endian, zero padding the last.
pub(crate) fn pack_bytes(bytes: &[u8]) -> Vec<Fp> {
    bytes
        .chunks(3)
        .map(|chunk| {
            let mut v = 0u32;
            for (i, byte) in chunk.iter().enumerate() {
                v |= (*byte as u32) << (8 * i);
            }
            Fp::new(v)
        })
        .collect()
}

/// Packs a text window into one sponge block, three bytes per element.
#[inline]
fn pack_window(window: &[u8]) -> [Fp; RATE] {
    let mut block = [Fp::ZERO; RATE];
    for (b, chunk) in block.iter_mut().zip(window.chunks(3)) {
        let mut v = 0u32;
        for (i, byte) in chunk.iter().enumerate() {
            v |= (*byte as u32) << (8 * i);
        }
        *b = Fp::new(v);
    }
    block
}

/// A nonce with the integer in its first eight bytes, for sequential search.
pub fn nonce_from_u64(n: u64) -> Nonce {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&n.to_le_bytes());
    out
}

/// Anything that can supply dataset items: the full [`Dataset`] or the
/// [`SeedText`] computing them on demand.
pub trait ItemSource {
    fn params(&self) -> &PowParams;
    fn item(&self, index: usize) -> Item;
}

/// The seed text, from which every dataset item is derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedText {
    params: PowParams,
    text: Vec<u8>,
}

impl SeedText {
    /// Loads the embedded text.
    pub fn new(params: PowParams) -> SeedText {
        Self::from_bytes(params, seed_text())
    }

    /// Uses arbitrary bytes as the seed (tests and future epochs). Must be at
    /// least [`WINDOW`] bytes long.
    pub fn from_bytes(params: PowParams, text: Vec<u8>) -> SeedText {
        assert!(text.len() >= WINDOW, "seed text shorter than one window");
        SeedText { params, text }
    }

    pub fn text(&self) -> &[u8] {
        &self.text
    }

    /// Computes dataset item `index`: `parents` sequential permutations, each
    /// preceded by absorbing the text window selected by the current state.
    pub fn calc_dataset_item(&self, index: usize) -> Item {
        assert!(index < self.params.dataset_items());
        let offsets = (self.text.len() - WINDOW + 1) as u64;
        let mut mix = [Fp::ZERO; WIDTH];
        mix[0] = Fp::from_u32(index as u32);
        mix[1] = Fp::new(DOM_ITEM);
        permute_in_place(&mut mix);
        for _ in 0..self.params.parents {
            let r = mix[0].to_canonical() as u64 | (mix[1].to_canonical() as u64) << 31;
            let offset = (r % offsets) as usize;
            let block = pack_window(&self.text[offset..offset + WINDOW]);
            for (m, b) in mix.iter_mut().zip(&block) {
                *m = m.add(b);
            }
            permute_in_place(&mut mix);
        }
        mix
    }
}

impl ItemSource for SeedText {
    fn params(&self) -> &PowParams {
        &self.params
    }

    fn item(&self, index: usize) -> Item {
        self.calc_dataset_item(index)
    }
}

/// The full dataset, held in memory by miners.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dataset {
    params: PowParams,
    items: Vec<Item>,
}

impl Dataset {
    /// Generates every item from the text, using all available threads.
    pub fn generate(seed: &SeedText) -> Dataset {
        let params = *seed.params();
        let n = params.dataset_items();
        let mut items = vec![[Fp::ZERO; WIDTH]; n];
        let threads = std::thread::available_parallelism().map(|t| t.get()).unwrap_or(1).min(n);
        let chunk = n.div_ceil(threads);
        std::thread::scope(|s| {
            for (t, slice) in items.chunks_mut(chunk).enumerate() {
                s.spawn(move || {
                    for (k, item) in slice.iter_mut().enumerate() {
                        *item = seed.calc_dataset_item(t * chunk + k);
                    }
                });
            }
        });
        Dataset { params, items }
    }

    /// Loads a dataset saved by [`Dataset::save`], or generates and saves
    /// it. A loaded file is accepted if it has the right size and a few
    /// items spread through it match the text.
    pub fn load_or_generate(seed: &SeedText, path: &std::path::Path) -> std::io::Result<Dataset> {
        let params = *seed.params();
        if let Ok(bytes) = std::fs::read(path)
            && let Some(d) = Self::from_bytes(params, &bytes)
        {
            let n = d.items.len();
            if (0..8).map(|k| k * (n - 1) / 7).all(|i| d.items[i] == seed.calc_dataset_item(i)) {
                return Ok(d);
            }
        }
        let d = Self::generate(seed);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, d.to_bytes())?;
        std::fs::rename(&tmp, path)?;
        Ok(d)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.items.len() * WIDTH * 4);
        for item in &self.items {
            for x in item {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        out
    }

    fn from_bytes(params: PowParams, bytes: &[u8]) -> Option<Dataset> {
        if bytes.len() != params.dataset_items() * WIDTH * 4 {
            return None;
        }
        let mut items = Vec::with_capacity(params.dataset_items());
        for chunk in bytes.chunks_exact(WIDTH * 4) {
            let mut item = [Fp::ZERO; WIDTH];
            for (x, b) in item.iter_mut().zip(chunk.chunks_exact(4)) {
                *x = Fp::from_le_bytes(b.try_into().unwrap())?;
            }
            items.push(item);
        }
        Some(Dataset { params, items })
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl ItemSource for Dataset {
    fn params(&self) -> &PowParams {
        &self.params
    }

    #[inline]
    fn item(&self, index: usize) -> Item {
        self.items[index]
    }
}

/// Seed state from the header hash and nonce: the header hash and a domain
/// tag fill the first block, the 32 nonce bytes (11 elements) follow.
fn seed(header_hash: &Digest, nonce: &Nonce) -> Item {
    let mut s = [Fp::ZERO; WIDTH];
    s[..DIGEST].copy_from_slice(header_hash);
    s[DIGEST] = Fp::new(DOM_SEED);
    permute_in_place(&mut s);
    for block in pack_bytes(nonce).chunks(RATE) {
        for (x, b) in s.iter_mut().zip(block) {
            *x = x.add(b);
        }
        permute_in_place(&mut s);
    }
    s
}

/// The final result for a claimed `mix`: two permutations, no dataset. Used
/// as a cheap pre-check before the full evaluation.
pub fn result_from_mix(header_hash: &Digest, nonce: &Nonce, mix: &Digest) -> Digest {
    let seed = seed(header_hash, nonce);
    let seed_head: Digest = seed[..DIGEST].try_into().unwrap();
    compress(mix, &seed_head)
}

/// Result of one proof-of-work evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowOutput {
    /// Folded mix, stored in the header so verifiers can check it.
    pub mix: Digest,
    /// Final hash compared against the target.
    pub result: Digest,
}

/// The memory-hard hash of `(header_hash, nonce)` using `source` for items.
pub fn hashimoto<S: ItemSource>(source: &S, header_hash: &Digest, nonce: &Nonce) -> PowOutput {
    let params = source.params();
    let seed = seed(header_hash, nonce);
    let mut mix = [Fp::ZERO; MIX_WORDS];
    mix[..WIDTH].copy_from_slice(&seed);
    mix[WIDTH..].copy_from_slice(&seed);
    let pairs = params.dataset_items() / 2;
    for i in 0..params.accesses {
        let sel = fnv(Fp::from_u32(i as u32).add(&seed[0]), mix[i % MIX_WORDS]);
        let idx = (sel.to_canonical() as usize % pairs) * 2;
        let a = source.item(idx);
        let b = source.item(idx + 1);
        for (m, d) in mix.iter_mut().zip(a.iter().chain(&b)) {
            *m = fnv(*m, *d);
        }
    }
    let mut cmix = [Fp::ZERO; DIGEST];
    for (k, c) in cmix.iter_mut().enumerate() {
        let w = &mix[4 * k..4 * k + 4];
        *c = fnv(fnv(fnv(w[0], w[1]), w[2]), w[3]);
    }
    let seed_head: Digest = seed[..DIGEST].try_into().unwrap();
    PowOutput { mix: cmix, result: compress(&cmix, &seed_head) }
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/// A 248-bit target as 32 little-endian bytes (the last one zero);
/// `result <= target` passes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Target(pub [u8; 32]);

/// The 248-bit integer a digest stands for (element 0 is the most
/// significant 31 bits), as 32 little-endian bytes with the last one zero.
pub fn digest_to_u248_le(d: &Digest) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut acc: u128 = 0;
    let mut bits = 0;
    let mut pos = 0;
    for e in d.iter().rev() {
        acc |= (e.to_canonical() as u128) << bits;
        bits += 31;
        while bits >= 8 {
            out[pos] = (acc & 0xff) as u8;
            pos += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
    out
}

impl Target {
    /// The largest possible target, 2^248 - 1: every result passes.
    pub const MAX: Target = {
        let mut t = [0xffu8; 32];
        t[31] = 0;
        Target(t)
    };

    /// Target requiring `bits` leading zero bits in the 248-bit result.
    pub fn from_leading_zero_bits(bits: u32) -> Target {
        assert!(bits <= 248);
        let ones = 248 - bits;
        let mut t = [0u8; 32];
        for (i, byte) in t.iter_mut().enumerate() {
            let lo = i as u32 * 8;
            if lo + 8 <= ones {
                *byte = 0xff;
            } else if lo < ones {
                *byte = ((1u32 << (ones - lo)) - 1) as u8;
            }
        }
        Target(t)
    }

    pub fn value(&self) -> U256 {
        U256::from_le_bytes(&self.0)
    }

    pub fn is_met_by(&self, result: &Digest) -> bool {
        U256::from_le_bytes(&digest_to_u248_le(result)) <= self.value()
    }
}

impl PartialOrd for Target {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Target {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.value().cmp(&other.value())
    }
}

/// Checks a proof of work using only the text: the mix must match and the
/// result must meet the target.
pub fn verify(seed: &SeedText, header_hash: &Digest, nonce: &Nonce, mix: &Digest, target: &Target) -> bool {
    let out = hashimoto(seed, header_hash, nonce);
    out.mix == *mix && target.is_met_by(&out.result)
}

/// Tries nonces in `nonces` until one meets `target`.
pub fn mine<S: ItemSource>(
    source: &S,
    header_hash: &Digest,
    target: &Target,
    nonces: impl IntoIterator<Item = Nonce>,
) -> Option<(Nonce, PowOutput)> {
    nonces.into_iter().map(|n| (n, hashimoto(source, header_hash, &n))).find(|(_, o)| target.is_met_by(&o.result))
}

const _: () = assert!(P > 0x0100_0193);

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    const SMALL: PowParams = PowParams { log_dataset_items: 10, parents: 256, accesses: 64 };

    fn small_seed() -> &'static SeedText {
        static SEED: OnceLock<SeedText> = OnceLock::new();
        SEED.get_or_init(|| SeedText::new(SMALL))
    }

    fn small_dataset() -> &'static Dataset {
        static DATASET: OnceLock<Dataset> = OnceLock::new();
        DATASET.get_or_init(|| Dataset::generate(small_seed()))
    }

    fn fnv1a64(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x0100_0000_01b3))
    }

    #[test]
    fn seed_text_is_the_expected_file() {
        let text = seed_text();
        assert_eq!(text.len(), SEED_TEXT_LEN);
        assert_eq!(fnv1a64(&text), 0xb128_7e0a_c9ad_c1c6);
        assert!(text.starts_with(b"### Genesis"));
        assert_eq!(small_seed().text().len(), SEED_TEXT_LEN);
    }

    #[test]
    fn mainnet_sizes() {
        assert_eq!(PowParams::MAINNET.dataset_bytes(), 64 << 20);
        assert_eq!(WINDOW, 24);
    }

    #[test]
    fn items_depend_on_every_part_of_the_text() {
        // A short synthetic text is covered densely by 256 windows per item:
        // an interior byte lies in 24 window offsets, so flipping it changes
        // nearly every item; an edge byte lies in a single offset and still
        // changes a good fraction of them.
        let base: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
        let a = SeedText::from_bytes(SMALL, base.clone());
        let items: Vec<Item> = (0..64).map(|i| a.calc_dataset_item(i)).collect();
        assert_eq!(items[..4], (0..4).map(|i| a.calc_dataset_item(i)).collect::<Vec<_>>()[..]);
        let changed = |pos: usize, count: usize| {
            let mut t = base.clone();
            t[pos] ^= 1;
            let b = SeedText::from_bytes(SMALL, t);
            (0..count).filter(|&i| b.calc_dataset_item(i) != items[i]).count()
        };
        for pos in [30usize, 499, 969] {
            let c = changed(pos, 8);
            assert!(c >= 7, "byte {pos}: only {c} of 8 items changed");
        }
        for pos in [0usize, 999] {
            let c = changed(pos, 64);
            assert!(c >= 8, "byte {pos}: only {c} of 64 items changed");
        }
        // A text shorter than one window is rejected.
        assert!(std::panic::catch_unwind(|| SeedText::from_bytes(SMALL, vec![0u8; WINDOW - 1])).is_err());
        // Exactly one window works and uses it every step.
        let one = SeedText::from_bytes(SMALL, vec![1u8; WINDOW]);
        assert_ne!(one.calc_dataset_item(0), one.calc_dataset_item(1));
    }

    #[test]
    fn dataset_matches_text_computation() {
        let seed = small_seed();
        let dataset = small_dataset();
        assert_eq!(dataset.len(), SMALL.dataset_items());
        for i in [0usize, 1, 2, 77, 1000, 1023] {
            assert_eq!(dataset.item(i), seed.calc_dataset_item(i), "item {i}");
        }
        assert_ne!(dataset.item(0), dataset.item(1));
    }

    #[test]
    fn light_and_full_evaluation_agree() {
        let seed = small_seed();
        let dataset = small_dataset();
        let h: Digest = core::array::from_fn(|i| Fp::new(100 + i as u32));
        let mut prev = None;
        for nonce in [0u64, 1, 2, u64::MAX, 1 << 40] {
            let nonce = nonce_from_u64(nonce);
            let full = hashimoto(dataset, &h, &nonce);
            let light = hashimoto(seed, &h, &nonce);
            assert_eq!(full, light, "nonce {nonce:?}");
            assert_ne!(Some(full.result), prev);
            prev = Some(full.result);
            assert_eq!(result_from_mix(&h, &nonce, &full.mix), full.result);
        }
        let zero = nonce_from_u64(0);
        let mut h2 = h;
        h2[7] += Fp::ONE;
        assert_ne!(hashimoto(dataset, &h2, &zero), hashimoto(dataset, &h, &zero));
        // All 32 nonce bytes matter.
        let mut tail = zero;
        tail[31] = 1;
        assert_ne!(hashimoto(dataset, &h, &tail), hashimoto(dataset, &h, &zero));
    }

    #[test]
    fn targets() {
        let zero = [Fp::ZERO; DIGEST];
        let max = [Fp::new(P - 1); DIGEST];
        assert_eq!(digest_to_u248_le(&zero), [0u8; 32]);
        let packed = digest_to_u248_le(&max);
        assert_eq!(packed[31], 0);
        // Elements 0..4 occupy bits 124..248 of the 248-bit value; the top 16
        // bytes hold bits 128..256, so they equal that 124-bit value >> 4.
        let mut big: u128 = 0;
        for e in max.iter().take(4) {
            big = (big << 31) | e.to_canonical() as u128;
        }
        let hi = u128::from_le_bytes(packed[16..].try_into().unwrap());
        assert_eq!(hi, big >> 4);
        let mut lo_expected: u128 = (max[3].to_canonical() & 0xf) as u128;
        for e in max.iter().skip(4) {
            lo_expected = (lo_expected << 31) | e.to_canonical() as u128;
        }
        assert_eq!(u128::from_le_bytes(packed[..16].try_into().unwrap()), lo_expected);

        assert!(Target::MAX.is_met_by(&max));
        assert_eq!(Target::from_leading_zero_bits(0), Target::MAX);
        let t8 = Target::from_leading_zero_bits(8);
        assert_eq!(t8.0[31], 0);
        assert_eq!(t8.0[30], 0);
        assert_eq!(t8.0[29], 0xff);
        let t3 = Target::from_leading_zero_bits(3);
        assert_eq!(t3.0[30], 0x1f);
        assert!(t3 > t8 && Target::MAX > t3);
        assert!(!t8.is_met_by(&max));
        let mut small = zero;
        small[0] = Fp::new(1 << 22); // 248-8 = 240 bits => element 0 must be < 2^23
        assert!(t8.is_met_by(&small));
        small[0] = Fp::new(1 << 23);
        assert!(!t8.is_met_by(&small));
        assert_eq!(Target::from_leading_zero_bits(248).0, [0u8; 32]);
        assert!(Target::from_leading_zero_bits(248).is_met_by(&zero));
    }

    /// Prints generation and evaluation timings at mainnet size.
    /// Run with `cargo test --release pow::tests::mainnet_timing -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn mainnet_timing() {
        use std::time::Instant;
        let t = Instant::now();
        let seed = SeedText::new(PowParams::MAINNET);
        println!("seed text ({} KB): {:?}", seed.text().len() / 1024, t.elapsed());
        let t = Instant::now();
        let dataset = Dataset::generate(&seed);
        println!("dataset ({} MB): {:?}", PowParams::MAINNET.dataset_bytes() >> 20, t.elapsed());
        let h: Digest = core::array::from_fn(|i| Fp::new(i as u32));
        let t = Instant::now();
        for n in 0..1000u64 {
            let _ = hashimoto(&dataset, &h, &nonce_from_u64(n));
        }
        println!("full hashimoto: {:?} per hash", t.elapsed() / 1000);
        let t = Instant::now();
        for n in 0..5u64 {
            let _ = hashimoto(&seed, &h, &nonce_from_u64(n));
        }
        println!("light hashimoto: {:?} per hash", t.elapsed() / 5);
        let five = nonce_from_u64(5);
        assert_eq!(hashimoto(&dataset, &h, &five), hashimoto(&seed, &h, &five));
    }

    #[test]
    fn mine_and_verify() {
        let seed = small_seed();
        let dataset = small_dataset();
        let h: Digest = core::array::from_fn(|i| Fp::new(7 * i as u32 + 1));
        let target = Target::from_leading_zero_bits(6);
        let (nonce, out) = mine(dataset, &h, &target, (0..10_000).map(nonce_from_u64)).expect("a nonce within range");
        assert!(target.is_met_by(&out.result));
        assert!(verify(seed, &h, &nonce, &out.mix, &target));
        let mut other = nonce;
        other[9] ^= 1;
        assert!(!verify(seed, &h, &other, &out.mix, &target));
        let mut bad_mix = out.mix;
        bad_mix[0] += Fp::ONE;
        assert!(!verify(seed, &h, &nonce, &bad_mix, &target));
        assert!(!verify(seed, &h, &nonce, &out.mix, &Target::from_leading_zero_bits(200)));
    }
}
