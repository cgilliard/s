//! Memory-hard proof of work in the style of Ethash, seeded by a text that
//! the chain exists to preserve.
//!
//! The seed is the American King James Bible as the gzip file
//! `resources/akjv.txt.gz` ([`SEED_TEXT_LEN`] bytes), embedded in the
//! binary and used as it is: nothing is decompressed. Its bytes are read in
//! [`WINDOW`]-byte windows on 24-byte boundaries, the last ending at the
//! file's end (it overlaps the one before), so every byte is in one: 53,795
//! of them. Aligned windows keep small the table a proof of the work looks
//! them up in (a row a window: `docs/NODE.md`, the work in the chain proof).
//!
//! Every dataset item is derived from the windows: starting from a state
//! seeded with the item index, each of [`PowParams::parents`] sequential
//! steps uses the state to pick a window, absorbs it and applies the
//! Poseidon2 permutation. Miners expand the file once into a 64 MB
//! [`Dataset`] of 64-byte items. The proof ([`hashimoto`]) seeds a
//! 32-element mix from the header hash and nonce and makes
//! [`PowParams::accesses`] reads, each folding in two adjacent items and one
//! window of the file itself, picked by a second selector; it then folds the
//! mix to 8 elements and hashes it with the seed.
//!
//! **Validating a block requires the entire seed file.** Checking a
//! header's work reads windows spread over the whole file: computing its 128
//! items from the file reads about 32,500 of them, and the direct reads take
//! 64 more however the items are had. So neither the dataset nor any hash of
//! the file substitutes for it, and a node missing any window soon meets a
//! block it cannot validate. Every validating node stores it.
//!
//! Verifiers compute only the items a proof touches, from the file. A hash
//! costs a few permutations with the dataset and about
//! `2 * accesses * parents` without it, a gap no cheaper arithmetic closes,
//! so keeping the table is the economical choice for miners, even with
//! custom silicon.
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

/// The seed file: the text gzipped, embedded at build time and used as it
/// is.
pub const SEED_TEXT_GZ: &[u8] = include_bytes!("../../resources/akjv.txt.gz");

/// The dev dataset ([`PowParams::DEV`]), generated once from the seed text
/// and built in (with the `dev` feature), so a dev node starts at once.
/// `dev_dataset_is_built_in` checks it; `write_dev_dataset` (an ignored
/// test) regenerates it.
#[cfg(feature = "dev")]
pub const DEV_DATASET: &[u8] = include_bytes!("../../resources/dev_dataset.bin");

/// Size of the seed file, checked when loading.
pub const SEED_TEXT_LEN: usize = 1_291_059;

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
    pub const MAINNET: PowParams = PowParams { log_dataset_items: 20, parents: 254, accesses: 64 };

    /// The dev networks' (`--network dev`): a 64 KB dataset, built into
    /// the binary ([`DEV_DATASET`]).
    pub const DEV: PowParams = PowParams { log_dataset_items: 10, parents: 254, accesses: 64 };

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

/// The seed file's bytes, as they are.
pub fn seed_text() -> Vec<u8> {
    assert_eq!(SEED_TEXT_GZ.len(), SEED_TEXT_LEN, "embedded seed file has unexpected length");
    SEED_TEXT_GZ.to_vec()
}

/// The window a direct read takes for a canonical selector value `v`, with
/// `n` windows: the low `L` bits of `v`, where `2^L` is the least power of
/// two at least `n`, less `n` once if that is `n` or more. Every window can
/// be taken; those below `2^L - n` twice as often.
pub fn direct_window(v: u32, n: usize) -> usize {
    let bits = (n as u32).next_power_of_two() - 1;
    let low = (v & bits) as usize;
    if low >= n { low - n } else { low }
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

/// Anything that can supply dataset items, and the seed file's windows: the
/// full [`Dataset`] beside the file, or the [`SeedText`] computing items on
/// demand.
pub trait ItemSource {
    fn params(&self) -> &PowParams;
    fn item(&self, index: usize) -> Item;
    /// The seed file, which [`hashimoto`] reads directly.
    fn seed(&self) -> &SeedText;
}

/// The seed file, from which every dataset item is derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedText {
    params: PowParams,
    text: Vec<u8>,
}

impl SeedText {
    /// The embedded seed file.
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

    /// The text's windows: one every [`WINDOW`] bytes, the last one ending
    /// at the text's end.
    pub fn windows(&self) -> usize {
        self.text.len().div_ceil(WINDOW)
    }

    /// Where window `w` starts: `w * WINDOW`, but the last one a window's
    /// length before the text's end.
    pub fn window_offset(&self, w: usize) -> usize {
        (w * WINDOW).min(self.text.len() - WINDOW)
    }

    /// Window `w`, packed into one sponge block.
    pub fn window(&self, w: usize) -> [Fp; RATE] {
        let at = self.window_offset(w);
        pack_window(&self.text[at..at + WINDOW])
    }

    /// Computes dataset item `index`: `parents` sequential permutations, each
    /// preceded by absorbing the text window selected by the current state.
    pub fn calc_dataset_item(&self, index: usize) -> Item {
        assert!(index < self.params.dataset_items());
        let windows = self.windows() as u64;
        let mut mix = [Fp::ZERO; WIDTH];
        mix[0] = Fp::from_u32(index as u32);
        mix[1] = Fp::new(DOM_ITEM);
        permute_in_place(&mut mix);
        for _ in 0..self.params.parents {
            let r = mix[0].to_canonical() as u64 | (mix[1].to_canonical() as u64) << 31;
            let offset = self.window_offset((r % windows) as usize);
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

    fn seed(&self) -> &SeedText {
        self
    }
}

/// The full dataset, held in memory by miners, with the seed file it was
/// made from (hashimoto reads both).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dataset {
    params: PowParams,
    items: Vec<Item>,
    seed: SeedText,
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
        Dataset { params, items, seed: seed.clone() }
    }

    /// Loads a saved dataset, or generates and saves it. A loaded file is
    /// accepted if it has the right size, its checksum holds (a corrupt
    /// item would make honest blocks look invalid) and a few items spread
    /// through it match the text.
    pub fn load_or_generate(seed: &SeedText, path: &std::path::Path) -> std::io::Result<Dataset> {
        if let Some(d) = Self::built_in(seed) {
            return Ok(d);
        }
        if let Ok(bytes) = std::fs::read(path)
            && bytes.len() > CHECKSUM_BYTES
            && let (body, sum) = bytes.split_at(bytes.len() - CHECKSUM_BYTES)
            && sum == checksum(body)
            && let Some(d) = Self::from_bytes(seed, body)
        {
            let n = d.items.len();
            if (0..8).map(|k| k * (n - 1) / 7).all(|i| d.items[i] == seed.calc_dataset_item(i)) {
                return Ok(d);
            }
        }
        let d = Self::generate(seed);
        let tmp = path.with_extension("tmp");
        let mut bytes = d.to_bytes();
        bytes.extend_from_slice(&checksum(&bytes));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(d)
    }

    /// The dataset built into the binary for `seed`, if any: the dev
    /// networks', from the embedded file, in a build with the `dev` feature.
    pub fn built_in(seed: &SeedText) -> Option<Dataset> {
        #[cfg(feature = "dev")]
        if seed.params == PowParams::DEV && seed.text == SEED_TEXT_GZ {
            return Self::from_bytes(seed, DEV_DATASET);
        }
        let _ = seed;
        None
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

    fn from_bytes(seed: &SeedText, bytes: &[u8]) -> Option<Dataset> {
        let params = seed.params;
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
        Some(Dataset { params, items, seed: seed.clone() })
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

const CHECKSUM_BYTES: usize = 8;

/// A checksum of the dataset file against corruption (not forgery: the
/// sampled items guard the contents, the chain's blocks the rest).
fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_BYTES] {
    use std::hash::Hasher;
    let mut h = std::hash::DefaultHasher::new();
    h.write(bytes);
    h.finish().to_le_bytes()
}

impl ItemSource for Dataset {
    fn params(&self) -> &PowParams {
        &self.params
    }

    #[inline]
    fn item(&self, index: usize) -> Item {
        self.items[index]
    }

    fn seed(&self) -> &SeedText {
        &self.seed
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

/// The memory-hard hash of `(header_hash, nonce)` using `source` for items
/// and the seed file. Each access folds in two adjacent items, picked by
/// `fnv(i + seed[0], mix[i % 32])`, and one window of the file, picked by
/// `fnv(i + seed[1], mix[(i + 16) % 32])` ([`direct_window`]): window
/// element `k % 8` is added to mix word `k` after its item's fold.
pub fn hashimoto<S: ItemSource>(source: &S, header_hash: &Digest, nonce: &Nonce) -> PowOutput {
    let params = source.params();
    let text = source.seed();
    let windows = text.windows();
    let seed = seed(header_hash, nonce);
    let mut mix = [Fp::ZERO; MIX_WORDS];
    mix[..WIDTH].copy_from_slice(&seed);
    mix[WIDTH..].copy_from_slice(&seed);
    let pairs = params.dataset_items() / 2;
    for i in 0..params.accesses {
        let sel = fnv(Fp::from_u32(i as u32).add(&seed[0]), mix[i % MIX_WORDS]);
        let sel2 = fnv(Fp::from_u32(i as u32).add(&seed[1]), mix[(i + WIDTH) % MIX_WORDS]);
        let idx = (sel.to_canonical() as usize % pairs) * 2;
        let x = text.window(direct_window(sel2.to_canonical(), windows));
        let a = source.item(idx);
        let b = source.item(idx + 1);
        for (k, (m, d)) in mix.iter_mut().zip(a.iter().chain(&b)).enumerate() {
            *m = fnv(*m, *d).add(&x[k % RATE]);
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

/// Checks a proof of work from `source`: the full [`Dataset`] with the seed
/// file (microseconds), or the file alone (tens of milliseconds). The mix
/// must be the true one and the result must meet the target.
pub fn verify<S: ItemSource>(source: &S, header_hash: &Digest, nonce: &Nonce, mix: &Digest, target: &Target) -> bool {
    let out = hashimoto(source, header_hash, nonce);
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

    /// The built-in dev dataset is the one the seed text gives.
    #[test]
    #[cfg(feature = "dev")]
    fn dev_dataset_is_built_in() {
        let built = Dataset::built_in(&SeedText::new(PowParams::DEV)).expect("the dev dataset decodes");
        assert_eq!(built, Dataset::generate(&SeedText::new(PowParams::DEV)), "regenerate it: write_dev_dataset");
        assert!(Dataset::built_in(&SeedText::new(PowParams::MAINNET)).is_none());
    }

    /// Writes `resources/dev_dataset.bin` from the seed text.
    #[test]
    #[ignore = "writes resources/dev_dataset.bin"]
    fn write_dev_dataset() {
        let d = Dataset::generate(&SeedText::new(PowParams::DEV));
        std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/../resources/dev_dataset.bin"), d.to_bytes()).unwrap();
    }
    use std::sync::OnceLock;

    const SMALL: PowParams = PowParams { log_dataset_items: 10, parents: 254, accesses: 64 };

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

    /// The seed is the gzip file as shipped, and it is the King James text.
    #[test]
    fn seed_file_is_the_king_james_text() {
        let file = seed_text();
        assert_eq!(file.len(), SEED_TEXT_LEN);
        assert_eq!(fnv1a64(&file), SEED_FILE_FNV);
        assert_eq!(small_seed().text(), &file[..]);
        let text = crate::inflate::gunzip(&file).expect("the seed file is gzip");
        assert_eq!(text.len(), 4_340_917);
        assert_eq!(fnv1a64(&text), 0xb128_7e0a_c9ad_c1c6);
        assert!(text.starts_with(b"### Genesis"));
    }

    const SEED_FILE_FNV: u64 = 0x9810_ea1c_2d2d_6c21;

    #[test]
    fn mainnet_sizes() {
        assert_eq!(PowParams::MAINNET.dataset_bytes(), 64 << 20);
        assert_eq!(WINDOW, 24);
        // Every byte of the file is in a window: the last one ends at its end.
        let seed = small_seed();
        assert_eq!(seed.windows(), 53_795);
        assert_eq!(seed.window_offset(53_793), 53_793 * WINDOW);
        assert_eq!(seed.window_offset(53_794) + WINDOW, SEED_TEXT_LEN);
        assert!(seed.window_offset(53_794) < 53_794 * WINDOW, "the last window overlaps the one before");
    }

    /// The direct reads' windows: every one reachable, the lowest twice.
    #[test]
    fn direct_windows_cover_the_file() {
        let n = 53_795;
        let mut hit = vec![0u8; n];
        for v in 0..1u32 << 16 {
            hit[direct_window(v, n)] += 1;
        }
        assert!(hit.iter().all(|&h| h >= 1));
        assert_eq!(hit.iter().filter(|&&h| h == 2).count(), (1 << 16) - n);
        assert_eq!(direct_window(0xffff, n), 0xffff - n);
        assert_eq!(direct_window(0x7000_0000 | 0x1234, n), 0x1234);
        assert_eq!(direct_window(12345, 1), 0);
        assert_eq!(direct_window(5, 8), 5);
    }

    /// Validating needs the entire file: the full dataset with any part of
    /// the file missing (zeroed) checks almost no proof of work, and
    /// computing items from a file with a single window changed fails some
    /// of sixteen headers (13 of 64 with this small dataset; about 45% of
    /// headers on mainnet, whose 2^20 items repeat less).
    #[test]
    fn validation_needs_the_entire_file() {
        let dataset = small_dataset();
        let h: Digest = core::array::from_fn(|i| Fp::new(31 + i as u32));
        let nonces: Vec<Nonce> = (0..64u64).map(nonce_from_u64).collect();
        let honest: Vec<PowOutput> = nonces.iter().map(|n| hashimoto(dataset, &h, n)).collect();
        let with_file = |file: Vec<u8>| Dataset { seed: SeedText::from_bytes(SMALL, file), ..dataset.clone() };
        let agree = |d: &Dataset| nonces.iter().zip(&honest).filter(|(n, o)| hashimoto(d, &h, n) == **o).count();
        // The dataset without the file.
        assert_eq!(agree(&with_file(vec![0u8; SEED_TEXT_LEN])), 0);
        // A tenth of it missing.
        let mut tenth = seed_text();
        tenth[SEED_TEXT_LEN / 2..SEED_TEXT_LEN / 2 + SEED_TEXT_LEN / 10].fill(0);
        assert!(agree(&with_file(tenth)) <= 1);
        // One window changed, items computed from the file.
        let mut one = seed_text();
        one[24 * 20_000] ^= 1;
        let damaged = SeedText::from_bytes(SMALL, one);
        let failed = nonces[..16].iter().zip(&honest).filter(|(n, o)| hashimoto(&damaged, &h, n) != **o).count();
        eprintln!("one window changed: {failed} of 16 fail");
        assert!(failed >= 1, "one window changed, and every header still checks");
    }

    #[test]
    fn items_depend_on_every_part_of_the_text() {
        // A short synthetic text of 42 windows (the last overlapping the one
        // before) is covered densely by 254 windows per item: every byte
        // lies in a window, so flipping any byte, the last ones included,
        // changes nearly every item.
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
        assert_eq!(a.windows(), 42);
        assert_eq!(a.window_offset(41), 1000 - WINDOW);
        for pos in [0usize, 30, 499, 969, 999] {
            let c = changed(pos, 8);
            assert!(c >= 7, "byte {pos}: only {c} of 8 items changed");
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
    fn dataset_and_file_evaluation_agree() {
        let seed = small_seed();
        let dataset = small_dataset();
        let h: Digest = core::array::from_fn(|i| Fp::new(100 + i as u32));
        let mut prev = None;
        for nonce in [0u64, 1, 2, u64::MAX, 1 << 40] {
            let nonce = nonce_from_u64(nonce);
            let full = hashimoto(dataset, &h, &nonce);
            let from_file = hashimoto(seed, &h, &nonce);
            assert_eq!(full, from_file, "nonce {nonce:?}");
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
        println!("seed file ({} KB): {:?}", seed.text().len() / 1024, t.elapsed());
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
        println!("hashimoto from the file: {:?} per hash", t.elapsed() / 5);
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
