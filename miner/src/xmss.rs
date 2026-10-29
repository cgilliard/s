//! XMSS (eXtended Merkle Signature Scheme) with WOTS+ one-time signatures,
//! built on the Poseidon2 permutation over BabyBear from [`crate::poseidon2`].
//!
//! The Merkle tree height `H` is a const generic parameter of
//! [`SecretKey`] and [`Signature`]; a key pair can sign `2^H` messages.
//!
//! # Construction
//!
//! All hashing goes through one tweakable sponge, [`th`], whose 8-element
//! capacity is initialised with the public seed, a domain tag, a 60-bit index
//! and a small extra word. Every call site therefore has a distinct tweak:
//!
//! | use                        | domain          | index          | extra             |
//! |----------------------------|-----------------|----------------|-------------------|
//! | WOTS secret chain starts   | `DOM_WOTS_PRF`  | leaf index     | chain             |
//! | WOTS chain steps           | `DOM_WOTS_CHAIN`| leaf index     | chain + step<<16  |
//! | WOTS public key (leaf)     | `DOM_WOTS_PK`   | leaf index     | 0                 |
//! | Merkle tree nodes          | `DOM_TREE`      | heap position  | level             |
//! | message digest             | `DOM_MSG`       | leaf index     | 0                 |
//! | message randomizer         | `DOM_RAND`      | leaf index     | 0                 |
//! | seed expansion             | `DOM_KEYGEN`    | 0 or 1         | 0                 |
//!
//! Digests are 8 BabyBear elements (248 bits). WOTS+ uses the Winternitz
//! parameter `w = 16`. Each 31-bit element is split into eight digits: seven
//! of four bits and a top digit of three bits, so every digit comes from a
//! single element (which keeps the in-circuit decomposition simple). That
//! gives 64 message chains plus 3 checksum chains. Chain steps use
//! per-position tweaks instead of bitmasks, as in SPHINCS+.
//!
//! Secret chain starts are derived from a secret seed with the PRF above, so
//! the secret key is just the two seeds plus the next unused leaf index. The
//! [`SecretKey`] additionally caches the full tree (`2^(H+1)` digests, 32
//! bytes each) so that signing does not recompute leaves.
//!
//! XMSS is stateful: a leaf must never be used twice. [`SecretKey::sign`]
//! advances the index before producing a signature, and
//! [`SecretKey::to_bytes`] records the index, so persist the key after each
//! signature and never restore an older copy.

use core::fmt;

use crate::poseidon2::{DIGEST, Fp, WIDTH, permute_in_place};

/// A hash output: 8 BabyBear elements.
pub type Digest = [Fp; DIGEST];

/// Winternitz parameter.
pub const W: usize = 16;
/// `log2(W)`: bits of message digest consumed per chain.
pub const LOG_W: usize = 4;
/// Bits of a digest used for the message part of a WOTS signature.
pub const MSG_BITS: usize = DIGEST * 31;
/// Digits per digest element: seven 4-bit digits and one 3-bit digit.
pub const DIGITS_PER_ELEMENT: usize = 8;
/// Number of WOTS chains covering the message digest.
pub const MSG_CHAINS: usize = DIGEST * DIGITS_PER_ELEMENT;
/// Number of WOTS chains covering the checksum.
pub const CSUM_CHAINS: usize = 3;
/// Total number of WOTS chains.
pub const CHAINS: usize = MSG_CHAINS + CSUM_CHAINS;
/// Largest possible checksum: 56 four-bit digits and 8 three-bit digits.
pub const MAX_CSUM: usize = DIGEST * 7 * (W - 1) + DIGEST * (W - 1);

const _: () = assert!(31 == 7 * LOG_W + 3);
const _: () = assert!(MAX_CSUM < 1 << (CSUM_CHAINS * LOG_W));
const _: () = assert!(2 * DIGEST == WIDTH);

/// Size in bytes of the seed accepted by [`SecretKey::generate`].
pub const SEED_SIZE: usize = 32;
/// Number of field elements in the public seed.
pub const PUB_SEED_LEN: usize = 4;
/// Serialized size of one field element.
const FP_BYTES: usize = 4;
/// Serialized size of a digest.
pub const DIGEST_BYTES: usize = DIGEST * FP_BYTES;
/// Serialized size of a [`SecretKey`] (seeds and index; independent of `H`).
pub const SECRET_KEY_SIZE: usize = (DIGEST + PUB_SEED_LEN) * FP_BYTES + 8;

const DOM_WOTS_PRF: u32 = 1;
pub(crate) const DOM_WOTS_CHAIN: u32 = 2;
pub(crate) const DOM_WOTS_PK: u32 = 3;
pub(crate) const DOM_TREE: u32 = 4;
pub(crate) const DOM_MSG: u32 = 5;
const DOM_RAND: u32 = 6;
const DOM_KEYGEN: u32 = 7;

const MASK30: u64 = (1 << 30) - 1;

// ---------------------------------------------------------------------------
// Tweakable hash
// ---------------------------------------------------------------------------

/// Tweakable sponge hash. The capacity holds `pub_seed`, `domain`, the
/// 60-bit `index` and `extra`; `msg` is absorbed 8 elements at a time by
/// addition into the rate with a permutation after every block (a short
/// final block is zero padded). Returns the first 8 state elements.
///
/// Callers must make the (domain, index, extra, message length) combination
/// unique per use so that zero padding is unambiguous.
pub(crate) fn th(pub_seed: &[Fp; PUB_SEED_LEN], domain: u32, index: u64, extra: u32, msg: &[Fp]) -> Digest {
    debug_assert!(index >> 60 == 0, "index exceeds 60 bits");
    let mut state = [Fp::ZERO; WIDTH];
    state[DIGEST..DIGEST + PUB_SEED_LEN].copy_from_slice(pub_seed);
    state[DIGEST + PUB_SEED_LEN] = Fp::new(domain);
    // Integers are split into 30-bit limbs: the modulus is below 2^31.
    state[DIGEST + PUB_SEED_LEN + 1] = Fp::new((index & MASK30) as u32);
    state[DIGEST + PUB_SEED_LEN + 2] = Fp::new((index >> 30) as u32);
    state[DIGEST + PUB_SEED_LEN + 3] = Fp::new(extra);
    let mut absorbed = false;
    for chunk in msg.chunks(DIGEST) {
        for (s, x) in state.iter_mut().zip(chunk) {
            *s = s.add(x);
        }
        permute_in_place(&mut state);
        absorbed = true;
    }
    if !absorbed {
        permute_in_place(&mut state);
    }
    state[..DIGEST].try_into().unwrap()
}

/// Packs bytes into field elements, three bytes (24 bits) per element,
/// little-endian, zero padding the final element.
fn bytes_to_fps(bytes: &[u8]) -> Vec<Fp> {
    bytes
        .chunks(3)
        .map(|c| {
            let mut v = 0u32;
            for (i, b) in c.iter().enumerate() {
                v |= (*b as u32) << (8 * i);
            }
            Fp::new(v)
        })
        .collect()
}

fn fps_to_bytes(out: &mut Vec<u8>, fps: &[Fp]) {
    for x in fps {
        out.extend_from_slice(&x.to_le_bytes());
    }
}

/// Parses `N` canonical field elements from the front of `bytes`, returning
/// them and the remaining slice. Fails on short input or non-canonical values.
fn read_fps<const N: usize>(bytes: &[u8]) -> Option<([Fp; N], &[u8])> {
    if bytes.len() < N * FP_BYTES {
        return None;
    }
    let mut out = [Fp::ZERO; N];
    for (i, c) in bytes[..N * FP_BYTES].chunks_exact(FP_BYTES).enumerate() {
        out[i] = Fp::from_le_bytes(c.try_into().unwrap())?;
    }
    Some((out, &bytes[N * FP_BYTES..]))
}

// ---------------------------------------------------------------------------
// WOTS+
// ---------------------------------------------------------------------------

/// Secret start of chain `chain` of the WOTS key pair at `leaf`.
fn wots_sk(pub_seed: &[Fp; PUB_SEED_LEN], sk_seed: &Digest, leaf: u64, chain: usize) -> Digest {
    th(pub_seed, DOM_WOTS_PRF, leaf, chain as u32, sk_seed)
}

/// Applies `steps` chain steps to `x`, starting at step `start`.
fn chain(pub_seed: &[Fp; PUB_SEED_LEN], leaf: u64, chain: usize, x: &Digest, start: usize, steps: usize) -> Digest {
    debug_assert!(start + steps < W);
    let mut x = *x;
    for step in start..start + steps {
        x = th(pub_seed, DOM_WOTS_CHAIN, leaf, (chain as u32) | ((step as u32) << 16), &x);
    }
    x
}

/// Compresses the `CHAINS` chain end points into the WOTS public key, which
/// is the Merkle leaf.
fn wots_pk_from_ends(pub_seed: &[Fp; PUB_SEED_LEN], leaf: u64, ends: &[Digest; CHAINS]) -> Digest {
    let flat: Vec<Fp> = ends.iter().flatten().copied().collect();
    th(pub_seed, DOM_WOTS_PK, leaf, 0, &flat)
}

/// Computes the WOTS public key (Merkle leaf) at `leaf` from the secret seed.
fn wots_leaf(pub_seed: &[Fp; PUB_SEED_LEN], sk_seed: &Digest, leaf: u64) -> Digest {
    let mut ends = [[Fp::ZERO; DIGEST]; CHAINS];
    for (c, end) in ends.iter_mut().enumerate() {
        let sk = wots_sk(pub_seed, sk_seed, leaf, c);
        *end = chain(pub_seed, leaf, c, &sk, 0, W - 1);
    }
    wots_pk_from_ends(pub_seed, leaf, &ends)
}

/// Splits a digest into `MSG_CHAINS` digits, eight per element (bits 0..28
/// as seven 4-bit digits, bits 28..31 as one 3-bit digit, least significant
/// first), and appends the `CSUM_CHAINS` base-16 checksum digits of
/// `sum(15 - digit)`.
pub(crate) fn digits(d: &Digest) -> [u8; CHAINS] {
    let mut out = [0u8; CHAINS];
    for (e, x) in d.iter().enumerate() {
        let v = x.to_canonical();
        for k in 0..DIGITS_PER_ELEMENT {
            out[e * DIGITS_PER_ELEMENT + k] = ((v >> (LOG_W * k)) & (W as u32 - 1)) as u8;
        }
    }
    let csum: u32 = out[..MSG_CHAINS].iter().map(|&x| (W - 1) as u32 - x as u32).sum();
    for i in 0..CSUM_CHAINS {
        out[MSG_CHAINS + i] = ((csum >> (LOG_W * i)) & (W as u32 - 1)) as u8;
    }
    out
}

/// Randomized digest of a message of field elements, bound to the leaf
/// index. The randomizer and the element count are absorbed first.
pub(crate) fn message_digest(pub_seed: &[Fp; PUB_SEED_LEN], leaf: u64, randomizer: &Digest, msg: &[Fp]) -> Digest {
    let mut input = Vec::with_capacity(DIGEST + 1 + msg.len());
    input.extend_from_slice(randomizer);
    input.push(Fp::from_u64(msg.len() as u64));
    input.extend_from_slice(msg);
    th(pub_seed, DOM_MSG, leaf, 0, &input)
}

/// Encodes a byte string as field elements: the byte length followed by the
/// bytes packed three per element.
pub fn bytes_to_message(bytes: &[u8]) -> Vec<Fp> {
    let mut out = Vec::with_capacity(1 + bytes.len().div_ceil(3));
    out.push(Fp::from_u64(bytes.len() as u64));
    out.extend(bytes_to_fps(bytes));
    out
}

// ---------------------------------------------------------------------------
// Merkle tree
// ---------------------------------------------------------------------------

/// Hashes two children into the node at heap position `pos` and height
/// `level` (leaves are level 0, the root is level `H`).
fn tree_node(pub_seed: &[Fp; PUB_SEED_LEN], pos: u64, level: u32, left: &Digest, right: &Digest) -> Digest {
    let mut input = [Fp::ZERO; 2 * DIGEST];
    input[..DIGEST].copy_from_slice(left);
    input[DIGEST..].copy_from_slice(right);
    th(pub_seed, DOM_TREE, pos, level, &input)
}

// ---------------------------------------------------------------------------
// Keys and signatures
// ---------------------------------------------------------------------------

/// Returned by [`SecretKey::sign`] once all `2^H` leaves have been used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyExhausted;

impl fmt::Display for KeyExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XMSS key exhausted: all one-time leaves have been used")
    }
}

impl std::error::Error for KeyExhausted {}

/// XMSS public key: Merkle root plus the public seed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicKey {
    pub root: Digest,
    pub pub_seed: [Fp; PUB_SEED_LEN],
}

/// XMSS signature for a tree of height `H`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature<const H: usize> {
    /// Leaf index used for this signature.
    pub index: u64,
    /// Randomizer mixed into the message digest.
    pub randomizer: Digest,
    /// WOTS+ signature: one intermediate chain value per chain.
    pub wots: [Digest; CHAINS],
    /// Sibling nodes from the leaf up to (but excluding) the root.
    pub auth_path: [Digest; H],
}

/// XMSS secret key for a tree of height `H`, with the tree cached.
#[derive(Clone)]
pub struct SecretKey<const H: usize> {
    sk_seed: Digest,
    pub_seed: [Fp; PUB_SEED_LEN],
    next_index: u64,
    /// Heap layout: position 1 is the root, leaf `i` is at `2^H + i`.
    tree: Vec<Digest>,
}

impl PublicKey {
    /// Serialized size in bytes.
    pub const SIZE: usize = (DIGEST + PUB_SEED_LEN) * FP_BYTES;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = Vec::with_capacity(Self::SIZE);
        fps_to_bytes(&mut out, &self.root);
        fps_to_bytes(&mut out, &self.pub_seed);
        out.try_into().unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<PublicKey> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        let (root, rest) = read_fps::<DIGEST>(bytes)?;
        let (pub_seed, _) = read_fps::<PUB_SEED_LEN>(rest)?;
        Some(PublicKey { root, pub_seed })
    }

    /// Verifies `sig` over a message of field elements. Returns `false` for
    /// an out-of-range leaf index or any mismatch.
    pub fn verify<const H: usize>(&self, msg: &[Fp], sig: &Signature<H>) -> bool {
        if H > 40 || sig.index >= (1u64 << H) {
            return false;
        }
        let d = digits(&message_digest(&self.pub_seed, sig.index, &sig.randomizer, msg));
        let mut ends = [[Fp::ZERO; DIGEST]; CHAINS];
        for (c, end) in ends.iter_mut().enumerate() {
            let done = d[c] as usize;
            *end = chain(&self.pub_seed, sig.index, c, &sig.wots[c], done, W - 1 - done);
        }
        let mut node = wots_pk_from_ends(&self.pub_seed, sig.index, &ends);
        let mut pos = (1u64 << H) + sig.index;
        for (level, sibling) in sig.auth_path.iter().enumerate() {
            let (left, right) = if pos & 1 == 0 { (&node, sibling) } else { (sibling, &node) };
            pos >>= 1;
            node = tree_node(&self.pub_seed, pos, (level + 1) as u32, left, right);
        }
        node == self.root
    }

    /// Verifies a signature made with [`SecretKey::sign_bytes`].
    pub fn verify_bytes<const H: usize>(&self, msg: &[u8], sig: &Signature<H>) -> bool {
        self.verify(&bytes_to_message(msg), sig)
    }
}

impl<const H: usize> Signature<H> {
    /// Serialized size in bytes.
    pub const SIZE: usize = 8 + (1 + CHAINS + H) * DIGEST_BYTES;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        out.extend_from_slice(&self.index.to_le_bytes());
        fps_to_bytes(&mut out, &self.randomizer);
        for d in &self.wots {
            fps_to_bytes(&mut out, d);
        }
        for d in &self.auth_path {
            fps_to_bytes(&mut out, d);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Signature<H>> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        let index = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let (randomizer, mut rest) = read_fps::<DIGEST>(&bytes[8..])?;
        let mut wots = [[Fp::ZERO; DIGEST]; CHAINS];
        for d in wots.iter_mut() {
            let (v, r) = read_fps::<DIGEST>(rest)?;
            *d = v;
            rest = r;
        }
        let mut auth_path = [[Fp::ZERO; DIGEST]; H];
        for d in auth_path.iter_mut() {
            let (v, r) = read_fps::<DIGEST>(rest)?;
            *d = v;
            rest = r;
        }
        Some(Signature { index, randomizer, wots, auth_path })
    }
}

impl<const H: usize> SecretKey<H> {
    /// Number of signatures a key pair can produce.
    pub const LEAVES: u64 = 1 << H;
    /// Serialized size in bytes (seeds and index; the tree is rebuilt on load).
    pub const SIZE: usize = SECRET_KEY_SIZE;

    /// Derives a key pair deterministically from `seed`, which must be
    /// uniformly random (for example 32 bytes from the operating system RNG).
    /// Builds the whole tree: cost grows as `2^H`.
    pub fn generate(seed: &[u8; SEED_SIZE]) -> SecretKey<H> {
        const {
            assert!(H >= 1 && H <= 40, "tree height must be between 1 and 40");
        }
        let seed_fps = bytes_to_fps(seed);
        let zero = [Fp::ZERO; PUB_SEED_LEN];
        let sk_seed = th(&zero, DOM_KEYGEN, 0, 0, &seed_fps);
        let ps = th(&zero, DOM_KEYGEN, 1, 0, &seed_fps);
        let pub_seed = ps[..PUB_SEED_LEN].try_into().unwrap();
        Self::from_parts(sk_seed, pub_seed, 0)
    }

    fn from_parts(sk_seed: Digest, pub_seed: [Fp; PUB_SEED_LEN], next_index: u64) -> SecretKey<H> {
        let n = 1usize << H;
        let mut tree = vec![[Fp::ZERO; DIGEST]; 2 * n];
        for i in 0..n {
            tree[n + i] = wots_leaf(&pub_seed, &sk_seed, i as u64);
        }
        for level in 1..=H {
            let start = 1usize << (H - level);
            for pos in start..2 * start {
                tree[pos] = tree_node(&pub_seed, pos as u64, level as u32, &tree[2 * pos], &tree[2 * pos + 1]);
            }
        }
        SecretKey { sk_seed, pub_seed, next_index, tree }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey { root: self.tree[1], pub_seed: self.pub_seed }
    }

    /// Index of the leaf the next signature will use.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Moves to leaf `index`, skipping the ones before it. Used to resume a
    /// key whose leaf count is kept elsewhere; never move backwards.
    pub fn set_next_index(&mut self, index: u64) {
        assert!(index <= Self::LEAVES, "leaf index beyond the tree");
        self.next_index = index;
    }

    /// Number of signatures left.
    pub fn remaining(&self) -> u64 {
        Self::LEAVES - self.next_index
    }

    /// Signs a message of field elements with the next unused leaf and
    /// advances the index.
    pub fn sign(&mut self, msg: &[Fp]) -> Result<Signature<H>, KeyExhausted> {
        if self.next_index >= Self::LEAVES {
            return Err(KeyExhausted);
        }
        let index = self.next_index;
        self.next_index += 1;

        let randomizer = th(&self.pub_seed, DOM_RAND, index, 0, &self.sk_seed);
        let d = digits(&message_digest(&self.pub_seed, index, &randomizer, msg));
        let mut wots = [[Fp::ZERO; DIGEST]; CHAINS];
        for (c, out) in wots.iter_mut().enumerate() {
            let sk = wots_sk(&self.pub_seed, &self.sk_seed, index, c);
            *out = chain(&self.pub_seed, index, c, &sk, 0, d[c] as usize);
        }
        let mut auth_path = [[Fp::ZERO; DIGEST]; H];
        let mut pos = (1usize << H) + index as usize;
        for sibling in auth_path.iter_mut() {
            *sibling = self.tree[pos ^ 1];
            pos >>= 1;
        }
        Ok(Signature { index, randomizer, wots, auth_path })
    }

    /// Signs a byte string, encoded with [`bytes_to_message`].
    pub fn sign_bytes(&mut self, msg: &[u8]) -> Result<Signature<H>, KeyExhausted> {
        self.sign(&bytes_to_message(msg))
    }

    /// Serializes the seeds and the next index. Store this after every
    /// signature; restoring an older copy reuses leaves and breaks security.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        let mut out = Vec::with_capacity(SECRET_KEY_SIZE);
        fps_to_bytes(&mut out, &self.sk_seed);
        fps_to_bytes(&mut out, &self.pub_seed);
        out.extend_from_slice(&self.next_index.to_le_bytes());
        out.try_into().unwrap()
    }

    /// Restores a key from [`SecretKey::to_bytes`], rebuilding the tree.
    pub fn from_bytes(bytes: &[u8]) -> Option<SecretKey<H>> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        let (sk_seed, rest) = read_fps::<DIGEST>(bytes)?;
        let (pub_seed, rest) = read_fps::<PUB_SEED_LEN>(rest)?;
        let next_index = u64::from_le_bytes(rest.try_into().unwrap());
        if next_index > Self::LEAVES {
            return None;
        }
        Some(Self::from_parts(sk_seed, pub_seed, next_index))
    }
}

impl<const H: usize> fmt::Debug for SecretKey<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("height", &H)
            .field("next_index", &self.next_index)
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::P;

    const SEED: [u8; SEED_SIZE] = [7u8; SEED_SIZE];

    fn other_seed() -> [u8; SEED_SIZE] {
        let mut s = SEED;
        s[0] ^= 1;
        s
    }

    #[test]
    fn parameters() {
        assert_eq!(MSG_BITS, 248);
        assert_eq!(MSG_CHAINS, 64);
        assert_eq!(CHAINS, 67);
        assert_eq!(MAX_CSUM, 960);
        assert_eq!(PublicKey::SIZE, 48);
        assert_eq!(Signature::<3>::SIZE, 8 + 32 + 67 * 32 + 3 * 32);
        assert_eq!(SecretKey::<3>::SIZE, 56);
        assert_eq!(SecretKey::<3>::LEAVES, 8);
    }

    #[test]
    fn digits_cover_all_bits_and_checksum() {
        let z = digits(&[Fp::ZERO; DIGEST]);
        assert!(z[..MSG_CHAINS].iter().all(|&x| x == 0));
        // checksum = 64 * 15 = 960 = 0x3c0 -> digits [0, 12, 3]
        assert_eq!(&z[MSG_CHAINS..], &[0, 12, 3]);

        let max = [Fp::new(P - 1); DIGEST];
        let v = digits(&max);
        // p - 1 = 0x78000000: digits 0..7 of each element are 0,0,0,0,0,0,8,7.
        for e in 0..DIGEST {
            assert_eq!(&v[e * 8..e * 8 + 8], &[0, 0, 0, 0, 0, 0, 8, 7], "element {e}");
        }
        // Independent reconstruction from the bit string, element by element.
        let mixed: Digest = core::array::from_fn(|i| Fp::new(0x1234_5678u32.wrapping_mul(i as u32 + 1) % P));
        let d = digits(&mixed);
        for (e, x) in mixed.iter().enumerate() {
            let c = x.to_canonical();
            for k in 0..8 {
                let bits = if k < 7 { 4 } else { 3 };
                let want = (c >> (4 * k)) & ((1 << bits) - 1);
                assert_eq!(d[e * 8 + k] as u32, want, "element {e} digit {k}");
            }
            // Every bit of the element is covered exactly once.
            let rebuilt: u32 = (0..8).map(|k| (d[e * 8 + k] as u32) << (4 * k)).sum();
            assert_eq!(rebuilt, c);
        }
        let csum: u32 = d[..MSG_CHAINS].iter().map(|&x| 15 - x as u32).sum();
        assert!(csum as usize <= MAX_CSUM);
        let csum_digits = (0..3).map(|i| (csum >> (4 * i)) & 15).collect::<Vec<_>>();
        assert_eq!(d[MSG_CHAINS..].iter().map(|&x| x as u32).collect::<Vec<_>>(), csum_digits);
    }

    #[test]
    fn th_separates_domains_and_tweaks() {
        let ps = [Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)];
        let m = [Fp::new(9); DIGEST];
        let base = th(&ps, DOM_TREE, 5, 6, &m);
        assert_eq!(base, th(&ps, DOM_TREE, 5, 6, &m));
        assert_ne!(base, th(&ps, DOM_MSG, 5, 6, &m));
        assert_ne!(base, th(&ps, DOM_TREE, 4, 6, &m));
        assert_ne!(base, th(&ps, DOM_TREE, 5, 7, &m));
        assert_ne!(base, th(&ps, DOM_TREE, 5 | (1 << 40), 6, &m));
        // Low limb at the modulus boundary must not panic.
        let _ = th(&ps, DOM_TREE, (1 << 31) - 1, 6, &m);
        let _ = th(&ps, DOM_TREE, (1 << 60) - 1, 6, &m);
        let mut ps2 = ps;
        ps2[3] = Fp::new(5);
        assert_ne!(base, th(&ps2, DOM_TREE, 5, 6, &m));
        // Zero padding: an empty message and a single zero element collide,
        // which is why every call site fixes the message length per tweak or
        // absorbs the length explicitly.
        assert_eq!(th(&ps, DOM_TREE, 0, 0, &[]), th(&ps, DOM_TREE, 0, 0, &[Fp::ZERO]));
        assert_ne!(th(&ps, DOM_TREE, 0, 0, &m), th(&ps, DOM_TREE, 0, 0, &m[..7]));
    }

    #[test]
    fn keygen_is_deterministic() {
        let a = SecretKey::<2>::generate(&SEED);
        let b = SecretKey::<2>::generate(&SEED);
        let c = SecretKey::<2>::generate(&other_seed());
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a.public_key(), c.public_key());
        assert_ne!(a.public_key().root, [Fp::ZERO; DIGEST]);
    }

    #[test]
    fn sign_verify_every_leaf_then_exhaust() {
        const H: usize = 3;
        let mut sk = SecretKey::<H>::generate(&SEED);
        let pk = sk.public_key();
        assert_eq!(sk.remaining(), 8);
        for i in 0..SecretKey::<H>::LEAVES {
            let msg = format!("message number {i}");
            assert_eq!(sk.next_index(), i);
            let sig = sk.sign_bytes(msg.as_bytes()).unwrap();
            assert_eq!(sig.index, i);
            assert!(pk.verify_bytes(msg.as_bytes(), &sig), "leaf {i}");
            assert!(!pk.verify_bytes(b"message number 99", &sig));
        }
        assert_eq!(sk.remaining(), 0);
        assert_eq!(sk.sign_bytes(b"one more"), Err(KeyExhausted));
    }

    #[test]
    fn tampered_signatures_fail() {
        const H: usize = 2;
        let mut sk = SecretKey::<H>::generate(&SEED);
        let pk = sk.public_key();
        let msg = b"hello";
        let sig = sk.sign_bytes(msg).unwrap();
        assert!(pk.verify_bytes(msg, &sig));

        let mut s = sig.clone();
        s.index = 1;
        assert!(!pk.verify_bytes(msg, &s));
        let mut s = sig.clone();
        s.index = 1 << H;
        assert!(!pk.verify_bytes(msg, &s));
        let mut s = sig.clone();
        s.randomizer[0] += Fp::ONE;
        assert!(!pk.verify_bytes(msg, &s));
        for c in [0, 31, MSG_CHAINS - 1, CHAINS - 1] {
            let mut s = sig.clone();
            s.wots[c][3] += Fp::ONE;
            assert!(!pk.verify_bytes(msg, &s), "chain {c}");
        }
        for l in 0..H {
            let mut s = sig.clone();
            s.auth_path[l][0] += Fp::ONE;
            assert!(!pk.verify_bytes(msg, &s), "auth level {l}");
        }
        let other = SecretKey::<H>::generate(&other_seed()).public_key();
        assert!(!other.verify_bytes(msg, &sig));
        // Empty message and a long multi-block message both round-trip.
        let sig = sk.sign_bytes(b"").unwrap();
        assert!(pk.verify_bytes(b"", &sig));
        assert!(!pk.verify_bytes(b"\0", &sig));
        let long = vec![0xabu8; 1000];
        let sig = sk.sign_bytes(&long).unwrap();
        assert!(pk.verify_bytes(&long, &sig));
        assert!(!pk.verify_bytes(&long[..999], &sig));
        // Field-element messages: empty and single zero element differ.
        let sig = sk.sign(&[]).unwrap();
        assert!(pk.verify(&[], &sig));
        assert!(!pk.verify(&[Fp::ZERO], &sig));
    }

    #[test]
    fn signatures_differ_per_leaf_and_message() {
        let mut sk = SecretKey::<1>::generate(&SEED);
        let a = sk.sign_bytes(b"same").unwrap();
        let b = sk.sign_bytes(b"same").unwrap();
        assert_ne!(a.index, b.index);
        assert_ne!(a.randomizer, b.randomizer);
        assert_ne!(a.wots, b.wots);
    }

    #[test]
    fn serialization_roundtrip() {
        const H: usize = 2;
        let mut sk = SecretKey::<H>::generate(&SEED);
        let pk = sk.public_key();
        let sig0 = sk.sign_bytes(b"first").unwrap();

        let pk_bytes = pk.to_bytes();
        assert_eq!(pk_bytes.len(), PublicKey::SIZE);
        assert_eq!(PublicKey::from_bytes(&pk_bytes), Some(pk));
        assert!(PublicKey::from_bytes(&pk_bytes[1..]).is_none());
        let mut bad = pk_bytes;
        bad[..4].copy_from_slice(&0x7800_0001u32.to_le_bytes()); // == p, non-canonical
        assert!(PublicKey::from_bytes(&bad).is_none());

        let sig_bytes = sig0.to_bytes();
        assert_eq!(sig_bytes.len(), Signature::<H>::SIZE);
        let back = Signature::<H>::from_bytes(&sig_bytes).unwrap();
        assert_eq!(back, sig0);
        assert!(pk.verify_bytes(b"first", &back));
        assert!(Signature::<H>::from_bytes(&sig_bytes[..sig_bytes.len() - 1]).is_none());
        assert!(Signature::<{ H + 1 }>::from_bytes(&sig_bytes).is_none());

        let sk_bytes = sk.to_bytes();
        assert_eq!(sk_bytes.len(), SecretKey::<H>::SIZE);
        let mut restored = SecretKey::<H>::from_bytes(&sk_bytes).unwrap();
        assert_eq!(restored.public_key(), pk);
        assert_eq!(restored.next_index(), 1);
        let sig1 = restored.sign_bytes(b"second").unwrap();
        assert_eq!(sig1.index, 1);
        assert!(pk.verify_bytes(b"second", &sig1));
        // The original key continues independently and produces the same leaf.
        let sig1_orig = sk.sign_bytes(b"second").unwrap();
        assert_eq!(sig1, sig1_orig);
        // An index past the end is rejected.
        let mut bad = sk_bytes;
        bad[48..].copy_from_slice(&(SecretKey::<H>::LEAVES + 1).to_le_bytes());
        assert!(SecretKey::<H>::from_bytes(&bad).is_none());
    }

    #[test]
    fn taller_tree() {
        const H: usize = 5;
        let mut sk = SecretKey::<H>::generate(&SEED);
        let pk = sk.public_key();
        for _ in 0..7 {
            let _ = sk.sign_bytes(b"skip").unwrap();
        }
        let sig = sk.sign_bytes(b"leaf seven").unwrap();
        assert_eq!(sig.index, 7);
        assert_eq!(sig.auth_path.len(), H);
        assert!(pk.verify_bytes(b"leaf seven", &sig));
    }
}
