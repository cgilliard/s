//! Poseidon2 permutation and hash over the BabyBear field, state width 16.
//!
//! This is bit-compatible with Plonky3's `default_babybear_poseidon2_16()`:
//! S-box `x^7`, eight full rounds, 13 partial rounds, Plonky3's round
//! constants, the external 4x4 block matrix `circ(2, 3, 1, 1)` and the
//! internal matrix `J + diag(V)` with Plonky3's optimised diagonal
//! `V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/4, 1/8, 1/2^27, -1/2^8, -1/16, -1/2^27]`.
//! The permutation is checked against Plonky3's known-answer test in [`tests`].
//!
//! Layout of one permutation:
//!
//! 1. external linear layer `M_E` on the input;
//! 2. four full rounds: add constants, S-box on every element, `M_E`;
//! 3. 13 partial rounds: add constant to element 0, S-box on element 0,
//!    internal linear layer `M_I`;
//! 4. four full rounds as in step 2.
//!
//! `M_E` applies `M4 = circ(2, 3, 1, 1)` to each aligned block of four
//! elements and then adds, to every element, the sum of the elements in the
//! same position of every block (the `circ(2M4, M4, M4, M4)` matrix from the
//! Poseidon2 paper).

use core::fmt;

// ---------------------------------------------------------------------------
// BabyBear field arithmetic
// ---------------------------------------------------------------------------

// Elements are stored in Montgomery form (`a * 2^32 mod p`) in a `u32`. All
// arithmetic is `const fn` so that round constants can be converted into
// Montgomery form at compile time.

/// The BabyBear modulus.
pub const P: u32 = 0x7800_0001;

/// `-p^{-1} mod 2^32`.
const MU: u32 = 0x77ff_ffff;

/// `2^32 mod p` (Montgomery form of 1).
const R: u32 = 268_435_454;

/// `2^64 mod p`, used to convert canonical values into Montgomery form.
const R2: u32 = 1_172_168_163;

/// An element of the BabyBear field, in Montgomery form.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Fp(u32);

/// Montgomery reduction of `x < p * 2^32`: returns `x * 2^-32 mod p`, reduced.
#[inline(always)]
const fn mont_reduce(x: u64) -> u32 {
    let m = (x as u32).wrapping_mul(MU);
    // x + m*p < p*2^32 + 2^32*p = 2^33 * p < 2^64, and is divisible by 2^32.
    let t = ((x + (m as u64) * (P as u64)) >> 32) as u32;
    if t >= P { t - P } else { t }
}

impl Fp {
    /// The raw Montgomery word, for vectorized arithmetic.
    #[inline(always)]
    pub(crate) const fn to_mont(self) -> u32 {
        self.0
    }

    /// From a raw Montgomery word below `p`.
    #[cfg(test)]
    #[inline(always)]
    pub(crate) const fn from_mont(x: u32) -> Fp {
        debug_assert!(x < P);
        Fp(x)
    }

    /// The additive identity.
    pub const ZERO: Fp = Fp(0);
    /// The multiplicative identity.
    pub const ONE: Fp = Fp(R);

    /// Builds an element from a canonical integer. Panics (at compile time
    /// for constants) if `v >= p`.
    pub const fn new(v: u32) -> Fp {
        assert!(v < P, "value is not a reduced field element");
        Fp(mont_reduce((v as u64) * (R2 as u64)))
    }

    /// Reduces an arbitrary `u32` modulo `p`.
    pub const fn from_u32(v: u32) -> Fp {
        Fp::new(v % P)
    }

    /// Reduces an arbitrary `u64` modulo `p`.
    pub const fn from_u64(v: u64) -> Fp {
        Fp::new((v % (P as u64)) as u32)
    }

    /// Returns the canonical integer representative in `[0, p)`.
    pub const fn to_canonical(&self) -> u32 {
        mont_reduce(self.0 as u64)
    }

    /// Parses a canonical little-endian encoding. Returns `None` if the value
    /// is not less than `p`.
    pub const fn from_le_bytes(bytes: [u8; 4]) -> Option<Fp> {
        let v = u32::from_le_bytes(bytes);
        if v < P { Some(Fp::new(v)) } else { None }
    }

    /// Canonical little-endian encoding.
    pub const fn to_le_bytes(&self) -> [u8; 4] {
        self.to_canonical().to_le_bytes()
    }

    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    #[inline(always)]
    pub const fn add(&self, rhs: &Fp) -> Fp {
        let s = self.0 + rhs.0; // < 2p < 2^32
        Fp(if s >= P { s - P } else { s })
    }

    #[inline(always)]
    pub const fn sub(&self, rhs: &Fp) -> Fp {
        let (d, borrow) = self.0.overflowing_sub(rhs.0);
        Fp(if borrow { d.wrapping_add(P) } else { d })
    }

    #[inline(always)]
    pub const fn neg(&self) -> Fp {
        Fp::ZERO.sub(self)
    }

    #[inline(always)]
    pub const fn double(&self) -> Fp {
        self.add(self)
    }

    #[inline(always)]
    pub const fn mul(&self, rhs: &Fp) -> Fp {
        Fp(mont_reduce((self.0 as u64) * (rhs.0 as u64)))
    }

    #[inline(always)]
    pub const fn square(&self) -> Fp {
        self.mul(self)
    }

    /// `self^7`, the Poseidon2 S-box for BabyBear.
    #[inline(always)]
    pub const fn pow7(&self) -> Fp {
        let x2 = self.square();
        let x4 = x2.square();
        x4.mul(&x2).mul(self)
    }

    /// `self^e` by square-and-multiply.
    pub const fn pow(&self, mut e: u64) -> Fp {
        let mut base = *self;
        let mut acc = Fp::ONE;
        while e != 0 {
            if e & 1 == 1 {
                acc = acc.mul(&base);
            }
            base = base.square();
            e >>= 1;
        }
        acc
    }

    /// Multiplicative inverse, or `None` for zero.
    pub const fn inverse(&self) -> Option<Fp> {
        if self.is_zero() { None } else { Some(self.pow((P - 2) as u64)) }
    }
}

impl fmt::Debug for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_canonical())
    }
}

impl fmt::Display for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_canonical())
    }
}

impl From<u32> for Fp {
    fn from(v: u32) -> Fp {
        Fp::from_u32(v)
    }
}

impl From<u64> for Fp {
    fn from(v: u64) -> Fp {
        Fp::from_u64(v)
    }
}

impl core::ops::Add for Fp {
    type Output = Fp;
    fn add(self, rhs: Fp) -> Fp {
        Fp::add(&self, &rhs)
    }
}

impl core::ops::AddAssign for Fp {
    fn add_assign(&mut self, rhs: Fp) {
        *self = Fp::add(self, &rhs);
    }
}

impl core::ops::Sub for Fp {
    type Output = Fp;
    fn sub(self, rhs: Fp) -> Fp {
        Fp::sub(&self, &rhs)
    }
}

impl core::ops::SubAssign for Fp {
    fn sub_assign(&mut self, rhs: Fp) {
        *self = Fp::sub(self, &rhs);
    }
}

impl core::ops::Mul for Fp {
    type Output = Fp;
    fn mul(self, rhs: Fp) -> Fp {
        Fp::mul(&self, &rhs)
    }
}

impl core::ops::MulAssign for Fp {
    fn mul_assign(&mut self, rhs: Fp) {
        *self = Fp::mul(self, &rhs);
    }
}

impl core::ops::Neg for Fp {
    type Output = Fp;
    fn neg(self) -> Fp {
        Fp::neg(&self)
    }
}

// ---------------------------------------------------------------------------
// Poseidon2 parameters (Plonky3 `default_babybear_poseidon2_16`)
// ---------------------------------------------------------------------------

// Round constants are copied verbatim from Plonky3 (`baby-bear/src/poseidon2.rs`);
// the internal diagonal is Plonky3's optimised vector evaluated in the field.

/// Round constants for the first four full rounds.
pub const RC_EXTERNAL_INITIAL: [[Fp; 16]; 4] = [
    [
        Fp::new(0x69cbb6af),
        Fp::new(0x46ad93f9),
        Fp::new(0x60a00f4e),
        Fp::new(0x6b1297cd),
        Fp::new(0x23189afe),
        Fp::new(0x732e7bef),
        Fp::new(0x72c246de),
        Fp::new(0x2c941900),
        Fp::new(0x0557eede),
        Fp::new(0x1580496f),
        Fp::new(0x3a3ea77b),
        Fp::new(0x54f3f271),
        Fp::new(0x0f49b029),
        Fp::new(0x47872fe1),
        Fp::new(0x221e2e36),
        Fp::new(0x1ab7202e),
    ],
    [
        Fp::new(0x487779a6),
        Fp::new(0x3851c9d8),
        Fp::new(0x38dc17c0),
        Fp::new(0x209f8849),
        Fp::new(0x268dcee8),
        Fp::new(0x350c48da),
        Fp::new(0x5b9ad32e),
        Fp::new(0x0523272b),
        Fp::new(0x3f89055b),
        Fp::new(0x01e894b2),
        Fp::new(0x13ddedde),
        Fp::new(0x1b2ef334),
        Fp::new(0x7507d8b4),
        Fp::new(0x6ceeb94e),
        Fp::new(0x52eb6ba2),
        Fp::new(0x50642905),
    ],
    [
        Fp::new(0x05453f3f),
        Fp::new(0x06349efc),
        Fp::new(0x6922787c),
        Fp::new(0x04bfff9c),
        Fp::new(0x768c714a),
        Fp::new(0x3e9ff21a),
        Fp::new(0x15737c9c),
        Fp::new(0x2229c807),
        Fp::new(0x0d47f88c),
        Fp::new(0x097e0ecc),
        Fp::new(0x27eadba0),
        Fp::new(0x2d7d29e4),
        Fp::new(0x3502aaa0),
        Fp::new(0x0f475fd7),
        Fp::new(0x29fbda49),
        Fp::new(0x018afffd),
    ],
    [
        Fp::new(0x0315b618),
        Fp::new(0x6d4497d1),
        Fp::new(0x1b171d9e),
        Fp::new(0x52861abd),
        Fp::new(0x2e5d0501),
        Fp::new(0x3ec8646c),
        Fp::new(0x6e5f250a),
        Fp::new(0x148ae8e6),
        Fp::new(0x17f5fa4a),
        Fp::new(0x3e66d284),
        Fp::new(0x0051aa3b),
        Fp::new(0x483f7913),
        Fp::new(0x2cfe5f15),
        Fp::new(0x023427ca),
        Fp::new(0x2cc78315),
        Fp::new(0x1e36ea47),
    ],
];

/// Round constants for the last four full rounds.
pub const RC_EXTERNAL_FINAL: [[Fp; 16]; 4] = [
    [
        Fp::new(0x7290a80d),
        Fp::new(0x6f7e5329),
        Fp::new(0x598ec8a8),
        Fp::new(0x76a859a0),
        Fp::new(0x6559e868),
        Fp::new(0x657b83af),
        Fp::new(0x13271d3f),
        Fp::new(0x1f876063),
        Fp::new(0x0aeeae37),
        Fp::new(0x706e9ca6),
        Fp::new(0x46400cee),
        Fp::new(0x72a05c26),
        Fp::new(0x2c589c9e),
        Fp::new(0x20bd37a7),
        Fp::new(0x6a2d3d10),
        Fp::new(0x20523767),
    ],
    [
        Fp::new(0x5b8fe9c4),
        Fp::new(0x2aa501d6),
        Fp::new(0x1e01ac3e),
        Fp::new(0x1448bc54),
        Fp::new(0x5ce5ad1c),
        Fp::new(0x4918a14d),
        Fp::new(0x2c46a83f),
        Fp::new(0x4fcf6876),
        Fp::new(0x61d8d5c8),
        Fp::new(0x6ddf4ff9),
        Fp::new(0x11fda4d3),
        Fp::new(0x02933a8f),
        Fp::new(0x170eaf81),
        Fp::new(0x5a9c314f),
        Fp::new(0x49a12590),
        Fp::new(0x35ec52a1),
    ],
    [
        Fp::new(0x58eb1611),
        Fp::new(0x5e481e65),
        Fp::new(0x367125c9),
        Fp::new(0x0eba33ba),
        Fp::new(0x1fc28ded),
        Fp::new(0x066399ad),
        Fp::new(0x0cbec0ea),
        Fp::new(0x75fd1af0),
        Fp::new(0x50f5bf4e),
        Fp::new(0x643d5f41),
        Fp::new(0x6f4fe718),
        Fp::new(0x5b3cbbde),
        Fp::new(0x1e3afb3e),
        Fp::new(0x296fb027),
        Fp::new(0x45e1547b),
        Fp::new(0x4a8db2ab),
    ],
    [
        Fp::new(0x59986d19),
        Fp::new(0x30bcdfa3),
        Fp::new(0x1db63932),
        Fp::new(0x1d7c2824),
        Fp::new(0x53b33681),
        Fp::new(0x0673b747),
        Fp::new(0x038a98a3),
        Fp::new(0x2c5bce60),
        Fp::new(0x351979cd),
        Fp::new(0x5008fb73),
        Fp::new(0x547bca78),
        Fp::new(0x711af481),
        Fp::new(0x3f93bf64),
        Fp::new(0x644d987b),
        Fp::new(0x3c8bcd87),
        Fp::new(0x608758b8),
    ],
];

/// Round constants for the 13 partial rounds (added to state element 0).
pub const RC_INTERNAL: [Fp; 13] = [
    Fp::new(0x5a8053c0),
    Fp::new(0x693be639),
    Fp::new(0x3858867d),
    Fp::new(0x19334f6b),
    Fp::new(0x128f0fd8),
    Fp::new(0x4e2b1ccb),
    Fp::new(0x61210ce0),
    Fp::new(0x3c318939),
    Fp::new(0x0b5b2f22),
    Fp::new(0x2edb11d5),
    Fp::new(0x213effdf),
    Fp::new(0x0cac4606),
    Fp::new(0x241af16d),
];

/// Diagonal `V` of the internal matrix `M_I = J + diag(V)`, as field elements:
/// `[-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/4, 1/8, 1/2^27, -1/2^8, -1/16, -1/2^27]`.
pub const INTERNAL_DIAG: [Fp; 16] = [
    Fp::new(2013265919), // -2
    Fp::new(1),          // 1
    Fp::new(2),          // 2
    Fp::new(1006632961), // 1/2
    Fp::new(3),          // 3
    Fp::new(4),          // 4
    Fp::new(1006632960), // -1/2
    Fp::new(2013265918), // -3
    Fp::new(2013265917), // -4
    Fp::new(2005401601), // 1/2^8
    Fp::new(1509949441), // 1/4
    Fp::new(1761607681), // 1/8
    Fp::new(2013265906), // 1/2^27
    Fp::new(7864320),    // -1/2^8
    Fp::new(125829120),  // -1/16
    Fp::new(15),         // -1/2^27
];

// ---------------------------------------------------------------------------
// Permutation and hash
// ---------------------------------------------------------------------------

/// State width.
pub const WIDTH: usize = 16;
/// Number of full rounds.
pub const ROUNDS_F: usize = 8;
/// Number of partial rounds.
pub const ROUNDS_P: usize = 13;
/// Digest size in field elements for [`compress`] and [`hash`].
pub const DIGEST: usize = 8;
/// Sponge rate of [`hash`] in field elements.
pub const RATE: usize = WIDTH - DIGEST;

/// Applies `M4 = circ(2, 3, 1, 1)` to each aligned block of four elements.
#[inline(always)]
fn matmul_m4(s: &mut [Fp; WIDTH]) {
    for x in s.chunks_exact_mut(4) {
        let t01 = x[0].add(&x[1]);
        let t23 = x[2].add(&x[3]);
        let t0123 = t01.add(&t23);
        let t01123 = t0123.add(&x[1]);
        let t01233 = t0123.add(&x[3]);
        x[3] = t01233.add(&x[0].double()); // 3*x0 + x1 + x2 + 2*x3
        x[1] = t01123.add(&x[2].double()); // x0 + 2*x1 + 3*x2 + x3
        x[0] = t01123.add(&t01); // 2*x0 + 3*x1 + x2 + x3
        x[2] = t01233.add(&t23); // x0 + x1 + 2*x2 + 3*x3
    }
}

/// External linear layer `M_E = circ(2M4, M4, M4, M4)`.
#[inline(always)]
fn matmul_external(s: &mut [Fp; WIDTH]) {
    matmul_m4(s);
    let mut col = [Fp::ZERO; 4];
    for (i, x) in s.iter().enumerate() {
        col[i % 4] = col[i % 4].add(x);
    }
    for (i, x) in s.iter_mut().enumerate() {
        *x = x.add(&col[i % 4]);
    }
}

/// Internal linear layer `M_I = J + diag(V)`: `s[i] = V[i] * s[i] + sum(s)`.
#[inline(always)]
fn matmul_internal(s: &mut [Fp; WIDTH]) {
    let mut sum = Fp::ZERO;
    for x in s.iter() {
        sum = sum.add(x);
    }
    for (x, v) in s.iter_mut().zip(&INTERNAL_DIAG) {
        *x = x.mul(v).add(&sum);
    }
}

#[inline(always)]
fn full_round(s: &mut [Fp; WIDTH], rc: &[Fp; WIDTH]) {
    for (x, c) in s.iter_mut().zip(rc) {
        *x = x.add(c).pow7();
    }
    matmul_external(s);
}

#[inline(always)]
fn partial_round(s: &mut [Fp; WIDTH], rc: &Fp) {
    s[0] = s[0].add(rc).pow7();
    matmul_internal(s);
}

/// Applies the Poseidon2 permutation to `state` in place.
pub fn permute_in_place(state: &mut [Fp; WIDTH]) {
    matmul_external(state);
    for rc in RC_EXTERNAL_INITIAL.iter() {
        full_round(state, rc);
    }
    for rc in RC_INTERNAL.iter() {
        partial_round(state, rc);
    }
    for rc in RC_EXTERNAL_FINAL.iter() {
        full_round(state, rc);
    }
}

/// Returns the Poseidon2 permutation of `state`.
pub fn permute(mut state: [Fp; WIDTH]) -> [Fp; WIDTH] {
    permute_in_place(&mut state);
    state
}

/// Two-to-one compression of two 8-element digests: the first 8 elements of
/// `perm(a || b)`. Suitable as a Merkle tree node function and identical to
/// Plonky3's `TruncatedPermutation<_, 2, 8, 16>`.
pub fn compress(a: &[Fp; DIGEST], b: &[Fp; DIGEST]) -> [Fp; DIGEST] {
    let mut state = [Fp::ZERO; WIDTH];
    state[..DIGEST].copy_from_slice(a);
    state[DIGEST..].copy_from_slice(b);
    permute_in_place(&mut state);
    state[..DIGEST].try_into().unwrap()
}

/// Fixed-length sponge hash of `input` with rate 8 and capacity 8.
///
/// The first capacity element is initialised with the input length for
/// domain separation. The input is absorbed `RATE` elements at a time by
/// addition into the rate part of the state, permuting after each block; a
/// final short block is zero padded. The output is the first `DIGEST`
/// elements of the state after the last permutation. This padding scheme is
/// specific to this crate and does not match Plonky3's `PaddingFreeSponge`.
pub fn hash(input: &[Fp]) -> [Fp; DIGEST] {
    let mut state = [Fp::ZERO; WIDTH];
    state[RATE] = Fp::from_u64(input.len() as u64);
    for chunk in input.chunks(RATE) {
        for (s, x) in state.iter_mut().zip(chunk) {
            *s = s.add(x);
        }
        permute_in_place(&mut state);
    }
    if input.is_empty() {
        permute_in_place(&mut state);
    }
    state[..DIGEST].try_into().unwrap()
}

/// Canonical little-endian encoding of a digest: 4 bytes per element.
pub fn digest_to_bytes(d: &[Fp; DIGEST]) -> [u8; DIGEST * 4] {
    let mut out = [0u8; DIGEST * 4];
    for (chunk, x) in out.chunks_exact_mut(4).zip(d) {
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    out
}

/// Parses a digest written by [`digest_to_bytes`]. Returns `None` on a
/// wrong length or a non-canonical element.
pub fn digest_from_bytes(bytes: &[u8]) -> Option<[Fp; DIGEST]> {
    if bytes.len() != DIGEST * 4 {
        return None;
    }
    let mut out = [Fp::ZERO; DIGEST];
    for (x, chunk) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        *x = Fp::from_le_bytes(chunk.try_into().unwrap())?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_is_babybear() {
        assert_eq!(P, 2_013_265_921);
        assert_eq!(P, (1u32 << 31) - (1u32 << 27) + 1);
    }

    #[test]
    fn montgomery_roundtrip() {
        for v in [0u32, 1, 2, 31, 0x2ed3_e23d, P - 1] {
            assert_eq!(Fp::new(v).to_canonical(), v);
            assert_eq!(Fp::from_le_bytes(Fp::new(v).to_le_bytes()), Some(Fp::new(v)));
        }
        assert_eq!(Fp::from_u32(P), Fp::ZERO);
        assert_eq!(Fp::from_u32(u32::MAX), Fp::new(u32::MAX % P));
        assert_eq!(Fp::from_u64(u64::MAX), Fp::new((u64::MAX % P as u64) as u32));
        assert!(Fp::from_le_bytes(P.to_le_bytes()).is_none());
        assert_eq!(Fp::ONE.to_canonical(), 1);
    }

    #[test]
    fn additive_identities() {
        let pm1 = Fp::new(P - 1);
        assert_eq!(pm1 + Fp::ONE, Fp::ZERO);
        assert_eq!(Fp::ZERO - Fp::ONE, pm1);
        assert_eq!(-Fp::ONE, pm1);
        assert_eq!(pm1.double(), pm1 - Fp::ONE);
        assert_eq!(pm1 + pm1, Fp::new(P - 2));
    }

    #[test]
    fn multiplication() {
        assert_eq!(Fp::new(6) * Fp::new(7), Fp::new(42));
        assert_eq!(Fp::new(3).pow7(), Fp::new(2187));
        assert_eq!(Fp::new(2).pow(31), Fp::new(((1u64 << 31) % P as u64) as u32));
        let pm1 = Fp::new(P - 1);
        assert_eq!(pm1.square(), Fp::ONE);
        assert_eq!(pm1 * Fp::new(5), -Fp::new(5));
        // Exhaustive-ish check against u64 arithmetic on a spread of values.
        let samples = [0u32, 1, 2, 3, 1 << 27, P - 1, P - 2, 0x2ed3_e23d, 0x57a9_9864, 12345];
        for &a in &samples {
            for &b in &samples {
                let want = ((a as u64 * b as u64) % P as u64) as u32;
                assert_eq!((Fp::new(a) * Fp::new(b)).to_canonical(), want, "{a} * {b}");
                let want = ((a as u64 + b as u64) % P as u64) as u32;
                assert_eq!((Fp::new(a) + Fp::new(b)).to_canonical(), want, "{a} + {b}");
                let want = ((a as u64 + P as u64 - b as u64) % P as u64) as u32;
                assert_eq!((Fp::new(a) - Fp::new(b)).to_canonical(), want, "{a} - {b}");
            }
        }
    }

    #[test]
    fn inverse_and_fermat() {
        assert!(Fp::ZERO.inverse().is_none());
        for v in [1u32, 2, 31, 0x2ed3_e23d, P - 1] {
            let x = Fp::new(v);
            assert_eq!(x * x.inverse().unwrap(), Fp::ONE);
            assert_eq!(x.pow((P - 1) as u64), Fp::ONE);
        }
        // 31 is a generator: 31^((p-1)/2) must be -1.
        assert_eq!(Fp::new(31).pow(((P - 1) / 2) as u64), -Fp::ONE);
    }

    fn arr<const N: usize>(v: [u32; N]) -> [Fp; N] {
        v.map(Fp::new)
    }

    /// Known-answer test from Plonky3
    /// (`test_default_babybear_poseidon2_width_16` in `baby-bear/src/poseidon2.rs`).
    #[test]
    fn plonky3_kat_width_16() {
        let input = arr([
            894848333, 1437655012, 1200606629, 1690012884, 71131202, 1749206695, 1717947831, 120589055, 19776022,
            42382981, 1831865506, 724844064, 171220207, 1299207443, 227047920, 1783754913,
        ]);
        let expected = arr([
            516096821, 90309867, 1101817252, 1660784290, 360715097, 1789519026, 1788910906, 563338433, 319524748,
            1741414159, 1650859320, 894311162, 1121347488, 1692793758, 1052633829, 1344246938,
        ]);
        let out = permute(input);
        for i in 0..WIDTH {
            assert_eq!(out[i].to_canonical(), expected[i].to_canonical(), "element {i}");
        }
        assert_eq!(out, expected);
    }

    #[test]
    fn constant_tables_match_plonky3_endpoints() {
        assert_eq!(RC_EXTERNAL_INITIAL[0][0], Fp::new(0x69cbb6af));
        assert_eq!(RC_EXTERNAL_INITIAL[3][15], Fp::new(0x1e36ea47));
        assert_eq!(RC_EXTERNAL_FINAL[0][0], Fp::new(0x7290a80d));
        assert_eq!(RC_EXTERNAL_FINAL[3][15], Fp::new(0x608758b8));
        assert_eq!(RC_INTERNAL[0], Fp::new(0x5a8053c0));
        assert_eq!(RC_INTERNAL[12], Fp::new(0x241af16d));
        assert_eq!(RC_EXTERNAL_INITIAL.len() + RC_EXTERNAL_FINAL.len(), ROUNDS_F);
        assert_eq!(RC_INTERNAL.len(), ROUNDS_P);
    }

    #[test]
    fn internal_diagonal_is_plonky3_vector() {
        let two = Fp::new(2);
        let inv = |k: u32| Fp::new(k).inverse().unwrap();
        let pow2 = |e: u64| two.pow(e);
        let want = [
            -two,
            Fp::ONE,
            two,
            inv(2),
            Fp::new(3),
            Fp::new(4),
            -inv(2),
            -Fp::new(3),
            -Fp::new(4),
            pow2(8).inverse().unwrap(),
            inv(4),
            inv(8),
            pow2(27).inverse().unwrap(),
            -pow2(8).inverse().unwrap(),
            -inv(16),
            -pow2(27).inverse().unwrap(),
        ];
        assert_eq!(INTERNAL_DIAG, want);
        // Every diagonal entry of M_I = J + diag(V) must be non-zero.
        for v in INTERNAL_DIAG {
            assert_ne!(v + Fp::ONE, Fp::ZERO);
        }
        assert_eq!(P - 2, INTERNAL_DIAG[0].to_canonical());
    }

    #[test]
    fn m4_matches_matrix() {
        // circ(2,3,1,1) = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] applied to [1,2,3,4].
        let mut s = arr([1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4]);
        matmul_m4(&mut s);
        let want = [2 + 6 + 3 + 4, 1 + 4 + 9 + 4, 1 + 2 + 6 + 12, 3 + 2 + 3 + 8];
        for i in 0..WIDTH {
            assert_eq!(s[i].to_canonical(), want[i % 4], "element {i}");
        }
    }

    #[test]
    fn internal_layer_matches_plonky3_formula() {
        // Plonky3 computes state[0] = part_sum - state[0] where part_sum
        // excludes state[0]; that equals sum - 2*state[0].
        let s0: [Fp; WIDTH] = core::array::from_fn(|i| Fp::new(1000 + 7 * i as u32));
        let mut s = s0;
        matmul_internal(&mut s);
        let part_sum = s0[1..].iter().fold(Fp::ZERO, |a, b| a + *b);
        assert_eq!(s[0], part_sum - s0[0]);
        let sum = part_sum + s0[0];
        assert_eq!(s[1], s0[1] + sum);
        assert_eq!(s[2], s0[2].double() + sum);
        assert_eq!(s[3] - sum, s0[3] * Fp::new(2).inverse().unwrap());
        assert_eq!(s[15], sum - s0[15] * Fp::new(2).pow(27).inverse().unwrap());
    }

    #[test]
    fn permutation_is_deterministic_and_distinct() {
        let a: [Fp; WIDTH] = core::array::from_fn(|i| Fp::new(i as u32));
        let mut b = a;
        b[15] = Fp::new(99);
        assert_eq!(permute(a), permute(a));
        assert_ne!(permute(a), permute(b));
        assert_ne!(permute(a), a);
        assert_ne!(permute([Fp::ZERO; WIDTH]), [Fp::ZERO; WIDTH]);
    }

    #[test]
    fn compress_matches_permutation() {
        let a: [Fp; DIGEST] = core::array::from_fn(|i| Fp::new(i as u32));
        let b: [Fp; DIGEST] = core::array::from_fn(|i| Fp::new(100 + i as u32));
        let mut state = [Fp::ZERO; WIDTH];
        state[..DIGEST].copy_from_slice(&a);
        state[DIGEST..].copy_from_slice(&b);
        assert_eq!(compress(&a, &b)[..], permute(state)[..DIGEST]);
        assert_ne!(compress(&a, &b), compress(&b, &a));
    }

    #[test]
    fn hash_basic_properties() {
        let one = [Fp::ONE];
        let one_zero = [Fp::ONE, Fp::ZERO];
        assert_ne!(hash(&one), hash(&one_zero));
        assert_ne!(hash(&[]), hash(&[Fp::ZERO]));
        assert_eq!(hash(&one), hash(&one));
        let long: Vec<Fp> = (0..20).map(Fp::from_u32).collect();
        assert_ne!(hash(&long), hash(&long[..19]));
        assert_ne!(hash(&long[..8]), hash(&long[..9]));
    }
}

#[cfg(test)]
mod bench {
    use super::*;

    #[test]
    #[ignore = "timing; run with --release"]
    fn permutation_throughput() {
        let mut s = [Fp::ZERO; WIDTH];
        let n = 1_000_000;
        let t = std::time::Instant::now();
        for i in 0..n {
            s[0] = s[0].add(&Fp::new(i % P));
            permute_in_place(&mut s);
        }
        let el = t.elapsed();
        println!("{n} permutations: {el:?} ({:?} each) {:?}", el / n, s[0]);
    }
}

// ---------------------------------------------------------------------------
// Batched permutation
// ---------------------------------------------------------------------------

/// Independent states permuted in lockstep. The lane loops are written so
/// the compiler can vectorise them.
pub const LANES: usize = 8;

type Lane = [u32; LANES];

/// `LANES` states in structure-of-arrays layout: `s[i][l]` is element `i`
/// of state `l`, in Montgomery form.
pub type BatchState = [Lane; WIDTH];

#[inline(always)]
fn lane_reduce(t: u32) -> u32 {
    t.min(t.wrapping_sub(P))
}

#[inline(always)]
fn lane_add(a: &Lane, b: &Lane) -> Lane {
    let mut r = [0u32; LANES];
    for l in 0..LANES {
        r[l] = lane_reduce(a[l] + b[l]);
    }
    r
}

#[inline(always)]
fn lane_add_const(a: &Lane, c: u32) -> Lane {
    let mut r = [0u32; LANES];
    for l in 0..LANES {
        r[l] = lane_reduce(a[l] + c);
    }
    r
}

#[inline(always)]
fn lane_mont(x: u64) -> u32 {
    let m = (x as u32).wrapping_mul(MU);
    let t = ((x + (m as u64) * (P as u64)) >> 32) as u32;
    lane_reduce(t)
}

#[inline(always)]
fn lane_mul(a: &Lane, b: &Lane) -> Lane {
    let mut r = [0u32; LANES];
    for l in 0..LANES {
        r[l] = lane_mont((a[l] as u64) * (b[l] as u64));
    }
    r
}

#[inline(always)]
fn lane_mul_const(a: &Lane, c: u32) -> Lane {
    let mut r = [0u32; LANES];
    for l in 0..LANES {
        r[l] = lane_mont((a[l] as u64) * (c as u64));
    }
    r
}

#[inline(always)]
fn lane_pow7(a: &Lane) -> Lane {
    let x2 = lane_mul(a, a);
    let x4 = lane_mul(&x2, &x2);
    let x6 = lane_mul(&x4, &x2);
    lane_mul(&x6, a)
}

fn batch_m4(s: &mut BatchState) {
    for x in s.chunks_exact_mut(4) {
        let t01 = lane_add(&x[0], &x[1]);
        let t23 = lane_add(&x[2], &x[3]);
        let t0123 = lane_add(&t01, &t23);
        let t01123 = lane_add(&t0123, &x[1]);
        let t01233 = lane_add(&t0123, &x[3]);
        let x0d = lane_add(&x[0], &x[0]);
        let x2d = lane_add(&x[2], &x[2]);
        x[3] = lane_add(&t01233, &x0d);
        x[1] = lane_add(&t01123, &x2d);
        x[0] = lane_add(&t01123, &t01);
        x[2] = lane_add(&t01233, &t23);
    }
}

fn batch_external(s: &mut BatchState) {
    batch_m4(s);
    let mut col = [[0u32; LANES]; 4];
    for (i, x) in s.iter().enumerate() {
        col[i % 4] = lane_add(&col[i % 4], x);
    }
    for (i, x) in s.iter_mut().enumerate() {
        *x = lane_add(x, &col[i % 4]);
    }
}

fn batch_internal(s: &mut BatchState) {
    let mut sum = [0u32; LANES];
    for x in s.iter() {
        sum = lane_add(&sum, x);
    }
    for (x, d) in s.iter_mut().zip(&INTERNAL_DIAG) {
        *x = lane_add(&lane_mul_const(x, d.0), &sum);
    }
}

/// Permutes `LANES` states at once.
#[inline]
pub fn permute_batch(s: &mut BatchState) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    avx2::permute_batch(s);
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    permute_batch_scalar(s);
}

/// Portable [`permute_batch`], on arrays the compiler may vectorize.
#[cfg_attr(all(target_arch = "x86_64", target_feature = "avx2"), allow(dead_code))]
fn permute_batch_scalar(s: &mut BatchState) {
    batch_external(s);
    for rc in RC_EXTERNAL_INITIAL.iter() {
        for (x, c) in s.iter_mut().zip(rc) {
            *x = lane_pow7(&lane_add_const(x, c.0));
        }
        batch_external(s);
    }
    for rc in RC_INTERNAL.iter() {
        s[0] = lane_pow7(&lane_add_const(&s[0], rc.0));
        batch_internal(s);
    }
    for rc in RC_EXTERNAL_FINAL.iter() {
        for (x, c) in s.iter_mut().zip(rc) {
            *x = lane_pow7(&lane_add_const(x, c.0));
        }
        batch_external(s);
    }
}

/// AVX2 permutation of eight states, one per 32-bit lane, on
/// [`crate::packed`] arithmetic (bit-identical to the scalar path).
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
mod avx2 {
    use super::{BatchState, INTERNAL_DIAG, RC_EXTERNAL_FINAL, RC_EXTERNAL_INITIAL, RC_INTERNAL, WIDTH};
    use crate::packed::{V, add, load, mul, splat, store};

    #[inline(always)]
    fn pow7(a: V) -> V {
        let x2 = mul(a, a);
        let x4 = mul(x2, x2);
        let x6 = mul(x4, x2);
        mul(x6, a)
    }

    #[inline(always)]
    fn external(s: &mut [V; WIDTH]) {
        for x in s.chunks_exact_mut(4) {
            let t01 = add(x[0], x[1]);
            let t23 = add(x[2], x[3]);
            let t0123 = add(t01, t23);
            let t01123 = add(t0123, x[1]);
            let t01233 = add(t0123, x[3]);
            let x0d = add(x[0], x[0]);
            let x2d = add(x[2], x[2]);
            x[3] = add(t01233, x0d);
            x[1] = add(t01123, x2d);
            x[0] = add(t01123, t01);
            x[2] = add(t01233, t23);
        }
        let mut col = [s[0], s[1], s[2], s[3]];
        for i in 4..WIDTH {
            col[i % 4] = add(col[i % 4], s[i]);
        }
        for (i, x) in s.iter_mut().enumerate() {
            *x = add(*x, col[i % 4]);
        }
    }

    #[inline(always)]
    fn internal(s: &mut [V; WIDTH]) {
        let mut sum = s[0];
        for x in &s[1..] {
            sum = add(sum, *x);
        }
        for (x, d) in s.iter_mut().zip(&INTERNAL_DIAG) {
            *x = add(mul(*x, splat(d.0)), sum);
        }
    }

    #[inline(always)]
    fn full_round(s: &mut [V; WIDTH], rc: &[super::Fp; WIDTH]) {
        for (x, c) in s.iter_mut().zip(rc) {
            *x = pow7(add(*x, splat(c.0)));
        }
        external(s);
    }

    pub fn permute_batch(state: &mut BatchState) {
        let mut s: [V; WIDTH] = core::array::from_fn(|i| load(&state[i]));
        external(&mut s);
        for rc in RC_EXTERNAL_INITIAL.iter() {
            full_round(&mut s, rc);
        }
        for rc in RC_INTERNAL.iter() {
            s[0] = pow7(add(s[0], splat(rc.0)));
            internal(&mut s);
        }
        for rc in RC_EXTERNAL_FINAL.iter() {
            full_round(&mut s, rc);
        }
        for (row, v) in state.iter_mut().zip(&s) {
            store(row, *v);
        }
    }
}

/// [`hash`] of `LANES` rows of equal length, in lockstep.
pub fn hash_batch(rows: [&[Fp]; LANES]) -> [[Fp; DIGEST]; LANES] {
    let len = rows[0].len();
    debug_assert!(rows.iter().all(|r| r.len() == len));
    let mut s: BatchState = [[0u32; LANES]; WIDTH];
    s[RATE] = [Fp::from_u64(len as u64).0; LANES];
    let blocks = len.div_ceil(RATE).max(1);
    for b in 0..blocks {
        for (i, lane) in s.iter_mut().enumerate().take(RATE) {
            let k = b * RATE + i;
            if k < len {
                for l in 0..LANES {
                    lane[l] = lane_reduce(lane[l] + rows[l][k].0);
                }
            }
        }
        permute_batch(&mut s);
    }
    let mut out = [[Fp::ZERO; DIGEST]; LANES];
    for (l, o) in out.iter_mut().enumerate() {
        for (i, x) in o.iter_mut().enumerate() {
            *x = Fp(s[i][l]);
        }
    }
    out
}

/// [`compress`] of `LANES` pairs, in lockstep.
pub fn compress_batch(pairs: [(&[Fp; DIGEST], &[Fp; DIGEST]); LANES]) -> [[Fp; DIGEST]; LANES] {
    let mut s: BatchState = [[0u32; LANES]; WIDTH];
    for (l, (a, b)) in pairs.iter().enumerate() {
        for i in 0..DIGEST {
            s[i][l] = a[i].0;
            s[DIGEST + i][l] = b[i].0;
        }
    }
    permute_batch(&mut s);
    let mut out = [[Fp::ZERO; DIGEST]; LANES];
    for (l, o) in out.iter_mut().enumerate() {
        for (i, x) in o.iter_mut().enumerate() {
            *x = Fp(s[i][l]);
        }
    }
    out
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    #[test]
    fn batch_matches_scalar() {
        let mut rows: Vec<Vec<Fp>> = Vec::new();
        for l in 0..LANES {
            rows.push(
                (0..19).map(|i| Fp::from_u32(((l * 1000 + i * 7919) as u32).wrapping_mul(2654435761u32))).collect(),
            );
        }
        let refs: [&[Fp]; LANES] = core::array::from_fn(|l| rows[l].as_slice());
        let got = hash_batch(refs);
        for l in 0..LANES {
            assert_eq!(got[l], hash(&rows[l]));
        }
        let a: Vec<[Fp; DIGEST]> = (0..2 * LANES).map(|l| hash(&[Fp::new(l as u32)])).collect();
        let pairs: [(&[Fp; DIGEST], &[Fp; DIGEST]); LANES] = core::array::from_fn(|l| (&a[2 * l], &a[2 * l + 1]));
        let got = compress_batch(pairs);
        for l in 0..LANES {
            assert_eq!(got[l], compress(&a[2 * l], &a[2 * l + 1]));
        }
        // Empty rows.
        let empty: [&[Fp]; LANES] = [&[]; LANES];
        assert!(hash_batch(empty).iter().all(|d| *d == hash(&[])));
    }

    #[test]
    fn vector_permutation_matches_portable() {
        let mut x = 0x1234_5678u32;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x % P
        };
        for _ in 0..50 {
            let mut a: BatchState = core::array::from_fn(|_| core::array::from_fn(|_| next()));
            // Extremes too: zero and p - 1.
            a[1][3] = 0;
            a[2][5] = P - 1;
            let mut b = a;
            permute_batch(&mut a);
            permute_batch_scalar(&mut b);
            assert_eq!(a, b);
        }
    }

    #[test]
    #[ignore = "timing; run with --release"]
    fn batch_throughput() {
        let mut s: BatchState = [[0u32; LANES]; WIDTH];
        let n = 1_000_000 / LANES;
        let t = std::time::Instant::now();
        for i in 0..n {
            s[0][0] = lane_reduce(s[0][0] + i as u32);
            permute_batch(&mut s);
        }
        let el = t.elapsed();
        println!("{} permutations batched: {el:?} ({:?} each) {}", n * LANES, el / (n * LANES) as u32, s[0][0]);
    }
}
