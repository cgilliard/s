//! ML-DSA-65 (FIPS 204): the long-lived signature key of the message
//! layer (`docs/ONION.md`), whose hash is an identity.
//!
//! Keys: public 1,952 bytes, secret 4,032 bytes, signatures 3,309 bytes.
//! Key generation is deterministic from a 32-byte seed, so a wallet
//! restored from its phrase has the same key. Signing is deterministic
//! (FIPS 204's zero randomness), over a message with a context string.

use crate::keccak::{Sponge, shake256};

const N: usize = 256;
const Q: i64 = 8_380_417;
const D: u32 = 13;
const TAU: usize = 49;
const LAMBDA: usize = 192;
const GAMMA1: i64 = 1 << 19;
const GAMMA2: i64 = (Q - 1) / 32;
const K: usize = 6;
const L: usize = 5;
const ETA: i64 = 4;
const BETA: i64 = TAU as i64 * ETA;
const OMEGA: usize = 55;
/// Bits of a `z` coefficient: `1 + bitlen(γ1 - 1)`.
const Z_BITS: usize = 20;
/// Bits of a `t1` coefficient.
const T1_BITS: usize = 23 - D as usize;
/// Bits of an `s` coefficient (`bitlen(2η)`).
const S_BITS: usize = 4;
/// Bits of a `w1` coefficient.
const W1_BITS: usize = 4;
/// `256^-1 mod q`.
const INV256: i64 = 8_347_681;
/// Bytes of the challenge hash.
const CT_LEN: usize = LAMBDA / 4;

/// Public key size.
pub const PK_LEN: usize = 32 + 32 * K * T1_BITS;
/// Secret key size.
pub const SK_LEN: usize = 32 + 32 + 64 + 32 * ((K + L) * S_BITS + K * D as usize);
/// Signature size.
pub const SIG_LEN: usize = CT_LEN + 32 * L * Z_BITS + OMEGA + K;
/// Seed size for key generation.
pub const SEED_LEN: usize = 32;

type Poly = [i64; N];

fn modq(a: i64) -> i64 {
    a.rem_euclid(Q)
}

/// `a mod± q`: the representative in `(-q/2, q/2]`.
fn centered(a: i64) -> i64 {
    let r = modq(a);
    if r > Q / 2 { r - Q } else { r }
}

fn powq(mut base: i64, mut exp: u64) -> i64 {
    let mut acc = 1i64;
    base = modq(base);
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base % Q;
        }
        base = base * base % Q;
        exp >>= 1;
    }
    acc
}

fn bitrev8(i: usize) -> usize {
    (0..8).fold(0, |acc, b| acc | (((i >> b) & 1) << (7 - b)))
}

fn zetas() -> [i64; N] {
    core::array::from_fn(|k| powq(1753, bitrev8(k) as u64))
}

fn ntt(w: &mut Poly) {
    let z = zetas();
    let mut k = 0;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = z[k];
            for j in start..start + len {
                let t = zeta * w[j + len] % Q;
                w[j + len] = modq(w[j] - t);
                w[j] = modq(w[j] + t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

fn inv_ntt(w: &mut Poly) {
    let z = zetas();
    let mut k = N;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = modq(-z[k]);
            for j in start..start + len {
                let t = w[j];
                w[j] = modq(t + w[j + len]);
                w[j + len] = modq(t - w[j + len]);
                w[j + len] = zeta * w[j + len] % Q;
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for x in w.iter_mut() {
        *x = *x * INV256 % Q;
    }
}

fn mul_ntt(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| a[i] * b[i] % Q)
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| modq(a[i] + b[i]))
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| modq(a[i] - b[i]))
}

fn infinity_norm(a: &Poly) -> i64 {
    a.iter().map(|&x| centered(x).abs()).max().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

/// A uniform polynomial in the NTT domain from `SHAKE128(ρ ‖ s ‖ r)`.
fn rej_ntt_poly(rho: &[u8; 32], s: u8, r: u8) -> Poly {
    let mut xof = Sponge::shake128();
    xof.absorb(rho).absorb(&[s, r]);
    let mut a = [0i64; N];
    let mut j = 0;
    let mut buf = [0u8; 168];
    while j < N {
        xof.squeeze(&mut buf);
        for c in buf.chunks(3) {
            if j == N {
                break;
            }
            let v = i64::from(c[0]) | (i64::from(c[1]) << 8) | (i64::from(c[2] & 0x7f) << 16);
            if v < Q {
                a[j] = v;
                j += 1;
            }
        }
    }
    a
}

/// A polynomial with coefficients in `[-η, η]` from `SHAKE256(ρ' ‖ nonce)`.
fn rej_bounded_poly(rho_prime: &[u8; 64], nonce: u16) -> Poly {
    let mut xof = Sponge::shake256();
    xof.absorb(rho_prime).absorb(&nonce.to_le_bytes());
    let mut a = [0i64; N];
    let mut j = 0;
    let mut buf = [0u8; 136];
    while j < N {
        xof.squeeze(&mut buf);
        for &z in &buf {
            for b in [z & 15, z >> 4] {
                if j < N && b < 9 {
                    a[j] = modq(ETA - i64::from(b));
                    j += 1;
                }
            }
            if j == N {
                break;
            }
        }
    }
    a
}

fn expand_a(rho: &[u8; 32]) -> Vec<Poly> {
    let mut a = Vec::with_capacity(K * L);
    for r in 0..K {
        for s in 0..L {
            a.push(rej_ntt_poly(rho, s as u8, r as u8));
        }
    }
    a
}

/// The mask vector `y` for attempt `kappa`: coefficients in `(-γ1, γ1]`.
fn expand_mask(rho2: &[u8; 64], kappa: u16) -> [Poly; L] {
    core::array::from_fn(|r| {
        let mut xof = Sponge::shake256();
        xof.absorb(rho2).absorb(&(kappa + r as u16).to_le_bytes());
        let v = xof.squeeze_vec(32 * Z_BITS);
        bit_unpack(&v, Z_BITS, GAMMA1 - 1, GAMMA1)
    })
}

/// The challenge polynomial with `τ` coefficients in `{-1, 1}`.
fn sample_in_ball(c_tilde: &[u8]) -> Poly {
    let mut xof = Sponge::shake256();
    xof.absorb(c_tilde);
    let mut signs = [0u8; 8];
    xof.squeeze(&mut signs);
    let s = u64::from_le_bytes(signs);
    let mut c = [0i64; N];
    for i in N - TAU..N {
        let mut j = [0u8; 1];
        loop {
            xof.squeeze(&mut j);
            if usize::from(j[0]) <= i {
                break;
            }
        }
        let j = usize::from(j[0]);
        c[i] = c[j];
        c[j] = if (s >> (i + TAU - N)) & 1 == 1 { Q - 1 } else { 1 };
    }
    c
}

// ---------------------------------------------------------------------------
// Rounding
// ---------------------------------------------------------------------------

/// `(r1, r0)` with `r = r1·2^d + r0`, `r0` centered.
fn power2round(r: i64) -> (i64, i64) {
    let r = modq(r);
    let half = 1i64 << (D - 1);
    let r0 = ((r + half - 1) & ((1 << D) - 1)) - half + 1;
    ((r - r0) >> D, r0)
}

/// `(r1, r0)` with `r = r1·2γ2 + r0`, `r0` centered, `r1` in `[0, 16)`.
fn decompose(r: i64) -> (i64, i64) {
    let r = modq(r);
    let mut r0 = r.rem_euclid(2 * GAMMA2);
    if r0 > GAMMA2 {
        r0 -= 2 * GAMMA2;
    }
    if r - r0 == Q - 1 { (0, r0 - 1) } else { ((r - r0) / (2 * GAMMA2), r0) }
}

fn high_bits(r: i64) -> i64 {
    decompose(r).0
}

fn low_bits(r: i64) -> i64 {
    decompose(r).1
}

fn make_hint(z: i64, r: i64) -> bool {
    high_bits(r) != high_bits(r + z)
}

fn use_hint(h: bool, r: i64) -> i64 {
    let m = (Q - 1) / (2 * GAMMA2);
    let (r1, r0) = decompose(r);
    if h && r0 > 0 {
        (r1 + 1).rem_euclid(m)
    } else if h {
        (r1 - 1).rem_euclid(m)
    } else {
        r1
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Packs `bits` bits per coefficient of `b - w[i]` (a centered value into
/// an unsigned one), least significant first.
fn bit_pack(w: &Poly, bits: usize, b: i64, out: &mut Vec<u8>) {
    let mut acc = 0u64;
    let mut n = 0;
    for &x in w {
        let v = (b - centered(x)) as u64;
        debug_assert!(v < 1 << bits);
        acc |= v << n;
        n += bits;
        while n >= 8 {
            out.push(acc as u8);
            acc >>= 8;
            n -= 8;
        }
    }
}

/// Packs `bits` bits per non-negative coefficient.
fn simple_bit_pack(w: &Poly, bits: usize, out: &mut Vec<u8>) {
    let mut acc = 0u64;
    let mut n = 0;
    for &x in w {
        debug_assert!(x >= 0 && x < 1 << bits);
        acc |= (x as u64) << n;
        n += bits;
        while n >= 8 {
            out.push(acc as u8);
            acc >>= 8;
            n -= 8;
        }
    }
}

fn simple_bit_unpack(v: &[u8], bits: usize) -> Poly {
    let mut w = [0i64; N];
    let mut acc = 0u64;
    let mut n = 0;
    let mut i = 0;
    for &byte in v {
        acc |= u64::from(byte) << n;
        n += 8;
        while n >= bits && i < N {
            w[i] = (acc & ((1 << bits) - 1)) as i64;
            acc >>= bits;
            n -= bits;
            i += 1;
        }
    }
    w
}

/// Unpacks `bits` bits per coefficient into `b - v`, reduced mod q.
fn bit_unpack(v: &[u8], bits: usize, _a: i64, b: i64) -> Poly {
    let raw = simple_bit_unpack(v, bits);
    core::array::from_fn(|i| modq(b - raw[i]))
}

fn hint_bit_pack(h: &[[bool; N]; K], out: &mut Vec<u8>) {
    let mut y = vec![0u8; OMEGA + K];
    let mut index = 0;
    for (i, hi) in h.iter().enumerate() {
        for (j, &bit) in hi.iter().enumerate() {
            if bit {
                y[index] = j as u8;
                index += 1;
            }
        }
        y[OMEGA + i] = index as u8;
    }
    out.extend_from_slice(&y);
}

fn hint_bit_unpack(y: &[u8]) -> Option<[[bool; N]; K]> {
    let mut h = [[false; N]; K];
    let mut index = 0usize;
    for i in 0..K {
        let end = usize::from(y[OMEGA + i]);
        if end < index || end > OMEGA {
            return None;
        }
        let first = index;
        while index < end {
            if index > first && y[index] <= y[index - 1] {
                return None;
            }
            h[i][usize::from(y[index])] = true;
            index += 1;
        }
    }
    if y[index..OMEGA].iter().any(|&b| b != 0) {
        return None;
    }
    Some(h)
}

fn w1_encode(w1: &[Poly; K]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * K * W1_BITS);
    for w in w1 {
        simple_bit_pack(w, W1_BITS, &mut out);
    }
    out
}

// ---------------------------------------------------------------------------
// Keys and signatures
// ---------------------------------------------------------------------------

/// A secret key, with its public key.
#[derive(Clone)]
pub struct SecretKey {
    sk: Vec<u8>,
    pk: Vec<u8>,
}

/// Generates a key pair from a 32-byte seed, deterministically.
pub fn keygen(seed: &[u8; SEED_LEN]) -> SecretKey {
    let mut input = [0u8; 34];
    input[..32].copy_from_slice(seed);
    input[32] = K as u8;
    input[33] = L as u8;
    let expanded = shake256(&input, 128);
    let rho: [u8; 32] = expanded[..32].try_into().unwrap();
    let rho_prime: [u8; 64] = expanded[32..96].try_into().unwrap();
    let kk: [u8; 32] = expanded[96..].try_into().unwrap();
    let a = expand_a(&rho);
    let s1: [Poly; L] = core::array::from_fn(|r| rej_bounded_poly(&rho_prime, r as u16));
    let s2: [Poly; K] = core::array::from_fn(|r| rej_bounded_poly(&rho_prime, (L + r) as u16));
    let s1_hat: [Poly; L] = core::array::from_fn(|r| {
        let mut p = s1[r];
        ntt(&mut p);
        p
    });
    let mut pk = Vec::with_capacity(PK_LEN);
    pk.extend_from_slice(&rho);
    let mut t0 = [[0i64; N]; K];
    for i in 0..K {
        let mut t = [0i64; N];
        for j in 0..L {
            t = poly_add(&t, &mul_ntt(&a[i * L + j], &s1_hat[j]));
        }
        inv_ntt(&mut t);
        t = poly_add(&t, &s2[i]);
        let mut t1 = [0i64; N];
        for c in 0..N {
            let (hi, lo) = power2round(t[c]);
            t1[c] = hi;
            t0[i][c] = modq(lo);
        }
        simple_bit_pack(&t1, T1_BITS, &mut pk);
    }
    let tr = shake256(&pk, 64);
    let mut sk = Vec::with_capacity(SK_LEN);
    sk.extend_from_slice(&rho);
    sk.extend_from_slice(&kk);
    sk.extend_from_slice(&tr);
    for s in &s1 {
        bit_pack(s, S_BITS, ETA, &mut sk);
    }
    for s in &s2 {
        bit_pack(s, S_BITS, ETA, &mut sk);
    }
    for t in &t0 {
        bit_pack(t, D as usize, 1 << (D - 1), &mut sk);
    }
    SecretKey { sk, pk }
}

/// The message as signed: a domain byte, the context's length, the
/// context and the message (FIPS 204's pure external interface).
fn framed(msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(2 + ctx.len() + msg.len());
    m.push(0);
    m.push(ctx.len() as u8);
    m.extend_from_slice(ctx);
    m.extend_from_slice(msg);
    m
}

impl SecretKey {
    pub fn public_key(&self) -> &[u8] {
        &self.pk
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.sk
    }

    /// Takes a secret key with its public key, checking their lengths and
    /// that the key's `tr` is the public key's hash.
    pub fn from_bytes(sk: &[u8], pk: &[u8]) -> Option<SecretKey> {
        if sk.len() != SK_LEN || pk.len() != PK_LEN || shake256(pk, 64) != sk[64..128] || sk[..32] != pk[..32] {
            return None;
        }
        Some(SecretKey { sk: sk.to_vec(), pk: pk.to_vec() })
    }

    /// Signs `msg` under `ctx` (at most 255 bytes), deterministically.
    pub fn sign(&self, msg: &[u8], ctx: &[u8]) -> Vec<u8> {
        assert!(ctx.len() <= 255, "context too long");
        self.sign_internal(&framed(msg, ctx), &[0u8; 32])
    }

    fn sign_internal(&self, m: &[u8], rnd: &[u8; 32]) -> Vec<u8> {
        let sk = &self.sk;
        let rho: [u8; 32] = sk[..32].try_into().unwrap();
        let kk = &sk[32..64];
        let tr = &sk[64..128];
        let mut at = 128;
        let mut take = |bits: usize, b: i64| -> Poly {
            let p = bit_unpack(&sk[at..at + 32 * bits], bits, 0, b);
            at += 32 * bits;
            p
        };
        let s1: [Poly; L] = core::array::from_fn(|_| take(S_BITS, ETA));
        let s2: [Poly; K] = core::array::from_fn(|_| take(S_BITS, ETA));
        let t0: [Poly; K] = core::array::from_fn(|_| take(D as usize, 1 << (D - 1)));
        let to_ntt = |p: &Poly| {
            let mut q = *p;
            ntt(&mut q);
            q
        };
        let s1_hat: [Poly; L] = core::array::from_fn(|i| to_ntt(&s1[i]));
        let s2_hat: [Poly; K] = core::array::from_fn(|i| to_ntt(&s2[i]));
        let t0_hat: [Poly; K] = core::array::from_fn(|i| to_ntt(&t0[i]));
        let a = expand_a(&rho);
        let mut mu_in = Vec::with_capacity(64 + m.len());
        mu_in.extend_from_slice(tr);
        mu_in.extend_from_slice(m);
        let mu = shake256(&mu_in, 64);
        let mut rho2_in = Vec::with_capacity(128);
        rho2_in.extend_from_slice(kk);
        rho2_in.extend_from_slice(rnd);
        rho2_in.extend_from_slice(&mu);
        let rho2: [u8; 64] = shake256(&rho2_in, 64).try_into().unwrap();
        let mut kappa: u16 = 0;
        loop {
            let y = expand_mask(&rho2, kappa);
            kappa += L as u16;
            let y_hat: [Poly; L] = core::array::from_fn(|i| to_ntt(&y[i]));
            let w: [Poly; K] = core::array::from_fn(|i| {
                let mut acc = [0i64; N];
                for j in 0..L {
                    acc = poly_add(&acc, &mul_ntt(&a[i * L + j], &y_hat[j]));
                }
                inv_ntt(&mut acc);
                acc
            });
            let w1: [Poly; K] = core::array::from_fn(|i| core::array::from_fn(|c| high_bits(w[i][c])));
            let mut c_in = Vec::with_capacity(64 + 32 * K * W1_BITS);
            c_in.extend_from_slice(&mu);
            c_in.extend_from_slice(&w1_encode(&w1));
            let c_tilde = shake256(&c_in, CT_LEN);
            let c = sample_in_ball(&c_tilde);
            let c_hat = to_ntt(&c);
            let z: [Poly; L] = core::array::from_fn(|i| {
                let mut cs1 = mul_ntt(&c_hat, &s1_hat[i]);
                inv_ntt(&mut cs1);
                poly_add(&y[i], &cs1)
            });
            if z.iter().any(|p| infinity_norm(p) >= GAMMA1 - BETA) {
                continue;
            }
            let w_minus_cs2: [Poly; K] = core::array::from_fn(|i| {
                let mut cs2 = mul_ntt(&c_hat, &s2_hat[i]);
                inv_ntt(&mut cs2);
                poly_sub(&w[i], &cs2)
            });
            let r0_max =
                w_minus_cs2.iter().map(|p| p.iter().map(|&x| low_bits(x).abs()).max().unwrap()).max().unwrap();
            if r0_max >= GAMMA2 - BETA {
                continue;
            }
            let ct0: [Poly; K] = core::array::from_fn(|i| {
                let mut p = mul_ntt(&c_hat, &t0_hat[i]);
                inv_ntt(&mut p);
                p
            });
            if ct0.iter().any(|p| infinity_norm(p) >= GAMMA2) {
                continue;
            }
            let mut h = [[false; N]; K];
            let mut weight = 0;
            for i in 0..K {
                for c in 0..N {
                    let bit = make_hint(modq(-ct0[i][c]), modq(w_minus_cs2[i][c] + ct0[i][c]));
                    h[i][c] = bit;
                    weight += usize::from(bit);
                }
            }
            if weight > OMEGA {
                continue;
            }
            let mut sig = Vec::with_capacity(SIG_LEN);
            sig.extend_from_slice(&c_tilde);
            for zi in &z {
                bit_pack(zi, Z_BITS, GAMMA1, &mut sig);
            }
            hint_bit_pack(&h, &mut sig);
            return sig;
        }
    }
}

/// Whether `sig` is `pk`'s signature over `msg` under `ctx`.
pub fn verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    if pk.len() != PK_LEN || sig.len() != SIG_LEN || ctx.len() > 255 {
        return false;
    }
    verify_internal(pk, &framed(msg, ctx), sig)
}

fn verify_internal(pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
    let rho: [u8; 32] = pk[..32].try_into().unwrap();
    let t1: [Poly; K] = core::array::from_fn(|i| simple_bit_unpack(&pk[32 + 32 * T1_BITS * i..32 + 32 * T1_BITS * (i + 1)], T1_BITS));
    let c_tilde = &sig[..CT_LEN];
    let z: [Poly; L] =
        core::array::from_fn(|i| bit_unpack(&sig[CT_LEN + 32 * Z_BITS * i..CT_LEN + 32 * Z_BITS * (i + 1)], Z_BITS, 0, GAMMA1));
    let Some(h) = hint_bit_unpack(&sig[CT_LEN + 32 * Z_BITS * L..]) else {
        return false;
    };
    if z.iter().any(|p| infinity_norm(p) >= GAMMA1 - BETA) {
        return false;
    }
    let a = expand_a(&rho);
    let tr = shake256(pk, 64);
    let mut mu_in = Vec::with_capacity(64 + m.len());
    mu_in.extend_from_slice(&tr);
    mu_in.extend_from_slice(m);
    let mu = shake256(&mu_in, 64);
    let c = sample_in_ball(c_tilde);
    let to_ntt = |p: &Poly| {
        let mut q = *p;
        ntt(&mut q);
        q
    };
    let c_hat = to_ntt(&c);
    let z_hat: [Poly; L] = core::array::from_fn(|i| to_ntt(&z[i]));
    let w1: [Poly; K] = core::array::from_fn(|i| {
        let mut acc = [0i64; N];
        for j in 0..L {
            acc = poly_add(&acc, &mul_ntt(&a[i * L + j], &z_hat[j]));
        }
        let t1_scaled: Poly = core::array::from_fn(|c| modq(t1[i][c] << D));
        let ct1 = mul_ntt(&c_hat, &to_ntt(&t1_scaled));
        acc = poly_sub(&acc, &ct1);
        inv_ntt(&mut acc);
        core::array::from_fn(|c| use_hint(h[i][c], acc[c]))
    });
    let mut c_in = Vec::with_capacity(64 + 32 * K * W1_BITS);
    c_in.extend_from_slice(&mu);
    c_in.extend_from_slice(&w1_encode(&w1));
    shake256(&c_in, CT_LEN) == c_tilde
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        if s == "-" {
            return Vec::new();
        }
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn sizes_and_rounding() {
        assert_eq!(PK_LEN, 1952);
        assert_eq!(SK_LEN, 4032);
        assert_eq!(SIG_LEN, 3309);
        assert_eq!(GAMMA2, 261_888);
        assert_eq!(powq(1753, 256), Q - 1, "ζ has order 512, so ζ^256 = -1");
        assert_eq!(256 * INV256 % Q, 1);
        for r in [0, 1, Q - 1, 123_456, 4_190_208, 4_190_209] {
            let (r1, r0) = power2round(r);
            assert_eq!(modq(r1 * (1 << D) + r0), modq(r));
            assert!(r0 > -(1 << (D - 1)) && r0 <= 1 << (D - 1));
            let (h, l) = decompose(r);
            assert_eq!(modq(h * 2 * GAMMA2 + l), modq(r));
            assert!((0..16).contains(&h));
        }
        let mut f: Poly = core::array::from_fn(|i| (i as i64 * 8_000_001) % Q);
        let g = f;
        ntt(&mut f);
        inv_ntt(&mut f);
        assert_eq!(f, g);
    }

    /// The known answers in `tests/vectors/ML-DSA-65.kat` (NIST ACVP).
    #[test]
    fn fips_204_known_answers() {
        let text = include_str!("../tests/vectors/ML-DSA-65.kat");
        let mut cases = 0;
        for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let mut parts = line.split(' ');
            let kind = parts.next().unwrap();
            let f: std::collections::HashMap<&str, &str> = parts.map(|p| p.split_once('=').unwrap()).collect();
            match kind {
                "keygen" => {
                    let sk = keygen(&hex(f["seed"]).try_into().unwrap());
                    assert_eq!(sk.public_key(), hex(f["pk"]));
                    assert_eq!(sk.to_bytes(), hex(f["sk"]));
                }
                "sign" => {
                    let sk_bytes = hex(f["sk"]);
                    let sk = SecretKey { sk: sk_bytes.clone(), pk: vec![] };
                    let sig = sk.sign(&hex(f["message"]), &hex(f["context"]));
                    assert_eq!(sig, hex(f["signature"]));
                }
                "verify" => {
                    let ok = verify(&hex(f["pk"]), &hex(f["message"]), &hex(f["context"]), &hex(f["signature"]));
                    assert_eq!(ok, f["ok"] == "1", "{}", f["reason"]);
                }
                other => panic!("unknown case {other}"),
            }
            cases += 1;
        }
        assert!(cases >= 10, "{cases} cases");
    }

    #[test]
    fn round_trips_and_rejects() {
        let seed = [3u8; 32];
        let sk = keygen(&seed);
        assert_eq!(keygen(&seed).public_key(), sk.public_key(), "deterministic");
        let pk = sk.public_key();
        let sig = sk.sign(b"hello", b"ctx");
        assert_eq!(sig.len(), SIG_LEN);
        assert!(verify(pk, b"hello", b"ctx", &sig));
        assert!(!verify(pk, b"hellp", b"ctx", &sig));
        assert!(!verify(pk, b"hello", b"", &sig));
        let mut bad = sig.clone();
        bad[100] ^= 1;
        assert!(!verify(pk, b"hello", b"ctx", &bad));
        let other = keygen(&[4u8; 32]);
        assert!(!verify(other.public_key(), b"hello", b"ctx", &sig));
        assert!(SecretKey::from_bytes(sk.to_bytes(), pk).is_some());
        assert!(SecretKey::from_bytes(sk.to_bytes(), other.public_key()).is_none());
        assert_eq!(sk.sign(b"hello", b"ctx"), sig, "deterministic signing");
    }
}
