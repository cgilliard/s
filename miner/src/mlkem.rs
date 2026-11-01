//! ML-KEM-768 (FIPS 203): the key encapsulation of the message layer
//! (`docs/ONION.md`), by which a sender and a holder of an encapsulation
//! key agree a 32-byte secret.
//!
//! Keys: encapsulation key 1,184 bytes, decapsulation key 2,400 bytes,
//! ciphertext 1,088 bytes, shared secret 32 bytes. Decapsulation never
//! fails: a ciphertext that does not decrypt yields a key derived from the
//! secret `z` and the ciphertext (implicit rejection), chosen without
//! branching on the comparison.

use crate::keccak::{Sponge, sha3_256, sha3_512, shake256};

const N: usize = 256;
const Q: u32 = 3329;
const K: usize = 3;
const ETA1: usize = 2;
const ETA2: usize = 2;
const DU: usize = 10;
const DV: usize = 4;

/// Encapsulation key size.
pub const EK_LEN: usize = 384 * K + 32;
/// Decapsulation key size.
pub const DK_LEN: usize = 768 * K + 96;
/// Ciphertext size.
pub const CT_LEN: usize = 32 * (DU * K + DV);
/// Shared secret size.
pub const SS_LEN: usize = 32;

type Poly = [u32; N];

/// `ζ^BitRev7(i) mod q`, ζ = 17.
const ZETAS: [u32; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046,
    56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650,
    1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474,
    3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703,
    1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220, 375,
    2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722,
    1212, 1874, 1029, 2110, 2935, 885, 2154,
];

fn mulq(a: u32, b: u32) -> u32 {
    (a * b) % Q
}

fn addq(a: u32, b: u32) -> u32 {
    (a + b) % Q
}

fn subq(a: u32, b: u32) -> u32 {
    (a + Q - b) % Q
}

fn ntt(f: &mut Poly) {
    let mut k = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = mulq(zeta, f[j + len]);
                f[j + len] = subq(f[j], t);
                f[j] = addq(f[j], t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

fn inv_ntt(f: &mut Poly) {
    let mut k = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = f[j];
                f[j] = addq(t, f[j + len]);
                f[j + len] = mulq(zeta, subq(f[j + len], t));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for x in f.iter_mut() {
        *x = mulq(*x, 3303);
    }
}

/// Product of two polynomials in the NTT domain.
fn mul_ntt(f: &Poly, g: &Poly) -> Poly {
    let mut h = [0u32; N];
    for i in 0..128 {
        let gamma = ZETAS_GAMMA[i];
        let (a0, a1, b0, b1) = (f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]);
        h[2 * i] = addq(mulq(a0, b0), mulq(mulq(a1, b1), gamma));
        h[2 * i + 1] = addq(mulq(a0, b1), mulq(a1, b0));
    }
    h
}

/// `ζ^(2·BitRev7(i)+1) mod q`.
const ZETAS_GAMMA: [u32; 128] = {
    let mut t = [0u32; 128];
    let mut i = 0;
    while i < 128 {
        // bitrev7 and modular exponentiation in const context
        let mut r = 0usize;
        let mut b = 0;
        while b < 7 {
            r |= ((i >> b) & 1) << (6 - b);
            b += 1;
        }
        let e = 2 * r + 1;
        let mut acc = 1u64;
        let mut base = 17u64;
        let mut exp = e;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = acc * base % 3329;
            }
            base = base * base % 3329;
            exp >>= 1;
        }
        t[i] = acc as u32;
        i += 1;
    }
    t
};

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| addq(a[i], b[i]))
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| subq(a[i], b[i]))
}

/// Rejection sampling of a uniform NTT polynomial from an XOF.
fn sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> Poly {
    let mut xof = Sponge::shake128();
    xof.absorb(rho).absorb(&[j, i]);
    let mut f = [0u32; N];
    let mut n = 0;
    let mut buf = [0u8; 3 * 168];
    while n < N {
        xof.squeeze(&mut buf);
        for c in buf.chunks(3) {
            let d1 = u32::from(c[0]) | (u32::from(c[1] & 15) << 8);
            let d2 = u32::from(c[1] >> 4) | (u32::from(c[2]) << 4);
            if d1 < Q && n < N {
                f[n] = d1;
                n += 1;
            }
            if d2 < Q && n < N {
                f[n] = d2;
                n += 1;
            }
        }
    }
    f
}

/// A centered binomial polynomial from `64·eta` PRF bytes.
fn sample_cbd(eta: usize, bytes: &[u8]) -> Poly {
    let bit = |i: usize| u32::from((bytes[i / 8] >> (i % 8)) & 1);
    let mut f = [0u32; N];
    for (i, c) in f.iter_mut().enumerate() {
        let x: u32 = (0..eta).map(|j| bit(2 * i * eta + j)).sum();
        let y: u32 = (0..eta).map(|j| bit(2 * i * eta + eta + j)).sum();
        *c = subq(x, y);
    }
    f
}

fn prf(eta: usize, s: &[u8; 32], b: u8) -> Vec<u8> {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(s);
    input[32] = b;
    shake256(&input, 64 * eta)
}

fn compress(d: usize, x: u32) -> u32 {
    (((x << d) + Q / 2) / Q) & ((1 << d) - 1)
}

fn decompress(d: usize, y: u32) -> u32 {
    (Q * y + (1 << (d - 1))) >> d
}

/// Packs coefficients of `d` bits each, least significant bit first.
fn byte_encode(d: usize, f: &Poly, out: &mut Vec<u8>) {
    let mut acc = 0u64;
    let mut bits = 0;
    for &c in f {
        acc |= u64::from(c) << bits;
        bits += d;
        while bits >= 8 {
            out.push(acc as u8);
            acc >>= 8;
            bits -= 8;
        }
    }
}

fn byte_decode(d: usize, bytes: &[u8]) -> Poly {
    let mut f = [0u32; N];
    let mut acc = 0u64;
    let mut bits = 0;
    let mut i = 0;
    for &b in bytes {
        acc |= u64::from(b) << bits;
        bits += 8;
        while bits >= d && i < N {
            // Twelve-bit coefficients are reduced, so re-encoding a key
            // with a coefficient at or above q changes it (the modulus check).
            f[i] = (acc & ((1 << d) - 1)) as u32;
            if d == 12 {
                f[i] %= Q;
            }
            acc >>= d;
            bits -= d;
            i += 1;
        }
    }
    f
}

/// K-PKE.KeyGen: the encapsulation key and the secret vector in the NTT
/// domain, from the seeds `(ρ, σ)` and the matrix they imply.
fn kpke_keygen(d: &[u8; 32]) -> (Vec<u8>, [Poly; K]) {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(d);
    input[32] = K as u8;
    let g = sha3_512(&input);
    let rho: [u8; 32] = g[..32].try_into().unwrap();
    let sigma: [u8; 32] = g[32..].try_into().unwrap();
    let mut n = 0u8;
    let mut s: [Poly; K] = [[0; N]; K];
    for sj in s.iter_mut() {
        *sj = sample_cbd(ETA1, &prf(ETA1, &sigma, n));
        ntt(sj);
        n += 1;
    }
    let mut e: [Poly; K] = [[0; N]; K];
    for ej in e.iter_mut() {
        *ej = sample_cbd(ETA1, &prf(ETA1, &sigma, n));
        ntt(ej);
        n += 1;
    }
    let mut ek = Vec::with_capacity(EK_LEN);
    for (i, ei) in e.iter().enumerate() {
        let mut t = *ei;
        for (j, sj) in s.iter().enumerate() {
            let a = sample_ntt(&rho, j as u8, i as u8);
            t = poly_add(&t, &mul_ntt(&a, sj));
        }
        byte_encode(12, &t, &mut ek);
    }
    ek.extend_from_slice(&rho);
    (ek, s)
}

fn kpke_encrypt(ek: &[u8], m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    let t: [Poly; K] = core::array::from_fn(|i| byte_decode(12, &ek[384 * i..384 * (i + 1)]));
    let rho: [u8; 32] = ek[384 * K..].try_into().unwrap();
    let mut n = 0u8;
    let mut y: [Poly; K] = [[0; N]; K];
    for yj in y.iter_mut() {
        *yj = sample_cbd(ETA1, &prf(ETA1, r, n));
        ntt(yj);
        n += 1;
    }
    let mut e1: [Poly; K] = [[0; N]; K];
    for e in e1.iter_mut() {
        *e = sample_cbd(ETA2, &prf(ETA2, r, n));
        n += 1;
    }
    let e2 = sample_cbd(ETA2, &prf(ETA2, r, n));
    let mut c = Vec::with_capacity(CT_LEN);
    for (i, e) in e1.iter().enumerate() {
        // u[i] = NTT^-1(sum_j A[j][i] * y[j]) + e1[i]
        let mut u = [0u32; N];
        for (j, yj) in y.iter().enumerate() {
            let a = sample_ntt(&rho, i as u8, j as u8);
            u = poly_add(&u, &mul_ntt(&a, yj));
        }
        inv_ntt(&mut u);
        u = poly_add(&u, e);
        let compressed: Poly = core::array::from_fn(|k| compress(DU, u[k]));
        byte_encode(DU, &compressed, &mut c);
    }
    let mut v = [0u32; N];
    for j in 0..K {
        v = poly_add(&v, &mul_ntt(&t[j], &y[j]));
    }
    inv_ntt(&mut v);
    v = poly_add(&v, &e2);
    let mu: Poly = {
        let bits = byte_decode(1, m);
        core::array::from_fn(|k| decompress(1, bits[k]))
    };
    v = poly_add(&v, &mu);
    let compressed: Poly = core::array::from_fn(|k| compress(DV, v[k]));
    byte_encode(DV, &compressed, &mut c);
    c
}

fn kpke_decrypt(s: &[Poly; K], c: &[u8]) -> [u8; 32] {
    let mut w = {
        let bytes = &c[32 * DU * K..];
        let v = byte_decode(DV, bytes);
        core::array::from_fn(|k| decompress(DV, v[k]))
    };
    let mut acc = [0u32; N];
    for i in 0..K {
        let bytes = &c[32 * DU * i..32 * DU * (i + 1)];
        let decoded = byte_decode(DU, bytes);
        let mut u: Poly = core::array::from_fn(|k| decompress(DU, decoded[k]));
        ntt(&mut u);
        acc = poly_add(&acc, &mul_ntt(&s[i], &u));
    }
    inv_ntt(&mut acc);
    w = poly_sub(&w, &acc);
    let bits: Poly = core::array::from_fn(|k| compress(1, w[k]));
    let mut m = Vec::with_capacity(32);
    byte_encode(1, &bits, &mut m);
    m.try_into().unwrap()
}

/// A decapsulation key, with its encapsulation key.
#[derive(Clone)]
pub struct SecretKey {
    bytes: Vec<u8>,
}

/// Generates a key pair from the two 32-byte seeds, deterministically.
pub fn keygen_from_seeds(d: &[u8; 32], z: &[u8; 32]) -> SecretKey {
    let (ek, s) = kpke_keygen(d);
    let mut dk = Vec::with_capacity(DK_LEN);
    for sj in &s {
        byte_encode(12, sj, &mut dk);
    }
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&sha3_256(&ek));
    dk.extend_from_slice(z);
    SecretKey { bytes: dk }
}

/// Generates a key pair from 64 random bytes.
pub fn keygen(seed: &[u8; 64]) -> SecretKey {
    keygen_from_seeds(seed[..32].try_into().unwrap(), seed[32..].try_into().unwrap())
}

impl SecretKey {
    /// The encapsulation key to publish.
    pub fn public_key(&self) -> &[u8] {
        &self.bytes[384 * K..384 * K + EK_LEN]
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Checks the key's form (lengths and the hash of its encapsulation
    /// key) and takes it.
    pub fn from_bytes(bytes: &[u8]) -> Option<SecretKey> {
        if bytes.len() != DK_LEN {
            return None;
        }
        let ek = &bytes[384 * K..384 * K + EK_LEN];
        if sha3_256(ek) != bytes[384 * K + EK_LEN..384 * K + EK_LEN + 32] || !valid_public_key(ek) {
            return None;
        }
        Some(SecretKey { bytes: bytes.to_vec() })
    }

    /// Recovers the shared secret from a ciphertext made for this key; a
    /// ciphertext not made for it yields an unrelated secret.
    pub fn decapsulate(&self, c: &[u8]) -> Option<[u8; SS_LEN]> {
        if c.len() != CT_LEN {
            return None;
        }
        let s: [Poly; K] = core::array::from_fn(|i| byte_decode(12, &self.bytes[384 * i..384 * (i + 1)]));
        let ek = self.public_key();
        let h = &self.bytes[384 * K + EK_LEN..384 * K + EK_LEN + 32];
        let z = &self.bytes[384 * K + EK_LEN + 32..];
        let m = kpke_decrypt(&s, c);
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&m);
        input[32..].copy_from_slice(h);
        let g = sha3_512(&input);
        let k: [u8; 32] = g[..32].try_into().unwrap();
        let r: [u8; 32] = g[32..].try_into().unwrap();
        let mut zc = Vec::with_capacity(32 + CT_LEN);
        zc.extend_from_slice(z);
        zc.extend_from_slice(c);
        let kbar: [u8; 32] = shake256(&zc, 32).try_into().unwrap();
        let c2 = kpke_encrypt(ek, &m, &r);
        let mut diff = 0u8;
        for (a, b) in c.iter().zip(&c2) {
            diff |= a ^ b;
        }
        // All ones if the ciphertexts differ.
        let mask = ((diff as u16).wrapping_neg() >> 8) as u8;
        Some(core::array::from_fn(|i| (k[i] & !mask) | (kbar[i] & mask)))
    }
}

/// Whether `ek` is a well-formed encapsulation key: the right length and
/// every coefficient below q.
pub fn valid_public_key(ek: &[u8]) -> bool {
    if ek.len() != EK_LEN {
        return false;
    }
    let mut again = Vec::with_capacity(384 * K);
    for i in 0..K {
        byte_encode(12, &byte_decode(12, &ek[384 * i..384 * (i + 1)]), &mut again);
    }
    again == ek[..384 * K]
}

/// Encapsulates to `ek` with the 32-byte randomness `m`: the shared secret
/// and the ciphertext. `None` for a malformed key.
pub fn encapsulate_with(ek: &[u8], m: &[u8; 32]) -> Option<([u8; SS_LEN], Vec<u8>)> {
    if !valid_public_key(ek) {
        return None;
    }
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(m);
    input[32..].copy_from_slice(&sha3_256(ek));
    let g = sha3_512(&input);
    let k: [u8; 32] = g[..32].try_into().unwrap();
    let r: [u8; 32] = g[32..].try_into().unwrap();
    Some((k, kpke_encrypt(ek, m, &r)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn arr32(v: Vec<u8>) -> [u8; 32] {
        v.try_into().unwrap()
    }

    /// The known answers in `tests/vectors/ML-KEM-768.kat` (NIST ACVP).
    #[test]
    fn fips_203_known_answers() {
        let text = include_str!("../tests/vectors/ML-KEM-768.kat");
        let mut cases = 0;
        for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let mut parts = line.split(' ');
            let kind = parts.next().unwrap();
            let fields: std::collections::HashMap<&str, &str> =
                parts.map(|p| p.split_once('=').unwrap()).collect();
            match kind {
                "keygen" => {
                    let sk = keygen_from_seeds(&arr32(hex(fields["d"])), &arr32(hex(fields["z"])));
                    assert_eq!(sk.public_key(), hex(fields["ek"]));
                    assert_eq!(sk.to_bytes(), hex(fields["dk"]));
                }
                "encaps" => {
                    let (k, c) = encapsulate_with(&hex(fields["ek"]), &arr32(hex(fields["m"]))).unwrap();
                    assert_eq!(c, hex(fields["c"]));
                    assert_eq!(k.to_vec(), hex(fields["k"]));
                }
                "decaps" => {
                    let sk = SecretKey::from_bytes(&hex(fields["dk"])).unwrap();
                    let k = sk.decapsulate(&hex(fields["c"])).unwrap();
                    assert_eq!(k.to_vec(), hex(fields["k"]), "{}", fields["reason"]);
                }
                "ekcheck" => {
                    assert_eq!(valid_public_key(&hex(fields["ek"])), fields["ok"] == "1", "{}", fields["reason"]);
                }
                other => panic!("unknown case {other}"),
            }
            cases += 1;
        }
        assert!(cases >= 8, "{cases} cases");
    }

    #[test]
    fn round_trips_and_rejects() {
        let mut seed = [0u8; 64];
        for t in 0..20u8 {
            seed[0] = t;
            let sk = keygen(&seed);
            assert_eq!(sk.public_key().len(), EK_LEN);
            assert_eq!(sk.to_bytes().len(), DK_LEN);
            let m = [t; 32];
            let (k, c) = encapsulate_with(sk.public_key(), &m).unwrap();
            assert_eq!(c.len(), CT_LEN);
            assert_eq!(sk.decapsulate(&c), Some(k));
            // A tampered ciphertext decapsulates to another secret, quietly.
            let mut bad = c.clone();
            bad[t as usize] ^= 1;
            let other = sk.decapsulate(&bad).unwrap();
            assert_ne!(other, k);
            // Another key's ciphertext too.
            let mut other_seed = seed;
            other_seed[1] = t + 1;
            let sk2 = keygen(&other_seed);
            assert_ne!(sk2.decapsulate(&c).unwrap(), k);
            assert_eq!(sk.decapsulate(&c[1..]), None);
        }
        // Malformed keys are refused.
        let sk = keygen(&seed);
        let mut ek = sk.public_key().to_vec();
        ek[0] = 0xff;
        ek[1] = 0x0f;
        assert!(!valid_public_key(&ek));
        assert!(encapsulate_with(&ek, &[1; 32]).is_none());
        assert!(encapsulate_with(&sk.public_key()[1..], &[1; 32]).is_none());
        assert!(SecretKey::from_bytes(&sk.to_bytes()[1..]).is_none());
        let mut dk = sk.to_bytes().to_vec();
        dk[DK_LEN - 40] ^= 1;
        assert!(SecretKey::from_bytes(&dk).is_none());
    }

    #[test]
    fn ntt_inverts() {
        let mut f: Poly = core::array::from_fn(|i| (i as u32 * 7919) % Q);
        let g = f;
        ntt(&mut f);
        inv_ntt(&mut f);
        assert_eq!(f, g);
        assert_eq!(ZETAS[1], 1729);
        assert_eq!(ZETAS_GAMMA[0], 17);
    }
}
