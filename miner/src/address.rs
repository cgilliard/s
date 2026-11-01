//! The text form of an identity (`docs/ONION.md`): the 32-byte id in
//! bech32m with the human-readable part `tab`, so an address reads
//! `tab1…`, 62 characters, case-insensitive, with a 30-bit checksum that
//! detects any four errors and most others.
//!
//! The id is a Poseidon2 digest (eight field elements), encoded as 32
//! little-endian bytes exactly as [`crate::poseidon2::digest_to_bytes`]
//! does, so an address round-trips to the digest a name's record holds.
//! The id itself is the hash of a Dilithium (ML-DSA-65) public key under
//! [`DOM_ID`] ([`id_of`]).

use crate::poseidon2::{digest_from_bytes, digest_to_bytes};
use crate::transaction::hash_domain;
use crate::xmss::Digest;

/// Domain tag of an id: `H(DOM_ID ‖ Dilithium public key)`.
pub const DOM_ID: u32 = 18;

/// The id of a Dilithium public key.
pub fn id_of(dilithium_public_key: &[u8]) -> Digest {
    hash_domain(DOM_ID, &crate::pow::pack_bytes(dilithium_public_key))
}

/// The human-readable part of every address.
pub const HRP: &str = "tab";
/// Characters of an address: the prefix, the separator, 52 data
/// characters and 6 of checksum.
pub const LEN: usize = HRP.len() + 1 + 52 + 6;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M: u32 = 0x2bc8_30a3;

fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk = 1u32;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand() -> Vec<u8> {
    let mut v: Vec<u8> = HRP.bytes().map(|b| b >> 5).collect();
    v.push(0);
    v.extend(HRP.bytes().map(|b| b & 31));
    v
}

/// The address of an id.
pub fn encode(id: &Digest) -> String {
    let bytes = digest_to_bytes(id);
    let mut data = Vec::with_capacity(52);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        data.push(((acc << (5 - bits)) & 31) as u8);
    }
    let mut values = hrp_expand();
    values.extend_from_slice(&data);
    values.extend_from_slice(&[0; 6]);
    let pm = polymod(values) ^ BECH32M;
    let mut out = String::with_capacity(LEN);
    out.push_str(HRP);
    out.push('1');
    for d in &data {
        out.push(CHARSET[*d as usize] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    out
}

/// The id of an address, if it is one: the prefix, the checksum and the
/// length must all hold, and the bytes must be a canonical digest.
pub fn decode(s: &str) -> Option<Digest> {
    if s.len() != LEN || (s.bytes().any(|b| b.is_ascii_lowercase()) && s.bytes().any(|b| b.is_ascii_uppercase())) {
        return None;
    }
    let s = s.to_ascii_lowercase();
    let (hrp, rest) = s.split_once('1')?;
    if hrp != HRP {
        return None;
    }
    let data: Vec<u8> =
        rest.bytes().map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8)).collect::<Option<_>>()?;
    let mut values = hrp_expand();
    values.extend_from_slice(&data);
    if polymod(values) != BECH32M {
        return None;
    }
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut bytes = Vec::with_capacity(32);
    for d in &data[..data.len() - 6] {
        acc = (acc << 5) | u32::from(*d);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // The last group pads with zero bits only.
    if bytes.len() != 32 || bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    digest_from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::Fp;

    #[test]
    fn addresses_round_trip_and_catch_errors() {
        let id: Digest = core::array::from_fn(|i| Fp::new(123_456_789 * (i as u32 + 1)));
        let a = encode(&id);
        assert_eq!(a.len(), LEN);
        assert!(a.starts_with("tab1"));
        assert_eq!(decode(&a), Some(id));
        assert_eq!(decode(&a.to_uppercase()), Some(id));
        // One wrong character, a swapped pair, a missing character, mixed
        // case and another prefix are all refused.
        let mut bytes: Vec<u8> = a.bytes().collect();
        bytes[10] = if bytes[10] == b'q' { b'p' } else { b'q' };
        assert_eq!(decode(std::str::from_utf8(&bytes).unwrap()), None);
        let mut swapped = a.clone().into_bytes();
        swapped.swap(20, 21);
        if swapped != a.as_bytes() {
            assert_eq!(decode(std::str::from_utf8(&swapped).unwrap()), None);
        }
        assert_eq!(decode(&a[..a.len() - 1]), None);
        let mixed = format!("{}{}", &a[..5].to_uppercase(), &a[5..]);
        assert_eq!(decode(&mixed), None);
        assert_eq!(decode(&format!("tbb{}", &a[3..])), None);
        // Every id is one address; the zero id too.
        let zero = [Fp::ZERO; 8];
        assert_eq!(decode(&encode(&zero)), Some(zero));
        assert_ne!(encode(&zero), a);
    }

    #[test]
    fn ids_come_from_keys() {
        let pk = crate::mldsa::keygen(&[9u8; 32]);
        let id = id_of(pk.public_key());
        assert_eq!(id, id_of(pk.public_key()));
        assert_ne!(id, id_of(crate::mldsa::keygen(&[10u8; 32]).public_key()));
        assert_ne!(id, id_of(&pk.public_key()[1..]));
        assert_eq!(decode(&encode(&id)), Some(id));
    }
}
