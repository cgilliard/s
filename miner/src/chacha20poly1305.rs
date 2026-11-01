//! ChaCha20-Poly1305 (RFC 8439): the symmetric layer of the message
//! layer (`docs/ONION.md`), for message bodies and circuit layers.
//!
//! [`seal`] and [`open`] are the AEAD with a 32-byte key, a 12-byte
//! nonce and associated data; the tag is 16 bytes appended to the
//! ciphertext. Nonces must never repeat under a key: callers derive a
//! fresh key per message (a KEM shared secret) or count. Constant time
//! where it matters: Poly1305 runs in fixed time over the data and the
//! tag comparison does not short-circuit.

/// Key size in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce size in bytes.
pub const NONCE_LEN: usize = 12;
/// Tag size in bytes.
pub const TAG_LEN: usize = 16;

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// The ChaCha20 block function: 64 bytes of keystream for a block
/// counter.
pub fn block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut w = state;
    for _ in 0..10 {
        quarter_round(&mut w, 0, 4, 8, 12);
        quarter_round(&mut w, 1, 5, 9, 13);
        quarter_round(&mut w, 2, 6, 10, 14);
        quarter_round(&mut w, 3, 7, 11, 15);
        quarter_round(&mut w, 0, 5, 10, 15);
        quarter_round(&mut w, 1, 6, 11, 12);
        quarter_round(&mut w, 2, 7, 8, 13);
        quarter_round(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&w[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

/// XORs the keystream from `counter` on into `data`, in place.
pub fn xor_stream(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let ks = block(key, counter.wrapping_add(i as u32), nonce);
        for (d, k) in chunk.iter_mut().zip(&ks) {
            *d ^= k;
        }
    }
}

/// Poly1305 over `msg` with a 32-byte one-time key (r, then s).
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; TAG_LEN] {
    // r clamped, in five 26-bit limbs; the accumulator likewise.
    let r0 = u32::from_le_bytes(key[0..4].try_into().unwrap()) & 0x03ff_ffff;
    let r1 = (u32::from_le_bytes(key[3..7].try_into().unwrap()) >> 2) & 0x03ff_ff03;
    let r2 = (u32::from_le_bytes(key[6..10].try_into().unwrap()) >> 4) & 0x03ff_c0ff;
    let r3 = (u32::from_le_bytes(key[9..13].try_into().unwrap()) >> 6) & 0x03f0_3fff;
    let r4 = (u32::from_le_bytes(key[12..16].try_into().unwrap()) >> 8) & 0x000f_ffff;
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u32, 0u32, 0u32, 0u32, 0u32);
    let mut blocks = msg.chunks(16);
    let mut process = |chunk: &[u8]| {
        // The block with its padding byte: bit 8·len set.
        let mut b = [0u8; 17];
        b[..chunk.len()].copy_from_slice(chunk);
        b[chunk.len()] = 1;
        let t0 = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let t1 = u32::from_le_bytes(b[4..8].try_into().unwrap());
        let t2 = u32::from_le_bytes(b[8..12].try_into().unwrap());
        let t3 = u32::from_le_bytes(b[12..16].try_into().unwrap());
        h0 += t0 & 0x03ff_ffff;
        h1 += ((((t1 as u64) << 32) | t0 as u64) >> 26) as u32 & 0x03ff_ffff;
        h2 += ((((t2 as u64) << 32) | t1 as u64) >> 20) as u32 & 0x03ff_ffff;
        h3 += ((((t3 as u64) << 32) | t2 as u64) >> 14) as u32 & 0x03ff_ffff;
        h4 += (t3 >> 8) | (u32::from(b[16]) << 24);
        let d0 = h0 as u64 * r0 as u64 + h1 as u64 * s4 as u64 + h2 as u64 * s3 as u64 + h3 as u64 * s2 as u64 + h4 as u64 * s1 as u64;
        let mut d1 = h0 as u64 * r1 as u64 + h1 as u64 * r0 as u64 + h2 as u64 * s4 as u64 + h3 as u64 * s3 as u64 + h4 as u64 * s2 as u64;
        let mut d2 = h0 as u64 * r2 as u64 + h1 as u64 * r1 as u64 + h2 as u64 * r0 as u64 + h3 as u64 * s4 as u64 + h4 as u64 * s3 as u64;
        let mut d3 = h0 as u64 * r3 as u64 + h1 as u64 * r2 as u64 + h2 as u64 * r1 as u64 + h3 as u64 * r0 as u64 + h4 as u64 * s4 as u64;
        let mut d4 = h0 as u64 * r4 as u64 + h1 as u64 * r3 as u64 + h2 as u64 * r2 as u64 + h3 as u64 * r1 as u64 + h4 as u64 * r0 as u64;
        let mut c = (d0 >> 26) as u32;
        h0 = d0 as u32 & 0x03ff_ffff;
        d1 += c as u64;
        c = (d1 >> 26) as u32;
        h1 = d1 as u32 & 0x03ff_ffff;
        d2 += c as u64;
        c = (d2 >> 26) as u32;
        h2 = d2 as u32 & 0x03ff_ffff;
        d3 += c as u64;
        c = (d3 >> 26) as u32;
        h3 = d3 as u32 & 0x03ff_ffff;
        d4 += c as u64;
        c = (d4 >> 26) as u32;
        h4 = d4 as u32 & 0x03ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;
    };
    for chunk in blocks.by_ref() {
        process(chunk);
    }
    // Full carry, then h mod p: compare against p by computing h - p.
    let mut c = h1 >> 26;
    h1 &= 0x03ff_ffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x03ff_ffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x03ff_ffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x03ff_ffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x03ff_ffff;
    h1 += c;
    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x03ff_ffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x03ff_ffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x03ff_ffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x03ff_ffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
    // Select g if h >= p (g4's top bit clear), else h, without branching.
    let mask = (g4 >> 31).wrapping_sub(1);
    let g0 = g0 & mask;
    let g1 = g1 & mask;
    let g2 = g2 & mask;
    let g3 = g3 & mask;
    let g4 = g4 & mask;
    let mask = !mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;
    // h as four 32-bit words, plus s.
    let w0 = h0 | (h1 << 26);
    let w1 = (h1 >> 6) | (h2 << 20);
    let w2 = (h2 >> 12) | (h3 << 14);
    let w3 = (h3 >> 18) | (h4 << 8);
    let s0 = u32::from_le_bytes(key[16..20].try_into().unwrap());
    let s1 = u32::from_le_bytes(key[20..24].try_into().unwrap());
    let s2 = u32::from_le_bytes(key[24..28].try_into().unwrap());
    let s3 = u32::from_le_bytes(key[28..32].try_into().unwrap());
    let mut f = w0 as u64 + s0 as u64;
    let w0 = f as u32;
    f = (f >> 32) + w1 as u64 + s1 as u64;
    let w1 = f as u32;
    f = (f >> 32) + w2 as u64 + s2 as u64;
    let w2 = f as u32;
    f = (f >> 32) + w3 as u64 + s3 as u64;
    let w3 = f as u32;
    let mut tag = [0u8; TAG_LEN];
    tag[0..4].copy_from_slice(&w0.to_le_bytes());
    tag[4..8].copy_from_slice(&w1.to_le_bytes());
    tag[8..12].copy_from_slice(&w2.to_le_bytes());
    tag[12..16].copy_from_slice(&w3.to_le_bytes());
    tag
}

/// The Poly1305 one-time key for a message: block 0 of the keystream.
fn mac_key(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    block(key, 0, nonce)[..32].try_into().unwrap()
}

fn tag_of(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    let mut mac_input = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
    mac_input.extend_from_slice(aad);
    mac_input.resize(aad.len().div_ceil(16) * 16, 0);
    mac_input.extend_from_slice(ciphertext);
    mac_input.resize(mac_input.len().div_ceil(16) * 16, 0);
    mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305(&mac_key(key, nonce), &mac_input)
}

/// Encrypts and authenticates `plaintext` with `aad`: the ciphertext with
/// the tag appended.
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut out = plaintext.to_vec();
    xor_stream(key, 1, nonce, &mut out);
    let tag = tag_of(key, nonce, aad, &out);
    out.extend_from_slice(&tag);
    out
}

/// Checks and decrypts what [`seal`] made; `None` if the tag, the key,
/// the nonce or the associated data differ.
pub fn open(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < TAG_LEN {
        return None;
    }
    let (ciphertext, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    let expected = tag_of(key, nonce, aad, ciphertext);
    let mut diff = 0u8;
    for (a, b) in tag.iter().zip(&expected) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }
    let mut out = ciphertext.to_vec();
    xor_stream(key, 1, nonce, &mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// RFC 8439 section 2.3.2.
    #[test]
    fn block_function_vector() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = hex("000000090000004a00000000").try_into().unwrap();
        let out = block(&key, 1, &nonce);
        let want = hex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );
        assert_eq!(out.to_vec(), want);
    }

    /// RFC 8439 section 2.5.2.
    #[test]
    fn poly1305_vector() {
        let key: [u8; 32] =
            hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").try_into().unwrap();
        let tag = poly1305(&key, b"Cryptographic Forum Research Group");
        assert_eq!(tag.to_vec(), hex("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    /// RFC 8439 section 2.8.2.
    #[test]
    fn aead_vector_and_rejections() {
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = seal(&key, &nonce, &aad, plaintext);
        let want_ct = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        assert_eq!(sealed[..sealed.len() - 16].to_vec(), want_ct);
        assert_eq!(sealed[sealed.len() - 16..].to_vec(), hex("1ae10b594f09e26a7e902ecbd0600691"));
        assert_eq!(open(&key, &nonce, &aad, &sealed).as_deref(), Some(&plaintext[..]));
        // Any change is caught.
        let mut bad = sealed.clone();
        bad[5] ^= 1;
        assert_eq!(open(&key, &nonce, &aad, &bad), None);
        let mut bad = sealed.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert_eq!(open(&key, &nonce, &aad, &bad), None);
        assert_eq!(open(&key, &nonce, &aad[1..], &sealed), None);
        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        assert_eq!(open(&key, &other_nonce, &aad, &sealed), None);
        assert_eq!(open(&key, &nonce, &aad, &sealed[..10]), None);
        // Empty messages and long ones round-trip.
        assert_eq!(open(&key, &nonce, &[], &seal(&key, &nonce, &[], &[])).as_deref(), Some(&[][..]));
        let long = vec![7u8; 1000];
        assert_eq!(open(&key, &nonce, &aad, &seal(&key, &nonce, &aad, &long)).as_deref(), Some(&long[..]));
    }
}
