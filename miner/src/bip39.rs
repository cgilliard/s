//! BIP39 mnemonic phrases, with the SHA-2 functions they need.
//!
//! A wallet's secret is 128 bits of entropy, shown as 12 words from the
//! standard English list (11 bits each: the entropy and a 4-bit checksum,
//! the first bits of its SHA-256). The 64-byte seed is
//! `PBKDF2-HMAC-SHA512(phrase, "mnemonic" || passphrase, 2048)`, as the
//! standard specifies, so any BIP39 tool agrees on whether a phrase is
//! valid. Phrases and passphrases are taken as ASCII (the English words are;
//! the standard's NFKD normalization is the identity on ASCII).

const WORDLIST: &str = include_str!("../../resources/bip39-english.txt");
/// Words in a phrase.
pub const WORDS: usize = 12;
/// Entropy bytes behind a 12-word phrase.
pub const ENTROPY_BYTES: usize = 16;
const ROUNDS: u32 = 2048;

fn words() -> Vec<&'static str> {
    WORDLIST.lines().map(str::trim).filter(|w| !w.is_empty()).collect()
}

/// The 12-word phrase for 16 bytes of entropy.
pub fn phrase(entropy: &[u8; ENTROPY_BYTES]) -> String {
    let list = words();
    let checksum = sha256(entropy)[0] >> 4;
    // 132 bits, most significant first: the entropy, then the checksum,
    // read 11 at a time. (The standard defines this bit string in
    // big-endian order; it is a text encoding, not a stored integer.)
    let bits = u128::from_be_bytes(*entropy);
    let mut out = Vec::with_capacity(WORDS);
    for i in 0..WORDS {
        let mut index = 0usize;
        for b in i * 11..i * 11 + 11 {
            let bit = if b < 128 { (bits >> (127 - b)) & 1 } else { u128::from((checksum >> (131 - b)) & 1) };
            index = (index << 1) | bit as usize;
        }
        out.push(list[index]);
    }
    out.join(" ")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PhraseError {
    /// Not 12 words.
    WordCount(usize),
    UnknownWord(String),
    Checksum,
    /// A passphrase with non-ASCII characters.
    NotAscii,
}

impl core::fmt::Display for PhraseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PhraseError::WordCount(n) => write!(f, "expected {WORDS} words, got {n}"),
            PhraseError::UnknownWord(w) => write!(f, "{w:?} is not a BIP39 word"),
            PhraseError::Checksum => f.write_str("the phrase's checksum does not match: a word is wrong"),
            PhraseError::NotAscii => f.write_str("the passphrase must be ASCII"),
        }
    }
}

impl std::error::Error for PhraseError {}

/// The entropy a phrase encodes, checking its words and checksum.
/// Whitespace and case are normalized.
pub fn entropy(phrase: &str) -> Result<[u8; ENTROPY_BYTES], PhraseError> {
    let list = words();
    let given: Vec<String> = phrase.split_whitespace().map(|w| w.to_ascii_lowercase()).collect();
    if given.len() != WORDS {
        return Err(PhraseError::WordCount(given.len()));
    }
    let mut bits: u128 = 0;
    let mut checksum: u8 = 0;
    for (i, w) in given.iter().enumerate() {
        let idx = list.binary_search(&w.as_str()).map_err(|_| PhraseError::UnknownWord(w.clone()))? as u64;
        for k in (0..11).rev() {
            let pos = i * 11 + (10 - k);
            let bit = (idx >> k) & 1;
            if pos < 128 {
                bits |= (bit as u128) << (127 - pos);
            } else {
                checksum |= (bit as u8) << (131 - pos);
            }
        }
    }
    let entropy = bits.to_be_bytes();
    if sha256(&entropy)[0] >> 4 != checksum {
        return Err(PhraseError::Checksum);
    }
    Ok(entropy)
}

/// The phrase in canonical form: lower case, single spaces.
pub fn normalize(phrase: &str) -> String {
    phrase.split_whitespace().map(|w| w.to_ascii_lowercase()).collect::<Vec<_>>().join(" ")
}

/// The BIP39 seed of a valid phrase and a passphrase (empty for none).
pub fn seed(phrase: &str, passphrase: &str) -> Result<[u8; 64], PhraseError> {
    entropy(phrase)?;
    if !passphrase.is_ascii() {
        return Err(PhraseError::NotAscii);
    }
    let salt = format!("mnemonic{passphrase}");
    Ok(pbkdf2_hmac_sha512(normalize(phrase).as_bytes(), salt.as_bytes(), ROUNDS))
}

// ---------------------------------------------------------------------------
// SHA-256, SHA-512, HMAC-SHA512, PBKDF2 (FIPS 180-4, RFC 2104, RFC 8018)
// ---------------------------------------------------------------------------

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-512 of `data`.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u128).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 128 != 112 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks_exact(128) {
        let mut w = [0u64; 80];
        for (i, word) in block.chunks_exact(8).enumerate() {
            w[i] = u64::from_be_bytes(word.try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 64];
    for (chunk, word) in out.chunks_exact_mut(8).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// HMAC-SHA512.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut k = [0u8; 128];
    if key.len() > 128 {
        k[..64].copy_from_slice(&sha512(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(128 + data.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(data);
    let ih = sha512(&inner);
    let mut outer = Vec::with_capacity(128 + 64);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&ih);
    sha512(&outer)
}

/// PBKDF2 with HMAC-SHA512, one 64-byte block.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 64] {
    let mut first = salt.to_vec();
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha512(password, &first);
    let mut out = u;
    for _ in 1..rounds {
        u = hmac_sha512(password, &u);
        for (o, x) in out.iter_mut().zip(&u) {
            *o ^= x;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn sha2_known_answers() {
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            hex(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        // RFC 4231 test case 2.
        assert_eq!(
            hex(&hmac_sha512(b"Jefe", b"what do ya want for nothing?")),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }

    #[test]
    fn wordlist_is_the_standard_one() {
        let list = words();
        assert_eq!(list.len(), 2048);
        assert!(list.windows(2).all(|w| w[0] < w[1]), "sorted, so binary search works");
        assert_eq!(
            hex(&sha256(WORDLIST.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    #[test]
    fn bip39_vectors() {
        // From the BIP39 reference vectors (passphrase "TREZOR").
        let cases = [
            (
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
                 1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f\
                 a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
            ),
            (
                "80808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30\
                 fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
            ),
            (
                "ffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13\
                 332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
            ),
        ];
        for (ent, words, seed_hex) in cases {
            let e: [u8; 16] = unhex(ent).try_into().unwrap();
            assert_eq!(phrase(&e), words);
            assert_eq!(entropy(words), Ok(e));
            assert_eq!(hex(&seed(words, "TREZOR").unwrap()), seed_hex.replace(' ', ""), "{words}");
        }
        assert_eq!(entropy("abandon abandon"), Err(PhraseError::WordCount(2)));
        assert!(matches!(
            entropy("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyz"),
            Err(PhraseError::UnknownWord(_))
        ));
        assert_eq!(
            entropy("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"),
            Err(PhraseError::Checksum)
        );
        assert_eq!(
            entropy("  Abandon ABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon About "),
            Ok([0u8; 16])
        );
        assert_eq!(seed("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", "pässword"), Err(PhraseError::NotAscii));
    }
}
