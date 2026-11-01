//! Keccak-f[1600] and the SHA-3 functions FIPS 203 and 204 use: SHA3-256,
//! SHA3-512, SHAKE128 and SHAKE256 (FIPS 202).

const ROUNDS: usize = 24;
const RC: [u64; ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];
const ROTC: [u32; 24] = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const PILN: [usize; 24] = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

/// The permutation on 25 lanes.
pub fn keccak_f(st: &mut [u64; 25]) {
    for rc in RC {
        let mut bc = [0u64; 5];
        for i in 0..5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                st[j + i] ^= t;
            }
        }
        let mut t = st[1];
        for i in 0..24 {
            let j = PILN[i];
            let tmp = st[j];
            st[j] = t.rotate_left(ROTC[i]);
            t = tmp;
        }
        for j in (0..25).step_by(5) {
            bc.copy_from_slice(&st[j..j + 5]);
            for i in 0..5 {
                st[j + i] ^= (!bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }
        st[0] ^= rc;
    }
}

/// A sponge over Keccak-f[1600] with a byte rate: absorb, then squeeze
/// any number of bytes (SHAKE), or a fixed digest (SHA-3).
pub struct Sponge {
    st: [u64; 25],
    rate: usize,
    pos: usize,
    squeezing: bool,
    suffix: u8,
}

impl Sponge {
    fn new(rate: usize, suffix: u8) -> Sponge {
        Sponge { st: [0; 25], rate, pos: 0, squeezing: false, suffix }
    }

    pub fn shake128() -> Sponge {
        Sponge::new(168, 0x1f)
    }

    pub fn shake256() -> Sponge {
        Sponge::new(136, 0x1f)
    }

    fn sha3_256() -> Sponge {
        Sponge::new(136, 0x06)
    }

    fn sha3_512() -> Sponge {
        Sponge::new(72, 0x06)
    }

    fn xor_byte(&mut self, i: usize, b: u8) {
        self.st[i / 8] ^= u64::from(b) << (8 * (i % 8));
    }

    fn byte(&self, i: usize) -> u8 {
        (self.st[i / 8] >> (8 * (i % 8))) as u8
    }

    /// Absorbs `data`; not after squeezing has begun.
    pub fn absorb(&mut self, data: &[u8]) -> &mut Sponge {
        assert!(!self.squeezing, "absorb after squeeze");
        for &b in data {
            self.xor_byte(self.pos, b);
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f(&mut self.st);
                self.pos = 0;
            }
        }
        self
    }

    fn pad(&mut self) {
        self.xor_byte(self.pos, self.suffix);
        self.xor_byte(self.rate - 1, 0x80);
        keccak_f(&mut self.st);
        self.pos = 0;
        self.squeezing = true;
    }

    /// Squeezes `out.len()` bytes; may be called repeatedly.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            self.pad();
        }
        for o in out.iter_mut() {
            if self.pos == self.rate {
                keccak_f(&mut self.st);
                self.pos = 0;
            }
            *o = self.byte(self.pos);
            self.pos += 1;
        }
    }

    /// Squeezes `n` bytes into a vector.
    pub fn squeeze_vec(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.squeeze(&mut v);
        v
    }
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Sponge::sha3_256().absorb(data).squeeze(&mut out);
    out
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    Sponge::sha3_512().absorb(data).squeeze(&mut out);
    out
}

pub fn shake128(data: &[u8], n: usize) -> Vec<u8> {
    Sponge::shake128().absorb(data).squeeze_vec(n)
}

pub fn shake256(data: &[u8], n: usize) -> Vec<u8> {
    Sponge::shake256().absorb(data).squeeze_vec(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn fips_202_vectors() {
        assert_eq!(hex(&sha3_256(b"")), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_eq!(hex(&sha3_256(b"abc")), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        assert_eq!(
            hex(&sha3_512(b"abc")),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        assert_eq!(hex(&shake128(b"", 32)), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        assert_eq!(
            hex(&shake256(b"", 64)),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
        // Squeezing in pieces equals squeezing at once, across the rate.
        let mut s = Sponge::shake128();
        s.absorb(b"abc");
        let mut pieces = Vec::new();
        for n in [1, 7, 160, 100, 32] {
            pieces.extend(s.squeeze_vec(n));
        }
        assert_eq!(pieces, shake128(b"abc", 300));
        // Absorbing in pieces equals absorbing at once, across the rate.
        let data: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let mut s = Sponge::shake256();
        s.absorb(&data[..100]).absorb(&data[100..300]).absorb(&data[300..]);
        assert_eq!(s.squeeze_vec(40), shake256(&data, 40));
    }
}
