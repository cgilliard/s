//! tabminer's XMSS keys and signatures for the fam node's signing
//! (`node/src/user/node/xsign.fam`, docs/GUI_WALLET.md phase 1):
//! `xsign_vectors.bin`, keys made from seeds by tabminer's own
//! [`crate::xmss::SecretKey::generate_with_height`], and signatures of
//! messages at several leaves by its `sign`, each checked by its verifier.
//!
//! The file, little-endian words: the number of keys; a key: its height,
//! its seed (32 bytes), its public key (49 bytes, then 3 zeros), the
//! number of signatures; a signature: the leaf, the message's length in
//! words, the message (canonical words), the signature's bytes
//! (`Signature::size(height)`).
//!
//! `write_fam_xmss_vectors` writes the file; `fam_xmss_vectors_are_current`
//! checks it.

#[cfg(test)]
mod tests {
    use crate::poseidon2::{Fp, P};
    use crate::xmss::{SEED_SIZE, SecretKey, Signature};

    const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/xsign_vectors.bin");

    /// splitmix64: the same values every run.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    /// (height, leaves signed at, message lengths in turn).
    const KEYS: [(usize, &[u64]); 5] = [
        (4, &[0, 1, 7, 8, 15]),
        (4, &[3, 12]),
        (4, &[9]),
        (1, &[0, 1]),
        (6, &[0, 33, 63]),
    ];
    const LENGTHS: [usize; 6] = [8, 8, 0, 1, 9, 20];

    fn generate() -> Vec<u8> {
        let mut r = Rng(0x5eed_8a55);
        let mut v = Vec::new();
        let w = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());
        w(&mut v, KEYS.len() as u32);
        let mut nmsg = 0;
        for (height, leaves) in KEYS {
            let seed: [u8; SEED_SIZE] = core::array::from_fn(|_| r.next() as u8);
            let key = SecretKey::generate_with_height(&seed, height);
            let pk = key.public_key();
            w(&mut v, height as u32);
            v.extend_from_slice(&seed);
            v.extend_from_slice(&pk.to_bytes());
            v.extend_from_slice(&[0; 3]);
            w(&mut v, leaves.len() as u32);
            for &leaf in leaves {
                let n = LENGTHS[nmsg % LENGTHS.len()];
                nmsg += 1;
                let msg: Vec<Fp> = (0..n).map(|_| Fp::new((r.next() % P as u64) as u32)).collect();
                let mut k = key.clone();
                k.set_next_index(leaf);
                let sig = k.sign(&msg).unwrap();
                assert_eq!(sig.index, leaf);
                assert!(pk.verify(&msg, &sig), "tabminer refused its own signature");
                let bytes = sig.to_bytes();
                assert_eq!(bytes.len(), Signature::size(height));
                w(&mut v, leaf as u32);
                w(&mut v, n as u32);
                for x in &msg {
                    w(&mut v, x.to_canonical());
                }
                v.extend_from_slice(&bytes);
            }
        }
        v
    }

    #[test]
    fn fam_xmss_vectors_are_current() {
        let file = std::fs::read(PATH).expect("node/src/user/node/xsign_vectors.bin");
        assert!(file == generate(), "the fam node's XMSS signing vectors are stale: run write_fam_xmss_vectors");
    }

    #[test]
    #[ignore = "writes the node's XMSS signing vectors: node/src/user/node/xsign_vectors.bin"]
    fn write_fam_xmss_vectors() {
        std::fs::write(PATH, generate()).unwrap();
    }
}
