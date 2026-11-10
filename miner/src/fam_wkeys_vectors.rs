//! A wallet's keys and memos for the fam OS's wallet
//! (`node/src/user/node/wkeys.fam`, docs/GUI_WALLET.md phase 1):
//! `wkeys_vectors.bin`, derived here from a BIP39 phrase as
//! `wallet.rs` does, and checked against a [`crate::wallet::Wallet`]
//! restored from the same phrase: its identity keys and addresses, the key
//! of each nonce, and outputs its own `receive` made.
//!
//! The file, little-endian words:
//! - the phrase (128 bytes, NUL-padded), its BIP39 seed (64 bytes, no
//!   passphrase), the master (32 bytes: canonical words);
//! - the number of identities; each: its address counter (8 bytes: a
//!   restored wallet's starts at a random 60-bit number), its Dilithium
//!   seed (32 bytes), its id (32), its address (64 bytes, NUL-padded);
//! - the number of outputs; each: the nonce (4 canonical words), the
//!   amount (8 bytes), the key's seed (32), the memo (20), the key's
//!   public key (49, then 3 zeros), the commitment (32);
//! - the number of strangers' memos; each 20 bytes, none of them this
//!   wallet's.
//!
//! `write_fam_wkeys_vectors` writes the file; `fam_wkeys_vectors_are_current`
//! checks it.

#[cfg(test)]
mod tests {
    use crate::poseidon2::{DIGEST, Fp, P, digest_to_bytes};
    use crate::transaction::{Memo, hash_domain, key_commitment, memo_to_bytes, pubkey_hash};
    use crate::wallet::Wallet;
    use crate::{address, bip39, mldsa, xmss};

    const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/wkeys_vectors.bin");

    // wallet.rs's domains
    const DOM_MASTER: u32 = 0x30;
    const DOM_TAG: u32 = 0x31;
    const DOM_KEY: u32 = 0x32;
    const DOM_IDENTITY: u32 = 0x36;

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
        fn fp(&mut self) -> Fp {
            Fp::new((self.next() % u64::from(P)) as u32)
        }
    }

    fn with(master: &[Fp; DIGEST], domain: u32, nonce: &[Fp; 4]) -> [Fp; DIGEST] {
        let mut input = master.to_vec();
        input.extend_from_slice(nonce);
        hash_domain(domain, &input)
    }

    fn phrase() -> String {
        let entropy: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        bip39::phrase(&entropy)
    }

    /// What varies run to run (a restored wallet's address counter, the
    /// nonces its receive draws): the identities' counters, and the
    /// outputs' nonces and amounts.
    struct Inputs {
        counters: Vec<u64>,
        outputs: Vec<([Fp; 4], u64)>,
    }

    /// The file from its inputs: everything else derived as wallet.rs does.
    fn build(inp: &Inputs) -> Vec<u8> {
        let phrase = phrase();
        let seed = bip39::seed(&phrase, "").unwrap();
        let master = hash_domain(DOM_MASTER, &crate::pow::pack_bytes(&seed));
        let mut v = Vec::new();
        let w = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());
        let mut text = phrase.as_bytes().to_vec();
        assert!(text.len() < 128);
        text.resize(128, 0);
        v.extend_from_slice(&text);
        v.extend_from_slice(&seed);
        v.extend_from_slice(&digest_to_bytes(&master));
        w(&mut v, inp.counters.len() as u32);
        for &i in &inp.counters {
            let (dseed, _, id, addr) = identity(&master, i);
            v.extend_from_slice(&i.to_le_bytes());
            v.extend_from_slice(&dseed);
            v.extend_from_slice(&digest_to_bytes(&id));
            let mut a = addr.into_bytes();
            a.resize(64, 0);
            v.extend_from_slice(&a);
        }
        w(&mut v, inp.outputs.len() as u32);
        let mut memos: Vec<Memo> = Vec::new();
        for (nonce, amount) in &inp.outputs {
            let (kseed, pk, memo, commitment) = output(&master, nonce, *amount);
            for x in nonce {
                v.extend_from_slice(&x.to_le_bytes());
            }
            v.extend_from_slice(&amount.to_le_bytes());
            v.extend_from_slice(&kseed);
            v.extend_from_slice(&memo_to_bytes(&memo));
            v.extend_from_slice(&pk.to_bytes());
            v.extend_from_slice(&[0; 3]);
            v.extend_from_slice(&digest_to_bytes(&commitment));
            memos.push(memo);
        }
        // strangers: a memo's tag one off, and a random memo
        let mut r = Rng(0x57_4a_9e);
        let mut off = memos[1];
        off[4] = Fp::from_u32(off[4].to_canonical() + 1);
        let random: Memo = [r.fp(), r.fp(), r.fp(), r.fp(), r.fp()];
        w(&mut v, 2);
        for m in [off, random] {
            v.extend_from_slice(&memo_to_bytes(&m));
        }
        v
    }

    /// Identity i: the Dilithium seed, its key, the id, the address.
    fn identity(master: &[Fp; DIGEST], i: u64) -> ([u8; mldsa::SEED_LEN], mldsa::SecretKey, [Fp; DIGEST], String) {
        let mut input = master.to_vec();
        input.extend_from_slice(&[Fp::new((i & ((1 << 30) - 1)) as u32), Fp::new((i >> 30 & ((1 << 30) - 1)) as u32)]);
        let dseed: [u8; mldsa::SEED_LEN] = digest_to_bytes(&hash_domain(DOM_IDENTITY, &input));
        let key = mldsa::keygen(&dseed);
        let id = address::id_of(key.public_key());
        let addr = address::encode(&id);
        (dseed, key, id, addr)
    }

    /// An output's key seed, public key, memo and commitment.
    fn output(
        master: &[Fp; DIGEST],
        nonce: &[Fp; 4],
        amount: u64,
    ) -> ([u8; xmss::SEED_SIZE], xmss::PublicKey, Memo, [Fp; DIGEST]) {
        let kseed: [u8; xmss::SEED_SIZE] = digest_to_bytes(&with(master, DOM_KEY, nonce));
        let pk = xmss::SecretKey::generate(&kseed).public_key();
        let mut memo: Memo = [Fp::ZERO; 5];
        memo[..4].copy_from_slice(nonce);
        memo[4] = with(master, DOM_TAG, nonce)[0];
        let commitment = key_commitment(&pubkey_hash(&pk), amount);
        (kseed, pk, memo, commitment)
    }

    /// A wallet restored from the phrase, every derivation checked against
    /// it: its identity and its next, the key of each nonce, two outputs
    /// its own receive made (their nonces among the inputs returned).
    fn from_wallet() -> Inputs {
        let phrase = phrase();
        let master = hash_domain(DOM_MASTER, &crate::pow::pack_bytes(&bip39::seed(&phrase, "").unwrap()));
        let dir = std::env::temp_dir().join(format!("tabminer-fam-wkeys-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        let wallet = Wallet::restore(&dir, &phrase, "", "").unwrap();
        let mut counters = Vec::new();
        for k in 0..2 {
            if k == 1 {
                wallet.next_address().unwrap();
            }
            let i = wallet.address_index();
            let (_, key, _, addr) = identity(&master, i);
            assert_eq!(key.public_key(), wallet.identity_key().public_key());
            assert_eq!(addr, wallet.address());
            counters.push(i);
        }
        let mut r = Rng(0x0a11_e7_5eed);
        let mut outputs = vec![
            ([Fp::ZERO; 4], 1),
            ([r.fp(), r.fp(), r.fp(), r.fp()], 50_000),
            ([Fp::new(P - 1), r.fp(), Fp::new(1), r.fp()], u64::MAX >> 1),
        ];
        for amount in [12_500_000_000u64, 7] {
            let out = wallet.receive(amount).unwrap();
            let nonce: [Fp; 4] = out.memo[..4].try_into().unwrap();
            let (_, _, memo, commitment) = output(&master, &nonce, amount);
            assert_eq!(out.memo, memo);
            assert_eq!(out.commitment, commitment);
            outputs.push((nonce, amount));
        }
        for (nonce, amount) in &outputs {
            assert_eq!(output(&master, nonce, *amount).1, wallet.key(nonce).public_key());
        }
        drop(wallet);
        let _ = std::fs::remove_dir_all(&dir);
        Inputs { counters, outputs }
    }

    /// The inputs a file holds.
    fn inputs_of(f: &[u8]) -> Inputs {
        let u32_at = |o: usize| u32::from_le_bytes(f[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(f[o..o + 8].try_into().unwrap());
        let mut o = 128 + 64 + 32;
        let n = u32_at(o) as usize;
        o += 4;
        let mut counters = Vec::new();
        for _ in 0..n {
            counters.push(u64_at(o));
            o += 8 + 32 + 32 + 64;
        }
        let n = u32_at(o) as usize;
        o += 4;
        let mut outputs = Vec::new();
        for _ in 0..n {
            let nonce: [Fp; 4] = core::array::from_fn(|k| Fp::new(u32_at(o + 4 * k)));
            outputs.push((nonce, u64_at(o + 16)));
            o += 16 + 8 + 32 + 20 + 52 + 32;
        }
        Inputs { counters, outputs }
    }

    #[test]
    #[ignore = "writes the fam wallet's key vectors: node/src/user/node/wkeys_vectors.bin"]
    fn write_fam_wkeys_vectors() {
        std::fs::write(PATH, build(&from_wallet())).unwrap();
    }

    /// The file is what its inputs derive (byte for byte), and the
    /// derivation is still the wallet's (a fresh restore checked).
    #[test]
    fn fam_wkeys_vectors_are_current() {
        let on_disk = std::fs::read(PATH).expect("node/src/user/node/wkeys_vectors.bin: run write_fam_wkeys_vectors");
        assert!(on_disk == build(&inputs_of(&on_disk)), "wkeys_vectors.bin is stale: run write_fam_wkeys_vectors");
        from_wallet();
    }
}
