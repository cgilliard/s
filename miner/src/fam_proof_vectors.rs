//! Payment proofs and proofs of burn for the fam OS's wallet
//! (`node/src/user/node/wproof.fam`, docs/GUI_WALLET.md phase 2, step 2a):
//! `wproof_vectors.bin`, proofs made with tabminer's own types
//! ([`crate::proofs::Proof`]), each with the state root it is checked
//! against and what [`Proof::check`] says of it, and bytes that do not
//! parse.
//!
//! The file, little-endian words, each blob its length then its bytes
//! (padded to 4): the number of cases; each: what tabminer says (0 the
//! proof holds, 1 not in the block, 2 the receipt does not hold, 3 not
//! that burn, -1 the bytes do not parse), the state root (32), the bytes,
//! the text (empty for bytes that do not parse).
//!
//! `write_fam_proof_vectors` writes the file; `fam_proof_vectors_are_current`
//! checks it.

#[cfg(test)]
mod tests {
    use crate::mldsa;
    use crate::poseidon2::{DIGEST, Fp, P, digest_to_bytes};
    use crate::proofs::{BURN_KEY_HASH, Burn, Claim, Proof, ProofError, Receipt, sender_tag};
    use crate::state_tree::{DEPTH, Digest};
    use crate::transaction::{Memo, Output, output_leaf};

    const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/wproof_vectors.bin");

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
        fn digest(&mut self) -> Digest {
            core::array::from_fn(|_| self.fp())
        }
        fn memo(&mut self) -> Memo {
            core::array::from_fn(|_| self.fp())
        }
        fn bytes<const N: usize>(&mut self) -> [u8; N] {
            core::array::from_fn(|_| self.next() as u8)
        }
    }

    fn blob(v: &mut Vec<u8>, b: &[u8]) {
        v.extend_from_slice(&(b.len() as u32).to_le_bytes());
        v.extend_from_slice(b);
        v.resize(v.len().div_ceil(4) * 4, 0);
    }

    /// The root a proof's path leads to from its own leaf: the root it
    /// holds against.
    fn root_of(p: &Proof) -> Digest {
        p.path.root(p.position, &output_leaf(&p.commitment(), &p.memo, p.amount, p.height))
    }

    fn code(p: &Proof, root: &Digest) -> i32 {
        match p.check(root) {
            Ok(()) => 0,
            Err(ProofError::NotInBlock) => 1,
            Err(ProofError::Receipt) => 2,
            Err(ProofError::Burn) => 3,
        }
    }

    fn generate() -> Vec<u8> {
        let mut r = Rng(0x9e0f_5eed);
        let key = mldsa::keygen(&r.bytes::<32>());
        let mut path = || crate::state_tree::Proof { siblings: core::array::from_fn(|_| r.digest()) };
        let (p1, p2, p3) = (path(), path(), path());
        let mut r = Rng(0x7e57);

        // a payment from a named sender
        let (key_hash, amount, memo) = (r.digest(), 2_500_000_000u64, r.memo());
        let slate_id: [u8; 32] = r.bytes();
        let sender = r.digest();
        let output = Output::with_memo(&key_hash, amount, memo);
        let named = Proof {
            height: 1234,
            position: (1u64 << 39) | 0x1234_5678,
            key_hash,
            amount,
            memo,
            path: p1,
            claim: Claim::Payment { sender, secret: None, slate_id, receipt: Receipt::sign(&key, &output, &slate_id, &sender) },
        };
        // a payment from an unnamed sender (its secret shown)
        let secret: [u8; 32] = r.bytes();
        let tag = sender_tag(&secret);
        let (key_hash2, amount2, memo2) = (r.digest(), 7u64, r.memo());
        let slate2: [u8; 32] = r.bytes();
        let output2 = Output::with_memo(&key_hash2, amount2, memo2);
        let unnamed = Proof {
            height: 5,
            position: 3,
            key_hash: key_hash2,
            amount: amount2,
            memo: memo2,
            path: p2,
            claim: Claim::Payment {
                sender: tag,
                secret: Some(secret),
                slate_id: slate2,
                receipt: Receipt::sign(&key, &output2, &slate2, &tag),
            },
        };
        // a burn
        let burn = Burn { beneficiary: r.digest(), nonce: r.bytes(), purpose: b"credit for the archive".to_vec() };
        let burned = Proof {
            height: 77,
            position: 0x0ff_ffff_ffff,
            key_hash: BURN_KEY_HASH,
            amount: 1_000_000_000,
            memo: burn.memo(),
            path: p3,
            claim: Claim::Burn(burn.clone()),
        };

        let mut cases: Vec<(Proof, Digest)> = Vec::new();
        for p in [&named, &unnamed, &burned] {
            cases.push((p.clone(), root_of(p)));
        }
        // another root: not in that block
        cases.push((named.clone(), r.digest()));
        // the amount changed (its leaf another)
        let mut x = named.clone();
        x.amount += 1;
        cases.push((x, root_of(&named)));
        // the receipt's signature changed; the slate id changed
        let mut x = named.clone();
        if let Claim::Payment { receipt, .. } = &mut x.claim {
            receipt.signature[100] ^= 1;
        }
        cases.push((x, root_of(&named)));
        let mut x = unnamed.clone();
        if let Claim::Payment { slate_id, .. } = &mut x.claim {
            slate_id[0] ^= 1;
        }
        cases.push((x, root_of(&unnamed)));
        // another sender's tag (the secret changed): the receipt
        let mut x = unnamed.clone();
        if let Claim::Payment { secret, sender, .. } = &mut x.claim {
            let s = [9u8; 32];
            *secret = Some(s);
            *sender = sender_tag(&s);
        }
        cases.push((x, root_of(&unnamed)));
        // a burn's purpose changed: not that burn
        let mut x = burned.clone();
        if let Claim::Burn(b) = &mut x.claim {
            b.purpose = b"credit for another".to_vec();
        }
        cases.push((x, root_of(&burned)));
        // a burn to a key hash not zero, its root its own: not a burn
        let mut x = burned.clone();
        x.key_hash = r.digest();
        let root = root_of(&x);
        cases.push((x, root));

        let mut v = Vec::new();
        let malformed: Vec<Vec<u8>> = {
            let good = named.to_bytes();
            let mut m = vec![good[..good.len() - 1].to_vec(), [good.clone(), vec![0]].concat()];
            let mut x = good.clone();
            x[0] = 3; // the format
            m.push(x);
            let mut x = good.clone();
            x[53..57].copy_from_slice(&P.to_le_bytes()); // the memo's first word, not canonical
            m.push(x);
            let mut x = burned.to_bytes();
            x[13] = 1; // fine as bytes: the check refuses it
            assert!(Proof::from_bytes(&x).is_some());
            let mut x = good.clone();
            x[0x549] = 2; // the sender's kind
            m.push(x);
            for b in &m {
                assert!(Proof::from_bytes(b).is_none());
            }
            m
        };
        v.extend_from_slice(&((cases.len() + malformed.len()) as u32).to_le_bytes());
        for (p, root) in &cases {
            let bytes = p.to_bytes();
            assert_eq!(Proof::from_bytes(&bytes).as_ref(), Some(p));
            assert_eq!(Proof::from_text(&p.to_text()).as_ref(), Some(p));
            v.extend_from_slice(&code(p, root).to_le_bytes());
            v.extend_from_slice(&digest_to_bytes(root));
            blob(&mut v, &bytes);
            blob(&mut v, p.to_text().as_bytes());
        }
        for m in &malformed {
            v.extend_from_slice(&(-1i32).to_le_bytes());
            v.extend_from_slice(&[0; 32]);
            blob(&mut v, m);
            blob(&mut v, b"");
        }
        let _ = DEPTH;
        let _ = DIGEST;
        v
    }

    #[test]
    #[ignore = "writes the fam wallet's proof vectors: node/src/user/node/wproof_vectors.bin"]
    fn write_fam_proof_vectors() {
        std::fs::write(PATH, generate()).unwrap();
    }

    #[test]
    fn fam_proof_vectors_are_current() {
        let on_disk = std::fs::read(PATH).expect("node/src/user/node/wproof_vectors.bin: run write_fam_proof_vectors");
        assert!(on_disk == generate(), "wproof_vectors.bin is stale: run write_fam_proof_vectors");
    }
}
