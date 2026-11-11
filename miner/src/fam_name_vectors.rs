//! Names for the fam OS's wallet (`node/src/user/node/wname.fam`,
//! docs/GUI_WALLET.md phase 2): `wname_vectors.bin`, made by tabminer's own
//! names.rs, name_trie.rs and transaction.rs from fixed inputs, the
//! wallet's derivations (owner key, salt, memo of a nonce: wallet.rs's
//! `owner_key`, `salt`, `name_memo`) checked against a [`Wallet`] restored
//! from the same phrase each run.
//!
//! The file, little-endian words, each blob its length then its bytes
//! (padded to 4):
//! - the phrase's BIP39 seed (64 bytes);
//! - names: a count; each its blob, whether valid (4), and if so its hash
//!   (32: canonical words) and trie key (16: the 120-bit key, little-endian);
//! - a registration with nonce 1 (16: four canonical words): the owner
//!   key's public key (49, then 3 zeros), its hash (32), the salt (32), the
//!   value (32), the commit hash (32), the name memo (32), the record
//!   (blob), its leaf value (32), the commit operation (blob) and its
//!   digest (32), the commit's position (8), the reveal operation (blob)
//!   and its digest (32);
//! - an update to nonce 2's key: nonce 2 (16), the new record (blob), its
//!   update message (32), the leaf nonce 1's key signs at (4), the update
//!   operation (blob) and its digest (32);
//! - two transactions carrying operations: an input (its key's seed 32,
//!   amount 8, signing leaf 4, position 8) and change (its key's seed 32,
//!   amount 8, memo 20); then the first (the commit) and the second (the
//!   reveal and the update), each as a blob and its id (32);
//! - trie proofs: the outputs half's root (32); the records registered (a
//!   count; each a blob); then cases (a count; each: the name (blob),
//!   member or not (4), the key (16), the terminal: none 0 or a leaf 1 (4),
//!   its key (16) and value (32), the siblings (a count; 32 each), the
//!   state root (32)).
//!
//! `write_fam_name_vectors` writes the file; `fam_name_vectors_are_current`
//! checks it.

#[cfg(test)]
mod tests {
    use crate::name_trie::{NameTrie, Terminal, key_of};
    use crate::names::{Record, commit_hash, name_elements, name_hash, update_message};
    use crate::names::NameOp;
    use crate::poseidon2::{DIGEST, Fp, P, compress, digest_to_bytes};
    use crate::state_tree::open_env;
    use crate::transaction::{Memo, Output, UnsignedTransaction, hash_domain, memo_slot, memo_to_bytes, pubkey_hash};
    use crate::wallet::Wallet;
    use crate::xmss::{SEED_SIZE, SecretKey};
    use crate::bip39;

    const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/wname_vectors.bin");

    // wallet.rs's domains
    const DOM_MASTER: u32 = 0x30;
    const DOM_TAG: u32 = 0x31;
    const DOM_OWNER: u32 = 0x33;
    const DOM_SALT: u32 = 0x34;

    type Digest = [Fp; DIGEST];

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
        fn bytes<const N: usize>(&mut self) -> [u8; N] {
            core::array::from_fn(|_| self.next() as u8)
        }
    }

    fn phrase() -> String {
        let entropy: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(7));
        bip39::phrase(&entropy)
    }

    fn with(master: &Digest, domain: u32, nonce: &[Fp; 4]) -> Digest {
        let mut input = master.to_vec();
        input.extend_from_slice(nonce);
        hash_domain(domain, &input)
    }
    fn owner_key(master: &Digest, nonce: &[Fp; 4]) -> SecretKey {
        let seed: [u8; SEED_SIZE] = digest_to_bytes(&with(master, DOM_OWNER, nonce));
        SecretKey::generate(&seed)
    }
    /// The output memo of a nonce (wallet.rs's `memo`), and the name memo:
    /// it as a memo slot of amount zero.
    fn memo(master: &Digest, nonce: &[Fp; 4]) -> Memo {
        let mut m = [Fp::ZERO; 5];
        m[..4].copy_from_slice(nonce);
        m[4] = with(master, DOM_TAG, nonce)[0];
        m
    }
    fn name_memo(master: &Digest, nonce: &[Fp; 4]) -> Digest {
        memo_slot(&memo(master, nonce), 0)
    }
    fn record(master: &Digest, name: &[u8], nonce: &[Fp; 4], value: &Digest) -> Record {
        Record::new(name, pubkey_hash(&owner_key(master, nonce).public_key()), *value, name_memo(master, nonce)).unwrap()
    }

    fn blob(v: &mut Vec<u8>, b: &[u8]) {
        v.extend_from_slice(&(b.len() as u32).to_le_bytes());
        v.extend_from_slice(b);
        v.resize(v.len().div_ceil(4) * 4, 0);
    }
    fn fps(v: &mut Vec<u8>, xs: &[Fp]) {
        for x in xs {
            v.extend_from_slice(&x.to_le_bytes());
        }
    }

    fn generate() -> Vec<u8> {
        let phrase = phrase();
        let seed = bip39::seed(&phrase, "").unwrap();
        let master = hash_domain(DOM_MASTER, &crate::pow::pack_bytes(&seed));
        let mut v = Vec::new();
        v.extend_from_slice(&seed);
        let mut r = Rng(0x0a3e_5eed);

        // names: valid and not
        let long_ok = "a".repeat(32);
        let long_bad = "b".repeat(33);
        let names: Vec<&[u8]> = vec![
            b"example", b"ex_1", b"z", long_ok.as_bytes(), b"0_9", b"", b"Example", b"a-b", b"a.b", long_bad.as_bytes(),
            b"caf\xc3\xa9",
        ];
        v.extend_from_slice(&(names.len() as u32).to_le_bytes());
        for n in &names {
            blob(&mut v, n);
            match name_elements(n) {
                Some(e) => {
                    v.extend_from_slice(&1u32.to_le_bytes());
                    let h = name_hash(&e);
                    fps(&mut v, &h);
                    v.extend_from_slice(&key_of(&h).to_le_bytes());
                }
                None => v.extend_from_slice(&0u32.to_le_bytes()),
            }
        }

        // a registration
        let name = b"example";
        let n1: [Fp; 4] = core::array::from_fn(|_| r.fp());
        let k1 = owner_key(&master, &n1);
        let owner1 = pubkey_hash(&k1.public_key());
        let salt = with(&master, DOM_SALT, &n1);
        let value = r.digest();
        let commit = commit_hash(&name_hash(&name_elements(name).unwrap()), &salt, &owner1);
        let rec1 = record(&master, name, &n1, &value);
        let commit_op = NameOp::Commit { commit, memo: memo(&master, &n1) };
        let position: u64 = (3 << 32) | 77;
        let reveal_op = NameOp::Reveal { record: rec1.clone(), salt, commit: position };
        fps(&mut v, &n1);
        v.extend_from_slice(&k1.public_key().to_bytes());
        v.extend_from_slice(&[0; 3]);
        fps(&mut v, &owner1);
        fps(&mut v, &salt);
        fps(&mut v, &value);
        fps(&mut v, &commit);
        fps(&mut v, &name_memo(&master, &n1));
        blob(&mut v, &rec1.to_bytes());
        fps(&mut v, &rec1.leaf_value().unwrap());
        blob(&mut v, &commit_op.to_bytes());
        fps(&mut v, &commit_op.digest().unwrap());
        v.extend_from_slice(&position.to_le_bytes());
        blob(&mut v, &reveal_op.to_bytes());
        fps(&mut v, &reveal_op.digest().unwrap());

        // an update to a fresh key, signed by nonce 1's
        let n2: [Fp; 4] = core::array::from_fn(|_| r.fp());
        let value2 = r.digest();
        let rec2 = record(&master, name, &n2, &value2);
        let leaf: u32 = 5;
        let mut signer = owner_key(&master, &n1);
        signer.set_next_index(u64::from(leaf));
        let update_op = NameOp::update(rec2.clone(), &mut signer).unwrap();
        assert!(update_op.verify_owner(&owner1));
        fps(&mut v, &n2);
        blob(&mut v, &rec2.to_bytes());
        fps(&mut v, &update_message(&rec2).unwrap());
        v.extend_from_slice(&leaf.to_le_bytes());
        blob(&mut v, &update_op.to_bytes());
        fps(&mut v, &update_op.digest().unwrap());

        // transactions carrying them
        let in_seed: [u8; 32] = r.bytes();
        let in_amount: u64 = 40_000_000_000;
        let in_leaf: u32 = 2;
        let in_pos: u64 = (1 << 32) | 9;
        let ch_seed: [u8; 32] = r.bytes();
        let ch_amount: u64 = 39_999_900_000;
        let ch_memo: Memo = core::array::from_fn(|_| r.fp());
        v.extend_from_slice(&in_seed);
        v.extend_from_slice(&in_amount.to_le_bytes());
        v.extend_from_slice(&in_leaf.to_le_bytes());
        v.extend_from_slice(&in_pos.to_le_bytes());
        v.extend_from_slice(&ch_seed);
        v.extend_from_slice(&ch_amount.to_le_bytes());
        v.extend_from_slice(&memo_to_bytes(&ch_memo));
        let change = Output::with_memo(&pubkey_hash(&SecretKey::generate(&ch_seed).public_key()), ch_amount, ch_memo);
        for ops in [vec![commit_op.clone()], vec![reveal_op.clone(), update_op.clone()]] {
            let mut key = SecretKey::generate(&in_seed);
            let unsigned = UnsignedTransaction::with_ops(vec![(key.public_key(), in_amount)], vec![change], ops);
            key.set_next_index(u64::from(in_leaf));
            let mut tx = unsigned.sign(|_, _, msg| key.sign(msg)).unwrap();
            tx.set_positions(&[in_pos]);
            blob(&mut v, &tx.to_bytes());
            fps(&mut v, &tx.txid());
        }

        // trie proofs against a state root
        let dir = std::env::temp_dir().join(format!("tabminer-fam-names-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = open_env(&dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let trie = NameTrie::open(&env, &mut wtxn, "names").unwrap();
        let outputs_root = r.digest();
        let registered: Vec<Record> = ["example", "alice", "bob", "carol", "dave", "erin", "frank", "x"]
            .iter()
            .map(|n| Record::new(n.as_bytes(), r.digest(), r.digest(), r.digest()).unwrap())
            .collect();
        for rec in &registered {
            trie.insert(&mut wtxn, rec.key().unwrap(), &rec.leaf_value().unwrap()).unwrap();
        }
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        let state_root = compress(&outputs_root, &trie.root(&rtxn).unwrap());
        fps(&mut v, &outputs_root);
        v.extend_from_slice(&(registered.len() as u32).to_le_bytes());
        for rec in &registered {
            blob(&mut v, &rec.to_bytes());
        }
        // every registered name (members), and absent ones until both
        // kinds of terminal are among them
        let mut cases: Vec<(Vec<u8>, bool)> = registered.iter().map(|r| (r.name.clone(), true)).collect();
        let (mut leafs, mut empties) = (0, 0);
        for i in 0..1000 {
            let n = format!("n{i}");
            let key = crate::names::name_key(n.as_bytes()).unwrap();
            let kind_leaf = matches!(trie.prove(&rtxn, key).unwrap().terminal, Terminal::Leaf { .. });
            if (kind_leaf && leafs < 2) || (!kind_leaf && empties < 2) {
                if kind_leaf {
                    leafs += 1;
                } else {
                    empties += 1;
                }
                cases.push((n.into_bytes(), false));
            }
            if leafs == 2 && empties == 2 {
                break;
            }
        }
        assert!(leafs == 2 && empties == 2);
        v.extend_from_slice(&(cases.len() as u32).to_le_bytes());
        for (n, member) in &cases {
            let key = crate::names::name_key(n).unwrap();
            let proof = trie.prove(&rtxn, key).unwrap();
            let trie_root = trie.root(&rtxn).unwrap();
            if *member {
                let rec = registered.iter().find(|r| &r.name == n).unwrap();
                assert!(proof.verify_member(&trie_root, key, &rec.leaf_value().unwrap()));
            } else {
                assert!(proof.verify_absent(&trie_root, key));
            }
            blob(&mut v, n);
            v.extend_from_slice(&u32::from(*member).to_le_bytes());
            v.extend_from_slice(&key.to_le_bytes());
            match proof.terminal {
                Terminal::Empty => {
                    v.extend_from_slice(&0u32.to_le_bytes());
                    v.extend_from_slice(&[0; 16]);
                    v.extend_from_slice(&[0; 32]);
                }
                Terminal::Leaf { key, value } => {
                    v.extend_from_slice(&1u32.to_le_bytes());
                    v.extend_from_slice(&key.to_le_bytes());
                    fps(&mut v, &value);
                }
            }
            v.extend_from_slice(&(proof.siblings.len() as u32).to_le_bytes());
            for s in &proof.siblings {
                fps(&mut v, s);
            }
            fps(&mut v, &state_root);
        }
        drop(rtxn);
        drop(env);
        let _ = std::fs::remove_dir_all(&dir);
        v
    }

    /// The derivations above are the wallet's: its owner key of a nonce,
    /// and the commit and memo its name_commit makes.
    fn check_against_wallet() {
        let phrase = phrase();
        let master = hash_domain(DOM_MASTER, &crate::pow::pack_bytes(&bip39::seed(&phrase, "").unwrap()));
        let dir = std::env::temp_dir().join(format!("tabminer-fam-names-w-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        let wallet = Wallet::restore(&dir, &phrase, "", "").unwrap();
        let value: Digest = core::array::from_fn(|i| Fp::new(i as u32 + 3));
        let op = wallet.name_commit(b"example", value).unwrap();
        let pending = wallet.pending_commits().unwrap();
        let entry = pending.iter().find(|c| c.name.as_deref() == Some(&b"example"[..])).unwrap();
        let nonce = entry.nonce;
        assert_eq!(wallet.owner_key(&nonce).public_key(), owner_key(&master, &nonce).public_key());
        let owner = pubkey_hash(&owner_key(&master, &nonce).public_key());
        let commit = commit_hash(&name_hash(&name_elements(b"example").unwrap()), &with(&master, DOM_SALT, &nonce), &owner);
        assert_eq!(op, NameOp::Commit { commit, memo: memo(&master, &nonce) });
        drop(wallet);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "writes the fam wallet's name vectors: node/src/user/node/wname_vectors.bin"]
    fn write_fam_name_vectors() {
        check_against_wallet();
        std::fs::write(PATH, generate()).unwrap();
    }

    #[test]
    fn fam_name_vectors_are_current() {
        check_against_wallet();
        let on_disk = std::fs::read(PATH).expect("node/src/user/node/wname_vectors.bin: run write_fam_name_vectors");
        assert!(on_disk == generate(), "wname_vectors.bin is stale: run write_fam_name_vectors");
    }
}
