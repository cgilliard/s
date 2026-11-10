//! Slates and transactions for the fam OS's wallet
//! (`node/src/user/node/wslate.fam`, docs/GUI_WALLET.md phase 1):
//! `wslate_vectors.bin`, a payment made by tabminer's own types — a
//! stage-1 [`Slate`] (two inputs, change), the recipient's answer
//! (its output and [`Receipt`]), the body hash, the signed
//! [`crate::transaction::Transaction`] — and slates `finalize` refuses or
//! that do not parse.
//!
//! The file, little-endian words, each blob as its length then its bytes
//! (padded to 4):
//! - the inputs to rebuild it: the slate id (32), the sender (32: an
//!   address's id), the amount, the fee (8 each); per input (2): its key's
//!   seed (32), its amount (8), the leaf it signs at (4), its position
//!   (8); the change: its key's seed, its amount (8), its memo (20); the
//!   recipient: its output key's seed, its memo, its Dilithium seed (32);
//!   an unnamed sender's secret (32);
//! - what tabminer made: the stage-1 slate, the stage-2 slate, the body
//!   hash (32), the signed transaction, the secret's sender tag (32);
//! - the number of other stage-2 slates; each: the code fam's finalize is
//!   to give (as wslate.fam's wsfin: 2 inputs changed, 4 amount or fee
//!   changed, 5 not balanced, 6 change changed, 9 not one recipient
//!   output, 10 the receipt), then the slate;
//! - the number of malformed slates; each a blob (Slate::from_bytes
//!   refuses each).

#[cfg(test)]
mod tests {
    use crate::mldsa;
    use crate::poseidon2::{Fp, P, digest_to_bytes};
    use crate::proofs::{Receipt, sender_tag};
    use crate::transaction::{Memo, Output, UnsignedTransaction, memo_to_bytes, pubkey_hash};
    use crate::wallet::Slate;
    use crate::xmss::{SEED_SIZE, SecretKey};

    const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/wslate_vectors.bin");

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
        fn bytes<const N: usize>(&mut self) -> [u8; N] {
            core::array::from_fn(|_| self.next() as u8)
        }
        fn memo(&mut self) -> Memo {
            core::array::from_fn(|_| Fp::new((self.next() % u64::from(P)) as u32))
        }
    }

    fn blob(v: &mut Vec<u8>, b: &[u8]) {
        v.extend_from_slice(&(b.len() as u32).to_le_bytes());
        v.extend_from_slice(b);
        v.resize(v.len().div_ceil(4) * 4, 0);
    }

    fn generate() -> Vec<u8> {
        let mut r = Rng(0x51a7_e5);
        let id: [u8; 32] = r.bytes();
        let sender_seed: [u8; 32] = r.bytes();
        let sender = crate::address::id_of(mldsa::keygen(&sender_seed).public_key());
        let (amount, fee) = (5_000_000_000u64, 60_000u64);
        // inputs: (seed, amount, leaf, position)
        let ins: Vec<([u8; SEED_SIZE], u64, u64, u64)> =
            vec![(r.bytes(), 3_000_000_000, 3, 17), (r.bytes(), 2_500_000_000, 12, 1 << 33 | 5)];
        let total: u64 = ins.iter().map(|i| i.1).sum();
        let change_seed: [u8; SEED_SIZE] = r.bytes();
        let change_amount = total - amount - fee;
        let change_memo = r.memo();
        let recv_seed: [u8; SEED_SIZE] = r.bytes();
        let recv_memo = r.memo();
        let recv_id_seed: [u8; 32] = r.bytes();
        let secret: [u8; 32] = r.bytes();

        let mut keys: Vec<SecretKey> = ins.iter().map(|i| SecretKey::generate(&i.0)).collect();
        let change = Output::with_memo(
            &pubkey_hash(&SecretKey::generate(&change_seed).public_key()),
            change_amount,
            change_memo,
        );
        let s1 = Slate {
            id,
            stage: 1,
            amount,
            fee,
            inputs: keys.iter().zip(&ins).map(|(k, i)| (k.public_key(), i.1)).collect(),
            outputs: vec![change],
            change: 1,
            sender,
            receipt: None,
        };
        let recv = Output::with_memo(&pubkey_hash(&SecretKey::generate(&recv_seed).public_key()), amount, recv_memo);
        let recv_key = mldsa::keygen(&recv_id_seed);
        let mut s2 = s1.clone();
        s2.receipt = Some(Receipt::sign(&recv_key, &recv, &id, &sender));
        s2.outputs.push(recv);
        s2.stage = 2;
        assert_eq!(Slate::from_bytes(&s2.to_bytes()).as_ref(), Some(&s2));
        let unsigned: UnsignedTransaction = s2.unsigned();
        let body = unsigned.body_hash();
        for (k, i) in keys.iter_mut().zip(&ins) {
            k.set_next_index(i.2);
        }
        let mut tx = unsigned.sign(|i, _, msg| keys[i].sign(msg)).unwrap();
        tx.set_positions(&ins.iter().map(|i| i.3).collect::<Vec<_>>());
        assert_eq!(tx.txid(), body);

        let mut v = Vec::new();
        v.extend_from_slice(&id);
        v.extend_from_slice(&digest_to_bytes(&sender));
        v.extend_from_slice(&amount.to_le_bytes());
        v.extend_from_slice(&fee.to_le_bytes());
        for i in &ins {
            v.extend_from_slice(&i.0);
            v.extend_from_slice(&i.1.to_le_bytes());
            v.extend_from_slice(&(i.2 as u32).to_le_bytes());
            v.extend_from_slice(&i.3.to_le_bytes());
        }
        v.extend_from_slice(&change_seed);
        v.extend_from_slice(&change_amount.to_le_bytes());
        v.extend_from_slice(&memo_to_bytes(&change_memo));
        v.extend_from_slice(&recv_seed);
        v.extend_from_slice(&memo_to_bytes(&recv_memo));
        v.extend_from_slice(&recv_id_seed);
        v.extend_from_slice(&secret);
        blob(&mut v, &s1.to_bytes());
        blob(&mut v, &s2.to_bytes());
        v.extend_from_slice(&digest_to_bytes(&body));
        blob(&mut v, &tx.to_bytes());
        v.extend_from_slice(&digest_to_bytes(&sender_tag(&secret)));

        // stage-2 slates finalize refuses, with the check that refuses each
        let mut bad: Vec<(u32, Slate)> = Vec::new();
        let mut s = s2.clone();
        s.inputs[1].1 += 1;
        bad.push((2, s));
        let mut s = s2.clone();
        s.amount += 1;
        bad.push((4, s));
        let mut s = s2.clone();
        s.fee -= 1;
        bad.push((4, s));
        let mut s = s2.clone();
        s.outputs[1].amount -= 1;
        bad.push((5, s));
        let mut s = s2.clone();
        s.outputs[0].memo[2] = Fp::new(7);
        bad.push((6, s));
        // a second recipient output, the change smaller to balance
        let mut s = s2.clone();
        let extra = Output::with_memo(&pubkey_hash(&SecretKey::generate(&recv_seed).public_key()), 30_000, recv_memo);
        s.outputs[0] = Output::with_memo(&s.outputs[0].key_hash, s.outputs[0].amount - 30_000, change_memo);
        s.outputs.push(extra);
        s.amount += 30_000;
        bad.push((4, s));
        // a receipt over another sender
        let mut s = s2.clone();
        s.receipt = Some(Receipt::sign(&recv_key, &s.outputs[1], &id, &sender_tag(&secret)));
        bad.push((10, s));
        // a receipt over another output
        let mut s = s2.clone();
        s.receipt = Some(Receipt::sign(&recv_key, &change, &id, &sender));
        bad.push((10, s));
        v.extend_from_slice(&(bad.len() as u32).to_le_bytes());
        for (code, s) in &bad {
            v.extend_from_slice(&code.to_le_bytes());
            blob(&mut v, &s.to_bytes());
        }

        // slates that do not parse
        let good = s2.to_bytes();
        let mut malformed: Vec<Vec<u8>> = Vec::new();
        malformed.push(good[..good.len() - 1].to_vec());
        let mut m = good.clone();
        m.push(0);
        malformed.push(m);
        let mut m = good.clone();
        m[72] = 3; // the stage
        malformed.push(m);
        let mut m = good.clone();
        m[89..93].copy_from_slice(&3u32.to_le_bytes()); // change past the outputs
        malformed.push(m);
        let mut m = good.clone();
        m[0] ^= 1; // the magic
        malformed.push(m);
        let mut m = s1.to_bytes();
        m[72] = 2; // stage 2 without a receipt
        malformed.push(m);
        // a memo element not canonical: the first output's memo, word 0
        let out0 = 8 + 32 + 32 + 1 + 8 + 8 + 4 + 4 + 2 * (49 + 8) + 4;
        let mut m = good.clone();
        m[out0 + 40..out0 + 44].copy_from_slice(&P.to_le_bytes());
        malformed.push(m);
        for m in &malformed {
            assert!(Slate::from_bytes(m).is_none());
        }
        v.extend_from_slice(&(malformed.len() as u32).to_le_bytes());
        for m in &malformed {
            blob(&mut v, m);
        }
        v
    }

    #[test]
    #[ignore = "writes the fam wallet's slate vectors: node/src/user/node/wslate_vectors.bin"]
    fn write_fam_slate_vectors() {
        std::fs::write(PATH, generate()).unwrap();
    }

    #[test]
    fn fam_slate_vectors_are_current() {
        let on_disk = std::fs::read(PATH).expect("node/src/user/node/wslate_vectors.bin: run write_fam_slate_vectors");
        assert!(on_disk == generate(), "wslate_vectors.bin is stale: run write_fam_slate_vectors");
    }
}
