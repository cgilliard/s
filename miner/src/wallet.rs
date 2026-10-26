//! A development wallet: one-time keys derived from a master seed, and the
//! outputs paid to them.
//!
//! Every output the wallet receives goes to a fresh key, and every key
//! signs once, so the XMSS leaf index never needs tracking. Key `i` is
//! generated from `H(master || i)`. The wallet file lists the outputs it
//! expects to own: an output is recorded before the block paying it is
//! applied, and [`Wallet::spendable`] keeps only those the UTXO set holds,
//! so a crash between the two loses nothing and invents nothing.
//!
//! File: `b"tabwlt01"`, master seed (32 bytes), `u64` next key index, `u32`
//! count, then per output its key index, amount and commitment.

use std::io;
use std::path::{Path, PathBuf};

use heed::RoTxn;

use crate::codec::{Reader, Writer};
use crate::parallel::par_map_min;
use crate::poseidon2::{DIGEST, Fp, digest_to_bytes, hash};
use crate::transaction::{Commitment, Key, Output, Transaction, UnsignedTransaction, commitment};
use crate::utxo::{self, UtxoSet};
use crate::xmss::{PublicKey, SEED_SIZE};

const MAGIC: &[u8; 8] = b"tabwlt01";

/// An output paid to one of the wallet's keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owned {
    pub key_index: u64,
    pub amount: u64,
    pub commitment: Commitment,
}

pub struct Wallet {
    path: PathBuf,
    master: [u8; 32],
    next_key: u64,
    owned: Vec<Owned>,
}

impl Wallet {
    /// Opens the wallet at `path`, creating it with a seed from the
    /// operating system if it does not exist.
    pub fn open(path: &Path) -> io::Result<Wallet> {
        match std::fs::read(path) {
            Ok(bytes) => Self::decode(path, &bytes).ok_or_else(|| io::Error::other("malformed wallet file")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut master = [0u8; 32];
                std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut master)?;
                let w = Wallet { path: path.to_path_buf(), master, next_key: 0, owned: vec![] };
                w.save()?;
                Ok(w)
            }
            Err(e) => Err(e),
        }
    }

    fn decode(path: &Path, bytes: &[u8]) -> Option<Wallet> {
        let mut r = Reader(bytes);
        if r.take(8)? != MAGIC {
            return None;
        }
        let master: [u8; 32] = r.take(32)?.try_into().ok()?;
        let next_key = r.u64()?;
        let n = r.u32()? as usize;
        let mut owned = Vec::with_capacity(n.min(1 << 16));
        for _ in 0..n {
            let key_index = r.u64()?;
            let amount = r.u64()?;
            let commitment = r.digest()?;
            owned.push(Owned { key_index, amount, commitment });
        }
        r.is_empty().then_some(Wallet { path: path.to_path_buf(), master, next_key, owned })
    }

    /// Writes the wallet, replacing the file atomically.
    pub fn save(&self) -> io::Result<()> {
        let mut w = Writer::default();
        w.0.extend_from_slice(MAGIC);
        w.0.extend_from_slice(&self.master);
        w.u64(self.next_key);
        w.u32(self.owned.len() as u32);
        for o in &self.owned {
            w.u64(o.key_index);
            w.u64(o.amount);
            w.digest(&o.commitment);
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, w.finish())?;
        std::fs::rename(&tmp, &self.path)
    }

    /// Key number `i`.
    pub fn key(&self, i: u64) -> Key {
        let mut input: Vec<Fp> =
            self.master.chunks(4).map(|c| Fp::from_u64(u32::from_le_bytes(c.try_into().unwrap()) as u64)).collect();
        input.push(Fp::from_u64(i & 0x3fff_ffff));
        input.push(Fp::from_u64(i >> 30));
        let seed: [u8; SEED_SIZE] = digest_to_bytes(&hash(&input));
        Key::generate(&seed)
    }

    /// A fresh key's public half and an output paying `amount` to it,
    /// recorded as owned.
    pub fn receive(&mut self, amount: u64) -> Output {
        let key_index = self.next_key;
        self.next_key += 1;
        let pk = self.key(key_index).public_key();
        let out = Output::new(&pk, amount);
        self.owned.push(Owned { key_index, amount, commitment: out.commitment });
        out
    }

    /// Owned outputs present in `utxo`, largest first. Records of outputs
    /// that were spent or never confirmed are dropped.
    pub fn spendable(&mut self, utxo: &UtxoSet, rtxn: &RoTxn) -> utxo::Result<Vec<Owned>> {
        let mut keep = Vec::with_capacity(self.owned.len());
        for o in &self.owned {
            if utxo.contains(rtxn, &o.commitment)? {
                keep.push(*o);
            }
        }
        self.owned = keep.clone();
        keep.sort_by(|a, b| b.amount.cmp(&a.amount).then(a.key_index.cmp(&b.key_index)));
        Ok(keep)
    }

    /// Total of the recorded outputs (call [`Wallet::spendable`] first for
    /// the confirmed total).
    pub fn balance(&self) -> u128 {
        self.owned.iter().map(|o| o.amount as u128).sum()
    }

    /// A transaction spending `coin` into `parts` fresh outputs of the
    /// wallet, splitting the amount as evenly as possible.
    pub fn split(&mut self, coin: &Owned, parts: usize) -> Transaction {
        self.split_all(core::slice::from_ref(coin), parts).pop().unwrap()
    }

    /// [`Wallet::split`] for each of `coins`, generating keys in parallel.
    pub fn split_all(&mut self, coins: &[Owned], parts: usize) -> Vec<Transaction> {
        // Amounts and key numbers first, in order; the keys are independent.
        let plans: Vec<(Owned, Vec<(u64, u64)>)> = coins
            .iter()
            .map(|coin| {
                let parts = (parts as u64).clamp(1, coin.amount.max(1));
                let outs = (0..parts)
                    .map(|j| {
                        self.next_key += 1;
                        (self.next_key - 1, coin.amount / parts + u64::from(j < coin.amount % parts))
                    })
                    .collect();
                (*coin, outs)
            })
            .collect();
        let built: Vec<(Transaction, Vec<Owned>)> = par_map_min(plans.len(), 1, |i| {
            let (coin, outs) = &plans[i];
            let owned: Vec<Owned> = outs
                .iter()
                .map(|&(key_index, amount)| {
                    let pk = self.key(key_index).public_key();
                    Owned { key_index, amount, commitment: commitment(&pk, amount) }
                })
                .collect();
            let outputs = owned.iter().map(|o| Output { commitment: o.commitment, amount: o.amount }).collect();
            let mut key = self.key(coin.key_index);
            let pk: PublicKey = key.public_key();
            debug_assert_eq!(commitment(&pk, coin.amount), coin.commitment);
            let tx = UnsignedTransaction::new(vec![(pk, coin.amount)], outputs)
                .sign_with(&mut key)
                .expect("fresh key signs once");
            (tx, owned)
        });
        built
            .into_iter()
            .map(|(tx, owned)| {
                self.owned.extend(owned);
                tx
            })
            .collect()
    }
}

const _: () = assert!(SEED_SIZE == DIGEST * 4);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_tree::open_env;

    #[test]
    fn records_survive_reopen_and_track_the_utxo_set() {
        let dir = std::env::temp_dir().join(format!("tabminer-wallet-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet");
        let mut w = Wallet::open(&path).unwrap();
        let paid = w.receive(10);
        let unconfirmed = w.receive(5);
        w.save().unwrap();
        let mut w = Wallet::open(&path).unwrap();
        assert_eq!(w.balance(), 15);

        let env = open_env(&dir.join("db"), 16 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        utxo.add(&mut wtxn, &paid).unwrap();
        let coins = w.spendable(&utxo, &wtxn).unwrap();
        assert_eq!(coins.len(), 1);
        assert_eq!((coins[0].amount, coins[0].commitment), (10, paid.commitment));
        assert_ne!(coins[0].commitment, unconfirmed.commitment);

        let tx = w.split(&coins[0], 3);
        assert!(tx.verify_signatures());
        assert_eq!(tx.outputs.iter().map(|o| o.amount).collect::<Vec<_>>(), vec![4, 3, 3]);
        assert_eq!(tx.balance(), 0);
        drop(wtxn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
