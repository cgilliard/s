//! The fam wallet's sub-name vectors (`node/src/user/node/wsub_vectors.fam`):
//! certificates signed by a name's owner (deterministic: Dilithium
//! unhedged), a query and an answer, from [`crate::subnames`], for
//! `node/src/user/node/wsub_test.fam`.

use crate::keccak::shake256;
use crate::poseidon2::digest_to_bytes;
use crate::subnames::{Bundle, Cert, answer, query};
use crate::{address, mldsa};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/wsub_vectors.fam");

fn bytes(o: &mut String, dst: &str, b: &[u8]) {
    o.push_str(&format!("{dst} @ sxp !\n"));
    for line in b.chunks(24) {
        let words: Vec<String> = line.iter().map(|x| format!("{x:X} lit sxc")).collect();
        o.push_str(&words.join(" "));
        o.push('\n');
    }
}

pub const SEQ: u64 = 0x0000_018b_0000_0007;
pub const EXPIRY: u64 = 1_700_500_000;
pub const NOW: u64 = 1_700_000_000;

fn generate() -> String {
    let mut o = String::from(
        "\\ node/wsub_vectors.fam — tabminer's values for node/wsub.fam\n\
         \\ (docs/SUBNAME_CERT.md; docs/GUI_WALLET.md, phase 3).  Written by\n\
         \\ miner/src/fam_sub_vectors.rs (`cargo test --release --features dev --lib\n\
         \\ write_fam_sub_vectors -- --ignored`); not to be edited.  Read by\n\
         \\ node/wsub_test.fam.\n\
         \\\n\
         \\ The owner's Dilithium seed at sxso, the holder's id at sxt; the name\n\
         \\ \"example\", the label \"ex1\"; seq and expiry at sxseq, sxexp (8 bytes\n\
         \\ each), sxnow a time before it.  SHAKE256-256 of the certificate naming\n\
         \\ the holder (sxhc, sxcl bytes), of the \"none\" one (sxhn, sxnl bytes),\n\
         \\ of the answer bearing the first (sxha, sxal bytes); the query's bytes\n\
         \\ at sxq (sxql); the full name's point id (onion mode's certificates\n\
         \\ are held at its rendezvous points) at sxpt.\n\n\
         : sxp variable ;  : sxso variable ;  : sxt variable ;  : sxseq variable ;  : sxexp variable ;  : sxnow variable ;\n\
         : sxhc variable ;  : sxcl variable ;  : sxhn variable ;  : sxnl variable ;  : sxha variable ;  : sxal variable ;\n\
         : sxq variable ;  : sxql variable ;  : sxpt variable ;\n\
         : sxc  sxp @ c!  sxp @ 1 lit + sxp ! ;\n\
         : sxbufs\n\
         sxso @ 0= if\n\
         \t20 lit alloc sxso !  20 lit alloc sxt !  8 lit alloc sxseq !  8 lit alloc sxexp !  20 lit alloc sxhc !\n\
         \t20 lit alloc sxhn !  20 lit alloc sxha !  40 lit alloc sxq !  20 lit alloc sxpt !\n\
         then ;\n\n",
    );
    let so: [u8; 32] = core::array::from_fn(|i| (3 * i + 7) as u8);
    let sh: [u8; 32] = core::array::from_fn(|i| (200 - i) as u8);
    let owner = mldsa::keygen(&so);
    let holder = address::id_of(mldsa::keygen(&sh).public_key());
    let (name, label) = (b"example".as_slice(), b"ex1".as_slice());
    let cert = Cert::id(&owner, name, label, &holder, SEQ, EXPIRY).unwrap();
    let value = address::id_of(owner.public_key());
    assert!(cert.verify_for(name, label, &value, None, NOW));
    let none = Cert::none(&owner, name, label, SEQ + 1, EXPIRY).unwrap();
    let q = query(name, label);
    let a = answer(name, label, Some(&Bundle { cert: cert.clone(), delegation: None }));
    let (cb, nb) = (cert.to_bytes(), none.to_bytes());
    o.push_str(": sxset\n");
    bytes(&mut o, "sxso", &so);
    bytes(&mut o, "sxt", &digest_to_bytes(&holder));
    bytes(&mut o, "sxseq", &SEQ.to_le_bytes());
    bytes(&mut o, "sxexp", &EXPIRY.to_le_bytes());
    bytes(&mut o, "sxhc", &shake256(&cb, 32));
    bytes(&mut o, "sxhn", &shake256(&nb, 32));
    bytes(&mut o, "sxha", &shake256(&a, 32));
    bytes(&mut o, "sxq", &q);
    bytes(&mut o, "sxpt", &digest_to_bytes(&Cert::point(name, label)));
    o.push_str(&format!(
        "{:X} lit sxcl !  {:X} lit sxnl !  {:X} lit sxal !  {:X} lit sxql !  {NOW:X} lit sxnow !\n;\n",
        cb.len(),
        nb.len(),
        a.len(),
        q.len()
    ));
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fam_sub_vectors_are_current() {
        let file = std::fs::read_to_string(PATH).expect("node/src/user/node/wsub_vectors.fam");
        assert!(file == generate(), "the fam wallet's sub-name vectors are stale: run write_fam_sub_vectors");
    }

    #[test]
    #[ignore = "writes the fam wallet's sub-name vectors: node/src/user/node/wsub_vectors.fam"]
    fn write_fam_sub_vectors() {
        std::fs::write(PATH, generate()).unwrap();
    }
}
