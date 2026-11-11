//! The fam node's Kyber vectors (`node/src/user/crypto/kyber_vectors.fam`):
//! key pairs from seeds (the first ones NIST ACVP's, from
//! `tests/vectors/ML-KEM-768.kat`), encapsulations, decapsulations of the
//! ciphertext as made and tampered with (implicit rejection), and the key
//! check on a malformed key, from [`crate::mlkem`], for
//! `node/src/user/crypto/kyber_test.fam`.

use crate::keccak::shake256;
use crate::mlkem::{encapsulate_with, keygen_from_seeds, valid_public_key};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/crypto/kyber_vectors.fam");

/// Bytes as fam pushes them to the buffer at `dst` (`kxp`, then `kxc`
/// each), 24 a line.
fn bytes(o: &mut String, dst: &str, b: &[u8]) {
    o.push_str(&format!("{dst} @ kxp !\n"));
    for line in b.chunks(24) {
        let words: Vec<String> = line.iter().map(|x| format!("{x:X} lit kxc")).collect();
        o.push_str(&words.join(" "));
        o.push('\n');
    }
}

fn hex32(s: &str) -> [u8; 32] {
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

/// The cases: seeds d and z, the encapsulation's randomness m, and the
/// ciphertext byte to tamper with (index, xor).
fn cases() -> Vec<([u8; 32], [u8; 32], [u8; 32], usize, u8)> {
    let kat = include_str!("../tests/vectors/ML-KEM-768.kat");
    let mut v = Vec::new();
    for line in kat.lines().filter(|l| l.starts_with("keygen ")).take(2) {
        let field = |name: &str| line.split(' ').find_map(|p| p.strip_prefix(name)).unwrap();
        v.push((hex32(field("d=")), hex32(field("z=")), [0x42; 32], 0, 1));
    }
    v.push(([0; 32], [0; 32], [0; 32], 1087, 0x80));
    v.push((core::array::from_fn(|i| i as u8), core::array::from_fn(|i| (255 - i) as u8), core::array::from_fn(|i| (7 * i + 3) as u8), 960, 0x10));
    v.push(([0xff; 32], [0x5a; 32], [0xff; 32], 500, 0x01));
    v
}

fn generate() -> String {
    let mut o = String::from(
        "\\ crypto/kyber_vectors.fam — tabminer's values for crypto/kyber.fam\n\
         \\ (docs/GUI_WALLET.md, phase 3).  Written by miner/src/fam_kyber_vectors.rs\n\
         \\ (`cargo test --release --features dev --lib write_fam_kyber_vectors --\n\
         \\ --ignored`); not to be edited.  Read by crypto/kyber_test.fam.\n\
         \\\n\
         \\ kxn ( -- n )  the cases; kxset ( i -- )  case i: the seeds at kxd and\n\
         \\ kxz, the encapsulation's randomness at kxm, SHAKE256-256 of the\n\
         \\ encapsulation key, decapsulation key and ciphertext at kxhe kxhd kxhc,\n\
         \\ the shared secret at kxss; the ciphertext's byte kxta xored with kxtx\n\
         \\ decapsulates to the secret at kxts; the encapsulation key with its\n\
         \\ first coefficient made 4095 is well formed or not as kxbad says (-1,\n\
         \\ 0).\n\n\
         : kxp variable ;  : kxd variable ;  : kxz variable ;  : kxm variable ;  : kxhe variable ;\n\
         : kxhd variable ;  : kxhc variable ;  : kxss variable ;  : kxts variable ;  : kxta variable ;\n\
         : kxtx variable ;  : kxbad variable ;\n\
         : kxc  kxp @ c!  kxp @ 1 lit + kxp ! ;\n\
         : kxbufs\n\
         kxd @ 0= if\n\
         \t20 lit alloc kxd !  20 lit alloc kxz !  20 lit alloc kxm !  20 lit alloc kxhe !  20 lit alloc kxhd !\n\
         \t20 lit alloc kxhc !  20 lit alloc kxss !  20 lit alloc kxts !\n\
         then ;\n\n",
    );
    let cs = cases();
    for (i, (d, z, m, ta, tx)) in cs.iter().enumerate() {
        let sk = keygen_from_seeds(d, z);
        let ek = sk.public_key().to_vec();
        let (ss, ct) = encapsulate_with(&ek, m).unwrap();
        assert_eq!(sk.decapsulate(&ct), Some(ss));
        let mut bad = ct.clone();
        bad[*ta] ^= tx;
        let ts = sk.decapsulate(&bad).unwrap();
        let mut ekbad = ek.clone();
        ekbad[0] = 0xff;
        ekbad[1] |= 0x0f;
        o.push_str(&format!(": kxq{i}\n"));
        bytes(&mut o, "kxd", d);
        bytes(&mut o, "kxz", z);
        bytes(&mut o, "kxm", m);
        bytes(&mut o, "kxhe", &shake256(&ek, 32));
        bytes(&mut o, "kxhd", &shake256(sk.to_bytes(), 32));
        bytes(&mut o, "kxhc", &shake256(&ct, 32));
        bytes(&mut o, "kxss", &ss);
        bytes(&mut o, "kxts", &ts);
        o.push_str(&format!(
            "{ta:X} lit kxta !  {tx:X} lit kxtx !  {} lit kxbad !\n;\n",
            if valid_public_key(&ekbad) { "FFFFFFFF" } else { "0" }
        ));
    }
    o.push_str(&format!(": kxn  {:X} lit ;\n: kxset\n", cs.len()));
    for i in 0..cs.len() {
        o.push_str(&format!("dup {i:X} lit = if kxq{i} then\n"));
    }
    o.push_str("drop ;\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fam_kyber_vectors_are_current() {
        let file = std::fs::read_to_string(PATH).expect("node/src/user/crypto/kyber_vectors.fam");
        assert!(file == generate(), "the fam node's Kyber vectors are stale: run write_fam_kyber_vectors");
    }

    #[test]
    #[ignore = "writes the node's Kyber vectors: node/src/user/crypto/kyber_vectors.fam"]
    fn write_fam_kyber_vectors() {
        std::fs::write(PATH, generate()).unwrap();
    }
}
