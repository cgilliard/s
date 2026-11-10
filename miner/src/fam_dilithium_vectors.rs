//! The fam node's Dilithium vectors (`node/src/user/crypto/dilithium_vectors.fam`):
//! keys from seeds, signatures of messages and verification verdicts,
//! tampered signatures among them, from [`crate::mldsa`] and
//! [`crate::keccak`], for `node/src/user/crypto/dilithium_test.fam`. A fam
//! signature equal to tabminer's (signing is deterministic) verifies here,
//! and tabminer's verify there.

use crate::keccak::{sha3_256, sha3_512, shake128, shake256};
use crate::mldsa::{SIG_LEN, keygen, verify};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/crypto/dilithium_vectors.fam");

/// Bytes as fam pushes them to the buffer at `dst` (`dvp`, then `dvc`
/// each), 24 a line.
fn bytes(o: &mut String, dst: &str, b: &[u8]) {
    o.push_str(&format!("{dst} @ dvp !\n"));
    for line in b.chunks(24) {
        let words: Vec<String> = line.iter().map(|x| format!("{x:X} lit dvc")).collect();
        o.push_str(&words.join(" "));
        o.push('\n');
    }
}

/// The checks of one case: what is changed before verifying (kind, a, b)
/// and tabminer's verdict. Kinds: 0 nothing; 1 the signature's byte a
/// xored with b; 2 the message's byte a xored with b; 3 the context's
/// byte a xored with b; 4 the context with the byte b after it; 5 the
/// public key's byte a xored with b; 6 the previous case's public key.
fn checks(pk: &[u8], prev_pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Vec<(u32, u32, u32, bool)> {
    const HINTS: usize = 48 + 32 * 5 * 20;
    let mut c = Vec::new();
    let mut add = |kind: u32, a: usize, b: u8| {
        let (mut p, mut m, mut x, mut s) = (pk.to_vec(), msg.to_vec(), ctx.to_vec(), sig.to_vec());
        match kind {
            0 => {}
            1 => s[a] ^= b,
            2 => m[a] ^= b,
            3 => x[a] ^= b,
            4 => x.push(b),
            5 => p[a] ^= b,
            _ => p = prev_pk.to_vec(),
        }
        c.push((kind, a as u32, u32::from(b), verify(&p, &m, &x, &s)));
    };
    add(0, 0, 0);
    // the challenge, z (a low bit, a high one), the hints' places and counts
    add(1, 0, 1);
    add(1, 47, 0x80);
    add(1, 48, 1);
    add(1, 48 + 2, 0x80);
    add(1, 1000, 4);
    add(1, HINTS - 1, 0x10);
    add(1, HINTS, 1);
    add(1, SIG_LEN - 7, 0x40);
    add(1, SIG_LEN - 6, 1);
    add(1, SIG_LEN - 1, 1);
    add(1, SIG_LEN - 1, 0x80);
    if !msg.is_empty() {
        add(2, msg.len() - 1, 1);
    }
    if !ctx.is_empty() {
        add(3, 0, 0x20);
    }
    add(4, 0, 0);
    add(5, 0, 1);
    add(5, 1000, 0x10);
    add(6, 0, 0);
    c
}

/// The vectors file.
fn generate() -> String {
    let mut o = String::from(
        "\\ crypto/dilithium_vectors.fam — tabminer's values for crypto/keccak.fam and\n\
         \\ crypto/dilithium.fam (docs/GUI_WALLET.md, phase 1).  Written by\n\
         \\ miner/src/fam_dilithium_vectors.rs (`cargo test --release --features dev\n\
         \\ --lib write_fam_dilithium_vectors -- --ignored`); not to be edited.  Read by\n\
         \\ crypto/dilithium_test.fam.\n\
         \\\n\
         \\ dvkn ( -- n )  the hash cases; dvk ( i -- )  case i: dvkf the function\n\
         \\ (0 SHAKE128, 1 SHAKE256, 2 SHA3-256, 3 SHA3-512), dvkl the input's\n\
         \\ length (byte j of it 7j+1), dvko the output's, its bytes at dvkx.\n\
         \\ dvn ( -- n )  the Dilithium cases; dvset ( i -- )  case i: the seed at\n\
         \\ dvsd (32), the message at dvmsg (dvml bytes), the context at dvctx\n\
         \\ (dvcl), SHAKE256-256 of the public key, secret key and signature at\n\
         \\ dvpkh dvskh dvsgh, and the checks at dvt (dvtn of them, four words\n\
         \\ each: kind, a, b, tabminer's verdict -1 or 0; the kinds as\n\
         \\ fam_dilithium_vectors.rs's checks).\n\n\
         : dvp variable ;  : dvkf variable ;  : dvkl variable ;  : dvko variable ;  : dvkx variable ;\n\
         : dvsd variable ;  : dvmsg variable ;  : dvml variable ;  : dvctx variable ;  : dvcl variable ;\n\
         : dvpkh variable ;  : dvskh variable ;  : dvsgh variable ;  : dvt variable ;  : dvtn variable ;\n\
         : dvc  dvp @ c!  dvp @ 1 lit + dvp ! ;\n\
         : dvbufs\n\
         dvkx @ 0= if\n\
         \t100 lit alloc dvkx !  20 lit alloc dvsd !  100 lit alloc dvmsg !  110 lit alloc dvctx !\n\
         \t20 lit alloc dvpkh !  20 lit alloc dvskh !  20 lit alloc dvsgh !  200 lit alloc dvt !\n\
         then ;\n\
         : dvck  dvtn @ 4 lit lshift dvt @ + tuck C lit + !  tuck 8 lit + !  tuck 4 lit + !  !  dvtn @ 1 lit + dvtn ! ;   \\ ( kind a b verdict -- )\n\n",
    );
    // hashes
    let hashes: Vec<(u32, usize, Vec<u8>)> = {
        let input = |n: usize| -> Vec<u8> { (0..n).map(|j| (7 * j + 1) as u8).collect() };
        let mut v = Vec::new();
        for &n in &[0usize, 3, 135, 136, 137, 167, 168, 169, 300] {
            let d = input(n);
            v.push((0, n, shake128(&d, 200)));
            v.push((1, n, shake256(&d, 200)));
        }
        for &n in &[0usize, 3, 136, 200] {
            let d = input(n);
            v.push((2, n, sha3_256(&d).to_vec()));
            v.push((3, n, sha3_512(&d).to_vec()));
        }
        v
    };
    for (i, (f, n, out)) in hashes.iter().enumerate() {
        o.push_str(&format!(": dvh{i}\n{f:X} lit dvkf !  {n:X} lit dvkl !  {:X} lit dvko !\n", out.len()));
        bytes(&mut o, "dvkx", out);
        o.push_str(";\n");
    }
    o.push_str(&format!(": dvkn  {:X} lit ;\n: dvk\n", hashes.len()));
    for i in 0..hashes.len() {
        o.push_str(&format!("dup {i:X} lit = if dvh{i} then\n"));
    }
    o.push_str("drop ;\n\n");
    // Dilithium
    let cases: Vec<([u8; 32], Vec<u8>, Vec<u8>)> = vec![
        ([0; 32], Vec::new(), Vec::new()),
        (core::array::from_fn(|i| i as u8), b"abc".to_vec(), b"tab".to_vec()),
        (core::array::from_fn(|i| (7 * i + 3) as u8), (0..200).map(|i| (13 * i + 5) as u8).collect(), (0..40).map(|i| (i * 3) as u8).collect()),
        ([0xff; 32], vec![0x5a], Vec::new()),
    ];
    let mut prev_pk = keygen(&cases[cases.len() - 1].0).public_key().to_vec();
    for (i, (seed, msg, ctx)) in cases.iter().enumerate() {
        let sk = keygen(seed);
        let pk = sk.public_key().to_vec();
        let sig = sk.sign(msg, ctx);
        o.push_str(&format!(": dvq{i}\n0 lit dvtn !\n"));
        bytes(&mut o, "dvsd", seed);
        bytes(&mut o, "dvmsg", msg);
        o.push_str(&format!("{:X} lit dvml !\n", msg.len()));
        bytes(&mut o, "dvctx", ctx);
        o.push_str(&format!("{:X} lit dvcl !\n", ctx.len()));
        bytes(&mut o, "dvpkh", &shake256(&pk, 32));
        bytes(&mut o, "dvskh", &shake256(sk.to_bytes(), 32));
        bytes(&mut o, "dvsgh", &shake256(&sig, 32));
        for (kind, a, b, ok) in checks(&pk, &prev_pk, msg, ctx, &sig) {
            o.push_str(&format!("{kind:X} lit {a:X} lit {b:X} lit {} lit dvck\n", if ok { "FFFFFFFF" } else { "0" }));
        }
        o.push_str(";\n");
        prev_pk = pk;
    }
    o.push_str(&format!(": dvn  {:X} lit ;\n: dvset\n", cases.len()));
    for i in 0..cases.len() {
        o.push_str(&format!("dup {i:X} lit = if dvq{i} then\n"));
    }
    o.push_str("drop ;\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fam_dilithium_vectors_are_current() {
        let file = std::fs::read_to_string(PATH).expect("node/src/user/crypto/dilithium_vectors.fam");
        assert!(file == generate(), "the fam node's Dilithium vectors are stale: run write_fam_dilithium_vectors");
    }

    #[test]
    #[ignore = "writes the node's Dilithium vectors: node/src/user/crypto/dilithium_vectors.fam"]
    fn write_fam_dilithium_vectors() {
        std::fs::write(PATH, generate()).unwrap();
    }
}
