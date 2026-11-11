//! The fam wallet's message-layer vectors (`node/src/user/node/wmsg_vectors.fam`):
//! announces made from known keys, a payload sealed from one to the other
//! (deterministic: the encapsulation's randomness and the nonce given,
//! Dilithium unhedged), object ids and rendezvous indexes, from
//! [`crate::onion`], for `node/src/user/node/wmsg_test.fam`.

use crate::keccak::shake256;
use crate::onion::{Announce, Object, Payload, rendezvous_indexes};
use crate::poseidon2::digest_to_bytes;
use crate::{mldsa, mlkem};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/wmsg_vectors.fam");

/// Bytes as fam pushes them to the buffer at `dst` (`mxp`, then `mxc`
/// each), 24 a line.
fn bytes(o: &mut String, dst: &str, b: &[u8]) {
    o.push_str(&format!("{dst} @ mxp !\n"));
    for line in b.chunks(24) {
        let words: Vec<String> = line.iter().map(|x| format!("{x:X} lit mxc")).collect();
        o.push_str(&words.join(" "));
        o.push('\n');
    }
}

fn u64s(o: &mut String, dst: &str, v: u64) {
    bytes(o, dst, &v.to_le_bytes());
}

pub const SEQ: u64 = 0x0000_018b_1234_5678;
pub const EXPIRY: u64 = 1_800_000_000;
pub const NONCE: u64 = 0x1122_3344_5566_7788;
pub const NOW: u64 = 1_700_000_000;

fn generate() -> String {
    let mut o = String::from(
        "\\ node/wmsg_vectors.fam — tabminer's values for node/wmsg.fam (docs/ONION.md,\n\
         \\ init mode; docs/GUI_WALLET.md, phase 3).  Written by\n\
         \\ miner/src/fam_msg_vectors.rs (`cargo test --release --features dev --lib\n\
         \\ write_fam_msg_vectors -- --ignored`); not to be edited.  Read by\n\
         \\ node/wmsg_test.fam.\n\
         \\\n\
         \\ Two participants, A and B: Dilithium seeds at mxsa, mxsb; Kyber seeds\n\
         \\ (d, z) at mxda mxza, mxdb mxzb.  mxseq, mxexp, mxnon (8 bytes each):\n\
         \\ A's session announce (nonce mxnon) hashes (SHAKE256-256) to mxha, its\n\
         \\ object (tag 1) has the id mxia; the carried announces (nonce 0) of A\n\
         \\ and B hash to mxhca, mxhcb.  A's payload to B: kind 1, the inner bytes\n\
         \\ byte j 5j+3 (mxil of them), the encapsulation's randomness mxm, the\n\
         \\ nonce mxn: its object is mxol bytes, hashing to mxho, its id mxio.\n\
         \\ mxnow: a time before expiry.  mxrn ( -- n )  the rendezvous cases;\n\
         \\ mxr ( i -- )  case i: the id at mxid, the epoch mxe, the nodes mxnn,\n\
         \\ the indexes at mxix (mxk of them).\n\n\
         : mxp variable ;  : mxsa variable ;  : mxsb variable ;  : mxda variable ;  : mxza variable ;\n\
         : mxdb variable ;  : mxzb variable ;  : mxseq variable ;  : mxexp variable ;  : mxnon variable ;\n\
         : mxha variable ;  : mxia variable ;  : mxhca variable ;  : mxhcb variable ;  : mxil variable ;\n\
         : mxm variable ;  : mxn variable ;  : mxol variable ;  : mxho variable ;  : mxio variable ;\n\
         : mxnow variable ;  : mxid variable ;  : mxe variable ;  : mxnn variable ;  : mxix variable ;  : mxk variable ;\n\
         : mxc  mxp @ c!  mxp @ 1 lit + mxp ! ;\n\
         : mxbufs\n\
         mxsa @ 0= if\n\
         \t20 lit alloc mxsa !  20 lit alloc mxsb !  20 lit alloc mxda !  20 lit alloc mxza !  20 lit alloc mxdb !\n\
         \t20 lit alloc mxzb !  8 lit alloc mxseq !  8 lit alloc mxexp !  8 lit alloc mxnon !  20 lit alloc mxha !\n\
         \t20 lit alloc mxia !  20 lit alloc mxhca !  20 lit alloc mxhcb !  20 lit alloc mxm !  C lit alloc mxn !\n\
         \t20 lit alloc mxho !  20 lit alloc mxio !  20 lit alloc mxid !  10 lit alloc mxix !\n\
         then ;\n\n",
    );
    let sa: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
    let sb: [u8; 32] = core::array::from_fn(|i| (0x80 + 3 * i) as u8);
    let (da, za): ([u8; 32], [u8; 32]) = (core::array::from_fn(|i| (5 * i) as u8), [0x11; 32]);
    let (db, zb): ([u8; 32], [u8; 32]) = (core::array::from_fn(|i| (255 - i) as u8), [0x22; 32]);
    let (ka, kb) = (mldsa::keygen(&sa), mldsa::keygen(&sb));
    let (ya, yb) = (mlkem::keygen_from_seeds(&da, &za), mlkem::keygen_from_seeds(&db, &zb));
    let session = Announce::make(&ka, ya.public_key(), SEQ, EXPIRY, NONCE);
    assert!(session.verify(NOW));
    let carried_a = Announce::make(&ka, ya.public_key(), SEQ, EXPIRY, 0);
    let carried_b = Announce::make(&kb, yb.public_key(), SEQ, EXPIRY, 0);
    let session_obj = Object::Announce(session.clone()).to_bytes();
    let inner: Vec<u8> = (0..300).map(|j| (5 * j + 3) as u8).collect();
    let (m, n) = ([7u8; 32], [9u8; 12]);
    let payload = Payload::seal(&carried_b, Some((&ka, &carried_a)), None, 1, &inner, &m, n).unwrap();
    let opened = payload.open(&yb, NOW).unwrap();
    assert_eq!((opened.kind, opened.inner.clone()), (1, inner.clone()));
    let pobj = Object::Payload(payload).to_bytes();
    o.push_str(": mxset\n");
    bytes(&mut o, "mxsa", &sa);
    bytes(&mut o, "mxsb", &sb);
    bytes(&mut o, "mxda", &da);
    bytes(&mut o, "mxza", &za);
    bytes(&mut o, "mxdb", &db);
    bytes(&mut o, "mxzb", &zb);
    u64s(&mut o, "mxseq", SEQ);
    u64s(&mut o, "mxexp", EXPIRY);
    u64s(&mut o, "mxnon", NONCE);
    bytes(&mut o, "mxha", &shake256(&session_obj[1..], 32));
    bytes(&mut o, "mxia", &digest_to_bytes(&Object::id_of(&session_obj)));
    bytes(&mut o, "mxhca", &shake256(&Object::Announce(carried_a).to_bytes()[1..], 32));
    bytes(&mut o, "mxhcb", &shake256(&Object::Announce(carried_b.clone()).to_bytes()[1..], 32));
    bytes(&mut o, "mxm", &m);
    bytes(&mut o, "mxn", &n);
    bytes(&mut o, "mxho", &shake256(&pobj, 32));
    bytes(&mut o, "mxio", &digest_to_bytes(&Object::id_of(&pobj)));
    o.push_str(&format!("{:X} lit mxil !  {:X} lit mxol !  {NOW:X} lit mxnow !\n;\n", inner.len(), pobj.len()));
    // rendezvous
    let ids = [session.id, carried_b.id];
    let mut cases = Vec::new();
    for id in &ids {
        for &epoch in &[0u32, 1, 12345] {
            for &nodes in &[1usize, 2, 3, 5, 9] {
                cases.push((digest_to_bytes(id), epoch, nodes, rendezvous_indexes(id, epoch, nodes)));
            }
        }
    }
    for (i, (id, epoch, nodes, ix)) in cases.iter().enumerate() {
        o.push_str(&format!(": mxr{i}\n"));
        bytes(&mut o, "mxid", id);
        let ixb: Vec<u8> = ix.iter().map(|&x| x as u8).collect();
        bytes(&mut o, "mxix", &ixb);
        o.push_str(&format!("{epoch:X} lit mxe !  {nodes:X} lit mxnn !  {:X} lit mxk !\n;\n", ix.len()));
    }
    o.push_str(&format!(": mxrn  {:X} lit ;\n: mxr\n", cases.len()));
    for i in 0..cases.len() {
        o.push_str(&format!("dup {i:X} lit = if mxr{i} then\n"));
    }
    o.push_str("drop ;\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fam_msg_vectors_are_current() {
        let file = std::fs::read_to_string(PATH).expect("node/src/user/node/wmsg_vectors.fam");
        assert!(file == generate(), "the fam wallet's message vectors are stale: run write_fam_msg_vectors");
    }

    #[test]
    #[ignore = "writes the fam wallet's message vectors: node/src/user/node/wmsg_vectors.fam"]
    fn write_fam_msg_vectors() {
        std::fs::write(PATH, generate()).unwrap();
    }
}
