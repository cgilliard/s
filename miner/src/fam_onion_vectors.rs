//! The fam wallet's onion-mode vectors (`node/src/user/node/wonion_vectors.fam`):
//! the link and circuit handshakes (a participant and a relay, from given
//! seeds and randomness), frames each way and an acknowledgement, relay
//! cells sealed to each of three hops and sent back by each, a payload
//! carrying a route and an answer sealed along it, and rendezvous points
//! chosen by weight, from [`crate::channel`], [`crate::circuit`] and
//! [`crate::onion`], for `node/src/user/node/wonion_test.fam`.

use crate::channel::{Domain, Opening, respond, respond_keys};
use crate::circuit::{BODY, HopKeys, Layer, open_from, seal_for};
use crate::codec::Writer;
use crate::keccak::shake256;
use crate::onion::{Announce, Object, Payload, Route, rendezvous_relays, reply_id};
use crate::poseidon2::{Fp, digest_to_bytes};
use crate::{address, mldsa, mlkem};
use std::time::Instant;

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../node/src/user/node/wonion_vectors.fam");

fn bytes(o: &mut String, dst: &str, b: &[u8]) {
    o.push_str(&format!("{dst} @ ovp !\n"));
    for line in b.chunks(24) {
        let words: Vec<String> = line.iter().map(|x| format!("{x:X} lit ovc")).collect();
        o.push_str(&words.join(" "));
        o.push('\n');
    }
}
fn h(b: &[u8]) -> Vec<u8> {
    shake256(b, 32)
}
fn frame_bytes(f: &crate::channel::Frame) -> Vec<u8> {
    let mut w = Writer(Vec::new());
    f.put(&mut w);
    w.0
}

pub const CHAN: u64 = 0x0123_4567_89ab_cdef;
pub const SEQ: u64 = 0x0000_018b_0000_0001;
pub const EXPIRY: u64 = 1_800_000_000;
pub const NOW: u64 = 1_700_000_000;

fn generate() -> String {
    let mut o = String::from(
        "\\ node/wonion_vectors.fam — tabminer's values for node/wonion.fam\n\
         \\ (docs/ONION.md, onion mode; docs/GUI_WALLET.md, phase 3).  Written by\n\
         \\ miner/src/fam_onion_vectors.rs (`cargo test --release --features dev\n\
         \\ --lib write_fam_onion_vectors -- --ignored`); not to be edited.  Read by\n\
         \\ node/wonion_test.fam.  Hashes are SHAKE256-256.\n\
         \\\n\
         \\ Handshakes: the relay's Dilithium seed ovrs; the participant's Kyber\n\
         \\ seed ovks (64), challenge ovch, the relay's encapsulation randomness\n\
         \\ ovm, the channel ovchan (8).  The channel's: the hello's hash ovhh,\n\
         \\ the reply's ovrh, the participant's keys out ovko and in ovki; the\n\
         \\ circuit hop's (chan 0): ovcrh, ovcko, ovcki.\n\
         \\ Frames, on the channel: the participant sends 300 bytes (byte j\n\
         \\ 7j+1): its frame hashes to ovf1 (ovf1l bytes); the relay's\n\
         \\ acknowledgement to ova1 (ova1l); the relay sends 100 bytes (3j+2):\n\
         \\ ovr1 (ovr1l).\n\
         \\ Cells: three hops, forward keys byte j 16k+j+1, backward 16k+j+101\n\
         \\ (k the hop); a body of 875 bytes (5j+3): sealed to hop 0, then 1,\n\
         \\ then 2 (ovs0 ovs1 ovs2); then sent back by hop 0, 1 and 2 in turn\n\
         \\ (originated by the hop, passed by those before it: ovb0 ovb1 ovb2).\n\
         \\ Routes: a one-time Kyber key from the seeds ovqd ovqz; the route to\n\
         \\ the relay (token ovtk, 16); its reply id ovrid; a recipient (Dilithium\n\
         \\ seed ovas, Kyber seeds ovad ovaz; its announce seq/expiry ovseq ovexp,\n\
         \\ nonce 0); a payload of kind 1, 200 bytes (11j+5), m ovpm, nonce ovpn,\n\
         \\ sealed to it unnamed with the route: ovph (ovpl bytes); the answer,\n\
         \\ 150 bytes (13j+7), sealed along the route: ovah (oval bytes).\n\
         \\ ovwn ( -- n )  the weight cases; ovw ( i -- )  case i: the id at ovwid,\n\
         \\ the epoch ovwe, the points (3 relay indexes) at ovwx; the relays\n\
         \\ (seven) at ovwr, 32 bytes each.\n\n\
         : ovp variable ;  : ovrs variable ;  : ovks variable ;  : ovch variable ;  : ovm variable ;  : ovchan variable ;\n\
         : ovhh variable ;  : ovrh variable ;  : ovko variable ;  : ovki variable ;  : ovcrh variable ;  : ovcko variable ;\n\
         : ovcki variable ;  : ovf1 variable ;  : ovf1l variable ;  : ova1 variable ;  : ova1l variable ;  : ovr1 variable ;\n\
         : ovr1l variable ;  : ovs0 variable ;  : ovs1 variable ;  : ovs2 variable ;  : ovb0 variable ;  : ovb1 variable ;\n\
         : ovb2 variable ;  : ovqd variable ;  : ovqz variable ;  : ovtk variable ;  : ovrid variable ;  : ovas variable ;\n\
         : ovad variable ;  : ovaz variable ;  : ovseq variable ;  : ovexp variable ;  : ovpm variable ;  : ovpn variable ;\n\
         : ovph variable ;  : ovpl variable ;  : ovah variable ;  : oval variable ;  : ovwid variable ;  : ovwe variable ;\n\
         : ovwx variable ;  : ovwr variable ;  : ovnow variable ;\n\
         : ovc  ovp @ c!  ovp @ 1 lit + ovp ! ;\n\
         : ovbufs\n\
         ovrs @ 0= if\n\
         \t20 lit alloc ovrs !  40 lit alloc ovks !  20 lit alloc ovch !  20 lit alloc ovm !  8 lit alloc ovchan !\n\
         \t20 lit alloc ovhh !  20 lit alloc ovrh !  20 lit alloc ovko !  20 lit alloc ovki !  20 lit alloc ovcrh !\n\
         \t20 lit alloc ovcko !  20 lit alloc ovcki !  20 lit alloc ovf1 !  20 lit alloc ova1 !  20 lit alloc ovr1 !\n\
         \t20 lit alloc ovs0 !  20 lit alloc ovs1 !  20 lit alloc ovs2 !  20 lit alloc ovb0 !  20 lit alloc ovb1 !\n\
         \t20 lit alloc ovb2 !  20 lit alloc ovqd !  20 lit alloc ovqz !  10 lit alloc ovtk !  20 lit alloc ovrid !\n\
         \t20 lit alloc ovas !  20 lit alloc ovad !  20 lit alloc ovaz !  8 lit alloc ovseq !  8 lit alloc ovexp !\n\
         \t20 lit alloc ovpm !  C lit alloc ovpn !  20 lit alloc ovph !  20 lit alloc ovah !  20 lit alloc ovwid !\n\
         \t4 lit alloc ovwx !  E0 lit alloc ovwr !\n\
         then ;\n\n",
    );
    // handshakes
    let rs: [u8; 32] = core::array::from_fn(|i| (9 * i + 4) as u8);
    let relay = mldsa::keygen(&rs);
    let rid = address::id_of(relay.public_key());
    let ks: [u8; 64] = core::array::from_fn(|i| (i * 5 + 1) as u8);
    let ch: [u8; 32] = core::array::from_fn(|i| (200 - 3 * i) as u8);
    let m: [u8; 32] = [0x6d; 32];
    let opening = Opening::new(CHAN, rid, false, &ks, ch);
    let hello = opening.hello.clone();
    let now = Instant::now();
    let (mut relay_ch, reply) = respond(CHAN, &hello, &relay, &m, now).unwrap();
    let (ko, ki, _) = opening.keys(&reply).unwrap();
    let (mut part_ch, _) = Opening::new(CHAN, rid, false, &ks, ch).finish(&reply, None, now).unwrap();
    let copening = Opening::circuit(rid, &ks, ch);
    let ((_, _, _), creply) = respond_keys(Domain::Circuit, 0, &copening.hello, &relay, &m).unwrap();
    let (cko, cki, _) = copening.keys(&creply).unwrap();
    // frames
    let b1: Vec<u8> = (0..300).map(|j| (7 * j + 1) as u8).collect();
    let b2: Vec<u8> = (0..100).map(|j| (3 * j + 2) as u8).collect();
    let f1 = part_ch.send(&b1, now).unwrap().remove(0);
    let got = relay_ch.receive(&f1, now).unwrap();
    assert_eq!(got.delivered, vec![b1.clone()]);
    let a1 = got.send.into_iter().next().unwrap();
    let r1 = relay_ch.send(&b2, now).unwrap().remove(0);
    let (f1b, a1b, r1b) = (frame_bytes(&f1), frame_bytes(&a1), frame_bytes(&r1));
    // cells
    let key = |k: usize, base: usize| -> [u8; 32] { core::array::from_fn(|j| (16 * k + j + base) as u8) };
    let mk = || -> Vec<HopKeys> {
        (0..3).map(|k| HopKeys { forward: Layer::new(key(k, 1)), backward: Layer::new(key(k, 101)) }).collect()
    };
    let body: [u8; BODY] = core::array::from_fn(|j| (5 * j + 3) as u8);
    let mut hops = mk();
    let s: Vec<Vec<u8>> = (0..3).map(|t| seal_for(&mut hops, t, &body).to_vec()).collect();
    let mut relays_side: Vec<Layer> = (0..3).map(|k| Layer::new(key(k, 101))).collect();
    let mut client = mk();
    let mut b: Vec<Vec<u8>> = Vec::new();
    for t in 0..3 {
        let mut p = relays_side[t].originate(&body);
        for j in (0..t).rev() {
            relays_side[j].pass(&mut p);
        }
        b.push(p.to_vec());
        let mut q = p.clone();
        assert_eq!(open_from(&mut client, &mut q), Some(t));
        assert_eq!(&q[16..16 + BODY], &body[..]);
    }
    // routes
    let (qd, qz): ([u8; 32], [u8; 32]) = ([0x51; 32], [0x52; 32]);
    let one = mlkem::keygen_from_seeds(&qd, &qz);
    let tk: [u8; 16] = core::array::from_fn(|i| (0xa0 + i) as u8);
    let route = Route { relay: rid, token: tk, kyber: one.public_key().to_vec() };
    let (as_, ad, az): ([u8; 32], [u8; 32], [u8; 32]) = ([0x61; 32], [0x62; 32], [0x63; 32]);
    let ak = mldsa::keygen(&as_);
    let ay = mlkem::keygen_from_seeds(&ad, &az);
    let rec = Announce::make(&ak, ay.public_key(), SEQ, EXPIRY, 0);
    let inner: Vec<u8> = (0..200).map(|j| (11 * j + 5) as u8).collect();
    let (pm, pn) = ([0x71u8; 32], [0x72u8; 12]);
    let payload = Payload::seal(&rec, None, Some(&route), 1, &inner, &pm, pn).unwrap();
    let opened = payload.open(&ay, NOW).unwrap();
    assert!(opened.route.is_some() && opened.from.is_none() && opened.inner == inner);
    let pb = Object::Payload(payload).to_bytes();
    let ans: Vec<u8> = (0..150).map(|j| (13 * j + 7) as u8).collect();
    let answer = Payload::seal_reply(&route, 1, &ans, &pm, pn).unwrap();
    assert_eq!(answer.open(&one, NOW).unwrap().inner, ans);
    let ab = Object::Payload(answer).to_bytes();
    o.push_str(": ovset\n");
    bytes(&mut o, "ovrs", &rs);
    bytes(&mut o, "ovks", &ks);
    bytes(&mut o, "ovch", &ch);
    bytes(&mut o, "ovm", &m);
    bytes(&mut o, "ovchan", &CHAN.to_le_bytes());
    bytes(&mut o, "ovhh", &h(&hello));
    bytes(&mut o, "ovrh", &h(&reply));
    bytes(&mut o, "ovko", &ko);
    bytes(&mut o, "ovki", &ki);
    bytes(&mut o, "ovcrh", &h(&creply));
    bytes(&mut o, "ovcko", &cko);
    bytes(&mut o, "ovcki", &cki);
    bytes(&mut o, "ovf1", &h(&f1b));
    bytes(&mut o, "ova1", &h(&a1b));
    bytes(&mut o, "ovr1", &h(&r1b));
    bytes(&mut o, "ovs0", &h(&s[0]));
    bytes(&mut o, "ovs1", &h(&s[1]));
    bytes(&mut o, "ovs2", &h(&s[2]));
    bytes(&mut o, "ovb0", &h(&b[0]));
    bytes(&mut o, "ovb1", &h(&b[1]));
    bytes(&mut o, "ovb2", &h(&b[2]));
    bytes(&mut o, "ovqd", &qd);
    bytes(&mut o, "ovqz", &qz);
    bytes(&mut o, "ovtk", &tk);
    bytes(&mut o, "ovrid", &digest_to_bytes(&reply_id(one.public_key())));
    bytes(&mut o, "ovas", &as_);
    bytes(&mut o, "ovad", &ad);
    bytes(&mut o, "ovaz", &az);
    bytes(&mut o, "ovseq", &SEQ.to_le_bytes());
    bytes(&mut o, "ovexp", &EXPIRY.to_le_bytes());
    bytes(&mut o, "ovpm", &pm);
    bytes(&mut o, "ovpn", &pn);
    bytes(&mut o, "ovph", &h(&pb));
    bytes(&mut o, "ovah", &h(&ab));
    o.push_str(&format!(
        "{:X} lit ovf1l !  {:X} lit ova1l !  {:X} lit ovr1l !  {:X} lit ovpl !  {:X} lit oval !  {NOW:X} lit ovnow !\n;\n",
        f1b.len(),
        a1b.len(),
        r1b.len(),
        pb.len(),
        ab.len()
    ));
    // weights
    let relays: Vec<_> = (0..7u32)
        .map(|k| core::array::from_fn::<Fp, 8, _>(|i| Fp::new(k * 1_000_003 + i as u32 * 77 + 1)))
        .collect();
    let rb: Vec<u8> = relays.iter().flat_map(|r| digest_to_bytes(r)).collect();
    let ids = [rid, address::id_of(ak.public_key())];
    let mut cases = Vec::new();
    for id in &ids {
        for &e in &[0u32, 1, 4242] {
            cases.push((digest_to_bytes(id), e, rendezvous_relays(id, e, &relays)));
        }
    }
    for (i, (id, e, ix)) in cases.iter().enumerate() {
        o.push_str(&format!(": ovw{i}\n"));
        bytes(&mut o, "ovwid", id);
        bytes(&mut o, "ovwr", &rb);
        let x: Vec<u8> = ix.iter().map(|&v| v as u8).collect();
        bytes(&mut o, "ovwx", &x);
        o.push_str(&format!("{e:X} lit ovwe !\n;\n"));
    }
    o.push_str(&format!(": ovwn  {:X} lit ;\n: ovw\n", cases.len()));
    for i in 0..cases.len() {
        o.push_str(&format!("dup {i:X} lit = if ovw{i} then\n"));
    }
    o.push_str("drop ;\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fam_onion_vectors_are_current() {
        let file = std::fs::read_to_string(PATH).expect("node/src/user/node/wonion_vectors.fam");
        assert!(file == generate(), "the fam wallet's onion vectors are stale: run write_fam_onion_vectors");
    }

    #[test]
    #[ignore = "writes the fam wallet's onion vectors: node/src/user/node/wonion_vectors.fam"]
    fn write_fam_onion_vectors() {
        std::fs::write(PATH, generate()).unwrap();
    }
}
