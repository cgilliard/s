//! The message layer's objects (`docs/ONION.md`): what a participant
//! publishes at its rendezvous points, what a sender wraps a message in,
//! and how rendezvous points are chosen. Pure data and cryptography; the
//! sessions that carry these live in the node.
//!
//! An [`Announce`] is a participant's Dilithium key with a fresh Kyber
//! key, a sequence number and an expiry, signed by the Dilithium key; its
//! id is the key's hash, so whoever holds the id checks it by one hash
//! and one signature. A [`Payload`] is a message to an id: the body is
//! encapsulated to the recipient's announced Kyber key and sealed with
//! ChaCha20-Poly1305, and carries inside it the sender's own announce
//! (for the reply) when the sender wants to be known, in which case the
//! whole payload is signed by the sender's Dilithium key.

use crate::address;
use crate::chacha20poly1305;
use crate::codec::{Reader, Writer};
use crate::mldsa;
use crate::mlkem;
use crate::poseidon2::{Fp, digest_from_bytes, digest_to_bytes};
use crate::transaction::hash_domain;
use crate::xmss::Digest;

/// Rendezvous points per participant.
pub const RENDEZVOUS: usize = 3;
/// Between keepalives on a rendezvous session.
pub const KEEPALIVE_SECS: u64 = 30;
/// A session with no keepalive for this long is gone.
pub const SESSION_TIMEOUT_SECS: u64 = 3 * KEEPALIVE_SECS;
/// How long a wallet's announce is valid; it is renewed well before.
pub const ANNOUNCE_LIFETIME_SECS: u64 = 86_400;
/// Largest object: an announce is about 6.5 KB, a payload a slate plus
/// an announce.
pub const MAX_OBJECT: usize = 64 << 10;

/// A payload's kind: a payment slate (`crate::wallet::Slate`), answered
/// at stage 1 and finalized at stage 2.
pub const KIND_SLATE: u8 = 1;

const DOM_OBJECT: u32 = 19;
const DOM_RENDEZVOUS: u32 = 20;
const DOM_WEIGHT: u32 = 21;
const ANNOUNCE_CONTEXT: &[u8] = b"tab-announce";
const PAYLOAD_CONTEXT: &[u8] = b"tab-payload";
const TAG_ANNOUNCE: u8 = 1;
const TAG_PAYLOAD: u8 = 2;

/// The zero digest: no sender named.
pub const NOBODY: Digest = [Fp::ZERO; 8];

/// A participant's published keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announce {
    /// The hash of `dilithium`.
    pub id: Digest,
    pub dilithium: Vec<u8>,
    pub kyber: Vec<u8>,
    /// Rises with every new Kyber key; a rendezvous point keeps the
    /// highest.
    pub seq: u64,
    /// Unix time after which the Kyber key is not to be used.
    pub expiry: u64,
    /// The nonce the rendezvous point gave for this session, binding the
    /// announce to it; zero for an announce carried inside a payload.
    pub nonce: u64,
    pub sig: Vec<u8>,
}

impl Announce {
    const FIXED: usize = 32 + mldsa::PK_LEN + mlkem::EK_LEN + 8 + 8 + 8 + mldsa::SIG_LEN;

    fn signed_part(id: &Digest, dilithium: &[u8], kyber: &[u8], seq: u64, expiry: u64, nonce: u64) -> Vec<u8> {
        let mut w = Writer::with_capacity(Self::FIXED);
        w.digest(id);
        w.0.extend_from_slice(dilithium);
        w.0.extend_from_slice(kyber);
        w.u64(seq);
        w.u64(expiry);
        w.u64(nonce);
        w.0
    }

    /// Signs an announce of `kyber` by `key`.
    pub fn make(key: &mldsa::SecretKey, kyber: &[u8], seq: u64, expiry: u64, nonce: u64) -> Announce {
        let dilithium = key.public_key().to_vec();
        let id = address::id_of(&dilithium);
        let sig = key.sign(&Self::signed_part(&id, &dilithium, kyber, seq, expiry, nonce), ANNOUNCE_CONTEXT);
        Announce { id, dilithium, kyber: kyber.to_vec(), seq, expiry, nonce, sig }
    }

    /// Whether the announce is sound at time `now`: the id is the key's
    /// hash, the Kyber key is well formed, it has not expired, and the
    /// signature holds.
    pub fn verify(&self, now: u64) -> bool {
        self.id == address::id_of(&self.dilithium)
            && mlkem::valid_public_key(&self.kyber)
            && self.expiry > now
            && mldsa::verify(
                &self.dilithium,
                &Self::signed_part(&self.id, &self.dilithium, &self.kyber, self.seq, self.expiry, self.nonce),
                ANNOUNCE_CONTEXT,
                &self.sig,
            )
    }

    fn put(&self, w: &mut Writer) {
        w.0.extend_from_slice(&Self::signed_part(&self.id, &self.dilithium, &self.kyber, self.seq, self.expiry, self.nonce));
        w.0.extend_from_slice(&self.sig);
    }

    fn get(r: &mut Reader) -> Option<Announce> {
        let id = r.digest()?;
        let dilithium = r.take(mldsa::PK_LEN)?.to_vec();
        let kyber = r.take(mlkem::EK_LEN)?.to_vec();
        let seq = r.u64()?;
        let expiry = r.u64()?;
        let nonce = r.u64()?;
        let sig = r.take(mldsa::SIG_LEN)?.to_vec();
        Some(Announce { id, dilithium, kyber, seq, expiry, nonce, sig })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(Self::FIXED);
        self.put(&mut w);
        w.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Announce> {
        let mut r = Reader(bytes);
        let a = Self::get(&mut r)?;
        r.is_empty().then_some(a)
    }
}

/// What a payload carries once opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The sender's announce, when it named itself; verified, and its id
    /// is the payload's `from`.
    pub from: Option<Announce>,
    pub kind: u8,
    pub inner: Vec<u8>,
}

/// A message to an id, sealed to its announced Kyber key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    pub to: Digest,
    /// The sender's id, or [`NOBODY`].
    pub from: Digest,
    /// The Kyber ciphertext.
    pub ct: Vec<u8>,
    pub nonce: [u8; chacha20poly1305::NONCE_LEN],
    /// Sealed: kind, the sender's announce if any, the inner bytes.
    pub body: Vec<u8>,
    /// By the sender's Dilithium key over everything above, when `from`
    /// is set; empty otherwise.
    pub sig: Vec<u8>,
}

impl Payload {
    fn signed_part(to: &Digest, from: &Digest, ct: &[u8], nonce: &[u8; 12], body: &[u8]) -> Vec<u8> {
        let mut w = Writer::with_capacity(64 + ct.len() + 12 + body.len());
        w.digest(to);
        w.digest(from);
        w.0.extend_from_slice(ct);
        w.0.extend_from_slice(nonce);
        w.0.extend_from_slice(body);
        w.0
    }

    /// Seals `inner` of `kind` to `to`'s Kyber key. With `from`, the
    /// sender's key and its announce (for the reply) go inside and the
    /// payload is signed. `m` is the encapsulation's randomness.
    pub fn seal(
        to: &Announce,
        from: Option<(&mldsa::SecretKey, &Announce)>,
        kind: u8,
        inner: &[u8],
        m: &[u8; 32],
        nonce: [u8; 12],
    ) -> Option<Payload> {
        let (shared, ct) = mlkem::encapsulate_with(&to.kyber, m)?;
        let mut plain = Writer::with_capacity(1 + Announce::FIXED + inner.len());
        plain.0.push(kind);
        match from {
            Some((_, announce)) => {
                plain.0.push(1);
                announce.put(&mut plain);
            }
            None => plain.0.push(0),
        }
        plain.0.extend_from_slice(inner);
        let from_id = from.map_or(NOBODY, |(_, a)| a.id);
        let aad = Self::signed_part(&to.id, &from_id, &ct, &nonce, &[]);
        let body = chacha20poly1305::seal(&shared, &nonce, &aad, &plain.0);
        let sig = match from {
            Some((key, _)) => key.sign(&Self::signed_part(&to.id, &from_id, &ct, &nonce, &body), PAYLOAD_CONTEXT),
            None => Vec::new(),
        };
        Some(Payload { to: to.id, from: from_id, ct, nonce, body, sig })
    }

    /// Opens a payload with the recipient's Kyber secret: `None` if it was
    /// not sealed to it, is malformed, or a named sender's announce or
    /// signature does not hold at time `now`.
    pub fn open(&self, kyber: &mlkem::SecretKey, now: u64) -> Option<Opened> {
        let shared = kyber.decapsulate(&self.ct)?;
        let aad = Self::signed_part(&self.to, &self.from, &self.ct, &self.nonce, &[]);
        let plain = chacha20poly1305::open(&shared, &self.nonce, &aad, &self.body)?;
        let mut r = Reader(&plain);
        let kind = r.take(1)?[0];
        let named = r.take(1)?[0];
        let from = match named {
            0 => None,
            1 => Some(Announce::get(&mut r)?),
            _ => return None,
        };
        let inner = r.0.to_vec();
        match &from {
            None => {
                if self.from != NOBODY || !self.sig.is_empty() {
                    return None;
                }
            }
            Some(a) => {
                if a.id != self.from
                    || !a.verify(now)
                    || !mldsa::verify(
                        &a.dilithium,
                        &Self::signed_part(&self.to, &self.from, &self.ct, &self.nonce, &self.body),
                        PAYLOAD_CONTEXT,
                        &self.sig,
                    )
                {
                    return None;
                }
            }
        }
        Some(Opened { from, kind, inner })
    }

    fn put(&self, w: &mut Writer) {
        w.digest(&self.to);
        w.digest(&self.from);
        w.0.extend_from_slice(&self.ct);
        w.0.extend_from_slice(&self.nonce);
        w.u32(self.body.len() as u32);
        w.0.extend_from_slice(&self.body);
        w.0.extend_from_slice(&self.sig);
    }

    fn get(r: &mut Reader) -> Option<Payload> {
        let to = r.digest()?;
        let from = r.digest()?;
        let ct = r.take(mlkem::CT_LEN)?.to_vec();
        let nonce: [u8; 12] = r.take(12)?.try_into().unwrap();
        let len = r.u32()? as usize;
        if len > MAX_OBJECT {
            return None;
        }
        let body = r.take(len)?.to_vec();
        let sig = if from == NOBODY { Vec::new() } else { r.take(mldsa::SIG_LEN)?.to_vec() };
        Some(Payload { to, from, ct, nonce, body, sig })
    }
}

/// What travels as one object through the chunked transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object {
    Announce(Announce),
    Payload(Payload),
}

impl Object {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(Announce::FIXED + 64);
        match self {
            Object::Announce(a) => {
                w.0.push(TAG_ANNOUNCE);
                a.put(&mut w);
            }
            Object::Payload(p) => {
                w.0.push(TAG_PAYLOAD);
                p.put(&mut w);
            }
        }
        w.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Object> {
        if bytes.len() > MAX_OBJECT {
            return None;
        }
        let mut r = Reader(bytes);
        let o = match r.take(1)?[0] {
            TAG_ANNOUNCE => Object::Announce(Announce::get(&mut r)?),
            TAG_PAYLOAD => Object::Payload(Payload::get(&mut r)?),
            _ => return None,
        };
        r.is_empty().then_some(o)
    }

    /// The id an object is fetched by: a hash of its bytes.
    pub fn id_of(bytes: &[u8]) -> Digest {
        hash_domain(DOM_OBJECT, &crate::pow::pack_bytes(bytes))
    }
}

/// A participant's rendezvous points among `n` nodes sorted by id (or by
/// address, in init mode): the indexes `H(id ‖ k)` for `k` from 0 on,
/// each reduced modulo `n`, skipping repeats, [`RENDEZVOUS`] of them or
/// every node when there are fewer.
pub fn rendezvous_indexes(id: &Digest, n: usize) -> Vec<usize> {
    let mut out = Vec::with_capacity(RENDEZVOUS);
    if n == 0 {
        return out;
    }
    let want = RENDEZVOUS.min(n);
    let mut k = 0u32;
    while out.len() < want {
        let mut input = [Fp::ZERO; 9];
        input[..8].copy_from_slice(id);
        input[8] = Fp::new(k);
        let h = hash_domain(DOM_RENDEZVOUS, &input);
        let bytes = digest_to_bytes(&h);
        let x = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let i = (x % n as u64) as usize;
        if !out.contains(&i) {
            out.push(i);
        }
        k += 1;
    }
    out
}

/// A participant's rendezvous points among the listed relays, by
/// rendezvous (highest random weight) hashing: every relay is weighed by
/// `H(id ‖ relay id)` and the [`RENDEZVOUS`] heaviest are the points,
/// heaviest first. Adding or removing a relay moves only the ids that had
/// it among their points, unlike reducing a hash modulo the number of
/// relays. Returns indexes into `relays`.
pub fn rendezvous_relays(id: &Digest, relays: &[Digest]) -> Vec<usize> {
    let weight = |r: &Digest| {
        let mut input = [Fp::ZERO; 16];
        input[..8].copy_from_slice(id);
        input[8..].copy_from_slice(r);
        let bytes = digest_to_bytes(&hash_domain(DOM_WEIGHT, &input));
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    };
    let mut ranked: Vec<(u64, usize)> = relays.iter().enumerate().map(|(i, r)| (weight(r), i)).collect();
    ranked.sort_by(|a, b| b.cmp(a));
    ranked.into_iter().take(RENDEZVOUS).map(|(_, i)| i).collect()
}

/// A digest's canonical text for logs: its address form.
pub fn short(id: &Digest) -> String {
    let a = address::encode(id);
    format!("{}…{}", &a[..10], &a[a.len() - 6..])
}

/// Parses an id written as a `tab1…` address or 64 hex digits.
pub fn parse_id(s: &str) -> Option<Digest> {
    if let Some(id) = address::decode(s) {
        return Some(id);
    }
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect();
    digest_from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(tag: u8) -> (mldsa::SecretKey, mlkem::SecretKey) {
        (mldsa::keygen(&[tag; 32]), mlkem::keygen(&[tag; 64]))
    }

    #[test]
    fn announces_verify_and_round_trip() {
        let (d, k) = keys(1);
        let a = Announce::make(&d, k.public_key(), 3, 1000, 77);
        assert_eq!(a.id, address::id_of(d.public_key()));
        assert!(a.verify(999));
        assert!(!a.verify(1000), "expired");
        let bytes = Object::Announce(a.clone()).to_bytes();
        assert_eq!(bytes.len(), 1 + Announce::FIXED);
        assert_eq!(Object::from_bytes(&bytes), Some(Object::Announce(a.clone())));
        assert_eq!(Announce::from_bytes(&a.to_bytes()), Some(a.clone()));
        assert_eq!(Object::from_bytes(&bytes[..bytes.len() - 1]), None);
        // Any change breaks it: the nonce, the key, the id.
        let mut t = a.clone();
        t.nonce = 78;
        assert!(!t.verify(0));
        let mut t = a.clone();
        t.kyber = keys(2).1.public_key().to_vec();
        assert!(!t.verify(0));
        let mut t = a.clone();
        t.id = [Fp::new(1); 8];
        assert!(!t.verify(0));
        let mut t = a.clone();
        t.kyber[0] = 0xff;
        t.kyber[1] = 0x0f;
        assert!(!t.verify(0));
    }

    #[test]
    fn payloads_open_only_for_the_recipient() {
        let (rd, rk) = keys(1);
        let (sd, sk) = keys(2);
        let recipient = Announce::make(&rd, rk.public_key(), 1, 1000, 5);
        let sender = Announce::make(&sd, sk.public_key(), 1, 1000, 0);
        let p = Payload::seal(&recipient, Some((&sd, &sender)), 7, b"hello", &[9u8; 32], [1u8; 12]).unwrap();
        assert_eq!(p.to, recipient.id);
        assert_eq!(p.from, sender.id);
        assert_eq!(p.sig.len(), mldsa::SIG_LEN);
        let o = p.open(&rk, 500).unwrap();
        assert_eq!(o, Opened { from: Some(sender.clone()), kind: 7, inner: b"hello".to_vec() });
        assert_eq!(p.open(&sk, 500), None, "another key");
        assert_eq!(p.open(&rk, 1000), None, "the sender's announce expired");
        let bytes = Object::Payload(p.clone()).to_bytes();
        assert_eq!(Object::from_bytes(&bytes), Some(Object::Payload(p.clone())));
        // Tampering with any field fails to open.
        let mut t = p.clone();
        t.body[3] ^= 1;
        assert_eq!(t.open(&rk, 500), None);
        let mut t = p.clone();
        t.from = NOBODY;
        assert_eq!(t.open(&rk, 500), None);
        let mut t = p.clone();
        t.sig[10] ^= 1;
        assert_eq!(t.open(&rk, 500), None);
        let mut t = p.clone();
        t.nonce[0] ^= 1;
        assert_eq!(t.open(&rk, 500), None);
        // An anonymous payload: no announce inside, no signature.
        let p = Payload::seal(&recipient, None, 2, b"anon", &[3u8; 32], [2u8; 12]).unwrap();
        assert_eq!(p.from, NOBODY);
        assert!(p.sig.is_empty());
        assert_eq!(p.open(&rk, 500), Some(Opened { from: None, kind: 2, inner: b"anon".to_vec() }));
        let bytes = Object::Payload(p.clone()).to_bytes();
        assert_eq!(Object::from_bytes(&bytes), Some(Object::Payload(p)));
        // Objects have ids; a malformed recipient key cannot be sealed to.
        assert_ne!(Object::id_of(&bytes), Object::id_of(&bytes[1..]));
        let mut bad = recipient.clone();
        bad.kyber.truncate(10);
        assert!(Payload::seal(&bad, None, 0, b"", &[0u8; 32], [0u8; 12]).is_none());
    }

    #[test]
    fn rendezvous_points_are_distinct_and_deterministic() {
        let id = address::id_of(keys(1).0.public_key());
        let r = rendezvous_indexes(&id, 10);
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|i| *i < 10));
        assert_eq!(r.iter().collect::<std::collections::HashSet<_>>().len(), 3);
        assert_eq!(rendezvous_indexes(&id, 10), r);
        assert_eq!(rendezvous_indexes(&id, 2).len(), 2);
        assert_eq!(rendezvous_indexes(&id, 1), vec![0]);
        assert_eq!(rendezvous_indexes(&id, 0), Vec::<usize>::new());
        let other = address::id_of(keys(2).0.public_key());
        assert_ne!(rendezvous_indexes(&other, 1000), rendezvous_indexes(&id, 1000));
        assert_eq!(parse_id(&address::encode(&id)), Some(id));
        let hex: String = digest_to_bytes(&id).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_id(&hex), Some(id));
        assert_eq!(parse_id("nope"), None);
        // Weighed: a relay added or removed moves only the ids that had it.
        let relays: Vec<Digest> = (0..20u8).map(|t| address::id_of(keys(100 + t).0.public_key())).collect();
        let ids: Vec<Digest> = (0..200u8).map(|t| address::id_of(&[t; 40])).collect();
        let points = |rs: &[Digest], id: &Digest| -> Vec<Digest> {
            rendezvous_relays(id, rs).into_iter().map(|i| rs[i]).collect()
        };
        let removed = &relays[1..];
        let mut moved = 0;
        for id in &ids {
            let before = points(&relays, id);
            assert_eq!(before.len(), 3);
            let after = points(removed, id);
            if before.contains(&relays[0]) {
                moved += 1;
                assert_eq!(after.iter().filter(|p| before.contains(p)).count(), 2);
            } else {
                assert_eq!(after, before, "an id that did not have the removed relay keeps its points");
            }
        }
        assert!(moved > 0 && moved < 80, "{moved}");
        assert_eq!(rendezvous_relays(&ids[0], &relays[..2]).len(), 2);
        assert!(short(&id).starts_with("tab1"));
    }
}
