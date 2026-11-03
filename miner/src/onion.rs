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
/// In onion mode, between keepalives on a session held over a circuit,
/// give or take a third (`docs/SCALING.md`): the circuit's channels keep
/// themselves alive, and a hop that dies destroys the circuit, which the
/// participant hears; the keepalive only catches a point that forgot it.
pub const CIRCUIT_KEEPALIVE_SECS: u64 = 15 * 60;
/// A session held over a circuit with no keepalive for this long is gone;
/// it ends with its circuit in any case.
pub const CIRCUIT_SESSION_TIMEOUT_SECS: u64 = 3 * CIRCUIT_KEEPALIVE_SECS;
/// How long a wallet's announce is valid: two hours. Its Kyber key is
/// replaced after half that, so a key decapsulates what anyone sends the
/// address for an hour at most (chosen ciphertexts for a timing attack).
pub const ANNOUNCE_LIFETIME_SECS: u64 = 2 * 3600;
/// Largest object: an announce is about 6.5 KB, a payload a slate plus
/// an announce.
pub const MAX_OBJECT: usize = 64 << 10;

/// A payload's kind: a payment slate (`crate::wallet::Slate`), answered
/// at stage 1 and finalized at stage 2.
pub const KIND_SLATE: u8 = 1;

const DOM_OBJECT: u32 = 19;
const DOM_RENDEZVOUS: u32 = 20;
const DOM_WEIGHT: u32 = 21;
const DOM_REPLY: u32 = 23;
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
        w.0.extend_from_slice(&Self::signed_part(
            &self.id,
            &self.dilithium,
            &self.kyber,
            self.seq,
            self.expiry,
            self.nonce,
        ));
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

/// The way back to a sender that does not name itself (`docs/PRIVACY.md`,
/// fix 4): the last relay of the circuit its payload came up, the token
/// that relay keeps for that circuit, and a Kyber key made for this one
/// answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub relay: Digest,
    pub token: [u8; crate::circuit::TOKEN_LEN],
    pub kyber: Vec<u8>,
}

impl Route {
    const SIZE: usize = 32 + crate::circuit::TOKEN_LEN + mlkem::EK_LEN;

    fn put(&self, w: &mut Writer) {
        w.digest(&self.relay);
        w.0.extend_from_slice(&self.token);
        w.0.extend_from_slice(&self.kyber);
    }

    fn get(r: &mut Reader) -> Option<Route> {
        let relay = r.digest()?;
        let token = r.take(crate::circuit::TOKEN_LEN)?.try_into().ok()?;
        let kyber = r.take(mlkem::EK_LEN)?.to_vec();
        Some(Route { relay, token, kyber })
    }

    /// The id an answer along the route is addressed to: a hash of its
    /// Kyber key, naming no one.
    pub fn reply_id(&self) -> Digest {
        reply_id(&self.kyber)
    }
}

/// The id of an answer sealed to the one-time Kyber key `kyber`.
pub fn reply_id(kyber: &[u8]) -> Digest {
    hash_domain(DOM_REPLY, &crate::pow::pack_bytes(kyber))
}

/// What a payload carries once opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The sender's announce, when it named itself; verified.
    pub from: Option<Announce>,
    /// The way back to the sender, when it gave one.
    pub route: Option<Route>,
    /// When this is the answer to a payload of ours, the id we sent that
    /// one to (only it could open it, so only it could answer).
    pub answers: Option<Digest>,
    pub kind: u8,
    pub inner: Vec<u8>,
}

/// A message to an id, sealed to its announced Kyber key. Only what
/// routing needs is in the clear (`docs/PRIVACY.md`, fix 1): a relay sees
/// whom a payload is for, never whom it is from. A named sender's
/// announce and signature travel inside the sealed body, as does a return
/// route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    pub to: Digest,
    /// The Kyber ciphertext.
    pub ct: Vec<u8>,
    pub nonce: [u8; chacha20poly1305::NONCE_LEN],
    /// Sealed: kind, flags (a return route, a named sender), the route,
    /// the sender's announce and its signature, then the inner bytes.
    pub body: Vec<u8>,
}

impl Payload {
    /// The associated data: what travels in the clear.
    fn aad(to: &Digest, ct: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
        let mut w = Writer::with_capacity(32 + ct.len() + 12);
        w.digest(to);
        w.0.extend_from_slice(ct);
        w.0.extend_from_slice(nonce);
        w.0
    }

    /// What a named sender signs: the clear part, then everything sealed
    /// but the signature (kind, flags, route, announce, inner bytes).
    fn signed_part(aad: &[u8], head: &[u8], inner: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(aad.len() + head.len() + inner.len());
        m.extend_from_slice(aad);
        m.extend_from_slice(head);
        m.extend_from_slice(inner);
        m
    }

    /// Seals `inner` of `kind` to `to`'s Kyber key. With `from`, the
    /// sender's announce (for the reply) and its signature go inside; with
    /// `route`, the way back to an unnamed sender. `m` is the
    /// encapsulation's randomness.
    pub fn seal(
        to: &Announce,
        from: Option<(&mldsa::SecretKey, &Announce)>,
        route: Option<&Route>,
        kind: u8,
        inner: &[u8],
        m: &[u8; 32],
        nonce: [u8; 12],
    ) -> Option<Payload> {
        Self::seal_to(&to.id, &to.kyber, from, route, kind, inner, m, nonce)
    }

    /// An answer along `route`: anonymous, sealed to its one-time key.
    pub fn seal_reply(route: &Route, kind: u8, inner: &[u8], m: &[u8; 32], nonce: [u8; 12]) -> Option<Payload> {
        Self::seal_to(&route.reply_id(), &route.kyber, None, None, kind, inner, m, nonce)
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_to(
        to: &Digest,
        kyber: &[u8],
        from: Option<(&mldsa::SecretKey, &Announce)>,
        route: Option<&Route>,
        kind: u8,
        inner: &[u8],
        m: &[u8; 32],
        nonce: [u8; 12],
    ) -> Option<Payload> {
        let (shared, ct) = mlkem::encapsulate_with(kyber, m)?;
        let aad = Self::aad(to, &ct, &nonce);
        let mut head = Writer::with_capacity(2 + Route::SIZE + Announce::FIXED);
        head.0.push(kind);
        head.0.push(u8::from(route.is_some()) | u8::from(from.is_some()) << 1);
        if let Some(r) = route {
            r.put(&mut head);
        }
        if let Some((_, announce)) = from {
            announce.put(&mut head);
        }
        let mut plain = head.0.clone();
        if let Some((key, _)) = from {
            plain.extend_from_slice(&key.sign(&Self::signed_part(&aad, &head.0, inner), PAYLOAD_CONTEXT));
        }
        plain.extend_from_slice(inner);
        let body = chacha20poly1305::seal(&shared, &nonce, &aad, &plain);
        Some(Payload { to: *to, ct, nonce, body })
    }

    /// Opens a payload with the recipient's Kyber secret: `None` if it was
    /// not sealed to it, is malformed, or a named sender's announce or
    /// signature does not hold at time `now`.
    pub fn open(&self, kyber: &mlkem::SecretKey, now: u64) -> Option<Opened> {
        let shared = kyber.decapsulate(&self.ct)?;
        let aad = Self::aad(&self.to, &self.ct, &self.nonce);
        let plain = chacha20poly1305::open(&shared, &self.nonce, &aad, &self.body)?;
        let mut r = Reader(&plain);
        let kind = r.take(1)?[0];
        let flags = r.take(1)?[0];
        if flags > 3 {
            return None;
        }
        let route = if flags & 1 == 1 { Some(Route::get(&mut r)?) } else { None };
        let from = if flags & 2 == 2 {
            let announce = Announce::get(&mut r)?;
            let head = &plain[..plain.len() - r.0.len()];
            let sig = r.take(mldsa::SIG_LEN)?;
            let signed = Self::signed_part(&aad, head, r.0);
            if !announce.verify(now) || !mldsa::verify(&announce.dilithium, &signed, PAYLOAD_CONTEXT, sig) {
                return None;
            }
            Some(announce)
        } else {
            None
        };
        Some(Opened { from, route, answers: None, kind, inner: r.0.to_vec() })
    }

    fn put(&self, w: &mut Writer) {
        w.digest(&self.to);
        w.0.extend_from_slice(&self.ct);
        w.0.extend_from_slice(&self.nonce);
        w.u32(self.body.len() as u32);
        w.0.extend_from_slice(&self.body);
    }

    fn get(r: &mut Reader) -> Option<Payload> {
        let to = r.digest()?;
        let ct = r.take(mlkem::CT_LEN)?.to_vec();
        let nonce: [u8; 12] = r.take(12)?.try_into().unwrap();
        let len = r.u32()? as usize;
        if len > MAX_OBJECT {
            return None;
        }
        let body = r.take(len)?.to_vec();
        Some(Payload { to, ct, nonce, body })
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

/// The rendezvous epoch at main-chain height `height`: the counter of
/// [`crate::consensus::EPOCH`]-block windows. Points are chosen afresh
/// each epoch (`docs/SUBNAMES.md`, section 2), from height alone, so a
/// reorganization never moves them.
pub fn rendezvous_epoch(height: u32) -> u32 {
    height / crate::consensus::EPOCH
}

/// A participant's rendezvous points in `epoch` among `n` nodes sorted by
/// id (or by address, in init mode): the indexes `H(id ‖ epoch ‖ k)` for
/// `k` from 0 on, each reduced modulo `n`, skipping repeats,
/// [`RENDEZVOUS`] of them or every node when there are fewer.
pub fn rendezvous_indexes(id: &Digest, epoch: u32, n: usize) -> Vec<usize> {
    let mut out = Vec::with_capacity(RENDEZVOUS);
    if n == 0 {
        return out;
    }
    let want = RENDEZVOUS.min(n);
    let mut k = 0u32;
    while out.len() < want {
        let mut input = [Fp::ZERO; 10];
        input[..8].copy_from_slice(id);
        input[8] = Fp::new(epoch);
        input[9] = Fp::new(k);
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
/// rendezvous (highest random weight) hashing: in `epoch` every relay is
/// weighed by `H(id ‖ epoch ‖ relay id)` and the [`RENDEZVOUS`] heaviest
/// are the points, heaviest first. Adding or removing a relay moves only
/// the ids that had it among their points, unlike reducing a hash modulo
/// the number of relays; a new epoch moves them all, so no relay is an
/// id's point for good. Returns indexes into `relays`.
pub fn rendezvous_relays(id: &Digest, epoch: u32, relays: &[Digest]) -> Vec<usize> {
    let weight = |r: &Digest| {
        let mut input = [Fp::ZERO; 17];
        input[..8].copy_from_slice(id);
        input[8] = Fp::new(epoch);
        input[9..].copy_from_slice(r);
        let bytes = digest_to_bytes(&hash_domain(DOM_WEIGHT, &input));
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    };
    let mut ranked: Vec<(u64, usize)> = relays.iter().enumerate().map(|(i, r)| (weight(r), i)).collect();
    ranked.sort_by(|a, b| b.cmp(a));
    ranked.into_iter().take(RENDEZVOUS).map(|(_, i)| i).collect()
}

/// Stage-1 slates a wallet answers from one sender, and in all, within
/// [`SLATE_WINDOW`]: answering creates an output, so anyone who knows an
/// address could otherwise make its wallet create them at will.
pub const SLATES_PER_SENDER: usize = 5;
pub const SLATES_TOTAL: usize = 60;
pub const SLATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

/// Counts what was answered, to refuse what is over the limits.
#[derive(Debug, Default)]
pub struct SlateLimit {
    answered: std::collections::VecDeque<(Digest, std::time::Instant)>,
}

impl SlateLimit {
    /// Whether a stage-1 slate from `from` may be answered now; if so, it
    /// is counted.
    pub fn allow(&mut self, from: &Digest, now: std::time::Instant) -> bool {
        while self.answered.front().is_some_and(|(_, t)| now.duration_since(*t) >= SLATE_WINDOW) {
            self.answered.pop_front();
        }
        if self.answered.len() >= SLATES_TOTAL
            || self.answered.iter().filter(|(f, _)| f == from).count() >= SLATES_PER_SENDER
        {
            return false;
        }
        self.answered.push_back((*from, now));
        true
    }
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
        let p = Payload::seal(&recipient, Some((&sd, &sender)), None, 7, b"hello", &[9u8; 32], [1u8; 12]).unwrap();
        assert_eq!(p.to, recipient.id);
        // Nothing of the sender's in the clear: not its id, not its key.
        let bytes = Object::Payload(p.clone()).to_bytes();
        let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(&crate::poseidon2::digest_to_bytes(&sender.id)));
        assert!(!contains(&sender.dilithium[..64]));
        assert!(contains(&crate::poseidon2::digest_to_bytes(&recipient.id)));
        let o = p.open(&rk, 500).unwrap();
        assert_eq!(
            o,
            Opened { from: Some(sender.clone()), route: None, answers: None, kind: 7, inner: b"hello".to_vec() }
        );
        assert_eq!(p.open(&sk, 500), None, "another key");
        assert_eq!(p.open(&rk, 1000), None, "the sender's announce expired");
        let bytes = Object::Payload(p.clone()).to_bytes();
        assert_eq!(Object::from_bytes(&bytes), Some(Object::Payload(p.clone())));
        // Tampering with any field fails to open.
        let mut t = p.clone();
        t.body[3] ^= 1;
        assert_eq!(t.open(&rk, 500), None);
        let mut t = p.clone();
        t.nonce[0] ^= 1;
        assert_eq!(t.open(&rk, 500), None);
        let mut t = p.clone();
        t.to = sender.id;
        assert_eq!(t.open(&rk, 500), None);
        // A signature that does not hold, sealed properly all the same.
        let other = Announce::make(&keys(3).0, sk.public_key(), 1, 1000, 0);
        let forged = Payload::seal(&recipient, Some((&sd, &other)), None, 7, b"hello", &[9u8; 32], [1u8; 12]).unwrap();
        assert_eq!(forged.open(&rk, 500), None);
        // An anonymous payload: no announce inside, no signature.
        let p = Payload::seal(&recipient, None, None, 2, b"anon", &[3u8; 32], [2u8; 12]).unwrap();
        assert_eq!(
            p.open(&rk, 500),
            Some(Opened { from: None, route: None, answers: None, kind: 2, inner: b"anon".to_vec() })
        );
        let bytes = Object::Payload(p.clone()).to_bytes();
        assert_eq!(Object::from_bytes(&bytes), Some(Object::Payload(p)));
        // Objects have ids; a malformed recipient key cannot be sealed to.
        assert_ne!(Object::id_of(&bytes), Object::id_of(&bytes[1..]));
        let mut bad = recipient.clone();
        bad.kyber.truncate(10);
        assert!(Payload::seal(&bad, None, None, 0, b"", &[0u8; 32], [0u8; 12]).is_none());
    }

    #[test]
    fn slates_are_answered_within_limits() {
        let t = std::time::Instant::now();
        let mut l = SlateLimit::default();
        let a = [Fp::new(1); 8];
        for _ in 0..SLATES_PER_SENDER {
            assert!(l.allow(&a, t));
        }
        assert!(!l.allow(&a, t), "too many from one sender");
        // Others still are, up to the total.
        for i in 0..(SLATES_TOTAL - SLATES_PER_SENDER) as u32 {
            assert!(l.allow(&[Fp::new(i + 2); 8], t));
        }
        assert!(!l.allow(&[Fp::new(9999); 8], t), "the total");
        // A window later, all over again.
        assert!(l.allow(&a, t + SLATE_WINDOW));
    }

    #[test]
    fn rendezvous_points_are_distinct_and_deterministic() {
        let id = address::id_of(keys(1).0.public_key());
        let r = rendezvous_indexes(&id, 0, 10);
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|i| *i < 10));
        assert_eq!(r.iter().collect::<std::collections::HashSet<_>>().len(), 3);
        assert_eq!(rendezvous_indexes(&id, 0, 10), r);
        assert_eq!(rendezvous_indexes(&id, 0, 2).len(), 2);
        assert_eq!(rendezvous_indexes(&id, 0, 1), vec![0]);
        assert_eq!(rendezvous_indexes(&id, 0, 0), Vec::<usize>::new());
        let other = address::id_of(keys(2).0.public_key());
        assert_ne!(rendezvous_indexes(&other, 0, 1000), rendezvous_indexes(&id, 0, 1000));
        assert_eq!(parse_id(&address::encode(&id)), Some(id));
        let hex: String = digest_to_bytes(&id).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_id(&hex), Some(id));
        assert_eq!(parse_id("nope"), None);
        // Weighed: a relay added or removed moves only the ids that had it.
        let relays: Vec<Digest> = (0..20u8).map(|t| address::id_of(keys(100 + t).0.public_key())).collect();
        let ids: Vec<Digest> = (0..200u8).map(|t| address::id_of(&[t; 40])).collect();
        let points = |rs: &[Digest], id: &Digest| -> Vec<Digest> {
            rendezvous_relays(id, 0, rs).into_iter().map(|i| rs[i]).collect()
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
        assert_eq!(rendezvous_relays(&ids[0], 0, &relays[..2]).len(), 2);
        assert!(short(&id).starts_with("tab1"));
    }

    #[test]
    fn rendezvous_points_move_each_epoch() {
        assert_eq!(rendezvous_epoch(0), 0);
        assert_eq!(rendezvous_epoch(143), 0);
        assert_eq!(rendezvous_epoch(144), 1);
        assert_eq!(rendezvous_epoch(300), 2);
        let relays: Vec<Digest> = (0..20u8).map(|t| address::id_of(keys(100 + t).0.public_key())).collect();
        let ids: Vec<Digest> = (0..100u8).map(|t| address::id_of(&[t; 40])).collect();
        let points = |id: &Digest, e: u32| -> Vec<Digest> {
            rendezvous_relays(id, e, &relays).into_iter().map(|i| relays[i]).collect()
        };
        // The same epoch, the same points; the next, nearly always others.
        let mut moved = 0;
        for id in &ids {
            assert_eq!(points(id, 7), points(id, 7));
            if points(id, 7) != points(id, 8) {
                moved += 1;
            }
        }
        assert!(moved > 90, "{moved}");
        // Init mode's seeds too.
        let moved = ids.iter().filter(|id| rendezvous_indexes(id, 7, 1000) != rendezvous_indexes(id, 8, 1000)).count();
        assert_eq!(moved, ids.len());
    }
}
