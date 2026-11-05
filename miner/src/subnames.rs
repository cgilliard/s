//! Sub-names (`docs/SUBNAME_CERT.md`): `label.name` resolved off chain.
//!
//! The holder of an id (the key whose hash it is) may publish a
//! [`Delegation`] at its rendezvous points naming up to [`MAX_ISSUERS`]
//! issuers by id, for every name whose value on chain is that id. A
//! [`Cert`] says what one label of a name is (an id, or none), signed by
//! the name's owner itself or by an issuer its delegation names: see
//! [`Cert::verify_for`]. The holder publishes it at the full name's own
//! rendezvous points ([`Cert::point`]); the highest `seq` counts.
//! Both carry the signer's Dilithium key, so each is checked alone: by
//! one hash against the id it must have and one signature.
//!
//! Until the server path goes (docs/SUBNAME_CERT.md, step 5), a server
//! also answers lookups with a [`Cert`] signed by its own key, checked as
//! one from an issuer.
//!
//! Pure data and cryptography; the node holds, serves and asks for them.

use crate::address;
use crate::codec::{Reader, Writer};
use crate::mldsa;
use crate::names::valid_name;
use crate::poseidon2::{digest_from_bytes, digest_to_bytes};
use crate::xmss::Digest;

/// Issuers a delegation names, at most.
pub const MAX_ISSUERS: usize = 3;
/// The longest a delegation or a certificate may be valid. Expiry is not
/// how a sub-name is withdrawn (a `none` certificate with a higher `seq`
/// is); it bounds a compromised issuer's leftovers and a point that
/// missed a change (docs/SUBNAME_CERT.md, "Lifetimes").
pub const MAX_LIFETIME_SECS: u64 = 30 * 86400;
/// How long delegations and certificates are signed for: renewed every
/// [`RENEW_SECS`], so an owner or its issuer can be down for about six
/// days before its sub-names lapse.
pub const LIFETIME_SECS: u64 = 7 * 86400;
/// How often an issuer renews its certificates, and an owner its
/// delegation.
pub const RENEW_SECS: u64 = 86400;
/// Domain tag of a full name's point id: `H(DOM_SUBNAME_POINT ‖ label.name)`.
pub const DOM_SUBNAME_POINT: u32 = 25;
/// A certificate's type: no such label (how a sub-name is withdrawn).
pub const TYPE_NONE: u8 = 0;
/// A certificate's type: the label is an id to pay (32 bytes).
pub const TYPE_ID: u8 = 1;
/// The largest value a certificate carries, of any type.
pub const MAX_VALUE: usize = 256;

/// How long a server's answer is valid, and so cached: an entry changed
/// reaches resolvers within this.
pub const ANSWER_LIFETIME_SECS: u64 = 3600;

const DELEGATION_CONTEXT: &[u8] = b"tab-delegation";
const ANSWER_CONTEXT: &[u8] = b"tab-subname";

fn put_name(w: &mut Writer, name: &[u8]) {
    w.0.push(name.len() as u8);
    w.0.extend_from_slice(name);
}

fn get_name(r: &mut Reader) -> Option<Vec<u8>> {
    let n = r.take(1)?[0] as usize;
    let name = r.take(n)?;
    valid_name(name).then(|| name.to_vec())
}

/// Whether `expiry` is in force at `now` and not further off than
/// [`MAX_LIFETIME_SECS`].
fn in_force(expiry: u64, now: u64) -> bool {
    expiry > now && expiry - now <= MAX_LIFETIME_SECS
}

/// An id's sub-name issuers, signed by the id's key: for every name whose
/// value is the id. Certificates name their name, so one name's cannot
/// stand for another's; names pointing at one id share its issuers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegation {
    /// The owner's key: its hash is the names' value on chain.
    pub dilithium: Vec<u8>,
    /// Rises with every new delegation (the time in milliseconds, as
    /// announces use); a rendezvous point keeps the highest.
    pub seq: u64,
    /// Unix time after which it does not count.
    pub expiry: u64,
    /// 1 to [`MAX_ISSUERS`] distinct issuer ids.
    pub issuers: Vec<Digest>,
    pub sig: Vec<u8>,
}

impl Delegation {
    fn signed_part(dilithium: &[u8], seq: u64, expiry: u64, issuers: &[Digest]) -> Vec<u8> {
        let mut w = Writer::with_capacity(mldsa::PK_LEN + 17 + 32 * issuers.len());
        w.0.extend_from_slice(dilithium);
        w.u64(seq);
        w.u64(expiry);
        w.0.push(issuers.len() as u8);
        for s in issuers {
            w.0.extend_from_slice(&digest_to_bytes(s));
        }
        w.0
    }

    fn issuers_ok(issuers: &[Digest]) -> bool {
        (1..=MAX_ISSUERS).contains(&issuers.len()) && issuers.iter().enumerate().all(|(i, s)| !issuers[..i].contains(s))
    }

    /// Signs a delegation of `key`'s id to `issuers`; `None` for a
    /// malformed issuer list.
    pub fn make(key: &mldsa::SecretKey, seq: u64, expiry: u64, issuers: &[Digest]) -> Option<Delegation> {
        if !Self::issuers_ok(issuers) {
            return None;
        }
        let dilithium = key.public_key().to_vec();
        let sig = key.sign(&Self::signed_part(&dilithium, seq, expiry, issuers), DELEGATION_CONTEXT);
        Some(Delegation { dilithium, seq, expiry, issuers: issuers.to_vec(), sig })
    }

    /// The id of the key that signed it.
    pub fn owner(&self) -> Digest {
        address::id_of(&self.dilithium)
    }

    /// Whether it is a sound delegation of `value` (a name's value on
    /// chain) at time `now`: signed by the key `value` is the hash of, in
    /// force, and naming a well-formed issuer list.
    pub fn verify(&self, value: &Digest, now: u64) -> bool {
        self.owner() == *value
            && in_force(self.expiry, now)
            && Self::issuers_ok(&self.issuers)
            && mldsa::verify(
                &self.dilithium,
                &Self::signed_part(&self.dilithium, self.seq, self.expiry, &self.issuers),
                DELEGATION_CONTEXT,
                &self.sig,
            )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Self::signed_part(&self.dilithium, self.seq, self.expiry, &self.issuers);
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Delegation> {
        let mut r = Reader(bytes);
        let dilithium = r.take(mldsa::PK_LEN)?.to_vec();
        let seq = r.u64()?;
        let expiry = r.u64()?;
        let n = r.take(1)?[0] as usize;
        if !(1..=MAX_ISSUERS).contains(&n) {
            return None;
        }
        let issuers = (0..n).map(|_| digest_from_bytes(r.take(32)?)).collect::<Option<Vec<_>>>()?;
        let sig = r.take(mldsa::SIG_LEN)?.to_vec();
        r.is_empty().then_some(Delegation { dilithium, seq, expiry, issuers, sig })
    }
}

/// What a label resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// No such label.
    None,
    /// An id to pay.
    Id(Digest),
    /// A type this node does not know: not to be used.
    Other(u8),
}

/// What one label of a name is, signed by an issuer: the name's owner
/// itself, or one its delegation names ([`Cert::verify_for`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cert {
    pub name: Vec<u8>,
    pub label: Vec<u8>,
    /// [`TYPE_NONE`], [`TYPE_ID`], or one defined later.
    pub kind: u8,
    pub value: Vec<u8>,
    /// Rises with every renewal and change (the time in milliseconds); the
    /// highest counts ([`Cert::supersedes`]).
    pub seq: u64,
    /// Unix time after which it does not count; resolvers cache it until
    /// then at most.
    pub expiry: u64,
    /// The issuer's key: its hash is the name's value, or one of the
    /// issuers of the value's delegation.
    pub dilithium: Vec<u8>,
    pub sig: Vec<u8>,
}

impl Cert {
    #[allow(clippy::too_many_arguments)]
    fn signed_part(
        name: &[u8],
        label: &[u8],
        kind: u8,
        value: &[u8],
        seq: u64,
        expiry: u64,
        dilithium: &[u8],
    ) -> Vec<u8> {
        let mut w = Writer::with_capacity(2 + name.len() + label.len() + 3 + value.len() + 16 + mldsa::PK_LEN);
        put_name(&mut w, name);
        put_name(&mut w, label);
        w.0.push(kind);
        w.0.extend_from_slice(&(value.len() as u16).to_le_bytes());
        w.0.extend_from_slice(value);
        w.u64(seq);
        w.u64(expiry);
        w.0.extend_from_slice(dilithium);
        w.0
    }

    /// Whether `value` is well formed for `kind`: any value of a type not
    /// known here, within [`MAX_VALUE`].
    fn value_ok(kind: u8, value: &[u8]) -> bool {
        match kind {
            TYPE_NONE => value.is_empty(),
            TYPE_ID => value.len() == 32 && digest_from_bytes(value).is_some(),
            _ => value.len() <= MAX_VALUE,
        }
    }

    /// Signs a certificate for `label.name` by the issuer key `key`; `None`
    /// for a malformed name, label or value.
    #[allow(clippy::too_many_arguments)]
    pub fn make(
        key: &mldsa::SecretKey,
        name: &[u8],
        label: &[u8],
        kind: u8,
        value: &[u8],
        seq: u64,
        expiry: u64,
    ) -> Option<Cert> {
        if !valid_name(name) || !valid_name(label) || !Self::value_ok(kind, value) {
            return None;
        }
        let dilithium = key.public_key().to_vec();
        let sig = key.sign(&Self::signed_part(name, label, kind, value, seq, expiry, &dilithium), ANSWER_CONTEXT);
        Some(Cert {
            name: name.to_vec(),
            label: label.to_vec(),
            kind,
            value: value.to_vec(),
            seq,
            expiry,
            dilithium,
            sig,
        })
    }

    /// A certificate that `label.name` is `id`.
    pub fn id(key: &mldsa::SecretKey, name: &[u8], label: &[u8], id: &Digest, seq: u64, expiry: u64) -> Option<Cert> {
        Self::make(key, name, label, TYPE_ID, &digest_to_bytes(id), seq, expiry)
    }

    /// A certificate that `name` has no label `label`.
    pub fn none(key: &mldsa::SecretKey, name: &[u8], label: &[u8], seq: u64, expiry: u64) -> Option<Cert> {
        Self::make(key, name, label, TYPE_NONE, &[], seq, expiry)
    }

    /// The id of the issuer that signed it.
    pub fn issuer(&self) -> Digest {
        address::id_of(&self.dilithium)
    }

    /// Whether it is a sound certificate for `label.name` at time `now`
    /// from one of `issuers`: for that label, in force, well formed and
    /// signed.
    pub fn verify(&self, name: &[u8], label: &[u8], issuers: &[Digest], now: u64) -> bool {
        self.name == name
            && self.label == label
            && issuers.contains(&self.issuer())
            && in_force(self.expiry, now)
            && Self::value_ok(self.kind, &self.value)
            && mldsa::verify(&self.dilithium, &self.signed(), ANSWER_CONTEXT, &self.sig)
    }

    /// Whether it is a sound certificate for `label.name`, whose value on
    /// chain is `value`, at time `now`: signed by `value`'s own key, or by
    /// an issuer `delegation` names, when that is a sound delegation of
    /// `value`. A resolver passes the delegation only when the issuer is
    /// not the owner itself.
    pub fn verify_for(
        &self,
        name: &[u8],
        label: &[u8],
        value: &Digest,
        delegation: Option<&Delegation>,
        now: u64,
    ) -> bool {
        let issuer = self.issuer();
        let authorized = issuer == *value
            || delegation.is_some_and(|d| d.issuers.contains(&issuer) && d.verify(value, now));
        authorized && self.verify(name, label, &[issuer], now)
    }

    /// Whether it takes the place of `other`, a certificate for the same
    /// label: a higher `seq` wins, renewals, changes and withdrawals alike.
    pub fn supersedes(&self, other: &Cert) -> bool {
        self.seq > other.seq
    }

    /// The id whose rendezvous points hold `label.name`'s certificate:
    /// ranked as any id's are, so they rotate by epoch.
    pub fn point(name: &[u8], label: &[u8]) -> Digest {
        let full = [label, b".", name].concat();
        crate::transaction::hash_domain(DOM_SUBNAME_POINT, &crate::pow::pack_bytes(&full))
    }

    fn signed(&self) -> Vec<u8> {
        Self::signed_part(&self.name, &self.label, self.kind, &self.value, self.seq, self.expiry, &self.dilithium)
    }

    /// What the label resolves to (of a verified certificate).
    pub fn entry(&self) -> Entry {
        match self.kind {
            TYPE_NONE => Entry::None,
            TYPE_ID if self.value.len() == 32 => {
                digest_from_bytes(&self.value).map_or(Entry::Other(TYPE_ID), Entry::Id)
            }
            k => Entry::Other(k),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.signed();
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Cert> {
        let mut r = Reader(bytes);
        let name = get_name(&mut r)?;
        let label = get_name(&mut r)?;
        let kind = r.take(1)?[0];
        let len = u16::from_le_bytes(r.take(2)?.try_into().ok()?) as usize;
        if len > MAX_VALUE {
            return None;
        }
        let value = r.take(len)?.to_vec();
        let seq = r.u64()?;
        let expiry = r.u64()?;
        let dilithium = r.take(mldsa::PK_LEN)?.to_vec();
        let sig = r.take(mldsa::SIG_LEN)?.to_vec();
        r.is_empty().then_some(Cert { name, label, kind, value, seq, expiry, dilithium, sig })
    }
}

/// A certificate as published and held: with the delegation naming its
/// issuer when the issuer is not the name's owner, so a point (and a
/// resolver) checks it against the chain alone, with no fetch of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub cert: Cert,
    pub delegation: Option<Delegation>,
}

impl Bundle {
    /// The id whose rendezvous points hold it.
    pub fn point(&self) -> Digest {
        Cert::point(&self.cert.name, &self.cert.label)
    }

    /// Whether it is sound for its name, whose value on chain is `value`,
    /// at time `now` ([`Cert::verify_for`]).
    pub fn verify(&self, value: &Digest, now: u64) -> bool {
        self.cert.verify_for(&self.cert.name, &self.cert.label, value, self.delegation.as_ref(), now)
    }

    /// Whether the certificate would still count under `newer`, a newer
    /// delegation of the name's value: always if the owner signed it.
    pub fn allowed_by(&self, value: &Digest, newer: &Delegation) -> bool {
        let issuer = self.cert.issuer();
        issuer == *value || newer.issuers.contains(&issuer)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let cert = self.cert.to_bytes();
        let mut w = Writer::with_capacity(4 + cert.len() + 4096);
        w.u32(cert.len() as u32);
        w.0.extend_from_slice(&cert);
        if let Some(d) = &self.delegation {
            w.0.extend_from_slice(&d.to_bytes());
        }
        w.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Bundle> {
        let mut r = Reader(bytes);
        let n = r.len(1)?;
        let cert = Cert::from_bytes(r.take(n)?)?;
        let delegation = if r.is_empty() { None } else { Some(Delegation::from_bytes(r.0)?) };
        Some(Bundle { cert, delegation })
    }
}

/// A query for `label.name`: the inner bytes of a payload of kind
/// [`crate::onion::KIND_SUBNAME_QUERY`] to the server, answered (along the
/// payload's way back, or to its named sender) by one of kind
/// [`crate::onion::KIND_SUBNAME_ANSWER`] whose inner bytes are an [`Cert`].
pub fn query(name: &[u8], label: &[u8]) -> Vec<u8> {
    let mut w = Writer::with_capacity(2 + name.len() + label.len());
    put_name(&mut w, name);
    put_name(&mut w, label);
    w.0
}

/// The name and label a query asks for.
pub fn parse_query(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut r = Reader(bytes);
    let name = get_name(&mut r)?;
    let label = get_name(&mut r)?;
    r.is_empty().then_some((name, label))
}

/// One name's sub-names, as a server holds them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Zone {
    /// Rises with every change (the time in milliseconds): every answer
    /// carries it, so a resolver keeps the newest.
    pub seq: u64,
    pub entries: std::collections::BTreeMap<Vec<u8>, Digest>,
}

/// What a server answers for, by name.
pub type Table = std::collections::HashMap<Vec<u8>, Zone>;

/// The server `key`'s answer to a query for `label.name` at time `now`:
/// the label's id, or none (for a name it does not hold too: harmless,
/// since only a server the name delegates to counts).
pub fn answer(key: &mldsa::SecretKey, table: &Table, name: &[u8], label: &[u8], now: u64) -> Option<Cert> {
    let zone = table.get(name);
    let seq = zone.map_or(0, |z| z.seq);
    let expiry = now + ANSWER_LIFETIME_SECS;
    match zone.and_then(|z| z.entries.get(label)) {
        Some(id) => Cert::id(key, name, label, id, seq, expiry),
        None => Cert::none(key, name, label, seq, expiry),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: u8) -> mldsa::SecretKey {
        mldsa::keygen(&[tag; 32])
    }

    fn id(tag: u8) -> Digest {
        address::id_of(key(tag).public_key())
    }

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn delegations_verify_only_for_their_owner_and_time() {
        let (owner, s1, s2) = (key(1), id(2), id(3));
        let d = Delegation::make(&owner, 5, NOW + 3600, &[s1, s2]).unwrap();
        crate::test_util::fuzz_decoder("Delegation::from_bytes", &[d.to_bytes()], 20_000, |b| {
            Delegation::from_bytes(b).map(|x| Some(x.to_bytes()))
        });
        assert!(d.verify(&id(1), NOW));
        assert_eq!(Delegation::from_bytes(&d.to_bytes()), Some(d.clone()));
        // Another value, or signed by a key that is not the value's.
        assert!(!d.verify(&id(9), NOW));
        let other = Delegation::make(&key(9), 5, NOW + 3600, &[s1]).unwrap();
        assert!(!other.verify(&id(1), NOW));
        // Expired, or valid for too long.
        assert!(!d.verify(&id(1), NOW + 3600));
        let long = Delegation::make(&owner, 5, NOW + MAX_LIFETIME_SECS + 1, &[s1]).unwrap();
        assert!(!long.verify(&id(1), NOW));
        // Forged: any signed field changed, or the signature.
        for f in [
            |d: &mut Delegation| d.seq += 1,
            |d: &mut Delegation| d.expiry += 1,
            |d: &mut Delegation| d.issuers[0] = id(7),
            |d: &mut Delegation| d.issuers.truncate(1),
            |d: &mut Delegation| d.sig[0] ^= 1,
        ] {
            let mut forged = d.clone();
            f(&mut forged);
            assert!(!forged.verify(&id(1), NOW), "{forged:?}");
        }
        // Malformed issuer lists are refused when made and read.
        assert!(Delegation::make(&owner, 5, NOW + 60, &[]).is_none());
        assert!(Delegation::make(&owner, 5, NOW + 60, &[s1, s1]).is_none());
        assert!(Delegation::make(&owner, 5, NOW + 60, &[s1, s2, id(4), id(5)]).is_none());
        let bytes = d.to_bytes();
        assert!(Delegation::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        assert!(Delegation::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_none());
    }

    #[test]
    fn answers_verify_only_from_a_named_server_for_their_label() {
        let server = key(2);
        let servers = [id(2), id(3)];
        let t = id(5);
        let a = Cert::id(&server, b"example", b"cool", &t, 9, NOW + 600).unwrap();
        crate::test_util::fuzz_decoder("Cert::from_bytes", &[a.to_bytes()], 20_000, |b| {
            Cert::from_bytes(b).map(|x| Some(x.to_bytes()))
        });
        assert!(a.verify(b"example", b"cool", &servers, NOW));
        assert_eq!(a.entry(), Entry::Id(t));
        assert_eq!(Cert::from_bytes(&a.to_bytes()), Some(a.clone()));
        // Another label or name, a server not named, out of time.
        assert!(!a.verify(b"example", b"cool2", &servers, NOW));
        assert!(!a.verify(b"other", b"cool", &servers, NOW));
        assert!(!a.verify(b"example", b"cool", &[id(3)], NOW));
        assert!(!a.verify(b"example", b"cool", &servers, NOW + 600));
        let long = Cert::id(&server, b"example", b"cool", &t, 9, NOW + MAX_LIFETIME_SECS + 1).unwrap();
        assert!(!long.verify(b"example", b"cool", &servers, NOW));
        // With no delegation the owner answers: its id is the only server.
        let own = Cert::id(&key(1), b"example", b"cool", &t, 9, NOW + 600).unwrap();
        assert!(own.verify(b"example", b"cool", &[id(1)], NOW));
        // Forged.
        for f in [
            |a: &mut Cert| a.value[0] ^= 1,
            |a: &mut Cert| a.seq += 1,
            |a: &mut Cert| a.expiry -= 1,
            |a: &mut Cert| a.label = b"cool2".to_vec(),
            |a: &mut Cert| a.kind = TYPE_NONE,
            |a: &mut Cert| a.sig[5] ^= 1,
        ] {
            let mut forged = a.clone();
            f(&mut forged);
            let label = forged.label.clone();
            assert!(!forged.verify(b"example", &label, &servers, NOW), "{forged:?}");
        }
        // None, and a type defined later: sound, but not an id.
        let none = Cert::none(&server, b"example", b"nope", 9, NOW + 600).unwrap();
        assert!(none.verify(b"example", b"nope", &servers, NOW));
        assert_eq!(none.entry(), Entry::None);
        let text = Cert::make(&server, b"example", b"site", 7, b"hello", 9, NOW + 600).unwrap();
        assert!(text.verify(b"example", b"site", &servers, NOW));
        assert_eq!(text.entry(), Entry::Other(7));
        // Malformed values and labels.
        assert!(Cert::make(&server, b"example", b"cool", TYPE_NONE, b"x", 9, NOW).is_none());
        assert!(Cert::make(&server, b"example", b"cool", TYPE_ID, &[0xff; 32], 9, NOW).is_none());
        assert!(Cert::make(&server, b"example", b"cool", 7, &[0; MAX_VALUE + 1], 9, NOW).is_none());
        assert!(Cert::make(&server, b"example", b"a.b", TYPE_NONE, &[], 9, NOW).is_none());
        let bytes = a.to_bytes();
        assert!(Cert::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        assert!(Cert::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_none());
    }

    /// docs/SUBNAME_CERT.md: a certificate counts when the name's owner
    /// signed it, or an issuer the owner's sound delegation names; the
    /// highest `seq` counts; lifetimes are a week, a month at most.
    #[test]
    fn certificates_verify_against_the_names_value_and_delegation() {
        let (owner, issuer) = (key(1), key(2));
        let value = id(1);
        let t = id(5);
        let life = NOW + LIFETIME_SECS;
        // Signed by the owner: the chain alone checks it.
        let c = Cert::id(&owner, b"example", b"cool", &t, 10, life).unwrap();
        assert!(c.verify_for(b"example", b"cool", &value, None, NOW));
        assert_eq!(c.entry(), Entry::Id(t));
        // By an issuer: only with the owner's sound delegation naming it.
        let by_issuer = Cert::id(&issuer, b"example", b"cool", &t, 11, life).unwrap();
        let d = Delegation::make(&owner, 1, life, &[id(2)]).unwrap();
        assert!(by_issuer.verify_for(b"example", b"cool", &value, Some(&d), NOW));
        assert!(!by_issuer.verify_for(b"example", b"cool", &value, None, NOW));
        let other_issuer = Delegation::make(&owner, 1, life, &[id(3)]).unwrap();
        assert!(!by_issuer.verify_for(b"example", b"cool", &value, Some(&other_issuer), NOW));
        // A delegation not the value's (another key's), or expired.
        let foreign = Delegation::make(&key(9), 1, life, &[id(2)]).unwrap();
        assert!(!by_issuer.verify_for(b"example", b"cool", &value, Some(&foreign), NOW));
        assert!(!by_issuer.verify_for(b"example", b"cool", &value, Some(&d), life));
        // After a transfer the name's value is another id: the old owner's
        // certificates stop counting.
        assert!(!c.verify_for(b"example", b"cool", &id(7), None, NOW));
        // An unauthorized key, another name or label.
        let rogue = Cert::id(&key(8), b"example", b"cool", &id(8), 99, life).unwrap();
        assert!(!rogue.verify_for(b"example", b"cool", &value, Some(&d), NOW));
        assert!(!c.verify_for(b"example", b"cool2", &value, None, NOW));
        assert!(!c.verify_for(b"other", b"cool", &value, None, NOW));
        // Lifetimes: a week is fine, past the month cap is not, for
        // certificates and delegations alike; expired is not.
        let month = Cert::id(&owner, b"example", b"cool", &t, 10, NOW + MAX_LIFETIME_SECS).unwrap();
        assert!(month.verify_for(b"example", b"cool", &value, None, NOW));
        let too_long = Cert::id(&owner, b"example", b"cool", &t, 10, NOW + MAX_LIFETIME_SECS + 1).unwrap();
        assert!(!too_long.verify_for(b"example", b"cool", &value, None, NOW));
        assert!(!c.verify_for(b"example", b"cool", &value, None, life));
        let long_d = Delegation::make(&owner, 1, NOW + MAX_LIFETIME_SECS + 1, &[id(2)]).unwrap();
        assert!(!by_issuer.verify_for(b"example", b"cool", &value, Some(&long_d), NOW));
        // Withdrawal: a `none` certificate with a higher seq takes the
        // place of the holder's; a lower one does not.
        let none = Cert::none(&owner, b"example", b"cool", 12, life).unwrap();
        assert!(none.verify_for(b"example", b"cool", &value, None, NOW));
        assert_eq!(none.entry(), Entry::None);
        assert!(none.supersedes(&c) && !c.supersedes(&none) && !c.supersedes(&c));
        // The point id is the full name's, distinct per label and name,
        // and not any id's.
        let p = Cert::point(b"example", b"cool");
        assert_eq!(p, Cert::point(b"example", b"cool"));
        assert_ne!(p, Cert::point(b"example", b"cool2"));
        assert_ne!(p, Cert::point(b"cool", b"example"));
        assert_ne!(Cert::point(b"ab", b"c"), Cert::point(b"b", b"ca"));
        assert_ne!(p, value);
    }

    #[test]
    fn bundles_carry_the_issuers_delegation() {
        let (owner, issuer) = (key(1), key(2));
        let life = NOW + LIFETIME_SECS;
        let own = Bundle { cert: Cert::id(&owner, b"example", b"cool", &id(5), 10, life).unwrap(), delegation: None };
        let d = Delegation::make(&owner, 3, life, &[id(2)]).unwrap();
        let by_issuer =
            Bundle { cert: Cert::id(&issuer, b"example", b"site", &id(6), 11, life).unwrap(), delegation: Some(d) };
        for b in [&own, &by_issuer] {
            assert_eq!(Bundle::from_bytes(&b.to_bytes()).as_ref(), Some(b));
            assert!(b.verify(&id(1), NOW));
            assert_eq!(b.point(), Cert::point(&b.cert.name, &b.cert.label));
        }
        crate::test_util::fuzz_decoder("Bundle::from_bytes", &[own.to_bytes(), by_issuer.to_bytes()], 20_000, |b| {
            Bundle::from_bytes(b).map(|x| Some(x.to_bytes()))
        });
        // Without its delegation an issuer's certificate does not count.
        let bare = Bundle { delegation: None, ..by_issuer.clone() };
        assert!(!bare.verify(&id(1), NOW));
        // A newer delegation without the issuer withdraws it; the owner's
        // own certificates stand under any.
        let newer = Delegation::make(&owner, 4, life, &[id(3)]).unwrap();
        assert!(!by_issuer.allowed_by(&id(1), &newer));
        assert!(own.allowed_by(&id(1), &newer));
    }

    #[test]
    fn a_server_answers_from_its_table() {
        let q = query(b"example", b"cool");
        assert_eq!(parse_query(&q), Some((b"example".to_vec(), b"cool".to_vec())));
        assert_eq!(parse_query(&q[..q.len() - 1]), None);
        assert_eq!(parse_query(&query(b"example", b"Cool")), None);
        let mut table = Table::new();
        let mut zone = Zone { seq: 42, ..Zone::default() };
        zone.entries.insert(b"cool".to_vec(), id(5));
        table.insert(b"example".to_vec(), zone);
        let a = answer(&key(2), &table, b"example", b"cool", NOW).unwrap();
        assert!(a.verify(b"example", b"cool", &[id(2)], NOW));
        assert_eq!((a.entry(), a.seq), (Entry::Id(id(5)), 42));
        let a = answer(&key(2), &table, b"example", b"nope", NOW).unwrap();
        assert_eq!((a.entry(), a.seq), (Entry::None, 42));
        let a = answer(&key(2), &table, b"other", b"cool", NOW).unwrap();
        assert_eq!((a.entry(), a.seq), (Entry::None, 0));
    }
}
