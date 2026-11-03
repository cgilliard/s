//! Sub-names (`docs/SUBNAMES.md`): `label.name` resolved off chain.
//!
//! The holder of an id (the key whose hash it is) may publish a
//! [`Delegation`] at its rendezvous points naming up to [`MAX_SERVERS`]
//! sub-name servers by id, for every name whose value on chain is that id;
//! with none, the id's own node is the server. A server answers a lookup of one label with an
//! [`Answer`] signed by its own key: the label's type and value, or none.
//! Both carry the signer's Dilithium key, so each is checked alone: by
//! one hash against the id it must have and one signature.
//!
//! Pure data and cryptography; the node holds, serves and asks for them.

use crate::address;
use crate::codec::{Reader, Writer};
use crate::mldsa;
use crate::names::valid_name;
use crate::poseidon2::{digest_from_bytes, digest_to_bytes};
use crate::xmss::Digest;

/// Servers a delegation names, at most: tried or raced in turn.
pub const MAX_SERVERS: usize = 3;
/// The longest a delegation or an answer may be valid: past this a
/// withdrawn server's answers stop counting. Owners republish delegations
/// every epoch (a day on mainnet), so two days leaves room.
pub const MAX_LIFETIME_SECS: u64 = 2 * 86400;
/// An answer's type: no such label.
pub const TYPE_NONE: u8 = 0;
/// An answer's type: the label is an id to pay (32 bytes).
pub const TYPE_ID: u8 = 1;
/// The largest value an answer carries, of any type.
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

/// An id's sub-name servers, signed by the id's key: for every name whose
/// value is the id. Answers name their name, so one name's answer cannot
/// stand for another's; names pointing at one id share its servers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegation {
    /// The owner's key: its hash is the names' value on chain.
    pub dilithium: Vec<u8>,
    /// Rises with every new delegation (the time in milliseconds, as
    /// announces use); a rendezvous point keeps the highest.
    pub seq: u64,
    /// Unix time after which it does not count.
    pub expiry: u64,
    /// 1 to [`MAX_SERVERS`] distinct server ids, the first tried first.
    pub servers: Vec<Digest>,
    pub sig: Vec<u8>,
}

impl Delegation {
    fn signed_part(dilithium: &[u8], seq: u64, expiry: u64, servers: &[Digest]) -> Vec<u8> {
        let mut w = Writer::with_capacity(mldsa::PK_LEN + 17 + 32 * servers.len());
        w.0.extend_from_slice(dilithium);
        w.u64(seq);
        w.u64(expiry);
        w.0.push(servers.len() as u8);
        for s in servers {
            w.0.extend_from_slice(&digest_to_bytes(s));
        }
        w.0
    }

    fn servers_ok(servers: &[Digest]) -> bool {
        (1..=MAX_SERVERS).contains(&servers.len()) && servers.iter().enumerate().all(|(i, s)| !servers[..i].contains(s))
    }

    /// Signs a delegation of `key`'s id to `servers`; `None` for a
    /// malformed server list.
    pub fn make(key: &mldsa::SecretKey, seq: u64, expiry: u64, servers: &[Digest]) -> Option<Delegation> {
        if !Self::servers_ok(servers) {
            return None;
        }
        let dilithium = key.public_key().to_vec();
        let sig = key.sign(&Self::signed_part(&dilithium, seq, expiry, servers), DELEGATION_CONTEXT);
        Some(Delegation { dilithium, seq, expiry, servers: servers.to_vec(), sig })
    }

    /// The id of the key that signed it.
    pub fn owner(&self) -> Digest {
        address::id_of(&self.dilithium)
    }

    /// Whether it is a sound delegation of `value` (a name's value on
    /// chain) at time `now`: signed by the key `value` is the hash of, in
    /// force, and naming a well-formed server list.
    pub fn verify(&self, value: &Digest, now: u64) -> bool {
        self.owner() == *value
            && in_force(self.expiry, now)
            && Self::servers_ok(&self.servers)
            && mldsa::verify(
                &self.dilithium,
                &Self::signed_part(&self.dilithium, self.seq, self.expiry, &self.servers),
                DELEGATION_CONTEXT,
                &self.sig,
            )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Self::signed_part(&self.dilithium, self.seq, self.expiry, &self.servers);
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Delegation> {
        let mut r = Reader(bytes);
        let dilithium = r.take(mldsa::PK_LEN)?.to_vec();
        let seq = r.u64()?;
        let expiry = r.u64()?;
        let n = r.take(1)?[0] as usize;
        if !(1..=MAX_SERVERS).contains(&n) {
            return None;
        }
        let servers = (0..n).map(|_| digest_from_bytes(r.take(32)?)).collect::<Option<Vec<_>>>()?;
        let sig = r.take(mldsa::SIG_LEN)?.to_vec();
        r.is_empty().then_some(Delegation { dilithium, seq, expiry, servers, sig })
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

/// A sub-name server's answer for one label, signed by the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub name: Vec<u8>,
    pub label: Vec<u8>,
    /// [`TYPE_NONE`], [`TYPE_ID`], or one defined later.
    pub kind: u8,
    pub value: Vec<u8>,
    /// Rises with every change of the entry (the time in milliseconds); a
    /// resolver keeps the highest it has seen.
    pub seq: u64,
    /// Unix time after which it does not count; resolvers cache it until
    /// then at most.
    pub expiry: u64,
    /// The server's key: its hash is one of the delegation's servers, or
    /// the name's value when there is no delegation.
    pub dilithium: Vec<u8>,
    pub sig: Vec<u8>,
}

impl Answer {
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

    /// Signs an answer for `label.name` by the server key `key`; `None`
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
    ) -> Option<Answer> {
        if !valid_name(name) || !valid_name(label) || !Self::value_ok(kind, value) {
            return None;
        }
        let dilithium = key.public_key().to_vec();
        let sig = key.sign(&Self::signed_part(name, label, kind, value, seq, expiry, &dilithium), ANSWER_CONTEXT);
        Some(Answer {
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

    /// An answer that `label.name` is `id`.
    pub fn id(key: &mldsa::SecretKey, name: &[u8], label: &[u8], id: &Digest, seq: u64, expiry: u64) -> Option<Answer> {
        Self::make(key, name, label, TYPE_ID, &digest_to_bytes(id), seq, expiry)
    }

    /// An answer that `name` has no label `label`.
    pub fn none(key: &mldsa::SecretKey, name: &[u8], label: &[u8], seq: u64, expiry: u64) -> Option<Answer> {
        Self::make(key, name, label, TYPE_NONE, &[], seq, expiry)
    }

    /// The id of the server that signed it.
    pub fn server(&self) -> Digest {
        address::id_of(&self.dilithium)
    }

    /// Whether it is a sound answer for `label.name` at time `now`, from
    /// one of `servers` (the delegation's, or the name's value alone when
    /// there is none): for that label, in force, well formed and signed.
    pub fn verify(&self, name: &[u8], label: &[u8], servers: &[Digest], now: u64) -> bool {
        self.name == name
            && self.label == label
            && servers.contains(&self.server())
            && in_force(self.expiry, now)
            && Self::value_ok(self.kind, &self.value)
            && mldsa::verify(&self.dilithium, &self.signed(), ANSWER_CONTEXT, &self.sig)
    }

    fn signed(&self) -> Vec<u8> {
        Self::signed_part(&self.name, &self.label, self.kind, &self.value, self.seq, self.expiry, &self.dilithium)
    }

    /// What the label resolves to (of a verified answer).
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

    pub fn from_bytes(bytes: &[u8]) -> Option<Answer> {
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
        r.is_empty().then_some(Answer { name, label, kind, value, seq, expiry, dilithium, sig })
    }
}

/// A query for `label.name`: the inner bytes of a payload of kind
/// [`crate::onion::KIND_SUBNAME_QUERY`] to the server, answered (along the
/// payload's way back, or to its named sender) by one of kind
/// [`crate::onion::KIND_SUBNAME_ANSWER`] whose inner bytes are an [`Answer`].
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
pub fn answer(key: &mldsa::SecretKey, table: &Table, name: &[u8], label: &[u8], now: u64) -> Option<Answer> {
    let zone = table.get(name);
    let seq = zone.map_or(0, |z| z.seq);
    let expiry = now + ANSWER_LIFETIME_SECS;
    match zone.and_then(|z| z.entries.get(label)) {
        Some(id) => Answer::id(key, name, label, id, seq, expiry),
        None => Answer::none(key, name, label, seq, expiry),
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
            |d: &mut Delegation| d.servers[0] = id(7),
            |d: &mut Delegation| d.servers.truncate(1),
            |d: &mut Delegation| d.sig[0] ^= 1,
        ] {
            let mut forged = d.clone();
            f(&mut forged);
            assert!(!forged.verify(&id(1), NOW), "{forged:?}");
        }
        // Malformed server lists are refused when made and read.
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
        let a = Answer::id(&server, b"example", b"cool", &t, 9, NOW + 600).unwrap();
        assert!(a.verify(b"example", b"cool", &servers, NOW));
        assert_eq!(a.entry(), Entry::Id(t));
        assert_eq!(Answer::from_bytes(&a.to_bytes()), Some(a.clone()));
        // Another label or name, a server not named, out of time.
        assert!(!a.verify(b"example", b"cool2", &servers, NOW));
        assert!(!a.verify(b"other", b"cool", &servers, NOW));
        assert!(!a.verify(b"example", b"cool", &[id(3)], NOW));
        assert!(!a.verify(b"example", b"cool", &servers, NOW + 600));
        let long = Answer::id(&server, b"example", b"cool", &t, 9, NOW + MAX_LIFETIME_SECS + 1).unwrap();
        assert!(!long.verify(b"example", b"cool", &servers, NOW));
        // With no delegation the owner answers: its id is the only server.
        let own = Answer::id(&key(1), b"example", b"cool", &t, 9, NOW + 600).unwrap();
        assert!(own.verify(b"example", b"cool", &[id(1)], NOW));
        // Forged.
        for f in [
            |a: &mut Answer| a.value[0] ^= 1,
            |a: &mut Answer| a.seq += 1,
            |a: &mut Answer| a.expiry -= 1,
            |a: &mut Answer| a.label = b"cool2".to_vec(),
            |a: &mut Answer| a.kind = TYPE_NONE,
            |a: &mut Answer| a.sig[5] ^= 1,
        ] {
            let mut forged = a.clone();
            f(&mut forged);
            let label = forged.label.clone();
            assert!(!forged.verify(b"example", &label, &servers, NOW), "{forged:?}");
        }
        // None, and a type defined later: sound, but not an id.
        let none = Answer::none(&server, b"example", b"nope", 9, NOW + 600).unwrap();
        assert!(none.verify(b"example", b"nope", &servers, NOW));
        assert_eq!(none.entry(), Entry::None);
        let text = Answer::make(&server, b"example", b"site", 7, b"hello", 9, NOW + 600).unwrap();
        assert!(text.verify(b"example", b"site", &servers, NOW));
        assert_eq!(text.entry(), Entry::Other(7));
        // Malformed values and labels.
        assert!(Answer::make(&server, b"example", b"cool", TYPE_NONE, b"x", 9, NOW).is_none());
        assert!(Answer::make(&server, b"example", b"cool", TYPE_ID, &[0xff; 32], 9, NOW).is_none());
        assert!(Answer::make(&server, b"example", b"cool", 7, &[0; MAX_VALUE + 1], 9, NOW).is_none());
        assert!(Answer::make(&server, b"example", b"a.b", TYPE_NONE, &[], 9, NOW).is_none());
        let bytes = a.to_bytes();
        assert!(Answer::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        assert!(Answer::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_none());
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
