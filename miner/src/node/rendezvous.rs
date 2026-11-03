//! Onion mode's rendezvous service (`docs/ONION.md`): a relay at the end
//! of a participant's circuit holds its session, and rendezvous points
//! pass lookups and payloads between them.
//!
//! # Over a participant's circuit
//!
//! Relay messages to the last hop, answered by relay messages from it:
//!
//! ```text
//! Session(id)          → SessionState(id, nonce, seq)   open or keep a session
//! Announce(announce)   → SessionState(id, nonce, seq)   the session's keys
//! GetAnnounce(id)      → Announce(announce) or Notice(id, offline)
//! Send(payload)        → Notice(object, forwarded or offline)
//!                        Deliver(payload)               to the recipient
//! Received(object)     (from the recipient: the payload arrived)
//! Publish(delegation)  → Notice(object, forwarded or rejected)
//! GetDelegation(id)    → Delegation(delegation) or Notice(id, offline)
//! Broadcast(tx)        → Notice(txid, forwarded or rejected)
//! Route(token)         (remembered for one answer, a couple of minutes)
//! Reply(relay, token, payload)
//!                      → Notice(object, forwarded or offline)
//!                        Deliver(payload)               down the token's circuit
//! ```
//!
//! A return route (`docs/PRIVACY.md`, fix 4) lets a recipient answer a
//! sender it cannot name: the sender's outbound circuit leaves a token at
//! its last relay, the payload carries that relay's id and the token, and
//! the answer goes up the recipient's own outbound circuit, relay to
//! relay to the token's, and down the sender's circuit.
//!
//! A broadcast transaction is pooled and announced by this relay as if
//! it were its own, so that its sender's address is never the first to
//! announce it.
//!
//! The nonce an announce must carry is this relay's SipHash of the
//! circuit and the id, so a session is bound to the circuit it was opened
//! on, as an init-mode session is bound to the participant's address. A
//! session lives while its circuit does and keepalives come.
//!
//! # Between rendezvous points
//!
//! `Rendezvous` cells on the relays' (mutual) channel, taken only from a
//! listed relay:
//!
//! ```text
//! Lookup(id)          → Found(announce) or Result(id, offline)
//! Forward(payload)    → Result(object, forwarded or offline)
//! Reply(token, payload) → Result(object, forwarded or offline)
//! Store(delegation)   (no answer)
//! Fetch(id)           → Held(delegation) or None(id)
//! ```
//!
//! A sub-name delegation (`docs/SUBNAMES.md`) is held by the owner's
//! points apart from its session, so it is found while the owner is
//! offline: a relay that takes one by `Publish` holds it if it is one of
//! the owner's points and passes it to the others by `Store` (to all of
//! them if it is not one, as when a server republishes it at the points
//! of a new epoch), and each keeps the highest sequence number until it
//! expires. `GetDelegation` asks the owner's points in turn, as a
//! lookup does, until one holds it.
//!
//! A sender's rendezvous point asks the recipient's points in the order
//! their id gives, itself first if it is one, until one holds a session;
//! it answers the sender when one does, or when none did.
//!
//! A payload counts as forwarded only once the recipient's node answers
//! the `Deliver` with `Received` (within [`ACK_WAIT`]): a payload sent
//! down a circuit that died unnoticed is reported offline, and the
//! sender's point tries the recipient's next point.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::Node;
use super::circuits::Link;
use crate::chain::ProofVerifier;
use crate::circuit::{self, Cell, Reassembly};
use crate::net::{NOTICE_FORWARDED, NOTICE_OFFLINE, NOTICE_REFUSED, NOTICE_REJECTED};
use crate::onion::{self, Announce, Object};
use crate::poseidon2::{digest_from_bytes, digest_to_bytes};
use crate::pow::Digest;
use crate::subnames::Delegation;

/// Messages between rendezvous points.
const LOOKUP: u8 = 1;
const FOUND: u8 = 2;
const FORWARD: u8 = 3;
const RESULT: u8 = 4;
const REPLY: u8 = 5;
const STORE: u8 = 6;
const FETCH: u8 = 7;
const HELD: u8 = 8;
const NONE: u8 = 9;

/// Between updates of one id's delegation, at least.
const DELEGATION_EVERY: Duration = Duration::from_secs(10);

/// How long a return route is kept.
const ROUTE_LIFETIME: Duration = Duration::from_secs(120);
/// Return routes a relay keeps; more are refused.
const MAX_ROUTES: usize = 10_000;

/// How long a recipient's point waits for `Received` after a `Deliver`.
const ACK_WAIT: Duration = Duration::from_secs(5);
/// How long a sender's rendezvous point waits on one of the recipient's:
/// longer than [`ACK_WAIT`].
const ASK_TIMEOUT: Duration = Duration::from_secs(12);
/// Questions out to other rendezvous points at once.
const MAX_ASKS: usize = 4096;
/// A session this relay holds over a circuit; its announce is in
/// [`Announces`].
struct Held {
    link: Link,
    seq: u64,
    seen: Instant,
}

/// Where a relay keeps its sessions' announces (`docs/SCALING.md`): in
/// an LMDB of its own in the data directory, `rendezvous`, apart from the
/// chain's so a block being applied never holds up the network thread,
/// and emptied at start (sessions do not outlive the process); in memory
/// when there is no data directory. Memory then holds only each session's
/// circuit, sequence number and time, about a hundred bytes.
#[derive(Default)]
pub(super) struct Announces {
    disk: Option<(heed::Env, [heed::Database<heed::types::Bytes, heed::types::Bytes>; 2])>,
    memory: [HashMap<Digest, Vec<u8>>; 2],
}

/// Which of [`Announces`]' tables: sessions' announces, or delegations.
#[derive(Clone, Copy)]
enum Table {
    Announce = 0,
    Delegation = 1,
}

impl Announces {
    /// The store in `dir`, emptied: an announce table, and one of
    /// delegations.
    pub(super) fn open(dir: &std::path::Path) -> Result<Announces, String> {
        let env = crate::state_tree::open_env(dir, 16 << 30).map_err(|e| e.to_string())?;
        let mut wtxn = env.write_txn().map_err(|e| e.to_string())?;
        let mut dbs = Vec::new();
        for name in ["announces", "delegations"] {
            let db: heed::Database<heed::types::Bytes, heed::types::Bytes> =
                env.create_database(&mut wtxn, Some(name)).map_err(|e| e.to_string())?;
            db.clear(&mut wtxn).map_err(|e| e.to_string())?;
            dbs.push(db);
        }
        wtxn.commit().map_err(|e| e.to_string())?;
        Ok(Announces { disk: Some((env, [dbs[0], dbs[1]])), memory: Default::default() })
    }

    fn put(&mut self, id: &Digest, bytes: &[u8]) -> Result<(), String> {
        self.put_in(Table::Announce, id, bytes)
    }

    fn get(&self, id: &Digest) -> Option<Vec<u8>> {
        self.get_in(Table::Announce, id)
    }

    fn remove(&mut self, id: &Digest) {
        self.remove_in(Table::Announce, id)
    }

    fn put_in(&mut self, t: Table, id: &Digest, bytes: &[u8]) -> Result<(), String> {
        let Some((env, dbs)) = &self.disk else {
            self.memory[t as usize].insert(*id, bytes.to_vec());
            return Ok(());
        };
        let mut wtxn = env.write_txn().map_err(|e| e.to_string())?;
        dbs[t as usize].put(&mut wtxn, &digest_to_bytes(id), bytes).map_err(|e| e.to_string())?;
        wtxn.commit().map_err(|e| e.to_string())
    }

    fn get_in(&self, t: Table, id: &Digest) -> Option<Vec<u8>> {
        let Some((env, dbs)) = &self.disk else {
            return self.memory[t as usize].get(id).cloned();
        };
        let rtxn = env.read_txn().ok()?;
        dbs[t as usize].get(&rtxn, &digest_to_bytes(id)).ok().flatten().map(<[u8]>::to_vec)
    }

    fn remove_in(&mut self, t: Table, id: &Digest) {
        let Some((env, dbs)) = &self.disk else {
            self.memory[t as usize].remove(id);
            return;
        };
        if let Ok(mut wtxn) = env.write_txn()
            && dbs[t as usize].delete(&mut wtxn, &digest_to_bytes(id)).is_ok()
        {
            let _ = wtxn.commit();
        }
    }
}

/// A delegation held, its bytes in [`Announces`]: its sequence number,
/// its expiry, and when it was last updated.
struct Delegated {
    seq: u64,
    expiry: u64,
    updated: Instant,
}

enum Asking {
    Lookup,
    /// The id's delegation.
    Delegation,
    /// The payload, and its object id.
    Forward(Vec<u8>, Digest),
    /// An answer along a return route: the token, the payload and its
    /// object id.
    Reply([u8; circuit::TOKEN_LEN], Vec<u8>, Digest),
}

/// Who hears whether a delivered payload arrived: the sender's circuit
/// (this relay is the sender's point too) or the sender's point.
#[derive(Clone, Copy)]
enum Waiter {
    Client(Link),
    Point((SocketAddr, u64)),
}

/// A sender's question to the recipient's rendezvous points.
struct Ask {
    /// The sender's circuit, where the answer goes.
    client: Link,
    to: Digest,
    what: Asking,
    /// The recipient's points not yet asked, in order.
    left: Vec<Digest>,
    /// The channel asked now, and since when.
    asked: Option<((SocketAddr, u64), Instant)>,
}

impl Ask {
    fn subject(&self) -> Digest {
        match &self.what {
            Asking::Lookup | Asking::Delegation => self.to,
            Asking::Forward(_, object) | Asking::Reply(_, _, object) => *object,
        }
    }
}

#[derive(Default)]
pub(super) struct Rendezvous {
    held: HashMap<Digest, Held>,
    by_link: HashMap<Link, Digest>,
    asks: Vec<Ask>,
    pub(super) announces: Announces,
    /// Return routes: a token's circuit, and when it was left.
    routes: HashMap<[u8; circuit::TOKEN_LEN], (Link, Instant)>,
    /// Messages from other rendezvous points coming together, by channel.
    incoming: HashMap<(SocketAddr, u64), Reassembly>,
    /// Payloads delivered and not yet acknowledged, by the recipient's
    /// circuit and the object: who to answer, and since when.
    delivering: HashMap<(Link, Digest), (Waiter, Instant)>,
    /// Delegations held, by owner id.
    delegations: HashMap<Digest, Delegated>,
}

impl Rendezvous {
    pub(super) fn sessions(&self) -> usize {
        self.held.len()
    }

    /// The delegation held for `id`, in force.
    fn delegation(&self, id: &Digest) -> Option<Vec<u8>> {
        let d = self.delegations.get(id)?;
        (d.expiry > super::unix_now()).then(|| self.announces.get_in(Table::Delegation, id)).flatten()
    }
}

/// A message to another rendezvous point, in `Rendezvous` cells on circuit
/// number 0 of the channel: a flag for more to come, a length, the bytes.
fn rendezvous_cells(kind: u8, body: &[u8]) -> Vec<Cell> {
    let mut msg = vec![kind];
    msg.extend_from_slice(body);
    let mut cells = circuit::handshake_cells(0, circuit::RENDEZVOUS, &msg);
    // Padded to a power of two of cells, and at least a payment's
    // (`circuit::PAYMENT_CELLS`), as a payment's relay messages are: empty
    // pieces before the last. Every message between rendezvous points is
    // a payment's.
    let want = cells.len().next_power_of_two().max(circuit::PAYMENT_CELLS);
    if want > cells.len() {
        let last = cells.pop().unwrap();
        while cells.len() + 1 < want {
            let mut c = Cell::new(0, circuit::RENDEZVOUS);
            c.payload[0] = 1;
            cells.push(c);
        }
        for c in &mut cells {
            c.payload[0] = 1;
        }
        cells.push(last);
    }
    cells
}

fn result(subject: &Digest, code: u8) -> Vec<u8> {
    let mut b = digest_to_bytes(subject).to_vec();
    b.push(code);
    b
}

impl<V: ProofVerifier + Send + Sync + 'static> Node<V> {
    /// Drops sessions gone quiet and questions not answered in time.
    pub(super) fn rendezvous_tick(&mut self, now: Instant) {
        let quiet: Vec<Digest> = self
            .rdv
            .held
            .iter()
            .filter(|(_, h)| now.duration_since(h.seen) >= Duration::from_secs(onion::CIRCUIT_SESSION_TIMEOUT_SECS))
            .map(|(id, _)| *id)
            .collect();
        for id in quiet {
            if let Some(h) = self.rdv.held.remove(&id) {
                self.rdv.by_link.remove(&h.link);
                self.rdv.announces.remove(&id);
            }
        }
        self.rdv.routes.retain(|_, (_, t)| now.duration_since(*t) < ROUTE_LIFETIME);
        let unix = super::unix_now();
        let expired: Vec<Digest> =
            self.rdv.delegations.iter().filter(|(_, d)| d.expiry <= unix).map(|(id, _)| *id).collect();
        for id in expired {
            self.rdv.delegations.remove(&id);
            self.rdv.announces.remove_in(Table::Delegation, &id);
        }
        let late: Vec<usize> = (0..self.rdv.asks.len())
            .filter(|&i| self.rdv.asks[i].asked.is_some_and(|(_, t)| now.duration_since(t) >= ASK_TIMEOUT))
            .collect();
        for i in late.into_iter().rev() {
            self.rdv.asks[i].asked = None;
            self.ask_next(i, now);
        }
        let unacknowledged: Vec<(Link, Digest)> = self
            .rdv
            .delivering
            .iter()
            .filter(|(_, (_, t))| now.duration_since(*t) >= ACK_WAIT)
            .map(|(k, _)| *k)
            .collect();
        for k in unacknowledged {
            let (waiter, _) = self.rdv.delivering.remove(&k).unwrap();
            self.answer_delivery(waiter, &k.1, NOTICE_OFFLINE, now);
        }
    }

    /// Delivers `payload` down the recipient's circuit `link`; `waiter`
    /// hears once it is acknowledged, or not.
    fn deliver(&mut self, link: Link, payload: &[u8], waiter: Waiter, now: Instant) {
        let object = Object::id_of(payload);
        if self.rdv.delivering.len() >= MAX_ASKS {
            return self.answer_delivery(waiter, &object, NOTICE_REFUSED, now);
        }
        self.hop_reply(link, circuit::DELIVER, payload, now);
        self.rdv.delivering.insert((link, object), (waiter, now));
    }

    /// Tells the sender's side what became of a delivery.
    fn answer_delivery(&mut self, waiter: Waiter, object: &Digest, code: u8, now: Instant) {
        match waiter {
            Waiter::Client(link) => self.hop_reply(link, circuit::NOTICE, &result(object, code), now),
            Waiter::Point(key) => {
                for c in rendezvous_cells(RESULT, &result(object, code)) {
                    let _ = self.channel_send(key, &c.to_bytes(), now);
                }
            }
        }
    }

    /// The channels questions to other rendezvous points wait on.
    pub(super) fn rendezvous_channels(&self) -> Vec<(SocketAddr, u64)> {
        self.rdv.asks.iter().filter_map(|a| a.asked.map(|(k, _)| k)).collect()
    }

    /// A circuit through us ended: a session on it ends too.
    pub(super) fn rendezvous_link_gone(&mut self, link: &Link) {
        if let Some(id) = self.rdv.by_link.remove(link) {
            self.rdv.held.remove(&id);
            self.rdv.announces.remove(&id);
        }
        self.rdv.asks.retain(|a| a.client != *link);
        self.rdv.routes.retain(|_, (l, _)| l != link);
    }

    /// An answer along the return route `token`, if it is still here:
    /// down its circuit, once.
    fn deliver_reply(&mut self, token: &[u8; circuit::TOKEN_LEN], payload: &[u8], waiter: Waiter, now: Instant) {
        match self.rdv.routes.remove(token) {
            Some((link, _)) => self.deliver(link, payload, waiter, now),
            None => self.answer_delivery(waiter, &Object::id_of(payload), NOTICE_OFFLINE, now),
        }
    }

    /// A relay message at the end of a participant's circuit, other than
    /// extending it. `true` if it was one of the rendezvous service's.
    pub(super) fn rendezvous_message(&mut self, link: Link, cmd: u8, msg: &[u8], now: Instant) -> bool {
        #[cfg(test)]
        self.circuits.seen.lock().unwrap().push(super::circuits::Seen::AtEnd(
            cmd,
            self.rdv.by_link.get(&link).copied(),
            msg.to_vec(),
        ));
        match cmd {
            circuit::SESSION => {
                let Some(id) = (msg.len() == 32).then(|| digest_from_bytes(msg)).flatten() else { return true };
                if !self.config.relay || !self.serves(&id) {
                    self.hop_reply(link, circuit::NOTICE, &result(&id, NOTICE_REFUSED), now);
                    return true;
                }
                let seq = match self.rdv.held.get_mut(&id) {
                    Some(h) if h.link == link => {
                        h.seen = now;
                        h.seq
                    }
                    _ => 0,
                };
                self.session_state(link, &id, seq, now);
            }
            circuit::ANNOUNCE => self.hold_over(link, msg, now),
            circuit::GET_ANNOUNCE => {
                let Some(id) = (msg.len() == 32).then(|| digest_from_bytes(msg)).flatten() else { return true };
                self.start_ask(link, id, Asking::Lookup, now);
            }
            circuit::GET_DELEGATION => {
                let Some(id) = (msg.len() == 32).then(|| digest_from_bytes(msg)).flatten() else { return true };
                self.start_ask(link, id, Asking::Delegation, now);
            }
            circuit::PUBLISH => {
                let code = self.publish_delegation(msg, now);
                self.hop_reply(link, circuit::NOTICE, &result(&Object::id_of(msg), code), now);
            }
            circuit::SEND => match Object::from_bytes(msg) {
                Some(Object::Payload(p)) => {
                    let object = Object::id_of(msg);
                    self.start_ask(link, p.to, Asking::Forward(msg.to_vec(), object), now);
                }
                _ => self.hop_reply(link, circuit::NOTICE, &result(&Object::id_of(msg), NOTICE_REJECTED), now),
            },
            circuit::ROUTE => {
                let Ok(token) = <[u8; circuit::TOKEN_LEN]>::try_from(msg) else { return true };
                if self.config.relay && self.rdv.routes.len() < MAX_ROUTES {
                    self.rdv.routes.insert(token, (link, now));
                }
            }
            circuit::REPLY => {
                if msg.len() < 32 + circuit::TOKEN_LEN {
                    return true;
                }
                let payload = &msg[32 + circuit::TOKEN_LEN..];
                let object = Object::id_of(payload);
                let (Some(relay), Some(Object::Payload(_))) =
                    (digest_from_bytes(&msg[..32]), Object::from_bytes(payload))
                else {
                    self.hop_reply(link, circuit::NOTICE, &result(&object, NOTICE_REJECTED), now);
                    return true;
                };
                let token: [u8; circuit::TOKEN_LEN] = msg[32..32 + circuit::TOKEN_LEN].try_into().unwrap();
                if self.my_id() == Some(relay) {
                    self.deliver_reply(&token, payload, Waiter::Client(link), now);
                    return true;
                }
                if self.rdv.asks.len() >= MAX_ASKS {
                    self.hop_reply(link, circuit::NOTICE, &result(&object, NOTICE_REFUSED), now);
                    return true;
                }
                let what = Asking::Reply(token, payload.to_vec(), object);
                self.rdv.asks.push(Ask { client: link, to: relay, what, left: vec![relay], asked: None });
                let i = self.rdv.asks.len() - 1;
                self.ask_next(i, now);
            }
            circuit::RECEIVED => {
                let Some(object) = (msg.len() == 32).then(|| digest_from_bytes(msg)).flatten() else { return true };
                if let Some((waiter, _)) = self.rdv.delivering.remove(&(link, object)) {
                    self.answer_delivery(waiter, &object, NOTICE_FORWARDED, now);
                }
            }
            circuit::BROADCAST => {
                if !self.config.relay {
                    return true;
                }
                let Some(tx) = crate::transaction::Transaction::from_bytes(msg) else {
                    return true;
                };
                let txid = tx.txid();
                let code = match self.pool_transaction(tx) {
                    Some(Ok(_)) | Some(Err(crate::mempool::Reject::Known)) => {
                        let n = self.announce_transaction(txid, None);
                        self.chatter(&format!("rendezvous: a transaction from a circuit announced to {n} peers"));
                        NOTICE_FORWARDED
                    }
                    Some(Err(e)) => {
                        self.chatter(&format!("rendezvous: a transaction from a circuit refused: {e}"));
                        NOTICE_REJECTED
                    }
                    None => NOTICE_REFUSED,
                };
                self.hop_reply(link, circuit::NOTICE, &result(&txid, code), now);
            }
            _ => return false,
        }
        true
    }

    fn session_state(&mut self, link: Link, id: &Digest, seq: u64, now: Instant) {
        let mut b = digest_to_bytes(id).to_vec();
        b.extend_from_slice(&self.link_nonce(&link, id).to_le_bytes());
        b.extend_from_slice(&seq.to_le_bytes());
        self.hop_reply(link, circuit::SESSION_STATE, &b, now);
    }

    /// An announce for a session over the circuit `link`.
    fn hold_over(&mut self, link: Link, bytes: &[u8], now: Instant) {
        let Some(a) = Announce::from_bytes(bytes) else {
            return self.hop_reply(link, circuit::NOTICE, &result(&Object::id_of(bytes), NOTICE_REJECTED), now);
        };
        let older = self.rdv.held.get(&a.id).is_some_and(|h| h.seq > a.seq);
        if !self.config.relay
            || a.nonce != self.link_nonce(&link, &a.id)
            || older
            || !self.serves(&a.id)
            || !a.verify(super::unix_now())
        {
            return self.hop_reply(link, circuit::NOTICE, &result(&a.id, NOTICE_REJECTED), now);
        }
        let (id, seq) = (a.id, a.seq);
        if self.rdv.held.len() >= self.config.max_sessions && !self.rdv.held.contains_key(&id) {
            return self.hop_reply(link, circuit::NOTICE, &result(&id, NOTICE_REFUSED), now);
        }
        if let Err(e) = self.rdv.announces.put(&id, bytes) {
            self.log(&format!("rendezvous: keeping an announce: {e}"));
            return self.hop_reply(link, circuit::NOTICE, &result(&id, NOTICE_REFUSED), now);
        }
        if let Some(old) = self.rdv.held.get(&id)
            && old.link != link
        {
            self.rdv.by_link.remove(&old.link);
        }
        let new = self.rdv.held.get(&id).is_none_or(|h| h.link != link);
        self.rdv.held.insert(id, Held { link, seq, seen: now });
        self.rdv.by_link.insert(link, id);
        if new {
            self.log(&format!("rendezvous: session for {} over a circuit", onion::short(&id)));
        }
        self.session_state(link, &id, seq, now);
    }

    /// A delegation published over a circuit: held here if this relay is
    /// one of the owner's points, and passed to the owner's other points
    /// (all of them, under every set in force, if it is not one: a server
    /// republishing it after the points moved, `docs/SUBNAMES.md`).
    fn publish_delegation(&mut self, bytes: &[u8], now: Instant) -> u8 {
        let Some(d) = Delegation::from_bytes(bytes).filter(|d| d.verify(&d.owner(), super::unix_now())) else {
            return NOTICE_REJECTED;
        };
        let owner = d.owner();
        if !self.config.relay {
            return NOTICE_REJECTED;
        }
        if self.serves(&owner)
            && let Err(code) = self.hold_delegation(bytes, now)
        {
            return code;
        }
        let me = self.my_id();
        for point in self.points_of(&owner).into_iter().filter(|p| Some(*p) != me) {
            let Some(addr) = self.relay_addr(&point) else { continue };
            let Ok(key) = self.channel_to(addr, point, now) else { continue };
            for c in rendezvous_cells(STORE, bytes) {
                let _ = self.channel_send(key, &c.to_bytes(), now);
            }
        }
        NOTICE_FORWARDED
    }

    /// A delegation to hold, published or passed on by another point: the
    /// owner's id once held, or why not. It must be sound in itself (the
    /// resolver checks it against the chain) and for an id this relay is a
    /// point of, newer than the one held, and not too soon after it.
    fn hold_delegation(&mut self, bytes: &[u8], now: Instant) -> Result<Digest, u8> {
        let d = Delegation::from_bytes(bytes).ok_or(NOTICE_REJECTED)?;
        let owner = d.owner();
        if !self.config.relay || !self.serves(&owner) || !d.verify(&owner, super::unix_now()) {
            return Err(NOTICE_REJECTED);
        }
        match self.rdv.delegations.get(&owner) {
            Some(h) if h.seq == d.seq => return Ok(owner),
            Some(h) if h.seq > d.seq || now.duration_since(h.updated) < DELEGATION_EVERY => {
                return Err(NOTICE_REFUSED);
            }
            None if self.rdv.delegations.len() >= self.config.max_sessions => return Err(NOTICE_REFUSED),
            _ => {}
        }
        if let Err(e) = self.rdv.announces.put_in(Table::Delegation, &owner, bytes) {
            self.log(&format!("rendezvous: keeping a delegation: {e}"));
            return Err(NOTICE_REFUSED);
        }
        self.rdv.delegations.insert(owner, Delegated { seq: d.seq, expiry: d.expiry, updated: now });
        self.chatter(&format!("rendezvous: a delegation for {}", onion::short(&owner)));
        Ok(owner)
    }

    /// The listed relays that are `id`'s rendezvous points, in the order
    /// they are asked: the preferred list's first, then, during a switch,
    /// the other's (`docs/ONION.md`).
    fn points_of(&self, id: &Digest) -> Vec<Digest> {
        self.onion_points_of(id)
    }

    fn my_id(&self) -> Option<Digest> {
        self.config.relay_id()
    }

    fn start_ask(&mut self, client: Link, to: Digest, what: Asking, now: Instant) {
        if self.rdv.asks.len() >= MAX_ASKS {
            let subject = match &what {
                Asking::Lookup | Asking::Delegation => to,
                Asking::Forward(_, o) | Asking::Reply(_, _, o) => *o,
            };
            return self.hop_reply(client, circuit::NOTICE, &result(&subject, NOTICE_REFUSED), now);
        }
        let left = self.points_of(&to);
        self.rdv.asks.push(Ask { client, to, what, left, asked: None });
        let i = self.rdv.asks.len() - 1;
        self.ask_next(i, now);
    }

    /// Asks the next of the recipient's points, answering locally if it
    /// is this relay, and the sender once one answers or none is left.
    fn ask_next(&mut self, i: usize, now: Instant) {
        let me = self.my_id();
        loop {
            let a = &mut self.rdv.asks[i];
            if a.left.is_empty() {
                let a = self.rdv.asks.remove(i);
                self.hop_reply(a.client, circuit::NOTICE, &result(&a.subject(), NOTICE_OFFLINE), now);
                return;
            }
            let point = a.left.remove(0);
            let to = a.to;
            if Some(point) == me {
                // This relay is one of the recipient's points.
                if matches!(a.what, Asking::Delegation) {
                    if let Some(bytes) = self.rdv.delegation(&to) {
                        let a = self.rdv.asks.remove(i);
                        return self.hop_reply(a.client, circuit::DELEGATION, &bytes, now);
                    }
                    continue;
                }
                if self.rdv.held.contains_key(&to) {
                    let a = self.rdv.asks.remove(i);
                    return self.answer_locally(a, now);
                }
                continue;
            }
            let Some(addr) = self.relay_addr(&point) else { continue };
            let Ok(key) = self.channel_to(addr, point, now) else { continue };
            let a = &mut self.rdv.asks[i];
            a.asked = Some((key, now));
            let cells = match &a.what {
                Asking::Lookup => rendezvous_cells(LOOKUP, &digest_to_bytes(&to)),
                Asking::Delegation => rendezvous_cells(FETCH, &digest_to_bytes(&to)),
                Asking::Forward(bytes, _) => rendezvous_cells(FORWARD, bytes),
                Asking::Reply(token, bytes, _) => {
                    let mut body = token.to_vec();
                    body.extend_from_slice(bytes);
                    rendezvous_cells(REPLY, &body)
                }
            };
            for c in cells {
                if let Err(e) = self.channel_send(key, &c.to_bytes(), now) {
                    self.chatter(&format!("rendezvous: a cell to {addr} dropped: {e}"));
                }
            }
            return;
        }
    }

    /// The recipient's session is here: the sender gets its announce, or
    /// the payload goes down the recipient's circuit.
    fn answer_locally(&mut self, a: Ask, now: Instant) {
        let Some(h) = self.rdv.held.get(&a.to) else { return };
        let link = h.link;
        match a.what {
            Asking::Lookup => {
                let Some(bytes) = self.rdv.announces.get(&a.to) else { return };
                self.hop_reply(a.client, circuit::ANNOUNCE, &bytes, now);
            }
            Asking::Forward(bytes, _) => self.deliver(link, &bytes, Waiter::Client(a.client), now),
            // Asked of the route's own relay only, which is not this one;
            // delegations are answered in `ask_next`.
            Asking::Reply(..) | Asking::Delegation => {}
        }
    }

    /// A `Rendezvous` cell from another relay.
    pub(super) fn on_rendezvous_cell(
        &mut self,
        key: (SocketAddr, u64),
        peer: Option<Digest>,
        cell: &Cell,
        now: Instant,
    ) {
        // Only from a listed relay that proved its id.
        let listed = peer.is_some_and(|p| self.rv.listed(&p).is_some());
        if !self.config.relay || !listed {
            return;
        }
        let Some((more, part)) = circuit::handshake_piece(cell) else { return };
        let r = self.rdv.incoming.entry(key).or_default();
        let msg = match r.add(circuit::RENDEZVOUS, more, part) {
            Ok(Some((_, msg))) => msg,
            Ok(None) => return,
            Err(_) => return,
        };
        let Some((&kind, body)) = msg.split_first() else { return };
        match kind {
            LOOKUP => {
                let Some(id) = (body.len() == 32).then(|| digest_from_bytes(body)).flatten() else { return };
                let found = self.rdv.held.contains_key(&id).then(|| self.rdv.announces.get(&id)).flatten();
                let reply = match found {
                    Some(bytes) => rendezvous_cells(FOUND, &bytes),
                    None => rendezvous_cells(RESULT, &result(&id, NOTICE_OFFLINE)),
                };
                for c in reply {
                    let _ = self.channel_send(key, &c.to_bytes(), now);
                }
            }
            FORWARD => {
                let object = Object::id_of(body);
                match Object::from_bytes(body) {
                    Some(Object::Payload(p)) => match self.rdv.held.get(&p.to) {
                        Some(h) => {
                            let link = h.link;
                            self.deliver(link, body, Waiter::Point(key), now);
                        }
                        None => self.answer_delivery(Waiter::Point(key), &object, NOTICE_OFFLINE, now),
                    },
                    _ => self.answer_delivery(Waiter::Point(key), &object, NOTICE_REJECTED, now),
                }
            }
            REPLY => {
                if body.len() < circuit::TOKEN_LEN {
                    return;
                }
                let (token, payload) = body.split_at(circuit::TOKEN_LEN);
                match Object::from_bytes(payload) {
                    Some(Object::Payload(_)) => {
                        self.deliver_reply(&token.try_into().unwrap(), payload, Waiter::Point(key), now)
                    }
                    _ => self.answer_delivery(Waiter::Point(key), &Object::id_of(payload), NOTICE_REJECTED, now),
                }
            }
            STORE => {
                let _ = self.hold_delegation(body, now);
            }
            FETCH => {
                let Some(id) = (body.len() == 32).then(|| digest_from_bytes(body)).flatten() else { return };
                let reply = match self.rdv.delegation(&id) {
                    Some(bytes) => rendezvous_cells(HELD, &bytes),
                    None => rendezvous_cells(NONE, body),
                };
                for c in reply {
                    let _ = self.channel_send(key, &c.to_bytes(), now);
                }
            }
            HELD | NONE => {
                let owner = match kind {
                    HELD => Delegation::from_bytes(body).map(|d| d.owner()),
                    _ => (body.len() == 32).then(|| digest_from_bytes(body)).flatten(),
                };
                let Some(owner) = owner else { return };
                let Some(i) = self.rdv.asks.iter().position(|q| {
                    q.asked.is_some_and(|(k, _)| k == key) && matches!(q.what, Asking::Delegation) && q.to == owner
                }) else {
                    return;
                };
                if kind == HELD {
                    let q = self.rdv.asks.remove(i);
                    self.hop_reply(q.client, circuit::DELEGATION, body, now);
                } else {
                    self.rdv.asks[i].asked = None;
                    self.ask_next(i, now);
                }
            }
            FOUND => {
                let Some(a) = Announce::from_bytes(body) else { return };
                let Some(i) = self.rdv.asks.iter().position(|q| {
                    q.asked.is_some_and(|(k, _)| k == key) && matches!(q.what, Asking::Lookup) && q.to == a.id
                }) else {
                    return;
                };
                let q = self.rdv.asks.remove(i);
                self.hop_reply(q.client, circuit::ANNOUNCE, body, now);
            }
            RESULT => {
                if body.len() != 33 {
                    return;
                }
                let Some(subject) = digest_from_bytes(&body[..32]) else { return };
                let code = body[32];
                let Some(i) =
                    self.rdv.asks.iter().position(|q| q.asked.is_some_and(|(k, _)| k == key) && q.subject() == subject)
                else {
                    return;
                };
                if code == NOTICE_FORWARDED {
                    let q = self.rdv.asks.remove(i);
                    self.hop_reply(q.client, circuit::NOTICE, &result(&subject, NOTICE_FORWARDED), now);
                } else {
                    self.rdv.asks[i].asked = None;
                    self.ask_next(i, now);
                }
            }
            _ => {}
        }
    }
}
