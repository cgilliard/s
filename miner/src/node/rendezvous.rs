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
//! Broadcast(tx)        → Notice(txid, forwarded or rejected)
//! ```
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
//! ```
//!
//! A sender's rendezvous point asks the recipient's points in the order
//! their id gives, itself first if it is one, until one holds a session;
//! it answers the sender when one does, or when none did.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::Node;
use super::circuits::Link;
use crate::chain::ProofVerifier;
use crate::circuit::{self, Cell, Reassembly};
use crate::net::{NOTICE_FORWARDED, NOTICE_OFFLINE, NOTICE_REFUSED, NOTICE_REJECTED};
use crate::onion::{self, Announce, Object};
use crate::pow::Digest;
use crate::poseidon2::{digest_from_bytes, digest_to_bytes};

/// Messages between rendezvous points.
const LOOKUP: u8 = 1;
const FOUND: u8 = 2;
const FORWARD: u8 = 3;
const RESULT: u8 = 4;

/// How long a sender's rendezvous point waits on one of the recipient's.
const ASK_TIMEOUT: Duration = Duration::from_secs(8);
/// Questions out to other rendezvous points at once.
const MAX_ASKS: usize = 4096;

/// A session this relay holds over a circuit.
struct Held {
    link: Link,
    announce: Announce,
    bytes: Vec<u8>,
    seen: Instant,
}

enum Asking {
    Lookup,
    /// The payload, and its object id.
    Forward(Vec<u8>, Digest),
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
            Asking::Lookup => self.to,
            Asking::Forward(_, object) => *object,
        }
    }
}

#[derive(Default)]
pub(super) struct Rendezvous {
    held: HashMap<Digest, Held>,
    by_link: HashMap<Link, Digest>,
    asks: Vec<Ask>,
    /// Messages from other rendezvous points coming together, by channel.
    incoming: HashMap<(SocketAddr, u64), Reassembly>,
}

impl Rendezvous {
    pub(super) fn sessions(&self) -> usize {
        self.held.len()
    }
}

/// A message to another rendezvous point, in `Rendezvous` cells on circuit
/// number 0 of the channel: a flag for more to come, a length, the bytes.
fn rendezvous_cells(kind: u8, body: &[u8]) -> Vec<Cell> {
    let mut msg = vec![kind];
    msg.extend_from_slice(body);
    circuit::handshake_cells(0, circuit::RENDEZVOUS, &msg)
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
            .filter(|(_, h)| now.duration_since(h.seen) >= Duration::from_secs(onion::SESSION_TIMEOUT_SECS))
            .map(|(id, _)| *id)
            .collect();
        for id in quiet {
            if let Some(h) = self.rdv.held.remove(&id) {
                self.rdv.by_link.remove(&h.link);
            }
        }
        let late: Vec<usize> = (0..self.rdv.asks.len())
            .filter(|&i| self.rdv.asks[i].asked.is_some_and(|(_, t)| now.duration_since(t) >= ASK_TIMEOUT))
            .collect();
        for i in late.into_iter().rev() {
            self.rdv.asks[i].asked = None;
            self.ask_next(i, now);
        }
    }

    /// A circuit through us ended: a session on it ends too.
    pub(super) fn rendezvous_link_gone(&mut self, link: &Link) {
        if let Some(id) = self.rdv.by_link.remove(link) {
            self.rdv.held.remove(&id);
        }
        self.rdv.asks.retain(|a| a.client != *link);
    }

    /// A relay message at the end of a participant's circuit, other than
    /// extending it. `true` if it was one of the rendezvous service's.
    pub(super) fn rendezvous_message(&mut self, link: Link, cmd: u8, msg: &[u8], now: Instant) -> bool {
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
                        h.announce.seq
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
            circuit::SEND => match Object::from_bytes(msg) {
                Some(Object::Payload(p)) => {
                    let object = Object::id_of(msg);
                    self.start_ask(link, p.to, Asking::Forward(msg.to_vec(), object), now);
                }
                _ => self.hop_reply(link, circuit::NOTICE, &result(&Object::id_of(msg), NOTICE_REJECTED), now),
            },
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
        let older = self.rdv.held.get(&a.id).is_some_and(|h| h.announce.seq > a.seq);
        if !self.config.relay
            || a.nonce != self.link_nonce(&link, &a.id)
            || older
            || !self.serves(&a.id)
            || !a.verify(super::unix_now())
        {
            return self.hop_reply(link, circuit::NOTICE, &result(&a.id, NOTICE_REJECTED), now);
        }
        let (id, seq) = (a.id, a.seq);
        if let Some(old) = self.rdv.held.get(&id)
            && old.link != link
        {
            self.rdv.by_link.remove(&old.link);
        }
        let new = self.rdv.held.get(&id).is_none_or(|h| h.link != link);
        self.rdv.held.insert(id, Held { link, announce: a, bytes: bytes.to_vec(), seen: now });
        self.rdv.by_link.insert(link, id);
        if new {
            self.log(&format!("rendezvous: session for {} over a circuit", onion::short(&id)));
        }
        self.session_state(link, &id, seq, now);
    }

    /// The listed relays that are `id`'s rendezvous points, in the order
    /// they are asked: the preferred list's first, then, during a switch,
    /// the other's (`docs/ONION.md`).
    fn points_of(&self, id: &Digest) -> Vec<Digest> {
        self.onion_points_of(id)
    }

    fn my_id(&self) -> Option<Digest> {
        self.config.identity.as_ref().map(|k| crate::address::id_of(k.public_key()))
    }

    fn start_ask(&mut self, client: Link, to: Digest, what: Asking, now: Instant) {
        if self.rdv.asks.len() >= MAX_ASKS {
            let subject = match &what {
                Asking::Lookup => to,
                Asking::Forward(_, o) => *o,
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
                Asking::Forward(bytes, _) => rendezvous_cells(FORWARD, bytes),
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
        match a.what {
            Asking::Lookup => {
                let bytes = h.bytes.clone();
                self.hop_reply(a.client, circuit::ANNOUNCE, &bytes, now);
            }
            Asking::Forward(bytes, object) => {
                let link = h.link;
                self.hop_reply(link, circuit::DELIVER, &bytes, now);
                self.hop_reply(a.client, circuit::NOTICE, &result(&object, NOTICE_FORWARDED), now);
            }
        }
    }

    /// A `Rendezvous` cell from another relay.
    pub(super) fn on_rendezvous_cell(&mut self, key: (SocketAddr, u64), peer: Option<Digest>, cell: &Cell, now: Instant) {
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
                let reply = match self.rdv.held.get(&id) {
                    Some(h) => rendezvous_cells(FOUND, &h.bytes),
                    None => rendezvous_cells(RESULT, &result(&id, NOTICE_OFFLINE)),
                };
                for c in reply {
                    let _ = self.channel_send(key, &c.to_bytes(), now);
                }
            }
            FORWARD => {
                let object = Object::id_of(body);
                let code = match Object::from_bytes(body) {
                    Some(Object::Payload(p)) => match self.rdv.held.get(&p.to) {
                        Some(h) => {
                            let link = h.link;
                            self.hop_reply(link, circuit::DELIVER, body, now);
                            NOTICE_FORWARDED
                        }
                        None => NOTICE_OFFLINE,
                    },
                    _ => NOTICE_REJECTED,
                };
                for c in rendezvous_cells(RESULT, &result(&object, code)) {
                    let _ = self.channel_send(key, &c.to_bytes(), now);
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
                let Some(i) = self.rdv.asks.iter().position(|q| q.asked.is_some_and(|(k, _)| k == key) && q.subject() == subject)
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
