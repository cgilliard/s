//! The message layer's rendezvous sessions (`docs/ONION.md`), as init
//! mode runs them: direct connections between participants and the nodes
//! that stand in for relays.
//!
//! # Relay side
//!
//! A node started with `--relay` holds sessions keyed by id. A participant
//! asks for one with `Session`; the answer, `SessionState`, gives the nonce
//! its announce must carry (this node's SipHash of the participant's
//! address and id, so it is bound to both without being stored) and the
//! sequence number of the announce held for it from that address, zero for
//! none. The participant then offers its announce; once checked (the id is
//! its key's hash, the signature holds, the nonce is this address's, the
//! sequence number is not older than the one held) the session is live,
//! and it stays live while `Session` keepalives come every
//! [`onion::KEEPALIVE_SECS`], for at most [`onion::SESSION_TIMEOUT_SECS`]
//! without one. A sender asks for an id's announce with `GetAnnounce` and
//! offers a payload sealed to it; a payload for an id with a live session
//! is offered down it, and the sender told `Notice` forwarded, or offline.
//! Nothing is stored beyond the time it takes the participant to pull it.
//!
//! # Participant side
//!
//! A node with the wallet's identity keeps a session at each of its
//! rendezvous points: the seeds (by name, sorted) in init mode, the listed
//! relays (sorted by id) in onion mode until circuits exist (step 4), each
//! chosen by [`onion::rendezvous_indexes`] of its id and the epoch. It announces one
//! Kyber key at all of them, made fresh at start, whenever a session it had
//! is lost (a reconnect) and when half its lifetime has passed; a retired
//! key still opens payloads for [`KEY_GRACE`], those in flight. Sends go to
//! the recipient's points in turn until one forwards the payload. What
//! arrives, and what became of each send, goes to the wallet as a
//! [`Note`].
//!
//! Every object (an announce or a payload) is offered and pulled as
//! [`Kind::Object`] chunks, served only to whom it was offered: nothing is
//! sent unasked, and the offer carries the token the receiver uses, so a
//! relay reaches a participant whether or not it is in its peer table.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use super::{Node, short, stalled, unix_now};
use crate::chain::ProofVerifier;
use crate::consensus;
use crate::mldsa;
use crate::mlkem;
use crate::net::{self, Download, Kind, Message, NOTICE_FORWARDED, NOTICE_OFFLINE, NOTICE_REFUSED, NOTICE_REJECTED};
use crate::onion::{self, Announce, MAX_OBJECT, Object, Opened, Payload};
use crate::poseidon2::digest_to_bytes;
use crate::pow::Digest;
use crate::wallet::random_bytes;

const KEEPALIVE: Duration = Duration::from_secs(onion::KEEPALIVE_SECS);
const SESSION_TIMEOUT: Duration = Duration::from_secs(onion::SESSION_TIMEOUT_SECS);
/// Between attempts at a session that is not live.
const SESSION_RETRY: Duration = Duration::from_secs(3);
/// A point that refused a session is asked again after this.
const REFUSED_RETRY: Duration = Duration::from_secs(60);
/// A Kyber key is replaced after half its announced lifetime.
const ROTATE_AFTER: Duration = Duration::from_secs(onion::ANNOUNCE_LIFETIME_SECS / 2);
/// A retired Kyber key still opens payloads this long: those in flight.
pub const KEY_GRACE: Duration = Duration::from_secs(600);
/// An offered object not pulled by then is dropped.
const OUTBOX_TIME: Duration = Duration::from_secs(60);
const MAX_OUTBOX: usize = 1024;
/// Addresses one offered object may be served to.
const MAX_TAKERS: usize = 64;
const MAX_OBJECT_DOWNLOADS: usize = 64;
const MAX_OBJECT_DOWNLOADS_PER_PEER: usize = 4;
/// Sessions a relay holds by default; more are refused (`--max-sessions`).
pub const MAX_SESSIONS: usize = 10_000;
/// How long a sender waits on one rendezvous point before the next.
const POINT_TIMEOUT: Duration = Duration::from_secs(8);
/// Sends in progress at once.
const MAX_SENDS: usize = 64;
/// Notes queued for the wallet; more are dropped.
const NOTES: usize = 256;

/// A message for an id, from the wallet.
#[derive(Clone, Debug)]
pub struct Outbound {
    /// The wallet's handle, given back in the [`Note`] saying what became
    /// of it.
    pub tag: u64,
    pub to: Digest,
    pub kind: u8,
    pub inner: Vec<u8>,
    /// The recipient's announce, when known (from a payload it sent):
    /// sealed to at once rather than asked of its rendezvous points.
    pub recipient: Option<Announce>,
    /// An answer to an unnamed sender, along the route its payload gave
    /// (`docs/PRIVACY.md`, fix 4); `to` is then the route's reply id.
    pub reply: Option<onion::Route>,
    /// Steps of one action (a sub-name's delegation, its query, then the
    /// payment) share a group, nonzero, and so one outbound circuit in
    /// onion mode: its last relay sees one action, as for any send. Zero:
    /// a circuit of its own.
    pub group: u64,
}

/// What the node tells the wallet.
#[derive(Clone, Debug)]
pub enum Note {
    /// A payload opened by one of our keys.
    Received(Opened),
    /// A rendezvous point handed the payload down the recipient's session.
    Delivered { tag: u64, to: Digest, via: SocketAddr },
    /// No rendezvous point took it: the last reason.
    Failed { tag: u64, to: Digest, why: String },
    /// What became of a transaction of ours: how it was announced, or
    /// why it was not.
    Broadcast { txid: Digest, how: Result<String, String> },
    /// The sub-name delegation asked for (`docs/SUBNAMES.md`): the one
    /// held, none (no point of the owner's holds one, or init mode), or
    /// why it could not be asked. Not yet checked against the chain.
    Delegation { tag: u64, owner: Digest, result: Result<Option<crate::subnames::Delegation>, String> },
}

/// The participant: its Dilithium key and its Kyber keys.
pub(super) struct Me {
    pub(super) key: mldsa::SecretKey,
    pub(super) id: Digest,
    /// The current Kyber key first, then retired ones with when.
    pub(super) keys: Vec<(mlkem::SecretKey, Option<Instant>)>,
    pub(super) seq: u64,
    expiry: u64,
    pub(super) made: Instant,
    /// The current key's announce for payloads (nonce zero), for replies.
    carried: Announce,
    pub(super) rotate: bool,
}

impl Me {
    fn new(key: mldsa::SecretKey, now: Instant) -> std::io::Result<Me> {
        let id = crate::address::id_of(key.public_key());
        let kyber = mlkem::keygen(&random_bytes::<64>()?);
        let (seq, expiry) = (unix_millis(), unix_now() + onion::ANNOUNCE_LIFETIME_SECS);
        let carried = Announce::make(&key, kyber.public_key(), seq, expiry, 0);
        Ok(Me { key, id, keys: vec![(kyber, None)], seq, expiry, made: now, carried, rotate: false })
    }

    /// A fresh Kyber key under a higher sequence number; the old one is
    /// kept for [`KEY_GRACE`].
    fn rotate(&mut self, now: Instant) -> std::io::Result<()> {
        let kyber = mlkem::keygen(&random_bytes::<64>()?);
        self.keys[0].1 = Some(now);
        self.keys.insert(0, (kyber, None));
        self.keys.retain(|(_, retired)| retired.is_none_or(|t| now.duration_since(t) < KEY_GRACE));
        self.seq = unix_millis().max(self.seq + 1);
        self.expiry = unix_now() + onion::ANNOUNCE_LIFETIME_SECS;
        self.made = now;
        self.carried = Announce::make(&self.key, self.keys[0].0.public_key(), self.seq, self.expiry, 0);
        self.rotate = false;
        Ok(())
    }

    pub(super) fn announce(&self, nonce: u64) -> Announce {
        Announce::make(&self.key, self.keys[0].0.public_key(), self.seq, self.expiry, nonce)
    }
}

/// Sequence numbers are the time in milliseconds, so they rise across
/// restarts.
fn unix_millis() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// One of the participant's rendezvous points.
struct Point {
    addr: SocketAddr,
    /// The nonce it gave our announces.
    nonce: Option<u64>,
    /// The sequence number of the announce it holds from us.
    held: u64,
    asked: Option<Instant>,
    answered: Option<Instant>,
    /// The sequence number last offered, and when.
    offered: Option<(u64, Instant)>,
    refused: Option<Instant>,
    /// It held our current announce: losing it is a reconnect.
    was_live: bool,
    /// The wait before the next keepalive, drawn when the last went
    /// (`docs/PRIVACY.md`, fix 3).
    interval: Duration,
}

impl Point {
    fn new(addr: SocketAddr) -> Point {
        Point {
            addr,
            nonce: None,
            held: 0,
            asked: None,
            answered: None,
            offered: None,
            refused: None,
            was_live: false,
            interval: KEEPALIVE,
        }
    }

    fn live(&self, seq: u64, now: Instant) -> bool {
        self.held == seq && self.answered.is_some_and(|t| now.duration_since(t) < SESSION_TIMEOUT)
    }
}

/// A session this relay holds.
struct Held {
    addr: SocketAddr,
    /// The participant's token for us: for offering it payloads.
    back: u64,
    announce: Announce,
    /// The announce as an object, and its id.
    bytes: Vec<u8>,
    object: Digest,
    seen: Instant,
}

/// An object offered, until pulled or stale.
struct Outgoing {
    bytes: Vec<u8>,
    takers: Vec<SocketAddr>,
    at: Instant,
}

enum Stage {
    /// Waiting to reach the current point.
    Start,
    /// `GetAnnounce` sent.
    Asked,
    /// The payload offered, by its object id.
    Offered(Digest),
}

/// A send in progress.
struct Job {
    out: Outbound,
    points: Vec<SocketAddr>,
    at: usize,
    stage: Stage,
    since: Instant,
    why: String,
}

impl Job {
    fn point(&self) -> Option<SocketAddr> {
        self.points.get(self.at).copied()
    }

    fn next(&mut self, why: String, now: Instant) {
        self.why = why;
        self.at += 1;
        self.stage = Stage::Start;
        self.since = now;
    }
}

/// The node's message-layer state.
pub(super) struct State {
    pub(super) me: Option<Me>,
    /// Whether the node has a wallet, whose address may be off.
    pub(super) wallet: bool,
    points: Vec<Point>,
    held: HashMap<Digest, Held>,
    nonce_key: RandomState,
    outbox: HashMap<Digest, Outgoing>,
    pub(super) downloads: HashMap<Digest, Download>,
    /// The token each object download's requests carry: its offer's.
    tokens: HashMap<Digest, u64>,
    sends: Vec<Job>,
    notes: SyncSender<Note>,
    notes_rx: Option<Receiver<Note>>,
    /// The relay set decided at the last boundary.
    current: RelaySet,
    /// The rendezvous epoch since the last boundary
    /// ([`onion::rendezvous_epoch`]); `previous` is under the one before.
    pub(super) epoch: u32,
    /// When this node moves its own session to the current set's points,
    /// while a switch lasts: a random moment in the first
    /// [`MOVE_WITHIN`] blocks after the boundary, so that participants do
    /// not all move in the block senders switch at; at [`MOVE_WITHIN`]
    /// blocks in, it moves in any case. The last boundary, and how far in.
    move_at: Option<Instant>,
    boundary: u32,
    into: u32,
    /// The one decided before it, while the switch lasts: every boundary
    /// switches, since points move each epoch even when the file stays.
    previous: Option<RelaySet>,
    /// Whether `current` is tried first: from the switch's third block.
    prefer_current: bool,
    /// Tests: sets given by hand rather than followed from the chain.
    #[cfg(test)]
    pinned: bool,
    /// Sends that may be tried again in the other mode while a switch
    /// between modes lasts: by tag and recipient.
    fallback: Vec<Outbound>,
    /// Sends to try again in the other mode.
    pub(super) retry: Vec<Outbound>,
    resolved: HashMap<String, Option<SocketAddr>>,
    /// The sub-names this node answers for, as a server.
    pub(super) subnames: crate::subnames::Table,
    /// Sub-name answers given in the current minute, and since when.
    answered: (usize, Option<Instant>),
}

/// The tag of a send the node makes itself (a sub-name answer): what
/// becomes of it is not the wallet's.
pub(super) const NODE_TAG: u64 = 1 << 63;
/// Blocks after a boundary within which every participant moves its
/// session to the new points, each at a random moment (`docs/SUBNAMES.md`,
/// section 2): before the old points close at `GRACE − 1`.
pub(super) const MOVE_WITHIN: u32 = 3;
/// Sub-name answers a server gives a minute, at most: each costs a
/// signature.
const ANSWERS_PER_MINUTE: usize = 600;

/// A file's relays, sorted by id, in onion mode; `None` in init mode,
/// where the seeds stand in.
pub(super) type RelaySet = Option<Vec<consensus::Relay>>;

/// A decided file's relay set.
fn relay_set(c: &consensus::Current) -> RelaySet {
    match (&c.mode, &c.file) {
        (consensus::Mode::Onion, Some(f)) => Some(f.relays.clone()),
        _ => None,
    }
}

/// `id`'s points under each of `sets` with its epoch, in order, each once.
fn points_under(id: &Digest, sets: Vec<(&[consensus::Relay], u32)>) -> Vec<Digest> {
    let mut out: Vec<Digest> = Vec::new();
    for (relays, epoch) in sets {
        let ids: Vec<Digest> = relays.iter().map(|r| r.id).collect();
        for i in onion::rendezvous_relays(id, epoch, &ids) {
            if !out.contains(&ids[i]) {
                out.push(ids[i]);
            }
        }
    }
    out
}

/// The sets in force at `epoch`'s height: the current one, the one before
/// while the grace period lasts (the old file, or the same one when it did
/// not change, under the epoch before), whether the current is preferred,
/// and the current epoch.
fn sets_of(epoch: &consensus::Epoch) -> (RelaySet, Option<RelaySet>, bool, u32) {
    let n = onion::rendezvous_epoch(epoch.boundary);
    let into = epoch.height - epoch.boundary;
    let previous =
        (n > 0 && into + 1 < consensus::GRACE).then(|| relay_set(epoch.previous.as_ref().unwrap_or(&epoch.current)));
    let prefer_current = previous.is_none() || into >= consensus::SWITCH;
    (relay_set(&epoch.current), previous, prefer_current, n)
}

impl State {
    pub(super) fn new(identity: Option<mldsa::SecretKey>, wallet: bool, now: Instant) -> std::io::Result<State> {
        let (notes, notes_rx) = sync_channel(NOTES);
        Ok(State {
            me: identity.map(|k| Me::new(k, now)).transpose()?,
            wallet,
            points: Vec::new(),
            held: HashMap::new(),
            nonce_key: RandomState::new(),
            outbox: HashMap::new(),
            downloads: HashMap::new(),
            tokens: HashMap::new(),
            sends: Vec::new(),
            notes,
            notes_rx: Some(notes_rx),
            current: None,
            epoch: 0,
            move_at: None,
            boundary: 0,
            into: 0,
            previous: None,
            prefer_current: true,
            #[cfg(test)]
            pinned: false,
            fallback: Vec::new(),
            retry: Vec::new(),
            resolved: HashMap::new(),
            subnames: crate::subnames::Table::new(),
            answered: (0, None),
        })
    }

    /// The sets in force, each with its rendezvous epoch, the preferred
    /// first: the current one and, while a switch lasts, the one before.
    fn sets(&self) -> Vec<(&RelaySet, u32)> {
        self.sets_ordered(self.prefer_current)
    }

    fn sets_ordered(&self, prefer_current: bool) -> Vec<(&RelaySet, u32)> {
        let mut out = vec![(&self.current, self.epoch)];
        if let Some(p) = &self.previous {
            let p = (p, self.epoch.saturating_sub(1));
            if prefer_current {
                out.push(p);
            } else {
                out.insert(0, p);
            }
        }
        out
    }

    /// The onion-mode relay lists in force, the preferred first.
    pub(super) fn onion_sets(&self) -> Vec<&[consensus::Relay]> {
        self.onion_epochs().into_iter().map(|(s, _)| s).collect()
    }

    /// Whether a switch between sets is under way.
    pub(super) fn switching(&self) -> bool {
        self.previous.is_some()
    }

    /// Whether this node's own session is at the current set's points:
    /// once it has moved (`move_at`), or, with no move drawn (tests, a
    /// switch between modes), as senders prefer.
    pub(super) fn moved(&self, now: Instant) -> bool {
        if self.previous.is_none() {
            return true;
        }
        match self.move_at {
            Some(t) => now >= t || self.into >= MOVE_WITHIN,
            None => self.prefer_current,
        }
    }

    /// The onion-mode relay lists in force with their epochs, in the order
    /// this node's own session takes them ([`Self::moved`]).
    pub(super) fn own_onion_epochs(&self, now: Instant) -> Vec<(&[consensus::Relay], u32)> {
        self.sets_ordered(self.moved(now)).into_iter().filter_map(|(s, e)| Some((s.as_deref()?, e))).collect()
    }

    /// The onion-mode relay lists in force with their epochs, the
    /// preferred first.
    pub(super) fn onion_epochs(&self) -> Vec<(&[consensus::Relay], u32)> {
        self.sets().into_iter().filter_map(|(s, e)| Some((s.as_deref()?, e))).collect()
    }

    /// The epochs of the init-mode sets in force, the preferred first.
    fn init_epochs(&self) -> Vec<u32> {
        self.sets().into_iter().filter(|(s, _)| s.is_none()).map(|(_, e)| e).collect()
    }

    /// Whether a set in force is init mode's: the seeds serve sessions.
    pub(super) fn init_active(&self) -> bool {
        !self.init_epochs().is_empty()
    }

    /// Whether a set in force is onion mode's.
    pub(super) fn onion_active(&self) -> bool {
        !self.onion_sets().is_empty()
    }

    /// Whether the preferred set is onion mode's.
    pub(super) fn prefers_onion(&self) -> bool {
        self.sets()[0].0.is_some()
    }

    /// The listed relay `id`, in any set in force.
    pub(super) fn listed(&self, id: &Digest) -> Option<&consensus::Relay> {
        self.onion_sets().into_iter().flat_map(|s| s.iter()).find(|r| r.id == *id)
    }

    /// Tests: relays as if an onion-mode file were in force, alone.
    #[cfg(test)]
    pub(super) fn set_relays(&mut self, relays: Vec<consensus::Relay>) {
        self.set_sets(Some(relays), None, true, 0);
    }

    /// Tests: the sets in force given by hand, `current` under `epoch`.
    #[cfg(test)]
    pub(super) fn set_sets(&mut self, current: RelaySet, previous: Option<RelaySet>, prefer_current: bool, epoch: u32) {
        self.current = current;
        self.epoch = epoch;
        self.previous = previous;
        self.prefer_current = prefer_current;
        self.pinned = true;
    }

    /// Forgets resolved addresses: the seeds are being looked up again.
    pub(super) fn reresolve(&mut self) {
        self.resolved.clear();
    }

    /// Follows the files in force (`docs/ONION.md`): decided at the last
    /// boundary, and the one before while the switch lasts. Rendezvous
    /// points move at every boundary (`docs/SUBNAMES.md`, section 2), so
    /// the set before stands through every grace period, with the same
    /// file when it did not change.
    pub(super) fn set_epoch(&mut self, epoch: &consensus::Epoch, block_time: Duration, now: Instant) {
        #[cfg(test)]
        if self.pinned {
            return;
        }
        let (current, previous, prefer_current, n) = sets_of(epoch);
        self.current = current;
        self.previous = previous;
        self.prefer_current = prefer_current;
        self.epoch = n;
        self.into = epoch.height - epoch.boundary;
        // A new boundary: a moment to move at, at random in what is left
        // of the first `MOVE_WITHIN` blocks.
        if self.previous.is_none() {
            self.move_at = None;
        } else if self.move_at.is_none() || self.boundary != epoch.boundary {
            let left = MOVE_WITHIN.saturating_sub(self.into);
            let x = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0);
            let span = (block_time * left).as_millis() as u64;
            self.move_at = Some(now + Duration::from_millis(x % span.max(1)));
        }
        self.boundary = epoch.boundary;
        if self.previous.is_none() {
            self.fallback.clear();
        }
    }

    /// Keeps a send to be tried in the other mode if this one fails,
    /// while a switch between the modes lasts.
    pub(super) fn keep_fallback(&mut self, out: &Outbound) {
        if self.init_active() && self.onion_active() {
            self.fallback.push(out.clone());
        }
    }

    /// For the prompt: each rendezvous point and whether its session is
    /// live, and how many sessions this node holds as a relay.
    pub(super) fn summary(&self, now: Instant) -> (Vec<(SocketAddr, bool)>, usize) {
        let points = match &self.me {
            Some(me) => self.points.iter().map(|p| (p.addr, p.live(me.seq, now))).collect(),
            None => Vec::new(),
        };
        (points, self.held.len())
    }

    pub(super) fn note(&mut self, note: Note) {
        // A send that failed in one mode during a switch is tried in the
        // other before the wallet hears of it.
        match &note {
            Note::Failed { tag, to, .. } => {
                if let Some(i) = self.fallback.iter().position(|o| o.tag == *tag && o.to == *to) {
                    let out = self.fallback.remove(i);
                    self.retry.push(out);
                    return;
                }
            }
            Note::Delivered { tag, to, .. } => self.fallback.retain(|o| !(o.tag == *tag && o.to == *to)),
            _ => {}
        }
        if let Note::Delivered { tag, .. } | Note::Failed { tag, .. } = &note
            && tag & NODE_TAG != 0
        {
            return;
        }
        if let Err(TrySendError::Full(_)) = self.notes.try_send(note) {
            crate::log::line("net: message layer: the wallet is not taking notes; one dropped");
        }
    }

    fn offer(&mut self, object: Digest, bytes: &[u8], to: SocketAddr, now: Instant) -> bool {
        if let Some(o) = self.outbox.get_mut(&object) {
            if !o.takers.contains(&to) && o.takers.len() < MAX_TAKERS {
                o.takers.push(to);
            }
            o.at = now;
            return true;
        }
        if self.outbox.len() >= MAX_OUTBOX {
            return false;
        }
        self.outbox.insert(object, Outgoing { bytes: bytes.to_vec(), takers: vec![to], at: now });
        true
    }
}

impl<V: ProofVerifier + Send + Sync + 'static> Node<V> {
    /// What the message layer tells the wallet: taken once.
    pub fn take_notes(&mut self) -> Option<Receiver<Note>> {
        self.rv.notes_rx.take()
    }

    /// The nonce an announce over the circuit `link` for `id` must carry.
    pub(super) fn link_nonce(&self, link: &super::circuits::Link, id: &Digest) -> u64 {
        std::hash::BuildHasher::hash_one(&self.rv.nonce_key, (link, digest_to_bytes(id)))
    }

    /// The nonce an announce from `addr` for `id` must carry.
    fn session_nonce(&self, addr: &SocketAddr, id: &Digest) -> u64 {
        std::hash::BuildHasher::hash_one(&self.rv.nonce_key, (addr, digest_to_bytes(id)))
    }

    fn resolve(&mut self, name: &str) -> Option<SocketAddr> {
        if let Some(a) = self.rv.resolved.get(name) {
            return *a;
        }
        let v6 = self.socket.local_addr().is_ok_and(|a| a.is_ipv6());
        let addrs: Vec<SocketAddr> = name.to_socket_addrs().map(|i| i.collect()).unwrap_or_default();
        let a = addrs.iter().find(|a| a.is_ipv6() == v6).or(addrs.first()).copied();
        self.rv.resolved.insert(name.to_string(), a);
        a
    }

    /// `id`'s init-mode rendezvous points that can be reached: resolved,
    /// and not this node. They are chosen among the seeds by name, under
    /// each init-mode epoch in force, the preferred first; only the chosen
    /// are resolved.
    fn points_for(&mut self, id: &Digest) -> Vec<SocketAddr> {
        let names: Vec<String> = {
            let mut seeds = self.config.seeds.clone();
            seeds.sort();
            seeds.dedup();
            let mut names: Vec<String> = Vec::new();
            for e in self.rv.init_epochs() {
                for i in onion::rendezvous_indexes(id, e, seeds.len()) {
                    if !names.contains(&seeds[i]) {
                        names.push(seeds[i].clone());
                    }
                }
            }
            names
        };
        let addrs: Vec<SocketAddr> = names.iter().filter_map(|n| self.resolve(n)).collect();
        addrs.into_iter().filter(|a| !self.peers.is_self(a)).collect()
    }

    /// Whether this node, as a relay, holds init-mode sessions: for any id,
    /// since the seeds cannot tell which seed name they are, while init
    /// mode is in force.
    fn serves_init(&self) -> bool {
        self.rv.init_active()
    }

    /// `id`'s onion-mode rendezvous points: under each relay list in
    /// force with its epoch, the preferred first, each point once.
    pub(super) fn onion_points_of(&self, id: &Digest) -> Vec<Digest> {
        points_under(id, self.rv.onion_epochs())
    }

    /// Our own points, in the order our session takes them: the new
    /// set's first once we have moved ([`State::moved`]).
    pub(super) fn own_points_of(&self, id: &Digest, now: Instant) -> Vec<Digest> {
        points_under(id, self.rv.own_onion_epochs(now))
    }

    /// Whether this node, as a relay, is a rendezvous point of `id` in
    /// onion mode: under any relay list in force with its epoch, during a
    /// switch too.
    pub(super) fn serves(&self, id: &Digest) -> bool {
        let Some(me) = self.config.relay_id() else { return false };
        self.rv.onion_epochs().into_iter().any(|(relays, epoch)| {
            let ids: Vec<Digest> = relays.iter().map(|r| r.id).collect();
            onion::rendezvous_relays(id, epoch, &ids).into_iter().any(|i| relays[i].id == me)
        })
    }

    /// Re-requests stalled object chunks, with each download's token.
    pub(super) fn retry_objects(&mut self, now: Instant) {
        let (requests, abandoned) = stalled(&mut self.rv.downloads, now, |a| self.peers.retry(a));
        for (to, msg) in requests {
            let Message::GetChunks { id, .. } = &msg else { continue };
            let token = self.rv.tokens.get(id).copied().unwrap_or(0);
            self.send_with(to, msg, token);
        }
        for id in abandoned {
            self.rv.downloads.remove(&id);
            self.rv.tokens.remove(&id);
        }
    }

    /// Once a second: expiry, the participant's sessions, sends.
    pub(super) fn sessions_tick(&mut self, now: Instant) {
        let before = self.rv.held.len();
        self.rv.held.retain(|_, h| now.duration_since(h.seen) < SESSION_TIMEOUT);
        if self.rv.held.len() < before {
            self.chatter(&format!("message layer: {} sessions went quiet", before - self.rv.held.len()));
        }
        self.rv.outbox.retain(|_, o| now.duration_since(o.at) < OUTBOX_TIME);
        // Onion mode keeps sessions over circuits, init mode directly; both
        // while a switch between them lasts.
        if self.rv.onion_active() {
            self.onion_participate(now);
        } else {
            self.onion_stand_down(now);
        }
        if self.rv.init_active() {
            self.participate(now);
        }
        for out in std::mem::take(&mut self.rv.retry) {
            self.chatter(&format!("message layer: trying {} in the other mode", onion::short(&out.to)));
            if self.rv.prefers_onion() {
                self.init_send(out, now);
            } else {
                self.onion_send(out, now);
            }
        }
        self.progress_sends(now);
    }

    /// Keeps a live session at each of the participant's rendezvous points.
    fn participate(&mut self, now: Instant) {
        let Some(id) = self.rv.me.as_ref().map(|m| m.id) else { return };
        let want = self.points_for(&id);
        if want.iter().ne(self.rv.points.iter().map(|p| &p.addr)) {
            let mut old: Vec<Point> = std::mem::take(&mut self.rv.points);
            self.rv.points = want
                .iter()
                .map(|a| match old.iter().position(|p| p.addr == *a) {
                    Some(i) => old.swap_remove(i),
                    None => Point::new(*a),
                })
                .collect();
            let list: Vec<String> = want.iter().map(|a| a.to_string()).collect();
            self.log(&format!("message layer: rendezvous points {}", list.join(", ")));
        }
        for a in &want {
            self.peers.add(*a, true);
        }
        let me = self.rv.me.as_mut().unwrap();
        let mut lost = Vec::new();
        for p in &mut self.rv.points {
            if p.was_live && !p.live(me.seq, now) && p.held == me.seq {
                // Silent too long: gone.
                p.was_live = false;
                p.held = 0;
                lost.push(p.addr);
            }
        }
        if !lost.is_empty() || (me.rotate || now.duration_since(me.made) >= ROTATE_AFTER) {
            for a in &lost {
                self.log(&format!("message layer: the session at {a} went quiet; reconnecting"));
            }
            self.rotate(now);
        }
        let seq = self.rv.me.as_ref().unwrap().seq;
        let mut asks = Vec::new();
        for p in &mut self.rv.points {
            if !self.peers.handshaken(&p.addr) || p.refused.is_some_and(|t| now.duration_since(t) < REFUSED_RETRY) {
                continue;
            }
            // Asked and not answered: lost, or it restarted and our token
            // for it is stale, so it is pinged for a fresh one.
            let unanswered = p.asked.is_some_and(|a| p.answered.is_none_or(|t| t < a));
            let wait = if p.live(seq, now) && !unanswered { p.interval } else { SESSION_RETRY };
            if p.asked.is_none_or(|t| now.duration_since(t) >= wait) {
                p.asked = Some(now);
                p.interval = super::participant::jitter(KEEPALIVE);
                asks.push((p.addr, unanswered));
            }
        }
        for (a, unanswered) in asks {
            if unanswered {
                let nonce = self.next_nonce();
                if self.peers.ping_now(a, nonce, now) {
                    let st = self.status(&a, nonce);
                    self.send(a, &Message::Ping(st));
                }
            }
            self.send(a, &Message::Session { id, back: self.token_for(&a), token: 0 });
        }
    }

    /// A new Kyber key: every point is asked at once, and each that holds
    /// the old one is offered the new.
    pub(super) fn rotate(&mut self, now: Instant) {
        let Some(me) = self.rv.me.as_mut() else { return };
        if let Err(e) = me.rotate(now) {
            self.log(&format!("message layer: no new Kyber key: {e}"));
            return;
        }
        for p in &mut self.rv.points {
            p.asked = None;
        }
        self.chatter("message layer: new Kyber key announced");
    }

    pub(super) fn on_session(&mut self, addr: SocketAddr, id: Digest, back: u64, now: Instant) {
        if !self.config.relay || !self.serves_init() {
            self.send(addr, &Message::Notice { subject: id, code: NOTICE_REFUSED });
            return;
        }
        if self.rv.held.len() >= self.config.max_sessions && !self.rv.held.contains_key(&id) {
            self.send(addr, &Message::Notice { subject: id, code: NOTICE_REFUSED });
            return;
        }
        let seq = match self.rv.held.get_mut(&id) {
            Some(h) if h.addr == addr => {
                h.seen = now;
                h.back = back;
                h.announce.seq
            }
            _ => 0,
        };
        let nonce = self.session_nonce(&addr, &id);
        self.send(addr, &Message::SessionState { id, nonce, seq });
    }

    pub(super) fn on_session_state(&mut self, addr: SocketAddr, id: Digest, nonce: u64, seq: u64, now: Instant) {
        let Some(me) = self.rv.me.as_mut() else { return };
        if id != me.id {
            return;
        }
        let Some(p) = self.rv.points.iter_mut().find(|p| p.addr == addr) else { return };
        p.answered = Some(now);
        p.nonce = Some(nonce);
        p.held = seq;
        p.refused = None;
        if seq == me.seq {
            if !p.was_live {
                p.was_live = true;
                self.log(&format!("message layer: rendezvous session at {addr} live"));
            }
            return;
        }
        if p.was_live && seq == 0 {
            // It lost our session (a restart): a reconnect, so a new key.
            p.was_live = false;
            self.log(&format!("message layer: {addr} lost our session; reconnecting"));
            self.rotate(now);
        }
        let me = self.rv.me.as_ref().unwrap();
        let p = self.rv.points.iter_mut().find(|p| p.addr == addr).unwrap();
        if p.offered.is_some_and(|(s, t)| s == me.seq && now.duration_since(t) < SESSION_RETRY) {
            return;
        }
        p.offered = Some((me.seq, now));
        p.asked = Some(now);
        let bytes = Object::Announce(me.announce(nonce)).to_bytes();
        let object = Object::id_of(&bytes);
        if self.rv.offer(object, &bytes, addr, now) {
            let back = self.token_for(&addr);
            self.send(addr, &Message::Offer { object, len: bytes.len() as u32, back, token: 0 });
        }
    }

    pub(super) fn on_get_announce(&mut self, addr: SocketAddr, id: Digest, back: u64, now: Instant) {
        if !self.config.relay {
            self.send(addr, &Message::Notice { subject: id, code: NOTICE_REFUSED });
            return;
        }
        let (bytes, object) = match (&self.rv.me, self.rv.held.get(&id)) {
            // This relay's own: a sender reaching it directly.
            (Some(me), _) if me.id == id => {
                let bytes = Object::Announce(me.carried.clone()).to_bytes();
                let object = Object::id_of(&bytes);
                (bytes, object)
            }
            (_, Some(h)) => (h.bytes.clone(), h.object),
            _ => {
                self.send(addr, &Message::Notice { subject: id, code: NOTICE_OFFLINE });
                return;
            }
        };
        if self.rv.offer(object, &bytes, addr, now) {
            let ours = self.token_for(&addr);
            self.send_with(addr, Message::Offer { object, len: bytes.len() as u32, back: ours, token: 0 }, back);
        }
    }

    /// An offer: pulled if it is expected from `addr` (anything, at a
    /// relay; a payload from a rendezvous point; an announce for a send).
    pub(super) fn on_offer(&mut self, addr: SocketAddr, object: Digest, len: u32, back: u64, now: Instant) {
        let expected = self.config.relay
            || self.rv.points.iter().any(|p| p.addr == addr)
            || self.rv.sends.iter().any(|j| j.point() == Some(addr));
        let from_peer = self.rv.downloads.values().filter(|d| d.from == addr).count();
        if !expected
            || len == 0
            || len as usize > MAX_OBJECT
            || self.rv.downloads.contains_key(&object)
            || self.rv.downloads.len() >= MAX_OBJECT_DOWNLOADS
            || from_peer >= MAX_OBJECT_DOWNLOADS_PER_PEER
        {
            return;
        }
        let mut d = Download::new(Kind::Object, object, addr, MAX_OBJECT, None, net::PeerPath::default(), now);
        let indexes = d.request(now);
        self.send_with(addr, Message::GetChunks { kind: Kind::Object, id: object, indexes, token: 0 }, back);
        self.rv.downloads.insert(object, d);
        self.rv.tokens.insert(object, back);
    }

    /// Serves chunks of an object offered to `to`.
    pub(super) fn serve_object(&self, to: SocketAddr, id: &Digest, indexes: &[u16]) {
        let Some(o) = self.rv.outbox.get(id) else { return };
        if !o.takers.contains(&to) {
            return;
        }
        for &i in indexes.iter().take(net::MAX_IN_FLIGHT) {
            if let Some(msg) = net::chunk_of(Kind::Object, id, &o.bytes, i) {
                self.send(to, &msg);
            }
        }
    }

    pub(super) fn on_object_chunk(
        &mut self,
        from: SocketAddr,
        id: Digest,
        len: u32,
        index: u16,
        data: Vec<u8>,
        now: Instant,
    ) {
        let Some(d) = self.rv.downloads.get_mut(&id) else { return };
        if d.from != from {
            return;
        }
        let token = self.rv.tokens.get(&id).copied().unwrap_or(0);
        match d.insert(len, index, data, now) {
            Ok(false) => {
                if d.wants_refill() {
                    let indexes = d.request(now);
                    for msg in net::chunk_requests(Kind::Object, id, &indexes) {
                        self.send_with(from, msg, token);
                    }
                }
            }
            Ok(true) => {
                let bytes = d.assemble().unwrap_or_default();
                self.rv.downloads.remove(&id);
                self.rv.tokens.remove(&id);
                if Object::id_of(&bytes) != id {
                    self.log(&format!("{from} sent an object that is not the one it offered"));
                    self.peers.strike(from);
                    return;
                }
                self.on_object(from, id, bytes, token, now);
            }
            Err(_) => {
                self.rv.downloads.remove(&id);
                self.rv.tokens.remove(&id);
            }
        }
    }

    fn on_object(&mut self, from: SocketAddr, object: Digest, bytes: Vec<u8>, back: u64, now: Instant) {
        match Object::from_bytes(&bytes) {
            Some(Object::Announce(a)) => {
                if let Some(j) = self
                    .rv
                    .sends
                    .iter()
                    .position(|j| j.point() == Some(from) && matches!(j.stage, Stage::Asked) && j.out.to == a.id)
                {
                    let job = &mut self.rv.sends[j];
                    if a.verify(unix_now()) {
                        job.out.recipient = Some(a);
                        job.stage = Stage::Start;
                    } else {
                        job.next(format!("{from} gave an announce that does not verify"), now);
                    }
                    self.progress_sends(now);
                    return;
                }
                if self.config.relay {
                    self.hold(from, object, a, bytes, back, now);
                }
            }
            Some(Object::Payload(p)) => {
                if self.rv.me.as_ref().is_some_and(|m| m.id == p.to) {
                    self.open(from, p);
                    if self.config.relay {
                        self.send(from, &Message::Notice { subject: object, code: NOTICE_FORWARDED });
                    }
                    return;
                }
                if !self.config.relay {
                    return;
                }
                let Some((addr, back)) = self.rv.held.get(&p.to).map(|h| (h.addr, h.back)) else {
                    self.chatter(&format!("message layer: a payload for {} who is offline", onion::short(&p.to)));
                    self.send(from, &Message::Notice { subject: object, code: NOTICE_OFFLINE });
                    return;
                };
                if !self.rv.offer(object, &bytes, addr, now) {
                    self.send(from, &Message::Notice { subject: object, code: NOTICE_REFUSED });
                    return;
                }
                let ours = self.token_for(&addr);
                self.send_with(addr, Message::Offer { object, len: bytes.len() as u32, back: ours, token: 0 }, back);
                self.send(from, &Message::Notice { subject: object, code: NOTICE_FORWARDED });
                self.chatter(&format!(
                    "message layer: payload {} forwarded to {}",
                    short(&object),
                    onion::short(&p.to)
                ));
            }
            None => {
                self.send(from, &Message::Notice { subject: object, code: NOTICE_REJECTED });
            }
        }
    }

    /// An announce offered for a session at this relay.
    fn hold(&mut self, from: SocketAddr, object: Digest, a: Announce, bytes: Vec<u8>, back: u64, now: Instant) {
        let older = self.rv.held.get(&a.id).is_some_and(|h| h.announce.seq > a.seq);
        let full = self.rv.held.len() >= self.config.max_sessions && !self.rv.held.contains_key(&a.id);
        if a.nonce != self.session_nonce(&from, &a.id) || older || !self.serves_init() || !a.verify(unix_now()) {
            self.chatter(&format!("message layer: {from} offered an announce that does not hold"));
            self.send(from, &Message::Notice { subject: object, code: NOTICE_REJECTED });
            return;
        }
        if full {
            self.send(from, &Message::Notice { subject: a.id, code: NOTICE_REFUSED });
            return;
        }
        let (id, nonce, seq) = (a.id, a.nonce, a.seq);
        let new = self.rv.held.get(&id).is_none_or(|h| h.addr != from);
        self.rv.held.insert(id, Held { addr: from, back, announce: a, bytes, object, seen: now });
        if new {
            self.log(&format!("message layer: session for {} at {from}", onion::short(&id)));
        }
        self.send(from, &Message::SessionState { id, nonce, seq });
    }

    /// A payload for us: opened with the newest key that opens it.
    pub(super) fn open(&mut self, from: impl std::fmt::Display, p: Payload) {
        let Some(me) = &self.rv.me else { return };
        let now = unix_now();
        match me.keys.iter().find_map(|(k, _)| p.open(k, now)) {
            Some(opened) if opened.kind == onion::KIND_SUBNAME_QUERY => {
                self.answer_subname(opened);
            }
            Some(opened) => {
                let who = opened.from.as_ref().map_or("someone unnamed".to_string(), |a| onion::short(&a.id));
                self.log(&format!("message layer: a message of kind {} from {who} via {from}", opened.kind));
                self.rv.note(Note::Received(opened));
            }
            None => self.log(&format!("message layer: a payload via {from} that none of our keys opens")),
        }
    }

    /// A sub-name query to this node as a server (`docs/SUBNAMES.md`):
    /// answered from its table, signed with its identity key, along the
    /// query's way back (or to the sender, when it named itself).
    fn answer_subname(&mut self, q: Opened) {
        let Some(me) = &self.rv.me else { return };
        let Some((name, label)) = crate::subnames::parse_query(&q.inner) else {
            return self.chatter("message layer: a malformed sub-name query");
        };
        let now = Instant::now();
        let (count, since) = &mut self.rv.answered;
        if since.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(60)) {
            (*count, *since) = (0, Some(now));
        }
        if *count >= ANSWERS_PER_MINUTE {
            return self.chatter("message layer: a sub-name query over the rate, unanswered");
        }
        *count += 1;
        let Some(answer) = crate::subnames::answer(&me.key, &self.rv.subnames, &name, &label, unix_now()) else {
            return;
        };
        let (to, recipient, reply) = match (q.route, q.from) {
            (Some(route), _) => (route.reply_id(), None, Some(route)),
            (None, Some(a)) => (a.id, Some(a), None),
            (None, None) => return,
        };
        let tag = NODE_TAG | (random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0) >> 1);
        let inner = answer.to_bytes();
        self.start_send(Outbound { tag, to, kind: onion::KIND_SUBNAME_ANSWER, inner, recipient, reply, group: 0 }, now);
    }

    pub(super) fn on_notice(&mut self, addr: SocketAddr, subject: Digest, code: u8, now: Instant) {
        if let Some(i) = self.rv.sends.iter().position(|j| {
            j.point() == Some(addr)
                && match j.stage {
                    Stage::Asked => j.out.to == subject,
                    Stage::Offered(o) => o == subject,
                    Stage::Start => false,
                }
        }) {
            let job = &mut self.rv.sends[i];
            if code == NOTICE_FORWARDED && matches!(job.stage, Stage::Offered(_)) {
                let job = self.rv.sends.remove(i);
                self.log(&format!("message layer: delivered to {} via {addr}", onion::short(&job.out.to)));
                self.rv.note(Note::Delivered { tag: job.out.tag, to: job.out.to, via: addr });
            } else {
                let why = match code {
                    NOTICE_OFFLINE => "offline",
                    NOTICE_REFUSED => "refused",
                    NOTICE_REJECTED => "rejected the payload",
                    _ => "an unknown answer",
                };
                job.next(format!("{addr}: {why}"), now);
                self.progress_sends(now);
            }
            return;
        }
        if code == NOTICE_REFUSED
            && self.rv.me.as_ref().is_some_and(|m| m.id == subject)
            && let Some(p) = self.rv.points.iter_mut().find(|p| p.addr == addr)
        {
            let first = p.refused.is_none();
            p.refused = Some(now);
            if first {
                self.log(&format!("message layer: {addr} refused a session (not a relay, or full)"));
            }
        }
    }

    /// The wallet's new address, or none (`docs/PRIVACY.md`, fix 5). The
    /// old address answers nothing from now on: its sessions are not kept
    /// alive and what comes for it is not opened. In onion mode its
    /// circuits stay until the new address's sessions are live.
    pub(super) fn set_identity(&mut self, key: Option<mldsa::SecretKey>, now: Instant) {
        let me = match key.map(|k| Me::new(k, now)).transpose() {
            Ok(me) => me,
            Err(e) => return self.log(&format!("message layer: no new identity: {e}")),
        };
        match &me {
            Some(m) => self.log(&format!("message layer: a new address, {}", onion::short(&m.id))),
            None => self.log("message layer: the address is off"),
        }
        self.rv.me = me;
        // The old address's delegation is for the old id.
        self.part.delegation = None;
        for p in &mut self.rv.points {
            p.held = 0;
            p.was_live = false;
            p.asked = None;
        }
        if self.rv.me.is_none() {
            self.rv.points.clear();
        }
    }

    /// A message from the wallet.
    pub(super) fn start_send(&mut self, out: Outbound, now: Instant) {
        let fail = |why: &str| Note::Failed { tag: out.tag, to: out.to, why: why.to_string() };
        if !self.rv.wallet {
            return self.rv.note(fail("this node has no wallet"));
        }
        // Init mode names the sender, to be answered: it needs an address.
        if self.rv.me.is_none() && !self.rv.prefers_onion() {
            return self.rv.note(fail("the address is off, and init mode needs one: address next"));
        }
        self.rv.keep_fallback(&out);
        if self.rv.prefers_onion() {
            return self.onion_send(out, now);
        }
        self.init_send(out, now);
    }

    /// A send by init mode's direct sessions.
    fn init_send(&mut self, out: Outbound, now: Instant) {
        let fail = |why: &str| Note::Failed { tag: out.tag, to: out.to, why: why.to_string() };
        if self.rv.sends.len() >= MAX_SENDS {
            return self.rv.note(fail("too many sends in progress"));
        }
        let points = self.points_for(&out.to);
        if points.is_empty() {
            return self.rv.note(fail("no rendezvous points: no seeds or relays to reach it by"));
        }
        for a in &points {
            self.peers.add(*a, true);
        }
        self.rv.sends.push(Job { out, points, at: 0, stage: Stage::Start, since: now, why: String::new() });
        self.progress_sends(now);
    }

    /// Moves each send on: to the next point when one is slow or fails,
    /// asks a point for the recipient's announce, seals and offers.
    fn progress_sends(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.rv.sends.len() {
            let Some(addr) = self.rv.sends[i].point() else {
                let job = self.rv.sends.remove(i);
                let why = if job.why.is_empty() { "no rendezvous point answered".into() } else { job.why };
                self.log(&format!("message layer: could not reach {}: {why}", onion::short(&job.out.to)));
                self.rv.note(Note::Failed { tag: job.out.tag, to: job.out.to, why });
                continue;
            };
            let job = &mut self.rv.sends[i];
            if now.duration_since(job.since) >= POINT_TIMEOUT {
                let asked = !matches!(job.stage, Stage::Start);
                job.next(format!("{addr}: no answer"), now);
                // It may have restarted, and our token for it be stale.
                let nonce = self.next_nonce();
                if asked && self.peers.ping_now(addr, nonce, now) {
                    let st = self.status(&addr, nonce);
                    self.send(addr, &Message::Ping(st));
                }
                continue;
            }
            if !matches!(job.stage, Stage::Start) || !self.peers.handshaken(&addr) {
                i += 1;
                continue;
            }
            let recipient = job.out.recipient.clone().filter(|a| a.verify(unix_now()));
            let ours = self.token_for(&addr);
            let job = &self.rv.sends[i];
            match recipient {
                None => {
                    let id = job.out.to;
                    let job = &mut self.rv.sends[i];
                    job.stage = Stage::Asked;
                    job.since = now;
                    self.send(addr, &Message::GetAnnounce { id, back: ours, token: 0 });
                }
                Some(a) => match self.seal(&a, job.out.kind, &job.out.inner) {
                    Ok(bytes) => {
                        let object = Object::id_of(&bytes);
                        if self.rv.offer(object, &bytes, addr, now) {
                            let job = &mut self.rv.sends[i];
                            job.stage = Stage::Offered(object);
                            job.since = now;
                            self.send(addr, &Message::Offer { object, len: bytes.len() as u32, back: ours, token: 0 });
                        }
                    }
                    Err(why) => {
                        let job = self.rv.sends.remove(i);
                        self.rv.note(Note::Failed { tag: job.out.tag, to: job.out.to, why });
                        continue;
                    }
                },
            }
            i += 1;
        }
    }

    /// A payload to `to`, naming us with our current key for the reply:
    /// how init mode sends, without circuits to answer along.
    pub(super) fn seal(&self, to: &Announce, kind: u8, inner: &[u8]) -> Result<Vec<u8>, String> {
        let me = self.rv.me.as_ref().ok_or("no identity")?;
        let m = random_bytes::<32>().map_err(|e| e.to_string())?;
        let nonce = random_bytes::<12>().map_err(|e| e.to_string())?;
        let p = Payload::seal(to, Some((&me.key, &me.carried)), None, kind, inner, &m, nonce)
            .ok_or("the recipient's Kyber key is malformed")?;
        let bytes = Object::Payload(p).to_bytes();
        if bytes.len() > MAX_OBJECT {
            return Err(format!("the message is too large: {} bytes, at most {MAX_OBJECT}", bytes.len()));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Current, Epoch, Mode, Votes};

    /// Points move at every boundary, the file changed or not: the epoch
    /// before stands from `B` to `B + 4`, is tried first until `B + 2`,
    /// and is gone at `B + 5`; the first epoch has none before it.
    #[test]
    fn every_boundary_switches_epochs_with_a_grace_period() {
        let init = Current { mode: Mode::Init, winner: None, file: None, skipped: vec![] };
        let at = |h: u32| sets_of(&Epoch::new(h, Votes::default(), init.clone(), Some(init.clone())));
        for h in [0, 5, 143] {
            let (_, previous, prefer, n) = at(h);
            assert_eq!((previous.is_some(), prefer, n), (false, true, 0), "at {h}");
        }
        for b in [144, 288] {
            for h in b..b + 5 {
                let (_, previous, prefer, n) = at(h);
                assert!(previous.is_some(), "both stand at {h}");
                assert_eq!((prefer, n), (h >= b + 2, b / 144), "at {h}");
            }
            for h in [b + 5, b + 100, b + 143] {
                let (_, previous, prefer, _) = at(h);
                assert_eq!((previous.is_some(), prefer), (false, true), "at {h}");
            }
        }
    }

    /// Each node moves its own session at its own random moment in the
    /// first `MOVE_WITHIN` blocks after a boundary, and at `MOVE_WITHIN`
    /// blocks in whatever it drew; with no switch under way it has moved.
    #[test]
    fn participants_move_at_random_within_the_first_blocks() {
        let init = Current { mode: Mode::Init, winner: None, file: None, skipped: vec![] };
        let epoch = |h: u32| Epoch::new(h, Votes::default(), init.clone(), Some(init.clone()));
        let block = Duration::from_secs(10);
        let now = Instant::now();
        let mut draws = Vec::new();
        for _ in 0..20 {
            let mut s = State::new(None, false, now).unwrap();
            s.set_epoch(&epoch(144), block, now);
            let at = s.move_at.unwrap();
            assert!(at >= now && at < now + block * MOVE_WITHIN, "{:?}", at - now);
            assert!(s.moved(at));
            if at > now {
                assert!(!s.moved(now));
            }
            // The same boundary seen again keeps the moment drawn.
            s.set_epoch(&epoch(145), block, now);
            assert_eq!(s.move_at, Some(at));
            // Three blocks in: moved, whatever was drawn.
            s.move_at = Some(now + Duration::from_secs(3600));
            s.set_epoch(&epoch(144 + MOVE_WITHIN), block, now);
            assert!(s.moved(now));
            // The switch over: nothing to move.
            s.set_epoch(&epoch(150), block, now);
            assert!(s.moved(now) && s.move_at.is_none());
            draws.push(at - now);
        }
        draws.sort();
        draws.dedup();
        assert!(draws.len() > 10, "moments spread at random: {draws:?}");
    }
}
