//! Onion mode's participant (`docs/ONION.md`): the wallet's node keeps a
//! circuit standing to each of its three rendezvous points, holds a
//! session over each, and receives over any of them. A sender's last
//! relay asks the points in a random order until one holds a session, so
//! the wallet is reached while any one of its points is up; a circuit
//! that fails (as it reaches its point, or later), or a point that
//! refuses the session, affects that point alone, its circuit built again
//! on its own.
//!
//! Each circuit runs through two listed relays chosen at random (fewer
//! when the file lists too few others) to the point, which the id names.
//! Over it the node asks for a session every [`onion::CIRCUIT_KEEPALIVE_SECS`]
//! (every few seconds while the point does not hold its current
//! announce) and offers its announce bound to the nonce the point gives,
//! the same Kyber key at every point, rotated as in init mode: at start,
//! when a session is lost (a circuit that dies, a point that forgets us)
//! and after half its lifetime. A circuit that dies is built again after
//! a few seconds; one whose keepalive goes unanswered for [`DEAD_AFTER`]
//! is taken for dead (a hop gone) and built again, rather than waiting
//! for its channel to give up. Every circuit is replaced after a random
//! two to four hours, the new one built and the session moved onto it
//! before the old one is closed.
//!
//! What the node sends goes up outbound circuits instead, which carry no
//! session of ours (`docs/PRIVACY.md`, fix 2): two random hops and a
//! random last relay that is none of our rendezvous points, so the points
//! that know our id never see whom we pay. Each is used for one send (the
//! recipient's announce asked of its last relay, unless the wallet gave
//! it, then the payload sealed to it; the relay answers forwarded, or
//! offline once every point of the recipient was tried) or one
//! broadcast, then closed; one is kept ready meanwhile. The steps of one
//! send share a circuit when the wallet groups them (a sub-name's
//! delegation, its query, then the payment), kept up to
//! [`KEEP_FOR_GROUP`] between them: its last relay still sees one send. A transaction of
//! ours goes up a circuit of its own to a relay that pools and announces
//! it as its own, so the first node to announce it is a relay, not the
//! one that saw the payment's payload, and not the sender. One that no
//! circuit takes in [`BROADCAST_TIMEOUT`] is left in the node's pool
//! unannounced, and the wallet told: it is never announced from the
//! node's own address. With too few relays listed for a last hop that is
//! not one of our points, one of them ends the circuit.
//!
//! A send names no one (`docs/PRIVACY.md`, fix 4): it leaves a token with
//! its circuit's last relay (`Route`) and puts the way back (that relay,
//! the token, a Kyber key made for the one answer) inside the payload,
//! sealed. The circuit is then held open for the answer, which comes down
//! it, sealed to that key; our rendezvous points never see it. An answer
//! of ours to such a payload goes up an outbound circuit as a `Reply`,
//! which the relays carry to the route's relay and down the sender's
//! circuit.
//!
//! A payload delivered down a standing circuit is opened with our keys
//! and handed to the wallet.
//!
//! Every circuit's first hop, standing or outbound, is one of [`GUARDS`]
//! relays the node keeps for one to two months (`docs/PRIVACY.md`, fix
//! 3), saved in the data directory beside the peers file: a hostile relay
//! then sees the node's network address only if it is a guard, not
//! sooner or later by chance. A guard that leaves the list, or whose time
//! is up, is replaced; one whose channel fails is passed over a while like
//! any relay. Keepalives come at random intervals of two thirds to four
//! thirds of [`onion::CIRCUIT_KEEPALIVE_SECS`], not on a beat a hostile
//! first hop and point could match. The channel to the guard keeps itself
//! alive (and the NAT mapping open) every [`crate::channel::KEEPALIVE`];
//! a hop that dies destroys the circuit, and the `Destroy` reaching us
//! has it built again, without a keepalive needing to notice.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::sessions::{Note, Outbound};
use super::{Node, unix_now};
use crate::chain::ProofVerifier;
use crate::circuit;
use crate::net::{NOTICE_FORWARDED, NOTICE_OFFLINE, NOTICE_REFUSED, NOTICE_REJECTED};
use crate::onion::{self, Announce, Object};
use crate::poseidon2::{digest_from_bytes, digest_to_bytes};
use crate::pow::Digest;
use crate::wallet::random_bytes;

const KEEPALIVE: Duration = Duration::from_secs(onion::CIRCUIT_KEEPALIVE_SECS);
const SESSION_TIMEOUT: Duration = Duration::from_secs(onion::CIRCUIT_SESSION_TIMEOUT_SECS);
const SESSION_RETRY: Duration = Duration::from_secs(3);
const REFUSED_RETRY: Duration = Duration::from_secs(60);
const ROTATE_AFTER: Duration = Duration::from_secs(onion::ANNOUNCE_LIFETIME_SECS / 2);
/// A circuit that died is built again after this.
const REBUILD_WAIT: Duration = Duration::from_secs(3);
/// Random hops before the rendezvous point.
const HOPS: usize = 2;
/// A keepalive unanswered this long means the circuit is dead.
const DEAD_AFTER: Duration = Duration::from_secs(30);
/// A circuit is replaced after this, plus up to as much again at random.
const ROTATE_EVERY: Duration = Duration::from_secs(2 * 3600);
/// An old circuit is closed once the session is live on its replacement,
/// or after this at most: long enough that a slow replacement does not
/// leave the point without our session meanwhile (`docs/TIMING_FIXES.md`;
/// it was 30 s, closing the old one whether or not the new was live).
const RETIRE_WAIT: Duration = Duration::from_secs(300);
/// A relay whose channel failed is not chosen as a hop for this long, while
/// enough others are left.
const AVOID: Duration = Duration::from_secs(300);
/// A relay that answered with a key other than its listed id's is not
/// chosen for this long: its address may be an honest chain peer and our
/// list the stale one, so it is not struck, only left alone.
const WRONG_KEY_AVOID: Duration = Duration::from_secs(3600);
/// A send not answered by then fails; it waits as long for a circuit.
const SEND_TIMEOUT: Duration = Duration::from_secs(120);
/// After an "offline" for a send, how long before asking again: a
/// recipient's sessions move (rebuilt around a relay that stopped, or to
/// a new point), and a lookup between two can find none.
const OFFLINE_RETRY: Duration = Duration::from_secs(3);
/// How long after the first "offline" a send keeps asking: a recipient
/// whose point, or a hop to it, stopped notices only after
/// [`DEAD_AFTER`], then builds a circuit and holds its session again.
#[cfg(not(test))]
const OFFLINE_WAIT: Duration = Duration::from_secs(60);
/// In tests, one more ask (as tests sending to nobody expect a prompt
/// "offline"); a test of sessions moving sets it (`set_timing`).
#[cfg(test)]
const OFFLINE_WAIT: Duration = OFFLINE_RETRY;
const MAX_SENDS: usize = 64;
/// A broadcast unanswered by then is tried on another circuit.
const BROADCAST_WAIT: Duration = Duration::from_secs(15);
/// One no circuit took by then is given up.
const BROADCAST_TIMEOUT: Duration = Duration::from_secs(120);
/// Outbound circuits kept ready, beyond those sends are waiting for.
const SPARE_OUTBOUND: usize = 1;
/// Most outbound circuits at once.
const MAX_OUTBOUND: usize = 8;
/// A ready outbound circuit unused this long is replaced.
const OUTBOUND_IDLE: Duration = Duration::from_secs(600);
/// How long a delivered payload's circuit is held open for its answer.
const ANSWER_WAIT: Duration = Duration::from_secs(180);
/// How long an outbound circuit is kept, after a step of a group, for the
/// group's next step; then closed.
const KEEP_FOR_GROUP: Duration = Duration::from_secs(30);
/// First hops a node keeps.
const GUARDS: usize = 3;
/// A guard is kept this long, plus up to as much again at random.
const GUARD_LIFETIME: u64 = 30 * 86_400;
/// A guard unreachable this long without a success between is replaced.
const GUARD_DOWN: u64 = 86_400;

/// `d` give or take a third, at random: a keepalive's interval.
pub(super) fn jitter(d: Duration) -> Duration {
    let x = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0);
    let third = (d.as_millis() as u64 / 3).max(1);
    d - Duration::from_millis(third) + Duration::from_millis(x % (2 * third))
}

/// A relay kept as a first hop, until a unix time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Guard {
    id: Digest,
    until: u64,
    /// Since when (unix) its channel has failed with no success since.
    down_since: Option<u64>,
}

/// A circuit standing to one of our rendezvous points, and our session
/// over it.
struct Standing {
    point: Digest,
    addr: Option<SocketAddr>,
    circuit: Option<u64>,
    ready: bool,
    held: u64,
    asked: Option<Instant>,
    answered: Option<Instant>,
    offered: Option<(u64, Instant)>,
    /// Not before then: a circuit to build again, or a refusal.
    wait: Option<Instant>,
    was_live: bool,
    /// Since when a keepalive has gone unanswered.
    unanswered: Option<Instant>,
    /// The wait before the next keepalive, drawn when the last went.
    interval: Duration,
    /// When the circuit is to be replaced.
    rotate_at: Option<Instant>,
    /// Its replacement, being built.
    next: Option<u64>,
    /// The circuit it replaced, closed once the session is live again.
    retiring: Option<(u64, Instant)>,
    /// Whether our delegation and certificates went up the circuit since
    /// it was built.
    published: bool,
}

impl Standing {
    fn live(&self, seq: u64, now: Instant) -> bool {
        self.ready && self.held == seq && self.answered.is_some_and(|t| now.duration_since(t) < SESSION_TIMEOUT)
    }
}

enum Stage {
    /// No live circuit yet.
    Waiting,
    /// Asked our point for the recipient's announce.
    Lookup,
    /// Sent, by the payload's object id.
    Sent(Digest),
    /// Delivered; the circuit held open for the answer, since then.
    Awaiting(Instant),
    /// Told the recipient was offline, once: asked again (a lookup on the
    /// same circuit) from then.
    Retry(Instant),
}

struct Job {
    out: Outbound,
    circuit: Option<u64>,
    stage: Stage,
    started: Instant,
    /// The return route the payload carries, and the one-time key its
    /// answer is sealed to.
    route: Option<(onion::Route, crate::mlkem::SecretKey)>,
    /// Told "offline" first then: asked again until [`OFFLINE_WAIT`] on.
    offline_since: Option<Instant>,
}

/// A circuit for one send or one broadcast, carrying no session of ours.
struct Out {
    handle: u64,
    /// Its last relay.
    last: Digest,
    ready: bool,
    /// Taken by a send or a broadcast: closed when that is done.
    taken: bool,
    built: Instant,
}

/// A delegation (`docs/SUBNAMES.md`) or a sub-name certificate
/// (`docs/SUBNAME_CERT.md`) asked for, over an outbound circuit.
struct Fetch {
    tag: u64,
    /// The owner's id, or the full name's point id for a certificate.
    owner: Digest,
    cert: bool,
    /// Its group (`Outbound::group`), zero for none.
    group: u64,
    circuit: Option<u64>,
    started: Instant,
}

/// A transaction of ours to be announced by a relay.
struct Broadcast {
    txid: Digest,
    bytes: Vec<u8>,
    /// The circuit it was sent on, and when.
    sent: Option<(u64, Instant)>,
    /// Circuits that did not take it.
    tried: Vec<u64>,
    started: Instant,
    why: String,
}

pub(super) struct Participant {
    standing: Vec<Standing>,
    /// Standing circuits to points we no longer have (a new address, or a
    /// new relay list), closed once the new points' sessions are live or
    /// after [`RETIRE_WAIT`]: we stay reachable throughout.
    leaving: Vec<(u64, Instant)>,
    /// The id the standing circuits hold sessions for: on a new address
    /// every one is replaced, even to the same point, so that no point
    /// sees one circuit move from the old id to the new.
    standing_id: Option<Digest>,
    outbound: Vec<Out>,
    /// Whether an outbound circuit had to end at one of our points, logged
    /// once.
    short_list: bool,
    jobs: Vec<Job>,
    broadcasts: Vec<Broadcast>,
    /// Our sub-name delegation, published at our points while it is set.
    pub(super) delegation: Option<Vec<u8>>,
    /// Sub-name certificates we hold (bundles), published through our
    /// points to their full names' points.
    pub(super) certs: Vec<Vec<u8>>,
    fetches: Vec<Fetch>,
    /// Outbound circuits a group's step is done with, kept for its next:
    /// the circuit, the group and until when.
    kept: Vec<(u64, u64, Instant)>,
    /// Outbound circuits built since start.
    built: u64,
    /// The epoch whose new points this node, as a sub-name issuer, has
    /// republished the delegations naming it at.
    republished: Option<u32>,
    /// The epoch whose new points this node has carried its certificates
    /// to: a standing circuit kept across the boundary (our own point
    /// unchanged) would not publish them again by itself.
    carried: Option<u32>,
    /// Delegations republished: the circuit, the delegation's object id
    /// and since when, until the relay answers.
    pushes: Vec<(u64, Digest, Instant)>,
    /// Tests: the owners a server republishes for, without names on chain.
    #[cfg(test)]
    pub(super) test_owners: Option<Vec<Digest>>,
    /// [`onion::KEEPALIVE_SECS`] and [`ROTATE_EVERY`], shorter in tests.
    keepalive: Duration,
    rotate_every: Duration,
    /// [`OFFLINE_WAIT`], set by tests.
    offline_wait: Duration,
    /// Relays whose channel failed lately, and when.
    /// Relays not chosen as hops until a time.
    avoid: std::collections::HashMap<Digest, Instant>,
    /// First hops, loaded from the data directory on first use.
    guards: Option<Vec<Guard>>,
}

impl Default for Participant {
    fn default() -> Participant {
        Participant {
            standing: Vec::new(),
            leaving: Vec::new(),
            standing_id: None,
            outbound: Vec::new(),
            short_list: false,
            jobs: Vec::new(),
            broadcasts: Vec::new(),
            delegation: None,
            certs: Vec::new(),
            fetches: Vec::new(),
            kept: Vec::new(),
            built: 0,
            republished: None,
            carried: None,
            pushes: Vec::new(),
            #[cfg(test)]
            test_owners: None,
            keepalive: KEEPALIVE,
            rotate_every: ROTATE_EVERY,
            offline_wait: OFFLINE_WAIT,
            avoid: std::collections::HashMap::new(),
            guards: None,
        }
    }
}

impl Participant {
    /// Tests: keepalives and rotation sooner.
    #[cfg(test)]
    pub(super) fn set_timing(&mut self, keepalive: Duration, rotate_every: Duration, offline_wait: Duration) {
        self.keepalive = keepalive;
        self.rotate_every = rotate_every;
        self.offline_wait = offline_wait;
    }

    /// A time to replace a circuit built now: two to four hours on.
    fn rotate_at(&self, now: Instant) -> Instant {
        let x = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0);
        let spread = self.rotate_every.as_millis() as u64;
        now + self.rotate_every + Duration::from_millis(x % spread.max(1))
    }
}

impl<V: ProofVerifier + Send + Sync + 'static> Node<V> {
    /// Our points and whether each session is live, for the prompt.
    pub(super) fn onion_summary(&self, now: Instant) -> Vec<(SocketAddr, bool)> {
        let Some(seq) = self.rv.me.as_ref().map(|m| m.seq) else { return Vec::new() };
        let unknown = SocketAddr::from(([0, 0, 0, 0], 0));
        self.part.standing.iter().map(|s| (s.addr.unwrap_or(unknown), s.live(seq, now))).collect()
    }

    /// Outbound circuits built since start.
    pub(super) fn outbound_built(&self) -> u64 {
        self.part.built
    }

    /// Whether our own transactions go out over a circuit: in onion mode,
    /// with a wallet.
    pub(super) fn broadcasts_privately(&self) -> bool {
        self.rv.onion_active() && self.rv.wallet
    }

    /// A transaction of ours, pooled: to a relay over a circuit.
    pub(super) fn onion_broadcast(&mut self, txid: Digest, bytes: Vec<u8>, now: Instant) {
        if self.part.broadcasts.iter().any(|b| b.txid == txid) {
            return;
        }
        self.part.broadcasts.push(Broadcast {
            txid,
            bytes,
            sent: None,
            tried: Vec::new(),
            started: now,
            why: String::new(),
        });
        self.progress_broadcasts(now);
    }

    /// Sends each broadcast not yet out over a live circuit it was not
    /// tried on; gives up those out of time.
    fn progress_broadcasts(&mut self, now: Instant) {
        if !self.rv.wallet {
            return;
        }
        let mut i = 0;
        while i < self.part.broadcasts.len() {
            let b = &mut self.part.broadcasts[i];
            if b.sent.is_some_and(|(_, t)| now.duration_since(t) >= BROADCAST_WAIT) {
                let (h, _) = b.sent.take().unwrap();
                b.tried.push(h);
                b.why = "no answer from the relay".into();
                self.release_outbound(h, "broadcast unanswered", now);
            }
            let b = &mut self.part.broadcasts[i];
            if b.sent.is_none() && now.duration_since(b.started) >= BROADCAST_TIMEOUT {
                let b = self.part.broadcasts.remove(i);
                let why = if b.why.is_empty() { "no circuit to send it over".to_string() } else { b.why };
                self.log(&format!(
                    "onion: transaction {} not broadcast: {why}; it stays in this node's pool, unannounced",
                    crate::poseidon2::digest_to_bytes(&b.txid)
                        .iter()
                        .take(8)
                        .map(|x| format!("{x:02x}"))
                        .collect::<String>()
                ));
                self.rv.note(Note::Broadcast { txid: b.txid, how: Err(why) });
                continue;
            }
            if b.sent.is_none()
                && let Some(h) = self.take_outbound()
            {
                // A circuit of its own: not the one the payment's payload
                // went up, so its relay cannot tie the two.
                let b = &mut self.part.broadcasts[i];
                b.sent = Some((h, now));
                let bytes = b.bytes.clone();
                let last = self.circuit_hops(h).saturating_sub(1);
                if let Err(e) = self.circuit_send(h, last, circuit::BROADCAST, &bytes, now) {
                    self.part.broadcasts[i].sent = None;
                    self.part.broadcasts[i].why = e;
                    self.release_outbound(h, "broadcast not sent", now);
                }
            }
            i += 1;
        }
    }

    /// A ready outbound circuit no send or broadcast has, now taken.
    fn take_outbound(&mut self) -> Option<u64> {
        let o = self.part.outbound.iter_mut().find(|o| o.ready && !o.taken)?;
        o.taken = true;
        Some(o.handle)
    }

    /// The circuit kept for `group`'s next step, if any, else a ready one.
    fn take_outbound_for(&mut self, group: u64) -> Option<u64> {
        if group != 0
            && let Some(i) = self.part.kept.iter().position(|(_, g, _)| *g == group)
        {
            let (h, _, _) = self.part.kept.remove(i);
            self.chatter("onion: a circuit used again for the next step of one send");
            return Some(h);
        }
        self.take_outbound()
    }

    /// A step on outbound circuit `handle` is done: kept a while for the
    /// next step of its group, or closed.
    fn finish_outbound(&mut self, handle: u64, group: u64, why: &str, now: Instant) {
        if group != 0 && self.part.outbound.iter().any(|o| o.handle == handle) {
            self.part.kept.retain(|(h, _, _)| *h != handle);
            self.part.kept.push((handle, group, now + KEEP_FOR_GROUP));
            return;
        }
        self.release_outbound(handle, why, now);
    }

    /// An outbound circuit's send or broadcast is done: it is closed, never
    /// used for another (but within a group: [`Self::finish_outbound`]).
    fn release_outbound(&mut self, handle: u64, why: &str, now: Instant) {
        self.part.kept.retain(|(h, _, _)| *h != handle);
        if let Some(i) = self.part.outbound.iter().position(|o| o.handle == handle) {
            self.part.outbound.remove(i);
            self.close_circuit(handle, why, now);
        }
    }

    /// Keeps outbound circuits ready: one spare, and one for each send or
    /// broadcast waiting; replaces spares idle too long.
    fn keep_outbound(&mut self, now: Instant) {
        let stale: Vec<u64> = self
            .part
            .outbound
            .iter()
            .filter(|o| o.ready && !o.taken && now.duration_since(o.built) >= OUTBOUND_IDLE)
            .map(|o| o.handle)
            .collect();
        for h in stale {
            self.release_outbound(h, "idle", now);
        }
        let done: Vec<u64> = self.part.kept.iter().filter(|(_, _, t)| now >= *t).map(|(h, _, _)| *h).collect();
        for h in done {
            self.release_outbound(h, "its group is done", now);
        }
        let kept = |g: u64| g != 0 && self.part.kept.iter().any(|(_, k, _)| *k == g);
        let waiting = self.part.jobs.iter().filter(|j| matches!(j.stage, Stage::Waiting) && !kept(j.out.group)).count()
            + self.part.broadcasts.iter().filter(|b| b.sent.is_none()).count()
            + self.part.fetches.iter().filter(|f| f.circuit.is_none()).count();
        let free = self.part.outbound.iter().filter(|o| !o.taken).count();
        let want = (SPARE_OUTBOUND + waiting).saturating_sub(free);
        for _ in 0..want {
            if self.part.outbound.len() >= MAX_OUTBOUND {
                break;
            }
            let Some(path) = self.outbound_path() else { break };
            let last = *path.last().unwrap();
            match self.build_circuit(path, Vec::new(), now) {
                Ok(handle) => {
                    self.part.built += 1;
                    self.part.outbound.push(Out { handle, last, ready: false, taken: false, built: now })
                }
                Err(e) => {
                    self.log(&format!("onion: no outbound circuit: {e}"));
                    break;
                }
            }
        }
    }

    /// A path for an outbound circuit: a random last relay that is none of
    /// our rendezvous points (one of them only when the list has no other),
    /// and two hops before it, the first a guard; relays whose channel
    /// failed lately are left out while enough others remain.
    fn outbound_path(&mut self) -> Option<Vec<Digest>> {
        let me = self.config.relay_id();
        // All three of our points, not only the one holding our session:
        // the session moves to another when one fails.
        let points: Vec<Digest> = match self.rv.me.as_ref() {
            Some(m) => self.onion_points_of(&m.id),
            None => Vec::new(),
        };
        let relays = self.rv.onion_sets().into_iter().next()?;
        let now = Instant::now();
        let mut all: Vec<Digest> = relays.iter().map(|r| r.id).filter(|r| Some(*r) != me).collect();
        let healthy: Vec<Digest> =
            all.iter().copied().filter(|r| self.part.avoid.get(r).is_none_or(|t| now >= *t)).collect();
        if healthy.len() > HOPS {
            all = healthy;
        }
        let pick = |v: &mut Vec<Digest>| {
            let x = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0);
            v.swap_remove((x % v.len() as u64) as usize)
        };
        let mut lasts: Vec<Digest> = all.iter().copied().filter(|r| !points.contains(r)).collect();
        if lasts.is_empty() {
            if !self.part.short_list {
                self.part.short_list = true;
                self.log("onion: too few relays listed for a last hop that is not one of our rendezvous points");
            }
            lasts = all.clone();
        }
        if lasts.is_empty() {
            return None;
        }
        let last = pick(&mut lasts);
        let mut others: Vec<Digest> = all.into_iter().filter(|r| *r != last).collect();
        let mut path = Vec::new();
        if let Some(g) = self.guard(&[last]) {
            others.retain(|r| *r != g);
            path.push(g);
        }
        while path.len() < HOPS && !others.is_empty() {
            path.push(pick(&mut others));
        }
        path.push(last);
        Some(path)
    }

    /// Back in init mode: the standing circuits go, sends fail.
    pub(super) fn onion_stand_down(&mut self, now: Instant) {
        if self.part.standing.is_empty()
            && self.part.leaving.is_empty()
            && self.part.outbound.is_empty()
            && self.part.jobs.is_empty()
            && self.part.broadcasts.is_empty()
        {
            return;
        }
        for b in std::mem::take(&mut self.part.broadcasts) {
            self.rv.note(Note::Broadcast { txid: b.txid, how: Err("the network went back to init mode".into()) });
        }
        let standing = std::mem::take(&mut self.part.standing);
        for s in standing {
            if let Some(h) = s.circuit {
                self.close_circuit(h, "init mode", now);
            }
        }
        self.part.kept.clear();
        for o in std::mem::take(&mut self.part.outbound) {
            self.close_circuit(o.handle, "init mode", now);
        }
        for (h, _) in std::mem::take(&mut self.part.leaving) {
            self.close_circuit(h, "init mode", now);
        }
        for j in std::mem::take(&mut self.part.jobs) {
            self.rv.note(Note::Failed {
                tag: j.out.tag,
                to: j.out.to,
                why: "the network went back to init mode".into(),
            });
        }
        // Init mode holds no delegations: none, so the owner is asked.
        for f in std::mem::take(&mut self.part.fetches) {
            self.fetch_note(&f, Ok(None));
        }
    }

    /// Once a second: circuits built, sessions kept, sends moved on.
    pub(super) fn onion_participate(&mut self, now: Instant) {
        #[cfg(test)]
        if self.quiet {
            return;
        }
        let Some(me) = self.rv.me.as_ref() else {
            // No address (`address off`): no sessions anywhere, though
            // sends and broadcasts go on, naming no one.
            let standing = std::mem::take(&mut self.part.standing);
            self.part.standing_id = None;
            for h in standing.iter().flat_map(|s| [s.circuit, s.next, s.retiring.map(|r| r.0)]).flatten() {
                self.close_circuit(h, "the address is off", now);
            }
            for (h, _) in std::mem::take(&mut self.part.leaving) {
                self.close_circuit(h, "the address is off", now);
            }
            self.keep_outbound(now);
            self.progress_onion_sends(now);
            self.progress_broadcasts(now);
            self.progress_fetches(now);
            return;
        };
        let (id, made) = (me.id, me.made);
        if me.rotate || now.duration_since(made) >= ROTATE_AFTER {
            self.rotate(now);
            for s in &mut self.part.standing {
                s.asked = None;
            }
        }
        // Our points under every relay list in force: during a switch, the
        // old list's and the new one's.
        // Not this node's own relay: a circuit cannot end where it starts
        // (a relay is best run without a wallet in any case).
        // A server carries the delegations naming it to the points of a
        // new epoch, once it has moved itself: their owners may be away.
        if self.rv.switching() && self.part.republished != Some(self.rv.epoch) && self.rv.moved(now) {
            self.part.republished = Some(self.rv.epoch);
            self.republish_delegations(id, now);
        }
        // A holder carries its certificates to their full names' points of
        // the new epoch, once it has moved: up whatever standing circuits
        // it has, new or kept.
        if self.rv.switching() && self.part.carried != Some(self.rv.epoch) && self.rv.moved(now) {
            self.part.carried = Some(self.rv.epoch);
            if !self.part.certs.is_empty() {
                for s in &mut self.part.standing {
                    s.published = false;
                }
            }
        }
        let relay = self.config.relay_id();
        let all: Vec<Digest> = self.own_points_of(&id, now).into_iter().filter(|p| Some(*p) != relay).collect();
        let new_id = self.part.standing_id.is_some_and(|s| s != id);
        self.part.standing_id = Some(id);
        // A session at every one of our points (`docs/ONION.md`): a sender
        // reaches us through any of them that is up, each one's circuit
        // rebuilt on its own when it fails.
        let points: Vec<Digest> = all;
        if new_id || points.iter().ne(self.part.standing.iter().map(|s| &s.point)) {
            let mut old = std::mem::take(&mut self.part.standing);
            if new_id {
                // Nothing of the old address's carries over.
                for s in std::mem::take(&mut old) {
                    for h in [s.circuit, s.retiring.map(|r| r.0)].into_iter().flatten() {
                        self.part.leaving.push((h, now));
                    }
                    if let Some(h) = s.next {
                        self.close_circuit(h, "a new address", now);
                    }
                }
            }
            for p in &points {
                match old.iter().position(|s| s.point == *p) {
                    Some(i) => self.part.standing.push(old.swap_remove(i)),
                    None => {
                        let addr = self.relay_addr(p);
                        self.part.standing.push(Standing {
                            point: *p,
                            addr,
                            circuit: None,
                            ready: false,
                            held: 0,
                            asked: None,
                            answered: None,
                            offered: None,
                            wait: None,
                            was_live: false,
                            unanswered: None,
                            interval: KEEPALIVE,
                            rotate_at: None,
                            next: None,
                            retiring: None,
                            published: false,
                        });
                    }
                }
            }
            // The old points' circuits stay until the new sessions are live.
            for s in old {
                for h in [s.circuit, s.retiring.map(|r| r.0)].into_iter().flatten() {
                    self.part.leaving.push((h, now));
                }
                if let Some(h) = s.next {
                    self.close_circuit(h, "no longer a rendezvous point", now);
                }
            }
            let names: Vec<String> = points.iter().map(onion::short).collect();
            self.log(&format!("onion: rendezvous points {}", names.join(", ")));
        }
        let seq = self.rv.me.as_ref().unwrap().seq;
        let all_live = self.part.standing.iter().all(|s| s.live(seq, now));
        let gone: Vec<u64> = self
            .part
            .leaving
            .iter()
            .filter(|(_, since)| all_live || now.duration_since(*since) >= RETIRE_WAIT)
            .map(|(h, _)| *h)
            .collect();
        self.part.leaving.retain(|(h, _)| !gone.contains(h));
        for h in gone {
            self.close_circuit(h, "no longer a rendezvous point", now);
        }
        let mut lost = Vec::new();
        let mut build = Vec::new();
        let mut replace = Vec::new();
        let mut retire = Vec::new();
        let mut ask = Vec::new();
        let mut publish = Vec::new();
        let keepalive = self.part.keepalive;
        let delegated = self.part.delegation.is_some() || !self.part.certs.is_empty();
        for (i, s) in self.part.standing.iter_mut().enumerate() {
            if let Some((old, since)) = s.retiring
                && (s.live(seq, now) || now.duration_since(since) >= RETIRE_WAIT)
            {
                s.retiring = None;
                retire.push(old);
            }
            if s.wait.is_some_and(|t| now < t) {
                continue;
            }
            let Some(h) = s.circuit else {
                build.push(i);
                continue;
            };
            if !s.ready {
                continue;
            }
            // A keepalive unanswered: a hop is gone, or the point.
            if s.unanswered.is_some_and(|t| now.duration_since(t) >= DEAD_AFTER)
                || (s.was_live && !s.live(seq, now) && s.held == seq)
            {
                lost.push(h);
                continue;
            }
            if s.next.is_none() && s.retiring.is_none() && s.rotate_at.is_some_and(|t| now >= t) && s.live(seq, now) {
                replace.push(i);
            }
            if delegated && !s.published && s.live(seq, now) {
                s.published = true;
                publish.push(h);
            }
            let wait = if s.live(seq, now) { s.interval } else { SESSION_RETRY };
            if s.asked.is_none_or(|t| now.duration_since(t) >= wait) {
                s.asked = Some(now);
                s.interval = jitter(keepalive);
                s.unanswered.get_or_insert(now);
                ask.push(h);
            }
        }
        for h in lost {
            self.log("onion: a rendezvous session went quiet; building its circuit again");
            self.close_circuit(h, "its session went quiet", now);
        }
        for h in retire {
            self.close_circuit(h, "replaced", now);
        }
        for i in build {
            self.build_standing(i, now);
        }
        for i in replace {
            if let Some(path) = self.standing_path(i) {
                match self.build_circuit(path, Vec::new(), now) {
                    Ok(h) => self.part.standing[i].next = Some(h),
                    Err(e) => self.log(&format!("onion: no replacement circuit: {e}")),
                }
            }
        }
        for h in ask {
            let last = self.circuit_hops(h).saturating_sub(1);
            let _ = self.circuit_send(h, last, circuit::SESSION, &digest_to_bytes(&id), now);
        }
        let certs = self.part.certs.clone();
        for h in publish {
            let last = self.circuit_hops(h).saturating_sub(1);
            if let Some(d) = self.part.delegation.clone() {
                let _ = self.circuit_send(h, last, circuit::PUBLISH, &d, now);
            }
            for b in &certs {
                let _ = self.circuit_send(h, last, circuit::PUBLISH_CERT, b, now);
            }
        }
        self.keep_outbound(now);
        self.progress_onion_sends(now);
        self.progress_broadcasts(now);
        self.progress_fetches(now);
    }

    /// Our delegation, or none: published at our point once its session
    /// is live, again on every new circuit or point.
    pub(super) fn set_delegation(&mut self, d: Option<Vec<u8>>) {
        self.part.delegation = d;
        for s in &mut self.part.standing {
            s.published = false;
        }
    }

    /// The sub-name certificates we hold, as bundles: published through
    /// our points once a session is live, again on every new circuit or
    /// point.
    pub(super) fn set_certs(&mut self, certs: Vec<Vec<u8>>) {
        self.part.certs = certs;
        for s in &mut self.part.standing {
            s.published = false;
        }
    }

    /// The wallet asks for `owner`'s delegation.
    pub(super) fn get_delegation(&mut self, tag: u64, owner: Digest, group: u64, now: Instant) {
        self.start_fetch(Fetch { tag, owner, cert: false, group, circuit: None, started: now }, now);
    }

    /// The wallet asks for the certificate of the full name whose point id
    /// is `point`.
    pub(super) fn get_cert(&mut self, tag: u64, point: Digest, group: u64, now: Instant) {
        self.start_fetch(Fetch { tag, owner: point, cert: true, group, circuit: None, started: now }, now);
    }

    fn start_fetch(&mut self, f: Fetch, now: Instant) {
        if !self.rv.onion_active() {
            // Init mode holds none: the owner is its own server.
            return self.fetch_note(&f, Ok(None));
        }
        if self.part.fetches.len() >= MAX_SENDS {
            return self.fetch_note(&f, Err("too many lookups in progress".into()));
        }
        self.part.fetches.push(f);
        self.progress_fetches(now);
    }

    /// The wallet's answer to fetch `f`: the bytes held (a delegation or a
    /// bundle), none, or why not.
    fn fetch_note(&mut self, f: &Fetch, result: Result<Option<Vec<u8>>, String>) {
        if f.cert {
            let result = result.map(|b| b.and_then(|b| crate::subnames::Bundle::from_bytes(&b)));
            self.rv.note(Note::Cert { tag: f.tag, point: f.owner, result });
        } else {
            let result = result.map(|b| b.and_then(|b| crate::subnames::Delegation::from_bytes(&b)));
            self.rv.note(Note::Delegation { tag: f.tag, owner: f.owner, result });
        }
    }

    /// Asks for each delegation not yet asked, over an outbound circuit of
    /// its own; gives up those out of time.
    fn progress_fetches(&mut self, now: Instant) {
        let late: Vec<u64> =
            self.part.pushes.iter().filter(|(_, _, t)| now.duration_since(*t) >= SEND_TIMEOUT).map(|p| p.0).collect();
        for h in late {
            self.part.pushes.retain(|p| p.0 != h);
            self.release_outbound(h, "republish unanswered", now);
        }
        let mut i = 0;
        while i < self.part.fetches.len() {
            if now.duration_since(self.part.fetches[i].started) >= SEND_TIMEOUT {
                let f = self.part.fetches.remove(i);
                if let Some(h) = f.circuit {
                    self.release_outbound(h, "lookup unanswered", now);
                }
                let why = if f.circuit.is_some() { "no answer from the relay" } else { "no circuit to ask over" };
                self.fetch_note(&f, Err(why.into()));
                continue;
            }
            let group = self.part.fetches[i].group;
            if self.part.fetches[i].circuit.is_none()
                && let Some(h) = self.take_outbound_for(group)
            {
                self.part.fetches[i].circuit = Some(h);
                let owner = self.part.fetches[i].owner;
                let cmd = if self.part.fetches[i].cert { circuit::GET_CERT } else { circuit::GET_DELEGATION };
                let last = self.circuit_hops(h).saturating_sub(1);
                if self.circuit_send(h, last, cmd, &digest_to_bytes(&owner), now).is_err() {
                    self.part.fetches[i].circuit = None;
                    self.release_outbound(h, "lookup not sent", now);
                }
            }
            i += 1;
        }
    }

    /// As a sub-name issuer: asks for the delegation of every owner it
    /// issued certificates under, to publish again those that name it
    /// ([`Self::fetched`]): an owner away at the boundary would otherwise
    /// leave its new points without the delegation the issuer renews by.
    fn republish_delegations(&mut self, me: Digest, now: Instant) {
        #[cfg(test)]
        if let Some(owners) = self.part.test_owners.clone() {
            for (i, owner) in owners.into_iter().enumerate() {
                self.get_delegation(super::sessions::NODE_TAG | i as u64, owner, 1000 + i as u64, now);
            }
            return;
        }
        // The owners whose delegations name us, from the certificates we
        // issued under them.
        let mut owners: Vec<Digest> = Vec::new();
        for b in self.part.certs.iter().filter_map(|b| crate::subnames::Bundle::from_bytes(b)) {
            if let Some(d) = &b.delegation
                && d.issuers.contains(&me)
                && b.cert.issuer() == me
                && !owners.contains(&d.owner())
            {
                owners.push(d.owner());
            }
        }
        for owner in owners {
            let x = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0);
            let tag = super::sessions::NODE_TAG | (x >> 1);
            self.get_delegation(tag, owner, x | 1, now);
        }
    }

    /// The answer to certificate fetch `i`: done, its circuit closed or
    /// kept for its group's next step.
    fn fetched_cert(&mut self, i: usize, result: Result<Option<Vec<u8>>, String>, now: Instant) {
        let f = self.part.fetches.remove(i);
        if let Some(h) = f.circuit {
            self.finish_outbound(h, f.group, "lookup answered", now);
        }
        self.fetch_note(&f, result);
    }

    /// The answer to fetch `i`: done, its circuit closed.
    fn fetched(&mut self, i: usize, result: Result<Option<crate::subnames::Delegation>, String>, now: Instant) {
        let f = self.part.fetches.remove(i);
        if f.tag & super::sessions::NODE_TAG != 0 {
            // Our own, to republish: up the same circuit, if it names us.
            let me = self.rv.me.as_ref().map(|m| m.id);
            match (result, f.circuit) {
                (Ok(Some(d)), Some(h))
                    if me.is_some_and(|m| d.issuers.contains(&m)) && d.verify(&f.owner, unix_now()) =>
                {
                    let bytes = d.to_bytes();
                    let last = self.circuit_hops(h).saturating_sub(1);
                    match self.circuit_send(h, last, circuit::PUBLISH, &bytes, now) {
                        Ok(()) => self.part.pushes.push((h, Object::id_of(&bytes), now)),
                        Err(_) => self.release_outbound(h, "republish not sent", now),
                    }
                }
                (_, Some(h)) => self.release_outbound(h, "nothing to republish", now),
                _ => {}
            }
            return;
        }
        if let Some(h) = f.circuit {
            self.finish_outbound(h, f.group, "lookup answered", now);
        }
        self.rv.note(Note::Delegation { tag: f.tag, owner: f.owner, result });
    }

    /// A relay whose channel failed: not a hop for a while.
    pub(super) fn avoid_relay(&mut self, id: Digest, now: Instant) {
        self.avoid_relay_for(id, now, AVOID);
    }

    /// A relay that answered with another key than its listed id's.
    pub(super) fn relay_key_mismatch(&mut self, id: Digest, now: Instant) {
        self.avoid_relay_for(id, now, WRONG_KEY_AVOID);
    }

    fn avoid_relay_for(&mut self, id: Digest, now: Instant, wait: Duration) {
        let until = self.part.avoid.get(&id).map_or(now + wait, |t| (*t).max(now + wait));
        self.part.avoid.insert(id, until);
        self.part.avoid.retain(|_, t| *t > now);
        // A guard's failures are counted in time: one down for a day
        // goes.
        if let Some(guards) = self.part.guards.as_mut()
            && let Some(g) = guards.iter_mut().find(|g| g.id == id && g.down_since.is_none())
        {
            g.down_since = Some(unix_now());
            self.save_guards();
        }
    }

    /// A channel to relay `id` opened: a guard down until now is up.
    pub(super) fn relay_reached(&mut self, id: Digest) {
        if let Some(guards) = self.part.guards.as_mut()
            && let Some(g) = guards.iter_mut().find(|g| g.id == id && g.down_since.is_some())
        {
            g.down_since = None;
            self.save_guards();
        }
    }

    fn save_guards(&mut self) {
        let (Some(f), Some(guards)) = (self.guards_file(), self.part.guards.as_ref()) else { return };
        let text: String = guards
            .iter()
            .map(|g| {
                let hex: String = digest_to_bytes(&g.id).iter().map(|b| format!("{b:02x}")).collect();
                match g.down_since {
                    Some(d) => format!("{hex} {} {d}\n", g.until),
                    None => format!("{hex} {}\n", g.until),
                }
            })
            .collect();
        if let Err(e) = std::fs::write(&f, text) {
            self.log(&format!("onion: saving guards: {e}"));
        }
    }

    /// A path to standing point `i`: a guard, a random hop from the list
    /// the point is in (the preferred one first), then it; relays whose
    /// channel failed lately are left out while enough others remain.
    fn standing_path(&mut self, i: usize) -> Option<Vec<Digest>> {
        let point = self.part.standing[i].point;
        let me = self.config.relay_id();
        let relays = self.rv.onion_sets().into_iter().find(|s| s.iter().any(|r| r.id == point))?;
        let mut others: Vec<Digest> = relays.iter().map(|r| r.id).filter(|r| *r != point && Some(*r) != me).collect();
        let now = Instant::now();
        let healthy: Vec<Digest> =
            others.iter().copied().filter(|r| self.part.avoid.get(r).is_none_or(|t| now >= *t)).collect();
        if healthy.len() >= HOPS.min(others.len()) {
            others = healthy;
        }
        let mut path = Vec::new();
        if let Some(g) = self.guard(&[point]) {
            others.retain(|r| *r != g);
            path.push(g);
        }
        while path.len() < HOPS && !others.is_empty() {
            let x = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0);
            path.push(others.swap_remove((x % others.len() as u64) as usize));
        }
        path.push(point);
        Some(path)
    }

    /// Where the guards are kept: beside the peers file.
    fn guards_file(&self) -> Option<std::path::PathBuf> {
        Some(self.config.peers_file.as_ref()?.with_file_name("guards"))
    }

    /// A guard to start a circuit with, not one of `exclude` (the
    /// circuit's last hop) nor one whose channel failed lately; `None`
    /// when no guard will do, and the first hop is then any relay. The
    /// guards are kept up first: loaded, those gone from the list or out
    /// of time replaced, the set saved when it changed.
    fn guard(&mut self, exclude: &[Digest]) -> Option<Digest> {
        let now_unix = unix_now();
        let listed: Vec<Digest> = self.rv.onion_sets().into_iter().next()?.iter().map(|r| r.id).collect();
        let me = self.config.relay_id();
        if self.part.guards.is_none() {
            let loaded = self
                .guards_file()
                .and_then(|f| std::fs::read_to_string(f).ok())
                .map(|text| {
                    text.lines()
                        .filter_map(|l| {
                            let mut f = l.split_whitespace();
                            let id = crate::wallet::digest_from_hex(f.next()?).and_then(|b| digest_from_bytes(&b))?;
                            let until = f.next()?.parse().ok()?;
                            let down_since = f.next().and_then(|d| d.parse().ok());
                            Some(Guard { id, until, down_since })
                        })
                        .collect()
                })
                .unwrap_or_default();
            self.part.guards = Some(loaded);
        }
        let mut guards = self.part.guards.clone().unwrap_or_default();
        let before = guards.clone();
        guards.retain(|g| {
            g.until > now_unix
                && listed.contains(&g.id)
                && Some(g.id) != me
                && g.down_since.is_none_or(|d| now_unix < d + GUARD_DOWN)
        });
        let mut candidates: Vec<Digest> =
            listed.iter().copied().filter(|r| Some(*r) != me && !guards.iter().any(|g| g.id == *r)).collect();
        while guards.len() < GUARDS && !candidates.is_empty() {
            let x = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0);
            let id = candidates.swap_remove((x % candidates.len() as u64) as usize);
            guards.push(Guard { id, until: now_unix + GUARD_LIFETIME + x % GUARD_LIFETIME, down_since: None });
        }
        if guards != before {
            self.part.guards = Some(guards.clone());
            self.save_guards();
            let names: Vec<String> = guards.iter().map(|g| onion::short(&g.id)).collect();
            self.log(&format!("onion: guards {}", names.join(", ")));
        }
        self.part.guards = Some(guards.clone());
        let now = Instant::now();
        let usable: Vec<Digest> = guards
            .iter()
            .map(|g| g.id)
            .filter(|g| !exclude.contains(g))
            .filter(|g| self.part.avoid.get(g).is_none_or(|t| now >= *t))
            .collect();
        if usable.is_empty() {
            return None;
        }
        let x = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0);
        Some(usable[(x % usable.len() as u64) as usize])
    }

    /// Builds the circuit to standing point `i`.
    fn build_standing(&mut self, i: usize, now: Instant) {
        let point = self.part.standing[i].point;
        let Some(path) = self.standing_path(i) else { return };
        let rotate_at = self.part.rotate_at(now);
        let s = &mut self.part.standing[i];
        s.wait = Some(now + REBUILD_WAIT);
        match self.build_circuit(path, Vec::new(), now) {
            Ok(h) => {
                let s = &mut self.part.standing[i];
                s.circuit = Some(h);
                s.ready = false;
                s.published = false;
                s.held = 0;
                s.asked = None;
                s.answered = None;
                s.offered = None;
                s.unanswered = None;
                s.rotate_at = Some(rotate_at);
            }
            Err(e) => self.log(&format!("onion: no circuit to {}: {e}", onion::short(&point))),
        }
    }

    /// A circuit of ours is built.
    pub(super) fn onion_circuit_ready(&mut self, handle: u64, now: Instant) {
        let rotate_at = self.part.rotate_at(now);
        if let Some(o) = self.part.outbound.iter_mut().find(|o| o.handle == handle) {
            o.ready = true;
            o.built = now;
            self.progress_onion_sends(now);
            self.progress_broadcasts(now);
        } else if let Some(s) = self.part.standing.iter_mut().find(|s| s.circuit == Some(handle)) {
            s.ready = true;
            s.asked = None;
            s.wait = None;
        } else if let Some(s) = self.part.standing.iter_mut().find(|s| s.next == Some(handle)) {
            // A replacement: the session moves onto it, then the old one
            // goes. The point holds nothing on the new circuit yet, which
            // is not a lost session: no new key.
            s.retiring = s.circuit.map(|old| (old, now));
            s.was_live = false;
            s.circuit = Some(handle);
            s.next = None;
            s.ready = true;
            s.published = false;
            s.held = 0;
            s.asked = None;
            s.answered = None;
            s.offered = None;
            s.unanswered = None;
            s.rotate_at = Some(rotate_at);
            self.chatter("onion: a standing circuit replaced");
        }
    }

    /// A circuit of ours ended: built again later, with a new key if its
    /// session was live; sends on it go to another.
    /// `at_end`: it failed while its last hop was being added, so for a
    /// standing circuit the point is at fault, not a hop on the way.
    pub(super) fn onion_circuit_gone(&mut self, handle: u64, at_end: bool, now: Instant) {
        self.part.outbound.retain(|o| o.handle != handle);
        self.part.kept.retain(|(h, _, _)| *h != handle);
        self.part.leaving.retain(|(h, _)| *h != handle);
        let mut rotate = false;
        for s in self.part.standing.iter_mut().filter(|s| s.next == Some(handle)) {
            // A replacement that failed: the next try a minute on.
            s.next = None;
            s.rotate_at = Some(now + Duration::from_secs(60));
        }
        let mut refused_at: Option<Digest> = None;
        for s in self.part.standing.iter_mut().filter(|s| s.circuit == Some(handle)) {
            if at_end {
                refused_at = Some(s.point);
            }
            rotate |= s.was_live;
            s.circuit = None;
            s.ready = false;
            s.was_live = false;
            // Not before a later wait already set (a point that refused
            // our session is asked again only after REFUSED_RETRY).
            let t = now + REBUILD_WAIT;
            s.wait = Some(s.wait.map_or(t, |w| w.max(t)));
        }
        if let Some(p) = refused_at {
            self.log(&format!("onion: our rendezvous point {} did not take the circuit", onion::short(&p)));
        }
        if rotate {
            self.rotate(now);
            for s in &mut self.part.standing {
                s.asked = None;
            }
        }
        for j in self.part.jobs.iter_mut().filter(|j| j.circuit == Some(handle)) {
            j.circuit = None;
            j.stage = Stage::Waiting;
        }
        for b in self.part.broadcasts.iter_mut().filter(|b| b.sent.is_some_and(|(h, _)| h == handle)) {
            b.sent = None;
            b.tried.push(handle);
        }
        for f in self.part.fetches.iter_mut().filter(|f| f.circuit == Some(handle)) {
            f.circuit = None;
        }
        self.part.pushes.retain(|(h, _, _)| *h != handle);
    }

    /// A message from the last hop of one of our circuits: `true` if it
    /// was the participant's.
    /// Tells the circuit's last hop that payload `msg` arrived.
    fn acknowledge(&mut self, handle: u64, msg: &[u8], now: Instant) {
        let last = self.circuit_hops(handle).saturating_sub(1);
        let object = digest_to_bytes(&Object::id_of(msg));
        if let Err(e) = self.circuit_send(handle, last, circuit::RECEIVED, &object, now) {
            self.chatter(&format!("onion: acknowledging a delivery: {e}"));
        }
    }

    pub(super) fn onion_message(&mut self, handle: u64, cmd: u8, msg: &[u8], now: Instant) -> bool {
        let standing = self.part.standing.iter().position(|s| s.circuit == Some(handle));
        let job = self.part.jobs.iter().any(|j| j.circuit == Some(handle))
            || self.part.outbound.iter().any(|o| o.handle == handle);
        // A circuit being replaced is still ours: what comes down it while
        // the session moves to the new one is taken.
        let retiring = self.part.standing.iter().any(|s| s.retiring.is_some_and(|(h, _)| h == handle))
            || self.part.leaving.iter().any(|(h, _)| *h == handle);
        if standing.is_none() && !job && !retiring {
            return false;
        }
        // The answer to a broadcast of ours.
        if cmd == circuit::NOTICE
            && msg.len() == 33
            && let Some(subject) = digest_from_bytes(&msg[..32])
            && let Some(i) =
                self.part.broadcasts.iter().position(|b| b.txid == subject && b.sent.is_some_and(|(h, _)| h == handle))
        {
            let relay = self.part.outbound.iter().find(|o| o.handle == handle).map_or(crate::onion::NOBODY, |o| o.last);
            self.release_outbound(handle, "broadcast answered", now);
            if msg[32] == NOTICE_FORWARDED {
                let b = self.part.broadcasts.remove(i);
                self.log(&format!("onion: our transaction announced by {}", onion::short(&relay)));
                self.rv.note(Note::Broadcast {
                    txid: b.txid,
                    how: Ok(format!("announced by relay {}", onion::short(&relay))),
                });
            } else {
                let b = &mut self.part.broadcasts[i];
                b.sent = None;
                b.tried.push(handle);
                b.why = "a relay refused it".into();
                self.progress_broadcasts(now);
            }
            return true;
        }
        // The answer to republishing another's delegation.
        if cmd == circuit::NOTICE
            && msg.len() == 33
            && let Some(i) =
                self.part.pushes.iter().position(|(h, o, _)| *h == handle && digest_from_bytes(&msg[..32]) == Some(*o))
        {
            self.part.pushes.remove(i);
            self.release_outbound(handle, "republished", now);
            if msg[32] == NOTICE_FORWARDED {
                self.chatter("onion: a delegation naming us republished at its owner's new points");
            } else {
                self.log("onion: a relay would not take a delegation we republished");
            }
            return true;
        }
        // The answer to publishing one of our certificates.
        if cmd == circuit::NOTICE
            && msg.len() == 33
            && self.part.certs.iter().any(|b| digest_from_bytes(&msg[..32]) == Some(Object::id_of(b)))
        {
            if msg[32] == NOTICE_FORWARDED {
                self.chatter("onion: a sub-name certificate passed to its points");
            } else {
                self.log("onion: a relay would not take our sub-name certificate");
            }
            return true;
        }
        // The answer to publishing our delegation.
        if cmd == circuit::NOTICE
            && msg.len() == 33
            && let Some(d) = &self.part.delegation
            && digest_from_bytes(&msg[..32]) == Some(Object::id_of(d))
        {
            if msg[32] == NOTICE_FORWARDED {
                self.chatter("onion: our delegation is held at our rendezvous point");
            } else {
                self.log("onion: our rendezvous point would not hold our delegation");
            }
            return true;
        }
        // The answer to a certificate asked for.
        if let Some(i) = self.part.fetches.iter().position(|f| f.circuit == Some(handle) && f.cert) {
            let point = self.part.fetches[i].owner;
            match cmd {
                circuit::CERT => match crate::subnames::Bundle::from_bytes(msg) {
                    Some(b) if b.point() == point => self.fetched_cert(i, Ok(Some(msg.to_vec())), now),
                    _ => self.fetched_cert(i, Err("a malformed certificate".into()), now),
                },
                circuit::NOTICE if msg.len() == 33 && digest_from_bytes(&msg[..32]) == Some(point) => match msg[32] {
                    NOTICE_OFFLINE => self.fetched_cert(i, Ok(None), now),
                    _ => self.fetched_cert(i, Err("refused by the relay".into()), now),
                },
                _ => {}
            }
            return true;
        }
        // The answer to a delegation asked for.
        if let Some(i) = self.part.fetches.iter().position(|f| f.circuit == Some(handle)) {
            let owner = self.part.fetches[i].owner;
            match cmd {
                circuit::DELEGATION => match crate::subnames::Delegation::from_bytes(msg) {
                    Some(d) if d.owner() == owner => self.fetched(i, Ok(Some(d)), now),
                    _ => self.fetched(i, Err("a malformed delegation".into()), now),
                },
                circuit::NOTICE if msg.len() == 33 && digest_from_bytes(&msg[..32]) == Some(owner) => match msg[32] {
                    NOTICE_OFFLINE => self.fetched(i, Ok(None), now),
                    _ => self.fetched(i, Err("refused by the relay".into()), now),
                },
                _ => {}
            }
            return true;
        }
        match cmd {
            circuit::SESSION_STATE => {
                if let Some(i) = standing
                    && msg.len() == 48
                {
                    let nonce = u64::from_le_bytes(msg[32..40].try_into().unwrap());
                    let seq = u64::from_le_bytes(msg[40..48].try_into().unwrap());
                    self.on_standing_state(i, handle, nonce, seq, now);
                }
            }
            circuit::ANNOUNCE => {
                let Some(a) = Announce::from_bytes(msg) else { return true };
                let Some(j) =
                    self.part.jobs.iter().position(|j| {
                        j.circuit == Some(handle) && matches!(j.stage, Stage::Lookup) && j.out.to == a.id
                    })
                else {
                    return true;
                };
                if !a.verify(unix_now()) {
                    return self.fail_send(j, "its announce does not verify".into());
                }
                self.part.jobs[j].out.recipient = Some(a);
                self.seal_and_send(j, handle, now);
            }
            circuit::NOTICE => {
                if msg.len() != 33 {
                    return true;
                }
                let Some(subject) = digest_from_bytes(&msg[..32]) else { return true };
                let code = msg[32];
                if let Some(j) = self.part.jobs.iter().position(|j| {
                    j.circuit == Some(handle)
                        && match j.stage {
                            Stage::Lookup => j.out.to == subject,
                            Stage::Sent(o) => o == subject,
                            Stage::Waiting | Stage::Awaiting(_) | Stage::Retry(_) => false,
                        }
                }) {
                    if code == NOTICE_FORWARDED {
                        let via = self.circuit_first(handle).unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
                        let (tag, to) = (self.part.jobs[j].out.tag, self.part.jobs[j].out.to);
                        self.log(&format!("onion: delivered to {}", onion::short(&to)));
                        self.rv.note(Note::Delivered { tag, to, via });
                        if self.part.jobs[j].route.is_some() {
                            // The answer comes down this circuit.
                            self.part.jobs[j].stage = Stage::Awaiting(now);
                        } else {
                            let job = self.part.jobs.remove(j);
                            self.finish_outbound(handle, job.out.group, "sent", now);
                        }
                    } else if code == NOTICE_OFFLINE
                        && now.duration_since(self.part.jobs[j].offline_since.unwrap_or(now)) < self.part.offline_wait
                        && now.duration_since(self.part.jobs[j].started) + OFFLINE_RETRY < SEND_TIMEOUT
                    {
                        // Its sessions may be moving: asked again shortly,
                        // its announce looked up afresh, until
                        // OFFLINE_WAIT after the first "offline".
                        let job = &mut self.part.jobs[j];
                        let first = job.offline_since.is_none();
                        job.offline_since.get_or_insert(now);
                        job.out.recipient = None;
                        job.stage = Stage::Retry(now + OFFLINE_RETRY);
                        let to = job.out.to;
                        if first {
                            self.chatter(&format!("onion: {} offline for now; asking again", onion::short(&to)));
                        }
                    } else {
                        let why = match code {
                            NOTICE_OFFLINE => "offline: none of its rendezvous points holds a session for it",
                            NOTICE_REFUSED => "refused by the relay",
                            NOTICE_REJECTED => "rejected",
                            _ => "an unknown answer",
                        };
                        self.fail_send(j, why.into());
                    }
                } else if code != NOTICE_FORWARDED
                    && let Some(i) = standing
                    && self.rv.me.as_ref().is_some_and(|m| m.id == subject)
                {
                    // Our point refused or rejected our session: asked
                    // again later; our other points hold theirs meanwhile.
                    self.log(&format!(
                        "onion: {} would not hold our session",
                        onion::short(&self.part.standing[i].point)
                    ));
                    self.part.standing[i].wait = Some(now + REFUSED_RETRY);
                    self.close_circuit(handle, "refused", now);
                }
            }
            circuit::DELIVER => {
                let object = Object::from_bytes(msg);
                // Acknowledged to the hop that delivered it, before
                // anything else (an answer releases its circuit).
                if matches!(object, Some(Object::Payload(_))) {
                    self.acknowledge(handle, msg, now);
                }
                match object {
                    Some(Object::Payload(p)) if self.rv.me.as_ref().is_some_and(|m| m.id == p.to) => {
                        self.open(format!("circuit {handle}"), p);
                    }
                    // The answer to a payload of ours, down its circuit.
                    Some(Object::Payload(p)) => {
                        let Some(j) = self.part.jobs.iter().position(|j| {
                            j.circuit == Some(handle) && j.route.as_ref().is_some_and(|(r, _)| r.reply_id() == p.to)
                        }) else {
                            self.chatter("onion: a delivery that is not a payload for us");
                            return true;
                        };
                        let job = self.part.jobs.remove(j);
                        // An answer before the point's notice (they race
                        // down the circuit) proves the delivery too.
                        if matches!(job.stage, Stage::Sent(_)) {
                            let via = self.circuit_first(handle).unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
                            self.log(&format!("onion: delivered to {}, answered first", onion::short(&job.out.to)));
                            self.rv.note(Note::Delivered { tag: job.out.tag, to: job.out.to, via });
                        }
                        self.finish_outbound(handle, job.out.group, "answered", now);
                        let (_, key) = job.route.unwrap();
                        match p.open(&key, unix_now()) {
                            Some(mut opened) => {
                                opened.answers = Some(job.out.to);
                                self.log(&format!("onion: an answer from {}", onion::short(&job.out.to)));
                                self.rv.note(Note::Received(opened));
                            }
                            None => self.log("onion: an answer that our one-time key does not open"),
                        }
                    }
                    _ => self.chatter("onion: a delivery that is not a payload for us"),
                }
            }
            _ => return false,
        }
        true
    }

    fn on_standing_state(&mut self, i: usize, handle: u64, nonce: u64, seq: u64, now: Instant) {
        let Some(me) = self.rv.me.as_ref() else { return };
        let s = &mut self.part.standing[i];
        s.answered = Some(now);
        s.unanswered = None;
        s.held = seq;
        if seq == me.seq {
            let s = &mut self.part.standing[i];
            if !s.was_live {
                s.was_live = true;
                let point = s.point;
                self.log(&format!("onion: rendezvous session at {} live", onion::short(&point)));
            }
            return;
        }
        if s.was_live && seq == 0 {
            // It forgot us: a reconnect, so a new key.
            s.was_live = false;
            self.rotate(now);
            for s in &mut self.part.standing {
                s.asked = None;
            }
        }
        let me = self.rv.me.as_ref().unwrap();
        let s = &mut self.part.standing[i];
        if s.offered.is_some_and(|(q, t)| q == me.seq && now.duration_since(t) < SESSION_RETRY) {
            return;
        }
        s.offered = Some((me.seq, now));
        s.asked = Some(now);
        let bytes = me.announce(nonce).to_bytes();
        let last = self.circuit_hops(handle).saturating_sub(1);
        let _ = self.circuit_send(handle, last, circuit::ANNOUNCE, &bytes, now);
    }

    /// A message from the wallet, in onion mode.
    pub(super) fn onion_send(&mut self, out: Outbound, now: Instant) {
        if self.part.jobs.len() >= MAX_SENDS {
            return self.rv.note(Note::Failed { tag: out.tag, to: out.to, why: "too many sends in progress".into() });
        }
        self.part.jobs.push(Job { out, circuit: None, stage: Stage::Waiting, started: now, route: None, offline_since: None });
        self.progress_onion_sends(now);
    }

    fn progress_onion_sends(&mut self, now: Instant) {
        if !self.rv.wallet {
            return;
        }
        let mut i = 0;
        while i < self.part.jobs.len() {
            if let Stage::Awaiting(since) = self.part.jobs[i].stage {
                if now.duration_since(since) >= ANSWER_WAIT {
                    // Delivered, unanswered: the circuit goes.
                    let job = self.part.jobs.remove(i);
                    self.chatter(&format!("onion: no answer from {}", onion::short(&job.out.to)));
                    if let Some(h) = job.circuit {
                        self.release_outbound(h, "no answer", now);
                    }
                    continue;
                }
                i += 1;
                continue;
            }
            // A retry due: its lookup again, on its circuit.
            if let Stage::Retry(at) = self.part.jobs[i].stage
                && now >= at
            {
                match self.part.jobs[i].circuit {
                    Some(h) => {
                        let to = self.part.jobs[i].out.to;
                        self.part.jobs[i].stage = Stage::Lookup;
                        let last = self.circuit_hops(h).saturating_sub(1);
                        let _ = self.circuit_send(h, last, circuit::GET_ANNOUNCE, &digest_to_bytes(&to), now);
                    }
                    None => self.part.jobs[i].stage = Stage::Waiting,
                }
            }
            if now.duration_since(self.part.jobs[i].started) >= SEND_TIMEOUT {
                let why = match self.part.jobs[i].stage {
                    Stage::Waiting => "no circuit to send over",
                    _ => "no answer from the relay",
                };
                self.fail_send(i, why.into());
                continue;
            }
            let group = self.part.jobs[i].out.group;
            if matches!(self.part.jobs[i].stage, Stage::Waiting)
                && let Some(h) = self.take_outbound_for(group)
            {
                let j = &mut self.part.jobs[i];
                j.circuit = Some(h);
                if j.out.reply.is_some() {
                    self.send_reply(i, h, now);
                    if i < self.part.jobs.len() && !matches!(self.part.jobs[i].stage, Stage::Waiting) {
                        i += 1;
                    }
                    continue;
                }
                // The way back: a token left with the circuit's last relay.
                let route = self.leave_route(h, now);
                let j = &mut self.part.jobs[i];
                j.route = route;
                match j.out.recipient.clone().filter(|a| a.verify(unix_now())) {
                    Some(_) => self.seal_and_send(i, h, now),
                    None => {
                        j.stage = Stage::Lookup;
                        let to = j.out.to;
                        let last = self.circuit_hops(h).saturating_sub(1);
                        let _ = self.circuit_send(h, last, circuit::GET_ANNOUNCE, &digest_to_bytes(&to), now);
                    }
                }
                if i < self.part.jobs.len() && !matches!(self.part.jobs[i].stage, Stage::Waiting) {
                    i += 1;
                }
                continue;
            }
            i += 1;
        }
    }

    /// Leaves a return route's token with the last relay of outbound
    /// circuit `h`: the route, and the key made for its one answer.
    fn leave_route(&mut self, h: u64, now: Instant) -> Option<(onion::Route, crate::mlkem::SecretKey)> {
        let relay = self.part.outbound.iter().find(|o| o.handle == h)?.last;
        let token = random_bytes::<{ circuit::TOKEN_LEN }>().ok()?;
        let key = crate::mlkem::keygen(&random_bytes::<64>().ok()?);
        let last = self.circuit_hops(h).saturating_sub(1);
        self.circuit_send(h, last, circuit::ROUTE, &token, now).ok()?;
        Some((onion::Route { relay, token, kyber: key.public_key().to_vec() }, key))
    }

    /// Sends job `j`, an answer along a return route, up circuit `h`.
    fn send_reply(&mut self, j: usize, h: u64, now: Instant) {
        let job = &self.part.jobs[j];
        let Some(route) = job.out.reply.clone() else { return };
        let (m, nonce) = match (random_bytes::<32>(), random_bytes::<12>()) {
            (Ok(m), Ok(n)) => (m, n),
            _ => {
                self.fail_send(j, "no randomness".into());
                return;
            }
        };
        let Some(p) = onion::Payload::seal_reply(&route, job.out.kind, &job.out.inner, &m, nonce) else {
            self.fail_send(j, "the route's key is malformed".into());
            return;
        };
        let bytes = Object::Payload(p).to_bytes();
        let mut msg = digest_to_bytes(&route.relay).to_vec();
        msg.extend_from_slice(&route.token);
        msg.extend_from_slice(&bytes);
        self.part.jobs[j].stage = Stage::Sent(Object::id_of(&bytes));
        let last = self.circuit_hops(h).saturating_sub(1);
        if let Err(e) = self.circuit_send(h, last, circuit::REPLY, &msg, now) {
            self.fail_send(j, e);
        }
    }

    fn seal_and_send(&mut self, j: usize, handle: u64, now: Instant) {
        let job = &self.part.jobs[j];
        let Some(a) = job.out.recipient.clone() else { return };
        // Unnamed: the way back is inside, no id or key of ours.
        let sealed = match (&job.route, random_bytes::<32>(), random_bytes::<12>()) {
            (Some((route, _)), Ok(m), Ok(nonce)) => {
                onion::Payload::seal(&a, None, Some(route), job.out.kind, &job.out.inner, &m, nonce)
                    .map(|p| Object::Payload(p).to_bytes())
                    .ok_or_else(|| "the recipient's Kyber key is malformed".to_string())
                    .and_then(|b| {
                        if b.len() > onion::MAX_OBJECT {
                            Err(format!("the message is too large: {} bytes", b.len()))
                        } else {
                            Ok(b)
                        }
                    })
            }
            (None, ..) => Err("no return route".to_string()),
            _ => Err("no randomness".to_string()),
        };
        match sealed {
            Ok(bytes) => {
                let object = Object::id_of(&bytes);
                self.part.jobs[j].stage = Stage::Sent(object);
                let last = self.circuit_hops(handle).saturating_sub(1);
                if let Err(e) = self.circuit_send(handle, last, circuit::SEND, &bytes, now) {
                    self.fail_send(j, e);
                }
            }
            Err(why) => {
                self.fail_send(j, why);
            }
        }
    }

    fn fail_send(&mut self, j: usize, why: String) -> bool {
        let job = self.part.jobs.remove(j);
        if let Some(h) = job.circuit {
            self.release_outbound(h, "send failed", Instant::now());
        }
        self.log(&format!("onion: could not reach {}: {why}", onion::short(&job.out.to)));
        self.rv.note(Note::Failed { tag: job.out.tag, to: job.out.to, why });
        true
    }
}
