//! Onion mode's participant (`docs/ONION.md`): the wallet's node keeps a
//! circuit standing to each of its rendezvous points, holds its session
//! over it, and sends and receives over them.
//!
//! Each circuit runs through two listed relays chosen at random (fewer
//! when the file lists too few others) to the point, which the id names.
//! Over it the node asks for a session every [`onion::KEEPALIVE_SECS`]
//! (every few seconds while the point does not hold its current
//! announce) and offers its announce bound to the nonce the point gives,
//! the same Kyber key at every point, rotated as in init mode: at start,
//! when a session is lost (a circuit that dies, a point that forgets us)
//! and after half its lifetime. A circuit that dies is built again after
//! a few seconds.
//!
//! The node's own transactions go the same way in onion mode: up a live
//! circuit to the rendezvous point, which pools and announces it as its
//! own, so that the first node to announce it is a relay and not the
//! sender. One that no circuit takes in [`BROADCAST_TIMEOUT`] is left in
//! the node's pool unannounced, and the wallet told: it is never
//! announced from the node's own address.
//!
//! A send goes over any live circuit: the recipient's announce is asked
//! of our point (unless the wallet gave it, from a payload it answers),
//! the payload sealed to it and sent; the point answers forwarded, or
//! offline once every point of the recipient was tried. A payload
//! delivered down a circuit is opened with our keys and handed to the
//! wallet.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::sessions::{Note, Outbound};
use super::{Node, unix_now};
use crate::chain::ProofVerifier;
use crate::circuit;
use crate::net::{NOTICE_FORWARDED, NOTICE_OFFLINE, NOTICE_REFUSED, NOTICE_REJECTED};
use crate::onion::{self, Announce, Object};
use crate::pow::Digest;
use crate::poseidon2::{digest_from_bytes, digest_to_bytes};
use crate::wallet::random_bytes;

const KEEPALIVE: Duration = Duration::from_secs(onion::KEEPALIVE_SECS);
const SESSION_TIMEOUT: Duration = Duration::from_secs(onion::SESSION_TIMEOUT_SECS);
const SESSION_RETRY: Duration = Duration::from_secs(3);
const REFUSED_RETRY: Duration = Duration::from_secs(60);
const ROTATE_AFTER: Duration = Duration::from_secs(onion::ANNOUNCE_LIFETIME_SECS / 2);
/// A circuit that died is built again after this.
const REBUILD_WAIT: Duration = Duration::from_secs(3);
/// Random hops before the rendezvous point.
const HOPS: usize = 2;
/// A send not answered by then fails; it waits as long for a circuit.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SENDS: usize = 64;
/// A broadcast unanswered by then is tried on another circuit.
const BROADCAST_WAIT: Duration = Duration::from_secs(15);
/// One no circuit took by then is given up.
const BROADCAST_TIMEOUT: Duration = Duration::from_secs(120);

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
}

struct Job {
    out: Outbound,
    circuit: Option<u64>,
    stage: Stage,
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

#[derive(Default)]
pub(super) struct Participant {
    standing: Vec<Standing>,
    jobs: Vec<Job>,
    broadcasts: Vec<Broadcast>,
}

impl<V: ProofVerifier + Send + Sync + 'static> Node<V> {
    /// Our points and whether each session is live, for the prompt.
    pub(super) fn onion_summary(&self, now: Instant) -> Vec<(SocketAddr, bool)> {
        let Some(seq) = self.rv.me.as_ref().map(|m| m.seq) else { return Vec::new() };
        let unknown = SocketAddr::from(([0, 0, 0, 0], 0));
        self.part.standing.iter().map(|s| (s.addr.unwrap_or(unknown), s.live(seq, now))).collect()
    }

    /// Whether our own transactions go out over a circuit: in onion mode,
    /// with a wallet.
    pub(super) fn broadcasts_privately(&self) -> bool {
        self.rv.relays().is_some() && self.rv.me.is_some()
    }

    /// A transaction of ours, pooled: to a relay over a circuit.
    pub(super) fn onion_broadcast(&mut self, txid: Digest, bytes: Vec<u8>, now: Instant) {
        if self.part.broadcasts.iter().any(|b| b.txid == txid) {
            return;
        }
        self.part.broadcasts.push(Broadcast { txid, bytes, sent: None, tried: Vec::new(), started: now, why: String::new() });
        self.progress_broadcasts(now);
    }

    /// Sends each broadcast not yet out over a live circuit it was not
    /// tried on; gives up those out of time.
    fn progress_broadcasts(&mut self, now: Instant) {
        let Some(seq) = self.rv.me.as_ref().map(|m| m.seq) else { return };
        let live: Vec<u64> = self.part.standing.iter().filter(|s| s.live(seq, now)).filter_map(|s| s.circuit).collect();
        let mut i = 0;
        while i < self.part.broadcasts.len() {
            let b = &mut self.part.broadcasts[i];
            if b.sent.is_some_and(|(_, t)| now.duration_since(t) >= BROADCAST_WAIT) {
                let (h, _) = b.sent.take().unwrap();
                b.tried.push(h);
                b.why = "no answer from the relay".into();
            }
            if b.sent.is_none() && now.duration_since(b.started) >= BROADCAST_TIMEOUT {
                let b = self.part.broadcasts.remove(i);
                let why = if b.why.is_empty() { "no circuit to send it over".to_string() } else { b.why };
                self.log(&format!(
                    "onion: transaction {} not broadcast: {why}; it stays in this node's pool, unannounced",
                    crate::poseidon2::digest_to_bytes(&b.txid).iter().take(8).map(|x| format!("{x:02x}")).collect::<String>()
                ));
                self.rv.note(Note::Broadcast { txid: b.txid, how: Err(why) });
                continue;
            }
            if b.sent.is_none() {
                // Circuits not yet tried first; all of them again once each was.
                let fresh: Vec<u64> = live.iter().copied().filter(|h| !b.tried.contains(h)).collect();
                let pool = if fresh.is_empty() { live.clone() } else { fresh };
                if !pool.is_empty() {
                    let x = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0) as usize;
                    let h = pool[x % pool.len()];
                    b.sent = Some((h, now));
                    let bytes = b.bytes.clone();
                    let last = self.circuit_hops(h).saturating_sub(1);
                    if let Err(e) = self.circuit_send(h, last, circuit::BROADCAST, &bytes, now) {
                        self.part.broadcasts[i].sent = None;
                        self.part.broadcasts[i].why = e;
                    }
                }
            }
            i += 1;
        }
    }

    /// Back in init mode: the standing circuits go, sends fail.
    pub(super) fn onion_stand_down(&mut self, now: Instant) {
        if self.part.standing.is_empty() && self.part.jobs.is_empty() && self.part.broadcasts.is_empty() {
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
        for j in std::mem::take(&mut self.part.jobs) {
            self.rv.note(Note::Failed { tag: j.out.tag, to: j.out.to, why: "the network went back to init mode".into() });
        }
    }

    /// Once a second: circuits built, sessions kept, sends moved on.
    pub(super) fn onion_participate(&mut self, now: Instant) {
        #[cfg(test)]
        if self.quiet {
            return;
        }
        let Some(me) = self.rv.me.as_ref() else { return };
        let (id, made) = (me.id, me.made);
        if me.rotate || now.duration_since(made) >= ROTATE_AFTER {
            self.rotate(now);
            for s in &mut self.part.standing {
                s.asked = None;
            }
        }
        let Some(relays) = self.rv.relays() else { return };
        let points: Vec<Digest> = onion::rendezvous_indexes(&id, relays.len())
            .into_iter()
            .map(|i| relays[i].id)
            .filter(|p| *p != id)
            .collect();
        if points.iter().ne(self.part.standing.iter().map(|s| &s.point)) {
            let mut old = std::mem::take(&mut self.part.standing);
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
                        });
                    }
                }
            }
            for s in old {
                if let Some(h) = s.circuit {
                    self.close_circuit(h, "no longer a rendezvous point", now);
                }
            }
            let names: Vec<String> = points.iter().map(onion::short).collect();
            self.log(&format!("onion: rendezvous points {}", names.join(", ")));
        }
        let seq = self.rv.me.as_ref().unwrap().seq;
        let mut lost = Vec::new();
        let mut build = Vec::new();
        let mut ask = Vec::new();
        for (i, s) in self.part.standing.iter_mut().enumerate() {
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
            if s.was_live && !s.live(seq, now) && s.held == seq {
                lost.push(h);
                continue;
            }
            let wait = if s.live(seq, now) { KEEPALIVE } else { SESSION_RETRY };
            if s.asked.is_none_or(|t| now.duration_since(t) >= wait) {
                s.asked = Some(now);
                ask.push(h);
            }
        }
        for h in lost {
            self.log("onion: a rendezvous session went quiet; building its circuit again");
            self.close_circuit(h, "its session went quiet", now);
        }
        for i in build {
            self.build_standing(i, now);
        }
        for h in ask {
            let last = self.circuit_hops(h).saturating_sub(1);
            let _ = self.circuit_send(h, last, circuit::SESSION, &digest_to_bytes(&id), now);
        }
        self.progress_onion_sends(now);
        self.progress_broadcasts(now);
    }

    /// Builds the circuit to standing point `i`: random hops, then it.
    fn build_standing(&mut self, i: usize, now: Instant) {
        let point = self.part.standing[i].point;
        let me = self.rv.me.as_ref().map(|m| m.id);
        let mut others: Vec<Digest> = match self.rv.relays() {
            Some(r) => r.iter().map(|r| r.id).filter(|r| *r != point && Some(*r) != me).collect(),
            None => return,
        };
        let mut path = Vec::new();
        while path.len() < HOPS && !others.is_empty() {
            let x = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0);
            path.push(others.swap_remove((x % others.len() as u64) as usize));
        }
        path.push(point);
        let s = &mut self.part.standing[i];
        s.wait = Some(now + REBUILD_WAIT);
        match self.build_circuit(path, Vec::new(), now) {
            Ok(h) => {
                let s = &mut self.part.standing[i];
                s.circuit = Some(h);
                s.ready = false;
                s.held = 0;
                s.asked = None;
                s.answered = None;
                s.offered = None;
            }
            Err(e) => self.log(&format!("onion: no circuit to {}: {e}", onion::short(&point))),
        }
    }

    /// A circuit of ours is built.
    pub(super) fn onion_circuit_ready(&mut self, handle: u64) {
        if let Some(s) = self.part.standing.iter_mut().find(|s| s.circuit == Some(handle)) {
            s.ready = true;
            s.asked = None;
            s.wait = None;
        }
    }

    /// A circuit of ours ended: built again later, with a new key if its
    /// session was live; sends on it go to another.
    pub(super) fn onion_circuit_gone(&mut self, handle: u64, now: Instant) {
        let mut rotate = false;
        for s in self.part.standing.iter_mut().filter(|s| s.circuit == Some(handle)) {
            rotate |= s.was_live;
            s.circuit = None;
            s.ready = false;
            s.was_live = false;
            s.wait = Some(now + REBUILD_WAIT);
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
    }

    /// A message from the last hop of one of our circuits: `true` if it
    /// was the participant's.
    pub(super) fn onion_message(&mut self, handle: u64, cmd: u8, msg: &[u8], now: Instant) -> bool {
        let standing = self.part.standing.iter().position(|s| s.circuit == Some(handle));
        let job = self.part.jobs.iter().any(|j| j.circuit == Some(handle));
        if standing.is_none() && !job {
            return false;
        }
        // The answer to a broadcast of ours.
        if cmd == circuit::NOTICE
            && msg.len() == 33
            && let Some(subject) = digest_from_bytes(&msg[..32])
            && let Some(i) = self.part.broadcasts.iter().position(|b| b.txid == subject && b.sent.is_some_and(|(h, _)| h == handle))
        {
            if msg[32] == NOTICE_FORWARDED {
                let b = self.part.broadcasts.remove(i);
                let point = standing.map_or(crate::onion::NOBODY, |s| self.part.standing[s].point);
                self.log(&format!("onion: our transaction announced by {}", onion::short(&point)));
                self.rv.note(Note::Broadcast { txid: b.txid, how: Ok(format!("announced by relay {}", onion::short(&point))) });
            } else {
                let b = &mut self.part.broadcasts[i];
                b.sent = None;
                b.tried.push(handle);
                b.why = "a relay refused it".into();
                self.progress_broadcasts(now);
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
                let Some(j) = self
                    .part
                    .jobs
                    .iter()
                    .position(|j| j.circuit == Some(handle) && matches!(j.stage, Stage::Lookup) && j.out.to == a.id)
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
                            Stage::Waiting => false,
                        }
                }) {
                    if code == NOTICE_FORWARDED {
                        let j = self.part.jobs.remove(j);
                        let via = self.circuit_first(handle).unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
                        self.log(&format!("onion: delivered to {}", onion::short(&j.out.to)));
                        self.rv.note(Note::Delivered { tag: j.out.tag, to: j.out.to, via });
                    } else {
                        let why = match code {
                            NOTICE_OFFLINE => "offline: none of its rendezvous points holds a session for it",
                            NOTICE_REFUSED => "refused by our rendezvous point",
                            NOTICE_REJECTED => "rejected",
                            _ => "an unknown answer",
                        };
                        self.fail_send(j, why.into());
                    }
                } else if code != NOTICE_FORWARDED
                    && let Some(i) = standing
                    && self.rv.me.as_ref().is_some_and(|m| m.id == subject)
                {
                    // Our point refused or rejected our session.
                    self.log(&format!("onion: {} would not hold our session", onion::short(&self.part.standing[i].point)));
                    self.part.standing[i].wait = Some(now + REFUSED_RETRY);
                    self.close_circuit(handle, "refused", now);
                }
            }
            circuit::DELIVER => match Object::from_bytes(msg) {
                Some(Object::Payload(p)) if self.rv.me.as_ref().is_some_and(|m| m.id == p.to) => {
                    self.open(format!("circuit {handle}"), p);
                }
                _ => self.chatter("onion: a delivery that is not a payload for us"),
            },
            _ => return false,
        }
        true
    }

    fn on_standing_state(&mut self, i: usize, handle: u64, nonce: u64, seq: u64, now: Instant) {
        let Some(me) = self.rv.me.as_ref() else { return };
        let s = &mut self.part.standing[i];
        s.answered = Some(now);
        s.held = seq;
        if seq == me.seq {
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
        self.part.jobs.push(Job { out, circuit: None, stage: Stage::Waiting, started: now });
        self.progress_onion_sends(now);
    }

    fn progress_onion_sends(&mut self, now: Instant) {
        let Some(seq) = self.rv.me.as_ref().map(|m| m.seq) else { return };
        let live: Vec<u64> = self.part.standing.iter().filter(|s| s.live(seq, now)).filter_map(|s| s.circuit).collect();
        let mut i = 0;
        while i < self.part.jobs.len() {
            if now.duration_since(self.part.jobs[i].started) >= SEND_TIMEOUT {
                let why = match self.part.jobs[i].stage {
                    Stage::Waiting => "no rendezvous session to send over",
                    _ => "no answer from our rendezvous point",
                };
                self.fail_send(i, why.into());
                continue;
            }
            if matches!(self.part.jobs[i].stage, Stage::Waiting) && !live.is_empty() {
                let x = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0) as usize;
                let h = live[x % live.len()];
                let j = &mut self.part.jobs[i];
                j.circuit = Some(h);
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

    fn seal_and_send(&mut self, j: usize, handle: u64, now: Instant) {
        let job = &self.part.jobs[j];
        let Some(a) = job.out.recipient.clone() else { return };
        match self.seal(&a, job.out.kind, &job.out.inner) {
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
        self.log(&format!("onion: could not reach {}: {why}", onion::short(&job.out.to)));
        self.rv.note(Note::Failed { tag: job.out.tag, to: job.out.to, why });
        true
    }
}
