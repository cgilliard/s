//! Channels of onion mode (`docs/ONION.md`): the handshake that opens an
//! authenticated, encrypted link to a relay, and the link itself, which
//! delivers bodies in order over a lossy datagram network by
//! acknowledgement and resending. Pure state; the node moves the bytes.
//!
//! # Handshake
//!
//! ```text
//! Hello  initiator → relay   mutual flag, challenge (32), fresh Kyber key
//! Reply  relay → initiator   Dilithium key, Kyber ciphertext, signature
//! Auth   initiator → relay   Dilithium key, signature (relay to relay only)
//! ```
//!
//! The transcript hash `th` covers the channel number, the hello, the
//! relay's key and the ciphertext; the relay signs it under its context,
//! the initiator (when it is a relay too) under another, so neither
//! signature can stand for the other. The initiator checks the relay's
//! key against the id it expects, so the relay proves it holds the key the
//! consensus file names. Both derive two keys, one per direction, from
//! the shared secret and `th`. The Kyber key is made for the one
//! handshake and dropped, so every channel is forward secret.
//!
//! # Frames
//!
//! A data frame carries a sequence number from 1, a body sealed with
//! ChaCha20-Poly1305 under the nonce `0 ‖ seq`, and what its sender has
//! received: everything below `ack`, and the 64 after it as a bitmap. An
//! ack-only frame carries the same under the nonce `1 ‖ n` of its own
//! counter. A frame is resent as the very bytes first sent, never sealed
//! again, so no nonce ever covers two messages. Bodies are delivered in
//! order; up to [`WINDOW`] frames are in flight, the rest queued. An
//! empty body is a keepalive.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use crate::chacha20poly1305::{self, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::codec::{Reader, Writer};
use crate::keccak;
use crate::mldsa;
use crate::mlkem;
use crate::xmss::Digest;

pub const HELLO_LEN: usize = 1 + 32 + mlkem::EK_LEN;
pub const REPLY_LEN: usize = mldsa::PK_LEN + mlkem::CT_LEN + mldsa::SIG_LEN;
pub const AUTH_LEN: usize = mldsa::PK_LEN + mldsa::SIG_LEN;
/// Frames in flight, unacknowledged; the acknowledgement bitmap covers
/// as many past the first missing.
pub const WINDOW: u64 = 64;
/// Bodies queued behind a full window before [`Channel::send`] refuses.
pub const MAX_QUEUE: usize = 1024;
/// Largest body: what fits a datagram with the frame's header.
pub const MAX_BODY: usize = 1232 - FRAME_OVERHEAD;
/// The datagram's magic and type, the channel number, the frame's kind,
/// sequence and acknowledgements, and the tag.
pub const FRAME_OVERHEAD: usize = 5 + 8 + 1 + 8 + 8 + 8 + TAG_LEN;
/// First wait for an acknowledgement, before the round trip is measured;
/// then it follows the round trip (RFC 6298: the smoothed time and four
/// times its variation), never under [`MIN_RTO`]; it doubles with each
/// resend. A geostationary satellite's round trip is 600 ms or more, so a
/// fixed short wait would send every frame twice.
pub const RTO: Duration = Duration::from_secs(1);
const MIN_RTO: Duration = Duration::from_millis(400);
const MAX_RTO: Duration = Duration::from_secs(5);
/// Sends of one frame before the channel is given up.
pub const MAX_TRIES: u32 = 12;
/// A frame unacknowledged this long after it was first sent ends the
/// channel, however many tries that took: the other end is gone, and the
/// circuits over the channel are better built elsewhere at once. Until a
/// round trip is measured; then [`DEAD_RTOS`] resend timeouts of the
/// channel's own, between [`MIN_DEAD`] and this: a LAN or a datacenter
/// notices in 30 s too, the floor (`docs/TIMING_FIXES.md`).
pub const DEAD_AFTER: Duration = Duration::from_secs(30);
const DEAD_RTOS: u32 = 10;
/// The floor, as before TIMING_FIXES 11: 5 s took a peer busy a few
/// seconds for dead (a fam node checking a header's proof of work holds
/// its loop ~5 s; eight nodes in one test on a loaded Windows runner,
/// relays_learn_nothing_of_the_sender, lost live channels so).
const MIN_DEAD: Duration = DEAD_AFTER;
/// Sends of a frame, all unanswered and nothing heard meanwhile, before
/// the channel is taken for dead under [`DEAD_AFTER`]: eight losses in a
/// row at 10% each way is one frame in six hundred thousand. A frame's
/// resends are at most a quarter of the window apart, so on a LAN the
/// eighth goes within the floor.
const DEAD_TRIES: u32 = 8;

/// An initiator sends a keepalive after this long without sending: under
/// the 30 s a home router may keep a quiet UDP mapping, so a participant's
/// channel to its guard keeps its NAT open (`docs/SCALING.md`).
#[cfg(not(test))]
pub const KEEPALIVE: Duration = Duration::from_secs(25);
#[cfg(test)]
pub const KEEPALIVE: Duration = Duration::from_secs(5);
/// A channel that hears nothing for this long is gone.
#[cfg(not(test))]
pub const TIMEOUT: Duration = Duration::from_secs(120);
#[cfg(test)]
pub const TIMEOUT: Duration = Duration::from_secs(20);

const RELAY_CONTEXT: &[u8] = b"tab-channel-relay";
const INITIATOR_CONTEXT: &[u8] = b"tab-channel-initiator";
const KIND_DATA: u8 = 0;
const KIND_ACK: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelError {
    Malformed,
    /// The relay's key is not the one its id names.
    WrongKey,
    BadSignature,
    /// A frame that does not open: forged, corrupted, or not ours.
    Decrypt,
    /// A frame before the initiator authenticated.
    NotAuthenticated,
    /// A frame went unacknowledged [`MAX_TRIES`] times, or the other end
    /// fell silent.
    Dead,
    /// The send queue is full.
    Full,
    /// Closed by this end: nothing used it for a while.
    Idle,
    /// The other end said it no longer has the channel (it closed it, or
    /// restarted): `ChannelGone`.
    Gone,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ChannelError::Malformed => "malformed",
            ChannelError::WrongKey => "the relay's key is not the one its id names",
            ChannelError::BadSignature => "the signature does not hold",
            ChannelError::Decrypt => "a frame that does not open",
            ChannelError::NotAuthenticated => "not authenticated yet",
            ChannelError::Gone => "the other end no longer has it",
            ChannelError::Dead => "the other end stopped answering",
            ChannelError::Full => "too much queued",
            ChannelError::Idle => "idle",
        })
    }
}

impl std::error::Error for ChannelError {}

/// A frame on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub chan: u64,
    pub kind: u8,
    /// The data sequence number, or an ack-only frame's counter.
    pub seq: u64,
    /// Every data frame below this was received.
    pub ack: u64,
    /// Bit `i`: frame `ack + 1 + i` was received.
    pub sack: u64,
    pub sealed: Vec<u8>,
}

impl Frame {
    fn header(&self) -> [u8; 33] {
        let mut h = [0u8; 33];
        h[..8].copy_from_slice(&self.chan.to_le_bytes());
        h[8] = self.kind;
        h[9..17].copy_from_slice(&self.seq.to_le_bytes());
        h[17..25].copy_from_slice(&self.ack.to_le_bytes());
        h[25..33].copy_from_slice(&self.sack.to_le_bytes());
        h
    }

    pub fn put(&self, w: &mut Writer) {
        w.0.extend_from_slice(&self.header());
        w.0.extend_from_slice(&self.sealed);
    }

    /// The frame filling the rest of `r`.
    pub fn get(r: &mut Reader) -> Option<Frame> {
        let chan = r.u64()?;
        let kind = r.take(1)?[0];
        let (seq, ack, sack) = (r.u64()?, r.u64()?, r.u64()?);
        let sealed = r.take(r.0.len())?.to_vec();
        (sealed.len() >= TAG_LEN && sealed.len() <= MAX_BODY + TAG_LEN && kind <= KIND_ACK).then_some(Frame {
            chan,
            kind,
            seq,
            ack,
            sack,
            sealed,
        })
    }
}

fn nonce(kind: u8, n: u64) -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    out[0] = kind;
    out[4..].copy_from_slice(&n.to_le_bytes());
    out
}

/// What a handshake gives: the key from this end to the other, the key
/// back, and the transcript hash.
pub type Keys = ([u8; KEY_LEN], [u8; KEY_LEN], [u8; 32]);

/// A channel's handshake, or a circuit hop's: the same exchange, kept
/// apart by the transcript's domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    Channel,
    Circuit,
}

fn transcript(domain: Domain, chan: u64, hello: &[u8], relay_pk: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut s = keccak::Sponge::shake256();
    s.absorb(match domain {
        Domain::Channel => b"tab-channel",
        Domain::Circuit => b"tab-circuit",
    })
    .absorb(&chan.to_le_bytes())
    .absorb(hello)
    .absorb(relay_pk)
    .absorb(ct);
    let mut out = [0u8; 32];
    s.squeeze(&mut out);
    out
}

/// The keys from initiator to relay and back.
fn keys(shared: &[u8; 32], th: &[u8; 32]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut s = keccak::Sponge::shake256();
    s.absorb(b"tab-channel-keys").absorb(shared).absorb(th);
    let mut out = [0u8; 2 * KEY_LEN];
    s.squeeze(&mut out);
    (out[..KEY_LEN].try_into().unwrap(), out[KEY_LEN..].try_into().unwrap())
}

/// An initiator waiting for the relay's reply.
pub struct Opening {
    pub domain: Domain,
    pub chan: u64,
    /// The relay's id, from the consensus file.
    pub expect: Digest,
    pub hello: Vec<u8>,
    kyber: mlkem::SecretKey,
}

impl Opening {
    /// A hello for channel `chan` to the relay `expect`, with a fresh
    /// Kyber key from `seed` and `challenge`; `mutual` when this end will
    /// authenticate too.
    pub fn new(chan: u64, expect: Digest, mutual: bool, seed: &[u8; 64], challenge: [u8; 32]) -> Opening {
        let kyber = mlkem::keygen(seed);
        let mut hello = Vec::with_capacity(HELLO_LEN);
        hello.push(u8::from(mutual));
        hello.extend_from_slice(&challenge);
        hello.extend_from_slice(kyber.public_key());
        Opening { domain: Domain::Channel, chan, expect, hello, kyber }
    }

    /// A hello for a hop of a circuit, to the relay `expect`: never
    /// mutual, the client stays anonymous.
    pub fn circuit(expect: Digest, seed: &[u8; 64], challenge: [u8; 32]) -> Opening {
        Opening { domain: Domain::Circuit, ..Opening::new(0, expect, false, seed, challenge) }
    }

    /// Checks the relay's reply and returns the keys from us to it and
    /// back.
    pub fn keys(&self, reply: &[u8]) -> Result<Keys, ChannelError> {
        if reply.len() != REPLY_LEN {
            return Err(ChannelError::Malformed);
        }
        let (pk, rest) = reply.split_at(mldsa::PK_LEN);
        let (ct, sig) = rest.split_at(mlkem::CT_LEN);
        if crate::address::id_of(pk) != self.expect {
            return Err(ChannelError::WrongKey);
        }
        let th = transcript(self.domain, self.chan, &self.hello, pk, ct);
        if !mldsa::verify(pk, &th, RELAY_CONTEXT, sig) {
            return Err(ChannelError::BadSignature);
        }
        let shared = self.kyber.decapsulate(ct).ok_or(ChannelError::Malformed)?;
        let (out, inn) = keys(&shared, &th);
        Ok((out, inn, th))
    }

    pub fn mutual(&self) -> bool {
        self.hello[0] == 1
    }

    /// Checks the relay's reply: its key is the expected id's, its
    /// signature holds, and the ciphertext opens. With `auth` (this end's
    /// key, for a mutual hello) also returns the `Auth` message.
    pub fn finish(
        self,
        reply: &[u8],
        auth: Option<&mldsa::SecretKey>,
        now: Instant,
    ) -> Result<(Channel, Option<Vec<u8>>), ChannelError> {
        let (out, inn, th) = self.keys(reply)?;
        let auth = match (self.mutual(), auth) {
            (true, Some(key)) => {
                let mut m = key.public_key().to_vec();
                m.extend_from_slice(&key.sign(&th, INITIATOR_CONTEXT));
                Some(m)
            }
            (true, None) => return Err(ChannelError::NotAuthenticated),
            (false, _) => None,
        };
        let mut ch = Channel::new(self.chan, true, out, inn, th, now);
        ch.peer = Some(self.expect);
        Ok((ch, auth))
    }
}

/// The relay's side of a hello: its reply, signed by `key`, and the
/// channel. `m` is the encapsulation's randomness.
pub fn respond(
    chan: u64,
    hello: &[u8],
    key: &mldsa::SecretKey,
    m: &[u8; 32],
    now: Instant,
) -> Result<(Channel, Vec<u8>), ChannelError> {
    let ((out, inn, th), reply) = respond_keys(Domain::Channel, chan, hello, key, m)?;
    let mut ch = Channel::new(chan, false, out, inn, th, now);
    ch.awaiting_auth = hello[0] == 1;
    Ok((ch, reply))
}

/// The relay's side of a hello in `domain`: the keys from it to the
/// initiator and back, the transcript hash, and its reply.
pub fn respond_keys(
    domain: Domain,
    chan: u64,
    hello: &[u8],
    key: &mldsa::SecretKey,
    m: &[u8; 32],
) -> Result<(Keys, Vec<u8>), ChannelError> {
    if hello.len() != HELLO_LEN || hello[0] > 1 || (domain == Domain::Circuit && hello[0] != 0) {
        return Err(ChannelError::Malformed);
    }
    let ek = &hello[33..];
    let (shared, ct) = mlkem::encapsulate_with(ek, m).ok_or(ChannelError::Malformed)?;
    let pk = key.public_key();
    let th = transcript(domain, chan, hello, pk, &ct);
    let sig = key.sign(&th, RELAY_CONTEXT);
    let mut reply = Vec::with_capacity(REPLY_LEN);
    reply.extend_from_slice(pk);
    reply.extend_from_slice(&ct);
    reply.extend_from_slice(&sig);
    let (inn, out) = keys(&shared, &th);
    Ok(((out, inn, th), reply))
}

/// A frame sent and not yet acknowledged.
struct InFlight {
    frame: Frame,
    first: Instant,
    sent: Instant,
    tries: u32,
    rto: Duration,
}

/// What a received frame gave.
#[derive(Debug, Default)]
pub struct Received {
    /// Bodies now in order, keepalives left out.
    pub delivered: Vec<Vec<u8>>,
    /// Frames to send: an acknowledgement, and queued data the
    /// acknowledgements made room for.
    pub send: Vec<Frame>,
}

/// An open channel.
pub struct Channel {
    pub chan: u64,
    pub initiator: bool,
    /// The other end's id, once proven: the relay's for an initiator, and
    /// for a relay the initiating relay's once it authenticated.
    pub peer: Option<Digest>,
    /// A relay waiting for a mutual initiator's `Auth`: frames until then
    /// are not taken.
    pub awaiting_auth: bool,
    send_key: [u8; KEY_LEN],
    recv_key: [u8; KEY_LEN],
    th: [u8; 32],
    next_seq: u64,
    in_flight: BTreeMap<u64, InFlight>,
    queue: VecDeque<Vec<u8>>,
    /// The next data frame to deliver.
    recv_next: u64,
    /// Data frames past a gap.
    recv_buf: BTreeMap<u64, Vec<u8>>,
    acks: u64,
    pub last_heard: Instant,
    last_sent: Instant,
    /// The smoothed round trip and its variation, once measured.
    srtt: Option<Duration>,
    rttvar: Duration,
}

impl Channel {
    fn new(chan: u64, initiator: bool, send_key: [u8; 32], recv_key: [u8; 32], th: [u8; 32], now: Instant) -> Channel {
        Channel {
            chan,
            initiator,
            peer: None,
            awaiting_auth: false,
            send_key,
            recv_key,
            th,
            next_seq: 1,
            in_flight: BTreeMap::new(),
            queue: VecDeque::new(),
            recv_next: 1,
            recv_buf: BTreeMap::new(),
            acks: 0,
            last_heard: now,
            srtt: None,
            rttvar: Duration::ZERO,
            last_sent: now,
        }
    }

    /// A relay's check of the initiating relay's `Auth`: returns its id.
    pub fn authenticate(&mut self, auth: &[u8]) -> Result<Digest, ChannelError> {
        if auth.len() != AUTH_LEN {
            return Err(ChannelError::Malformed);
        }
        let (pk, sig) = auth.split_at(mldsa::PK_LEN);
        if !mldsa::verify(pk, &self.th, INITIATOR_CONTEXT, sig) {
            return Err(ChannelError::BadSignature);
        }
        let id = crate::address::id_of(pk);
        self.peer = Some(id);
        self.awaiting_auth = false;
        Ok(id)
    }

    /// What we have received: the next expected and the bitmap past it.
    fn acks(&self) -> (u64, u64) {
        let mut sack = 0u64;
        for &s in self.recv_buf.keys() {
            let i = s - self.recv_next - 1;
            if i < 64 {
                sack |= 1 << i;
            }
        }
        (self.recv_next, sack)
    }

    fn seal(&mut self, body: &[u8], now: Instant) -> Frame {
        let seq = self.next_seq;
        self.next_seq += 1;
        let (ack, sack) = self.acks();
        let mut f = Frame { chan: self.chan, kind: KIND_DATA, seq, ack, sack, sealed: Vec::new() };
        f.sealed = chacha20poly1305::seal(&self.send_key, &nonce(KIND_DATA, seq), &f.header(), body);
        self.in_flight.insert(seq, InFlight { frame: f.clone(), first: now, sent: now, tries: 1, rto: self.rto() });
        self.last_sent = now;
        f
    }

    /// Frames queued bodies may go out as, while the window has room: no
    /// frame goes past the oldest unacknowledged one by [`WINDOW`] or
    /// more, which the other end would not buffer.
    fn fill(&mut self, now: Instant) -> Vec<Frame> {
        let mut out = Vec::new();
        loop {
            let base = self.in_flight.keys().next().copied().unwrap_or(self.next_seq);
            if self.next_seq >= base + WINDOW {
                break;
            }
            let Some(body) = self.queue.pop_front() else { break };
            out.push(self.seal(&body, now));
        }
        out
    }

    /// Sends `body`: the frames to put on the wire now (none while the
    /// window is full, the body then queued).
    pub fn send(&mut self, body: &[u8], now: Instant) -> Result<Vec<Frame>, ChannelError> {
        if body.len() > MAX_BODY {
            return Err(ChannelError::Malformed);
        }
        if self.queue.len() >= MAX_QUEUE {
            return Err(ChannelError::Full);
        }
        self.queue.push_back(body.to_vec());
        Ok(self.fill(now))
    }

    /// The wait for a new frame's acknowledgement.
    /// How long a frame may go unacknowledged before the channel is
    /// given up: [`DEAD_AFTER`] until the round trip is measured, then
    /// [`DEAD_RTOS`] resend timeouts, [`MIN_DEAD`] to [`DEAD_AFTER`].
    fn dead_after(&self) -> Duration {
        match self.srtt {
            Some(_) => (self.rto() * DEAD_RTOS).clamp(MIN_DEAD, DEAD_AFTER),
            None => DEAD_AFTER,
        }
    }

    fn rto(&self) -> Duration {
        match self.srtt {
            Some(srtt) => (srtt + 4 * self.rttvar).clamp(MIN_RTO, MAX_RTO),
            None => RTO,
        }
    }

    /// A round trip measured: a frame acknowledged that was sent once
    /// (Karn's rule: a resent one's could be either send's).
    fn sample(&mut self, rtt: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let diff = if srtt > rtt { srtt - rtt } else { rtt - srtt };
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((srtt * 7 + rtt) / 8);
            }
        }
    }

    /// An ack-only frame.
    fn ack_frame(&mut self) -> Frame {
        self.acks += 1;
        let (ack, sack) = self.acks();
        let mut f = Frame { chan: self.chan, kind: KIND_ACK, seq: self.acks, ack, sack, sealed: Vec::new() };
        f.sealed = chacha20poly1305::seal(&self.send_key, &nonce(KIND_ACK, self.acks), &f.header(), &[]);
        f
    }

    /// Takes a frame from the other end: opens it, drops what it
    /// acknowledges, and delivers the bodies now in order.
    pub fn receive(&mut self, f: &Frame, now: Instant) -> Result<Received, ChannelError> {
        if f.chan != self.chan {
            return Err(ChannelError::Decrypt);
        }
        let body = chacha20poly1305::open(&self.recv_key, &nonce(f.kind, f.seq), &f.header(), &f.sealed)
            .ok_or(ChannelError::Decrypt)?;
        if f.kind == KIND_DATA && self.awaiting_auth {
            return Err(ChannelError::NotAuthenticated);
        }
        self.last_heard = now;
        // What the other end has: everything below `ack`, and the bitmap.
        let mut rtt = None;
        self.in_flight.retain(|&s, fl| {
            let keep = s >= f.ack && !(s > f.ack && s - f.ack - 1 < 64 && f.sack >> (s - f.ack - 1) & 1 == 1);
            if !keep && fl.tries == 1 {
                rtt = Some(now.saturating_duration_since(fl.sent));
            }
            keep
        });
        if let Some(rtt) = rtt {
            self.sample(rtt);
        }
        let mut out = Received::default();
        if f.kind == KIND_DATA {
            if f.seq >= self.recv_next && f.seq < self.recv_next + WINDOW {
                self.recv_buf.entry(f.seq).or_insert(body);
                while let Some(b) = self.recv_buf.remove(&self.recv_next) {
                    self.recv_next += 1;
                    if !b.is_empty() {
                        out.delivered.push(b);
                    }
                }
            }
            // A duplicate is acknowledged again: our ack may have been lost.
            out.send.push(self.ack_frame());
        }
        out.send.extend(self.fill(now));
        Ok(out)
    }

    /// Frames due again, and a keepalive when this end has been quiet and
    /// either opened the channel or proved the other end a relay (between
    /// relays both ends send them, so either notices the other gone within
    /// a keepalive and [`DEAD_AFTER`], not [`TIMEOUT`]);
    /// [`ChannelError::Dead`] when a frame ran out of tries or the other
    /// end fell silent.
    pub fn poll(&mut self, now: Instant) -> Result<Vec<Frame>, ChannelError> {
        if now.duration_since(self.last_heard) >= TIMEOUT {
            return Err(ChannelError::Dead);
        }
        let mut out = Vec::new();
        let dead_after = self.dead_after();
        for f in self.in_flight.values_mut() {
            // Every poll, not only when a resend falls due (up to 5 s on).
            // Under DEAD_AFTER only if nothing at all came back meanwhile:
            // a lossy link keeps acknowledging other frames, a dead one is
            // silent (five losses in a row at 10% each way are common
            // enough among thousands of frames to end a living channel).
            let waited = now.duration_since(f.first);
            if waited >= DEAD_AFTER
                || waited >= dead_after && now.duration_since(self.last_heard) >= dead_after && f.tries >= DEAD_TRIES
            {
                return Err(ChannelError::Dead);
            }
            if now.duration_since(f.sent) < f.rto {
                continue;
            }
            if f.tries >= MAX_TRIES {
                return Err(ChannelError::Dead);
            }
            f.tries += 1;
            f.sent = now;
            f.rto = (f.rto * 2).min(MAX_RTO).min((dead_after / 4).max(MIN_RTO));
            out.push(f.frame.clone());
        }
        if !out.is_empty() {
            self.last_sent = now;
        }
        let keeps_alive = self.initiator || (self.peer.is_some() && !self.awaiting_auth);
        if keeps_alive && self.in_flight.is_empty() && now.duration_since(self.last_sent) >= KEEPALIVE {
            out.extend(self.send(&[], now)?);
        }
        Ok(out)
    }

    /// Frames sent and not yet acknowledged, and bodies queued.
    pub fn backlog(&self) -> (usize, usize) {
        (self.in_flight.len(), self.queue.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resend_wait_follows_the_round_trip() {
        let (mut i, mut r, now) = open_pair(false);
        assert_eq!(i.rto(), RTO, "1 s before a round trip is measured");
        // A satellite's round trip: 800 ms each time.
        let mut t = now;
        for _ in 0..8 {
            let f = i.send(b"x", t).unwrap().remove(0);
            t += Duration::from_millis(400);
            let back = r.receive(&f, t).unwrap().send;
            t += Duration::from_millis(400);
            for b in back {
                i.receive(&b, t).unwrap();
            }
        }
        let rto = i.rto();
        assert!(rto >= Duration::from_millis(800) && rto <= Duration::from_secs(2), "{rto:?}");
        // No resend before the wait: none at 700 ms after a send.
        i.send(b"y", t).unwrap();
        assert!(i.poll(t + Duration::from_millis(700)).unwrap().is_empty());
        // A fast link's wait is never under the floor.
        let (mut i, mut r, now) = open_pair(false);
        for k in 0..8 {
            let t = now + Duration::from_millis(k * 10);
            let f = i.send(b"x", t).unwrap().remove(0);
            for b in r.receive(&f, t).unwrap().send {
                i.receive(&b, t + Duration::from_millis(1)).unwrap();
            }
        }
        assert_eq!(i.rto(), MIN_RTO);
    }

    fn relay(tag: u8) -> (mldsa::SecretKey, Digest) {
        let k = mldsa::keygen(&[tag; 32]);
        let id = crate::address::id_of(k.public_key());
        (k, id)
    }

    fn open_pair(mutual: bool) -> (Channel, Channel, Instant) {
        let now = Instant::now();
        let (rk, rid) = relay(1);
        let (ik, iid) = relay(2);
        let o = Opening::new(7, rid, mutual, &[3u8; 64], [4u8; 32]);
        let (mut r, reply) = respond(7, &o.hello, &rk, &[5u8; 32], now).unwrap();
        let (i, auth) = o.finish(&reply, Some(&ik), now).unwrap();
        assert_eq!(i.peer, Some(rid));
        assert_eq!(auth.is_some(), mutual);
        if let Some(a) = auth {
            assert_eq!(r.authenticate(&a), Ok(iid));
        }
        (i, r, now)
    }

    #[test]
    fn the_handshake_authenticates_the_relay() {
        let now = Instant::now();
        let (rk, rid) = relay(1);
        let (other, _) = relay(9);
        let o = || Opening::new(1, rid, false, &[3u8; 64], [4u8; 32]);
        assert_eq!(o().hello.len(), HELLO_LEN);
        // A relay with another key cannot pass for this id.
        let (_, reply) = respond(1, &o().hello, &other, &[5u8; 32], now).unwrap();
        assert_eq!(reply.len(), REPLY_LEN);
        assert!(matches!(o().finish(&reply, None, now), Err(ChannelError::WrongKey)));
        // Any change to the reply breaks it.
        let (_, reply) = respond(1, &o().hello, &rk, &[5u8; 32], now).unwrap();
        for at in [10, mldsa::PK_LEN + 10, REPLY_LEN - 10] {
            let mut bad = reply.clone();
            bad[at] ^= 1;
            assert!(o().finish(&bad, None, now).is_err(), "byte {at}");
        }
        // A reply to another hello (another channel, challenge or key) fails.
        let (_, other_chan) = respond(2, &o().hello, &rk, &[5u8; 32], now).unwrap();
        assert!(matches!(o().finish(&other_chan, None, now), Err(ChannelError::BadSignature)));
        let mut hello = o().hello;
        hello[5] ^= 1;
        let (_, other_challenge) = respond(1, &hello, &rk, &[5u8; 32], now).unwrap();
        assert!(matches!(o().finish(&other_challenge, None, now), Err(ChannelError::BadSignature)));
        assert!(o().finish(&reply, None, now).is_ok());
        assert!(matches!(respond(1, &hello[1..], &rk, &[5u8; 32], now), Err(ChannelError::Malformed)));
        // A mutual hello needs this end's key; a bad Auth is refused.
        let m = Opening::new(1, rid, true, &[3u8; 64], [4u8; 32]);
        let (mut r, reply) = respond(1, &m.hello, &rk, &[5u8; 32], now).unwrap();
        assert!(r.awaiting_auth);
        assert!(matches!(m.finish(&reply, None, now), Err(ChannelError::NotAuthenticated)));
        let m = Opening::new(1, rid, true, &[3u8; 64], [4u8; 32]);
        let (_, auth) = m.finish(&reply, Some(&other), now).unwrap();
        let mut bad = auth.clone().unwrap();
        bad[AUTH_LEN - 5] ^= 1;
        assert_eq!(r.authenticate(&bad), Err(ChannelError::BadSignature));
        assert!(r.awaiting_auth);
        assert_eq!(r.authenticate(&auth.unwrap()), Ok(crate::address::id_of(other.public_key())));
    }

    #[test]
    fn frames_go_both_ways_and_tampering_fails() {
        let (mut i, mut r, now) = open_pair(false);
        let f = i.send(b"hello", now).unwrap().remove(0);
        let got = r.receive(&f, now).unwrap();
        assert_eq!(got.delivered, vec![b"hello".to_vec()]);
        // The ack clears the initiator's frame.
        assert_eq!(i.backlog(), (1, 0));
        i.receive(&got.send[0], now).unwrap();
        assert_eq!(i.backlog(), (0, 0));
        let back = r.send(b"back", now).unwrap().remove(0);
        assert_eq!(i.receive(&back, now).unwrap().delivered, vec![b"back".to_vec()]);
        // A replay delivers nothing new but is acknowledged again.
        let again = r.receive(&f, now).unwrap();
        assert!(again.delivered.is_empty() && again.send.len() == 1);
        // Tampering with the header or the body, or the wrong direction.
        let f = i.send(b"x", now).unwrap().remove(0);
        let tampered: [fn(&mut Frame); 4] = [|f| f.ack += 1, |f| f.sack ^= 1, |f| f.seq += 1, |f| f.kind = KIND_ACK];
        for t in tampered {
            let mut bad = f.clone();
            t(&mut bad);
            assert_eq!(r.receive(&bad, now).err(), Some(ChannelError::Decrypt));
        }
        let mut bad = f.clone();
        bad.sealed[0] ^= 1;
        assert_eq!(r.receive(&bad, now).err(), Some(ChannelError::Decrypt));
        assert_eq!(i.receive(&f, now).err(), Some(ChannelError::Decrypt));
        // Over the wire.
        let mut w = Writer::default();
        f.put(&mut w);
        assert_eq!(Frame::get(&mut Reader(&w.0)), Some(f));
        assert_eq!(MAX_BODY + FRAME_OVERHEAD, 1232);
    }

    #[test]
    fn a_mutual_channel_takes_nothing_before_the_auth() {
        let now = Instant::now();
        let (rk, rid) = relay(1);
        let (ik, _) = relay(2);
        let o = Opening::new(3, rid, true, &[3u8; 64], [4u8; 32]);
        let (mut r, reply) = respond(3, &o.hello, &rk, &[5u8; 32], now).unwrap();
        let (mut i, auth) = o.finish(&reply, Some(&ik), now).unwrap();
        let f = i.send(b"early", now).unwrap().remove(0);
        assert_eq!(r.receive(&f, now).err(), Some(ChannelError::NotAuthenticated));
        r.authenticate(&auth.unwrap()).unwrap();
        // The resend, after the auth, is taken.
        let later = now + RTO;
        let resent = i.poll(later).unwrap();
        assert_eq!(resent, vec![f]);
        assert_eq!(r.receive(&resent[0], later).unwrap().delivered, vec![b"early".to_vec()]);
    }

    /// A lossy, reordering link: every body arrives once, in order.
    #[test]
    fn bodies_arrive_in_order_over_a_lossy_link() {
        for seed in 1..=20u64 {
            lossy_link(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        }
    }

    fn lossy_link(seed: u64) {
        let (mut i, mut r, start) = open_pair(true);
        let mut rng = seed;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let n = 500usize;
        let mut to_r: Vec<Frame> = Vec::new();
        let mut to_i: Vec<Frame> = Vec::new();
        for k in 0..n {
            to_r.extend(i.send(format!("body {k}").as_bytes(), start).unwrap());
        }
        assert_eq!(i.backlog(), (WINDOW as usize, n - WINDOW as usize));
        let mut got: Vec<Vec<u8>> = Vec::new();
        let mut now = start;
        for _ in 0..2000 {
            now += Duration::from_millis(50);
            // Drop a tenth each way, shuffle the rest, deliver.
            let mut batch: Vec<Frame> = to_r.drain(..).filter(|_| next() % 10 != 0).collect();
            batch.sort_by_cached_key(|_| next());
            for f in batch {
                let out = r.receive(&f, now).unwrap();
                got.extend(out.delivered);
                to_i.extend(out.send);
            }
            let batch: Vec<Frame> = to_i.drain(..).filter(|_| next() % 10 != 0).collect();
            for f in batch {
                to_r.extend(i.receive(&f, now).unwrap().send);
            }
            to_r.extend(i.poll(now).unwrap());
            if got.len() == n && i.backlog() == (0, 0) {
                break;
            }
        }
        assert_eq!(got.len(), n, "seed {seed}");
        for (k, b) in got.iter().enumerate() {
            assert_eq!(b, format!("body {k}").as_bytes());
        }
        assert_eq!(i.backlog(), (0, 0));
    }

    /// A channel's death follows its measured round trip: a fast link's
    /// in 30 s (the floor), a satellite's after ten of its resend timeouts,
    /// and one not yet measured after the full 30 s.
    #[test]
    fn a_dead_channel_is_noticed_from_its_round_trip() {
        // Not measured: 30 s (alive well past the floor; the test's own
        // silence timeout, 20 s, would end it first).
        let (mut i, _r, now) = open_pair(false);
        assert_eq!(i.dead_after(), DEAD_AFTER);
        i.send(b"lost", now).unwrap();
        let mut t = now;
        while t < now + Duration::from_secs(19) {
            t += Duration::from_millis(100);
            assert!(i.poll(t).is_ok(), "{:?}", t - now);
        }
        // A fast link (1 ms): no longer given up early; the floor is the
        // full 30 s (resends at most 7.5 s apart).
        let (mut i, mut r, now) = open_pair(false);
        let mut t = now;
        for _ in 0..8 {
            let f = i.send(b"x", t).unwrap().remove(0);
            for b in r.receive(&f, t).unwrap().send {
                i.receive(&b, t + Duration::from_millis(1)).unwrap();
            }
            t += Duration::from_millis(10);
        }
        i.send(b"lost", t).unwrap();
        let start = t;
        let dead = loop {
            t += Duration::from_millis(100);
            if i.poll(t).is_err() {
                break t - start;
            }
            assert!(t - start <= DEAD_AFTER + Duration::from_secs(1), "not given up");
        };
        // Not before the floor's own silence check: the channel's silence
        // timeout (TIMEOUT, 20 s, from before item 11) ends it first.
        assert!(dead >= TIMEOUT, "died after {dead:?}");
        // A satellite (800 ms): ten resend timeouts, past the floor.
        let (mut i, mut r, now) = open_pair(false);
        let mut t = now;
        for _ in 0..8 {
            let f = i.send(b"x", t).unwrap().remove(0);
            t += Duration::from_millis(400);
            let back = r.receive(&f, t).unwrap().send;
            t += Duration::from_millis(400);
            for b in back {
                i.receive(&b, t).unwrap();
            }
        }
        let allowed = i.dead_after();
        assert_eq!(allowed, (i.rto() * DEAD_RTOS).clamp(MIN_DEAD, DEAD_AFTER));
        assert_eq!(allowed, DEAD_AFTER);
    }

    #[test]
    fn a_silent_channel_dies_and_an_idle_one_keeps_alive() {
        let (mut i, mut r, now) = open_pair(false);
        // Idle: the initiator sends a keepalive, delivered as nothing.
        let ka = i.poll(now + KEEPALIVE).unwrap();
        assert_eq!(ka.len(), 1);
        let got = r.receive(&ka[0], now + KEEPALIVE).unwrap();
        assert!(got.delivered.is_empty());
        assert!(r.poll(now + KEEPALIVE).unwrap().is_empty(), "a relay sends none to a participant");
        // Between relays both ends do.
        let (_, mut r2, now2) = open_pair(true);
        assert_eq!(r2.poll(now2 + KEEPALIVE).unwrap().len(), 1);
        // Unanswered frames run out of tries.
        i.send(b"lost", now).unwrap();
        let mut t = now;
        let dead = loop {
            t += MAX_RTO;
            match i.poll(t) {
                Ok(_) => continue,
                Err(e) => break e,
            }
        };
        assert_eq!(dead, ChannelError::Dead);
        // Silence ends a channel too.
        assert_eq!(r.poll(now + KEEPALIVE + TIMEOUT).err(), Some(ChannelError::Dead));
    }
}
