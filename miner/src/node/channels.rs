//! Onion mode's channels in the node (`docs/ONION.md`, [`crate::channel`]):
//! opening one to a relay, answering hellos as a relay, and carrying
//! frames between the socket and each channel.
//!
//! A handshake message travels as `Handshake` fragments, each a request
//! with the receiver's token, so a node must have pinged the relay first.
//! The initiator resends its hello until the reply is whole; a relay that
//! hears a hello again for a channel it answered sends the same reply,
//! never a second one. A relay opening a channel to a relay sends its
//! auth after the reply, and again until the other end acknowledges a
//! frame (it acknowledges nothing before), with a keepalive behind it so
//! that there is a frame to acknowledge. Bodies sent while the channel is
//! opening wait for it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::Node;
use crate::chain::ProofVerifier;
use crate::channel::{self, Channel, ChannelError, Frame, Opening};
use crate::net::{HANDSHAKE_FRAGMENT, Message};
use crate::pow::Digest;
use crate::wallet::random_bytes;

/// Between sends of a hello, or of an auth, not yet answered.
const HANDSHAKE_RETRY: Duration = Duration::from_secs(1);
/// Hellos sent before an opening is given up.
const HANDSHAKE_TRIES: u32 = 8;
/// An opening waits this long for the relay to answer our ping first.
const PING_WAIT: Duration = Duration::from_secs(10);
/// Channels held at once, either end.
pub const MAX_CHANNELS: usize = 4096;
/// Handshake messages being reassembled at once, and for how long.
const MAX_REASSEMBLY: usize = 1024;
const REASSEMBLY_TIME: Duration = Duration::from_secs(10);
/// Bodies held for a channel still opening.
const MAX_WAITING: usize = 256;
/// Channels a relay holds from one IP address. A handshake already needs
/// the token this node gave the address, so a forged address gets
/// nothing; this bounds what a real one can take.
pub const MAX_PER_HOST: usize = 32;
/// A channel a relay answered that carries no frame by then is closed: its
/// initiator gave up, or never meant to use it.
#[cfg(not(test))]
const UNUSED_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(test)]
const UNUSED_TIMEOUT: Duration = Duration::from_secs(3);

const STAGE_HELLO: u8 = 1;
const STAGE_REPLY: u8 = 2;
const STAGE_AUTH: u8 = 3;

/// An open channel and what its handshake left to do.
struct Open {
    ch: Channel,
    /// The other end's token for us, for handshake messages.
    back: u64,
    /// A relay's reply, sent again if the hello comes again.
    reply: Option<Vec<u8>>,
    /// An initiating relay's auth, until the other end acknowledges.
    auth: Option<(Vec<u8>, Instant)>,
    opened: Instant,
    /// A frame has come.
    used: bool,
}

/// A channel we are opening.
struct Pending {
    opening: Opening,
    started: Instant,
    sent: Option<Instant>,
    tries: u32,
    waiting: Vec<Vec<u8>>,
}

struct Fragments {
    parts: Vec<Option<Vec<u8>>>,
    at: Instant,
}

/// Tests: a body a channel delivered, with the other end's address and
/// proven id.
#[cfg(test)]
pub(super) type Delivered = (SocketAddr, Option<Digest>, Vec<u8>);

/// The node's channels, by the other end's address and channel number.
#[derive(Default)]
pub(super) struct Channels {
    open: HashMap<(SocketAddr, u64), Open>,
    pending: HashMap<(SocketAddr, u64), Pending>,
    fragments: HashMap<(SocketAddr, u64, u8), Fragments>,
    /// Our channel to each relay, by its id.
    to: HashMap<Digest, (SocketAddr, u64)>,
    /// Tests: what the channels delivered, with the other end's address
    /// and proven id.
    #[cfg(test)]
    pub(super) sink: std::sync::Arc<std::sync::Mutex<Vec<Delivered>>>,
}

impl Channels {
    /// Whether frames from `addr` on `chan` are expected.
    pub(super) fn knows(&self, addr: &SocketAddr, chan: u64) -> bool {
        self.open.contains_key(&(*addr, chan))
    }

    pub(super) fn count(&self) -> usize {
        self.open.len()
    }

    /// The proven id of the other end of channel `key`: `Some(None)` for a
    /// participant, `None` for no such channel.
    pub(super) fn peer(&self, key: &(SocketAddr, u64)) -> Option<Option<Digest>> {
        self.open.get(key).map(|o| o.ch.peer)
    }

    /// Whether we opened channel `key`: `None` for no such channel.
    pub(super) fn initiator(&self, key: &(SocketAddr, u64)) -> Option<bool> {
        if self.pending.contains_key(key) {
            return Some(true);
        }
        self.open.get(key).map(|o| o.ch.initiator)
    }
}

/// `msg` cut into `Handshake` fragments.
fn fragments(chan: u64, stage: u8, msg: &[u8], back: u64) -> impl Iterator<Item = Message> + '_ {
    let count = msg.len().div_ceil(HANDSHAKE_FRAGMENT) as u8;
    msg.chunks(HANDSHAKE_FRAGMENT).enumerate().map(move |(i, data)| Message::Handshake {
        chan,
        stage,
        index: i as u8,
        count,
        data: data.to_vec(),
        back,
        token: 0,
    })
}

impl<V: ProofVerifier + Send + Sync + 'static> Node<V> {
    /// Opens a channel to the relay `id` at `addr`, or finds the one open
    /// or opening, and returns its key. A relay's channel to a relay is
    /// mutual: it authenticates too.
    pub(super) fn channel_to(&mut self, addr: SocketAddr, id: Digest, now: Instant) -> std::io::Result<(SocketAddr, u64)> {
        if let Some(key) = self.channels.to.get(&id)
            && (self.channels.open.contains_key(key) || self.channels.pending.contains_key(key))
        {
            return Ok(*key);
        }
        let chan = u64::from_le_bytes(random_bytes::<8>()?);
        let mutual = self.config.relay && self.config.relay_key.is_some();
        let opening = Opening::new(chan, id, mutual, &random_bytes::<64>()?, random_bytes::<32>()?);
        let key = (addr, chan);
        self.peers.add(addr, true);
        self.channels.pending.insert(key, Pending { opening, started: now, sent: None, tries: 0, waiting: Vec::new() });
        self.channels.to.insert(id, key);
        self.chatter(&format!("channel: opening {chan:016x} to {} at {addr}", crate::onion::short(&id)));
        self.pump_pending(key, now);
        Ok(key)
    }

    /// Sends `body` on a channel, or holds it until the channel is open.
    pub(super) fn channel_send(&mut self, key: (SocketAddr, u64), body: &[u8], now: Instant) -> Result<(), ChannelError> {
        if let Some(p) = self.channels.pending.get_mut(&key) {
            if p.waiting.len() >= MAX_WAITING {
                return Err(ChannelError::Full);
            }
            p.waiting.push(body.to_vec());
            return Ok(());
        }
        let o = self.channels.open.get_mut(&key).ok_or(ChannelError::Dead)?;
        let frames = o.ch.send(body, now)?;
        self.send_frames(key.0, frames);
        Ok(())
    }

    fn send_frames(&self, addr: SocketAddr, frames: Vec<Frame>) {
        for f in frames {
            self.send(addr, &Message::Frame(f));
        }
    }

    /// Sends a pending channel's hello, if it is due and the relay has
    /// answered our ping (its token is in our requests).
    fn pump_pending(&mut self, key: (SocketAddr, u64), now: Instant) {
        let handshaken = self.peers.handshaken(&key.0);
        let back = self.token_for(&key.0);
        let Some(p) = self.channels.pending.get_mut(&key) else { return };
        if !handshaken || p.sent.is_some_and(|t| now.duration_since(t) < HANDSHAKE_RETRY) {
            return;
        }
        p.sent = Some(now);
        p.tries += 1;
        let hello = p.opening.hello.clone();
        for m in fragments(key.1, STAGE_HELLO, &hello, back) {
            self.send(key.0, &m);
        }
    }

    /// Resends, keepalives, and channels given up; every loop.
    pub(super) fn poll_channels(&mut self, now: Instant) {
        let mut failed = Vec::new();
        for (key, p) in &self.channels.pending {
            let waited = if self.peers.handshaken(&key.0) { p.tries >= HANDSHAKE_TRIES } else { now.duration_since(p.started) >= PING_WAIT };
            if waited && p.sent.is_none_or(|t| now.duration_since(t) >= HANDSHAKE_RETRY) {
                failed.push(*key);
            }
        }
        for key in failed {
            let p = self.channels.pending.remove(&key).unwrap();
            self.channels.to.retain(|_, k| *k != key);
            self.avoid_relay(p.opening.expect, now);
            self.log(&format!(
                "channel: {} at {} did not answer the handshake",
                crate::onion::short(&p.opening.expect),
                key.0
            ));
            self.channel_closed(key, now);
        }
        let keys: Vec<(SocketAddr, u64)> = self.channels.pending.keys().copied().collect();
        for key in keys {
            self.pump_pending(key, now);
        }
        let mut dead = Vec::new();
        let mut out = Vec::new();
        let mut auths = Vec::new();
        for (key, o) in self.channels.open.iter_mut() {
            if !o.ch.initiator && !o.used && now.duration_since(o.opened) >= UNUSED_TIMEOUT {
                dead.push((*key, ChannelError::Dead));
                continue;
            }
            match o.ch.poll(now) {
                Ok(frames) => out.push((key.0, frames)),
                Err(e) => dead.push((*key, e)),
            }
            if let Some((auth, sent)) = &mut o.auth
                && now.duration_since(*sent) >= HANDSHAKE_RETRY
            {
                *sent = now;
                auths.push((*key, auth.clone(), o.back));
            }
        }
        for (addr, frames) in out {
            self.send_frames(addr, frames);
        }
        for (key, auth, _) in auths {
            for m in fragments(key.1, STAGE_AUTH, &auth, self.token_for(&key.0)) {
                self.send(key.0, &m);
            }
        }
        for (key, e) in dead {
            let o = self.channels.open.remove(&key).unwrap();
            self.channels.to.retain(|_, k| *k != key);
            if o.ch.initiator
                && let Some(id) = o.ch.peer
            {
                self.avoid_relay(id, now);
            }
            let who = o.ch.peer.map_or("a participant".to_string(), |id| crate::onion::short(&id));
            self.log(&format!("channel: {:016x} with {who} at {} closed: {e}", key.1, key.0));
            self.channel_closed(key, now);
        }
    }

    /// A handshake fragment (its token already checked).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn on_handshake(
        &mut self,
        addr: SocketAddr,
        chan: u64,
        stage: u8,
        index: u8,
        count: u8,
        data: Vec<u8>,
        back: u64,
        now: Instant,
    ) {
        let max = match stage {
            STAGE_HELLO => channel::HELLO_LEN,
            STAGE_REPLY => channel::REPLY_LEN,
            _ => channel::AUTH_LEN,
        };
        if count as usize != max.div_ceil(HANDSHAKE_FRAGMENT) {
            return;
        }
        // Only what we can use: a hello at a relay, a reply to our hello,
        // an auth on a channel waiting for one.
        let wanted = match stage {
            STAGE_HELLO => self.config.relay && self.config.relay_key.is_some(),
            STAGE_REPLY => self.channels.pending.contains_key(&(addr, chan)),
            _ => self.channels.open.get(&(addr, chan)).is_some_and(|o| o.ch.awaiting_auth),
        };
        if !wanted {
            return;
        }
        // A hello for a channel answered already: the same reply again.
        if stage == STAGE_HELLO
            && let Some(o) = self.channels.open.get(&(addr, chan))
        {
            if let Some(reply) = o.reply.clone() {
                for m in fragments(chan, STAGE_REPLY, &reply, self.token_for(&addr)) {
                    self.send_with(addr, m, back);
                }
            }
            return;
        }
        let fkey = (addr, chan, stage);
        if !self.channels.fragments.contains_key(&fkey) {
            self.channels.fragments.retain(|_, f| now.duration_since(f.at) < REASSEMBLY_TIME);
            if self.channels.fragments.len() >= MAX_REASSEMBLY {
                return;
            }
        }
        let f = self.channels.fragments.entry(fkey).or_insert_with(|| Fragments { parts: vec![None; count as usize], at: now });
        f.parts[index as usize] = Some(data);
        if f.parts.iter().any(|p| p.is_none()) {
            return;
        }
        let msg: Vec<u8> = self.channels.fragments.remove(&fkey).unwrap().parts.into_iter().flatten().flatten().collect();
        match stage {
            STAGE_HELLO => self.on_hello(addr, chan, &msg, back, now),
            STAGE_REPLY => self.on_reply(addr, chan, &msg, back, now),
            _ => self.on_auth(addr, chan, &msg),
        }
    }

    fn on_hello(&mut self, addr: SocketAddr, chan: u64, hello: &[u8], back: u64, now: Instant) {
        if self.channels.open.len() >= MAX_CHANNELS {
            self.chatter(&format!("channel: refusing {addr}: {MAX_CHANNELS} channels open"));
            return;
        }
        if self.channels.open.keys().filter(|k| k.0.ip() == addr.ip()).count() >= MAX_PER_HOST {
            self.chatter(&format!("channel: refusing {addr}: {MAX_PER_HOST} channels from its host"));
            return;
        }
        let Some(key) = self.config.relay_key.as_ref() else { return };
        let m = match random_bytes::<32>() {
            Ok(m) => m,
            Err(e) => return self.log(&format!("channel: no randomness: {e}")),
        };
        match channel::respond(chan, hello, key, &m, now) {
            Ok((ch, reply)) => {
                let mutual = ch.awaiting_auth;
                for m in fragments(chan, STAGE_REPLY, &reply, self.token_for(&addr)) {
                    self.send_with(addr, m, back);
                }
                self.channels.open.insert((addr, chan), Open { ch, back, reply: Some(reply), auth: None, opened: now, used: false });
                self.chatter(&format!(
                    "channel: {chan:016x} from {addr} open{}",
                    if mutual { ", waiting for its auth" } else { "" }
                ));
            }
            Err(e) => self.chatter(&format!("channel: a bad hello from {addr}: {e}")),
        }
    }

    fn on_reply(&mut self, addr: SocketAddr, chan: u64, reply: &[u8], back: u64, now: Instant) {
        let key = (addr, chan);
        let Some(p) = self.channels.pending.remove(&key) else { return };
        let expect = p.opening.expect;
        let auth_key = if p.opening.mutual() { self.config.relay_key.as_ref() } else { None };
        match p.opening.finish(reply, auth_key, now) {
            Ok((ch, auth)) => {
                self.log(&format!("channel: {chan:016x} to {} at {addr} open", crate::onion::short(&expect)));
                let auth = auth.map(|a| {
                    for m in fragments(chan, STAGE_AUTH, &a, self.token_for(&addr)) {
                        self.send(addr, &m);
                    }
                    (a, now)
                });
                let mutual = auth.is_some();
                self.channels.open.insert(key, Open { ch, back, reply: None, auth, opened: now, used: true });
                // Something for the relay to acknowledge once it has our
                // auth, which ends its resending.
                if mutual {
                    let _ = self.channel_send(key, &[], now);
                }
                for body in p.waiting {
                    if let Err(e) = self.channel_send(key, &body, now) {
                        self.log(&format!("channel: {chan:016x}: a body dropped: {e}"));
                    }
                }
            }
            Err(e) => {
                self.channels.to.retain(|_, k| *k != key);
                // No strike: the address may be an honest peer, and our
                // consensus file the stale one.
                self.log(&format!("channel: {} at {addr} failed the handshake: {e}", crate::onion::short(&expect)));
                self.channel_closed(key, now);
            }
        }
    }

    fn on_auth(&mut self, addr: SocketAddr, chan: u64, auth: &[u8]) {
        let Some(o) = self.channels.open.get_mut(&(addr, chan)) else { return };
        match o.ch.authenticate(auth) {
            Ok(id) => self.log(&format!("channel: {chan:016x} from relay {} at {addr} open", crate::onion::short(&id))),
            Err(e) => self.chatter(&format!("channel: a bad auth from {addr}: {e}")),
        }
    }

    /// A frame for one of our channels.
    pub(super) fn on_frame(&mut self, addr: SocketAddr, f: Frame, now: Instant) {
        let key = (addr, f.chan);
        let Some(o) = self.channels.open.get_mut(&key) else { return };
        let got = match o.ch.receive(&f, now) {
            Ok(got) => got,
            Err(e) => return self.chatter(&format!("channel: {:016x} from {addr}: {e}", f.chan)),
        };
        // The relay acknowledges only once it has our auth.
        o.auth = None;
        o.used = true;
        let peer = o.ch.peer;
        self.send_frames(addr, got.send);
        for body in got.delivered {
            self.on_channel_body(key, peer, body, now);
        }
    }

    /// A body a channel delivered, in order: a cell of a circuit.
    fn on_channel_body(&mut self, key: (SocketAddr, u64), peer: Option<Digest>, body: Vec<u8>, now: Instant) {
        if let Some(cell) = crate::circuit::Cell::from_bytes(&body) {
            return self.on_cell(key, peer, cell, now);
        }
        #[cfg(test)]
        self.channels.sink.lock().unwrap().push((key.0, peer, body.clone()));
        self.chatter(&format!(
            "channel: {} bytes on {:016x} from {} ({})",
            body.len(),
            key.1,
            key.0,
            peer.map_or("a participant".to_string(), |id| crate::onion::short(&id))
        ));
    }
}
