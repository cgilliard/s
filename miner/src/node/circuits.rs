//! Onion mode's circuits in the node (`docs/ONION.md`, [`crate::circuit`]):
//! a client building one hop by hop and talking to its hops, and a relay
//! serving as a hop.
//!
//! The client opens a channel to the first relay and sends it a hop
//! handshake in `Create` cells; each further hop is added by an `Extend`
//! message to the last hop, which opens (or reuses) its channel to the
//! named relay, passes the handshake on in `Create` cells and returns the
//! reply as `Extended`. A relay extends only to a relay the consensus
//! file lists, at the address the file gives. Circuit numbers are per
//! channel: the end that opened the channel uses numbers with the top bit
//! clear, the other end with it set, so the two never pick the same.
//! When a channel closes, every circuit over it is destroyed, and the
//! hop at the other side of each passes the `Destroy` on.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use super::Node;
use crate::chain::ProofVerifier;
use crate::channel::{self, Domain, Opening};
use crate::circuit::{self, Cell, HopKeys, Layer, Reassembly};
use crate::poseidon2::{digest_from_bytes, digest_to_bytes};
use crate::pow::Digest;
use crate::wallet::random_bytes;

/// A circuit not built by then is given up.
const BUILD_TIMEOUT: Duration = Duration::from_secs(30);
/// Hops a relay serves at once by default (`--max-hops`).
pub const MAX_HOPS: usize = 16_384;
/// Circuits a participant's channel may carry: a participant keeps three
/// standing, and a few more while they are replaced. A relay's channel
/// carries many people's circuits and has no such limit.
pub const MAX_HOPS_PER_PARTICIPANT: usize = 64;
/// Hops a client circuit may have.
pub const MAX_PATH: usize = circuit::MAX_PATH;
/// A hop that carries no cell for this long is dropped: a standing
/// circuit's session keepalive passes every 10 to 20 minutes.
const HOP_IDLE: Duration = Duration::from_secs(3600);
/// Cells a client may push through a hop: a bucket of this many (six
/// largest messages), refilled at [`HOP_CELLS_PER_SEC`]. Past it the
/// circuit ends, so one circuit cannot fill a channel's queue.
const HOP_BURST: f64 = 1024.0;
const HOP_CELLS_PER_SEC: f64 = 128.0;

/// A circuit on one channel: the channel and the circuit's number on it.
pub(super) type Link = ((SocketAddr, u64), u32);

/// What this relay keeps for a circuit through it.
struct Hop {
    keys: HopKeys,
    next: Option<Link>,
    /// The next hop's handshake reply, while extending.
    extending: Option<Vec<u8>>,
    /// A relay message for this hop, coming together.
    message: Reassembly,
    /// When a cell last passed, either way.
    last_used: Instant,
    /// Cells the client may still send, and when last refilled.
    budget: (f64, Instant),
}

/// A circuit this node built, or is building.
struct Mine {
    path: Vec<Digest>,
    first: Link,
    hops: Vec<HopKeys>,
    /// The handshake with the hop being added, and its reply so far.
    adding: Option<(Opening, Vec<u8>)>,
    /// Messages from each hop, coming together.
    messages: Vec<Reassembly>,
    started: Instant,
    /// Data to send to a hop once the circuit is built.
    queued: Vec<(usize, Vec<u8>)>,
}

impl Mine {
    fn ready(&self) -> bool {
        self.hops.len() == self.path.len()
    }
}

/// Tests: what circuits did.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Seen {
    Ready(u64),
    Failed(u64),
    /// Data from hop `.1` of circuit `.0`.
    Data(u64, usize, Vec<u8>),
    /// Data a hop of ours was sent.
    AtHop(Vec<u8>),
    /// Another message from hop `.1` of circuit `.0`: its command, bytes.
    Msg(u64, usize, u8, Vec<u8>),
    /// At a relay, a message at the end of a circuit through it: its
    /// command, the session the circuit holds here if any, its bytes.
    AtEnd(u8, Option<crate::pow::Digest>, Vec<u8>),
}

#[derive(Default)]
pub(super) struct Circuits {
    hops: HashMap<Link, Hop>,
    /// A hop's next link, back to its previous one.
    by_next: HashMap<Link, Link>,
    /// Handshakes coming together, by the link they arrive on.
    creating: HashMap<Link, (Vec<u8>, Instant)>,
    mine: HashMap<u64, Mine>,
    by_link: HashMap<Link, u64>,
    next_handle: u64,
    #[cfg(test)]
    pub(super) seen: std::sync::Arc<std::sync::Mutex<Vec<Seen>>>,
    /// Tests: the paths of the circuits this node built.
    #[cfg(test)]
    pub(super) paths: std::sync::Arc<std::sync::Mutex<Vec<Vec<crate::pow::Digest>>>>,
}

impl Circuits {
    pub(super) fn counts(&self) -> (usize, usize) {
        (self.mine.values().filter(|m| m.ready()).count(), self.hops.len())
    }

    fn in_use(&self, link: &Link) -> bool {
        self.hops.contains_key(link) || self.by_next.contains_key(link) || self.by_link.contains_key(link)
    }
}

impl<V: ProofVerifier + Send + Sync + 'static> Node<V> {
    /// The listed relay `id`'s address, in onion mode.
    pub(super) fn relay_addr(&mut self, id: &Digest) -> Option<SocketAddr> {
        let name = self.rv.listed(id)?.addr.clone();
        name.to_socket_addrs().ok()?.find(|a| a.is_ipv4())
    }

    /// A circuit number free on channel `key`, from our half.
    fn new_circ(&self, key: (SocketAddr, u64)) -> std::io::Result<u32> {
        let top = if self.channels.initiator(&key).unwrap_or(true) { 0 } else { 1 << 31 };
        loop {
            let c = (u32::from_le_bytes(random_bytes::<4>()?) & 0x7fff_ffff) | top;
            if !self.circuits.in_use(&(key, c)) {
                return Ok(c);
            }
        }
    }

    fn send_cell(&mut self, link: Link, cell: Cell, now: Instant) {
        if let Err(e) = self.channel_send(link.0, &cell.to_bytes(), now) {
            self.chatter(&format!("circuit: a cell to {} dropped: {e}", link.0.0));
        }
    }

    /// Builds a circuit through the listed relays `path`, in order; data
    /// queued for it goes once it is built. Returns its handle. (The
    /// wallet's standing circuits use it, step 4e.)
    pub(super) fn build_circuit(
        &mut self,
        path: Vec<Digest>,
        queued: Vec<(usize, Vec<u8>)>,
        now: Instant,
    ) -> Result<u64, String> {
        if path.is_empty() || path.len() > MAX_PATH {
            return Err(format!("a circuit has 1 to {MAX_PATH} hops"));
        }
        if (1..path.len()).any(|i| path[..i].contains(&path[i])) {
            return Err("a relay twice in one circuit".into());
        }
        #[cfg(test)]
        self.circuits.paths.lock().unwrap().push(path.clone());
        let addr = self.relay_addr(&path[0]).ok_or("the first hop is not a listed relay")?;
        let key = self.channel_to(addr, path[0], now).map_err(|e| e.to_string())?;
        let circ = self.new_circ(key).map_err(|e| e.to_string())?;
        let opening = Opening::circuit(
            path[0],
            &random_bytes::<64>().map_err(|e| e.to_string())?,
            random_bytes::<32>().map_err(|e| e.to_string())?,
        );
        let handle = self.circuits.next_handle;
        self.circuits.next_handle += 1;
        let first = (key, circ);
        for c in circuit::handshake_cells(circ, circuit::CREATE, &opening.hello) {
            self.send_cell(first, c, now);
        }
        let n = path.len();
        self.circuits.mine.insert(
            handle,
            Mine {
                path,
                first,
                hops: Vec::new(),
                adding: Some((opening, Vec::new())),
                messages: (0..n).map(|_| Reassembly::default()).collect(),
                started: now,
                queued,
            },
        );
        self.circuits.by_link.insert(first, handle);
        Ok(handle)
    }

    /// Ends circuit `handle` of ours.
    pub(super) fn close_circuit(&mut self, handle: u64, why: &str, now: Instant) {
        self.drop_mine(handle, why, true, now);
    }

    /// How many hops circuit `handle` of ours has, built or not.
    pub(super) fn circuit_hops(&self, handle: u64) -> usize {
        self.circuits.mine.get(&handle).map_or(0, |m| m.path.len())
    }

    /// The first hop's address of circuit `handle` of ours.
    pub(super) fn circuit_first(&self, handle: u64) -> Option<SocketAddr> {
        self.circuits.mine.get(&handle).map(|m| m.first.0.0)
    }

    /// Sends `data` to hop `hop` of circuit `handle`.
    pub(super) fn circuit_send(
        &mut self,
        handle: u64,
        hop: usize,
        cmd: u8,
        data: &[u8],
        now: Instant,
    ) -> Result<(), String> {
        let m = self.circuits.mine.get_mut(&handle).ok_or("no such circuit")?;
        if hop >= m.hops.len() {
            return Err("no such hop yet".into());
        }
        let first = m.first;
        let cells: Vec<Cell> = circuit::relay_bodies(cmd, data)
            .iter()
            .map(|b| Cell { circ: first.1, cmd: circuit::RELAY, payload: circuit::seal_for(&mut m.hops, hop, b) })
            .collect();
        for c in cells {
            self.send_cell(first, c, now);
        }
        Ok(())
    }

    /// Gives up circuits that are not built in time.
    pub(super) fn circuits_tick(&mut self, now: Instant) {
        let late: Vec<u64> = self
            .circuits
            .mine
            .iter()
            .filter(|(_, m)| !m.ready() && now.duration_since(m.started) >= BUILD_TIMEOUT)
            .map(|(h, _)| *h)
            .collect();
        for h in late {
            // The hop being added never answered: most likely it is down.
            if let Some(m) = self.circuits.mine.get(&h) {
                let hop = m.path[m.hops.len()];
                self.avoid_relay(hop, now);
            }
            self.drop_mine(h, "not built in time", true, now);
        }
        self.circuits.creating.retain(|_, (_, t)| now.duration_since(*t) < BUILD_TIMEOUT);
        let idle: Vec<Link> = self
            .circuits
            .hops
            .iter()
            .filter(|(_, h)| now.duration_since(h.last_used) >= HOP_IDLE)
            .map(|(l, _)| *l)
            .collect();
        for link in idle {
            self.destroy_hop(link, true, true, now);
        }
    }

    fn drop_mine(&mut self, handle: u64, why: &str, destroy: bool, now: Instant) {
        let Some(m) = self.circuits.mine.remove(&handle) else { return };
        self.circuits.by_link.remove(&m.first);
        if destroy {
            self.send_cell(m.first, Cell::new(m.first.1, circuit::DESTROY), now);
        }
        self.log(&format!("circuit {handle}: closed after {} of {} hops: {why}", m.hops.len(), m.path.len()));
        // Failed while a hop was being added: most likely that hop is
        // down, so it is left out of the next paths for a while.
        if !m.ready() && !destroy {
            self.avoid_relay(m.path[m.hops.len()], now);
        }
        // Failed adding its last hop: the far end is at fault.
        let at_end = !m.ready() && m.hops.len() + 1 == m.path.len();
        #[cfg(test)]
        self.circuits.seen.lock().unwrap().push(Seen::Failed(handle));
        self.onion_circuit_gone(handle, at_end, now);
    }

    /// The channels a circuit runs over, ours or through us, or one being
    /// built, or a question to another rendezvous point waits on.
    pub(super) fn channels_in_use(&self) -> std::collections::HashSet<(SocketAddr, u64)> {
        let mut busy: std::collections::HashSet<(SocketAddr, u64)> = std::collections::HashSet::new();
        busy.extend(self.circuits.hops.keys().map(|l| l.0));
        busy.extend(self.circuits.by_next.keys().map(|l| l.0));
        busy.extend(self.circuits.by_link.keys().map(|l| l.0));
        busy.extend(self.circuits.creating.keys().map(|l| l.0));
        busy.extend(self.rendezvous_channels());
        busy
    }

    /// Every circuit over a channel that closed: ours are dropped, and a
    /// hop's other side is told.
    pub(super) fn channel_closed(&mut self, key: (SocketAddr, u64), now: Instant) {
        let mine: Vec<u64> = self.circuits.by_link.iter().filter(|(l, _)| l.0 == key).map(|(_, h)| *h).collect();
        for h in mine {
            self.drop_mine(h, "its channel closed", false, now);
        }
        let prevs: Vec<Link> = self.circuits.hops.keys().filter(|l| l.0 == key).copied().collect();
        for prev in prevs {
            self.destroy_hop(prev, false, true, now);
        }
        let nexts: Vec<Link> = self.circuits.by_next.iter().filter(|(l, _)| l.0 == key).map(|(_, p)| *p).collect();
        for prev in nexts {
            self.destroy_hop(prev, true, false, now);
        }
        self.circuits.creating.retain(|l, _| l.0 != key);
    }

    /// Ends the hop entered at `prev`, telling the previous side, the
    /// next, or both (not the side the end came from).
    fn destroy_hop(&mut self, prev: Link, tell_prev: bool, tell_next: bool, now: Instant) {
        let Some(h) = self.circuits.hops.remove(&prev) else { return };
        self.rendezvous_link_gone(&prev);
        if let Some(next) = h.next {
            self.circuits.by_next.remove(&next);
            if tell_next {
                self.send_cell(next, Cell::new(next.1, circuit::DESTROY), now);
            }
        }
        if tell_prev {
            self.send_cell(prev, Cell::new(prev.1, circuit::DESTROY), now);
        }
    }

    /// A cell on one of our channels.
    pub(super) fn on_cell(&mut self, key: (SocketAddr, u64), peer: Option<Digest>, mut cell: Cell, now: Instant) {
        if cell.cmd == circuit::RENDEZVOUS {
            return self.on_rendezvous_cell(key, peer, &cell, now);
        }
        let link = (key, cell.circ);
        // Ours: a hop's reply, or a cell coming back.
        if let Some(&handle) = self.circuits.by_link.get(&link) {
            return self.on_my_cell(handle, cell, now);
        }
        // Coming back through us from the next hop: our layer on, to the
        // previous one.
        if let Some(&prev) = self.circuits.by_next.get(&link) {
            match cell.cmd {
                circuit::RELAY => {
                    let h = self.circuits.hops.get_mut(&prev).unwrap();
                    h.last_used = now;
                    h.keys.backward.pass(&mut cell.payload);
                    cell.circ = prev.1;
                    self.send_cell(prev, cell, now);
                }
                circuit::CREATED => self.on_next_created(prev, &cell, now),
                circuit::DESTROY => self.destroy_hop(prev, true, false, now),
                _ => {}
            }
            return;
        }
        match cell.cmd {
            circuit::CREATE => self.on_create(link, &cell, now),
            circuit::RELAY => self.on_forward(link, cell, now),
            circuit::DESTROY => self.destroy_hop(link, false, true, now),
            _ => {}
        }
    }

    /// A hop handshake for a circuit through us.
    fn on_create(&mut self, link: Link, cell: &Cell, now: Instant) {
        if !self.config.relay || self.circuits.hops.contains_key(&link) {
            return;
        }
        let Some((more, part)) = circuit::handshake_piece(cell) else { return };
        let e = self.circuits.creating.entry(link).or_insert_with(|| (Vec::new(), now));
        e.0.extend_from_slice(part);
        if more {
            if e.0.len() > channel::HELLO_LEN {
                self.circuits.creating.remove(&link);
            }
            return;
        }
        let hello = self.circuits.creating.remove(&link).unwrap().0;
        let participant = self.channels.peer(&link.0) == Some(None);
        if self.circuits.hops.len() >= self.config.max_hops
            || participant && self.circuits.hops.keys().filter(|l| l.0 == link.0).count() >= MAX_HOPS_PER_PARTICIPANT
        {
            return self.send_cell(link, Cell::new(link.1, circuit::DESTROY), now);
        }
        let (Some(key), Ok(m)) = (self.config.relay_key.as_ref(), random_bytes::<32>()) else { return };
        match channel::respond_keys(Domain::Circuit, 0, &hello, key, &m) {
            Ok(((out, inn, _), reply)) => {
                let keys = HopKeys { forward: Layer::new(inn), backward: Layer::new(out) };
                self.circuits.hops.insert(
                    link,
                    Hop {
                        keys,
                        next: None,
                        extending: None,
                        message: Reassembly::default(),
                        last_used: now,
                        budget: (HOP_BURST, now),
                    },
                );
                for c in circuit::handshake_cells(link.1, circuit::CREATED, &reply) {
                    self.send_cell(link, c, now);
                }
            }
            Err(e) => {
                self.chatter(&format!("circuit: a bad create from {}: {e}", link.0.0));
                self.send_cell(link, Cell::new(link.1, circuit::DESTROY), now);
            }
        }
    }

    /// A relay cell from the previous hop: ours to read, or to pass on.
    fn on_forward(&mut self, link: Link, mut cell: Cell, now: Instant) {
        let Some(h) = self.circuits.hops.get_mut(&link) else { return };
        h.last_used = now;
        let (tokens, at) = &mut h.budget;
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * HOP_CELLS_PER_SEC).min(HOP_BURST);
        *at = now;
        if *tokens < 1.0 {
            self.chatter(&format!("circuit: {} sent cells too fast; ending the circuit", link.0.0));
            return self.destroy_hop(link, true, true, now);
        }
        *tokens -= 1.0;
        let body = match circuit::hop_forward(&mut h.keys.forward, &mut cell.payload) {
            circuit::Forward::Mine(body) => body,
            circuit::Forward::Pass => {
                match h.next {
                    Some(next) => {
                        cell.circ = next.1;
                        self.send_cell(next, cell, now);
                    }
                    // For nobody: the circuit is broken.
                    None => self.destroy_hop(link, true, true, now),
                }
                return;
            }
            // A hop before flipped bits, or the cell is forged: the
            // circuit ends.
            circuit::Forward::Tampered => {
                self.chatter(&format!("circuit: a tampered cell from {}; ending the circuit", link.0.0));
                return self.destroy_hop(link, true, true, now);
            }
        };
        let done = match circuit::relay_piece(&body[..]) {
            Some((cmd, more, data)) => h.message.add(cmd, more, data),
            None => Err(circuit::Malformed),
        };
        match done {
            Ok(None) => {}
            Ok(Some((cmd, msg))) => self.on_hop_message(link, cmd, msg, now),
            Err(_) => self.destroy_hop(link, true, true, now),
        }
    }

    /// Originates a relay message back toward the client.
    pub(super) fn hop_reply(&mut self, link: Link, cmd: u8, msg: &[u8], now: Instant) {
        let Some(h) = self.circuits.hops.get_mut(&link) else { return };
        h.last_used = now;
        let cells: Vec<Cell> = circuit::relay_bodies(cmd, msg)
            .iter()
            .map(|b| Cell { circ: link.1, cmd: circuit::RELAY, payload: h.keys.backward.originate(b) })
            .collect();
        for c in cells {
            self.send_cell(link, c, now);
        }
    }

    /// A relay message for this hop.
    fn on_hop_message(&mut self, link: Link, cmd: u8, msg: Vec<u8>, now: Instant) {
        match cmd {
            circuit::EXTEND => {
                let ok = self.extend(link, &msg, now);
                if let Err(why) = ok {
                    self.chatter(&format!("circuit: not extending for {}: {why}", link.0.0));
                    self.destroy_hop(link, true, true, now);
                }
            }
            circuit::DATA => self.hop_data(link, msg, now),
            // The rendezvous service, at the end of a circuit only.
            cmd if self.circuits.hops.get(&link).is_some_and(|h| h.next.is_none())
                && !self.rendezvous_message(link, cmd, &msg, now) =>
            {
                self.chatter(&format!("circuit: an unknown message {cmd} at a hop"));
            }
            _ => {}
        }
    }

    /// Data a client sent this hop. The rendezvous service takes it in
    /// step 4d; tests echo what asks for it.
    fn hop_data(&mut self, link: Link, msg: Vec<u8>, now: Instant) {
        #[cfg(test)]
        {
            self.circuits.seen.lock().unwrap().push(Seen::AtHop(msg.clone()));
            if let Some(rest) = msg.strip_prefix(b"echo:") {
                let mut back = b"echoed:".to_vec();
                back.extend_from_slice(rest);
                return self.hop_reply(link, circuit::DATA, &back, now);
            }
        }
        let _ = (now, &link);
        self.chatter(&format!("circuit: {} bytes of data at a hop", msg.len()));
    }

    /// Extends a circuit through us to the relay an `Extend` names.
    fn extend(&mut self, link: Link, msg: &[u8], now: Instant) -> Result<(), String> {
        if msg.len() != 32 + channel::HELLO_LEN {
            return Err("malformed".into());
        }
        if self.circuits.hops.get(&link).is_some_and(|h| h.next.is_some()) {
            return Err("extended already".into());
        }
        let id = digest_from_bytes(&msg[..32]).ok_or("malformed id")?;
        if self.config.relay_id() == Some(id) {
            return Err("to itself".into());
        }
        let addr = self.relay_addr(&id).ok_or("not a listed relay")?;
        let key = self.channel_to(addr, id, now).map_err(|e| e.to_string())?;
        let circ = self.new_circ(key).map_err(|e| e.to_string())?;
        let next = (key, circ);
        let h = self.circuits.hops.get_mut(&link).unwrap();
        h.next = Some(next);
        h.extending = Some(Vec::new());
        self.circuits.by_next.insert(next, link);
        for c in circuit::handshake_cells(circ, circuit::CREATE, &msg[32..]) {
            self.send_cell(next, c, now);
        }
        Ok(())
    }

    /// The next hop's handshake reply, while extending: passed back.
    fn on_next_created(&mut self, prev: Link, cell: &Cell, now: Instant) {
        let Some((more, part)) = circuit::handshake_piece(cell) else { return };
        let Some(h) = self.circuits.hops.get_mut(&prev) else { return };
        let Some(buf) = h.extending.as_mut() else { return };
        buf.extend_from_slice(part);
        if buf.len() > channel::REPLY_LEN {
            h.extending = None;
            return;
        }
        if more {
            return;
        }
        let reply = h.extending.take().unwrap();
        self.hop_reply(prev, circuit::EXTENDED, &reply, now);
    }

    /// A cell on one of our circuits.
    fn on_my_cell(&mut self, handle: u64, mut cell: Cell, now: Instant) {
        match cell.cmd {
            circuit::CREATED => {
                let Some((more, part)) = circuit::handshake_piece(&cell) else { return };
                let Some(m) = self.circuits.mine.get_mut(&handle) else { return };
                if !m.hops.is_empty() {
                    return;
                }
                let Some((_, buf)) = m.adding.as_mut() else { return };
                buf.extend_from_slice(part);
                if !more {
                    let (opening, reply) = m.adding.take().unwrap();
                    self.hop_added(handle, opening, &reply, now);
                }
            }
            circuit::RELAY => {
                let Some(m) = self.circuits.mine.get_mut(&handle) else { return };
                let Some(j) = circuit::open_from(&mut m.hops, &mut cell.payload) else {
                    return self.drop_mine(handle, "a cell no hop sent", true, now);
                };
                // The body follows the originating hop's tag.
                let body = &cell.payload[crate::chacha20poly1305::TAG_LEN..][..circuit::BODY];
                let Some((cmd, more, data)) = circuit::relay_piece(body) else {
                    return;
                };
                match m.messages[j].add(cmd, more, data) {
                    Ok(None) => {}
                    Ok(Some((cmd, msg))) => self.on_my_message(handle, j, cmd, msg, now),
                    Err(_) => self.drop_mine(handle, "a malformed message", true, now),
                }
            }
            circuit::DESTROY => self.drop_mine(handle, "a hop ended it", false, now),
            _ => {}
        }
    }

    fn on_my_message(&mut self, handle: u64, hop: usize, cmd: u8, msg: Vec<u8>, now: Instant) {
        match cmd {
            circuit::EXTENDED => {
                let Some(m) = self.circuits.mine.get_mut(&handle) else { return };
                if hop + 1 != m.hops.len() {
                    return;
                }
                let Some((opening, _)) = m.adding.take() else { return };
                self.hop_added(handle, opening, &msg, now);
            }
            circuit::DATA => {
                #[cfg(test)]
                self.circuits.seen.lock().unwrap().push(Seen::Data(handle, hop, msg.clone()));
                self.chatter(&format!("circuit {handle}: {} bytes from hop {hop}", msg.len()));
            }
            _ => {
                #[cfg(test)]
                self.circuits.seen.lock().unwrap().push(Seen::Msg(handle, hop, cmd, msg.clone()));
                let last = self.circuit_hops(handle).saturating_sub(1);
                if hop != last || !self.onion_message(handle, cmd, &msg, now) {
                    self.chatter(&format!("circuit {handle}: message {cmd} from hop {hop}"));
                }
            }
        }
    }

    /// A hop's reply came: its keys join the circuit, and the next hop
    /// is asked for, or the circuit is built.
    fn hop_added(&mut self, handle: u64, opening: Opening, reply: &[u8], now: Instant) {
        let (out, inn) = match opening.keys(reply) {
            Ok((out, inn, _)) => (out, inn),
            Err(e) => {
                return self.drop_mine(
                    handle,
                    &format!("hop {} failed its handshake: {e}", crate::onion::short(&opening.expect)),
                    true,
                    now,
                );
            }
        };
        let m = self.circuits.mine.get_mut(&handle).unwrap();
        m.hops.push(HopKeys { forward: Layer::new(out), backward: Layer::new(inn) });
        if m.ready() {
            let queued = std::mem::take(&mut m.queued);
            let n = m.path.len();
            self.log(&format!("circuit {handle}: built, {n} hops"));
            #[cfg(test)]
            self.circuits.seen.lock().unwrap().push(Seen::Ready(handle));
            self.onion_circuit_ready(handle, now);
            for (hop, data) in queued {
                if let Err(e) = self.circuit_send(handle, hop, circuit::DATA, &data, now) {
                    self.log(&format!("circuit {handle}: {e}"));
                }
            }
            return;
        }
        let next = m.path[m.hops.len()];
        let last = m.hops.len() - 1;
        let (seed, challenge) = match (random_bytes::<64>(), random_bytes::<32>()) {
            (Ok(s), Ok(c)) => (s, c),
            _ => return self.drop_mine(handle, "no randomness", true, now),
        };
        let opening = Opening::circuit(next, &seed, challenge);
        let mut msg = digest_to_bytes(&next).to_vec();
        msg.extend_from_slice(&opening.hello);
        m.adding = Some((opening, Vec::new()));
        if let Err(e) = self.circuit_send(handle, last, circuit::EXTEND, &msg, now) {
            self.drop_mine(handle, &e, true, now);
        }
    }
}
