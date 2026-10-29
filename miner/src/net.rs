//! Peer-to-peer transport over UDP: the wire format, the peer table and
//! chunked block transfer. [`crate::node`] drives it.
//!
//! # Datagrams
//!
//! Every datagram is `MAGIC`, a type byte and a payload encoded with
//! [`crate::codec`], and fits in [`MAX_DATAGRAM`] bytes so it crosses any
//! IPv6 path without fragmentation. Nothing is encrypted or signed: blocks
//! and headers carry their own proof of work and validity proof, and a peer
//! table entry is only an address to try.
//!
//! # Messages
//!
//! | message      | payload                                   | reply            |
//! |--------------|-------------------------------------------|------------------|
//! | `Ping`       | [`Status`]: nonce, version, genesis, tip  | `Pong`           |
//! | `Pong`       | [`Status`] echoing the nonce              |                  |
//! | `GetPeers`   |                                           | `Peers`          |
//! | `Peers`      | up to 32 addresses                        |                  |
//! | `GetHeaders` | block locator, up to 32 ids               | `Headers`, several |
//! | `Headers`    | up to 6 main-chain headers, oldest first  |                  |
//! | `Inv`        | the header of a new block                 |                  |
//! | `GetChunks`  | block id and up to 32 chunk indexes       | `Chunk`, one each |
//! | `Chunk`      | block id, block length, index, bytes      |                  |
//!
//! A block is fetched as [`CHUNK_BYTES`]-byte chunks of its serialization
//! ([`crate::block::Block::to_bytes`]), pulled by the receiver in windows
//! of [`WINDOW`] with [`Download`] tracking what arrived. A node only sends
//! data in reply to a request and never more than the request asked for,
//! so it cannot be used to amplify traffic.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::block::{HEADER_SIZE, Header};
use crate::codec::{Reader, Writer};
use crate::difficulty::U256;
use crate::pow::Digest;

pub const MAGIC: [u8; 4] = *b"TAB1";
pub const PROTOCOL_VERSION: u32 = 1;
/// Largest datagram sent: the IPv6 minimum MTU less its headers.
pub const MAX_DATAGRAM: usize = 1232;
/// Block bytes per chunk.
pub const CHUNK_BYTES: usize = 1024;
/// Chunks requested at once.
pub const WINDOW: usize = 32;
/// Headers per `Headers` message.
pub const HEADERS_PER_MESSAGE: usize = 6;
/// Most headers a `GetHeaders` is answered with, over several messages.
pub const MAX_HEADERS: usize = 60;
pub const MAX_LOCATOR: usize = 32;
pub const MAX_PEERS_MESSAGE: usize = 32;

const T_PING: u8 = 1;
const T_PONG: u8 = 2;
const T_GET_PEERS: u8 = 3;
const T_PEERS: u8 = 4;
const T_GET_HEADERS: u8 = 5;
const T_HEADERS: u8 = 6;
const T_INV: u8 = 7;
const T_GET_CHUNKS: u8 = 8;
const T_CHUNK: u8 = 9;

/// What a node says about itself in `Ping` and `Pong`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// Set by the pinger; the pong echoes it.
    pub nonce: u64,
    pub version: u32,
    /// Genesis block id; peers on another chain are ignored.
    pub genesis: Digest,
    pub height: u32,
    pub tip: Digest,
    /// Cumulative work of the main chain.
    pub work: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Ping(Status),
    Pong(Status),
    GetPeers,
    Peers(Vec<SocketAddr>),
    GetHeaders { locator: Vec<Digest> },
    Headers(Vec<Header>),
    Inv(Header),
    GetChunks { id: Digest, indexes: Vec<u16> },
    Chunk { id: Digest, len: u32, index: u16, data: Vec<u8> },
}

fn put_status(w: &mut Writer, s: &Status) {
    w.u64(s.nonce);
    w.u32(s.version);
    w.digest(&s.genesis);
    w.u32(s.height);
    w.digest(&s.tip);
    w.0.extend_from_slice(&s.work.to_le_bytes());
}

fn get_status(r: &mut Reader) -> Option<Status> {
    Some(Status {
        nonce: r.u64()?,
        version: r.u32()?,
        genesis: r.digest()?,
        height: r.u32()?,
        tip: r.digest()?,
        work: U256::from_le_bytes(r.take(32)?.try_into().unwrap()),
    })
}

fn put_addr(w: &mut Writer, a: &SocketAddr) {
    match a.ip() {
        IpAddr::V4(ip) => {
            w.0.push(4);
            w.0.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            w.0.push(6);
            w.0.extend_from_slice(&ip.octets());
        }
    }
    w.0.extend_from_slice(&a.port().to_le_bytes());
}

fn get_addr(r: &mut Reader) -> Option<SocketAddr> {
    let ip = match r.take(1)?[0] {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(r.take(4)?).unwrap())),
        6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(r.take(16)?).unwrap())),
        _ => return None,
    };
    let port = u16::from_le_bytes(r.take(2)?.try_into().unwrap());
    Some(SocketAddr::new(ip, port))
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(MAX_DATAGRAM);
        w.0.extend_from_slice(&MAGIC);
        match self {
            Message::Ping(s) => {
                w.0.push(T_PING);
                put_status(&mut w, s);
            }
            Message::Pong(s) => {
                w.0.push(T_PONG);
                put_status(&mut w, s);
            }
            Message::GetPeers => w.0.push(T_GET_PEERS),
            Message::Peers(addrs) => {
                w.0.push(T_PEERS);
                w.0.push(addrs.len().min(MAX_PEERS_MESSAGE) as u8);
                for a in addrs.iter().take(MAX_PEERS_MESSAGE) {
                    put_addr(&mut w, a);
                }
            }
            Message::GetHeaders { locator } => {
                w.0.push(T_GET_HEADERS);
                w.digest_vec(&locator[..locator.len().min(MAX_LOCATOR)]);
            }
            Message::Headers(headers) => {
                w.0.push(T_HEADERS);
                w.0.push(headers.len().min(HEADERS_PER_MESSAGE) as u8);
                for h in headers.iter().take(HEADERS_PER_MESSAGE) {
                    w.0.extend_from_slice(&h.to_bytes());
                }
            }
            Message::Inv(h) => {
                w.0.push(T_INV);
                w.0.extend_from_slice(&h.to_bytes());
            }
            Message::GetChunks { id, indexes } => {
                w.0.push(T_GET_CHUNKS);
                w.digest(id);
                w.0.push(indexes.len().min(WINDOW) as u8);
                for i in indexes.iter().take(WINDOW) {
                    w.0.extend_from_slice(&i.to_le_bytes());
                }
            }
            Message::Chunk { id, len, index, data } => {
                w.0.push(T_CHUNK);
                w.digest(id);
                w.u32(*len);
                w.0.extend_from_slice(&index.to_le_bytes());
                w.0.extend_from_slice(&(data.len() as u16).to_le_bytes());
                w.0.extend_from_slice(data);
            }
        }
        debug_assert!(w.0.len() <= MAX_DATAGRAM, "datagram of {} bytes", w.0.len());
        w.finish()
    }

    /// Decodes a datagram; `None` for anything malformed, including
    /// trailing bytes.
    pub fn decode(bytes: &[u8]) -> Option<Message> {
        if bytes.len() > MAX_DATAGRAM || bytes.len() < 5 || bytes[..4] != MAGIC {
            return None;
        }
        let mut r = Reader(&bytes[5..]);
        let count = |r: &mut Reader, max: usize| -> Option<usize> {
            let n = r.take(1)?[0] as usize;
            (n <= max).then_some(n)
        };
        let msg = match bytes[4] {
            T_PING => Message::Ping(get_status(&mut r)?),
            T_PONG => Message::Pong(get_status(&mut r)?),
            T_GET_PEERS => Message::GetPeers,
            T_PEERS => {
                let n = count(&mut r, MAX_PEERS_MESSAGE)?;
                Message::Peers((0..n).map(|_| get_addr(&mut r)).collect::<Option<Vec<_>>>()?)
            }
            T_GET_HEADERS => {
                let locator = r.digest_vec()?;
                (locator.len() <= MAX_LOCATOR).then_some(())?;
                Message::GetHeaders { locator }
            }
            T_HEADERS => {
                let n = count(&mut r, HEADERS_PER_MESSAGE)?;
                let headers = (0..n).map(|_| Header::from_bytes(r.take(HEADER_SIZE)?)).collect::<Option<Vec<_>>>()?;
                Message::Headers(headers)
            }
            T_INV => Message::Inv(Header::from_bytes(r.take(HEADER_SIZE)?)?),
            T_GET_CHUNKS => {
                let id = r.digest()?;
                let n = count(&mut r, WINDOW)?;
                let indexes = (0..n)
                    .map(|_| Some(u16::from_le_bytes(r.take(2)?.try_into().unwrap())))
                    .collect::<Option<Vec<_>>>()?;
                Message::GetChunks { id, indexes }
            }
            T_CHUNK => {
                let id = r.digest()?;
                let len = r.u32()?;
                let index = u16::from_le_bytes(r.take(2)?.try_into().unwrap());
                let n = u16::from_le_bytes(r.take(2)?.try_into().unwrap()) as usize;
                (n <= CHUNK_BYTES).then_some(())?;
                let data = r.take(n)?.to_vec();
                Message::Chunk { id, len, index, data }
            }
            _ => return None,
        };
        r.is_empty().then_some(msg)
    }
}

/// Number of chunks of a block of `len` bytes.
pub fn chunk_count(len: u32) -> usize {
    (len as usize).div_ceil(CHUNK_BYTES)
}

/// Chunk `index` of `bytes`, for a `Chunk` message.
pub fn chunk_of(id: &Digest, bytes: &[u8], index: u16) -> Option<Message> {
    let start = index as usize * CHUNK_BYTES;
    if start >= bytes.len() {
        return None;
    }
    let end = (start + CHUNK_BYTES).min(bytes.len());
    Some(Message::Chunk { id: *id, len: bytes.len() as u32, index, data: bytes[start..end].to_vec() })
}

/// How long a download may go without a new chunk before its window is
/// requested again.
pub const RETRY: Duration = Duration::from_millis(400);
/// Retries without progress before a download is abandoned.
pub const MAX_RETRIES: u32 = 8;

/// A block being fetched chunk by chunk from one peer, with a sliding
/// window of requested chunks: [`Download::request`] asks for up to
/// [`WINDOW`] chunks not yet in flight, and the node refills when half the
/// window has arrived or when nothing has arrived for [`RETRY`].
#[derive(Debug)]
pub struct Download {
    pub id: Digest,
    pub from: SocketAddr,
    pub max_len: usize,
    /// Known once the first chunk arrives.
    len: Option<u32>,
    chunks: Vec<Option<Vec<u8>>>,
    /// Requested and not yet received.
    in_flight: Vec<u16>,
    pub last_progress: Instant,
    pub last_request: Instant,
    pub retries: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChunkError {
    /// Chunk from a different block or peer.
    Unexpected,
    /// Length or index out of bounds, or inconsistent with earlier chunks.
    Malformed,
}

impl Download {
    pub fn new(id: Digest, from: SocketAddr, max_len: usize, now: Instant) -> Download {
        Download {
            id,
            from,
            max_len,
            len: None,
            chunks: Vec::new(),
            in_flight: Vec::new(),
            last_progress: now,
            last_request: now,
            retries: 0,
        }
    }

    /// Indexes still missing, up to `max`, from the start.
    pub fn missing(&self, max: usize) -> Vec<u16> {
        match self.len {
            None => (0..max.min(WINDOW) as u16).collect(),
            Some(_) => {
                self.chunks.iter().enumerate().filter(|(_, c)| c.is_none()).map(|(i, _)| i as u16).take(max).collect()
            }
        }
    }

    /// Missing indexes to request now: those not in flight, up to the free
    /// part of the window. They become in flight.
    pub fn request(&mut self, now: Instant) -> Vec<u16> {
        let room = WINDOW.saturating_sub(self.in_flight.len());
        let fresh: Vec<u16> = self
            .missing(WINDOW + self.in_flight.len())
            .into_iter()
            .filter(|i| !self.in_flight.contains(i))
            .take(room)
            .collect();
        self.in_flight.extend(&fresh);
        if !fresh.is_empty() {
            self.last_request = now;
        }
        fresh
    }

    /// Forgets what is in flight, so the next request repeats it.
    pub fn reset_window(&mut self) {
        self.in_flight.clear();
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Records a chunk; `Ok(true)` when the block is complete.
    pub fn insert(&mut self, len: u32, index: u16, data: Vec<u8>, now: Instant) -> Result<bool, ChunkError> {
        if len as usize > self.max_len || len == 0 {
            return Err(ChunkError::Malformed);
        }
        match self.len {
            None => {
                self.len = Some(len);
                self.chunks = vec![None; chunk_count(len)];
            }
            Some(l) if l != len => return Err(ChunkError::Malformed),
            Some(_) => {}
        }
        let i = index as usize;
        let expected = if i + 1 == self.chunks.len() { len as usize - i * CHUNK_BYTES } else { CHUNK_BYTES };
        if i >= self.chunks.len() || data.len() != expected {
            return Err(ChunkError::Malformed);
        }
        if self.chunks[i].is_none() {
            self.chunks[i] = Some(data);
            self.last_progress = now;
            self.retries = 0;
        }
        self.in_flight.retain(|&j| j != index);
        Ok(self.chunks.iter().all(Option::is_some))
    }

    /// The block bytes once every chunk has arrived.
    pub fn assemble(&self) -> Option<Vec<u8>> {
        let len = self.len? as usize;
        let mut out = Vec::with_capacity(len);
        for c in &self.chunks {
            out.extend_from_slice(c.as_ref()?);
        }
        Some(out)
    }

    pub fn received(&self) -> usize {
        self.chunks.iter().filter(|c| c.is_some()).count()
    }

    pub fn total(&self) -> Option<usize> {
        self.len.map(chunk_count)
    }
}

/// A peer waits this long between pings.
pub const PING_INTERVAL: Duration = Duration::from_secs(30);
/// A peer silent for this long is dropped (unless it is a seed).
pub const PEER_TIMEOUT: Duration = Duration::from_secs(180);
/// Peers kept in the table.
pub const MAX_PEERS: usize = 64;
/// Below this many live peers the node looks for more.
pub const TARGET_PEERS: usize = 8;

#[derive(Clone, Debug)]
pub struct Peer {
    pub addr: SocketAddr,
    /// When a well-formed message last arrived; `None` until the first.
    pub last_seen: Option<Instant>,
    pub last_ping: Option<Instant>,
    /// Nonce of the ping awaiting its pong.
    pub pending: Option<u64>,
    pub status: Option<Status>,
    /// Malformed or useless replies; dropped past a threshold.
    pub strikes: u32,
    pub seed: bool,
}

/// The peer table.
#[derive(Default)]
pub struct Peers {
    map: HashMap<SocketAddr, Peer>,
}

impl Peers {
    pub fn new() -> Peers {
        Peers::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<&Peer> {
        self.map.get(addr)
    }

    /// Adds an address to try, if there is room. Returns whether it is new.
    pub fn add(&mut self, addr: SocketAddr, seed: bool) -> bool {
        if addr.ip().is_unspecified() || addr.port() == 0 {
            return false;
        }
        if let Some(p) = self.map.get_mut(&addr) {
            p.seed |= seed;
            return false;
        }
        if self.map.len() >= MAX_PEERS {
            // Replace a never-seen non-seed entry, if any.
            let Some(victim) = self.map.values().find(|p| p.last_seen.is_none() && !p.seed).map(|p| p.addr) else {
                return false;
            };
            self.map.remove(&victim);
        }
        self.map.insert(
            addr,
            Peer { addr, last_seen: None, last_ping: None, pending: None, status: None, strikes: 0, seed },
        );
        true
    }

    /// Notes a well-formed message from `addr`, adding the peer if unknown.
    pub fn seen(&mut self, addr: SocketAddr, now: Instant) {
        self.add(addr, false);
        if let Some(p) = self.map.get_mut(&addr) {
            p.last_seen = Some(now);
            p.strikes = 0;
        }
    }

    pub fn set_status(&mut self, addr: SocketAddr, status: Status) {
        if let Some(p) = self.map.get_mut(&addr) {
            p.status = Some(status);
        }
    }

    /// Records a pong; `false` if no ping with that nonce is outstanding.
    pub fn pong(&mut self, addr: SocketAddr, status: Status) -> bool {
        let Some(p) = self.map.get_mut(&addr) else {
            return false;
        };
        if p.pending != Some(status.nonce) {
            return false;
        }
        p.pending = None;
        p.status = Some(status);
        true
    }

    pub fn strike(&mut self, addr: SocketAddr) {
        if let Some(p) = self.map.get_mut(&addr) {
            p.strikes += 1;
        }
    }

    pub fn remove(&mut self, addr: &SocketAddr) {
        self.map.remove(addr);
    }

    /// Peers heard from within the timeout.
    pub fn live(&self, now: Instant) -> impl Iterator<Item = &Peer> {
        self.map.values().filter(move |p| p.last_seen.is_some_and(|t| now.duration_since(t) < PEER_TIMEOUT))
    }

    pub fn live_count(&self, now: Instant) -> usize {
        self.live(now).count()
    }

    /// Peers due for a ping: never pinged, or pinged longer ago than the
    /// interval. Marks them pinged with `nonce`.
    pub fn due_for_ping(&mut self, now: Instant, mut nonce: impl FnMut() -> u64) -> Vec<(SocketAddr, u64)> {
        let mut out = Vec::new();
        for p in self.map.values_mut() {
            if p.last_ping.is_none_or(|t| now.duration_since(t) >= PING_INTERVAL) {
                let n = nonce();
                p.last_ping = Some(now);
                p.pending = Some(n);
                out.push((p.addr, n));
            }
        }
        out
    }

    /// Drops peers that have been silent for the timeout since their last
    /// ping (or never answered), and peers with too many strikes. Seeds
    /// stay.
    pub fn prune(&mut self, now: Instant) {
        self.map.retain(|_, p| {
            if p.seed {
                return true;
            }
            if p.strikes >= 5 {
                return false;
            }
            match (p.last_seen, p.last_ping) {
                (Some(seen), _) => now.duration_since(seen) < PEER_TIMEOUT,
                (None, Some(pinged)) => now.duration_since(pinged) < PEER_TIMEOUT,
                (None, None) => true,
            }
        });
    }

    /// Up to `n` live peers other than `exclude`, in table order.
    pub fn sample(&self, n: usize, exclude: Option<SocketAddr>, now: Instant) -> Vec<SocketAddr> {
        self.live(now).map(|p| p.addr).filter(|a| Some(*a) != exclude).take(n).collect()
    }

    /// The live peer claiming the most work, if it exceeds `work`.
    pub fn best_above(&self, work: U256, now: Instant) -> Option<&Peer> {
        self.live(now).filter(|p| p.status.is_some_and(|s| s.work > work)).max_by_key(|p| p.status.unwrap().work)
    }

    /// Loads addresses saved by [`Peers::save`], one per line.
    pub fn load(&mut self, path: &Path) -> std::io::Result<usize> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let mut n = 0;
        for line in text.lines() {
            if let Ok(addr) = line.trim().parse::<SocketAddr>()
                && self.add(addr, false)
            {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Saves the addresses of peers that have ever answered.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut text = String::new();
        for p in self.map.values().filter(|p| p.last_seen.is_some()) {
            text.push_str(&p.addr.to_string());
            text.push('\n');
        }
        std::fs::write(path, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::Fp;
    use crate::state_tree::EMPTY;

    fn digest(tag: u32) -> Digest {
        let mut d = EMPTY;
        d[0] = Fp::new(tag);
        d
    }

    fn header(tag: u32) -> Header {
        Header {
            prev_hash: digest(tag),
            height: tag,
            timestamp: 1_700_000_000 + tag as u64,
            body_commitment: digest(tag + 1),
            state_root: digest(tag + 2),
            mix: digest(tag + 3),
            nonce: [tag as u8; 32],
        }
    }

    fn status() -> Status {
        Status {
            nonce: 77,
            version: PROTOCOL_VERSION,
            genesis: digest(1),
            height: 42,
            tip: digest(2),
            work: U256([1, 2, 3, 4]),
        }
    }

    #[test]
    fn messages_roundtrip_within_the_datagram_limit() {
        let v4: SocketAddr = "10.1.2.3:7417".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:7417".parse().unwrap();
        let msgs = vec![
            Message::Ping(status()),
            Message::Pong(status()),
            Message::GetPeers,
            Message::Peers(vec![v4, v6]),
            Message::Peers(vec![v6; MAX_PEERS_MESSAGE]),
            Message::GetHeaders { locator: (0..MAX_LOCATOR as u32).map(digest).collect() },
            Message::Headers((0..HEADERS_PER_MESSAGE as u32).map(header).collect()),
            Message::Inv(header(5)),
            Message::GetChunks { id: digest(9), indexes: (0..WINDOW as u16).collect() },
            Message::Chunk { id: digest(9), len: 200_000, index: 3, data: vec![7u8; CHUNK_BYTES] },
        ];
        for m in msgs {
            let bytes = m.encode();
            assert!(bytes.len() <= MAX_DATAGRAM, "{m:?}: {} bytes", bytes.len());
            assert_eq!(Message::decode(&bytes), Some(m.clone()), "{m:?}");
            // Trailing or missing bytes are rejected.
            let mut longer = bytes.clone();
            longer.push(0);
            assert_eq!(Message::decode(&longer), None);
            assert_eq!(Message::decode(&bytes[..bytes.len() - 1]), None);
        }
        assert_eq!(Message::decode(b"TAB1\xff"), None);
        assert_eq!(Message::decode(b"XXXX\x03"), None);
    }

    #[test]
    fn downloads_assemble_from_chunks_in_any_order() {
        let now = Instant::now();
        let bytes: Vec<u8> = (0..2500u32).map(|i| (i % 251) as u8).collect();
        let id = digest(3);
        let from: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut d = Download::new(id, from, 1 << 20, now);
        assert_eq!(d.missing(4), vec![0, 1, 2, 3]);
        let chunk = |i: u16| match chunk_of(&id, &bytes, i) {
            Some(Message::Chunk { len, index, data, .. }) => (len, index, data),
            _ => panic!(),
        };
        assert!(chunk_of(&id, &bytes, 3).is_none());
        assert_eq!(d.request(now), (0..WINDOW as u16).collect::<Vec<_>>());
        assert_eq!(d.in_flight(), WINDOW);
        assert!(d.request(now).is_empty());
        let (len, i, data) = chunk(2);
        assert_eq!(d.insert(len, i, data.clone(), now), Ok(false));
        assert_eq!(d.missing(10), vec![0, 1]);
        assert_eq!(d.insert(len, i, data, now), Ok(false));
        // Wrong length, index or size.
        assert_eq!(d.insert(len + 1, 0, vec![0; CHUNK_BYTES], now), Err(ChunkError::Malformed));
        assert_eq!(d.insert(len, 3, vec![0; 10], now), Err(ChunkError::Malformed));
        assert_eq!(d.insert(len, 0, vec![0; 10], now), Err(ChunkError::Malformed));
        assert_eq!(d.in_flight(), WINDOW - 1);
        d.reset_window();
        assert_eq!(d.request(now), vec![0, 1]);
        let (_, i, data) = chunk(0);
        assert_eq!(d.insert(len, i, data, now), Ok(false));
        let (_, i, data) = chunk(1);
        assert_eq!(d.insert(len, i, data, now), Ok(true));
        assert_eq!(d.in_flight(), 0);
        assert_eq!(d.assemble(), Some(bytes));
        // Too large for the chain's limit.
        let mut small = Download::new(id, from, 100, now);
        assert_eq!(small.insert(2500, 0, vec![0; CHUNK_BYTES], now), Err(ChunkError::Malformed));
    }

    #[test]
    fn peer_table_pings_prunes_and_persists() {
        let t0 = Instant::now();
        let mut peers = Peers::new();
        let a: SocketAddr = "10.0.0.1:7417".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:7417".parse().unwrap();
        let s: SocketAddr = "10.0.0.3:7417".parse().unwrap();
        assert!(peers.add(a, false));
        assert!(!peers.add(a, false));
        assert!(!peers.add("0.0.0.0:7417".parse().unwrap(), false));
        peers.add(b, false);
        peers.add(s, true);
        let mut n = 0u64;
        let pings = peers.due_for_ping(t0, || {
            n += 1;
            n
        });
        assert_eq!(pings.len(), 3);
        assert!(peers.due_for_ping(t0 + Duration::from_secs(1), || 0).is_empty());
        // a answers with the right nonce, b with a wrong one.
        let nonce_a = pings.iter().find(|(p, _)| *p == a).unwrap().1;
        peers.seen(a, t0 + Duration::from_secs(1));
        assert!(peers.pong(a, Status { nonce: nonce_a, ..status() }));
        assert!(!peers.pong(b, Status { nonce: 999, ..status() }));
        assert_eq!(peers.live_count(t0 + Duration::from_secs(2)), 1);
        assert_eq!(peers.sample(5, Some(a), t0 + Duration::from_secs(2)), Vec::<SocketAddr>::new());
        assert_eq!(peers.best_above(U256::ZERO, t0 + Duration::from_secs(2)).map(|p| p.addr), Some(a));
        assert!(peers.best_above(U256([1, 2, 3, 4]), t0 + Duration::from_secs(2)).is_none());
        // After the timeout b (never answered) goes, the seed stays, a goes too.
        peers.prune(t0 + PEER_TIMEOUT + Duration::from_secs(5));
        assert!(peers.get(&b).is_none());
        assert!(peers.get(&s).is_some());
        assert!(peers.get(&a).is_none());
        // Persistence keeps only peers that answered.
        let mut peers = Peers::new();
        peers.add(a, false);
        peers.add(b, false);
        peers.seen(a, t0);
        let dir = std::env::temp_dir().join(format!("tabminer-peers-{}", std::process::id()));
        peers.save(&dir).unwrap();
        let mut loaded = Peers::new();
        assert_eq!(loaded.load(&dir).unwrap(), 1);
        assert!(loaded.get(&a).is_some());
        let _ = std::fs::remove_file(&dir);
        assert_eq!(Peers::new().load(Path::new("/nonexistent/peers")).unwrap(), 0);
    }
}
