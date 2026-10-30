//! The network node: keeps peers, follows the heaviest chain it hears of,
//! relays new blocks and serves its own to others, over [`crate::net`].
//!
//! One thread reads the UDP socket into a channel; [`Node::run`] consumes
//! that channel, applying blocks to the shared [`Chain`] and ticking timers
//! between messages. A miner feeds its blocks in as [`Event::Mined`] and
//! watches [`Node::tip_changes`] to restart on a new tip.
//!
//! # Sync
//!
//! Every peer is pinged periodically and answers with its tip and work.
//! When a live peer claims more work than our main chain and nothing is in
//! flight, we send it our block locator; its `Headers` replies list the
//! main-chain headers after our fork point, which we queue and fetch in
//! order, a few blocks at a time. A block whose parent we do not have waits
//! in a small orphan pool while the parent is fetched. A block that extends
//! or reorganizes our main chain is announced to every live peer as an
//! `Inv`; peers that lack it fetch it, so a new block floods the network
//! in a few hops. Transactions travel the same way: a transaction that
//! enters the [`Mempool`] is announced as a `TxInv` and fetched by id.
//!
//! Headers, chunks and peer lists are only served to peers that answered
//! one of our pings, so a forged source address gets nothing back but a
//! pong of the same size as the ping.
//!
//! # Fast sync
//!
//! A node starting from genesis with a sync point (by default 144 blocks)
//! first downloads every header from the peer claiming the most work,
//! checking proof of work, difficulty and timestamps, without bodies.
//! It then takes the block `sync_point` below the best header and fetches
//! it with a manifest of the state after it: the output counter and the
//! root of each part's subtree (4096 positions), which must compose to the
//! block's state root. The block's proof, a chain proof, is checked
//! against the counter: it shows that block and every one before it valid,
//! so nothing about the past is trusted. The parts come from every peer
//! that can serve them, in parallel, each checked against its root; the
//! snapshot is installed and ordinary sync fetches the blocks after it.
//!
//! # Seeds
//!
//! On start the node resolves [`SEEDS`] and the configured peers, loads the
//! peers it saved last time, and keeps asking peers for more until it has
//! [`crate::net::TARGET_PEERS`] live ones.

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::block::{Block, Header};
use crate::chain::{Applied, Chain, ChainError, ProofVerifier, SNAPSHOT_PART_LOG};
use crate::difficulty::U256;
use crate::mempool::{MAX_TX_SIZE, Mempool, Reject};
use crate::net::{
    self, Download, Kind, MAX_HEADERS, Message, PROTOCOL_VERSION, Peers, Status, TARGET_PEERS, WINDOW, chunk_of,
};
use crate::pow::Digest;
use crate::transaction::Transaction;

/// UDP port nodes listen on by default.
pub const DEFAULT_PORT: u16 = 7417;
/// Seed nodes, `host:port`, resolved at start and whenever peers run low.
/// Fill in before a public launch; `--peer` adds more at run time.
pub const SEEDS: &[&str] = &[];
/// Blocks fetched at once.
pub const MAX_DOWNLOADS: usize = 4;
/// Blocks held while their parents are fetched.
pub const MAX_ORPHANS: usize = 32;
/// Recently served block serializations kept in memory.
const SERVED_CACHE: usize = 4;
/// Minimum spacing of header requests to the same end.
const SYNC_INTERVAL: Duration = Duration::from_secs(2);
const SEED_INTERVAL: Duration = Duration::from_secs(60);
const SAVE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    /// Peers to contact at start, besides the seeds and the saved ones.
    pub peers: Vec<SocketAddr>,
    pub seeds: Vec<String>,
    /// Where the peer table is saved between runs.
    pub peers_file: Option<PathBuf>,
    /// Log every message handled, not only blocks and peers.
    pub verbose: bool,
    /// Fast sync from this many blocks below the best header, when starting
    /// from genesis; `None` validates every block from genesis instead.
    pub sync_point: Option<u32>,
}

/// Default depth of the fast-sync snapshot: a day of blocks.
pub const DEFAULT_SYNC_POINT: u32 = 144;
/// Snapshot parts fetched at once.
const MAX_PART_DOWNLOADS: usize = 16;
/// Snapshot objects kept for serving.
const SERVED_SNAPSHOTS: usize = 8;
/// Failed snapshot attempts before validating from genesis instead.
const MAX_SNAPSHOT_ATTEMPTS: u32 = 4;

/// How the node is catching up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Following the chain block by block.
    Normal,
    /// Fast sync: downloading headers.
    Headers,
    /// Fast sync: downloading a snapshot of the state.
    Snapshot,
}

/// A snapshot being assembled.
struct Snap {
    target: Header,
    block: Option<Block>,
    manifest: Option<(u64, Vec<Digest>)>,
    /// The block's proof checked against the manifest's counter.
    verified: bool,
    #[allow(clippy::type_complexity)]
    parts: Vec<Option<Vec<(u64, Digest, Digest)>>>,
    /// Rotates the peers asked.
    next_peer: usize,
}

/// What the node's loop consumes.
pub enum Event {
    Packet(SocketAddr, Vec<u8>),
    /// A block produced locally: apply it and announce it.
    Mined(Block),
    /// A transaction made locally: pool it and announce it.
    Transaction(Transaction),
    Stop,
}

/// A snapshot of the node for the prompt, refreshed every second.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub peers: Vec<PeerInfo>,
    pub downloads: usize,
    pub mode: Option<Mode>,
    /// Snapshot parts received and expected, during a fast sync.
    pub parts: Option<(usize, usize)>,
    pub wanted: usize,
    pub orphans: usize,
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub height: Option<u32>,
    pub live: bool,
    pub handshaken: bool,
}

pub struct Node<V: ProofVerifier> {
    chain: Arc<Chain<V>>,
    mempool: Arc<Mutex<Mempool>>,
    stats: Arc<Mutex<Stats>>,
    socket: UdpSocket,
    config: Config,
    genesis: Digest,
    peers: Peers,
    downloads: HashMap<Digest, Download>,
    /// Headers whose blocks we need, oldest first, with who told us.
    wanted: VecDeque<(Header, SocketAddr)>,
    orphans: HashMap<Digest, (Block, Option<SocketAddr>)>,
    served: VecDeque<(Digest, Vec<u8>)>,
    served_snapshots: VecDeque<((Kind, Digest), Vec<u8>)>,
    mode: Mode,
    snap: Option<Snap>,
    snap_downloads: HashMap<Kind, Download>,
    snap_attempts: u32,
    last_header_request: Option<Instant>,
    syncing: Arc<AtomicBool>,
    rx: Receiver<Event>,
    tip_changes: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    nonce: u64,
    last_sync: Option<Instant>,
    last_seed_lookup: Option<Instant>,
    last_save: Instant,
    started: Instant,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn short(d: &Digest) -> String {
    crate::poseidon2::digest_to_bytes(d).iter().take(8).map(|b| format!("{b:02x}")).collect()
}

impl<V: ProofVerifier + Send + Sync + 'static> Node<V> {
    /// Binds the socket, loads and resolves peers, and starts the reader
    /// thread. The chain must have its genesis. Returns the node and the
    /// sender its loop listens on.
    pub fn bind(
        chain: Arc<Chain<V>>,
        mempool: Arc<Mutex<Mempool>>,
        config: Config,
    ) -> std::io::Result<(Node<V>, Sender<Event>)> {
        let socket = UdpSocket::bind(config.listen)?;
        let genesis = chain
            .header_at(0)
            .map_err(std::io::Error::other)?
            .ok_or_else(|| std::io::Error::other("chain has no genesis"))?
            .hash();
        let mut peers = Peers::new();
        if let Some(path) = &config.peers_file {
            let n = peers.load(path)?;
            if n > 0 {
                crate::log::line(&format!("net: {n} saved peers"));
            }
        }
        for &p in &config.peers {
            peers.add(p, true);
        }
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = channel::<Event>();
        // The reader thread: datagrams into the channel until stopped.
        let reader = socket.try_clone()?;
        reader.set_read_timeout(Some(Duration::from_millis(200)))?;
        let flag = Arc::clone(&running);
        let sender = tx.clone();
        std::thread::Builder::new().name("net-reader".into()).spawn(move || {
            let mut buf = [0u8; 2048];
            while flag.load(Ordering::Relaxed) {
                match reader.recv_from(&mut buf) {
                    Ok((n, addr)) => {
                        if sender.send(Event::Packet(addr, buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                    Err(e) => {
                        eprintln!("net: socket error: {e}");
                        break;
                    }
                }
            }
        })?;
        let now = Instant::now();
        let mut node = Node {
            chain,
            mempool,
            stats: Arc::new(Mutex::new(Stats::default())),
            socket,
            config,
            genesis,
            peers,
            downloads: HashMap::new(),
            wanted: VecDeque::new(),
            orphans: HashMap::new(),
            served: VecDeque::new(),
            served_snapshots: VecDeque::new(),
            mode: Mode::Normal,
            snap: None,
            snap_downloads: HashMap::new(),
            snap_attempts: 0,
            last_header_request: None,
            syncing: Arc::new(AtomicBool::new(true)),
            rx,
            tip_changes: Arc::new(AtomicU64::new(0)),
            running,
            nonce: now.elapsed().as_nanos() as u64 ^ unix_now().rotate_left(17),
            last_sync: None,
            last_seed_lookup: None,
            last_save: now,
            started: now,
        };
        if node.config.sync_point.is_some() && node.chain.tip().ok().flatten().is_some_and(|t| t.height == 0) {
            node.mode = Mode::Headers;
            node.log("fast sync: downloading headers");
        }
        node.resolve_seeds(now);
        Ok((node, tx))
    }

    /// Counter bumped whenever the main chain's tip changes.
    pub fn tip_changes(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.tip_changes)
    }

    /// Whether the node is catching up: fast-syncing, or a live peer
    /// claims more work than its tip. A miner waits while it is.
    pub fn syncing(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.syncing)
    }

    /// Shared snapshot of peers and transfers, refreshed every second.
    pub fn stats(&self) -> Arc<Mutex<Stats>> {
        Arc::clone(&self.stats)
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Runs the node until an [`Event::Stop`] arrives or every sender is
    /// gone. Saves the peer table on the way out.
    pub fn run(mut self) {
        let mut last_tick = Instant::now();
        self.tick(last_tick);
        loop {
            match self.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Event::Packet(addr, bytes)) => self.handle_packet(addr, &bytes),
                Ok(Event::Mined(block)) => self.handle_block(block, None),
                Ok(Event::Transaction(tx)) => self.handle_transaction(tx, None),
                Ok(Event::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {}
            }
            let now = Instant::now();
            self.retry_downloads(now);
            self.retry_snapshot_downloads(now);
            if now.duration_since(last_tick) >= Duration::from_secs(1) {
                last_tick = now;
                self.tick(now);
            }
        }
        self.running.store(false, Ordering::Relaxed);
        self.save_peers();
    }

    fn log(&self, msg: &str) {
        crate::log::line(&format!("net: {msg}"));
    }

    fn chatter(&self, msg: &str) {
        if self.config.verbose {
            crate::log::line(&format!("net: {msg}"));
        }
    }

    fn send(&self, addr: SocketAddr, msg: &Message) {
        if let Err(e) = self.socket.send_to(&msg.encode(), addr) {
            self.chatter(&format!("send to {addr} failed: {e}"));
        }
    }

    fn status(&self, nonce: u64) -> Status {
        let tip = self.chain.tip().ok().flatten();
        Status {
            nonce,
            version: PROTOCOL_VERSION,
            genesis: self.genesis,
            height: tip.map_or(0, |h| h.height),
            tip: tip.map_or(self.genesis, |h| h.hash()),
            work: self.chain.tip_work().unwrap_or(U256::ZERO),
        }
    }

    fn resolve_seeds(&mut self, now: Instant) {
        self.last_seed_lookup = Some(now);
        let seeds: Vec<String> = SEEDS.iter().map(|s| s.to_string()).chain(self.config.seeds.iter().cloned()).collect();
        for seed in seeds {
            match seed.to_socket_addrs() {
                Ok(addrs) => {
                    for a in addrs {
                        if self.peers.add(a, true) {
                            self.chatter(&format!("seed {seed}: {a}"));
                        }
                    }
                }
                Err(e) => self.log(&format!("seed {seed}: {e}")),
            }
        }
    }

    fn save_peers(&self) {
        if let Some(path) = &self.config.peers_file
            && let Err(e) = self.peers.save(path)
        {
            self.log(&format!("saving peers: {e}"));
        }
    }

    /// Once a second: pings, pruning, discovery, sync, persistence.
    fn tick(&mut self, now: Instant) {
        self.peers.prune(now);
        let mut nonce = {
            let mut n = self.nonce;
            move || {
                n = n.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                n
            }
        };
        let due = self.peers.due_for_ping(now, &mut nonce);
        self.nonce = nonce();
        for (addr, n) in due {
            let st = self.status(n);
            self.send(addr, &Message::Ping(st));
        }
        if self.peers.live_count(now) < TARGET_PEERS {
            if self.last_seed_lookup.is_none_or(|t| now.duration_since(t) >= SEED_INTERVAL) && self.started != now {
                self.resolve_seeds(now);
            }
            if let Some(p) = self.peers.sample(1, None, now).first() {
                self.send(*p, &Message::GetPeers);
            }
        }
        match self.mode {
            Mode::Normal => self.sync(now),
            Mode::Headers => self.header_sync(now),
            Mode::Snapshot => self.snapshot_sync(now),
        }
        let behind = self.peers.best_above(self.chain.tip_work().unwrap_or(U256::ZERO), now).is_some();
        let fresh = self.peers.live_count(now) == 0 && now.duration_since(self.started) < Duration::from_secs(5);
        self.syncing.store(self.mode != Mode::Normal || behind || fresh, Ordering::Release);
        if now.duration_since(self.last_save) >= SAVE_INTERVAL {
            self.last_save = now;
            self.save_peers();
        }
        let live: std::collections::HashSet<SocketAddr> = self.peers.live(now).map(|p| p.addr).collect();
        let peers = self
            .peers
            .all()
            .map(|p| PeerInfo {
                addr: p.addr,
                height: p.status.map(|s| s.height),
                live: live.contains(&p.addr),
                handshaken: p.handshaken,
            })
            .collect();
        let parts = self
            .snap
            .as_ref()
            .filter(|s| !s.parts.is_empty())
            .map(|s| (s.parts.iter().filter(|p| p.is_some()).count(), s.parts.len()));
        *self.stats.lock().unwrap() = Stats {
            peers,
            downloads: self.downloads.len() + self.snap_downloads.len(),
            wanted: self.wanted.len(),
            orphans: self.orphans.len(),
            mode: Some(self.mode),
            parts,
        };
    }

    /// Asks the peer with the most work for headers when nothing is in
    /// flight, and starts downloads for queued headers.
    fn sync(&mut self, now: Instant) {
        if self.downloads.is_empty() && self.wanted.is_empty() {
            let ours = self.chain.tip_work().unwrap_or(U256::ZERO);
            if let Some(best) = self.peers.best_above(ours, now).map(|p| p.addr)
                && self.last_sync.is_none_or(|t| now.duration_since(t) >= SYNC_INTERVAL)
            {
                self.last_sync = Some(now);
                self.request_headers(best);
            }
        }
        self.start_downloads(now);
    }

    fn request_headers(&mut self, to: SocketAddr) {
        match self.chain.locator() {
            Ok(locator) => {
                self.chatter(&format!("asking {to} for headers"));
                self.send(to, &Message::GetHeaders { locator });
            }
            Err(e) => self.log(&format!("locator: {e}")),
        }
    }

    fn start_downloads(&mut self, now: Instant) {
        while self.downloads.len() < MAX_DOWNLOADS {
            let Some((header, from)) = self.wanted.pop_front() else {
                break;
            };
            let id = header.hash();
            if self.downloads.contains_key(&id) || self.orphans.contains_key(&id) {
                continue;
            }
            if self.have_block(&id) {
                continue;
            }
            self.start_download(Kind::Block, id, from, now);
        }
    }

    fn start_download(&mut self, kind: Kind, id: Digest, from: SocketAddr, now: Instant) {
        if self.downloads.contains_key(&id) {
            return;
        }
        let max_len = match kind {
            Kind::Block => self.chain.params().max_block_size,
            Kind::Tx => MAX_TX_SIZE,
            Kind::Manifest => net::MAX_MANIFEST,
            Kind::Part(_) => net::MAX_PART,
        };
        let mut d = Download::new(kind, id, from, max_len, now);
        let indexes = d.request(now);
        self.send(from, &Message::GetChunks { kind, id, indexes });
        self.chatter(&format!("fetching {kind:?} {} from {from}", short(&id)));
        self.downloads.insert(id, d);
    }

    fn retry_downloads(&mut self, now: Instant) {
        let mut abandoned = Vec::new();
        let mut requests = Vec::new();
        for d in self.downloads.values_mut() {
            if now.duration_since(d.last_progress) < net::RETRY || now.duration_since(d.last_request) < net::RETRY {
                continue;
            }
            d.retries += 1;
            d.last_request = now;
            if d.retries > net::MAX_RETRIES {
                abandoned.push((d.id, d.from));
            } else {
                d.reset_window();
                let indexes = d.request(now);
                requests.push((d.from, Message::GetChunks { kind: d.kind, id: d.id, indexes }));
            }
        }
        for (to, msg) in requests {
            self.send(to, &msg);
        }
        for (id, from) in abandoned {
            self.downloads.remove(&id);
            self.peers.strike(from);
            self.log(&format!("gave up fetching {} from {from}", short(&id)));
        }
    }

    fn handle_packet(&mut self, addr: SocketAddr, bytes: &[u8]) {
        let Some(msg) = Message::decode(bytes) else {
            self.peers.strike(addr);
            return;
        };
        let now = Instant::now();
        match msg {
            Message::Ping(st) => {
                if st.genesis != self.genesis {
                    self.chatter(&format!("{addr} is on another chain"));
                    self.peers.remove(&addr);
                    return;
                }
                let new = self.peers.get(&addr).is_none_or(|p| p.last_seen.is_none());
                self.peers.seen(addr, now);
                self.peers.set_status(addr, st);
                if new {
                    self.log(&format!("peer {addr} (height {})", st.height));
                }
                let reply = self.status(st.nonce);
                self.send(addr, &Message::Pong(reply));
                // Complete the handshake from our side at once.
                if !self.peers.handshaken(&addr) {
                    self.nonce = self.nonce.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let nonce = self.nonce;
                    if self.peers.ping_now(addr, nonce, now) {
                        let ping = self.status(nonce);
                        self.send(addr, &Message::Ping(ping));
                    }
                }
                self.consider(addr, &st, now);
            }
            Message::Pong(st) => {
                if st.genesis != self.genesis {
                    self.peers.remove(&addr);
                    return;
                }
                if !self.peers.pong(addr, st) {
                    self.peers.strike(addr);
                    return;
                }
                let new = self.peers.get(&addr).is_none_or(|p| p.last_seen.is_none());
                self.peers.seen(addr, now);
                if new {
                    self.log(&format!("peer {addr} (height {})", st.height));
                }
                self.consider(addr, &st, now);
            }
            Message::GetPeers => {
                if !self.peers.handshaken(&addr) {
                    return;
                }
                self.peers.seen(addr, now);
                let sample = self.peers.sample(net::MAX_PEERS_MESSAGE, Some(addr), now);
                self.send(addr, &Message::Peers(sample));
            }
            Message::Peers(addrs) => {
                self.peers.seen(addr, now);
                for a in addrs {
                    if self.peers.add(a, false) {
                        self.chatter(&format!("{addr} told us about {a}"));
                    }
                }
            }
            Message::GetHeaders { locator } => {
                if !self.peers.handshaken(&addr) {
                    return;
                }
                self.peers.seen(addr, now);
                match self.chain.headers_after(&locator, MAX_HEADERS) {
                    Ok(headers) => {
                        for batch in headers.chunks(net::HEADERS_PER_MESSAGE) {
                            self.send(addr, &Message::Headers(batch.to_vec()));
                        }
                    }
                    Err(e) => self.log(&format!("headers: {e}")),
                }
            }
            Message::Headers(headers) => {
                self.peers.seen(addr, now);
                self.handle_headers(addr, headers, now);
            }
            Message::Inv(header) => {
                self.peers.seen(addr, now);
                self.handle_inv(addr, header, now);
            }
            Message::TxInv(txid) => {
                self.peers.seen(addr, now);
                if !self.mempool.lock().unwrap().contains(&txid) && !self.downloads.contains_key(&txid) {
                    self.start_download(Kind::Tx, txid, addr, now);
                }
            }
            Message::GetChunks { kind, id, indexes } => {
                if !self.peers.handshaken(&addr) {
                    return;
                }
                self.peers.seen(addr, now);
                self.serve_chunks(addr, kind, id, &indexes);
            }
            Message::Chunk { kind, id, len, index, data } => {
                self.peers.seen(addr, now);
                self.handle_chunk(addr, kind, id, len, index, data, now);
            }
        }
    }

    /// A peer's status: if it claims more work than we have and we are not
    /// already fetching, ask it for headers.
    fn consider(&mut self, addr: SocketAddr, st: &Status, now: Instant) {
        if self.mode != Mode::Normal {
            return;
        }
        let ours = self.chain.tip_work().unwrap_or(U256::ZERO);
        if st.work > ours
            && self.downloads.is_empty()
            && self.wanted.is_empty()
            && self.last_sync.is_none_or(|t| now.duration_since(t) >= SYNC_INTERVAL)
        {
            self.last_sync = Some(now);
            self.request_headers(addr);
        }
    }

    fn handle_headers(&mut self, from: SocketAddr, headers: Vec<Header>, now: Instant) {
        match self.mode {
            Mode::Normal => {}
            Mode::Headers => return self.accept_headers(from, headers, now),
            Mode::Snapshot => return,
        }
        for h in headers {
            let id = h.hash();
            if self.have_block(&id)
                || self.downloads.contains_key(&id)
                || self.orphans.contains_key(&id)
                || self.wanted.iter().any(|(w, _)| w.hash() == id)
            {
                continue;
            }
            let parent_known = self.chain.entry(&h.prev_hash).ok().flatten().is_some_and(|e| !e.invalid)
                || self.downloads.contains_key(&h.prev_hash)
                || self.wanted.iter().any(|(w, _)| w.hash() == h.prev_hash);
            if !parent_known {
                self.chatter(&format!("{from} sent header {} with unknown parent", short(&id)));
                self.peers.strike(from);
                break;
            }
            self.wanted.push_back((h, from));
        }
        self.start_downloads(now);
    }

    fn handle_inv(&mut self, from: SocketAddr, header: Header, now: Instant) {
        if self.mode != Mode::Normal {
            return;
        }
        let id = header.hash();
        if self.have_block(&id) || self.downloads.contains_key(&id) {
            return;
        }
        match self.chain.entry(&header.prev_hash).ok().flatten() {
            Some(e) if e.invalid => {}
            Some(_) => self.start_download(Kind::Block, id, from, now),
            None => {
                // Behind by more than one block: sync from this peer.
                if self.downloads.is_empty() && self.wanted.is_empty() {
                    self.last_sync = Some(now);
                    self.request_headers(from);
                }
            }
        }
    }

    fn serve_chunks(&mut self, to: SocketAddr, kind: Kind, id: Digest, indexes: &[u16]) {
        let bytes = match kind {
            Kind::Tx => match self.mempool.lock().unwrap().get(&id) {
                Some(tx) => tx.to_bytes(),
                None => return,
            },
            Kind::Block => match self.served.iter().position(|(i, _)| *i == id) {
                Some(pos) => {
                    let entry = self.served.remove(pos).unwrap();
                    self.served.push_front(entry);
                    self.served.front().unwrap().1.clone()
                }
                None => match self.chain.block_by_hash(&id) {
                    Ok(Some(block)) => {
                        let bytes = block.to_bytes();
                        self.served.push_front((id, bytes.clone()));
                        self.served.truncate(SERVED_CACHE);
                        bytes
                    }
                    _ => return,
                },
            },
            Kind::Manifest | Kind::Part(_) => match self.snapshot_bytes(kind, &id) {
                Some(b) => b,
                None => return,
            },
        };
        for &i in indexes.iter().take(WINDOW) {
            if let Some(msg) = chunk_of(kind, &id, &bytes, i) {
                self.send(to, &msg);
            }
        }
    }

    fn handle_chunk(
        &mut self,
        from: SocketAddr,
        kind: Kind,
        id: Digest,
        len: u32,
        index: u16,
        data: Vec<u8>,
        now: Instant,
    ) {
        if matches!(kind, Kind::Manifest | Kind::Part(_))
            || (kind == Kind::Block && self.snap.as_ref().is_some_and(|s| s.target.hash() == id))
        {
            return self.handle_snapshot_chunk(from, kind, id, len, index, data, now);
        }
        let Some(d) = self.downloads.get_mut(&id) else {
            return;
        };
        if d.from != from || d.kind != kind {
            return;
        }
        match d.insert(len, index, data, now) {
            Ok(false) => {
                // Refill the window once half of it has arrived.
                if d.in_flight() <= WINDOW / 2 {
                    let indexes = d.request(now);
                    if !indexes.is_empty() {
                        self.send(from, &Message::GetChunks { kind, id, indexes });
                    }
                }
            }
            Ok(true) => {
                let bytes = d.assemble().unwrap_or_default();
                self.downloads.remove(&id);
                match kind {
                    Kind::Block => match Block::from_bytes(&bytes) {
                        Ok(block) if block.header.hash() == id => self.handle_block(block, Some(from)),
                        _ => {
                            self.log(&format!("{from} sent a malformed block for {}", short(&id)));
                            self.peers.strike(from);
                        }
                    },
                    Kind::Tx => match Transaction::from_bytes(&bytes) {
                        Some(tx) if tx.txid() == id => self.handle_transaction(tx, Some(from)),
                        _ => {
                            self.log(&format!("{from} sent a malformed transaction for {}", short(&id)));
                            self.peers.strike(from);
                        }
                    },
                    Kind::Manifest | Kind::Part(_) => {}
                }
                self.start_downloads(now);
            }
            Err(_) => {
                self.downloads.remove(&id);
                self.peers.strike(from);
                self.log(&format!("{from} sent bad chunks for {}", short(&id)));
            }
        }
    }

    /// Applies a block, announces a new tip, and connects waiting orphans.
    fn handle_block(&mut self, block: Block, from: Option<SocketAddr>) {
        let mut queue = VecDeque::from([(block, from)]);
        while let Some((block, from)) = queue.pop_front() {
            let id = block.header.hash();
            let height = block.header.height;
            match self.chain.apply_block(&block, unix_now()) {
                Ok(Applied::Known) => {}
                Ok(Applied::Side) => {
                    let whose = from.map_or("our".to_string(), |a| format!("{a}'s"));
                    self.log(&format!("{whose} block {} at height {height} is a side block, not the tip", short(&id)));
                }
                Ok(applied) => {
                    let whose = from.map_or("our block".to_string(), |a| format!("block from {a}"));
                    match applied {
                        Applied::Reorganized { fork_height, unwound } => self.log(&format!(
                            "reorganized onto {whose} {} at height {height}: {unwound} blocks above {fork_height} replaced",
                            short(&id)
                        )),
                        _ => self.log(&format!("{whose} {} is the tip at height {height}", short(&id))),
                    }
                    self.tip_changes.fetch_add(1, Ordering::Release);
                    let told = self.announce(&block.header, from);
                    if from.is_none() {
                        self.log(&format!("announced block {height} to {told} peers"));
                    }
                    self.revalidate_mempool();
                }
                Err(ChainError::UnknownParent(parent)) => {
                    if self.orphans.len() < MAX_ORPHANS {
                        self.orphans.insert(id, (block, from));
                    }
                    if let Some(from) = from {
                        self.chatter(&format!("orphan {} at height {height}; fetching its parent", short(&id)));
                        if !self.have_block(&parent) {
                            self.start_download(Kind::Block, parent, from, Instant::now());
                        }
                        if self.downloads.len() <= 1 && self.wanted.is_empty() {
                            self.request_headers(from);
                        }
                    }
                    continue;
                }
                Err(e) => {
                    self.log(&format!("rejected block {} at height {height}: {e}", short(&id)));
                    if let Some(from) = from {
                        self.peers.strike(from);
                    }
                    continue;
                }
            }
            // Children waiting for this block.
            let children: Vec<Digest> =
                self.orphans.iter().filter(|(_, (b, _))| b.header.prev_hash == id).map(|(k, _)| *k).collect();
            for c in children {
                if let Some(entry) = self.orphans.remove(&c) {
                    queue.push_back(entry);
                }
            }
        }
    }

    /// Pools a transaction and announces it if new.
    fn handle_transaction(&mut self, tx: Transaction, from: Option<SocketAddr>) {
        let result = {
            let rtxn = match self.chain.env().read_txn() {
                Ok(t) => t,
                Err(e) => {
                    self.log(&format!("mempool: {e}"));
                    return;
                }
            };
            self.mempool.lock().unwrap().insert(tx, self.chain.utxo(), &rtxn)
        };
        match result {
            Ok(txid) => {
                let whose = from.map_or("our transaction".to_string(), |a| format!("transaction from {a}"));
                self.log(&format!("{whose} {} pooled", short(&txid)));
                let now = Instant::now();
                for addr in self.peers.sample(net::MAX_PEERS, from, now) {
                    self.send(addr, &Message::TxInv(txid));
                }
            }
            Err(Reject::Known) => {}
            Err(e) => {
                self.log(&format!("rejected transaction{}: {e}", from.map_or(String::new(), |a| format!(" from {a}"))));
                // Conflicts, spent or not-yet-seen inputs and a full pool
                // happen to honest peers in races; the rest cannot.
                let honest = matches!(e, Reject::ReplacementFee { .. } | Reject::UnknownInput(_) | Reject::Full);
                if let Some(from) = from
                    && !honest
                {
                    self.peers.strike(from);
                }
            }
        }
    }

    /// After the tip moved: drop pooled transactions the chain has spent,
    /// restore shelved ones a reorganization freed.
    fn revalidate_mempool(&mut self) {
        let Ok(rtxn) = self.chain.env().read_txn() else {
            return;
        };
        match self.mempool.lock().unwrap().revalidate(self.chain.utxo(), &rtxn) {
            Ok((gone, back)) if gone + back > 0 => {
                self.chatter(&format!("mempool: {gone} transactions confirmed or conflicted, {back} restored"));
            }
            Ok(_) => {}
            Err(e) => self.log(&format!("mempool: {e}")),
        }
    }

    /// Sends `Inv` to every live peer but `except`; returns how many.
    fn announce(&self, header: &Header, except: Option<SocketAddr>) -> usize {
        let now = Instant::now();
        let peers = self.peers.sample(net::MAX_PEERS, except, now);
        for addr in &peers {
            self.send(*addr, &Message::Inv(*header));
        }
        peers.len()
    }
}

impl<V: ProofVerifier + Send + Sync + 'static> Node<V> {
    /// Whether the block is stored with its body (a header stored alone
    /// during a fast sync still needs fetching).
    fn have_block(&self, id: &Digest) -> bool {
        self.chain.entry(id).ok().flatten().is_some_and(|e| !e.header_only)
    }

    /// Fast sync, headers: ask the peer claiming the most work for headers
    /// after our best; once no peer claims more, pick the snapshot.
    fn header_sync(&mut self, now: Instant) {
        let ours = self.chain.best_header_work().unwrap_or(U256::ZERO);
        let recent = self.last_header_request.is_some_and(|t| now.duration_since(t) < SYNC_INTERVAL);
        if let Some(best) = self.peers.best_above(ours, now).map(|p| p.addr) {
            if !recent {
                self.request_best_headers(best, now);
            }
            return;
        }
        // Nobody claims more: done, once at least one peer has said so. With
        // no peer at all for a while, this may be the first node: start
        // from genesis.
        if !self.peers.live(now).any(|p| p.status.is_some()) {
            if now.duration_since(self.started) >= Duration::from_secs(10) {
                self.log("fast sync: no peers answered; starting from genesis");
                self.mode = Mode::Normal;
            }
            return;
        }
        if recent {
            return;
        }
        let best = match self.chain.best_header() {
            Ok(b) => b,
            Err(e) => return self.log(&format!("fast sync: {e}")),
        };
        let depth = self.config.sync_point.unwrap_or(0);
        if best.height <= depth.max(1) {
            self.log(&format!("fast sync: best header at height {}; validating every block instead", best.height));
            self.mode = Mode::Normal;
            return;
        }
        let target = match self.chain.ancestor(&best, best.height - depth) {
            Ok(Some(t)) => t,
            _ => return self.log("fast sync: snapshot block's header is missing"),
        };
        self.log(&format!(
            "fast sync: {} headers checked; fetching the state after block {} ({})",
            best.height,
            target.height,
            short(&target.hash())
        ));
        self.snap =
            Some(Snap { target, block: None, manifest: None, verified: false, parts: Vec::new(), next_peer: 0 });
        self.mode = Mode::Snapshot;
        self.snapshot_sync(now);
    }

    fn request_best_headers(&mut self, to: SocketAddr, now: Instant) {
        match self.chain.header_locator() {
            Ok(locator) => {
                self.last_header_request = Some(now);
                self.send(to, &Message::GetHeaders { locator });
            }
            Err(e) => self.log(&format!("header locator: {e}")),
        }
    }

    /// Fast sync: checks and stores headers; asks for more while they come.
    fn accept_headers(&mut self, from: SocketAddr, headers: Vec<Header>, now: Instant) {
        let mut new = 0;
        for h in headers {
            match self.chain.accept_header(&h, unix_now()) {
                Ok(true) => new += 1,
                Ok(false) => {}
                Err(e) => {
                    self.log(&format!("fast sync: header {} from {from} refused: {e}", short(&h.hash())));
                    self.peers.strike(from);
                    break;
                }
            }
        }
        if new > 0 {
            if let Ok(best) = self.chain.best_header() {
                self.chatter(&format!("fast sync: headers to height {}", best.height));
            }
            // More may follow this reply; ask again once it has arrived.
            if self.last_header_request.is_none_or(|t| now.duration_since(t) >= Duration::from_millis(300)) {
                self.request_best_headers(from, now);
            }
        }
    }

    /// Peers that may serve the snapshot: live, at or past its block.
    fn snapshot_peers(&self, now: Instant) -> Vec<SocketAddr> {
        let height = self.snap.as_ref().map_or(0, |s| s.target.height);
        self.peers.live(now).filter(|p| p.status.is_some_and(|s| s.height >= height)).map(|p| p.addr).collect()
    }

    fn start_snapshot_download(&mut self, kind: Kind, now: Instant) {
        let peers = self.snapshot_peers(now);
        let Some(snap) = self.snap.as_mut() else {
            return;
        };
        if peers.is_empty() || self.snap_downloads.contains_key(&kind) {
            return;
        }
        let from = peers[snap.next_peer % peers.len()];
        snap.next_peer += 1;
        let id = snap.target.hash();
        let max_len = match kind {
            Kind::Block => self.chain.params().max_block_size,
            Kind::Manifest => net::MAX_MANIFEST,
            Kind::Part(_) => net::MAX_PART,
            Kind::Tx => MAX_TX_SIZE,
        };
        let mut d = Download::new(kind, id, from, max_len, now);
        let indexes = d.request(now);
        self.send(from, &Message::GetChunks { kind, id, indexes });
        self.snap_downloads.insert(kind, d);
    }

    /// Fast sync, snapshot: fetch what is missing, verify, install.
    fn snapshot_sync(&mut self, now: Instant) {
        let Some(snap) = self.snap.as_ref() else {
            self.mode = Mode::Normal;
            return;
        };
        let (has_block, has_manifest) = (snap.block.is_some(), snap.manifest.is_some());
        if !has_block {
            self.start_snapshot_download(Kind::Block, now);
        }
        if !has_manifest {
            self.start_snapshot_download(Kind::Manifest, now);
        }
        if has_block && has_manifest && !self.snap.as_ref().unwrap().verified {
            let snap = self.snap.as_ref().unwrap();
            let next = snap.manifest.as_ref().unwrap().0;
            match self.chain.verify_snapshot_block(snap.block.as_ref().unwrap(), next) {
                Ok(()) => {
                    self.log(&format!(
                        "fast sync: block {}'s proof verifies the chain up to it; {} outputs to fetch in {} parts",
                        snap.target.height,
                        next,
                        snap.parts.len()
                    ));
                    self.snap.as_mut().unwrap().verified = true;
                }
                Err(e) => return self.restart_snapshot(&format!("the snapshot block does not verify: {e}")),
            }
        }
        let missing: Vec<u32> = match self.snap.as_ref() {
            Some(s) if s.verified => {
                s.parts.iter().enumerate().filter(|(_, p)| p.is_none()).map(|(i, _)| i as u32).collect()
            }
            _ => return,
        };
        if missing.is_empty() {
            return self.install_snapshot();
        }
        for i in missing {
            if self.snap_downloads.len() >= MAX_PART_DOWNLOADS {
                break;
            }
            self.start_snapshot_download(Kind::Part(i), now);
        }
    }

    fn install_snapshot(&mut self) {
        let Some(snap) = self.snap.take() else {
            return;
        };
        let (next, _) = snap.manifest.as_ref().unwrap();
        let outputs: Vec<(u64, Digest, Digest)> = snap.parts.iter().flatten().flatten().copied().collect();
        match self.chain.install_snapshot(snap.block.as_ref().unwrap(), &outputs, *next) {
            Ok(()) => {
                self.log(&format!(
                    "fast sync: installed the state after block {} ({} unspent outputs); following the chain from there",
                    snap.target.height,
                    outputs.len()
                ));
                self.mode = Mode::Normal;
                self.tip_changes.fetch_add(1, Ordering::Release);
                self.revalidate_mempool();
            }
            Err(e) => {
                self.snap = Some(snap);
                self.restart_snapshot(&format!("installing the snapshot failed: {e}"));
            }
        }
    }

    /// Drops what was fetched and starts the snapshot again from other
    /// peers, or gives up on fast sync after a few attempts.
    fn restart_snapshot(&mut self, why: &str) {
        self.snap_attempts += 1;
        self.snap_downloads.clear();
        if self.snap_attempts >= MAX_SNAPSHOT_ATTEMPTS {
            self.log(&format!("fast sync: {why}; giving up, validating every block instead"));
            self.snap = None;
            self.mode = Mode::Normal;
            return;
        }
        self.log(&format!("fast sync: {why}; trying again"));
        if let Some(s) = self.snap.as_mut() {
            s.block = None;
            s.manifest = None;
            s.verified = false;
            s.parts.clear();
        }
    }

    fn retry_snapshot_downloads(&mut self, now: Instant) {
        let mut abandoned = Vec::new();
        let mut requests = Vec::new();
        for (kind, d) in self.snap_downloads.iter_mut() {
            if now.duration_since(d.last_progress) < net::RETRY || now.duration_since(d.last_request) < net::RETRY {
                continue;
            }
            d.retries += 1;
            d.last_request = now;
            if d.retries > net::MAX_RETRIES {
                abandoned.push((*kind, d.from));
            } else {
                d.reset_window();
                let indexes = d.request(now);
                requests.push((d.from, Message::GetChunks { kind: *kind, id: d.id, indexes }));
            }
        }
        for (to, msg) in requests {
            self.send(to, &msg);
        }
        for (kind, from) in abandoned {
            self.snap_downloads.remove(&kind);
            self.chatter(&format!("fast sync: {from} did not serve {kind:?}; asking another peer"));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_snapshot_chunk(
        &mut self,
        from: SocketAddr,
        kind: Kind,
        id: Digest,
        len: u32,
        index: u16,
        data: Vec<u8>,
        now: Instant,
    ) {
        let Some(d) = self.snap_downloads.get_mut(&kind) else {
            return;
        };
        if d.from != from || d.id != id {
            return;
        }
        match d.insert(len, index, data, now) {
            Ok(false) => {
                if d.in_flight() <= WINDOW / 2 {
                    let indexes = d.request(now);
                    if !indexes.is_empty() {
                        self.send(from, &Message::GetChunks { kind, id, indexes });
                    }
                }
            }
            Ok(true) => {
                let bytes = d.assemble().unwrap_or_default();
                self.snap_downloads.remove(&kind);
                if !self.accept_snapshot_object(kind, &bytes) {
                    self.log(&format!("fast sync: {from} sent a bad {kind:?}"));
                    self.peers.strike(from);
                }
                self.snapshot_sync(now);
            }
            Err(_) => {
                self.snap_downloads.remove(&kind);
                self.peers.strike(from);
            }
        }
    }

    /// Checks a fetched snapshot object and keeps it; `false` if it is bad.
    fn accept_snapshot_object(&mut self, kind: Kind, bytes: &[u8]) -> bool {
        let Some(snap) = self.snap.as_mut() else {
            return true;
        };
        match kind {
            Kind::Block => match Block::from_bytes(bytes) {
                Ok(block) if block.header == snap.target => {
                    snap.block = Some(block);
                    true
                }
                _ => false,
            },
            Kind::Manifest => {
                let Some((next, roots)) = net::decode_manifest(bytes) else {
                    return false;
                };
                let parts = next.div_ceil(1 << SNAPSHOT_PART_LOG);
                if roots.len() as u64 != parts
                    || crate::state_tree::root_from_subtrees(SNAPSHOT_PART_LOG, &roots) != snap.target.state_root
                {
                    return false;
                }
                snap.parts = vec![None; roots.len()];
                snap.manifest = Some((next, roots));
                true
            }
            Kind::Part(i) => {
                let Some((next, roots)) = snap.manifest.as_ref() else {
                    return true;
                };
                let Some(outputs) = net::decode_part(bytes) else {
                    return false;
                };
                let first = (i as u64) << SNAPSHOT_PART_LOG;
                let end = (first + (1 << SNAPSHOT_PART_LOG)).min(*next);
                let ordered = outputs.windows(2).all(|w| w[0].0 < w[1].0);
                let in_range = outputs.iter().all(|o| o.0 >= first && o.0 < end);
                let leaves: Vec<(u64, Digest)> =
                    outputs.iter().map(|(p, c, m)| (*p, crate::transaction::leaf(c, m))).collect();
                let Some(root) = roots.get(i as usize) else {
                    return false;
                };
                if !ordered || !in_range || crate::state_tree::subtree_root(SNAPSHOT_PART_LOG, first, &leaves) != *root
                {
                    return false;
                }
                snap.parts[i as usize] = Some(outputs);
                true
            }
            Kind::Tx => true,
        }
    }

    /// A manifest or part this node serves, for the state after block `id`.
    fn snapshot_bytes(&mut self, kind: Kind, id: &Digest) -> Option<Vec<u8>> {
        if let Some(pos) = self.served_snapshots.iter().position(|(k, _)| *k == (kind, *id)) {
            let entry = self.served_snapshots.remove(pos).unwrap();
            let bytes = entry.1.clone();
            self.served_snapshots.push_front(entry);
            return Some(bytes);
        }
        let bytes = match kind {
            Kind::Manifest => {
                let (next, roots) = self.chain.snapshot_manifest(id).ok().flatten()?;
                net::encode_manifest(next, &roots)
            }
            Kind::Part(i) => net::encode_part(&self.chain.snapshot_part(id, i as u64).ok().flatten()?),
            _ => return None,
        };
        self.served_snapshots.push_front(((kind, *id), bytes.clone()));
        self.served_snapshots.truncate(SERVED_SNAPSHOTS);
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregate::AggregatorParams;
    use crate::block::{Body, HEADER_SIZE};
    use crate::chain::{AcceptAllProofs, ChainParams};
    use crate::pow::{self, Dataset, PowParams, SeedText, nonce_from_u64};
    use crate::state_tree::EMPTY;
    use crate::transaction::{Key, Output};
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("tabminer-node-{}-{name}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const POW: PowParams = PowParams { log_dataset_items: 8, parents: 32, accesses: 64 };
    const T0: u64 = 1_700_000_000;

    fn params() -> ChainParams {
        ChainParams {
            pow: POW,
            genesis_timestamp: T0,
            genesis_target: U256([0, 0, 0, 1 << 48]),
            max_target: ChainParams::MAINNET.max_target,
            max_block_size: HEADER_SIZE + 12 + 4 * crate::block::COMMITMENT_SIZE + 3000,
            max_future_drift: 7200,
            median_time_window: 11,
            emission: &[(1000, 50)],
            aggregator: AggregatorParams::MAINNET,
        }
    }

    fn seed() -> SeedText {
        let text: Vec<u8> = (0..20_000u32).map(|i| (i * 31 % 253) as u8).collect();
        SeedText::from_bytes(POW, text)
    }

    struct Fixture {
        dir: TempDir,
        chain: Arc<Chain<AcceptAllProofs>>,
        dataset: Dataset,
    }

    fn open(name: &str) -> Fixture {
        let dir = TempDir::new(name);
        let seed = seed();
        let dataset = Dataset::generate(&seed);
        let chain = Chain::open(&dir.0.join("chain"), 64 << 20, params(), seed, AcceptAllProofs).unwrap();
        chain.init_or_check_genesis().unwrap();
        Fixture { dir, chain: Arc::new(chain), dataset }
    }

    fn pool() -> Arc<Mutex<Mempool>> {
        Arc::new(Mutex::new(Mempool::new(1 << 20)))
    }

    fn pk(tag: u8) -> crate::xmss::PublicKey {
        let mut s = [0u8; 32];
        s[0] = tag;
        Key::generate(&s).public_key()
    }

    /// Mines a block with one output and a padding "proof" on the tip.
    fn mine(f: &Fixture, tag: u8, timestamp: u64) -> Block {
        let body =
            Body { inputs: vec![], outputs: vec![Output::new(&pk(tag), 1).block_output()], proof: vec![tag; 2500] };
        mine_body(f, body, timestamp)
    }

    fn mine_body(f: &Fixture, body: Body, timestamp: u64) -> Block {
        let mut header = f.chain.template(&body, timestamp).unwrap();
        let tip = f.chain.tip().unwrap().unwrap();
        let target = f.chain.expected_target(&tip).unwrap();
        let (nonce, out) =
            pow::mine(&f.dataset, &header.pow_hash(), &target, (0..1_000_000).map(nonce_from_u64)).unwrap();
        header.nonce = nonce;
        header.mix = out.mix;
        Block { header, body }
    }

    fn config(peers: Vec<SocketAddr>, dir: &TempDir) -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            peers,
            seeds: vec![],
            peers_file: Some(dir.0.join("peers")),
            verbose: true,
            sync_point: None,
        }
    }

    fn wait_for_tip(chain: &Chain<AcceptAllProofs>, want: &Header, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if chain.tip().unwrap().as_ref() == Some(want) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    #[test]
    fn nodes_sync_relay_and_reorganize() {
        // a has three blocks; b starts from genesis and must catch up.
        let a = open("sync-a");
        let b = open("sync-b");
        let now = unix_now();
        let mut t = T0;
        let mut a_blocks = Vec::new();
        for tag in 1..=3u8 {
            t += 600;
            let block = mine(&a, tag, t);
            a.chain.apply_block(&block, now).unwrap();
            a_blocks.push(block);
        }
        let (pool_a, pool_b) = (pool(), pool());
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), Arc::clone(&pool_a), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let (node_b, tx_b) =
            Node::bind(Arc::clone(&b.chain), Arc::clone(&pool_b), config(vec![addr_a], &b.dir)).unwrap();
        let changes_b = node_b.tip_changes();
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());

        let a_tip = a.chain.tip().unwrap().unwrap();
        assert!(wait_for_tip(&b.chain, &a_tip, 20), "b did not sync to a's tip");
        assert_eq!(b.chain.state_root().unwrap(), a.chain.state_root().unwrap());
        assert!(changes_b.load(Ordering::Acquire) >= 1);

        // A block mined on a is relayed to b.
        t += 600;
        let b4 = mine(&a, 4, t);
        tx_a.send(Event::Mined(b4.clone())).unwrap();
        assert!(wait_for_tip(&b.chain, &b4.header, 20), "b did not receive the relayed block");
        assert_eq!(a.chain.tip().unwrap().unwrap(), b4.header);

        // A transaction spending block 1's output, submitted on a, reaches
        // b's pool; a block spending that output clears both pools.
        let spent = Output::new(&pk(1), 1);
        let mut k = Key::generate(&{
            let mut s = [0u8; 32];
            s[0] = 1;
            s
        });
        let tx = crate::transaction::UnsignedTransaction::new(vec![(k.public_key(), 1)], vec![Output::new(&pk(50), 1)])
            .sign_with(&mut k)
            .unwrap();
        let txid = tx.txid();
        tx_a.send(Event::Transaction(tx)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !pool_b.lock().unwrap().contains(&txid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(pool_b.lock().unwrap().contains(&txid), "transaction was not relayed");
        assert!(pool_a.lock().unwrap().contains(&txid));
        let position = {
            let rtxn = a.chain.env().read_txn().unwrap();
            a.chain.utxo().positions(&rtxn, &spent.commitment).unwrap()[0]
        };
        t += 600;
        let b5 = mine_body(
            &a,
            Body {
                inputs: vec![position],
                outputs: vec![Output::new(&pk(50), 1).block_output()],
                proof: vec![5; 2500],
            },
            t,
        );
        tx_a.send(Event::Mined(b5.clone())).unwrap();
        assert!(wait_for_tip(&b.chain, &b5.header, 20), "b did not receive block 5");
        std::thread::sleep(Duration::from_millis(200));
        assert!(!pool_a.lock().unwrap().contains(&txid));
        assert!(!pool_b.lock().unwrap().contains(&txid));
        let b4 = b5;

        // c mines a longer competing branch from genesis offline, then joins
        // through b only: both a and b reorganize to it.
        let c = open("sync-c");
        let mut tc = T0;
        for tag in 10..=15u8 {
            tc += 300;
            let block = mine(&c, tag, tc);
            c.chain.apply_block(&block, now).unwrap();
        }
        let c_tip = c.chain.tip().unwrap().unwrap();
        assert!(c.chain.tip_work().unwrap() > a.chain.tip_work().unwrap());
        let (node_c, tx_c) = Node::bind(Arc::clone(&c.chain), pool(), config(vec![addr_a], &c.dir)).unwrap();
        let hc = std::thread::spawn(move || node_c.run());
        assert!(wait_for_tip(&a.chain, &c_tip, 30), "a did not reorganize to c's chain");
        assert!(wait_for_tip(&b.chain, &c_tip, 30), "b did not reorganize to c's chain");
        assert_eq!(a.chain.state_root().unwrap(), c.chain.state_root().unwrap());
        assert_eq!(b.chain.state_root().unwrap(), c.chain.state_root().unwrap());
        // The old branch is still stored on a, validated and off-chain.
        let e = a.chain.entry(&b4.header.hash()).unwrap().unwrap();
        assert!(e.validated && !e.invalid);
        assert_eq!(
            a.chain.header_at(4).unwrap().map(|h| h.hash()),
            Some(c.chain.header_at(4).unwrap().unwrap().hash())
        );

        for tx in [tx_a, tx_b, tx_c] {
            tx.send(Event::Stop).unwrap();
        }
        ha.join().unwrap();
        hb.join().unwrap();
        hc.join().unwrap();
        // Peers were saved.
        let saved = std::fs::read_to_string(b.dir.0.join("peers")).unwrap();
        assert!(saved.contains(&addr_a.to_string()), "{saved}");
    }

    #[test]
    fn a_fresh_node_fast_syncs() {
        // a has twelve blocks, spending some outputs after block 8; b starts
        // empty with a sync point of 4: headers, the state after block 8,
        // then blocks 9 to 12.
        let a = open("fast-a");
        let now = unix_now();
        let mut t = T0;
        for tag in 1..=12u8 {
            t += 600;
            let body = if tag >= 3 {
                let pos = (tag as u64 - 3) * 1;
                Body {
                    inputs: vec![pos],
                    outputs: vec![Output::new(&pk(tag), 1).block_output()],
                    proof: vec![tag; 2500],
                }
            } else {
                Body { inputs: vec![], outputs: vec![Output::new(&pk(tag), 1).block_output()], proof: vec![tag; 2500] }
            };
            let block = mine_body(&a, body, t);
            a.chain.apply_block(&block, now).unwrap();
        }
        let a_tip = a.chain.tip().unwrap().unwrap();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let b = open("fast-b");
        let mut cb = config(vec![addr_a], &b.dir);
        cb.sync_point = Some(4);
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        let syncing = node_b.syncing();
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        assert!(wait_for_tip(&b.chain, &a_tip, 30), "b did not fast-sync to a's tip");
        assert_eq!(b.chain.state_root().unwrap(), a.chain.state_root().unwrap());
        assert_eq!(b.chain.floor().unwrap(), Some(8));
        // b has no bodies below its snapshot, but every header.
        assert!(b.chain.block_by_hash(&b.chain.header_at(3).unwrap().unwrap().hash()).unwrap().is_none());
        assert_eq!(b.chain.header_at(3).unwrap(), a.chain.header_at(3).unwrap());
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!syncing.load(Ordering::Acquire));
        tx_a.send(Event::Stop).unwrap();
        tx_b.send(Event::Stop).unwrap();
        ha.join().unwrap();
        hb.join().unwrap();
    }

    #[test]
    fn nodes_on_another_chain_are_ignored() {
        let a = open("other-a");
        let dir_b = TempDir::new("other-b");
        let chain_b = Chain::open(&dir_b.0.join("chain"), 64 << 20, params(), seed(), AcceptAllProofs).unwrap();
        let genesis = {
            let body = Body { inputs: vec![], outputs: vec![Output::new(&pk(1), 1).block_output()], proof: vec![] };
            let mut header = params().genesis().header;
            header.body_commitment = body.commitment();
            header.state_root = chain_b.preview_state_root(&body).unwrap();
            Block { header, body }
        };
        chain_b.init_genesis(&genesis).unwrap();
        let chain_b = Arc::new(chain_b);
        let block = mine(&a, 1, T0 + 600);
        a.chain.apply_block(&block, unix_now()).unwrap();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let (node_b, tx_b) = Node::bind(Arc::clone(&chain_b), pool(), config(vec![addr_a], &dir_b)).unwrap();
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        std::thread::sleep(Duration::from_secs(3));
        assert_eq!(chain_b.tip().unwrap().unwrap().height, 0);
        assert_eq!(chain_b.tip().unwrap().unwrap().prev_hash, EMPTY);
        tx_a.send(Event::Stop).unwrap();
        tx_b.send(Event::Stop).unwrap();
        ha.join().unwrap();
        hb.join().unwrap();
    }
}
