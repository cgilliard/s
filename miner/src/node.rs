//! The network node: keeps peers, follows the heaviest chain it hears of,
//! relays new blocks and serves its own to others, over [`crate::net`].
//!
//! One thread reads the UDP socket into a bounded channel; [`Node::run`]
//! consumes that channel, ticking timers between messages, and hands blocks
//! to an applier thread, which applies them to the shared [`Chain`] in
//! order while the network goes on, and reports each back. A miner feeds its blocks in as [`Event::Mined`] and
//! watches [`Node::tip_changes`] to restart on a new tip.
//!
//! # Sync
//!
//! Every peer is pinged periodically and answers with its tip, its work
//! and the lowest height from which it holds every block. Only peers that
//! answered our own ping are believed. While any claims more work than our
//! best header, headers are fetched in batches by height
//! (`GetHeadersFrom`, [`MAX_HEADERS`] each), up to `HEADER_BATCHES` at
//! once, each from a different such peer; complete batches are checked
//! (proof of work, in parallel, difficulty, timestamps) and stored in
//! order, so a slow peer delays only its share, and a batch late by
//! `BATCH_TIMEOUT` goes to another peer. A batch that does not follow
//! our best header means a fork: a locator (`GetHeaders`) finds where. A
//! peer that sends no header we lack within [`net::HEADER_TIMEOUT`] is not
//! believed for a while, so a false claim cannot stall the sync.
//! Transaction announcements are ignored until the node has caught up.
//!
//! The blocks of the best header's branch are then fetched in parallel:
//! up to [`MAX_DOWNLOADS`] at once, at most [`MAX_PER_PEER`] from one
//! peer, each from the peer that announced it or else from a peer whose
//! status shows it holds it, and no further than [`LOOKAHEAD`] past the
//! first one missing. Blocks that arrive before their parent wait in
//! memory and are applied in order. A download that stalls or crawls is
//! given up and its peer passed over. A block that extends or reorganizes
//! our main chain is announced to every live peer as an `Inv`; peers check
//! its header and fetch it, so a new block floods the network in a few
//! hops. Transactions travel the same way: a transaction that enters the
//! [`Mempool`] is announced as a `TxInv` and fetched by id.
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
//! It then takes the newest block at least `sync_point` below the best
//! header whose height is a multiple of the snapshot interval (nodes take a
//! snapshot after each such block and serve only those), and fetches it
//! with a manifest of the state after it: the output counter and the
//! root of each part's subtree (16,384 positions), which must compose to the
//! block's state root. The block's proof, a chain proof, is checked
//! against the counter: it shows that block and every one before it valid,
//! so nothing about the past is trusted. The parts come from every peer
//! that can serve them, `MAX_PART_DOWNLOADS` at once, and are checked
//! against their roots and stored on the applier thread; the snapshot is
//! installed and ordinary sync fetches the blocks after it.
//!
//! Every transfer keeps [`net::WINDOW`] chunks in flight at first and
//! doubles that each time a whole window arrives without a retry, up to
//! [`net::MAX_IN_FLIGHT`], halving when chunks go missing.
//!
//! # Seeds
//!
//! On start the node resolves its configured seeds (the binary passes
//! [`SEEDS`] unless told not to) and peers, loads the
//! peers it saved last time, and keeps asking peers for more until it has
//! [`crate::net::TARGET_PEERS`] live ones.

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
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
pub const DEFAULT_PORT: u16 = 3737;
/// Seed nodes, `host:port`, resolved at start and whenever peers run low.
/// Fill in before a public launch; `--peer` adds more at run time.
pub const SEEDS: &[&str] = &["tabernacle1.root.sx:3737", "tabernacle2.root.sx:3737"];
/// Blocks fetched at once, from as many peers as hold them.
pub const MAX_DOWNLOADS: usize = 24;
/// Blocks fetched at once from one peer.
pub const MAX_PER_PEER: usize = 8;
/// How far past the first missing block downloads may run. Blocks fetched
/// ahead of their parent wait in memory, so this bounds it: 64 MB at the
/// 2 MB block size limit.
pub const LOOKAHEAD: usize = 32;
/// Transactions fetched at once, and from one peer.
const MAX_TX_DOWNLOADS: usize = 32;
const MAX_TX_PER_PEER: usize = 4;
/// Header batches asked ahead of the best header, each of a different
/// peer: [`MAX_HEADERS`] headers apiece, so about a thousand in flight.
const HEADER_BATCHES: usize = 16;
/// A header batch not complete by then is asked of another peer, and the
/// slow one passed over.
const BATCH_TIMEOUT: Duration = Duration::from_secs(4);
/// Blocks remembered with the peer that announced them.
const MAX_SOURCES: usize = 4096;
/// A fetched block whose parent has not arrived by then is dropped.
const PENDING_TIMEOUT: Duration = Duration::from_secs(600);
/// Recently served block serializations kept in memory.
const SERVED_CACHE: usize = 4;
/// Datagrams and local events queued for the node's loop: about 10 MB.
const EVENT_QUEUE: usize = 8192;
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
const MAX_PART_DOWNLOADS: usize = 32;
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
    /// Which parts are stored. Each verified part goes straight to the
    /// database, so memory holds one part at a time, not the whole state.
    parts: Vec<bool>,
    /// Rotates the peers asked.
    next_peer: usize,
    /// Who sent the manifest: to blame if the block's proof rejects it.
    manifest_from: Option<SocketAddr>,
    /// Manifests the block's proof rejected so far.
    bad_manifests: u32,
    /// Peers that did not serve something of this snapshot: perhaps they
    /// do not keep it. Asked again only if no other can be.
    unserved: std::collections::HashSet<SocketAddr>,
    /// Parts fetched and with the applier, being checked and stored.
    staging: std::collections::HashSet<u32>,
}

/// What the node's loop consumes.
pub enum Event {
    Packet(SocketAddr, Vec<u8>),
    /// A block produced locally: apply it and announce it.
    Mined(Block),
    /// A transaction made locally: pool it and announce it.
    Transaction(Transaction),
    /// The applier thread has a result: nothing else to do but take it.
    Wake,
    Stop,
}

/// Headers asked of one peer by height (`GetHeadersFrom`), keyed in the
/// node by their first height.
struct HeaderBatch {
    start: u32,
    peer: SocketAddr,
    asked: Instant,
    /// The last height expected: the peer's height when asked, at most
    /// [`MAX_HEADERS`] on.
    end: u32,
    headers: std::collections::BTreeMap<u32, Header>,
}

/// A block handed to the applier thread, with who sent it.
enum Job {
    Block(Block, Option<SocketAddr>),
    /// A fast-sync part, checked against its manifest root and stored.
    Part {
        index: u32,
        bytes: Vec<u8>,
        next: u64,
        root: Digest,
        from: SocketAddr,
    },
}
/// What applying it gave.
enum Outcome {
    Block(Box<Block>, Option<SocketAddr>, Result<Applied, ChainError>),
    Part { index: u32, from: SocketAddr, result: Result<(), ChainError> },
}

/// A snapshot of the node for the prompt, refreshed every second.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub peers: Vec<PeerInfo>,
    pub downloads: usize,
    pub mode: Option<Mode>,
    /// Snapshot parts received and expected, during a fast sync.
    pub parts: Option<(usize, usize)>,
    /// Blocks between the tip and the best header.
    pub wanted: usize,
    /// Fetched blocks waiting for their parent.
    pub waiting: usize,
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
    /// Blocks being fetched.
    downloads: HashMap<Digest, Download>,
    /// Transactions being fetched.
    tx_downloads: HashMap<Digest, Download>,
    /// Fetched blocks waiting for their parent's body, with who sent them
    /// and when.
    pending: HashMap<Digest, (Block, Option<SocketAddr>, Instant)>,
    /// Who announced a block we may fetch: asked first, since its status
    /// may not show the block yet.
    sources: HashMap<Digest, SocketAddr>,
    /// Header batches in flight or complete, by first height, verified in
    /// order as the one at the best header comes in.
    header_batches: std::collections::BTreeMap<u32, HeaderBatch>,
    /// Header batches each peer let time out in a row: the first may be a
    /// request that arrived before it had checked our address.
    slow_batches: HashMap<SocketAddr, u32>,
    /// Blocks handed to the applier thread and not yet reported back.
    applying: std::collections::HashSet<Digest>,
    jobs: Option<std::sync::mpsc::Sender<Job>>,
    outcomes: Receiver<Outcome>,
    applier: Option<std::thread::JoinHandle<()>>,
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
    /// Ping nonces are this key's SipHash of a counter: a peer seeing its
    /// own cannot predict the next, so cannot answer a ping sent to an
    /// address it does not hold.
    nonce_key: std::collections::hash_map::RandomState,
    nonce_count: u64,
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

/// Asks for 4 MB socket buffers, so bursts of chunks are not dropped while
/// the reader thread catches up. The kernel caps them (`net.core.rmem_max`
/// and `wmem_max`) for an unprivileged process.
fn enlarge_buffers(socket: &UdpSocket) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        unsafe extern "C" {
            fn setsockopt(fd: i32, level: i32, name: i32, value: *const std::ffi::c_void, len: u32) -> i32;
        }
        const SOL_SOCKET: i32 = 1;
        const SO_SNDBUF: i32 = 7;
        const SO_RCVBUF: i32 = 8;
        let size: i32 = 4 << 20;
        for name in [SO_RCVBUF, SO_SNDBUF] {
            // SAFETY: a valid socket and a pointer to an int of the size given.
            unsafe {
                setsockopt(socket.as_raw_fd(), SOL_SOCKET, name, (&size as *const i32).cast(), 4);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = socket;
}

/// Re-requests the window of downloads that stalled; returns the requests
/// to send and the downloads to give up: no progress after
/// [`net::MAX_RETRIES`] retries, or, for a block, crawling.
fn stalled(downloads: &mut HashMap<Digest, Download>, now: Instant) -> (Vec<(SocketAddr, Message)>, Vec<Digest>) {
    let mut requests = Vec::new();
    let mut abandoned = Vec::new();
    for d in downloads.values_mut() {
        if d.kind == Kind::Block && d.too_slow(now) {
            abandoned.push(d.id);
            continue;
        }
        if now.duration_since(d.last_progress) < net::RETRY || now.duration_since(d.last_request) < net::RETRY {
            continue;
        }
        d.retries += 1;
        d.last_request = now;
        if d.retries > net::MAX_RETRIES {
            abandoned.push(d.id);
        } else {
            d.reset_window();
            let indexes = d.request(now);
            requests.extend(net::chunk_requests(d.kind, d.id, &indexes).map(|m| (d.from, m)));
        }
    }
    (requests, abandoned)
}

impl<V: ProofVerifier + Send + Sync + 'static> Node<V> {
    /// Binds the socket, loads and resolves peers, and starts the reader
    /// thread. The chain must have its genesis. Returns the node and the
    /// sender its loop listens on.
    pub fn bind(
        chain: Arc<Chain<V>>,
        mempool: Arc<Mutex<Mempool>>,
        config: Config,
    ) -> std::io::Result<(Node<V>, SyncSender<Event>)> {
        let socket = UdpSocket::bind(config.listen)?;
        enlarge_buffers(&socket);
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
        let (tx, rx) = sync_channel::<Event>(EVENT_QUEUE);
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
                        // A full queue (the loop busy applying a block, or
                        // a flood) drops the datagram: requests are retried.
                        if let Err(TrySendError::Disconnected(_)) =
                            sender.try_send(Event::Packet(addr, buf[..n].to_vec()))
                        {
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
        // The applier: blocks are applied, and fast-sync parts checked and
        // stored, in the order handed over, on a thread of their own, so
        // the network goes on meanwhile.
        let (jobs, job_rx) = std::sync::mpsc::channel::<Job>();
        let (outcome_tx, outcomes) = std::sync::mpsc::channel::<Outcome>();
        let applier = {
            let chain = Arc::clone(&chain);
            let wake = tx.clone();
            std::thread::Builder::new().name("applier".into()).spawn(move || {
                for job in job_rx {
                    let outcome = match job {
                        Job::Block(block, from) => {
                            let result = chain.apply_block(&block, unix_now());
                            crate::parallel::release_free_memory();
                            Outcome::Block(Box::new(block), from, result)
                        }
                        Job::Part { index, bytes, next, root, from } => {
                            let result = match net::decode_part(&bytes) {
                                Some(outputs) => {
                                    chain.stage_snapshot_part(index as u64, &outputs, next, Some(&root)).map(|_| ())
                                }
                                None => Err(ChainError::BadSnapshot),
                            };
                            Outcome::Part { index, from, result }
                        }
                    };
                    if outcome_tx.send(outcome).is_err() {
                        break;
                    }
                    let _ = wake.try_send(Event::Wake);
                }
            })?
        };
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
            tx_downloads: HashMap::new(),
            pending: HashMap::new(),
            sources: HashMap::new(),
            applying: std::collections::HashSet::new(),
            header_batches: std::collections::BTreeMap::new(),
            slow_batches: HashMap::new(),
            jobs: Some(jobs),
            outcomes,
            applier: Some(applier),
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
            nonce_key: std::collections::hash_map::RandomState::new(),
            nonce_count: 0,
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
                Ok(Event::Mined(block)) => self.submit_block(block, None),
                Ok(Event::Transaction(tx)) => self.handle_transaction(tx, None),
                Ok(Event::Wake) | Err(RecvTimeoutError::Timeout) => {}
                Ok(Event::Stop) | Err(RecvTimeoutError::Disconnected) => break,
            }
            while let Ok(outcome) = self.outcomes.try_recv() {
                self.on_outcome(outcome);
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
        // The applier finishes the block it is on; the rest are dropped.
        self.jobs = None;
        if let Some(h) = self.applier.take() {
            let _ = h.join();
        }
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

    fn next_nonce(&mut self) -> u64 {
        self.nonce_count += 1;
        std::hash::BuildHasher::hash_one(&self.nonce_key, self.nonce_count)
    }

    fn status(&self, nonce: u64) -> Status {
        let tip = self.chain.tip().ok().flatten();
        Status {
            nonce,
            version: PROTOCOL_VERSION,
            genesis: self.genesis,
            height: tip.map_or(0, |h| h.height),
            oldest: self.chain.oldest_body().unwrap_or_else(|_| tip.map_or(1, |h| h.height + 1)),
            tip: tip.map_or(self.genesis, |h| h.hash()),
            work: self.chain.tip_work().unwrap_or(U256::ZERO),
        }
    }

    fn resolve_seeds(&mut self, now: Instant) {
        self.last_seed_lookup = Some(now);
        let seeds = self.config.seeds.clone();
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
        let (key, count) = (&self.nonce_key, &mut self.nonce_count);
        let due = self.peers.due_for_ping(now, || {
            *count += 1;
            std::hash::BuildHasher::hash_one(key, *count)
        });
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
        let best_work = self.chain.best_header_work().unwrap_or(U256::ZERO);
        for addr in self.peers.expire_header_requests(best_work, now) {
            self.log(&format!("{addr} sent no headers for the work it claims; passing it over"));
        }
        let stale = now.checked_sub(PENDING_TIMEOUT);
        self.pending.retain(|_, (_, _, at)| stale.is_none_or(|s| *at > s));
        match self.mode {
            Mode::Normal => self.sync(now),
            Mode::Headers => self.header_sync(now),
            Mode::Snapshot => self.snapshot_sync(now),
        }
        let behind = self.peers.claimants(self.chain.tip_work().unwrap_or(U256::ZERO), now).next().is_some();
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
            .map(|s| (s.parts.iter().filter(|p| **p).count(), s.parts.len()));
        let wanted = match (self.chain.best_header(), self.chain.tip()) {
            (Ok(best), Ok(Some(tip))) => best.height.saturating_sub(tip.height) as usize,
            _ => 0,
        };
        *self.stats.lock().unwrap() = Stats {
            peers,
            downloads: self.downloads.len() + self.tx_downloads.len() + self.snap_downloads.len(),
            wanted,
            waiting: self.pending.len(),
            mode: Some(self.mode),
            parts,
        };
    }

    /// Fetches headers while a peer claims more work than our best header,
    /// and the blocks of the best header's branch.
    fn sync(&mut self, now: Instant) {
        self.pump_headers(now);
        self.start_downloads(now);
    }

    /// The header pipeline: verifies the complete batches at the best
    /// header in order, gives late ones to other peers, and asks for more,
    /// up to `HEADER_BATCHES` ahead, each of a different peer claiming
    /// more work, so one slow peer slows only its own share.
    fn pump_headers(&mut self, now: Instant) {
        if self.mode == Mode::Snapshot {
            return;
        }
        let late: Vec<u32> = self
            .header_batches
            .iter()
            .filter(|(_, b)| !self.batch_complete(b) && now.duration_since(b.asked) >= BATCH_TIMEOUT)
            .map(|(s, _)| *s)
            .collect();
        for start in late {
            let b = self.header_batches.remove(&start).unwrap();
            let misses = self.slow_batches.entry(b.peer).or_insert(0);
            *misses += 1;
            if *misses >= 2 {
                self.chatter(&format!("{} was slow with headers again; passing it over", b.peer));
                self.peers.fetch_failed(b.peer, now);
                self.slow_batches.remove(&b.peer);
            }
        }
        self.verify_header_batches(now);
        let Ok(best) = self.chain.best_header() else { return };
        let ours = self.chain.best_header_work().unwrap_or(U256::ZERO);
        // Believable peers claiming more; if every one was passed over,
        // those, rather than none.
        let mut sources: Vec<(SocketAddr, u32)> =
            self.peers.claimants(ours, now).map(|p| (p.addr, p.status.unwrap().height)).collect();
        if sources.is_empty() {
            sources = self
                .peers
                .trusted(now)
                .filter(|p| p.status.is_some_and(|s| s.work > ours))
                .map(|p| (p.addr, p.status.unwrap().height))
                .collect();
        }
        let busy: std::collections::HashSet<SocketAddr> = self.header_batches.values().map(|b| b.peer).collect();
        let mut free: Vec<(SocketAddr, u32)> = sources.into_iter().filter(|(a, _)| !busy.contains(a)).collect();
        let step = MAX_HEADERS as u32;
        let mut start = best.height + 1;
        while self.header_batches.len() < HEADER_BATCHES && !free.is_empty() {
            if let Some((&s, _)) = self.header_batches.range(..=start).next_back()
                && start < s + step
            {
                start = s + step;
                continue;
            }
            // The free peer reaching furthest past `start` takes it.
            let Some(i) = (0..free.len()).filter(|&i| free[i].1 >= start).max_by_key(|&i| free[i].1) else {
                break;
            };
            let (peer, height) = free.swap_remove(i);
            self.send(peer, &Message::GetHeadersFrom { height: start });
            self.peers.asked_headers(peer, now);
            let end = height.min(start + step - 1);
            self.header_batches.insert(
                start,
                HeaderBatch { start, peer, asked: now, end, headers: std::collections::BTreeMap::new() },
            );
            start += step;
        }
    }

    /// Whether a batch holds every header it needs: from the best header on
    /// to its end.
    fn batch_complete(&self, b: &HeaderBatch) -> bool {
        let from = self.chain.best_header().map_or(0, |h| h.height + 1);
        (from.max(b.start)..=b.end).all(|h| b.headers.contains_key(&h))
    }

    /// Verifies and stores, in order, the complete batches that start at or
    /// below the best header's successor.
    fn verify_header_batches(&mut self, now: Instant) {
        loop {
            let Ok(best) = self.chain.best_header() else { return };
            let Some((&start, b)) = self.header_batches.iter().next() else { return };
            if start > best.height + 1 || !self.batch_complete(b) {
                return;
            }
            let b = self.header_batches.remove(&start).unwrap();
            let headers: Vec<Header> = b.headers.into_values().filter(|h| h.height > best.height).collect();
            let before = self.chain.best_header_work().unwrap_or(U256::ZERO);
            let (new, stop) = self.chain.accept_headers(&headers, unix_now());
            for h in headers.iter().take(new) {
                self.note_source(h.hash(), b.peer);
            }
            self.slow_batches.remove(&b.peer);
            if self.chain.best_header_work().unwrap_or(U256::ZERO) > before {
                self.peers.headers_arrived(b.peer);
                if let Ok(best) = self.chain.best_header() {
                    self.chatter(&format!("headers to height {}", best.height));
                }
            }
            match stop {
                None => {}
                // Not on our best branch: find where it forks with a
                // locator. The batches ahead assumed our branch.
                Some(ChainError::UnknownParent(_)) if new == 0 => {
                    self.header_batches.clear();
                    self.request_headers(b.peer, now);
                    return;
                }
                // Clocks differ: not a fault; asked again later.
                Some(ChainError::TimestampTooNew { .. }) => return,
                Some(e) => {
                    self.log(&format!("headers from {} refused: {e}", b.peer));
                    self.peers.strike(b.peer);
                    self.peers.fetch_failed(b.peer, now);
                    self.header_batches.clear();
                    return;
                }
            }
        }
    }

    /// Sends `to` our header locator, to find where its chain and ours
    /// part; it should answer with headers we lack within
    /// [`net::HEADER_TIMEOUT`].
    fn request_headers(&mut self, to: SocketAddr, now: Instant) {
        match self.chain.header_locator() {
            Ok(locator) => {
                self.chatter(&format!("asking {to} for headers"));
                self.last_header_request = Some(now);
                self.peers.asked_headers(to, now);
                self.send(to, &Message::GetHeaders { locator });
            }
            Err(e) => self.log(&format!("header locator: {e}")),
        }
    }

    /// Starts fetching the blocks of the best header's branch that are
    /// neither here nor on their way, at most [`LOOKAHEAD`] past the first
    /// one missing.
    fn start_downloads(&mut self, now: Instant) {
        if self.mode != Mode::Normal || self.downloads.len() >= MAX_DOWNLOADS {
            return;
        }
        let plan = match self.chain.missing_bodies(LOOKAHEAD) {
            Ok(p) => p,
            Err(e) => return self.log(&format!("planning downloads: {e}")),
        };
        for header in plan {
            if self.downloads.len() >= MAX_DOWNLOADS {
                break;
            }
            let id = header.hash();
            if self.downloads.contains_key(&id) || self.pending.contains_key(&id) || self.applying.contains(&id) {
                continue;
            }
            if let Some(from) = self.block_source(&id, header.height, now) {
                self.start_download(Kind::Block, id, from, now);
            }
        }
    }

    /// Where to fetch block `id` at `height`: the peer that announced it,
    /// if it may serve and has room, else the holder with the fewest
    /// downloads in flight, then the most work.
    fn block_source(&self, id: &Digest, height: u32, now: Instant) -> Option<SocketAddr> {
        let load = |a: &SocketAddr| self.downloads.values().filter(|d| d.from == *a).count();
        if let Some(a) = self.sources.get(id)
            && self.peers.may_serve(a, now)
            && load(a) < MAX_PER_PEER
        {
            return Some(*a);
        }
        let pick = |passed_over: bool| {
            self.peers
                .trusted(now)
                .filter(|p| {
                    p.status.is_some_and(|s| s.oldest <= height && height <= s.height)
                        && passed_over != self.peers.may_serve(&p.addr, now)
                        && load(&p.addr) < MAX_PER_PEER
                })
                .min_by_key(|p| (load(&p.addr), std::cmp::Reverse(p.status.unwrap().work)))
                .map(|p| p.addr)
        };
        // Peers passed over after a failure only if no other holds it.
        pick(false).or_else(|| pick(true))
    }

    /// Remembers that `from` announced block `id`.
    fn note_source(&mut self, id: Digest, from: SocketAddr) {
        if self.sources.len() >= MAX_SOURCES {
            self.sources.clear();
        }
        self.sources.entry(id).or_insert(from);
    }

    fn start_download(&mut self, kind: Kind, id: Digest, from: SocketAddr, now: Instant) {
        let busy = match kind {
            Kind::Tx => self.tx_downloads.contains_key(&id),
            _ => self.downloads.contains_key(&id),
        };
        if busy {
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
        match kind {
            Kind::Tx => self.tx_downloads.insert(id, d),
            _ => self.downloads.insert(id, d),
        };
    }

    fn retry_downloads(&mut self, now: Instant) {
        let (mut requests, blocks) = stalled(&mut self.downloads, now);
        let (tx_requests, txs) = stalled(&mut self.tx_downloads, now);
        requests.extend(tx_requests);
        for (to, msg) in requests {
            self.send(to, &msg);
        }
        for id in txs {
            if let Some(d) = self.tx_downloads.remove(&id) {
                self.peers.strike(d.from);
            }
        }
        if blocks.is_empty() {
            return;
        }
        for id in blocks {
            let Some(d) = self.downloads.remove(&id) else { continue };
            self.log(&format!("gave up fetching block {} from {}; trying another peer", short(&id), d.from));
            // It may lack old bodies (pruned, or fast-synced), or be slow
            // or hostile: pass it over for a while.
            self.peers.strike(d.from);
            self.peers.fetch_failed(d.from, now);
            if self.sources.get(&id) == Some(&d.from) {
                self.sources.remove(&id);
            }
        }
        self.start_downloads(now);
    }

    fn handle_packet(&mut self, addr: SocketAddr, bytes: &[u8]) {
        // Anyone can forge a source address: nothing that arrives unasked
        // counts against the peer it names, and only peers that answered
        // our ping are heard beyond a ping or pong.
        let Some(msg) = Message::decode(bytes) else {
            return;
        };
        let now = Instant::now();
        if !matches!(msg, Message::Ping(_) | Message::Pong(_)) && !self.peers.handshaken(&addr) {
            return;
        }
        match msg {
            Message::Ping(st) => {
                if st.genesis != self.genesis {
                    // Answer, so the other side can see why we will not
                    // talk to it. (Its pong to our ping, which proves the
                    // address, is what drops it.)
                    self.chatter(&format!("{addr} is on another chain"));
                    self.send(addr, &Message::Pong(self.status(st.nonce)));
                    return;
                }
                // Our own ping to this address arrived back: it is us (a
                // seed name or peer list giving our public address).
                if self.peers.is_own_ping(&addr, st.nonce) {
                    self.log(&format!("{addr} is this node; not a peer"));
                    self.peers.mark_self(addr);
                    return;
                }
                if self.peers.handshaken(&addr) {
                    self.peers.seen(addr, now);
                    self.peers.set_status(addr, st);
                } else {
                    self.peers.add(addr, false);
                }
                let reply = self.status(st.nonce);
                self.send(addr, &Message::Pong(reply));
                // Complete the handshake from our side at once, within the
                // budget for unverified addresses.
                if !self.peers.handshaken(&addr) {
                    let nonce = self.next_nonce();
                    if self.peers.ping_now(addr, nonce, now) {
                        let ping = self.status(nonce);
                        self.send(addr, &Message::Ping(ping));
                    }
                }
                self.consider(addr, &st, now);
            }
            Message::Pong(st) => {
                if st.genesis != self.genesis {
                    if self.peers.pong(addr, st) {
                        self.log(&format!(
                            "{addr} is on another chain: its genesis is {}, ours {}; is one of us out of date?",
                            short(&st.genesis),
                            short(&self.genesis)
                        ));
                        self.peers.remove(&addr);
                    }
                    return;
                }
                if !self.peers.pong(addr, st) {
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
            Message::GetHeadersFrom { height } => {
                self.peers.seen(addr, now);
                match self.chain.headers_from(height, MAX_HEADERS) {
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
                // Transactions wait until we have caught up: checked
                // against an old state, they would mostly fail.
                let tip_work = self.chain.tip_work().unwrap_or(U256::ZERO);
                if self.mode != Mode::Normal || self.peers.claimants(tip_work, now).next().is_some() {
                    return;
                }
                let from_peer = self.tx_downloads.values().filter(|d| d.from == addr).count();
                if self.tx_downloads.len() < MAX_TX_DOWNLOADS
                    && from_peer < MAX_TX_PER_PEER
                    && !self.mempool.lock().unwrap().contains(&txid)
                {
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

    /// A peer's status: if a trusted peer claims more work than our best
    /// header, fetch headers now rather than at the next tick.
    fn consider(&mut self, addr: SocketAddr, st: &Status, now: Instant) {
        if self.mode != Mode::Snapshot
            && self.peers.handshaken(&addr)
            && st.work > self.chain.best_header_work().unwrap_or(U256::ZERO)
        {
            self.pump_headers(now);
        }
    }

    /// Headers from `from`: into the batch it was asked for, or, if none
    /// (a reply to a locator), checked and stored at once.
    fn handle_headers(&mut self, from: SocketAddr, headers: Vec<Header>, now: Instant) {
        if self.mode == Mode::Snapshot {
            return;
        }
        let step = MAX_HEADERS as u32;
        if let Some(b) = self
            .header_batches
            .iter_mut()
            .find(|(s, b)| b.peer == from && headers.first().is_some_and(|h| h.height >= **s && h.height < **s + step))
        {
            let start = *b.0;
            for h in headers.into_iter().filter(|h| h.height >= start && h.height < start + step) {
                b.1.headers.insert(h.height, h);
            }
        } else {
            let before = self.chain.best_header_work().unwrap_or(U256::ZERO);
            let (new, stop) = self.chain.accept_headers(&headers, unix_now());
            for h in headers.iter().take(new) {
                self.note_source(h.hash(), from);
            }
            match stop {
                None | Some(ChainError::TimestampTooNew { .. }) => {}
                Some(e) => {
                    self.log(&format!("headers from {from} refused: {e}"));
                    self.peers.strike(from);
                }
            }
            if self.chain.best_header_work().unwrap_or(U256::ZERO) > before {
                self.peers.headers_arrived(from);
                // The fork is found: the pipeline goes on from here.
                if headers.len() == net::HEADERS_PER_MESSAGE {
                    self.request_headers(from, now);
                }
            }
        }
        match self.mode {
            Mode::Headers => self.header_sync(now),
            _ => self.sync(now),
        }
    }

    /// A block announced: its header is checked and stored before the
    /// block is fetched.
    fn handle_inv(&mut self, from: SocketAddr, header: Header, now: Instant) {
        if self.mode != Mode::Normal {
            return;
        }
        let id = header.hash();
        if self.have_block(&id)
            || self.downloads.contains_key(&id)
            || self.pending.contains_key(&id)
            || self.applying.contains(&id)
        {
            return;
        }
        match self.chain.accept_header(&header, unix_now()) {
            Ok(_) => {
                self.note_source(id, from);
                self.start_downloads(now);
            }
            Err(ChainError::UnknownParent(_)) => {
                // Behind by more than one block: ask this peer for headers.
                if self.peers.handshaken(&from)
                    && self.last_header_request.is_none_or(|t| now.duration_since(t) >= SYNC_INTERVAL)
                {
                    self.request_headers(from, now);
                }
            }
            Err(ChainError::KnownInvalid | ChainError::TimestampTooNew { .. }) => {}
            Err(e) => {
                self.chatter(&format!("{from} announced a bad header {}: {e}", short(&id)));
                self.peers.strike(from);
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
                None => match self.chain.block_bytes(&id) {
                    Ok(Some(bytes)) => {
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
        let downloads = if kind == Kind::Tx { &mut self.tx_downloads } else { &mut self.downloads };
        let Some(d) = downloads.get_mut(&id) else {
            return;
        };
        if d.from != from || d.kind != kind {
            return;
        }
        match d.insert(len, index, data, now) {
            Ok(false) => {
                // Refill the window once half of it has arrived.
                if d.wants_refill() {
                    let indexes = d.request(now);
                    for msg in net::chunk_requests(kind, id, &indexes) {
                        self.send(from, &msg);
                    }
                }
            }
            Ok(true) => {
                let bytes = d.assemble().unwrap_or_default();
                downloads.remove(&id);
                match kind {
                    Kind::Block => match Block::from_bytes(&bytes) {
                        Ok(block) if block.header.hash() == id => self.receive_block(block, from),
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
                downloads.remove(&id);
                self.peers.strike(from);
                self.log(&format!("{from} sent bad chunks for {}", short(&id)));
            }
        }
    }

    /// A fetched block: applied if its parent's body is here or on its way
    /// to the applier ahead of it, else held until it is.
    fn receive_block(&mut self, block: Block, from: SocketAddr) {
        let id = block.header.hash();
        self.sources.remove(&id);
        let prev = block.header.prev_hash;
        if self.have_block(&prev) || self.applying.contains(&prev) {
            self.submit_block(block, Some(from));
        } else if self.pending.len() < LOOKAHEAD {
            self.pending.insert(id, (block, Some(from), Instant::now()));
        }
    }

    /// Hands a block to the applier thread; [`Node::on_applied`] takes the
    /// outcome.
    fn submit_block(&mut self, block: Block, from: Option<SocketAddr>) {
        if !self.applying.insert(block.header.hash()) {
            return;
        }
        if let Some(jobs) = &self.jobs {
            let _ = jobs.send(Job::Block(block, from));
        }
    }

    /// A block applied: announces a new tip, and hands over the fetched
    /// blocks that were waiting for it.
    fn on_outcome(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Block(block, from, result) => self.on_applied(*block, from, result),
            Outcome::Part { index, from, result } => self.on_part_staged(index, from, result),
        }
    }

    /// A fast-sync part checked and stored, or refused.
    fn on_part_staged(&mut self, index: u32, from: SocketAddr, result: Result<(), ChainError>) {
        let Some(snap) = self.snap.as_mut() else { return };
        if !snap.staging.remove(&index) {
            return;
        }
        match result {
            Ok(()) => {
                if let Some(p) = snap.parts.get_mut(index as usize) {
                    *p = true;
                }
            }
            Err(e) => {
                self.log(&format!("fast sync: part {index} from {from} refused: {e}"));
                self.peers.strike(from);
                self.peers.fetch_failed(from, Instant::now());
            }
        }
        self.snapshot_sync(Instant::now());
    }

    fn on_applied(&mut self, block: Block, from: Option<SocketAddr>, result: Result<Applied, ChainError>) {
        let id = block.header.hash();
        let height = block.header.height;
        self.applying.remove(&id);
        let connected = match result {
            Ok(Applied::Known) => true,
            Ok(Applied::Side) => {
                let whose = from.map_or("our".to_string(), |a| format!("{a}'s"));
                self.log(&format!("{whose} block {} at height {height} is a side block, not the tip", short(&id)));
                true
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
                true
            }
            Err(ChainError::UnknownParent(_) | ChainError::MissingBody) => {
                // A body of its branch is still on its way.
                if self.pending.len() < LOOKAHEAD {
                    self.pending.insert(id, (block, from, Instant::now()));
                }
                false
            }
            Err(e) => {
                self.log(&format!("rejected block {} at height {height}: {e}", short(&id)));
                if e.is_invalid_block() {
                    if let Some(from) = from {
                        self.peers.strike(from);
                    }
                    self.drop_pending_descendants(id);
                }
                false
            }
        };
        if connected {
            self.sources.remove(&id);
            // Fetched blocks waiting for this one.
            let children: Vec<Digest> =
                self.pending.iter().filter(|(_, (b, _, _))| b.header.prev_hash == id).map(|(k, _)| *k).collect();
            for c in children {
                if let Some((b, f, _)) = self.pending.remove(&c) {
                    self.submit_block(b, f);
                }
            }
        }
        self.start_downloads(Instant::now());
    }

    /// Forgets the fetched blocks descending from an invalid one.
    fn drop_pending_descendants(&mut self, id: Digest) {
        let mut bad = vec![id];
        while let Some(b) = bad.pop() {
            let children: Vec<Digest> =
                self.pending.iter().filter(|(_, (blk, _, _))| blk.header.prev_hash == b).map(|(k, _)| *k).collect();
            for c in children {
                self.pending.remove(&c);
                bad.push(c);
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
        self.pump_headers(now);
        let ours = self.chain.best_header_work().unwrap_or(U256::ZERO);
        if !self.header_batches.is_empty() || self.peers.claimants(ours, now).next().is_some() {
            return;
        }
        // Nobody believable claims more: done, once at least one peer has
        // said so. With no peer at all for a while, this may be the first
        // node: start from genesis.
        if !self.peers.trusted(now).any(|p| p.status.is_some()) {
            if now.duration_since(self.started) >= Duration::from_secs(10) {
                self.log("fast sync: no peers answered; starting from genesis");
                self.mode = Mode::Normal;
            }
            return;
        }
        let best = match self.chain.best_header() {
            Ok(b) => b,
            Err(e) => return self.log(&format!("fast sync: {e}")),
        };
        // The newest snapshot at least the sync point deep: peers take one
        // every `snapshot_interval` blocks and serve no others.
        let depth = self.config.sync_point.unwrap_or(0);
        let interval = self.chain.params().snapshot_interval;
        let height = best.height.saturating_sub(depth) / interval * interval;
        if height == 0 {
            self.log(&format!("fast sync: best header at height {}; validating every block instead", best.height));
            self.mode = Mode::Normal;
            return;
        }
        let target = match self.chain.ancestor(&best, height) {
            Ok(Some(t)) => t,
            _ => return self.log("fast sync: snapshot block's header is missing"),
        };
        self.log(&format!(
            "fast sync: {} headers checked; fetching the state after block {} ({})",
            best.height,
            target.height,
            short(&target.hash())
        ));
        self.snap = Some(Snap {
            target,
            block: None,
            manifest: None,
            verified: false,
            parts: Vec::new(),
            next_peer: 0,
            manifest_from: None,
            bad_manifests: 0,
            unserved: std::collections::HashSet::new(),
            staging: std::collections::HashSet::new(),
        });
        self.mode = Mode::Snapshot;
        self.snapshot_sync(now);
    }

    /// Peers that may serve the snapshot: trusted, at or past its block.
    /// Peers passed over after a failure are asked only if no other can.
    fn snapshot_peers(&self, now: Instant) -> Vec<SocketAddr> {
        let height = self.snap.as_ref().map_or(0, |s| s.target.height);
        let at = |p: &&net::Peer| p.status.is_some_and(|s| s.height >= height);
        let unserved = |a: &SocketAddr| self.snap.as_ref().is_some_and(|s| s.unserved.contains(a));
        let fresh: Vec<SocketAddr> = self
            .peers
            .trusted(now)
            .filter(at)
            .filter(|p| self.peers.may_serve(&p.addr, now) && !unserved(&p.addr))
            .map(|p| p.addr)
            .collect();
        if !fresh.is_empty() {
            return fresh;
        }
        self.peers.trusted(now).filter(at).map(|p| p.addr).collect()
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
                        "fast sync: block {}'s proof verifies the chain up to it; {} positions to fetch in {} parts",
                        snap.target.height,
                        next,
                        snap.parts.len()
                    ));
                    if let Err(e) = self.chain.begin_snapshot() {
                        return self.restart_snapshot(&format!("cannot start installing the snapshot: {e}"));
                    }
                    self.snap.as_mut().unwrap().verified = true;
                }
                // The block was checked against its header on arrival, so
                // the manifest's counter is at fault: one peer's lie, not a
                // failed attempt, unless manifest after manifest fails.
                Err(e) => {
                    let snap = self.snap.as_mut().unwrap();
                    snap.bad_manifests += 1;
                    snap.manifest = None;
                    snap.parts.clear();
                    let (from, bad) = (snap.manifest_from.take(), snap.bad_manifests);
                    if bad >= MAX_SNAPSHOT_ATTEMPTS {
                        return self.restart_snapshot(&format!("the snapshot block does not verify: {e}"));
                    }
                    if let Some(from) = from {
                        self.log(&format!("fast sync: the manifest from {from} does not fit the block's proof"));
                        self.peers.strike(from);
                        self.peers.fetch_failed(from, now);
                    }
                    return;
                }
            }
        }
        let (done, staging, missing): (bool, usize, Vec<u32>) = match self.snap.as_ref() {
            Some(s) if s.verified => (
                s.parts.iter().all(|p| *p),
                s.staging.len(),
                s.parts
                    .iter()
                    .enumerate()
                    .filter(|(i, p)| !**p && !s.staging.contains(&(*i as u32)))
                    .map(|(i, _)| i as u32)
                    .collect(),
            ),
            _ => return,
        };
        if done {
            return self.install_snapshot();
        }
        for i in missing {
            // Parts waiting for the applier count too, so a slow disk
            // bounds what is held in memory.
            if self.snap_downloads.len() + staging >= MAX_PART_DOWNLOADS {
                break;
            }
            self.start_snapshot_download(Kind::Part(i), now);
        }
    }

    fn install_snapshot(&mut self) {
        let Some(snap) = self.snap.take() else {
            return;
        };
        let (next, roots) = snap.manifest.as_ref().unwrap();
        match self.chain.finish_snapshot(snap.block.as_ref().unwrap(), roots, *next) {
            Ok(()) => {
                let unspent = self.chain.env().read_txn().ok().and_then(|r| self.chain.utxo().len(&r).ok());
                self.log(&format!(
                    "fast sync: installed the state after block {} ({} unspent outputs); following the chain from there",
                    snap.target.height,
                    unspent.unwrap_or(0)
                ));
                self.mode = Mode::Normal;
                self.tip_changes.fetch_add(1, Ordering::Release);
                self.revalidate_mempool();
                self.sync(Instant::now());
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
        // Parts still with the applier belong to this attempt: let them
        // land before the partial state is cleared.
        while self.snap.as_ref().is_some_and(|s| !s.staging.is_empty()) {
            match self.outcomes.recv() {
                Ok(Outcome::Part { index, .. }) => {
                    self.snap.as_mut().unwrap().staging.remove(&index);
                }
                Ok(Outcome::Block(b, f, r)) => self.on_applied(*b, f, r),
                Err(_) => break,
            }
        }
        self.snap_attempts += 1;
        self.snap_downloads.clear();
        if let Err(e) = self.chain.abort_snapshot() {
            self.log(&format!("fast sync: clearing the partial state: {e}"));
        }
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
            s.manifest_from = None;
            s.bad_manifests = 0;
        }
    }

    fn retry_snapshot_downloads(&mut self, now: Instant) {
        let mut abandoned = Vec::new();
        let mut requests = Vec::new();
        for (kind, d) in self.snap_downloads.iter_mut() {
            if d.too_slow(now) {
                abandoned.push((*kind, d.from));
                continue;
            }
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
                requests.extend(net::chunk_requests(*kind, d.id, &indexes).map(|m| (d.from, m)));
            }
        }
        for (to, msg) in requests {
            self.send(to, &msg);
        }
        for (kind, from) in abandoned {
            self.snap_downloads.remove(&kind);
            if let Some(s) = self.snap.as_mut() {
                s.unserved.insert(from);
            }
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
                if d.wants_refill() {
                    let indexes = d.request(now);
                    for msg in net::chunk_requests(kind, id, &indexes) {
                        self.send(from, &msg);
                    }
                }
            }
            Ok(true) => {
                let bytes = d.assemble().unwrap_or_default();
                self.snap_downloads.remove(&kind);
                if !self.accept_snapshot_object(kind, &bytes, from) {
                    self.log(&format!("fast sync: {from} sent a bad {kind:?}"));
                    self.peers.strike(from);
                    self.peers.fetch_failed(from, now);
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
    fn accept_snapshot_object(&mut self, kind: Kind, bytes: &[u8], from: SocketAddr) -> bool {
        let Some(snap) = self.snap.as_mut() else {
            return true;
        };
        match kind {
            // The body is checked against the header here, so a corrupted
            // copy is one peer's fault, not a failed attempt.
            Kind::Block => match Block::from_bytes(bytes) {
                Ok(block) if block.header == snap.target && block.body.commitment() == block.header.body_commitment => {
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
                snap.parts = vec![false; roots.len()];
                snap.manifest = Some((next, roots));
                snap.manifest_from = Some(from);
                true
            }
            Kind::Part(i) => {
                let (Some((next, roots)), true) = (snap.manifest.as_ref(), snap.verified) else {
                    return true;
                };
                if snap.parts.get(i as usize).is_none_or(|p| *p) || snap.staging.contains(&i) {
                    return true;
                }
                let Some(&root) = roots.get(i as usize) else {
                    return false;
                };
                // Checked against its root and stored on the applier
                // thread, hashed once, while the network goes on; one
                // part's outputs in memory there at a time.
                let next = *next;
                snap.staging.insert(i);
                if let Some(jobs) = &self.jobs {
                    let _ = jobs.send(Job::Part { index: i, bytes: bytes.to_vec(), next, root, from });
                }
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
            genesis_nonce: [0u8; 32],
            genesis_target: U256([0, 0, 0, 1 << 48]),
            max_target: ChainParams::MAINNET.max_target,
            max_block_size: HEADER_SIZE + 12 + 4 * crate::block::COMMITMENT_SIZE + 3000,
            max_future_drift: 7200,
            median_time_window: 11,
            emission: &[(1000, 50)],
            aggregator: AggregatorParams::MAINNET,
            snapshot_interval: 4,
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
    fn a_node_does_not_peer_with_itself() {
        // A seed name resolving to the node's own address: its ping comes
        // back to itself, and the address is dropped for good.
        let f = open("self");
        let addr: SocketAddr = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        };
        let mut cfg = config(vec![addr], &f.dir);
        cfg.listen = addr;
        let (node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
        let stats = node.stats();
        let h = std::thread::spawn(move || node.run());
        std::thread::sleep(Duration::from_secs(3));
        assert!(stats.lock().unwrap().peers.is_empty(), "{:?}", stats.lock().unwrap().peers);
        tx.send(Event::Stop).unwrap();
        h.join().unwrap();
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
        let position = {
            let rtxn = a.chain.env().read_txn().unwrap();
            let unspent = a.chain.utxo().unspent(&rtxn).unwrap();
            unspent.iter().find(|(_, (c, _))| *c == spent.commitment).unwrap().0
        };
        let mut tx =
            crate::transaction::UnsignedTransaction::new(vec![(k.public_key(), 1)], vec![Output::new(&pk(50), 1)])
                .sign_with(&mut k)
                .unwrap();
        tx.set_positions(&[position]);
        let txid = tx.txid();
        tx_a.send(Event::Transaction(tx)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !pool_b.lock().unwrap().contains(&txid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(pool_b.lock().unwrap().contains(&txid), "transaction was not relayed");
        assert!(pool_a.lock().unwrap().contains(&txid));
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
    fn a_peer_without_old_bodies_is_passed_over() {
        // b fast-syncs from a, then takes a block of its own, three hours
        // ahead so that no other node accepts it yet: b claims the most
        // work but has no bodies below its snapshot. c starts from genesis
        // knowing only b, hears of a from b, and must fetch the blocks from
        // a.
        let a = open("bodies-a");
        let now = unix_now();
        let mut t = T0;
        for tag in 1..=12u8 {
            t += 600;
            a.chain.apply_block(&mine(&a, tag, t), now).unwrap();
        }
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let ha = std::thread::spawn(move || node_a.run());
        let b = open("bodies-b");
        let mut cb = config(vec![addr_a], &b.dir);
        cb.sync_point = Some(4);
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        let hb = std::thread::spawn(move || node_b.run());
        assert!(wait_for_tip(&b.chain, &a.chain.tip().unwrap().unwrap(), 30), "b did not fast-sync");
        tx_b.send(Event::Stop).unwrap();
        hb.join().unwrap();
        let a_tip = a.chain.tip().unwrap().unwrap();
        let ahead = now + 3 * 3600;
        b.chain.apply_block(&mine(&b, 13, ahead), ahead).unwrap();
        assert_eq!(b.chain.oldest_body().unwrap(), 8);

        let mut cb = config(vec![addr_a], &b.dir);
        cb.sync_point = Some(4);
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        let addr_b = node_b.local_addr().unwrap();
        let hb = std::thread::spawn(move || node_b.run());
        let c = open("bodies-c");
        let (node_c, tx_c) = Node::bind(Arc::clone(&c.chain), pool(), config(vec![addr_b], &c.dir)).unwrap();
        let hc = std::thread::spawn(move || node_c.run());
        assert!(wait_for_tip(&c.chain, &a_tip, 30), "c did not sync from a");
        for (tx, h) in [(tx_a, ha), (tx_b, hb), (tx_c, hc)] {
            tx.send(Event::Stop).unwrap();
            h.join().unwrap();
        }
    }

    #[test]
    fn headers_come_in_batches_from_several_peers() {
        // a and b hold 130 blocks: three header batches. c replays from
        // genesis, asking both.
        let a = open("batches-a");
        let b = open("batches-b");
        let now = unix_now();
        let mut t = T0;
        for i in 1..=130u32 {
            t += 600;
            let block = mine(&a, (i % 200) as u8, t);
            a.chain.apply_block(&block, now).unwrap();
            b.chain.apply_block(&block, now).unwrap();
        }
        let tip = a.chain.tip().unwrap().unwrap();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), config(vec![], &b.dir)).unwrap();
        let peers = vec![node_a.local_addr().unwrap(), node_b.local_addr().unwrap()];
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        let c = open("batches-c");
        let (node_c, tx_c) = Node::bind(Arc::clone(&c.chain), pool(), config(peers, &c.dir)).unwrap();
        let hc = std::thread::spawn(move || node_c.run());
        assert!(wait_for_tip(&c.chain, &tip, 60), "c did not sync");
        assert_eq!(c.chain.state_root().unwrap(), a.chain.state_root().unwrap());
        for (tx, h) in [(tx_a, ha), (tx_b, hb), (tx_c, hc)] {
            tx.send(Event::Stop).unwrap();
            h.join().unwrap();
        }
    }

    #[test]
    fn a_false_claim_of_work_does_not_stall_the_sync() {
        // The liar answers pings claiming all the work there could be, and
        // nothing else. c, knowing it and a, must still sync from a, and
        // stop counting itself as behind (which would idle its miner).
        let a = open("liar-a");
        let now = unix_now();
        let mut t = T0;
        for tag in 1..=3u8 {
            t += 600;
            a.chain.apply_block(&mine(&a, tag, t), now).unwrap();
        }
        let a_tip = a.chain.tip().unwrap().unwrap();
        let genesis = a.chain.header_at(0).unwrap().unwrap().hash();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let ha = std::thread::spawn(move || node_a.run());
        let liar = UdpSocket::bind("127.0.0.1:0").unwrap();
        liar.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let liar_addr = liar.local_addr().unwrap();
        let lying = Arc::new(AtomicBool::new(true));
        let hl = {
            let lying = Arc::clone(&lying);
            std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while lying.load(Ordering::Relaxed) {
                    let Ok((n, from)) = liar.recv_from(&mut buf) else { continue };
                    if let Some(Message::Ping(st)) = Message::decode(&buf[..n]) {
                        let claim = Status {
                            nonce: st.nonce,
                            version: PROTOCOL_VERSION,
                            genesis,
                            height: 1_000_000,
                            oldest: 1,
                            tip: genesis,
                            work: U256([u64::MAX; 4]),
                        };
                        let _ = liar.send_to(&Message::Pong(claim).encode(), from);
                    }
                }
            })
        };
        let c = open("liar-c");
        let (node_c, tx_c) = Node::bind(Arc::clone(&c.chain), pool(), config(vec![liar_addr, addr_a], &c.dir)).unwrap();
        let syncing = node_c.syncing();
        let hc = std::thread::spawn(move || node_c.run());
        assert!(wait_for_tip(&c.chain, &a_tip, 40), "c did not sync from a");
        let deadline = Instant::now() + Duration::from_secs(10);
        while syncing.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!syncing.load(Ordering::Acquire), "c still counts itself behind the liar");
        lying.store(false, Ordering::Relaxed);
        hl.join().unwrap();
        for (tx, h) in [(tx_a, ha), (tx_c, hc)] {
            tx.send(Event::Stop).unwrap();
            h.join().unwrap();
        }
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
