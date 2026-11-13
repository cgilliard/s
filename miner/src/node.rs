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
//! (proof of work, in parallel, difficulty, timestamps; during a fast sync
//! only the quick proof of work, below) and stored in
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
//! checking difficulty, timestamps and the quick proof of work (the claimed
//! `mix` meets the target: two permutations), without bodies. It then takes
//! the block `sync_point` below the best header (every node keeps a
//! snapshot manifest for each block in its undo window), checks the full
//! proof of work of that header and every one after it
//! ([`Chain::confirm_work`]), and fetches the block with a manifest of the
//! state after it: the output counter and the root of each part's subtree
//! (16,384 positions), which must compose to the block's state root. The
//! block's proof, a chain proof, is checked against the counter: it shows
//! that block and every one before it valid, and every header before it
//! with its true `mix` (docs/NODE.md, the work in the chain proof), so
//! nothing about the past is trusted and no work before it is checked
//! again. The parts come from every peer
//! that can serve them, `MAX_PART_DOWNLOADS` at once, and are checked
//! against their roots and stored on the applier thread; the snapshot is
//! installed and ordinary sync fetches the blocks after it.
//!
//! Every transfer keeps a window of chunks in flight, learned per peer
//! ([`net::PeerPath`]): [`net::INITIAL_WINDOW`] for a peer not yet measured,
//! doubling per round trip until a loss, halving at one, then growing by an
//! eighth per round trip, up to [`net::MAX_IN_FLIGHT`]. A block's size comes
//! with its `Inv`, so the window's worth of it is asked for at once; a
//! chunk passed by later ones is asked again at once, and a stall waits the
//! peer's smoothed round trip plus four deviations.
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
use crate::chain::{
    Applied, CarriedNamePart, CarriedPart, Chain, ChainError, Manifest, OutputPart, ProofVerifier,
    aux_merkle_root,
};
use crate::consensus;
use crate::difficulty::U256;
use crate::mempool::{MAX_TX_SIZE, Mempool, Reject};
use crate::net::{
    self, Download, Kind, MAX_HEADERS, MAX_IN_FLIGHT, Message, PROTOCOL_VERSION, Peers, Status, TARGET_PEERS, chunk_of,
};
use crate::pow::Digest;
use crate::transaction::Transaction;

mod channels;
mod circuits;
mod participant;
mod rendezvous;
mod sessions;
pub use channels::MAX_CHANNELS;
pub use circuits::MAX_HOPS;
pub use sessions::{MAX_SESSIONS, Note, Outbound};

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
/// A line about one peer's repeated trouble (`Node::log_every`) is
/// written at most this often.
const LOG_EVERY: Duration = Duration::from_secs(600);
const MAX_TX_DOWNLOADS: usize = 32;
/// Pooled transactions announced to a new peer at most (`announce_pool_to`).
const MAX_POOL_CATCHUP: usize = 256;
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
/// How long headers with more work than the tip hold the miner back while
/// the tip does not move: blocks that do not come are not waited for.
const CATCH_UP_PATIENCE: Duration = Duration::from_secs(10);
/// Recently served block serializations kept in memory.
const SERVED_CACHE: usize = 4;
/// Datagrams and local events queued for the node's loop: about 10 MB.
const EVENT_QUEUE: usize = 8192;
/// Minimum spacing of header requests to the same end.
const SYNC_INTERVAL: Duration = Duration::from_secs(2);
const SEED_INTERVAL: Duration = Duration::from_secs(60);
const SAVE_INTERVAL: Duration = Duration::from_secs(60);
/// The saved pool's format (`docs/FEES.md`: with arrival times and the
/// ids expired lately).
const MEMPOOL_FILE_TAG: &[u8; 4] = b"POL2";

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
    /// Started with `--relay`: the operator's consent to relay for others
    /// on the message layer (`docs/ONION.md`).
    pub relay: bool,
    /// The wallet's Dilithium key: with it the node keeps rendezvous
    /// sessions for the wallet's id and sends and receives its messages.
    /// `None` without a wallet (`--no-wallet`), or while its address is
    /// off (`docs/PRIVACY.md`, fix 5).
    pub identity: Option<crate::mldsa::SecretKey>,
    /// Whether the node has a wallet, address or not: its transactions go
    /// out over circuits in onion mode.
    pub wallet: bool,
    /// A relay's caps (`docs/SCALING.md`), sized to its memory: sessions
    /// it holds, circuit hops through it, channels open at once.
    pub max_sessions: usize,
    pub max_hops: usize,
    pub max_channels: usize,
    /// The relay's Dilithium key, apart from the wallet's (derived from the
    /// same phrase under another domain tag): the id a relay is listed
    /// under in `consensus.txt`, proven in every handshake. Set with
    /// `--relay`.
    pub relay_key: Option<crate::mldsa::SecretKey>,
}

impl Config {
    /// The relay's id, the hash of its key.
    pub fn relay_id(&self) -> Option<Digest> {
        self.relay_key.as_ref().map(|k| crate::address::id_of(k.public_key()))
    }
}

/// Default depth of the fast-sync snapshot: a day of blocks.
pub const DEFAULT_SYNC_POINT: u32 = 144;
/// Snapshot parts fetched at once.
const MAX_PART_DOWNLOADS: usize = 32;
/// Snapshot objects kept for serving.
/// Served snapshot parts kept encoded: a syncer has `MAX_PART_DOWNLOADS`
/// in flight and asks for each in windows, and a part is costly to make
/// (a range read and the undo records since the snapshot), so enough for
/// two syncers at once; name parts are the largest, under a megabyte.
const SERVED_SNAPSHOTS: usize = 2 * MAX_PART_DOWNLOADS;
/// Chunks served to one peer a second, at most (8 MB/s), with a burst of
/// [`SERVE_BURST`]: past it requests are dropped, and the peer asks again.
/// The burst is twice the largest window, so a peer's full window is never
/// cut short by it.
const SERVE_RATE: f64 = 8192.0;
const SERVE_BURST: f64 = 2.0 * MAX_IN_FLIGHT as f64;

/// Blocks a snapshot target keeps clear of the start of a peer's undo
/// window: a window moves with its tip, and the blocks after the snapshot
/// are wanted too. A small share of the window itself (about 7 blocks of
/// the default 1,008), at least one.
fn snapshot_margin(status: &net::Status) -> u32 {
    (status.height.saturating_sub(status.oldest) / 128).max(1)
}
/// Failed snapshot attempts before validating from genesis instead.
const MAX_SNAPSHOT_ATTEMPTS: u32 = 4;
/// Between requests for a block's aux leaves.
const AUX_RETRY: Duration = Duration::from_secs(2);
/// Requests for a block's aux leaves before it is given up (until the
/// next scan of the window wants it again).
const AUX_MAX_TRIES: u32 = 16;
/// Aux leaf requests sent per tick.
const AUX_REQUESTS_PER_TICK: usize = 64;
/// A file no live peer served is not asked for again for this long.
const FILE_BACKOFF: Duration = Duration::from_secs(600);
/// Between scans of the window for leaves not yet fetched and the file
/// the window names; a scan also follows every tip change and arrival.
const AUX_SCAN: Duration = Duration::from_secs(10);

/// A block's aux leaves wanted from peers.
struct AuxWant {
    height: u32,
    /// Who sent the block: asked first.
    from: Option<SocketAddr>,
    asked: Option<Instant>,
    tries: u32,
    tried: Vec<SocketAddr>,
}
/// Output parts the applier stages in one transaction, at most.
const PART_BATCH: usize = 16;

/// Staged parts carried forward in one job (one transaction).
const CARRY_BATCH: usize = 64;

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
    manifest: Option<Manifest>,
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
    /// Parts fetched and with the applier, being checked and stored, or
    /// being carried forward.
    staging: std::collections::HashSet<u32>,
    /// Staging has begun in the database: it outlasts a move to a later
    /// snapshot, whose parts are carried forward rather than fetched again.
    begun: bool,
    carry: Option<Carry>,
}

/// Parts staged for an earlier snapshot, to be carried forward to the
/// snapshot being fetched once the bodies between them are in.
struct Carry {
    /// The output parts staged for it: their subtrees.
    staged: Vec<(usize, u64)>,
    /// The name parts staged for it: their records stay, and satisfy the
    /// later manifest's name parts where its hashes agree.
    names: usize,
    /// Blocks after it, up to the snapshot's, whose bodies are still
    /// wanted: their inputs are the outputs the parts lose.
    wanted: HashMap<Digest, Header>,
    /// Positions spent by the bodies received.
    spent: Vec<u64>,
}

/// The `Proof` messages answering a request for `position`: the output
/// there (zero when none) and its path in two parts. `None` before
/// genesis.
pub fn proof_messages<V: ProofVerifier>(chain: &Chain<V>, position: u64) -> Result<Option<Vec<Message>>, ChainError> {
    let Some((tip, output, proof)) = chain.output_proof(position)? else {
        return Ok(None);
    };
    let (commitment, slot, created) = output.unwrap_or((crate::state_tree::EMPTY, crate::state_tree::EMPTY, 0));
    let (memo, amount) = crate::transaction::slot_parts(&slot).ok_or(ChainError::Corrupt("output amount"))?;
    let tip = tip.hash();
    let msgs = proof
        .siblings
        .chunks(net::PROOF_SIBLINGS_PER_MESSAGE)
        .enumerate()
        .map(|(part, s)| Message::Proof {
            position,
            tip,
            commitment,
            memo,
            amount,
            created,
            part: part as u8,
            siblings: s.to_vec(),
        })
        .collect();
    Ok(Some(msgs))
}

/// Whether a state proof's output (zero for none; `slot` its memo and
/// amount, [`crate::transaction::memo_slot`]) and full path put the leaf
/// at `position` under `state_root`.
pub fn verify_proof(
    state_root: &Digest,
    position: u64,
    commitment: &Digest,
    slot: &Digest,
    created: u32,
    siblings: &[Digest],
) -> bool {
    let Ok(siblings) = <[Digest; crate::state_tree::DEPTH]>::try_from(siblings.to_vec()) else {
        return false;
    };
    let leaf = if *commitment == crate::state_tree::EMPTY {
        crate::state_tree::EMPTY
    } else {
        crate::transaction::leaf(commitment, slot, created)
    };
    crate::state_tree::Proof { siblings }.verify(state_root, position, &leaf)
}

/// What the node's loop consumes.
pub enum Event {
    Packet(SocketAddr, Vec<u8>),
    /// A block produced locally: apply it and announce it.
    Mined(Block),
    /// A transaction made locally: pool it and announce it.
    Transaction(Transaction),
    /// A message for an id, from the wallet (`docs/ONION.md`).
    Send(Outbound),
    /// The wallet's new address (`docs/PRIVACY.md`, fix 5), or none: its
    /// sessions move to the new address's rendezvous points, or close.
    Identity(Option<crate::mldsa::SecretKey>),
    /// The wallet's sub-name delegation, published at its rendezvous
    /// points, or none (`docs/SUBNAMES.md`).
    Delegate(Option<Vec<u8>>),
    /// The wallet asks for an id's delegation, under a tag and in a group
    /// (`Outbound::group`): answered by `Note::Delegation`.
    GetDelegation(u64, Digest, u64),
    /// The sub-name certificates this node holds, as bundles
    /// (`docs/SUBNAME_CERT.md`): published at their full names' points.
    Certs(Vec<Vec<u8>>),
    /// The wallet asks for the certificate of the full name whose point id
    /// this is, under a tag and in a group: answered by `Note::Cert`.
    GetCert(u64, Digest, u64),
    /// Tests: names' values for the rendezvous points to check
    /// certificates against, instead of the chain's.
    #[cfg(test)]
    TestNames(HashMap<Vec<u8>, Digest>),
    /// Tests: a body for the relay with this id at this address, over a
    /// channel opened for it if need be.
    #[cfg(test)]
    TestChannel(SocketAddr, Digest, Vec<u8>),
    /// Tests (and dev builds' `--test-relays`): relays as if an onion-mode
    /// file listed them.
    #[cfg(any(test, feature = "dev"))]
    TestRelays(Vec<consensus::Relay>),
    /// Tests: a circuit through these relays, and data for its hops once
    /// it is built.
    #[cfg(test)]
    TestCircuit(Vec<Digest>, Vec<(usize, Vec<u8>)>),
    /// Tests: keep no standing circuits.
    #[cfg(test)]
    TestQuiet,
    /// Tests: close the channels that carry no circuit now, as if idle
    /// for the whole timeout.
    #[cfg(test)]
    TestExpireIdle,
    /// Tests: every channel forgotten without a word, as a restart would.
    #[cfg(test)]
    TestForgetChannels,
    /// Tests: keepalives and circuit replacement sooner, and how long a
    /// send keeps asking after an "offline".
    #[cfg(test)]
    TestTiming(Duration, Duration, Duration),
    /// Tests: the relay lists in force given by hand (`None` for init
    /// mode): the current one, the one before while a switch lasts, and
    /// whether the current one is tried first.
    #[cfg(test)]
    TestEpoch(Option<Vec<consensus::Relay>>, Option<Option<Vec<consensus::Relay>>>, bool, u32),
    /// Tests: a relay message to a hop of a circuit built.
    #[cfg(test)]
    TestCircuitSend(u64, usize, u8, Vec<u8>),
    /// Tests: the owners this node, as a sub-name issuer, republishes the
    /// delegations of, without their names on chain.
    #[cfg(test)]
    TestServes(Vec<Digest>),
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
    /// The missing heights were asked for again once.
    retried: bool,
}

/// Bytes served to several peers without copying.
type Shared = Arc<Vec<u8>>;

/// A change to the snapshot that waits for the applier (see
/// `Node::deferred`).
enum Deferred {
    Move(Box<Header>, String),
    Restart(String),
    /// Restart, then leave the snapshot for header sync.
    Abandon(String),
}

/// A block handed to the applier thread, with who sent it.
enum Job {
    Block(Block, Option<SocketAddr>),
    /// A fast-sync output part, checked against its manifest entry and
    /// stored.
    Part {
        index: u32,
        bytes: Vec<u8>,
        next: u64,
        part: OutputPart,
        from: SocketAddr,
    },
    /// A fast-sync name part, checked against its manifest hash and stored.
    NamePart {
        index: u32,
        bytes: Vec<u8>,
        lo: crate::name_trie::Key,
        hi: crate::name_trie::Key,
        hash: Digest,
        from: SocketAddr,
    },
    /// Staged parts carried forward to a later snapshot.
    Carry {
        parts: Vec<CarriedPart>,
        next: u64,
    },
    /// Staged name records checked against a later manifest's name parts.
    CarryNames(Vec<CarriedNamePart>),
}
/// What applying it gave.
enum Outcome {
    Block(Box<Block>, Option<SocketAddr>, Result<Applied, ChainError>),
    Part {
        index: u32,
        from: SocketAddr,
        result: Result<(), ChainError>,
    },
    /// Which parts were carried.
    Carry {
        indexes: Vec<u32>,
        result: Result<Vec<bool>, ChainError>,
    },
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
    /// Blocks whose aux leaves are still to be fetched.
    pub aux_wanted: usize,
    /// The wallet's rendezvous points and whether each session is live.
    pub rendezvous: Vec<(SocketAddr, bool)>,
    /// Sessions held for others, as a relay.
    pub sessions: usize,
    /// Onion-mode channels open, either end.
    pub channels: usize,
    /// Onion-mode circuits: ours built, and hops served for others.
    pub circuits: (usize, usize),
    /// Outbound circuits of ours built since start.
    pub outbound_built: u64,
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub height: Option<u32>,
    pub live: bool,
    pub handshaken: bool,
    /// Its relay floor, base units a byte, once it has told us.
    pub min_fee: Option<u64>,
    /// Its pool's admission minimum, base units a byte, once it has told us.
    pub pool_fee: Option<u64>,
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
    /// When a rate-limited line (`log_every`) was last written, by key.
    logged: HashMap<(SocketAddr, &'static str), Instant>,
    /// Fetched blocks waiting for their parent's body, with who sent them
    /// and when.
    pending: HashMap<Digest, (Block, Option<SocketAddr>, Instant)>,
    /// Who announced a block we may fetch: asked first, since its status
    /// may not show the block yet.
    sources: HashMap<Digest, SocketAddr>,
    /// Block sizes as announced (`Inv`), so a download asks for the whole
    /// window at once; bounded as `sources`.
    sizes: HashMap<Digest, u32>,
    /// What downloads learned of the path to each peer: the window to
    /// start the next one with.
    paths: HashMap<SocketAddr, net::PeerPath>,
    /// Blocks of a branch forking below what the chain can unwind: not
    /// fetched again.
    unfollowable: std::collections::HashSet<Digest>,
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
    served: VecDeque<(Digest, Arc<Vec<u8>>)>,
    served_snapshots: VecDeque<((Kind, Digest), Shared)>,
    /// Chunks each peer may still be served: a bucket refilled at
    /// [`SERVE_RATE`] a second up to [`SERVE_BURST`], and when last
    /// refilled.
    serve_budget: HashMap<SocketAddr, (f64, Instant)>,
    mode: Mode,
    snap: Option<Snap>,
    snap_downloads: HashMap<(Kind, Digest), Download>,
    /// When each peer last delivered a chunk of the snapshot: one that is
    /// serving it, but at its rate limit, leaves some downloads unanswered
    /// for a while without failing to serve them.
    snap_heard: HashMap<SocketAddr, Instant>,
    snap_attempts: u32,
    /// Fast sync was left for want of peers: it is taken up again when the
    /// first one appears, if no block has been replayed meanwhile.
    alone: bool,
    /// A change to the snapshot waiting for the parts still with the
    /// applier to land: nothing new is fetched or staged meanwhile, and
    /// the network thread goes on.
    deferred: Option<Deferred>,
    /// Peers whose headers were dated in this node's future, lately; with
    /// several, this node's clock is the likelier fault. When that was
    /// last said.
    too_new: HashMap<SocketAddr, Instant>,
    skew_said: Option<Instant>,
    /// Tests: fetch at most this many parts of the first snapshot, so that
    /// a move to a later one finds parts staged.
    #[cfg(test)]
    hold_parts: Option<usize>,
    #[cfg(test)]
    moved: bool,
    /// Tests: parts fetched and staged.
    #[cfg(test)]
    parts_staged: Arc<AtomicU64>,
    /// Tests: serve manifests whose output counter is one too high (the
    /// state root, which does not commit to it, still matches).
    #[cfg(test)]
    lie_manifest: bool,
    /// Tests: serve no manifest or part.
    #[cfg(test)]
    withhold_snapshots: bool,
    /// Tests: what the fast sync went through.
    #[cfg(test)]
    seen: Arc<Seen>,
    /// State proofs received in part, by peer, position and tip.
    #[allow(clippy::type_complexity)]
    proof_parts: HashMap<(SocketAddr, u64, Digest), [Option<(Digest, Digest, u32, Vec<Digest>)>; 2]>,
    /// State proofs received and verified against a known header.
    pub proofs_verified: Arc<AtomicU64>,
    last_header_request: Option<Instant>,
    /// Peers whose branch we are walking with locators because they claim
    /// more work than our best header without yet showing it: the height
    /// the last request continued from, so each reply brings one more.
    fork_probe: HashMap<SocketAddr, u32>,
    syncing: Arc<AtomicBool>,
    rx: Receiver<Event>,
    tip_changes: Arc<AtomicU64>,
    /// The last block of our own (a miner's) the chain refused, and why.
    refused: Arc<Mutex<Option<(Digest, String)>>>,
    running: Arc<AtomicBool>,
    /// Ping nonces are this key's SipHash of a counter: a peer seeing its
    /// own cannot predict the next, so cannot answer a ping sent to an
    /// address it does not hold.
    nonce_key: std::collections::hash_map::RandomState,
    nonce_count: u64,
    /// Request tokens are this key's SipHash of the peer's address.
    token_key: std::collections::hash_map::RandomState,
    last_seed_lookup: Option<Instant>,
    last_save: Instant,
    started: Instant,
    /// While headers with more work than the tip are held: the tip's
    /// generation ([`Node::tip_changes`]) and when it was last seen to move.
    catch_up: Option<(u64, Instant)>,
    /// Blocks whose aux leaves are to be fetched (`docs/ONION.md`).
    aux_wants: HashMap<Digest, AuxWant>,
    last_aux_scan: Option<Instant>,
    /// The tip change count at the last scan.
    aux_scanned_at: u64,
    /// The consensus file the window names and this node lacks.
    file_want: Option<consensus::Hash>,
    /// What the window last decided, to log changes: the winning hash and
    /// the mode in force.
    last_consensus: Option<(u32, Option<consensus::Hash>, consensus::Mode, bool, bool)>,
    /// Peers that did not serve the wanted file.
    file_failed: std::collections::HashSet<SocketAddr>,
    /// Files no live peer served, and when they were given up.
    file_unavailable: HashMap<consensus::Hash, Instant>,
    /// The message layer's sessions and sends.
    rv: sessions::State,
    /// Onion mode's channels.
    channels: channels::Channels,
    /// Onion mode's circuits: ours and those through us.
    circuits: circuits::Circuits,
    /// Onion mode's rendezvous service.
    rdv: rendezvous::Rendezvous,
    /// Onion mode's participant: standing circuits and sends.
    part: participant::Participant,
    /// Tests: no standing circuits, for tests that drive circuits by hand.
    #[cfg(test)]
    quiet: bool,
    /// Tests: transactions this node announced, by its own `TxInv`s.
    #[cfg(test)]
    announced: Arc<AtomicU64>,
    /// Tests: channel frames this node sent.
    #[cfg(test)]
    frames_sent: Arc<AtomicU64>,
    /// Tests: datagrams dropped on the way out, per thousand, and the
    /// generator's state.
    #[cfg(test)]
    loss: std::cell::Cell<(u64, u64)>,
    /// Tests: datagrams per thousand held back and sent after the next one
    /// (released at the next tick if none follows), as a reordering
    /// network would; the generator's state; the one held.
    #[cfg(test)]
    reorder: std::cell::Cell<(u64, u64)>,
    #[cfg(test)]
    held: std::cell::RefCell<Option<(SocketAddr, Vec<u8>)>>,
    /// Tests: outgoing messages this says to drop are not sent (a fault
    /// injected by kind, rather than at random).
    #[cfg(test)]
    drop_out: std::cell::RefCell<Option<DropFilter>>,
    last_channel_poll: Instant,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Tests: a draw from `(per_mille, state)`'s xorshift generator, true
/// `per_mille` times in a thousand.
#[cfg(test)]
fn chance(c: &std::cell::Cell<(u64, u64)>) -> bool {
    let (per_mille, mut x) = c.get();
    if per_mille == 0 {
        return false;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    c.set((per_mille, x));
    x % 1000 < per_mille
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
/// Tests: which outgoing messages to drop.
#[cfg(test)]
pub(crate) type DropFilter = Box<dyn FnMut(&Message) -> bool + Send>;

/// A message's name, for the log.
fn message_name(m: &Message) -> &'static str {
    match m {
        Message::Ping(_) => "Ping",
        Message::Pong(_) => "Pong",
        Message::GetPeers { .. } => "GetPeers",
        Message::Peers(_) => "Peers",
        Message::GetHeaders { .. } | Message::GetHeadersFrom { .. } => "GetHeaders",
        Message::Headers(_) => "Headers",
        Message::Inv(..) => "Inv (a block)",
        Message::TxInv(_) => "TxInv (a transaction)",
        Message::GetChunks { .. } => "GetChunks",
        Message::Chunk { .. } => "Chunk",
        Message::GetAux { .. } | Message::Aux { .. } => "Aux",
        Message::Frame(_) | Message::Handshake { .. } | Message::ChannelGone { .. } => "a channel's frame",
        Message::Goodbye { .. } => "Goodbye",
        Message::NotHeld { .. } => "NotHeld",
        _ => "a message-layer message",
    }
}

fn stalled(
    downloads: &mut HashMap<Digest, Download>,
    now: Instant,
    retry: impl Fn(&SocketAddr) -> Duration,
) -> (Vec<(SocketAddr, Message)>, Vec<Digest>) {
    let mut requests = Vec::new();
    let mut abandoned = Vec::new();
    for d in downloads.values_mut() {
        if d.not_held || d.kind == Kind::Block && d.too_slow(now) {
            abandoned.push(d.id);
            continue;
        }
        let wait = retry(&d.from);
        if now.duration_since(d.last_progress) < wait || now.duration_since(d.last_request) < wait {
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

/// Tests: counts of what a fast sync went through.
#[cfg(test)]
#[derive(Default)]
struct Seen {
    /// Snapshot blocks verified against their manifest.
    verified: AtomicU64,
    /// Manifests that did not fit the snapshot block's proof.
    refused: AtomicU64,
    /// Attempts used up with no peer keeping every block.
    kept_trying: AtomicU64,
    /// Snapshots abandoned for leaving the best chain.
    abandoned: AtomicU64,
    /// What the node was doing, and when: written each tick, for a test
    /// that fails to say where the node was stuck (a stale one: its loop
    /// stopped).
    state: Mutex<Option<(Instant, String)>>,
}

#[cfg(test)]
impl Seen {
    /// The last state written, and how long ago.
    fn state(&self) -> String {
        match &*self.state.lock().unwrap() {
            Some((at, s)) => format!("as of {:.1} s ago: {s}", at.elapsed().as_secs_f64()),
            None => "never written".to_string(),
        }
    }
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
        if !config.listen.is_ipv4() {
            return Err(std::io::Error::other("IPv6 is not supported: listen on an IPv4 address"));
        }
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
            let mut last_error: Option<std::io::ErrorKind> = None;
            while flag.load(Ordering::Relaxed) {
                match reader.recv_from(&mut buf) {
                    Ok((n, addr)) => {
                        last_error = None;
                        // A full queue (the loop busy applying a block, or
                        // a flood) drops the datagram: requests are retried.
                        if let Err(TrySendError::Disconnected(_)) =
                            sender.try_send(Event::Packet(addr, buf[..n].to_vec()))
                        {
                            break;
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::Interrupted
                        ) => {}
                    // Anything else (the network gone while the machine
                    // slept, an ICMP error reported on the socket) passes:
                    // the reader keeps reading until the node stops, logging
                    // each kind of error once and pausing so as not to spin.
                    Err(e) => {
                        if last_error != Some(e.kind()) {
                            crate::log::line(&format!("net: socket error: {e}; still listening"));
                            last_error = Some(e.kind());
                        }
                        std::thread::sleep(Duration::from_millis(100));
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
                let mut held: Option<Job> = None;
                loop {
                    let job = match held.take() {
                        Some(j) => j,
                        None => match job_rx.recv() {
                            Ok(j) => j,
                            Err(_) => break,
                        },
                    };
                    let outcome = match job {
                        Job::Block(block, from) => {
                            let result = chain.apply_block(&block, unix_now());
                            crate::parallel::release_free_memory();
                            Outcome::Block(Box::new(block), from, result)
                        }
                        // Output parts queued together are staged in one
                        // transaction: one wait on the disk, not one each.
                        part @ Job::Part { .. } => {
                            let mut batch = vec![part];
                            while batch.len() < PART_BATCH {
                                match job_rx.try_recv() {
                                    Ok(p @ Job::Part { .. }) => batch.push(p),
                                    Ok(other) => {
                                        held = Some(other);
                                        break;
                                    }
                                    Err(_) => break,
                                }
                            }
                            let mut decoded = Vec::new();
                            let mut outcomes: Vec<Outcome> = Vec::new();
                            let mut slots = Vec::new();
                            for (n, job) in batch.into_iter().enumerate() {
                                let Job::Part { index, bytes, next, part, from } = job else { unreachable!() };
                                if let Some((outputs, commits)) = net::decode_part(&bytes) {
                                    decoded.push((part, outputs, commits, next));
                                    slots.push(n);
                                }
                                outcomes.push(Outcome::Part { index, from, result: Err(ChainError::BadSnapshot) });
                            }
                            for (n, r) in slots.into_iter().zip(chain.stage_snapshot_parts(&decoded)) {
                                if let Outcome::Part { result, .. } = &mut outcomes[n] {
                                    *result = r.map(|_| ());
                                }
                            }
                            let mut gone = false;
                            for o in outcomes {
                                gone |= outcome_tx.send(o).is_err();
                            }
                            if gone {
                                break;
                            }
                            let _ = wake.try_send(Event::Wake);
                            continue;
                        }
                        Job::NamePart { index, bytes, lo, hi, hash, from } => {
                            let result = match net::decode_name_part(&bytes) {
                                Some(records) => chain.stage_name_part(&records, lo, hi, Some(&hash)).map(|_| ()),
                                None => Err(ChainError::BadSnapshot),
                            };
                            Outcome::Part { index, from, result }
                        }
                        // A part the later manifest has none for: no slot
                        // (out of range, so nothing recorded).
                        Job::Carry { parts, next } => Outcome::Carry {
                            indexes: parts.iter().map(|p| p.slot.unwrap_or(u32::MAX)).collect(),
                            result: chain.carry_snapshot_parts(&parts, next),
                        },
                        Job::CarryNames(parts) => Outcome::Carry {
                            indexes: parts.iter().map(|p| p.index).collect(),
                            result: chain.carry_name_parts(&parts),
                        },
                    };
                    if outcome_tx.send(outcome).is_err() {
                        break;
                    }
                    let _ = wake.try_send(Event::Wake);
                }
            })?
        };
        let now = Instant::now();
        let rv = sessions::State::new(config.identity.clone(), config.wallet || config.identity.is_some(), now)?;
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
            logged: HashMap::new(),
            pending: HashMap::new(),
            sources: HashMap::new(),
            sizes: HashMap::new(),
            paths: HashMap::new(),
            unfollowable: std::collections::HashSet::new(),
            applying: std::collections::HashSet::new(),
            header_batches: std::collections::BTreeMap::new(),
            slow_batches: HashMap::new(),
            jobs: Some(jobs),
            outcomes,
            applier: Some(applier),
            served: VecDeque::new(),
            served_snapshots: VecDeque::new(),
            serve_budget: HashMap::new(),
            mode: Mode::Normal,
            snap: None,
            snap_downloads: HashMap::new(),
            snap_heard: HashMap::new(),
            snap_attempts: 0,
            alone: false,
            deferred: None,
            too_new: HashMap::new(),
            skew_said: None,
            #[cfg(test)]
            hold_parts: None,
            #[cfg(test)]
            moved: false,
            #[cfg(test)]
            parts_staged: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            lie_manifest: false,
            #[cfg(test)]
            withhold_snapshots: false,
            #[cfg(test)]
            seen: Arc::default(),
            proof_parts: HashMap::new(),
            proofs_verified: Arc::new(AtomicU64::new(0)),
            last_header_request: None,
            fork_probe: HashMap::new(),
            syncing: Arc::new(AtomicBool::new(true)),
            rx,
            tip_changes: Arc::new(AtomicU64::new(0)),
            refused: Arc::new(Mutex::new(None)),
            running,
            nonce_key: std::collections::hash_map::RandomState::new(),
            nonce_count: 0,
            token_key: std::collections::hash_map::RandomState::new(),
            last_seed_lookup: None,
            last_save: now,
            started: now,
            catch_up: None,
            aux_wants: HashMap::new(),
            last_aux_scan: None,
            aux_scanned_at: 0,
            file_want: None,
            last_consensus: None,
            file_failed: std::collections::HashSet::new(),
            file_unavailable: HashMap::new(),
            rv,
            channels: channels::Channels::default(),
            circuits: circuits::Circuits::default(),
            rdv: rendezvous::Rendezvous::default(),
            part: participant::Participant::default(),
            #[cfg(test)]
            quiet: false,
            #[cfg(test)]
            announced: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            frames_sent: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            loss: std::cell::Cell::new((0, 0x9e37_79b9_7f4a_7c15)),
            #[cfg(test)]
            reorder: std::cell::Cell::new((0, 0x2545_f491_4f6c_dd1d)),
            #[cfg(test)]
            held: std::cell::RefCell::new(None),
            #[cfg(test)]
            drop_out: std::cell::RefCell::new(None),
            last_channel_poll: now,
        };
        if node.config.sync_point.is_some() && node.chain.tip().ok().flatten().is_some_and(|t| t.height == 0) {
            node.mode = Mode::Headers;
            node.log("fast sync: downloading headers");
        }
        let pooled = node.load_mempool();
        if pooled > 0 {
            node.log(&format!("mempool: {pooled} saved transactions pooled again"));
        }
        // A relay keeps its sessions' announces on disk (`docs/SCALING.md`).
        if node.config.relay
            && let Some(dir) = node.config.peers_file.as_ref().and_then(|p| p.parent())
        {
            match rendezvous::Announces::open(&dir.join("rendezvous")) {
                Ok(a) => node.rdv.announces = a,
                Err(e) => node.log(&format!("rendezvous: announces kept in memory: {e}")),
            }
        }
        node.resolve_seeds(now);
        Ok((node, tx))
    }

    /// Counter bumped whenever the main chain's tip changes.
    pub fn tip_changes(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.tip_changes)
    }

    /// The last block fed in as [`Event::Mined`] that the chain refused,
    /// and why: a miner waiting on its block's verdict learns of a refusal
    /// that leaves no record in the chain.
    pub fn refused(&self) -> Arc<Mutex<Option<(Digest, String)>>> {
        Arc::clone(&self.refused)
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
                Ok(Event::Send(out)) => self.start_send(out, Instant::now()),
                Ok(Event::Identity(key)) => self.set_identity(key, Instant::now()),
                Ok(Event::Delegate(d)) => self.set_delegation(d),
                Ok(Event::GetDelegation(tag, owner, group)) => self.get_delegation(tag, owner, group, Instant::now()),
                Ok(Event::Certs(certs)) => self.set_certs(certs),
                Ok(Event::GetCert(tag, point, group)) => self.get_cert(tag, point, group, Instant::now()),
                #[cfg(test)]
                Ok(Event::TestNames(names)) => self.rdv.test_names = Some(names),
                #[cfg(test)]
                Ok(Event::TestChannel(addr, id, body)) => {
                    let now = Instant::now();
                    let key = self.channel_to(addr, id, now).unwrap();
                    self.channel_send(key, &body, now).unwrap();
                }
                #[cfg(any(test, feature = "dev"))]
                Ok(Event::TestRelays(relays)) => self.rv.set_relays(relays),
                #[cfg(test)]
                Ok(Event::TestQuiet) => self.quiet = true,
                #[cfg(test)]
                Ok(Event::TestExpireIdle) => self.channels.expire_idle = true,
                #[cfg(test)]
                Ok(Event::TestForgetChannels) => self.channels.forget(),
                #[cfg(test)]
                Ok(Event::TestServes(owners)) => self.part.test_owners = Some(owners),
                #[cfg(test)]
                Ok(Event::TestTiming(keepalive, rotate, offline)) => self.part.set_timing(keepalive, rotate, offline),
                #[cfg(test)]
                Ok(Event::TestEpoch(current, previous, prefer, epoch)) => {
                    self.rv.set_sets(current, previous, prefer, epoch)
                }
                #[cfg(test)]
                Ok(Event::TestCircuit(path, queued)) => {
                    if let Err(e) = self.build_circuit(path, queued, Instant::now()) {
                        self.log(&format!("circuit: {e}"));
                        self.circuits.seen.lock().unwrap().push(circuits::Seen::Failed(u64::MAX));
                    }
                }
                #[cfg(test)]
                Ok(Event::TestCircuitSend(handle, hop, cmd, data)) => {
                    if let Err(e) = self.circuit_send(handle, hop, cmd, &data, Instant::now()) {
                        self.log(&format!("circuit: {e}"));
                    }
                }
                Ok(Event::Wake) | Err(RecvTimeoutError::Timeout) => {}
                Ok(Event::Stop) | Err(RecvTimeoutError::Disconnected) => {
                    self.goodbye(Instant::now());
                    break;
                }
            }
            while let Ok(outcome) = self.outcomes.try_recv() {
                self.on_outcome(outcome);
            }
            let now = Instant::now();
            self.retry_downloads(now);
            self.retry_snapshot_downloads(now);
            self.retry_objects(now);
            if now.duration_since(self.last_channel_poll) >= Duration::from_millis(100) {
                self.last_channel_poll = now;
                self.poll_channels(now);
            }
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
        self.save_mempool();
    }

    /// The pool's file, beside the peers file.
    fn mempool_file(&self) -> Option<PathBuf> {
        Some(self.config.peers_file.as_ref()?.with_file_name("mempool"))
    }

    /// Writes the pooled transactions to the data directory, so a restart
    /// keeps pending payments and their ages (`docs/FEES.md`): after a
    /// tag, each as its arrival time, its length and its bytes; then the
    /// ids expired lately, each with until when it is refused.
    fn save_mempool(&self) {
        let Some(path) = self.mempool_file() else { return };
        let pool = self.mempool.lock().unwrap();
        let mut bytes = MEMPOOL_FILE_TAG.to_vec();
        bytes.extend_from_slice(&(pool.len() as u32).to_le_bytes());
        for e in pool.entries() {
            let tx = e.tx.to_bytes();
            bytes.extend_from_slice(&e.arrived.to_le_bytes());
            bytes.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&tx);
        }
        let expired: Vec<_> = pool.expired().map(|(id, until)| (*id, *until)).collect();
        let confirmed: Vec<_> = pool.confirmed().copied().collect();
        drop(pool);
        bytes.extend_from_slice(&(expired.len() as u32).to_le_bytes());
        for (id, until) in expired {
            bytes.extend_from_slice(&crate::poseidon2::digest_to_bytes(&id));
            bytes.extend_from_slice(&until.to_le_bytes());
        }
        // The confirmations the fee estimates use: rate, wait and when.
        bytes.extend_from_slice(&(confirmed.len() as u32).to_le_bytes());
        for (rate, waited, at) in confirmed {
            for v in [rate, waited, at] {
                bytes.extend_from_slice(&v.to_le_bytes());
            }
        }
        let tmp = path.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp, &bytes).and_then(|_| std::fs::rename(&tmp, &path)) {
            self.log(&format!("saving the pool: {e}"));
        }
    }

    /// Pools the transactions saved by [`Node::save_mempool`], each checked
    /// again and keeping its arrival time, the ids expired lately and the
    /// confirmations the fee estimates use;
    /// returns how many transactions were taken. A file of another format
    /// is passed over.
    fn load_mempool(&mut self) -> usize {
        let Some(bytes) = self.mempool_file().and_then(|p| std::fs::read(p).ok()) else { return 0 };
        let height = self.chain.tip().ok().flatten().map_or(1, |t| t.height + 1);
        let Ok(rtxn) = self.chain.env().read_txn() else { return 0 };
        let mut pool = self.mempool.lock().unwrap();
        let Some(rest) = bytes.strip_prefix(MEMPOOL_FILE_TAG) else { return 0 };
        let mut r = crate::codec::Reader(rest);
        let mut taken = 0;
        for _ in 0..r.u32().unwrap_or(0) {
            let (Some(arrived), Some(len)) = (r.u64(), r.u32()) else { break };
            let Some(tx) = r.take(len as usize) else { break };
            if let Some(tx) = Transaction::from_bytes(tx)
                && pool.insert_at(tx, self.chain.utxo(), self.chain.names(), &rtxn, height, arrived).is_ok()
            {
                taken += 1;
            }
        }
        for _ in 0..r.u32().unwrap_or(0) {
            let (Some(id), Some(until)) = (r.digest(), r.u64()) else { break };
            pool.remember_expired(id, until);
        }
        // Absent from a file saved before they were kept.
        for _ in 0..r.u32().unwrap_or(0) {
            let (Some(rate), Some(waited), Some(at)) = (r.u64(), r.u64(), r.u64()) else { break };
            pool.remember_confirmed(rate, waited, at);
        }
        taken
    }

    fn log(&self, msg: &str) {
        crate::log::line(&format!("net: {msg}"));
    }

    /// Shutting down: each channel's other end told it is gone (it closes
    /// at once, and with it every circuit through it, both ways), and each
    /// peer that we are going (it drops us now), rather than all of them
    /// finding out by silence, 30 s to 3 minutes later. A restart or an
    /// upgrade is then not a crash to the network (`docs/TIMING_FIXES.md`).
    fn goodbye(&mut self, now: Instant) {
        let chans = self.channels.keys();
        for &(addr, chan) in &chans {
            self.send(addr, &Message::ChannelGone { chan });
        }
        let peers: Vec<SocketAddr> = self.peers.live(now).map(|p| p.addr).collect();
        for &addr in &peers {
            self.send(addr, &Message::Goodbye { token: 0 });
        }
        self.log(&format!("going: {} channels and {} peers told", chans.len(), peers.len()));
    }

    /// `log`, at most once each [`LOG_EVERY`] for the same peer and kind
    /// of trouble (a peer that keeps sending what is not heard).
    fn log_every(&mut self, addr: SocketAddr, kind: &'static str, msg: &str, now: Instant) {
        if self.logged.get(&(addr, kind)).is_none_or(|t| now.duration_since(*t) >= LOG_EVERY) {
            self.logged.insert((addr, kind), now);
            self.log(msg);
        }
    }

    fn chatter(&self, msg: &str) {
        if self.config.verbose {
            crate::log::line(&format!("net: {msg}"));
        }
    }

    /// Tests: whether to drop the next datagram, as a lossy network would.
    #[cfg(test)]
    fn lost(&self) -> bool {
        chance(&self.loss)
    }

    /// Tests: whether `drop_out` drops this message.
    #[cfg(test)]
    fn dropped(&self, msg: &Message) -> bool {
        self.drop_out.borrow_mut().as_mut().is_some_and(|f| f(msg))
    }

    /// Sends a datagram as encoded. Tests: one in `reorder` is held back
    /// and goes after the next.
    fn send_bytes(&self, addr: SocketAddr, bytes: &[u8]) {
        #[cfg(test)]
        {
            let before = self.held.borrow_mut().take();
            if before.is_none() && chance(&self.reorder) {
                *self.held.borrow_mut() = Some((addr, bytes.to_vec()));
                return;
            }
            self.send_raw(addr, bytes);
            if let Some((a, b)) = before {
                self.send_raw(a, &b);
            }
        }
        #[cfg(not(test))]
        self.send_raw(addr, bytes);
    }

    fn send_raw(&self, addr: SocketAddr, bytes: &[u8]) {
        if let Err(e) = self.socket.send_to(bytes, addr) {
            self.chatter(&format!("send to {addr} failed: {e}"));
        }
    }

    /// Tests: what the node is doing, for [`Seen::state`].
    #[cfg(test)]
    fn note_state(&self, now: Instant) {
        let tip = self.chain.tip().ok().flatten().map_or("none".to_string(), |t| t.height.to_string());
        let best = self.chain.best_header().map_or("none".to_string(), |b| b.height.to_string());
        let mut s = format!("mode {:?}, tip {tip}, best header {best}", self.mode);
        for d in self.downloads.values() {
            s += &format!(
                "; fetching {:?} {} from {}: {} of {} chunks, {} retries, last progress {:.1} s ago",
                d.kind,
                short(&d.id),
                d.from,
                d.received(),
                d.total().map_or("?".to_string(), |n| n.to_string()),
                d.retries,
                now.duration_since(d.last_progress).as_secs_f64()
            );
        }
        for (id, (b, from, _)) in &self.pending {
            s += &format!("; waiting for its parent: {} at height {} from {from:?}", short(id), b.header.height);
        }
        for id in &self.applying {
            s += &format!("; applying {}", short(id));
        }
        *self.seen.state.lock().unwrap() = Some((now, s));
    }

    /// Tests: sends the datagram held back for reordering, if any.
    #[cfg(test)]
    fn release_held(&self) {
        if let Some((a, b)) = self.held.borrow_mut().take() {
            self.send_raw(a, &b);
        }
    }

    /// Sends a message, giving a request the token its receiver gave us.
    fn send(&self, addr: SocketAddr, msg: &Message) {
        #[cfg(test)]
        if self.lost() || self.dropped(msg) {
            return;
        }
        let bytes = match msg.token() {
            Some(_) => msg.clone().with_token(self.peers.token(&addr)).encode(),
            None => msg.encode(),
        };
        self.send_bytes(addr, &bytes);
    }

    /// Sends a request with `token` in it, rather than the one the peer
    /// table holds: the token an offer, a session request or a handshake
    /// carried.
    fn send_with(&self, addr: SocketAddr, msg: Message, token: u64) {
        #[cfg(test)]
        if self.lost() || self.dropped(&msg) {
            return;
        }
        self.send_bytes(addr, &msg.with_token(token).encode());
    }

    /// The token `addr` must put in its requests: derived from the address
    /// with a secret of this node's, so it need not be remembered and
    /// nobody who did not receive it (at that address) can present it.
    fn token_for(&self, addr: &SocketAddr) -> u64 {
        std::hash::BuildHasher::hash_one(&self.token_key, addr)
    }

    /// Whether a request from `addr` carries `addr`'s token.
    fn request_ok(&self, addr: &SocketAddr, token: u64) -> bool {
        token == self.token_for(addr)
    }

    fn next_nonce(&mut self) -> u64 {
        self.nonce_count += 1;
        std::hash::BuildHasher::hash_one(&self.nonce_key, self.nonce_count)
    }

    /// Our status for `to`, with the token it must put in its requests.
    fn status(&self, to: &SocketAddr, nonce: u64) -> Status {
        let tip = self.chain.tip().ok().flatten();
        let pool = self.mempool.lock().unwrap();
        Status {
            nonce,
            version: PROTOCOL_VERSION,
            token: self.token_for(to),
            genesis: self.genesis,
            height: tip.map_or(0, |h| h.height),
            oldest: self.chain.oldest_body().unwrap_or_else(|_| tip.map_or(1, |h| h.height + 1)),
            tip: tip.map_or(self.genesis, |h| h.hash()),
            work: self.chain.tip_work().unwrap_or(U256::ZERO),
            min_fee: pool.policy().min_fee_per_byte,
            pool_fee: pool.admission_fee(crate::mempool::unix_now()),
        }
    }

    fn resolve_seeds(&mut self, now: Instant) {
        self.last_seed_lookup = Some(now);
        self.rv.reresolve();
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
        #[cfg(test)]
        self.release_held();
        #[cfg(test)]
        self.note_state(now);
        for addr in self.peers.prune(now) {
            self.log(&format!("{addr} never answered our pings; dropped from the peer table"));
        }
        self.logged.retain(|_, t| now.duration_since(*t) < LOG_EVERY);
        let (key, count) = (&self.nonce_key, &mut self.nonce_count);
        let due = self.peers.due_for_ping(now, || {
            *count += 1;
            std::hash::BuildHasher::hash_one(key, *count)
        });
        for (addr, n) in due {
            let st = self.status(&addr, n);
            self.send(addr, &Message::Ping(st));
        }
        if self.peers.live_count(now) < TARGET_PEERS {
            if self.last_seed_lookup.is_none_or(|t| now.duration_since(t) >= SEED_INTERVAL) && self.started != now {
                self.resolve_seeds(now);
            }
            if let Some(p) = self.peers.sample(1, None, now).first() {
                self.send(*p, &Message::GetPeers { token: 0 });
            }
        }
        let best_work = self.chain.best_header_work().unwrap_or(U256::ZERO);
        for addr in self.peers.expire_header_requests(best_work, now) {
            self.fork_probe.remove(&addr);
            self.log(&format!("{addr} sent no headers for the work it claims; passing it over"));
        }
        let stale = now.checked_sub(PENDING_TIMEOUT);
        self.pending.retain(|_, (_, _, at)| stale.is_none_or(|s| *at > s));
        match self.mode {
            Mode::Normal => {
                self.sync(now);
                self.aux_sync(now);
            }
            Mode::Headers => self.header_sync(now),
            Mode::Snapshot => {
                self.pump_headers(now);
                self.check_snapshot_target(now);
                // An abandoned snapshot goes back to header sync, not on.
                if self.mode == Mode::Snapshot {
                    self.snapshot_sync(now);
                }
            }
        }
        self.sessions_tick(now);
        self.circuits_tick(now);
        self.rendezvous_tick(now);
        // Behind: holding headers, their proof of work checked, with more
        // work than the tip, and their blocks coming in. A peer's claim of
        // work alone never holds the miner back (it costs nothing to make),
        // nor do headers whose blocks stop coming: mining a block on a stale
        // tip loses only that block.
        let tip_work = self.chain.tip_work().unwrap_or(U256::ZERO);
        let ahead = self.chain.best_header_work().unwrap_or(U256::ZERO) > tip_work;
        let generation = self.tip_changes.load(Ordering::Acquire);
        let behind = match self.catch_up {
            _ if !ahead => {
                self.catch_up = None;
                false
            }
            Some((g, since)) if g == generation => now.duration_since(since) < CATCH_UP_PATIENCE,
            _ => {
                self.catch_up = Some((generation, now));
                true
            }
        };
        // Just started, peers not heard yet: unless there are none to hear
        // (none configured).
        let expecting = !self.config.peers.is_empty() || !self.config.seeds.is_empty();
        let fresh =
            expecting && self.peers.live_count(now) == 0 && now.duration_since(self.started) < Duration::from_secs(5);
        self.syncing.store(self.mode != Mode::Normal || behind || fresh, Ordering::Release);
        if now.duration_since(self.last_save) >= SAVE_INTERVAL {
            self.last_save = now;
            let expired = self.mempool.lock().unwrap().expire(crate::mempool::unix_now());
            if !expired.is_empty() {
                self.log(&format!("{} transactions expired from the pool, unconfirmed", expired.len()));
            }
            self.save_peers();
            self.save_mempool();
        }
        let live: std::collections::HashSet<SocketAddr> = self.peers.live(now).map(|p| p.addr).collect();
        let peers = self
            .peers
            .all()
            .map(|p| PeerInfo {
                addr: p.addr,
                height: p.status.map(|s| s.height),
                min_fee: p.status.map(|s| s.min_fee),
                pool_fee: p.status.map(|s| s.pool_fee),
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
        let (mut rendezvous, sessions) = self.rv.summary(now);
        if !self.rv.init_active() {
            rendezvous.clear();
        }
        rendezvous.extend(self.onion_summary(now));
        *self.stats.lock().unwrap() = Stats {
            peers,
            downloads: self.downloads.len() + self.tx_downloads.len() + self.snap_downloads.len(),
            wanted,
            waiting: self.pending.len(),
            mode: Some(self.mode),
            parts,
            aux_wanted: self.aux_wants.len(),
            rendezvous,
            sessions: sessions + self.rdv.sessions(),
            channels: self.channels.count(),
            circuits: self.circuits.counts(),
            outbound_built: self.outbound_built(),
        };
    }

    /// Fetches headers while a peer claims more work than our best header,
    /// and the blocks of the best header's branch.
    fn sync(&mut self, now: Instant) {
        if self.alone && self.peers.trusted(now).any(|p| p.status.is_some_and(|s| s.height > 0)) {
            self.alone = false;
            // Only if nothing was replayed from genesis meanwhile.
            if self.mode == Mode::Normal && self.chain.tip().ok().flatten().is_some_and(|t| t.height == 0) {
                self.log("fast sync: a peer answered; fast-syncing after all");
                self.mode = Mode::Headers;
                return self.header_sync(now);
            }
        }
        self.pump_headers(now);
        self.start_downloads(now);
    }

    /// The header pipeline: verifies the complete batches at the best
    /// header in order, gives late ones to other peers, and asks for more,
    /// up to `HEADER_BATCHES` ahead, each of a different peer claiming
    /// more work, so one slow peer slows only its own share.
    fn pump_headers(&mut self, now: Instant) {
        let late: Vec<u32> = self
            .header_batches
            .iter()
            .filter(|(_, b)| !self.batch_complete(b) && now.duration_since(b.asked) >= BATCH_TIMEOUT)
            .map(|(s, _)| *s)
            .collect();
        for start in late {
            // A lost datagram: ask once more from the first height missing
            // before giving the batch to another peer.
            let b = self.header_batches.get_mut(&start).unwrap();
            if !b.retried {
                b.retried = true;
                b.asked = now;
                let from = (b.start..=b.end).find(|h| !b.headers.contains_key(h)).unwrap_or(b.start);
                let peer = b.peer;
                self.send(peer, &Message::GetHeadersFrom { height: from, token: 0 });
                self.peers.asked_headers(peer, now);
                continue;
            }
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
            self.send(peer, &Message::GetHeadersFrom { height: start, token: 0 });
            self.peers.asked_headers(peer, now);
            let end = height.min(start + step - 1);
            self.header_batches.insert(
                start,
                HeaderBatch {
                    start,
                    peer,
                    asked: now,
                    end,
                    headers: std::collections::BTreeMap::new(),
                    retried: false,
                },
            );
            start += step;
        }
        // A peer claiming more work at or below our best header's height
        // is on another branch, or lying: a locator finds the fork, and a
        // peer that sends nothing for its claim is passed over in time.
        let probes: Vec<SocketAddr> = free
            .iter()
            .filter(|(a, h)| *h <= best.height && !self.peers.awaiting_headers(a))
            .map(|(a, _)| *a)
            .collect();
        for peer in probes {
            self.request_headers(peer, now);
        }
    }

    /// `peer` sent a header dated more than the allowed drift past this
    /// node's clock. Not held against it: it is not passed over for the
    /// headers it could not give. With several peers doing so lately, the
    /// fault is likelier this node's clock, and the log says so.
    fn timestamp_too_new(&mut self, peer: SocketAddr, now: Instant) {
        const WINDOW: Duration = Duration::from_secs(600);
        self.peers.headers_arrived(peer);
        self.too_new.insert(peer, now);
        self.too_new.retain(|_, t| now.duration_since(*t) < WINDOW);
        if self.too_new.len() >= 2 && self.skew_said.is_none_or(|t| now.duration_since(t) >= WINDOW) {
            self.skew_said = Some(now);
            self.log(&format!(
                "{} peers sent headers dated in this node's future: its clock may be behind (check the system time)",
                self.too_new.len()
            ));
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
            let (new, stop) = self.chain.accept_headers_with(&headers, unix_now(), self.mode != Mode::Normal);
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
                Some(ChainError::TimestampTooNew { .. }) => return self.timestamp_too_new(b.peer, now),
                Some(ChainError::SetAside) => {
                    self.header_batches.clear();
                    return;
                }
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
                self.send(to, &Message::GetHeaders { locator, token: 0 });
            }
            Err(e) => self.log(&format!("header locator: {e}")),
        }
    }

    /// Asks `to` for the headers after `from`, a header of its branch we
    /// hold, falling back to our main chain's locator.
    fn continue_headers(&mut self, to: SocketAddr, from: Digest, now: Instant) {
        match self.chain.header_locator() {
            Ok(mut locator) => {
                locator.insert(0, from);
                locator.truncate(32);
                self.chatter(&format!("asking {to} for more of its branch"));
                self.peers.asked_headers(to, now);
                self.send(to, &Message::GetHeaders { locator, token: 0 });
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
            if self.unfollowable.contains(&header.hash()) {
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
                // Least loaded; then one that has delivered blocks before
                // one that only claims work, then the most work.
                .min_by_key(|p| (load(&p.addr), p.delivered == 0, std::cmp::Reverse(p.status.unwrap().work)))
                .map(|p| p.addr)
        };
        // Peers passed over after a failure only if no other holds it; the
        // one that announced it first among them (a failure may have been
        // for a block of another branch, and its height is as of its last
        // ping).
        let announcer = self
            .sources
            .get(id)
            .filter(|a| self.peers.may_serve_passed_over(a, now) && load(a) < MAX_PER_PEER)
            .copied();
        pick(false).or(announcer).or_else(|| pick(true))
    }

    /// Remembers that `from` sent block `id`'s header, unless another
    /// peer did first.
    fn note_source(&mut self, id: Digest, from: SocketAddr) {
        if self.sources.len() >= MAX_SOURCES {
            self.sources.clear();
        }
        self.sources.entry(id).or_insert(from);
    }

    /// Remembers that `from` announced block `id`: it holds the body,
    /// which a peer that only passed on the header (on a branch of its
    /// own) may not, so it becomes the source.
    fn note_announcer(&mut self, id: Digest, from: SocketAddr) {
        if self.sources.len() >= MAX_SOURCES {
            self.sources.clear();
        }
        self.sources.insert(id, from);
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
            Kind::Consensus => consensus::MAX_CONSENSUS,
            Kind::Object => crate::onion::MAX_OBJECT,
        };
        let len = if kind == Kind::Block { self.sizes.get(&id).copied() } else { None };
        let mut d = Download::new(kind, id, from, max_len, len, self.path_to(&from), now);
        let indexes = d.request(now);
        for msg in net::chunk_requests(kind, id, &indexes) {
            self.send(from, &msg);
        }
        self.chatter(&format!("fetching {kind:?} {} from {from} ({} chunks asked)", short(&id), indexes.len()));
        match kind {
            Kind::Tx => self.tx_downloads.insert(id, d),
            _ => self.downloads.insert(id, d),
        };
    }

    /// The window to start a download from `peer` with.
    fn path_to(&self, peer: &SocketAddr) -> net::PeerPath {
        self.paths.get(peer).copied().unwrap_or_default()
    }

    /// Keeps what a download learned of the path to its peer, and its
    /// round-trip sample.
    fn learn_path(&mut self, peer: SocketAddr, path: net::PeerPath, sample: Option<Duration>) {
        if self.paths.len() > 4 * net::MAX_PEERS && !self.paths.contains_key(&peer) {
            self.paths.clear();
        }
        self.paths.insert(peer, path);
        if let Some(s) = sample {
            self.peers.rtt_sample(&peer, s);
        }
    }

    fn retry_downloads(&mut self, now: Instant) {
        let retry = |a: &SocketAddr| self.peers.retry(a);
        let (mut requests, blocks) = stalled(&mut self.downloads, now, retry);
        let (tx_requests, txs) = stalled(&mut self.tx_downloads, now, retry);
        // A stall is a loss: the halved windows are kept.
        let learned: Vec<(SocketAddr, net::PeerPath)> =
            self.downloads.values().filter(|d| d.retries > 0).map(|d| (d.from, d.path())).collect();
        for (from, path) in learned {
            self.learn_path(from, path, None);
        }
        requests.extend(tx_requests);
        for (to, msg) in requests {
            self.send(to, &msg);
        }
        // A transaction gone from its pool, or a slow link: no fault.
        for id in txs {
            if let Some(d) = self.tx_downloads.remove(&id) {
                self.log(&format!("gave up fetching transaction {} from {}", short(&id), d.from));
            }
        }
        if blocks.is_empty() {
            return;
        }
        for id in blocks {
            let Some(d) = self.downloads.remove(&id) else { continue };
            if d.kind == Kind::Consensus {
                // A peer may simply not hold the file: asked elsewhere.
                self.chatter(&format!("{} did not serve the consensus file; asking another peer", d.from));
                self.file_failed.insert(d.from);
                continue;
            }
            self.log(&format!("gave up fetching block {} from {}; trying another peer", short(&id), d.from));
            // It may lack old bodies (pruned, or fast-synced), or be slow,
            // or the fault may be on our side: pass it over for a while.
            // Strikes are for bad data, not for silence.
            self.peers.fetch_failed(d.from, now);
            if self.sources.get(&id) == Some(&d.from) {
                self.sources.remove(&id);
            }
        }
        self.start_downloads(now);
    }

    fn handle_packet(&mut self, addr: SocketAddr, bytes: &[u8]) {
        // Anyone can forge a source address: nothing that arrives unasked
        // counts against the peer it names, and beyond a ping or pong only
        // peers that answered our ping, or requests carrying the token we
        // gave their address, are heard.
        let Some(msg) = Message::decode(bytes) else {
            self.chatter(&format!(
                "{addr} sent {} bytes that are not a message; another protocol version?",
                bytes.len()
            ));
            return;
        };
        let now = Instant::now();
        // A request proves its address with its token; anything else
        // unasked for is heard only from a peer that answered our ping.
        // Chunks of a message-layer object come from whoever was asked
        // for them with the token its offer carried, in our table or not.
        let asked = match &msg {
            Message::Chunk { kind: Kind::Object, id, .. } => self.rv.downloads.get(id).is_some_and(|d| d.from == addr),
            // Frames are sealed: one that is not ours does not open.
            Message::Frame(f) => self.channels.knows(&addr, f.chan),
            // Only about what we are fetching from that address.
            Message::NotHeld { kind, id } => {
                let downloads = if *kind == Kind::Tx { &self.tx_downloads } else { &self.downloads };
                downloads.get(id).is_some_and(|d| d.from == addr && d.kind == *kind)
            }
            // Only about a channel we have with that address.
            Message::ChannelGone { chan } => {
                self.channels.knows(&addr, *chan) || self.channels.opening(&addr, *chan)
            }
            _ => false,
        };
        if !matches!(msg, Message::Ping(_) | Message::Pong(_))
            && msg.token().is_none()
            && !asked
            && !self.peers.handshaken(&addr)
        {
            let state = match self.peers.get(&addr) {
                Some(_) => "it has not answered our ping yet".to_string(),
                None => match self.peers.refusal(&addr) {
                    Some(why) => format!("not in our peer table: {why}"),
                    None => "not in our peer table (it has not pinged us)".to_string(),
                },
            };
            // A frame for a channel we do not have (we closed it, or
            // restarted): the other end is told, not left to time out.
            if let Message::Frame(f) = &msg {
                return self.channel_unknown(addr, f.chan, now);
            }
            let text = format!("{addr} sent {}, not heard: {state}", message_name(&msg));
            self.log_every(addr, "unheard", &text, now);
            return;
        }
        match msg {
            Message::Ping(st) => {
                if st.version != PROTOCOL_VERSION {
                    // Answer, so the other side can see why; not a peer.
                    self.chatter(&format!("{addr} speaks protocol v{}, ours is v{PROTOCOL_VERSION}", st.version));
                    self.send(addr, &Message::Pong(self.status(&addr, st.nonce)));
                    return;
                }
                if st.genesis != self.genesis {
                    // Answer, so the other side can see why we will not
                    // talk to it. (Its pong to our ping, which proves the
                    // address, is what drops it.)
                    self.chatter(&format!("{addr} is on another chain"));
                    self.send(addr, &Message::Pong(self.status(&addr, st.nonce)));
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
                } else if let Some(why) = self.peers.refusal(&addr) {
                    let text = format!("{addr} pinged us but is not taken as a peer: {why}");
                    self.log_every(addr, "refused", &text, now);
                } else {
                    self.peers.add(addr, false);
                }
                let reply = self.status(&addr, st.nonce);
                self.send(addr, &Message::Pong(reply));
                // Complete the handshake from our side at once, within the
                // budget for unverified addresses.
                if !self.peers.handshaken(&addr) {
                    let nonce = self.next_nonce();
                    if self.peers.ping_now(addr, nonce, now) {
                        let ping = self.status(&addr, nonce);
                        self.send(addr, &Message::Ping(ping));
                    }
                }
                self.consider(addr, &st, now);
            }
            Message::Pong(st) => {
                if st.version != PROTOCOL_VERSION {
                    if self.peers.pong(addr, st) {
                        self.log(&format!(
                            "{addr} speaks protocol v{}, ours is v{PROTOCOL_VERSION}; is one of us out of date?",
                            st.version
                        ));
                        self.peers.remove(&addr);
                    }
                    return;
                }
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
                    // It missed the first announcements of what we pool.
                    let n = self.announce_pool_to(addr, &st);
                    if n > 0 {
                        self.log(&format!("{n} pooled transactions announced to {addr}"));
                    }
                }
                self.consider(addr, &st, now);
            }
            Message::GetPeers { token } => {
                if !self.request_ok(&addr, token) {
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
            Message::GetHeaders { locator, token } => {
                if !self.request_ok(&addr, token) {
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
            Message::GetHeadersFrom { height, token } => {
                if !self.request_ok(&addr, token) {
                    return;
                }
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
            Message::GetProof { position, token } => {
                if !self.request_ok(&addr, token) {
                    return;
                }
                self.peers.seen(addr, now);
                match proof_messages(&self.chain, position) {
                    Ok(Some(msgs)) => {
                        for m in msgs {
                            self.send(addr, &m);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => self.log(&format!("proof: {e}")),
                }
            }
            Message::Proof { position, tip, commitment, memo, amount, created, part, siblings } => {
                self.peers.seen(addr, now);
                let memo = crate::transaction::memo_slot(&memo, amount);
                // Two parts, the second completing the path; checked against
                // the header the proof names, if we have it.
                let key = (addr, position, tip);
                let entry = self.proof_parts.entry(key).or_insert([None, None]);
                entry[part as usize] = Some((commitment, memo, created, siblings));
                if let [Some(a), Some(b)] = entry.clone() {
                    self.proof_parts.remove(&key);
                    let mut siblings = a.3.clone();
                    siblings.extend(b.3);
                    let ok = a.0 == b.0
                        && a.1 == b.1
                        && a.2 == b.2
                        && self
                            .chain
                            .header_by_hash(&tip)
                            .ok()
                            .flatten()
                            .is_some_and(|h| verify_proof(&h.state_root, position, &a.0, &a.1, a.2, &siblings));
                    self.log(&format!(
                        "proof of position {position} after {} from {addr}: {}",
                        short(&tip),
                        if ok { "verified" } else { "invalid" }
                    ));
                    if ok {
                        self.proofs_verified.fetch_add(1, Ordering::Relaxed);
                    }
                } else if self.proof_parts.len() > 64 {
                    self.proof_parts.clear();
                }
            }
            Message::Headers(headers) => {
                self.peers.seen(addr, now);
                self.handle_headers(addr, headers, now);
            }
            Message::Inv(header, len) => {
                self.peers.seen(addr, now);
                self.handle_inv(addr, header, len, now);
            }
            Message::TxInv(txid) => {
                self.peers.seen(addr, now);
                // Transactions wait until we have caught up: checked
                // against an old state, they would mostly fail.
                let tip_work = self.chain.tip_work().unwrap_or(U256::ZERO);
                if self.mode != Mode::Normal || self.peers.claimants(tip_work, now).next().is_some() {
                    let text = format!("transaction {} from {addr} not fetched: we are catching up", short(&txid));
                    self.log_every(addr, "txinv-behind", &text, now);
                    return;
                }
                let from_peer = self.tx_downloads.values().filter(|d| d.from == addr).count();
                if self.tx_downloads.len() < MAX_TX_DOWNLOADS
                    && from_peer < MAX_TX_PER_PEER
                    && !self.mempool.lock().unwrap().contains(&txid)
                {
                    self.log(&format!("fetching transaction {} from {addr}", short(&txid)));
                    self.start_download(Kind::Tx, txid, addr, now);
                }
            }
            Message::GetChunks { kind, id, indexes, token } => {
                if !self.request_ok(&addr, token) {
                    return;
                }
                self.peers.seen(addr, now);
                self.serve_chunks(addr, kind, id, &indexes);
            }
            Message::Chunk { kind, id, len, index, data } => {
                self.peers.seen(addr, now);
                self.handle_chunk(addr, kind, id, len, index, data, now);
            }
            Message::GetAux { id, token } => {
                if !self.request_ok(&addr, token) {
                    return;
                }
                self.peers.seen(addr, now);
                if let Ok(Some(leaves)) = self.chain.aux_leaves_of(&id) {
                    self.send(addr, &Message::Aux { id, leaves });
                }
            }
            Message::Aux { id, leaves } => {
                self.peers.seen(addr, now);
                let Some(want) = self.aux_wants.get_mut(&id) else {
                    return;
                };
                match self.chain.put_aux_leaves(&id, &leaves) {
                    Ok(()) => {
                        self.aux_wants.remove(&id);
                        self.chatter(&format!("aux leaves of block {} from {addr}", short(&id)));
                        // Count the vote.
                        self.last_aux_scan = None;
                    }
                    Err(ChainError::AuxMismatch) => {
                        want.asked = None;
                        self.log(&format!("{addr} sent aux leaves that do not match block {}", short(&id)));
                        self.peers.strike(addr);
                    }
                    Err(e) => self.log(&format!("keeping aux leaves of {}: {e}", short(&id))),
                }
            }
            Message::Session { id, back, token } => {
                if self.request_ok(&addr, token) {
                    self.on_session(addr, id, back, now);
                }
            }
            Message::SessionState { id, nonce, seq } => self.on_session_state(addr, id, nonce, seq, now),
            Message::GetAnnounce { id, back, token } => {
                if self.request_ok(&addr, token) {
                    self.on_get_announce(addr, id, back, now);
                }
            }
            Message::Offer { object, len, back, token } => {
                if self.request_ok(&addr, token) {
                    self.on_offer(addr, object, len, back, now);
                }
            }
            Message::Notice { subject, code } => self.on_notice(addr, subject, code, now),
            Message::Handshake { chan, stage, index, count, data, back, token } => {
                if self.request_ok(&addr, token) {
                    self.on_handshake(addr, chan, stage, index, count, data, back, now);
                }
            }
            Message::Frame(f) => self.on_frame(addr, f, now),
            Message::ChannelGone { chan } => self.on_channel_gone(addr, chan, now),
            Message::NotHeld { kind, id } => {
                let downloads = if kind == Kind::Tx { &mut self.tx_downloads } else { &mut self.downloads };
                if let Some(d) = downloads.get_mut(&id)
                    && d.from == addr
                    && d.kind == kind
                {
                    d.not_held = true;
                    self.chatter(&format!("{addr} does not hold {}; asking another peer", short(&id)));
                    self.retry_downloads(now);
                }
            }
            Message::Goodbye { token } => {
                // Only from that address: it carries the token we gave it.
                if self.request_ok(&addr, token) && self.peers.get(&addr).is_some() {
                    self.peers.remove(&addr);
                    self.log(&format!("peer {addr} is shutting down; dropped from the peer table"));
                }
            }
        }
    }

    /// Wants the aux leaves of a block whose header has a nonzero aux root,
    /// unless they are held already or are this node's own (a block mined
    /// here, or by a peer with the same leaves).
    fn want_aux(&mut self, header: &Header, from: Option<SocketAddr>) {
        if header.aux == [0u8; 32] {
            return;
        }
        let id = header.hash();
        match self.chain.aux_leaves_of(&id) {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(e) => return self.log(&format!("aux leaves of {}: {e}", short(&id))),
        }
        if let Ok(leaves) = self.chain.aux_leaves()
            && aux_merkle_root(&leaves) == header.aux
        {
            match self.chain.put_aux_leaves(&id, &leaves) {
                Ok(()) => {
                    self.last_aux_scan = None;
                    return;
                }
                Err(e) => self.log(&format!("keeping our aux leaves for {}: {e}", short(&id))),
            }
        }
        self.aux_wants.entry(id).or_insert(AuxWant {
            height: header.height,
            from,
            asked: None,
            tries: 0,
            tried: Vec::new(),
        });
    }

    /// Fetches the aux leaves of the window's blocks that lack them and the
    /// consensus file the window names (`docs/ONION.md`).
    fn aux_sync(&mut self, now: Instant) {
        let changes = self.tip_changes.load(Ordering::Acquire);
        if self.last_aux_scan.is_none_or(|t| now.duration_since(t) >= AUX_SCAN) || changes != self.aux_scanned_at {
            self.last_aux_scan = Some(now);
            self.aux_scanned_at = changes;
            match (self.chain.consensus_epoch(), self.chain.consensus()) {
                (Ok(epoch), Ok((votes, running))) => {
                    let block_time = Duration::from_secs(self.chain.params().schedule.block_time.max(1) as u64);
                    self.rv.set_epoch(&epoch, block_time, now);
                    let current = &epoch.current;
                    let decided = (
                        epoch.boundary,
                        current.winner.map(|w| w.0),
                        current.mode,
                        epoch.previous.is_some(),
                        epoch.prefer_current,
                    );
                    if self.last_consensus != Some(decided) {
                        let first = self.last_consensus.is_none();
                        let changed = self.last_consensus.is_none_or(|l| (l.1, l.2) != (decided.1, decided.2));
                        let was_switching = self.last_consensus.is_some_and(|l| l.3);
                        self.last_consensus = Some(decided);
                        let by = match &current.winner {
                            None if epoch.votes.counts.is_empty() => "no block of its window voted".to_string(),
                            None => {
                                format!("none of the {} files its window voted for counts", epoch.votes.counts.len())
                            }
                            Some((h, n)) => format!(
                                "file {} with {n} of its window's {} votes{}",
                                consensus::hex(h),
                                epoch.votes.blocks,
                                current.file.as_ref().map_or(String::new(), |f| format!(", {} relays", f.relays.len()))
                            ),
                        };
                        if changed || first {
                            self.log(&format!("consensus: {} mode from block {}: {by}", current.mode, epoch.boundary));
                            for (h, n, why) in &current.skipped {
                                self.log(&format!(
                                    "consensus: file {} with {n} votes does not count: {why}",
                                    consensus::hex(h)
                                ));
                            }
                        }
                        match &epoch.previous {
                            Some(p) => self.log(&format!(
                                "consensus: switching from {} mode until block {}; the new file is tried first {}",
                                p.mode,
                                epoch.boundary + consensus::GRACE - 1,
                                if epoch.prefer_current {
                                    "now".to_string()
                                } else {
                                    format!("from block {}", epoch.boundary + consensus::SWITCH)
                                }
                            )),
                            None if was_switching => self.log("consensus: the switch is done"),
                            None => {}
                        }
                    }
                    // Leaves for both windows: the one that decided, and the
                    // running count for the next boundary.
                    for (id, _) in epoch.votes.missing.iter().chain(&votes.missing) {
                        if let Ok(Some(header)) = self.chain.header_by_hash(id) {
                            self.want_aux(&header, None);
                        }
                    }
                    // Files voted for more than the one that counts, the
                    // deciding window's first, most voted first, passing over
                    // those no peer served lately.
                    let unavailable = &self.file_unavailable;
                    let want = current
                        .unfetched()
                        .chain(running.unfetched())
                        .find(|h| unavailable.get(*h).is_none_or(|t| now.duration_since(*t) >= FILE_BACKOFF))
                        .copied();
                    if want != self.file_want {
                        self.file_failed.clear();
                        if let Some(hash) = want {
                            let n =
                                running.skipped.iter().chain(&current.skipped).find(|s| s.0 == hash).map_or(0, |s| s.1);
                            self.log(&format!("consensus: file {} has {n} votes; fetching it", consensus::hex(&hash)));
                        }
                    }
                    self.file_want = want;
                }
                (Err(e), _) | (_, Err(e)) => self.log(&format!("counting aux votes: {e}")),
            }
        }
        let peers: Vec<(SocketAddr, u32)> =
            self.peers.live(now).map(|p| (p.addr, p.status.map_or(0, |s| s.height))).collect();
        if peers.is_empty() {
            return;
        }
        let live: Vec<SocketAddr> = peers.iter().map(|(a, _)| *a).collect();
        // Leaves: the block's sender first, then each live peer that has
        // the block in turn.
        let mut requests = Vec::new();
        let mut given_up = Vec::new();
        for (id, w) in self.aux_wants.iter_mut() {
            if w.asked.is_some_and(|t| now.duration_since(t) < AUX_RETRY) || requests.len() >= AUX_REQUESTS_PER_TICK {
                continue;
            }
            if w.tries >= AUX_MAX_TRIES {
                given_up.push(*id);
                continue;
            }
            // The sender has it whatever its last status said; then peers
            // whose status reaches the block; then any, as statuses age.
            let able: Vec<SocketAddr> = peers.iter().filter(|(_, h)| *h >= w.height).map(|(a, _)| *a).collect();
            let peer = w
                .from
                .take()
                .filter(|a| live.contains(a))
                .or_else(|| able.iter().find(|a| !w.tried.contains(a)).copied())
                .or_else(|| live.iter().find(|a| !w.tried.contains(a)).copied())
                .or_else(|| live.get(w.tries as usize % live.len()).copied());
            if let Some(p) = peer {
                w.asked = Some(now);
                w.tries += 1;
                w.tried.push(p);
                requests.push((p, *id));
            }
        }
        for id in given_up {
            self.aux_wants.remove(&id);
        }
        for (p, id) in requests {
            self.send(p, &Message::GetAux { id, token: 0 });
        }
        // The file, from a peer that has not failed to serve it.
        if let Some(hash) = self.file_want {
            let id = consensus::file_id(&hash);
            if !self.downloads.contains_key(&id) {
                match live.iter().find(|a| !self.file_failed.contains(a)).copied() {
                    Some(from) => self.start_download(Kind::Consensus, id, from, now),
                    None => {
                        // No live peer serves it: it counts for nothing
                        // for a while, and the next is fetched.
                        self.log(&format!(
                            "consensus: no peer serves file {}; passing it over for now",
                            consensus::hex(&hash)
                        ));
                        self.file_unavailable.insert(hash, now);
                        self.file_want = None;
                        self.file_failed.clear();
                        self.last_aux_scan = None;
                    }
                }
            }
        }
    }

    /// A peer's status: if a trusted peer claims more work than our best
    /// header, fetch headers now rather than at the next tick.
    fn consider(&mut self, addr: SocketAddr, st: &Status, now: Instant) {
        if self.peers.handshaken(&addr) && st.work > self.chain.best_header_work().unwrap_or(U256::ZERO) {
            self.pump_headers(now);
        }
    }

    /// Headers from `from`: into the batch it was asked for, or, if none
    /// (a reply to a locator), checked and stored at once.
    fn handle_headers(&mut self, from: SocketAddr, headers: Vec<Header>, now: Instant) {
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
            // Complete, it has answered, even if it waits behind slower
            // batches before it is verified.
            if (b.1.start..=b.1.end).all(|h| b.1.headers.contains_key(&h)) {
                self.peers.headers_arrived(from);
            }
        } else {
            let before = self.chain.best_header_work().unwrap_or(U256::ZERO);
            let (new, stop) = self.chain.accept_headers_with(&headers, unix_now(), self.mode != Mode::Normal);
            for h in headers.iter().take(new) {
                self.note_source(h.hash(), from);
            }
            let mut refused = false;
            match stop {
                None => {}
                Some(ChainError::TimestampTooNew { .. }) => self.timestamp_too_new(from, now),
                // A reply comes in several datagrams, which may arrive out
                // of order or not at all: a header whose parent is still on
                // its way is no fault.
                Some(ChainError::UnknownParent(_)) => refused = true,
                // A branch this node cannot follow: no fault of the peer.
                Some(ChainError::SetAside) => refused = true,
                Some(e) => {
                    refused = true;
                    self.log(&format!("headers from {from} refused: {e}"));
                    self.peers.strike(from);
                }
            }
            if self.chain.best_header_work().unwrap_or(U256::ZERO) > before {
                self.peers.headers_arrived(from);
                self.fork_probe.remove(&from);
                // The fork is found: the pipeline goes on from here.
                if headers.len() == net::HEADERS_PER_MESSAGE {
                    self.request_headers(from, now);
                }
            } else if !refused
                && headers.len() == net::HEADERS_PER_MESSAGE
                && let Some(last) = headers.last()
                && self.peers.awaiting_headers(&from)
                && self.fork_probe.get(&from).is_none_or(|&p| last.height >= p + MAX_HEADERS as u32)
            {
                // Its branch so far is no heavier than ours, and a locator
                // from our main chain would bring these same headers again:
                // continue from the last one, one request per reply.
                self.fork_probe.insert(from, last.height);
                self.continue_headers(from, last.hash(), now);
            }
        }
        match self.mode {
            Mode::Headers => self.header_sync(now),
            _ => self.sync(now),
        }
    }

    /// A block announced: its header is checked and stored before the
    /// block is fetched. During a snapshot sync only the header is taken,
    /// to keep the snapshot within peers' windows.
    fn handle_inv(&mut self, from: SocketAddr, header: Header, len: u32, now: Instant) {
        if self.mode == Mode::Headers {
            return;
        }
        let id = header.hash();
        if self.have_block(&id) || self.pending.contains_key(&id) || self.applying.contains(&id) {
            return;
        }
        // On its way already, perhaps from a peer that has the header
        // alone: the announcer is asked if that fails.
        if self.downloads.contains_key(&id) {
            return self.note_announcer(id, from);
        }
        match self.chain.accept_header(&header, unix_now()) {
            Ok(_) => {
                self.note_announcer(id, from);
                if self.sizes.len() >= MAX_SOURCES {
                    self.sizes.clear();
                }
                // The size as announced; the first chunk must agree.
                self.sizes.entry(id).or_insert(len);
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
            Err(ChainError::KnownInvalid | ChainError::SetAside | ChainError::TimestampTooNew { .. }) => {}
            Err(e) => {
                self.chatter(&format!("{from} announced a bad header {}: {e}", short(&id)));
                self.peers.strike(from);
            }
        }
    }

    fn serve_chunks(&mut self, to: SocketAddr, kind: Kind, id: Digest, indexes: &[u16]) {
        let mut wanted = indexes.len().min(MAX_IN_FLIGHT);
        if kind != Kind::Object {
            let now = Instant::now();
            if self.serve_budget.len() > 4 * net::MAX_PEERS {
                self.serve_budget.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(10));
            }
            let (tokens, at) = self.serve_budget.entry(to).or_insert((SERVE_BURST, now));
            *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * SERVE_RATE).min(SERVE_BURST);
            *at = now;
            // As many as the budget allows, the first asked first: the rest
            // the peer takes for lost and asks again with a smaller window.
            wanted = wanted.min(*tokens as usize);
            if wanted == 0 {
                return;
            }
            *tokens -= wanted as f64;
        }
        let bytes: Arc<Vec<u8>> = match kind {
            Kind::Tx => match self.mempool.lock().unwrap().get(&id) {
                Some(tx) => Arc::new(tx.to_bytes()),
                None => return self.send(to, &Message::NotHeld { kind, id }),
            },
            Kind::Block => match self.served.iter().position(|(i, _)| *i == id) {
                Some(pos) => {
                    let entry = self.served.remove(pos).unwrap();
                    self.served.push_front(entry);
                    Arc::clone(&self.served.front().unwrap().1)
                }
                None => match self.chain.block_bytes(&id) {
                    Ok(Some(bytes)) => {
                        let bytes = Arc::new(bytes);
                        self.served.push_front((id, Arc::clone(&bytes)));
                        self.served.truncate(SERVED_CACHE);
                        bytes
                    }
                    _ => return self.send(to, &Message::NotHeld { kind, id }),
                },
            },
            Kind::Manifest | Kind::Part(_) => match self.snapshot_bytes(kind, &id) {
                Some(b) => b,
                None => return self.send(to, &Message::NotHeld { kind, id }),
            },
            Kind::Consensus => match self.chain.consensus_file_by_id(&id) {
                Ok(Some(b)) => Arc::new(b),
                _ => return self.send(to, &Message::NotHeld { kind, id }),
            },
            Kind::Object => return self.serve_object(to, &id, indexes),
        };
        for &i in indexes.iter().take(wanted) {
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
        if kind == Kind::Object {
            return self.on_object_chunk(from, id, len, index, data, now);
        }
        if matches!(kind, Kind::Manifest | Kind::Part(_)) || self.snap_downloads.contains_key(&(kind, id)) {
            return self.handle_snapshot_chunk(from, kind, id, len, index, data, now);
        }
        let downloads = if kind == Kind::Tx { &mut self.tx_downloads } else { &mut self.downloads };
        let Some(d) = downloads.get_mut(&id) else {
            return;
        };
        if d.from != from || d.kind != kind {
            return;
        }
        let done = d.insert(len, index, data, now);
        let (path, sample) = (d.path(), d.take_sample());
        let refill = match done {
            // Topped up as chunks arrive (`net::REFILL`).
            Ok(false) if d.wants_refill() => d.request(now),
            _ => Vec::new(),
        };
        self.learn_path(from, path, sample);
        for msg in net::chunk_requests(kind, id, &refill) {
            self.send(from, &msg);
        }
        let downloads = if kind == Kind::Tx { &mut self.tx_downloads } else { &mut self.downloads };
        match done {
            Ok(false) => {}
            Ok(true) => {
                let Some(d) = downloads.remove(&id) else { return };
                let bytes = d.assemble().unwrap_or_default();
                match kind {
                    Kind::Block => match Block::from_bytes(&bytes) {
                        Ok(block) if block.header.hash() == id => {
                            self.peers.delivered(from);
                            self.receive_block(block, from)
                        }
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
                    Kind::Consensus => match self.file_want {
                        Some(hash) if consensus::file_id(&hash) == id && consensus::file_matches(&hash, &bytes) => {
                            match self.chain.put_consensus_file(&bytes) {
                                Ok(_) => {
                                    let verdict = match consensus::File::parse(&bytes) {
                                        Ok(f) => format!("mode {}", f.mode),
                                        Err(e) => format!("invalid, so ignored: {e}"),
                                    };
                                    self.log(&format!(
                                        "consensus: fetched file {} ({} bytes) from {from}: {verdict}",
                                        consensus::hex(&hash),
                                        bytes.len()
                                    ));
                                    self.file_want = None;
                                    self.last_aux_scan = None;
                                }
                                Err(e) => self.log(&format!("keeping the consensus file: {e}")),
                            }
                        }
                        _ => {
                            self.log(&format!("{from} sent a consensus file that is not the one asked for"));
                            self.peers.strike(from);
                            self.file_failed.insert(from);
                        }
                    },
                    Kind::Manifest | Kind::Part(_) | Kind::Object => {}
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
            Outcome::Part { index, from, result } => {
                self.record_part(index, from, result);
                self.run_deferred();
                self.snapshot_sync(Instant::now());
            }
            Outcome::Carry { indexes, result } => {
                let carried = self.record_carry(indexes, result);
                self.run_deferred();
                match carried {
                    Ok(()) => self.snapshot_sync(Instant::now()),
                    Err(why) => self.restart_snapshot(&why),
                }
            }
        }
    }

    /// A fast-sync part checked and stored, or refused.
    fn record_part(&mut self, index: u32, from: SocketAddr, result: Result<(), ChainError>) {
        let Some(snap) = self.snap.as_mut() else { return };
        if !snap.staging.remove(&index) {
            return;
        }
        match result {
            Ok(()) => {
                if let Some(p) = snap.parts.get_mut(index as usize) {
                    *p = true;
                }
                #[cfg(test)]
                self.parts_staged.fetch_add(1, Ordering::Relaxed);
            }
            // Only a part that fails its checks is the peer's fault; a
            // local error (the database, a snapshot no longer staging) is
            // not, and the part is fetched again.
            Err(ChainError::BadSnapshot) => {
                self.log(&format!("fast sync: part {index} from {from} refused: {}", ChainError::BadSnapshot));
                self.peers.strike(from);
                self.peers.fetch_failed(from, Instant::now());
            }
            Err(e) => self.log(&format!("fast sync: storing part {index}: {e}")),
        }
    }

    /// Staged parts carried forward, or those that were not cleared, to be
    /// fetched. An error leaves the staged state unknown: start over.
    fn record_carry(&mut self, indexes: Vec<u32>, result: Result<Vec<bool>, ChainError>) -> Result<(), String> {
        let Some(snap) = self.snap.as_mut() else { return Ok(()) };
        for i in &indexes {
            snap.staging.remove(i);
        }
        let carried = result.map_err(|e| format!("carrying the staged parts forward failed: {e}"))?;
        for (i, ok) in indexes.iter().zip(carried) {
            if let Some(p) = snap.parts.get_mut(*i as usize) {
                *p = ok;
            }
        }
        Ok(())
    }

    /// Waits for the parts with the applier, recording what became of
    /// them; blocks applied meanwhile are taken too.
    /// Holds `change` back while parts are with the applier, returning
    /// whether it did: downloads stop, and [`Node::run_deferred`] makes the
    /// change once they have landed. A restart supersedes a move.
    fn defer(&mut self, change: Deferred) -> bool {
        if self.snap.as_ref().is_none_or(|s| s.staging.is_empty()) {
            return false;
        }
        self.snap_downloads.clear();
        self.deferred = match (self.deferred.take(), change) {
            (Some(d @ (Deferred::Restart(_) | Deferred::Abandon(_))), Deferred::Move(..)) => Some(d),
            (Some(Deferred::Abandon(w)), Deferred::Restart(_)) => Some(Deferred::Abandon(w)),
            (_, c) => Some(c),
        };
        true
    }

    /// Makes the deferred change once the applier holds no part.
    fn run_deferred(&mut self) {
        if self.snap.as_ref().is_some_and(|s| !s.staging.is_empty()) {
            return;
        }
        match self.deferred.take() {
            None => {}
            Some(Deferred::Move(target, why)) => self.move_snapshot(*target, &why),
            Some(Deferred::Restart(why)) => self.restart_snapshot(&why),
            Some(Deferred::Abandon(why)) => self.abandon_snapshot(&why),
        }
    }

    /// Starts over from header sync: the snapshot block left the best
    /// chain.
    fn abandon_snapshot(&mut self, why: &str) {
        if self.defer(Deferred::Abandon(why.to_string())) {
            return;
        }
        self.restart_snapshot(why);
        if self.mode == Mode::Snapshot {
            self.snap = None;
            self.mode = Mode::Headers;
        }
        #[cfg(test)]
        {
            self.seen.abandoned.fetch_add(1, Ordering::Relaxed);
            self.moved = true;
        }
    }

    fn on_applied(&mut self, block: Block, from: Option<SocketAddr>, result: Result<Applied, ChainError>) {
        let id = block.header.hash();
        let height = block.header.height;
        let header = block.header;
        self.applying.remove(&id);
        if from.is_none()
            && let Err(e) = &result
        {
            *self.refused.lock().unwrap() = Some((id, e.to_string()));
        }
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
                let fork = match applied {
                    Applied::Reorganized { fork_height, .. } => Some(fork_height),
                    _ => None,
                };
                self.tip_changes.fetch_add(1, Ordering::Release);
                let told = self.announce(&block, from);
                if from.is_none() {
                    self.log(&format!("announced block {height} to {told} peers"));
                }
                self.revalidate_mempool(fork);
                true
            }
            Err(ChainError::UnknownParent(_) | ChainError::MissingBody) => {
                // A body of its branch is still on its way.
                if self.pending.len() < LOOKAHEAD {
                    self.pending.insert(id, (block, from, Instant::now()));
                }
                false
            }
            Err(e @ (ChainError::BelowSnapshot | ChainError::BeyondUndo)) => {
                // The best header's branch forks below what this node can
                // unwind: it will not be fetched again until restarted.
                if self.unfollowable.insert(id) {
                    self.log(&format!(
                        "cannot follow block {} at height {height}: {e}; the network's chain forked below \
                         what this node keeps (start again with a fresh data directory to follow it)",
                        short(&id)
                    ));
                }
                self.drop_pending_descendants(id);
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
            // Its aux leaves, if it is near enough the tip to count.
            let floor = self.chain.best_header().map_or(0, |b| {
                b.height.saturating_sub(self.chain.undo_window().unwrap_or(crate::chain::DEFAULT_MAX_UNDO))
            });
            if height >= floor {
                self.want_aux(&header, from);
            }
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
    /// Puts a transaction in the pool against the tip; `None` when the
    /// chain cannot be read.
    fn pool_transaction(&mut self, tx: Transaction) -> Option<Result<Digest, Reject>> {
        let rtxn = match self.chain.env().read_txn() {
            Ok(t) => t,
            Err(e) => {
                self.log(&format!("mempool: {e}"));
                return None;
            }
        };
        let height = self.chain.tip().ok().flatten().map_or(1, |t| t.height + 1);
        Some(self.mempool.lock().unwrap().insert(tx, self.chain.utxo(), self.chain.names(), &rtxn, height))
    }

    /// Announces a pooled transaction to every live peer but `except`;
    /// returns how many.
    /// A peer whose admission minimum it pays less than is passed over,
    /// unless it is one of the aged reserve's candidates here: a peer
    /// admits those whatever its minimum, if it has room for them.
    /// A peer new to us (or back on a new address): the transactions we
    /// already pool announced to it, since it missed their first
    /// announcement; those it would take (its pool's fee, as
    /// `announce_transaction`), the best paying first, [`MAX_POOL_CATCHUP`]
    /// at most.
    fn announce_pool_to(&self, addr: SocketAddr, st: &net::Status) -> usize {
        let ids: Vec<Digest> = {
            let pool = self.mempool.lock().unwrap();
            let mut v: Vec<(u128, Digest)> = pool
                .entries()
                .filter(|e| {
                    pool.is_protected(&e.txid) || e.fee as u128 >= st.pool_fee as u128 * e.size as u128
                })
                .map(|e| (((e.fee as u128) << 32) / e.size.max(1) as u128, e.txid))
                .collect();
            v.sort_by(|a, b| b.0.cmp(&a.0));
            v.into_iter().take(MAX_POOL_CATCHUP).map(|(_, id)| id).collect()
        };
        for id in &ids {
            self.send(addr, &Message::TxInv(*id));
        }
        ids.len()
    }

    fn announce_transaction(&self, txid: Digest, except: Option<SocketAddr>) -> usize {
        let mut peers = self.peers.sample(net::MAX_PEERS, except, Instant::now());
        {
            let pool = self.mempool.lock().unwrap();
            if let Some(e) = pool.entry(&txid)
                && !pool.is_protected(&txid)
            {
                let (fee, size) = (e.fee as u128, e.size as u128);
                peers.retain(|a| {
                    self.peers.get(a).and_then(|p| p.status).is_none_or(|s| fee >= s.pool_fee as u128 * size)
                });
            }
        }
        #[cfg(test)]
        self.announced.fetch_add(1, Ordering::Relaxed);
        for addr in &peers {
            self.send(*addr, &Message::TxInv(txid));
        }
        peers.len()
    }

    fn handle_transaction(&mut self, tx: Transaction, from: Option<SocketAddr>) {
        let txid = tx.txid();
        // Ours goes over a circuit in onion mode, so keep its bytes.
        let ours = from.is_none().then(|| tx.to_bytes());
        let Some(result) = self.pool_transaction(tx) else { return };
        match result {
            // Ours may have been pooled already, by the prompt. In onion
            // mode a relay announces it, never this node: the first to
            // announce a transaction is taken for its sender.
            Ok(_) | Err(Reject::Known) if from.is_none() => {
                self.log(&format!("our transaction {} pooled", short(&txid)));
                if self.broadcasts_privately() {
                    self.onion_broadcast(txid, ours.unwrap_or_default(), Instant::now());
                } else {
                    let n = self.announce_transaction(txid, None);
                    self.rv.note(Note::Broadcast { txid, how: Ok(format!("announced to {n} peers")) });
                }
            }
            Ok(txid) => {
                self.log(&format!("transaction from {} {} pooled", from.unwrap(), short(&txid)));
                self.announce_transaction(txid, from);
            }
            Err(Reject::Known) => {}
            Err(e) => {
                self.log(&format!("rejected transaction{}: {e}", from.map_or(String::new(), |a| format!(" from {a}"))));
                // Conflicts, spent or not-yet-seen inputs and a full pool
                // happen to honest peers in races; the rest cannot.
                let honest = matches!(
                    e,
                    Reject::ReplacementFee { .. }
                        | Reject::UnknownInput(_)
                        | Reject::Full
                        | Reject::FeeTooLow { .. }
                        | Reject::Dust { .. }
                        | Reject::Name(_)
                        | Reject::NameConflict
                );
                if let Some(from) = from
                    && !honest
                {
                    self.peers.strike(from);
                }
                if from.is_none() {
                    self.rv.note(Note::Broadcast { txid, how: Err(format!("the pool refused it: {e}")) });
                }
            }
        }
    }

    /// After the tip moved: drop pooled transactions the chain has spent,
    /// restore shelved ones a reorganization freed, at the positions the
    /// new branch gave their outputs (`fork`: the height it forked at).
    fn revalidate_mempool(&mut self, fork: Option<u32>) {
        let tip = self.chain.tip().ok().flatten().map_or(0, |t| t.height);
        let mut moved: HashMap<crate::transaction::Commitment, Vec<u64>> = HashMap::new();
        // What the new blocks made, and when: a pooled transaction whose
        // outputs are all among them confirmed (blocks carry no
        // transactions), at its block's timestamp.
        let mut created = HashMap::new();
        for h in fork.map_or(tip, |f| f + 1)..=tip {
            let at = self.chain.header_at(h).ok().flatten().map_or_else(crate::mempool::unix_now, |h| h.timestamp);
            if let Ok(Some((_, first, outputs))) = self.chain.main_outputs(h) {
                for (i, o) in outputs.iter().enumerate() {
                    created.insert(o.commitment, at);
                    if fork.is_some() {
                        moved.entry(o.commitment).or_default().push(first + i as u64);
                    }
                }
            }
        }
        let Ok(rtxn) = self.chain.env().read_txn() else {
            return;
        };
        let height = tip + 1;
        match self.mempool.lock().unwrap().revalidate(self.chain.utxo(), self.chain.names(), &rtxn, height, &moved, &created) {
            Ok((gone, back)) if gone + back > 0 => {
                self.chatter(&format!("mempool: {gone} transactions confirmed or conflicted, {back} restored"));
            }
            Ok(_) => {}
            Err(e) => self.log(&format!("mempool: {e}")),
        }
    }

    /// Sends `Inv` to every live peer but `except`; returns how many.
    fn announce(&self, block: &Block, except: Option<SocketAddr>) -> usize {
        let now = Instant::now();
        let peers = self.peers.sample(net::MAX_PEERS, except, now);
        let len = block.size() as u32;
        for addr in &peers {
            self.send(*addr, &Message::Inv(block.header, len));
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
            // Nobody to wait for (no peer or seed configured, a dev node):
            // at once.
            let nobody = self.config.peers.is_empty() && self.config.seeds.is_empty();
            if nobody || now.duration_since(self.started) >= Duration::from_secs(10) {
                self.log("fast sync: no peers answered; starting from genesis until one does");
                self.mode = Mode::Normal;
                self.alone = true;
            }
            return;
        }
        let best = match self.chain.best_header() {
            Ok(b) => b,
            Err(e) => return self.log(&format!("fast sync: {e}")),
        };
        let height = self.snapshot_height(&best, now);
        if height == 0 {
            self.log(&format!("fast sync: best header at height {}; validating every block instead", best.height));
            self.mode = Mode::Normal;
            return;
        }
        let target = match self.chain.ancestor(&best, height) {
            Ok(Some(t)) => t,
            _ => return self.log("fast sync: snapshot block's header is missing"),
        };
        if !self.confirm_work(&best, height) {
            return;
        }
        self.log(&format!(
            "fast sync: {} headers checked; fetching the state after block {} ({})",
            best.height,
            target.height,
            short(&target.hash())
        ));
        let depth = self.config.sync_point.unwrap_or(0);
        if best.height - height < depth {
            self.log(&format!(
                "fast sync: peers keep no snapshot {depth} blocks deep; using one {} deep",
                best.height - height
            ));
        }
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
            begun: false,
            carry: None,
        });
        self.mode = Mode::Snapshot;
        self.snapshot_sync(now);
    }

    /// Checks the full proof of work of the headers from `from` to `best`
    /// stored with only the quick check: the snapshot block's chain proof
    /// attests the work before it, not its own or what follows. A header
    /// that fails is refused with every header after it, and its source
    /// struck. Whether all passed.
    fn confirm_work(&mut self, best: &Header, from: u32) -> bool {
        match self.chain.confirm_work(best, from) {
            Ok(Ok(0)) => true,
            Ok(Ok(n)) => {
                self.log(&format!(
                    "fast sync: full proof of work checked for {n} headers from {from} to {}; the chain proof covers the rest",
                    best.height
                ));
                true
            }
            Ok(Err((height, id))) => {
                self.log(&format!("fast sync: header {height} ({}) fails its proof of work", short(&id)));
                if let Some(&from) = self.sources.get(&id) {
                    self.peers.strike(from);
                }
                self.header_batches.clear();
                false
            }
            Err(e) => {
                self.log(&format!("fast sync: checking the work after the snapshot block: {e}"));
                false
            }
        }
    }

    /// Peers that may serve the snapshot: trusted, past its block and
    /// still holding the blocks after it, which a snapshot is kept as long
    /// as. Peers passed over after a failure are asked only if no other can.
    fn snapshot_peers(&self, now: Instant) -> Vec<SocketAddr> {
        let height = self.snap.as_ref().map_or(0, |s| s.target.height);
        let at = |p: &&net::Peer| p.status.is_some_and(|s| s.height >= height && s.oldest <= height);
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
        let Some(id) = self.snap.as_ref().map(|s| s.target.hash()) else {
            return;
        };
        let peers = self.snapshot_peers(now);
        self.fetch_for_snapshot(kind, id, &peers, now);
    }

    /// Fetches `kind` of `id` for the snapshot, from the next of `peers`.
    fn fetch_for_snapshot(&mut self, kind: Kind, id: Digest, peers: &[SocketAddr], now: Instant) {
        let Some(snap) = self.snap.as_mut() else {
            return;
        };
        if peers.is_empty() || self.snap_downloads.contains_key(&(kind, id)) {
            return;
        }
        let from = peers[snap.next_peer % peers.len()];
        snap.next_peer += 1;
        let max_len = match kind {
            Kind::Block => self.chain.params().max_block_size,
            Kind::Manifest => net::MAX_MANIFEST,
            Kind::Part(_) => net::MAX_PART,
            Kind::Tx => MAX_TX_SIZE,
            Kind::Consensus => consensus::MAX_CONSENSUS,
            Kind::Object => crate::onion::MAX_OBJECT,
        };
        let mut d = Download::new(kind, id, from, max_len, None, self.path_to(&from), now);
        let indexes = d.request(now);
        for msg in net::chunk_requests(kind, id, &indexes) {
            self.send(from, &msg);
        }
        self.snap_downloads.insert((kind, id), d);
    }

    /// The height of the snapshot to fetch below `best`: the block the sync
    /// point deep (peers keep a manifest for every block in their undo
    /// windows). With a sync point deeper than every peer's window, the
    /// deepest block a peer keeps, with a margin, since waiting for a deeper
    /// one would never end. 0 if the chain is too short for any.
    fn snapshot_height(&self, best: &Header, now: Instant) -> u32 {
        let depth = self.config.sync_point.unwrap_or(0);
        let want = best.height.saturating_sub(depth);
        if want == 0 {
            return 0;
        }
        // A window moves with its tip: blocks found since a peer's status
        // moved its oldest too.
        let lowest = self
            .peers
            .trusted(now)
            .filter_map(|p| p.status)
            .filter(|s| s.height >= want)
            .map(|s| s.oldest + best.height.saturating_sub(s.height) + snapshot_margin(&s))
            .min();
        match lowest {
            Some(l) if l > want && l <= best.height => l,
            _ => want,
        }
    }

    /// The snapshot block [`Node::snapshot_height`] picks.
    fn snapshot_target(&self, best: &Header, now: Instant) -> Option<Header> {
        match self.snapshot_height(best, now) {
            0 => None,
            height => self.chain.ancestor(best, height).ok().flatten(),
        }
    }

    /// Moves to a later snapshot when peers are about to drop this one (it
    /// nears the end of their undo windows: the bodies after it, which a
    /// carry needs, go at the same time) or none serves it, and starts over
    /// if the best chain no longer holds it.
    fn check_snapshot_target(&mut self, now: Instant) {
        if self.deferred.is_some() {
            return;
        }
        let Some(snap) = self.snap.as_ref() else { return };
        let Ok(best) = self.chain.best_header() else { return };
        let target = snap.target;
        if self.chain.ancestor(&best, target.height).ok().flatten() != Some(target) {
            return self.abandon_snapshot("the best chain no longer holds the snapshot block");
        }
        let later = self.snapshot_target(&best, now).filter(|h| h.height > target.height);
        let at: Vec<SocketAddr> = self
            .peers
            .trusted(now)
            .filter(|p| p.status.is_some_and(|s| s.height >= target.height))
            .map(|p| p.addr)
            .collect();
        // A window moves with its tip: blocks found since a peer's status
        // moved its oldest too.
        let expiring = !at.is_empty()
            && !self.peers.trusted(now).any(|p| {
                p.status.is_some_and(|s| {
                    let oldest = s.oldest + best.height.saturating_sub(s.height);
                    s.height >= target.height && oldest + snapshot_margin(&s) <= target.height
                })
            });
        let unserved = !at.is_empty() && at.iter().all(|a| snap.unserved.contains(a));
        match later {
            Some(later) if expiring => self.move_snapshot(later, "peers are about to drop the snapshot"),
            Some(later) if unserved => self.move_snapshot(later, "no peer serves the snapshot"),
            // No later snapshot to move to yet: a failed attempt, towards
            // giving up on fast sync, and the peers get another chance.
            None if unserved => {
                if let Some(s) = self.snap.as_mut() {
                    s.unserved.clear();
                }
                self.restart_snapshot("no peer serves the snapshot");
            }
            _ => {}
        }
    }

    /// Fetches the snapshot after `target`, later on the same chain,
    /// instead: the parts already staged are carried forward once the
    /// bodies in between are in, rather than fetched again.
    fn move_snapshot(&mut self, target: Header, why: &str) {
        // Parts with the applier belong to the old snapshot: let them land
        // first.
        if self.defer(Deferred::Move(Box::new(target), why.to_string())) {
            return;
        }
        self.snap_downloads.clear();
        #[cfg(test)]
        {
            self.moved = true;
        }
        let Some(snap) = self.snap.as_mut() else { return };
        let old = snap.target;
        if snap.begun {
            let carry = match (snap.carry.take(), &snap.manifest) {
                // Moving again before carrying: the same parts, more bodies.
                (Some(c), _) => c,
                (None, Some(m)) => Carry {
                    staged: m
                        .outputs
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| snap.parts[*i])
                        .map(|(_, p)| (p.level as usize, p.index))
                        .collect(),
                    names: snap.parts[m.outputs.len()..].iter().filter(|p| **p).count(),
                    wanted: HashMap::new(),
                    spent: Vec::new(),
                },
                (None, None) => unreachable!("staging begins only once the manifest is checked"),
            };
            snap.carry = Some(carry);
        }
        let Some(snap) = self.snap.as_mut() else { return };
        snap.target = target;
        snap.block = None;
        snap.manifest = None;
        snap.verified = false;
        snap.parts.clear();
        snap.manifest_from = None;
        snap.bad_manifests = 0;
        snap.unserved.clear();
        let mut bodies = Vec::new();
        if snap.carry.is_some() {
            let mut h = target;
            while h.height > old.height {
                let prev = h.prev_hash;
                bodies.push(h);
                match self.chain.header_by_hash(&prev) {
                    Ok(Some(p)) => h = p,
                    _ => return self.restart_snapshot("a header between the snapshots is missing"),
                }
            }
        }
        let snap = self.snap.as_mut().unwrap();
        if let Some(carry) = snap.carry.as_mut() {
            carry.wanted.extend(bodies.into_iter().map(|h| (h.hash(), h)));
        }
        let (staged, names) = snap.carry.as_ref().map_or((0, 0), |c| (c.staged.len(), c.names));
        self.log(&format!(
            "fast sync: {why}; moving to the state after block {} ({}), {staged} staged output parts and {names} name parts to carry forward",
            target.height,
            short(&target.hash())
        ));
    }

    /// Fetches the bodies a carry still wants, from peers holding them. If
    /// no peer holds one any more, the staged parts are dropped and the
    /// state fetched afresh.
    fn fetch_carry_bodies(&mut self, now: Instant) {
        let wanted: Vec<Header> = match self.snap.as_ref().and_then(|s| s.carry.as_ref()) {
            Some(c) => c.wanted.values().copied().collect(),
            None => return,
        };
        let held = |h: u32| self.peers.trusted(now).any(|p| p.status.is_some_and(|s| s.oldest <= h && h <= s.height));
        if wanted.iter().any(|h| !held(h.height)) {
            return self.drop_carry();
        }
        for header in wanted {
            if self.snap_downloads.len() >= MAX_PART_DOWNLOADS {
                break;
            }
            let peers: Vec<SocketAddr> = self.peers.holders(header.height, now).map(|p| p.addr).collect();
            self.fetch_for_snapshot(Kind::Block, header.hash(), &peers, now);
        }
    }

    /// Gives up carrying the staged parts forward: they are cleared, and
    /// the snapshot is staged from the start once its block is checked.
    fn drop_carry(&mut self) {
        let Some(snap) = self.snap.as_mut() else { return };
        let Some(carry) = snap.carry.take() else { return };
        let target = snap.target.hash();
        snap.begun = false;
        snap.verified = false;
        self.snap_downloads.retain(|(kind, id), _| *kind != Kind::Block || *id == target);
        if let Err(e) = self.chain.abort_snapshot() {
            return self.restart_snapshot(&format!("clearing the staged parts: {e}"));
        }
        self.log(&format!(
            "fast sync: the blocks between the snapshots are no longer served; dropping {} staged parts",
            carry.staged.len()
        ));
    }

    /// Hands the staged parts to the applier to carry forward to the
    /// snapshot's manifest, with the outputs spent in between.
    fn dispatch_carry(&mut self) {
        let Some(snap) = self.snap.as_mut() else { return };
        let (Some(carry), Some(manifest)) = (snap.carry.take(), snap.manifest.as_ref()) else {
            return;
        };
        let (next, outputs) = (manifest.next, &manifest.outputs);
        let mut spent = carry.spent;
        spent.sort_unstable();
        spent.dedup();
        // Each staged part against the later manifest's part for the same
        // subtree, if it has one (a part grown since fails its root).
        let parts: Vec<CarriedPart> = carry
            .staged
            .iter()
            .map(|&(level, index)| {
                let (first, end) = (index << level, (index + 1) << level);
                let (lo, hi) = (spent.partition_point(|p| *p < first), spent.partition_point(|p| *p < end));
                let slot = outputs
                    .binary_search_by_key(&first, |p| p.first())
                    .ok()
                    .filter(|&i| outputs[i].level as usize == level);
                CarriedPart {
                    level,
                    index,
                    spent: spent[lo..hi].to_vec(),
                    part: slot.map(|i| outputs[i]),
                    slot: slot.map(|i| i as u32),
                }
            })
            .collect();
        for batch in parts.chunks(CARRY_BATCH) {
            snap.staging.extend(batch.iter().filter_map(|p| p.slot));
            if let Some(jobs) = &self.jobs {
                let _ = jobs.send(Job::Carry { parts: batch.to_vec(), next });
            }
        }
        // Staged name records satisfy the name parts whose ranges saw no
        // name operation since, which the hashes tell; the rest are
        // cleared and fetched.
        let names: Vec<CarriedNamePart> = if carry.names > 0 {
            (0..manifest.names.len())
                .filter_map(|j| {
                    let (lo, hi) = manifest.name_range(j)?;
                    let index = (outputs.len() + j) as u32;
                    Some(CarriedNamePart { index, lo, hi, hash: manifest.names[j].hash })
                })
                .collect()
        } else {
            Vec::new()
        };
        for batch in names.chunks(CARRY_BATCH) {
            snap.staging.extend(batch.iter().map(|p| p.index));
            if let Some(jobs) = &self.jobs {
                let _ = jobs.send(Job::CarryNames(batch.to_vec()));
            }
        }
        let height = snap.target.height;
        self.log(&format!(
            "fast sync: carrying {} staged output parts forward to block {height}, less {} outputs spent since, and {} staged name parts against its {} name parts",
            parts.len(),
            spent.len(),
            carry.names,
            names.len()
        ));
    }

    /// Fast sync, snapshot: fetch what is missing, verify, install.
    fn snapshot_sync(&mut self, now: Instant) {
        if self.deferred.is_some() {
            return;
        }
        let Some(snap) = self.snap.as_ref() else {
            self.mode = Mode::Normal;
            return;
        };
        let (has_block, has_manifest) = (snap.block.is_some(), snap.manifest.is_some());
        self.fetch_carry_bodies(now);
        if !has_block {
            self.start_snapshot_download(Kind::Block, now);
        }
        if !has_manifest {
            self.start_snapshot_download(Kind::Manifest, now);
        }
        if has_block && has_manifest && !self.snap.as_ref().unwrap().verified {
            // The target may have moved, and headers come in, since the
            // header sync checked the work after it.
            let target = self.snap.as_ref().unwrap().target;
            let best = self.chain.best_header();
            if let Ok(best) = best
                && !self.confirm_work(&best, target.height)
            {
                return self.abandon_snapshot("a header after the snapshot block fails its proof of work");
            }
            let snap = self.snap.as_ref().unwrap();
            let next = snap.manifest.as_ref().unwrap().next;
            match self.chain.verify_snapshot_block(snap.block.as_ref().unwrap(), next) {
                Ok(()) => {
                    self.log(&format!(
                        "fast sync: block {}'s proof verifies the chain up to it; {} positions to fetch in {} parts",
                        snap.target.height,
                        next,
                        snap.parts.len()
                    ));
                    #[cfg(test)]
                    self.seen.verified.fetch_add(1, Ordering::Relaxed);
                    if !self.snap.as_ref().unwrap().begun {
                        if let Err(e) = self.chain.begin_snapshot() {
                            return self.restart_snapshot(&format!("cannot start installing the snapshot: {e}"));
                        }
                        self.snap.as_mut().unwrap().begun = true;
                    }
                    self.snap.as_mut().unwrap().verified = true;
                }
                // The block was checked against its header on arrival, so
                // the manifest's counter is at fault: one peer's lie, not a
                // failed attempt, unless manifest after manifest fails.
                Err(e) => {
                    #[cfg(test)]
                    self.seen.refused.fetch_add(1, Ordering::Relaxed);
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
        // Staged parts are carried forward before any is fetched for this
        // snapshot, once every body in between is in.
        match self.snap.as_ref().and_then(|s| s.carry.as_ref().map(|c| (s.verified, c.wanted.is_empty()))) {
            Some((true, true)) => self.dispatch_carry(),
            Some(_) => return,
            None => {}
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
        if done && staging == 0 {
            return self.install_snapshot();
        }
        for i in missing {
            // Parts waiting for the applier count too, so a slow disk
            // bounds what is held in memory.
            if self.snap_downloads.len() + staging >= MAX_PART_DOWNLOADS {
                break;
            }
            #[cfg(test)]
            if !self.moved
                && self.hold_parts.is_some_and(|n| {
                    let s = self.snap.as_ref().unwrap();
                    s.parts.iter().filter(|p| **p).count() + staging + self.snap_downloads.len() >= n
                })
            {
                break;
            }
            self.start_snapshot_download(Kind::Part(i), now);
        }
    }

    fn install_snapshot(&mut self) {
        let Some(snap) = self.snap.take() else {
            return;
        };
        let manifest = snap.manifest.as_ref().unwrap();
        match self.chain.finish_snapshot(snap.block.as_ref().unwrap(), manifest) {
            Ok(()) => {
                let unspent = self.chain.env().read_txn().ok().and_then(|r| self.chain.utxo().len(&r).ok());
                self.log(&format!(
                    "fast sync: installed the state after block {} ({} unspent outputs); following the chain from there",
                    snap.target.height,
                    unspent.unwrap_or(0)
                ));
                self.mode = Mode::Normal;
                self.tip_changes.fetch_add(1, Ordering::Release);
                self.revalidate_mempool(None);
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
        if self.defer(Deferred::Restart(why.to_string())) {
            return;
        }
        self.snap_attempts += 1;
        self.snap_downloads.clear();
        if let Err(e) = self.chain.abort_snapshot() {
            self.log(&format!("fast sync: clearing the partial state: {e}"));
        }
        if self.snap_attempts >= MAX_SNAPSHOT_ATTEMPTS {
            // Validating from genesis needs a peer keeping every block;
            // without one it would stall for good, so keep trying.
            let archive =
                self.peers.trusted(Instant::now()).any(|p| p.status.is_some_and(|s| s.height > 0 && s.oldest <= 1));
            if archive {
                self.log(&format!("fast sync: {why}; giving up, validating every block instead"));
                self.snap = None;
                self.mode = Mode::Normal;
                return;
            }
            self.log(&format!("fast sync: {why}; no peer keeps every block to validate instead"));
            #[cfg(test)]
            self.seen.kept_trying.fetch_add(1, Ordering::Relaxed);
            self.snap_attempts = 0;
        }
        self.log(&format!("fast sync: {why}; trying again"));
        if let Some(s) = self.snap.as_mut() {
            s.block = None;
            s.manifest = None;
            s.verified = false;
            s.parts.clear();
            s.manifest_from = None;
            s.bad_manifests = 0;
            s.begun = false;
            s.carry = None;
        }
    }

    fn retry_snapshot_downloads(&mut self, now: Instant) {
        let mut abandoned = Vec::new();
        let mut requests = Vec::new();
        for (&(kind, id), d) in self.snap_downloads.iter_mut() {
            if d.too_slow(now) {
                abandoned.push((kind, id, d.from, true));
                continue;
            }
            let wait = self.peers.retry(&d.from);
            if now.duration_since(d.last_progress) < wait || now.duration_since(d.last_request) < wait {
                continue;
            }
            d.retries += 1;
            d.last_request = now;
            if d.retries > net::MAX_RETRIES {
                // Something came, then nothing: slow; nothing at all: it
                // does not serve it, unless it is delivering other parts
                // of it meanwhile (its rate limit dropped these requests).
                let busy =
                    self.snap_heard.get(&d.from).is_some_and(|t| now.duration_since(*t) < Duration::from_secs(5));
                abandoned.push((kind, id, d.from, d.received() > 0 || busy));
            } else {
                d.reset_window();
                let indexes = d.request(now);
                requests.extend(net::chunk_requests(kind, d.id, &indexes).map(|m| (d.from, m)));
            }
        }
        for (to, msg) in requests {
            self.send(to, &msg);
        }
        for (kind, id, from, slow) in abandoned {
            self.snap_downloads.remove(&(kind, id));
            match self.snap.as_mut() {
                // A slow peer is passed over for a while and asked again
                // when no other can serve: only a peer that sends nothing
                // counts towards moving the snapshot.
                Some(s) if s.target.hash() == id && !slow => {
                    s.unserved.insert(from);
                }
                // A body between snapshots: like any block download.
                _ => self.peers.fetch_failed(from, now),
            }
            self.chatter(&format!("fast sync: {from} did not serve {kind:?} {}; asking another peer", short(&id)));
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
        let Some(d) = self.snap_downloads.get_mut(&(kind, id)) else {
            return;
        };
        if d.from != from || d.id != id {
            return;
        }
        self.snap_heard.insert(from, now);
        let done = d.insert(len, index, data, now);
        let (path, sample) = (d.path(), d.take_sample());
        let refill = match done {
            Ok(false) if d.wants_refill() => d.request(now),
            _ => Vec::new(),
        };
        self.learn_path(from, path, sample);
        for msg in net::chunk_requests(kind, id, &refill) {
            self.send(from, &msg);
        }
        match done {
            Ok(false) => {}
            Ok(true) => {
                let Some(d) = self.snap_downloads.remove(&(kind, id)) else { return };
                let bytes = d.assemble().unwrap_or_default();
                if !self.accept_snapshot_object(kind, id, &bytes, from) {
                    self.log(&format!("fast sync: {from} sent a bad {kind:?}"));
                    self.peers.strike(from);
                    self.peers.fetch_failed(from, now);
                }
                self.snapshot_sync(now);
            }
            Err(_) => {
                self.snap_downloads.remove(&(kind, id));
                self.peers.strike(from);
            }
        }
    }

    /// Checks a fetched snapshot object and keeps it; `false` if it is bad.
    fn accept_snapshot_object(&mut self, kind: Kind, id: Digest, bytes: &[u8], from: SocketAddr) -> bool {
        let Some(snap) = self.snap.as_mut() else {
            return true;
        };
        match kind {
            // A body between an earlier snapshot and this one, for its
            // inputs: checked against its stored header.
            Kind::Block if id != snap.target.hash() => {
                let Some(carry) = snap.carry.as_mut() else {
                    return true;
                };
                let Some(header) = carry.wanted.get(&id).copied() else {
                    return true;
                };
                match Block::from_bytes(bytes) {
                    Ok(block) if block.header == header && block.body.commitment() == header.body_commitment => {
                        carry.wanted.remove(&id);
                        carry.spent.extend_from_slice(&block.body.inputs);
                        true
                    }
                    _ => false,
                }
            }
            // The body is checked against the header here, so a corrupted
            // copy is one peer's fault, not a failed attempt.
            Kind::Block => match Block::from_bytes(bytes) {
                Ok(block) if block.header == snap.target && block.body.commitment() == block.header.body_commitment => {
                    // A carry wants its body too, the last between them.
                    if let Some(carry) = snap.carry.as_mut()
                        && carry.wanted.remove(&id).is_some()
                    {
                        carry.spent.extend_from_slice(&block.body.inputs);
                    }
                    snap.block = Some(block);
                    true
                }
                _ => false,
            },
            Kind::Manifest => {
                let Some(manifest) = net::decode_manifest(bytes) else {
                    return false;
                };
                if !manifest.well_formed() || manifest.state_root() != snap.target.state_root {
                    return false;
                }
                snap.parts = vec![false; manifest.parts()];
                snap.manifest = Some(manifest);
                snap.manifest_from = Some(from);
                true
            }
            Kind::Part(i) => {
                let (Some(manifest), true) = (snap.manifest.as_ref(), snap.verified) else {
                    return true;
                };
                if snap.parts.get(i as usize).is_none_or(|p| *p) || snap.staging.contains(&i) {
                    return true;
                }
                // Checked against its root or hash and stored on the
                // applier thread, hashed once, while the network goes on;
                // one part in memory there at a time.
                let job = if let Some(&part) = manifest.outputs.get(i as usize) {
                    Job::Part { index: i, bytes: bytes.to_vec(), next: manifest.next, part, from }
                } else {
                    let j = i as usize - manifest.outputs.len();
                    let (Some(part), Some((lo, hi))) = (manifest.names.get(j), manifest.name_range(j)) else {
                        return false;
                    };
                    Job::NamePart { index: i, bytes: bytes.to_vec(), lo, hi, hash: part.hash, from }
                };
                snap.staging.insert(i);
                if let Some(jobs) = &self.jobs {
                    let _ = jobs.send(job);
                }
                true
            }
            Kind::Tx | Kind::Consensus | Kind::Object => true,
        }
    }

    /// A manifest or part this node serves, for the state after block `id`.
    fn snapshot_bytes(&mut self, kind: Kind, id: &Digest) -> Option<Arc<Vec<u8>>> {
        if let Some(pos) = self.served_snapshots.iter().position(|(k, _)| *k == (kind, *id)) {
            let entry = self.served_snapshots.remove(pos).unwrap();
            let bytes = Arc::clone(&entry.1);
            self.served_snapshots.push_front(entry);
            return Some(bytes);
        }
        #[cfg(test)]
        if self.withhold_snapshots {
            return None;
        }
        let bytes = match kind {
            #[cfg(test)]
            Kind::Manifest if self.lie_manifest => {
                let mut m = self.chain.snapshot_manifest(id).ok().flatten()?;
                m.next += 1;
                net::encode_manifest(&m)
            }
            Kind::Manifest => net::encode_manifest(&self.chain.snapshot_manifest(id).ok().flatten()?),
            Kind::Part(i) => {
                let manifest = self.chain.snapshot_manifest(id).ok().flatten()?;
                if (i as usize) < manifest.outputs.len() {
                    let (outputs, commits) = match self.chain.snapshot_part(id, i as u64) {
                        Ok(p) => p?,
                        // A part this node should hold: say why it cannot.
                        Err(e) => {
                            self.log(&format!("serving part {i} of the snapshot after {}: {e}", short(id)));
                            return None;
                        }
                    };
                    net::encode_part(&outputs, &commits)
                } else {
                    let j = i as u64 - manifest.outputs.len() as u64;
                    net::encode_name_part(&self.chain.snapshot_name_part(id, j).ok().flatten()?)
                }
            }
            _ => return None,
        };
        let bytes = Arc::new(bytes);
        self.served_snapshots.push_front(((kind, *id), Arc::clone(&bytes)));
        self.served_snapshots.truncate(SERVED_SNAPSHOTS);
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregate::AggregatorParams;
    use crate::block::{Body, HEADER_SIZE};
    use crate::chain::{AcceptAllProofs, BlockStatement, ChainParams};
    use crate::circuit;
    use crate::poseidon2::digest_to_bytes;
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
            // A subsidy a wallet can pay from.
            emission: &[(1000, SUBSIDY)],
            aggregator: AggregatorParams::MAINNET,
            schedule: crate::difficulty::Schedule::MAINNET,
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
        Arc::new(Mutex::new(Mempool::with_policy(1 << 20, crate::mempool::Policy::NONE)))
    }

    fn pk(tag: u8) -> crate::xmss::PublicKey {
        let mut s = [0u8; 32];
        s[0] = tag;
        Key::generate(&s).public_key()
    }

    /// Mines a block with one output and a padding "proof" on the tip.
    const SUBSIDY: u64 = 60_000_000;

    /// What the next block on `f` must create when it spends `inputs`:
    /// their amounts and the subsidy.
    fn claim(f: &Fixture, inputs: &[u64]) -> u64 {
        let height = f.chain.tip().unwrap().unwrap().height + 1;
        let rtxn = f.chain.env().read_txn().unwrap();
        let spent: u64 = inputs
            .iter()
            .map(|&p| crate::transaction::slot_parts(&f.chain.utxo().slot(&rtxn, p).unwrap()).unwrap().1)
            .sum();
        spent + f.chain.params().subsidy(height)
    }

    /// A block whose one output claims the subsidy, to `pk(tag)`.
    fn mine(f: &Fixture, tag: u8, timestamp: u64) -> Block {
        let height = f.chain.tip().unwrap().unwrap().height + 1;
        let body = Body {
            inputs: vec![],
            outputs: vec![Output::new(&pk(tag), f.chain.params().subsidy(height)).block_output()],
            proof: vec![tag; 2500],
            ..Default::default()
        };
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

    /// How long a test waits for something that must happen before it
    /// calls the node stuck: only a hang guard, so generous, and three
    /// times as long in debug builds, where the proving tests running
    /// alongside leave the nodes little CPU.
    fn guard(secs: u64) -> Duration {
        Duration::from_secs(if cfg!(debug_assertions) { 3 * secs } else { secs })
    }

    fn config(peers: Vec<SocketAddr>, dir: &TempDir) -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            peers,
            seeds: vec![],
            peers_file: Some(dir.0.join("peers")),
            verbose: true,
            sync_point: None,
            relay: false,
            identity: None,
            wallet: false,
            relay_key: None,
            max_sessions: MAX_SESSIONS,
            max_hops: MAX_HOPS,
            max_channels: MAX_CHANNELS,
        }
    }

    fn wait_for_tip<V: ProofVerifier>(chain: &Chain<V>, want: &Header, secs: u64) -> bool {
        let deadline = Instant::now() + guard(secs);
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
        let spent = Output::new(&pk(1), SUBSIDY);
        let mut k = Key::generate(&{
            let mut s = [0u8; 32];
            s[0] = 1;
            s
        });
        let position = {
            let rtxn = a.chain.env().read_txn().unwrap();
            let unspent = a.chain.utxo().unspent(&rtxn).unwrap();
            unspent.iter().find(|(_, (c, _, _))| *c == spent.commitment).unwrap().0
        };
        let mut tx = crate::transaction::UnsignedTransaction::new(
            vec![(k.public_key(), SUBSIDY)],
            vec![Output::new(&pk(50), SUBSIDY)],
        )
        .sign_with(&mut k)
        .unwrap();
        tx.set_positions(&[position]);
        let txid = tx.txid();
        tx_a.send(Event::Transaction(tx)).unwrap();
        let deadline = Instant::now() + guard(20);
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
                outputs: vec![Output::new(&pk(50), claim(&a, &[position])).block_output()],
                proof: vec![5; 2500],
                ..Default::default()
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

    /// Blocks with aux leaves: the miner keeps its own leaves, a peer
    /// fetches and checks them, counts the window's votes and fetches the
    /// file the winning hash names; a later file takes over once more
    /// blocks vote for it.
    #[test]
    fn aux_leaves_and_the_consensus_file_propagate() {
        let a = open("aux-a");
        let b = open("aux-b");
        let now = unix_now();
        let file = b"mode init\n# the first file\n";
        let hash = a.chain.put_consensus_file(file).unwrap();
        a.chain.set_aux_leaf(0, hash).unwrap();
        a.chain.set_aux_leaf(7, [7u8; 32]).unwrap();
        let leaves = a.chain.aux_leaves().unwrap();
        let mut t = T0;
        let mut blocks = Vec::new();
        for tag in 1..=2u8 {
            t += 600;
            let block = mine(&a, tag, t);
            assert_eq!(block.header.aux, crate::chain::aux_merkle_root(&leaves));
            a.chain.apply_block(&block, now).unwrap();
            blocks.push(block);
        }
        // Applied directly, so the node has not kept their leaves yet.
        assert_eq!(a.chain.aux_leaves_of(&blocks[0].header.hash()).unwrap(), None);
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), config(vec![addr_a], &b.dir)).unwrap();
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        t += 600;
        let b3 = mine(&a, 3, t);
        tx_a.send(Event::Mined(b3.clone())).unwrap();
        blocks.push(b3.clone());
        assert!(wait_for_tip(&b.chain, &b3.header, 20), "b did not sync");
        let settled = |chain: &Chain<AcceptAllProofs>, want: consensus::Hash, secs: u64| {
            let deadline = Instant::now() + guard(secs);
            while Instant::now() < deadline {
                let v = chain.consensus_votes(consensus::WINDOW).unwrap();
                if v.missing.is_empty()
                    && v.counts.first().map(|c| c.0) == Some(want)
                    && chain.has_consensus_file(&want).unwrap()
                {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            false
        };
        assert!(
            settled(&b.chain, hash, 20),
            "b did not fetch the leaves and the file: {:?}",
            b.chain.consensus_votes(144)
        );
        for block in &blocks {
            assert_eq!(b.chain.aux_leaves_of(&block.header.hash()).unwrap(), Some(leaves));
            assert_eq!(a.chain.aux_leaves_of(&block.header.hash()).unwrap(), Some(leaves), "a keeps its own");
        }
        assert_eq!(b.chain.consensus_file(&hash).unwrap().as_deref(), Some(&file[..]));
        let v = b.chain.consensus_votes(consensus::WINDOW).unwrap();
        assert_eq!(v.counts, vec![(hash, 3, 3)]);
        assert_eq!(v.blocks, 4);
        // A second file: three votes against three go to the most recent
        // commitment, so it wins at block 6 and holds at 7.
        let file2 = b"mode init\n# the second file\n";
        let hash2 = a.chain.put_consensus_file(file2).unwrap();
        a.chain.set_aux_leaf(0, hash2).unwrap();
        for tag in 4..=7u8 {
            t += 600;
            let block = mine(&a, tag, t);
            tx_a.send(Event::Mined(block.clone())).unwrap();
            assert!(wait_for_tip(&b.chain, &block.header, 20), "b did not receive block {tag}");
            if tag < 6 {
                std::thread::sleep(Duration::from_millis(300));
                assert_eq!(b.chain.consensus_votes(consensus::WINDOW).unwrap().counts[0].0, hash, "at block {tag}");
            }
        }
        assert!(settled(&b.chain, hash2, 20), "the second file did not take over: {:?}", b.chain.consensus_votes(144));
        let v = b.chain.consensus_votes(consensus::WINDOW).unwrap();
        assert_eq!(v.counts, vec![(hash2, 4, 7), (hash, 3, 3)]);
        assert_eq!(b.chain.consensus_file(&hash2).unwrap().as_deref(), Some(&file2[..]));
        let (_, current) = b.chain.consensus().unwrap();
        assert_eq!((current.mode, current.winner, current.skipped), (consensus::Mode::Init, Some((hash2, 4)), vec![]));
        // Both files stay.
        assert!(b.chain.has_consensus_file(&hash).unwrap());
        // A peer serves leaves it holds and nothing for a block it does not.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let token = {
            // Learn our token from a's pong.
            let genesis = a.chain.header_at(0).unwrap().unwrap().hash();
            let st = net::Status {
                nonce: 1,
                version: net::PROTOCOL_VERSION,
                token: 0,
                genesis,
                height: 0,
                oldest: 1,
                tip: genesis,
                work: U256::ZERO,
                min_fee: 0,
                pool_fee: 0,
            };
            sock.send_to(&Message::Ping(st).encode(), addr_a).unwrap();
            let mut buf = [0u8; net::MAX_DATAGRAM];
            let mut token = None;
            for _ in 0..4 {
                let Ok((n, _)) = sock.recv_from(&mut buf) else { break };
                if let Some(Message::Pong(s)) = Message::decode(&buf[..n]) {
                    token = Some(s.token);
                    break;
                }
            }
            token.expect("a's pong")
        };
        sock.send_to(&Message::GetAux { id: b3.header.hash(), token }.encode(), addr_a).unwrap();
        let mut buf = [0u8; net::MAX_DATAGRAM];
        let mut got = None;
        for _ in 0..4 {
            let Ok((n, _)) = sock.recv_from(&mut buf) else { break };
            if let Some(Message::Aux { id, leaves: l }) = Message::decode(&buf[..n]) {
                got = Some((id, l));
                break;
            }
        }
        assert_eq!(got, Some((b3.header.hash(), leaves)));
        for tx in [tx_a, tx_b] {
            tx.send(Event::Stop).unwrap();
        }
        ha.join().unwrap();
        hb.join().unwrap();
    }

    /// A state proof for an unspent output and for an empty position
    /// travels in two datagrams and verifies against the tip's state root.
    #[test]
    fn state_proofs_verify_against_the_tip() {
        let a = open("proof");
        let now = unix_now();
        let mut t = T0;
        for tag in 1..=2u8 {
            t += 600;
            a.chain.apply_block(&mine(&a, tag, t), now).unwrap();
        }
        let tip = a.chain.tip().unwrap().unwrap();
        let (occupied, empty) = {
            let rtxn = a.chain.env().read_txn().unwrap();
            let next = a.chain.utxo().next_position(&rtxn).unwrap();
            (next - 1, next + 5)
        };
        let fetch = |position: u64| {
            let msgs = proof_messages(&a.chain, position).unwrap().unwrap();
            assert_eq!(msgs.len(), 2);
            let mut siblings = Vec::new();
            let mut output = None;
            for (i, m) in msgs.iter().enumerate() {
                let bytes = m.encode();
                assert!(bytes.len() <= net::MAX_DATAGRAM);
                let Some(Message::Proof { position: p, tip: h, commitment, memo, amount, created, part, siblings: s }) =
                    Message::decode(&bytes)
                else {
                    panic!("not a proof");
                };
                assert_eq!((p, h, part as usize), (position, tip.hash(), i));
                siblings.extend(s);
                output = Some((commitment, crate::transaction::memo_slot(&memo, amount), created));
            }
            (output.unwrap(), siblings)
        };
        let ((c, m, created), siblings) = fetch(occupied);
        assert_ne!(c, EMPTY);
        assert_eq!(created, 2);
        assert!(verify_proof(&tip.state_root, occupied, &c, &m, created, &siblings));
        assert!(!verify_proof(&tip.state_root, occupied, &c, &m, created + 1, &siblings));
        assert!(!verify_proof(&tip.state_root, occupied + 1, &c, &m, created, &siblings));
        assert!(!verify_proof(&EMPTY, occupied, &c, &m, created, &siblings));
        // The amount is in the leaf: another one does not verify.
        let (memo, amount) = crate::transaction::slot_parts(&m).unwrap();
        let other = crate::transaction::memo_slot(&memo, amount + 1);
        assert!(!verify_proof(&tip.state_root, occupied, &c, &other, created, &siblings));
        let ((c, m, created), siblings) = fetch(empty);
        assert_eq!((c, m, created), (EMPTY, EMPTY, 0));
        assert!(verify_proof(&tip.state_root, empty, &c, &m, created, &siblings));
        assert!(!verify_proof(&tip.state_root, occupied, &c, &m, created, &siblings));
        // The request round-trips too.
        let req = Message::GetProof { position: 7, token: 9 };
        assert_eq!(Message::decode(&req.encode()), Some(req));
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
                    outputs: vec![Output::new(&pk(tag), claim(&a, &[pos])).block_output()],
                    proof: vec![tag; 2500],
                    ..Default::default()
                }
            } else {
                Body {
                    inputs: vec![],
                    outputs: vec![Output::new(&pk(tag), claim(&a, &[])).block_output()],
                    proof: vec![tag; 2500],
                    ..Default::default()
                }
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
        // No full proof of work checked below the snapshot block, whose
        // chain proof attests it; its own and every one after it checked.
        let mut checked = b.chain.full_pow_heights.lock().unwrap().clone();
        checked.sort();
        checked.dedup();
        assert_eq!(checked, (8..=12).collect::<Vec<u32>>());
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!syncing.load(Ordering::Acquire));
        tx_a.send(Event::Stop).unwrap();
        tx_b.send(Event::Stop).unwrap();
        ha.join().unwrap();
        hb.join().unwrap();
    }

    /// The same over a network that loses a tenth of the datagrams each
    /// way: every request is retried, and the sync completes.
    #[test]
    fn a_fresh_node_fast_syncs_over_a_lossy_network() {
        fast_sync_over("lossy", 100, 0);
    }

    /// The same over a network that delivers almost a third of the
    /// datagrams after the one sent next.
    #[test]
    fn a_fresh_node_fast_syncs_over_a_reordering_network() {
        fast_sync_over("reorder", 0, 300);
    }

    /// A fast sync of twelve blocks with datagrams lost and reordered, per
    /// thousand, each way.
    fn fast_sync_over(name: &str, loss: u64, reorder: u64) {
        let a = open(&format!("{name}-a"));
        let now = unix_now();
        let mut t = T0;
        for tag in 1..=12u8 {
            t += 600;
            let inputs = if tag >= 3 { vec![tag as u64 - 3] } else { vec![] };
            let body = Body {
                outputs: vec![Output::new(&pk(tag), claim(&a, &inputs)).block_output()],
                inputs,
                proof: vec![tag; 2500],
                ..Default::default()
            };
            let block = mine_body(&a, body, t);
            a.chain.apply_block(&block, now).unwrap();
        }
        let a_tip = a.chain.tip().unwrap().unwrap();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let b = open(&format!("{name}-b"));
        let mut cb = config(vec![addr_a], &b.dir);
        cb.sync_point = Some(4);
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        node_a.loss.set((loss, 1));
        node_b.loss.set((loss, 2));
        node_a.reorder.set((reorder, 3));
        node_b.reorder.set((reorder, 4));
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        assert!(
            wait_for_tip(&b.chain, &a_tip, 120),
            "b did not fast-sync to a's tip ({loss} lost, {reorder} reordered)"
        );
        assert_eq!(b.chain.state_root().unwrap(), a.chain.state_root().unwrap());
        tx_a.send(Event::Stop).unwrap();
        tx_b.send(Event::Stop).unwrap();
        ha.join().unwrap();
        hb.join().unwrap();
    }

    /// A fresh node whose peer answers only after 10 s starts from genesis
    /// meanwhile, and goes back to fast sync when the peer appears: it ends
    /// on a snapshot, not a replay.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn a_fresh_node_fast_syncs_when_its_first_peer_comes_late() {
        let a = open("late-a");
        let now = unix_now();
        let mut t = T0;
        for tag in 1..=12u8 {
            t += 600;
            let body = Body {
                outputs: vec![Output::new(&pk(tag), claim(&a, &[])).block_output()],
                proof: vec![tag; 2500],
                ..Default::default()
            };
            a.chain.apply_block(&mine_body(&a, body, t), now).unwrap();
        }
        let a_tip = a.chain.tip().unwrap().unwrap();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let b = open("late-b");
        let mut cb = config(vec![addr_a], &b.dir);
        cb.sync_point = Some(4);
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        let hb = std::thread::spawn(move || node_b.run());
        // a is bound but not running: b hears nothing and gives up waiting.
        std::thread::sleep(Duration::from_secs(11));
        assert_eq!(b.chain.tip().unwrap().unwrap().height, 0);
        let ha = std::thread::spawn(move || node_a.run());
        assert!(wait_for_tip(&b.chain, &a_tip, 60), "b did not sync once a answered");
        assert_eq!(b.chain.floor().unwrap(), Some(8), "b fast-synced rather than replaying from genesis");
        tx_a.send(Event::Stop).unwrap();
        tx_b.send(Event::Stop).unwrap();
        ha.join().unwrap();
        hb.join().unwrap();
    }

    /// Garbage reaching the node, random or a real message cut or bent,
    /// is dropped: the node keeps answering.
    #[test]
    fn malformed_datagrams_are_dropped() {
        let a = open("garbage");
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let ha = std::thread::spawn(move || node_a.run());
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let genesis = a.chain.header_at(0).unwrap().unwrap().hash();
        let st = Status {
            nonce: 7,
            version: PROTOCOL_VERSION,
            token: 0,
            genesis,
            height: 0,
            oldest: 1,
            tip: genesis,
            work: U256::ZERO,
            min_fee: 0,
            pool_fee: 0,
        };
        let real = [
            Message::Ping(st).encode(),
            Message::GetPeers { token: 0 }.encode(),
            Message::GetHeadersFrom { height: 0, token: 0 }.encode(),
        ];
        let mut x = 0x1234_5678_u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for i in 0..3000 {
            let bytes: Vec<u8> = match i % 3 {
                0 => (0..next() % 1500).map(|_| next() as u8).collect(),
                1 => {
                    let m = &real[(next() % 3) as usize];
                    m[..(next() as usize % m.len())].to_vec()
                }
                _ => {
                    let mut m = real[(next() % 3) as usize].clone();
                    let at = next() as usize % m.len();
                    m[at] ^= 1 << (next() % 8);
                    m
                }
            };
            sock.send_to(&bytes, addr_a).unwrap();
        }
        // Still answering others (the garbage's sender may rightly be
        // banned by now), a ping or two lost to a full receive buffer
        // aside.
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        other.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut buf = [0u8; net::MAX_DATAGRAM];
        let ping = Message::Ping(Status { nonce: 99, ..st }).encode();
        let mut answered = false;
        for _ in 0..5 {
            other.send_to(&ping, addr_a).unwrap();
            while let Ok((n, _)) = other.recv_from(&mut buf) {
                if matches!(Message::decode(&buf[..n]), Some(Message::Pong(s)) if s.nonce == 99) {
                    answered = true;
                    break;
                }
            }
            if answered {
                break;
            }
        }
        assert!(answered, "the node still answers");
        tx_a.send(Event::Stop).unwrap();
        ha.join().unwrap();
    }

    /// Fast sync with names: the snapshot carries the records, a pending
    /// commit's metadata, and the blocks after it reveal from it.
    #[test]
    fn a_fresh_node_fast_syncs_names() {
        use crate::names::{BlockNameOp as Op, Record};
        let a = open("fast-names-a");
        let now = unix_now();
        let mut t = T0;
        let d = |n: u32| -> Digest { core::array::from_fn(|i| crate::poseidon2::Fp::new(n * 10 + i as u32)) };
        let alice = Record::new(b"alice", d(1), d(2), d(3)).unwrap();
        let alice2 = Record::new(b"alice", d(4), d(5), d(6)).unwrap();
        let bob = Record::new(b"bob", d(7), d(8), d(9)).unwrap();
        // Blocks 1 and 2 commit (positions 1 and 3; one a block); blocks 3
        // to 12 spend an output made before (block 2's at 2, then the one
        // two blocks before); 13 reveals alice and commits again (position
        // 15), 14 updates alice, 15 reveals bob.
        for tag in 1..=20u8 {
            t += 600;
            let ops = match tag {
                1 => vec![Op::Commit { commit: d(10), memo: crate::transaction::memo5(d(11)) }],
                2 => vec![Op::Commit { commit: d(12), memo: crate::transaction::memo5(d(13)) }],
                13 => vec![
                    Op::Reveal { record: alice.clone(), commit: 1 },
                    Op::Commit { commit: d(14), memo: crate::transaction::memo5(d(15)) },
                ],
                14 => vec![Op::Update(alice2.clone())],
                15 => vec![Op::Reveal { record: bob.clone(), commit: 3 }],
                _ => vec![],
            };
            let inputs = match tag {
                3 => vec![2],
                4..=12 => vec![tag as u64],
                _ => vec![],
            };
            let body = Body {
                outputs: vec![Output::new(&pk(tag), claim(&a, &inputs)).block_output()],
                inputs,
                ops,
                proof: vec![tag; 2500],
                ..Default::default()
            };
            let block = mine_body(&a, body, t);
            a.chain.apply_block(&block, now).unwrap();
        }
        let a_tip = a.chain.tip().unwrap().unwrap();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let b = open("fast-names-b");
        let mut cb = config(vec![addr_a], &b.dir);
        cb.sync_point = Some(4);
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        assert!(wait_for_tip(&b.chain, &a_tip, 30), "b did not fast-sync to a's tip");
        assert_eq!(b.chain.state_root().unwrap(), a.chain.state_root().unwrap());
        assert_eq!(b.chain.floor().unwrap(), Some(16));
        let rtxn = b.chain.env().read_txn().unwrap();
        assert_eq!(b.chain.names().lookup(&rtxn, b"alice").unwrap(), Some(alice2));
        assert_eq!(b.chain.names().lookup(&rtxn, b"bob").unwrap(), Some(bob));
        assert_eq!(b.chain.names().commit_at(&rtxn, 15).unwrap().map(|c| (c.hash, c.height)), Some((d(14), 13)));
        assert!(b.chain.names().commit_at(&rtxn, 1).unwrap().is_none());
        drop(rtxn);
        tx_a.send(Event::Stop).unwrap();
        tx_b.send(Event::Stop).unwrap();
        ha.join().unwrap();
        hb.join().unwrap();
    }

    #[test]
    fn staged_parts_are_carried_to_a_later_snapshot() {
        // a keeps nine blocks of undo; its block 1 makes 20,000 outputs, so
        // the state has two parts. b fast-syncs with a sync point of 4 from
        // block 8's snapshot, but fetches only part 0 of it. a then grows to
        // 16, so that block 8 is about to leave its window: b moves to block
        // 12's snapshot, carries part 0 forward through the spend in block
        // 10, and fetches only part 1 again.
        let big = || ChainParams { max_block_size: ChainParams::MAINNET.max_block_size, ..params() };
        let make = |name: &str, window: Option<u32>| {
            let dir = TempDir::new(name);
            let seed = seed();
            let dataset = Dataset::generate(&seed);
            let chain = Chain::open(&dir.0.join("chain"), 256 << 20, big(), seed, AcceptAllProofs).unwrap();
            let chain = chain.with_max_undo(window);
            chain.init_or_check_genesis().unwrap();
            Fixture { dir, chain: Arc::new(chain), dataset }
        };
        let a = make("carry-a", Some(9));
        let now = unix_now();
        let mut t = T0;
        let mut grow = |a: &Fixture, h: u64, via: Option<&SyncSender<Event>>| {
            t += 600;
            let n = if h == 1 { 20_000 } else { 1 };
            let key = pk(h as u8);
            let inputs = match h {
                10 => vec![5],
                14 => vec![7],
                _ => vec![],
            };
            // The first output claims it all; the rest, of amount zero,
            // are made distinct by their memos.
            let total = claim(a, &inputs);
            let outputs = (0..n)
                .map(|i| {
                    let memo = [
                        crate::poseidon2::Fp::from_u64(i),
                        crate::poseidon2::Fp::ZERO,
                        crate::poseidon2::Fp::ZERO,
                        crate::poseidon2::Fp::ZERO,
                        crate::poseidon2::Fp::ZERO,
                    ];
                    let mut o = Output::new(&key, if i == 0 { total } else { 0 }).block_output();
                    o.memo = memo;
                    o
                })
                .collect();
            let block = mine_body(a, Body { inputs, outputs, proof: vec![h as u8; 100], ..Default::default() }, t);
            match via {
                // Through a's node, which announces it.
                Some(tx) => {
                    let id = block.header.hash();
                    tx.send(Event::Mined(block)).unwrap();
                    while a.chain.tip().unwrap().unwrap().hash() != id {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                None => {
                    a.chain.apply_block(&block, now).unwrap();
                }
            }
        };
        for h in 1..=12 {
            grow(&a, h, None);
        }
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let b = make("carry-b", None);
        let mut cb = config(vec![addr_a], &b.dir);
        cb.sync_point = Some(4);
        let (mut node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        node_b.hold_parts = Some(1);
        let staged = Arc::clone(&node_b.parts_staged);
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        let deadline = Instant::now() + guard(30);
        while staged.load(Ordering::Relaxed) < 1 {
            assert!(Instant::now() < deadline, "b staged no part of block 8's snapshot");
            std::thread::sleep(Duration::from_millis(50));
        }
        for h in 13..=16 {
            grow(&a, h, Some(&tx_a));
        }
        let a_tip = a.chain.tip().unwrap().unwrap();
        assert!(wait_for_tip(&b.chain, &a_tip, 60), "b did not reach a's tip");
        assert_eq!(b.chain.state_root().unwrap(), a.chain.state_root().unwrap());
        assert_eq!(b.chain.floor().unwrap(), Some(12));
        // Part 0 once, for block 8, and part 1 once, for block 12.
        assert_eq!(staged.load(Ordering::Relaxed), 2);
        tx_a.send(Event::Stop).unwrap();
        tx_b.send(Event::Stop).unwrap();
        ha.join().unwrap();
        hb.join().unwrap();
    }

    #[test]
    fn a_sync_point_deeper_than_peers_keep_uses_the_deepest_snapshot_kept() {
        // a keeps nine blocks of undo, so of its sixteen it serves snapshots
        // from block 8 on. b asks for a sync point of 12, which would be
        // block 4's: it takes block 12's, the deepest a keeps with a margin,
        // rather than waiting for ever.
        let dir = TempDir::new("deep-a");
        let seed = seed();
        let dataset = Dataset::generate(&seed);
        let chain = Chain::open(&dir.0.join("chain"), 64 << 20, params(), seed, AcceptAllProofs).unwrap();
        let chain = chain.with_max_undo(Some(9));
        chain.init_or_check_genesis().unwrap();
        let a = Fixture { dir, chain: Arc::new(chain), dataset };
        let now = unix_now();
        for tag in 1..=16u8 {
            let block = mine(&a, tag, T0 + 600 * tag as u64);
            a.chain.apply_block(&block, now).unwrap();
        }
        assert_eq!(a.chain.oldest_body().unwrap(), 8);
        let a_tip = a.chain.tip().unwrap().unwrap();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let b = open("deep-b");
        let mut cb = config(vec![addr_a], &b.dir);
        cb.sync_point = Some(12);
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        assert!(wait_for_tip(&b.chain, &a_tip, 30), "b did not fast-sync to a's tip");
        // a keeps bodies from 8: the snapshot sits a block above that.
        assert_eq!(b.chain.floor().unwrap(), Some(9));
        assert_eq!(b.chain.state_root().unwrap(), a.chain.state_root().unwrap());
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
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn a_false_claim_of_work_does_not_stall_the_sync() {
        // The liar answers pings claiming all the work there could be, and
        // nothing else. c, knowing it and a, must still sync from a, and
        // stop counting itself as behind (which would idle its miner).
        false_claim_does_not_stall("liar", 1_000_000);
    }

    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn a_false_claim_of_work_at_a_low_height_does_not_stall_the_sync() {
        // The same liar, claiming its work at height 1: too short for the
        // header pipeline, it used to be neither asked nor passed over.
        false_claim_does_not_stall("short-liar", 1);
    }

    /// A peer that answers pings claiming all the work there could be at
    /// `height`, and nothing else; it lies until the flag is cleared.
    fn liar(genesis: Digest, height: u32) -> (SocketAddr, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let liar = UdpSocket::bind("127.0.0.1:0").unwrap();
        liar.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let addr = liar.local_addr().unwrap();
        let lying = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&lying);
        let h = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while flag.load(Ordering::Relaxed) {
                let Ok((n, from)) = liar.recv_from(&mut buf) else { continue };
                if let Some(Message::Ping(st)) = Message::decode(&buf[..n]) {
                    let claim = Status {
                        nonce: st.nonce,
                        version: PROTOCOL_VERSION,
                        token: 0,
                        genesis,
                        height,
                        oldest: 1,
                        tip: genesis,
                        work: U256([u64::MAX; 4]),
                        min_fee: 0,
                        pool_fee: 0,
                    };
                    let _ = liar.send_to(&Message::Pong(claim).encode(), from);
                }
            }
        });
        (addr, lying, h)
    }

    /// A claim of more work, with no header to back it, never holds the
    /// miner back: a peer could otherwise stop every miner it reaches by
    /// claiming (`syncing` is what the miner waits on).
    #[test]
    fn a_claim_of_work_alone_does_not_hold_the_miner() {
        let c = open("claim-c");
        let now = unix_now();
        let mut t = T0;
        for tag in 1..=3u8 {
            t += 600;
            c.chain.apply_block(&mine(&c, tag, t), now).unwrap();
        }
        let genesis = c.chain.header_at(0).unwrap().unwrap().hash();
        let (liar_addr, lying, hl) = liar(genesis, 1_000_000);
        let (node_c, tx_c) = Node::bind(Arc::clone(&c.chain), pool(), config(vec![liar_addr], &c.dir)).unwrap();
        let syncing = node_c.syncing();
        let stats = node_c.stats();
        let hc = std::thread::spawn(move || node_c.run());
        // Once the liar is a live peer (stats refresh once a second), c
        // never counts itself behind, before or after HEADER_TIMEOUT.
        let deadline = Instant::now() + guard(10);
        while !stats.lock().unwrap().peers.iter().any(|p| p.live) {
            assert!(Instant::now() < deadline, "the liar never became a peer");
            std::thread::sleep(Duration::from_millis(100));
        }
        let until = Instant::now() + net::HEADER_TIMEOUT + Duration::from_secs(2);
        while Instant::now() < until {
            assert!(!syncing.load(Ordering::Acquire), "c counts itself behind a bare claim");
            std::thread::sleep(Duration::from_millis(100));
        }
        lying.store(false, Ordering::Relaxed);
        hl.join().unwrap();
        tx_c.send(Event::Stop).unwrap();
        hc.join().unwrap();
    }

    fn false_claim_does_not_stall(name: &str, liar_height: u32) {
        let a = open(&format!("{name}-a"));
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
        let (liar_addr, lying, hl) = liar(genesis, liar_height);
        let c = open(&format!("{name}-c"));
        let (node_c, tx_c) = Node::bind(Arc::clone(&c.chain), pool(), config(vec![liar_addr, addr_a], &c.dir)).unwrap();
        let syncing = node_c.syncing();
        let hc = std::thread::spawn(move || node_c.run());
        assert!(wait_for_tip(&c.chain, &a_tip, 40), "c did not sync from a");
        // The liar is passed over once it has sent nothing for HEADER_TIMEOUT.
        let deadline = Instant::now() + net::HEADER_TIMEOUT + Duration::from_secs(5);
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

    /// The message layer in init mode: a seed started with `--relay`
    /// holds the sessions of two participants; one reaches the other by
    /// id, and the answer comes back sealed to the key the first carried.
    /// An id with no session is reported offline; a node without
    /// `--relay` refuses sessions.
    #[test]
    fn messages_meet_at_a_rendezvous_point() {
        use crate::onion;
        let (r, p, q, n, x) = (open("rv-relay"), open("rv-p"), open("rv-q"), open("rv-plain"), open("rv-x"));
        let mut cfg = config(vec![], &r.dir);
        cfg.relay = true;
        let (node_r, tx_r) = Node::bind(Arc::clone(&r.chain), pool(), cfg).unwrap();
        let addr_r = node_r.local_addr().unwrap();
        let (node_n, tx_n) = Node::bind(Arc::clone(&n.chain), pool(), config(vec![], &n.dir)).unwrap();
        let addr_n = node_n.local_addr().unwrap();
        let participant = |f: &Fixture, tag: u8, seed: SocketAddr| {
            let mut cfg = config(vec![], &f.dir);
            cfg.seeds = vec![seed.to_string()];
            cfg.identity = Some(crate::mldsa::keygen(&[tag; 32]));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let notes = node.take_notes().unwrap();
            let stats = node.stats();
            (node, tx, notes, stats)
        };
        let (node_p, tx_p, notes_p, stats_p) = participant(&p, 1, addr_r);
        let (node_q, tx_q, notes_q, _) = participant(&q, 2, addr_r);
        let (node_x, tx_x, _, stats_x) = participant(&x, 3, addr_n);
        let id_p = crate::address::id_of(crate::mldsa::keygen(&[1; 32]).public_key());
        let id_q = crate::address::id_of(crate::mldsa::keygen(&[2; 32]).public_key());
        let handles: Vec<_> =
            [node_r, node_n, node_p, node_q, node_x].into_iter().map(|n| std::thread::spawn(move || n.run())).collect();
        let live = |stats: &Arc<Mutex<Stats>>, secs: u64| {
            let deadline = Instant::now() + guard(secs);
            while Instant::now() < deadline {
                let s = stats.lock().unwrap().clone();
                if !s.rendezvous.is_empty() && s.rendezvous.iter().all(|(_, l)| *l) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            false
        };
        assert!(live(&stats_p, 15), "p's session did not go live: {:?}", stats_p.lock().unwrap().rendezvous);
        let wait = |rx: &Receiver<Note>| rx.recv_timeout(guard(20)).expect("a note");
        // q reaches p by id alone: q's node asks the point for p's announce.
        let out = Outbound {
            tag: 7,
            to: id_p,
            kind: onion::KIND_SLATE,
            inner: b"a slate".to_vec(),
            recipient: None,
            reply: None,
            group: 0,
        };
        tx_q.send(Event::Send(out)).unwrap();
        let mut got = None;
        let mut delivered = false;
        let deadline = Instant::now() + guard(20);
        while (got.is_none() || !delivered) && Instant::now() < deadline {
            if let Ok(Note::Received(o)) = notes_p.recv_timeout(Duration::from_millis(100)) {
                got = Some(o);
            }
            if let Ok(note) = notes_q.try_recv() {
                assert!(matches!(note, Note::Delivered { tag: 7, via, .. } if via == addr_r), "{note:?}");
                delivered = true;
            }
        }
        let got = got.expect("p did not receive q's message");
        assert!(delivered, "q was not told its message was delivered");
        assert_eq!((got.kind, &got.inner[..]), (onion::KIND_SLATE, &b"a slate"[..]));
        let q_announce = got.from.expect("q names itself");
        assert_eq!(q_announce.id, id_q);
        // p answers to the key q carried; q need not ask for it.
        let out = Outbound {
            tag: 8,
            to: id_q,
            kind: onion::KIND_SLATE,
            inner: b"answered".to_vec(),
            recipient: Some(q_announce),
            reply: None,
            group: 0,
        };
        tx_p.send(Event::Send(out)).unwrap();
        let mut answer = None;
        let deadline = Instant::now() + guard(20);
        while answer.is_none() && Instant::now() < deadline {
            if let Ok(Note::Received(o)) = notes_q.recv_timeout(Duration::from_millis(100)) {
                answer = Some(o);
            }
        }
        let answer = answer.expect("q did not receive p's answer");
        assert_eq!(&answer.inner[..], b"answered");
        assert_eq!(answer.from.map(|a| a.id), Some(id_p));
        assert!(matches!(wait(&notes_p), Note::Delivered { tag: 8, .. }));
        // An id with no session anywhere: offline.
        let nobody = crate::address::id_of(crate::mldsa::keygen(&[9; 32]).public_key());
        tx_q.send(Event::Send(Outbound {
            tag: 9,
            to: nobody,
            kind: 1,
            inner: vec![],
            recipient: None,
            reply: None,
            group: 0,
        }))
        .unwrap();
        match wait(&notes_q) {
            Note::Failed { tag: 9, why, .. } => assert!(why.contains("offline"), "{why}"),
            other => panic!("{other:?}"),
        }
        // A node without --relay holds no sessions.
        std::thread::sleep(Duration::from_secs(2));
        let s = stats_x.lock().unwrap().clone();
        assert_eq!(s.rendezvous, vec![(addr_n, false)]);
        for tx in [tx_r, tx_n, tx_p, tx_q, tx_x] {
            tx.send(Event::Stop).unwrap();
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    /// A payment end to end over the message layer: alice's wallet starts
    /// a slate for bob's id, bob's wallet answers it over the key alice
    /// carried, and alice's signs the answer; an answer from anyone else
    /// is refused.
    #[test]
    fn a_payment_by_id_goes_and_comes_back() {
        use crate::onion;
        use crate::wallet::{Incoming, Wallet};
        let (r, p, q) = (open("pay-relay"), open("pay-alice"), open("pay-bob"));
        let (alice, _) = Wallet::open(&p.dir.0.join("wallet")).unwrap();
        let (bob, _) = Wallet::open(&q.dir.0.join("wallet")).unwrap();
        // alice holds an output on her node's chain.
        let funds = alice.receive(SUBSIDY).unwrap();
        let body =
            Body { inputs: vec![], outputs: vec![funds.block_output()], proof: vec![1; 2500], ..Default::default() };
        let block = mine_body(&p, body, T0 + 600);
        p.chain.apply_block(&block, unix_now()).unwrap();
        let (_, first, outputs) = p.chain.main_outputs(1).unwrap().unwrap();
        assert_eq!(alice.locate(first, &outputs).unwrap(), 1);
        let mut cfg = config(vec![], &r.dir);
        cfg.relay = true;
        let (node_r, tx_r) = Node::bind(Arc::clone(&r.chain), pool(), cfg).unwrap();
        let addr_r = node_r.local_addr().unwrap();
        let participant = |f: &Fixture, w: &Wallet| {
            let mut cfg = config(vec![], &f.dir);
            cfg.seeds = vec![addr_r.to_string()];
            cfg.identity = Some(w.identity_key());
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let notes = node.take_notes().unwrap();
            let stats = node.stats();
            (node, tx, notes, stats)
        };
        let (node_a, tx_a, notes_a, stats_a) = participant(&p, &alice);
        let (node_b, tx_b, notes_b, stats_b) = participant(&q, &bob);
        let handles: Vec<_> =
            [node_r, node_a, node_b].into_iter().map(|n| std::thread::spawn(move || n.run())).collect();
        let deadline = Instant::now() + guard(15);
        let live = |s: &Arc<Mutex<Stats>>| s.lock().unwrap().rendezvous.iter().any(|(_, l)| *l);
        while !(live(&stats_a) && live(&stats_b)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(live(&stats_a) && live(&stats_b), "the sessions did not go live");
        let received = |rx: &Receiver<Note>| {
            let deadline = Instant::now() + guard(20);
            while Instant::now() < deadline {
                if let Ok(Note::Received(o)) = rx.recv_timeout(Duration::from_millis(100)) {
                    return o;
                }
            }
            panic!("nothing received");
        };
        // alice sends a slate to bob's id, as `send AMOUNT tab1…` does.
        let slate = {
            let rtxn = p.chain.env().read_txn().unwrap();
            alice.send(20_000_000, None, false, p.chain.utxo(), &rtxn).unwrap()
        };
        let out = Outbound {
            tag: 1,
            to: bob.id(),
            kind: onion::KIND_SLATE,
            inner: slate.to_bytes(),
            recipient: None,
            reply: None,
            group: 0,
        };
        tx_a.send(Event::Send(out)).unwrap();
        // bob's wallet answers it, to the key alice carried.
        let o = received(&notes_b);
        let from = o.from.expect("alice names herself");
        assert_eq!(from.id, alice.id());
        let answered = match bob.take_slate(&o.inner, Some(&from.id), None).unwrap() {
            Incoming::Answered(s) => s,
            Incoming::Finalized(..) => panic!("bob had nothing to finalize"),
        };
        assert_eq!((answered.id, answered.stage), (slate.id, 2));
        let out = Outbound {
            tag: 2,
            to: from.id,
            kind: onion::KIND_SLATE,
            inner: answered.to_bytes(),
            recipient: Some(from),
            reply: None,
            group: 0,
        };
        tx_b.send(Event::Send(out)).unwrap();
        // alice's wallet signs the answer; only bob's id may give it.
        let o = received(&notes_a);
        let bob_id = o.from.as_ref().expect("bob names himself").id;
        assert_eq!(bob_id, bob.id());
        let stranger = crate::address::id_of(crate::mldsa::keygen(&[9; 32]).public_key());
        assert!(alice.take_slate(&o.inner, Some(&stranger), Some(&bob.id())).is_err());
        let (finished, signed) = match alice.take_slate(&o.inner, Some(&bob_id), Some(&bob.id())).unwrap() {
            Incoming::Finalized(s, signed) => (s, signed),
            Incoming::Answered(_) => panic!("alice had nothing to answer"),
        };
        assert_eq!(finished.id, slate.id);
        let tx = signed.tx;
        assert!(tx.verify_signatures());
        assert_eq!(tx.balance(), slate.fee as i128);
        // The transaction pays bob an output his wallet holds.
        let to_bob = answered.outputs[1].commitment;
        assert!(tx.outputs.iter().any(|out| out.commitment == to_bob));
        assert_eq!(bob.owned(&to_bob).unwrap().map(|o| o.amount), Some(20_000_000));
        for tx in [tx_r, tx_a, tx_b] {
            tx.send(Event::Stop).unwrap();
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    /// A channel that carries no circuit and nothing but keepalives for a
    /// while is closed (`docs/SCALING.md`), at both ends; a body opens one
    /// again.
    #[test]
    fn idle_channels_are_closed() {
        let (a, b) = (open("idle-ch-a"), open("idle-ch-b"));
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let start = |f: &Fixture, tag: u8| {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = true;
            cfg.identity = Some(key(tag));
            cfg.relay_key = cfg.identity.clone();
            let (node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let (sink, stats) = (Arc::clone(&node.channels.sink), node.stats());
            (addr, tx, sink, stats, std::thread::spawn(move || node.run()))
        };
        let (addr_a, tx_a, sink_a, stats_a, h_a) = start(&a, 1);
        let (_, tx_b, _, stats_b, h_b) = start(&b, 2);
        let channels = |s: &Arc<Mutex<Stats>>| s.lock().unwrap().channels;
        let wait = |want: usize, secs: u64| {
            let deadline = Instant::now() + guard(secs);
            while !(channels(&stats_a) == want && channels(&stats_b) == want) {
                assert!(
                    Instant::now() < deadline,
                    "{} and {} channels, wanted {want}",
                    channels(&stats_a),
                    channels(&stats_b)
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        tx_b.send(Event::TestChannel(addr_a, id(1), b"hello".to_vec())).unwrap();
        wait(1, 20);
        // Idle: closed at both ends, by hand rather than after the timeout.
        for tx in [&tx_a, &tx_b] {
            tx.send(Event::TestExpireIdle).unwrap();
        }
        wait(0, 30);
        tx_b.send(Event::TestChannel(addr_a, id(1), b"again".to_vec())).unwrap();
        wait(1, 20);
        // The channel can be open before the body arrives over it.
        let deadline = Instant::now() + guard(20);
        while sink_a.lock().unwrap().len() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let got: Vec<Vec<u8>> = sink_a.lock().unwrap().iter().map(|d| d.2.clone()).collect();
        assert_eq!(got, vec![b"hello".to_vec(), b"again".to_vec()]);
        for tx in [tx_a, tx_b] {
            tx.send(Event::Stop).unwrap();
        }
        for h in [h_a, h_b] {
            h.join().unwrap();
        }
    }

    /// Onion mode's channels between nodes: a participant opens one to a
    /// relay and stays anonymous; a relay opens one to a relay and proves
    /// its id; bodies arrive in order. A wrong id, or a node that does not
    /// relay, gets no channel.
    /// A relay's auth held back past the unused window (3 s in tests),
    /// its frames refused meanwhile for want of it: the channel is kept,
    /// each refused frame and hello again showing the initiator is there,
    /// and opens once the auth comes; before, it was closed at 3 s without
    /// a word and the bodies lost. No timing race: the auth is dropped by
    /// kind until a set time, and what is asserted is that the bodies come.
    #[test]
    fn a_channel_waits_for_an_auth_held_back() {
        let (a, b) = (open("held-auth-a"), open("held-auth-b"));
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        // Past the window (the channel closed there before), short of the
        // frames' resends spacing out past it (1, 2, 4 s).
        let release = Instant::now() + super::channels::UNUSED_TIMEOUT + Duration::from_secs(1);
        let start = |f: &Fixture, tag: u8, hold: bool| {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = true;
            cfg.identity = Some(key(tag));
            cfg.relay_key = cfg.identity.clone();
            let (node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            if hold {
                *node.drop_out.borrow_mut() = Some(Box::new(move |m: &Message| {
                    matches!(m, Message::Handshake { stage: 3, .. }) && Instant::now() < release
                }));
            }
            let addr = node.local_addr().unwrap();
            let sink = Arc::clone(&node.channels.sink);
            (addr, tx, sink, std::thread::spawn(move || node.run()))
        };
        let (addr_a, tx_a, sink_a, h_a) = start(&a, 1, false);
        let (_, tx_b, _, h_b) = start(&b, 2, true);
        for k in 0..5 {
            tx_b.send(Event::TestChannel(addr_a, id(1), format!("held {k}").into_bytes())).unwrap();
        }
        let deadline = Instant::now() + guard(30);
        while sink_a.lock().unwrap().len() < 5 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let got: Vec<(Option<Digest>, Vec<u8>)> = sink_a.lock().unwrap().iter().map(|(_, p, b)| (*p, b.clone())).collect();
        let want: Vec<(Option<Digest>, Vec<u8>)> = (0..5).map(|k| (Some(id(2)), format!("held {k}").into_bytes())).collect();
        assert_eq!(got, want);
        for tx in [tx_a, tx_b] {
            tx.send(Event::Stop).unwrap();
        }
        h_a.join().unwrap();
        h_b.join().unwrap();
    }

    /// A relay that lost a channel (a restart) tells the other end at its
    /// next frame, which closes at once rather than after its own timeout
    /// (20 s in tests); a new channel then carries on.
    #[test]
    fn a_channel_the_other_end_lost_is_closed_at_once() {
        let (a, b) = (open("gone-a"), open("gone-b"));
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let start = |f: &Fixture, tag: u8| {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = true;
            cfg.identity = Some(key(tag));
            cfg.relay_key = cfg.identity.clone();
            let (node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let sink = Arc::clone(&node.channels.sink);
            let stats = node.stats();
            (addr, tx, sink, stats, std::thread::spawn(move || node.run()))
        };
        let (addr_a, tx_a, sink_a, _, h_a) = start(&a, 1);
        let (_, tx_b, _, stats_b, h_b) = start(&b, 2);
        let wait_for = |what: &str, secs: u64, ok: &dyn Fn() -> bool| {
            let deadline = Instant::now() + guard(secs);
            while !ok() {
                assert!(Instant::now() < deadline, "{what}");
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        tx_b.send(Event::TestChannel(addr_a, id(1), b"first".to_vec())).unwrap();
        wait_for("the first body", 10, &|| sink_a.lock().unwrap().len() == 1);
        wait_for("b's channel counted", 5, &|| stats_b.lock().unwrap().channels == 1);
        tx_a.send(Event::TestForgetChannels).unwrap();
        // b's next frame (its keepalive, 5 s in tests, or a body) is
        // answered ChannelGone; b closes within the round trip, far short
        // of its 20 s.
        tx_b.send(Event::TestChannel(addr_a, id(1), b"lost".to_vec())).unwrap();
        wait_for("b closing the lost channel", 5, &|| stats_b.lock().unwrap().channels == 0);
        tx_b.send(Event::TestChannel(addr_a, id(1), b"again".to_vec())).unwrap();
        wait_for("a body over a new channel", 10, &|| {
            sink_a.lock().unwrap().iter().any(|(_, _, b)| b == b"again")
        });
        for tx in [tx_a, tx_b] {
            tx.send(Event::Stop).unwrap();
        }
        h_a.join().unwrap();
        h_b.join().unwrap();
    }

    /// A node stopping says goodbye: a relay it had a channel to closes
    /// it at once, and a peer drops it from its table, rather than after
    /// 20 s (a channel's timeout in tests) and 180 s of silence.
    #[test]
    fn a_node_stopping_tells_its_channels_and_peers() {
        let (a, b) = (open("bye-a"), open("bye-b"));
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut cfg = config(vec![], &a.dir);
        cfg.relay = true;
        cfg.identity = Some(key(1));
        cfg.relay_key = cfg.identity.clone();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), cfg).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let stats_a = node_a.stats();
        let sink_a = Arc::clone(&node_a.channels.sink);
        let h_a = std::thread::spawn(move || node_a.run());
        let mut cfg = config(vec![addr_a], &b.dir);
        cfg.relay = true;
        cfg.identity = Some(key(2));
        cfg.relay_key = cfg.identity.clone();
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cfg).unwrap();
        let addr_b = node_b.local_addr().unwrap();
        let h_b = std::thread::spawn(move || node_b.run());
        let wait_for = |what: &str, secs: u64, ok: &dyn Fn() -> bool| {
            let deadline = Instant::now() + guard(secs);
            while !ok() {
                assert!(Instant::now() < deadline, "{what}");
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        let b_peer_of_a =
            || stats_a.lock().unwrap().peers.iter().any(|p| p.addr == addr_b && p.handshaken && p.live);
        tx_b.send(Event::TestChannel(addr_a, id(1), b"hello".to_vec())).unwrap();
        wait_for("b's body at a", 10, &|| sink_a.lock().unwrap().len() == 1);
        wait_for("b a peer of a", 15, &b_peer_of_a);
        wait_for("a's channel counted", 5, &|| stats_a.lock().unwrap().channels == 1);
        tx_b.send(Event::Stop).unwrap();
        h_b.join().unwrap();
        wait_for("a closing b's channel", 5, &|| stats_a.lock().unwrap().channels == 0);
        wait_for("a dropping b", 5, &|| !stats_a.lock().unwrap().peers.iter().any(|p| p.addr == addr_b));
        tx_a.send(Event::Stop).unwrap();
        h_a.join().unwrap();
    }

    #[test]
    fn channels_open_between_nodes() {
        let (a, b, c, d) = (open("ch-relay-a"), open("ch-relay-b"), open("ch-participant"), open("ch-plain"));
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let start = |f: &Fixture, relay: bool, tag: u8| {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = relay;
            cfg.identity = Some(key(tag));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let sink = Arc::clone(&node.channels.sink);
            let stats = node.stats();
            (addr, tx, sink, stats, std::thread::spawn(move || node.run()))
        };
        let (addr_a, tx_a, sink_a, stats_a, h_a) = start(&a, true, 1);
        let (_, tx_b, _, _, h_b) = start(&b, true, 2);
        let (_, tx_c, _, _, h_c) = start(&c, false, 3);
        let (addr_d, tx_d, sink_d, _, h_d) = start(&d, false, 4);
        let n = 100usize;
        for k in 0..n {
            tx_b.send(Event::TestChannel(addr_a, id(1), format!("from b {k}").into_bytes())).unwrap();
            tx_c.send(Event::TestChannel(addr_a, id(1), format!("from c {k}").into_bytes())).unwrap();
        }
        // c expects another key at a's address; nobody relays at d.
        tx_c.send(Event::TestChannel(addr_a, id(9), b"to an impostor".to_vec())).unwrap();
        tx_c.send(Event::TestChannel(addr_d, id(4), b"to a non-relay".to_vec())).unwrap();
        let deadline = Instant::now() + guard(20);
        while sink_a.lock().unwrap().len() < 2 * n && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_millis(500));
        let got = sink_a.lock().unwrap().clone();
        let from = |who: &str| -> Vec<(Option<Digest>, Vec<u8>)> {
            got.iter()
                .filter(|(_, _, b)| b.starts_with(format!("from {who}").as_bytes()))
                .map(|(_, p, b)| (*p, b.clone()))
                .collect()
        };
        let (bs, cs) = (from("b"), from("c"));
        assert_eq!(
            (bs.len(), cs.len(), got.len()),
            (n, n, 2 * n),
            "{:?}",
            got.iter().map(|g| &g.2).collect::<Vec<_>>()
        );
        for k in 0..n {
            // b proved it is the relay with id 2; c is nobody.
            assert_eq!(bs[k], (Some(id(2)), format!("from b {k}").into_bytes()));
            assert_eq!(cs[k], (None, format!("from c {k}").into_bytes()));
        }
        assert!(sink_d.lock().unwrap().is_empty());
        // b's and c's: the one c abandoned when a's key was not the one it
        // expected carries no frame, and a closes it (after 3 s in tests).
        // Stats refresh once a second.
        let deadline = Instant::now() + guard(10);
        while stats_a.lock().unwrap().channels != 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(stats_a.lock().unwrap().channels, 2);
        for tx in [tx_a, tx_b, tx_c, tx_d] {
            tx.send(Event::Stop).unwrap();
        }
        for h in [h_a, h_b, h_c, h_d] {
            h.join().unwrap();
        }
    }

    /// A circuit through three listed relays: data reaches the hop it is
    /// for and no other, answers come back from the right hop, a message
    /// spans several cells. A hop refuses to extend to an unlisted relay.
    #[test]
    fn circuits_are_built_hop_by_hop() {
        use circuits::Seen;
        let fixtures: Vec<Fixture> = (0..5).map(|i| open(&format!("circ-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 4;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let seen = Arc::clone(&node.circuits.seen);
            nodes.push((addr, tx, seen, std::thread::spawn(move || node.run())));
        }
        // a, b and c are listed; d relays but is not; p is the client.
        let listed: Vec<consensus::Relay> =
            (0..3).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        for n in &nodes {
            n.1.send(Event::TestQuiet).unwrap();
            n.1.send(Event::TestRelays(listed.clone())).unwrap();
        }
        let big: Vec<u8> = b"echo:".iter().copied().chain((0..5000u32).map(|i| i as u8)).collect();
        let queued = vec![(2, b"echo:one".to_vec()), (1, b"echo:mid".to_vec()), (2, big.clone())];
        nodes[4].1.send(Event::TestCircuit(vec![id(1), id(2), id(3)], queued)).unwrap();
        let wait = |seen: &Arc<Mutex<Vec<Seen>>>, n: usize| {
            let deadline = Instant::now() + guard(30);
            while seen.lock().unwrap().len() < n && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            seen.lock().unwrap().clone()
        };
        let got = wait(&nodes[4].2, 4);
        let mut echoed = b"echoed:".to_vec();
        echoed.extend_from_slice(&big[5..]);
        assert_eq!(got.len(), 4);
        assert_eq!(got[0], Seen::Ready(0));
        // In order from each hop; the middle one's answer may come first.
        let from = |hop: usize| {
            got.iter().filter(|s| matches!(s, Seen::Data(0, h, _) if *h == hop)).cloned().collect::<Vec<_>>()
        };
        assert_eq!(from(1), vec![Seen::Data(0, 1, b"echoed:mid".to_vec())]);
        assert_eq!(from(2), vec![Seen::Data(0, 2, b"echoed:one".to_vec()), Seen::Data(0, 2, echoed)]);
        // Each hop saw only what was for it.
        assert!(nodes[0].2.lock().unwrap().is_empty());
        assert_eq!(*nodes[1].2.lock().unwrap(), vec![Seen::AtHop(b"echo:mid".to_vec())]);
        assert_eq!(*nodes[2].2.lock().unwrap(), vec![Seen::AtHop(b"echo:one".to_vec()), Seen::AtHop(big)]);
        // Through a to d, which is not listed: a refuses, the circuit ends.
        nodes[4].1.send(Event::TestCircuit(vec![id(1), id(4)], vec![])).unwrap();
        let got = wait(&nodes[4].2, 5);
        assert_eq!(got[4], Seen::Failed(1));
        assert!(nodes[3].2.lock().unwrap().is_empty());
        for n in &nodes {
            n.1.send(Event::Stop).unwrap();
        }
        for n in nodes {
            n.3.join().unwrap();
        }
    }

    /// Onion mode's rendezvous service, the participants driven by hand:
    /// p holds a session at its rendezvous point over a circuit; q, whose
    /// circuit ends at another relay, looks p up and sends it a payload,
    /// which its relay forwards to p's point and down p's circuit.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn rendezvous_points_meet_over_circuits() {
        use crate::onion::{Announce, Object, Payload};
        use circuits::Seen;
        let fixtures: Vec<Fixture> = (0..5).map(|i| open(&format!("rdv-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 3;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let seen = Arc::clone(&node.circuits.seen);
            nodes.push((addr, tx, seen, std::thread::spawn(move || node.run())));
        }
        let mut listed: Vec<consensus::Relay> =
            (0..3).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        listed.sort_by_key(|r| digest_to_bytes(&r.id));
        for n in &nodes {
            n.1.send(Event::TestQuiet).unwrap();
            n.1.send(Event::TestRelays(listed.clone())).unwrap();
        }
        let (p, q) = (3usize, 4usize);
        let (id_p, key_p, key_q) = (id(4), key(4), key(5));
        // p's first rendezvous point; q's circuit ends elsewhere.
        let ids: Vec<Digest> = listed.iter().map(|r| r.id).collect();
        let rp = listed[crate::onion::rendezvous_relays(&id_p, 0, &ids)[0]].id;
        let others: Vec<Digest> = listed.iter().map(|r| r.id).filter(|r| *r != rp).collect();
        let wait = |n: usize, pred: &dyn Fn(&Seen) -> bool| {
            let deadline = Instant::now() + guard(30);
            loop {
                if let Some(s) = nodes[n].2.lock().unwrap().iter().find(|s| pred(s)).cloned() {
                    return s;
                }
                assert!(Instant::now() < deadline, "waited in vain: {:?}", nodes[n].2.lock().unwrap());
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        let msg = |n: usize, cmd: u8| match wait(n, &|s| matches!(s, Seen::Msg(_, _, c, _) if *c == cmd)) {
            Seen::Msg(_, _, _, b) => {
                nodes[n].2.lock().unwrap().retain(|s| !matches!(s, Seen::Msg(_, _, c, _) if *c == cmd));
                b
            }
            _ => unreachable!(),
        };
        // p: a circuit to its rendezvous point, a session, an announce.
        nodes[p].1.send(Event::TestCircuit(vec![others[0], rp], vec![])).unwrap();
        wait(p, &|s| *s == Seen::Ready(0));
        nodes[p].1.send(Event::TestCircuitSend(0, 1, circuit::SESSION, digest_to_bytes(&id_p).to_vec())).unwrap();
        let state = msg(p, circuit::SESSION_STATE);
        assert_eq!((&state[..32], &state[40..]), (&digest_to_bytes(&id_p)[..], &0u64.to_le_bytes()[..]));
        let nonce = u64::from_le_bytes(state[32..40].try_into().unwrap());
        let kyber = crate::mlkem::keygen(&[7u8; 64]);
        let announce = Announce::make(&key_p, kyber.public_key(), 1, unix_now() + 3600, nonce);
        // An announce bound to another nonce is refused.
        let wrong = Announce::make(&key_p, kyber.public_key(), 1, unix_now() + 3600, nonce ^ 1);
        nodes[p].1.send(Event::TestCircuitSend(0, 1, circuit::ANNOUNCE, wrong.to_bytes())).unwrap();
        let notice = msg(p, circuit::NOTICE);
        assert_eq!(notice[32], net::NOTICE_REJECTED);
        nodes[p].1.send(Event::TestCircuitSend(0, 1, circuit::ANNOUNCE, announce.to_bytes())).unwrap();
        let state = msg(p, circuit::SESSION_STATE);
        assert_eq!(&state[40..], &1u64.to_le_bytes());
        // q: a circuit ending at a relay that is not p's point.
        nodes[q].1.send(Event::TestCircuit(vec![others[0], others[1]], vec![])).unwrap();
        wait(q, &|s| *s == Seen::Ready(0));
        nodes[q].1.send(Event::TestCircuitSend(0, 1, circuit::GET_ANNOUNCE, digest_to_bytes(&id_p).to_vec())).unwrap();
        let found = Announce::from_bytes(&msg(q, circuit::ANNOUNCE)).unwrap();
        assert_eq!(found, announce);
        let q_announce = Announce::make(&key_q, crate::mlkem::keygen(&[8u8; 64]).public_key(), 1, unix_now() + 3600, 0);
        let payload =
            Payload::seal(&found, Some((&key_q, &q_announce)), None, 1, b"a slate", &[3u8; 32], [4u8; 12]).unwrap();
        let bytes = Object::Payload(payload).to_bytes();
        nodes[q].1.send(Event::TestCircuitSend(0, 1, circuit::SEND, bytes.clone())).unwrap();
        let delivered = msg(p, circuit::DELIVER);
        let Some(Object::Payload(got)) = Object::from_bytes(&delivered) else { panic!() };
        let opened = got.open(&kyber, unix_now()).unwrap();
        assert_eq!((opened.kind, &opened.inner[..]), (1, &b"a slate"[..]));
        assert_eq!(opened.from.map(|a| a.id), Some(id(5)));
        // Forwarded once p's node says it arrived.
        let object = digest_to_bytes(&Object::id_of(&bytes)).to_vec();
        nodes[p].1.send(Event::TestCircuitSend(0, 1, circuit::RECEIVED, object.clone())).unwrap();
        let notice = msg(q, circuit::NOTICE);
        assert_eq!((&notice[..32], notice[32]), (&object[..], net::NOTICE_FORWARDED));
        // Unacknowledged, a delivery is reported offline: the payload may
        // have gone down a dead circuit.
        let again =
            Payload::seal(&found, Some((&key_q, &q_announce)), None, 1, b"lost", &[5u8; 32], [6u8; 12]).unwrap();
        let bytes = Object::Payload(again).to_bytes();
        nodes[q].1.send(Event::TestCircuitSend(0, 1, circuit::SEND, bytes.clone())).unwrap();
        msg(p, circuit::DELIVER);
        let notice = msg(q, circuit::NOTICE);
        assert_eq!((&notice[..32], notice[32]), (&digest_to_bytes(&Object::id_of(&bytes))[..], net::NOTICE_OFFLINE));
        // Nobody holds a session for this id.
        nodes[q].1.send(Event::TestCircuitSend(0, 1, circuit::GET_ANNOUNCE, digest_to_bytes(&id(9)).to_vec())).unwrap();
        let notice = msg(q, circuit::NOTICE);
        assert_eq!((&notice[..32], notice[32]), (&digest_to_bytes(&id(9))[..], net::NOTICE_OFFLINE));
        // A lookup at p's own point is answered there.
        nodes[q].1.send(Event::TestCircuit(vec![others[1], rp], vec![])).unwrap();
        wait(q, &|s| *s == Seen::Ready(1));
        nodes[q].1.send(Event::TestCircuitSend(1, 1, circuit::GET_ANNOUNCE, digest_to_bytes(&id_p).to_vec())).unwrap();
        assert_eq!(Announce::from_bytes(&msg(q, circuit::ANNOUNCE)), Some(announce));
        for n in &nodes {
            n.1.send(Event::Stop).unwrap();
        }
        for n in nodes {
            n.3.join().unwrap();
        }
    }

    /// Onion mode end to end: two wallets' nodes keep circuits standing
    /// to their rendezvous points among three listed relays, and one
    /// reaches the other by id and is answered, as in init mode.
    /// The message layer in onion mode over a network that loses a tenth
    /// of the datagrams each way: sessions come up, and messages and their
    /// answers along the route back arrive, sent again when a send fails.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn messages_meet_over_a_lossy_network() {
        messages_over("msg-lossy", 100, 0);
    }

    /// The same over a network that delivers almost a third of the
    /// datagrams after the one sent next.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn messages_meet_over_a_reordering_network() {
        messages_over("msg-reorder", 0, 300);
    }

    /// Three relays and two participants with datagrams lost and reordered,
    /// per thousand: q sends p five messages, and p answers each.
    fn messages_over(name: &str, loss: u64, reorder: u64) {
        use crate::onion;
        let fixtures: Vec<Fixture> = (0..5).map(|i| open(&format!("{name}-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 3;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            node.loss.set((loss, 10 + i as u64));
            node.reorder.set((reorder, 20 + i as u64));
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let stats = node.stats();
            nodes.push((addr, tx, notes, stats, std::thread::spawn(move || node.run())));
        }
        let listed: Vec<consensus::Relay> =
            (0..3).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        for n in &nodes {
            n.1.send(Event::TestRelays(listed.clone())).unwrap();
        }
        let (p, q) = (3usize, 4usize);
        let live = |n: usize| {
            let s = nodes[n].3.lock().unwrap().clone();
            !s.rendezvous.is_empty() && s.rendezvous.iter().all(|(_, l)| *l)
        };
        let deadline = Instant::now() + guard(60);
        while !(live(p) && live(q)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(live(p) && live(q), "sessions never came up ({loss} lost, {reorder} reordered)");
        // A session at each of the three points (three relays: all of them).
        for n in [p, q] {
            assert_eq!(nodes[n].3.lock().unwrap().rendezvous.len(), 3);
        }
        // Sends `out` from `from`, again whenever a send fails or nothing
        // arrives, for up to `secs`: what `to` received, if anything. The
        // reasons sends failed are kept.
        let failures = Mutex::new(Vec::new());
        let deliver = |from: usize, to: usize, out: &Outbound, secs: u64| -> Option<onion::Opened> {
            let deadline = Instant::now() + guard(secs);
            while Instant::now() < deadline {
                nodes[from].1.send(Event::Send(out.clone())).unwrap();
                let until = Instant::now() + guard(15);
                'wait: while Instant::now() < until {
                    if let Ok(Note::Received(o)) = nodes[to].2.recv_timeout(Duration::from_millis(100))
                        && o.inner == out.inner
                    {
                        return Some(o);
                    }
                    while let Ok(n) = nodes[from].2.try_recv() {
                        if let Note::Failed { tag, why, .. } = n
                            && tag == out.tag
                        {
                            failures.lock().unwrap().push(why);
                            break 'wait;
                        }
                    }
                }
            }
            None
        };
        let outbound = |tag: u64, to: Digest, inner: Vec<u8>, reply: Option<onion::Route>| Outbound {
            tag,
            to,
            kind: onion::KIND_SLATE,
            inner,
            recipient: None,
            reply,
            group: 0,
        };
        // An answer goes back along the route the message gave: if that
        // route's circuit is gone, the message is sent again for a new one,
        // as a wallet sends a slate again.
        let mut fresh_routes = 0;
        for k in 0..5u64 {
            let deadline = Instant::now() + guard(180);
            loop {
                let msg = format!("message {k}").into_bytes();
                let o = deliver(q, p, &outbound(100 + k, id(4), msg.clone(), None), 90)
                    .unwrap_or_else(|| panic!("message {k} never arrived: {:?}", failures.lock().unwrap()));
                assert_eq!(o.inner, msg);
                let route = o.route.expect("a way back");
                let answer = outbound(200 + k, route.reply_id(), format!("answer {k}").into_bytes(), Some(route));
                if let Some(a) = deliver(p, q, &answer, 30) {
                    assert_eq!(a.answers, Some(id(4)));
                    break;
                }
                fresh_routes += 1;
                assert!(Instant::now() < deadline, "answer {k} never arrived: {:?}", failures.lock().unwrap());
            }
        }
        eprintln!(
            "{loss} lost, {reorder} reordered: {fresh_routes} answers needed a fresh route; sends failed: {:?}",
            failures.lock().unwrap()
        );
        for n in nodes {
            n.1.send(Event::Stop).unwrap();
            n.4.join().unwrap();
        }
    }

    #[test]
    fn messages_meet_in_onion_mode() {
        use crate::onion;
        let fixtures: Vec<Fixture> = (0..5).map(|i| open(&format!("onion-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 3;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let stats = node.stats();
            nodes.push((addr, tx, notes, stats, std::thread::spawn(move || node.run())));
        }
        let listed: Vec<consensus::Relay> =
            (0..3).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        for n in &nodes {
            n.1.send(Event::TestRelays(listed.clone())).unwrap();
        }
        let (p, q) = (3usize, 4usize);
        let live = |n: usize| {
            let s = nodes[n].3.lock().unwrap().clone();
            !s.rendezvous.is_empty() && s.rendezvous.iter().all(|(_, l)| *l)
        };
        let deadline = Instant::now() + guard(30);
        while !(live(p) && live(q)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            live(p) && live(q),
            "{:?} {:?}",
            nodes[p].3.lock().unwrap().rendezvous,
            nodes[q].3.lock().unwrap().rendezvous
        );
        let delivered = Mutex::new(Vec::new());
        let received = |n: usize| loop {
            match nodes[n].2.recv_timeout(guard(20)).expect("a note") {
                Note::Received(o) => return o,
                Note::Failed { why, .. } => panic!("{why}"),
                Note::Delivered { tag, .. } => delivered.lock().unwrap().push(tag),
                Note::Broadcast { .. } | Note::Delegation { .. } | Note::Cert { .. } => {}
            }
        };
        let out = Outbound {
            tag: 1,
            to: id(4),
            kind: onion::KIND_SLATE,
            inner: b"a slate".to_vec(),
            recipient: None,
            reply: None,
            group: 0,
        };
        nodes[q].1.send(Event::Send(out)).unwrap();
        let o = received(p);
        assert_eq!((o.kind, &o.inner[..]), (onion::KIND_SLATE, &b"a slate"[..]));
        // q is not named: p answers along the route the payload gave.
        assert_eq!(o.from, None);
        let route = o.route.expect("a way back");
        let out = Outbound {
            tag: 2,
            to: route.reply_id(),
            kind: onion::KIND_SLATE,
            inner: b"answered".to_vec(),
            recipient: None,
            reply: Some(route),
            group: 0,
        };
        nodes[p].1.send(Event::Send(out)).unwrap();
        let o = received(q);
        assert_eq!(&o.inner[..], b"answered");
        // The answer came down q's own circuit: it is from whom q sent to.
        assert_eq!((o.from, o.answers), (None, Some(id(4))));
        // Each send was confirmed delivered; the confirmation of one may
        // come after the answer to it.
        for (n, tag) in [(q, 1), (p, 2)] {
            let deadline = Instant::now() + guard(10);
            while !delivered.lock().unwrap().contains(&tag) && Instant::now() < deadline {
                if let Ok(Note::Delivered { tag, .. }) = nodes[n].2.recv_timeout(Duration::from_millis(500)) {
                    delivered.lock().unwrap().push(tag);
                }
            }
        }
        let mut tags = delivered.lock().unwrap().clone();
        tags.sort();
        assert_eq!(tags, vec![1, 2]);
        // Nobody holds a session for this id.
        nodes[q]
            .1
            .send(Event::Send(Outbound {
                tag: 3,
                to: id(9),
                kind: 1,
                inner: vec![],
                recipient: None,
                reply: None,
                group: 0,
            }))
            .unwrap();
        match nodes[q].2.recv_timeout(guard(30)).expect("a note") {
            Note::Failed { tag: 3, why, .. } => assert!(why.contains("offline"), "{why}"),
            other => panic!("{other:?}"),
        }
        for n in &nodes {
            n.1.send(Event::Stop).unwrap();
        }
        for n in nodes {
            n.4.join().unwrap();
        }
    }

    /// `docs/SCALING.md`: an idle participant sends only its channels'
    /// keepalives (its session's comes once an hour here), and when a hop
    /// of its standing circuit dies it learns so from the `Destroy` the
    /// relays pass back, and is reachable again, with no keepalive of its
    /// own to notice.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn an_idle_participant_is_quiet_and_learns_of_a_dead_hop() {
        let fixtures: Vec<Fixture> = (0..6).map(|i| open(&format!("idle-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        let mut handles = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 4;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let (stats, paths, frames) =
                (node.stats(), Arc::clone(&node.circuits.paths), Arc::clone(&node.frames_sent));
            nodes.push((addr, tx, notes, stats, paths, frames));
            handles.push(Some(std::thread::spawn(move || node.run())));
        }
        let mut list: Vec<consensus::Relay> =
            (0..4).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        list.sort_by_key(|r| digest_to_bytes(&r.id));
        let (p, q) = (4usize, 5usize);
        for n in &nodes {
            n.1.send(Event::TestRelays(list.clone())).unwrap();
        }
        let hour = Duration::from_secs(3600);
        for n in [p, q] {
            nodes[n].1.send(Event::TestTiming(hour, hour, Duration::from_secs(3))).unwrap();
        }
        // Every session of p's live, but at `gone` (a relay stopped, which
        // may be one of its three points).
        let live = |secs: u64, gone: Option<SocketAddr>| {
            let deadline = Instant::now() + guard(secs);
            loop {
                let s = nodes[p].3.lock().unwrap().rendezvous.clone();
                if s.len() == 3 && s.iter().filter(|(a, _)| Some(*a) != gone).all(|(_, l)| *l) {
                    return;
                }
                assert!(Instant::now() < deadline, "p: {s:?}");
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        live(30, None);
        // Idle: only keepalive frames on its channels (one each per
        // `channel::KEEPALIVE`, at most three channels: its guards).
        std::thread::sleep(Duration::from_secs(3));
        let before = nodes[p].5.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_secs(15));
        let sent = nodes[p].5.load(Ordering::Relaxed) - before;
        let per_channel = 15 / crate::channel::KEEPALIVE.as_secs() + 1;
        assert!(sent <= 3 * per_channel, "{sent} frames in 15 s idle");
        // The standing circuit's middle hop dies.
        let ids: Vec<Digest> = list.iter().map(|r| r.id).collect();
        let point = ids[crate::onion::rendezvous_relays(&id(5), 0, &ids)[0]];
        let path =
            nodes[p].4.lock().unwrap().iter().rev().find(|path| *path.last().unwrap() == point).cloned().unwrap();
        assert_eq!(path.len(), 3, "a guard, a hop, the point: {path:?}");
        let middle = (0..4).find(|&i| id(i as u8 + 1) == path[1]).unwrap();
        nodes[middle].1.send(Event::Stop).unwrap();
        handles[middle].take().unwrap().join().unwrap();
        let stopped = Instant::now();
        // The `Destroy` reaches p: its session is down until it rebuilds.
        let deadline = stopped + guard(60);
        while nodes[p].3.lock().unwrap().rendezvous.iter().all(|(_, l)| *l) {
            assert!(Instant::now() < deadline, "p never heard its circuit was gone");
            std::thread::sleep(Duration::from_millis(50));
        }
        eprintln!("p heard {:?} after its hop stopped", stopped.elapsed());
        live(60, Some(nodes[middle].0));
        // And it is reached there.
        let out =
            Outbound { tag: 1, to: id(5), kind: 1, inner: b"after".to_vec(), recipient: None, reply: None, group: 0 };
        let deadline = Instant::now() + guard(60);
        'sent: loop {
            nodes[q].1.send(Event::Send(out.clone())).unwrap();
            let until = Instant::now() + guard(10);
            while Instant::now() < until {
                if let Ok(Note::Received(o)) = nodes[p].2.recv_timeout(Duration::from_millis(200))
                    && o.inner == b"after"
                {
                    break 'sent;
                }
            }
            assert!(Instant::now() < deadline, "p not reached after the hop died");
        }
        for (i, n) in nodes.iter().enumerate() {
            if i != middle {
                n.1.send(Event::Stop).unwrap();
            }
        }
        for h in handles.into_iter().flatten() {
            h.join().unwrap();
        }
    }

    /// The pool outlives a restart: saved on the way out, pooled again,
    /// checked, when the node starts; each transaction keeps its arrival
    /// time (its age, `docs/FEES.md`), and the ids expired lately stay
    /// refused.
    #[test]
    fn the_pool_is_kept_across_a_restart() {
        let f = open("pool-kept");
        let block = mine(&f, 1, T0 + 600);
        f.chain.apply_block(&block, unix_now()).unwrap();
        let mut k = Key::generate(&{
            let mut s = [0u8; 32];
            s[0] = 1;
            s
        });
        let mut tx = crate::transaction::UnsignedTransaction::new(
            vec![(k.public_key(), SUBSIDY)],
            vec![Output::new(&pk(50), SUBSIDY - 1000)],
        )
        .sign_with(&mut k)
        .unwrap();
        tx.set_positions(&[0]);
        let txid = tx.txid();
        let mempool = pool();
        let (node, events) = Node::bind(Arc::clone(&f.chain), Arc::clone(&mempool), config(vec![], &f.dir)).unwrap();
        let h = std::thread::spawn(move || node.run());
        events.send(Event::Transaction(tx)).unwrap();
        let deadline = Instant::now() + guard(10);
        while !mempool.lock().unwrap().contains(&txid) {
            assert!(Instant::now() < deadline, "not pooled");
            std::thread::sleep(Duration::from_millis(20));
        }
        let arrived = mempool.lock().unwrap().entries().find(|e| e.txid == txid).unwrap().arrived;
        let gone = crate::xmss::Digest::default();
        mempool.lock().unwrap().remember_expired(gone, unix_now() + 3600);
        let seen = (42, 600, unix_now() - 60);
        mempool.lock().unwrap().remember_confirmed(seen.0, seen.1, seen.2);
        events.send(Event::Stop).unwrap();
        h.join().unwrap();
        // A fresh pool, the same data directory: the transaction is back,
        // as old as it was, the expired id still refused, and the
        // confirmation the estimates use kept.
        std::thread::sleep(Duration::from_millis(1100));
        let again = pool();
        let (node, events) = Node::bind(Arc::clone(&f.chain), Arc::clone(&again), config(vec![], &f.dir)).unwrap();
        let pool = again.lock().unwrap();
        assert_eq!(pool.entries().find(|e| e.txid == txid).map(|e| e.arrived), Some(arrived));
        assert!(pool.expired().any(|(id, _)| *id == gone));
        assert_eq!(pool.confirmed().collect::<Vec<_>>(), vec![&seen]);
        drop(pool);
        drop(node);
        drop(events);
    }

    /// Keepalives come 20 to 40 s apart at random (`docs/PRIVACY.md`, fix 3).
    #[test]
    fn keepalives_are_jittered() {
        let d = Duration::from_secs(30);
        let waits: Vec<Duration> = (0..2000).map(|_| participant::jitter(d)).collect();
        assert!(waits.iter().all(|w| *w >= Duration::from_secs(20) && *w < Duration::from_secs(40)));
        let lo = waits.iter().filter(|w| **w < Duration::from_secs(25)).count();
        let hi = waits.iter().filter(|w| **w >= Duration::from_secs(35)).count();
        assert!(lo > 300 && hi > 300, "spread over the range: {lo} low, {hi} high");
    }

    /// What the relays learn of a payment (`docs/PRIVACY.md`, fixes 1, 2
    /// and 4), with six relays so that a sender's outbound circuits can end
    /// away from its rendezvous points: none of its sends goes over a
    /// circuit holding its session, its points see none of them, no relay
    /// sees its id, and the answer comes back down its own circuit.
    #[test]
    fn relays_learn_nothing_of_the_sender() {
        use crate::onion;
        use circuits::Seen;
        const RELAYS: usize = 6;
        let fixtures: Vec<Fixture> = (0..RELAYS + 2).map(|i| open(&format!("priv-{i}"))).collect();
        let mut paths = Vec::new();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < RELAYS;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let (stats, seen) = (node.stats(), Arc::clone(&node.circuits.seen));
            paths.push(Arc::clone(&node.circuits.paths));
            nodes.push((addr, tx, notes, stats, seen, std::thread::spawn(move || node.run())));
        }
        let mut listed: Vec<consensus::Relay> =
            (0..RELAYS).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        listed.sort_by_key(|r| digest_to_bytes(&r.id));
        for n in &nodes {
            n.1.send(Event::TestRelays(listed.clone())).unwrap();
        }
        // p receives, q pays.
        let (p, q) = (RELAYS, RELAYS + 1);
        let (id_p, id_q) = (id(p as u8 + 1), id(q as u8 + 1));
        let live = |n: usize| {
            let s = nodes[n].3.lock().unwrap().clone();
            !s.rendezvous.is_empty() && s.rendezvous.iter().all(|(_, l)| *l)
        };
        let deadline = Instant::now() + guard(30);
        while !(live(p) && live(q)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(live(p) && live(q));
        let received = |n: usize| loop {
            match nodes[n].2.recv_timeout(guard(20)).expect("a note") {
                Note::Received(o) => return o,
                Note::Failed { why, .. } => panic!("{why}"),
                _ => {}
            }
        };
        let out = Outbound {
            tag: 1,
            to: id_p,
            kind: onion::KIND_SLATE,
            inner: b"a slate".to_vec(),
            recipient: None,
            reply: None,
            group: 0,
        };
        nodes[q].1.send(Event::Send(out)).unwrap();
        let o = received(p);
        assert_eq!((o.from.as_ref(), &o.inner[..]), (None, &b"a slate"[..]), "the recipient learns nothing of q");
        let route = o.route.expect("a way back");
        let answer = Outbound {
            tag: 2,
            to: route.reply_id(),
            kind: onion::KIND_SLATE,
            inner: b"answered".to_vec(),
            recipient: None,
            reply: Some(route),
            group: 0,
        };
        nodes[p].1.send(Event::Send(answer)).unwrap();
        let o = received(q);
        assert_eq!((&o.inner[..], o.answers), (&b"answered"[..], Some(id_p)));

        let ids: Vec<Digest> = listed.iter().map(|r| r.id).collect();
        let points = |who: &Digest| -> Vec<Digest> {
            crate::onion::rendezvous_relays(who, 0, &ids).into_iter().map(|i| ids[i]).collect()
        };
        let (points_p, points_q) = (points(&id_p), points(&id_q));
        let q_bytes = digest_to_bytes(&id_q);
        let mut sends = 0;
        for r in 0..RELAYS {
            let me = id(r as u8 + 1);
            for s in nodes[r].4.lock().unwrap().iter() {
                let Seen::AtEnd(cmd, session, msg) = s else { continue };
                let what = [circuit::GET_ANNOUNCE, circuit::SEND, circuit::ROUTE, circuit::REPLY, circuit::BROADCAST];
                if !what.contains(cmd) {
                    continue;
                }
                sends += 1;
                assert_eq!(*session, None, "command {cmd} at {} over a circuit holding a session", onion::short(&me));
                assert!(!msg.windows(32).any(|w| w == q_bytes), "q's id at a relay");
                // q's sends (the lookup, the payload, the route) never at
                // q's points; p's answer never at p's.
                if [circuit::GET_ANNOUNCE, circuit::SEND, circuit::ROUTE].contains(cmd) {
                    assert!(!points_q.contains(&me), "q's command {cmd} at its own point");
                }
                if *cmd == circuit::REPLY {
                    assert!(!points_p.contains(&me), "p's answer at its own point");
                }
            }
        }
        assert!(sends >= 3, "the route, the payload and the answer went up circuits: {sends}");
        // Every circuit of p's and q's starts at one of its guards, kept in
        // its data directory: three at most, for all its circuits.
        for n in [p, q] {
            let text = std::fs::read_to_string(fixtures[n].dir.0.join("guards")).expect("guards saved");
            let guards: Vec<String> = text.lines().map(|l| l.split(' ').next().unwrap().to_string()).collect();
            assert_eq!(guards.len(), 3);
            let hex = |d: &Digest| digest_to_bytes(d).iter().map(|b| format!("{b:02x}")).collect::<String>();
            let mut first: Vec<String> = paths[n].lock().unwrap().iter().map(|path| hex(&path[0])).collect();
            assert!(first.len() >= 2, "standing and outbound circuits: {}", first.len());
            first.sort();
            first.dedup();
            assert!(first.iter().all(|f| guards.contains(f)), "a first hop that is not a guard");
        }
        for n in &nodes {
            n.1.send(Event::Stop).unwrap();
        }
        for n in nodes {
            n.5.join().unwrap();
        }
    }

    /// A new address (`docs/PRIVACY.md`, fix 5): reachable once its
    /// sessions are live, the old one then unreachable, no circuit moving
    /// from one id to the other at any relay; with the address off nobody
    /// reaches the wallet, which can still pay.
    #[test]
    fn a_new_address_leaves_the_old_one_behind() {
        use circuits::Seen;
        const RELAYS: usize = 6;
        let fixtures: Vec<Fixture> = (0..RELAYS + 2).map(|i| open(&format!("addr-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < RELAYS;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let (stats, seen) = (node.stats(), Arc::clone(&node.circuits.seen));
            nodes.push((addr, tx, notes, stats, seen, std::thread::spawn(move || node.run())));
        }
        let listed: Vec<consensus::Relay> =
            (0..RELAYS).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        for n in &nodes {
            n.1.send(Event::TestRelays(listed.clone())).unwrap();
        }
        let (p, q) = (RELAYS, RELAYS + 1);
        let (old, new, id_q) = (id(p as u8 + 1), id(99), id(q as u8 + 1));
        let live = |n: usize| {
            let s = nodes[n].3.lock().unwrap().clone();
            !s.rendezvous.is_empty() && s.rendezvous.iter().all(|(_, l)| *l)
        };
        let deadline = Instant::now() + guard(30);
        while !(live(p) && live(q)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(live(p) && live(q));
        // `from` sends to `to` until it is delivered (`true`) or offline.
        let mut tag = 0u64;
        let mut send = |from: usize, to: Digest| -> bool {
            tag += 1;
            let out = Outbound { tag, to, kind: 1, inner: vec![1], recipient: None, reply: None, group: 0 };
            nodes[from].1.send(Event::Send(out)).unwrap();
            loop {
                match nodes[from].2.recv_timeout(guard(40)).expect("a note") {
                    Note::Delivered { tag: t, .. } if t == tag => return true,
                    Note::Failed { tag: t, why, .. } if t == tag => {
                        assert!(why.contains("offline"), "{why}");
                        return false;
                    }
                    _ => {}
                }
            }
        };
        let until = |want: bool, from: usize, to: Digest, send: &mut dyn FnMut(usize, Digest) -> bool| {
            let deadline = Instant::now() + guard(60);
            while send(from, to) != want {
                assert!(Instant::now() < deadline, "never {}", if want { "delivered" } else { "offline" });
                std::thread::sleep(Duration::from_millis(500));
            }
        };
        assert!(send(q, old));
        nodes[p].1.send(Event::Identity(Some(key(99)))).unwrap();
        until(true, q, new, &mut send);
        until(false, q, old, &mut send);
        // At no relay did a circuit holding the old id's session ask for
        // the new one's.
        for r in 0..RELAYS {
            for s in nodes[r].4.lock().unwrap().iter() {
                if let Seen::AtEnd(cmd, Some(held), msg) = s
                    && *cmd == circuit::SESSION
                {
                    assert!(!(*held == old && msg[..] == digest_to_bytes(&new)[..]), "a circuit moved from old to new");
                }
            }
        }
        // Off: nobody reaches p, which still pays.
        nodes[p].1.send(Event::Identity(None)).unwrap();
        let deadline = Instant::now() + guard(10);
        while !nodes[p].3.lock().unwrap().rendezvous.is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(nodes[p].3.lock().unwrap().rendezvous.is_empty());
        until(false, q, new, &mut send);
        assert!(send(p, id_q), "an address that is off still pays");
        for n in &nodes {
            n.1.send(Event::Stop).unwrap();
        }
        for n in nodes {
            n.5.join().unwrap();
        }
    }

    /// Payment proofs and proofs of burn (`docs/PROOFS.md`), end to end on a
    /// chain: made from the block that created the output, checked against
    /// its header, and refused when anything in them is changed.
    #[test]
    fn payment_and_burn_proofs_verify_against_their_block() {
        use crate::proofs::{Claim, Proof, ProofError, Receipt};
        use crate::wallet::{Slate, Wallet};
        let f = open("proofs");
        let (alice, _) = Wallet::open(&f.dir.0.join("alice")).unwrap();
        let (bob, _) = Wallet::open(&f.dir.0.join("bob")).unwrap();
        let now = unix_now();
        let t = std::cell::Cell::new(T0);
        // Whether the wallet follows the blocks as they come.
        let follow = std::cell::Cell::new(true);
        // Mines `txs` with a reward taking the rest; returns the block.
        let block_with = |txs: &[&crate::transaction::Transaction], inputs: Vec<u64>| {
            t.set(t.get() + 600);
            let mut outputs: Vec<_> = txs.iter().flat_map(|tx| tx.outputs.iter().map(|o| o.block_output())).collect();
            let made: u64 = outputs.iter().map(|o| o.amount).sum();
            outputs.push(Output::new(&pk(9), claim(&f, &inputs) - made).block_output());
            let block = mine_body(&f, Body { inputs, outputs, proof: vec![1; 2500], ..Default::default() }, t.get());
            f.chain.apply_block(&block, now).unwrap();
            let (_, first, outs) = f.chain.main_outputs(block.header.height).unwrap().unwrap();
            if !follow.get() {
                return (block, first, 0);
            }
            alice.locate(first, &outs).unwrap();
            let landed = alice.land_payments(block.header.height, first, &outs).unwrap();
            for p in &landed {
                let (h, position) = p.landed.unwrap();
                let (header, _, path) = f.chain.output_proof_at(position, h).unwrap().unwrap();
                alice.set_payment_path(&p.txid, h, position, path, &header.state_root).unwrap();
            }
            (block, first, landed.len())
        };
        // alice's funds, from block 1.
        let funds = alice.receive(SUBSIDY).unwrap();
        t.set(t.get() + 600);
        let b1 = mine_body(
            &f,
            Body { outputs: vec![funds.block_output()], proof: vec![1; 2500], ..Default::default() },
            t.get(),
        );
        f.chain.apply_block(&b1, now).unwrap();
        alice.locate(0, &[funds.block_output()]).unwrap();

        // A payment to bob by file slates: bob's receipt comes back with it.
        let rtxn = f.chain.env().read_txn().unwrap();
        let mut slate = alice.send(10_000_000, None, true, f.chain.utxo(), &rtxn).unwrap();
        drop(rtxn);
        assert_eq!(slate.sender, alice.id());
        bob.receive_slate(&mut slate).unwrap();
        let mut unsigned = slate.clone();
        unsigned.receipt = None;
        assert!(Slate::from_bytes(&unsigned.to_bytes()).is_none(), "an answered slate without a receipt");
        let mut forged = slate.clone();
        forged.receipt.as_mut().unwrap().signature[7] ^= 1;
        assert!(alice.finalize(&forged).is_err());
        let mut elsewhere = slate.clone();
        elsewhere.sender = bob.id();
        assert!(alice.finalize(&elsewhere).is_err());
        let signed = alice.finalize(&slate).unwrap();
        let (b2, first2, landed) = block_with(&[&signed.tx], vec![0]);
        assert_eq!(landed, 1);
        let payment = alice.payments().unwrap().into_iter().find(|p| !p.is_burn()).unwrap();
        assert_eq!(payment.landed, Some((2, first2 + 1)));
        let proof = payment.proof().expect("made when it landed");
        assert_eq!(proof.check(&b2.header.state_root), Ok(()));
        let Claim::Payment { sender, receipt, .. } = &proof.claim else { panic!() };
        assert_eq!((*sender, receipt.recipient()), (alice.id(), bob.id()));
        assert_eq!(proof.amount, 10_000_000);
        // As text, whatever surrounds it.
        let text = proof.to_text();
        assert!(text.starts_with("-----BEGIN TAB PAYMENT PROOF-----\n"));
        assert_eq!(Proof::from_text(&format!("from alice:\n{text}thanks\n")), Some(proof.clone()));
        assert!(Proof::from_text(&text.replace("PAYMENT", "BURN")).is_none());
        // Only against its own block, and only as it is.
        assert_eq!(proof.check(&b1.header.state_root), Err(ProofError::NotInBlock));
        let tweak = |change: &dyn Fn(&mut Proof)| {
            let mut p = proof.clone();
            change(&mut p);
            p.check(&b2.header.state_root)
        };
        assert_eq!(tweak(&|p| p.amount += 1), Err(ProofError::NotInBlock));
        assert_eq!(tweak(&|p| p.memo[0] += crate::poseidon2::Fp::ONE), Err(ProofError::NotInBlock));
        assert_eq!(tweak(&|p| p.position += 1), Err(ProofError::NotInBlock));
        let other = alice.id();
        assert_eq!(
            tweak(&|p| if let Claim::Payment { sender, .. } = &mut p.claim {
                *sender = bob.id()
            }),
            Err(ProofError::Receipt)
        );
        // A receipt claimed for another address: its key, the same signature.
        let theirs = Receipt::sign(&alice.identity_key(), &proof.output(), &[0; 32], &other);
        assert_eq!(
            tweak(&|p| if let Claim::Payment { receipt, .. } = &mut p.claim {
                receipt.key = theirs.key.clone()
            }),
            Err(ProofError::Receipt)
        );

        // A burn for bob, from alice's change.
        let rtxn = f.chain.env().read_txn().unwrap();
        let burn = alice.burn(1_000_000, &bob.id(), b"credit", None, f.chain.utxo(), &rtxn).unwrap();
        drop(rtxn);
        // The wallet misses the block (a fast sync, say): the burn is found
        // in the output set afterwards, with the block that made it.
        follow.set(false);
        let (b3, _, _) = block_with(&[&burn.tx], vec![first2]);
        follow.set(true);
        let rtxn = f.chain.env().read_txn().unwrap();
        let found = alice.find_payments(f.chain.utxo(), &rtxn).unwrap();
        drop(rtxn);
        assert_eq!(found.len(), 1);
        let (h, position) = found[0].landed.unwrap();
        assert_eq!(h, 3);
        let (header, _, path) = f.chain.output_proof_at(position, h).unwrap().unwrap();
        alice.set_payment_path(&found[0].txid, h, position, path, &header.state_root).unwrap();
        let burned = alice.payments().unwrap().into_iter().find(|p| p.is_burn()).unwrap();
        let proof = burned.proof().unwrap();
        assert_eq!(proof.key_hash, crate::proofs::BURN_KEY_HASH);
        assert_eq!(proof.check(&b3.header.state_root), Ok(()));
        let Claim::Burn(b) = &proof.claim else { panic!() };
        assert_eq!((b.beneficiary, &b.purpose[..]), (bob.id(), &b"credit"[..]));
        assert_eq!(Proof::from_text(&proof.to_text()), Some(proof.clone()));
        let mut other = proof.clone();
        if let Claim::Burn(b) = &mut other.claim {
            b.beneficiary = alice.id();
        }
        assert_eq!(other.check(&b3.header.state_root), Err(ProofError::Burn));
        // A proof against a later block than the one that made the output
        // fails, the output still unspent there.
        let mut later = proof.clone();
        let (_, _, path) = f.chain.output_proof_at(proof.position, 3).unwrap().unwrap();
        later.path = path;
        later.height = 3;
        assert_eq!(later.check(&b3.header.state_root), Ok(()));
        let (b4, _, _) = block_with(&[], vec![]);
        let (_, _, path) = f.chain.output_proof_at(proof.position, 4).unwrap().unwrap();
        later.path = path;
        later.height = 4;
        assert_eq!(later.check(&b4.header.state_root), Err(ProofError::NotInBlock));
    }

    /// In onion mode a wallet's own transaction goes to a relay over a
    /// circuit, which pools and announces it; the wallet's node never
    /// announces it itself.
    #[test]
    fn our_transactions_are_announced_by_a_relay() {
        use crate::wallet::Wallet;
        let fixtures: Vec<Fixture> = (0..4).map(|i| open(&format!("bcast-{i}"))).collect();
        let (alice, _) = Wallet::open(&fixtures[3].dir.0.join("wallet")).unwrap();
        let (bob, _) = Wallet::open(&fixtures[3].dir.0.join("bob")).unwrap();
        // alice's funds, in a block every node has.
        let funds = alice.receive(SUBSIDY).unwrap();
        let body =
            Body { inputs: vec![], outputs: vec![funds.block_output()], proof: vec![1; 2500], ..Default::default() };
        let block = mine_body(&fixtures[3], body, T0 + 600);
        for f in &fixtures {
            f.chain.apply_block(&block, unix_now()).unwrap();
        }
        let (_, first, outputs) = fixtures[3].chain.main_outputs(1).unwrap().unwrap();
        alice.locate(first, &outputs).unwrap();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 3;
            cfg.identity = Some(if i < 3 { key(i as u8 + 1) } else { alice.identity_key() });
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let mempool = pool();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), Arc::clone(&mempool), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let (stats, announced) = (node.stats(), Arc::clone(&node.announced));
            nodes.push((addr, tx, notes, stats, mempool, announced, std::thread::spawn(move || node.run())));
        }
        let listed: Vec<consensus::Relay> =
            (0..3).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        for n in &nodes {
            n.1.send(Event::TestRelays(listed.clone())).unwrap();
        }
        let deadline = Instant::now() + guard(30);
        let live = || {
            let s = nodes[3].3.lock().unwrap().rendezvous.clone();
            !s.is_empty() && s.iter().all(|(_, l)| *l)
        };
        while !live() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(live());
        // alice pays bob, by slate files; the transaction is finished.
        let mut slate = {
            let rtxn = fixtures[3].chain.env().read_txn().unwrap();
            alice.send(20_000_000, None, false, fixtures[3].chain.utxo(), &rtxn).unwrap()
        };
        bob.receive_slate(&mut slate).unwrap();
        let signed = alice.finalize(&slate).unwrap();
        let txid = signed.tx.txid();
        nodes[3].1.send(Event::Transaction(signed.tx)).unwrap();
        match nodes[3].2.recv_timeout(guard(20)).expect("a note") {
            Note::Broadcast { txid: t, how: Ok(how) } => {
                assert_eq!(t, txid);
                assert!(how.starts_with("announced by relay"), "{how}");
            }
            other => panic!("{other:?}"),
        }
        // A relay pooled it; alice's node pooled it and announced nothing.
        let deadline = Instant::now() + guard(10);
        let relays_have = || (0..3).filter(|&i| nodes[i].4.lock().unwrap().contains(&txid)).count();
        while relays_have() < 3 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(relays_have(), 3, "the relays pass it on among themselves");
        assert!(nodes[3].4.lock().unwrap().contains(&txid));
        assert_eq!(nodes[3].5.load(Ordering::Relaxed), 0, "alice's node announced it");
        for n in &nodes {
            n.1.send(Event::Stop).unwrap();
        }
        for n in nodes {
            n.6.join().unwrap();
        }
    }

    /// Delegations and sub-name answers (`docs/SUBNAME_CERT.md`): the
    /// owner of a name publishes a delegation at its rendezvous points; a
    /// resolver finds it there (an issuer renews by it), while the owner is
    /// online and after it has gone. A node asked for a label (as an owner
    /// is in init mode) answers with the bundle it holds for that full
    /// name, or none, along the query's way back; one action's steps share
    /// one outbound circuit.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn delegations_and_sub_name_answers_reach_resolvers() {
        use crate::onion;
        use crate::subnames::{Bundle, Cert, Delegation, Entry};
        let fixtures: Vec<Fixture> = (0..6).map(|i| open(&format!("subnames-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 3;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let stats = node.stats();
            nodes.push((addr, tx, notes, stats, std::thread::spawn(move || node.run())));
        }
        let listed: Vec<consensus::Relay> =
            (0..3).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        for n in &nodes {
            n.1.send(Event::TestRelays(listed.clone())).unwrap();
        }
        // The owner of `example`, its server, a resolver.
        let (owner, server, resolver) = (3usize, 4usize, 5usize);
        let live = |n: usize| {
            let s = nodes[n].3.lock().unwrap().clone();
            !s.rendezvous.is_empty() && s.rendezvous.iter().all(|(_, l)| *l)
        };
        let deadline = Instant::now() + guard(30);
        while !(live(owner) && live(server) && live(resolver)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(live(owner) && live(server) && live(resolver));
        let now = unix_now();
        let d = Delegation::make(&key(4), 1, now + 3600, &[id(5)]).unwrap();
        nodes[owner].1.send(Event::Delegate(Some(d.to_bytes()))).unwrap();
        let mut tag = 0;
        let mut fetch = |who: Digest| -> Option<Delegation> {
            tag += 1;
            nodes[resolver].1.send(Event::GetDelegation(tag, who, 0)).unwrap();
            loop {
                match nodes[resolver].2.recv_timeout(guard(40)).expect("a note") {
                    Note::Delegation { tag: t, owner: o, result } if t == tag => {
                        assert_eq!(o, who);
                        return result.expect("asked");
                    }
                    _ => {}
                }
            }
        };
        // Published once the owner's session is live: soon.
        let deadline = Instant::now() + guard(30);
        let got = loop {
            if let Some(got) = fetch(id(4)) {
                break got;
            }
            assert!(Instant::now() < deadline, "the delegation never appeared");
            std::thread::sleep(Duration::from_millis(500));
        };
        assert_eq!(got, d);
        assert!(got.verify(&id(4), now));
        // An id with none.
        assert_eq!(fetch(id(9)), None);
        // The owner goes offline: its points still hold the delegation.
        nodes[owner].1.send(Event::Stop).unwrap();
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(fetch(id(4)).as_ref(), Some(&d));
        // The issuer (key 5) holds a bundle for `cool.example`, under the
        // owner's delegation, and answers for it.
        let cool = Bundle {
            cert: Cert::id(&key(5), b"example", b"cool", &id(9), 7, unix_now() + 3600).unwrap(),
            delegation: Some(d.clone()),
        };
        nodes[server].1.send(Event::Certs(vec![cool.to_bytes()])).unwrap();
        let ask = |label: &[u8], tag: u64, group: u64| -> Option<Bundle> {
            let out = Outbound {
                tag,
                to: id(5),
                kind: onion::KIND_SUBNAME_QUERY,
                inner: crate::subnames::query(b"example", label),
                recipient: None,
                reply: None,
                group,
            };
            nodes[resolver].1.send(Event::Send(out)).unwrap();
            loop {
                match nodes[resolver].2.recv_timeout(guard(30)).expect("a note") {
                    Note::Received(o) if o.kind == onion::KIND_SUBNAME_ANSWER => {
                        assert_eq!(o.answers, Some(id(5)));
                        let (n, l, b) = crate::subnames::parse_answer(&o.inner).expect("an answer");
                        assert_eq!((&n[..], &l[..]), (&b"example"[..], label));
                        return b;
                    }
                    Note::Failed { why, .. } => panic!("{why}"),
                    _ => {}
                }
            }
        };
        let a = ask(b"cool", 100, 0).expect("the bundle held");
        assert_eq!(a, cool);
        assert!(a.verify(&id(4), unix_now()));
        assert_eq!((a.cert.entry(), a.cert.seq), (Entry::Id(id(9)), 7));
        // One send's steps in a group share one outbound circuit: the
        // delegation, then the query, cost one circuit, not two.
        let built = || nodes[resolver].3.lock().unwrap().outbound_built;
        std::thread::sleep(Duration::from_secs(2));
        let before = built();
        nodes[resolver].1.send(Event::GetDelegation(500, id(4), 77)).unwrap();
        loop {
            if let Note::Delegation { tag: 500, result, .. } =
                nodes[resolver].2.recv_timeout(guard(40)).expect("a note")
            {
                assert_eq!(result.unwrap().as_ref(), Some(&d));
                break;
            }
        }
        let a = ask(b"cool", 501, 77).expect("the bundle held");
        assert_eq!(a.cert.entry(), Entry::Id(id(9)));
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(built() - before, 1, "the query went over the delegation's circuit");
        assert_eq!(ask(b"nope", 101, 0), None);
        for (i, n) in nodes.iter().enumerate() {
            if i != owner {
                n.1.send(Event::Stop).unwrap();
            }
        }
        for n in nodes {
            n.4.join().unwrap();
        }
    }

    /// Sub-name certificates at their full names' points
    /// (`docs/SUBNAME_CERT.md`): a holder publishes bundles up its own
    /// circuit; the points check each against their chain and hold the
    /// sound ones; a resolver finds them, the holder online or not. The
    /// owner's `none` certificate takes the place of the holder's, though
    /// it comes within the points' update interval (held back, not
    /// dropped); an older one does not come back; a newer delegation that drops an issuer
    /// replaces that issuer's certificate; a name that changes hands drops
    /// its old owner's.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn sub_name_certificates_are_held_at_their_points() {
        use crate::subnames::{Bundle, Cert, Delegation, Entry, LIFETIME_SECS};
        let fixtures: Vec<Fixture> = (0..6).map(|i| open(&format!("certs-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 3;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let stats = node.stats();
            nodes.push((addr, tx, notes, stats, std::thread::spawn(move || node.run())));
        }
        let listed: Vec<consensus::Relay> =
            (0..3).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        // `example` is the owner's (key 4) on every chain.
        let names = |owner: Digest| HashMap::from([(b"example".to_vec(), owner)]);
        for n in &nodes {
            n.1.send(Event::TestRelays(listed.clone())).unwrap();
            n.1.send(Event::TestNames(names(id(4)))).unwrap();
        }
        let (owner, holder, resolver) = (3usize, 4usize, 5usize);
        let live = |n: usize| {
            let s = nodes[n].3.lock().unwrap().clone();
            !s.rendezvous.is_empty() && s.rendezvous.iter().all(|(_, l)| *l)
        };
        let deadline = Instant::now() + guard(30);
        while !(live(owner) && live(holder) && live(resolver)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(live(owner) && live(holder) && live(resolver));
        let life = unix_now() + LIFETIME_SECS;
        let bundle = |cert: Cert, delegation: Option<Delegation>| Bundle { cert, delegation };
        // `cool` by the owner itself; `site` by an issuer (key 7) the
        // owner's delegation names; `evil` by a key nobody authorized.
        let cool = bundle(Cert::id(&key(4), b"example", b"cool", &id(5), 10, life).unwrap(), None);
        let d1 = Delegation::make(&key(4), 1, life, &[id(7)]).unwrap();
        let site = bundle(Cert::id(&key(7), b"example", b"site", &id(5), 11, life).unwrap(), Some(d1));
        let evil = bundle(Cert::id(&key(9), b"example", b"evil", &id(9), 99, life).unwrap(), None);
        nodes[holder].1.send(Event::Certs(vec![cool.to_bytes(), site.to_bytes(), evil.to_bytes()])).unwrap();
        let mut tag = 0;
        let mut fetch = |label: &[u8]| -> Option<Bundle> {
            tag += 1;
            nodes[resolver].1.send(Event::GetCert(tag, Cert::point(b"example", label), 0)).unwrap();
            loop {
                if let Note::Cert { tag: t, result, .. } = nodes[resolver].2.recv_timeout(guard(40)).expect("a note")
                    && t == tag
                {
                    return result.expect("asked");
                }
            }
        };
        let deadline = Instant::now() + guard(30);
        let mut wait_for = |label: &[u8], want: &dyn Fn(&Option<Bundle>) -> bool, what: &str| {
            loop {
                let got = fetch(label);
                if want(&got) {
                    return got;
                }
                assert!(Instant::now() < deadline, "{what}: got {got:?}");
                std::thread::sleep(Duration::from_millis(500));
            }
        };
        assert_eq!(wait_for(b"cool", &|g| g.is_some(), "the owner's certificate").as_ref(), Some(&cool));
        assert_eq!(wait_for(b"site", &|g| g.is_some(), "the issuer's certificate").as_ref(), Some(&site));
        assert_eq!(fetch(b"evil"), None, "an unauthorized certificate was held");
        assert_eq!(fetch(b"nope"), None);
        // The holder goes: its certificates stay with the full names' points.
        nodes[holder].1.send(Event::Stop).unwrap();
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(fetch(b"cool").as_ref(), Some(&cool));
        // The owner withdraws `cool` at once, within the points' update
        // interval: held back until it has passed, not dropped.
        let none = bundle(Cert::none(&key(4), b"example", b"cool", 12, life).unwrap(), None);
        nodes[owner].1.send(Event::Certs(vec![none.to_bytes()])).unwrap();
        let deadline = Instant::now() + guard(30);
        let got = loop {
            let got = fetch(b"cool");
            if got.as_ref() != Some(&cool) {
                break got;
            }
            assert!(Instant::now() < deadline, "the withdrawal never replaced the certificate");
            std::thread::sleep(Duration::from_millis(500));
        };
        assert_eq!(got.as_ref(), Some(&none));
        assert_eq!(got.unwrap().cert.entry(), Entry::None);
        // The holder's older certificate, published again, does not come back.
        nodes[resolver].1.send(Event::Certs(vec![cool.to_bytes()])).unwrap();
        std::thread::sleep(Duration::from_secs(4));
        assert_eq!(fetch(b"cool").as_ref(), Some(&none));
        // A newer delegation that no longer names key 7 replaces its
        // certificate for `site`, though with a lower seq.
        let d2 = Delegation::make(&key(4), 2, life, &[id(8)]).unwrap();
        let mine = bundle(Cert::id(&key(4), b"example", b"site", &id(6), 3, life).unwrap(), Some(d2));
        nodes[owner].1.send(Event::Certs(vec![none.to_bytes(), mine.to_bytes()])).unwrap();
        let deadline = Instant::now() + guard(30);
        loop {
            if fetch(b"site").as_ref() == Some(&mine) {
                break;
            }
            assert!(Instant::now() < deadline, "the newer delegation never withdrew the issuer's certificate");
            std::thread::sleep(Duration::from_millis(500));
        }
        // `example` changes hands: the old owner's certificates stop
        // counting at every point, as soon as they are asked for.
        for n in nodes.iter().take(3) {
            n.1.send(Event::TestNames(names(id(9)))).unwrap();
        }
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(fetch(b"cool"), None);
        assert_eq!(fetch(b"site"), None);
        for (i, n) in nodes.iter().enumerate() {
            if i != holder {
                n.1.send(Event::Stop).unwrap();
            }
        }
        for n in nodes {
            n.4.join().unwrap();
        }
    }

    /// A delegation outlives its owner's absence across a boundary
    /// (`docs/SUBNAMES.md`): the owner publishes and goes; at the next
    /// epoch, whose points are none of the old ones, the issuer it names
    /// carries the delegation there, and a resolver asking only the new
    /// points finds it.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn an_issuer_carries_a_delegation_to_new_points() {
        use crate::subnames::Delegation;
        let fixtures: Vec<Fixture> = (0..9).map(|i| open(&format!("carry-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 6;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let stats = node.stats();
            nodes.push((addr, tx, notes, stats, std::thread::spawn(move || node.run())));
        }
        let mut listed: Vec<consensus::Relay> =
            (0..6).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        listed.sort_by_key(|r| digest_to_bytes(&r.id));
        let ids: Vec<Digest> = listed.iter().map(|r| r.id).collect();
        let (owner, server, resolver) = (6usize, 7usize, 8usize);
        let v = id(7);
        let points = |e: u32| -> Vec<Digest> {
            crate::onion::rendezvous_relays(&v, e, &ids).into_iter().map(|i| ids[i]).collect()
        };
        // An epoch whose points for the owner are none of epoch 0's.
        let e = (1..).find(|&e| points(e).iter().all(|p| !points(0).contains(p))).unwrap();
        let epoch = |previous: bool, prefer: bool, n: u32| {
            for x in &nodes {
                let p = previous.then(|| Some(listed.clone()));
                // A stopped node takes nothing.
                let _ = x.1.send(Event::TestEpoch(Some(listed.clone()), p, prefer, n));
            }
        };
        epoch(false, true, 0);
        let live = |n: usize| {
            let s = nodes[n].3.lock().unwrap().clone();
            !s.rendezvous.is_empty() && s.rendezvous.iter().all(|(_, l)| *l)
        };
        let deadline = Instant::now() + guard(30);
        while !(live(owner) && live(server) && live(resolver)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(live(owner) && live(server) && live(resolver));
        let d = Delegation::make(&key(7), 1, unix_now() + 3600, &[id(8)]).unwrap();
        nodes[owner].1.send(Event::Delegate(Some(d.to_bytes()))).unwrap();
        let mut tag = 0;
        let mut fetch = || -> Option<Delegation> {
            tag += 1;
            nodes[resolver].1.send(Event::GetDelegation(tag, v, 0)).unwrap();
            loop {
                if let Note::Delegation { tag: t, result, .. } =
                    nodes[resolver].2.recv_timeout(guard(40)).expect("a note")
                    && t == tag
                {
                    return result.expect("asked");
                }
            }
        };
        let deadline = Instant::now() + guard(30);
        while fetch().is_none() {
            assert!(Instant::now() < deadline, "the delegation never appeared");
            std::thread::sleep(Duration::from_millis(500));
        }
        // The owner goes; the issuer knows whose delegations name it.
        nodes[owner].1.send(Event::Stop).unwrap();
        nodes[server].1.send(Event::TestServes(vec![v])).unwrap();
        std::thread::sleep(Duration::from_secs(1));
        // The boundary: both sets stand, and the issuer has moved.
        epoch(true, true, e);
        std::thread::sleep(Duration::from_secs(4));
        // The grace period over: only the new points are asked.
        epoch(false, true, e);
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(fetch().as_ref(), Some(&d), "the issuer carried it to the new points");
        for (i, n) in nodes.iter().enumerate() {
            if i != owner {
                n.1.send(Event::Stop).unwrap();
            }
        }
        for n in nodes {
            n.4.join().unwrap();
        }
    }

    /// A certificate follows its full name's points across an epoch
    /// boundary (`docs/SUBNAME_CERT.md`): the holder publishes at epoch 0;
    /// at an epoch whose points for the full name are none of epoch 0's,
    /// the holder carries it there, and a resolver asking only the new
    /// points finds it.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn a_holder_carries_its_certificate_to_new_points() {
        use crate::subnames::{Bundle, Cert, LIFETIME_SECS};
        let fixtures: Vec<Fixture> = (0..8).map(|i| open(&format!("cert-carry-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 6;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let stats = node.stats();
            nodes.push((addr, tx, notes, stats, std::thread::spawn(move || node.run())));
        }
        let mut listed: Vec<consensus::Relay> =
            (0..6).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        listed.sort_by_key(|r| digest_to_bytes(&r.id));
        let ids: Vec<Digest> = listed.iter().map(|r| r.id).collect();
        let (holder, resolver) = (6usize, 7usize);
        let point = Cert::point(b"example", b"cool");
        let points = |e: u32| -> Vec<Digest> {
            crate::onion::rendezvous_relays(&point, e, &ids).into_iter().map(|i| ids[i]).collect()
        };
        // An epoch whose points for the full name are none of epoch 0's,
        // while the holder's own first point stays: its standing circuit is
        // kept across the boundary, so only carrying its certificates on
        // purpose gets them to the new points.
        let first = |e: u32| crate::onion::rendezvous_relays(&id(7), e, &ids)[0];
        let e = (1..10_000)
            .find(|&e| points(e).iter().all(|p| !points(0).contains(p)) && first(e) == first(0))
            .expect("such an epoch");
        let epoch = |previous: bool, prefer: bool, n: u32| {
            for x in &nodes {
                let p = previous.then(|| Some(listed.clone()));
                let _ = x.1.send(Event::TestEpoch(Some(listed.clone()), p, prefer, n));
            }
        };
        // `example` is key 9's; it signed `cool` for the holder.
        for n in &nodes {
            n.1.send(Event::TestNames(HashMap::from([(b"example".to_vec(), id(9))]))).unwrap();
        }
        epoch(false, true, 0);
        let live = |n: usize| {
            let s = nodes[n].3.lock().unwrap().clone();
            !s.rendezvous.is_empty() && s.rendezvous.iter().all(|(_, l)| *l)
        };
        let deadline = Instant::now() + guard(30);
        while !(live(holder) && live(resolver)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(live(holder) && live(resolver));
        let cool = Bundle {
            cert: Cert::id(&key(9), b"example", b"cool", &id(7), 1, unix_now() + LIFETIME_SECS).unwrap(),
            delegation: None,
        };
        nodes[holder].1.send(Event::Certs(vec![cool.to_bytes()])).unwrap();
        let mut tag = 0;
        let mut fetch = || -> Option<Bundle> {
            tag += 1;
            nodes[resolver].1.send(Event::GetCert(tag, point, 0)).unwrap();
            loop {
                if let Note::Cert { tag: t, result, .. } = nodes[resolver].2.recv_timeout(guard(40)).expect("a note")
                    && t == tag
                {
                    return result.expect("asked");
                }
            }
        };
        let deadline = Instant::now() + guard(30);
        while fetch().is_none() {
            assert!(Instant::now() < deadline, "the certificate never appeared");
            std::thread::sleep(Duration::from_millis(500));
        }
        // The boundary: both sets stand, and the holder moves.
        epoch(true, true, e);
        std::thread::sleep(Duration::from_secs(4));
        // The grace period over: only the new points are asked.
        epoch(false, true, e);
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(fetch().as_ref(), Some(&cool), "the holder carried it to the new points");
        for n in &nodes {
            n.1.send(Event::Stop).unwrap();
        }
        for n in nodes {
            n.4.join().unwrap();
        }
    }

    /// A switch from one relay list to another: during the grace period a
    /// participant keeps sessions at its points under both, so messages get
    /// through whichever list a sender's rendezvous point tries first; once
    /// it is over, only the new list's points remain.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn a_switch_of_relays_keeps_messages_flowing() {
        use crate::onion;
        let fixtures: Vec<Fixture> = (0..6).map(|i| open(&format!("switch-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 4;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let stats = node.stats();
            nodes.push((addr, tx, notes, stats, std::thread::spawn(move || node.run())));
        }
        let relay = |i: usize| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() };
        let sorted = |mut v: Vec<consensus::Relay>| {
            v.sort_by_key(|r| digest_to_bytes(&r.id));
            v
        };
        let a = sorted((0..3).map(relay).collect());
        let b = sorted((1..4).map(relay).collect());
        let (p, q) = (4usize, 5usize);
        let points_in = |list: &[consensus::Relay], who: Digest, e: u32| -> Vec<Digest> {
            let ids: Vec<Digest> = list.iter().map(|r| r.id).collect();
            onion::rendezvous_relays(&who, e, &ids).into_iter().map(|i| ids[i]).collect()
        };
        let points = |list: &[consensus::Relay], who: Digest| points_in(list, who, 0);
        let addr_of = |d: &Digest| (0..4).find(|&i| id(i as u8 + 1) == *d).map(|i| nodes[i].0).unwrap();
        // p's sessions are live at exactly these points.
        let live_at = |want: &[Digest]| {
            let mut want: Vec<SocketAddr> = want.iter().map(addr_of).collect();
            want.sort();
            let deadline = Instant::now() + guard(30);
            loop {
                let mut have: Vec<SocketAddr> =
                    nodes[p].3.lock().unwrap().rendezvous.iter().filter(|(_, l)| *l).map(|(a, _)| *a).collect();
                have.sort();
                let all = nodes[p].3.lock().unwrap().rendezvous.len();
                if have == want && all == want.len() {
                    return;
                }
                assert!(Instant::now() < deadline, "p live at {have:?} of {all}, wanted {want:?}");
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        let mut tag = 0u64;
        let mut message = |round: &str| {
            tag += 1;
            let out = Outbound {
                tag,
                to: id(5),
                kind: onion::KIND_SLATE,
                inner: round.as_bytes().to_vec(),
                recipient: None,
                reply: None,
                group: 0,
            };
            nodes[q].1.send(Event::Send(out)).unwrap();
            let deadline = Instant::now() + guard(30);
            loop {
                match nodes[p].2.recv_timeout(Duration::from_millis(200)) {
                    Ok(Note::Received(o)) if o.inner == round.as_bytes() => break,
                    _ => {}
                }
                if let Ok(Note::Failed { why, .. }) = nodes[q].2.try_recv() {
                    panic!("{round}: {why}");
                }
                assert!(Instant::now() < deadline, "{round}: nothing arrived");
            }
        };
        let epoch_in =
            |current: &Vec<consensus::Relay>, previous: Option<&Vec<consensus::Relay>>, prefer: bool, e: u32| {
                for n in &nodes {
                    n.1.send(Event::TestEpoch(Some(current.clone()), previous.map(|p| Some(p.clone())), prefer, e))
                        .unwrap();
                }
            };
        let epoch = |current: &Vec<consensus::Relay>, previous: Option<&Vec<consensus::Relay>>, prefer: bool| {
            epoch_in(current, previous, prefer, 0)
        };
        // A session at each point (`docs/ONION.md`); during a switch, at
        // each point of both lists.
        let both = |x: Vec<Digest>, y: Vec<Digest>| {
            let mut v = x;
            for p in y {
                if !v.contains(&p) {
                    v.push(p);
                }
            }
            v
        };
        // List a alone.
        epoch(&a, None, true);
        live_at(&points(&a, id(5)));
        message("under a");
        // The switch to b: both stand, a tried first, then b.
        epoch(&b, Some(&a), false);
        live_at(&both(points(&a, id(5)), points(&b, id(5))));
        message("switching, a first");
        epoch(&b, Some(&a), true);
        live_at(&both(points(&b, id(5)), points(&a, id(5))));
        message("switching, b first");
        // The switch is over: b alone.
        epoch(&b, None, true);
        live_at(&points(&b, id(5)));
        message("under b");
        // A new epoch with b unchanged (`docs/SUBNAMES.md`): the points
        // move all the same, through the same grace period. The first
        // epoch where p's points change, to see the sessions follow.
        let e = (1..).find(|&e| points_in(&b, id(5), e) != points(&b, id(5))).unwrap();
        epoch_in(&b, Some(&b), false, e);
        live_at(&both(points_in(&b, id(5), e - 1), points_in(&b, id(5), e)));
        message("a new epoch, the old one first");
        epoch_in(&b, Some(&b), true, e);
        live_at(&both(points_in(&b, id(5), e), points_in(&b, id(5), e - 1)));
        message("a new epoch, the new one first");
        epoch_in(&b, None, true, e);
        live_at(&points_in(&b, id(5), e));
        message("the new epoch alone");
        for n in &nodes {
            n.1.send(Event::Stop).unwrap();
        }
        for n in nodes {
            n.4.join().unwrap();
        }
    }

    /// A switch between init and onion mode: during it a participant holds
    /// both kinds of session, and a send that fails in the mode tried first
    /// is tried in the other before the wallet hears of it.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn a_switch_between_modes_falls_back() {
        use crate::onion;
        let fixtures: Vec<Fixture> = (0..6).map(|i| open(&format!("modes-{i}"))).collect();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        // Relay 0 is also the seed of init mode; node 5 (r) uses it too.
        let seed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 3;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            if i == 0 {
                cfg.listen = seed;
            } else {
                cfg.seeds = vec![seed.to_string()];
            }
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let stats = node.stats();
            nodes.push((addr, tx, notes, stats, std::thread::spawn(move || node.run())));
        }
        let mut list: Vec<consensus::Relay> =
            (0..3).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        list.sort_by_key(|r| digest_to_bytes(&r.id));
        let (p, q, r) = (3usize, 4usize, 5usize);
        let live = |n: usize, want: usize| {
            let deadline = Instant::now() + guard(30);
            loop {
                let s = nodes[n].3.lock().unwrap().rendezvous.clone();
                if s.len() == want && s.iter().all(|(_, l)| *l) {
                    return;
                }
                assert!(Instant::now() < deadline, "node {n}: {s:?}, wanted {want} live");
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        let mut tag = 0u64;
        let mut message_to = |to: usize, round: &str| {
            tag += 1;
            let out = Outbound {
                tag,
                to: id(to as u8 + 1),
                kind: onion::KIND_SLATE,
                inner: round.as_bytes().to_vec(),
                recipient: None,
                reply: None,
                group: 0,
            };
            nodes[q].1.send(Event::Send(out)).unwrap();
            let deadline = Instant::now() + guard(40);
            loop {
                match nodes[to].2.recv_timeout(Duration::from_millis(200)) {
                    Ok(Note::Received(o)) if o.inner == round.as_bytes() => break,
                    _ => {}
                }
                if let Ok(Note::Failed { why, .. }) = nodes[q].2.try_recv() {
                    panic!("{round}: {why}");
                }
                assert!(Instant::now() < deadline, "{round}: nothing arrived");
            }
        };
        let set = |n: usize,
                   current: Option<&Vec<consensus::Relay>>,
                   previous: Option<Option<&Vec<consensus::Relay>>>,
                   prefer: bool| {
            nodes[n].1.send(Event::TestEpoch(current.cloned(), previous.map(|p| p.cloned()), prefer, 0)).unwrap();
        };
        // r is in onion mode from the start: it never holds an init session.
        set(r, Some(&list), None, true);
        // Init mode: sessions at the seed only.
        for n in 0..5 {
            set(n, None, None, true);
        }
        live(p, 1);
        message_to(p, "init");
        // The switch to onion mode, init still tried first: both kinds.
        for n in 0..5 {
            set(n, Some(&list), Some(None), false);
        }
        // The seed's session, and an onion session at each of the three
        // points (three relays: all of them).
        live(p, 4);
        live(r, 3);
        message_to(p, "switching, init first");
        // r is reachable only by onion mode: the sender tries init first,
        // the seed has no session for r, and the send goes by onion mode.
        message_to(r, "only by onion");
        for n in 0..5 {
            set(n, Some(&list), Some(None), true);
        }
        message_to(p, "switching, onion first");
        for n in 0..5 {
            set(n, Some(&list), None, true);
        }
        live(p, 3);
        message_to(p, "onion");
        for n in &nodes {
            n.1.send(Event::Stop).unwrap();
        }
        for n in nodes {
            n.4.join().unwrap();
        }
    }

    /// Standing circuits are replaced on a timer without losing the
    /// session, and a circuit whose hop goes down is noticed by its
    /// unanswered keepalive and built again around it.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn standing_circuits_are_replaced_and_rebuilt() {
        use crate::onion;
        let fixtures: Vec<Fixture> = (0..6).map(|i| open(&format!("rotate-{i}"))).collect();
        let mut handles = Vec::new();
        let key = |tag: u8| crate::mldsa::keygen(&[tag; 32]);
        let id = |tag: u8| crate::address::id_of(key(tag).public_key());
        let mut nodes = Vec::new();
        for (i, f) in fixtures.iter().enumerate() {
            let mut cfg = config(vec![], &f.dir);
            cfg.relay = i < 4;
            cfg.identity = Some(key(i as u8 + 1));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            let notes = node.take_notes().unwrap();
            let (stats, seen) = (node.stats(), Arc::clone(&node.circuits.seen));
            nodes.push((addr, tx, notes, stats, seen));
            handles.push(Some(std::thread::spawn(move || node.run())));
        }
        let mut list: Vec<consensus::Relay> =
            (0..4).map(|i| consensus::Relay { id: id(i as u8 + 1), addr: nodes[i].0.to_string() }).collect();
        list.sort_by_key(|r| digest_to_bytes(&r.id));
        let (p, q) = (4usize, 5usize);
        for n in &nodes {
            n.1.send(Event::TestRelays(list.clone())).unwrap();
        }
        for n in [p, q] {
            nodes[n].1.send(Event::TestTiming(Duration::from_secs(1), Duration::from_secs(3), Duration::from_secs(60))).unwrap();
        }
        let live = |secs: u64| {
            let deadline = Instant::now() + guard(secs);
            loop {
                let s = nodes[p].3.lock().unwrap().rendezvous.clone();
                if s.len() == 3 && s.iter().all(|(_, l)| *l) {
                    return;
                }
                assert!(Instant::now() < deadline, "p: {s:?}");
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        let mut tag = 0u64;
        let mut message = |round: &str| {
            tag += 1;
            let out = Outbound {
                tag,
                to: id(5),
                kind: onion::KIND_SLATE,
                inner: round.as_bytes().to_vec(),
                recipient: None,
                reply: None,
                group: 0,
            };
            nodes[q].1.send(Event::Send(out)).unwrap();
            let deadline = Instant::now() + guard(40);
            loop {
                match nodes[p].2.recv_timeout(Duration::from_millis(200)) {
                    Ok(Note::Received(o)) if o.inner == round.as_bytes() => break,
                    _ => {}
                }
                if let Ok(Note::Failed { why, .. }) = nodes[q].2.try_recv() {
                    panic!("{round}: {why}");
                }
                assert!(Instant::now() < deadline, "{round}: nothing arrived");
            }
        };
        live(30);
        message("first");
        // Replaced, the session kept: p's standing circuit and its spare
        // outbound one, then the replacement at least.
        let built = || nodes[p].4.lock().unwrap().iter().filter(|s| matches!(s, circuits::Seen::Ready(_))).count();
        let deadline = Instant::now() + guard(40);
        while built() < 3 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(built() >= 3, "{} circuits built", built());
        live(20);
        message("after replacement");
        // The relay that is none of p's points is only ever a hop: stop it.
        let ids: Vec<Digest> = list.iter().map(|r| r.id).collect();
        let points: Vec<Digest> = onion::rendezvous_relays(&id(5), 0, &ids).into_iter().map(|i| ids[i]).collect();
        let hop = (0..4).find(|&i| !points.contains(&id(i as u8 + 1))).unwrap();
        for n in [p, q] {
            nodes[n].1.send(Event::TestTiming(Duration::from_secs(1), Duration::from_secs(3600), Duration::from_secs(60))).unwrap();
        }
        nodes[hop].1.send(Event::Stop).unwrap();
        handles[hop].take().unwrap().join().unwrap();
        let stopped = Instant::now();
        // Circuits through it die; p notices (DEAD_AFTER, 30 s, after an
        // unanswered keepalive, sent every second here), builds around
        // it. Until it notices, a circuit through the stopped relay still
        // looks live, and q, sending meanwhile, is told "offline": it asks
        // again every 3 s for up to 60 s (OFFLINE_WAIT), until p's session
        // is held again.
        std::thread::sleep(Duration::from_secs(13));
        live(90);
        eprintln!("p live again {:?} after the relay stopped", stopped.elapsed());
        message("around the stopped relay");
        eprintln!("reachable again {:?} after the relay stopped", stopped.elapsed());
        for (i, n) in nodes.iter().enumerate() {
            if i != hop {
                n.1.send(Event::Stop).unwrap();
            }
        }
        for h in handles.into_iter().flatten() {
            h.join().unwrap();
        }
    }

    /// A relay that restarts has lost every session and given new tokens:
    /// its participants find their requests unanswered, ping it again,
    /// see their announce gone, reconnect with a new Kyber key, and are
    /// reachable again within a keepalive or so.
    #[test]
    #[ignore = "slow: one job each in .github/workflows/test.yml"]
    fn sessions_come_back_after_the_relay_restarts() {
        use crate::onion;
        let (r, p, q) = (open("rs-relay"), open("rs-p"), open("rs-q"));
        let start_relay = |addr: Option<SocketAddr>| {
            let mut cfg = config(vec![], &r.dir);
            cfg.relay = true;
            if let Some(a) = addr {
                cfg.listen = a;
            }
            let (node, tx) = Node::bind(Arc::clone(&r.chain), pool(), cfg).unwrap();
            let addr = node.local_addr().unwrap();
            (addr, tx, std::thread::spawn(move || node.run()))
        };
        let (addr_r, tx_r, h_r) = start_relay(None);
        let participant = |f: &Fixture, tag: u8| {
            let mut cfg = config(vec![], &f.dir);
            cfg.seeds = vec![addr_r.to_string()];
            cfg.identity = Some(crate::mldsa::keygen(&[tag; 32]));
            cfg.relay_key = cfg.relay.then(|| cfg.identity.clone()).flatten();
            let (mut node, tx) = Node::bind(Arc::clone(&f.chain), pool(), cfg).unwrap();
            let notes = node.take_notes().unwrap();
            let stats = node.stats();
            (tx, notes, stats, std::thread::spawn(move || node.run()))
        };
        let (tx_p, notes_p, stats_p, h_p) = participant(&p, 1);
        let (tx_q, notes_q, _, h_q) = participant(&q, 2);
        let id_p = crate::address::id_of(crate::mldsa::keygen(&[1; 32]).public_key());
        let live = |secs: u64| {
            let deadline = Instant::now() + guard(secs);
            while Instant::now() < deadline {
                if stats_p.lock().unwrap().rendezvous.iter().any(|(_, l)| *l) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            false
        };
        let deliver = |tag: u64, recipient: Option<onion::Announce>| {
            let out = Outbound { tag, to: id_p, kind: 1, inner: vec![tag as u8], recipient, reply: None, group: 0 };
            tx_q.send(Event::Send(out)).unwrap();
            let deadline = Instant::now() + guard(20);
            let mut opened = None;
            while Instant::now() < deadline {
                if let Ok(Note::Received(o)) = notes_p.recv_timeout(Duration::from_millis(100)) {
                    opened = Some(o);
                    break;
                }
            }
            while notes_q.try_recv().is_ok() {}
            opened
        };
        assert!(live(15), "p's session did not go live");
        // q fetches p's announce, which carries p's first Kyber key.
        let first = deliver(1, None).expect("the first message");
        assert_eq!(first.inner, vec![1]);
        // The relay restarts on the same address, holding nothing.
        tx_r.send(Event::Stop).unwrap();
        h_r.join().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let (_, tx_r, h_r) = start_relay(Some(addr_r));
        // p notices (its keepalive finds no announce held), reconnects
        // with a new key, and is reachable again.
        let deadline = Instant::now() + Duration::from_secs(70);
        let mut back = None;
        while back.is_none() && Instant::now() < deadline {
            back = deliver(3, None);
        }
        let back = back.expect("p was not reachable after the restart");
        assert_eq!(back.inner, vec![3]);
        for tx in [tx_r, tx_p, tx_q] {
            tx.send(Event::Stop).unwrap();
        }
        for h in [h_r, h_p, h_q] {
            h.join().unwrap();
        }
    }

    #[test]
    fn requests_need_the_token_the_node_gave_that_address() {
        // A request forged from another address cannot make a node send
        // data there: the token in its status to that address is required.
        let a = open("token-a");
        a.chain.apply_block(&mine(&a, 1, T0 + 600), unix_now()).unwrap();
        let block_id = a.chain.tip().unwrap().unwrap().hash();
        let genesis = a.chain.header_at(0).unwrap().unwrap().hash();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let addr_a = node_a.local_addr().unwrap();
        let ha = std::thread::spawn(move || node_a.run());
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut buf = [0u8; 2048];
        let mut receive = |want: fn(&Message) -> bool| -> Option<Message> {
            let deadline = Instant::now() + guard(2);
            while Instant::now() < deadline {
                if let Ok((n, _)) = sock.recv_from(&mut buf)
                    && let Some(m) = Message::decode(&buf[..n])
                    && want(&m)
                {
                    return Some(m);
                }
            }
            None
        };
        let status = Status {
            nonce: 5,
            version: PROTOCOL_VERSION,
            token: 0,
            genesis,
            height: 0,
            oldest: 1,
            tip: genesis,
            work: U256::ZERO,
            min_fee: 0,
            pool_fee: 0,
        };
        sock.send_to(&Message::Ping(status).encode(), addr_a).unwrap();
        let Some(Message::Pong(st)) = receive(|m| matches!(m, Message::Pong(_))) else { panic!("no pong") };
        let ask = |token: u64| Message::GetChunks { kind: Kind::Block, id: block_id, indexes: vec![0], token };
        sock.send_to(&ask(0).encode(), addr_a).unwrap();
        sock.send_to(&ask(st.token ^ 1).encode(), addr_a).unwrap();
        assert!(receive(|m| matches!(m, Message::Chunk { .. })).is_none(), "served without the token");
        sock.send_to(&ask(st.token).encode(), addr_a).unwrap();
        assert!(receive(|m| matches!(m, Message::Chunk { .. })).is_some(), "not served with the token");
        tx_a.send(Event::Stop).unwrap();
        ha.join().unwrap();
    }

    #[test]
    fn nodes_on_another_chain_are_ignored() {
        let a = open("other-a");
        let dir_b = TempDir::new("other-b");
        let chain_b = Chain::open(&dir_b.0.join("chain"), 64 << 20, params(), seed(), AcceptAllProofs).unwrap();
        let genesis = {
            let body = Body {
                inputs: vec![],
                outputs: vec![Output::new(&pk(1), 1).block_output()],
                proof: vec![],
                ..Default::default()
            };
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

    /// A verifier for the fast-sync tests that checks what a lying
    /// manifest gets wrong: the block's first output position, which the
    /// "proof" of [`grow`] carries in its first eight bytes.
    struct PositionProofs;

    impl ProofVerifier for PositionProofs {
        fn verify(&self, statement: &BlockStatement<'_>, proof: &[u8]) -> bool {
            proof.get(..8).is_some_and(|b| b == statement.first_output_position.to_le_bytes())
        }
    }

    /// Mines blocks `tags` on `chains[0]`, each with one output and a proof
    /// [`PositionProofs`] accepts, and applies each to every chain.
    fn grow<V: ProofVerifier>(f: &Fixture, others: &[&Chain<V>], tags: std::ops::RangeInclusive<u8>) {
        let now = unix_now();
        for tag in tags {
            let tip = f.chain.tip().unwrap().unwrap();
            let first = f.chain.utxo().next_position(&f.chain.env().read_txn().unwrap()).unwrap();
            let mut proof = first.to_le_bytes().to_vec();
            proof.resize(2500, tag);
            let body = Body {
                outputs: vec![Output::new(&pk(tag), claim(f, &[])).block_output()],
                proof,
                ..Default::default()
            };
            let block = mine_body(f, body, tip.timestamp.max(T0) + 600);
            f.chain.apply_block(&block, now).unwrap();
            for c in others {
                c.apply_block(&block, now).unwrap();
            }
        }
    }

    /// A chain checked by [`PositionProofs`], keeping `window` blocks of
    /// undo.
    fn open_checked(name: &str, window: Option<u32>) -> (TempDir, Arc<Chain<PositionProofs>>) {
        let dir = TempDir::new(name);
        let chain = Chain::open(&dir.0.join("chain"), 64 << 20, params(), seed(), PositionProofs).unwrap();
        let chain = chain.with_max_undo(window);
        chain.init_or_check_genesis().unwrap();
        (dir, Arc::new(chain))
    }

    /// A fixture keeping `window` blocks of undo.
    fn open_window(name: &str, window: Option<u32>) -> Fixture {
        let dir = TempDir::new(name);
        let seed = seed();
        let dataset = Dataset::generate(&seed);
        let chain = Chain::open(&dir.0.join("chain"), 64 << 20, params(), seed, AcceptAllProofs).unwrap();
        let chain = chain.with_max_undo(window);
        chain.init_or_check_genesis().unwrap();
        Fixture { dir, chain: Arc::new(chain), dataset }
    }

    fn wait_for(what: &str, secs: u64, done: impl Fn() -> bool) {
        let deadline = Instant::now() + guard(secs);
        while !done() {
            assert!(Instant::now() < deadline, "{what} within {secs} s");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn a_manifest_that_does_not_fit_the_proof_is_passed_over() {
        // l and a hold the same twelve blocks; l serves manifests with the
        // output counter one too high, which the state root does not catch
        // but block 8's proof does. b hears from l first: it refuses l's
        // manifest, then takes a's once a answers, and installs the
        // snapshot (not a replay from genesis).
        let l = open("liar-l");
        let a = open("liar-a");
        grow(&l, &[&a.chain], 1..=12);
        let a_tip = a.chain.tip().unwrap().unwrap();
        let (mut node_l, tx_l) = Node::bind(Arc::clone(&l.chain), pool(), config(vec![], &l.dir)).unwrap();
        node_l.lie_manifest = true;
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let (dir_b, chain_b) = open_checked("liar-b", None);
        let mut cb = config(vec![node_l.local_addr().unwrap(), node_a.local_addr().unwrap()], &dir_b);
        cb.sync_point = Some(4);
        let (node_b, tx_b) = Node::bind(Arc::clone(&chain_b), pool(), cb).unwrap();
        let seen = Arc::clone(&node_b.seen);
        let hl = std::thread::spawn(move || node_l.run());
        let hb = std::thread::spawn(move || node_b.run());
        wait_for("b refused l's manifest", 30, || seen.refused.load(Ordering::Relaxed) >= 1);
        let ha = std::thread::spawn(move || node_a.run());
        assert!(wait_for_tip(&chain_b, &a_tip, 60), "b did not fast-sync to a's tip");
        assert_eq!(chain_b.state_root().unwrap(), a.chain.state_root().unwrap());
        assert_eq!(chain_b.floor().unwrap(), Some(8), "b installed a snapshot");
        assert_eq!(seen.verified.load(Ordering::Relaxed), 1, "only a's manifest fitted");
        for tx in [tx_l, tx_a, tx_b] {
            tx.send(Event::Stop).unwrap();
        }
        for h in [hl, ha, hb] {
            h.join().unwrap();
        }
    }

    #[test]
    fn with_no_snapshot_served_a_fresh_node_validates_every_block() {
        // a keeps every block but serves no snapshot: b's attempts run out
        // and, a keeping every block, it validates from genesis instead.
        let a = open("unserved-a");
        grow(&a, &[] as &[&Chain<AcceptAllProofs>], 1..=12);
        let a_tip = a.chain.tip().unwrap().unwrap();
        let (mut node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        node_a.withhold_snapshots = true;
        let b = open("unserved-b");
        let mut cb = config(vec![node_a.local_addr().unwrap()], &b.dir);
        cb.sync_point = Some(4);
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        assert!(wait_for_tip(&b.chain, &a_tip, 120), "b did not reach a's tip");
        assert_eq!(b.chain.floor().unwrap(), None, "b validated every block");
        assert_eq!(b.chain.state_root().unwrap(), a.chain.state_root().unwrap());
        tx_a.send(Event::Stop).unwrap();
        tx_b.send(Event::Stop).unwrap();
        ha.join().unwrap();
        hb.join().unwrap();
    }

    #[test]
    fn with_no_snapshot_served_and_no_archive_a_fresh_node_keeps_trying() {
        // a keeps nine blocks of undo and serves no snapshot: b's attempts
        // run out with nothing to validate from genesis, so b keeps trying,
        // and takes c's snapshot once c answers.
        let a = open_window("keep-a", Some(9));
        let c = open_window("keep-c", Some(9));
        grow(&a, &[&c.chain], 1..=16);
        let a_tip = a.chain.tip().unwrap().unwrap();
        let (mut node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        node_a.withhold_snapshots = true;
        let (node_c, tx_c) = Node::bind(Arc::clone(&c.chain), pool(), config(vec![], &c.dir)).unwrap();
        let b = open("keep-b");
        let mut cb = config(vec![node_a.local_addr().unwrap(), node_c.local_addr().unwrap()], &b.dir);
        cb.sync_point = Some(4);
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        let seen = Arc::clone(&node_b.seen);
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        wait_for("b ran out of attempts", 120, || seen.kept_trying.load(Ordering::Relaxed) >= 1);
        assert_eq!(b.chain.tip().unwrap().unwrap().height, 0, "b did not give up on fast sync");
        let hc = std::thread::spawn(move || node_c.run());
        assert!(wait_for_tip(&b.chain, &a_tip, 60), "b did not fast-sync once c answered; b {}", seen.state());
        assert!(b.chain.floor().unwrap().is_some(), "b installed a snapshot");
        assert_eq!(b.chain.state_root().unwrap(), a.chain.state_root().unwrap());
        for tx in [tx_a, tx_b, tx_c] {
            tx.send(Event::Stop).unwrap();
        }
        for h in [ha, hb, hc] {
            h.join().unwrap();
        }
    }

    #[test]
    fn a_reorganization_past_the_snapshot_during_a_fast_sync_starts_over() {
        // b verifies block 8's snapshot from a but fetches no part of it;
        // then c, on a heavier branch from genesis, answers: block 8 leaves
        // the best chain, and b starts over and installs c's state.
        let a = open("past-a");
        grow(&a, &[] as &[&Chain<AcceptAllProofs>], 1..=12);
        let c = open("past-c");
        grow(&c, &[] as &[&Chain<AcceptAllProofs>], 101..=114);
        let c_tip = c.chain.tip().unwrap().unwrap();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let (node_c, tx_c) = Node::bind(Arc::clone(&c.chain), pool(), config(vec![], &c.dir)).unwrap();
        let b = open("past-b");
        let mut cb = config(vec![node_a.local_addr().unwrap(), node_c.local_addr().unwrap()], &b.dir);
        cb.sync_point = Some(4);
        let (mut node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        node_b.hold_parts = Some(0);
        let seen = Arc::clone(&node_b.seen);
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        wait_for("b verified a's snapshot", 30, || seen.verified.load(Ordering::Relaxed) >= 1);
        let hc = std::thread::spawn(move || node_c.run());
        assert!(wait_for_tip(&b.chain, &c_tip, 60), "b did not sync to c's tip");
        assert!(seen.abandoned.load(Ordering::Relaxed) >= 1, "b abandoned a's snapshot");
        assert_eq!(b.chain.floor().unwrap(), Some(10), "b installed c's snapshot");
        assert_eq!(b.chain.state_root().unwrap(), c.chain.state_root().unwrap());
        for tx in [tx_a, tx_b, tx_c] {
            tx.send(Event::Stop).unwrap();
        }
        for h in [ha, hb, hc] {
            h.join().unwrap();
        }
    }

    #[test]
    fn a_heavier_branch_below_the_floor_is_refused_after_install() {
        // b fast-syncs a's twelve blocks (floor 8). c shares blocks 1 and
        // 2 and goes on to 14 of its own: heavier, but forking below b's
        // floor (and below a's nine blocks of undo, so a stays too), so b
        // stays on a's chain and goes on following it.
        let a = open_window("floor-a", Some(9));
        let c = open("floor-c");
        grow(&a, &[&c.chain], 1..=2);
        grow(&a, &[] as &[&Chain<AcceptAllProofs>], 3..=12);
        grow(&c, &[] as &[&Chain<AcceptAllProofs>], 103..=114);
        let a_tip = a.chain.tip().unwrap().unwrap();
        let c_tip = c.chain.tip().unwrap().unwrap();
        let (node_a, tx_a) = Node::bind(Arc::clone(&a.chain), pool(), config(vec![], &a.dir)).unwrap();
        let b = open("floor-b");
        let mut cb = config(vec![node_a.local_addr().unwrap()], &b.dir);
        cb.sync_point = Some(4);
        let (node_b, tx_b) = Node::bind(Arc::clone(&b.chain), pool(), cb).unwrap();
        let addr_b = node_b.local_addr().unwrap();
        let ha = std::thread::spawn(move || node_a.run());
        let hb = std::thread::spawn(move || node_b.run());
        assert!(wait_for_tip(&b.chain, &a_tip, 30), "b did not fast-sync to a's tip");
        assert!(b.chain.floor().unwrap().is_some_and(|f| f > 2));
        let (node_c, tx_c) = Node::bind(Arc::clone(&c.chain), pool(), config(vec![addr_b], &c.dir)).unwrap();
        let hc = std::thread::spawn(move || node_c.run());
        // c's tip's header stored at b: what stays once b, finding the
        // branch forks below its floor, sets it aside (its best header is
        // c's only until then, a moment now that a says it does not hold
        // c's blocks, NotHeld, and b fetches them from c at once).
        wait_for("b heard of c's branch", 30, || b.chain.header_by_hash(&c_tip.hash()).is_ok_and(|h| h.is_some()));
        std::thread::sleep(Duration::from_secs(3));
        assert_eq!(b.chain.tip().unwrap().unwrap(), a_tip, "b reorganized below its floor");
        assert_eq!(a.chain.tip().unwrap().unwrap(), a_tip, "a reorganized past its undo window");
        // a's next block still reaches b.
        let tip = a.chain.tip().unwrap().unwrap();
        let first = a.chain.utxo().next_position(&a.chain.env().read_txn().unwrap()).unwrap();
        let mut proof = first.to_le_bytes().to_vec();
        proof.resize(2500, 13);
        let body =
            Body { outputs: vec![Output::new(&pk(13), claim(&a, &[])).block_output()], proof, ..Default::default() };
        let block = mine_body(&a, body, tip.timestamp + 600);
        let next = block.header;
        tx_a.send(Event::Mined(block)).unwrap();
        assert!(wait_for_tip(&b.chain, &next, 30), "b stopped following a");
        for tx in [tx_a, tx_b, tx_c] {
            tx.send(Event::Stop).unwrap();
        }
        for h in [ha, hb, hc] {
            h.join().unwrap();
        }
    }

    /// A transaction from key `tag`'s output of `amount` at `position` to
    /// key 100, less `fee`.
    fn pooled_spend(tag: u8, amount: u64, fee: u64, position: u64) -> crate::transaction::Transaction {
        let mut s = [0u8; 32];
        s[0] = tag;
        let mut k = Key::generate(&s);
        let outs = vec![Output::new(&pk(100), amount - fee)];
        let mut tx = crate::transaction::UnsignedTransaction::new(vec![(k.public_key(), amount)], outs)
            .sign_with(&mut k)
            .unwrap();
        tx.set_positions(&[position]);
        tx
    }

    #[test]
    fn a_reorganization_leaves_only_valid_transactions_in_the_pool() {
        // a and c share blocks 1 to 3. a goes on to 6 with four pooled
        // transactions; c, heavier, to 8. Once a follows c:
        // - T0, spending a's block 6 reward, a lost output, stays out;
        // - T1, spending a's block 4 reward, which c's block 4 makes too but
        //   one position later, comes back moved there;
        // - T2, spending block 2's reward, which c spends otherwise, stays out;
        // - T3, mined in a's block 5 (so shelved as confirmed), spending block
        //   1's reward, which c leaves unspent, comes back;
        // and a block of what the pool then selects applies.
        let a = open("reorg-pool-a");
        let c = open("reorg-pool-c");
        let now = unix_now();
        let mut t = T0;
        let next = |f: &Fixture| f.chain.utxo().next_position(&f.chain.env().read_txn().unwrap()).unwrap();
        let subsidy = |f: &Fixture| f.chain.params().subsidy(f.chain.tip().unwrap().unwrap().height + 1);
        // Where each block's reward lands, by tag.
        let mut at = HashMap::new();
        for tag in 1..=3u8 {
            t += 600;
            at.insert(tag, next(&a));
            let block = mine(&a, tag, t);
            a.chain.apply_block(&block, now).unwrap();
            c.chain.apply_block(&block, now).unwrap();
        }
        let (fork_t, reward) = (t, subsidy(&a));
        let pool_a = pool();
        let fee = 1000;
        let tx = |tag: u8, pos: u64| pooled_spend(tag, reward, fee, pos);
        // a's branch: block 4 to pk(40), block 5 carries T3, block 6 to pk(60).
        let rtxn_insert = |pool: &Arc<Mutex<Mempool>>, f: &Fixture, tx: crate::transaction::Transaction| {
            let rtxn = f.chain.env().read_txn().unwrap();
            let height = f.chain.tip().unwrap().unwrap().height + 1;
            pool.lock().unwrap().insert(tx, f.chain.utxo(), f.chain.names(), &rtxn, height).unwrap()
        };
        t += 600;
        let p40 = next(&a);
        a.chain.apply_block(&mine(&a, 40, t), now).unwrap();
        let t3 = tx(1, at[&1]);
        let t3_id = rtxn_insert(&pool_a, &a, t3.clone());
        t += 600;
        let body = Body {
            inputs: t3.spent_positions(),
            outputs: t3
                .outputs
                .iter()
                .map(|o| o.block_output())
                .chain([Output::new(&pk(5), subsidy(&a) + fee).block_output()])
                .collect(),
            proof: vec![5; 2500],
            ..Default::default()
        };
        a.chain.apply_block(&mine_body(&a, body, t), now).unwrap();
        t += 600;
        let p60 = next(&a);
        a.chain.apply_block(&mine(&a, 60, t), now).unwrap();
        // The node would revalidate after each block: T3 is confirmed.
        {
            let rtxn = a.chain.env().read_txn().unwrap();
            let height = a.chain.tip().unwrap().unwrap().height + 1;
            let (gone, back) = pool_a
                .lock()
                .unwrap()
                .revalidate(a.chain.utxo(), a.chain.names(), &rtxn, height, &HashMap::new(), &HashMap::new())
                .unwrap();
            assert_eq!((gone, back), (1, 0), "T3 left the pool, confirmed");
        }
        let t0_id = rtxn_insert(&pool_a, &a, tx(60, p60));
        let t1_id = rtxn_insert(&pool_a, &a, tx(40, p40));
        let t2_id = rtxn_insert(&pool_a, &a, tx(2, at[&2]));
        // c's branch: block 4 makes a zero output, then pk(40)'s, one later;
        // block 5 spends block 2's reward elsewhere; then 6 to 8.
        let mut t = fork_t;
        t += 600;
        let body = Body {
            outputs: vec![Output::new(&pk(77), 0).block_output(), Output::new(&pk(40), subsidy(&c)).block_output()],
            proof: vec![41; 2500],
            ..Default::default()
        };
        c.chain.apply_block(&mine_body(&c, body, t), now).unwrap();
        t += 600;
        let other = pooled_spend(2, reward, fee, at[&2]);
        let body = Body {
            inputs: other.spent_positions(),
            outputs: vec![
                Output::new(&pk(101), reward - fee).block_output(),
                Output::new(&pk(51), subsidy(&c) + fee).block_output(),
            ],
            proof: vec![51; 2500],
            ..Default::default()
        };
        c.chain.apply_block(&mine_body(&c, body, t), now).unwrap();
        for tag in 61..=63u8 {
            t += 600;
            c.chain.apply_block(&mine(&c, tag, t), now).unwrap();
        }
        let c_tip = c.chain.tip().unwrap().unwrap();
        let (node_c, tx_c) = Node::bind(Arc::clone(&c.chain), pool(), config(vec![], &c.dir)).unwrap();
        let addr_c = node_c.local_addr().unwrap();
        let (node_a, tx_a) =
            Node::bind(Arc::clone(&a.chain), Arc::clone(&pool_a), config(vec![addr_c], &a.dir)).unwrap();
        let hc = std::thread::spawn(move || node_c.run());
        let ha = std::thread::spawn(move || node_a.run());
        assert!(wait_for_tip(&a.chain, &c_tip, 30), "a did not follow c's heavier branch");
        let pooled = || {
            let mut ids: Vec<Digest> = pool_a.lock().unwrap().entries().map(|e| e.txid).collect();
            ids.sort_by_key(digest_to_bytes);
            ids
        };
        let mut want = vec![t1_id, t3_id];
        want.sort_by_key(digest_to_bytes);
        let deadline = Instant::now() + guard(10);
        while pooled() != want && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(pooled(), want, "T1 and T3 only (T0 {t0_id:?}, T2 {t2_id:?} out)");
        let p40_c = p40 + 1;
        assert_eq!(pool_a.lock().unwrap().get(&t1_id).unwrap().spent_positions(), vec![p40_c], "T1 moved");
        // A block of what the pool selects applies on the new tip.
        tx_a.send(Event::Stop).unwrap();
        tx_c.send(Event::Stop).unwrap();
        ha.join().unwrap();
        hc.join().unwrap();
        let chosen = {
            let rtxn = a.chain.env().read_txn().unwrap();
            let height = a.chain.tip().unwrap().unwrap().height + 1;
            pool_a.lock().unwrap().select(a.chain.names(), &rtxn, height, 0, |_| true)
        };
        assert_eq!(chosen.len(), 2);
        let fees: u64 = chosen.iter().map(|t| t.balance() as u64).sum();
        let body = Body {
            inputs: chosen.iter().flat_map(|t| t.spent_positions()).collect(),
            outputs: chosen
                .iter()
                .flat_map(|t| t.outputs.iter().map(|o| o.block_output()))
                .chain([Output::new(&pk(90), subsidy(&a) + fees).block_output()])
                .collect(),
            proof: vec![90; 2500],
            ..Default::default()
        };
        let block = mine_body(&a, body, c_tip.timestamp + 600);
        a.chain.apply_block(&block, now).unwrap();
        assert_eq!(a.chain.tip().unwrap().unwrap(), block.header);
    }
}
