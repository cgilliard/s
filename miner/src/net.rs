//! Peer-to-peer transport over UDP: the wire format, the peer table and
//! chunked block transfer. [`crate::node`] drives it.
//!
//! # Datagrams
//!
//! Every datagram is `MAGIC`, a type byte and a payload encoded with
//! [`crate::codec`], and fits in [`MAX_DATAGRAM`] bytes so it crosses any
//! path without fragmentation. Only IPv4 is spoken: a peer's address is
//! its four bytes and port, and IPv6 addresses are never taken (cheap in
//! bulk, they would weaken the network-group limit). Nothing is encrypted or signed: blocks
//! and headers carry their own proof of work and validity proof, and a peer
//! table entry is only an address to try.
//!
//! # Messages
//!
//! | message      | payload                                   | reply            |
//! |--------------|-------------------------------------------|------------------|
//! | `Ping`       | [`Status`]: nonce, version, token, genesis, tip | `Pong`     |
//! | `Pong`       | [`Status`] echoing the nonce              |                  |
//! | `GetPeers`   | token                                     | `Peers`          |
//! | `Peers`      | up to 32 addresses                        |                  |
//! | `GetHeaders` | token, block locator, up to 32 ids        | `Headers`, several |
//! | `GetHeadersFrom` | token, height                         | `Headers`, several |
//! | `Headers`    | up to 6 main-chain headers, oldest first  |                  |
//! | `Inv`        | the header of a new block                 |                  |
//! | `TxInv`      | the id of a new transaction               |                  |
//! | `GetChunks`  | token, kind, id and up to 32 chunk indexes | `Chunk`, one each |
//! | `Chunk`      | kind, id, object length, index, bytes     |                  |
//! | `Session`    | token, id, our token for the receiver     | `SessionState`   |
//! | `SessionState` | id, announce nonce, sequence held       |                  |
//! | `GetAnnounce`| token, id, our token for the receiver     | `Offer` or `Notice` |
//! | `Offer`      | token, object id and length, our token    | `GetChunks`      |
//! | `Notice`     | subject (an id or object), code           |                  |
//! | `Handshake`  | token, our token, channel, stage, fragment | `Handshake`     |
//! | `Frame`      | a channel's frame ([`crate::channel::Frame`]) | `Frame` (ack) |
//!
//! The last five are the message layer's rendezvous sessions
//! (`docs/ONION.md`, [`crate::node`]). An object of the message layer
//! (an announce or a payload, [`crate::onion::Object`]) is offered, never
//! pushed: the receiver pulls it as [`Kind::Object`] chunks with the token
//! the offer carried, so a relay can reach a participant that is not in
//! its peer table.
//!
//! The last two are onion mode's channels (`docs/ONION.md`): a handshake
//! message is cut into fragments of [`HANDSHAKE_FRAGMENT`] bytes, each a
//! request carrying the receiver's token and ours, so a relay answers a
//! hello (a datagram or two) with its reply (six) only to an address that
//! proved itself. Frames are sealed under the channel's keys and need no
//! token: a forged one does not open.
//!
//! A block or transaction (the [`Kind`]) is fetched as [`CHUNK_BYTES`]-byte
//! chunks of its serialization, pulled by the receiver with a window of
//! chunks in flight learned per peer ([`PeerPath`]) and asked for as index
//! ranges, with [`Download`] tracking what arrived; a block's `Inv` carries
//! its size, so its chunks are asked for exactly. A node only sends data in
//! reply to a request, never more than the request asked for (at most
//! [`MAX_IN_FLIGHT`] chunks a request, within a per-peer budget), and only
//! to a request carrying the token it gave that address in its own status
//! (so neither the address nor the request is forged), so it cannot be
//! used to amplify traffic.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::block::{HEADER_SIZE, Header};
use crate::chain::{Manifest, NamePart, OutputPart, PartCommits};
use crate::codec::{Reader, Writer};
use crate::difficulty::U256;
use crate::name_trie::Key;
use crate::names::{NAME_PART_RECORDS, Record};
use crate::pow::Digest;

pub const MAGIC: [u8; 4] = *b"TAB1";
pub const PROTOCOL_VERSION: u32 = 10;
/// Largest datagram sent: the IPv6 minimum MTU less its headers, well
/// within what IPv4 paths carry unfragmented in practice.
pub const MAX_DATAGRAM: usize = 1232;
/// Block bytes per chunk.
pub const CHUNK_BYTES: usize = 1024;
/// Chunks a download keeps in flight from a peer not yet measured: 64 KiB,
/// a modest first burst (`docs/HARDENING.md`, "Block relay").
pub const INITIAL_WINDOW: usize = 64;
/// The smallest window, however lossy the path.
pub const MIN_WINDOW: usize = 32;
/// The largest: a full 2 MiB block in one round trip on a path that
/// carries it. The window doubles per round trip until a loss (slow
/// start), halves at one, then grows by an eighth per round trip; it grows
/// only when a download filled it, and is kept per peer across downloads
/// ([`PeerPath`]), so a block from a peer already measured goes out in as few
/// round trips as that path allows.
pub const MAX_IN_FLIGHT: usize = 2048;
/// Free slots in the window before more chunks are asked for: topped up as
/// chunks arrive, in small batches.
pub const REFILL: usize = 8;
/// A chunk still missing once this many asked after it have arrived is
/// taken for lost and asked again at once (fast retransmit).
pub const REORDER: u8 = 8;
/// A round that loses more than one chunk in this many halves the window
/// (2%, as BBR): a full buffer drops much of a burst, a lossy link a few
/// chunks, and halving on every one would leave a 2 MiB block, which on
/// most paths loses a chunk or two, with the smallest window. A stall
/// (nothing for the retry time) halves it in any case.
pub const LOSS_TOLERANCE: usize = 50;
/// Index ranges in one `GetChunks`, at most.
pub const MAX_RANGES: usize = 64;
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
const T_TX_INV: u8 = 10;
const T_GET_HEADERS_FROM: u8 = 11;
const T_GET_PROOF: u8 = 12;
const T_PROOF: u8 = 13;
const T_GET_AUX: u8 = 14;
const T_AUX: u8 = 15;
const T_SESSION: u8 = 16;
const T_SESSION_STATE: u8 = 17;
const T_GET_ANNOUNCE: u8 = 18;
const T_OFFER: u8 = 19;
const T_NOTICE: u8 = 20;
const T_HANDSHAKE: u8 = 21;
const T_FRAME: u8 = 22;
/// Bytes of a handshake message per `Handshake` datagram.
pub const HANDSHAKE_FRAGMENT: usize = 1152;
/// Siblings per `Proof` message: a 40-level path takes two datagrams.
pub const PROOF_SIBLINGS_PER_MESSAGE: usize = crate::state_tree::DEPTH / 2;

/// What a chunked transfer carries. Snapshot objects are named by the
/// block whose state they describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Block,
    Tx,
    /// The manifest of the state after a block ([`encode_manifest`]).
    Manifest,
    /// One part of that state: an output part ([`encode_part`]) or, after
    /// those, a name part ([`encode_name_part`]).
    Part(u32),
    /// A consensus file (`docs/ONION.md`), named by
    /// [`crate::consensus::file_id`] of its SHA-256.
    Consensus,
    /// An object of the message layer ([`crate::onion::Object`]), named by
    /// [`crate::onion::Object::id_of`] and served only to whom it was
    /// offered.
    Object,
}

impl Kind {
    fn put(self, w: &mut Writer) {
        match self {
            Kind::Block => w.0.push(0),
            Kind::Tx => w.0.push(1),
            Kind::Manifest => w.0.push(2),
            Kind::Part(i) => {
                w.0.push(3);
                w.u32(i);
            }
            Kind::Consensus => w.0.push(4),
            Kind::Object => w.0.push(5),
        }
    }

    fn get(r: &mut Reader) -> Option<Kind> {
        match r.take(1)?[0] {
            0 => Some(Kind::Block),
            1 => Some(Kind::Tx),
            2 => Some(Kind::Manifest),
            3 => Some(Kind::Part(r.u32()?)),
            4 => Some(Kind::Consensus),
            5 => Some(Kind::Object),
            _ => None,
        }
    }
}

/// Largest manifest: about 600,000 output parts (5 billion unspent
/// outputs at least), or as many name parts.
pub const MAX_MANIFEST: usize = 32 << 20;
/// Largest part: every output of an output part a commit, which also
/// bounds a name part of [`NAME_PART_RECORDS`] records.
pub const MAX_PART: usize = 8 + crate::chain::PART_OUTPUTS as usize * (PART_ENTRY + COMMIT_ENTRY);
/// An output part in a manifest: level, index, count, root.
const MANIFEST_PART: usize = 1 + 8 + 4 + 32;
/// An output in a part: position, commitment, memo, amount, height.
const PART_ENTRY: usize = 8 + 32 + crate::transaction::MEMO_BYTES + 8 + 4;
const COMMIT_ENTRY: usize = 8 + 32 + 4;
const _: () = assert!(MAX_PART >= 4 + NAME_PART_RECORDS * (1 + 32 + 96));

/// A manifest: the output counter after the block, every output part's
/// subtree (level, index), count of unspent outputs and root, the name
/// root, and every name part's first key and hash.
pub fn encode_manifest(m: &Manifest) -> Vec<u8> {
    let mut w = Writer::with_capacity(48 + MANIFEST_PART * m.outputs.len() + 47 * m.names.len());
    w.u64(m.next);
    w.u32(m.outputs.len() as u32);
    for p in &m.outputs {
        w.0.push(p.level);
        w.u64(p.index);
        w.u32(p.count);
        w.digest(&p.root);
    }
    w.digest(&m.name_root);
    w.u32(m.names.len() as u32);
    for n in &m.names {
        w.0.extend_from_slice(&n.first.to_be_bytes()[1..]);
        w.digest(&n.hash);
    }
    w.finish()
}

pub fn decode_manifest(bytes: &[u8]) -> Option<Manifest> {
    let mut r = Reader(bytes);
    let next = r.u64()?;
    let n = r.len(MANIFEST_PART)?;
    let mut outputs = Vec::with_capacity(n);
    for _ in 0..n {
        let level = r.take(1)?[0];
        outputs.push(OutputPart { level, index: r.u64()?, count: r.u32()?, root: r.digest()? });
    }
    let name_root = r.digest()?;
    let n = r.len(15 + 32)?;
    let mut names = Vec::with_capacity(n);
    for _ in 0..n {
        let mut k = [0u8; 16];
        k[1..].copy_from_slice(r.take(15)?);
        names.push(NamePart { first: Key::from_be_bytes(k), hash: r.digest()? });
    }
    r.is_empty().then_some(Manifest { next, outputs, name_root, names })
}

/// An output part: its unspent outputs, position, commitment, memo and
/// creation height, ascending; then which of them are commits: position,
/// commit hash and height, ascending.
pub fn encode_part(outputs: &[(u64, Digest, Digest, u32)], commits: &[(u64, Digest, u32)]) -> Vec<u8> {
    let mut w = Writer::with_capacity(8 + PART_ENTRY * outputs.len() + COMMIT_ENTRY * commits.len());
    w.u32(outputs.len() as u32);
    for (p, c, slot, h) in outputs {
        let (memo, amount) = crate::transaction::slot_parts(slot).expect("a stored slot");
        w.u64(*p);
        w.digest(c);
        w.fps(&memo);
        w.u64(amount);
        w.u32(*h);
    }
    w.u32(commits.len() as u32);
    for (p, hash, height) in commits {
        w.u64(*p);
        w.digest(hash);
        w.u32(*height);
    }
    w.finish()
}

#[allow(clippy::type_complexity)]
pub fn decode_part(bytes: &[u8]) -> Option<(Vec<(u64, Digest, Digest, u32)>, PartCommits)> {
    let mut r = Reader(bytes);
    let n = r.len(PART_ENTRY)?;
    let out = (0..n)
        .map(|_| {
            let (p, c, memo) = (r.u64()?, r.digest()?, memo(&mut r)?);
            Some((p, c, crate::transaction::memo_slot(&memo, r.u64()?), r.u32()?))
        })
        .collect::<Option<Vec<_>>>()?;
    let n = r.len(COMMIT_ENTRY)?;
    let commits = (0..n).map(|_| Some((r.u64()?, r.digest()?, r.u32()?))).collect::<Option<Vec<_>>>()?;
    r.is_empty().then_some((out, commits))
}

fn memo(r: &mut Reader) -> Option<crate::transaction::Memo> {
    Some([r.fp()?, r.fp()?, r.fp()?, r.fp()?, r.fp()?])
}

/// A name part: its records, in key order.
pub fn encode_name_part(records: &[Record]) -> Vec<u8> {
    let mut w = Writer::with_capacity(4 + 130 * records.len());
    w.u32(records.len() as u32);
    for r in records {
        w.0.extend_from_slice(&r.to_bytes());
    }
    w.finish()
}

pub fn decode_name_part(bytes: &[u8]) -> Option<Vec<Record>> {
    let mut r = Reader(bytes);
    let n = r.len(1 + 96)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = *r.0.first()? as usize;
        out.push(Record::from_bytes(r.take(1 + len + 96)?)?);
    }
    r.is_empty().then_some(out)
}

/// What a node says about itself in `Ping` and `Pong`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// Set by the pinger; the pong echoes it.
    pub nonce: u64,
    pub version: u32,
    /// What the receiver must put in its requests to the sender: a value
    /// the sender derives from the receiver's address with a secret of its
    /// own, so a request forged from another address goes unanswered and
    /// the sender cannot be made to flood anyone.
    pub token: u64,
    /// Genesis block id; peers on another chain are ignored.
    pub genesis: Digest,
    pub height: u32,
    /// Lowest height from which the sender holds every main-chain body up
    /// to its tip ([`crate::chain::Chain::oldest_body`]): pruned and
    /// fast-synced nodes serve headers below it but not blocks.
    pub oldest: u32,
    pub tip: Digest,
    /// Cumulative work of the main chain.
    pub work: U256,
    /// The sender's relay floor, base units a byte (`docs/FEES.md`): it
    /// pools and relays nothing paying less.
    pub min_fee: u64,
    /// Its pool's admission minimum, base units a byte: the floor, or more
    /// while its pool is under pressure. Only the aged reserve's
    /// candidates are worth sending it for less.
    pub pool_fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Ping(Status),
    Pong(Status),
    /// Every request carries the [`Status::token`] the receiver gave the
    /// sender; the node fills it in as it sends.
    GetPeers {
        token: u64,
    },
    Peers(Vec<SocketAddr>),
    GetHeaders {
        locator: Vec<Digest>,
        token: u64,
    },
    /// Main-chain headers from `height` on, up to [`MAX_HEADERS`]: several
    /// can be asked of different peers at once, unlike `GetHeaders`.
    GetHeadersFrom {
        height: u32,
        token: u64,
    },
    Headers(Vec<Header>),
    /// A new block: its header and its size in bytes, so the whole of it
    /// can be asked for at once.
    Inv(Header, u32),
    TxInv(Digest),
    GetChunks {
        kind: Kind,
        id: Digest,
        indexes: Vec<u16>,
        token: u64,
    },
    Chunk {
        kind: Kind,
        id: Digest,
        len: u32,
        index: u16,
        data: Vec<u8>,
    },
    /// A state proof for the output at `position` against the sender's
    /// tip: for light clients holding headers.
    GetProof {
        position: u64,
        token: u64,
    },
    /// The output at `position` (commitment, memo, amount and creation
    /// height; all zero when the position is spent or unassigned) and its
    /// path in the
    /// state after block `tip`, in two parts of
    /// [`PROOF_SIBLINGS_PER_MESSAGE`] siblings each, bottom up.
    Proof {
        position: u64,
        tip: Digest,
        commitment: Digest,
        memo: crate::transaction::Memo,
        amount: u64,
        created: u32,
        part: u8,
        siblings: Vec<Digest>,
    },
    /// The 16 aux leaves of block `id` (`docs/ONION.md`), answered by a
    /// node that holds them checked.
    GetAux {
        id: Digest,
        token: u64,
    },
    Aux {
        id: Digest,
        leaves: [[u8; 32]; crate::chain::AUX_LEAVES],
    },
    /// Opens or keeps a rendezvous session for `id` at a relay; `back` is
    /// the sender's token for the relay, for the relay's requests to it.
    Session {
        id: Digest,
        back: u64,
        token: u64,
    },
    /// The relay's answer: the nonce an announce for this session must
    /// carry, and the sequence number of the announce it holds for `id`
    /// from this address (0 for none: the session is not live).
    SessionState {
        id: Digest,
        nonce: u64,
        seq: u64,
    },
    /// Asks a relay for the announce of `id`: answered with an `Offer` of
    /// it while `id` has a live session there, else a `Notice`.
    GetAnnounce {
        id: Digest,
        back: u64,
        token: u64,
    },
    /// An object of `len` bytes for the receiver to pull as
    /// [`Kind::Object`] chunks, using `back` as its token.
    Offer {
        object: Digest,
        len: u32,
        back: u64,
        token: u64,
    },
    /// What became of a request about `subject`: one of the `NOTICE_`
    /// codes.
    Notice {
        subject: Digest,
        code: u8,
    },
    /// Fragment `index` of `count` of a channel handshake message
    /// (`stage` 1 hello, 2 reply, 3 auth) for channel `chan`; `back` is the
    /// sender's token for the receiver.
    Handshake {
        chan: u64,
        stage: u8,
        index: u8,
        count: u8,
        data: Vec<u8>,
        back: u64,
        token: u64,
    },
    Frame(crate::channel::Frame),
}

/// A payload was handed down the recipient's live session.
pub const NOTICE_FORWARDED: u8 = 0;
/// The id has no live session here.
pub const NOTICE_OFFLINE: u8 = 1;
/// This node does not relay, or holds no more sessions.
pub const NOTICE_REFUSED: u8 = 2;
/// The object was not what it should be.
pub const NOTICE_REJECTED: u8 = 3;

fn put_status(w: &mut Writer, s: &Status) {
    w.u64(s.nonce);
    w.u32(s.version);
    w.u64(s.token);
    w.digest(&s.genesis);
    w.u32(s.height);
    w.u32(s.oldest);
    w.digest(&s.tip);
    w.0.extend_from_slice(&s.work.to_le_bytes());
    w.u64(s.min_fee);
    w.u64(s.pool_fee);
}

fn get_status(r: &mut Reader) -> Option<Status> {
    Some(Status {
        nonce: r.u64()?,
        version: r.u32()?,
        token: r.u64()?,
        genesis: r.digest()?,
        height: r.u32()?,
        oldest: r.u32()?,
        tip: r.digest()?,
        work: U256::from_le_bytes(r.take(32)?.try_into().unwrap()),
        min_fee: r.u64()?,
        pool_fee: r.u64()?,
    })
}

/// An IPv4 address and port (the caller leaves IPv6 ones out).
fn put_addr(w: &mut Writer, a: &SocketAddr) {
    if let IpAddr::V4(ip) = a.ip() {
        w.0.extend_from_slice(&ip.octets());
        w.0.extend_from_slice(&a.port().to_le_bytes());
    }
}

fn get_addr(r: &mut Reader) -> Option<SocketAddr> {
    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(r.take(4)?).unwrap());
    let port = u16::from_le_bytes(r.take(2)?.try_into().unwrap());
    Some(SocketAddr::new(IpAddr::V4(ip), port))
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
            Message::GetPeers { token } => {
                w.0.push(T_GET_PEERS);
                w.u64(*token);
            }
            Message::Peers(addrs) => {
                w.0.push(T_PEERS);
                let v4: Vec<&SocketAddr> = addrs.iter().filter(|a| a.is_ipv4()).take(MAX_PEERS_MESSAGE).collect();
                w.0.push(v4.len() as u8);
                for a in v4 {
                    put_addr(&mut w, a);
                }
            }
            Message::GetHeaders { locator, token } => {
                w.0.push(T_GET_HEADERS);
                w.u64(*token);
                w.digest_vec(&locator[..locator.len().min(MAX_LOCATOR)]);
            }
            Message::GetHeadersFrom { height, token } => {
                w.0.push(T_GET_HEADERS_FROM);
                w.u64(*token);
                w.u32(*height);
            }
            Message::Headers(headers) => {
                w.0.push(T_HEADERS);
                w.0.push(headers.len().min(HEADERS_PER_MESSAGE) as u8);
                for h in headers.iter().take(HEADERS_PER_MESSAGE) {
                    w.0.extend_from_slice(&h.to_bytes());
                }
            }
            Message::Inv(h, len) => {
                w.0.push(T_INV);
                w.0.extend_from_slice(&h.to_bytes());
                w.u32(*len);
            }
            Message::TxInv(id) => {
                w.0.push(T_TX_INV);
                w.digest(id);
            }
            Message::GetChunks { kind, id, indexes, token } => {
                w.0.push(T_GET_CHUNKS);
                w.u64(*token);
                kind.put(&mut w);
                w.digest(id);
                // Runs of consecutive indexes, as (start, count).
                let runs = runs(indexes);
                w.0.push(runs.len().min(MAX_RANGES) as u8);
                for (start, n) in runs.into_iter().take(MAX_RANGES) {
                    w.0.extend_from_slice(&start.to_le_bytes());
                    w.0.extend_from_slice(&n.to_le_bytes());
                }
            }
            Message::Chunk { kind, id, len, index, data } => {
                w.0.push(T_CHUNK);
                kind.put(&mut w);
                w.digest(id);
                w.u32(*len);
                w.0.extend_from_slice(&index.to_le_bytes());
                w.0.extend_from_slice(&(data.len() as u16).to_le_bytes());
                w.0.extend_from_slice(data);
            }
            Message::GetProof { position, token } => {
                w.0.push(T_GET_PROOF);
                w.u64(*position);
                w.u64(*token);
            }
            Message::Proof { position, tip, commitment, memo, amount, created, part, siblings } => {
                w.0.push(T_PROOF);
                w.u64(*position);
                w.digest(tip);
                w.digest(commitment);
                w.fps(memo);
                w.u64(*amount);
                w.u32(*created);
                w.0.push(*part);
                w.0.push(siblings.len() as u8);
                for s in siblings {
                    w.digest(s);
                }
            }
            Message::GetAux { id, token } => {
                w.0.push(T_GET_AUX);
                w.u64(*token);
                w.digest(id);
            }
            Message::Aux { id, leaves } => {
                w.0.push(T_AUX);
                w.digest(id);
                for l in leaves {
                    w.0.extend_from_slice(l);
                }
            }
            Message::Session { id, back, token } => {
                w.0.push(T_SESSION);
                w.u64(*token);
                w.digest(id);
                w.u64(*back);
            }
            Message::SessionState { id, nonce, seq } => {
                w.0.push(T_SESSION_STATE);
                w.digest(id);
                w.u64(*nonce);
                w.u64(*seq);
            }
            Message::GetAnnounce { id, back, token } => {
                w.0.push(T_GET_ANNOUNCE);
                w.u64(*token);
                w.digest(id);
                w.u64(*back);
            }
            Message::Offer { object, len, back, token } => {
                w.0.push(T_OFFER);
                w.u64(*token);
                w.digest(object);
                w.u32(*len);
                w.u64(*back);
            }
            Message::Notice { subject, code } => {
                w.0.push(T_NOTICE);
                w.digest(subject);
                w.0.push(*code);
            }
            Message::Handshake { chan, stage, index, count, data, back, token } => {
                w.0.push(T_HANDSHAKE);
                w.u64(*token);
                w.u64(*back);
                w.u64(*chan);
                w.0.extend_from_slice(&[*stage, *index, *count]);
                w.0.extend_from_slice(&(data.len() as u16).to_le_bytes());
                w.0.extend_from_slice(data);
            }
            Message::Frame(f) => {
                w.0.push(T_FRAME);
                f.put(&mut w);
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
            T_GET_PEERS => Message::GetPeers { token: r.u64()? },
            T_PEERS => {
                let n = count(&mut r, MAX_PEERS_MESSAGE)?;
                Message::Peers((0..n).map(|_| get_addr(&mut r)).collect::<Option<Vec<_>>>()?)
            }
            T_GET_HEADERS => {
                let token = r.u64()?;
                let locator = r.digest_vec()?;
                (locator.len() <= MAX_LOCATOR).then_some(())?;
                Message::GetHeaders { locator, token }
            }
            T_GET_HEADERS_FROM => {
                let token = r.u64()?;
                Message::GetHeadersFrom { height: r.u32()?, token }
            }
            T_HEADERS => {
                let n = count(&mut r, HEADERS_PER_MESSAGE)?;
                let headers = (0..n).map(|_| Header::from_bytes(r.take(HEADER_SIZE)?)).collect::<Option<Vec<_>>>()?;
                Message::Headers(headers)
            }
            T_INV => Message::Inv(Header::from_bytes(r.take(HEADER_SIZE)?)?, r.u32()?),
            T_TX_INV => Message::TxInv(r.digest()?),
            T_GET_CHUNKS => {
                let token = r.u64()?;
                let kind = Kind::get(&mut r)?;
                let id = r.digest()?;
                let n = count(&mut r, MAX_RANGES)?;
                let mut indexes: Vec<u16> = Vec::new();
                for _ in 0..n {
                    let start = u16::from_le_bytes(r.take(2)?.try_into().unwrap());
                    let len = u16::from_le_bytes(r.take(2)?.try_into().unwrap());
                    (len > 0 && indexes.len() + len as usize <= MAX_IN_FLIGHT).then_some(())?;
                    // Runs as the sender writes them: ascending, apart (one
                    // that touches the last would have been part of it), and
                    // within range. One request, one encoding, and no index
                    // asked twice.
                    let end = start as u32 + len as u32;
                    (end <= 1 << 16).then_some(())?;
                    if let Some(&last) = indexes.last() {
                        (start as u32 > last as u32 + 1).then_some(())?;
                    }
                    indexes.extend((0..len).map(|k| start + k));
                }
                Message::GetChunks { kind, id, indexes, token }
            }
            T_CHUNK => {
                let kind = Kind::get(&mut r)?;
                let id = r.digest()?;
                let len = r.u32()?;
                let index = u16::from_le_bytes(r.take(2)?.try_into().unwrap());
                let n = u16::from_le_bytes(r.take(2)?.try_into().unwrap()) as usize;
                (n <= CHUNK_BYTES).then_some(())?;
                let data = r.take(n)?.to_vec();
                Message::Chunk { kind, id, len, index, data }
            }
            T_GET_PROOF => {
                let position = r.u64()?;
                let token = r.u64()?;
                Message::GetProof { position, token }
            }
            T_PROOF => {
                let position = r.u64()?;
                let tip = r.digest()?;
                let commitment = r.digest()?;
                let memo = memo(&mut r)?;
                let amount = r.u64()?;
                let created = r.u32()?;
                let part = r.take(1)?[0];
                let n = r.take(1)?[0] as usize;
                if part > 1 || n > PROOF_SIBLINGS_PER_MESSAGE {
                    return None;
                }
                let siblings = (0..n).map(|_| r.digest()).collect::<Option<Vec<_>>>()?;
                Message::Proof { position, tip, commitment, memo, amount, created, part, siblings }
            }
            T_GET_AUX => {
                let token = r.u64()?;
                Message::GetAux { id: r.digest()?, token }
            }
            T_AUX => {
                let id = r.digest()?;
                let mut leaves = [[0u8; 32]; crate::chain::AUX_LEAVES];
                for l in leaves.iter_mut() {
                    l.copy_from_slice(r.take(32)?);
                }
                Message::Aux { id, leaves }
            }
            T_SESSION => {
                let token = r.u64()?;
                Message::Session { id: r.digest()?, back: r.u64()?, token }
            }
            T_SESSION_STATE => Message::SessionState { id: r.digest()?, nonce: r.u64()?, seq: r.u64()? },
            T_GET_ANNOUNCE => {
                let token = r.u64()?;
                Message::GetAnnounce { id: r.digest()?, back: r.u64()?, token }
            }
            T_OFFER => {
                let token = r.u64()?;
                Message::Offer { object: r.digest()?, len: r.u32()?, back: r.u64()?, token }
            }
            T_NOTICE => Message::Notice { subject: r.digest()?, code: r.take(1)?[0] },
            T_HANDSHAKE => {
                let (token, back, chan) = (r.u64()?, r.u64()?, r.u64()?);
                let h = r.take(3)?;
                let (stage, index, count) = (h[0], h[1], h[2]);
                let n = u16::from_le_bytes(r.take(2)?.try_into().unwrap()) as usize;
                if n > HANDSHAKE_FRAGMENT || index >= count || !(1..=3).contains(&stage) {
                    return None;
                }
                Message::Handshake { chan, stage, index, count, data: r.take(n)?.to_vec(), back, token }
            }
            T_FRAME => Message::Frame(crate::channel::Frame::get(&mut r)?),
            _ => return None,
        };
        r.is_empty().then_some(msg)
    }
}

/// `indexes` as runs of consecutive ones: (start, count).
fn runs(indexes: &[u16]) -> Vec<(u16, u16)> {
    let mut out: Vec<(u16, u16)> = Vec::new();
    for &i in indexes {
        match out.last_mut() {
            Some((start, n)) if start.checked_add(*n) == Some(i) && *n < u16::MAX => *n += 1,
            _ => out.push((i, 1)),
        }
    }
    out
}

/// `GetChunks` messages asking for `indexes`: as runs, [`MAX_RANGES`] of
/// them and [`MAX_IN_FLIGHT`] chunks at most to a message.
pub fn chunk_requests(kind: Kind, id: Digest, indexes: &[u16]) -> impl Iterator<Item = Message> {
    let mut messages = Vec::new();
    let mut current: Vec<u16> = Vec::new();
    let mut ranges = 0;
    for &i in indexes {
        let starts_run = current.last().is_none_or(|&l| l.checked_add(1) != Some(i));
        if !current.is_empty() && ((starts_run && ranges == MAX_RANGES) || current.len() == MAX_IN_FLIGHT) {
            messages.push(std::mem::take(&mut current));
            ranges = 0;
        }
        if current.last().is_none_or(|&l| l.checked_add(1) != Some(i)) {
            ranges += 1;
        }
        current.push(i);
    }
    if !current.is_empty() {
        messages.push(current);
    }
    messages.into_iter().map(move |indexes| Message::GetChunks { kind, id, indexes, token: 0 })
}

impl Message {
    /// The request's token, if it is a request.
    pub fn token(&self) -> Option<u64> {
        match self {
            Message::GetPeers { token }
            | Message::GetHeaders { token, .. }
            | Message::GetHeadersFrom { token, .. }
            | Message::GetChunks { token, .. }
            | Message::GetAux { token, .. }
            | Message::Session { token, .. }
            | Message::GetAnnounce { token, .. }
            | Message::Offer { token, .. }
            | Message::Handshake { token, .. } => Some(*token),
            _ => None,
        }
    }

    /// The same message with `token` as its request token, if it is a request.
    pub fn with_token(mut self, t: u64) -> Message {
        match &mut self {
            Message::GetPeers { token }
            | Message::GetHeaders { token, .. }
            | Message::GetHeadersFrom { token, .. }
            | Message::GetChunks { token, .. }
            | Message::GetAux { token, .. }
            | Message::Session { token, .. }
            | Message::GetAnnounce { token, .. }
            | Message::Offer { token, .. }
            | Message::Handshake { token, .. } => *token = t,
            _ => {}
        }
        self
    }
}

/// Number of chunks of a block of `len` bytes.
pub fn chunk_count(len: u32) -> usize {
    (len as usize).div_ceil(CHUNK_BYTES)
}

/// Chunk `index` of `bytes`, for a `Chunk` message.
pub fn chunk_of(kind: Kind, id: &Digest, bytes: &[u8], index: u16) -> Option<Message> {
    let start = index as usize * CHUNK_BYTES;
    if start >= bytes.len() {
        return None;
    }
    let end = (start + CHUNK_BYTES).min(bytes.len());
    Some(Message::Chunk { kind, id: *id, len: bytes.len() as u32, index, data: bytes[start..end].to_vec() })
}

/// How long a download may go without a new chunk before its window is
/// requested again, from a peer whose round trip is not yet measured.
pub const RETRY: Duration = Duration::from_millis(400);
/// The bounds of a measured retry wait: the smoothed round trip plus four
/// times its variation (RFC 6298).
pub const MIN_RETRY: Duration = Duration::from_millis(100);
pub const MAX_RETRY: Duration = Duration::from_secs(1);
/// Retries without progress before a download is abandoned.
pub const MAX_RETRIES: u32 = 8;
/// A block download averaging under this many bytes a second after
/// [`SLOW_GRACE`] is abandoned for another peer.
pub const MIN_RATE: usize = 8 << 10;
pub const SLOW_GRACE: Duration = Duration::from_secs(15);

/// What a node has learned of the path to one peer, carried from one
/// download to the next: the window and, after a loss, the slow-start
/// threshold above which it grows by an eighth per round trip instead of
/// doubling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerPath {
    pub window: usize,
    pub threshold: Option<usize>,
}

impl Default for PeerPath {
    fn default() -> PeerPath {
        PeerPath { window: INITIAL_WINDOW, threshold: None }
    }
}

/// A chunk asked for and not yet received.
#[derive(Clone, Copy, Debug)]
struct Asked {
    index: u16,
    at: Instant,
    /// The order it was asked in: the server sends in that order.
    seq: u64,
    /// Chunks asked after it that arrived while it did not: [`REORDER`]
    /// of them and it is taken for lost.
    passed: u8,
    /// Asked before: its arrival is no round-trip sample (Karn).
    again: bool,
}

/// A block (or other object) being fetched chunk by chunk from one peer,
/// with a window of chunks in flight ([`PeerPath`]): [`Download::request`]
/// asks for the missing chunks that fit, the node tops up once
/// [`REFILL`] slots are free, and a chunk passed by [`REORDER`] later ones,
/// or a stall (`node::stalled`), counts as a loss.
#[derive(Debug)]
pub struct Download {
    pub kind: Kind,
    pub id: Digest,
    pub from: SocketAddr,
    pub max_len: usize,
    /// Known from the announcement (`Inv`), else once the first chunk
    /// arrives.
    len: Option<u32>,
    chunks: Vec<Option<Vec<u8>>>,
    in_flight: Vec<Asked>,
    /// Indexes asked before, to tell retries from first asks.
    asked_before: Vec<bool>,
    /// The next ask's [`Asked::seq`].
    next_seq: u64,
    pub last_progress: Instant,
    pub last_request: Instant,
    pub retries: u32,
    pub started: Instant,
    path: PeerPath,
    /// Chunks arrived since the window last grew, and whether the window
    /// was full meanwhile (it grows only if so).
    delivered: usize,
    filled: bool,
    /// Chunks taken for lost this round.
    losses: usize,
    /// The window was cut this round: no second cut, and no growth, until
    /// a window arrives.
    recovering: bool,
    /// A round-trip sample from the last chunk, for the peer table.
    sample: Option<Duration>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChunkError {
    /// Chunk from a different block or peer.
    Unexpected,
    /// Length or index out of bounds, or inconsistent with earlier chunks.
    Malformed,
}

impl Download {
    /// A download of `id` from `from` with the window `path` learned of
    /// it, and the length `len` when announced.
    pub fn new(
        kind: Kind,
        id: Digest,
        from: SocketAddr,
        max_len: usize,
        len: Option<u32>,
        path: PeerPath,
        now: Instant,
    ) -> Download {
        let len = len.filter(|&l| l > 0 && l as usize <= max_len);
        let path = PeerPath { window: path.window.clamp(MIN_WINDOW, MAX_IN_FLIGHT), ..path };
        Download {
            kind,
            id,
            from,
            max_len,
            len,
            chunks: len.map_or(Vec::new(), |l| vec![None; chunk_count(l)]),
            in_flight: Vec::new(),
            asked_before: len.map_or(Vec::new(), |l| vec![false; chunk_count(l)]),
            next_seq: 0,
            last_progress: now,
            last_request: now,
            retries: 0,
            started: now,
            path,
            delivered: 0,
            filled: false,
            losses: 0,
            recovering: false,
            sample: None,
        }
    }

    /// What this download has learned of the path, for the next one.
    pub fn path(&self) -> PeerPath {
        self.path
    }

    /// The round-trip sample of the last chunk received, once.
    pub fn take_sample(&mut self) -> Option<Duration> {
        self.sample.take()
    }

    /// Indexes still missing, up to `max`, from the start: before the
    /// length is known, the first ones blind.
    pub fn missing(&self, max: usize) -> Vec<u16> {
        match self.len {
            None => (0..max.min(self.path.window) as u16).collect(),
            Some(_) => {
                self.chunks.iter().enumerate().filter(|(_, c)| c.is_none()).map(|(i, _)| i as u16).take(max).collect()
            }
        }
    }

    /// Missing indexes to request now: those not in flight, up to the free
    /// part of the window. They become in flight. Send them with
    /// [`chunk_requests`].
    pub fn request(&mut self, now: Instant) -> Vec<u16> {
        let window = self.path.window;
        let room = window.saturating_sub(self.in_flight.len());
        if room == 0 {
            return Vec::new();
        }
        let fresh: Vec<u16> = self
            .missing(window + self.in_flight.len())
            .into_iter()
            .filter(|i| !self.in_flight.iter().any(|a| a.index == *i))
            .take(room)
            .collect();
        for &index in &fresh {
            let again = match self.asked_before.get_mut(index as usize) {
                Some(b) => std::mem::replace(b, true),
                None => false,
            };
            self.in_flight.push(Asked { index, at: now, seq: self.next_seq, passed: 0, again });
            self.next_seq += 1;
        }
        if self.in_flight.len() >= window {
            self.filled = true;
        }
        if !fresh.is_empty() {
            self.last_request = now;
        }
        fresh
    }

    /// Halves the window, once a round, down to [`MIN_WINDOW`]; past it
    /// the window grows by an eighth per round trip.
    fn cut(&mut self) {
        if self.recovering {
            return;
        }
        self.recovering = true;
        let half = (self.path.window / 2).max(MIN_WINDOW);
        self.path = PeerPath { window: half, threshold: Some(half) };
    }

    /// A round ends (a window's worth arrived, or the download did): cut
    /// if it lost more than [`LOSS_TOLERANCE`] allows, else grow the
    /// window if it was used.
    fn end_round(&mut self) {
        let sent = self.delivered + self.losses;
        if self.losses * LOSS_TOLERANCE > sent {
            self.cut();
        } else if self.filled && !self.recovering {
            let w = self.path.window;
            let grown = match self.path.threshold {
                Some(t) if w >= t => w + w / 8,
                _ => 2 * w,
            };
            self.path.window = grown.min(MAX_IN_FLIGHT);
        }
        self.recovering = false;
        self.delivered = 0;
        self.losses = 0;
        self.filled = self.in_flight.len() >= self.path.window;
    }

    /// Forgets what is in flight, so the next request repeats it: nothing
    /// arrived for the retry time, a loss whatever the rate.
    pub fn reset_window(&mut self) {
        self.in_flight.clear();
        self.cut();
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// The window now.
    pub fn window(&self) -> usize {
        self.path.window
    }

    /// Whether to ask for more now: [`REFILL`] slots are free, or every
    /// chunk still missing fits in those that are.
    pub fn wants_refill(&self) -> bool {
        let free = self.path.window.saturating_sub(self.in_flight.len());
        if free >= REFILL {
            return true;
        }
        let unasked = self.chunks.iter().filter(|c| c.is_none()).count().saturating_sub(self.in_flight.len());
        free > 0 && self.len.is_some() && unasked > 0 && unasked <= free
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
                let mut before = vec![false; chunk_count(len)];
                for a in &self.in_flight {
                    if let Some(b) = before.get_mut(a.index as usize) {
                        *b = true;
                    }
                }
                self.asked_before = before;
                // Blind indexes past the end will never come.
                let n = self.chunks.len();
                self.in_flight.retain(|a| (a.index as usize) < n);
            }
            Some(l) if l != len => return Err(ChunkError::Malformed),
            Some(_) => {}
        }
        let i = index as usize;
        let expected = if i + 1 == self.chunks.len() { len as usize - i * CHUNK_BYTES } else { CHUNK_BYTES };
        if i >= self.chunks.len() || data.len() != expected {
            return Err(ChunkError::Malformed);
        }
        let asked = self.in_flight.iter().position(|a| a.index == index).map(|p| self.in_flight.remove(p));
        if self.chunks[i].is_none() {
            self.chunks[i] = Some(data);
            self.last_progress = now;
            self.retries = 0;
            if let Some(a) = asked
                && !a.again
            {
                self.sample = Some(now.duration_since(a.at));
            }
            // Chunks asked before this one and still missing have been
            // passed: past `REORDER`, lost.
            if let Some(a) = asked {
                let mut lost = false;
                for b in self.in_flight.iter_mut().filter(|b| b.seq < a.seq) {
                    b.passed = b.passed.saturating_add(1);
                    lost |= b.passed >= REORDER;
                }
                if lost {
                    let before = self.in_flight.len();
                    self.in_flight.retain(|b| b.passed < REORDER);
                    self.losses += before - self.in_flight.len();
                }
            }
            self.delivered += 1;
            if self.delivered >= self.path.window {
                self.end_round();
            }
        }
        let done = self.chunks.iter().all(Option::is_some);
        if done && self.delivered > 0 {
            // A block smaller than the window: its losses count too.
            self.end_round();
        }
        Ok(done)
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

    /// Whether, after [`SLOW_GRACE`], it averages under [`MIN_RATE`]: a
    /// peer trickling chunks just fast enough to avoid retries.
    pub fn too_slow(&self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.started);
        elapsed >= SLOW_GRACE && (self.received() * CHUNK_BYTES) as f64 / elapsed.as_secs_f64() < MIN_RATE as f64
    }

    pub fn total(&self) -> Option<usize> {
        self.len.map(chunk_count)
    }
}

/// A peer waits this long between pings.
pub const PING_INTERVAL: Duration = Duration::from_secs(30);
/// A peer that has not answered a ping yet is pinged again after this,
/// doubling up to [`PING_INTERVAL`]: a lost first ping or pong would
/// otherwise keep it from us (and channels to it waiting for its token)
/// for a whole interval.
pub const FIRST_PING_RETRY: Duration = Duration::from_secs(2);
/// A peer silent for this long is dropped (unless it is a seed).
pub const PEER_TIMEOUT: Duration = Duration::from_secs(180);
/// How long a peer a block download failed from, or that did not back its
/// claimed work with headers, is passed over.
pub const FETCH_BACKOFF: Duration = Duration::from_secs(600);
/// How long a peer asked for headers may take to send one we lack.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
/// Peers kept in the table.
pub const MAX_PEERS: usize = 64;
/// Most peer entries one public host may hold, over all its ports: room
/// for several nodes behind one address (a household, an office, a
/// carrier's NAT), while the network-group limit below keeps one party
/// from surrounding a node.
pub const MAX_PER_HOST: usize = 4;
/// A host's entry silent this long (two pings unanswered) gives its place
/// to a new address of the same host: a node there restarted, behind NAT,
/// on a new port, is taken at once rather than when the old entry times
/// out.
pub const HOST_STALE: Duration = Duration::from_secs(60);
/// Most peer entries one network group (a /16) may hold: an attacker with addresses in one network cannot fill the
/// table and surround the node.
pub const MAX_PER_GROUP: usize = 8;

/// The network group of an address, for [`MAX_PER_GROUP`]: its /16. The
/// table holds IPv4 addresses only.
fn group(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) >> 16,
        IpAddr::V6(_) => u32::MAX,
    }
}

/// What a ban is keyed by: the host, for a public address (a new port
/// would get around it), the socket address for loopback, where many
/// nodes may run on one machine.
fn ban_key(addr: &SocketAddr) -> SocketAddr {
    if addr.ip().is_loopback() { *addr } else { SocketAddr::new(addr.ip(), 0) }
}
/// Pings sent per tick to addresses that have not yet answered one: a
/// forged ping costs at most this much traffic towards its victim.
pub const UNVERIFIED_PINGS: usize = 8;
/// Strikes after which a peer is dropped and its address refused for
/// [`BAN_TIME`]; a peer's strikes are forgotten [`STRIKE_DECAY`] after the
/// last one.
pub const MAX_STRIKES: u32 = 5;
pub const STRIKE_DECAY: Duration = Duration::from_secs(600);
pub const BAN_TIME: Duration = Duration::from_secs(3600);
/// Below this many live peers the node looks for more.
pub const TARGET_PEERS: usize = 8;

#[derive(Clone, Debug)]
pub struct Peer {
    pub addr: SocketAddr,
    /// Blocks it delivered whole (by hash): a peer that has delivered is
    /// asked before one that only claims.
    pub delivered: u32,
    /// Smoothed round trip and its mean deviation (RFC 6298), from our
    /// pings to its pongs and from chunks asked and received.
    pub rtt: Option<Duration>,
    pub rtt_var: Duration,
    /// When a well-formed message last arrived; `None` until the first.
    pub last_seen: Option<Instant>,
    pub last_ping: Option<Instant>,
    /// Nonce of the ping awaiting its pong.
    pub pending: Option<u64>,
    /// Pings sent before its first pong ([`FIRST_PING_RETRY`]).
    pub first_pings: u32,
    /// When it was first pinged: one that never answers is dropped
    /// [`PEER_TIMEOUT`] after, however often it was pinged again (each
    /// retry moves `last_ping`).
    pub first_ping: Option<Instant>,
    pub status: Option<Status>,
    /// Bad replies to our requests; dropped at [`MAX_STRIKES`].
    pub strikes: u32,
    pub last_strike: Option<Instant>,
    pub seed: bool,
    /// Answered one of our pings with its nonce: it really is at this
    /// address, so it may be served data.
    pub handshaken: bool,
    /// When a block download from it was last abandoned, or it last
    /// failed to send headers for the work it claims. A pruned or
    /// fast-synced peer has every header but not every old body; a lying
    /// peer has neither.
    pub failed_fetch: Option<Instant>,
    /// Since when we have been waiting for headers from it.
    pub headers_asked: Option<Instant>,
}

impl Peer {
    /// Folds a round-trip sample into the smoothed estimate (RFC 6298:
    /// variation by a quarter, mean by an eighth).
    fn round_trip(&mut self, sample: Duration) {
        match self.rtt {
            None => {
                self.rtt = Some(sample);
                self.rtt_var = sample / 2;
            }
            Some(r) => {
                let dev = r.abs_diff(sample);
                self.rtt_var = (self.rtt_var * 3 + dev) / 4;
                self.rtt = Some((r * 7 + sample) / 8);
            }
        }
    }

    /// Whether a block download from it failed within [`FETCH_BACKOFF`].
    fn recently_failed(&self, now: Instant) -> bool {
        self.failed_fetch.is_some_and(|t| now.duration_since(t) < FETCH_BACKOFF)
    }
}

/// The peer table.
#[derive(Default)]
pub struct Peers {
    map: HashMap<SocketAddr, Peer>,
    /// Addresses found to be this node itself (a seed or peer list naming
    /// our own public address); never added again.
    selves: std::collections::HashSet<SocketAddr>,
    /// Addresses dropped for strikes, and when.
    banned: HashMap<SocketAddr, Instant>,
    /// Pings to unverified addresses left this tick.
    budget: usize,
    /// State of the generator that samples peers.
    rng: std::cell::Cell<u64>,
}

impl Peers {
    pub fn new() -> Peers {
        Peers::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// A pseudorandom number, for sampling: xorshift, seeded from the
    /// process's random hash keys.
    fn next_random(&self) -> u64 {
        let mut x = self.rng.get();
        if x == 0 {
            x = std::hash::BuildHasher::hash_one(&std::collections::hash_map::RandomState::new(), 0u8) | 1;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng.set(x);
        x
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<&Peer> {
        self.map.get(addr)
    }

    /// Adds an address to try, if there is room. Returns whether it is new.
    /// One host (a public address, whatever its ports) gets at most
    /// [`MAX_PER_HOST`] entries, so it cannot fill the table.
    pub fn add(&mut self, addr: SocketAddr, seed: bool) -> bool {
        if addr.ip().is_unspecified() || addr.port() == 0 || self.selves.contains(&addr) {
            return false;
        }
        // IPv4 only (see the module doc).
        if !addr.is_ipv4() {
            return false;
        }
        if self.banned.get(&ban_key(&addr)).is_some_and(|t| t.elapsed() < BAN_TIME) {
            return false;
        }
        if let Some(p) = self.map.get_mut(&addr) {
            p.seed |= seed;
            return false;
        }
        if !seed
            && !addr.ip().is_loopback()
            && self.map.values().filter(|p| p.addr.ip() == addr.ip()).count() >= MAX_PER_HOST
        {
            // The host's longest silent entry gives way, if one is silent.
            match self.stale_of_host(addr, Instant::now()) {
                Some(old) => {
                    self.map.remove(&old);
                }
                None => return false,
            }
        }
        if !seed
            && !addr.ip().is_loopback()
            && self.map.values().filter(|p| !p.seed && group(p.addr.ip()) == group(addr.ip())).count() >= MAX_PER_GROUP
        {
            return false;
        }
        if self.map.len() >= MAX_PEERS {
            // Replace a non-seed entry that never proved its address, so
            // forged pings and peer lists cannot crowd out real peers.
            let Some(victim) = self.map.values().find(|p| !p.handshaken && !p.seed).map(|p| p.addr) else {
                return false;
            };
            self.map.remove(&victim);
        }
        self.map.insert(
            addr,
            Peer {
                addr,
                delivered: 0,
                rtt: None,
                rtt_var: Duration::ZERO,
                last_seen: None,
                last_ping: None,
                pending: None,
                first_pings: 0,
                first_ping: None,
                status: None,
                strikes: 0,
                last_strike: None,
                seed,
                handshaken: false,
                failed_fetch: None,
                headers_asked: None,
            },
        );
        true
    }

    /// Notes a well-formed message from `addr`, adding the peer if unknown.
    pub fn seen(&mut self, addr: SocketAddr, now: Instant) {
        self.add(addr, false);
        if let Some(p) = self.map.get_mut(&addr) {
            p.last_seen = Some(now);
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
        p.handshaken = true;
        // Karn's rule: a ping sent more than once times nothing.
        if p.first_pings == 0
            && let Some(sample) = p.last_ping.map(|t| t.elapsed())
        {
            p.round_trip(sample);
        }
        p.first_pings = 0;
        true
    }

    /// A round trip measured to `addr`: a chunk asked once and received.
    pub fn rtt_sample(&mut self, addr: &SocketAddr, sample: Duration) {
        if let Some(p) = self.map.get_mut(addr) {
            p.round_trip(sample);
        }
    }

    /// How long to wait for a chunk from `addr` before asking again: its
    /// smoothed round trip plus four times the deviation, from
    /// [`MIN_RETRY`] to [`MAX_RETRY`]; [`RETRY`] before one is measured.
    pub fn retry(&self, addr: &SocketAddr) -> Duration {
        self.map
            .get(addr)
            .and_then(|p| p.rtt.map(|r| r + 4 * p.rtt_var))
            .map_or(RETRY, |w| w.clamp(MIN_RETRY, MAX_RETRY))
    }

    /// The token `addr` gave us to put in requests (0 before its status).
    pub fn token(&self, addr: &SocketAddr) -> u64 {
        self.map.get(addr).and_then(|p| p.status).map_or(0, |s| s.token)
    }

    /// Whether `addr` has answered a ping of ours.
    pub fn handshaken(&self, addr: &SocketAddr) -> bool {
        self.map.get(addr).is_some_and(|p| p.handshaken)
    }

    /// Marks `addr` pinged now with `nonce`, if it has no ping outstanding.
    /// Returns whether to send one.
    /// An unverified address is pinged only within this tick's budget of
    /// [`UNVERIFIED_PINGS`].
    pub fn ping_now(&mut self, addr: SocketAddr, nonce: u64, now: Instant) -> bool {
        match self.map.get_mut(&addr) {
            Some(p) if p.pending.is_none() && (p.handshaken || p.seed || self.budget > 0) => {
                if !p.handshaken && !p.seed {
                    self.budget -= 1;
                }
                p.last_ping = Some(now);
                p.first_ping.get_or_insert(now);
                p.pending = Some(nonce);
                true
            }
            _ => false,
        }
    }

    /// Whether a ping from `addr` carrying `nonce` is our own ping to
    /// `addr` come back: `addr` is this node.
    pub fn is_own_ping(&self, addr: &SocketAddr, nonce: u64) -> bool {
        self.map.get(addr).is_some_and(|p| p.pending == Some(nonce))
    }

    /// Whether `addr` was found to be this node.
    pub fn is_self(&self, addr: &SocketAddr) -> bool {
        self.selves.contains(addr)
    }

    /// Forgets `addr` for good: it is this node.
    pub fn mark_self(&mut self, addr: SocketAddr) {
        self.map.remove(&addr);
        self.selves.insert(addr);
    }

    /// A bad reply from `addr`. Strikes are forgotten after
    /// [`STRIKE_DECAY`] without another.
    pub fn strike(&mut self, addr: SocketAddr) {
        let now = Instant::now();
        if let Some(p) = self.map.get_mut(&addr) {
            if p.last_strike.is_some_and(|t| now.duration_since(t) >= STRIKE_DECAY) {
                p.strikes = 0;
            }
            p.strikes += 1;
            p.last_strike = Some(now);
        }
    }

    /// Notes that a block download from `addr` was abandoned.
    /// Notes that `addr` delivered a block matching its hash.
    pub fn delivered(&mut self, addr: SocketAddr) {
        if let Some(p) = self.map.get_mut(&addr) {
            p.delivered = p.delivered.saturating_add(1);
        }
    }

    pub fn fetch_failed(&mut self, addr: SocketAddr, now: Instant) {
        if let Some(p) = self.map.get_mut(&addr) {
            p.failed_fetch = Some(now);
        }
    }

    pub fn remove(&mut self, addr: &SocketAddr) {
        self.map.remove(addr);
    }

    /// Every known peer.
    pub fn all(&self) -> impl Iterator<Item = &Peer> {
        self.map.values()
    }

    /// Peers that proved their address by answering our ping, heard from
    /// within the timeout: the only ones counted, told of blocks and peers,
    /// or believed.
    pub fn live(&self, now: Instant) -> impl Iterator<Item = &Peer> {
        self.map
            .values()
            .filter(move |p| p.handshaken && p.last_seen.is_some_and(|t| now.duration_since(t) < PEER_TIMEOUT))
    }

    pub fn live_count(&self, now: Instant) -> usize {
        self.live(now).count()
    }

    /// Peers due for a ping: never pinged, or pinged longer ago than the
    /// interval. Marks them pinged with `nonce`.
    pub fn due_for_ping(&mut self, now: Instant, mut nonce: impl FnMut() -> u64) -> Vec<(SocketAddr, u64)> {
        let mut out = Vec::new();
        self.budget = UNVERIFIED_PINGS;
        for p in self.map.values_mut() {
            // Until its first pong, sooner: 2 s, 4 s, 8 s, 16 s, then 30.
            let interval = if p.handshaken {
                PING_INTERVAL
            } else {
                FIRST_PING_RETRY.saturating_mul(1 << p.first_pings.min(4)).min(PING_INTERVAL)
            };
            if p.last_ping.is_none_or(|t| now.duration_since(t) >= interval) {
                if !p.handshaken && !p.seed {
                    if self.budget == 0 {
                        continue;
                    }
                    self.budget -= 1;
                }
                // Before the first pong, the same ping again: a slow pong to
                // an earlier copy still counts.
                let n = match p.pending {
                    Some(n) if !p.handshaken => {
                        p.first_pings += 1;
                        n
                    }
                    _ => nonce(),
                };
                p.last_ping = Some(now);
                p.first_ping.get_or_insert(now);
                p.pending = Some(n);
                out.push((p.addr, n));
            }
        }
        out
    }

    /// Drops peers that have been silent for the timeout since they last
    /// answered, or that never answered within it of their first ping, and
    /// peers with too many strikes. Seeds stay.
    /// Returns the addresses dropped for never answering.
    pub fn prune(&mut self, now: Instant) -> Vec<SocketAddr> {
        self.banned.retain(|_, t| now.duration_since(*t) < BAN_TIME);
        let banned = &mut self.banned;
        let mut unanswered = Vec::new();
        self.map.retain(|_, p| {
            if p.seed {
                return true;
            }
            if p.strikes >= MAX_STRIKES && p.last_strike.is_some_and(|t| now.duration_since(t) < STRIKE_DECAY) {
                banned.insert(ban_key(&p.addr), now);
                return false;
            }
            // One that never answered: from its first ping, not its last
            // (retried every 30 s at most, it would never go), so that dead
            // addresses do not hold a host's MAX_PER_HOST entries for good
            // and shut out the address it is at now.
            match (p.last_seen, p.first_ping) {
                (Some(seen), _) => now.duration_since(seen) < PEER_TIMEOUT,
                (None, Some(pinged)) => {
                    let keep = now.duration_since(pinged) < PEER_TIMEOUT;
                    if !keep {
                        unanswered.push(p.addr);
                    }
                    keep
                }
                (None, None) => true,
            }
        });
        // A banned host's other entries go with it.
        let banned = &self.banned;
        self.map.retain(|_, p| p.seed || !banned.contains_key(&ban_key(&p.addr)));
        unanswered
    }

    /// The entry of `addr`'s host (not a seed) silent longest, if silent
    /// for [`HOST_STALE`] at least since it last answered (or, never having
    /// answered, since its first ping). One never pinged yet does not give
    /// way: addresses from peer lists cannot push each other out.
    fn stale_of_host(&self, addr: SocketAddr, now: Instant) -> Option<SocketAddr> {
        self.map
            .values()
            .filter(|p| p.addr.ip() == addr.ip() && !p.seed)
            .filter_map(|p| p.last_seen.or(p.first_ping).map(|t| (t, p.addr)))
            .filter(|(t, _)| now.saturating_duration_since(*t) >= HOST_STALE)
            .min_by_key(|(t, _)| *t)
            .map(|(_, a)| a)
    }

    /// Why `add` would not take `addr` now, if it would not; the entries
    /// in its way are named.
    pub fn refusal(&self, addr: &SocketAddr) -> Option<String> {
        if self.map.contains_key(addr) {
            return None;
        }
        if self.banned.get(&ban_key(addr)).is_some_and(|t| t.elapsed() < BAN_TIME) {
            return Some("its host is banned".into());
        }
        let list = |f: &dyn Fn(&Peer) -> bool| -> String {
            let v: Vec<String> = self
                .map
                .values()
                .filter(|p| f(p))
                .map(|p| format!("{}{}", p.addr, if p.handshaken { "" } else { " (never answered)" }))
                .collect();
            v.join(", ")
        };
        if !addr.ip().is_loopback() {
            if self.map.values().filter(|p| p.addr.ip() == addr.ip()).count() >= MAX_PER_HOST
                && self.stale_of_host(*addr, Instant::now()).is_none()
            {
                return Some(format!(
                    "its host has {MAX_PER_HOST} entries already, none silent for a minute: {}",
                    list(&|p| p.addr.ip() == addr.ip())
                ));
            }
            if self.map.values().filter(|p| !p.seed && group(p.addr.ip()) == group(addr.ip())).count() >= MAX_PER_GROUP
            {
                return Some(format!("its /16 has {MAX_PER_GROUP} entries already"));
            }
        }
        if self.map.len() >= MAX_PEERS && !self.map.values().any(|p| !p.handshaken && !p.seed) {
            return Some(format!("the table is full ({MAX_PEERS} answering peers)"));
        }
        None
    }

    /// Up to `n` live peers other than `exclude`, at random.
    pub fn sample(&self, n: usize, exclude: Option<SocketAddr>, now: Instant) -> Vec<SocketAddr> {
        let mut all: Vec<SocketAddr> = self.live(now).map(|p| p.addr).filter(|a| Some(*a) != exclude).collect();
        // A partial shuffle: a random `n`, not the table's first.
        let n = n.min(all.len());
        for i in 0..n {
            let j = i + (self.next_random() % (all.len() - i) as u64) as usize;
            all.swap(i, j);
        }
        all.truncate(n);
        all
    }

    /// The live peer claiming the most work, if it exceeds `work`.
    pub fn best_above(&self, work: U256, now: Instant) -> Option<&Peer> {
        self.live(now).filter(|p| p.status.is_some_and(|s| s.work > work)).max_by_key(|p| p.status.unwrap().work)
    }

    /// Live peers: only their claims count.
    pub fn trusted(&self, now: Instant) -> impl Iterator<Item = &Peer> {
        self.live(now)
    }

    /// Trusted peers claiming more work than `work`, but for those passed
    /// over after a failure.
    pub fn claimants(&self, work: U256, now: Instant) -> impl Iterator<Item = &Peer> {
        self.trusted(now).filter(move |p| !p.recently_failed(now) && p.status.is_some_and(|s| s.work > work))
    }

    /// The peer to ask for headers, among those claiming more than `work`:
    /// preferably one holding the body at `next`, the first height we lack,
    /// then the one claiming the most.
    pub fn best_source(&self, work: U256, next: u32, now: Instant) -> Option<&Peer> {
        self.claimants(work, now).max_by_key(|p| (p.status.unwrap().oldest <= next, p.status.unwrap().work))
    }

    /// Trusted peers, not passed over, whose main chain reaches `height`
    /// with every body from it up.
    pub fn holders(&self, height: u32, now: Instant) -> impl Iterator<Item = &Peer> {
        self.trusted(now).filter(move |p| {
            !p.recently_failed(now) && p.status.is_some_and(|s| s.oldest <= height && height <= s.height)
        })
    }

    /// Whether `addr` may be asked for a block: trusted and not passed over.
    pub fn may_serve(&self, addr: &SocketAddr, now: Instant) -> bool {
        self.map.get(addr).is_some_and(|p| {
            p.handshaken && p.last_seen.is_some_and(|t| now.duration_since(t) < PEER_TIMEOUT) && !p.recently_failed(now)
        })
    }

    /// Whether `addr` may be asked for a block once passed over: trusted.
    pub fn may_serve_passed_over(&self, addr: &SocketAddr, now: Instant) -> bool {
        self.map
            .get(addr)
            .is_some_and(|p| p.handshaken && p.last_seen.is_some_and(|t| now.duration_since(t) < PEER_TIMEOUT))
    }

    /// Notes that `addr` was asked for headers, unless already waiting.
    pub fn asked_headers(&mut self, addr: SocketAddr, now: Instant) {
        if let Some(p) = self.map.get_mut(&addr) {
            p.headers_asked.get_or_insert(now);
        }
    }

    /// Whether `addr` was asked for headers and has not yet sent any we lacked.
    pub fn awaiting_headers(&self, addr: &SocketAddr) -> bool {
        self.map.get(addr).is_some_and(|p| p.headers_asked.is_some())
    }

    /// Notes that `addr` sent headers we lacked.
    pub fn headers_arrived(&mut self, addr: SocketAddr) {
        if let Some(p) = self.map.get_mut(&addr) {
            p.headers_asked = None;
        }
    }

    /// Peers asked for headers longer than [`HEADER_TIMEOUT`] ago that sent
    /// none we lacked and still claim more than `ours`, our best header's
    /// work: their claims are not believed for [`FETCH_BACKOFF`]. (One whose
    /// claim we have since reached, from it or another, is not to blame.)
    pub fn expire_header_requests(&mut self, ours: U256, now: Instant) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        for p in self.map.values_mut() {
            if p.headers_asked.is_some_and(|t| now.duration_since(t) >= HEADER_TIMEOUT) {
                p.headers_asked = None;
                if p.status.is_some_and(|s| s.work > ours) {
                    p.failed_fetch = Some(now);
                    out.push(p.addr);
                }
            }
        }
        out
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
            aux: [tag as u8; 32],
            mix: digest(tag + 3),
            nonce: [tag as u8; 32],
        }
    }

    fn status() -> Status {
        Status {
            nonce: 77,
            version: PROTOCOL_VERSION,
            token: 0x1234_5678_9abc_def0,
            genesis: digest(1),
            height: 42,
            oldest: 5,
            tip: digest(2),
            work: U256([1, 2, 3, 4]),
            min_fee: 10,
            pool_fee: 30,
        }
    }

    #[test]
    fn the_window_grows_while_whole_and_halves_on_loss() {
        let t = Instant::now();
        let len = (CHUNK_BYTES * 20_000) as u32;
        let from: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let mut d = Download::new(Kind::Part(0), digest(1), from, len as usize, Some(len), PeerPath::default(), t);
        let chunk = vec![0u8; CHUNK_BYTES];
        // Delivers what is in flight, in order.
        let round = |d: &mut Download| {
            let asked = d.request(t);
            for &i in &asked {
                d.insert(len, i, chunk.clone(), t).unwrap();
            }
            asked.len()
        };
        // Slow start: the window doubles per round trip, from 64 to 2048.
        let mut sizes = Vec::new();
        for _ in 0..7 {
            sizes.push(round(&mut d));
        }
        assert_eq!(sizes, vec![64, 128, 256, 512, 1024, 2048, 2048]);
        // In one message: consecutive indexes are one range.
        let asked: Vec<u16> = (0..2048).collect();
        assert_eq!(chunk_requests(Kind::Part(0), digest(1), &asked).count(), 1);
        // A loss halves it; the window that recovers does not grow, and
        // after it the window grows by an eighth per round trip.
        d.reset_window();
        assert_eq!(d.window(), 1024);
        assert_eq!(round(&mut d), 1024);
        assert_eq!(d.window(), 1024);
        round(&mut d);
        assert_eq!(d.window(), 1152);
        round(&mut d);
        assert_eq!(d.window(), 1296);
        // Down to the floor, however many losses (one cut per round).
        for _ in 0..20 {
            d.reset_window();
            round(&mut d);
            d.reset_window();
        }
        assert!(d.window() >= MIN_WINDOW && d.window() <= 2 * MIN_WINDOW, "{}", d.window());
        // The next download from the peer starts where this one left off.
        let path = d.path();
        let mut next = Download::new(Kind::Part(1), digest(2), from, len as usize, Some(len), path, t);
        assert_eq!(next.request(t).len(), path.window);
    }

    /// A window larger than the block is never filled, so it does not
    /// grow: small blocks teach no window they did not use.
    #[test]
    fn the_window_grows_only_when_used() {
        let t = Instant::now();
        let from: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let len = (CHUNK_BYTES * 210) as u32;
        let chunk = vec![0u8; CHUNK_BYTES];
        let path = PeerPath { window: 256, threshold: None };
        let mut d = Download::new(Kind::Block, digest(1), from, 1 << 22, Some(len), path, t);
        let asked = d.request(t);
        assert_eq!(asked.len(), 210, "the whole block at once");
        for &i in &asked {
            d.insert(len, i, chunk.clone(), t).unwrap();
        }
        assert_eq!(d.window(), 256);
        // A 210 KB block from a new peer: 64, 128, then the last 18 (the
        // third asked as the second arrives, in practice).
        let mut d = Download::new(Kind::Block, digest(1), from, 1 << 22, Some(len), PeerPath::default(), t);
        let mut rounds = 0;
        loop {
            let asked = d.request(t);
            if asked.is_empty() {
                break;
            }
            rounds += 1;
            for &i in &asked {
                d.insert(len, i, chunk.clone(), t).unwrap();
            }
        }
        assert_eq!((rounds, d.window()), (3, 256));
    }

    /// A chunk passed by `REORDER` later ones is taken for lost and asked
    /// again at once; one in a round is noise and the window holds, many
    /// halve it; a round-trip sample comes only from a chunk asked once.
    #[test]
    fn a_gap_is_asked_again_without_waiting() {
        let t = Instant::now();
        let from: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let len = (CHUNK_BYTES * 1000) as u32;
        let chunk = vec![0u8; CHUNK_BYTES];
        let path = PeerPath { window: 128, threshold: None };
        let mut d = Download::new(Kind::Block, digest(1), from, 1 << 22, Some(len), path, t);
        assert_eq!(d.request(t).len(), 128);
        let later = t + Duration::from_millis(80);
        for i in 1..REORDER as u16 {
            d.insert(len, i, chunk.clone(), later).unwrap();
        }
        assert_eq!(d.take_sample(), Some(Duration::from_millis(80)));
        assert_eq!((d.in_flight(), d.window()), (128 - 7, 128), "not yet lost");
        d.insert(len, REORDER as u16, chunk.clone(), later).unwrap();
        assert_eq!((d.in_flight(), d.window()), (128 - 9, 128), "chunk 0 lost: out of flight, the window held");
        assert!(d.wants_refill());
        assert_eq!(d.request(later).first(), Some(&0), "asked again at once, first");
        // The round ends with one loss in 128: under 2%, and the window,
        // filled, grows.
        for i in (9..128u16).chain([0]) {
            d.insert(len, i, chunk.clone(), later).unwrap();
        }
        assert_eq!(d.window(), 256);
        // A round that loses more than 2% is halved.
        let mut d = Download::new(Kind::Block, digest(1), from, 1 << 22, Some(len), path, t);
        d.request(t);
        for i in 10..128u16 {
            d.insert(len, i, chunk.clone(), later).unwrap();
        }
        let again = d.request(later);
        assert_eq!(&again[..10], &(0..10).collect::<Vec<u16>>()[..]);
        for i in 0..10u16 {
            d.insert(len, i, chunk.clone(), later).unwrap();
        }
        assert_eq!(d.window(), 64, "ten lost in 128");
        // A stall halves whatever the rate, once a round.
        d.reset_window();
        assert_eq!(d.window(), 32);
        d.reset_window();
        assert_eq!(d.window(), 32);
        // Asked twice: no sample.
        let mut d = Download::new(Kind::Block, digest(1), from, 1 << 22, Some(len), path, t);
        d.request(t);
        d.reset_window();
        d.request(t);
        d.insert(len, 0, chunk.clone(), later).unwrap();
        assert_eq!(d.take_sample(), None);
    }

    #[test]
    fn retry_waits_the_smoothed_round_trip_plus_four_deviations() {
        let mut peers = Peers::new();
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        peers.add(a, false);
        assert_eq!(peers.retry(&a), RETRY);
        peers.rtt_sample(&a, Duration::from_millis(100));
        // 100 + 4 × 50.
        assert_eq!(peers.retry(&a), Duration::from_millis(300));
        for _ in 0..50 {
            peers.rtt_sample(&a, Duration::from_millis(100));
        }
        assert!(peers.retry(&a) < Duration::from_millis(110), "{:?}", peers.retry(&a));
        for _ in 0..50 {
            peers.rtt_sample(&a, Duration::from_millis(10));
        }
        assert_eq!(peers.retry(&a), MIN_RETRY);
        for _ in 0..50 {
            peers.rtt_sample(&a, Duration::from_secs(3));
        }
        assert_eq!(peers.retry(&a), MAX_RETRY);
    }

    #[test]
    fn chunk_requests_go_as_ranges() {
        // Scattered indexes: MAX_RANGES runs to a message.
        let scattered: Vec<u16> = (0..200u16).map(|i| i * 2).collect();
        let msgs: Vec<Message> = chunk_requests(Kind::Block, digest(1), &scattered).collect();
        assert_eq!(msgs.len(), 200usize.div_ceil(MAX_RANGES));
        let mut back = Vec::new();
        for m in msgs {
            let bytes = m.encode();
            match Message::decode(&bytes) {
                Some(Message::GetChunks { indexes, .. }) => back.extend(indexes),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(back, scattered);
        // A run longer than a message's worth is split.
        let long: Vec<u16> = (0..5000).collect();
        assert_eq!(chunk_requests(Kind::Block, digest(1), &long).count(), 3);
    }

    #[test]
    fn one_host_gets_few_entries_and_a_ban_covers_its_ports() {
        let mut peers = Peers::new();
        let host = |port: u16| -> SocketAddr { format!("10.0.0.9:{port}").parse().unwrap() };
        for port in 1..=MAX_PER_HOST as u16 {
            assert!(peers.add(host(port), false));
        }
        assert!(!peers.add(host(MAX_PER_HOST as u16 + 1), false));
        // Loopback is exempt: many nodes may share one machine.
        for port in 1..5 {
            assert!(peers.add(format!("127.0.0.1:{port}").parse().unwrap(), false));
        }
        // Strikes against one port ban the host, every port of it.
        for _ in 0..MAX_STRIKES {
            peers.strike(host(1));
        }
        peers.prune(Instant::now());
        assert!(peers.get(&host(1)).is_none() && peers.get(&host(2)).is_none());
        assert!(!peers.add(host(3), false));
        assert_eq!(peers.len(), 4);
        // One network gets a few entries, however many hosts it has; a
        // seed is taken regardless.
        let net = |i: u8| -> SocketAddr { format!("10.7.0.{i}:1").parse().unwrap() };
        for i in 1..=MAX_PER_GROUP as u8 {
            assert!(peers.add(net(i), false));
        }
        assert!(!peers.add(net(100), false));
        assert!(peers.add("10.7.9.9:1".parse().unwrap(), true));
        assert!(peers.add("10.8.0.1:1".parse().unwrap(), false));
    }

    #[test]
    fn forged_addresses_cannot_crowd_the_table() {
        let t0 = Instant::now();
        let mut peers = Peers::new();
        // Each in a network of its own.
        let addr = |i: u32| -> SocketAddr { SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + (i << 16))), 1) };
        // One real peer, proven by answering our ping.
        let real = addr(1);
        peers.add(real, false);
        let pings = peers.due_for_ping(t0, || 42);
        assert_eq!(pings, [(real, 42)]);
        assert!(peers.pong(real, Status { nonce: 42, ..status() }));
        peers.seen(real, t0);
        // A flood of forged pings fills the table with unverified entries:
        // none is live, and they are pinged a few per tick, not all.
        for i in 2..1000 {
            peers.add(addr(i), false);
        }
        assert_eq!(peers.len(), MAX_PEERS);
        assert_eq!(peers.live_count(t0), 1);
        let mut n = 100;
        let pings = peers.due_for_ping(t0 + Duration::from_secs(1), || {
            n += 1;
            n
        });
        assert_eq!(pings.len(), UNVERIFIED_PINGS);
        // A newcomer still gets in, replacing an unverified entry.
        assert!(peers.add(addr(5000), false));
        assert!(peers.get(&real).is_some());
        // Strikes are forgotten after a quiet spell; enough at once drop
        // the peer and keep its address out for a while.
        for _ in 0..MAX_STRIKES - 1 {
            peers.strike(real);
        }
        peers.prune(t0);
        assert!(peers.get(&real).is_some());
        peers.map.get_mut(&real).unwrap().last_strike = Some(t0 - STRIKE_DECAY);
        peers.strike(real);
        assert_eq!(peers.get(&real).unwrap().strikes, 1);
        for _ in 0..MAX_STRIKES {
            peers.strike(real);
        }
        peers.prune(Instant::now());
        assert!(peers.get(&real).is_none());
        assert!(!peers.add(real, false));
    }

    #[test]
    fn claims_and_bodies_are_believed_from_trusted_peers() {
        // a has every body to height 100; b more work, but bodies only
        // from 90; c the least work above ours, everything; d claims the
        // most but never answered our ping.
        let addr = |i: u8| -> SocketAddr { format!("10.0.0.{i}:1").parse().unwrap() };
        let (a, b, c, d) = (addr(1), addr(2), addr(3), addr(4));
        let t0 = Instant::now();
        let mut peers = Peers::new();
        for x in [a, b, c, d] {
            peers.add(x, false);
        }
        let mut n = 0;
        let pings = peers.due_for_ping(t0, || {
            n += 1;
            n
        });
        for (x, oldest, height, work) in [(a, 1, 100, 10), (b, 90, 101, 11), (c, 1, 50, 6), (d, 1, 500, 99)] {
            let st = Status { oldest, height, work: U256([work, 0, 0, 0]), ..status() };
            peers.seen(x, t0);
            if x == d {
                peers.set_status(x, st);
            } else {
                let nonce = pings.iter().find(|(p, _)| *p == x).unwrap().1;
                assert!(peers.pong(x, Status { nonce, ..st }));
            }
        }
        let ours = U256([5, 0, 0, 0]);
        let best = |peers: &Peers, next: u32, now: Instant| peers.best_source(ours, next, now).map(|p| p.addr);
        let holders = |peers: &Peers, height: u32, now: Instant| {
            let mut v: Vec<SocketAddr> = peers.holders(height, now).map(|p| p.addr).collect();
            v.sort();
            v
        };
        assert_eq!(peers.claimants(ours, t0).count(), 3);
        // Starting low, a holds the next body; past 90, b's work wins.
        assert_eq!(best(&peers, 10, t0), Some(a));
        assert_eq!(best(&peers, 95, t0), Some(b));
        assert_eq!(holders(&peers, 20, t0), [a, c]);
        assert_eq!(holders(&peers, 95, t0), [a, b]);
        assert_eq!(holders(&peers, 101, t0), [b]);
        // b, asked for headers, sends none in time: passed over.
        let t1 = t0 + HEADER_TIMEOUT;
        peers.asked_headers(b, t0);
        assert!(peers.expire_header_requests(ours, t0 + HEADER_TIMEOUT / 2).is_empty());
        assert_eq!(peers.expire_header_requests(ours, t1), [b]);
        assert_eq!(best(&peers, 95, t1), Some(a));
        assert!(holders(&peers, 101, t1).is_empty());
        // a, asked, sends none, but we have since reached its claim.
        peers.asked_headers(a, t0);
        assert!(peers.expire_header_requests(U256([10, 0, 0, 0]), t1).is_empty());
        // A failed download passes a peer over until the backoff ends.
        peers.fetch_failed(a, t1);
        assert_eq!(best(&peers, 10, t1), Some(c));
        assert_eq!(holders(&peers, 20, t1), [c]);
        let t2 = t1 + FETCH_BACKOFF;
        for x in [a, b, c] {
            peers.seen(x, t2);
        }
        assert_eq!(best(&peers, 10, t2), Some(a));
        assert!(peers.may_serve(&a, t2) && !peers.may_serve(&d, t2));
    }

    #[test]
    fn ipv6_addresses_are_neither_taken_nor_sent() {
        let mut peers = Peers::new();
        let v6: SocketAddr = "[2001:db8::1]:7417".parse().unwrap();
        let v4: SocketAddr = "10.1.2.3:7417".parse().unwrap();
        assert!(!peers.add(v6, true));
        assert!(peers.add(v4, false));
        let bytes = Message::Peers(vec![v6, v4]).encode();
        assert_eq!(Message::decode(&bytes), Some(Message::Peers(vec![v4])));
    }

    /// One message of every kind, as the roundtrip test sends them.
    fn sample_messages() -> Vec<Message> {
        let v4: SocketAddr = "10.1.2.3:7417".parse().unwrap();
        let v4b: SocketAddr = "203.0.113.9:65535".parse().unwrap();
        vec![
            Message::Ping(status()),
            Message::Pong(status()),
            Message::GetPeers { token: 7 },
            Message::Peers(vec![v4, v4b]),
            Message::Peers(vec![v4b; MAX_PEERS_MESSAGE]),
            Message::GetHeaders { locator: (0..MAX_LOCATOR as u32).map(digest).collect(), token: u64::MAX },
            Message::GetHeadersFrom { height: 123_456, token: 1 },
            Message::Headers((0..HEADERS_PER_MESSAGE as u32).map(header).collect()),
            Message::Inv(header(5), 210_000),
            Message::TxInv(digest(6)),
            Message::GetChunks {
                kind: Kind::Tx,
                id: digest(9),
                indexes: (0..MAX_IN_FLIGHT as u16).collect(),
                token: 3,
            },
            Message::GetChunks { kind: Kind::Block, id: digest(9), indexes: vec![0, 1, 2, 7, 9, 10, 65535], token: 3 },
            Message::Chunk { kind: Kind::Block, id: digest(9), len: 200_000, index: 3, data: vec![7u8; CHUNK_BYTES] },
            Message::Chunk { kind: Kind::Part(7), id: digest(9), len: 9, index: 0, data: vec![1u8; 9] },
            Message::GetChunks { kind: Kind::Manifest, id: digest(2), indexes: vec![0, 1], token: 0 },
            Message::GetChunks { kind: Kind::Consensus, id: digest(4), indexes: vec![0], token: 5 },
            Message::GetAux { id: digest(8), token: 9 },
            Message::Aux { id: digest(8), leaves: core::array::from_fn(|i| [i as u8; 32]) },
            Message::Session { id: digest(1), back: 11, token: 12 },
            Message::SessionState { id: digest(1), nonce: u64::MAX, seq: 3 },
            Message::GetAnnounce { id: digest(2), back: 13, token: 14 },
            Message::Offer { object: digest(3), len: 6_500, back: 15, token: 16 },
            Message::GetChunks { kind: Kind::Object, id: digest(3), indexes: vec![0, 6], token: 15 },
            Message::Notice { subject: digest(4), code: NOTICE_OFFLINE },
            Message::Handshake {
                chan: u64::MAX,
                stage: 2,
                index: 5,
                count: 6,
                data: vec![9u8; HANDSHAKE_FRAGMENT],
                back: 1,
                token: 2,
            },
            Message::Frame(crate::channel::Frame {
                chan: 3,
                kind: 0,
                seq: 4,
                ack: 5,
                sack: 6,
                sealed: vec![7u8; crate::channel::MAX_BODY + 16],
            }),
        ]
    }

    /// The datagram decoder, fuzzed: no input makes it panic, and what it
    /// decodes encodes back to the same bytes.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
    fn fuzz_message_decoder() {
        let samples: Vec<Vec<u8>> = sample_messages().iter().map(Message::encode).collect();
        let decoded = crate::test_util::fuzz_decoder("Message::decode", &samples, 20_000, |b| {
            Message::decode(b).map(|m| Some(m.encode()))
        });

        // Fast sync's parts: manifest, output part, name part.
        let d = |x: u32| {
            let mut v = [crate::poseidon2::Fp::ZERO; crate::poseidon2::DIGEST];
            v[0] = crate::poseidon2::Fp::new(x);
            v
        };
        let manifest = Manifest {
            next: 20_000,
            outputs: vec![
                OutputPart { level: 14, index: 0, count: 3, root: d(1) },
                OutputPart { level: 14, index: 1, count: 9, root: d(2) },
            ],
            name_root: d(3),
            names: vec![NamePart { first: 0, hash: d(4) }, NamePart { first: 1 << 100, hash: d(5) }],
        };
        crate::test_util::fuzz_decoder("decode_manifest", &[encode_manifest(&manifest)], 20_000, |b| {
            decode_manifest(b).map(|m| Some(encode_manifest(&m)))
        });
        let slot = crate::transaction::memo_slot(&[crate::poseidon2::Fp::new(7); crate::transaction::MEMO_LEN], 1000);
        let part = encode_part(&[(5, d(1), slot, 3), (9, d(2), slot, 4)], &[(9, d(6), 4)]);
        crate::test_util::fuzz_decoder("decode_part", &[part], 20_000, |b| {
            decode_part(b).map(|(o, c)| Some(encode_part(&o, &c)))
        });
        let records =
            [Record::new(b"alice", d(1), d(2), d(3)).unwrap(), Record::new(b"bob", d(4), d(5), d(6)).unwrap()];
        crate::test_util::fuzz_decoder("decode_name_part", &[encode_name_part(&records)], 20_000, |b| {
            decode_name_part(b).map(|r| Some(encode_name_part(&r)))
        });
        eprintln!("{decoded} mutants decoded");
    }

    #[test]
    fn messages_roundtrip_within_the_datagram_limit() {
        let msgs = sample_messages();
        for m in msgs {
            let bytes = m.encode();
            assert!(bytes.len() <= MAX_DATAGRAM, "{m:?}: {} bytes", bytes.len());
            assert_eq!(Message::decode(&bytes), Some(m.clone()), "{m:?}");
            // Trailing or missing bytes are rejected; a frame's sealed body
            // runs to the end, so a shorter one only fails to open.
            let mut longer = bytes.clone();
            longer.push(0);
            assert_eq!(Message::decode(&longer), None);
            if !matches!(m, Message::Frame(_)) {
                assert_eq!(Message::decode(&bytes[..bytes.len() - 1]), None);
            }
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
        let mut d = Download::new(Kind::Block, id, from, 1 << 20, None, PeerPath::default(), now);
        assert_eq!(d.missing(4), vec![0, 1, 2, 3]);
        let chunk = |i: u16| match chunk_of(Kind::Block, &id, &bytes, i) {
            Some(Message::Chunk { len, index, data, .. }) => (len, index, data),
            _ => panic!(),
        };
        assert!(chunk_of(Kind::Block, &id, &bytes, 3).is_none());
        // The length unknown: the first window blind.
        assert_eq!(d.request(now), (0..INITIAL_WINDOW as u16).collect::<Vec<_>>());
        assert_eq!(d.in_flight(), INITIAL_WINDOW);
        assert!(d.request(now).is_empty());
        let (len, i, data) = chunk(2);
        assert_eq!(d.insert(len, i, data.clone(), now), Ok(false));
        // Known now: indexes past the end are out of flight.
        assert_eq!(d.in_flight(), 2);
        assert_eq!(d.missing(10), vec![0, 1]);
        assert_eq!(d.insert(len, i, data, now), Ok(false));
        // Wrong length, index or size.
        assert_eq!(d.insert(len + 1, 0, vec![0; CHUNK_BYTES], now), Err(ChunkError::Malformed));
        assert_eq!(d.insert(len, 3, vec![0; 10], now), Err(ChunkError::Malformed));
        assert_eq!(d.insert(len, 0, vec![0; 10], now), Err(ChunkError::Malformed));
        assert_eq!(d.in_flight(), 2);
        d.reset_window();
        assert_eq!(d.request(now), vec![0, 1]);
        let (_, i, data) = chunk(0);
        assert_eq!(d.insert(len, i, data, now), Ok(false));
        let (_, i, data) = chunk(1);
        assert_eq!(d.insert(len, i, data, now), Ok(true));
        assert_eq!(d.in_flight(), 0);
        assert_eq!(d.assemble().as_ref(), Some(&bytes));
        // Too large for the chain's limit.
        let mut small = Download::new(Kind::Block, id, from, 100, None, PeerPath::default(), now);
        assert_eq!(small.insert(2500, 0, vec![0; CHUNK_BYTES], now), Err(ChunkError::Malformed));
        // Announced: exactly its chunks asked, and a chunk of another
        // length refused.
        let mut told = Download::new(Kind::Block, id, from, 1 << 20, Some(2500), PeerPath::default(), now);
        assert_eq!(told.request(now), vec![0, 1, 2]);
        assert_eq!(told.insert(2600, 0, vec![0; CHUNK_BYTES], now), Err(ChunkError::Malformed));
        let (len, i, data) = chunk(0);
        assert_eq!(told.insert(len, i, data, now), Ok(false));
        // An announced length over the limit is ignored.
        let mut big = Download::new(Kind::Block, id, from, 100, Some(2500), PeerPath::default(), now);
        assert_eq!(big.request(now).len(), INITIAL_WINDOW);
    }

    /// A first ping that goes unanswered is sent again after 2, 4, 8 and
    /// 16 s, then every 30 s, as the same ping, so a pong to any copy
    /// counts (but times nothing); once answered, every 30 s with a new
    /// nonce.
    #[test]
    fn an_unanswered_first_ping_is_sent_again_sooner() {
        let t0 = Instant::now();
        let mut peers = Peers::new();
        let a: SocketAddr = "10.0.0.1:7417".parse().unwrap();
        peers.add(a, true);
        let mut n = 0u64;
        let mut due = |peers: &mut Peers, at: u64| -> Vec<u64> {
            peers
                .due_for_ping(t0 + Duration::from_secs(at), || {
                    n += 1;
                    n
                })
                .into_iter()
                .map(|(_, nonce)| nonce)
                .collect()
        };
        assert_eq!(due(&mut peers, 0), vec![1]);
        for (at, sent) in [(1, false), (2, true), (5, false), (6, true), (13, false), (14, true), (29, false)] {
            assert_eq!(due(&mut peers, at), if sent { vec![1] } else { vec![] }, "at {at} s");
        }
        assert_eq!(due(&mut peers, 30), vec![1]);
        assert!(due(&mut peers, 59).is_empty());
        assert_eq!(due(&mut peers, 60), vec![1]);
        assert!(peers.pong(a, Status { nonce: 1, ..status() }));
        assert!(peers.get(&a).unwrap().rtt.is_none(), "a ping sent more than once times nothing");
        assert!(due(&mut peers, 89).is_empty());
        assert_eq!(due(&mut peers, 90), vec![2]);
    }

    #[test]
    fn a_new_port_of_a_host_replaces_its_silent_entry() {
        // Four nodes behind one NAT, one restarted on a new port: the old
        // port, silent a minute, gives way at once; a live one never does.
        let now = Instant::now();
        let ago = |s: u64| now.checked_sub(Duration::from_secs(s)).unwrap();
        let mut peers = Peers::new();
        let host = |port: u16| -> SocketAddr { format!("10.9.0.2:{port}").parse().unwrap() };
        for port in 1..=MAX_PER_HOST as u16 {
            assert!(peers.add(host(port), false));
            peers.seen(host(port), ago(10));
        }
        assert!(peers.refusal(&host(100)).is_some());
        assert!(!peers.add(host(100), false));
        peers.seen(host(3), ago(HOST_STALE.as_secs() + 30));
        peers.seen(host(2), ago(HOST_STALE.as_secs() + 5));
        assert!(peers.refusal(&host(100)).is_none());
        assert!(peers.add(host(100), false));
        assert!(peers.get(&host(3)).is_none(), "the longest silent goes");
        assert!(peers.get(&host(2)).is_some());
        assert!(peers.get(&host(1)).is_some() && peers.get(&host(4)).is_some());
    }

    #[test]
    fn a_dead_address_does_not_hold_its_hosts_entries() {
        // A host behind NAT gets a new port each time a node there starts:
        // addresses that never answer, retried every 30 s, still go
        // PEER_TIMEOUT after their first ping, so the host's next address
        // finds room among its MAX_PER_HOST entries.
        let t0 = Instant::now();
        let mut peers = Peers::new();
        let host = |port: u16| -> SocketAddr { format!("10.9.0.1:{port}").parse().unwrap() };
        for port in 1..=MAX_PER_HOST as u16 {
            assert!(peers.add(host(port), false));
        }
        assert!(!peers.add(host(100), false));
        let mut t = t0;
        while t < t0 + PEER_TIMEOUT + Duration::from_secs(60) {
            peers.due_for_ping(t, || 1);
            peers.prune(t);
            t += Duration::from_secs(10);
        }
        for port in 1..=MAX_PER_HOST as u16 {
            assert!(peers.get(&host(port)).is_none(), "port {port} kept");
        }
        assert!(peers.add(host(100), false));
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
        assert!(!peers.handshaken(&a));
        assert!(peers.pong(a, Status { nonce: nonce_a, ..status() }));
        assert!(peers.handshaken(&a));
        assert!(!peers.pong(b, Status { nonce: 999, ..status() }));
        assert!(!peers.handshaken(&b));
        assert!(!peers.ping_now(b, 5, t0));
        peers.pong(b, Status { nonce: pings.iter().find(|(p, _)| *p == b).unwrap().1, ..status() });
        assert!(peers.ping_now(b, 5, t0));
        assert!(!peers.ping_now(b, 6, t0));
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
