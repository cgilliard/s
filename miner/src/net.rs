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
//! chunks of its serialization, pulled by the receiver in windows of
//! [`WINDOW`] with [`Download`] tracking what arrived. A node only sends
//! data in reply to a request, never more than the request asked for, and
//! only to a request carrying the token it gave that address in its own
//! status (so neither the address nor the request is forged), so it
//! cannot be used to amplify traffic.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::block::{HEADER_SIZE, Header};
use crate::chain::{Manifest, NamePart, PartCommits};
use crate::codec::{Reader, Writer};
use crate::difficulty::U256;
use crate::name_trie::Key;
use crate::names::{NAME_PART_RECORDS, Record};
use crate::pow::Digest;

pub const MAGIC: [u8; 4] = *b"TAB1";
pub const PROTOCOL_VERSION: u32 = 7;
/// Largest datagram sent: the IPv6 minimum MTU less its headers.
pub const MAX_DATAGRAM: usize = 1232;
/// Block bytes per chunk.
pub const CHUNK_BYTES: usize = 1024;
/// Chunks named in one `GetChunks`, and in flight when a download starts.
pub const WINDOW: usize = 32;
/// Most chunks a download keeps in flight, asked in several `GetChunks`:
/// the window doubles each time a whole one arrives without a retry, and
/// halves when chunks go missing, so a fast path is filled and a lossy one
/// is not flooded.
pub const MAX_IN_FLIGHT: usize = 512;
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

/// Largest manifest: about a million parts, 17 billion positions.
pub const MAX_MANIFEST: usize = 32 << 20;
/// Largest part: every position of an output part unspent and a commit,
/// which also bounds a name part of [`NAME_PART_RECORDS`] records.
pub const MAX_PART: usize = 8 + (1 << crate::chain::SNAPSHOT_PART_LOG) * (PART_ENTRY + COMMIT_ENTRY);
/// An output in a part: position, commitment, memo, amount, height.
const PART_ENTRY: usize = 8 + 32 + crate::transaction::MEMO_BYTES + 8 + 4;
const COMMIT_ENTRY: usize = 8 + 32 + 4;
const _: () = assert!(MAX_PART >= 4 + NAME_PART_RECORDS * (1 + 32 + 96));

/// A manifest: the output counter after the block, the root of every
/// output part's subtree, the name root, and every name part's first key
/// and hash.
pub fn encode_manifest(m: &Manifest) -> Vec<u8> {
    let mut w = Writer::with_capacity(48 + 32 * m.roots.len() + 47 * m.names.len());
    w.u64(m.next);
    w.digest_vec(&m.roots);
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
    let roots = r.digest_vec()?;
    let name_root = r.digest()?;
    let n = r.len(15 + 32)?;
    let mut names = Vec::with_capacity(n);
    for _ in 0..n {
        let mut k = [0u8; 16];
        k[1..].copy_from_slice(r.take(15)?);
        names.push(NamePart { first: Key::from_be_bytes(k), hash: r.digest()? });
    }
    r.is_empty().then_some(Manifest { next, roots, name_root, names })
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
    Inv(Header),
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
            Message::GetPeers { token } => {
                w.0.push(T_GET_PEERS);
                w.u64(*token);
            }
            Message::Peers(addrs) => {
                w.0.push(T_PEERS);
                w.0.push(addrs.len().min(MAX_PEERS_MESSAGE) as u8);
                for a in addrs.iter().take(MAX_PEERS_MESSAGE) {
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
            Message::Inv(h) => {
                w.0.push(T_INV);
                w.0.extend_from_slice(&h.to_bytes());
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
                w.0.push(indexes.len().min(WINDOW) as u8);
                for i in indexes.iter().take(WINDOW) {
                    w.0.extend_from_slice(&i.to_le_bytes());
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
            T_INV => Message::Inv(Header::from_bytes(r.take(HEADER_SIZE)?)?),
            T_TX_INV => Message::TxInv(r.digest()?),
            T_GET_CHUNKS => {
                let token = r.u64()?;
                let kind = Kind::get(&mut r)?;
                let id = r.digest()?;
                let n = count(&mut r, WINDOW)?;
                let indexes = (0..n)
                    .map(|_| Some(u16::from_le_bytes(r.take(2)?.try_into().unwrap())))
                    .collect::<Option<Vec<_>>>()?;
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

/// `GetChunks` messages asking for `indexes`, [`WINDOW`] at a time.
pub fn chunk_requests(kind: Kind, id: Digest, indexes: &[u16]) -> impl Iterator<Item = Message> + '_ {
    indexes.chunks(WINDOW).map(move |c| Message::GetChunks { kind, id, indexes: c.to_vec(), token: 0 })
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
/// requested again.
pub const RETRY: Duration = Duration::from_millis(400);
/// The longest a retry waits, however slow the path.
pub const MAX_RETRY: Duration = Duration::from_secs(4);
/// Retries without progress before a download is abandoned.
pub const MAX_RETRIES: u32 = 8;
/// A block download averaging under this many bytes a second after
/// [`SLOW_GRACE`] is abandoned for another peer.
pub const MIN_RATE: usize = 8 << 10;
pub const SLOW_GRACE: Duration = Duration::from_secs(15);

/// A block being fetched chunk by chunk from one peer, with a sliding
/// window of requested chunks: [`Download::request`] asks for up to
/// [`WINDOW`] chunks not yet in flight, and the node refills when half the
/// window has arrived or when nothing has arrived for [`RETRY`].
#[derive(Debug)]
pub struct Download {
    pub kind: Kind,
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
    pub started: Instant,
    /// Chunks kept in flight, from [`WINDOW`] to [`MAX_IN_FLIGHT`].
    window: usize,
    /// Chunks arrived since the window last grew.
    delivered: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChunkError {
    /// Chunk from a different block or peer.
    Unexpected,
    /// Length or index out of bounds, or inconsistent with earlier chunks.
    Malformed,
}

impl Download {
    pub fn new(kind: Kind, id: Digest, from: SocketAddr, max_len: usize, now: Instant) -> Download {
        Download {
            kind,
            id,
            from,
            max_len,
            len: None,
            chunks: Vec::new(),
            in_flight: Vec::new(),
            last_progress: now,
            last_request: now,
            retries: 0,
            started: now,
            window: WINDOW,
            delivered: 0,
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
    /// part of the window. They become in flight. Send them with
    /// [`chunk_requests`].
    pub fn request(&mut self, now: Instant) -> Vec<u16> {
        let room = self.window.saturating_sub(self.in_flight.len());
        let fresh: Vec<u16> = self
            .missing(self.window + self.in_flight.len())
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

    /// Forgets what is in flight, so the next request repeats it: chunks
    /// went missing, so the window halves.
    pub fn reset_window(&mut self) {
        self.in_flight.clear();
        self.window = (self.window / 2).max(WINDOW);
        self.delivered = 0;
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Whether enough of the window has arrived to ask for more: half.
    pub fn wants_refill(&self) -> bool {
        self.in_flight.len() <= self.window / 2
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
            self.delivered += 1;
            if self.delivered >= self.window && self.window < MAX_IN_FLIGHT {
                self.window = (self.window * 2).min(MAX_IN_FLIGHT);
                self.delivered = 0;
            }
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
/// A peer silent for this long is dropped (unless it is a seed).
pub const PEER_TIMEOUT: Duration = Duration::from_secs(180);
/// How long a peer a block download failed from, or that did not back its
/// claimed work with headers, is passed over.
pub const FETCH_BACKOFF: Duration = Duration::from_secs(600);
/// How long a peer asked for headers may take to send one we lack.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
/// Peers kept in the table.
pub const MAX_PEERS: usize = 64;
/// Most peer entries one public host may hold, over all its ports.
pub const MAX_PER_HOST: usize = 2;
/// Most peer entries one network group may hold (a /16 for IPv4, a /32
/// for IPv6): an attacker with addresses in one network cannot fill the
/// table and surround the node.
pub const MAX_PER_GROUP: usize = 8;

/// The network group of an address, for [`MAX_PER_GROUP`].
fn group(ip: std::net::IpAddr) -> u32 {
    match ip {
        std::net::IpAddr::V4(v4) => u32::from(v4) >> 16,
        std::net::IpAddr::V6(v6) => (u128::from(v6) >> 96) as u32 | 1 << 31,
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
    /// Smoothed round trip, from our pings to its pongs.
    pub rtt: Option<Duration>,
    /// When a well-formed message last arrived; `None` until the first.
    pub last_seen: Option<Instant>,
    pub last_ping: Option<Instant>,
    /// Nonce of the ping awaiting its pong.
    pub pending: Option<u64>,
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
    /// Whether the socket is IPv6: addresses of the other family cannot
    /// be reached from it and are not taken. `None` takes both.
    v6: Option<bool>,
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

    /// Takes only addresses of the socket's family from now on.
    pub fn set_family(&mut self, v6: bool) {
        self.v6 = Some(v6);
        self.map.retain(|a, _| a.is_ipv6() == v6);
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
        if self.v6.is_some_and(|v6| addr.is_ipv6() != v6) {
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
            && (self.map.values().filter(|p| p.addr.ip() == addr.ip()).count() >= MAX_PER_HOST
                || self.map.values().filter(|p| !p.seed && group(p.addr.ip()) == group(addr.ip())).count()
                    >= MAX_PER_GROUP)
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
                last_seen: None,
                last_ping: None,
                pending: None,
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
        if let Some(sample) = p.last_ping.map(|t| t.elapsed()) {
            p.rtt = Some(p.rtt.map_or(sample, |r| (r * 7 + sample) / 8));
        }
        true
    }

    /// How long to wait for a chunk from `addr` before asking again: twice
    /// its round trip, at least [`RETRY`] and at most [`MAX_RETRY`].
    pub fn retry(&self, addr: &SocketAddr) -> Duration {
        self.map.get(addr).and_then(|p| p.rtt).map_or(RETRY, |r| (2 * r).clamp(RETRY, MAX_RETRY))
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
            if p.last_ping.is_none_or(|t| now.duration_since(t) >= PING_INTERVAL) {
                if !p.handshaken && !p.seed {
                    if self.budget == 0 {
                        continue;
                    }
                    self.budget -= 1;
                }
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
        self.banned.retain(|_, t| now.duration_since(*t) < BAN_TIME);
        let banned = &mut self.banned;
        self.map.retain(|_, p| {
            if p.seed {
                return true;
            }
            if p.strikes >= MAX_STRIKES && p.last_strike.is_some_and(|t| now.duration_since(t) < STRIKE_DECAY) {
                banned.insert(ban_key(&p.addr), now);
                return false;
            }
            match (p.last_seen, p.last_ping) {
                (Some(seen), _) => now.duration_since(seen) < PEER_TIMEOUT,
                (None, Some(pinged)) => now.duration_since(pinged) < PEER_TIMEOUT,
                (None, None) => true,
            }
        });
        // A banned host's other entries go with it.
        let banned = &self.banned;
        self.map.retain(|_, p| p.seed || !banned.contains_key(&ban_key(&p.addr)));
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
        }
    }

    #[test]
    fn the_window_grows_while_whole_and_halves_on_loss() {
        let t = Instant::now();
        let len = (CHUNK_BYTES * 4000) as u32;
        let mut d = Download::new(Kind::Part(0), digest(1), "10.0.0.1:1".parse().unwrap(), len as usize, t);
        let chunk = vec![0u8; CHUNK_BYTES];
        let mut next = 0u16;
        let mut deliver = |d: &mut Download, n: usize| {
            for _ in 0..n {
                d.insert(len, next, chunk.clone(), t).unwrap();
                next += 1;
            }
        };
        assert_eq!(d.request(t).len(), WINDOW);
        deliver(&mut d, WINDOW);
        // A whole window arrived: the next asks for twice as many, in
        // messages of at most WINDOW indexes.
        let asked = d.request(t);
        assert_eq!(asked.len(), 2 * WINDOW);
        assert_eq!(chunk_requests(Kind::Part(0), digest(1), &asked).count(), 2);
        deliver(&mut d, 2 * WINDOW);
        assert_eq!(d.request(t).len(), 4 * WINDOW);
        deliver(&mut d, 4 * WINDOW);
        for _ in 0..4 {
            d.request(t);
            let n = d.in_flight();
            deliver(&mut d, n);
        }
        assert_eq!(d.request(t).len(), MAX_IN_FLIGHT);
        // Chunks went missing: half the window, and so on down to WINDOW.
        d.reset_window();
        assert_eq!(d.request(t).len(), MAX_IN_FLIGHT / 2);
        for _ in 0..8 {
            d.reset_window();
        }
        assert_eq!(d.request(t).len(), WINDOW);
    }

    #[test]
    fn one_host_gets_few_entries_and_a_ban_covers_its_ports() {
        let mut peers = Peers::new();
        let host = |port: u16| -> SocketAddr { format!("10.0.0.9:{port}").parse().unwrap() };
        assert!(peers.add(host(1), false));
        assert!(peers.add(host(2), false));
        assert!(!peers.add(host(3), false));
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
    fn messages_roundtrip_within_the_datagram_limit() {
        let v4: SocketAddr = "10.1.2.3:7417".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:7417".parse().unwrap();
        let msgs = vec![
            Message::Ping(status()),
            Message::Pong(status()),
            Message::GetPeers { token: 7 },
            Message::Peers(vec![v4, v6]),
            Message::Peers(vec![v6; MAX_PEERS_MESSAGE]),
            Message::GetHeaders { locator: (0..MAX_LOCATOR as u32).map(digest).collect(), token: u64::MAX },
            Message::GetHeadersFrom { height: 123_456, token: 1 },
            Message::Headers((0..HEADERS_PER_MESSAGE as u32).map(header).collect()),
            Message::Inv(header(5)),
            Message::TxInv(digest(6)),
            Message::GetChunks { kind: Kind::Tx, id: digest(9), indexes: (0..WINDOW as u16).collect(), token: 3 },
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
        ];
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
        let mut d = Download::new(Kind::Block, id, from, 1 << 20, now);
        assert_eq!(d.missing(4), vec![0, 1, 2, 3]);
        let chunk = |i: u16| match chunk_of(Kind::Block, &id, &bytes, i) {
            Some(Message::Chunk { len, index, data, .. }) => (len, index, data),
            _ => panic!(),
        };
        assert!(chunk_of(Kind::Block, &id, &bytes, 3).is_none());
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
        let mut small = Download::new(Kind::Block, id, from, 100, now);
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
