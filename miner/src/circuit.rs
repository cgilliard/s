//! Circuits of onion mode (`docs/ONION.md`): cells, and the layers of
//! encryption a circuit puts on them, one per hop. Pure; the node moves
//! the cells over channels ([`crate::channel`]).
//!
//! # Cells
//!
//! A cell is [`CELL_BYTES`] long, one channel body: a circuit number (the
//! channel's), a command and a payload. `Create` and `Created` carry a hop
//! handshake ([`crate::channel::Opening::circuit`]) in pieces, `Relay`
//! carries a layered message, `Destroy` ends a circuit.
//!
//! # Layers
//!
//! Every hop shares two keys with the client, one per direction, and
//! counts the relay cells it passes each way. A layer is ChaCha20 under
//! the hop's key with the count as nonce (from block 1); a cell for hop
//! `t` carries, before its layers, a Poly1305 tag of its body under the
//! one-time key of block 0, as ChaCha20-Poly1305 does. The client puts on
//! the layers of hops `t` down to the first; each hop takes its own off
//! and checks the tag: the hop it is for finds it right (a wrong one
//! matches by chance once in 2^128), any other passes the cell on. Back
//! toward the client a hop tags and layers what it originates, every hop
//! before it adds its layer, and the client takes them off in order until
//! a tag holds, which names the hop that sent it. The layers carry no tag
//! of their own, so a hop could flip bits for the hops after it; the tag
//! at the end catches that, but not which hop did it.

use crate::chacha20poly1305::{self, KEY_LEN, NONCE_LEN, TAG_LEN};

/// One cell: a channel body.
pub const CELL_BYTES: usize = 1024;
/// A cell's payload after its circuit number and command.
pub const PAYLOAD: usize = CELL_BYTES - 5;
/// A relay cell's body after its tag.
pub const BODY: usize = PAYLOAD - TAG_LEN;
/// Message bytes in one relay cell, after its command, flag and length.
pub const RELAY_DATA: usize = BODY - 4;
/// Handshake bytes in one `Create` or `Created` cell.
pub const CREATE_DATA: usize = PAYLOAD - 3;
/// Largest relay message reassembled: a transaction, the largest thing a
/// circuit carries, with room to spare.
pub const MAX_MESSAGE: usize = 136 << 10;
const _: () = assert!(MAX_MESSAGE >= crate::mempool::MAX_TX_SIZE + 1024);

pub const CREATE: u8 = 1;
pub const CREATED: u8 = 2;
pub const RELAY: u8 = 3;
pub const DESTROY: u8 = 4;
/// Between rendezvous points, on circuit number 0 of their channel
/// (`node/rendezvous.rs`), in pieces as `Create` is.
pub const RENDEZVOUS: u8 = 5;

/// Relay messages: extend the circuit by a hop (the relay's id and the
/// client's hello), the hop's reply, and data for the hop or from it.
pub const EXTEND: u8 = 1;
pub const EXTENDED: u8 = 2;
pub const DATA: u8 = 3;
/// The rendezvous service's, at the last hop (`node/rendezvous.rs`).
pub const SESSION: u8 = 4;
pub const SESSION_STATE: u8 = 5;
pub const ANNOUNCE: u8 = 6;
pub const GET_ANNOUNCE: u8 = 7;
pub const SEND: u8 = 8;
pub const DELIVER: u8 = 9;
pub const NOTICE: u8 = 10;
/// A participant's finished transaction, for the last hop to pool and
/// announce as its own; answered by `Notice(txid, forwarded or rejected)`.
pub const BROADCAST: u8 = 11;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    pub circ: u32,
    pub cmd: u8,
    pub payload: Box<[u8; PAYLOAD]>,
}

impl Cell {
    pub fn new(circ: u32, cmd: u8) -> Cell {
        Cell { circ, cmd, payload: Box::new([0u8; PAYLOAD]) }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CELL_BYTES);
        out.extend_from_slice(&self.circ.to_le_bytes());
        out.push(self.cmd);
        out.extend_from_slice(&self.payload[..]);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Cell> {
        if b.len() != CELL_BYTES || !(CREATE..=RENDEZVOUS).contains(&b[4]) {
            return None;
        }
        let mut c = Cell::new(u32::from_le_bytes(b[..4].try_into().unwrap()), b[4]);
        c.payload.copy_from_slice(&b[5..]);
        Some(c)
    }
}

/// A handshake message cut into `Create` or `Created` cells: a flag for
/// more to come, a length, the bytes.
pub fn handshake_cells(circ: u32, cmd: u8, msg: &[u8]) -> Vec<Cell> {
    let n = msg.len().div_ceil(CREATE_DATA).max(1);
    msg.chunks(CREATE_DATA)
        .enumerate()
        .map(|(i, part)| {
            let mut c = Cell::new(circ, cmd);
            c.payload[0] = u8::from(i + 1 < n);
            c.payload[1..3].copy_from_slice(&(part.len() as u16).to_le_bytes());
            c.payload[3..3 + part.len()].copy_from_slice(part);
            c
        })
        .collect()
}

/// A `Create` or `Created` cell's piece: whether more follow, and the bytes.
pub fn handshake_piece(c: &Cell) -> Option<(bool, &[u8])> {
    let n = u16::from_le_bytes(c.payload[1..3].try_into().unwrap()) as usize;
    (c.payload[0] <= 1 && n <= CREATE_DATA).then(|| (c.payload[0] == 1, &c.payload[3..3 + n]))
}

/// A relay message cut into cell bodies: command, a flag for more to
/// come, a length, the bytes, zeros.
pub fn relay_bodies(cmd: u8, msg: &[u8]) -> Vec<[u8; BODY]> {
    let n = msg.len().div_ceil(RELAY_DATA).max(1);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let part = &msg[(i * RELAY_DATA).min(msg.len())..((i + 1) * RELAY_DATA).min(msg.len())];
        let mut b = [0u8; BODY];
        b[0] = cmd;
        b[1] = u8::from(i + 1 < n);
        b[2..4].copy_from_slice(&(part.len() as u16).to_le_bytes());
        b[4..4 + part.len()].copy_from_slice(part);
        out.push(b);
    }
    out
}

/// A relay body's command, whether more follow, and its bytes.
pub fn relay_piece(b: &[u8]) -> Option<(u8, bool, &[u8])> {
    let n = u16::from_le_bytes(b[2..4].try_into().unwrap()) as usize;
    (b[1] <= 1 && n <= RELAY_DATA).then(|| (b[0], b[1] == 1, &b[4..4 + n]))
}

/// A relay message that does not come together: a piece of another
/// command midway, or too much.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

/// Pieces of one relay message coming together.
#[derive(Debug, Default)]
pub struct Reassembly {
    cmd: Option<u8>,
    buf: Vec<u8>,
}

impl Reassembly {
    /// Adds a piece: the message once its last piece is in; an error for
    /// a piece of another command midway, or too much.
    pub fn add(&mut self, cmd: u8, more: bool, data: &[u8]) -> Result<Option<(u8, Vec<u8>)>, Malformed> {
        if self.cmd.is_some_and(|c| c != cmd) || self.buf.len() + data.len() > MAX_MESSAGE {
            *self = Reassembly::default();
            return Err(Malformed);
        }
        self.cmd = Some(cmd);
        self.buf.extend_from_slice(data);
        if more {
            return Ok(None);
        }
        let buf = std::mem::take(&mut self.buf);
        self.cmd = None;
        Ok(Some((cmd, buf)))
    }
}

/// One direction of one hop: its key and the relay cells counted so far.
#[derive(Clone)]
pub struct Layer {
    key: [u8; KEY_LEN],
    count: u64,
}

impl Layer {
    pub fn new(key: [u8; KEY_LEN]) -> Layer {
        Layer { key, count: 0 }
    }

    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n[4..].copy_from_slice(&self.count.to_le_bytes());
        n
    }

    fn xor(&self, p: &mut [u8; PAYLOAD]) {
        chacha20poly1305::xor_stream(&self.key, 1, &self.nonce(), &mut p[..]);
    }

    fn tag(&self, body: &[u8]) -> [u8; TAG_LEN] {
        let block = chacha20poly1305::block(&self.key, 0, &self.nonce());
        chacha20poly1305::poly1305(block[..32].try_into().unwrap(), body)
    }

    /// Puts on what this hop originates: the tag, then the layer.
    pub fn originate(&mut self, body: &[u8; BODY]) -> Box<[u8; PAYLOAD]> {
        let mut p = Box::new([0u8; PAYLOAD]);
        p[..TAG_LEN].copy_from_slice(&self.tag(body));
        p[TAG_LEN..].copy_from_slice(body);
        self.xor(&mut p);
        self.count += 1;
        p
    }

    /// Takes this layer off, or puts it on (the same): passing a cell on.
    pub fn pass(&mut self, p: &mut [u8; PAYLOAD]) {
        self.xor(p);
        self.count += 1;
    }

    /// Takes this layer off and says whether the cell is for this hop.
    pub fn take(&mut self, p: &mut [u8; PAYLOAD]) -> bool {
        self.xor(p);
        let mine = self.tag(&p[TAG_LEN..]) == p[..TAG_LEN];
        self.count += 1;
        mine
    }
}

/// A hop's two layers: toward the far end, and back to the client.
#[derive(Clone)]
pub struct HopKeys {
    pub forward: Layer,
    pub backward: Layer,
}

/// The client's side: seals `body` for hop `t` under the layers of hops
/// `t` down to the first.
pub fn seal_for(hops: &mut [HopKeys], t: usize, body: &[u8; BODY]) -> Box<[u8; PAYLOAD]> {
    let mut p = hops[t].forward.originate(body);
    for h in hops[..t].iter_mut().rev() {
        h.forward.pass(&mut p);
    }
    p
}

/// The client's side: takes the layers off a cell coming back, hop by
/// hop, until one's tag holds; the hop that sent it.
pub fn open_from(hops: &mut [HopKeys], p: &mut [u8; PAYLOAD]) -> Option<usize> {
    for (j, h) in hops.iter_mut().enumerate() {
        if h.backward.take(p) {
            return Some(j);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize) -> (Vec<HopKeys>, Vec<HopKeys>) {
        let client: Vec<HopKeys> = (0..n)
            .map(|i| HopKeys { forward: Layer::new([i as u8; 32]), backward: Layer::new([100 + i as u8; 32]) })
            .collect();
        (client.clone(), client)
    }

    #[test]
    fn cells_round_trip_and_pieces_reassemble() {
        let c = handshake_cells(9, CREATE, &[7u8; 2500]);
        assert_eq!(c.len(), 3);
        let mut msg = Vec::new();
        for cell in &c {
            let bytes = cell.to_bytes();
            assert_eq!(bytes.len(), CELL_BYTES);
            let back = Cell::from_bytes(&bytes).unwrap();
            assert_eq!(&back, cell);
            let (more, part) = handshake_piece(&back).unwrap();
            msg.extend_from_slice(part);
            assert_eq!(more, !std::ptr::eq(cell, c.last().unwrap()));
        }
        assert_eq!(msg, vec![7u8; 2500]);
        assert!(Cell::from_bytes(&[0u8; CELL_BYTES]).is_none(), "no command 0");
        assert!(Cell::from_bytes(&[3u8; CELL_BYTES - 1]).is_none());
        let mut r = Reassembly::default();
        let bodies = relay_bodies(DATA, &[5u8; 2 * RELAY_DATA + 1]);
        assert_eq!(bodies.len(), 3);
        let mut done = None;
        for b in &bodies {
            let (cmd, more, data) = relay_piece(b).unwrap();
            done = r.add(cmd, more, data).unwrap();
        }
        assert_eq!(done, Some((DATA, vec![5u8; 2 * RELAY_DATA + 1])));
        assert_eq!(relay_bodies(DATA, &[]).len(), 1, "an empty message is one cell");
        // A piece of another command midway is refused.
        let (cmd, more, data) = relay_piece(&bodies[0]).unwrap();
        r.add(cmd, more, data).unwrap();
        assert!(r.add(EXTEND, false, b"x").is_err());
    }

    /// Cells to each hop of a three-hop circuit and back.
    #[test]
    fn each_hop_finds_its_cells_and_only_those() {
        let (mut client, mut relays) = keys(3);
        for round in 0..5u8 {
            for t in 0..3 {
                let body = relay_bodies(DATA, &[round, t as u8])[0];
                let mut p = seal_for(&mut client, t, &body);
                // Forward: each hop takes its layer and checks the tag.
                let mut found = None;
                for (j, hop) in relays.iter_mut().enumerate() {
                    if hop.forward.take(&mut p) {
                        found = Some(j);
                        break;
                    }
                }
                assert_eq!(found, Some(t));
                assert_eq!(relay_piece(&p[TAG_LEN..]).unwrap().2, &[round, t as u8]);
                // Back: hop t answers, the hops before add their layers.
                let answer = relay_bodies(DATA, &[round, 9, t as u8])[0];
                let mut p = relays[t].backward.originate(&answer);
                for hop in relays[..t].iter_mut().rev() {
                    hop.backward.pass(&mut p);
                }
                assert_eq!(open_from(&mut client, &mut p), Some(t));
                assert_eq!(relay_piece(&p[TAG_LEN..]).unwrap().2, &[round, 9, t as u8]);
            }
        }
        // A flipped bit anywhere is found by nobody.
        let body = relay_bodies(DATA, b"tamper")[0];
        let mut p = seal_for(&mut client, 2, &body);
        p[500] ^= 1;
        assert!(!relays[0].forward.take(&mut p));
        assert!(!relays[1].forward.take(&mut p));
        assert!(!relays[2].forward.take(&mut p));
    }
}
