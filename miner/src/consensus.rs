//! The message layer's consensus file (`docs/ONION.md`): the vote that
//! aux leaf 0 of every block casts, counted over a window of the main
//! chain, and the file the winning hash names.
//!
//! A miner that publishes a file sets leaf 0 to its SHA-256; a node that
//! follows the chain fetches every block's leaves, counts the nonzero
//! leaf-0 values over the last [`WINDOW`] main-chain blocks, and fetches
//! the file the most common one names. The chain keeps the leaves with
//! the block (`Chain::aux_leaves_of`) and the files for good
//! (`Chain::consensus_file`); this module holds the constants, the count
//! and the file's transfer id.

use crate::poseidon2::Fp;
use crate::xmss::Digest;

/// Blocks over which votes are counted.
pub const WINDOW: u32 = 144;
/// Largest file.
pub const MAX_CONSENSUS: usize = 1 << 20;
/// Most relays a file may list.
pub const MAX_RELAYS: usize = 8192;

/// A file's vote value: its SHA-256.
pub type Hash = [u8; 32];

/// The votes over a window of main-chain blocks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Votes {
    /// Each hash voted for, with its votes and the highest height that
    /// voted for it, most votes first, then most recent.
    pub counts: Vec<(Hash, u32, u32)>,
    /// Blocks of the window with a nonzero aux root whose leaves are not
    /// here yet, so whose vote is unknown: their id and height.
    pub missing: Vec<(Digest, u32)>,
    /// Blocks in the window.
    pub blocks: u32,
    /// The window's first and last heights.
    pub range: (u32, u32),
}

impl Votes {
    /// Builds the count from each block's vote, `None` for a block whose
    /// leaves are missing.
    pub fn tally(range: (u32, u32), blocks: impl Iterator<Item = (Digest, u32, Option<Hash>)>) -> Votes {
        let mut counts: Vec<(Hash, u32, u32)> = Vec::new();
        let mut missing = Vec::new();
        let mut n = 0;
        for (id, height, vote) in blocks {
            n += 1;
            match vote {
                None => missing.push((id, height)),
                Some(h) if h == [0u8; 32] => {}
                Some(h) => match counts.iter_mut().find(|c| c.0 == h) {
                    Some(c) => {
                        c.1 += 1;
                        c.2 = c.2.max(height);
                    }
                    None => counts.push((h, 1, height)),
                },
            }
        }
        counts.sort_by_key(|c| std::cmp::Reverse((c.1, c.2)));
        Votes { counts, missing, blocks: n, range }
    }

    /// The winning hash: the most voted, ties to the most recently
    /// committed. `None` when no block in the window votes.
    pub fn winner(&self) -> Option<Hash> {
        self.counts.first().map(|c| c.0)
    }

    /// The winner's votes.
    pub fn winning_votes(&self) -> u32 {
        self.counts.first().map_or(0, |c| c.1)
    }
}

/// The transfer id of the file with SHA-256 `hash`: the hash's eight
/// little-endian words, each cut to 30 bits so the id is a canonical
/// digest (every word below the field's modulus). A file is still checked
/// by its full hash once it arrives; the id only names it on the wire.
pub fn file_id(hash: &Hash) -> Digest {
    core::array::from_fn(|i| Fp::new(u32::from_le_bytes(hash[4 * i..4 * i + 4].try_into().unwrap()) & 0x3fff_ffff))
}

/// Whether `bytes` are the file `hash` names.
pub fn file_matches(hash: &Hash, bytes: &[u8]) -> bool {
    crate::bip39::sha256(bytes) == *hash
}

pub fn hex(hash: &Hash) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Fewest relays an onion-mode file may list: a participant's three
/// rendezvous points must be distinct.
pub const MIN_RELAYS: usize = 3;

/// Which mode a file puts the network in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// No relays: the seed nodes stand in for them.
    Init,
    /// The listed relays carry the traffic.
    Onion,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Mode::Init => "init",
            Mode::Onion => "onion",
        })
    }
}

/// A relay's optional flags; their meaning is an open point of the design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    Exit,
    Rendezvous,
    Guard,
}

/// A `relay` line: the relay's id, its UDP address as written
/// (`host:port`, not resolved here) and its flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relay {
    pub id: Digest,
    pub addr: String,
    pub flags: Vec<Flag>,
}

/// A parsed `consensus.txt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    pub mode: Mode,
    /// The relays, sorted by id (the order rendezvous points are chosen
    /// in); empty in init mode.
    pub relays: Vec<Relay>,
}

/// Why a file is invalid; the line number counts from 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    TooLarge(usize),
    NotText,
    /// The first directive is not `mode init` or `mode onion`.
    NoMode,
    BadMode(usize),
    /// A `relay` line without an id and an address, or with extra words
    /// that are not flags.
    BadRelay(usize),
    BadId(usize),
    BadAddress(usize),
    BadFlag(usize),
    DuplicateRelay(usize),
    TooManyRelays,
    TooFewRelays(usize),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooLarge(n) => write!(f, "{n} bytes, over the {MAX_CONSENSUS} allowed"),
            ParseError::NotText => f.write_str("not UTF-8 text"),
            ParseError::NoMode => f.write_str("the first directive must be `mode init` or `mode onion`"),
            ParseError::BadMode(l) => write!(f, "line {l}: the mode must be init or onion"),
            ParseError::BadRelay(l) => write!(f, "line {l}: a relay line is `relay ID HOST:PORT [FLAGS]`"),
            ParseError::BadId(l) => write!(f, "line {l}: the id must be a tab1… address or 64 hex digits"),
            ParseError::BadAddress(l) => write!(f, "line {l}: the address must be HOST:PORT"),
            ParseError::BadFlag(l) => write!(f, "line {l}: flags are exit, rendezvous and guard"),
            ParseError::DuplicateRelay(l) => write!(f, "line {l}: the relay is listed already"),
            ParseError::TooManyRelays => write!(f, "more than {MAX_RELAYS} relays"),
            ParseError::TooFewRelays(n) => write!(f, "onion mode lists {n} relays, fewer than the {MIN_RELAYS} needed"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parses an id: a `tab1…` address, or 64 hex digits of the digest's
/// little-endian bytes.
fn parse_id(word: &str) -> Option<Digest> {
    if let Some(id) = crate::address::decode(word) {
        return Some(id);
    }
    if word.len() != 64 || !word.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&word[2 * i..2 * i + 2], 16).unwrap()).collect();
    crate::poseidon2::digest_from_bytes(&bytes)
}

/// Whether `addr` reads as `HOST:PORT`: a host name or an IP (a v6
/// address in brackets) and a port.
fn address_ok(addr: &str) -> bool {
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    if port.parse::<u16>().is_err() {
        return false;
    }
    if host.starts_with('[') {
        host.ends_with(']') && host[1..host.len() - 1].parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        !host.is_empty()
            && host.len() <= 253
            && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    }
}

impl File {
    /// Parses and validates a `consensus.txt` (`docs/ONION.md`): UTF-8,
    /// one directive per line, `#` comments, blank lines ignored, the
    /// first directive the mode. In init mode the rest is ignored; in
    /// onion mode `relay ID HOST:PORT [FLAGS]` lines list the relays,
    /// between [`MIN_RELAYS`] and [`MAX_RELAYS`] of them, no id twice.
    /// Unknown directives are ignored.
    pub fn parse(bytes: &[u8]) -> Result<File, ParseError> {
        if bytes.len() > MAX_CONSENSUS {
            return Err(ParseError::TooLarge(bytes.len()));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| ParseError::NotText)?;
        let mut mode = None;
        let mut relays: Vec<Relay> = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = i + 1;
            let content = raw.split('#').next().unwrap_or("").trim();
            if content.is_empty() {
                continue;
            }
            let mut words = content.split_whitespace();
            let directive = words.next().unwrap();
            let Some(mode) = mode else {
                if directive != "mode" {
                    return Err(ParseError::NoMode);
                }
                mode = Some(match (words.next(), words.next()) {
                    (Some("init"), None) => Mode::Init,
                    (Some("onion"), None) => Mode::Onion,
                    _ => return Err(ParseError::BadMode(line)),
                });
                continue;
            };
            if mode == Mode::Init || directive != "relay" {
                continue;
            }
            let (Some(id), Some(addr)) = (words.next(), words.next()) else {
                return Err(ParseError::BadRelay(line));
            };
            let id = parse_id(id).ok_or(ParseError::BadId(line))?;
            if !address_ok(addr) {
                return Err(ParseError::BadAddress(line));
            }
            let mut flags = Vec::new();
            for w in words {
                let flag = match w {
                    "exit" => Flag::Exit,
                    "rendezvous" => Flag::Rendezvous,
                    "guard" => Flag::Guard,
                    _ => return Err(ParseError::BadFlag(line)),
                };
                if !flags.contains(&flag) {
                    flags.push(flag);
                }
            }
            if relays.iter().any(|r| r.id == id) {
                return Err(ParseError::DuplicateRelay(line));
            }
            if relays.len() >= MAX_RELAYS {
                return Err(ParseError::TooManyRelays);
            }
            relays.push(Relay { id, addr: addr.to_string(), flags });
        }
        let mode = mode.ok_or(ParseError::NoMode)?;
        if mode == Mode::Onion && relays.len() < MIN_RELAYS {
            return Err(ParseError::TooFewRelays(relays.len()));
        }
        relays.sort_by_key(|r| crate::poseidon2::digest_to_bytes(&r.id));
        Ok(File { mode, relays })
    }
}

/// The file in force: the window's winner, if its file is held and parses,
/// else init mode with the reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Current {
    pub mode: Mode,
    /// The winning hash, if any block of the window voted.
    pub winner: Option<Hash>,
    /// The winner's file, when it is held and valid.
    pub file: Option<File>,
    /// Why the winner's file is not in force: not fetched yet, or invalid.
    pub problem: Option<String>,
}

impl Current {
    /// Decides from the votes and the winner's bytes, if held.
    pub fn decide(votes: &Votes, bytes: Option<&[u8]>) -> Current {
        let Some(winner) = votes.winner() else {
            return Current { mode: Mode::Init, winner: None, file: None, problem: None };
        };
        match bytes.map(File::parse) {
            None => Current { mode: Mode::Init, winner: Some(winner), file: None, problem: Some("not fetched yet".into()) },
            Some(Err(e)) => Current { mode: Mode::Init, winner: Some(winner), file: None, problem: Some(format!("invalid: {e}")) },
            Some(Ok(file)) => Current { mode: file.mode, winner: Some(winner), file: Some(file), problem: None },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::digest_to_bytes;

    fn id(i: u32) -> Digest {
        core::array::from_fn(|k| Fp::new(i * 8 + k as u32))
    }

    #[test]
    fn votes_count_and_break_ties_by_recency() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let blocks = vec![
            (id(1), 10, Some(a)),
            (id(2), 11, Some(b)),
            (id(3), 12, Some([0u8; 32])),
            (id(4), 13, None),
            (id(5), 14, Some(b)),
            (id(6), 15, Some(a)),
        ];
        let v = Votes::tally((10, 15), blocks.into_iter());
        assert_eq!(v.blocks, 6);
        assert_eq!(v.missing, vec![(id(4), 13)]);
        // Two each; a was committed most recently.
        assert_eq!(v.counts, vec![(a, 2, 15), (b, 2, 14)]);
        assert_eq!(v.winner(), Some(a));
        assert_eq!(v.winning_votes(), 2);
        let v = Votes::tally((1, 2), vec![(id(1), 1, Some([0u8; 32])), (id(2), 2, None)].into_iter());
        assert_eq!(v.winner(), None);
        assert_eq!(Votes::default().winner(), None);
    }

    #[test]
    fn files_parse_and_invalid_ones_are_refused() {
        let ids: Vec<Digest> = (1..=4).map(id).collect();
        let addr = |i: usize| crate::address::encode(&ids[i]);
        let hex = |i: usize| crate::consensus::hex(&digest_to_bytes(&ids[i]));
        assert_eq!(File::parse(b"mode init\n"), Ok(File { mode: Mode::Init, relays: vec![] }));
        // Comments, blank lines, and in init mode anything else, are ignored.
        let init = "# a comment\n\n  mode init  # trailing\nrelay garbage\nfuture directive\n";
        assert_eq!(File::parse(init.as_bytes()).unwrap().mode, Mode::Init);
        let onion = format!(
            "mode onion\nrelay {} relay3.example.org:3737 exit guard\nrelay {} 10.0.0.2:3737\n\
             relay {} [2001:db8::1]:3737 rendezvous rendezvous\nfuture directive\n",
            addr(2),
            hex(0),
            addr(1)
        );
        let f = File::parse(onion.as_bytes()).unwrap();
        assert_eq!(f.mode, Mode::Onion);
        assert_eq!(f.relays.len(), 3);
        // Sorted by id, whatever the order written and the id's form.
        assert_eq!(f.relays.iter().map(|r| r.id).collect::<Vec<_>>(), ids[..3].to_vec());
        assert_eq!(f.relays[2].addr, "relay3.example.org:3737");
        assert_eq!(f.relays[2].flags, vec![Flag::Exit, Flag::Guard]);
        assert_eq!(f.relays[0].flags, vec![]);
        assert_eq!(f.relays[1].flags, vec![Flag::Rendezvous]);
        let bad = [
            ("", ParseError::NoMode),
            ("# only a comment\n", ParseError::NoMode),
            ("relay x y\nmode init\n", ParseError::NoMode),
            ("mode tor\n", ParseError::BadMode(1)),
            ("mode init now\n", ParseError::BadMode(1)),
            ("mode onion\n", ParseError::TooFewRelays(0)),
            ("mode onion\nrelay\n", ParseError::BadRelay(2)),
            ("mode onion\nrelay tab1qqqq 1.2.3.4:1\n", ParseError::BadId(2)),
            ("mode onion\nrelay 00 1.2.3.4:1\n", ParseError::BadId(2)),
        ];
        for (text, err) in bad {
            assert_eq!(File::parse(text.as_bytes()), Err(err), "{text:?}");
        }
        let with = |line: &str| format!("mode onion\nrelay {} a:1\nrelay {} b:2\n{line}\n", addr(0), addr(1));
        assert_eq!(File::parse(with(&format!("relay {} c", addr(2))).as_bytes()), Err(ParseError::BadAddress(4)));
        assert_eq!(File::parse(with(&format!("relay {} :3737", addr(2))).as_bytes()), Err(ParseError::BadAddress(4)));
        assert_eq!(File::parse(with(&format!("relay {} c:99999", addr(2))).as_bytes()), Err(ParseError::BadAddress(4)));
        assert_eq!(File::parse(with(&format!("relay {} [::1:3737", addr(2))).as_bytes()), Err(ParseError::BadAddress(4)));
        assert_eq!(File::parse(with(&format!("relay {} c:1 fast", addr(2))).as_bytes()), Err(ParseError::BadFlag(4)));
        assert_eq!(File::parse(with(&format!("relay {} c:1", addr(1))).as_bytes()), Err(ParseError::DuplicateRelay(4)));
        assert_eq!(File::parse(&[0xffu8, 0xfe]), Err(ParseError::NotText));
        assert!(matches!(File::parse(&vec![b' '; MAX_CONSENSUS + 1]), Err(ParseError::TooLarge(_))));
        assert_eq!(ParseError::TooFewRelays(2).to_string(), "onion mode lists 2 relays, fewer than the 3 needed");
        // The decision: no votes, a winner not fetched, invalid, valid.
        let votes = Votes::tally((1, 2), vec![(id(1), 1, Some([1u8; 32]))].into_iter());
        assert_eq!(Current::decide(&Votes::default(), None).mode, Mode::Init);
        let c = Current::decide(&votes, None);
        assert_eq!((c.mode, c.winner, c.problem.as_deref()), (Mode::Init, Some([1u8; 32]), Some("not fetched yet")));
        let c = Current::decide(&votes, Some(b"mode tor\n"));
        assert_eq!(c.mode, Mode::Init);
        assert!(c.problem.unwrap().starts_with("invalid: line 1"));
        let c = Current::decide(&votes, Some(onion.as_bytes()));
        assert_eq!(c.mode, Mode::Onion);
        assert_eq!(c.file.unwrap().relays.len(), 3);
        assert_eq!(c.problem, None);
    }

    #[test]
    fn file_ids_are_canonical_digests() {
        let hash = crate::bip39::sha256(b"mode init\n");
        let id = file_id(&hash);
        assert_eq!(crate::poseidon2::digest_from_bytes(&digest_to_bytes(&id)), Some(id));
        assert_ne!(file_id(&[0xffu8; 32]), file_id(&[0u8; 32]));
        assert!(crate::poseidon2::digest_from_bytes(&digest_to_bytes(&file_id(&[0xffu8; 32]))).is_some());
        assert!(file_matches(&hash, b"mode init\n"));
        assert!(!file_matches(&hash, b"mode init"));
        assert_eq!(hex(&[0xabu8; 32]).len(), 64);
    }
}
