//! The message layer's consensus file (`docs/ONION.md`): the vote that
//! aux leaf 0 of every block casts, counted over a window of the main
//! chain, and the file the winning hash names.
//!
//! A miner that publishes a file sets leaf 0 to its SHA-256; a node that
//! follows the chain fetches every block's leaves, counts the nonzero
//! leaf-0 values over the last [`WINDOW`] main-chain blocks, and fetches
//! the files they name, most voted first. The most voted file that is
//! held and valid is in force, whatever its mode, so a file saying
//! `mode init` is a vote for init mode; votes for a file that cannot be
//! fetched or does not parse count for nothing, and with no vote that
//! counts the network is in init mode. The chain keeps the leaves with
//! the block (`Chain::aux_leaves_of`) and the files for good
//! (`Chain::consensus_file`); this module holds the constants, the count
//! and the file's transfer id.

use crate::poseidon2::Fp;
use crate::xmss::Digest;

/// Blocks over which votes are counted.
pub const WINDOW: u32 = 144;
/// The file in force changes only at heights that are multiples of this,
/// decided from the window ending there.
pub const EPOCH: u32 = WINDOW;
/// Blocks from a boundary `B` over which a change is made: both files
/// stand from `B` to `B + GRACE - 2`, the old one goes at `B + GRACE - 1`.
pub const GRACE: u32 = 6;
/// From `B + SWITCH` senders prefer the new file.
pub const SWITCH: u32 = 2;

/// The last boundary at or below `height`.
pub fn boundary(height: u32) -> u32 {
    height / EPOCH * EPOCH
}
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

    /// Votes cast, for any file.
    pub fn cast(&self) -> u32 {
        self.counts.iter().map(|c| c.1).sum()
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

/// A `relay` line: the relay's id (the hash of its Dilithium key) and its
/// UDP address as written (`host:port`, not resolved here). Every relay
/// may serve any role: a hop, or a rendezvous point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relay {
    pub id: Digest,
    pub addr: String,
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
    /// A `relay` line that is not an id and an address.
    BadRelay(usize),
    BadId(usize),
    BadAddress(usize),
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
            ParseError::BadRelay(l) => write!(f, "line {l}: a relay line is `relay ID HOST:PORT`"),
            ParseError::BadId(l) => write!(f, "line {l}: the id must be a tab1… address or 64 hex digits"),
            ParseError::BadAddress(l) => write!(f, "line {l}: the address must be HOST:PORT"),
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

/// Whether `addr` reads as `HOST:PORT`: a host name or an IPv4 address,
/// and a port. IPv6 is not spoken (`docs/HARDENING.md`), so a bracketed
/// address is refused.
fn address_ok(addr: &str) -> bool {
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    if port.parse::<u16>().is_err() {
        return false;
    }
    !host.is_empty() && host.len() <= 253 && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

impl File {
    /// Parses and validates a `consensus.txt` (`docs/ONION.md`): UTF-8,
    /// one directive per line, `#` comments, blank lines ignored, the
    /// first directive the mode. In init mode the rest is ignored; in
    /// onion mode `relay ID HOST:PORT` lines list the relays,
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
            let (Some(id), Some(addr), None) = (words.next(), words.next(), words.next()) else {
                return Err(ParseError::BadRelay(line));
            };
            let id = parse_id(id).ok_or(ParseError::BadId(line))?;
            if !address_ok(addr) {
                return Err(ParseError::BadAddress(line));
            }
            if relays.iter().any(|r| r.id == id) {
                return Err(ParseError::DuplicateRelay(line));
            }
            if relays.len() >= MAX_RELAYS {
                return Err(ParseError::TooManyRelays);
            }
            relays.push(Relay { id, addr: addr.to_string() });
        }
        let mode = mode.ok_or(ParseError::NoMode)?;
        if mode == Mode::Onion && relays.len() < MIN_RELAYS {
            return Err(ParseError::TooFewRelays(relays.len()));
        }
        relays.sort_by_key(|r| crate::poseidon2::digest_to_bytes(&r.id));
        Ok(File { mode, relays })
    }
}

/// Why a voted-for file does not count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Skip {
    /// Not fetched (yet).
    NotHeld,
    Invalid(ParseError),
}

impl std::fmt::Display for Skip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Skip::NotHeld => f.write_str("not fetched"),
            Skip::Invalid(e) => write!(f, "invalid: {e}"),
        }
    }
}

/// The file in force: the most voted of the window's files that is held
/// and valid, ties to the most recently committed; init mode when there
/// is none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Current {
    pub mode: Mode,
    /// The file in force, its hash and its votes.
    pub winner: Option<(Hash, u32)>,
    pub file: Option<File>,
    /// The files voted for more than the winner (every one, without a
    /// winner) that do not count, most voted first, and why: a node
    /// fetches those not held, since one may yet win.
    pub skipped: Vec<(Hash, u32, Skip)>,
}

impl Current {
    /// Decides from the votes, given the bytes of each file held.
    pub fn decide(votes: &Votes, mut held: impl FnMut(&Hash) -> Option<Vec<u8>>) -> Current {
        let mut skipped = Vec::new();
        for &(hash, n, _) in &votes.counts {
            match held(&hash).map(|b| File::parse(&b)) {
                None => skipped.push((hash, n, Skip::NotHeld)),
                Some(Err(e)) => skipped.push((hash, n, Skip::Invalid(e))),
                Some(Ok(file)) => return Current { mode: file.mode, winner: Some((hash, n)), file: Some(file), skipped },
            }
        }
        Current { mode: Mode::Init, winner: None, file: None, skipped }
    }

    /// The files to fetch: voted for more than the winner, not held.
    pub fn unfetched(&self) -> impl Iterator<Item = &Hash> {
        self.skipped.iter().filter(|s| s.2 == Skip::NotHeld).map(|s| &s.0)
    }
}

/// The files in force at a height: the one decided at the last boundary
/// and, while the switch from the one before lasts, that one too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Epoch {
    /// The main chain's tip.
    pub height: u32,
    /// The last boundary at or below it.
    pub boundary: u32,
    /// The votes of the window ending at the boundary.
    pub votes: Votes,
    /// What they decided.
    pub current: Current,
    /// The file decided at the boundary before, while the switch lasts and
    /// only if it differs.
    pub previous: Option<Current>,
    /// Whether senders try `current` first: from `boundary + SWITCH`.
    pub prefer_current: bool,
}

impl Epoch {
    /// From the decisions at the last boundary and the one before.
    pub fn new(height: u32, votes: Votes, current: Current, before: Option<Current>) -> Epoch {
        let boundary = boundary(height);
        let into = height - boundary;
        let same = |a: &Current, b: &Current| a.mode == b.mode && a.winner.map(|w| w.0) == b.winner.map(|w| w.0);
        let previous = before.filter(|b| into + 1 < GRACE && !same(b, &current));
        let prefer_current = previous.is_none() || into >= SWITCH;
        Epoch { height, boundary, votes, current, previous, prefer_current }
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
        assert_eq!(v.cast(), 4);
        let v = Votes::tally((1, 2), vec![(id(1), 1, Some([0u8; 32])), (id(2), 2, None)].into_iter());
        assert!(v.counts.is_empty());
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
            "mode onion\nrelay {} relay3.example.org:3737\nrelay {} 10.0.0.2:3737\n\
             relay {} 10.0.0.3:3737\nfuture directive\n",
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
        assert_eq!(File::parse(with(&format!("relay {} [::1]:3737", addr(2))).as_bytes()), Err(ParseError::BadAddress(4)));
        // No flags: any relay serves any role.
        assert_eq!(File::parse(with(&format!("relay {} c:1 exit", addr(2))).as_bytes()), Err(ParseError::BadRelay(4)));
        assert_eq!(File::parse(with(&format!("relay {} c:1", addr(1))).as_bytes()), Err(ParseError::DuplicateRelay(4)));
        assert_eq!(File::parse(&[0xffu8, 0xfe]), Err(ParseError::NotText));
        assert!(matches!(File::parse(&vec![b' '; MAX_CONSENSUS + 1]), Err(ParseError::TooLarge(_))));
        assert_eq!(ParseError::TooFewRelays(2).to_string(), "onion mode lists 2 relays, fewer than the 3 needed");
        // The decision: the most voted file held and valid, whatever its
        // mode; files not held or invalid count for nothing.
        let (x, y, z) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let votes = Votes::tally(
            (1, 6),
            vec![
                (id(1), 1, Some(x)),
                (id(2), 2, Some(x)),
                (id(3), 3, Some(x)),
                (id(4), 4, Some(y)),
                (id(5), 5, Some(y)),
                (id(6), 6, Some(z)),
            ]
            .into_iter(),
        );
        fn files<'a>(
            x: Option<&'a [u8]>,
            y: Option<&'a [u8]>,
            z: Option<&'a [u8]>,
        ) -> impl FnMut(&Hash) -> Option<Vec<u8>> + 'a {
            move |h: &Hash| [x, y, z][h[0] as usize - 1].map(|b| b.to_vec())
        }
        assert_eq!(Current::decide(&Votes::default(), |_| None), Current {
            mode: Mode::Init,
            winner: None,
            file: None,
            skipped: vec![]
        });
        // Nothing held: init, and every file is to be fetched.
        let c = Current::decide(&votes, files(None, None, None));
        assert_eq!((c.mode, c.winner), (Mode::Init, None));
        assert_eq!(c.unfetched().collect::<Vec<_>>(), vec![&x, &y, &z]);
        // The leader is not held: the next, valid, is in force meanwhile,
        // and the leader is still wanted.
        let c = Current::decide(&votes, files(None, Some(onion.as_bytes()), None));
        assert_eq!((c.mode, c.winner), (Mode::Onion, Some((y, 2))));
        assert_eq!(c.file.as_ref().unwrap().relays.len(), 3);
        assert_eq!(c.unfetched().collect::<Vec<_>>(), vec![&x]);
        // The leader is invalid: it counts for nothing.
        let c = Current::decide(&votes, files(Some(b"mode tor\n"), Some(onion.as_bytes()), None));
        assert_eq!(c.winner, Some((y, 2)));
        assert!(matches!(c.skipped[..], [(h, 3, Skip::Invalid(ParseError::BadMode(1)))] if h == x));
        assert_eq!(c.unfetched().count(), 0);
        // An explicit vote for init wins like any other.
        let c = Current::decide(&votes, files(Some(b"mode init\n"), Some(onion.as_bytes()), None));
        assert_eq!((c.mode, c.winner), (Mode::Init, Some((x, 3))));
        // Only invalid files: init, with nothing in force.
        let c = Current::decide(&votes, files(Some(b"x"), Some(b"y"), Some(b"z")));
        assert_eq!((c.mode, c.winner, c.skipped.len()), (Mode::Init, None, 3));
        assert_eq!(c.skipped[2].2.to_string(), "invalid: the first directive must be `mode init` or `mode onion`");
    }

    /// The switch at a boundary: both files from `B` to `B + 4`, the new
    /// one preferred from `B + 2`, the old one gone at `B + 5`; no switch
    /// when the file is the same, and none between boundaries.
    #[test]
    fn files_change_only_at_boundaries_with_a_grace_period() {
        let init = Current { mode: Mode::Init, winner: None, file: None, skipped: vec![] };
        let onion = Current { mode: Mode::Onion, winner: Some(([1u8; 32], 1)), file: None, skipped: vec![] };
        assert_eq!(boundary(143), 0);
        assert_eq!(boundary(144), 144);
        assert_eq!(boundary(287), 144);
        let at = |h: u32| Epoch::new(h, Votes::default(), onion.clone(), Some(init.clone()));
        for h in 144..=148 {
            let e = at(h);
            assert_eq!(e.boundary, 144);
            assert_eq!(e.previous, Some(init.clone()), "both stand at {h}");
            assert_eq!(e.prefer_current, h >= 146, "at {h}");
        }
        for h in [149, 150, 200, 287] {
            assert_eq!(at(h).previous, None, "the old one is gone at {h}");
            assert!(at(h).prefer_current);
        }
        // The same file again: nothing to switch.
        let same = Epoch::new(145, Votes::default(), onion.clone(), Some(onion.clone()));
        assert_eq!((same.previous, same.prefer_current), (None, true));
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

    /// The file parser, fuzzed: no input makes it panic (a file comes
    /// from the chain, chosen by whoever mines the votes).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "slow in debug builds; run with --release")]
    fn fuzz_the_parser() {
        let ids: Vec<Digest> = (1..=3u32)
            .map(|i| {
                let mut d = [Fp::ZERO; crate::poseidon2::DIGEST];
                d[0] = Fp::new(i);
                d
            })
            .collect();
        let onion = format!(
            "# relays\nmode onion\nrelay {} relay1.example.org:3737\nrelay {} 10.0.0.2:3737\nrelay {} 10.0.0.3:3737\n",
            crate::address::encode(&ids[0]),
            hex(&digest_to_bytes(&ids[1])),
            crate::address::encode(&ids[2])
        );
        let samples = [b"mode init\n".to_vec(), onion.into_bytes()];
        crate::test_util::fuzz_decoder("consensus File::parse", &samples, 20_000, |b| File::parse(b).ok().map(|_| None));
    }
}
