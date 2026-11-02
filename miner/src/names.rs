//! The name registry's records: names, their records in the
//! [`NameTrie`], and the commits that precede a registration.
//!
//! See `docs/NAMES.md` for the design. This module is the store; the
//! rules (the commit window, the caps, who may update) are the chain's
//! and the circuit's.
//!
//! # Names
//!
//! A name is 1 to [`NAME_MAX`] characters of `[a-z0-9_]`. For hashing, and
//! for the circuit, each character is a field element from 1 to 37
//! ([`CHARSET`] in order), padded with zeros to [`NAME_MAX`] elements:
//! zero never occurs inside a name, so the padding is unambiguous. The
//! name's hash is the domain-separated hash of those elements, and the
//! trie key is [`key_of`] it.
//!
//! # Records
//!
//! A [`Record`] is the name, its owner (the hash of an XMSS public key),
//! its value (the hash of the owner's payment keys) and a memo for the
//! owner's wallet. Its leaf in the trie holds the hash of the name's hash,
//! owner, value and memo, so the leaf binds the whole name, not only the
//! 120 bits of its key. Records are stored by key, so a lookup is one read.
//!
//! # Commits
//!
//! A commit `c = H(H(name), salt, owner)` is stored as an output in the UTXO
//! set, at the next counter position, with the commitment field
//! [`commit_leaf`]`(c, height)` so the leaf binds the block it was made in,
//! and the memo the committer gave. This module keeps the side table that
//! says what each commit position holds, which the UTXO record does not
//! reveal: the commit hash and height by position, and the position by
//! commit hash, so a reveal finds its commit and a sweep its contents.
//!
//! # Operations
//!
//! A [`NameOp`] is an item of a transaction, signed by its inputs along
//! with them. A block lists the public part of each, a [`BlockNameOp`],
//! in its name section; the salt of a reveal and the owner's signature on
//! an update go only to the prover. Sweeps are not operations: a block
//! lists the positions it sweeps, and the miner picks them.
//!
//! ```text
//! block op := tag (1) | fields
//!   commit (1):  commit (32) | memo (20)
//!   reveal (2):  len (1) | name | owner (32) | value (32) | memo (32) | commit position (5)
//!   update (3):  len (1) | name | owner (32) | value (32) | memo (32)
//! name op  := block op | witness
//!   reveal:      salt (32)
//!   update:      owner public key (48) | signature (2312)
//! ```
//!
//! An operation's [digest](BlockNameOp::digest) hashes its tag and public
//! fields in whole sponge blocks: it is what the transaction body carries,
//! what the block commitment covers, and what the transaction and name
//! segments of the proof agree on. A reveal's commit position is not in
//! the digest, like an input's position: it tells nodes which output the
//! commit occupies, and the proof's state root holds it to the truth.
//!
//! An update is signed by the current owner key over the new record's
//! [`update_message`], and must name a new owner: the key rotates with
//! every signed operation, which also makes a replayed signature useless.

use heed::byteorder::BigEndian;
use heed::types::{Bytes, U32, U64};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::name_trie::{self, KEY_BITS, Key, NameProof, NameTrie, key_of};
use crate::poseidon2::{DIGEST, Fp, digest_from_bytes, digest_to_bytes};
use crate::state_tree::Digest;
use crate::transaction::{
    Key as OwnerKey, MEMO_BYTES, Memo, Sig, hash_domain, memo_from_bytes, memo_slot, memo_to_bytes, pubkey_hash,
};
use crate::utxo::UtxoSet;
use crate::xmss::{KeyExhausted, PublicKey};

/// Longest name, in characters.
pub const NAME_MAX: usize = 32;
/// The characters a name may use; a character's element is its index
/// here plus one.
pub const CHARSET: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
/// Element values run from 1 to this; 0 is padding.
pub const CHAR_MAX: u32 = CHARSET.len() as u32;

/// Most reveals in a block.
pub const MAX_REVEALS: usize = 5;
/// Most commits in a block.
pub const MAX_COMMITS: usize = 8;
/// Most updates in a block.
pub const MAX_UPDATES: usize = 8;
/// Most swept commits in a block.
pub const MAX_SWEEPS: usize = 16;
/// A commit made in the block at height `h` can be revealed in blocks
/// `h + MIN_REVEAL` to `h + MAX_REVEAL`, and swept after that.
pub const MIN_REVEAL: u32 = 12;
pub const MAX_REVEAL: u32 = 288;

/// Serialized size of a commit operation.
pub const COMMIT_OP_SIZE: usize = 1 + DIGEST_BYTES + MEMO_BYTES;
/// Bytes of a position in an operation.
const POSITION_BYTES: usize = 5;
/// Serialized size of a reveal or update as a block lists it, less the name.
pub const RECORD_OP_FIXED: usize = 1 + RECORD_FIXED;

// Domains, in the space of `transaction::hash_domain` (1 to 3 are the
// transaction's, 4 the trie leaf's).
pub(crate) const DOM_NAME: u32 = 5;
pub(crate) const DOM_RECORD: u32 = 6;
pub(crate) const DOM_COMMIT: u32 = 7;
pub(crate) const DOM_COMMIT_LEAF: u32 = 8;

pub(crate) const DOM_OP: u32 = 9;
pub(crate) const DOM_UPDATE: u32 = 10;
const DOM_NAME_PART: u32 = 11;
const DOM_NAME_BUCKET: u32 = 12;

const DIGEST_BYTES: usize = DIGEST * 4;
const COMMIT_ENTRY: usize = DIGEST_BYTES + 4;
const RECORD_FIXED: usize = 1 + 3 * DIGEST_BYTES;
pub(crate) const TAG_COMMIT: u8 = 1;
pub(crate) const TAG_REVEAL: u8 = 2;
pub(crate) const TAG_UPDATE: u8 = 3;

#[derive(Debug)]
pub enum Error {
    Heed(heed::Error),
    Trie(name_trie::Error),
    /// Not 1 to [`NAME_MAX`] characters of [`CHARSET`].
    BadName,
    /// A stored record or commit could not be decoded.
    Corrupt(&'static str),
    /// No commit at that position, or none with that hash.
    NoCommit,
    /// The owner key has no leaves left.
    Exhausted(KeyExhausted),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Heed(e) => write!(f, "lmdb error: {e}"),
            Error::Trie(e) => write!(f, "{e}"),
            Error::BadName => write!(f, "a name is 1 to {NAME_MAX} characters of a-z, 0-9 and _"),
            Error::Corrupt(what) => write!(f, "corrupt name store: {what}"),
            Error::NoCommit => f.write_str("no such commit"),
            Error::Exhausted(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<heed::Error> for Error {
    fn from(e: heed::Error) -> Self {
        Error::Heed(e)
    }
}

impl From<name_trie::Error> for Error {
    fn from(e: name_trie::Error) -> Self {
        Error::Trie(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// A name's characters as field elements, zero padded: `None` unless it
/// is 1 to [`NAME_MAX`] characters of [`CHARSET`].
pub fn name_elements(name: &[u8]) -> Option<[Fp; NAME_MAX]> {
    if name.is_empty() || name.len() > NAME_MAX {
        return None;
    }
    let mut out = [Fp::ZERO; NAME_MAX];
    for (e, c) in out.iter_mut().zip(name) {
        let i = CHARSET.iter().position(|x| x == c)?;
        *e = Fp::new(i as u32 + 1);
    }
    Some(out)
}

/// Whether `name` is well formed.
pub fn valid_name(name: &[u8]) -> bool {
    name_elements(name).is_some()
}

/// The hash of a well-formed name.
pub fn name_hash(elements: &[Fp; NAME_MAX]) -> Digest {
    hash_domain(DOM_NAME, elements)
}

/// The trie key of a well-formed name.
pub fn name_key(name: &[u8]) -> Option<Key> {
    name_elements(name).map(|e| key_of(&name_hash(&e)))
}

/// A commit `H(H(name), salt, owner)`: what a registrant publishes first.
pub fn commit_hash(name_hash: &Digest, salt: &Digest, owner: &Digest) -> Digest {
    let mut input = [Fp::ZERO; 3 * DIGEST];
    input[..DIGEST].copy_from_slice(name_hash);
    input[DIGEST..2 * DIGEST].copy_from_slice(salt);
    input[2 * DIGEST..].copy_from_slice(owner);
    hash_domain(DOM_COMMIT, &input)
}

/// The commitment field of a commit's UTXO record: the commit hash bound
/// to the height of the block that made it.
pub fn commit_leaf(commit: &Digest, height: u32) -> Digest {
    let mut input = [Fp::ZERO; DIGEST + 1];
    input[..DIGEST].copy_from_slice(commit);
    input[DIGEST] = Fp::new(height);
    hash_domain(DOM_COMMIT_LEAF, &input)
}

/// A registered name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: Vec<u8>,
    /// Hash of the XMSS public key that may update the record.
    pub owner: Digest,
    /// The hash of the owner's payment keys.
    pub value: Digest,
    /// The owner's wallet data.
    pub memo: Digest,
}

impl Record {
    /// A record for `name`; `None` unless the name is well formed.
    pub fn new(name: &[u8], owner: Digest, value: Digest, memo: Digest) -> Option<Record> {
        valid_name(name).then(|| Record { name: name.to_vec(), owner, value, memo })
    }

    pub fn elements(&self) -> Option<[Fp; NAME_MAX]> {
        name_elements(&self.name)
    }

    pub fn key(&self) -> Option<Key> {
        name_key(&self.name)
    }

    /// The value its trie leaf holds: the hash of the name's hash, owner,
    /// value and memo. `None` for a malformed name.
    pub fn leaf_value(&self) -> Option<Digest> {
        let mut input = [Fp::ZERO; 4 * DIGEST];
        input[..DIGEST].copy_from_slice(&name_hash(&self.elements()?));
        input[DIGEST..2 * DIGEST].copy_from_slice(&self.owner);
        input[2 * DIGEST..3 * DIGEST].copy_from_slice(&self.value);
        input[3 * DIGEST..].copy_from_slice(&self.memo);
        Some(hash_domain(DOM_RECORD, &input))
    }

    /// Length byte, name, owner, value, memo.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECORD_FIXED + self.name.len());
        out.push(self.name.len() as u8);
        out.extend_from_slice(&self.name);
        out.extend_from_slice(&digest_to_bytes(&self.owner));
        out.extend_from_slice(&digest_to_bytes(&self.value));
        out.extend_from_slice(&digest_to_bytes(&self.memo));
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Record> {
        let n = *bytes.first()? as usize;
        if bytes.len() != RECORD_FIXED + n {
            return None;
        }
        let name = bytes[1..1 + n].to_vec();
        if !valid_name(&name) {
            return None;
        }
        let rest = &bytes[1 + n..];
        let d = DIGEST_BYTES;
        Some(Record {
            name,
            owner: digest_from_bytes(&rest[..d])?,
            value: digest_from_bytes(&rest[d..2 * d])?,
            memo: digest_from_bytes(&rest[2 * d..])?,
        })
    }

    /// Serialized size.
    pub fn size(&self) -> usize {
        RECORD_FIXED + self.name.len()
    }
}

/// A commit as the side table holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commit {
    pub hash: Digest,
    pub height: u32,
}

impl Commit {
    fn to_bytes(self) -> [u8; COMMIT_ENTRY] {
        let mut out = [0u8; COMMIT_ENTRY];
        out[..DIGEST_BYTES].copy_from_slice(&digest_to_bytes(&self.hash));
        out[DIGEST_BYTES..].copy_from_slice(&self.height.to_le_bytes());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Commit> {
        if bytes.len() != COMMIT_ENTRY {
            return None;
        }
        Some(Commit {
            hash: digest_from_bytes(&bytes[..DIGEST_BYTES])?,
            height: u32::from_le_bytes(bytes[DIGEST_BYTES..].try_into().unwrap()),
        })
    }
}

/// The message the current owner signs to update a record to `record`:
/// the hash of its [leaf value](Record::leaf_value), which covers the
/// name, owner, value and memo.
pub fn update_message(record: &Record) -> Option<Digest> {
    Some(hash_domain(DOM_UPDATE, &record.leaf_value()?))
}

/// A name operation as a block lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockNameOp {
    /// Stores `commit` with the block height and `memo` as an output of
    /// amount zero at the next counter position.
    Commit { commit: Digest, memo: Memo },
    /// Registers the record; the commit at `commit` must be its, in the
    /// window.
    Reveal { record: Record, commit: u64 },
    /// Replaces the record of a registered name.
    Update(Record),
}

/// A name operation as a transaction carries it: the public part and
/// what the prover needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameOp {
    Commit {
        commit: Digest,
        memo: Memo,
    },
    /// `commit` is the position of the commit's output, unsigned like an
    /// input's position.
    Reveal {
        record: Record,
        salt: Digest,
        commit: u64,
    },
    Update {
        record: Record,
        pubkey: PublicKey,
        signature: Sig,
    },
}

/// Which kind of operation, for counting against the caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Commit,
    Reveal,
    Update,
    /// Not an operation a transaction carries; counted like one.
    Sweep,
}

impl OpKind {
    pub fn cap(self) -> usize {
        match self {
            OpKind::Commit => MAX_COMMITS,
            OpKind::Reveal => MAX_REVEALS,
            OpKind::Update => MAX_UPDATES,
            OpKind::Sweep => MAX_SWEEPS,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            OpKind::Commit => "commit",
            OpKind::Reveal => "reveal",
            OpKind::Update => "update",
            OpKind::Sweep => "sweep",
        }
    }
}

/// Counts of each kind in `kinds`, indexed by `OpKind as usize`; `Err`
/// with the kind if one exceeds its cap.
pub fn count_ops(kinds: impl IntoIterator<Item = OpKind>) -> core::result::Result<[usize; 4], OpKind> {
    let mut counts = [0usize; 4];
    for k in kinds {
        counts[k as usize] += 1;
        if counts[k as usize] > k.cap() {
            return Err(k);
        }
    }
    Ok(counts)
}

fn write_record(out: &mut Vec<u8>, record: &Record) {
    out.extend_from_slice(&record.to_bytes());
}

fn read_record(bytes: &[u8]) -> Option<(Record, &[u8])> {
    let n = *bytes.first()? as usize;
    let (head, rest) = bytes.split_at_checked(RECORD_FIXED + n)?;
    Some((Record::from_bytes(head)?, rest))
}

fn read_digest(bytes: &[u8]) -> Option<(Digest, &[u8])> {
    let (head, rest) = bytes.split_at_checked(DIGEST_BYTES)?;
    Some((digest_from_bytes(head)?, rest))
}

impl BlockNameOp {
    pub fn kind(&self) -> OpKind {
        match self {
            BlockNameOp::Commit { .. } => OpKind::Commit,
            BlockNameOp::Reveal { .. } => OpKind::Reveal,
            BlockNameOp::Update(_) => OpKind::Update,
        }
    }

    fn tag(&self) -> u8 {
        match self {
            BlockNameOp::Commit { .. } => TAG_COMMIT,
            BlockNameOp::Reveal { .. } => TAG_REVEAL,
            BlockNameOp::Update(_) => TAG_UPDATE,
        }
    }

    /// The record a reveal or update writes.
    pub fn record(&self) -> Option<&Record> {
        match self {
            BlockNameOp::Commit { .. } => None,
            BlockNameOp::Reveal { record, .. } => Some(record),
            BlockNameOp::Update(r) => Some(r),
        }
    }

    /// The position a reveal spends.
    pub fn spends(&self) -> Option<u64> {
        match self {
            BlockNameOp::Reveal { commit, .. } => Some(*commit),
            _ => None,
        }
    }

    /// Whether the record's name, if any, is well formed.
    pub fn is_well_formed(&self) -> bool {
        self.record().is_none_or(|r| valid_name(&r.name))
    }

    /// The elements the digest hashes, in whole sponge blocks:
    ///
    /// ```text
    /// [tag, 0, 0, 0, 0, 0, 0, 0]
    /// commit:         [commit(8)] [memo slot(8): the memo and amount zero]
    /// reveal, update: [record leaf value(8)]
    /// ```
    ///
    /// The leaf value covers the name's hash, owner, value and memo.
    /// `None` for a malformed name.
    pub fn elements(&self) -> Option<Vec<Fp>> {
        let mut v = Vec::with_capacity(24);
        v.push(Fp::new(self.tag() as u32));
        v.extend_from_slice(&[Fp::ZERO; 7]);
        match self {
            BlockNameOp::Commit { commit, memo } => {
                v.extend_from_slice(commit);
                v.extend_from_slice(&memo_slot(memo, 0));
            }
            BlockNameOp::Reveal { record, .. } => v.extend_from_slice(&record.leaf_value()?),
            BlockNameOp::Update(r) => v.extend_from_slice(&r.leaf_value()?),
        }
        Some(v)
    }

    /// The operation's digest, over its tag and public fields. `None` for
    /// a malformed name.
    pub fn digest(&self) -> Option<Digest> {
        Some(hash_domain(DOM_OP, &self.elements()?))
    }

    /// Serialized size.
    pub fn size(&self) -> usize {
        match self {
            BlockNameOp::Commit { .. } => COMMIT_OP_SIZE,
            BlockNameOp::Reveal { record, .. } => 1 + record.size() + POSITION_BYTES,
            BlockNameOp::Update(r) => 1 + r.size(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        out.push(self.tag());
        match self {
            BlockNameOp::Commit { commit, memo } => {
                out.extend_from_slice(&digest_to_bytes(commit));
                out.extend_from_slice(&memo_to_bytes(memo));
            }
            BlockNameOp::Reveal { record, commit } => {
                write_record(&mut out, record);
                out.extend_from_slice(&commit.to_le_bytes()[..POSITION_BYTES]);
            }
            BlockNameOp::Update(r) => write_record(&mut out, r),
        }
        out
    }

    /// Parses one operation from the front of `bytes`; returns the rest.
    pub fn parse(bytes: &[u8]) -> Option<(BlockNameOp, &[u8])> {
        let (&tag, rest) = bytes.split_first()?;
        match tag {
            TAG_COMMIT => {
                let (commit, rest) = read_digest(rest)?;
                let (memo, rest) = rest.split_at_checked(MEMO_BYTES)?;
                let memo = memo_from_bytes(memo)?;
                Some((BlockNameOp::Commit { commit, memo }, rest))
            }
            TAG_REVEAL => {
                let (record, rest) = read_record(rest)?;
                let (head, rest) = rest.split_at_checked(POSITION_BYTES)?;
                let mut buf = [0u8; 8];
                buf[..POSITION_BYTES].copy_from_slice(head);
                Some((BlockNameOp::Reveal { record, commit: u64::from_le_bytes(buf) }, rest))
            }
            TAG_UPDATE => read_record(rest).map(|(r, rest)| (BlockNameOp::Update(r), rest)),
            _ => None,
        }
    }
}

impl NameOp {
    /// An update of `record`'s name to `record`, signed by `key`, the
    /// name's current owner key.
    pub fn update(record: Record, key: &mut OwnerKey) -> core::result::Result<NameOp, Error> {
        let msg = update_message(&record).ok_or(Error::BadName)?;
        let signature = key.sign(&msg).map_err(Error::Exhausted)?;
        Ok(NameOp::Update { record, pubkey: key.public_key(), signature })
    }

    pub fn kind(&self) -> OpKind {
        self.block_op().kind()
    }

    /// The part a block lists.
    pub fn block_op(&self) -> BlockNameOp {
        match self {
            NameOp::Commit { commit, memo } => BlockNameOp::Commit { commit: *commit, memo: *memo },
            NameOp::Reveal { record, commit, .. } => BlockNameOp::Reveal { record: record.clone(), commit: *commit },
            NameOp::Update { record, .. } => BlockNameOp::Update(record.clone()),
        }
    }

    /// The record a reveal or update writes.
    pub fn record(&self) -> Option<&Record> {
        match self {
            NameOp::Commit { .. } => None,
            NameOp::Reveal { record, .. } | NameOp::Update { record, .. } => Some(record),
        }
    }

    /// Whether the record's name, if any, is well formed.
    pub fn is_well_formed(&self) -> bool {
        self.record().is_none_or(|r| valid_name(&r.name))
    }

    /// The digest of the public part: see [`BlockNameOp::digest`].
    pub fn digest(&self) -> Option<Digest> {
        self.block_op().digest()
    }

    /// For an update: whether the carried key is the one `current_owner`
    /// names, its signature covers the new record, and the record names a
    /// different owner. Other operations carry no signature and pass.
    pub fn verify_owner(&self, current_owner: &Digest) -> bool {
        match self {
            NameOp::Update { record, pubkey, signature } => {
                record.owner != *current_owner
                    && pubkey_hash(pubkey) == *current_owner
                    && update_message(record).is_some_and(|m| pubkey.verify(&m, signature))
            }
            _ => true,
        }
    }

    /// Serialized size.
    pub fn size(&self) -> usize {
        self.block_op().size()
            + match self {
                NameOp::Commit { .. } => 0,
                NameOp::Reveal { .. } => DIGEST_BYTES,
                NameOp::Update { pubkey, .. } => PublicKey::SIZE + Sig::size(pubkey.height()),
            }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.block_op().to_bytes();
        match self {
            NameOp::Commit { .. } => {}
            NameOp::Reveal { salt, .. } => out.extend_from_slice(&digest_to_bytes(salt)),
            NameOp::Update { pubkey, signature, .. } => {
                out.extend_from_slice(&pubkey.to_bytes());
                out.extend_from_slice(&signature.to_bytes());
            }
        }
        out
    }

    /// Parses one operation from the front of `bytes`; returns the rest.
    pub fn parse(bytes: &[u8]) -> Option<(NameOp, &[u8])> {
        let (op, rest) = BlockNameOp::parse(bytes)?;
        match op {
            BlockNameOp::Commit { commit, memo } => Some((NameOp::Commit { commit, memo }, rest)),
            BlockNameOp::Reveal { record, commit } => {
                let (salt, rest) = read_digest(rest)?;
                Some((NameOp::Reveal { record, salt, commit }, rest))
            }
            BlockNameOp::Update(record) => {
                let (pk, rest) = rest.split_at_checked(PublicKey::SIZE)?;
                let pubkey = PublicKey::from_bytes(pk)?;
                let (sig, rest) = rest.split_at_checked(Sig::size(pubkey.height()))?;
                let signature = Sig::from_bytes(sig, pubkey.height())?;
                Some((NameOp::Update { record, pubkey, signature }, rest))
            }
        }
    }
}

/// The registry: the trie, the records by key, and the commit tables.
#[derive(Clone)]
pub struct NameSet {
    trie: NameTrie,
    records: Database<Bytes, Bytes>,
    /// Commit position to hash and height.
    commits: Database<U64<BigEndian>, Bytes>,
    /// Commit hash to position.
    by_hash: Database<Bytes, U64<BigEndian>>,
    /// Per key bucket (the top [`NAME_BUCKET_LOG`] bits), the count and
    /// hash of its records: what a snapshot's name parts are made of, kept
    /// as records change so taking a snapshot never reads them all.
    buckets: Database<U32<BigEndian>, Bytes>,
}

/// Key bits that pick a record's bucket.
pub const NAME_BUCKET_LOG: usize = 16;

/// The bucket of a key.
pub fn bucket_of(key: Key) -> u32 {
    (key >> (KEY_BITS - NAME_BUCKET_LOG)) as u32
}

/// The first key of bucket `b`.
pub fn bucket_start(b: u32) -> Key {
    (b as Key) << (KEY_BITS - NAME_BUCKET_LOG)
}

/// The keys of bucket `b`: `start <= key < end` (`end` is `Key::MAX` for
/// the last, which excludes only a key no hash gives).
fn bucket_range(b: u32) -> (Key, Key) {
    let start = bucket_start(b);
    let end = if b as usize + 1 == 1 << NAME_BUCKET_LOG { Key::MAX } else { bucket_start(b + 1) };
    (start, end)
}

/// The hash of a bucket's records in key order; the empty bucket's is zero.
pub fn bucket_hash(records: &[Record]) -> Digest {
    if records.is_empty() {
        return [Fp::ZERO; DIGEST];
    }
    let mut bytes = Vec::with_capacity(records.len() * (RECORD_FIXED + 16));
    for r in records {
        bytes.extend_from_slice(&r.to_bytes());
    }
    let mut v = Vec::with_capacity(1 + bytes.len().div_ceil(3));
    v.push(Fp::from_u64(records.len() as u64));
    v.extend(crate::pow::pack_bytes(&bytes));
    hash_domain(DOM_NAME_BUCKET, &v)
}

/// The hash of a snapshot name part: its non-empty buckets' indexes and
/// hashes, ascending.
fn part_hash_of_buckets(buckets: &[(u32, Digest)]) -> Digest {
    let mut v = Vec::with_capacity(buckets.len() * (1 + DIGEST));
    for (b, h) in buckets {
        v.push(Fp::new(*b));
        v.extend_from_slice(h);
    }
    hash_domain(DOM_NAME_PART, &v)
}

/// The hash of a name part made of `records`, which must be in key order
/// within `lo <= key < hi`; `None` if they are not.
pub fn part_hash(records: &[Record], lo: Key, hi: Key) -> Option<Digest> {
    let mut buckets: Vec<(u32, Digest)> = Vec::new();
    let mut i = 0;
    let mut prev: Option<Key> = None;
    while i < records.len() {
        let key = records[i].key()?;
        if key < lo || key >= hi || prev.is_some_and(|p| p >= key) {
            return None;
        }
        let b = bucket_of(key);
        let mut j = i + 1;
        while j < records.len() {
            let k = records[j].key()?;
            if bucket_of(k) != b {
                break;
            }
            if k <= records[j - 1].key()? {
                return None;
            }
            j += 1;
        }
        buckets.push((b, bucket_hash(&records[i..j])));
        prev = records[j - 1].key();
        i = j;
    }
    Some(part_hash_of_buckets(&buckets))
}

fn key_bytes(key: Key) -> [u8; 15] {
    key.to_be_bytes()[1..].try_into().unwrap()
}

impl NameSet {
    /// Opens the registry stored under `prefix` in `env`, creating its
    /// databases if needed. The transaction must be committed by the caller.
    pub fn open(env: &Env, wtxn: &mut RwTxn, prefix: &str) -> Result<NameSet> {
        let trie = NameTrie::open(env, wtxn, &format!("{prefix}.trie"))?;
        let records = env.create_database(wtxn, Some(&format!("{prefix}.records")))?;
        let commits = env.create_database(wtxn, Some(&format!("{prefix}.commits")))?;
        let by_hash = env.create_database(wtxn, Some(&format!("{prefix}.commits_by_hash")))?;
        let buckets = env.create_database(wtxn, Some(&format!("{prefix}.buckets")))?;
        Ok(NameSet { trie, records, commits, by_hash, buckets })
    }

    pub fn trie(&self) -> &NameTrie {
        &self.trie
    }

    /// The trie's root: the state tree's right half.
    pub fn root(&self, rtxn: &RoTxn) -> Result<Digest> {
        Ok(self.trie.root(rtxn)?)
    }

    /// Number of registered names.
    pub fn len(&self, rtxn: &RoTxn) -> Result<u64> {
        Ok(self.trie.len(rtxn)?)
    }

    pub fn is_empty(&self, rtxn: &RoTxn) -> Result<bool> {
        Ok(self.trie.is_empty(rtxn)?)
    }

    /// The record under `key`, if any.
    pub fn record(&self, rtxn: &RoTxn, key: Key) -> Result<Option<Record>> {
        match self.records.get(rtxn, &key_bytes(key))? {
            None => Ok(None),
            Some(b) => Record::from_bytes(b).map(Some).ok_or(Error::Corrupt("record")),
        }
    }

    /// The record of `name`, if registered.
    pub fn lookup(&self, rtxn: &RoTxn, name: &[u8]) -> Result<Option<Record>> {
        match name_key(name) {
            Some(key) => self.record(rtxn, key),
            None => Err(Error::BadName),
        }
    }

    /// Registers a name that is not yet registered. Returns the trie root.
    pub fn register(&self, wtxn: &mut RwTxn, record: &Record) -> Result<Digest> {
        let root = self.register_unindexed(wtxn, record)?;
        self.reindex_bucket(wtxn, bucket_of(record.key().expect("checked")))?;
        Ok(root)
    }

    /// [`NameSet::register`] without maintaining the bucket table: for bulk
    /// loads, followed by [`NameSet::rebuild_buckets`].
    pub fn register_unindexed(&self, wtxn: &mut RwTxn, record: &Record) -> Result<Digest> {
        let key = record.key().ok_or(Error::BadName)?;
        let root = self.trie.insert(wtxn, key, &record.leaf_value().ok_or(Error::BadName)?)?;
        self.records.put(wtxn, &key_bytes(key), &record.to_bytes())?;
        Ok(root)
    }

    /// Replaces the record of a registered name (the name itself must be
    /// unchanged). Returns the previous record and the trie root.
    pub fn update(&self, wtxn: &mut RwTxn, record: &Record) -> Result<(Record, Digest)> {
        let key = record.key().ok_or(Error::BadName)?;
        let previous = self.record(wtxn, key)?.ok_or(name_trie::Error::Absent(key))?;
        let root = self.trie.update(wtxn, key, &record.leaf_value().ok_or(Error::BadName)?)?;
        self.records.put(wtxn, &key_bytes(key), &record.to_bytes())?;
        self.reindex_bucket(wtxn, bucket_of(key))?;
        Ok((previous, root))
    }

    /// Removes a registered name: undoing a registration. Returns the
    /// record and the trie root.
    pub fn unregister(&self, wtxn: &mut RwTxn, key: Key) -> Result<(Record, Digest)> {
        let record = self.record(wtxn, key)?.ok_or(name_trie::Error::Absent(key))?;
        let root = self.trie.remove(wtxn, key)?;
        self.records.delete(wtxn, &key_bytes(key))?;
        self.reindex_bucket(wtxn, bucket_of(key))?;
        Ok((record, root))
    }

    /// Removes the records with `lo <= key < hi` and their leaves, without
    /// maintaining the bucket table: for staging, which rebuilds it.
    pub fn clear_range_unindexed(&self, wtxn: &mut RwTxn, lo: Key, hi: Key) -> Result<()> {
        let keys: Vec<Key> = self.trie.entries_in(wtxn, lo, hi)?.into_iter().map(|(k, _)| k).collect();
        for key in keys {
            self.trie.remove(wtxn, key)?;
            self.records.delete(wtxn, &key_bytes(key))?;
        }
        Ok(())
    }

    fn put_bucket(&self, wtxn: &mut RwTxn, b: u32, records: &[Record]) -> Result<()> {
        if records.is_empty() {
            self.buckets.delete(wtxn, &b)?;
            return Ok(());
        }
        let mut value = Vec::with_capacity(4 + DIGEST_BYTES);
        value.extend_from_slice(&(records.len() as u32).to_le_bytes());
        value.extend_from_slice(&digest_to_bytes(&bucket_hash(records)));
        self.buckets.put(wtxn, &b, &value)?;
        Ok(())
    }

    /// Recomputes bucket `b` from its records.
    fn reindex_bucket(&self, wtxn: &mut RwTxn, b: u32) -> Result<()> {
        let (lo, hi) = bucket_range(b);
        let records = self.records_in(wtxn, lo, hi)?;
        self.put_bucket(wtxn, b, &records)
    }

    /// Recomputes every bucket from the records, a page at a time.
    pub fn rebuild_buckets(&self, wtxn: &mut RwTxn) -> Result<()> {
        self.buckets.clear(wtxn)?;
        let mut from: Key = 0;
        let mut current: Vec<Record> = Vec::new();
        loop {
            let page = self.records_from(wtxn, from, NAME_PART_RECORDS)?;
            let Some(last) = page.last() else { break };
            let last_key = last.key().ok_or(Error::Corrupt("record"))?;
            for r in page.iter() {
                let b = bucket_of(r.key().ok_or(Error::Corrupt("record"))?);
                if current.first().is_some_and(|c| bucket_of(c.key().unwrap()) != b) {
                    let cb = bucket_of(current[0].key().unwrap());
                    self.put_bucket(wtxn, cb, &current)?;
                    current.clear();
                }
                current.push(r.clone());
            }
            if page.len() < NAME_PART_RECORDS || last_key == Key::MAX {
                break;
            }
            from = last_key + 1;
        }
        if !current.is_empty() {
            let cb = bucket_of(current[0].key().unwrap());
            self.put_bucket(wtxn, cb, &current)?;
        }
        Ok(())
    }

    /// A snapshot's name parts from the bucket table: consecutive buckets
    /// grouped to at most [`NAME_PART_RECORDS`] records each (a larger
    /// bucket is a part of its own), as the first key and the hash of each.
    pub fn name_parts(&self, rtxn: &RoTxn) -> Result<Vec<(Key, Digest)>> {
        let mut parts = Vec::new();
        let mut group: Vec<(u32, Digest)> = Vec::new();
        let mut count = 0usize;
        for item in self.buckets.iter(rtxn)? {
            let (b, value) = item?;
            if value.len() != 4 + DIGEST_BYTES {
                return Err(Error::Corrupt("bucket"));
            }
            let n = u32::from_le_bytes(value[..4].try_into().unwrap()) as usize;
            let h = digest_from_bytes(&value[4..]).ok_or(Error::Corrupt("bucket"))?;
            if !group.is_empty() && count + n > NAME_PART_RECORDS {
                parts.push((bucket_start(group[0].0), part_hash_of_buckets(&group)));
                group.clear();
                count = 0;
            }
            group.push((b, h));
            count += n;
        }
        if !group.is_empty() {
            parts.push((bucket_start(group[0].0), part_hash_of_buckets(&group)));
        }
        Ok(parts)
    }

    /// A membership or non-membership proof for `name`.
    pub fn prove(&self, rtxn: &RoTxn, name: &[u8]) -> Result<NameProof> {
        let key = name_key(name).ok_or(Error::BadName)?;
        Ok(self.trie.prove(rtxn, key)?)
    }

    /// Every record with `lo <= key < hi`, ascending by key.
    pub fn records_in(&self, rtxn: &RoTxn, lo: Key, hi: Key) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        for (key, _) in self.trie.entries_in(rtxn, lo, hi)? {
            out.push(self.record(rtxn, key)?.ok_or(Error::Corrupt("record missing for a leaf"))?);
        }
        Ok(out)
    }

    /// Notes a commit made at `position` in the block at `height`.
    pub fn add_commit(&self, wtxn: &mut RwTxn, position: u64, commit: Commit) -> Result<()> {
        self.commits.put(wtxn, &position, &commit.to_bytes())?;
        self.by_hash.put(wtxn, &digest_to_bytes(&commit.hash), &position)?;
        Ok(())
    }

    /// Forgets the commit at `position` (revealed, swept, or undone).
    /// Returns what it was.
    pub fn remove_commit(&self, wtxn: &mut RwTxn, position: u64) -> Result<Commit> {
        let commit = self.commit_at(wtxn, position)?.ok_or(Error::NoCommit)?;
        self.commits.delete(wtxn, &position)?;
        self.by_hash.delete(wtxn, &digest_to_bytes(&commit.hash))?;
        Ok(commit)
    }

    /// The commit at `position`, if one is there.
    pub fn commit_at(&self, rtxn: &RoTxn, position: u64) -> Result<Option<Commit>> {
        match self.commits.get(rtxn, &position)? {
            None => Ok(None),
            Some(b) => Commit::from_bytes(b).map(Some).ok_or(Error::Corrupt("commit")),
        }
    }

    /// The position of the commit with `hash`, if any.
    pub fn commit_position(&self, rtxn: &RoTxn, hash: &Digest) -> Result<Option<u64>> {
        Ok(self.by_hash.get(rtxn, &digest_to_bytes(hash))?)
    }

    /// Every commit, ascending by position.
    pub fn commits(&self, rtxn: &RoTxn) -> Result<Vec<(u64, Commit)>> {
        let mut out = Vec::new();
        for item in self.commits.iter(rtxn)? {
            let (p, b) = item?;
            out.push((p, Commit::from_bytes(b).ok_or(Error::Corrupt("commit"))?));
        }
        Ok(out)
    }

    /// The commits made at or before `height`, ascending by position:
    /// those past their window once `height` is the last they could be
    /// revealed at. Positions grow with height, so the walk stops at the
    /// first later commit and costs what it returns.
    pub fn commits_up_to(&self, rtxn: &RoTxn, height: u32) -> Result<Vec<(u64, Commit)>> {
        let mut out = Vec::new();
        for item in self.commits.iter(rtxn)? {
            let (p, b) = item?;
            let c = Commit::from_bytes(b).ok_or(Error::Corrupt("commit"))?;
            if c.height > height {
                break;
            }
            out.push((p, c));
        }
        Ok(out)
    }

    /// Up to `limit` records with keys from `from` on, ascending: a page
    /// of the registry, for walking it without holding it all.
    pub fn records_from(&self, rtxn: &RoTxn, from: Key, limit: usize) -> Result<Vec<Record>> {
        let mut out = Vec::with_capacity(limit);
        let lo = key_bytes(from);
        let bounds: (std::ops::Bound<&[u8]>, std::ops::Bound<&[u8]>) =
            (std::ops::Bound::Included(&lo[..]), std::ops::Bound::Unbounded);
        for item in self.records.range(rtxn, &bounds)? {
            let (_, b) = item?;
            out.push(Record::from_bytes(b).ok_or(Error::Corrupt("record"))?);
            if out.len() == limit {
                break;
            }
        }
        Ok(out)
    }

    /// Removes everything.
    pub fn clear(&self, wtxn: &mut RwTxn) -> Result<()> {
        self.trie.clear(wtxn)?;
        self.records.clear(wtxn)?;
        self.commits.clear(wtxn)?;
        self.by_hash.clear(wtxn)?;
        self.buckets.clear(wtxn)?;
        Ok(())
    }
}

/// Why a name operation cannot be applied.
#[derive(Debug)]
pub enum ApplyError {
    Utxo(crate::utxo::Error),
    Names(Error),
    BadName,
    /// A reveal whose commit is not in the set, or a sweep of a position
    /// that holds no commit.
    NoCommit,
    /// A reveal outside the window of its commit, made at this height.
    Window(u32),
    /// A reveal of a registered name.
    Registered,
    /// An update of a name that is not registered.
    NotRegistered,
    /// An update not signed by the current owner, or keeping it.
    BadOwner,
    /// A sweep of a commit still in its window (made at this height).
    NotExpired(u32),
    /// More operations of a kind than the cap.
    TooMany(OpKind),
}

impl core::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ApplyError::Utxo(e) => write!(f, "{e}"),
            ApplyError::Names(e) => write!(f, "{e}"),
            ApplyError::BadName => f.write_str("malformed name"),
            ApplyError::NoCommit => f.write_str("no such commit"),
            ApplyError::Window(h) => write!(f, "the commit at height {h} is outside its reveal window"),
            ApplyError::Registered => f.write_str("the name is registered"),
            ApplyError::NotRegistered => f.write_str("the name is not registered"),
            ApplyError::BadOwner => f.write_str("not signed by the current owner, or the owner is unchanged"),
            ApplyError::NotExpired(h) => write!(f, "the commit at height {h} has not expired"),
            ApplyError::TooMany(k) => write!(f, "more than {} {} operations", k.cap(), k.name()),
        }
    }
}

impl std::error::Error for ApplyError {}

impl From<crate::utxo::Error> for ApplyError {
    fn from(e: crate::utxo::Error) -> Self {
        ApplyError::Utxo(e)
    }
}

impl From<Error> for ApplyError {
    fn from(e: Error) -> Self {
        ApplyError::Names(e)
    }
}

/// Records a fast-sync name part holds at most, buckets permitting (see
/// [`NameSet::name_parts`]).
pub const NAME_PART_RECORDS: usize = 4096;

/// Whether a commit made at `commit_height` can be revealed at `height`.
pub fn in_window(height: u32, commit_height: u32) -> bool {
    height >= commit_height && (MIN_REVEAL..=MAX_REVEAL).contains(&(height - commit_height))
}

/// Whether a commit made at `commit_height` can be swept at `height`.
pub fn expired(height: u32, commit_height: u32) -> bool {
    height > commit_height && height - commit_height > MAX_REVEAL
}

/// What undoing a block's name section needs (see [`NameSet::apply`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameUndo {
    /// Commits the block made, in order: their positions follow its
    /// outputs.
    pub commits: Vec<Commit>,
    /// Commits its reveals and sweeps consumed, in order: position, commit
    /// and the output's memo.
    pub consumed: Vec<(u64, Commit, Digest)>,
    /// Keys its reveals registered, in order.
    pub registered: Vec<Key>,
    /// The records its updates replaced, in order.
    pub updated: Vec<Record>,
}

impl NameUndo {
    pub fn is_empty(&self) -> bool {
        self.commits.is_empty() && self.consumed.is_empty() && self.registered.is_empty() && self.updated.is_empty()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.commits.len() as u32).to_le_bytes());
        for c in &self.commits {
            out.extend_from_slice(&c.to_bytes());
        }
        out.extend_from_slice(&(self.consumed.len() as u32).to_le_bytes());
        for (p, c, m) in &self.consumed {
            out.extend_from_slice(&p.to_le_bytes());
            out.extend_from_slice(&c.to_bytes());
            out.extend_from_slice(&digest_to_bytes(m));
        }
        out.extend_from_slice(&(self.registered.len() as u32).to_le_bytes());
        for k in &self.registered {
            out.extend_from_slice(&key_bytes(*k));
        }
        out.extend_from_slice(&(self.updated.len() as u32).to_le_bytes());
        for r in &self.updated {
            out.extend_from_slice(&r.to_bytes());
        }
        out
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Option<NameUndo> {
        fn count(bytes: &mut &[u8]) -> Option<usize> {
            let (head, rest) = bytes.split_at_checked(4)?;
            *bytes = rest;
            Some(u32::from_le_bytes(head.try_into().unwrap()) as usize)
        }
        fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            let (head, rest) = bytes.split_at_checked(n)?;
            *bytes = rest;
            Some(head)
        }
        let mut undo = NameUndo::default();
        for _ in 0..count(&mut bytes)? {
            undo.commits.push(Commit::from_bytes(take(&mut bytes, COMMIT_ENTRY)?)?);
        }
        for _ in 0..count(&mut bytes)? {
            let p = u64::from_le_bytes(take(&mut bytes, 8)?.try_into().unwrap());
            let c = Commit::from_bytes(take(&mut bytes, COMMIT_ENTRY)?)?;
            let m = digest_from_bytes(take(&mut bytes, DIGEST_BYTES)?)?;
            undo.consumed.push((p, c, m));
        }
        for _ in 0..count(&mut bytes)? {
            let mut k = [0u8; 16];
            k[1..].copy_from_slice(take(&mut bytes, 15)?);
            undo.registered.push(Key::from_be_bytes(k));
        }
        for _ in 0..count(&mut bytes)? {
            let n = *bytes.first()? as usize;
            undo.updated.push(Record::from_bytes(take(&mut bytes, RECORD_FIXED + n)?)?);
        }
        bytes.is_empty().then_some(undo)
    }
}

impl NameSet {
    /// Applies a block's name section at `height` to the UTXO set and the
    /// registry, in order, as the proof attests it: commits take the
    /// positions after the block's outputs, reveals register their record
    /// and spend their commit, updates replace a record, sweeps spend an
    /// expired commit. Checks what a node can check without the witnesses
    /// (the window, the caps, that names and commits exist) and sets the
    /// tree's name root. Returns what undoing it needs.
    pub fn apply(
        &self,
        utxo: &UtxoSet,
        wtxn: &mut RwTxn,
        height: u32,
        ops: &[BlockNameOp],
        sweeps: &[u64],
    ) -> core::result::Result<NameUndo, ApplyError> {
        let kinds = ops.iter().map(BlockNameOp::kind).chain(sweeps.iter().map(|_| OpKind::Sweep));
        count_ops(kinds).map_err(ApplyError::TooMany)?;
        let mut undo = NameUndo::default();
        for op in ops {
            match op {
                BlockNameOp::Commit { commit, memo } => {
                    let position = utxo.next_position(wtxn)?;
                    let c = Commit { hash: *commit, height };
                    utxo.add_output(
                        wtxn,
                        &crate::block::BlockOutput { commitment: commit_leaf(commit, height), memo: *memo, amount: 0 },
                        height,
                    )?;
                    self.add_commit(wtxn, position, c)?;
                    undo.commits.push(c);
                }
                BlockNameOp::Reveal { record, commit: position } => {
                    let key = record.key().ok_or(ApplyError::BadName)?;
                    let commit = self.commit_at(wtxn, *position)?.ok_or(ApplyError::NoCommit)?;
                    if !in_window(height, commit.height) {
                        return Err(ApplyError::Window(commit.height));
                    }
                    if self.record(wtxn, key)?.is_some() {
                        return Err(ApplyError::Registered);
                    }
                    self.register(wtxn, record)?;
                    let memo = self.consume_commit(utxo, wtxn, *position, &commit)?;
                    undo.consumed.push((*position, commit, memo));
                    undo.registered.push(key);
                }
                BlockNameOp::Update(record) => {
                    let key = record.key().ok_or(ApplyError::BadName)?;
                    if self.record(wtxn, key)?.is_none() {
                        return Err(ApplyError::NotRegistered);
                    }
                    let (previous, _) = self.update(wtxn, record)?;
                    undo.updated.push(previous);
                }
            }
        }
        for &position in sweeps {
            let commit = self.commit_at(wtxn, position)?.ok_or(ApplyError::NoCommit)?;
            if !expired(height, commit.height) {
                return Err(ApplyError::NotExpired(commit.height));
            }
            let memo = self.consume_commit(utxo, wtxn, position, &commit)?;
            undo.consumed.push((position, commit, memo));
        }
        utxo.set_name_root(wtxn, &self.root(wtxn)?)?;
        Ok(undo)
    }

    /// Spends the commit's output and forgets it; returns the output's memo.
    fn consume_commit(
        &self,
        utxo: &UtxoSet,
        wtxn: &mut RwTxn,
        position: u64,
        commit: &Commit,
    ) -> core::result::Result<Digest, ApplyError> {
        let memo = utxo.slot(wtxn, position)?;
        if !utxo.spend_at(wtxn, &commit_leaf(&commit.hash, commit.height), position)? {
            return Err(ApplyError::NoCommit);
        }
        self.remove_commit(wtxn, position)?;
        Ok(memo)
    }

    /// Undoes [`NameSet::apply`] for the block at `height` whose commits
    /// took positions from `first_commit`: the caller has already removed
    /// the block's outputs and commit leaves from the UTXO set. Restores
    /// the consumed commits' outputs, the records and the commit table,
    /// and sets the tree's name root.
    pub fn undo(
        &self,
        utxo: &UtxoSet,
        wtxn: &mut RwTxn,
        undo: &NameUndo,
        first_commit: u64,
    ) -> core::result::Result<(), ApplyError> {
        for i in 0..undo.commits.len() as u64 {
            self.remove_commit(wtxn, first_commit + i)?;
        }
        for record in undo.updated.iter().rev() {
            self.update(wtxn, record)?;
        }
        for key in undo.registered.iter().rev() {
            self.unregister(wtxn, *key)?;
        }
        for (position, commit, memo) in undo.consumed.iter().rev() {
            utxo.insert_at(wtxn, *position, &commit_leaf(&commit.hash, commit.height), memo, commit.height)?;
            self.add_commit(wtxn, *position, *commit)?;
        }
        utxo.set_name_root(wtxn, &self.root(wtxn)?)?;
        Ok(())
    }

    /// The commits at positions `first <= p < end`, ascending.
    pub fn commits_in(&self, rtxn: &RoTxn, first: u64, end: u64) -> Result<Vec<(u64, Commit)>> {
        let mut out = Vec::new();
        for item in self.commits.range(rtxn, &(first..end))? {
            let (p, b) = item?;
            out.push((p, Commit::from_bytes(b).ok_or(Error::Corrupt("commit"))?));
        }
        Ok(out)
    }

    /// Disk use of the registry's databases: name, bytes in pages, entries.
    pub fn storage(&self, rtxn: &RoTxn) -> Result<Vec<(&'static str, u64, usize)>> {
        let size =
            |s: heed::DatabaseStat| (s.branch_pages + s.leaf_pages + s.overflow_pages) as u64 * s.page_size as u64;
        let mut out = Vec::with_capacity(4);
        for (name, stat) in [
            ("name trie", self.trie.db_stat(rtxn)?),
            ("name records", self.records.stat(rtxn)?),
            ("commits", self.commits.stat(rtxn)?),
            ("commits by hash", self.by_hash.stat(rtxn)?),
            ("name buckets", self.buckets.stat(rtxn)?),
        ] {
            out.push((name, size(stat), stat.entries));
        }
        Ok(out)
    }

    /// Removes every record, the trie and the buckets, keeping the commit
    /// tables.
    pub fn clear_names(&self, wtxn: &mut RwTxn) -> Result<()> {
        self.trie.clear(wtxn)?;
        self.records.clear(wtxn)?;
        self.buckets.clear(wtxn)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name_trie::{Terminal, empty_root};
    use crate::state_tree::{EMPTY, open_env};
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let p = std::env::temp_dir().join(format!("tabminer-names-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn setup(name: &str) -> (TempDir, Env, NameSet) {
        let dir = TempDir::new(name);
        let env = open_env(&dir.0, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let set = NameSet::open(&env, &mut wtxn, "names").unwrap();
        wtxn.commit().unwrap();
        (dir, env, set)
    }

    fn d(n: u32) -> Digest {
        let mut x = EMPTY;
        x[0] = Fp::new(n);
        x[5] = Fp::new(n * 3);
        x
    }

    fn record(name: &str, n: u32) -> Record {
        Record { name: name.as_bytes().to_vec(), owner: d(n), value: d(n + 1), memo: d(n + 2) }
    }

    #[test]
    fn names_are_validated_and_hashed_as_elements() {
        assert!(valid_name(b"example"));
        assert!(valid_name(b"a"));
        assert!(valid_name(b"nvidia_2026"));
        assert!(valid_name(&[b'z'; NAME_MAX]));
        assert!(!valid_name(b""));
        assert!(!valid_name(&[b'z'; NAME_MAX + 1]));
        assert!(!valid_name(b"Example"));
        assert!(!valid_name(b"cool.example"));
        assert!(!valid_name(b"a-b"));
        assert!(!valid_name("é".as_bytes()));
        let e = name_elements(b"az0_").unwrap();
        assert_eq!(&e[..5], &[Fp::new(1), Fp::new(26), Fp::new(27), Fp::new(37), Fp::ZERO]);
        assert_eq!(CHAR_MAX, 37);
        assert_ne!(name_hash(&e), name_hash(&name_elements(b"az0").unwrap()));
        assert_ne!(name_key(b"abc"), name_key(b"abd"));
        assert_eq!(name_key(b"abc"), name_key(b"abc"));
        // The commit binds every field; the leaf binds the height.
        let h = name_hash(&e);
        let c = commit_hash(&h, &d(1), &d(2));
        assert_ne!(c, commit_hash(&h, &d(1), &d(3)));
        assert_ne!(c, commit_hash(&h, &d(9), &d(2)));
        assert_ne!(c, commit_hash(&name_hash(&name_elements(b"az0").unwrap()), &d(1), &d(2)));
        assert_ne!(commit_leaf(&c, 5), commit_leaf(&c, 6));
    }

    #[test]
    fn records_round_trip() {
        let r = record("example", 4);
        assert_eq!(r.size(), 1 + 7 + 96);
        let bytes = r.to_bytes();
        assert_eq!(bytes.len(), r.size());
        assert_eq!(Record::from_bytes(&bytes), Some(r.clone()));
        assert_eq!(Record::from_bytes(&bytes[..bytes.len() - 1]), None);
        let mut bad = bytes.clone();
        bad[1] = b'E';
        assert_eq!(Record::from_bytes(&bad), None);
        assert_ne!(r.leaf_value(), record("example", 5).leaf_value());
        assert_ne!(r.leaf_value(), record("exampl", 4).leaf_value());
        assert_eq!(Record { name: b"".to_vec(), ..r }.leaf_value(), None);
    }

    #[test]
    fn registers_updates_unregisters_and_looks_up() {
        let (_dir, env, set) = setup("registry");
        let mut wtxn = env.write_txn().unwrap();
        assert_eq!(set.root(&wtxn).unwrap(), empty_root());
        assert_eq!(set.lookup(&wtxn, b"example").unwrap(), None);
        assert!(matches!(set.lookup(&wtxn, b"Bad"), Err(Error::BadName)));
        let a = record("example", 1);
        let root1 = set.register(&mut wtxn, &a).unwrap();
        assert_eq!(set.lookup(&wtxn, b"example").unwrap(), Some(a.clone()));
        assert!(matches!(set.register(&mut wtxn, &a), Err(Error::Trie(name_trie::Error::Present(_)))));
        let b = record("nvidia", 10);
        let root2 = set.register(&mut wtxn, &b).unwrap();
        assert_ne!(root1, root2);
        assert_eq!(set.len(&wtxn).unwrap(), 2);
        // Proofs: membership for the registered, absence for the rest.
        let proof = set.prove(&wtxn, b"example").unwrap();
        assert!(proof.verify_member(&root2, a.key().unwrap(), &a.leaf_value().unwrap()));
        let proof = set.prove(&wtxn, b"other").unwrap();
        assert!(proof.verify_absent(&root2, name_key(b"other").unwrap()));
        assert!(matches!(proof.terminal, Terminal::Empty | Terminal::Leaf { .. }));
        // Update keeps the name, changes the leaf, returns the old record.
        let a2 = Record { owner: d(50), value: d(51), memo: d(52), ..a.clone() };
        let (old, root3) = set.update(&mut wtxn, &a2).unwrap();
        assert_eq!(old, a);
        assert_ne!(root3, root2);
        assert_eq!(set.lookup(&wtxn, b"example").unwrap(), Some(a2.clone()));
        assert!(matches!(set.update(&mut wtxn, &record("nobody", 1)), Err(Error::Trie(name_trie::Error::Absent(_)))));
        // Undo the update by updating back, and the registration by
        // unregistering: the roots retrace.
        assert_eq!(set.update(&mut wtxn, &a).unwrap().1, root2);
        let (gone, root) = set.unregister(&mut wtxn, b.key().unwrap()).unwrap();
        assert_eq!((gone, root), (b, root1));
        assert_eq!(set.records_in(&wtxn, 0, Key::MAX).unwrap(), vec![a.clone()]);
        let (_, root) = set.unregister(&mut wtxn, a.key().unwrap()).unwrap();
        assert_eq!(root, empty_root());
        assert!(set.is_empty(&wtxn).unwrap());
        // Ranges split the records by key.
        let names = ["a", "bb", "ccc", "dddd", "e5", "f_"];
        for (i, n) in names.iter().enumerate() {
            set.register(&mut wtxn, &record(n, i as u32)).unwrap();
        }
        let mut keys: Vec<Key> = names.iter().map(|n| name_key(n.as_bytes()).unwrap()).collect();
        keys.sort_unstable();
        let mid = keys[3];
        let low = set.records_in(&wtxn, 0, mid).unwrap();
        let high = set.records_in(&wtxn, mid, Key::MAX).unwrap();
        assert_eq!((low.len(), high.len()), (3, 3));
        assert!(low.iter().all(|r| r.key().unwrap() < mid) && high.iter().all(|r| r.key().unwrap() >= mid));
        set.clear(&mut wtxn).unwrap();
        assert_eq!(set.root(&wtxn).unwrap(), empty_root());
    }

    #[test]
    fn commits_are_found_by_position_and_hash() {
        let (_dir, env, set) = setup("commits");
        let mut wtxn = env.write_txn().unwrap();
        let c1 = Commit { hash: d(1), height: 100 };
        let c2 = Commit { hash: d(2), height: 101 };
        set.add_commit(&mut wtxn, 7, c1).unwrap();
        set.add_commit(&mut wtxn, 9, c2).unwrap();
        assert_eq!(set.commit_at(&wtxn, 7).unwrap(), Some(c1));
        assert_eq!(set.commit_at(&wtxn, 8).unwrap(), None);
        assert_eq!(set.commit_position(&wtxn, &d(2)).unwrap(), Some(9));
        assert_eq!(set.commit_position(&wtxn, &d(3)).unwrap(), None);
        assert_eq!(set.commits(&wtxn).unwrap(), vec![(7, c1), (9, c2)]);
        assert_eq!(set.commits_up_to(&wtxn, 100).unwrap(), vec![(7, c1)]);
        assert_eq!(set.remove_commit(&mut wtxn, 7).unwrap(), c1);
        assert!(matches!(set.remove_commit(&mut wtxn, 7), Err(Error::NoCommit)));
        assert_eq!(set.commit_position(&wtxn, &d(1)).unwrap(), None);
        assert_eq!(set.commits(&wtxn).unwrap(), vec![(9, c2)]);
    }

    fn owner_key(tag: u8) -> OwnerKey {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        seed[1] = 77;
        OwnerKey::generate(&seed)
    }

    #[test]
    fn operations_encode_digest_and_count() {
        let commit = NameOp::Commit { commit: d(1), memo: crate::transaction::memo5(d(2)) };
        let reveal = NameOp::Reveal { record: record("alice", 3), salt: d(4), commit: 77 };
        let mut k = owner_key(1);
        let update = NameOp::update(record("alice", 5), &mut k).unwrap();
        for op in [&commit, &reveal, &update] {
            let bytes = op.to_bytes();
            assert_eq!(bytes.len(), op.size());
            let (back, rest) = NameOp::parse(&bytes).unwrap();
            assert_eq!((&back, rest.len()), (op, 0));
            assert!(NameOp::parse(&bytes[..bytes.len() - 1]).is_none());
            let public = op.block_op();
            let pb = public.to_bytes();
            assert_eq!(pb.len(), public.size());
            assert_eq!(BlockNameOp::parse(&pb).unwrap(), (public.clone(), &[][..]));
            assert!(bytes.starts_with(&pb));
            assert_eq!(public.digest(), op.digest());
            assert_eq!(public.elements().unwrap().len() % DIGEST, 0);
        }
        assert_eq!(commit.size(), COMMIT_OP_SIZE);
        assert_eq!(reveal.block_op().size(), RECORD_OP_FIXED + 5 + 5);
        assert_eq!(reveal.size(), RECORD_OP_FIXED + 5 + 5 + 32);
        assert_eq!(update.size(), RECORD_OP_FIXED + 5 + PublicKey::SIZE + Sig::size(crate::transaction::TREE_HEIGHT));
        assert_eq!(update.block_op().elements().unwrap().len(), 16);
        assert_eq!(commit.block_op().elements().unwrap().len(), 24);

        // Digests separate kinds and fields; the witness and the commit
        // position are not in them.
        let other_salt = NameOp::Reveal { record: record("alice", 3), salt: d(9), commit: 78 };
        assert_eq!(other_salt.digest(), reveal.digest());
        assert_ne!(reveal.digest(), NameOp::Reveal { record: record("alicf", 3), salt: d(4), commit: 77 }.digest());
        assert_ne!(BlockNameOp::Reveal { record: record("alice", 5), commit: 0 }.digest(), update.digest());
        assert_ne!(commit.digest(), NameOp::Commit { commit: d(2), memo: crate::transaction::memo5(d(1)) }.digest());
        let mut digests: Vec<_> = [&commit, &reveal, &update].iter().map(|op| op.digest().unwrap()).collect();
        digests.dedup();
        assert_eq!(digests.len(), 3);

        // A malformed name has no digest and is not well formed.
        let bad = BlockNameOp::Reveal {
            record: Record { name: b"Alice".to_vec(), owner: d(1), value: d(2), memo: d(3) },
            commit: 0,
        };
        assert!(bad.digest().is_none());
        assert!(!bad.is_well_formed());
        assert!(BlockNameOp::parse(&bad.to_bytes()).is_none());
        assert!(BlockNameOp::parse(&[9, 0, 0]).is_none());
        assert!(Record::new(b"Alice", d(1), d(2), d(3)).is_none());
        assert_eq!(Record::new(b"alice", d(1), d(2), d(3)), Some(record("alice", 1)));

        // Counts against the caps.
        let kinds = |n: usize, k: OpKind| std::iter::repeat_n(k, n);
        assert_eq!(
            count_ops(kinds(MAX_REVEALS, OpKind::Reveal).chain(kinds(MAX_COMMITS, OpKind::Commit))),
            Ok([8, 5, 0, 0])
        );
        assert_eq!(count_ops(kinds(MAX_REVEALS + 1, OpKind::Reveal)), Err(OpKind::Reveal));
        assert_eq!(count_ops(kinds(MAX_UPDATES + 1, OpKind::Update)), Err(OpKind::Update));
        assert_eq!(count_ops(kinds(MAX_SWEEPS + 1, OpKind::Sweep)), Err(OpKind::Sweep));
        assert_eq!(count_ops(kinds(MAX_SWEEPS, OpKind::Sweep)), Ok([0, 0, 0, 16]));
    }

    #[test]
    fn updates_are_signed_by_the_current_owner_and_rotate_it() {
        let mut k1 = owner_key(1);
        let owner1 = pubkey_hash(&k1.public_key());
        let new = Record::new(b"alice", d(20), d(21), d(22)).unwrap();
        let update = NameOp::update(new.clone(), &mut k1).unwrap();
        assert!(update.verify_owner(&owner1));
        // Wrong current owner, wrong key, tampered record.
        assert!(!update.verify_owner(&d(99)));
        let mut k2 = owner_key(2);
        let by_other = NameOp::update(new.clone(), &mut k2).unwrap();
        assert!(!by_other.verify_owner(&owner1));
        if let NameOp::Update { record, pubkey, signature } = update.clone() {
            let mut tampered = record.clone();
            tampered.value = d(5);
            assert!(!NameOp::Update { record: tampered, pubkey, signature: signature.clone() }.verify_owner(&owner1));
            // Keeping the same owner is refused: every signed operation rotates the key.
            let same = Record::new(b"alice", owner1, d(21), d(22)).unwrap();
            let op = NameOp::update(same, &mut k1).unwrap();
            assert!(!op.verify_owner(&owner1));
            // The message is domain separated from the leaf value.
            assert_ne!(update_message(&record), record.leaf_value());
        } else {
            unreachable!()
        }
        // Operations without a signature pass the owner check.
        assert!(NameOp::Commit { commit: d(1), memo: crate::transaction::memo5(d(2)) }.verify_owner(&d(3)));
        assert!(NameOp::Reveal { record: new, salt: d(1), commit: 0 }.verify_owner(&d(3)));
    }

    #[test]
    fn applies_and_undoes_block_sections() {
        use crate::names::BlockNameOp as Op;
        let (_dir, env, set) = setup("apply");
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        utxo.add(&mut wtxn, &d(1)).unwrap();
        let root0 = utxo.root(&wtxn).unwrap();
        // Block 10: two commits at positions 1 and 2.
        let ops10 = [
            Op::Commit { commit: d(10), memo: crate::transaction::memo5(d(11)) },
            Op::Commit { commit: d(12), memo: crate::transaction::memo5(d(13)) },
        ];
        let u10 = set.apply(&utxo, &mut wtxn, 10, &ops10, &[]).unwrap();
        assert_eq!(u10.commits.len(), 2);
        assert_eq!(utxo.next_position(&wtxn).unwrap(), 3);
        assert_eq!(set.commit_at(&wtxn, 2).unwrap(), Some(Commit { hash: d(12), height: 10 }));
        let root10 = utxo.root(&wtxn).unwrap();
        assert_ne!(root10, root0);
        // Block 22: reveal at position 1, then update the name.
        let alice = record("alice", 20);
        let alice2 = record("alice", 30);
        let ops22 = [Op::Reveal { record: alice.clone(), commit: 1 }, Op::Update(alice2.clone())];
        let u22 = set.apply(&utxo, &mut wtxn, 22, &ops22, &[]).unwrap();
        // The commit's memo slot: its memo, then amount zero.
        let slot11 = crate::transaction::memo_slot(&crate::transaction::memo5(d(11)), 0);
        assert_eq!(u22.consumed, vec![(1, Commit { hash: d(10), height: 10 }, slot11)]);
        assert_eq!(u22.registered, vec![alice.key().unwrap()]);
        assert_eq!(u22.updated, vec![alice.clone()]);
        assert_eq!(set.lookup(&wtxn, b"alice").unwrap(), Some(alice2.clone()));
        assert!(utxo.output_at(&wtxn, 1).unwrap().is_none());
        assert_eq!(utxo.name_root(&wtxn).unwrap(), set.root(&wtxn).unwrap());
        let root22 = utxo.root(&wtxn).unwrap();
        // Block 300: sweep position 2.
        let u300 = set.apply(&utxo, &mut wtxn, 300, &[], &[2]).unwrap();
        assert_eq!(u300.consumed.len(), 1);
        assert!(set.commit_at(&wtxn, 2).unwrap().is_none());
        let root300 = utxo.root(&wtxn).unwrap();
        // Refusals: the chain's checks without the witnesses.
        let err = |r: core::result::Result<NameUndo, ApplyError>| r.expect_err("refused");
        assert!(matches!(err(set.apply(&utxo, &mut wtxn, 301, &[], &[2])), ApplyError::NoCommit));
        assert!(matches!(
            err(set.apply(&utxo, &mut wtxn, 301, &[Op::Reveal { record: record("bob", 1), commit: 2 }], &[])),
            ApplyError::NoCommit
        ));
        assert!(matches!(
            err(set.apply(&utxo, &mut wtxn, 301, &[Op::Update(record("bob", 1))], &[])),
            ApplyError::NotRegistered
        ));
        let c = [Op::Commit { commit: d(40), memo: crate::transaction::memo5(d(41)) }];
        set.apply(&utxo, &mut wtxn, 301, &c, &[]).unwrap();
        assert!(matches!(
            err(set.apply(&utxo, &mut wtxn, 302, &[Op::Reveal { record: record("bob", 1), commit: 3 }], &[])),
            ApplyError::Window(301)
        ));
        assert!(matches!(err(set.apply(&utxo, &mut wtxn, 302, &[], &[3])), ApplyError::NotExpired(301)));
        assert!(matches!(
            err(set.apply(&utxo, &mut wtxn, 320, &[Op::Reveal { record: record("alice", 1), commit: 3 }], &[])),
            ApplyError::Registered
        ));
        wtxn.abort();
        // Undo, in reverse, from a fresh application.
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u2").unwrap();
        utxo.add(&mut wtxn, &d(1)).unwrap();
        set.clear(&mut wtxn).unwrap();
        let u10 = set.apply(&utxo, &mut wtxn, 10, &ops10, &[]).unwrap();
        let u22 = set.apply(&utxo, &mut wtxn, 22, &ops22, &[]).unwrap();
        let u300 = set.apply(&utxo, &mut wtxn, 300, &[], &[2]).unwrap();
        assert_eq!(utxo.root(&wtxn).unwrap(), root300);
        let bytes = u22.to_bytes();
        assert_eq!(NameUndo::from_bytes(&bytes), Some(u22.clone()));
        assert!(NameUndo::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        assert_eq!(NameUndo::from_bytes(&NameUndo::default().to_bytes()), Some(NameUndo::default()));
        set.undo(&utxo, &mut wtxn, &u300, 3).unwrap();
        assert_eq!(utxo.root(&wtxn).unwrap(), root22);
        assert_eq!(set.commit_at(&wtxn, 2).unwrap(), Some(Commit { hash: d(12), height: 10 }));
        set.undo(&utxo, &mut wtxn, &u22, 3).unwrap();
        assert_eq!(utxo.root(&wtxn).unwrap(), root10);
        assert_eq!(set.lookup(&wtxn, b"alice").unwrap(), None);
        assert!(utxo.output_at(&wtxn, 1).unwrap().is_some());
        // The block's commits are removed by the caller's truncate.
        utxo.truncate(&mut wtxn, 1, &[commit_leaf(&d(10), 10), commit_leaf(&d(12), 10)]).unwrap();
        set.undo(&utxo, &mut wtxn, &u10, 1).unwrap();
        assert_eq!(utxo.root(&wtxn).unwrap(), root0);
        assert!(set.commits(&wtxn).unwrap().is_empty());
        assert!(set.is_empty(&wtxn).unwrap());
        wtxn.abort();
    }

    /// Scale: `TABMINER_SCALE_NAMES` synthetic names (default a million)
    /// registered in batches, then lookups, proofs and the snapshot's
    /// name-part pass timed over them.
    #[test]
    #[ignore = "registers a million names; run with --release"]
    fn scale() {
        let n: usize = std::env::var("TABMINER_SCALE_NAMES").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
        let dir = TempDir::new("scale");
        let env = open_env(&dir.0, 64 << 30).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let set = NameSet::open(&env, &mut wtxn, "names").unwrap();
        wtxn.commit().unwrap();
        let name_of = |i: usize| format!("n{i:x}").into_bytes();
        let t = std::time::Instant::now();
        let batch = 10_000;
        for start in (0..n).step_by(batch) {
            let mut wtxn = env.write_txn().unwrap();
            for i in start..(start + batch).min(n) {
                let r = Record { name: name_of(i), owner: d(i as u32), value: d(1), memo: d(2) };
                set.register(&mut wtxn, &r).unwrap();
            }
            wtxn.commit().unwrap();
            if (start / batch) % 10 == 9 {
                eprintln!("  {} names in {:?}", start + batch, t.elapsed());
            }
        }
        let insert_time = t.elapsed();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(set.len(&rtxn).unwrap(), n as u64);
        // Lookups and proofs of random names.
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            (rng % n as u64) as usize
        };
        let samples = 2000;
        let t = std::time::Instant::now();
        for _ in 0..samples {
            assert!(set.lookup(&rtxn, &name_of(next())).unwrap().is_some());
        }
        let lookup = t.elapsed() / samples;
        let t = std::time::Instant::now();
        let mut depth = (usize::MAX, 0usize, 0usize);
        for _ in 0..samples {
            let p = set.prove(&rtxn, &name_of(next())).unwrap();
            depth = (depth.0.min(p.depth()), depth.1.max(p.depth()), depth.2 + p.depth());
        }
        let prove = t.elapsed() / samples;
        let t = std::time::Instant::now();
        assert!(set.lookup(&rtxn, b"notregistered").unwrap().is_none());
        let miss = t.elapsed();
        // The snapshot's pass over the buckets, and a full rebuild.
        let t = std::time::Instant::now();
        let parts = set.name_parts(&rtxn).unwrap().len();
        let snapshot = t.elapsed();
        drop(rtxn);
        let t = std::time::Instant::now();
        let mut wtxn = env.write_txn().unwrap();
        set.rebuild_buckets(&mut wtxn).unwrap();
        wtxn.commit().unwrap();
        let rebuild = t.elapsed();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(set.name_parts(&rtxn).unwrap().len(), parts);
        let storage = set.storage(&rtxn).unwrap();
        let bytes: u64 = storage.iter().map(|(_, b, _)| *b).sum();
        println!(
            "{n} names: registered in {insert_time:?} ({:.0}/s); lookup {lookup:?}, miss {miss:?}, proof {prove:?} \
             (depth {} to {}, mean {:.1}); snapshot pass {snapshot:?} over {parts} parts, bucket rebuild {rebuild:?}; {} MB on disk ({:?})",
            n as f64 / insert_time.as_secs_f64(),
            depth.0,
            depth.1,
            depth.2 as f64 / samples as f64,
            bytes >> 20,
            storage.iter().map(|(k, b, e)| format!("{k}: {} MB, {e} entries", b >> 20)).collect::<Vec<_>>()
        );
    }
}
