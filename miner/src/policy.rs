//! Spend policies: the conditions under which an output may be spent, for
//! multisig, HTLCs and eltoo payment channels (see `docs/ELTOO.md`).
//!
//! # Model
//!
//! An output's commitment is `H(policy ‖ amount)`. A plain output's policy
//! is the hash of its XMSS public key, exactly as [`crate::transaction`]
//! has always had it; any other policy is the root of a Merkle tree of
//! [`Leaf`]s, each the conjunction of up to [`LEAF_CONDS`] conditions.
//! Disjunction is separate leaves. A spend reveals one leaf, its index and
//! the sibling digests up to the root, with the data satisfying each
//! condition, to the block prover only: the chain sees the spent position
//! and nothing else, and a policy output is indistinguishable from a plain
//! one.
//!
//! | condition | satisfied when |
//! |---|---|
//! | `Thresh` | `m` of the `n` listed key hashes sign, in `body` mode over the transaction's body hash (as plain inputs do) or in `rebindable` mode over `H(DOM_REBIND, channel ‖ state ‖ covered outputs)`, which does not name the position spent |
//! | `Hash` | the spender reveals `p` with [`hash_lock`]`(p)` equal to it |
//! | `After` | the block's height is at least it (CLTV) |
//! | `Older` | the block's height is at least the output's creation height plus it (CSV) |
//! | `State` | the spending transaction's state number exceeds it |
//! | `Outputs` | the spend's covered outputs (a run of the transaction's outputs the input names) are exactly the listed ones, commitment and memo |
//!
//! The covered run is hashed once, [`covered_digest`], and serves both the
//! covenant (its digest is what the leaf holds) and the rebindable
//! message, so the block circuit checks the run against the transaction's
//! outputs with one sponge.
//!
//! A rebindable signature for state `n` uses leaf index `n` of the signer's
//! key, so a stateful key never reuses a leaf within a channel and each
//! party can check the other's index.
//!
//! # Hashing
//!
//! A leaf's hash is `H(DOM_POLICY_LEAF, elements)` over its canonical
//! elements, laid out in whole sponge blocks of eight so the block circuit
//! absorbs one block per row and reads each condition off its own rows
//! (`Leaf::blocks`):
//!
//! ```text
//! header:  [n_conds, tag_0, tag_1, tag_2, tag_3, 0, 0, 0]   tags 1 to 6, 0 for none
//! Thresh:  [mode, m, n, 0, 0, 0, 0, 0] [channel (8), zero in body mode] n * [key hash (8)]
//! Hash:    [hash (8)]
//! After:   [height, 0, ...]
//! Older:   [age, 0, ...]
//! State:   [state, 0, ...]
//! Outputs: [covered digest (8)]
//! ```
//!
//! The tree is [`POLICY_DEPTH`] deep, leaves padded with the empty digest,
//! nodes compressed as the state tree's are. State numbers are below
//! `2^30`: one element, and a rebindable signature's leaf index.
//!
//! # Encoding
//!
//! All integers little-endian.
//!
//! ```text
//! leaf   := u8 n_conds, n_conds * cond
//! cond   := u8 0 | u8 mode (0 body, 1 rebindable) | [channel (32) if rebindable] | u8 m | u8 n | n * key hash (32)
//!         | u8 1 | hash (32)
//!         | u8 2 | u32 height
//!         | u8 3 | u32 age
//!         | u8 4 | u32 state
//!         | u8 5 | u8 k | k * (commitment (32) | memo (32))      (hashed into the leaf as its covered digest)
//! input  := u64 amount | u64 position | u8 leaf index | POLICY_DEPTH * sibling (32)
//!         | u32 state | u8 covered start | u8 covered count | leaf | per condition: witness
//! witness:= Thresh: u8 count, count * (u8 key, pubkey (49), signature)
//!         | Hash: preimage (32)
//!         | others: nothing
//! ```

use crate::poseidon2::{DIGEST, Fp, compress, digest_from_bytes, digest_to_bytes};
use crate::state_tree::EMPTY;
use crate::transaction::{Commitment, Memo, Output, hash_domain, key_commitment, pubkey_hash};
use crate::xmss::{Digest, PublicKey, Signature};

/// Conditions a leaf may hold at most.
pub const LEAF_CONDS: usize = 4;
/// Keys a threshold may list at most.
pub const MAX_KEYS: usize = 32;
/// Outputs a covenant may name at most.
pub const MAX_COVENANT: usize = 128;
/// Depth of the policy tree: up to `2^POLICY_DEPTH` leaves.
pub const POLICY_DEPTH: usize = 4;
/// Leaves a policy may have at most.
pub const MAX_LEAVES: usize = 1 << POLICY_DEPTH;

pub(crate) const DOM_POLICY_LEAF: u32 = 13;
pub(crate) const DOM_HASHLOCK: u32 = 14;
pub(crate) const DOM_REBIND: u32 = 15;
pub(crate) const DOM_COVERED: u32 = 16;
pub(crate) const DOM_SIGNERS: u32 = 17;

const DIGEST_BYTES: usize = DIGEST * 4;

/// What a threshold's signatures cover.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// The transaction's body hash, as a plain input signs.
    Body,
    /// [`rebind_message`] for this channel: the state number and the
    /// covered outputs, never the position spent.
    Rebindable { channel: Digest },
}

/// One condition of a leaf.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Cond {
    Thresh { mode: Mode, m: u8, keys: Vec<Digest> },
    Hash(Digest),
    After(u32),
    Older(u32),
    State(u32),
    Outputs(Vec<(Commitment, Memo)>),
}

/// A conjunction of conditions.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Leaf {
    pub conds: Vec<Cond>,
}

/// A policy: its leaves, in tree order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Policy {
    pub leaves: Vec<Leaf>,
}

/// One signer of a threshold: which listed key, and the proof.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signer {
    pub key: u8,
    pub pubkey: PublicKey,
    pub signature: Signature,
}

/// The data satisfying one condition.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CondWitness {
    Signatures(Vec<Signer>),
    Preimage(Digest),
    None,
}

/// A spend of a policy output: the leaf used, its place in the tree, and
/// what satisfies it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PolicyInput {
    pub amount: u64,
    pub position: u64,
    pub leaf: Leaf,
    pub index: u8,
    pub siblings: [Digest; POLICY_DEPTH],
    /// The spending transaction's state number (below `2^30`), for `State`
    /// conditions and rebindable signatures, whose leaf index it is.
    pub state: u32,
    /// The outputs rebindable signatures cover: a run of the transaction's
    /// outputs, start and count.
    pub covered: (u8, u8),
    /// One per condition of the leaf, in order.
    pub witness: Vec<CondWitness>,
}

/// Why a policy input does not satisfy its leaf.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PolicyError {
    /// The leaf or a condition is out of bounds or malformed.
    Malformed,
    /// A witness does not match its condition's kind, or is missing.
    Witness,
    /// Fewer valid signatures than the threshold, a key not listed, a key
    /// listed twice, or a wrong leaf index for a rebindable signature.
    Signatures,
    Preimage,
    /// A timelock has not passed.
    Locked,
    /// The state number does not exceed the output's.
    State,
    /// The covered outputs are not the covenant's.
    Covenant,
    /// The covered outputs run past the transaction's outputs.
    Covered,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PolicyError::Malformed => "malformed policy leaf",
            PolicyError::Witness => "witness does not fit the condition",
            PolicyError::Signatures => "threshold signatures do not verify",
            PolicyError::Preimage => "wrong hash lock preimage",
            PolicyError::Locked => "timelock has not passed",
            PolicyError::State => "state number does not exceed the output's",
            PolicyError::Covenant => "covered outputs are not the covenant's",
            PolicyError::Covered => "covered outputs run past the transaction's",
        })
    }
}

impl std::error::Error for PolicyError {}

/// State numbers fit one element and a leaf index.
pub const MAX_STATE: u32 = (1 << 30) - 1;

/// The hash lock of a preimage.
pub fn hash_lock(preimage: &Digest) -> Digest {
    hash_domain(DOM_HASHLOCK, preimage)
}

/// The digest of a run of outputs, commitment and memo each: what a
/// covenant holds and a rebindable message covers. `[count, 0, …]`, then
/// a block per commitment and per memo.
pub fn covered_digest(outputs: &[(Commitment, Memo)]) -> Digest {
    let mut v = Vec::with_capacity(DIGEST + 2 * DIGEST * outputs.len());
    v.push(Fp::new(outputs.len() as u32));
    v.extend_from_slice(&[Fp::ZERO; DIGEST - 1]);
    for (c, m) in outputs {
        v.extend_from_slice(c);
        v.extend_from_slice(m);
    }
    hash_domain(DOM_COVERED, &v)
}

/// The message rebindable signatures sign: the channel, the state number
/// and the digest of the outputs the spend must create.
pub fn rebind_message(channel: &Digest, state: u32, outputs: &[(Commitment, Memo)]) -> Digest {
    let mut v = Vec::with_capacity(2 * DIGEST + 1);
    v.extend_from_slice(channel);
    v.push(Fp::new(state));
    v.extend_from_slice(&covered_digest(outputs));
    hash_domain(DOM_REBIND, &v)
}

impl Cond {
    const TAG_THRESH: u8 = 0;
    const TAG_HASH: u8 = 1;
    const TAG_AFTER: u8 = 2;
    const TAG_OLDER: u8 = 3;
    const TAG_STATE: u8 = 4;
    const TAG_OUTPUTS: u8 = 5;

    /// Within bounds and well formed.
    pub fn valid(&self) -> bool {
        match self {
            Cond::Thresh { m, keys, .. } => *m >= 1 && (*m as usize) <= keys.len() && keys.len() <= MAX_KEYS,
            Cond::Outputs(list) => !list.is_empty() && list.len() <= MAX_COVENANT,
            Cond::State(n) => *n <= MAX_STATE,
            _ => true,
        }
    }

    /// The tag the leaf header lists for this condition (1 to 6).
    pub fn tag(&self) -> u32 {
        match self {
            Cond::Thresh { .. } => 1,
            Cond::Hash(_) => 2,
            Cond::After(_) => 3,
            Cond::Older(_) => 4,
            Cond::State(_) => 5,
            Cond::Outputs(_) => 6,
        }
    }

    /// The condition's sponge blocks (see the module's hashing section).
    pub fn blocks(&self, out: &mut Vec<[Fp; DIGEST]>) {
        let word = |x: u32| {
            let mut b = [Fp::ZERO; DIGEST];
            b[0] = Fp::new(x);
            b
        };
        match self {
            Cond::Thresh { mode, m, keys } => {
                let (mode_tag, channel) = match mode {
                    Mode::Body => (0, EMPTY),
                    Mode::Rebindable { channel } => (1, *channel),
                };
                let mut head = [Fp::ZERO; DIGEST];
                head[0] = Fp::new(mode_tag);
                head[1] = Fp::new(*m as u32);
                head[2] = Fp::new(keys.len() as u32);
                out.push(head);
                out.push(channel);
                out.extend(keys.iter().copied());
            }
            Cond::Hash(h) => out.push(*h),
            Cond::After(h) => out.push(word(*h)),
            Cond::Older(d) => out.push(word(*d)),
            Cond::State(n) => out.push(word(*n)),
            Cond::Outputs(list) => out.push(covered_digest(list)),
        }
    }

    /// Signatures the condition checks: its weight.
    pub fn signatures(&self) -> usize {
        match self {
            Cond::Thresh { m, .. } => *m as usize,
            _ => 0,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Cond::Thresh { mode, keys, .. } => {
                1 + 1
                    + if matches!(mode, Mode::Rebindable { .. }) { DIGEST_BYTES } else { 0 }
                    + 2
                    + DIGEST_BYTES * keys.len()
            }
            Cond::Hash(_) => 1 + DIGEST_BYTES,
            Cond::After(_) | Cond::Older(_) => 1 + 4,
            Cond::State(_) => 1 + 4,
            Cond::Outputs(list) => 1 + 1 + 2 * DIGEST_BYTES * list.len(),
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Cond::Thresh { mode, m, keys } => {
                out.push(Self::TAG_THRESH);
                match mode {
                    Mode::Body => out.push(0),
                    Mode::Rebindable { channel } => {
                        out.push(1);
                        out.extend_from_slice(&digest_to_bytes(channel));
                    }
                }
                out.push(*m);
                out.push(keys.len() as u8);
                for k in keys {
                    out.extend_from_slice(&digest_to_bytes(k));
                }
            }
            Cond::Hash(h) => {
                out.push(Self::TAG_HASH);
                out.extend_from_slice(&digest_to_bytes(h));
            }
            Cond::After(h) => {
                out.push(Self::TAG_AFTER);
                out.extend_from_slice(&h.to_le_bytes());
            }
            Cond::Older(d) => {
                out.push(Self::TAG_OLDER);
                out.extend_from_slice(&d.to_le_bytes());
            }
            Cond::State(n) => {
                out.push(Self::TAG_STATE);
                out.extend_from_slice(&n.to_le_bytes());
            }
            Cond::Outputs(list) => {
                out.push(Self::TAG_OUTPUTS);
                out.push(list.len() as u8);
                for (c, m) in list {
                    out.extend_from_slice(&digest_to_bytes(c));
                    out.extend_from_slice(&digest_to_bytes(m));
                }
            }
        }
    }

    fn read(bytes: &[u8]) -> Option<(Cond, &[u8])> {
        let (&tag, rest) = bytes.split_first()?;
        match tag {
            Self::TAG_THRESH => {
                let (&mode_tag, mut rest) = rest.split_first()?;
                let mode = match mode_tag {
                    0 => Mode::Body,
                    1 => {
                        let (c, r) = read_digest(rest)?;
                        rest = r;
                        Mode::Rebindable { channel: c }
                    }
                    _ => return None,
                };
                let (&m, rest) = rest.split_first()?;
                let (&n, mut rest) = rest.split_first()?;
                if n as usize > MAX_KEYS {
                    return None;
                }
                let mut keys = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let (k, r) = read_digest(rest)?;
                    keys.push(k);
                    rest = r;
                }
                Some((Cond::Thresh { mode, m, keys }, rest))
            }
            Self::TAG_HASH => {
                let (h, rest) = read_digest(rest)?;
                Some((Cond::Hash(h), rest))
            }
            Self::TAG_AFTER | Self::TAG_OLDER => {
                let (v, rest) = rest.split_at_checked(4)?;
                let v = u32::from_le_bytes(v.try_into().unwrap());
                Some((if tag == Self::TAG_AFTER { Cond::After(v) } else { Cond::Older(v) }, rest))
            }
            Self::TAG_STATE => {
                let (v, rest) = rest.split_at_checked(4)?;
                Some((Cond::State(u32::from_le_bytes(v.try_into().unwrap())), rest))
            }
            Self::TAG_OUTPUTS => {
                let (&k, mut rest) = rest.split_first()?;
                if k as usize > MAX_COVENANT {
                    return None;
                }
                let mut list = Vec::with_capacity(k as usize);
                for _ in 0..k {
                    let (c, r) = read_digest(rest)?;
                    let (m, r) = read_digest(r)?;
                    list.push((c, m));
                    rest = r;
                }
                Some((Cond::Outputs(list), rest))
            }
            _ => None,
        }
    }
}

fn read_digest(bytes: &[u8]) -> Option<(Digest, &[u8])> {
    let (head, rest) = bytes.split_at_checked(DIGEST_BYTES)?;
    Some((digest_from_bytes(head)?, rest))
}

impl Leaf {
    pub fn new(conds: Vec<Cond>) -> Leaf {
        Leaf { conds }
    }

    /// A plain key's leaf: one body-mode signature.
    pub fn key(key_hash: Digest) -> Leaf {
        Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 1, keys: vec![key_hash] }])
    }

    /// Within bounds and well formed.
    pub fn valid(&self) -> bool {
        !self.conds.is_empty() && self.conds.len() <= LEAF_CONDS && self.conds.iter().all(Cond::valid)
    }

    /// Signatures the leaf checks: the weight of a spend through it.
    pub fn signatures(&self) -> usize {
        self.conds.iter().map(Cond::signatures).sum()
    }

    /// The leaf's sponge blocks: the header, then each condition's.
    pub fn blocks(&self) -> Vec<[Fp; DIGEST]> {
        let mut header = [Fp::ZERO; DIGEST];
        header[0] = Fp::new(self.conds.len() as u32);
        for (i, c) in self.conds.iter().enumerate() {
            header[1 + i] = Fp::new(c.tag());
        }
        let mut out = vec![header];
        for c in &self.conds {
            c.blocks(&mut out);
        }
        out
    }

    /// The canonical elements the leaf hash covers: the blocks flattened.
    pub fn elements(&self) -> Vec<Fp> {
        self.blocks().into_iter().flatten().collect()
    }

    pub fn hash(&self) -> Digest {
        hash_domain(DOM_POLICY_LEAF, &self.elements())
    }

    pub fn size(&self) -> usize {
        1 + self.conds.iter().map(Cond::size).sum::<usize>()
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.conds.len() as u8);
        for c in &self.conds {
            c.write(out);
        }
    }

    pub fn read(bytes: &[u8]) -> Option<(Leaf, &[u8])> {
        let (&n, mut rest) = bytes.split_first()?;
        if n == 0 || n as usize > LEAF_CONDS {
            return None;
        }
        let mut conds = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let (c, r) = Cond::read(rest)?;
            conds.push(c);
            rest = r;
        }
        Some((Leaf { conds }, rest))
    }
}

/// The root over `leaves` (hashed), padded with the empty digest to
/// `2^POLICY_DEPTH` and compressed pairwise.
fn tree_root(leaves: &[Digest]) -> Digest {
    let mut level: Vec<Digest> = leaves.to_vec();
    level.resize(MAX_LEAVES, EMPTY);
    while level.len() > 1 {
        level = level.chunks(2).map(|p| compress(&p[0], &p[1])).collect();
    }
    level[0]
}

/// The root from one leaf's hash, its index and siblings.
pub fn root_from_path(leaf: &Digest, index: usize, siblings: &[Digest; POLICY_DEPTH]) -> Digest {
    let mut node = *leaf;
    for (level, sib) in siblings.iter().enumerate() {
        node = if (index >> level) & 1 == 0 { compress(&node, sib) } else { compress(sib, &node) };
    }
    node
}

impl Policy {
    pub fn new(leaves: Vec<Leaf>) -> Policy {
        Policy { leaves }
    }

    pub fn valid(&self) -> bool {
        !self.leaves.is_empty() && self.leaves.len() <= MAX_LEAVES && self.leaves.iter().all(Leaf::valid)
    }

    /// The policy hash: what an output commits to with the amount.
    pub fn root(&self) -> Digest {
        let hashes: Vec<Digest> = self.leaves.iter().map(Leaf::hash).collect();
        tree_root(&hashes)
    }

    /// The siblings of leaf `index`, bottom up.
    pub fn siblings(&self, index: usize) -> [Digest; POLICY_DEPTH] {
        let mut level: Vec<Digest> = self.leaves.iter().map(Leaf::hash).collect();
        level.resize(MAX_LEAVES, EMPTY);
        let mut out = [EMPTY; POLICY_DEPTH];
        let mut i = index;
        for sib in out.iter_mut() {
            *sib = level[i ^ 1];
            level = level.chunks(2).map(|p| compress(&p[0], &p[1])).collect();
            i >>= 1;
        }
        out
    }

    /// `u8 n_leaves`, then the leaves.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.leaves.len() as u8];
        for l in &self.leaves {
            l.write(&mut out);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Policy> {
        let (&n, mut rest) = bytes.split_first()?;
        if n == 0 || n as usize > MAX_LEAVES {
            return None;
        }
        let mut leaves = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let (l, r) = Leaf::read(rest)?;
            leaves.push(l);
            rest = r;
        }
        rest.is_empty().then_some(Policy { leaves })
    }

    /// An output paying `amount` under this policy.
    pub fn output(&self, amount: u64, memo: Memo) -> Output {
        Output::with_memo(&self.root(), amount, memo)
    }

    /// A spend through leaf `index`, to be given its witness.
    pub fn spend(&self, index: usize, amount: u64, position: u64) -> PolicyInput {
        let leaf = self.leaves[index].clone();
        let witness = leaf
            .conds
            .iter()
            .map(|c| match c {
                Cond::Thresh { .. } => CondWitness::Signatures(Vec::new()),
                Cond::Hash(_) => CondWitness::Preimage(EMPTY),
                _ => CondWitness::None,
            })
            .collect();
        PolicyInput {
            amount,
            position,
            leaf,
            index: index as u8,
            siblings: self.siblings(index),
            state: 0,
            covered: (0, 0),
            witness,
        }
    }
}

impl PolicyInput {
    /// The policy hash this spend reveals.
    pub fn policy(&self) -> Digest {
        root_from_path(&self.leaf.hash(), self.index as usize, &self.siblings)
    }

    /// The commitment of the output this input spends.
    pub fn commitment(&self) -> Commitment {
        key_commitment(&self.policy(), self.amount)
    }

    /// Signatures checked: the weight.
    pub fn signatures(&self) -> usize {
        self.leaf.signatures()
    }

    /// The outputs a rebindable signature of this input covers.
    pub fn covered_outputs(&self, outputs: &[Output]) -> Option<Vec<(Commitment, Memo)>> {
        let (start, count) = (self.covered.0 as usize, self.covered.1 as usize);
        let run = outputs.get(start..start.checked_add(count)?)?;
        Some(run.iter().map(|o| (o.commitment, o.memo)).collect())
    }

    /// Whether the leaf is satisfied: `body` is the transaction's body hash,
    /// `outputs` its outputs, `height` the block's and `created` the spent
    /// output's creation height.
    pub fn check(&self, body: &Digest, outputs: &[Output], height: u32, created: u32) -> Result<(), PolicyError> {
        if !self.leaf.valid() || (self.index as usize) >= MAX_LEAVES || self.witness.len() != self.leaf.conds.len() {
            return Err(PolicyError::Malformed);
        }
        let covered = self.covered_outputs(outputs).ok_or(PolicyError::Covered)?;
        for (cond, w) in self.leaf.conds.iter().zip(&self.witness) {
            match (cond, w) {
                (Cond::Thresh { mode, m, keys }, CondWitness::Signatures(signers)) => {
                    let msg = match mode {
                        Mode::Body => *body,
                        Mode::Rebindable { channel } => rebind_message(channel, self.state, &covered),
                    };
                    let mut seen = [false; MAX_KEYS];
                    let mut good = 0usize;
                    for s in signers {
                        let k = s.key as usize;
                        if k >= keys.len() || seen[k] || pubkey_hash(&s.pubkey) != keys[k] {
                            return Err(PolicyError::Signatures);
                        }
                        if matches!(mode, Mode::Rebindable { .. }) && s.signature.index != self.state as u64 {
                            return Err(PolicyError::Signatures);
                        }
                        if !s.pubkey.verify(&msg, &s.signature) {
                            return Err(PolicyError::Signatures);
                        }
                        seen[k] = true;
                        good += 1;
                    }
                    if good < *m as usize {
                        return Err(PolicyError::Signatures);
                    }
                }
                (Cond::Hash(h), CondWitness::Preimage(p)) => {
                    if hash_lock(p) != *h {
                        return Err(PolicyError::Preimage);
                    }
                }
                (Cond::After(h), CondWitness::None) => {
                    if height < *h {
                        return Err(PolicyError::Locked);
                    }
                }
                (Cond::Older(d), CondWitness::None) => {
                    if (height as u64) < created as u64 + *d as u64 {
                        return Err(PolicyError::Locked);
                    }
                }
                (Cond::State(n), CondWitness::None) => {
                    if self.state > MAX_STATE || self.state <= *n {
                        return Err(PolicyError::State);
                    }
                }
                (Cond::Outputs(list), CondWitness::None) => {
                    if covered != *list {
                        return Err(PolicyError::Covenant);
                    }
                }
                _ => return Err(PolicyError::Witness),
            }
        }
        Ok(())
    }

    pub fn size(&self) -> usize {
        8 + 8 + 1 + POLICY_DEPTH * DIGEST_BYTES + 4 + 2 + self.leaf.size() + self.witness_size()
    }

    fn witness_size(&self) -> usize {
        self.witness
            .iter()
            .map(|w| match w {
                CondWitness::Signatures(s) => {
                    1 + s.iter().map(|s| 1 + PublicKey::SIZE + Signature::size(s.pubkey.height())).sum::<usize>()
                }
                CondWitness::Preimage(_) => DIGEST_BYTES,
                CondWitness::None => 0,
            })
            .sum()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.position.to_le_bytes());
        out.push(self.index);
        for s in &self.siblings {
            out.extend_from_slice(&digest_to_bytes(s));
        }
        out.extend_from_slice(&self.state.to_le_bytes());
        out.push(self.covered.0);
        out.push(self.covered.1);
        self.leaf.write(&mut out);
        for w in &self.witness {
            match w {
                CondWitness::Signatures(signers) => {
                    out.push(signers.len() as u8);
                    for s in signers {
                        out.push(s.key);
                        out.extend_from_slice(&s.pubkey.to_bytes());
                        out.extend_from_slice(&s.signature.to_bytes());
                    }
                }
                CondWitness::Preimage(p) => out.extend_from_slice(&digest_to_bytes(p)),
                CondWitness::None => {}
            }
        }
        out
    }

    /// Parses an input from the front of `bytes`, returning the rest.
    pub fn read(bytes: &[u8]) -> Option<(PolicyInput, &[u8])> {
        let (amount, rest) = bytes.split_at_checked(8)?;
        let amount = u64::from_le_bytes(amount.try_into().unwrap());
        let (position, rest) = rest.split_at_checked(8)?;
        let position = u64::from_le_bytes(position.try_into().unwrap());
        let (&index, mut rest) = rest.split_first()?;
        if index as usize >= MAX_LEAVES {
            return None;
        }
        let mut siblings = [EMPTY; POLICY_DEPTH];
        for s in siblings.iter_mut() {
            let (d, r) = read_digest(rest)?;
            *s = d;
            rest = r;
        }
        let (state, rest) = rest.split_at_checked(4)?;
        let state = u32::from_le_bytes(state.try_into().unwrap());
        if state > MAX_STATE {
            return None;
        }
        let (&start, rest) = rest.split_first()?;
        let (&count, rest) = rest.split_first()?;
        let (leaf, mut rest) = Leaf::read(rest)?;
        let mut witness = Vec::with_capacity(leaf.conds.len());
        for cond in &leaf.conds {
            let w = match cond {
                Cond::Thresh { .. } => {
                    let (&n, mut r) = rest.split_first()?;
                    if n as usize > MAX_KEYS {
                        return None;
                    }
                    let mut signers = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        let (&key, r2) = r.split_first()?;
                        let (pk, r2) = r2.split_at_checked(PublicKey::SIZE)?;
                        let pubkey = PublicKey::from_bytes(pk)?;
                        let (sig, r2) = r2.split_at_checked(Signature::size(pubkey.height()))?;
                        let signature = Signature::from_bytes(sig, pubkey.height())?;
                        signers.push(Signer { key, pubkey, signature });
                        r = r2;
                    }
                    rest = r;
                    CondWitness::Signatures(signers)
                }
                Cond::Hash(_) => {
                    let (p, r) = read_digest(rest)?;
                    rest = r;
                    CondWitness::Preimage(p)
                }
                _ => CondWitness::None,
            };
            witness.push(w);
        }
        Some((PolicyInput { amount, position, leaf, index, siblings, state, covered: (start, count), witness }, rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Key, UnsignedTransaction};

    fn key(tag: u8) -> Key {
        let mut s = [0u8; 32];
        s[0] = tag;
        Key::generate(&s)
    }

    fn d(x: u32) -> Digest {
        let mut v = EMPTY;
        v[0] = Fp::new(x);
        v
    }

    #[test]
    fn leaves_hash_and_encode() {
        let (a, b, c) = (key(1), key(2), key(3));
        let keys: Vec<Digest> = [&a, &b, &c].iter().map(|k| pubkey_hash(&k.public_key())).collect();
        let leaf = Leaf::new(vec![
            Cond::Thresh { mode: Mode::Rebindable { channel: d(9) }, m: 2, keys: keys.clone() },
            Cond::State(5),
            Cond::Outputs(vec![(d(1), d(2)), (d(3), d(4))]),
            Cond::Older(144),
        ]);
        assert!(leaf.valid());
        assert_eq!(leaf.signatures(), 2);
        let mut bytes = Vec::new();
        leaf.write(&mut bytes);
        assert_eq!(bytes.len(), leaf.size());
        let (back, rest) = Leaf::read(&bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(back, leaf);
        assert_eq!(back.hash(), leaf.hash());
        // Any change moves the hash.
        let other = Leaf::new(vec![Cond::State(6)]);
        assert_ne!(other.hash(), Leaf::new(vec![Cond::State(5)]).hash());
        assert_ne!(Leaf::new(vec![Cond::After(5)]).hash(), Leaf::new(vec![Cond::Older(5)]).hash());
        // Bounds.
        assert!(!Leaf::new(vec![]).valid());
        assert!(!Leaf::new(vec![Cond::After(1); LEAF_CONDS + 1]).valid());
        assert!(!Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 2, keys: keys[..1].to_vec() }]).valid());
        assert!(!Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 0, keys: keys.clone() }]).valid());
        assert!(!Leaf::new(vec![Cond::Outputs(vec![])]).valid());
    }

    #[test]
    fn policy_roots_and_paths() {
        let leaves: Vec<Leaf> = (0..5).map(|i| Leaf::new(vec![Cond::After(i)])).collect();
        let p = Policy::new(leaves.clone());
        assert!(p.valid());
        let root = p.root();
        for (i, leaf) in leaves.iter().enumerate() {
            assert_eq!(root_from_path(&leaf.hash(), i, &p.siblings(i)), root);
        }
        assert_ne!(root_from_path(&leaves[0].hash(), 1, &p.siblings(0)), root);
        // The leaf order matters; a one-leaf policy differs from a key hash.
        let swapped = Policy::new(vec![leaves[1].clone(), leaves[0].clone()]);
        assert_ne!(swapped.root(), Policy::new(leaves[..2].to_vec()).root());
        let kh = pubkey_hash(&key(1).public_key());
        assert_ne!(Policy::new(vec![Leaf::key(kh)]).root(), kh);
    }

    #[test]
    fn multisig_htlc_and_channel_leaves_are_checked() {
        let (mut a, mut b, mut c) = (key(1), key(2), key(3));
        let keys: Vec<Digest> = [&a, &b, &c].iter().map(|k| pubkey_hash(&k.public_key())).collect();
        let preimage = d(77);
        let channel = d(5);
        let settle = vec![(d(11), d(12)), (d(13), d(14))];
        let policy = Policy::new(vec![
            // 0: 2-of-3, body mode.
            Leaf::new(vec![Cond::Thresh { mode: Mode::Body, m: 2, keys: keys.clone() }]),
            // 1: HTLC claim; 2: HTLC refund.
            Leaf::new(vec![
                Cond::Hash(hash_lock(&preimage)),
                Cond::Thresh { mode: Mode::Body, m: 1, keys: keys[1..2].to_vec() },
            ]),
            Leaf::new(vec![Cond::After(100), Cond::Thresh { mode: Mode::Body, m: 1, keys: keys[..1].to_vec() }]),
            // 3: eltoo update; 4: settlement covenant.
            Leaf::new(vec![
                Cond::Thresh { mode: Mode::Rebindable { channel }, m: 2, keys: keys[..2].to_vec() },
                Cond::State(3),
            ]),
            Leaf::new(vec![Cond::Older(144), Cond::Outputs(settle.clone())]),
        ]);
        let amount = 1000;
        let outputs: Vec<Output> = vec![
            Output::with_memo(&d(1), 10, d(2)),
            Output::with_memo(&d(11), 500, d(12)),
            Output::with_memo(&d(13), 490, d(14)),
        ];
        // Fix the commitments to the covenant's: with_memo derives them.
        let outputs: Vec<Output> = outputs
            .into_iter()
            .enumerate()
            .map(|(i, mut o)| {
                if i > 0 {
                    o.commitment = settle[i - 1].0;
                }
                o
            })
            .collect();
        let body = UnsignedTransaction::new(vec![], outputs.clone()).body_hash();

        // 2-of-3 body mode.
        let mut spend = policy.spend(0, amount, 7);
        assert_eq!(spend.commitment(), key_commitment(&policy.root(), amount));
        assert_eq!(spend.check(&body, &outputs, 1, 0), Err(PolicyError::Signatures));
        let sa = Signer { key: 0, pubkey: a.public_key(), signature: a.sign(&body).unwrap() };
        let sc = Signer { key: 2, pubkey: c.public_key(), signature: c.sign(&body).unwrap() };
        spend.witness[0] = CondWitness::Signatures(vec![sa.clone(), sc.clone()]);
        assert_eq!(spend.check(&body, &outputs, 1, 0), Ok(()));
        assert_eq!(spend.signatures(), 2);
        // The same key twice does not count twice; a wrong key is refused.
        spend.witness[0] = CondWitness::Signatures(vec![sa.clone(), sa.clone()]);
        assert_eq!(spend.check(&body, &outputs, 1, 0), Err(PolicyError::Signatures));
        let wrong = Signer { key: 1, ..sa.clone() };
        spend.witness[0] = CondWitness::Signatures(vec![wrong, sc.clone()]);
        assert_eq!(spend.check(&body, &outputs, 1, 0), Err(PolicyError::Signatures));
        // Encoding round trip, with signatures.
        spend.witness[0] = CondWitness::Signatures(vec![sa, sc]);
        let bytes = spend.to_bytes();
        assert_eq!(bytes.len(), spend.size());
        let (back, rest) = PolicyInput::read(&bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(back, spend);

        // HTLC claim with the preimage; refund after the timeout.
        let mut claim = policy.spend(1, amount, 7);
        claim.witness[0] = CondWitness::Preimage(preimage);
        claim.witness[1] =
            CondWitness::Signatures(vec![Signer { key: 0, pubkey: b.public_key(), signature: b.sign(&body).unwrap() }]);
        assert_eq!(claim.check(&body, &outputs, 1, 0), Ok(()));
        claim.witness[0] = CondWitness::Preimage(d(78));
        assert_eq!(claim.check(&body, &outputs, 1, 0), Err(PolicyError::Preimage));
        let mut refund = policy.spend(2, amount, 7);
        refund.witness[1] =
            CondWitness::Signatures(vec![Signer { key: 0, pubkey: a.public_key(), signature: a.sign(&body).unwrap() }]);
        assert_eq!(refund.check(&body, &outputs, 99, 0), Err(PolicyError::Locked));
        assert_eq!(refund.check(&body, &outputs, 100, 0), Ok(()));

        // Eltoo update: rebindable signatures with leaf index = state over
        // the covered outputs; the state must exceed the output's.
        let mut update = policy.spend(3, amount, 7);
        update.state = 4;
        update.covered = (1, 2);
        let covered = update.covered_outputs(&outputs).unwrap();
        let msg = rebind_message(&channel, 4, &covered);
        let mut a4 = key(1);
        a4.set_next_index(4);
        let mut b4 = key(2);
        b4.set_next_index(4);
        update.witness[0] = CondWitness::Signatures(vec![
            Signer { key: 0, pubkey: a4.public_key(), signature: a4.sign(&msg).unwrap() },
            Signer { key: 1, pubkey: b4.public_key(), signature: b4.sign(&msg).unwrap() },
        ]);
        assert_eq!(update.check(&body, &outputs, 1, 0), Ok(()));
        // The same signatures spend any earlier state: the body is not covered.
        let other_body = d(123);
        assert_eq!(update.check(&other_body, &outputs, 1, 0), Ok(()));
        // But not a lower state, nor with a leaf index other than the state.
        update.state = 3;
        assert_eq!(update.check(&body, &outputs, 1, 0), Err(PolicyError::Signatures));
        update.state = 4;
        let mut a5 = key(1);
        a5.set_next_index(5);
        update.witness[0] = CondWitness::Signatures(vec![
            Signer { key: 0, pubkey: a5.public_key(), signature: a5.sign(&msg).unwrap() },
            Signer { key: 1, pubkey: b4.public_key(), signature: b4.sign(&msg).unwrap() },
        ]);
        assert_eq!(update.check(&body, &outputs, 1, 0), Err(PolicyError::Signatures));
        // State 3 would fail the ordering even with valid signatures.
        let mut stale = policy.spend(3, amount, 7);
        stale.state = 3;
        stale.covered = (1, 2);
        let msg3 = rebind_message(&channel, 3, &covered);
        let mut a3 = key(1);
        a3.set_next_index(3);
        let mut b3 = key(2);
        b3.set_next_index(3);
        stale.witness[0] = CondWitness::Signatures(vec![
            Signer { key: 0, pubkey: a3.public_key(), signature: a3.sign(&msg3).unwrap() },
            Signer { key: 1, pubkey: b3.public_key(), signature: b3.sign(&msg3).unwrap() },
        ]);
        assert_eq!(stale.check(&body, &outputs, 1, 0), Err(PolicyError::State));

        // Settlement: no signature, after the delay, into the named outputs,
        // which the spend points at as its covered run.
        let mut settle_spend = policy.spend(4, amount, 7);
        settle_spend.covered = (1, 2);
        assert_eq!(settle_spend.signatures(), 0);
        assert_eq!(settle_spend.check(&body, &outputs, 150, 10), Err(PolicyError::Locked));
        assert_eq!(settle_spend.check(&body, &outputs, 154, 10), Ok(()));
        let without = &outputs[..1];
        assert_eq!(settle_spend.check(&body, without, 154, 10), Err(PolicyError::Covered));
        let mut wrong_run = settle_spend.clone();
        wrong_run.covered = (0, 2);
        assert_eq!(wrong_run.check(&body, &outputs, 154, 10), Err(PolicyError::Covenant));
        let mut off = settle_spend.clone();
        off.covered = (2, 5);
        assert_eq!(off.check(&body, &outputs, 154, 10), Err(PolicyError::Covered));
        let _ = (&mut a, &mut b, &mut c);
    }
}
