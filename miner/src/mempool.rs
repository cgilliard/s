//! The memory pool: valid, unconfirmed transactions waiting to be mined.
//!
//! A transaction enters the pool ([`Mempool::insert`]) only if it decodes,
//! spends at least one input, has a non-negative balance (its fee), carries a
//! valid signature on every input, spends outputs the UTXO set holds at the
//! positions its inputs give, and conflicts with nothing already pooled. The proof cannot tell a user
//! transaction from a block reward, so the non-negative fee is this policy
//! rule, not consensus: a negative-balance transaction would be paid out of
//! the miner's reward.
//!
//! A transaction that spends an output a pooled one already spends
//! replaces it (and any other it conflicts with) if its fee is at least
//! theirs together plus [`REPLACEMENT_FEE_PER_BYTE`] per byte of its own
//! size; that is how a wallet cancels a payment. The bump keeps a sender
//! from churning the network with free replacements.
//!
//! When the pool is full, a new transaction with a higher fee per byte
//! evicts the lowest, and the pool's admission minimum rises to the
//! evicted rate plus the increment, decaying back to the floor with a
//! half-life ([`Mempool::admission_fee`]). The oldest transactions, up to
//! [`Policy::protect_bytes`], are never evicted and are admitted whatever
//! that minimum: they are the aged reserve's candidates (`docs/FEES.md`).
//! After every change of tip the pool is revalidated
//! ([`Mempool::revalidate`]): transactions whose inputs are now spent leave
//! the pool but are shelved for a while, and return if a reorganization
//! makes their inputs unspent again. Blocks carry no transactions, so this
//! shelf is the only way a reorganized-out transaction can come back.
//!
//! The miner takes transactions with [`Mempool::select`]: the aged
//! reserve's share of the block to the longest-waiting, the rest by fee
//! rate; it pays itself the subsidy plus their fees.
//!
//! # Name operations
//!
//! A transaction's name operations (see [`crate::names`]) are checked
//! against the registry as the chain would check them, less what only the
//! proof knows: a reveal's commit must be at the position it names, with
//! the hash the name, salt and owner give, and not past its window (one
//! not yet in it is pooled and mined once it is); the name must be free
//! for a reveal and registered for an update, whose signature the current
//! owner must have made. A name and a commit position are claimed by at
//! most one pooled transaction: a second claim is refused rather than
//! replacing the first, since no fee rule makes the two comparable.
//! Revalidation drops transactions whose claims the chain has settled
//! otherwise. The miner takes operations within the block's caps, skipping
//! what does not fit and reveals whose window has not opened.

use std::collections::{BTreeMap, HashMap, VecDeque};

use heed::RoTxn;

use crate::name_trie::Key;
use crate::names::{MAX_REVEAL, NameOp, NameSet, OpKind, commit_hash, count_ops, name_hash};
use crate::pow::Digest;
use crate::transaction::{Commitment, INPUT_SIZE, OUTPUT_SIZE, Transaction};
use crate::utxo::{self, UtxoSet};

/// Why the registry refuses a name operation (the storage errors apart).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameReject {
    /// No commit at the position, or not this reveal's.
    NoCommit,
    /// The commit (made at this height) is past its window.
    Expired(u32),
    Registered,
    NotRegistered,
    /// Not signed by the current owner, or keeping it.
    BadOwner,
    /// The registry could not be read.
    Store,
}

impl core::fmt::Display for NameReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NameReject::NoCommit => f.write_str("no such commit"),
            NameReject::Expired(h) => write!(f, "the commit at height {h} is past its window"),
            NameReject::Registered => f.write_str("the name is registered"),
            NameReject::NotRegistered => f.write_str("the name is not registered"),
            NameReject::BadOwner => f.write_str("not signed by the current owner, or the owner is unchanged"),
            NameReject::Store => f.write_str("the registry could not be read"),
        }
    }
}

/// What a pooled name operation holds for itself: a name, or a commit's
/// position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Claim {
    Name(Key),
    Commit(u64),
}

/// Largest transaction accepted, in bytes (about 50 inputs).
pub const MAX_TX_SIZE: usize = 128 << 10;
/// Default pool capacity in bytes.
pub const DEFAULT_CAPACITY: usize = 64 << 20;
/// Shelved transactions kept, at most.
const SHELF: usize = 1024;
/// Base units per byte a replacement must add over what it replaces
/// (10^-9 coins, at ten decimals).
pub const REPLACEMENT_FEE_PER_BYTE: u64 = 10;
/// Base units per byte a transaction must pay to be pooled at all, so
/// that filling blocks, and the UTXO set, costs something (10^-9 coins,
/// at ten decimals; `docs/FEES.md`).
pub const MIN_FEE_PER_BYTE: u64 = 10;
/// The smallest output pooled: one worth the fee of spending it at that
/// rate, so that nobody fills the UTXO set with outputs no one will spend.
pub const DUST: u64 = (INPUT_SIZE as u64) * MIN_FEE_PER_BYTE;
/// Trace rows a transaction with a policy input may take: it is proven
/// whole in one segment, with its start and end rows and the segment's
/// padding row. About 27 signatures of 16-level keys.
pub const MAX_TX_ROWS: usize = (1 << crate::aggregate::AggregatorParams::MAINNET.segment_log_n) - 1;

/// How long the rolling admission minimum takes to fall halfway back to
/// the floor (`docs/FEES.md`), by default: as Bitcoin's.
pub const HALF_LIFE_SECS: u64 = 12 * 3600;
/// How long a transaction may wait in the pool, by default: then it is
/// dropped, and its id refused for as long again.
pub const EXPIRY_SECS: u64 = 14 * 86400;
/// Expired ids a pool remembers, at most: the oldest are forgotten first.
const MAX_EXPIRED: usize = 100_000;
/// About the size of a block's proof, the rest of a block being space
/// for transactions.
pub const PROOF_BYTES: usize = 205_000;
/// The share of a block's space for transactions the reference miner
/// gives to the longest-waiting ones, by default (`docs/FEES.md`).
pub const RESERVE_PERCENT: usize = 10;
/// The aged reserve, in bytes: about 180 KB, some 60 simple payments.
pub const RESERVE_BYTES: usize = reserve_bytes(crate::chain::ChainParams::MAINNET.max_block_size, RESERVE_PERCENT);

/// The aged reserve of a block of `max_block_size` at `percent` of its
/// space for transactions.
pub const fn reserve_bytes(max_block_size: usize, percent: usize) -> usize {
    max_block_size.saturating_sub(PROOF_BYTES) * percent / 100
}
/// The oldest transactions kept from eviction, by default: about a day
/// of the reserve (some 26 MB), so that in a flood they still age into it.
/// Confirmations a pool remembers for its fee estimates.
const CONFIRMED_KEPT: usize = 5000;
/// How long a confirmation counts for estimates.
const CONFIRMED_FOR: u64 = 7 * 86400;
/// Transactions an estimate needs at or above its rate, else none.
const MIN_SAMPLES: usize = 20;
/// The share of those that must have confirmed in time.
const SUCCESS: f64 = 0.85;
/// The waits estimates are made for: about a block, an hour, a day.
pub const TARGET_BLOCK: u64 = crate::difficulty::IDEAL_BLOCK_TIME as u64;
pub const TARGET_HOUR: u64 = 3600;
pub const TARGET_DAY: u64 = 86400;
pub const PROTECT_BYTES: usize = RESERVE_BYTES * (86_400 / crate::difficulty::IDEAL_BLOCK_TIME as usize);

/// What a pool asks of a transaction beyond validity (`docs/FEES.md`): a
/// node's own policy, set by its operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The relay floor: base units a byte, below which a transaction is
    /// neither pooled nor relayed.
    pub min_fee_per_byte: u64,
    /// The smallest output pooled: the fee of spending it at the floor.
    pub dust: u64,
    /// The rolling minimum's half-life.
    pub half_life_secs: u64,
    /// How long a transaction may wait in the pool.
    pub expiry_secs: u64,
    /// The oldest transactions' bytes kept from eviction and admitted
    /// whatever the rolling minimum; at most half the pool, so that fees
    /// always compete for the rest.
    pub protect_bytes: usize,
}

impl Policy {
    pub const MAINNET: Policy = Policy {
        min_fee_per_byte: MIN_FEE_PER_BYTE,
        dust: DUST,
        half_life_secs: HALF_LIFE_SECS,
        expiry_secs: EXPIRY_SECS,
        protect_bytes: PROTECT_BYTES,
    };
    /// Anything valid, for tests.
    pub const NONE: Policy = Policy { min_fee_per_byte: 0, dust: 0, ..Policy::MAINNET };

    /// The mainnet policy at another floor, its dust limit following.
    pub const fn with_floor(min_fee_per_byte: u64) -> Policy {
        Policy { min_fee_per_byte, dust: (INPUT_SIZE as u64) * min_fee_per_byte, ..Policy::MAINNET }
    }

    /// The smallest fee a transaction of `inputs` and `outputs` and no
    /// name operations may pay.
    pub fn min_fee(&self, inputs: usize, outputs: usize) -> u64 {
        self.min_fee_for(16 + inputs * INPUT_SIZE + outputs * OUTPUT_SIZE)
    }

    /// The smallest fee a transaction of `size` bytes may pay.
    pub fn min_fee_for(&self, size: usize) -> u64 {
        self.min_fee_per_byte * size as u64
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Already in the pool.
    Known,
    /// Expired from this pool lately: refused for as long again.
    Expired,
    /// No inputs: only a block reward looks like that.
    NoInputs,
    TooLarge(usize),
    /// Outputs exceed inputs.
    NegativeFee,
    /// Zero-amount output or duplicate input.
    Malformed,
    /// Pays less than [`Policy::min_fee`].
    FeeTooLow {
        min: u64,
    },
    /// An output below the pool's dust limit.
    Dust {
        min: u64,
    },
    BadSignature,
    /// A policy input's leaf is not satisfied.
    Policy(crate::policy::PolicyError),
    /// The transaction takes more trace rows than one segment holds: a
    /// policy spend is proven whole, so its signatures are bounded.
    TooManyRows(usize),
    /// An input's output is not unspent.
    UnknownInput(Commitment),
    /// Spends an output pooled transactions spend, without paying enough
    /// to replace them.
    ReplacementFee {
        min: u64,
    },
    /// The pool is full of better-paying transactions.
    Full,
    /// A name operation the registry refuses.
    Name(NameReject),
    /// A name or commit another pooled transaction already claims.
    NameConflict,
}

impl core::fmt::Display for Reject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Reject::Known => f.write_str("already in the pool"),
            Reject::Expired => f.write_str("expired from the pool lately"),
            Reject::NoInputs => f.write_str("no inputs"),
            Reject::TooLarge(n) => write!(f, "{n} bytes exceeds the transaction size limit"),
            Reject::NegativeFee => f.write_str("outputs exceed inputs"),
            Reject::FeeTooLow { min } => write!(f, "fee below the minimum of {min} base units"),
            Reject::Dust { min } => write!(f, "an output is below the dust limit of {min} base units"),
            Reject::Malformed => f.write_str("malformed transaction"),
            Reject::BadSignature => f.write_str("invalid signature"),
            Reject::Policy(e) => write!(f, "policy input: {e}"),
            Reject::TooManyRows(n) => write!(f, "{n} trace rows exceeds a segment: too many signatures"),
            Reject::UnknownInput(_) => f.write_str("spends an output that is not unspent"),
            Reject::ReplacementFee { min } => {
                write!(f, "conflicts with a pooled transaction; a replacement must pay at least {min}")
            }
            Reject::Full => f.write_str("pool is full"),
            Reject::Name(e) => write!(f, "name operation: {e}"),
            Reject::NameConflict => f.write_str("a pooled transaction already claims the name or commit"),
        }
    }
}

impl std::error::Error for Reject {}

#[derive(Clone, Debug)]
pub struct Entry {
    pub tx: Transaction,
    pub txid: Digest,
    pub fee: u64,
    pub size: usize,
    /// When it reached this node, in Unix seconds: its age, kept across
    /// restarts in the saved pool (`docs/FEES.md`).
    pub arrived: u64,
    /// Its place in the order this pool took transactions: the last tie
    /// breaker, arrival times being whole seconds.
    pub order: u64,
    /// What its name operations claim.
    pub claims: Vec<Claim>,
}

impl Entry {
    /// Fee per byte, scaled by 2^16 for integer comparison.
    fn rate(&self) -> u128 {
        rate(self.fee, self.size)
    }

    fn age_key(&self) -> (u64, u64) {
        (self.arrived, self.order)
    }
}

/// Fee per byte, scaled by 2^16.
fn rate(fee: u64, size: usize) -> u128 {
    ((fee as u128) << 16) / size.max(1) as u128
}

/// A scaled rate per byte, rounded up to base units.
fn per_byte(rate: u128) -> u64 {
    rate.div_ceil(1 << 16).min(u64::MAX as u128) as u64
}

pub struct Mempool {
    txs: HashMap<Digest, Entry>,
    /// Spent position to the pooled transaction spending it: the chain
    /// spends by position, and two unspent outputs may share a commitment.
    spends: HashMap<u64, Digest>,
    /// Name or commit to the pooled transaction claiming it.
    claims: HashMap<Claim, Digest>,
    bytes: usize,
    capacity: usize,
    /// Transactions dropped for spent inputs, oldest first, in case a
    /// reorganization brings their inputs back.
    shelf: Vec<Entry>,
    policy: Policy,
    /// Ids expired here, and until when they are refused: so one a peer
    /// still holds does not come back with a fresh age.
    expired: HashMap<Digest, u64>,
    /// The next entry's [`Entry::order`].
    next_order: u64,
    /// Pooled transactions oldest first, by [`Entry::age_key`].
    by_age: BTreeMap<(u64, u64), Digest>,
    /// The rolling admission minimum (a scaled rate) when last settled,
    /// and when, in Unix seconds.
    rolling: u128,
    rolling_at: u64,
    /// Transactions seen confirmed: their rate (base units a byte), how
    /// long they waited here, and when, oldest first.
    confirmed: VecDeque<(u64, u64, u64)>,
}

/// The time now, in Unix seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The cheap checks of a transaction on its own: all but its signatures,
/// which [`Mempool::insert`] checks last, the pool and the UTXO set.
fn check_static(tx: &Transaction, policy: &Policy) -> Result<u64, Reject> {
    if tx.inputs.is_empty() && tx.policy_inputs.is_empty() {
        return Err(Reject::NoInputs);
    }
    if tx.policy_inputs.len() > 1 {
        return Err(Reject::Malformed);
    }
    if !tx.policy_inputs.is_empty() {
        let rows = crate::block_air::tx_rows(tx);
        if rows > MAX_TX_ROWS {
            return Err(Reject::TooManyRows(rows));
        }
    }
    let size = tx.size();
    if size > MAX_TX_SIZE {
        return Err(Reject::TooLarge(size));
    }
    if tx.outputs.iter().any(|o| o.amount == 0) {
        return Err(Reject::Malformed);
    }
    // Name operations: within the caps and well formed.
    if count_ops(tx.ops.iter().map(NameOp::kind)).is_err() || !tx.ops.iter().all(NameOp::is_well_formed) {
        return Err(Reject::Malformed);
    }
    if tx.outputs.iter().any(|o| o.amount < policy.dust) {
        return Err(Reject::Dust { min: policy.dust });
    }
    let mut spent = tx.spent_positions();
    spent.sort_unstable();
    if spent.windows(2).any(|w| w[0] == w[1]) {
        return Err(Reject::Malformed);
    }
    let fee = tx.balance();
    if fee < 0 {
        return Err(Reject::NegativeFee);
    }
    let fee = fee.min(u64::MAX as i128) as u64;
    let min = policy.min_fee_for(size);
    if fee < min {
        return Err(Reject::FeeTooLow { min });
    }
    Ok(fee)
}

/// The name operations of `tx` against the registry, for a block at
/// `height` or later: returns what they claim, distinct within the
/// transaction.
fn check_ops(tx: &Transaction, names: &NameSet, rtxn: &RoTxn, height: u32) -> Result<Vec<Claim>, Reject> {
    let mut claims = Vec::with_capacity(tx.ops.len());
    let name_err = |_: crate::names::Error| Reject::Name(NameReject::Store);
    for op in &tx.ops {
        match op {
            NameOp::Commit { .. } => {}
            NameOp::Reveal { record, salt, commit } => {
                let elements = record.elements().ok_or(Reject::Malformed)?;
                let nh = name_hash(&elements);
                let found = names.commit_at(rtxn, *commit).map_err(name_err)?;
                match found {
                    Some(c) if c.hash == commit_hash(&nh, salt, &record.owner) => {
                        if c.height.saturating_add(MAX_REVEAL) < height {
                            return Err(Reject::Name(NameReject::Expired(c.height)));
                        }
                    }
                    _ => return Err(Reject::Name(NameReject::NoCommit)),
                }
                let key = crate::name_trie::key_of(&nh);
                if names.record(rtxn, key).map_err(name_err)?.is_some() {
                    return Err(Reject::Name(NameReject::Registered));
                }
                claims.push(Claim::Name(key));
                claims.push(Claim::Commit(*commit));
            }
            NameOp::Update { record, .. } => {
                let key = record.key().ok_or(Reject::Malformed)?;
                let current =
                    names.record(rtxn, key).map_err(name_err)?.ok_or(Reject::Name(NameReject::NotRegistered))?;
                if !op.verify_owner(&current.owner) {
                    return Err(Reject::Name(NameReject::BadOwner));
                }
                claims.push(Claim::Name(key));
            }
        }
    }
    let mut sorted = claims.clone();
    sorted.sort_unstable_by_key(|c| match c {
        Claim::Name(k) => (0u8, *k),
        Claim::Commit(p) => (1u8, *p as u128),
    });
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(Reject::Malformed);
    }
    Ok(claims)
}

/// Whether every reveal of `tx` is in its window at `height`.
fn reveals_open(tx: &Transaction, names: &NameSet, rtxn: &RoTxn, height: u32) -> bool {
    tx.ops.iter().all(|op| match op {
        NameOp::Reveal { commit, .. } => {
            matches!(names.commit_at(rtxn, *commit), Ok(Some(c)) if names.in_window(height, c.height))
        }
        _ => true,
    })
}

impl Mempool {
    /// A pool of `capacity` bytes with the mainnet policy.
    pub fn new(capacity: usize) -> Mempool {
        Self::with_policy(capacity, Policy::MAINNET)
    }

    pub fn with_policy(capacity: usize, policy: Policy) -> Mempool {
        Mempool {
            txs: HashMap::new(),
            spends: HashMap::new(),
            claims: HashMap::new(),
            bytes: 0,
            capacity,
            shelf: Vec::new(),
            policy,
            expired: HashMap::new(),
            next_order: 0,
            by_age: BTreeMap::new(),
            rolling: 0,
            rolling_at: 0,
            confirmed: VecDeque::new(),
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The rolling minimum's scaled rate at `now`, at least the floor:
    /// what it was raised to, decayed by half each half-life (a half or a
    /// quarter of it while the pool is under half or a quarter full, as
    /// Bitcoin's), and back at the floor once within half the increment.
    fn rolling_rate(&self, now: u64) -> u128 {
        let floor = (self.policy.min_fee_per_byte as u128) << 16;
        if self.rolling <= floor {
            return floor;
        }
        let mut half_life = self.policy.half_life_secs as f64;
        if self.bytes < self.capacity / 4 {
            half_life /= 4.0;
        } else if self.bytes < self.capacity / 2 {
            half_life /= 2.0;
        }
        let elapsed = now.saturating_sub(self.rolling_at) as f64;
        let excess = if half_life > 0.0 {
            (self.rolling - floor) as f64 * 0.5f64.powf(elapsed / half_life)
        } else {
            0.0
        };
        if excess < ((REPLACEMENT_FEE_PER_BYTE as u128) << 15) as f64 {
            return floor;
        }
        floor + excess as u128
    }

    /// Settles the rolling minimum's decay to `now`, so the pool's fill
    /// from here on sets its pace.
    fn settle(&mut self, now: u64) {
        self.rolling = self.rolling_rate(now);
        self.rolling_at = now;
    }

    /// The pool's admission minimum at `now`, base units a byte: the floor,
    /// or above it while the rolling minimum is up after evictions. Peers
    /// are told it, so they do not send what it would refuse; the aged
    /// reserve's candidates are admitted whatever it is.
    pub fn admission_fee(&self, now: u64) -> u64 {
        per_byte(self.rolling_rate(now))
    }

    /// The bytes kept from eviction: [`Policy::protect_bytes`], at most
    /// half the pool.
    fn protect_budget(&self) -> usize {
        self.policy.protect_bytes.min(self.capacity / 2)
    }

    /// The age key of the youngest protected transaction: the oldest are
    /// protected while their bytes together fit the budget.
    fn protected_until(&self) -> Option<(u64, u64)> {
        let budget = self.protect_budget();
        let mut used = 0;
        let mut last = None;
        for (key, id) in &self.by_age {
            used += self.txs[id].size;
            if used > budget {
                break;
            }
            last = Some(*key);
        }
        last
    }

    /// Whether a transaction of `size` with age key `key` would be among
    /// the protected: what is older and it fit the budget.
    fn would_protect(&self, key: (u64, u64), size: usize) -> bool {
        let budget = self.protect_budget();
        let mut used = size;
        for id in self.by_age.range(..key).map(|(_, id)| id) {
            used += self.txs[id].size;
            if used > budget {
                return false;
            }
        }
        used <= budget
    }

    /// Whether a pooled transaction is kept from eviction: one of the aged
    /// reserve's candidates, relayed whatever a peer's admission minimum.
    pub fn is_protected(&self, txid: &Digest) -> bool {
        match (self.txs.get(txid), self.protected_until()) {
            (Some(e), Some(until)) => e.age_key() <= until,
            _ => false,
        }
    }

    /// A pooled transaction's entry.
    pub fn entry(&self, txid: &Digest) -> Option<&Entry> {
        self.txs.get(txid)
    }

    /// The lowest rate, base units a byte, at which this pool has seen
    /// transactions confirm within `target` seconds: of those it saw at
    /// or above that rate, confirmed lately or still waiting past the
    /// target, [`SUCCESS`] of them in time. `None` until it has seen
    /// enough (a new node).
    pub fn estimate(&self, target: u64, now: u64) -> Option<u64> {
        let mut samples: Vec<(u64, bool)> = self
            .confirmed
            .iter()
            .filter(|(_, _, at)| now.saturating_sub(*at) < CONFIRMED_FOR)
            .map(|(rate, waited, _)| (*rate, *waited <= target))
            .collect();
        samples.extend(
            self.txs.values().filter(|e| now.saturating_sub(e.arrived) > target).map(|e| (per_byte(e.rate()), false)),
        );
        samples.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        let (mut total, mut ok, mut best) = (0usize, 0usize, None);
        for (i, (rate, in_time)) in samples.iter().enumerate() {
            total += 1;
            ok += usize::from(*in_time);
            // Only once every sample at this rate is counted.
            if samples.get(i + 1).is_some_and(|next| next.0 == *rate) || total < MIN_SAMPLES {
                continue;
            }
            if (ok as f64) < SUCCESS * total as f64 {
                break;
            }
            best = Some(*rate);
        }
        best
    }

    /// The rate, base units a byte, to suggest for a transaction of `size`
    /// to confirm within `target` seconds: the admission minimum while the
    /// pool would fit one block with it (nothing ahead to wait for), else
    /// the estimate, the admission minimum until there is one.
    pub fn suggest(&self, target: u64, size: usize, now: u64) -> u64 {
        let admission = self.admission_fee(now);
        let space = crate::chain::ChainParams::MAINNET.max_block_size - PROOF_BYTES;
        if self.bytes + size <= space {
            return admission;
        }
        self.estimate(target, now).map_or(admission, |r| r.max(admission))
    }

    /// Blocks a transaction of `size` arriving now waits at most for the
    /// aged reserve, if miners keep the default: everything pooled is
    /// older and ahead of it.
    pub fn reserve_wait(&self, size: usize) -> u64 {
        (self.bytes + size).div_ceil(RESERVE_BYTES.max(1)) as u64
    }

    /// Notes a transaction seen confirmed at `at`, for estimates.
    fn note_confirmed(&mut self, e: &Entry, at: u64) {
        self.remember_confirmed(per_byte(e.rate()), at.saturating_sub(e.arrived), at);
    }

    /// The confirmations the estimates use, oldest first: rate (base
    /// units a byte), wait and when, as the saved pool keeps them.
    pub fn confirmed(&self) -> impl Iterator<Item = &(u64, u64, u64)> {
        self.confirmed.iter()
    }

    /// A confirmation seen before a restart, or just now.
    pub fn remember_confirmed(&mut self, rate: u64, waited: u64, at: u64) {
        self.confirmed.push_back((rate, waited, at));
        if self.confirmed.len() > CONFIRMED_KEPT {
            self.confirmed.pop_front();
        }
    }

    /// Drops the transactions that have waited [`Policy::expiry_secs`] by
    /// `now`, remembering their ids for as long again, and forgets the ids
    /// whose time is up; returns those dropped.
    pub fn expire(&mut self, now: u64) -> Vec<Digest> {
        self.settle(now);
        let limit = self.policy.expiry_secs;
        let old: Vec<Digest> =
            self.txs.values().filter(|e| now.saturating_sub(e.arrived) >= limit).map(|e| e.txid).collect();
        for id in &old {
            self.remove(id);
            self.expired.insert(*id, now.saturating_add(limit));
        }
        self.expired.retain(|_, until| *until > now);
        if self.expired.len() > MAX_EXPIRED {
            let mut by_time: Vec<(u64, Digest)> = self.expired.iter().map(|(id, u)| (*u, *id)).collect();
            by_time.sort_unstable_by_key(|(u, _)| *u);
            for (_, id) in &by_time[..self.expired.len() - MAX_EXPIRED] {
                self.expired.remove(id);
            }
        }
        old
    }

    /// The ids expired here and until when they are refused, as the saved
    /// pool keeps them.
    pub fn expired(&self) -> impl Iterator<Item = (&Digest, &u64)> {
        self.expired.iter()
    }

    /// An id expired before a restart, refused until `until`.
    pub fn remember_expired(&mut self, id: Digest, until: u64) {
        if self.expired.len() < MAX_EXPIRED {
            self.expired.insert(id, until);
        }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn contains(&self, txid: &Digest) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn get(&self, txid: &Digest) -> Option<&Transaction> {
        self.txs.get(txid).map(|e| &e.tx)
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.txs.values()
    }

    /// Validates and adds `tx`, arrived now, for a block at `height` or
    /// later; returns its id.
    pub fn insert(
        &mut self,
        tx: Transaction,
        utxo: &UtxoSet,
        names: &NameSet,
        rtxn: &RoTxn,
        height: u32,
    ) -> Result<Digest, Reject> {
        self.insert_at(tx, utxo, names, rtxn, height, unix_now())
    }

    /// [`Mempool::insert`], for a transaction that arrived at `arrived`
    /// (Unix seconds): one loaded from the saved pool keeps its age.
    pub fn insert_at(
        &mut self,
        tx: Transaction,
        utxo: &UtxoSet,
        names: &NameSet,
        rtxn: &RoTxn,
        height: u32,
        arrived: u64,
    ) -> Result<Digest, Reject> {
        let txid = tx.txid();
        if self.txs.contains_key(&txid) {
            return Err(Reject::Known);
        }
        if self.expired.get(&txid).is_some_and(|until| *until > unix_now()) {
            return Err(Reject::Expired);
        }
        let fee = check_static(&tx, &self.policy)?;
        let size = tx.size();
        let now = unix_now();
        self.settle(now);
        let order = self.next_order;
        let admission = self.rolling_rate(now);
        if rate(fee, size) < admission && !self.would_protect((arrived, order), size) {
            return Err(Reject::FeeTooLow { min: per_byte(admission).saturating_mul(size as u64) });
        }
        let mut conflicts: Vec<Digest> = Vec::new();
        for (c, p) in tx.spent_commitments().into_iter().zip(tx.spent_positions()) {
            if let Some(other) = self.spends.get(&p)
                && !conflicts.contains(other)
            {
                conflicts.push(*other);
            }
            if !utxo.holds(rtxn, p, &c).map_err(|_| Reject::UnknownInput(c))? {
                return Err(Reject::UnknownInput(c));
            }
        }
        let claims = check_ops(&tx, names, rtxn, height)?;
        // Claims held by the transactions this one replaces are free.
        if claims.iter().any(|c| self.claims.get(c).is_some_and(|holder| !conflicts.contains(holder))) {
            return Err(Reject::NameConflict);
        }
        // Signatures last: they cost about half a millisecond an input, and
        // an input naming an output the set does not hold, which anyone can
        // sign with a key of their own, is turned away above for a lookup.
        if !tx.verify_signatures() {
            return Err(Reject::BadSignature);
        }
        tx.check_policy_inputs(height, |p| utxo.output_at(rtxn, p).ok().flatten().map(|(_, _, h)| h))
            .map_err(Reject::Policy)?;
        if !conflicts.is_empty() {
            let replaced: u64 = conflicts.iter().map(|id| self.txs[id].fee).sum();
            let min = replaced.saturating_add(REPLACEMENT_FEE_PER_BYTE * size as u64);
            if fee < min {
                return Err(Reject::ReplacementFee { min });
            }
        }
        self.next_order += 1;
        let entry = Entry { size, tx, txid, fee, arrived, order, claims };
        // Replaced transactions go first, so their room counts; they are
        // put back if the new one still does not fit.
        let removed: Vec<Entry> = conflicts.iter().filter_map(|id| self.remove(id)).collect();
        if let Err(e) = self.make_room(&entry) {
            for e in removed {
                self.add(e);
            }
            return Err(e);
        }
        self.add(entry);
        Ok(txid)
    }

    /// Evicts the lowest-rate transactions but the protected until `entry`
    /// fits, raising the rolling minimum past each, or refuses if `entry`
    /// pays less than what it would evict.
    fn make_room(&mut self, entry: &Entry) -> Result<(), Reject> {
        if entry.size > self.capacity {
            return Err(Reject::Full);
        }
        if self.bytes + entry.size <= self.capacity {
            return Ok(());
        }
        // Evicting the unprotected, all younger than the protected, leaves
        // the protected as they are.
        let until = self.protected_until();
        let mut victims: Vec<&Entry> = self.txs.values().filter(|e| until.is_none_or(|u| e.age_key() > u)).collect();
        victims.sort_unstable_by_key(|e| (e.rate(), std::cmp::Reverse(e.age_key())));
        let mut room = self.capacity - self.bytes;
        let mut evict = Vec::new();
        for v in victims {
            if room >= entry.size {
                break;
            }
            if v.rate() >= entry.rate() {
                return Err(Reject::Full);
            }
            room += v.size;
            evict.push((v.txid, v.rate()));
        }
        if room < entry.size {
            return Err(Reject::Full);
        }
        let now = unix_now();
        self.settle(now);
        for (id, r) in evict {
            self.remove(&id);
            self.rolling = self.rolling.max(r + ((REPLACEMENT_FEE_PER_BYTE as u128) << 16));
        }
        Ok(())
    }

    fn add(&mut self, entry: Entry) {
        for p in entry.tx.spent_positions() {
            self.spends.insert(p, entry.txid);
        }
        for c in &entry.claims {
            self.claims.insert(*c, entry.txid);
        }
        self.bytes += entry.size;
        self.by_age.insert(entry.age_key(), entry.txid);
        self.txs.insert(entry.txid, entry);
    }

    /// Removes a transaction; returns it if it was pooled.
    pub fn remove(&mut self, txid: &Digest) -> Option<Entry> {
        let entry = self.txs.remove(txid)?;
        for p in entry.tx.spent_positions() {
            self.spends.remove(&p);
        }
        for c in &entry.claims {
            self.claims.remove(c);
        }
        self.bytes -= entry.size;
        self.by_age.remove(&entry.age_key());
        Some(entry)
    }

    /// After the tip changed: drops transactions whose inputs are no longer
    /// unspent or whose name operations the chain has settled otherwise,
    /// shelving them, and brings back shelved ones that became valid again.
    /// `moved` holds, after a reorganization, the positions the new
    /// branch's blocks gave their outputs, by commitment: a shelved
    /// transaction whose input is no longer at its position is moved to
    /// where the same output is now (positions are not signed, so the
    /// signatures stand) and comes back too. Returns how many left and
    /// how many returned.
    pub fn revalidate(
        &mut self,
        utxo: &UtxoSet,
        names: &NameSet,
        rtxn: &RoTxn,
        height: u32,
        moved: &HashMap<Commitment, Vec<u64>>,
        created: &HashMap<Commitment, u64>,
    ) -> utxo::Result<(usize, usize)> {
        let mut gone = Vec::new();
        for e in self.txs.values() {
            for (c, p) in e.tx.spent_commitments().iter().zip(e.tx.spent_positions()) {
                if !utxo.holds(rtxn, p, c)? {
                    gone.push(e.txid);
                    break;
                }
            }
            if !e.tx.ops.is_empty() && check_ops(&e.tx, names, rtxn, height).is_err() && !gone.contains(&e.txid) {
                gone.push(e.txid);
            }
        }
        let now = unix_now();
        for id in &gone {
            if let Some(e) = self.remove(id) {
                // Its outputs made by the new blocks: it confirmed, and its
                // wait, to its block's timestamp (blocks replayed after a
                // restart are not timed by the clock), goes to the
                // estimates; never later than now.
                let at = e.tx.outputs.iter().map(|o| created.get(&o.commitment)).collect::<Option<Vec<_>>>();
                if let Some(at) = at.and_then(|t| t.into_iter().copied().min()) {
                    self.note_confirmed(&e, at.min(now));
                }
                self.shelf.push(e);
            }
        }
        if self.shelf.len() > SHELF {
            let excess = self.shelf.len() - SHELF;
            self.shelf.drain(..excess);
        }
        let mut back = 0;
        let mut keep = Vec::with_capacity(self.shelf.len());
        for mut e in std::mem::take(&mut self.shelf) {
            let mut ok = !self.txs.contains_key(&e.txid);
            let mut positions = e.tx.spent_positions();
            let mut relocated = false;
            for (i, c) in e.tx.spent_commitments().iter().enumerate() {
                if !ok {
                    break;
                }
                let p = positions[i];
                ok = utxo.holds(rtxn, p, c)? && !self.spends.contains_key(&p);
                if !ok && let Some(candidates) = moved.get(c) {
                    // The same output, replayed at a new position.
                    for &q in candidates {
                        if !positions.contains(&q) && !self.spends.contains_key(&q) && utxo.holds(rtxn, q, c)? {
                            positions[i] = q;
                            relocated = true;
                            ok = true;
                            break;
                        }
                    }
                }
            }
            if ok && relocated {
                let mut tx = e.tx.clone();
                tx.set_positions(&positions);
                // A policy input's timelocks count from its output's
                // creation, which the move may have changed.
                ok = tx
                    .check_policy_inputs(height, |p| utxo.output_at(rtxn, p).ok().flatten().map(|(_, _, h)| h))
                    .is_ok();
                if ok {
                    e.tx = tx;
                }
            }
            if ok && !e.tx.ops.is_empty() {
                ok = check_ops(&e.tx, names, rtxn, height).is_ok()
                    && e.claims.iter().all(|c| !self.claims.contains_key(c));
            }
            if ok && self.make_room(&e).is_ok() {
                self.add(e);
                back += 1;
            } else {
                keep.push(e);
            }
        }
        // Shelved entries that are spent for good age out with the shelf.
        self.shelf = keep;
        Ok((gone.len(), back))
    }

    /// Transactions for a block at `height` while `fits` accepts the
    /// running selection (it is called with the candidate list including
    /// the next transaction): first the aged reserve, the longest-waiting
    /// transactions, oldest first, while their bytes together fit
    /// `reserve_bytes` (`docs/FEES.md`: stopping at the first that does not,
    /// so the wait is by age alone; [`MAX_TX_SIZE`] fits the default
    /// reserve whole); then the rest by fee rate, highest first.
    /// Transactions whose name operations would exceed the block's caps,
    /// or whose reveals are not yet in their window, are passed over.
    pub fn select(
        &self,
        names: &NameSet,
        rtxn: &RoTxn,
        height: u32,
        reserve_bytes: usize,
        mut fits: impl FnMut(&[&Transaction]) -> bool,
    ) -> Vec<Transaction> {
        let mut chosen: Vec<&Transaction> = Vec::new();
        let mut taken: std::collections::HashSet<Digest> = std::collections::HashSet::new();
        let mut counts = [0usize; 4];
        // Whether `e` may join, its name operations counted if so.
        let admit = |e: &Entry, counts: &mut [usize; 4]| {
            if e.tx.ops.is_empty() {
                return true;
            }
            let mut with = *counts;
            for op in &e.tx.ops {
                with[op.kind() as usize] += 1;
            }
            let over = [OpKind::Commit, OpKind::Reveal, OpKind::Update].iter().any(|k| with[*k as usize] > k.cap());
            if over || !reveals_open(&e.tx, names, rtxn, height) {
                return false;
            }
            *counts = with;
            true
        };
        let mut reserved = 0;
        for e in self.by_age.values().map(|id| &self.txs[id]) {
            if reserved + e.size > reserve_bytes {
                break;
            }
            let before = counts;
            if !admit(e, &mut counts) {
                continue;
            }
            chosen.push(&e.tx);
            if !fits(&chosen) {
                chosen.pop();
                counts = before;
                break;
            }
            reserved += e.size;
            taken.insert(e.txid);
        }
        let mut entries: Vec<&Entry> = self.txs.values().filter(|e| !taken.contains(&e.txid)).collect();
        entries.sort_by(|a, b| b.rate().cmp(&a.rate()).then(a.age_key().cmp(&b.age_key())));
        for e in entries {
            if !admit(e, &mut counts) {
                continue;
            }
            chosen.push(&e.tx);
            if !fits(&chosen) {
                chosen.pop();
                break;
            }
        }
        chosen.into_iter().cloned().collect()
    }

    /// The expired commits a block at `height` may sweep, by position, at
    /// most the cap.
    pub fn sweeps(names: &NameSet, rtxn: &RoTxn, height: u32) -> Vec<u64> {
        let Some(last) = height.checked_sub(MAX_REVEAL + 1) else {
            return vec![];
        };
        match names.commits_up_to(rtxn, last) {
            Ok(commits) => commits.into_iter().map(|(p, _)| p).take(crate::names::MAX_SWEEPS).collect(),
            Err(_) => vec![],
        }
    }

    /// Sum of the fees of `txs`.
    pub fn fees(txs: &[Transaction]) -> u64 {
        txs.iter().map(|t| t.balance().max(0) as u64).sum()
    }

    /// Ids of pooled transactions, in no particular order.
    pub fn ids(&self) -> Vec<Digest> {
        self.txs.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::NameSet;
    use crate::state_tree::open_env;
    use crate::transaction::{Key, Output, UnsignedTransaction};
    use crate::xmss::PublicKey;

    fn key(tag: u8) -> Key {
        let mut s = [0u8; 32];
        s[0] = tag;
        Key::generate(&s)
    }

    fn pk(tag: u8) -> PublicKey {
        key(tag).public_key()
    }

    /// A transaction spending `amount` from key `tag` to key 100 with `fee`,
    /// the output of key `tag` being at position `tag - 1`.
    fn spend(tag: u8, amount: u64, fee: u64) -> Transaction {
        let mut k = key(tag);
        let outs = vec![Output::new(&pk(100), amount - fee)];
        let mut tx = UnsignedTransaction::new(vec![(k.public_key(), amount)], outs).sign_with(&mut k).unwrap();
        tx.set_positions(&[u64::from(tag) - 1]);
        tx
    }

    /// Two unspent outputs with one commitment (one key hash, one amount)
    /// are two outputs: spending one does not conflict with spending the
    /// other, a transaction may spend both, and a conflict is a second
    /// spend of the same position.
    #[test]
    fn outputs_sharing_a_commitment_are_told_apart() {
        let dir = std::env::temp_dir().join(format!("tabminer-mempool-twins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = open_env(&dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let names = NameSet::open(&env, &mut wtxn, "n").unwrap();
        for _ in 0..2 {
            utxo.add_output(&mut wtxn, &Output::new(&pk(1), 500).block_output(), 0).unwrap();
        }
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        let mut k = key(1);
        let mut spend_at = |positions: &[u64], fee: u64| {
            let inputs = positions.iter().map(|_| (pk(1), 500)).collect();
            let total = 500 * positions.len() as u64;
            // Paid to a key by its first position: the txid covers neither
            // positions nor signatures, so these differ only by output.
            let to = pk(100 + positions[0] as u8);
            let mut tx = UnsignedTransaction::new(inputs, vec![Output::new(&to, total - fee)])
                .sign(|_, _, m| k.sign(m))
                .unwrap();
            tx.set_positions(positions);
            tx
        };
        let mut pool = Mempool::with_policy(1 << 20, Policy::NONE);
        pool.insert(spend_at(&[0], 5), &utxo, &names, &rtxn, 1).unwrap();
        pool.insert(spend_at(&[1], 5), &utxo, &names, &rtxn, 1).unwrap();
        assert_eq!(pool.len(), 2);
        // A second spend of position 0 conflicts with the first.
        let again = spend_at(&[0], 6);
        assert!(matches!(pool.insert(again, &utxo, &names, &rtxn, 1), Err(Reject::ReplacementFee { .. })));
        // Both at once is no duplicate; the same position twice is.
        let mut other = Mempool::with_policy(1 << 20, Policy::NONE);
        other.insert(spend_at(&[0, 1], 5), &utxo, &names, &rtxn, 1).unwrap();
        assert_eq!(other.insert(spend_at(&[1, 1], 5), &utxo, &names, &rtxn, 1), Err(Reject::Malformed));
        drop(rtxn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A reorganization that replays an output at a new position: the
    /// transaction spending it leaves the pool for the shelf, and comes
    /// back spending it where it now is.
    #[test]
    fn shelved_transactions_follow_their_outputs() {
        let dir = std::env::temp_dir().join(format!("tabminer-mempool-moved-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = open_env(&dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let names = NameSet::open(&env, &mut wtxn, "n").unwrap();
        let out = Output::new(&pk(1), 1000);
        utxo.add_output(&mut wtxn, &out.block_output(), 0).unwrap();
        wtxn.commit().unwrap();
        let mut pool = Mempool::with_policy(1 << 20, Policy::NONE);
        let rtxn = env.read_txn().unwrap();
        let id = pool.insert(spend(1, 1000, 5), &utxo, &names, &rtxn, 1).unwrap();
        drop(rtxn);
        // The block that made it is replaced: the output is gone from
        // position 0, and the new branch makes it again at position 2.
        let mut wtxn = env.write_txn().unwrap();
        assert!(utxo.spend_at(&mut wtxn, &out.commitment, 0).unwrap());
        utxo.add_output(&mut wtxn, &Output::new(&pk(9), 7).block_output(), 0).unwrap();
        let at = utxo.add_output(&mut wtxn, &out.block_output(), 0).unwrap();
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(pool.revalidate(&utxo, &names, &rtxn, 2, &HashMap::new(), &HashMap::new()).unwrap(), (1, 0));
        // Told nothing moved, it stays shelved; told where, it comes back.
        assert_eq!(pool.revalidate(&utxo, &names, &rtxn, 2, &HashMap::new(), &HashMap::new()).unwrap(), (0, 0));
        let moved = HashMap::from([(out.commitment, vec![1, at])]);
        assert_eq!(pool.revalidate(&utxo, &names, &rtxn, 2, &moved, &HashMap::new()).unwrap(), (0, 1));
        assert_eq!(pool.get(&id).unwrap().spent_positions(), vec![at]);
        // The signature still holds: positions are not signed.
        assert!(pool.get(&id).unwrap().verify_signatures());
        drop(rtxn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// docs/FEES.md: a transaction that has waited the expiry is dropped
    /// and its id refused for as long again, then forgotten; one loaded
    /// with its arrival time keeps its age; the floor sets the dust limit.
    #[test]
    fn transactions_expire_and_stay_refused() {
        let dir = std::env::temp_dir().join(format!("tabminer-mempool-expiry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = open_env(&dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let names = NameSet::open(&env, &mut wtxn, "n").unwrap();
        for (tag, amount) in [(1u8, 1000u64), (2, 1000)] {
            utxo.add_output(&mut wtxn, &Output::new(&pk(tag), amount).block_output(), 0).unwrap();
        }
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        let policy = Policy { expiry_secs: 100, ..Policy::NONE };
        let mut pool = Mempool::with_policy(1 << 20, policy);
        let now = unix_now();
        // One arrived 150 s ago (as loaded from a saved pool), one now:
        // given, not read from the clock after signing, which a slow
        // machine takes seconds over.
        let old = pool.insert_at(spend(1, 1000, 5), &utxo, &names, &rtxn, 1, now - 150).unwrap();
        let new = pool.insert_at(spend(2, 1000, 5), &utxo, &names, &rtxn, 1, now).unwrap();
        assert_eq!(pool.expire(now), vec![old]);
        assert!(!pool.contains(&old) && pool.contains(&new));
        // Relayed back by a peer: refused, not taken with a fresh age.
        assert_eq!(pool.insert(spend(1, 1000, 5), &utxo, &names, &rtxn, 1), Err(Reject::Expired));
        assert!(pool.expired().any(|(id, until)| *id == old && *until == now + 100));
        // Forgotten once its time is up (when the other has expired too).
        assert_eq!(pool.expire(now + 101), vec![new]);
        assert!(!pool.expired().any(|(id, _)| *id == old));
        assert!(pool.expired().any(|(id, _)| *id == new));
        // The floor sets the dust limit.
        assert_eq!(Policy::with_floor(7).dust, INPUT_SIZE as u64 * 7);
        assert_eq!(Policy::with_floor(MIN_FEE_PER_BYTE), Policy::MAINNET);
        drop(rtxn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// docs/FEES.md: eviction passes over the oldest, raises the pool's
    /// minimum past what it evicted, which then decays back to the floor;
    /// a transaction that would be among the protected is admitted below
    /// it, and only while there is room for it.
    #[test]
    fn the_admission_minimum_rises_decays_and_spares_the_oldest() {
        let dir = std::env::temp_dir().join(format!("tabminer-mempool-rolling-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = open_env(&dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let names = NameSet::open(&env, &mut wtxn, "n").unwrap();
        for tag in 1u8..=7 {
            utxo.add_output(&mut wtxn, &Output::new(&pk(tag), 100_000).block_output(), 0).unwrap();
        }
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        let size = spend(1, 100_000, 1).size();
        // Room for three; the oldest one protected.
        let policy = Policy { min_fee_per_byte: 1, protect_bytes: size, ..Policy::NONE };
        let mut pool = Mempool::with_policy(3 * size, policy);
        let now = unix_now();
        let fee = |per_byte: u64| per_byte * size as u64;
        let a = pool.insert_at(spend(1, 100_000, fee(2)), &utxo, &names, &rtxn, 1, now - 1000).unwrap();
        let b = pool.insert(spend(2, 100_000, fee(4)), &utxo, &names, &rtxn, 1).unwrap();
        let c = pool.insert(spend(3, 100_000, fee(6)), &utxo, &names, &rtxn, 1).unwrap();
        assert!(pool.is_protected(&a) && !pool.is_protected(&b));
        assert_eq!(pool.admission_fee(now), 1);
        // A better payer evicts b, not a, which pays less but is protected.
        let d = pool.insert(spend(4, 100_000, fee(8)), &utxo, &names, &rtxn, 1).unwrap();
        assert!(pool.contains(&a) && !pool.contains(&b) && pool.contains(&c) && pool.contains(&d));
        // The minimum is now b's rate plus the increment.
        let raised = 4 + REPLACEMENT_FEE_PER_BYTE;
        assert_eq!(pool.admission_fee(unix_now()), raised);
        let e = spend(5, 100_000, fee(raised - 1));
        assert_eq!(
            pool.insert(e.clone(), &utxo, &names, &rtxn, 1),
            Err(Reject::FeeTooLow { min: raised * size as u64 })
        );
        // It decays by half each half-life while the pool is full, and is
        // back at the floor in a few days.
        let later = unix_now() + HALF_LIFE_SECS;
        assert_eq!(pool.admission_fee(later), 1 + (raised - 1).div_ceil(2));
        assert_eq!(pool.admission_fee(unix_now() + 7 * 86400), 1);
        // With the pool emptied (mined), a transaction below the minimum
        // that would be protected is admitted; the next is not.
        for id in [a, c, d] {
            pool.remove(&id);
        }
        assert!(pool.admission_fee(unix_now()) > raised - 1);
        let e = pool.insert(e, &utxo, &names, &rtxn, 1).unwrap();
        assert!(pool.is_protected(&e));
        assert!(matches!(
            pool.insert(spend(6, 100_000, fee(raised - 1)), &utxo, &names, &rtxn, 1),
            Err(Reject::FeeTooLow { .. })
        ));
        // The default protects about a day of the aged reserve.
        assert_eq!(RESERVE_BYTES, 179_500);
        assert_eq!(PROTECT_BYTES, 179_500 * 144);
        drop(rtxn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// docs/FEES.md: a block's aged reserve goes to the longest-waiting,
    /// oldest first whatever they pay, while they fit it; the rest by fee
    /// rate.
    #[test]
    fn the_aged_reserve_goes_to_the_longest_waiting() {
        let dir = std::env::temp_dir().join(format!("tabminer-mempool-reserve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = open_env(&dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let names = NameSet::open(&env, &mut wtxn, "n").unwrap();
        for tag in 1u8..=5 {
            utxo.add_output(&mut wtxn, &Output::new(&pk(tag), 1_000_000).block_output(), 0).unwrap();
        }
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        let size = spend(1, 1_000_000, 1).size();
        let mut pool = Mempool::with_policy(1 << 20, Policy::NONE);
        let now = unix_now();
        // The two oldest pay least; the youngest most.
        let ids: Vec<Digest> = [(1u8, 1u64, 500), (2, 2, 400), (3, 30, 300), (4, 40, 200), (5, 50, 100)]
            .into_iter()
            .map(|(tag, per_byte, age)| {
                pool.insert_at(spend(tag, 1_000_000, per_byte * size as u64), &utxo, &names, &rtxn, 1, now - age)
                    .unwrap()
            })
            .collect();
        let pick = |reserve: usize, room: usize| -> Vec<Digest> {
            pool.select(&names, &rtxn, 1, reserve, |c| c.len() <= room).iter().map(|t| t.txid()).collect()
        };
        // Without a reserve, by fee rate alone.
        assert_eq!(pick(0, 3), vec![ids[4], ids[3], ids[2]]);
        // A reserve of one: the oldest first, then by rate.
        assert_eq!(pick(size, 3), vec![ids[0], ids[4], ids[3]]);
        // Of two: both oldest, though the second pays less than the rest.
        assert_eq!(pick(2 * size, 3), vec![ids[0], ids[1], ids[4]]);
        // Of one and a half: one; the next waits its turn, not passed for
        // a smaller younger one.
        assert_eq!(pick(size * 3 / 2, 3), vec![ids[0], ids[4], ids[3]]);
        // A block with room for one only: the oldest.
        assert_eq!(pick(size, 1), vec![ids[0]]);
        // The reserve's share of the space for transactions.
        assert_eq!(reserve_bytes(2_000_000, 10), RESERVE_BYTES);
        assert_eq!(reserve_bytes(2_000_000, 0), 0);
        assert!(MAX_TX_SIZE <= RESERVE_BYTES);
        drop(rtxn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// docs/FEES.md: estimates come from what this pool saw confirm, and
    /// how long it waited; a transaction is noted confirmed when the new
    /// blocks made its outputs, not when a conflict spent its inputs.
    #[test]
    fn estimates_follow_what_confirmed() {
        let dir = std::env::temp_dir().join(format!("tabminer-mempool-estimate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = open_env(&dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let names = NameSet::open(&env, &mut wtxn, "n").unwrap();
        for tag in 1u8..=3 {
            utxo.add_output(&mut wtxn, &Output::new(&pk(tag), 1_000_000).block_output(), 0).unwrap();
        }
        wtxn.commit().unwrap();
        let mut pool = Mempool::new(1 << 20);
        let now = unix_now();
        // Nothing seen: no estimate, and the minimum suggested.
        assert_eq!(pool.estimate(TARGET_BLOCK, now), None);
        assert_eq!(pool.suggest(TARGET_HOUR, 3000, now), MIN_FEE_PER_BYTE);
        assert_eq!(pool.reserve_wait(3000), 1);
        // 30 at 50 a byte confirmed in five minutes, 30 at 20 in over an
        // hour and a half.
        for _ in 0..30 {
            pool.confirmed.push_back((50, 300, now));
            pool.confirmed.push_back((20, 5000, now));
        }
        assert_eq!(pool.estimate(TARGET_BLOCK, now), Some(50));
        assert_eq!(pool.estimate(TARGET_HOUR, now), Some(50));
        assert_eq!(pool.estimate(TARGET_DAY, now), Some(20));
        // A week on, they no longer count.
        assert_eq!(pool.estimate(TARGET_DAY, now + 8 * 86400), None);
        // While the pool would fit a block, nothing is ahead: the minimum.
        assert_eq!(pool.suggest(TARGET_BLOCK, 3000, now), MIN_FEE_PER_BYTE);
        pool.confirmed.clear();

        // Confirmed: its input spent and its output made by the new block.
        let rtxn = env.read_txn().unwrap();
        let t1 = spend(1, 1_000_000, 100_000);
        let t2 = spend(2, 1_000_000, 200_000);
        pool.insert_at(t1.clone(), &utxo, &names, &rtxn, 1, now - 1000).unwrap();
        pool.insert(t2.clone(), &utxo, &names, &rtxn, 1).unwrap();
        drop(rtxn);
        let mut wtxn = env.write_txn().unwrap();
        for tag in 1u8..=2 {
            assert!(utxo.spend_at(&mut wtxn, &Output::new(&pk(tag), 1_000_000).commitment, u64::from(tag) - 1).unwrap());
        }
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        // t1's output was made, by a block 50 s after it arrived (as a
        // block replayed after a restart: not timed by the clock); t2's
        // input went to something else.
        let arrived = pool.entry(&t1.txid()).unwrap().arrived;
        let created: HashMap<Commitment, u64> = [(t1.outputs[0].commitment, arrived + 50)].into_iter().collect();
        assert_eq!(pool.revalidate(&utxo, &names, &rtxn, 2, &HashMap::new(), &created).unwrap(), (2, 0));
        assert_eq!(pool.confirmed().collect::<Vec<_>>(), vec![&(100_000 / t1.size() as u64 + 1, 50, arrived + 50)]);
        // A block timed ahead of the clock counts as now (bounded by the
        // clock around it: a slow runner can take seconds in between).
        let mut ahead = Mempool::new(1 << 20);
        let before = unix_now();
        let t3 = spend(3, 1_000_000, 300_000);
        ahead.insert(t3.clone(), &utxo, &names, &rtxn, 2).unwrap();
        drop(rtxn);
        let mut wtxn = env.write_txn().unwrap();
        assert!(utxo.spend_at(&mut wtxn, &Output::new(&pk(3), 1_000_000).commitment, 2).unwrap());
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        let created: HashMap<Commitment, u64> = [(t3.outputs[0].commitment, unix_now() + 3600)].into_iter().collect();
        assert_eq!(ahead.revalidate(&utxo, &names, &rtxn, 3, &HashMap::new(), &created).unwrap(), (1, 0));
        let (_, waited, at) = *ahead.confirmed().next().unwrap();
        let after = unix_now();
        assert!(before <= at && at <= after && waited <= after - before);
        drop(rtxn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store with an output of 1,000,000 for each of keys `1..=n`.
    fn funded(dir: &std::path::Path, n: u8) -> (heed::Env, UtxoSet, NameSet) {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        let env = open_env(dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let names = NameSet::open(&env, &mut wtxn, "n").unwrap();
        for tag in 1..=n {
            utxo.add_output(&mut wtxn, &Output::new(&pk(tag), 1_000_000).block_output(), 0).unwrap();
        }
        wtxn.commit().unwrap();
        (env, utxo, names)
    }

    /// docs/FEES.md, step 5: a flood of better payers fills the pool. Its
    /// minimum rises with each eviction, the protected oldest stay, a
    /// newcomer at the floor is refused; once the flood is mined the
    /// minimum decays back to the floor, faster in an emptier pool.
    #[test]
    fn a_flood_raises_the_minimum_and_it_decays_back() {
        let dir = std::env::temp_dir().join(format!("tabminer-mempool-flood-{}", std::process::id()));
        let (env, utxo, names) = funded(&dir, 40);
        let rtxn = env.read_txn().unwrap();
        let size = spend(1, 1_000_000, 1).size();
        let floor = MIN_FEE_PER_BYTE;
        // Room for 12; the oldest 4 protected.
        let policy = Policy { protect_bytes: 4 * size, ..Policy::MAINNET };
        let mut pool = Mempool::with_policy(12 * size, policy);
        let now = unix_now();
        // Six waiting at the floor, an hour old and more.
        let waiting: Vec<Digest> = (1..=6u8)
            .map(|t| {
                let fee = floor * size as u64 + u64::from(t);
                pool.insert_at(spend(t, 1_000_000, fee), &utxo, &names, &rtxn, 1, now - 7200 + u64::from(t)).unwrap()
            })
            .collect();
        // The flood: 30, each paying past the minimum the last raised.
        let mut last = pool.admission_fee(now);
        assert_eq!(last, floor);
        let mut flood = Vec::new();
        for (i, t) in (7..=36u8).enumerate() {
            let fee = (20 + 11 * i as u64) * size as u64;
            flood.push(pool.insert(spend(t, 1_000_000, fee), &utxo, &names, &rtxn, 1).unwrap());
            let m = pool.admission_fee(unix_now());
            assert!(m >= last, "the minimum fell during the flood: {last} to {m}");
            last = m;
        }
        assert!(pool.bytes() <= 12 * size);
        // The protected four are still there; the other two were evicted.
        assert!(waiting[..4].iter().all(|id| pool.contains(id)));
        assert!(waiting[4..].iter().all(|id| !pool.contains(id)));
        // The minimum is past what the last eviction paid.
        let evicted = flood.iter().filter(|id| !pool.contains(id)).count();
        assert_eq!(evicted, 30 - 8);
        assert!(last >= 20 + 11 * (evicted as u64 - 1) + REPLACEMENT_FEE_PER_BYTE, "minimum {last}");
        // A newcomer at the floor is refused: the protected space is full.
        assert!(matches!(
            pool.insert(spend(37, 1_000_000, floor * size as u64), &utxo, &names, &rtxn, 1),
            Err(Reject::FeeTooLow { .. })
        ));
        // Still full: half way back to the floor in a half-life.
        let t = unix_now();
        let half = pool.admission_fee(t + HALF_LIFE_SECS);
        assert!(half.abs_diff(floor + (last - floor).div_ceil(2)) <= 1, "{half} after a half-life from {last}");
        // The flood mined: a third full, under half, the minimum halves
        // every half of a half-life.
        for id in &flood {
            pool.remove(id);
        }
        let halved = floor + (last - floor).div_ceil(2);
        let at = pool.admission_fee(t + HALF_LIFE_SECS / 2);
        assert!(at.abs_diff(halved) <= 1, "{at} from {last}, a third full");
        // Two more mined, a sixth full, under a quarter: every quarter.
        pool.remove(&waiting[0]);
        pool.remove(&waiting[1]);
        let at = pool.admission_fee(t + HALF_LIFE_SECS / 4);
        assert!(at.abs_diff(halved) <= 1, "{at} from {last}, a sixth full");
        // Back at the floor within days.
        assert_eq!(pool.admission_fee(t + 3 * 86400), floor);
        drop(rtxn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// docs/FEES.md, step 5: blocks kept full by better payers still take
    /// a backlog at the floor through the aged reserve, each transaction
    /// within the bound: its bytes and those older, over the reserve.
    #[test]
    fn full_blocks_still_confirm_the_floor_within_the_bound() {
        let dir = std::env::temp_dir().join(format!("tabminer-mempool-backlog-{}", std::process::id()));
        let (env, utxo, names) = funded(&dir, 120);
        let rtxn = env.read_txn().unwrap();
        let size = spend(1, 1_000_000, 1).size();
        let floor = MIN_FEE_PER_BYTE;
        let mut pool = Mempool::new(1 << 24);
        let now = unix_now();
        // Ten waiting at the floor, oldest first.
        let backlog: Vec<Digest> = (1..=10u8)
            .map(|t| {
                let fee = floor * size as u64 + u64::from(t);
                pool.insert_at(spend(t, 1_000_000, fee), &utxo, &names, &rtxn, 1, now - 1000 + u64::from(t)).unwrap()
            })
            .collect();
        // Blocks of ten transactions, two of them the reserve; each block,
        // twelve newcomers paying ten times the floor, more than a block.
        let (room, reserve) = (10, 2 * size);
        let mut next = 11u8;
        let mut confirmed_at = HashMap::new();
        for block in 1..=6 {
            for _ in 0..12 {
                if next > 120 {
                    break;
                }
                let fee = 10 * floor * size as u64 + u64::from(next);
                pool.insert(spend(next, 1_000_000, fee), &utxo, &names, &rtxn, 1).unwrap();
                next += 1;
            }
            let chosen = pool.select(&names, &rtxn, 1, reserve, |c| c.len() <= room);
            assert_eq!(chosen.len(), room, "block {block} is full");
            for tx in &chosen {
                let id = tx.txid();
                pool.remove(&id);
                confirmed_at.insert(id, block);
            }
            // Without the reserve, none of the backlog would get in.
            assert!(chosen.iter().filter(|t| backlog.contains(&t.txid())).count() <= 2);
        }
        for (i, id) in backlog.iter().enumerate() {
            let bound = ((i + 1) * size).div_ceil(reserve);
            let at = confirmed_at.get(id).copied();
            assert!(at.is_some_and(|b| b <= bound), "backlog {i} confirmed at {at:?}, bound {bound}");
        }
        // And without a reserve, fee rate alone: the backlog waits.
        let mut pool0 = Mempool::new(1 << 24);
        pool0.insert_at(spend(1, 1_000_000, floor * size as u64 + 1), &utxo, &names, &rtxn, 1, now - 1000).unwrap();
        for t in 11..=22u8 {
            let _ = pool0.insert(spend(t, 1_000_000, 10 * floor * size as u64 + u64::from(t)), &utxo, &names, &rtxn, 1);
        }
        let chosen = pool0.select(&names, &rtxn, 1, 0, |c| c.len() <= room);
        assert!(!chosen.iter().any(|t| t.txid() == backlog[0]));
        drop(rtxn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pool_validates_orders_and_revalidates() {
        let dir = std::env::temp_dir().join(format!("tabminer-mempool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = open_env(&dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let names = NameSet::open(&env, &mut wtxn, "n").unwrap();
        // Outputs: key 1 with 100000, key 2 with 50, key 3 with 10.
        for (tag, amount) in [(1u8, 100_000u64), (2, 50), (3, 10)] {
            utxo.add_output(&mut wtxn, &Output::new(&pk(tag), amount).block_output(), 0).unwrap();
        }
        wtxn.commit().unwrap();

        let mut pool = Mempool::with_policy(1 << 20, Policy::NONE);
        let rtxn = env.read_txn().unwrap();
        // The mainnet policy wants a fee per byte and no dust.
        let mut strict = Mempool::new(1 << 20);
        let min = Policy::MAINNET.min_fee(1, 1);
        assert_eq!(strict.insert(spend(1, 100_000, min - 1), &utxo, &names, &rtxn, 1), Err(Reject::FeeTooLow { min }));
        assert_eq!(
            strict.insert(spend(1, 100_000, 100_000 - DUST + 1), &utxo, &names, &rtxn, 1),
            Err(Reject::Dust { min: DUST })
        );
        strict.insert(spend(1, 100_000, min), &utxo, &names, &rtxn, 1).unwrap();
        let t1 = spend(1, 100_000, 5);
        let t2 = spend(2, 50, 10);
        let id1 = pool.insert(t1.clone(), &utxo, &names, &rtxn, 1).unwrap();
        let id2 = pool.insert(t2.clone(), &utxo, &names, &rtxn, 1).unwrap();
        assert_eq!(pool.insert(t1.clone(), &utxo, &names, &rtxn, 1), Err(Reject::Known));
        assert_eq!(pool.len(), 2);
        // Conflicts, unknown inputs, negative fees, bad signatures, rewards.
        let double = spend(1, 100_000, 6);
        let min = 5 + REPLACEMENT_FEE_PER_BYTE * double.size() as u64;
        assert_eq!(pool.insert(double, &utxo, &names, &rtxn, 1), Err(Reject::ReplacementFee { min }));
        let unknown = spend(4, 7, 1);
        assert!(matches!(pool.insert(unknown, &utxo, &names, &rtxn, 1), Err(Reject::UnknownInput(_))));
        // An unspent output named at the wrong position is unknown too.
        let mut misplaced = spend(3, 10, 1);
        misplaced.set_positions(&[1]);
        assert!(matches!(pool.insert(misplaced, &utxo, &names, &rtxn, 1), Err(Reject::UnknownInput(_))));
        let mut k3 = key(3);
        let generous =
            UnsignedTransaction::new(vec![(pk(3), 10)], vec![Output::new(&pk(100), 11)]).sign_with(&mut k3).unwrap();
        assert_eq!(pool.insert(generous, &utxo, &names, &rtxn, 1), Err(Reject::NegativeFee));
        let mut forged = spend(3, 10, 1);
        forged.outputs[0] = Output::new(&pk(101), 9);
        assert_eq!(pool.insert(forged, &utxo, &names, &rtxn, 1), Err(Reject::BadSignature));
        let reward = UnsignedTransaction::new(vec![], vec![Output::new(&pk(100), 5)])
            .sign(|_, _, _| Err::<crate::transaction::Sig, ()>(()))
            .unwrap();
        assert_eq!(pool.insert(reward, &utxo, &names, &rtxn, 1), Err(Reject::NoInputs));

        // Selection: t2 pays a higher rate (same size, bigger fee).
        let all = pool.select(&names, &rtxn, 1, 0, |_| true);
        assert_eq!(all.iter().map(|t| t.txid()).collect::<Vec<_>>(), vec![id2, id1]);
        assert_eq!(Mempool::fees(&all), 15);
        let one = pool.select(&names, &rtxn, 1, 0, |c| c.len() <= 1);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].txid(), id2);
        drop(rtxn);

        // Spending key 1's output on chain drops t1 to the shelf; undoing
        // the spend brings it back.
        let mut wtxn = env.write_txn().unwrap();
        let c1 = Output::new(&pk(1), 100_000).commitment;
        assert!(utxo.spend_at(&mut wtxn, &c1, 0).unwrap());
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(pool.revalidate(&utxo, &names, &rtxn, 1, &HashMap::new(), &HashMap::new()).unwrap(), (1, 0));
        assert!(!pool.contains(&id1) && pool.contains(&id2));
        drop(rtxn);
        let mut wtxn = env.write_txn().unwrap();
        utxo.unspend(&mut wtxn, &c1, &crate::state_tree::EMPTY, 0, 0).unwrap();
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(pool.revalidate(&utxo, &names, &rtxn, 1, &HashMap::new(), &HashMap::new()).unwrap(), (0, 1));
        assert!(pool.contains(&id1));

        // Replacement: paying the old fee plus the increment per byte
        // takes t1's place.
        let mut k1 = key(1);
        let bump = 5 + REPLACEMENT_FEE_PER_BYTE * t1.size() as u64;
        let mut replacement =
            UnsignedTransaction::new(vec![(k1.public_key(), 100_000)], vec![Output::new(&pk(1), 100_000 - bump)])
                .sign_with(&mut k1)
                .unwrap();
        replacement.set_positions(&[0]);
        let rid = pool.insert(replacement.clone(), &utxo, &names, &rtxn, 1).unwrap();
        assert!(pool.contains(&rid) && !pool.contains(&id1));
        assert_eq!(pool.len(), 2);
        // The original cannot come back.
        assert!(matches!(pool.insert(t1.clone(), &utxo, &names, &rtxn, 1), Err(Reject::ReplacementFee { .. })));
        pool.remove(&rid);
        pool.insert(t1.clone(), &utxo, &names, &rtxn, 1).unwrap();

        // Capacity: a tiny pool evicts the lower rate for a higher one and
        // refuses a lower one.
        let mut small = Mempool::with_policy(t1.size(), Policy::NONE);
        small.insert(t1.clone(), &utxo, &names, &rtxn, 1).unwrap();
        assert_eq!(small.insert(t2.clone(), &utxo, &names, &rtxn, 1), Ok(id2));
        assert!(!small.contains(&id1));
        // The eviction raised the pool's minimum past what t1 pays.
        assert!(matches!(small.insert(t1.clone(), &utxo, &names, &rtxn, 1), Err(Reject::FeeTooLow { .. })));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn name_operations_are_checked_claimed_and_selected() {
        use crate::names::{BlockNameOp, Record, commit_hash, name_hash};
        let dir = std::env::temp_dir().join(format!("tabminer-mempool-names-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = open_env(&dir, 64 << 20).unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let utxo = UtxoSet::open(&env, &mut wtxn, "u").unwrap();
        let names = NameSet::open(&env, &mut wtxn, "n").unwrap();
        // Keys 1 to 6 each own an output of 1000 at positions 0 to 5.
        for tag in 1..=6u8 {
            utxo.add_output(&mut wtxn, &Output::new(&pk(tag), 1000).block_output(), 0).unwrap();
        }
        let d = |n: u32| -> Digest { core::array::from_fn(|i| crate::poseidon2::Fp::new(n * 10 + i as u32)) };
        let mut o1 = key(21);
        let owner1 = crate::transaction::pubkey_hash(&o1.public_key());
        let owner2 = crate::transaction::pubkey_hash(&key(22).public_key());
        let alice = Record::new(b"alice", owner1, d(1), d(2)).unwrap();
        let salt = d(9);
        let c = commit_hash(&name_hash(&alice.elements().unwrap()), &salt, &owner1);
        // The chain made alice's commit at position 6 in block 10, and
        // registered bob.
        names
            .apply(
                &utxo,
                &mut wtxn,
                10,
                &[BlockNameOp::Commit { commit: c, memo: crate::transaction::memo5(d(3)) }],
                &[],
            )
            .unwrap();
        let bob = Record::new(b"bob", owner2, d(4), d(5)).unwrap();
        names.register(&mut wtxn, &bob).unwrap();
        let root = names.root(&wtxn).unwrap();
        utxo.set_name_root(&mut wtxn, &root).unwrap();
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        let mut pool = Mempool::with_policy(1 << 20, Policy::NONE);
        // A transaction from key `tag` carrying `ops`, paying 1 in fee.
        let with = |tag: u8, ops: Vec<NameOp>| {
            let mut k = key(tag);
            let mut tx =
                UnsignedTransaction::with_ops(vec![(k.public_key(), 1000)], vec![Output::new(&pk(100), 999)], ops)
                    .sign_with(&mut k)
                    .unwrap();
            tx.set_positions(&[u64::from(tag) - 1]);
            tx
        };
        let reveal = NameOp::Reveal { record: alice.clone(), salt, commit: 6 };
        // Height 15: the reveal's window has not opened, but it pools.
        let t1 = with(1, vec![reveal.clone()]);
        let id1 = pool.insert(t1.clone(), &utxo, &names, &rtxn, 15).unwrap();
        // Another reveal of the same name, or of the same commit, conflicts.
        let other = Record::new(b"alice", owner2, d(6), d(7)).unwrap();
        let wrong = with(2, vec![NameOp::Reveal { record: other.clone(), salt, commit: 6 }]);
        assert_eq!(pool.insert(wrong, &utxo, &names, &rtxn, 15), Err(Reject::Name(NameReject::NoCommit)));
        let dup = with(2, vec![reveal.clone()]);
        assert_eq!(pool.insert(dup, &utxo, &names, &rtxn, 15), Err(Reject::NameConflict));
        // Wrong position, registered name, update of an unregistered name,
        // update by the wrong key, update keeping the owner.
        let moved = with(2, vec![NameOp::Reveal { record: alice.clone(), salt, commit: 5 }]);
        assert_eq!(pool.insert(moved, &utxo, &names, &rtxn, 15), Err(Reject::Name(NameReject::NoCommit)));
        let bob_c = commit_hash(&name_hash(&bob.elements().unwrap()), &salt, &owner2);
        let mut wtxn = env.write_txn().unwrap();
        names
            .apply(
                &utxo,
                &mut wtxn,
                11,
                &[BlockNameOp::Commit { commit: bob_c, memo: crate::transaction::memo5(d(3)) }],
                &[],
            )
            .unwrap();
        wtxn.commit().unwrap();
        drop(rtxn);
        let rtxn = env.read_txn().unwrap();
        let taken = with(2, vec![NameOp::Reveal { record: bob.clone(), salt, commit: 7 }]);
        assert_eq!(pool.insert(taken, &utxo, &names, &rtxn, 15), Err(Reject::Name(NameReject::Registered)));
        let carol = Record::new(b"carol", owner2, d(1), d(2)).unwrap();
        let unknown = with(2, vec![NameOp::update(carol, &mut o1).unwrap()]);
        assert_eq!(pool.insert(unknown, &utxo, &names, &rtxn, 15), Err(Reject::Name(NameReject::NotRegistered)));
        let bob2 = Record::new(b"bob", owner1, d(8), d(8)).unwrap();
        let forged = with(2, vec![NameOp::update(bob2.clone(), &mut o1).unwrap()]);
        assert_eq!(pool.insert(forged, &utxo, &names, &rtxn, 15), Err(Reject::Name(NameReject::BadOwner)));
        let mut o2 = key(22);
        let same = with(2, vec![NameOp::update(Record::new(b"bob", owner2, d(8), d(8)).unwrap(), &mut o2).unwrap()]);
        assert_eq!(pool.insert(same, &utxo, &names, &rtxn, 15), Err(Reject::Name(NameReject::BadOwner)));
        // A good update of bob, and a second one conflicts.
        let t2 = with(2, vec![NameOp::update(bob2.clone(), &mut o2).unwrap()]);
        let id2 = pool.insert(t2, &utxo, &names, &rtxn, 15).unwrap();
        let again = with(3, vec![NameOp::update(bob2.clone(), &mut o2).unwrap()]);
        assert_eq!(pool.insert(again, &utxo, &names, &rtxn, 15), Err(Reject::NameConflict));
        // Commits pool freely; more than the cap in one transaction do not.
        let t3 = with(3, vec![NameOp::Commit { commit: d(50), memo: crate::transaction::memo5(d(51)) }]);
        let id3 = pool.insert(t3, &utxo, &names, &rtxn, 15).unwrap();
        let many: Vec<NameOp> = (0..crate::names::MAX_COMMITS as u32 + 1)
            .map(|i| NameOp::Commit { commit: d(60 + i), memo: crate::transaction::memo5(d(1)) })
            .collect();
        assert_eq!(pool.insert(with(4, many), &utxo, &names, &rtxn, 15), Err(Reject::Malformed));
        // Selection at height 15 skips the closed reveal; at 22 takes it;
        // the commit cap holds across transactions.
        let ids = |txs: Vec<Transaction>| txs.iter().map(|t| t.txid()).collect::<Vec<_>>();
        let picked = ids(pool.select(&names, &rtxn, 15, 0, |_| true));
        assert!(!picked.contains(&id1) && picked.contains(&id2) && picked.contains(&id3));
        assert!(ids(pool.select(&names, &rtxn, 22, 0, |_| true)).contains(&id1));
        let big: Vec<NameOp> = (0..crate::names::MAX_COMMITS as u32)
            .map(|i| NameOp::Commit { commit: d(70 + i), memo: crate::transaction::memo5(d(1)) })
            .collect();
        let t4 = with(4, big);
        // t4 pays a higher rate than t3? Same fee, larger size: lower rate,
        // so t3 comes first and t4's eight commits do not fit beside it.
        let id4 = pool.insert(t4, &utxo, &names, &rtxn, 15).unwrap();
        let picked = ids(pool.select(&names, &rtxn, 15, 0, |_| true));
        assert!(picked.contains(&id3) && !picked.contains(&id4));
        // Expiry: a reveal whose commit is too old is refused, before the
        // pool's own claims are consulted.
        assert_eq!(
            pool.insert(with(5, vec![reveal.clone()]), &utxo, &names, &rtxn, 10 + MAX_REVEAL + 1),
            Err(Reject::Name(NameReject::Expired(10)))
        );
        assert_eq!(pool.insert(with(5, vec![reveal.clone()]), &utxo, &names, &rtxn, 22), Err(Reject::NameConflict));
        // Sweeps: none before expiry, the commits after.
        assert!(Mempool::sweeps(&names, &rtxn, 10 + MAX_REVEAL).is_empty());
        assert_eq!(Mempool::sweeps(&names, &rtxn, 10 + MAX_REVEAL + 1), vec![6]);
        assert_eq!(Mempool::sweeps(&names, &rtxn, 11 + MAX_REVEAL + 1), vec![6, 7]);
        drop(rtxn);
        // The chain reveals alice from another transaction: t1 is dropped
        // on revalidation, t2 stays until bob's owner changes.
        let mut wtxn = env.write_txn().unwrap();
        names.apply(&utxo, &mut wtxn, 22, &[BlockNameOp::Reveal { record: alice.clone(), commit: 6 }], &[]).unwrap();
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(pool.revalidate(&utxo, &names, &rtxn, 23, &HashMap::new(), &HashMap::new()).unwrap(), (1, 0));
        assert!(!pool.contains(&id1) && pool.contains(&id2));
        drop(rtxn);
        let mut wtxn = env.write_txn().unwrap();
        names.apply(&utxo, &mut wtxn, 23, &[BlockNameOp::Update(bob2.clone())], &[]).unwrap();
        wtxn.commit().unwrap();
        let rtxn = env.read_txn().unwrap();
        assert_eq!(pool.revalidate(&utxo, &names, &rtxn, 24, &HashMap::new(), &HashMap::new()).unwrap(), (1, 0));
        assert!(!pool.contains(&id2));
        drop(rtxn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
