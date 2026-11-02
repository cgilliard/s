//! Transactions: lists of inputs and outputs signed with XMSS.
//!
//! # Model
//!
//! An output pays `amount` to the key with hash `H(pubkey)`; only its
//! commitment `H(H(pubkey) || amount)` goes on chain. Every output uses a
//! fresh key, so the key hash is a secret of the payer and payee and the
//! commitment hides the amount from everyone else. To spend an output, an
//! input reveals the `pubkey` and `amount` (from which the prover recomputes
//! the commitment and finds the output) and carries an XMSS signature, made
//! with that key, over the transaction body. Transactions themselves travel
//! only to whoever proves the block; the block proof attests to them and
//! reveals nothing about them.
//!
//! The body is the canonical encoding of all inputs (key and amount), all
//! outputs (commitment and amount) and the digests of the name operations,
//! with signatures excluded, laid out in whole sponge blocks per item (see
//! `body_elements`). Every input signs the same body hash, which is also the
//! transaction id.
//!
//! A transaction may carry name operations (see [`crate::names`]): the
//! inputs sign them and pay their fee, the block lists their public part
//! and the proof's name segment applies them.
//!
//! Fees are implicit: a transaction's [`balance`](Transaction::balance) is the
//! sum of input amounts minus the sum of output amounts. It may be negative;
//! that is how a block reward is paid, and there is no special coinbase type.
//! Per-transaction validation does not constrain the balance; the block rule
//! is that the balances of all its transactions sum to minus the block reward.
//!
//! Each input consumes one XMSS leaf of its key, so a key with tree height
//! [`TREE_HEIGHT`] can appear in at most `2^TREE_HEIGHT` inputs in total.
//!
//! # Encoding
//!
//! All multi-byte integers are little-endian. Field elements use the 4-byte
//! canonical encoding from [`crate::poseidon2`].
//!
//! ```text
//! transaction := u32 n_in, n_in * input, u32 n_out, n_out * output, u32 n_ops, n_ops * op
//! input       := pubkey (48) | amount u64 (8) | position u64 (8) | signature (2312)
//! output      := key hash (32) | amount u64 (8) | memo (20)
//! op          := see `crate::names::NameOp`
//! ```
//!
//! An output's memo is eight field elements its owner's wallet fills to find
//! the output again from its seed (see `crate::wallet`); consensus only
//! carries it: it is signed with the body and listed with the commitment.
//!
//! Hashing works on field elements rather than bytes: a 64-bit amount is
//! three limbs of 30, 30 and 4 bits, a public key is its 12 elements and a
//! commitment its 8.

use crate::names::NameOp;
use crate::policy::{PolicyError, PolicyInput};
use crate::poseidon2::{DIGEST, Fp, WIDTH, digest_from_bytes, digest_to_bytes, permute_in_place};
use crate::xmss::{Digest, KeyExhausted, PUB_SEED_LEN, PublicKey, SecretKey, Signature};

/// XMSS tree height of payment keys (16 leaves per key): the height the
/// block circuit verifies today.
pub const TREE_HEIGHT: usize = crate::xmss::PLAIN_HEIGHT;
/// Signature type used in inputs.
pub type Sig = Signature;
/// Secret key type matching [`Sig`].
pub type Key = SecretKey;
/// An output commitment `H(H(pubkey) || amount)`.
pub type Commitment = Digest;
/// Elements of an output's memo: a nonce of four and a recognition tag.
pub const MEMO_LEN: usize = 5;
/// An output's recovery memo: opaque to consensus.
pub type Memo = [Fp; MEMO_LEN];
/// The empty memo.
pub const EMPTY_MEMO: Memo = [Fp::ZERO; MEMO_LEN];

/// Serialized size of a field element.
const FP_BYTES: usize = 4;
/// Serialized size of a digest or commitment.
const DIGEST_BYTES: usize = DIGEST * FP_BYTES;
/// Serialized size of an [`Input`] whose key has [`TREE_HEIGHT`]; an input
/// is [`Input::size`] bytes in general.
pub const INPUT_SIZE: usize = PublicKey::SIZE + 8 + 8 + Signature::size(TREE_HEIGHT);
/// Serialized size of a memo.
pub const MEMO_BYTES: usize = MEMO_LEN * FP_BYTES;
/// Serialized size of an [`Output`].
pub const OUTPUT_SIZE: usize = DIGEST_BYTES + 8 + MEMO_BYTES;

pub(crate) const DOM_PUBKEY: u32 = 1;
pub(crate) const DOM_COMMITMENT: u32 = 2;
pub(crate) const DOM_BODY: u32 = 3;

const MASK30: u64 = (1 << 30) - 1;
const AMOUNT_LIMBS: usize = 3;
const PUBKEY_FPS: usize = DIGEST + PUB_SEED_LEN + 1;

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Domain-separated sponge over the Poseidon2 permutation. The capacity holds
/// the domain tag and the input length, so inputs of different lengths never
/// collide through zero padding.
pub(crate) fn hash_domain(domain: u32, input: &[Fp]) -> Digest {
    let len = input.len() as u64;
    let mut state = [Fp::ZERO; WIDTH];
    state[DIGEST] = Fp::new(domain);
    state[DIGEST + 1] = Fp::new((len & MASK30) as u32);
    state[DIGEST + 2] = Fp::new((len >> 30) as u32);
    let mut absorbed = false;
    for chunk in input.chunks(DIGEST) {
        for (s, x) in state.iter_mut().zip(chunk) {
            *s = s.add(x);
        }
        permute_in_place(&mut state);
        absorbed = true;
    }
    if !absorbed {
        permute_in_place(&mut state);
    }
    state[..DIGEST].try_into().unwrap()
}

/// Splits a `u64` into three field elements of 30, 30 and 4 bits, least
/// significant first. Limbs are kept below 2^30 because the BabyBear modulus
/// is smaller than 2^31.
pub(crate) fn amount_fps(amount: u64) -> [Fp; AMOUNT_LIMBS] {
    [Fp::new((amount & MASK30) as u32), Fp::new(((amount >> 30) & MASK30) as u32), Fp::new((amount >> 60) as u32)]
}

fn pubkey_fps(pk: &PublicKey) -> [Fp; PUBKEY_FPS] {
    let mut out = [Fp::ZERO; PUBKEY_FPS];
    out[..DIGEST].copy_from_slice(&pk.root);
    out[DIGEST..DIGEST + PUB_SEED_LEN].copy_from_slice(&pk.pub_seed);
    out[DIGEST + PUB_SEED_LEN] = Fp::new(pk.height as u32);
    out
}

/// `H(pubkey)`: the root, the public seed and the tree height.
pub fn pubkey_hash(pk: &PublicKey) -> Digest {
    hash_domain(DOM_PUBKEY, &pubkey_fps(pk))
}

/// `H(H(pubkey) || amount)`, the commitment stored in an output.
pub fn commitment(pk: &PublicKey, amount: u64) -> Commitment {
    key_commitment(&pubkey_hash(pk), amount)
}

/// What a leaf, a block's outputs sponge and a body hash take for an
/// output's memo: the memo's five elements, then the amount's three limbs
/// (`docs/AMOUNTS.md`), so that the amount, public, is bound wherever the
/// memo is. An output of amount zero (a name commit) has the memo padded
/// with zeros.
pub fn memo_slot(memo: &Memo, amount: u64) -> Digest {
    let mut slot = [Fp::ZERO; DIGEST];
    slot[..MEMO_LEN].copy_from_slice(memo);
    slot[MEMO_LEN..].copy_from_slice(&amount_fps(amount));
    slot
}

/// The memo and the amount a slot holds; `None` for limbs that are not an
/// amount's (each of the first two below 2^30, the third below 2^4).
pub fn slot_parts(slot: &Digest) -> Option<(Memo, u64)> {
    let memo: Memo = slot[..MEMO_LEN].try_into().unwrap();
    let limb = |i: usize| slot[MEMO_LEN + i].to_canonical() as u64;
    let (lo, mid, hi) = (limb(0), limb(1), limb(2));
    (lo < 1 << 30 && mid < 1 << 30 && hi < 1 << 4).then_some((memo, lo | mid << 30 | hi << 60))
}

/// A memo from a digest's first five elements (tests).
#[cfg(test)]
pub(crate) fn memo5(d: Digest) -> Memo {
    d[..MEMO_LEN].try_into().unwrap()
}

/// A memo's bytes.
pub fn memo_to_bytes(memo: &Memo) -> [u8; MEMO_BYTES] {
    let mut out = [0u8; MEMO_BYTES];
    for (chunk, x) in out.chunks_exact_mut(FP_BYTES).zip(memo) {
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    out
}

/// A memo from its bytes: `None` on a wrong length or a non-canonical
/// element.
pub fn memo_from_bytes(bytes: &[u8]) -> Option<Memo> {
    if bytes.len() != MEMO_BYTES {
        return None;
    }
    let mut out = EMPTY_MEMO;
    for (x, chunk) in out.iter_mut().zip(bytes.chunks_exact(FP_BYTES)) {
        *x = Fp::from_le_bytes(chunk.try_into().unwrap())?;
    }
    Some(out)
}

/// The state tree leaf from a commitment, a memo slot ([`memo_slot`]) and
/// a creation height: the commitment and the slot compressed, then that
/// with the height, so the state root covers the memo and the amount too.
pub fn leaf(commitment: &Commitment, slot: &Digest, height: u32) -> Digest {
    crate::poseidon2::compress(&crate::poseidon2::compress(commitment, slot), &height_digest(height))
}

/// The state tree leaf of an unspent output.
pub fn output_leaf(commitment: &Commitment, memo: &Memo, amount: u64, height: u32) -> Digest {
    leaf(commitment, &memo_slot(memo, amount), height)
}

/// A block height as a digest: one element, then zeros. The second half
/// of a leaf's final compression (see [`leaf`]).
pub fn height_digest(height: u32) -> Digest {
    let mut d = [Fp::ZERO; DIGEST];
    d[0] = Fp::new(height);
    d
}

/// `H(key_hash || amount)`: [`commitment`] from the key's hash.
pub fn key_commitment(key_hash: &Digest, amount: u64) -> Commitment {
    let mut input = [Fp::ZERO; DIGEST + AMOUNT_LIMBS];
    input[..DIGEST].copy_from_slice(key_hash);
    input[DIGEST..].copy_from_slice(&amount_fps(amount));
    hash_domain(DOM_COMMITMENT, &input)
}

fn read_u32(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let (head, rest) = bytes.split_at_checked(4)?;
    Some((u32::from_le_bytes(head.try_into().unwrap()), rest))
}

fn read_u64(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (head, rest) = bytes.split_at_checked(8)?;
    Some((u64::from_le_bytes(head.try_into().unwrap()), rest))
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A spend of an existing output: the revealed key and amount plus a
/// signature over the transaction body, and the output's position in the
/// UTXO set. The position is not signed (nor part of the transaction id):
/// it only tells nodes where to find the output, which they check, so a
/// wallet can correct it after a reorganization moves the output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Input {
    pub pubkey: PublicKey,
    pub amount: u64,
    pub position: u64,
    pub signature: Sig,
}

/// A newly created output: the recipient's key hash and the amount, which
/// travel with the transaction, the commitment derived from them, and the
/// memo. The commitment and the memo are all that goes on chain.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Output {
    pub key_hash: Digest,
    pub amount: u64,
    pub commitment: Commitment,
    pub memo: Memo,
}

/// A transaction with signed inputs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    pub inputs: Vec<Input>,
    /// Spends of policy outputs (see [`crate::policy`]), after the plain
    /// inputs in the body and in position order.
    pub policy_inputs: Vec<PolicyInput>,
    pub outputs: Vec<Output>,
    /// Name operations, signed by the inputs.
    pub ops: Vec<NameOp>,
}

/// A transaction whose inputs have not been signed yet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnsignedTransaction {
    /// Revealed key and amount of each output being spent.
    pub inputs: Vec<(PublicKey, u64)>,
    /// Policy spends, with or without their witnesses yet.
    pub policy_inputs: Vec<PolicyInput>,
    pub outputs: Vec<Output>,
    pub ops: Vec<NameOp>,
}

impl Output {
    /// Creates an output paying `amount` to `pk`, with an empty memo.
    pub fn new(pk: &PublicKey, amount: u64) -> Output {
        Output::to_key_hash(&pubkey_hash(pk), amount)
    }

    /// Creates an output paying `amount` to the key with hash `key_hash`,
    /// with an empty memo.
    pub fn to_key_hash(key_hash: &Digest, amount: u64) -> Output {
        Output::with_memo(key_hash, amount, EMPTY_MEMO)
    }

    /// The part a block lists: the commitment, the memo and the amount.
    pub fn block_output(&self) -> crate::block::BlockOutput {
        crate::block::BlockOutput { commitment: self.commitment, memo: self.memo, amount: self.amount }
    }

    /// Its memo slot ([`memo_slot`]).
    pub fn slot(&self) -> Digest {
        memo_slot(&self.memo, self.amount)
    }

    /// Creates an output with a memo.
    pub fn with_memo(key_hash: &Digest, amount: u64, memo: Memo) -> Output {
        Output { key_hash: *key_hash, amount, commitment: key_commitment(key_hash, amount), memo }
    }

    /// Key hash, amount, memo; the commitment is recomputed on decoding.
    pub fn to_bytes(&self) -> [u8; OUTPUT_SIZE] {
        let mut out = [0u8; OUTPUT_SIZE];
        out[..DIGEST_BYTES].copy_from_slice(&digest_to_bytes(&self.key_hash));
        out[DIGEST_BYTES..DIGEST_BYTES + 8].copy_from_slice(&self.amount.to_le_bytes());
        out[DIGEST_BYTES + 8..].copy_from_slice(&memo_to_bytes(&self.memo));
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Output> {
        if bytes.len() != OUTPUT_SIZE {
            return None;
        }
        let key_hash = digest_from_bytes(&bytes[..DIGEST_BYTES])?;
        let (amount, _) = read_u64(&bytes[DIGEST_BYTES..DIGEST_BYTES + 8])?;
        let memo = memo_from_bytes(&bytes[DIGEST_BYTES + 8..])?;
        Some(Output::with_memo(&key_hash, amount, memo))
    }
}

impl Input {
    /// The commitment of the output this input spends.
    pub fn commitment(&self) -> Commitment {
        commitment(&self.pubkey, self.amount)
    }

    /// Serialized size: the signature's grows with the key's tree height.
    pub fn size(&self) -> usize {
        PublicKey::SIZE + 8 + 8 + Signature::size(self.pubkey.height())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(&self.pubkey.to_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.position.to_le_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    /// Parses an input from the front of `bytes`, returning the rest.
    pub fn read(bytes: &[u8]) -> Option<(Input, &[u8])> {
        let (pk, rest) = bytes.split_at_checked(PublicKey::SIZE)?;
        let pubkey = PublicKey::from_bytes(pk)?;
        let (amount, rest) = read_u64(rest)?;
        let (position, rest) = read_u64(rest)?;
        let (sig, rest) = rest.split_at_checked(Signature::size(pubkey.height()))?;
        let signature = Sig::from_bytes(sig, pubkey.height())?;
        Some((Input { pubkey, amount, position, signature }, rest))
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Input> {
        match Self::read(bytes)? {
            (input, []) => Some(input),
            _ => None,
        }
    }
}

/// Body elements, block aligned so each item is whole sponge blocks:
///
/// ```text
/// [n_in, n_out, n_ops, n_policy, 0, 0, 0, 0]
/// per input:        [root(8)] [pub_seed(4), amount lo30, mid30, hi4, 0]
/// per policy input: [policy(8)] [0, 0, 0, 0, amount lo30, mid30, hi4, 1]
/// per output:       [commitment(8)] [amount lo30, mid30, hi4, 0, 0, 0, 0, 0] [memo(8)]
/// per op:           [digest(8)]
/// ```
///
/// A policy input contributes what identifies the output it spends, not
/// its witness, so two spends of the same output through different
/// witnesses are the same transaction. A malformed operation (a bad name)
/// contributes a zero digest; such a transaction is invalid regardless.
pub(crate) fn body_elements(
    inputs: &[(PublicKey, u64)],
    policy: &[PolicyInput],
    outputs: &[Output],
    ops: &[NameOp],
) -> Vec<Fp> {
    let mut body = Vec::with_capacity(8 + 16 * (inputs.len() + policy.len()) + 24 * outputs.len() + 8 * ops.len());
    body.push(Fp::from_u64(inputs.len() as u64));
    body.push(Fp::from_u64(outputs.len() as u64));
    body.push(Fp::from_u64(ops.len() as u64));
    body.push(Fp::from_u64(policy.len() as u64));
    body.extend_from_slice(&[Fp::ZERO; 4]);
    for (pk, amount) in inputs {
        body.extend_from_slice(&pk.root);
        body.extend_from_slice(&pk.pub_seed);
        body.extend_from_slice(&amount_fps(*amount));
        body.push(Fp::ZERO);
    }
    for p in policy {
        body.extend_from_slice(&p.policy());
        body.extend_from_slice(&[Fp::ZERO; 4]);
        body.extend_from_slice(&amount_fps(p.amount));
        body.push(Fp::ONE);
    }
    for out in outputs {
        body.extend_from_slice(&out.commitment);
        body.extend_from_slice(&amount_fps(out.amount));
        body.extend_from_slice(&[Fp::ZERO; 5]);
        body.extend_from_slice(&out.slot());
    }
    for op in ops {
        body.extend_from_slice(&op.digest().unwrap_or([Fp::ZERO; DIGEST]));
    }
    body
}

/// Hash of the canonical body (see [`body_elements`]).
fn body_hash(inputs: &[(PublicKey, u64)], policy: &[PolicyInput], outputs: &[Output], ops: &[NameOp]) -> Digest {
    hash_domain(DOM_BODY, &body_elements(inputs, policy, outputs, ops))
}

impl UnsignedTransaction {
    /// A transaction without name operations.
    pub fn new(inputs: Vec<(PublicKey, u64)>, outputs: Vec<Output>) -> UnsignedTransaction {
        UnsignedTransaction { inputs, policy_inputs: vec![], outputs, ops: vec![] }
    }

    /// A transaction carrying name operations.
    pub fn with_ops(inputs: Vec<(PublicKey, u64)>, outputs: Vec<Output>, ops: Vec<NameOp>) -> UnsignedTransaction {
        UnsignedTransaction { inputs, policy_inputs: vec![], outputs, ops }
    }

    /// Adds policy spends. Their body-mode signatures are over the body
    /// hash this gives once every input is in place.
    pub fn with_policy_inputs(mut self, policy_inputs: Vec<PolicyInput>) -> UnsignedTransaction {
        self.policy_inputs = policy_inputs;
        self
    }

    /// The body hash every input must sign; equals the final transaction id.
    pub fn body_hash(&self) -> Digest {
        body_hash(&self.inputs, &self.policy_inputs, &self.outputs, &self.ops)
    }

    /// Signs every input. `signer` is called once per input, in order, with
    /// the input index, its public key and the body hash to sign, and must
    /// return a signature made with the matching secret key. Using a closure
    /// lets one key sign several inputs. Positions start at zero; see
    /// [`Transaction::set_positions`].
    pub fn sign<E>(
        self,
        mut signer: impl FnMut(usize, &PublicKey, &Digest) -> Result<Sig, E>,
    ) -> Result<Transaction, E> {
        let msg = self.body_hash();
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for (i, (pubkey, amount)) in self.inputs.into_iter().enumerate() {
            let signature = signer(i, &pubkey, &msg)?;
            inputs.push(Input { pubkey, amount, position: 0, signature });
        }
        Ok(Transaction { inputs, policy_inputs: self.policy_inputs, outputs: self.outputs, ops: self.ops })
    }

    /// Signs every input with the one key `key`, which must own all of them.
    pub fn sign_with(self, key: &mut Key) -> Result<Transaction, SignError> {
        let pk = key.public_key();
        self.sign(|i, input_pk, msg| {
            if *input_pk != pk {
                return Err(SignError::WrongKey(i));
            }
            key.sign(msg).map_err(SignError::Exhausted)
        })
    }
}

/// Errors from [`UnsignedTransaction::sign_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// The key ran out of one-time leaves.
    Exhausted(KeyExhausted),
    /// Input at this index belongs to a different key.
    WrongKey(usize),
}

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignError::Exhausted(e) => write!(f, "{e}"),
            SignError::WrongKey(i) => write!(f, "input {i} is not owned by the signing key"),
        }
    }
}

impl std::error::Error for SignError {}

impl Transaction {
    /// Hash of the body, excluding signatures.
    pub fn body_hash(&self) -> Digest {
        let inputs: Vec<(PublicKey, u64)> = self.inputs.iter().map(|i| (i.pubkey, i.amount)).collect();
        body_hash(&inputs, &self.policy_inputs, &self.outputs, &self.ops)
    }

    /// Transaction id: the body hash.
    pub fn txid(&self) -> Digest {
        self.body_hash()
    }

    /// The unsigned form, for example to re-derive the body.
    pub fn unsigned(&self) -> UnsignedTransaction {
        UnsignedTransaction {
            inputs: self.inputs.iter().map(|i| (i.pubkey, i.amount)).collect(),
            policy_inputs: self.policy_inputs.clone(),
            outputs: self.outputs.clone(),
            ops: self.ops.clone(),
        }
    }

    /// The digests of the name operations, in order; `None` if one has a
    /// malformed name.
    pub fn op_digests(&self) -> Option<Vec<Digest>> {
        self.ops.iter().map(NameOp::digest).collect()
    }

    /// Checks that every input carries a valid signature over the body by
    /// its revealed key. Does not check that the spent outputs exist or are
    /// unspent, and does not constrain the balance.
    pub fn verify_signatures(&self) -> bool {
        let msg = self.body_hash();
        self.inputs.iter().all(|i| i.pubkey.verify(&msg, &i.signature))
    }

    /// Checks every policy input's leaf against this transaction, for a
    /// block at `height`; `created` gives the creation height of the
    /// output at a position (`None` if unknown: unspendable).
    pub fn check_policy_inputs(&self, height: u32, created: impl Fn(u64) -> Option<u32>) -> Result<(), PolicyError> {
        if self.policy_inputs.is_empty() {
            return Ok(());
        }
        let body = self.body_hash();
        for p in &self.policy_inputs {
            let c = created(p.position).ok_or(PolicyError::Locked)?;
            p.check(&body, &self.outputs, height, c)?;
        }
        Ok(())
    }

    /// Signatures the block proof checks for this transaction: its weight
    /// toward block capacity.
    pub fn weight(&self) -> usize {
        self.inputs.len() + self.policy_inputs.iter().map(PolicyInput::signatures).sum::<usize>()
    }

    /// Sets where each input's output is in the UTXO set, in input order
    /// (plain inputs, then policy inputs). Leaves the signatures and the
    /// transaction id unchanged.
    pub fn set_positions(&mut self, positions: &[u64]) {
        assert_eq!(positions.len(), self.inputs.len() + self.policy_inputs.len(), "one position per input");
        let (plain, policy) = positions.split_at(self.inputs.len());
        for (i, p) in self.inputs.iter_mut().zip(plain) {
            i.position = *p;
        }
        for (i, p) in self.policy_inputs.iter_mut().zip(policy) {
            i.position = *p;
        }
    }

    /// Positions of the outputs being spent, in input order (plain inputs,
    /// then policy inputs).
    pub fn spent_positions(&self) -> Vec<u64> {
        self.inputs.iter().map(|i| i.position).chain(self.policy_inputs.iter().map(|p| p.position)).collect()
    }

    /// Commitments of the outputs being spent, in input order.
    pub fn spent_commitments(&self) -> Vec<Commitment> {
        self.inputs
            .iter()
            .map(Input::commitment)
            .chain(self.policy_inputs.iter().map(PolicyInput::commitment))
            .collect()
    }

    /// Sum of input amounts.
    pub fn input_total(&self) -> u128 {
        self.inputs.iter().map(|i| i.amount as u128).sum::<u128>()
            + self.policy_inputs.iter().map(|p| p.amount as u128).sum::<u128>()
    }

    /// Sum of output amounts.
    pub fn output_total(&self) -> u128 {
        self.outputs.iter().map(|o| o.amount as u128).sum()
    }

    /// Inputs minus outputs. Positive is an implicit fee; negative is a
    /// block reward claim, to be checked at the block level.
    pub fn balance(&self) -> i128 {
        self.input_total() as i128 - self.output_total() as i128
    }

    /// Serialized size in bytes.
    pub fn size(&self) -> usize {
        16 + self.inputs.iter().map(Input::size).sum::<usize>()
            + self.policy_inputs.iter().map(PolicyInput::size).sum::<usize>()
            + self.outputs.len() * OUTPUT_SIZE
            + self.ops.iter().map(NameOp::size).sum::<usize>()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for i in &self.inputs {
            out.extend_from_slice(&i.to_bytes());
        }
        out.extend_from_slice(&(self.policy_inputs.len() as u32).to_le_bytes());
        for p in &self.policy_inputs {
            out.extend_from_slice(&p.to_bytes());
        }
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            out.extend_from_slice(&o.to_bytes());
        }
        out.extend_from_slice(&(self.ops.len() as u32).to_le_bytes());
        for op in &self.ops {
            out.extend_from_slice(&op.to_bytes());
        }
        out
    }

    /// Parses a transaction; the whole slice must be consumed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Transaction> {
        let (n_in, mut rest) = read_u32(bytes)?;
        let mut inputs = Vec::with_capacity((n_in as usize).min(rest.len() / INPUT_SIZE));
        for _ in 0..n_in {
            let (input, tail) = Input::read(rest)?;
            inputs.push(input);
            rest = tail;
        }
        let (n_policy, mut rest) = read_u32(rest)?;
        let mut policy_inputs = Vec::with_capacity((n_policy as usize).min(rest.len() / 64));
        for _ in 0..n_policy {
            let (input, tail) = PolicyInput::read(rest)?;
            policy_inputs.push(input);
            rest = tail;
        }
        let (n_out, mut rest) = read_u32(rest)?;
        let mut outputs = Vec::with_capacity((n_out as usize).min(rest.len() / OUTPUT_SIZE));
        for _ in 0..n_out {
            let (head, tail) = rest.split_at_checked(OUTPUT_SIZE)?;
            outputs.push(Output::from_bytes(head)?);
            rest = tail;
        }
        let (n_ops, mut rest) = read_u32(rest)?;
        let mut ops = Vec::with_capacity((n_ops as usize).min(rest.len() / crate::names::COMMIT_OP_SIZE));
        for _ in 0..n_ops {
            let (op, tail) = NameOp::parse(rest)?;
            ops.push(op);
            rest = tail;
        }
        if !rest.is_empty() {
            return None;
        }
        Some(Transaction { inputs, policy_inputs, outputs, ops })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: u8) -> Key {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        Key::generate(&seed)
    }

    #[test]
    fn sizes() {
        assert_eq!(OUTPUT_SIZE, 60);
        assert_eq!(INPUT_SIZE, 49 + 8 + 8 + 2312);
        assert_eq!(TREE_HEIGHT, 4);
        assert_eq!(Key::generate(&[7; 32]).leaves(), 16);
    }

    #[test]
    fn amount_limbs_cover_u64() {
        let p = crate::poseidon2::P as u64;
        for a in [0u64, 1, MASK30, MASK30 + 1, p, p - 1, p << 30, u64::MAX, 1 << 60, (1 << 60) - 1] {
            let l = amount_fps(a);
            let back =
                l[0].to_canonical() as u64 | (l[1].to_canonical() as u64) << 30 | (l[2].to_canonical() as u64) << 60;
            assert_eq!(back, a);
        }
    }

    #[test]
    fn commitments() {
        let a = key(1).public_key();
        let b = key(2).public_key();
        assert_eq!(commitment(&a, 5), commitment(&a, 5));
        assert_ne!(commitment(&a, 5), commitment(&a, 6));
        assert_ne!(commitment(&a, 5), commitment(&b, 5));
        assert_ne!(commitment(&a, 5), pubkey_hash(&a));
        assert_ne!(pubkey_hash(&a), pubkey_hash(&b));
        let out = Output::new(&a, 5);
        assert_eq!(out.amount, 5);
        assert_eq!(out.commitment, commitment(&a, 5));
    }

    #[test]
    fn hash_domain_separates() {
        let x = [Fp::new(1), Fp::new(2)];
        assert_ne!(hash_domain(DOM_BODY, &x), hash_domain(DOM_COMMITMENT, &x));
        assert_ne!(hash_domain(DOM_BODY, &x), hash_domain(DOM_BODY, &x[..1]));
        assert_ne!(hash_domain(DOM_BODY, &[]), hash_domain(DOM_BODY, &[Fp::ZERO]));
        let nine = [Fp::new(3); 9];
        assert_ne!(hash_domain(DOM_BODY, &nine), hash_domain(DOM_BODY, &nine[..8]));
    }

    #[test]
    fn spend_two_keys_with_fee() {
        let mut ka = key(1);
        let mut kb = key(2);
        let kc = key(3);
        let utxo_a = Output::new(&ka.public_key(), 50);
        let utxo_b = Output::new(&kb.public_key(), 30);

        let unsigned = UnsignedTransaction::new(
            vec![(ka.public_key(), 50), (kb.public_key(), 30)],
            vec![Output::new(&kc.public_key(), 70), Output::new(&ka.public_key(), 5)],
        );
        let body = unsigned.body_hash();
        let tx = unsigned.sign(|i, _pk, msg| if i == 0 { ka.sign(msg) } else { kb.sign(msg) }).unwrap();

        assert!(tx.verify_signatures());
        assert_eq!(tx.txid(), body);
        assert_eq!(tx.spent_commitments(), vec![utxo_a.commitment, utxo_b.commitment]);
        assert_eq!(tx.input_total(), 80);
        assert_eq!(tx.output_total(), 75);
        assert_eq!(tx.balance(), 5);
        assert_eq!(ka.next_index(), 1);
        assert_eq!(kb.next_index(), 1);
    }

    #[test]
    fn one_key_spends_several_inputs() {
        let mut k = key(4);
        let pk = k.public_key();
        let unsigned = UnsignedTransaction::new(vec![(pk, 10), (pk, 20), (pk, 30)], vec![Output::new(&pk, 60)]);
        let tx = unsigned.sign_with(&mut k).unwrap();
        assert!(tx.verify_signatures());
        assert_eq!(tx.balance(), 0);
        assert_eq!(k.next_index(), 3);
        let leaves: Vec<u64> = tx.inputs.iter().map(|i| i.signature.index).collect();
        assert_eq!(leaves, vec![0, 1, 2]);

        // sign_with refuses inputs owned by another key.
        let other = key(5).public_key();
        let unsigned = UnsignedTransaction::new(vec![(pk, 1), (other, 1)], vec![]);
        assert_eq!(unsigned.sign_with(&mut k).unwrap_err(), SignError::WrongKey(1));
    }

    #[test]
    fn reward_transaction_has_negative_balance() {
        let miner = key(6).public_key();
        let tx = UnsignedTransaction::new(vec![], vec![Output::new(&miner, 100)])
            .sign(|_, _, _| Err::<Sig, ()>(()))
            .unwrap();
        assert!(tx.inputs.is_empty());
        assert!(tx.verify_signatures());
        assert_eq!(tx.balance(), -100);
        assert_ne!(tx.txid(), [Fp::ZERO; DIGEST]);
    }

    #[test]
    fn tampering_breaks_signatures() {
        let mut ka = key(7);
        let kb = key(8).public_key();
        let unsigned = UnsignedTransaction::new(
            vec![(ka.public_key(), 40)],
            vec![Output::new(&kb, 25), Output::new(&ka.public_key(), 10)],
        );
        let tx = unsigned.sign_with(&mut ka).unwrap();
        assert!(tx.verify_signatures());

        let mut t = tx.clone();
        t.outputs[0].amount = 30;
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.outputs[0].commitment = Output::new(&ka.public_key(), 25).commitment;
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.outputs.swap(0, 1);
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.outputs.pop();
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.inputs[0].amount = 41;
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.inputs[0].pubkey = kb;
        assert!(!t.verify_signatures());
        // A valid signature by the right key over a different body.
        let other = UnsignedTransaction::new(vec![(ka.public_key(), 40)], vec![]).sign_with(&mut ka).unwrap();
        let mut t = tx.clone();
        t.inputs[0].signature = other.inputs[0].signature.clone();
        assert!(!t.verify_signatures());
        // Changing the signature does not change the id.
        assert_eq!(t.txid(), tx.txid());
        assert_eq!(tx.unsigned().body_hash(), tx.txid());
    }

    #[test]
    fn name_operations_are_signed_and_carried() {
        use crate::names::{BlockNameOp, NameOp, Record};
        let d = |n: u32| -> Digest { core::array::from_fn(|i| Fp::new(n + i as u32)) };
        let mut ka = key(11);
        let mut owner = key(12);
        let commit = NameOp::Commit { commit: d(1), memo: crate::transaction::memo5(d(2)) };
        let reveal = NameOp::Reveal { record: Record::new(b"alice", d(3), d(4), d(5)).unwrap(), salt: d(6), commit: 1 };
        let update = NameOp::update(Record::new(b"bob", d(7), d(8), d(9)).unwrap(), &mut owner).unwrap();
        let ops = vec![commit.clone(), reveal.clone(), update.clone()];
        let unsigned = UnsignedTransaction::with_ops(
            vec![(ka.public_key(), 40)],
            vec![Output::new(&ka.public_key(), 30)],
            ops.clone(),
        );
        let tx = unsigned.sign_with(&mut ka).unwrap();
        assert!(tx.verify_signatures());
        assert_eq!(tx.ops, ops);
        assert_eq!(tx.balance(), 10);
        assert_eq!(tx.op_digests().unwrap(), ops.iter().map(|o| o.digest().unwrap()).collect::<Vec<_>>());

        // The same inputs and outputs without the operations sign differently.
        let plain = UnsignedTransaction::new(vec![(ka.public_key(), 40)], vec![Output::new(&ka.public_key(), 30)]);
        assert_ne!(plain.body_hash(), tx.txid());
        // Changing an operation's public part breaks the signatures; the witness is not signed.
        let mut t = tx.clone();
        t.ops.swap(0, 1);
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.ops.pop();
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.ops[0] = NameOp::Commit { commit: d(2), memo: crate::transaction::memo5(d(2)) };
        assert!(!t.verify_signatures());
        let mut t = tx.clone();
        t.ops[1] = NameOp::Reveal { record: Record::new(b"alice", d(3), d(4), d(5)).unwrap(), salt: d(60), commit: 2 };
        assert!(t.verify_signatures());
        assert_eq!(t.txid(), tx.txid());
        assert_eq!(tx.ops[2].block_op(), BlockNameOp::Update(Record::new(b"bob", d(7), d(8), d(9)).unwrap()));

        let bytes = tx.to_bytes();
        assert_eq!(bytes.len(), tx.size());
        assert_eq!(bytes.len(), 16 + INPUT_SIZE + OUTPUT_SIZE + ops.iter().map(NameOp::size).sum::<usize>());
        assert_eq!(Transaction::from_bytes(&bytes), Some(tx.clone()));
        assert!(Transaction::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        assert_eq!(tx.unsigned().body_hash(), tx.txid());
    }

    #[test]
    fn serialization_roundtrip() {
        let mut ka = key(9);
        let kb = key(10).public_key();
        let mut tx = UnsignedTransaction::new(
            vec![(ka.public_key(), 7), (ka.public_key(), 8)],
            vec![Output::new(&kb, 9), Output::new(&kb, u64::MAX)],
        )
        .sign_with(&mut ka)
        .unwrap();
        // Positions are carried but not signed.
        let id = tx.txid();
        tx.set_positions(&[1 << 39, 12345]);
        assert_eq!((tx.txid(), tx.spent_positions()), (id, vec![1 << 39, 12345]));
        assert!(tx.verify_signatures());

        let bytes = tx.to_bytes();
        assert_eq!(bytes.len(), tx.size());
        assert_eq!(bytes.len(), 16 + 2 * INPUT_SIZE + 2 * OUTPUT_SIZE);
        let back = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(back, tx);
        assert!(back.verify_signatures());
        assert_eq!(back.txid(), tx.txid());

        assert!(Transaction::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Transaction::from_bytes(&extra).is_none());
        let mut huge = bytes.clone();
        huge[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Transaction::from_bytes(&huge).is_none());
        assert!(Transaction::from_bytes(&[]).is_none());

        let empty = Transaction { inputs: vec![], policy_inputs: vec![], outputs: vec![], ops: vec![] };
        assert_eq!(Transaction::from_bytes(&empty.to_bytes()), Some(empty));

        let out = Output::new(&kb, 3);
        assert_eq!(Output::from_bytes(&out.to_bytes()), Some(out));
        let input = &tx.inputs[1];
        assert_eq!(Input::from_bytes(&input.to_bytes()).as_ref(), Some(input));
    }
}
