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
//! The body is the canonical encoding of all inputs (key and amount) and all
//! outputs (commitment and amount), with signatures excluded, laid out in
//! whole sponge blocks per item (see `body_elements`). Every input
//! signs the same body hash, which is also the transaction id.
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
//! transaction := u32 n_in, n_in * input, u32 n_out, n_out * output
//! input       := pubkey (48) | amount u64 (8) | signature (2312)
//! output      := key hash (32) | amount u64 (8) | memo (32)
//! ```
//!
//! An output's memo is eight field elements its owner's wallet fills to find
//! the output again from its seed (see `crate::wallet`); consensus only
//! carries it: it is signed with the body and listed with the commitment.
//!
//! Hashing works on field elements rather than bytes: a 64-bit amount is
//! three limbs of 30, 30 and 4 bits, a public key is its 12 elements and a
//! commitment its 8.

use crate::poseidon2::{DIGEST, Fp, WIDTH, digest_from_bytes, digest_to_bytes, permute_in_place};
use crate::xmss::{Digest, KeyExhausted, PUB_SEED_LEN, PublicKey, SecretKey, Signature};

/// XMSS tree height used for all transaction signatures (16 leaves per key).
pub const TREE_HEIGHT: usize = 4;
/// Signature type used in inputs.
pub type Sig = Signature<TREE_HEIGHT>;
/// Secret key type matching [`Sig`].
pub type Key = SecretKey<TREE_HEIGHT>;
/// An output commitment `H(H(pubkey) || amount)`.
pub type Commitment = Digest;
/// An output's recovery memo: opaque to consensus.
pub type Memo = Digest;

/// Serialized size of a field element.
const FP_BYTES: usize = 4;
/// Serialized size of a digest or commitment.
const DIGEST_BYTES: usize = DIGEST * FP_BYTES;
/// Serialized size of an [`Input`].
pub const INPUT_SIZE: usize = PublicKey::SIZE + 8 + 8 + Sig::SIZE;
/// Serialized size of an [`Output`].
pub const OUTPUT_SIZE: usize = DIGEST_BYTES + 8 + DIGEST_BYTES;

pub(crate) const DOM_PUBKEY: u32 = 1;
pub(crate) const DOM_COMMITMENT: u32 = 2;
pub(crate) const DOM_BODY: u32 = 3;

const MASK30: u64 = (1 << 30) - 1;
const AMOUNT_LIMBS: usize = 3;
const PUBKEY_FPS: usize = DIGEST + PUB_SEED_LEN;

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
    out[DIGEST..].copy_from_slice(&pk.pub_seed);
    out
}

/// `H(pubkey)`.
pub fn pubkey_hash(pk: &PublicKey) -> Digest {
    hash_domain(DOM_PUBKEY, &pubkey_fps(pk))
}

/// `H(H(pubkey) || amount)`, the commitment stored in an output.
pub fn commitment(pk: &PublicKey, amount: u64) -> Commitment {
    key_commitment(&pubkey_hash(pk), amount)
}

/// The state tree leaf of an unspent output: its commitment and memo
/// compressed, so the state root covers the memo too.
pub fn leaf(commitment: &Commitment, memo: &Memo) -> Digest {
    crate::poseidon2::compress(commitment, memo)
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
    pub outputs: Vec<Output>,
}

/// A transaction whose inputs have not been signed yet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnsignedTransaction {
    /// Revealed key and amount of each output being spent.
    pub inputs: Vec<(PublicKey, u64)>,
    pub outputs: Vec<Output>,
}

impl Output {
    /// Creates an output paying `amount` to `pk`, with an empty memo.
    pub fn new(pk: &PublicKey, amount: u64) -> Output {
        Output::to_key_hash(&pubkey_hash(pk), amount)
    }

    /// Creates an output paying `amount` to the key with hash `key_hash`,
    /// with an empty memo.
    pub fn to_key_hash(key_hash: &Digest, amount: u64) -> Output {
        Output::with_memo(key_hash, amount, [Fp::ZERO; DIGEST])
    }

    /// The part a block lists: the commitment and the memo.
    pub fn block_output(&self) -> crate::block::BlockOutput {
        crate::block::BlockOutput { commitment: self.commitment, memo: self.memo }
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
        out[DIGEST_BYTES + 8..].copy_from_slice(&digest_to_bytes(&self.memo));
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Output> {
        if bytes.len() != OUTPUT_SIZE {
            return None;
        }
        let key_hash = digest_from_bytes(&bytes[..DIGEST_BYTES])?;
        let (amount, _) = read_u64(&bytes[DIGEST_BYTES..DIGEST_BYTES + 8])?;
        let memo = digest_from_bytes(&bytes[DIGEST_BYTES + 8..])?;
        Some(Output::with_memo(&key_hash, amount, memo))
    }
}

impl Input {
    /// The commitment of the output this input spends.
    pub fn commitment(&self) -> Commitment {
        commitment(&self.pubkey, self.amount)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INPUT_SIZE);
        out.extend_from_slice(&self.pubkey.to_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.position.to_le_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Input> {
        if bytes.len() != INPUT_SIZE {
            return None;
        }
        let pubkey = PublicKey::from_bytes(&bytes[..PublicKey::SIZE])?;
        let (amount, rest) = read_u64(&bytes[PublicKey::SIZE..])?;
        let (position, rest) = read_u64(rest)?;
        let signature = Sig::from_bytes(rest)?;
        Some(Input { pubkey, amount, position, signature })
    }
}

/// Body elements, block aligned so each item is whole sponge blocks:
///
/// ```text
/// [n_in, n_out, 0, 0, 0, 0, 0, 0]
/// per input:  [root(8)] [pub_seed(4), amount lo30, mid30, hi4, 0]
/// per output: [commitment(8)] [amount lo30, mid30, hi4, 0, 0, 0, 0, 0] [memo(8)]
/// ```
pub(crate) fn body_elements(inputs: &[(PublicKey, u64)], outputs: &[Output]) -> Vec<Fp> {
    let mut body = Vec::with_capacity(8 + 16 * inputs.len() + 24 * outputs.len());
    body.push(Fp::from_u64(inputs.len() as u64));
    body.push(Fp::from_u64(outputs.len() as u64));
    body.extend_from_slice(&[Fp::ZERO; 6]);
    for (pk, amount) in inputs {
        body.extend_from_slice(&pk.root);
        body.extend_from_slice(&pk.pub_seed);
        body.extend_from_slice(&amount_fps(*amount));
        body.push(Fp::ZERO);
    }
    for out in outputs {
        body.extend_from_slice(&out.commitment);
        body.extend_from_slice(&amount_fps(out.amount));
        body.extend_from_slice(&[Fp::ZERO; 5]);
        body.extend_from_slice(&out.memo);
    }
    body
}

/// Hash of the canonical body (see [`body_elements`]).
fn body_hash(inputs: &[(PublicKey, u64)], outputs: &[Output]) -> Digest {
    hash_domain(DOM_BODY, &body_elements(inputs, outputs))
}

impl UnsignedTransaction {
    pub fn new(inputs: Vec<(PublicKey, u64)>, outputs: Vec<Output>) -> UnsignedTransaction {
        UnsignedTransaction { inputs, outputs }
    }

    /// The body hash every input must sign; equals the final transaction id.
    pub fn body_hash(&self) -> Digest {
        body_hash(&self.inputs, &self.outputs)
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
        Ok(Transaction { inputs, outputs: self.outputs })
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
        body_hash(&inputs, &self.outputs)
    }

    /// Transaction id: the body hash.
    pub fn txid(&self) -> Digest {
        self.body_hash()
    }

    /// The unsigned form, for example to re-derive the body.
    pub fn unsigned(&self) -> UnsignedTransaction {
        UnsignedTransaction {
            inputs: self.inputs.iter().map(|i| (i.pubkey, i.amount)).collect(),
            outputs: self.outputs.clone(),
        }
    }

    /// Checks that every input carries a valid signature over the body by
    /// its revealed key. Does not check that the spent outputs exist or are
    /// unspent, and does not constrain the balance.
    pub fn verify_signatures(&self) -> bool {
        let msg = self.body_hash();
        self.inputs.iter().all(|i| i.pubkey.verify(&msg, &i.signature))
    }

    /// Sets where each input's output is in the UTXO set, in input order.
    /// Leaves the signatures and the transaction id unchanged.
    pub fn set_positions(&mut self, positions: &[u64]) {
        assert_eq!(positions.len(), self.inputs.len(), "one position per input");
        for (i, p) in self.inputs.iter_mut().zip(positions) {
            i.position = *p;
        }
    }

    /// Positions of the outputs being spent, in input order.
    pub fn spent_positions(&self) -> Vec<u64> {
        self.inputs.iter().map(|i| i.position).collect()
    }

    /// Commitments of the outputs being spent, in input order.
    pub fn spent_commitments(&self) -> Vec<Commitment> {
        self.inputs.iter().map(Input::commitment).collect()
    }

    /// Sum of input amounts.
    pub fn input_total(&self) -> u128 {
        self.inputs.iter().map(|i| i.amount as u128).sum()
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
        8 + self.inputs.len() * INPUT_SIZE + self.outputs.len() * OUTPUT_SIZE
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for i in &self.inputs {
            out.extend_from_slice(&i.to_bytes());
        }
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs {
            out.extend_from_slice(&o.to_bytes());
        }
        out
    }

    /// Parses a transaction; the whole slice must be consumed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Transaction> {
        let (n_in, mut rest) = read_u32(bytes)?;
        let mut inputs = Vec::with_capacity((n_in as usize).min(rest.len() / INPUT_SIZE));
        for _ in 0..n_in {
            let (head, tail) = rest.split_at_checked(INPUT_SIZE)?;
            inputs.push(Input::from_bytes(head)?);
            rest = tail;
        }
        let (n_out, mut rest) = read_u32(rest)?;
        let mut outputs = Vec::with_capacity((n_out as usize).min(rest.len() / OUTPUT_SIZE));
        for _ in 0..n_out {
            let (head, tail) = rest.split_at_checked(OUTPUT_SIZE)?;
            outputs.push(Output::from_bytes(head)?);
            rest = tail;
        }
        if !rest.is_empty() {
            return None;
        }
        Some(Transaction { inputs, outputs })
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
        assert_eq!(OUTPUT_SIZE, 72);
        assert_eq!(INPUT_SIZE, 48 + 8 + 8 + 2312);
        assert_eq!(TREE_HEIGHT, 4);
        assert_eq!(Key::LEAVES, 16);
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
        assert_eq!(bytes.len(), 8 + 2 * INPUT_SIZE + 2 * OUTPUT_SIZE);
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

        let empty = Transaction { inputs: vec![], outputs: vec![] };
        assert_eq!(Transaction::from_bytes(&empty.to_bytes()), Some(empty));

        let out = Output::new(&kb, 3);
        assert_eq!(Output::from_bytes(&out.to_bytes()), Some(out));
        let input = &tx.inputs[1];
        assert_eq!(Input::from_bytes(&input.to_bytes()).as_ref(), Some(input));
    }
}
