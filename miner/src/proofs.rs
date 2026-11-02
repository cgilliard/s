//! Payment proofs and proofs of burn (`docs/PROOFS.md`): that an output of
//! a key hash, an amount and a memo was created in a given block, shown by
//! its path to that block's state root, with what says whose it is.
//!
//! - A **payment proof** carries the recipient's receipt: its Dilithium
//!   identity key (whose hash is its `tab1…` address) and a signature over
//!   the output, the slate and the sender's address, made when it
//!   answered the slate. It shows that the holder of the recipient's
//!   address acknowledged that output as a payment from the sender.
//! - A **proof of burn** is of an output to the key hash zero, which no
//!   key hashes to, so nobody can spend it. Its memo is the hash of the
//!   beneficiary's address, a nonce and a purpose, which the proof gives:
//!   the burn names whom it credits, and the validity proof bound the memo
//!   to the transaction, so it cannot be claimed for anyone else.
//!
//! A proof is against the block that created the output, never a later
//! one: the leaf's creation height is the proof's height, so there is one
//! proof per payment and it says nothing of what became of the output.
//! Whether that block is on the main chain, and how deep, the caller
//! checks against its headers ([`Proof::check`] takes the state root).
//!
//! Format (`format` 1 for a payment, 2 for a burn), little endian:
//!
//! ```text
//! format (1) | height (4) | position (8) | key hash (32) | amount (8)
//! | memo (20) | path (40 * 32)
//! payment: 0 | sender's address (32), or 1 | the unnamed sender's secret (32)
//!          | slate id (32) | receipt key (1952) | receipt signature (3309)
//! burn:    beneficiary (32) | nonce (32) | purpose length (1) | purpose
//! ```
//!
//! As text, the bytes in base64, 64 characters a line, between
//! `-----BEGIN TAB PAYMENT PROOF-----` (or `BURN`) and its end marker;
//! text outside the markers is ignored.

use crate::codec::{Reader, Writer};
use crate::poseidon2::{DIGEST, Fp, digest_to_bytes};
use crate::state_tree::{DEPTH, Digest};
use crate::transaction::{
    Commitment, MEMO_LEN, Memo, Output, hash_domain, key_commitment, memo_from_bytes, memo_to_bytes, output_leaf,
};

/// The context string receipts are signed under.
pub const RECEIPT_CONTEXT: &[u8] = b"tab-receipt";
/// Longest purpose a burn names, in bytes.
pub const MAX_PURPOSE: usize = 255;
/// The key hash of a burn: no key hashes to it.
pub const BURN_KEY_HASH: Digest = [Fp::ZERO; DIGEST];

const DOM_BURN: u32 = 22;
const DOM_SENDER: u32 = 24;
const FORMAT_PAYMENT: u8 = 1;
const FORMAT_BURN: u8 = 2;
const PAYMENT_MARKER: &str = "TAB PAYMENT PROOF";
const BURN_MARKER: &str = "TAB BURN PROOF";

/// A recipient's acknowledgement of a payment: its identity key and its
/// signature over the output, the slate and the sender's address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Receipt {
    pub const SIZE: usize = crate::mldsa::PK_LEN + crate::mldsa::SIG_LEN;

    /// What a receipt signs: the output's commitment, amount and memo, the
    /// slate's id and the sender's address.
    pub fn message(output: &Output, slate_id: &[u8; 32], sender: &Digest) -> Vec<u8> {
        let mut m = Vec::with_capacity(32 + 8 + 20 + 32 + 32);
        m.extend_from_slice(&digest_to_bytes(&output.commitment));
        m.extend_from_slice(&output.amount.to_le_bytes());
        m.extend_from_slice(&memo_to_bytes(&output.memo));
        m.extend_from_slice(slate_id);
        m.extend_from_slice(&digest_to_bytes(sender));
        m
    }

    /// The recipient's receipt for `output`, signed with its identity key.
    pub fn sign(key: &crate::mldsa::SecretKey, output: &Output, slate_id: &[u8; 32], sender: &Digest) -> Receipt {
        let signature = key.sign(&Self::message(output, slate_id, sender), RECEIPT_CONTEXT);
        Receipt { key: key.public_key().to_vec(), signature }
    }

    /// Whether the signature holds for `output` in slate `slate_id` from
    /// `sender`.
    pub fn verify(&self, output: &Output, slate_id: &[u8; 32], sender: &Digest) -> bool {
        crate::mldsa::verify(&self.key, &Self::message(output, slate_id, sender), RECEIPT_CONTEXT, &self.signature)
    }

    /// The recipient's id: its address's 32 bytes.
    pub fn recipient(&self) -> Digest {
        crate::address::id_of(&self.key)
    }

    pub fn write(&self, w: &mut Writer) {
        w.0.extend_from_slice(&self.key);
        w.0.extend_from_slice(&self.signature);
    }

    pub fn read(r: &mut Reader) -> Option<Receipt> {
        let key = r.take(crate::mldsa::PK_LEN)?.to_vec();
        let signature = r.take(crate::mldsa::SIG_LEN)?.to_vec();
        Some(Receipt { key, signature })
    }
}

/// What a burn credits: the beneficiary's address, a random nonce and a
/// purpose, whose hash is the burn's memo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Burn {
    pub beneficiary: Digest,
    pub nonce: [u8; 32],
    pub purpose: Vec<u8>,
}

impl Burn {
    /// The memo: the first five elements of the hash of the beneficiary,
    /// the nonce and the purpose (three bytes an element).
    pub fn memo(&self) -> Memo {
        let mut bytes = Vec::with_capacity(64 + self.purpose.len());
        bytes.extend_from_slice(&digest_to_bytes(&self.beneficiary));
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.purpose);
        let fps: Vec<Fp> =
            bytes.chunks(3).map(|c| Fp::new(c.iter().rev().fold(0u32, |acc, &b| acc << 8 | b as u32))).collect();
        hash_domain(DOM_BURN, &fps)[..MEMO_LEN].try_into().unwrap()
    }

    /// The burn output for `amount`.
    pub fn output(&self, amount: u64) -> Output {
        Output::with_memo(&BURN_KEY_HASH, amount, self.memo())
    }

    pub fn write(&self, w: &mut Writer) {
        w.digest(&self.beneficiary);
        w.0.extend_from_slice(&self.nonce);
        w.0.push(self.purpose.len() as u8);
        w.0.extend_from_slice(&self.purpose);
    }

    pub fn read(r: &mut Reader) -> Option<Burn> {
        let beneficiary = r.digest()?;
        let nonce = r.take(32)?.try_into().ok()?;
        let n = r.take(1)?[0] as usize;
        let purpose = r.take(n)?.to_vec();
        Some(Burn { beneficiary, nonce, purpose })
    }
}

/// What an unnamed sender puts in a slate in place of its address
/// (`docs/PRIVACY.md`, fix 4): the hash of a secret only it holds, which
/// it shows to prove the payment its own.
pub fn sender_tag(secret: &[u8; 32]) -> Digest {
    let fps: Vec<Fp> =
        secret.chunks(3).map(|c| Fp::new(c.iter().rev().fold(0u32, |acc, &b| acc << 8 | b as u32))).collect();
    hash_domain(DOM_SENDER, &fps)
}

/// Whose an output is: a recipient's receipt for a payment, or a burn's
/// preimage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Claim {
    /// `sender` is what the slate named: the sender's address, or with
    /// `secret` the secret's [`sender_tag`].
    Payment {
        sender: Digest,
        secret: Option<[u8; 32]>,
        slate_id: [u8; 32],
        receipt: Receipt,
    },
    Burn(Burn),
}

impl Claim {
    /// Writes a payment's sender: its address, or its secret.
    fn write_sender(w: &mut Writer, sender: &Digest, secret: &Option<[u8; 32]>) {
        match secret {
            None => {
                w.0.push(0);
                w.digest(sender);
            }
            Some(s) => {
                w.0.push(1);
                w.0.extend_from_slice(s);
            }
        }
    }

    fn read_sender(r: &mut Reader) -> Option<(Digest, Option<[u8; 32]>)> {
        match r.take(1)?[0] {
            0 => Some((r.digest()?, None)),
            1 => {
                let secret: [u8; 32] = r.take(32)?.try_into().ok()?;
                Some((sender_tag(&secret), Some(secret)))
            }
            _ => None,
        }
    }

    pub fn write(&self, w: &mut Writer) {
        match self {
            Claim::Payment { sender, secret, slate_id, receipt } => {
                w.0.push(FORMAT_PAYMENT);
                Self::write_sender(w, sender, secret);
                w.0.extend_from_slice(slate_id);
                receipt.write(w);
            }
            Claim::Burn(burn) => {
                w.0.push(FORMAT_BURN);
                burn.write(w);
            }
        }
    }

    pub fn read(r: &mut Reader) -> Option<Claim> {
        Self::read_after(r.take(1)?[0], r)
    }

    fn read_after(format: u8, r: &mut Reader) -> Option<Claim> {
        match format {
            FORMAT_PAYMENT => {
                let (sender, secret) = Self::read_sender(r)?;
                let slate_id = r.take(32)?.try_into().ok()?;
                Some(Claim::Payment { sender, secret, slate_id, receipt: Receipt::read(r)? })
            }
            FORMAT_BURN => Some(Claim::Burn(Burn::read(r)?)),
            _ => None,
        }
    }
}

/// Why a proof does not hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    /// The output's leaf and path do not lead to the block's state root.
    NotInBlock,
    /// The receipt's signature does not hold.
    Receipt,
    /// A burn's key hash is not zero, or its memo not its preimage's hash.
    Burn,
}

impl core::fmt::Display for ProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ProofError::NotInBlock => "the output is not in that block's state",
            ProofError::Receipt => "the recipient's receipt does not hold",
            ProofError::Burn => "the output is not that burn",
        })
    }
}

/// A payment proof or proof of burn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// The block that created the output.
    pub height: u32,
    pub position: u64,
    pub key_hash: Digest,
    pub amount: u64,
    pub memo: Memo,
    /// The output's path to the state root after block `height`.
    pub path: crate::state_tree::Proof,
    pub claim: Claim,
}

impl Proof {
    /// The output the proof is of.
    pub fn output(&self) -> Output {
        Output::with_memo(&self.key_hash, self.amount, self.memo)
    }

    pub fn commitment(&self) -> Commitment {
        key_commitment(&self.key_hash, self.amount)
    }

    /// Checks the proof against `state_root`, the state root of the
    /// caller's main-chain header at [`Proof::height`]: the output's leaf
    /// (created at that height) and path lead there, and the receipt holds
    /// or the burn is the one its preimage names.
    pub fn check(&self, state_root: &Digest) -> Result<(), ProofError> {
        let leaf = output_leaf(&self.commitment(), &self.memo, self.amount, self.height);
        if !self.path.verify(state_root, self.position, &leaf) {
            return Err(ProofError::NotInBlock);
        }
        match &self.claim {
            Claim::Payment { sender, slate_id, receipt, .. } => {
                if !receipt.verify(&self.output(), slate_id, sender) {
                    return Err(ProofError::Receipt);
                }
            }
            Claim::Burn(burn) => {
                if self.key_hash != BURN_KEY_HASH || burn.memo() != self.memo {
                    return Err(ProofError::Burn);
                }
            }
        }
        Ok(())
    }

    pub fn is_burn(&self) -> bool {
        matches!(self.claim, Claim::Burn(_))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.0.push(if self.is_burn() { FORMAT_BURN } else { FORMAT_PAYMENT });
        w.u32(self.height);
        w.u64(self.position);
        w.digest(&self.key_hash);
        w.u64(self.amount);
        w.0.extend_from_slice(&memo_to_bytes(&self.memo));
        w.0.extend_from_slice(&self.path.to_bytes());
        match &self.claim {
            Claim::Payment { sender, secret, slate_id, receipt } => {
                Claim::write_sender(&mut w, sender, secret);
                w.0.extend_from_slice(slate_id);
                receipt.write(&mut w);
            }
            Claim::Burn(burn) => burn.write(&mut w),
        }
        w.finish()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Proof> {
        let mut r = Reader(bytes);
        let format = r.take(1)?[0];
        let height = r.u32()?;
        let position = r.u64()?;
        let key_hash = r.digest()?;
        let amount = r.u64()?;
        let memo = memo_from_bytes(r.take(crate::transaction::MEMO_BYTES)?)?;
        let path = crate::state_tree::Proof::from_bytes(r.take(crate::state_tree::Proof::SIZE)?)?;
        let claim = Claim::read_after(format, &mut r)?;
        r.is_empty().then_some(Proof { height, position, key_hash, amount, memo, path, claim })
    }

    /// The proof as text to paste: base64 between markers.
    pub fn to_text(&self) -> String {
        let marker = if self.is_burn() { BURN_MARKER } else { PAYMENT_MARKER };
        let b64 = base64_encode(&self.to_bytes());
        let mut out = format!("-----BEGIN {marker}-----\n");
        for line in b64.as_bytes().chunks(64) {
            out.push_str(core::str::from_utf8(line).unwrap());
            out.push('\n');
        }
        out.push_str(&format!("-----END {marker}-----\n"));
        out
    }

    /// A proof from text holding one between its markers, whatever
    /// surrounds it.
    pub fn from_text(text: &str) -> Option<Proof> {
        for (marker, burn) in [(PAYMENT_MARKER, false), (BURN_MARKER, true)] {
            let begin = format!("-----BEGIN {marker}-----");
            let end = format!("-----END {marker}-----");
            let Some(start) = text.find(&begin) else {
                continue;
            };
            let body = &text[start + begin.len()..];
            let stop = body.find(&end)?;
            let b64: String = body[..stop].chars().filter(|c| !c.is_whitespace()).collect();
            let proof = Proof::from_bytes(&base64_decode(&b64)?)?;
            return (proof.is_burn() == burn).then_some(proof);
        }
        None
    }

    /// Whether `text` holds a proof's end marker: a paste is complete.
    pub fn text_ends(text: &str) -> bool {
        text.contains(&format!("-----END {PAYMENT_MARKER}-----"))
            || text.contains(&format!("-----END {BURN_MARKER}-----"))
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64, with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes standard base64 with padding; `None` on anything else.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for (k, chunk) in s.chunks(4).enumerate() {
        let last = k + 1 == s.len() / 4;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            n = n << 6 | B64.iter().position(|&x| x == c)? as u32;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

const _: () = assert!(DEPTH == 40);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for n in 0..70 {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let s = base64_encode(&bytes);
            assert_eq!(base64_decode(&s), Some(bytes), "{n} bytes");
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_decode("Zm8="), Some(b"fo".to_vec()));
        assert_eq!(base64_decode("Zm8"), None);
        assert_eq!(base64_decode("Zm=8"), None);
        assert_eq!(base64_decode("Z===Zm8="), None);
        assert_eq!(base64_decode("Zm8*"), None);
    }

    /// An unnamed sender's proof carries its secret, not its tag: the tag
    /// the receipt binds is rebuilt from it, so only the secret's holder
    /// can show the proof as its own.
    #[test]
    fn unnamed_senders_prove_by_their_secret() {
        let key = crate::mldsa::keygen(&[3; 32]);
        let secret = [9u8; 32];
        let output = Output::with_memo(&[Fp::new(4); DIGEST], 500, [Fp::new(1); MEMO_LEN]);
        let receipt = Receipt::sign(&key, &output, &[2; 32], &sender_tag(&secret));
        let proof = Proof {
            height: 7,
            position: 3,
            key_hash: output.key_hash,
            amount: output.amount,
            memo: output.memo,
            path: crate::state_tree::Proof { siblings: [[Fp::ZERO; DIGEST]; DEPTH] },
            claim: Claim::Payment { sender: sender_tag(&secret), secret: Some(secret), slate_id: [2; 32], receipt },
        };
        let bytes = proof.to_bytes();
        assert!(!bytes.windows(32).any(|w| w == digest_to_bytes(&sender_tag(&secret))), "the tag is not sent");
        let back = Proof::from_bytes(&bytes).unwrap();
        assert_eq!(back, proof);
        let Claim::Payment { sender, receipt, slate_id, .. } = &back.claim else { panic!() };
        assert!(receipt.verify(&back.output(), slate_id, sender));
        // Another secret names another sender, which the receipt does not.
        let mut other = bytes.clone();
        let at = bytes.windows(32).position(|w| w == secret).unwrap();
        other[at] ^= 1;
        let Claim::Payment { sender, receipt, slate_id, .. } = Proof::from_bytes(&other).unwrap().claim else {
            panic!()
        };
        assert!(!receipt.verify(&output, &slate_id, &sender));
    }

    #[test]
    fn burn_memos_name_their_beneficiary() {
        let burn = Burn { beneficiary: [Fp::new(5); DIGEST], nonce: [7; 32], purpose: b"credit".to_vec() };
        let memo = burn.memo();
        assert_ne!(Burn { beneficiary: [Fp::new(6); DIGEST], ..burn.clone() }.memo(), memo);
        assert_ne!(Burn { nonce: [8; 32], ..burn.clone() }.memo(), memo);
        assert_ne!(Burn { purpose: b"credit!".to_vec(), ..burn.clone() }.memo(), memo);
        let out = burn.output(1000);
        assert_eq!(out.memo, memo);
        assert_eq!(out.commitment, key_commitment(&BURN_KEY_HASH, 1000));
    }
}
