# Payment proofs

A design note, 2026-11-02: proving that you paid an address, or burned
coins for someone, to anyone who holds the chain's headers. No consensus
change is needed; it is wallet work. Implemented 2026-11-02
(`miner/src/proofs.rs`, the wallet's `Payment`, `Chain::output_proof_at`).

## What exists

Every output is a leaf of the state tree (depth 40), and every header
carries the tree's root after its block:

```
leaf = compress(compress(commitment, slot), height_digest(created))
slot = memo ‖ amount            (transaction::memo_slot, docs/AMOUNTS.md)
commitment = key_commitment(key_hash, amount)
```

`created` is the height of the block that made the output. A node
answers `GetProof` for a position with the output there and its path to
its tip's state root (`Chain::output_proof`), and `node::verify_proof`
checks such a path against a root. Headers are kept forever by every
node; bodies and the undo records that let a node rebuild an earlier
state are kept for the undo window only (`--max-undo-blocks`, 1,008
blocks, a week, by default; 0 keeps everything, an archive node).

A path alone proves that an output of some key hash and amount was
created at some height. It does not say whose the key hash is: an
output's key is a one-time key the recipient's wallet derived, linked on
chain to nothing, and a sender who saw the slate knows its key hash and
amount and could claim it for any address. The recipient has to say so.

## A payment proof

```
height     the block that created the output
position   its position in the state tree
key_hash   the output's key hash
amount     its amount
memo       its memo
path       40 siblings from its leaf to the header's state root
receipt    the recipient's Dilithium key and its signature over
           H(commitment ‖ amount ‖ memo ‖ slate id ‖ sender)
           under the context "tab-receipt"
sender     the sender's address, as the receipt names it, or for a sender
           that did not name itself the secret whose hash the receipt
           names (docs/PRIVACY.md, fix 4)
slate id
```

About 6.7 KB, most of it the receipt (a Dilithium key and signature).
The exact layout is in `proofs.rs`.

**Checking it**, with the chain's headers:

1. The header at `height` is on the main chain. The check reports how
   many confirmations it has (the tip's height less `height`, plus one)
   and imposes no threshold: how many are enough is the verifier's call.
2. `commitment = key_commitment(key_hash, amount)`.
3. The leaf from `commitment`, `memo`, `amount` and `height` (the creation height
   must be the proof's height) and `path` lead to that header's state
   root at `position`.
4. The receipt's key hashes to the recipient's address
   (`address::id_of`), and its signature holds over the commitment,
   amount, memo, slate id and sender's address.

It shows that the holder of the recipient's address acknowledged an
output of that amount from the sender's address, and that the output
was created in that block. It does not show that the output is still
unspent, which is no business of the proof's.

**The creation height, and no other.** A proof is against the header of
the block that created the output, never a later one. There is then one
proof per payment and one header to look up, and the proof says nothing
of what became of the output afterwards: a path against a later header
would also show it still unspent at that block, which tells the verifier
about the recipient's spending. A proof whose height is not its leaf's
creation height is refused.

**When it can be made.** The path is against the state as it stood at
the creating block. Any node rebuilds that state from its current tree
and its undo records (as it does to serve fast-sync snapshots for any
block of its undo window), so a proof can be made for a week after the
payment confirms, by default; an archive node (`--max-undo-blocks 0`)
can make one at any time. Old bodies alone would not do: a path needs
the whole tree at that height. So the wallet makes and keeps the proof
when it records the payment as confirmed, normally moments after the
block, the week being the slack for a wallet that was offline. Once
made, checking it needs only the header, for good.

## The receipt

The recipient signs the receipt when it answers a slate, with
its identity key (the Dilithium key behind its `tab1…` address), and it
travels back in the answered slate; the sender checks it before
finalizing and keeps it with the payment. The sender's address in it is
the one the slate came from over the message layer, or the one the
sender puts in a file slate. The receipt is part of the slate's format
(the wallet's, not the chain's; `tabslt05`): a slate carries its sender
from the start, an answered slate always carries a receipt, and one
without, or with a receipt that does not hold, is malformed and refused.
Over the message layer the sender refuses a receipt from another id than
the one it sent to. A slate pays one recipient output, which the receipt
is for.

**Unnamed senders.** By default a slate does not name its sender
(`docs/PRIVACY.md`, fix 4): the wallet draws a secret, keeps it with the
payment, and the slate carries its hash where the address would be. The
receipt binds that hash, and the payment proof carries the secret, which
`verify-proof` checks against it: the proof then shows that the recipient
acknowledged a payment from whoever holds the proof, without naming the
sender to the recipient or to anyone. `send AMOUNT TO named` names the
sender's address instead. The recipient cannot tell the two apart and
does not check either: a sender naming someone else's address only
credits that address with its own payment. There is nothing to be compatible with: the change ships before
launch, with every test wallet and node started afresh.

The receipt's message binds the output's commitment (so its key and
amount), its memo, the slate (so this payment) and the sender (so it
cannot be presented as someone else's payment).

## Burns

A burn is the case with no recipient: an output to the key hash zero,
which no key hashes to, so nobody can ever spend it, with its memo
naming what it is for:

```
key_hash  =  0
memo      =  the first five elements of
             H(beneficiary's address ‖ nonce ‖ purpose)
```

The memo is bound to the transaction by the validity proof and is in the
state leaf, so a burn names whom it credits and cannot be redirected;
without it, whoever saw a burn's proof could present it as their own.
Outputs with equal commitments are fine (the state spends by position).

A proof of burn is a payment proof with `key_hash` zero and no receipt,
and the memo's preimage (the beneficiary, the nonce and the purpose)
instead: the verifier checks steps 1 to 3, that the key hash is zero, and
that the memo is the hash of the preimage given. The transaction that
made the burn need not be shown: it would only tell which outputs funded
it. The amount is on chain (`docs/AMOUNTS.md`), in the leaf the path
checks.

## In the wallet

- **Receipts**: signed when answering a slate, checked when finalizing,
  kept with the payment.
- **Making proofs**: when `sync_wallet` finds a payment's (or a burn's)
  output in a newly applied block (by commitment and memo: burns of one
  amount share a commitment), the wallet asks the chain for the path at
  that block and keeps it with the payment (`Wallet::land_payments`,
  `set_payment_path`). `Chain::output_proof_at(position, height)` gives
  the path against the state after block `height`: the leaves of the
  output's snapshot part as they stood then (the part as fast sync
  serves it, from the spent log), then the block's manifest's part roots
  up to the state root. A reorganization that moves the output lands it
  again, and the path is remade. A cancelled payment's record goes.
- **Commands**: `payments` lists them, where they landed and whether
  the proof is ready; `payment-proof TXID [FILE]` prints (or writes) a
  payment's proof, making it then if it can; `burn AMOUNT PURPOSE [FOR]
  [FEE]` burns for FOR (an address or `@NAME`, this wallet's by
  default), and `burn-proof TXID [FILE]` gives its proof; `verify-proof
  [FILE]` checks a proof, pasted at the prompt or from a file, against
  the node's headers and says what it shows: the amount, the addresses
  (or the beneficiary and purpose), the block and its confirmations.

A burn's memo is the first five elements of a Poseidon2 hash (domain 22)
of the beneficiary's id, a random 32-byte nonce and the purpose (up to
255 bytes), three bytes to an element.

## The text form

A proof is text, to paste into a message or a web form: its bytes in
base64, in lines of 64 characters, between markers that say what it is,

```
-----BEGIN TAB PAYMENT PROOF-----
dGFiIHBheW1lbnQgcHJvb2YgYnl0ZXMgaW4gYmFzZTY0LCA2NCBjaGFyYWN0ZXJz
...
-----END TAB PAYMENT PROOF-----
```

and `-----BEGIN TAB BURN PROOF-----` for a burn. The bytes start with a
format byte; text outside the markers is ignored, so a proof survives
being pasted with what surrounds it. A payment proof is about 9 KB of
text.

## Decisions

Settled on 2026-11-02.

- **Pasteable text** between `-----BEGIN TAB PAYMENT PROOF-----` and
  its end marker (above).
- **Confirmations reported, not required**: `verify-proof` says how many
  the proof's block has, and the user decides what is enough.
- **No compatibility**: an answered slate without a receipt is malformed;
  the change ships before launch on fresh wallets.
- **A proof is meant to be shown**: it reveals the amount, both addresses
  and the block to whoever sees it, which is its purpose.

## Tests

- `chain::tests::output_proofs_at_earlier_blocks`: at the tip the path is
  `output_proof`'s; after an earlier block, outputs spent since are
  proven present, outputs made since absent, against that block's root
  only.
- `node::tests::payment_and_burn_proofs_verify_against_their_block`: a
  payment by slates and a burn, landed in blocks, their paths made as the
  wallet syncs; each proof verifies against its block and fails against
  another, or with a changed amount, memo, position, sender, receipt key
  or beneficiary, or against a later block than its own; the text form
  round-trips through surrounding text; an answered slate without a
  receipt is malformed, and one with a tampered receipt or another
  sender is refused.
- `proofs::tests`: base64, and burn memos binding beneficiary, nonce and
  purpose.

A burn output cannot be spent because no key hashes to zero; there is no
test that tries.
