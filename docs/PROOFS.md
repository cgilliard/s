# Payment proofs

A design note, 2026-11-02: proving that you paid an address, or burned
coins for someone, to anyone who holds the chain's headers. No consensus
change is needed; it is wallet work. Not implemented yet.

## What exists

Every output is a leaf of the state tree (depth 40), and every header
carries the tree's root after its block:

```
leaf = compress(compress(commitment, memo), height_digest(created))
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
           H(commitment ‖ amount ‖ memo ‖ slate id ‖ sender's address)
           under the context "tab-receipt"
sender     the sender's address, as the receipt names it
slate id
```

About 6.7 KB, most of it the receipt (a Dilithium key and signature).

**Checking it**, with the chain's headers:

1. The header at `height` is on the main chain. The check reports how
   many confirmations it has (the tip's height less `height`, plus one)
   and imposes no threshold: how many are enough is the verifier's call.
2. `commitment = key_commitment(key_hash, amount)`.
3. The leaf from `commitment`, `memo` and `height` (the creation height
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
(the wallet's, not the chain's): an answered slate always carries one,
and one without, or with a receipt that does not hold, is malformed and
refused. There is nothing to be compatible with: the change ships before
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
memo      =  H(beneficiary's address ‖ purpose ‖ nonce), its first five
             elements once memos are five long (docs/AMOUNTS.md)
```

The memo is bound to the transaction by the validity proof and is in the
state leaf, so a burn names whom it credits and cannot be redirected;
without it, whoever saw a burn's proof could present it as their own.
Outputs with equal commitments are fine (the state spends by position).

A proof of burn is a payment proof with `key_hash` zero and no receipt,
and the memo's preimage (the beneficiary, the purpose and the nonce)
instead: the verifier checks steps 1 to 3, that the key hash is zero, and
that the memo is the hash of the preimage given. The transaction that
made the burn need not be shown: it would only tell which outputs funded
it. With public amounts (`docs/AMOUNTS.md`) the amount is on chain as
well; without, the commitment checks the amount the burner states.

## In the wallet

- **Receipts**: signed when answering a slate, checked when finalizing,
  kept with the payment.
- **Making proofs**: when `sync_wallet` finds a payment's (or a burn's)
  output in a newly applied block, the wallet asks the chain for the
  path at that block and keeps it with the payment. The chain needs one
  function, `output_proof_at(position, height)`: the path against the
  state after block `height`, rebuilt from the undo records, for any
  block of the undo window.
- **Commands**: `payment-proof TXID [FILE]` prints (or writes) a
  payment's proof; `burn AMOUNT TAG` burns (an output to key hash zero,
  the memo from the tag), and `burn-proof TXID [FILE]` prints its proof;
  `verify-proof [FILE]` checks a proof, pasted or from a file, against
  the node's headers and says what it shows: the amount, the addresses
  (or the beneficiary), the block and its confirmations.

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

## Implementation order

1. `Chain::output_proof_at(position, height)` over the undo window, and
   its test against `output_proof` at the tip and against a block a few
   back.
2. The receipt in the slate: signed, checked, kept; a slate without one
   refused.
3. Proofs made when a payment confirms, kept with it.
4. The proof's bytes and its text form, `payment-proof` and
   `verify-proof` (with its confirmations).
5. Burns: `burn`, `burn-proof`, and their check in `verify-proof`.
6. Tests: a proof verifies against its header and fails against any
   other; a changed amount, memo, position or sender fails; a receipt
   from another address fails; a proof against a later header than the
   creation height is refused; a burn's proof verifies and its output
   cannot be spent.
7. Docs: the README's wallet section.
