# Public amounts

A design note, 2026-11-02: put every output's amount on chain, in the
clear, so that every node checks the money supply with plain arithmetic,
outside the validity proof. Not implemented yet.

## Why

A block today lists its outputs as a commitment and a memo, and its inputs
as state-tree positions; keys, amounts and signatures stay off chain, and
the validity proof attests that every transaction balances
(`miner/src/block.rs`). That makes the proof the only thing standing
between the chain and counterfeiting: a missed constraint in the
transaction AIR, or a soundness bug in the STARK, would let someone mint
coins, and with amounts hidden nobody could see it. Zcash's counterfeiting
bug was in its circuit from launch until it was found in 2018, and
whether anyone used it cannot be told from the chain. The circuit has not had an
independent review, and a launch audit is out of reach; a fair-launch
coin is usually audited after launch.

The amounts are not private anyway. A transaction travels through the
pool with its outputs' key hashes and amounts and its inputs' amounts in
the clear (`miner/src/transaction.rs`, `Output`, `Input`); only the block
reduces them to commitments. Anyone who watches the mempool sees every
amount. Putting them on chain gives up little and buys a supply check
that does not depend on the circuit being right.

What it does not change: key hashes stay off chain, so who is paid is not
on chain; memos stay opaque; inputs are already named by position, so the
transaction graph is already visible and only gains its amounts.

## The supply invariant

Let `issued(h)` be the subsidies of blocks 1 to `h` (`ChainParams::subsidy`),
so `issued(0)` is zero: genesis creates no outputs, as a fair launch
has none. Any change to genesis would have to be counted in it.
Fees move value from a transaction's inputs to the reward output, so they
create nothing. Then after every block `h`:

```
Σ amounts of unspent outputs  =  issued(h)
```

and each block keeps it, checked by every node when it applies the block:

```
Σ amounts of the block's outputs  =  Σ amounts of the outputs it spends + subsidy(h)
```

The amounts spent are those the state already holds for the positions the
block names, not anything the block claims. A miner must claim the whole
subsidy and every fee: claiming less would burn coins without anyone
being able to say who burned them, which is no use to anyone. Burning is
done instead by an output nobody can spend, attributable and provable
(below).

Every sum is taken in 128 bits (or with checked arithmetic): an amount is
a `u64`, but a block's outputs, the amounts it spends, the unspent total
and `issued(h)` are sums of them, and a sum that wrapped around 2⁶⁴ could
make the equality hold for a block that mints. A block whose sums
overflow is refused.

A counterfeit then has nowhere to hide: the public ledger of amounts is
the one the equality runs over, and the amount a later spend is
counted at is the amount recorded when the output was created. A circuit
bug that let an output's commitment carry more than its public amount
would gain nothing, because spending it is counted at the public amount.
The proof still guards ownership (signatures and keys), the binding of
each commitment to its key and amount, the state root, and names; only
the arithmetic of supply leaves it.

## What changes

**Block outputs.** A block output becomes a commitment, a memo and an
amount, and the memo shrinks (below): 60 bytes instead of 64. The body
commitment covers the amount. Name commits occupy positions with amount
zero.

**The memo.** It holds today a nonce (four field elements, from which the
wallet derives the output's key), the amount encrypted under a pad from
the wallet's master key (three), and a recognition tag (one), by which a
scan tells the wallet's outputs from others' in one comparison
(`Wallet::memo`). With the amount public the middle three are dead
weight, so the memo becomes the nonce and the tag: five elements, 20
bytes. Neither is a secret, and 128-bit strength is not the measure: the
nonce is in the clear and the keys' security rests on the master key,
so the nonce need only be unique (about 124 bits: two of a wallet's
outputs sharing one, which would reuse a key, is about `n²/2¹²⁵`); the
tag sets only how often a scan takes a stranger's output for its own
(once in 2³¹), and a match is confirmed by recomputing the commitment
from the derived key and the public amount. Nothing else needs the 32
bytes: name commits use the wallet's memo; policy and channel outputs
take whatever the caller gives and nothing reads it; covenants and
rebindable signatures hash an output's memo as a digest; a burn's tag
(`docs/PROOFS.md`) fits in five elements (about 155 bits). The leaf and
the body hash still take a memo of eight elements, the last three zero,
and the circuit constrains them so. A name's record keeps its own memo,
apart from outputs'.

**State leaves.** A leaf is today `compress(compress(commitment, memo),
height_digest(height))`, the height in one element of a digest of eight
(`transaction::leaf`). The amount goes into the spare elements of that
second digest (a `u64` as three 30-bit limbs, each below the BabyBear
modulus), so the state root, and so the chain proof, covers it. A spend
reads the amount from the leaf it opens.

**The circuit.** The transaction AIR exposes each output's amount as a
public value bound to the block's list, and checks it is the amount inside
the output's commitment; the state-update rows hash the amount into the
leaf. The balance constraint inside the circuit stays, as a second line
of defence: the in-circuit and out-of-circuit checks then have to fail
together for a counterfeit to land. To check in the code: where the AIR's
public values come from today (`block_air.rs`, `aggregate.rs`), and what
the recursion passes up.

**Consensus.** `Chain::apply_block` reads the amounts of the positions the
block spends from the state, sums both sides, and refuses the block unless
the equality holds, before the proof is checked (a cheap check first).
The chain keeps the unspent total in its database, updated with each
block and restored from the block's undo record when a reorganization
rolls the block back, so the total always matches the main chain's tip
without summing the whole state again.
The UTXO set keeps each output's amount with its commitment and memo
(`utxo.rs`): with the shorter memo, four bytes less an entry.

**Fast sync.** A snapshot part carries each output's amount (with the
shorter memo, `PART_ENTRY` shrinks by 4 bytes), checked against the
part's root like the rest. Once every part is in, the node sums the
amounts and refuses the snapshot
unless the total is exactly `issued(h)` for its height: a node that fast
syncs checks the supply of everything before it without replaying it. The
manifest may carry the total too, as a convenience; the sum of the parts
is what counts.

**State proofs.** A `Proof` message (`GetProof`, which payment proofs in
`docs/PROOFS.md` use) carries the output's amount, and the leaf it checks
includes it.

**The wallet.** The memo carries the nonce and the tag only; `scan` reads
an output's amount from the chain and confirms a tag's match by the
commitment. `balance` and `outputs` are unchanged.
`status` shows a supply line: the unspent total beside `issued(h)`, which
every node can now compute.

## Burns

A burn is an output to the key hash zero, which no key hashes to, with
its memo naming the beneficiary; how it is made and proven is in
`docs/PROOFS.md`. For the supply it is an ordinary output: it stays in
the state for good and counts in the unspent total, so the invariant
stays an equality; it is only that nobody can ever spend it.

## Cost

The amount's eight bytes less the memo's twelve: an output on chain goes
from 64 bytes to 60, so blocks get a little smaller (some 80 KB at
10,000 two-output transactions). The same in the state: four bytes less
per unspent output (about 0.7 GB less at a Bitcoin-sized set of 170
million). A few more trace
columns in the transaction AIR and the state-update rows; the proof's
size hardly moves. The check itself is one sum per block.

## Privacy

Before: the chain shows which positions each block spends and creates,
and nothing about value. After: it shows the value of every output, so
anyone can follow value along the graph, as on Bitcoin, without knowing
who holds it (key hashes and memos stay hidden). The mempool showed the
amounts already, to whoever was watching at the time; the chain now keeps
them for good.

Channels are no exception. A channel's funding output, a policy output,
shows its amount, the channel's capacity; a unilateral close shows the
balances it settles to. The states in between are never published, so
the payments inside a channel stay off chain, as before. None of this was
private before either: every transaction that funded or closed a channel
crossed the mempool with its amounts in the clear.

## Migration

The block format, the state leaf, the AIR and the snapshot format all
change: a new chain format and protocol version, wiped data directories,
a regenerated genesis, and the seeds updated. Before launch this is a
rebuild, not a fork.

## Decisions

Settled on 2026-11-02.

- **Equality.** A miner claims the whole subsidy and every fee; the
  unspent total is exactly `issued(h)`.
- **Burns are outputs to the key hash zero** with the beneficiary in the
  memo (`docs/PROOFS.md`), not unclaimed rewards.
- **The memo shrinks to the nonce and the tag**, 20 bytes; the encrypted
  amount goes.
- **`status` shows the supply.**

## Implementation order

1. The leaf and the block output with an amount, the memo of five
   elements (the last three of the leaf's and body's memo constrained
   zero); the body commitment.
2. The transaction AIR: amounts as public values, bound to the
   commitments and hashed into the leaves; the in-circuit balance kept.
3. `apply_block`: amounts from the state for the inputs, the equality.
4. The UTXO set and snapshot parts with amounts; the total checked on
   fast sync.
5. State proofs, the wallet's `scan`, `status`'s supply line; the unspent
   total in the chain's database, undone with the block on a
   reorganization.
6. Tests: a block that inflates by one base unit, or claims one too few,
   is refused before its proof is checked, whatever the proof says (with
   the proof checker that accepts anything); a block whose outputs sum
   past 2⁶⁴ is refused; a snapshot whose total is not `issued(h)` is
   refused; the chain's unspent total equals `issued(h)` after every
   block, and again after a reorganization rolls blocks back.
7. Docs: README, SECURITY.md (the supply no longer rests on the proof),
   HARDENING.md.
