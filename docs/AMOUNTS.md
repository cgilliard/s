# Public amounts

A design note, 2026-11-02: put every output's amount on chain, in the
clear, so that every node checks the money supply with plain arithmetic,
outside the validity proof. Implemented 2026-11-02; the sections below
describe it as built.

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

Let `issued(h)` be what genesis created plus the subsidies of blocks 1 to
`h` (`Chain::issued`, from `ChainParams::issued`). On mainnet genesis is
empty, as a fair launch has nothing before its first block, so `issued(0)`
is zero; the chain records what its genesis created (test chains start
with coins) and counts it, which is sound because a network's genesis is
fixed by its parameters (`WrongGenesis` otherwise).
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

Every sum is taken in 128 bits: an amount is a `u64`, but a block's
outputs, the amounts it spends, the unspent total and `issued(h)` are
sums of them, and a sum that wrapped around 2⁶⁴ could make the equality
hold for a block that mints. In 128 bits no sum of a block's amounts can
wrap, so such a block simply fails the equality.

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

**The memo.** It held a nonce (four field elements, from which the
wallet derives the output's key), the amount encrypted under a pad from
the wallet's master key (three), and a recognition tag (one), by which a
scan tells the wallet's outputs from others' in one comparison
(`Wallet::memo`). With the amount public the middle three are dead
weight, so the memo is now the nonce and the tag: five elements, 20
bytes (`transaction::Memo`). Neither is a secret, and 128-bit strength is not the measure: the
nonce is in the clear and the keys' security rests on the master key,
so the nonce need only be unique (about 124 bits: two of a wallet's
outputs sharing one, which would reuse a key, is about `n²/2¹²⁵`); the
tag sets only how often a scan takes a stranger's output for its own
(once in 2³¹), and a match is confirmed by recomputing the commitment
from the derived key and the public amount. Nothing else needs the 32
bytes: name commits use the wallet's memo; policy and channel outputs
take whatever the caller gives and nothing reads it; covenants and
rebindable signatures hash an output's memo as a digest; a burn's tag
(`docs/PROOFS.md`) fits in five elements (about 155 bits). A name's
record keeps its own 32-byte memo, apart from outputs'; the wallet writes
its five elements there padded with zeros.

**The memo slot.** Everywhere an output's memo was hashed as eight
elements (its state leaf, the block's outputs sponge, the transaction
body the signatures cover, covenants and rebindable messages), what is
hashed now is its slot (`transaction::memo_slot`): the memo's five
elements, then the amount as three limbs of 30, 30 and 4 bits, each
below the BabyBear modulus. The amount is then bound wherever the memo
was, with no new hashing:

```
slot = memo(5) ‖ amount limbs(3)
leaf = compress(compress(commitment, slot), height_digest(created))
```

so the state root, and so the chain proof, covers each output's amount,
and a spend reads the amount from the leaf it opens. A name commit is an
output of amount zero, its slot the memo and three zeros.

**The circuit.** One constraint, on the rows that hash an amount into a
commitment (an input's or policy input's `cm1`, an output's `ocm1`): the
memo register's last three elements equal the amount's limbs there
(`block_air.rs`, "the memo slot's last three elements"). Since that
register is what the leaf and the outputs sponge take, the amount in a
spent leaf, and the amount a block lists, is the amount the commitment
hides and the in-circuit sums count. Nothing new is public: the block's
listed amounts reach the proof through the outputs sponge, whose final
state the chain statement already carries (`block_air::outputs_state`).
The balance constraint inside the circuit stays, as a second line of
defence: the in-circuit and out-of-circuit checks have to fail together
for a counterfeit to land. The test
`the_amount_in_the_leaf_is_the_committed_one` spends an output whose leaf
holds another amount than its commitment, which the constraint alone
refuses.

**Consensus.** `Chain::connect` reads the amounts of the positions the
block spends from the state, sums both sides, and refuses the block
(`ChainError::Supply`) unless the equality holds, after the state root
and before the proof is checked (cheap checks first). The chain keeps the
unspent total in its database (`supply`), updated with each block and
restored from the spent log when a reorganization rolls a block back, and
checks it against `issued(h)` both ways, so the total always matches the
main chain's tip without summing the whole state again.
The UTXO set keeps each output's amount with its commitment and memo
(`utxo.rs`): 64 bytes a record with the creation height, four less than
before.

**Fast sync.** A snapshot part carries each output's memo and amount
(`PART_ENTRY` 4 bytes shorter), checked against the part's root like the
rest. Once every part is in, the node sums the amounts and refuses the
snapshot unless the total is exactly `issued(h)` for its height: a node
that fast syncs checks the supply of everything before it without
replaying it. The manifest does not carry the total; the sum of the parts
is what counts.

**State proofs.** A `Proof` message (`GetProof`, which payment proofs in
`docs/PROOFS.md` use) carries the output's memo and amount, and the leaf
it checks includes them.

**The wallet.** The memo carries the nonce and the tag only; `scan` reads
an output's amount from the chain and confirms a tag's match by the
commitment. `balance` and `outputs` are unchanged.
`status` shows a supply line: the unspent total beside `issued(h)`.

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
million). No new trace columns: three constraints of degree two in the
transaction AIR. The check itself is one sum per block.

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
change: chain format 14, protocol version 6, slate format `tabslt04`,
regenerated `MAINNET_CHAIN` constants, wiped data directories and
wallets, and the seeds updated. Genesis, empty, is unchanged. Before
launch this is a rebuild, not a fork.

## Decisions

Settled on 2026-11-02.

- **Equality.** A miner claims the whole subsidy and every fee; the
  unspent total is exactly `issued(h)`.
- **Burns are outputs to the key hash zero** with the beneficiary in the
  memo (`docs/PROOFS.md`), not unclaimed rewards.
- **The memo shrinks to the nonce and the tag**, 20 bytes; the encrypted
  amount goes.
- **`status` shows the supply.**

## Tests

- `chain::tests::blocks_keep_the_supply`: with the proof checker that
  accepts anything, a block that inflates by one base unit, claims one
  too few, claims nothing, or whose outputs wrap past 2⁶⁴ to the right
  sum is refused; the unspent total equals `issued(h)` after each block
  and after a reorganization replaces two blocks with three.
- `chain::tests::fast_sync_from_a_snapshot`: the total arrives with the
  snapshot; a node whose schedule issues more by that height refuses the
  same snapshot.
- `chain::tests::issued_sums_the_schedule`.
- `block_air::tests::the_amount_in_the_leaf_is_the_committed_one`: the
  circuit refuses a spend whose leaf amount is not its commitment's.
- `node::tests::state_proofs_verify_against_the_tip`: a proof with
  another amount does not verify.
