# Names

A post-quantum name registry in the state tree. A name resolves to a
32-byte value, the hash of its owner's Kyber and Dilithium keys, from which
the payment layer derives the owner's rendezvous points and obtains the
keys themselves. Registration is commit-then-reveal, as in Namecoin;
ownership is perpetual and transferable; the chain verifies only XMSS
signatures, as it does for payments.

This is the design as settled on 2026-10-31. Constants are listed at the
end.

## Names and records

A name is one label of 1 to 32 characters from `[a-z0-9_]`. There is no
hierarchy on chain: no dots, no sub-names (see "Sub-names" below).

A name's record is

| field | bytes | meaning |
|---|---|---|
| name | 1 + 1..32 | length and the characters |
| owner | 32 | hash of the XMSS public key that may update the record |
| value | 32 | `H(Kyber key ‖ Dilithium key)`, the owner's payment identity |
| memo | 32 | the owner's wallet data: the nonce of the owner key and a check value |

Every node keeps every record, keyed by the name's hash, and answers
lookups from it. Fast sync transfers the records by key range and checks
them against the state root.

Ownership never expires. A name whose owner key is lost is dead.

## The tree

The state tree keeps its depth-40 base and its root in the header. The
first bit of a path selects a half:

- **Low half, outputs.** Counter positions below `2^39`, leaves always at
  depth 40. Storage (buckets, 256-leaf groups), circuit fragment and body
  format are unchanged. The output counter refuses `2^39`.
- **High half, names.** A binary trie keyed by a one followed by the
  bits of `H(name)`. A leaf sits at the depth where its key prefix is
  unique: 40 in the normal case, deeper only where hashes collide, at
  most `NAME_DEPTH` (120). A leaf is hashed under its own domain, distinct
  from internal nodes, and carries the full key hash, so a path cannot
  stop early at another name's leaf. Non-membership is a path ending at
  an empty slot or at a leaf with a different key hash.

Collisions cannot block a name: a colliding registration only deepens
the victim's path by one level, which costs the attacker about
`2^(39+k)` hashes and a registration for the `k`-th level. Pushing a name
past the depth cap would take `2^119` hashes. Names and outputs never
share a slot, since their paths start with different bits.

The name half stores its path nodes sparsely, about 32 bytes per node
unique to a name: roughly 640 bytes at a million names, plus the record.

Commit records live in the low half at counter positions, like outputs,
and are removed when revealed or swept.

## Operations

Name operations are items of an ordinary transaction, next to its inputs
and outputs. The transaction's inputs sign them (they are part of the
signed body) and pay their fee, which goes to the miner like any fee.
There is no consensus fee.

| op | effect | body bytes | in the proof only |
|---|---|---|---|
| commit | stores `c = H(name, salt, owner)` with the block height and a memo at the next counter position | 1 + 32 + 32 | the fee payer's inputs |
| reveal | `MIN_REVEAL` to `MAX_REVEAL` blocks after the commit: recomputes `c`, proves the commit record and its height, deletes it, proves the name's slot empty, inserts the record | 1 + (1..33) + 32 + 32 + 32 | salt |
| update | signed by the current owner key: writes a new owner hash, value and memo; covers transfer, key rotation and value changes | as reveal | the XMSS signature and public key |
| sweep | deletes a commit past `MAX_REVEAL`; filled in by the miner, no transaction | 1 + 5 | |

A reveal needs no owner signature: the commit binds the owner hash, so
anyone who learns the salt can only register the name to that owner.

Sweeping is garbage collection. The circuit proves every swept commit
was expired; whether every expired commit is swept is a miner default,
not a rule, since a node cannot prove completeness without the commit
lists of past blocks.

### Caps

Consensus caps, per block, by count:

| op | cap |
|---|---|
| reveal | 5 |
| commit | 8 |
| update | 8 |
| sweep | 16 |

The reveal cap is the one that shapes the system: at most 5 new names a
block, 720 a day, about 263,000 a year, which at about a kilobyte each
(record and tree nodes) is about 300 MB a year at saturation. The others
exist so that the name segment has a fixed size; the miner counts
operations and never rows.

### The commit window

A reveal is valid from `MIN_REVEAL` (12) to `MAX_REVEAL` (288) blocks
after its commit. To take a name after seeing its reveal, an attacker
must rewrite the chain from before the commit to put its own commit
first, then mine to its own reveal: a reorganization as deep as the gap
between the victim's commit and reveal. `MIN_REVEAL` is the floor a
careless registrant gets; `MAX_REVEAL` is how much depth a careful one
can buy by waiting, two days. The wallet's reveal command takes a
minimum wait for that purpose and warns when the minimum is used.

## Keys and recovery

Owner keys are XMSS keys with 16 leaves, derived from the wallet's phrase
and a nonce exactly as output keys are, under a separate domain. Every
operation signed by an owner key rotates the record to a fresh key with a
fresh nonce, so no key is long-lived and none runs out; the 16 leaves
exist for cancellations, as with outputs. The circuit verifies only
XMSS.

The record's memo holds the owner key's nonce and a check value, the
output memo layout with the amount unused, so `scan` recovers names from
the records every node keeps. Commits carry a memo too, and the salt is
derived from the seed and the commit's nonce, so a wallet restored
between commit and reveal can still reveal. A restored wallet signs from
leaves 8 to 15, as for outputs.

Kyber and Dilithium never touch consensus. Their hash is the record's
value; the keys are revealed at the rendezvous points derived from that
hash, and a payer checks them against the chain.

### Walk-throughs

**Register `example`.** The wallet draws a nonce, derives the owner key
`K1` and its hash `O1`, derives the salt, computes `c`, and submits a
transaction paying the fee with `commit(c, memo)`. After the wait it
submits one with `reveal(example, salt, O1, value, memo)`. `K1` has
signed nothing yet.

**Rotate payment keys or change the value.** `update` signed by `K1`,
writing the new value and the hash of a fresh key `K2`.

**Transfer to Bob.** Bob's wallet derives a key and hands over its hash
and a memo (and the value Bob wants) in a small file. Alice submits
`update` signed by her current key with Bob's fields. Bob's wallet finds
the record by name or by scan.

## Sub-names

Sub-names are a payment-layer feature, not a chain feature. A name's
owner publishes a signed zone to its rendezvous points: a sequence
number and `label → payment hash` entries, signed by the Dilithium key
whose hash is the name's value. Resolving `cool.example` is a chain
lookup of `example`, a fetch of the zone from `example`'s rendezvous
points with a signature check (the sequence number stops a stale zone),
then the normal handshake at `cool.example`'s own rendezvous points.

Sub-names are therefore free, unlimited and changeable at runtime, and
entirely under the parent's control; anyone wanting an identity the
parent cannot touch registers a top-level name. The zone format belongs
to the rendezvous layer's specification.

## The proof

One block proof, as today. Each block has exactly one **name segment**,
a fixed-shape proof of `NAME_ROWS` (2^15) rows holding all of the
block's name operations, proven beside the transaction segments and
aggregated with them. Its cost is one extra segment per block, paid
whether or not the block has name operations.

The name segment's AIR does the trie walks (a variable-depth walk under
the cap, two rows a level), the commit hash and charset checks (one
lookup per character against a table of the 37 allowed values), and the
XMSS verification for updates. Its public values carry the state root
before and after, the block height, a sponge over the operations in
order, and the four counts. The aggregator checks the counts against the
caps, chains the root through the transaction segments and the name
segment, and checks the operations sponge against the block body's name
section.

Transactions bind their name operations through public values: each
transaction segment absorbs the digests of the operations its
transactions carry into a sponge that chains across segments, the name
segment absorbs the same digests in the same order, and the aggregator
checks the two agree. An operation is therefore signed by the inputs of
the transaction that carries it and proven in the name segment.

Worst-case rows at the caps, paths at the depth cap:

| op | rows each | total |
|---|---|---|
| reveal | 480 | 2,400 |
| commit | 240 | 1,920 |
| update | 1,740 | 13,920 |
| sweep | 240 | 3,840 |

about 22,000, within 2^15.

## Block body

The body gains a name section after the outputs: the operations in
order, each as in the table above, then the swept positions. The body
commitment covers it. Everything a node needs to apply the block is
published; salts, signatures, keys and which transaction carried an
operation are not.

## Constants

| constant | value |
|---|---|
| name length | 1 to 32 characters of `[a-z0-9_]` |
| value | 32 bytes |
| output positions | below `2^39` |
| `NAME_DEPTH` | 120 |
| `MIN_REVEAL`, `MAX_REVEAL` | 12, 288 blocks |
| caps per block | 5 reveals, 8 commits, 8 updates, 16 sweeps |
| `NAME_ROWS` | 2^15 |

## Implementation order

1. **Tree and storage.** Variable-depth paths in the high half with the
   leaf domain and key hash; insert, delete, membership and
   non-membership proofs; the record and commit tables; undo entries;
   snapshot parts by key range; output capacity `2^39`. Tests against a
   plain map, with a hook to inject colliding keys.
2. **Formats.** `NameOp`; transaction body and signing; the block body's
   name section; size accounting; chain and wallet format bumps.
3. **Circuit.** The name segment AIR; the transaction segment's
   operations sponge; aggregator checks; the name segment in the proof
   plan; regenerate `MAINNET_CHAIN` and the soundness table; measure the
   added proving time.
4. **Chain.** Apply and disconnect with undo; template; fast sync of the
   name half; pruning.
5. **Pool and miner.** Rules for duplicate names and records, commit
   timing, pending commits; selection of the best reveals by fee within
   the caps; sweeps; relay.
6. **Wallet and prompt.** `name-commit`, `name-reveal [--after N]`,
   `name-update`, `name-transfer`, `names`, `name NAME`; `scan` over
   records and commits.
7. **Docs.** README, SECURITY.md, HARDENING.md for anything new; a note
   on the zone format for the rendezvous layer.

Steps 1 and 2 are independent; 3 needs both; 4 to 6 follow in order.
