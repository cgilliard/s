# Names

A post-quantum name registry in the state tree. A name resolves to a
32-byte value, the hash of its owner's Dilithium key (the owner's onion
identity, `docs/ONION.md`), from which the message layer derives the
owner's rendezvous points and obtains the keys themselves. Registration is commit-then-reveal, as in Namecoin;
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
| value | 32 | `H(Dilithium key)`, the owner's payment identity (`docs/ONION.md`); written as a `tab1…` address |
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
- **High half, names.** A binary trie keyed by a one followed by
  `KEY_BITS` (120) bits of `H(name)`, four 30-bit limbs. The trie is
  canonical: a leaf sits at the first depth at which its key's prefix is
  unique among the names registered, so with `n` names paths are about
  `log2(n)` levels below the half's root, deeper only where two keys
  share a longer prefix, and never deeper than the key is long. A leaf
  is hashed under its own domain, distinct from internal nodes, and
  carries its key, so a path cannot stop early at another name's leaf.
  Non-membership is a path ending at an empty slot or at a leaf with a
  different key. The empty trie's root is the hash of the empty subtree
  the state tree had there before, so a chain without names keeps its
  state roots.

Collisions cannot block a name: a registration whose key shares `d` bits
with a name's only pushes that name's leaf one level deeper, at about
`2^d` hashes and one registration per level, and a path can grow no
deeper than the 120-bit key. Names and outputs never share a slot, since
their paths start with different bits.

The name half stores its nodes sparsely, 32 bytes each: about `log2(n)`
nodes unique to a name, under a kilobyte, plus the record.

Commit records live in the low half at counter positions, like outputs,
and are removed when revealed or swept.

## Operations

Name operations are items of an ordinary transaction, next to its inputs
and outputs. The transaction's inputs sign them (they are part of the
signed body) and pay their fee, which goes to the miner like any fee.
There is no consensus fee. Commits may repeat (two transactions may
commit the same hash): a reveal names its commit by position, and the
registry's hash index is a convenience for wallets.

| op | effect | body bytes | in the proof only |
|---|---|---|---|
| commit | stores `c = H(H(name), salt, owner)` with the block height and a memo at the next counter position | 1 + 32 + 32 | the fee payer's inputs |
| reveal | `MIN_REVEAL` to `MAX_REVEAL` blocks after the commit: recomputes `c`, proves the commit record and its height, deletes it, proves the name's slot empty, inserts the record; lists the commit's position | 1 + (1..33) + 32 + 32 + 32 + 5 | salt |
| update | signed by the current owner key: writes a new owner hash, value and memo; covers transfer, key rotation and value changes | as reveal | the XMSS signature and public key |
| sweep | deletes a commit past `MAX_REVEAL`; filled in by the miner, no transaction | 1 + 5 | |

A reveal needs no owner signature: the commit binds the owner hash, so
anyone who learns the salt can only register the name to that owner.

An update's signature is over the new record (its name hash, owner, value
and memo) under its own domain, and the new owner must differ from the
current one: the key rotates with every signed operation, so a captured
signature cannot be replayed to revert a later update.

Each operation has a digest over its tag and public fields (not the salt
or the signature), hashed in whole sponge blocks. The transaction body
carries one digest per operation after its outputs, so the inputs sign
the operations; the block commitment covers the same digests; and the
transaction and name segments of the proof agree on them. A commit takes
the counter position after the block's outputs, in operation order.

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

Dilithium never touches consensus. Its hash is the record's value; the
key, and the ephemeral Kyber keys it signs, are revealed at the
rendezvous points derived from that hash, and a payer checks them against
the chain.

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

Sub-names are a message-layer feature, not a chain feature, specified in
`docs/SUBNAMES.md`. The holder of a name's value may delegate its
sub-names to up to three servers, by a signed delegation held at its
rendezvous points; with none, its own node answers. Resolving
`cool.example` is a chain lookup of `example`, the delegation from its
value's rendezvous points, a sealed query to a server, whose signed
answer gives an id, then the normal payment to that id.

Sub-names are therefore free, unlimited and changeable at runtime, and
entirely under the parent's control; anyone wanting an identity the
parent cannot touch registers a top-level name. They exist because a
block admits five reveals: one name can carry as many users as its
owner admits.

## The proof

One block proof, as today. Each block has exactly one **name segment**,
a fixed-shape proof of `NAME_ROWS` (2^15) rows holding all of the
block's name operations and sweeps, proven beside the transaction
segments at their parameters and verified by the root of the
aggregation tree as one more child. Its cost is one extra segment per
block, paid whether or not the block has name operations.

The name segment's circuit (`name_air.rs`) hashes the name (one row per
eight characters, each checked to be a charset value or zero padding),
decomposes the hash into the 120 key bits, hashes the records and their
trie leaves, recomputes a reveal's commit and the output leaf it occupies,
checks the reveal window or a sweep's expiry against the block height,
and walks the state tree top down, two rows a level, from the root to a
terminal: a commit's empty slot, a revealed or swept commit's leaf, a
name's current leaf for an update, or, for a reveal, the empty slot or
colliding leaf where the name goes, continued by one row per level of
the chain down to the first bit where the two keys differ (a second
register of the colliding key's bits checks the split). Updates verify
the owner's XMSS signature with the same fragment the transaction
segments use (`xmss_fragment.rs`), check the key's hash is the current
owner and that the new owner differs.

Its public values are the state root and next output position before and
after, the operations sponge, the sweeps sponge, the block height and the
four counts. The root of the aggregation tree checks that the segment
continues from the last transaction segment's root and position to the
statement's, that its operations sponge equals the transaction segments'
and the statement's (every operation applied was signed by a
transaction's inputs, in this order, and none was skipped), that its
sweeps sponge is the statement's, its height the block's and each count
within its cap. The statement (what the chain proof carries) gains the
height, the operations state and the sweeps state, and its end position
counts commits.

Transaction segments bind their operations as a third kind of item after
the outputs, two rows each: the operation's digest is a witness absorbed
into the signed body and into the operations sponge, which chains across
segments like the input and output sponges. Operation digests cover the
public fields only: a commit's hash and memo, or a record's leaf value
(the hash of its name hash, owner, value and memo), so the segment hashes
each name once.

Rows per operation: a commit 90, a sweep 88, a reveal 118 plus two a trie
level and one a split level, an update 1,181 (the signature is 1,150)
plus two a trie level. At the caps with 40-level trie paths that is about
13,400 rows, within 2^15. The circuit has 995 columns, against the
transaction segment's 766; at mainnet parameters the segment proves in
about 2.4 s, empty or full, and verifies natively in 27 ms.

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
| `KEY_BITS`, the deepest a name path can be | 120 |
| `MIN_REVEAL`, `MAX_REVEAL` | 12, 288 blocks |
| caps per block | 5 reveals, 8 commits, 8 updates, 16 sweeps |
| `NAME_ROWS` | 2^15 |

## Implementation order

1. **Tree and storage.** Done: `name_trie.rs` (the canonical trie with
   insert, update, remove for undo, membership and non-membership proofs
   and range iteration), `names.rs` (names as elements, records, the
   registry and the commit tables), the state tree's stored right half
   and output capacity `2^39`. Tests use chosen keys to force deep
   collisions.
2. **Formats.** Done: `NameOp` and `BlockNameOp` in `names.rs` with the
   caps and window constants, the operation digest and the update
   message; transactions carry and sign operations; the block body's
   name section (operations, then swept positions) with validation of
   caps, names and sweep positions; size accounting; chain format 10,
   protocol v5 and a new genesis id (the body commitment changed). The
   wallet format is unchanged until it stores name data (step 6). Until
   step 4 the chain refuses bodies with a name section and the pool
   refuses transactions with operations.
3. **Circuit.** Done: `xmss_fragment.rs` (the signature verifier shared
   by both segment circuits), the transaction segment's operation items
   and sponge, `name_air.rs` with its witness collector (which applies a
   block's name section to the stores and is what the chain will use),
   the root program's name child and checks, the statement's new fields,
   the native verifier in `block_proof.rs`, `MAINNET_CHAIN` regenerated,
   the soundness table extended. Tests prove blocks carrying commits,
   reveals and updates end to end at the small parameters.
4. **Chain.** Done: the chain owns the registry; `NameSet::apply` and
   `undo` (shared with the circuit's witness collector) apply a block's
   name section and reverse it from an undo record that keeps the
   commits made and consumed, the keys registered and the records
   replaced; consumed commits join the spent log; the template applies
   the name section. Snapshots carry the name half: the manifest holds
   the name root and name parts (groups of key buckets of up to 4,096
   records, each part its first key and a hash of its buckets' hashes;
   the registry keeps a count and hash per bucket, the top 16 key bits,
   as records change, so a snapshot reads the bucket table and never the
   records), output parts list which outputs are commits (hash and
   height, checked against the leaf), name parts are served as the
   records were at the snapshot by undoing later blocks, and the trie is
   rebuilt from them and checked against the name root. Moving to a
   later snapshot carries output parts, and keeps the staged name
   records: the later manifest's name parts whose ranges hash to the
   same value are satisfied by them, and only the ranges with a name
   operation since are cleared and fetched again. Chain format 12. The body gained the position of the
   commit a reveal spends (unsigned, like an input's position; the body
   commitment covers it), since a node cannot find the commit without
   the salt. The pool still refuses transactions with operations, and
   the miner builds empty name segments, until step 5.
5. **Pool and miner.** Done. The pool checks a transaction's operations
   against the registry as the chain would, less what only the proof
   knows: a reveal's commit must sit at the position named with the hash
   its name, salt and owner give, and not be past its window (one whose
   window has not opened is pooled and mined once it has); the name must
   be free for a reveal and registered for an update signed by the
   current owner. Each name and each commit position is claimed by one
   pooled transaction; a second claim is refused rather than replaced,
   since no fee rule makes the two comparable. Revalidation after every
   block drops transactions whose claims the chain settled otherwise.
   The miner selects by fee rate within the caps, passing over what does
   not fit or whose window is closed, sweeps up to 16 expired commits a
   block, sizes the name section into the block limit, and rebuilds the
   block without its name operations if the state moved under them.
   Transactions with operations relay like any other.
6. **Wallet and prompt.** Done. One nonce per registration gives the
   owner key (its own domain), the commit salt and the memo (the output
   memo with a zero amount) of both the commit's output and the record.
   `name-commit`, `name-reveal NAME [WAIT]`, `name-update`, `name-offer`
   (the recipient writes a record under a fresh key) and `name-transfer`
   (the owner signs it over), `names` and `name NAME`; operations ride in
   a transaction of the wallet's that pays their fee, cancellable like a
   payment. The wallet reconciles its names with the chain's records
   after every tip change: a rotation settles when the record names the
   new key, an offered name arrives, a transferred one leaves. `scan`
   recovers names from the records and pending commits from the commit
   outputs; a recovered commit's name is matched when the user reveals
   it. Owner keys sign from leaves 0 to 7, or 8 to 15 when recovered, as
   output keys do. Wallet format 5. The pool's minimum fee is by
   transaction size, so operations pay for their bytes.
   Scale test (2026-11-01, two debug nodes filled with 10M synthetic
   names by `--debug-fill-names`, one in RAM and one on disk): fill
   10M in 944 s in RAM and 2,830 s on disk, bucket rebuild 116 s;
   registry 4.9 GB (trie 2.9 GB, records 2.0 GB, buckets 3.4 MB); point
   lookups instant; block build with a name op 0.02 s; block accept
   0.05 s, 0.12 s on snapshot blocks; commit, reveal and update
   confirmed; a third start fast-synced the registry from the other node
   in about 24 minutes (2,489 name parts, 2 GB, trie rebuilt and name
   root matched), then followed the chain to the same tip. Found and
   fixed along the way: snapshots read every record (bucket table), and
   a snapshot move discarded all staged name parts (carried by hash now).
   Open: served-part cache and lone-peer handling, see HARDENING.md.

7. **Docs.** README, SECURITY.md, HARDENING.md for anything new; a note
   on the zone format for the rendezvous layer.

Steps 1 and 2 are independent; 3 needs both; 4 to 6 follow in order.
