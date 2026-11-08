# The node

Written 2026-11-07, to be tracked; not built. This is the plan for
`docs/OS.md`'s step 12: the full node, written in fam, running on the
OS as a daemon. It covers what the node does, how it fits the machine,
the API it offers, and the order to build it in.

Paths in `miner/src` are to the Rust node, tabminer. It is the
reference: the fam node must accept and reject exactly the blocks and
transactions it does.

## Decided

- **Verification only.** The node does not prove or mine.
- **A daemon with an API.** It has no interface of its own; wallets and
  other clients use its HTTP API, served by its own process.
- **An API token.** Every request carries it (The API, below).
- **A 25 GB disk.** It holds essentially the whole chain, even at
  Bitcoin's scale, with tabminer's full undo window. The store must be
  made to scale to it first (step 0).
- **The work in the chain proof.** Each block's chain proof attests to
  its parent's proof of work, and the proof of work reads aligned
  windows of the seed text (The work in the chain proof, below): a
  change to tabminer, made first, so the node never checks old work.
- **No M extension.** RV32I as everywhere else: products in software,
  and the verification loop optimised until it is fast enough.
  Verification without M has been done before.

## What it is

- **A verifying node.** It checks every block and transaction it
  accepts against the consensus rules, keeps the chain's state, and
  relays what is valid. It does not prove and does not mine:
  - no block proofs (`block_air`, `name_air`, `smt_air`, `xmss_air`,
    `recursion`, and the provers in `aggregate`, `stark` and `fri`);
  - no proof-of-work search, and no 64 MB dataset;
  - no block templates (`Mempool::select`).
  Mining stays with tabminer, which a fam node peers with like any
  other.
- **Purely a daemon.** It has no user interface: no screen, no
  prompts, no wallet. Everything it knows and does is reached through
  its API (below). Wallets, explorers and anything else with a face
  are separate programs, inside the OS or outside it, that use the
  API. The node holds no keys; signing is the wallets' business.
- **Its own process, its own HTTP server.** The API is HTTP, served by
  the node's own process on its own port. It may share code with
  `wm`'s server (`src/user/wm.fam`'s request parsing, its WebSocket
  framing), but it is a different program: nothing passes through
  `wm`, and `wm` need not be running.

## What it checks

As `Chain::apply_block` does (`miner/src/chain.rs:1453`, its rules
listed at 25-44), in the same order.

### A header

- Its parent is known and not invalid, and its height is its parent's
  plus one, up to `final_height()`.
- Its timestamp is above the median of the last 11, and at most two
  hours ahead.
- Its target is the ASERT (aserti3-2d) target after its parent: 600 s
  blocks with a half-life of two days, as U256 arithmetic
  (`difficulty.rs`).
- Its proof-of-work (below) meets that target.
- Fork choice uses cumulative work: 2^256 / (target + 1) per block.

### A body

- Its commitment matches the header, and `Body::validate` holds: no
  duplicate or out-of-range inputs, and the operation caps. It is at
  most 2,000,000 bytes.
- Applying it:
  - each input is unspent at its position, and the outputs are added;
  - the name operations are valid (`names.rs:1154`);
  - the new state root equals the header's;
  - supply: the outputs equal what is spent plus the subsidy, and the
    running supply equals `issued(height)`.
- **The block's proof:** one recursive *chain proof* that attests to
  this block and every one before it (`aggregate.rs:31-35`), checked
  against the block's statement (`Statement::from_block`). Balances,
  signatures and commitment preimages are inside the proof; the node
  checks them only through it.
- On a reorganisation, blocks are disconnected with their undo records
  and the new branch connected, as `chain.rs:1504-1549` does.

### A transaction (for the pool)

As `Mempool::insert` checks it (`mempool.rs:720-770`):
- it decodes, has at least one input, and pays a fee at or above the
  admission minimum;
- its inputs are unspent and its name operations valid;
- conflicts and replacements follow the pool's rules;
- its **XMSS signatures** verify (WOTS+, w = 16, 67 chains:
  `xmss.rs:343`), and so do its policy inputs.

Fees are policy, not consensus (`docs/FEES.md`): the pool's rules
(minimum rate, replacement, ageing, expiry) are the node's own and may
differ from tabminer's.

## The work, on this machine

RV32I has no multiply and no 64-bit registers. Everything below is in
fam, on one or a few harts under QEMU. The estimates here are to be
measured in the first step, and the plan adjusted to what is found.

- **Field arithmetic.** BabyBear (p = 0x78000001, Montgomery form) and
  its degree-4 extension (W = 11). A product needs a 32×32→64 multiply
  done in software, from 16-bit halves, since there is no M extension
  (decided). This is the inner loop of everything else, so it is
  written first and then optimised: machine code words as the kernel's
  are, Poseidon2's rounds unrolled, constants laid out for the loop,
  reductions deferred where the bounds allow.
- **Poseidon2.** Width 16, x^7, 8 full and 13 partial rounds,
  bit-compatible with Plonky3's `default_babybear_poseidon2_16`. A
  permutation is roughly 800 field products. Estimate: around
  100,000 instructions each.
- **The chain proof.** About 205 KB per block, from the published
  parameters (`aggregate.rs:145`):
  - rate 1/32, 22 queries, 16 bits of grinding, zero-knowledge;
  - FRI folding by 4;
  - two tables: the VM (92 columns) and the hash table (about 314).
  Verifying it means Merkle paths, the FRI checks and the AIR
  constraints at the out-of-domain point. Rough estimate: on the
  order of 10^4 permutations, so seconds per block.
- **Proof-of-work.** An Ethash-like hashimoto over Poseidon2 (`pow.rs`).
  The node takes the light path: each item it needs is computed from
  the seed text instead of a 64 MB dataset:
  - 64 accesses × 2 items × 257 permutations ≈ 33,000 permutations a
    header, so several seconds each by the estimate above;
  - it needs the seed (the King James text, 1.29 MB gzipped,
    4.34 MB inflated) with random access: inflated once at start,
    held in memory;
  - `quick_pow_check` (2 permutations) runs first, to throw out junk
    cheaply.
- **Wide integers.** U256 for targets and work; 64-bit amounts and
  supply; u64 `%` for seed offsets; a u128 logarithm for the grinding
  check. They are small routines over words.

A block every 600 s leaves room: a header, its proof and its state
change should take well under a minute. Catching up is the hard case
(below).

## Syncing

As tabminer (`node.rs:10-56`), within the machine's limits:

1. **Headers first**, `GetHeadersFrom` in batches of 60 from several
   peers, each header's rules and proof-of-work checked.
2. **Fast sync**, the default:
   - pick a block about 144 deep;
   - fetch its snapshot (a manifest and its parts) and check them
     against the block's state root;
   - verify that block's chain proof, which covers all history before
     it.
   No block before it is replayed.
3. **Bodies after that**, each block applied as above, then follow
   the tip.

Proof-of-work over a long header chain is settled by
the work in the chain proof (below): each block's chain proof attests to its parent's
work, so a node:
- checks every header's cheap rules natively: link, timestamps, ASERT
  target, and `quick_pow_check` (two permutations a header);
- trusts the work before the sync block to its chain proof;
- checks the full proof of work only for the headers after it.
No checkpoints, so no one has to keep shipping trusted values.

## Its state

In the OS's store, in a tree of the node's own (`docs/OS.md`, section
6): transactional, so a crash leaves the last committed block, never a
half-applied one.

- **The state tree:** a sparse Merkle tree of depth 40 over Poseidon2.
  The left half is the outputs, at positions never reused; the right
  half's node is the names trie's root (`state_tree.rs`).
  - Stored as tabminer stores it, levels 8 and up, in buckets
    (`utxo.rs`): about 85 bytes per unspent output.
  - Kept as store keys: a bucket is a value.
- **The names trie:** a binary trie keyed by 120 bits of the name's
  hash (`name_trie.rs`).
- **Blocks and headers:** headers all kept; bodies within the undo
  window, and proofs only for the tip.
- **Undo records** for reorganisations, within the undo window: as
  tabminer, 1,008 blocks, with a snapshot manifest each (about 150 KB;
  3.2 GB with full blocks). So the node can serve fast sync to others
  as tabminer does.
- **The disk: 25 GB** (decided), sparse, as `node.sh` and `makenode.sh`
  make it. Outside the window a block costs about 500 bytes (26 MB a
  year) and an unspent output about 85, so the disk holds essentially
  the whole chain for a long time, even at Bitcoin's scale.
- **The store at that size.** Two of its structures grow with the disk
  today, and must not (step 0):
  - the map from a disk page to its cache slot (`pslot`) is 4 bytes for
    every page: about 24 MB of RAM for 25 GB. It becomes a hash table
    sized to the cache (16 MiB: 4,096 slots);
  - a writer transaction's bitmap of pages (`XBMAP`) is a bit for every
    page, zeroed for each transaction: about 750 KB for 25 GB. It
    becomes a record of the pages the transaction touches, sized to the
    transaction (which `DLMAX` already bounds).
  `node.sh`'s default disk stays 256 MiB until then.
- **Memory:** the node's own region and its `malloc`, the seed text
  (4.34 MB), a proof being verified (205 KB and its working state),
  the pool (bounded far below tabminer's 64 MiB), and buffers for
  peers. The store's page cache is shared with everything else, as
  OS.md's memory section says. The target is the whole system in
  128 MiB.

## The network

- **Peers:** tabminer's protocol (`net.rs`): UDP, IPv4, magic `TAB1`,
  protocol version 10, datagrams of at most 1,232 bytes, chunks of
  1,024. The node uses messages 1 to 15:
  - Ping, Pong (the status: height, tip, work, minimum fee);
  - GetPeers, Peers;
  - GetHeaders, Headers, GetHeadersFrom;
  - Inv, TxInv;
  - GetChunks, Chunk (blocks, transactions, manifests, parts);
  - GetProof, Proof;
  - GetAux, Aux.
  Requests carry the token from the peer's Pong. The node keeps about 8
  peers, from the seeds (`tabernacle1/2.root.sx:3737`) and from
  `Peers`. Messages 16 to 22, the onion and message layer
  (`docs/ONION.md`), are not in the first node.
- **Images:** the node serves its own image to tabernacles: GetImages,
  Images, GetImage and ImageChunk (64 to 67, `docs/TABERNACLE.md`). It
  takes over from `tools/server.py`, which plays that part today.
- **The API:** HTTP on its own TCP port (3738 unless configured), in
  its own process. By default it listens for the machine only: wm's
  terminals, programs in the OS, and the host through a forwarded port
  when the user chooses.

## The API

JSON over HTTP, one request a connection to begin with. Paths are
versioned (`/v1/...`) so they can change without breaking wallets.

**The token** (decided). Every request carries it, as `Authorization:
Bearer <token>`. A request without it, or with another, gets 401 and
nothing else.
- The node makes the token at its first start: 32 random bytes, in hex.
  It writes it to `/etc/node/token`, owned by the node's user, mode 600
  (`docs/OS.md`, section 11). A wallet run by that user (or root)
  reads it from there. One on the host is given it by the user, as for
  bitcoind's cookie.
- `POST /v1/token` with the current token makes a new one; the old one
  stops working.
- Randomness for it: the OS has no source yet. QEMU's virtio-rng device
  (`-device virtio-rng-device`) gives one: a small driver, and
  `/dev/random`.
- Configuration may open the read-only endpoints without the token
  (for a public explorer). Writing always needs it.

- **Reading:**
  - `GET /v1/status`: height, tip, work, sync progress, peers, version.
  - `GET /v1/header/<height|id>`, `GET /v1/block/<height|id>`: a block,
    decoded, or raw with `?raw`.
  - `GET /v1/outputs?from=<position>&count=<n>`: outputs in position
    order (commitment, memo slot, height), for wallets to scan. The
    chain carries no keys or addresses (`docs/PRIVACY.md`), so a
    wallet finds its own by scanning, as tabminer's does.
  - `GET /v1/spent?from=<height>`: what was spent since a height, so a
    wallet can keep its balance current.
  - `GET /v1/name/<name>`: a name's record and its proof against the
    state root.
  - `GET /v1/proof/output/<position>`: a Merkle path to the state root,
    for a wallet building a transaction.
  - `GET /v1/fees`: the pool's minimum and estimates (`docs/FEES.md`).
  - `GET /v1/mempool`: its size and what it holds.
- **Writing:**
  - `POST /v1/tx`: a transaction, checked as for the pool, then relayed.
    The answer says accepted, or which rule it broke.
- **Waiting:** `GET /v1/tip?after=<id>` returns when the tip moves
  (long polling), so a GUI can update without asking again and again.
  A WebSocket for events can come later; the framing is wm's.

The API holds nothing secret but the token. A wallet's keys never
reach the node. Whether to answer only local programs, or anyone, is
configuration; the token is needed either way.

## In the OS

- **Its program:** `node` in the image, its memory given in the table
  (tens of MiB; its `malloc` maps more).
- **Its data:** the seed text, as a data file in the image
  (`/lib/akjv.txt.gz`, as the compiler's libraries are). Inflated at
  start.
- **Starting it:** started by init from `/etc/init`, as its own user
  with its own tickets, and restarted if it ends:
  ```text
  restart 2 300 node
  ```
- **Its data in the store:** one tree, its own, on a 25 GB disk.
- **Its token:** `/etc/node/token` (The API, above).
- **Its threads:** one poll loop for the network and the API, as
  `wm` has; verification on another thread, so a slow proof never
  stalls peers or API clients; a second hart if there is one.
- **Its log:** `/proc` keys for its state (height, peers, sync
  progress), readable with `cat`, as `/proc/net` is.

## Testing

Against tabminer, which is the reference:

- **Vectors:** field and extension arithmetic, Poseidon2, the
  challenger, Merkle paths, a real chain proof with its statement, a
  header's proof-of-work, ASERT targets, state roots after known
  blocks. Each generated by a small Rust program, and checked in fam
  under `tools/fam --test`.
- **A live chain:** tabminer's `--network dev` and `dev-recursive`
  produce real blocks and proofs quickly. A fam node syncing from a
  tabminer node over UDP must reach the same tip and the same state
  root, block by block.
- **Rejection:** blocks and transactions broken one rule at a time,
  each refused for that rule, as tabminer refuses it.
- **The OS:** the node under `oscheck.sh`, booted with a disk, syncing
  a short dev chain, answering the API, surviving a kill and restart
  with its state whole.

## The work in the chain proof

Decided 2026-11-07 (pre-launch, so the proof of work and the proof may
change): the chain proof will attest to the proof of work of every block
before it, so that no node has to check the work of a long header
history. This is a change to tabminer. It lands step by step (the order
below), and the README, `miner/src/pow.rs`'s documentation and
`miner/SECURITY.md` are updated as each part does.

### What changes, in short

1. **The proof of work reads aligned windows.** A dataset item's 256
   steps each read 24 bytes of the seed text at a position the state
   picks. Today that position is any byte. It becomes a multiple of 24.
   That makes proving the reads about 20 times cheaper (below).
2. **A block's chain proof attests to its parent's work.** Block `N`'s
   chain proof shows, besides what it shows today, that the `mix` in
   block `N-1`'s header is the true hashimoto mix. Recursively, that
   covers every block before it. It is the parent's work, not the
   block's own, because a block's work exists only once its nonce is
   found, and proving it then would delay publishing by a minute
   (below).
3. **The chain proof binds the headers.** Its statement gains the hash of
   the parent header. Each step checks the parent's `prev_hash` against
   what the previous step bound, so a chain proof stands for one header
   chain back to genesis. Today "the proof binds transitions, not
   headers" (`README.md`).

What stays native, on every header, because it is cheap: the timestamp
rules, the ASERT target from the parent, and `quick_pow_check`: the
result from the claimed `mix` meets the target, two permutations. The
proof supplies the one expensive fact, that the `mix` is the true one.

### 1. Aligned windows

`SeedText::calc_dataset_item` (`miner/src/pow.rs`): each of the
`parents` steps picks `offset = r mod (len - 24 + 1)` and absorbs
`text[offset..offset + 24]`. With aligned windows it picks
`w = r mod floor(len / 24)` and absorbs `text[24w..24w + 24]`: one of
180,871 windows instead of 4,340,894.

- **The same:** the dataset (2^20 items of 64 bytes, 64 MB), hashimoto's
  64 accesses, the cost of mining and of building the dataset, the light
  path's cost, and the need to hold the whole text to verify.
- **Different:** every item's value, so the dataset itself. Also the
  dev dataset built into the binary, and any genesis or test block mined
  with the old one.
- **The module's claim changes.** It says arbitrary offsets mean no
  table smaller than the text reproduces the derivation, since hashing
  every window would take thirty times more space. With aligned
  windows, the smallest table is the windows themselves as field
  elements: 180,871 × 32 bytes, 5.8 MB, more than the 4.34 MB text. So
  holding something at least text-sized is still required, and the
  claim is restated that way.
- **Why:** the proof shows each window came from the text by looking it
  up in a committed table of every possible window. That table has
  4.34 M rows (2^23) today, and 180,871 (2^18) aligned. It is the whole
  difference between 81–89 s and 3–4.5 s to prove (Measured, below).
- **Optionally 254 parents instead of 256.** A header's work is then
  32,643 permutations instead of 32,899, which fits a 2^15-row table
  instead of 2^16: 3.2 s instead of 4.5 s. It is a change to the
  parameter, nothing else.

### 2. The parent's work

A miner proves a block's transactions before mining it (`README.md`:
"proves them, mines them"). So the block goes out the moment a nonce is
found. The work of block `N` cannot be proven before its nonce exists.
Putting it in block `N`'s own proof would put the work proof, its fold
into the block's tree, the wrap (about 22 s) and the chain step
(about 25 s) between finding the nonce and publishing: about a minute,
which favours large miners and raises orphan rates.

Block `N`'s proof attests instead to the work of block `N-1`, which is
known once `N-1` is. A miner proves it as soon as it starts on a new
tip, once per tip (not per template), beside the block's segments.
Publishing waits for nothing new.

What a node checks for a block it receives at the tip: the chain proof,
as now, and the block's own header natively (the full proof of work,
one header). The work before it comes with the chain proof.

### 3. What the proof carries

- **A work segment:** one more child in the block's tree, at the segment
  configuration. Its public values are the parent header's
  `pow_hash` (8 elements), its nonce (11 elements) and its `mix`
  (8 elements). It proves `hashimoto(pow_hash, nonce)` on the light path
  gives that `mix`. `miner/src/pow_air.rs` is its prototype: the hash
  machine with the seed and the 128 items, the window indices proven in
  10-bit limbs, the windows looked up in a preprocessed table of the
  text, the 64 accesses folded in a mix table, and a range table. Still
  to add: the final fold to the 8-element `mix`, checked against the
  public value.
- **The statement** (`aggregate::Statement`) gains the parent header's
  hash and its `pow_hash`, nonce and `mix`. The parent's other fields
  are needed to recompute its hash in the circuit: about 204 bytes, a
  few permutations.
- **The chain step** checks, besides what it checks today:
  - the parent header's hash is what the previous chain proof bound as
    *its* block's header, and its `prev_hash` is what that proof bound
    as its parent's;
  - the work segment's public values are this parent header's.
  - At height 1, the parent is genesis, whose header is a constant.
- **The plan** (`plan_leaves`, `MAINNET_PLAN`, `MAINNET_CHAIN`): each
  block's tree has one more child. The plan constants are regenerated.

### 4. Syncing with it

A node starting from scratch:

1. Downloads every header and checks, natively, its link, height,
   timestamps, ASERT target and `quick_pow_check`: two permutations a
   header, cheap even for the fam node.
2. Picks the sync block `S`, as now a set depth below the best header.
3. Verifies `S`'s chain proof, bound to `S`'s header chain. That covers
   every state transition before `S` (as now) and now the true `mix` of
   every header before `S`.
4. Checks the full proof of work natively for the headers from `S` to
   the tip, and fetches the snapshot and the blocks after `S` as now.

No header before `S` has its dataset items computed by anyone but the
miners who proved them. The sync section above is this.

### Measured

`miner/src/pow_air.rs`, `pow_air::tests::cost`: one header's proof of
work, proven and verified at the mainnet segment configuration (rate 1/4,
54 queries, 16 bits of grinding, commit grinding to 121), on the
development laptop (12 threads).

| windows | parents | text table | perm table | prove | proof | verify |
|---|---|---|---|---|---|---|
| aligned | 256 | 2^18 | 2^16 | 4.5 s | 462 KB | 19 ms |
| aligned | 254 | 2^18 | 2^15 | 3.2 s | 469 KB | 20 ms |
| any byte (today) | 256 | 2^23 | 2^16 | 88.7 s | 572 KB | 29 ms |
| any byte (today) | 254 | 2^23 | 2^15 | 81.2 s | 561 KB | 48 ms |

The text table's commitment is made once per miner: 0.3 s aligned, 15 s
at any byte. The byte-offset variant's mix equals `pow::hashimoto`'s
(`mix_matches_hashimoto`).

What it means for a block, with aligned windows:

- **Proving:** the work segment's 3–4.5 s, run with the block's other
  segments, plus its fold into the tree: one more child of the root for a
  one-segment block, perhaps one more node for a sixteen-segment one.
  Estimated at about +5–15 s a block, against 29 s and 170 s today
  (`miner/SECURITY.md`). The fold is the part still to measure.
- **The published proof:** unchanged, about 205 KB, since the wrap and
  the chain step keep their shape. The work segment's 462 KB never
  leaves the miner.
- **Verifying it:** unchanged, about 13 ms. The work segment verifies
  natively in 19–20 ms, the range of children the nodes already fold
  (the name segment's 27 ms). No node checks old work again.

### Its order

Each step done when its test passes.

1. **Aligned windows** in `pow.rs` (and 254 parents if chosen).
   Regenerate the dev dataset, the genesis block and every test vector
   built on the old dataset. Done when the suite passes on the new proof
   of work.
2. **The work segment, complete**: the prototype's tables, the final
   fold to the `mix` checked against its public value, the attack tests
   (each constraint broken alone is refused, as the other circuits'
   tests do). Done when it proves a real header's work and refuses a
   wrong `mix`.
3. **Into the block's tree**: the work segment as one more child, the
   plan regenerated. Done when a block proves with its parent's work,
   and the fold's cost is measured against the estimate above.
4. **The statement and the chain step**: the parent header bound, its
   hash recomputed and linked, genesis at height 1, the constants
   regenerated. Done when a chain proof verifies only against the header
   chain it was made for.
5. **Sync**: the node checks headers natively as in section 4 and full
   work only after `S`. Done when a node fast-syncs a dev-recursive
   chain checking no full proof of work before `S`.
6. **Measure and document**: `miner/SECURITY.md`'s cost table with the
   work segment, and `README.md`'s fast-sync section.

### Its open questions

- **254 parents:** take the second saved, or leave the parameter alone.
- **The sync depth:** today 144 blocks. The full proof of work is
  checked natively for every header after `S`, so a deeper `S` costs a
  node more, and the fam node most.
- **The first block:** at height 1 the parent is genesis. Genesis can
  either be proven like any other block's work (a work segment for it)
  or taken as a constant in the circuit.

## Implementation order

Each step done when its test passes.

0. **The store at 25 GB, and randomness**:
   - the page-to-slot map sized to the cache, and transactions' page
     records sized to them (Its state, above);
   - `node.sh` and `makenode.sh` making 25 GB disks;
   - virtio-rng and `/dev/random`.
   Done when storetest passes on a 25 GB disk, and RAM in use is the
   same as on 256 MiB.
1. **Arithmetic.** The 32×32→64 product, BabyBear, its extension, and
   the wide integers. Done when they match tabminer's vectors, and the
   cost of a product is measured.
2. **Poseidon2 and Merkle paths.** Done when they match the vectors,
   and a permutation's cost is measured. Then this document's
   estimates are revised, and the proof-of-work question settled.
3. **The chain proof's verifier**: the challenger, FRI, the STARK
   check, and the two tables' constraints. Done when it accepts a real
   proof from tabminer and rejects it with any byte changed.
4. **Proof-of-work and headers**: inflate, the light path, ASERT,
   median time, fork choice by work. Done when a header chain from a
   dev network is accepted as tabminer accepts it.
5. **The state**: the state tree and the names trie in the store, a
   block applied and undone. Done when the state roots of a dev chain
   match, block by block.
6. **The protocol**: peers, headers first, bodies, fast sync from a
   snapshot. Done when a fam node syncs a dev chain from tabminer over
   UDP.
7. **The pool**: XMSS verification, admission, replacement, relay.
   Done when transactions from tabminer's wallet are accepted, relayed
   and mined by a tabminer peer.
8. **The API**: the HTTP server, the token, and the endpoints above.
   Done when a program in the OS and a client on the host read the
   chain and send a transaction through it with the token, and are
   refused without it.
9. **Images**: serving tabernacles. Done when a tabernacle boots from
   a fam node with `tools/server.py` gone.
10. **The daemon**: in the image, started by init, its `/proc` keys,
    restart after a kill. Done when a booted OS runs the node on its
    own, synced, and answers the API.

## Open questions

- **How fast verification gets without M**: step 1 and step 2 measure
  it, and say how much optimising the loop needs.
- **The API's reach**: local only by default; how a user opens it
  wider. The token is needed either way.
- **Messages and onion routing**: protocol messages 16 to 22, in a
  later step.
