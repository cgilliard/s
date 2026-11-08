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
- **Full validation, as tabminer.** The node checks the full proof of
  work of every block it accepts that no verified chain proof covers:
  the fast-sync block and those after it, then each new block, before
  accepting it (decided 2026-11-08). It does not defer a block's work
  to its child's proof, which would leave the tip unchecked: at every
  moment it accepts exactly what tabminer accepts.
- **The seed file, whole and as shipped.** The proof of work reads the
  King James text as the 1,291,059-byte gzip file embedded in the
  binaries, never decompressed, and each of hashimoto's accesses reads a
  window of it directly besides its two items (decided 2026-11-08). So
  validating a block requires the entire file: neither the 64 MB dataset
  nor any hash of the file substitutes, and every validating node, this
  one and tabminer, stores it. The node needs no inflate.
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
- **Proof-of-work.** An Ethash-like hashimoto over Poseidon2 (`pow.rs`),
  checked in full only for the fast-sync block and the headers after it
  (about 145, once) and then for each new block (one every 600 s); every
  header before the sync block is attested by its chain proof.
  The node computes each item it needs from the seed file instead of
  holding the 64 MB dataset:
  - 64 accesses × 2 items × (254 parents + 1) ≈ 32,643 permutations
    a header, so several seconds each by the estimate above, and 64
    windows read directly;
  - it needs the seed file (1.29 MB, the text gzipped, used as it is)
    with random access, held in memory: nothing to inflate;
  - `quick_pow_check` (2 permutations) runs first, to throw out junk
    cheaply, and is all that headers below the sync block get;
  - genesis's true `mix`, which block 1's statement carries (its
    header's is empty), computed once from the file.
- **Wide integers.** U256 for targets and work; 64-bit amounts and
  supply; u64 `%` for seed offsets; a u128 logarithm for the grinding
  check. They are small routines over words.

A block every 600 s leaves room: a header, its proof and its state
change should take well under a minute. Catching up costs the full
proof of work of about 145 headers once, spread over the harts, and
then a chain proof and the full work per block after the sync block
(below); no work before it is checked.

## Syncing

As tabminer (`node.rs:10-56`), within the machine's limits:

1. **Headers first**, `GetHeadersFrom` in batches of 60 from several
   peers, each header's rules and quick proof of work checked; the full
   proof of work for the sync block and those after it (below).
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
- **Memory:** the node's own region and its `malloc`, the seed file
  (1.29 MB), a proof being verified (205 KB and its working state),
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

Done (2026-11-07), with 254 parents. `SeedText::calc_dataset_item`
(`miner/src/pow.rs`) picked `offset = r mod (len - 24 + 1)`, any byte,
and absorbed `text[offset..offset + 24]`. It now picks
`w = r mod ceil(len / 24)` and absorbs window `w`: 24 bytes from `24w`,
except that the last window ends at the text's end, overlapping the one
before. So every byte is in a window, the text's last words included
(`len` is 13 more than a multiple of 24). That is 180,872 windows
instead of 4,340,894.

- **The same:** the dataset (2^20 items of 64 bytes, 64 MB), hashimoto's
  64 accesses, the cost of mining and of building the dataset, and the
  need to hold the whole text to verify. Genesis, whose proof of work is
  not checked (its `mix` is empty), and its id.
- **Different:** every item's value, so the dataset itself; the dev
  dataset built into the binary was regenerated. A node's saved mainnet
  dataset fails its sampled check and is rebuilt.
- **The module's claim, restated.** It said arbitrary offsets meant no
  table smaller than the text reproduces the derivation, since hashing
  every window would take thirty times more space. With aligned
  windows, the smallest table is the windows themselves as field
  elements: 180,872 × 32 bytes, 5.8 MB, more than the 4.34 MB text.
- **Why:** the proof shows each window came from the text by looking it
  up in a committed table of every possible window: 4.34 M rows (2^23)
  at any byte, 180,872 (2^18) aligned. That is the whole difference
  between 81–89 s and 3–4.5 s to prove (Measured, below).
- **254 parents instead of 256:** a header's work is 32,643 permutations
  instead of 32,899, which fits a 2^15-row table instead of 2^16: 3.2 s
  instead of 4.5 s to prove. Computing items from the text costs 1% less
  with it.

Revised (2026-11-08): **the gzip file, read directly.** The windows are
now those of the seed file as shipped, `resources/akjv.txt.gz`
(1,291,059 bytes, never decompressed): 53,795 windows, the last 3 bytes
short of a whole one, so it overlaps the one before. And each of
hashimoto's 64 accesses reads one window directly besides its two items:
a second selector, `fnv(i + seed[1], mix[(i + 16) % 32])`, gives the
window (its low 16 bits, less 53,795 once if they are that or more:
`pow::direct_window`), whose eight packed elements are added to the mix
words as the items fold in.

- **Why:** validating a block must require the entire text, which the
  chain exists to preserve. The dataset is a hash of the windows, so
  before, a node holding it verified without the text. Now every check of
  a header's work reads 64 windows of the file directly, and computing
  its items from the file reads about 32,500: a node missing any window
  soon meets a block it cannot validate (`validation_needs_the_entire_file`).
  And the file as shipped is 1.29 MB in memory where the inflated text
  was 4.34 MB, against a node budget of 128 MiB, with no inflate to write
  in fam.
- **What it costs:** mining stays memory-bound: one more read, of a
  window in a 1.29 MB file, an access, and no permutation. Computing a
  header's items from the file is unchanged. The work segment's mix table
  proves the second selector canonical in bits, the subtraction and
  `w < N` in two 10-bit limbs each, and looks the window up in the text
  table: 189 columns instead of 142. The text table is 2^16 rows instead
  of 2^18. Proving is about the same (3.4–3.6 s; the perm table
  dominates), the table's commitment 0.07 s instead of 0.3 s, the proof
  450 KB (Measured, below).
- **Different:** every item and every mix, so the dev dataset and the
  plan and chain constants were regenerated; genesis's work too (its id
  is unchanged). The file is pinned by its bytes: recompressing the text
  gives other bytes. `seed_file_is_the_king_james_text` inflates it, in
  the tests only, and checks it is the text.
- **The module's claim, restated** (`miner/src/pow.rs`): validating a
  block requires the entire seed file, and every validating node stores
  it. The smallest table reproducing the items is still the windows
  themselves as field elements: 53,795 × 32 bytes, 1.7 MB, more than the
  file.

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
  (8 elements). It proves `hashimoto(pow_hash, nonce)`, items computed from the seed file,
  gives that `mix`. `miner/src/pow_air.rs` is its prototype: the hash
  machine with the seed and the 128 items, the window indices proven in
  10-bit limbs, the windows looked up in a preprocessed table of the
  text, the 64 accesses folded in a mix table, and a range table. The
  final fold to the 8-element `mix` is checked against the public value
  (step 2, done).
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
| gzip file, direct reads (now) | 254 | 2^16 | 2^15 | 3.4–3.6 s | 450 KB | 19–20 ms |
| any byte (before) | 256 | 2^23 | 2^16 | 88.7 s | 572 KB | 29 ms |
| any byte (before) | 254 | 2^23 | 2^15 | 81.2 s | 561 KB | 48 ms |

The text table's commitment is made once per miner: 0.3 s aligned, 15 s
at any byte. Measured before the change, with the aligned variant's
table one window shorter; the aligned variant now computes exactly
`pow::hashimoto`'s mix (`mix_matches_hashimoto`).

What it means for a block, with aligned windows:

- **Proving:** the work segment's 3–4.5 s, run with the block's other
  segments, plus its fold into the tree: one more child of the root for a
  one-segment block, perhaps one more node for a sixteen-segment one.
  Estimated at about +5–15 s a block, against 29 s and 170 s today
  (`miner/SECURITY.md`). The fold's sizes are measured (step 3): a
  one-segment root goes from 2^18 to 2^19 rows, larger roots and the
  wrap keep their heights.
- **The published proof:** unchanged, about 205 KB, since the wrap and
  the chain step keep their shape. The work segment's 462 KB never
  leaves the miner.
- **Verifying it:** unchanged, about 13 ms. The work segment verifies
  natively in 19–20 ms, the range of children the nodes already fold
  (the name segment's 27 ms). No node checks old work again.

### Its order

Each step done when its test passes.

1. **Aligned windows** in `pow.rs`, and 254 parents; the dev dataset
   regenerated. Done (2026-11-07): section 1.
2. **The work segment, complete**: the prototype's tables, the final
   fold to the `mix` checked against its public value, the attack tests
   (each constraint broken alone is refused, as the other circuits'
   tests do). Done (2026-11-07). `miner/src/pow_air.rs`:
   - Public values: `pow_hash`, the nonce's 11 elements, the `mix`.
   - The mix table's row after the 64th access folds the mix to eight
     elements and checks it against them.
   - `WorkSetup` commits the window table once; `prove_work` and
     `verify_work` (with a `WorkVerifier`: root, layout, parents) make
     and check the proof, under transcript domain 0x35.
   - `attacks`: eleven cheats, each generated leniently as a cheating
     prover would, are refused. They are: another window absorbed;
     another index shown; changed text; a parent too few or too many;
     an item for another index; another pair picked; a non-canonical
     decomposition; an index past N into the table's padding; another
     mix; another header hash.
   - `proves_a_real_header`: a `block::Header`'s work proven, and
     verified only against its own `pow_hash`, nonce, `mix` and window
     table.
3. **Into the block's tree**: the work segment as one more child, the
   plan regenerated. Done when a block proves with its parent's work,
   and the fold's cost is measured against the estimate above. Done
   (2026-11-07):
   - The root verifies the work segment after the name segment, with the
     window table's root a constant of its program, and requires its
     public values to be the statement's new `parent_work` (the parent's
     `pow_hash`, nonce and `mix`, 27 elements). The root's tree digest
     ends with a `WORK_TAG` (0x43) descriptor.
   - `AggregatorParams` gains `pow`, the proof of work the parent's is
     proven under. It must be the chain's (`networks_prove_their_own_work`).
   - `prove_wrap` proves the parent's work as one more job, first, beside
     the segments. The last work proof is kept, so a template rebuilt on
     the same parent reuses it.
   - Genesis's `mix` is empty, so for block 1 the parent's true mix is
     computed from the seed text (`Chain::parent_work`, once).
   - Every wrap is padded to one set of heights (`wrap_pad`): the tallest
     of the roots over 1 to `fan_in` segments and over `max_segments`.
     The chain program verifies every wrap at one set of heights, and
     with the work segment the roots' heights spread further.
   - Measured on a dev-recursive chain of three blocks: the parent's work
     proves in 1.6 s beside the segment and name segment, and the root
     over one segment (2^17 rows) in 2.2 s; 7.5–7.8 s to prove a block.
     Each block verifies in 3 ms, and its proof is 35 KB.
   - Mainnet, planned: the root of a one-segment block passes 2^19 rows
     (it was 2^18); the roots of 2 to 16384 segments stay at 2^19 rows
     and a 2^17-row hash table, and the wrap at 2^17. So a one-segment
     block's root costs about twice as much to prove, a larger block's
     about the same, plus the work segment's 3.2 s alongside its
     segments: within the estimate. The mainnet timings in
     `miner/SECURITY.md` are redone in step 6.
4. **The statement and the chain step**: the parent header bound, its
   hash recomputed and linked, genesis at height 1, the constants
   regenerated. Done when a chain proof verifies only against the header
   chain it was made for. Done (2026-11-08):
   - The header hashes (`Header::pow_hash`, `Header::hash`) are the
     plain sponge with the domain tag as the first element, so that the
     chain program's machine, whose sponge sets only the length in the
     capacity, can recompute them. Every block id changed with them,
     mainnet's genesis included (`src/genesis.rs`'s `ID`; its inputs are
     the same).
   - The statement gains `parent_hash`, the block's `prev_hash`.
   - The base program (height 1) requires the parent to be genesis: its
     hash, and its work with the true mix (`aggregate::Genesis`, which
     the verifier is made with and the chain setup's programs fix).
   - Each step takes the parent header (the previous block's) and
     recomputes its `pow_hash` and hash: its `prev_hash` is the parent
     hash the previous proof bound, its height that proof's, its state
     root this block's previous one, and its `pow_hash`, nonce and mix
     the work this block's root proved. The hash must be the statement's
     `parent_hash`.
   - `chain_proofs_cover_history`: a proof does not verify with another
     parent hash, and a step is refused on a parent header with another
     timestamp, body or aux, on a parent not linked to genesis, and for
     a block 1 that names another parent.
   - Dev-recursive, four blocks mined on a fresh chain, each accepted:
     the chain step proves in 2.0–2.2 s, as before.
5. **Sync**: the node checks headers natively as in section 4 and full
   work only after `S`. Done when a node fast-syncs a dev-recursive
   chain checking no full proof of work before `S`. Done (2026-11-08),
   in tabminer's node:
   - During a fast sync, headers are stored with their work pending
     (`Chain::accept_headers_with`): checked so far for link, height,
     timestamps, target, and the claimed `mix` meeting it.
   - Once `S` is picked, `Chain::confirm_work` checks the full proof of
     work of `S` and every header after it on the best branch, in
     parallel. It runs again before `S`'s proof is verified, since the
     target may have moved and headers come in. A header that fails is
     marked invalid with every header after it, the best header falls
     back, and the peer that sent it is struck.
   - `S`'s own work is checked before its proof is verified and its
     snapshot installed (`verify_snapshot_block`, `finish_snapshot`):
     its proof attests its parent's work, not its own.
   - A block whose header's work is pending has its full work checked when
     it is applied, so a sync that falls back to replaying blocks checks
     every one.
   - Tests: `pending_work_is_checked_from_the_sync_point`
     (a forged header that passes the quick check is refused at
     `confirm_work` with what follows it, and on applying its block);
     `a_fresh_node_fast_syncs` checks the full work of blocks 8 to 12
     alone, the snapshot block 8 and after.
   - Dev-recursive, ten blocks mined, a fresh node with `--sync-point 4`:
     full proof of work for headers 6 to 10, block 6's proof verified,
     its state installed, blocks 7 to 10 applied; headers 1 to 5 never
     checked in full.
6. **Measure and document**: `miner/SECURITY.md`'s cost table with the
   work segment, and `README.md`'s fast-sync section.

### Its open questions

- **The sync depth:** today 144 blocks. The full proof of work is
  checked natively for every header after `S`, so a deeper `S` costs a
  node more, and the fam node most: about 145 headers at several seconds
  each by the estimates, before the harts share them.
- **The first block:** settled in step 4. Genesis's `mix` is empty, so
  its true mix is computed once from the seed text, and the base program
  (height 1) fixes genesis's hash and that work as constants.

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
   estimates are revised, with the cost of the full proof of work at
   sync (about 145 headers) and per block.
3. **The chain proof's verifier**: the challenger, FRI, the STARK
   check, and the two tables' constraints. Done when it accepts a real
   proof from tabminer and rejects it with any byte changed.
4. **Proof-of-work and headers**: items and the direct reads from the
   seed file, ASERT,
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
