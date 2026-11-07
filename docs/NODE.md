# The node

Written 2026-11-07, to be tracked; not built. This is the plan for
`docs/OS.md`'s step 12: the full node, written in fam, running on the
OS as a daemon. It covers what the node does, how it fits the machine,
the API it offers, and the order to build it in.

Paths in `miner/src` are to the Rust node, tabminer. It is the
reference: the fam node must accept and reject exactly the blocks and
transactions it does.

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
  done in software, from 16-bit halves. This is the inner loop of
  everything else, so it is written first, with care, perhaps as
  machine code words as the kernel's are.
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

The open question is proof-of-work over a long header chain: at
several seconds a header, 50,000 headers is days. The chain proof
attests to every block's validity, but not to its work. Options, to
choose once Poseidon2's real cost is measured:
- check every header's work, and accept a slow first sync;
- check the work of the last N headers in full, and the rest by
  sampling;
- start from a checkpoint carried in the image. The image is already
  trusted, through tabernacle's hash.

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
- **Undo records** for reorganisations, within the undo window. Its
  depth and the disk's size go together:
  - tabminer keeps 1,008 blocks, with a snapshot manifest each (about
    150 KB, 3.2 GB with full blocks);
  - a fam node on a 256 MiB disk can't. It keeps a shorter window by
    default, enough for any likely reorganisation, and serves no
    snapshots, or serves only recent ones.
  The disk `node.sh` makes may need to grow.
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

The API holds nothing secret. A wallet's keys never reach the node.
Whether to answer only local programs, or anyone, is configuration.

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
- **Its data in the store:** one tree, its own.
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

## Implementation order

Each step done when its test passes.

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
8. **The API**: the HTTP server and the endpoints above. Done when a
   program in the OS and a client on the host read the chain and send
   a transaction through it.
9. **Images**: serving tabernacles. Done when a tabernacle boots from
   a fam node with `tools/server.py` gone.
10. **The daemon**: in the image, started by init, its `/proc` keys,
    restart after a kill. Done when a booted OS runs the node on its
    own, synced, and answers the API.

## Open questions

- **Proof-of-work over a long header chain**: all of it, sampled, or
  from a checkpoint in the image (Syncing, above).
- **The undo window and the disk**: how deep a reorganisation the node
  survives on the disk it is given; whether it serves snapshots.
- **Multiplication's cost**: step 1 decides whether the field
  arithmetic stays in fam words or becomes machine code, and whether
  to ask for the M extension (QEMU has it; the design so far avoids
  it).
- **The API's reach**: local only by default; how a user opens it
  wider, and whether writing (`POST /v1/tx`) needs a token when it
  does.
- **Messages and onion routing**: protocol messages 16 to 22, in a
  later step.
