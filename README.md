# s

A proof-of-work chain whose blocks carry only output commitments and a
zero-knowledge validity proof. `miner/` holds the node, the prover and the
wallet; `miner/SECURITY.md` analyses the proofs.

## Genesis

`miner/src/genesis.rs` holds mainnet's genesis, written by the genesis tool:

```
cd miner
cargo run --release --bin genesis                      # testing: about 65,536 hashes per block
cargo run --release --bin genesis -- --hashrate 1000000  # a launch: ten-minute blocks at 1 MH/s
```

It records the current time and the hash of the latest Bitcoin block (fetched
from mempool.space with `curl`, or given with `--bitcoin-hash`), which goes in
the genesis header's nonce: the chain provably did not exist before that
Bitcoin block. `--hashrate` is the network's expected proof-of-work rate at
launch, in hashes per second; it sets the first target so blocks average ten
minutes from the start. Without it the target is the testing one, so blocks
come as fast as they can be proven. Every run makes a new chain, so run it just before
launch, rebuild, and publish the genesis id it prints.

## Build

```
cd miner
cargo build --release
```

## Run

```
tabminer [mine] [--data DIR] [--blocks N] [--jobs N] [--no-mine] [options]
tabminer node [--data DIR] [options]
tabminer show [--data DIR]
tabminer restore [--data DIR]

options: [--listen ADDR] [--peer ADDR]... [--seed HOST:PORT]... [--verbose] [--no-prompt]
```

`tabminer` with no command mines: it syncs to the heaviest chain its peers
know, then builds blocks from the pooled transactions plus a reward paying
the subsidy and their fees to its wallet, proves them, mines them and
announces them, starting over whenever the network delivers a better tip.
`tabminer node` (or `--no-mine`) follows the chain and relays without
mining. Both listen on UDP port 3737 by default, contact the seed nodes in
`miner/src/node.rs` and any `--peer`, and keep the peers they found in
`DIR/peers` for next time. `show` prints the main chain.

Logs go to `DIR/tabminer.log`; the terminal shows a prompt (`help` lists
the commands). `--no-prompt` logs to the terminal instead, for scripts.

Every node starts from the mainnet genesis in `miner/src/genesis.rs`.

## Fast sync

Every block carries a chain proof: it verifies the block and the previous
block's chain proof, so one proof shows the whole chain up to that block
valid. A node starting from scratch therefore does not replay history. It
downloads every header (checking proof of work, difficulty and timestamps),
takes the block `--sync-point` below the best header (144 by default),
verifies that block's chain proof, downloads the state after it from its
peers in parallel parts (each checked against the block's state root, memos
included, and written to disk as it arrives, so memory stays small whatever
the state's size; a node stopped midway starts the state over cleanly), and
then fetches the blocks after it. Nothing about the past is taken on trust.
`--sync-point 0` replays every block instead, which needs a peer that keeps
every body (`--max-undo-blocks 0`); a fast sync that keeps failing falls back
to that only when such a peer is known, and otherwise tries again. A miner waits until its node has caught
up before mining.

Catching up, a node checks and stores headers first, in batches of 60
asked of up to 16 peers at once and checked in order, so one slow peer
delays only its own share. Proofs of work are checked against the 64 MB
dataset, which every node builds once (about 30 s on 12 cores) and keeps
in its data directory: 19 microseconds a header, against 30 ms from the
seed text, which is used, across all cores, until it is ready. Only then
does it fetch blocks, from several peers at once (up to 24 blocks, 8 from any one peer,
and no more than 32 past the first one missing), applying them in order.
Each peer's status says the lowest height from which it holds every block,
so blocks are only asked of peers that have them. A peer that claims more
work but sends no headers for it, or whose downloads stall or crawl, is
passed over for ten minutes, and only peers that answered the node's own
ping are believed at all. Replaying 60 full blocks over links with 80 ms
round trips took 20 s from three peers and 30 s from one, against about
60 s before; blocks are applied on a thread of their own, so downloads go
on meanwhile. A fast sync of a 1,487-block chain from three peers took
38 s on a first start, 29 s of it building the dataset, against 92 s
before. Transaction announcements are ignored until a node has caught up.

The state comes in parts of 16,384 positions, up to 32 at once from every
peer that can serve them. Each download keeps 32 chunks in flight at first
and doubles that each time a whole window arrives without a retry, up to
512, halving when chunks go missing; parts are checked against their roots
and stored on the applier thread, so the network goes on meanwhile. A fast
sync of 2.16 million unspent outputs (155 MB) from three peers at 80 ms
round trips installed the state in 8.6 s, against 57 s with 32 chunks and
16 parts in flight, and reached the tip, 156 full blocks on, in 29 s
rather than 90 s.

Nodes take a snapshot after every block whose height is a multiple of 144
and keep those within the undo window; fast sync uses the newest one at
least `--sync-point` deep, so any sync point up to 865 is always served;
with a deeper one than its peers keep, it uses the deepest snapshot they
do keep rather than wait for one that will never come.
A download that outlasts its snapshot loses nothing: as the snapshot nears
the end of its peers' windows (each peer's status says where its window
starts), or if no peer serves it, the node moves to a later one, fetches
the blocks in between and carries the parts it has forward, removing the
outputs those blocks spent and checking each part against the later
manifest; only parts that do not match are fetched again.
A snapshot stores only its manifest: the output counter and each part's
root, read from the state tree when the block connects. The outputs spent
by blocks in the undo window are kept once, by position, with the height
spending them; disconnecting a block restores its inputs from there, and a
part is served from the outputs unspent now in its range plus those spent
after the snapshot, so serving costs two range reads, whatever the request.

Nodes keep undo records and block bodies, which reorganizations need, for
the last `--max-undo-blocks` blocks (1008 by default, a week); older blocks
keep only their headers, since every later chain proof covers them. A
reorganization deeper than that is refused. `--max-undo-blocks 0` keeps
everything, for an archive node.

## Storage

The chain database grows as it fills (its LMDB map is a 1 TiB bound, reserved
as address space, never allocated ahead). Measured costs:

| what | cost |
|---|---|
| each unspent output, at any density (measured at 20% and 6% of outputs unspent) | about 85 bytes |
| each block past the undo window (header, index, height) | about 500 bytes, 26 MB a year |
| the undo window | its 1008 bodies and undo records: about 3.2 GB with full 2 MB blocks |

So a Bitcoin-sized set of 170 million unspent outputs takes about 14 GB, and a
node with it, decades of headers and a full undo window stays under 20 GB.
The unspent outputs are kept in buckets of consecutive ones, each one LMDB
page of 4 KB at most, split when full and repacked with their neighbours as
spending thins them, so pages stay about 80% full; each output costs its
64 bytes of commitment and memo plus a byte or two. The state tree is
stored only from subtrees of 256 positions up, the levels below being
recomputed from the outputs when needed. There is no index by commitment:
blocks name their inputs by position, a transaction input carries its
output's position (not signed, so a wallet can correct it after a
reorganization), and wallets learn where their outputs landed from the
blocks that add them.

A full 2 MB block (20,000 spends at random, 25,000 new outputs) applies in
about 0.4 s against a million unspent outputs and 0.6 s against ten million,
on a 6-core laptop. Against 170 million (a 12 GB set, more than a small
node's memory) it takes about 2.8 s with the outputs' pages on disk: the
pages a block will need are read from many threads at once before it is
applied, so the drive works in parallel (one with 36,000 random reads a
second here), and the state tree and bucket index, which every block uses,
stay cached. `TABMINER_BLOCK_DIR=DIR TABMINER_BLOCK_UNSPENT=170000000 cargo
test --release --lib full_block_cost -- --ignored --nocapture` repeats it.

`cargo test --release --lib storage -- --ignored --nocapture` repeats the
measurements. Large blocks can be simulated end to end with
`--debug-no-validate-proofs` and `--debug-fill` (see `tabminer --help`), and
the prompt's `storage` command reports a node's database part by part.

Proving a chain step adds about 25 seconds per block; the proof stays at
about 205 KB and verifies in under 10 ms.

## Wallet

Each node has a wallet in `DIR/wallet`. It is created on first run with a
12-word BIP39 recovery phrase, shown once in the terminal and again with
`phrase`. Every output the wallet creates has its own one-time key, derived
from the phrase and a random nonce, and carries a 32-byte memo on chain that
only the phrase can read: it holds the nonce and the encrypted amount.

To recover a wallet from its phrase:

```
tabminer restore --data DIR2       # asks for the phrase and an optional passphrase
tabminer --data DIR2               # sync, then at the prompt:
> scan                             # finds the wallet's unspent outputs from their memos
```

Each output's key has 16 one-time signing leaves. A wallet signs its own
outputs from leaves 0 to 7 (a spend and up to seven cancellations, the last
one flagged); outputs found by `scan` sign from leaves 8 to 15, from a random
start, so a restored copy never signs with a leaf the original used.

Payments use slate files passed between the two wallets by any channel:

```
> send 10 0.5 /tmp/pay.slate        # sender: 10 coins, 0.5 fee; reserves inputs
> receive /tmp/pay.slate            # recipient: adds their output, writes /tmp/pay.slate.received
> finalize /tmp/pay.slate.received  # sender: signs and pools the transaction
> cancel ID                         # sender: replace it, before it confirms, with
                                    # one paying the inputs back at a higher fee
```

`balance` shows confirmed, pending (incoming), reserved (held for a slate)
and locked (signed and being sent) funds; `outputs`, `slates`, `sent`,
`mempool`, `peers` and `status` show the rest. The reward of a mined block goes to the miner's wallet.

To try two nodes on one machine:

```
tabminer mine --data /tmp/a --listen 127.0.0.1:3737
tabminer node --data /tmp/b --listen 127.0.0.1:3738 --peer 127.0.0.1:3737
```
