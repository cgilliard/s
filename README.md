# s

A proof-of-work chain whose blocks carry only output commitments and a
zero-knowledge validity proof. `miner/` holds the node, the prover and the
wallet; `miner/SECURITY.md` analyses the proofs and the message layer;
`docs/HARDENING.md` lists the known gaps still to close; `docs/NAMES.md`
is the design of the name registry, `docs/ONION.md` of the message layer
that carries payments between wallets, `docs/ELTOO.md` of payment
channels.

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

options: [--listen ADDR] [--peer ADDR]... [--seed HOST:PORT]... [--no-seeds] [--relay]
         [--no-wallet] [--verbose] [--no-prompt]
```

`tabminer` with no command mines: it syncs to the heaviest chain its peers
know, then builds blocks from the pooled transactions plus a reward paying
the subsidy and their fees to its wallet, proves them, mines them and
announces them, starting over whenever the network delivers a better tip.
`tabminer node` (or `--no-mine`) follows the chain and relays without
mining. Both listen on UDP port 3737 by default, contact the seed nodes in
`miner/src/node.rs` and any `--peer`, and keep the peers they found in
`DIR/peers` for next time. `show` prints the main chain. `--relay` makes
the node relay for others on the message layer (below). `--no-wallet`
runs the node without a wallet, and so without mining; seeds and relays
are best run that way.

Logs go to `DIR/tabminer.log`; the terminal shows a prompt (`help` lists
the commands). `--no-prompt` logs to the terminal instead, for scripts.

Every node starts from the mainnet genesis in `miner/src/genesis.rs`.

## Aux leaves

Every header carries 32 aux bytes under the proof of work that consensus
never reads. A miner fills them with the SHA-256 Merkle root of 16 leaves it
sets at the prompt, `set-leaf INDEX FILE` (the file's SHA-256) or
`set-leaf-value INDEX HEX`, shown by `leaves`. Leaf 0 is a vote for a
consensus file of the message layer (below): nodes fetch and check every
block's leaves, count leaf 0 over the last 144 blocks, and fetch the files
voted for; `consensus` shows the count, each file's state and the file in
force. The leaves are kept in the
chain directory and go into every block the node mines until one is
changed; while all are zero the aux bytes are zero.

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
passed over for ten minutes (a strike, five of which ban a host for an
hour, is only for bad data), and only peers that answered the node's own
ping are believed at all. A peer claiming more work at or below the node's
own height is asked for its branch with a locator, and walked further
along it as long as it has more, so a fork deeper than one reply is still
found. Every request carries a token the serving node derived from the
asking address with a secret of its own and sent there in its status, so
a request forged from another address goes unanswered: a node cannot be
made to flood anyone. One public host gets at most two peer entries,
whatever its ports. Replaying 60 full blocks over links with 80 ms
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

Nodes keep a snapshot manifest for every block within the undo window;
fast sync uses the block `--sync-point` deep, so any sync point up to 1008
is always served; with a deeper one than its peers keep, it uses the
deepest block they do keep rather than wait for one that will never come.
A download that outlasts its snapshot loses nothing: as the snapshot nears
the end of its peers' windows (each peer's status says where its window
starts), or if no peer serves it, the node moves to a later one, fetches
the blocks in between and carries the parts it has forward, removing the
outputs those blocks spent and checking each part against the later
manifest; only parts that do not match are fetched again.
A snapshot stores only its manifest, about 150 KB with millions of outputs
and names: the output counter, each output part's root, the name root and
each name part's hash, read from the state tree and the registry's bucket
table when the block connects. The outputs spent
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
68 bytes of commitment, memo and creation height plus a byte or two. The
state tree is stored only from subtrees of 256 positions up, the levels
below being recomputed from the outputs when needed. There is no index by commitment:
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

A payment is a slate the two wallets pass back and forth. With both
online, the message layer carries it (below): give `send` the recipient's
`tab1…` address, or a registered name with `@`:

```
> send 10 tab1…                     # 10 coins to that address
> send 10 0.5 @alice                # to the address the name alice points at, fee 0.5
```

The recipient's wallet answers at once and the sender's signs and pools
the answer; each prompt reports what happened. A slate no rendezvous point
would take (the recipient is offline) is cancelled and its inputs freed.
Without the message layer, slates go as files by any channel:

```
> send 10 /tmp/pay.slate            # sender: 10 coins at the smallest fee; reserves inputs
> send 10 0.5 /tmp/pay.slate        # the same with a 0.5 fee
> receive /tmp/pay.slate            # recipient: adds their output, writes /tmp/pay.slate.received
> finalize /tmp/pay.slate.received  # sender: signs and pools the transaction
> cancel ID                         # sender: replace it, before it confirms, with
                                    # one paying the inputs back at a higher fee
```

The recipient may only add its output: `finalize` checks the amount and
fee the sender offered, the change output down to its memo, and what the
pool would refuse, before signing. The pool takes a transaction only if it
pays at least one base unit per byte and makes no output worth less than
the fee of spending it (about 0.000023 coins), so filling blocks, and the
set of unspent outputs, costs something; `send` folds change below that
into the fee. A payment the pool refuses is reported at the prompt and
can be cancelled. The signatures, the leaves they use and the record of
the payment are written in one wallet transaction, so a crash leaves
nothing half done.

`balance` shows confirmed, pending (incoming), reserved (held for a slate)
and locked (signed and being sent) funds; `outputs`, `slates`, `sent`,
`mempool`, `peers` and `status` show the rest. The reward of a mined block goes to the miner's wallet.

## Policies and channels

An output may be paid to a spend policy instead of a single key: a Merkle
tree of leaves, each a set of conditions, from which a spend reveals one
leaf in zero knowledge, so a multisig, an HTLC or an eltoo channel state is
indistinguishable on chain from any other output (`docs/ELTOO.md`).
Conditions are `m`-of-`n` signatures in body mode or rebindable mode,
a hash lock, an absolute or relative timelock, a state number the spend
must exceed, and a covenant naming the outputs the spend must create.
Keys may have up to 20 tree levels; `channel-key [HEIGHT]` derives a fresh
one and prints its key hash for a policy. The wallet tracks the policy
outputs it is party to (`policies`), funds them, builds spends through a
chosen leaf and signs with its own keys, rebindable signatures using the
state number as the leaf index; the parties pass the transaction's bytes
between them to collect signatures. Policy outputs are not recoverable
from the phrase: a wallet keeps them as channel state. Any peer answers
`GetProof` for a position with the output there and its path against the
peer's tip, so a client holding headers (and a chain proof for one of
them) checks its outputs and watches spends without trusting a node.

## Names

The chain carries a registry of names, 1 to 32 characters of `a-z`, `0-9`
and `_`, owned for good by whoever registers them (see `docs/NAMES.md`).
A name's record holds its owner's key hash, a 32-byte value (an address
on the message layer: `name-commit` sets the wallet's own unless given
another) and a memo the owner's wallet reads; `send 10 @alice` pays the
address alice points at. Registering
takes two transactions: a commit, which hides the name, and a reveal, at
least 12 blocks later, which names it. A block admits five reveals, so
registrations are paid for by their fees.

```
> name-commit alice                 # pool a commit to "alice" (optionally an address and a fee)
> names                             # ... committed at block N, ready in 12 blocks
> name-reveal alice                 # reveal once the commit is 12 blocks old
> name-reveal alice 100             # or wait longer: a deeper reorganization is needed to take it
> name-update alice tab1…           # change the value; the owner key rotates
> name alice                        # look a name up
```

To transfer a name, the recipient writes a record under a key of theirs
and the owner signs it over:

```
> name-offer alice /tmp/alice.rec   # recipient: writes the record (optionally with a value)
> name-transfer /tmp/alice.rec      # owner: signs the update and pools it
```

Operations ride in a transaction of the wallet's that pays their fee and
can be cancelled like a payment while unconfirmed. `scan` recovers a
restored wallet's names from the chain's records and its pending commits
from their outputs; a recovered commit is matched to its name when you
reveal it. Names must be revealed within 288 blocks of their commit or the
commit is swept.

## Message layer

Wallets reach each other without a server and, once relays exist,
without learning each other's network address (`docs/ONION.md`). Each
wallet has an address, `tab1…` (`address` at the prompt): bech32m with a
checksum, the hash of an ML-DSA-65 (Dilithium) key derived from the
phrase, so a restore keeps it. Messages to it are sealed with ML-KEM-768
(Kyber) keys the wallet makes fresh, signs and rotates, and
ChaCha20-Poly1305; the primitives are the crate's own, tested against the
standard vectors. There is no mailbox: a wallet is reached while it is
online and not otherwise.

An address names three rendezvous points, chosen from it by hash among
the nodes that relay. A wallet's node keeps a session at each, which
forwards what is sent to the address. What relays exist, and so which
mode the network is in, is a file the miners vote for in aux leaf 0
(above). The file in force changes only every 144 blocks: at each
multiple of 144, the most voted `consensus.txt` of the 144 blocks ending
there that is fetched and valid takes over (one vote is enough; with
none, init mode), over a grace period of six blocks during which both
files stand, and stays until the next.

- **Init mode** (`mode init`, or no file): the seed nodes are the
  rendezvous points, run with `--relay`, and wallets connect to them
  directly. Bodies are sealed, but a seed sees which addresses talk, when,
  from which network addresses.
- **Onion mode**: the file lists the relays, at least three, each as
  `relay ID HOST:PORT`, where the id is the hash of the relay's Dilithium
  key: derived from the node's phrase, but not its wallet's address. A
  node started with `--relay` (best with `--no-wallet`) prints its line
  at startup, ready to paste, and `address` shows it:

  ```
  mode onion
  relay tab1… relay1.example.org:3737
  relay tab1… 203.0.113.7:3737
  relay tab1… [2001:db8::1]:3737
  ```

  Every link is opened by a handshake in which the relay proves its key
  (a Dilithium signature over the exchange) and the two agree a fresh
  Kyber key; wallets stay anonymous. Each wallet keeps a circuit to each
  of its rendezvous points through two other relays chosen at random, in
  the manner of Tor: fixed 1,024-byte cells, one layer of encryption per
  hop. A message goes up the sender's circuit to its rendezvous point,
  across to the recipient's, and down the recipient's circuit: six
  relays, each knowing only its neighbours. The finished transaction
  goes up a circuit too, and a relay announces it, so the sender's
  address is never the first to.

A miner votes with `set-leaf 0 consensus.txt`, which checks the file first;
votes for a file that does not parse, or that no peer serves, count for
nothing, and a file saying `mode init` votes the network back to init
mode. `status` shows the wallet's rendezvous sessions and, on a relay, the
sessions it holds; `consensus` the file in force since the last
boundary and the running count for the next. The known gaps (no cover traffic,
a hop could tag cells for a later one, circuits not rotated on a timer)
are in `miner/SECURITY.md` and `docs/HARDENING.md`.

To try a message layer on one machine, start the seed as a relay and point
the wallets at it (init mode):

```
tabminer node --data /tmp/seed --listen 127.0.0.1:4000 --no-seeds --relay
tabminer mine --data /tmp/a --listen 127.0.0.1:4001 --no-seeds --seed 127.0.0.1:4000
tabminer node --data /tmp/b --listen 127.0.0.1:4002 --no-seeds --seed 127.0.0.1:4000
```

then `address` on b and `send 1 tab1…` on a once it has mined a block.

## Two nodes

To try two nodes on one machine:

```
tabminer mine --data /tmp/a --listen 127.0.0.1:3737
tabminer node --data /tmp/b --listen 127.0.0.1:3738 --peer 127.0.0.1:3737
```
