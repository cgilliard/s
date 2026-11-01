# Onion routing

The message layer: how wallets and channel parties reach each other
without a server, without revealing to the network who talks to whom.
Payments (slates), channel updates and name zones travel over it; the
chain only ever sees the transactions that result.

Its basis is a file, `consensus.txt`, that miners commit to in aux leaf 0
of the blocks they mine and that every node fetches, checks and follows,
the way it follows blocks: the file most miners committed to over the
last 144 blocks is the one in force. The file says which mode the network
is in and, in onion mode, which relays exist. There is no store and
forward anywhere: a recipient is reachable while it is online and
connected to its rendezvous points, and not otherwise.

This is the design as discussed on 2026-11-01: the parts settled so far,
with the open points listed at the end. Constants are listed before them.

## Identities

Every participant, relay or wallet, is known by one 32-byte value:

```
id = H(DOM_ID ‖ Dilithium public key)
```

the same value a registered name resolves to (`docs/NAMES.md`), so a name
is a human handle for an onion identity. The id is the address: what a
payer is given (or a name that resolves to it), what every message is
addressed by, and what the holder's rendezvous points are derived from
(`H(id ‖ k)`, see "Rendezvous"), so an id alone is enough to reach its
holder. The Dilithium key is long-lived
and signs everything the holder publishes. Encryption to the holder uses
Kyber keys that are ephemeral: made fresh, signed by the Dilithium key
with a sequence number and an expiry, published where the holder is
reached (a wallet at its rendezvous points, a relay in its descriptor),
and rotated often, so a key compromised later opens nothing sent before
its rotation (forward secrecy), and a holder rotates without touching the
chain. Anyone given the Dilithium key checks it against the id by one
hash, then checks a Kyber key by one signature. The chain never carries
either key.

**Text form.** An id is written in bech32m with the human-readable part
`tab`: `tab1` followed by 52 characters of data and 6 of checksum, 62
characters in all, case-insensitive, the checksum catching any four
errors (`address.rs`). This is what a payer is given and what the
prompt accepts and shows wherever an id or a name's value appears.

A signed key announcement is

```
kyber   Kyber public key
seq     sequence number, increasing
expires unix time
sig     Dilithium signature over the above and the id
```

about 5 KB at the lowest Dilithium parameter set, sent once per session
or rotation; a receiver keeps the newest sequence number it has seen for
an id and ignores older announcements.

## consensus.txt

A text file, UTF-8, one directive per line, `#` comments, blank lines
ignored, at most `MAX_CONSENSUS` bytes. The first directive is the mode.

```
mode init
```

Init mode: there are no relays yet; the seed nodes (`SEEDS` in `node.rs`)
stand in for them (see "Init mode"). The rest of the file is ignored, so
it may carry comments or an announcement. No file at all means init mode.

```
mode onion
relay ID ADDRESS [FLAGS]
relay ID ADDRESS [FLAGS]
...
```

Onion mode: `relay` lines list the relays, one per line: its id
(64 hex digits), its address (`host:port`, UDP, the same transport as the
chain's), and optional flags (`exit`, `rendezvous`, `guard`; their meaning
is an open point). Addresses may change without a new consensus: a relay
whose address is stale is found through its descriptor served by other
relays (open point).

Unknown directives are ignored (forward compatibility); a file that does
not parse, exceeds the size, or lists more than `MAX_RELAYS` relays is
invalid and never replaces the current one.

## Commitment and propagation

A miner that wants to publish a file sets aux leaf 0 to its SHA-256
(`set-leaf 0 consensus.txt` at the prompt) and keeps the file; every block
it mines from then on carries the aux root over that leaf. A node
following the chain treats leaf 0 the way it treats a block's body: a
thing the header commits to, fetched from peers, checked, kept.

**The aux leaves.** For every block whose header has a nonzero aux root a
node fetches the block's 16 leaves (512 bytes, one datagram) from the
peer that gave it the block, then from any peer, and checks
`aux_merkle_root(leaves) == header.aux`. A miner always has the leaves of
its own blocks; a node that has checked a block's leaves serves them. The
leaves are kept with the block for the undo window. Leaf 0 is the
block's vote: the SHA-256 of a `consensus.txt`, or zero for no vote.

**The file.** A node fetches a file only when it needs it: the one whose
hash wins the window below, from any peer that serves it (a miner serves
the file it committed; a node that has fetched and checked a file serves
it). The file is checked by `SHA-256(file) == hash`. It is at most
`MAX_CONSENSUS` bytes and travels through the chunked transfer the chain
uses for blocks (`Kind::Consensus`, keyed by the file's hash), so it
arrives in windows of datagrams and is checked once whole. Files that
won at any time are kept for good.

**Which file is current.** Over the last `WINDOW` (144) main-chain blocks,
count the nonzero leaf-0 hashes; the most common one, if its file has
been fetched, checked and parses, is the current file. Ties go to the hash
committed most recently. If no block in the window votes, or the winning
file cannot be fetched or does not parse, the network is in init mode.
The window moves with the chain, so the current file follows the main
chain through reorganizations without any special case, and a file has
to be committed by more blocks than any other over a day to take effect:
one miner's block changes nothing. Who may author the file is an open
point below, and until it is settled the file is whatever most miners
choose, as with any aux leaf.

**Why propagate rather than embed.** The header carries 32 bytes; the file
is the thing those bytes commit to. Propagating it with the block gives
every node the same file at the same height with the same guarantee the
block's body has: committed to by the work, and by a day of it.

## Rendezvous

Both modes work the same way; only the set of nodes differs. A
participant's three rendezvous points are chosen from the available
nodes (the seeds in init mode, the relays in onion mode) by the hash of
its 32-byte id: `H(id ‖ k)` for `k` in 0, 1, 2, each reduced to an index
into the list sorted by id, skipping repeats. Anyone holding the
consensus and the id computes the same three.

A participant that wants to be reached is online: it opens a session to
each of its rendezvous points (a circuit in onion mode, a direct
connection in init mode), gives it its Dilithium key and a signed
announcement of a fresh Kyber key, pings it every `KEEPALIVE` seconds and
reconnects when the session drops, with a new Kyber key on every
reconnect and at least daily. A rendezvous point forwards messages for
an id only down a live session for it; with no live session the message
is refused and the sender learns the recipient is offline. There is no
mailbox and nothing is stored: you must be online to be paid, as with a
channel.

A sender resolves a name or takes an id, computes the recipient's
rendezvous points, reaches one (through a circuit of its own in onion
mode, directly in init mode), asks it for the id's keys, checks the
Dilithium key against the id and the Kyber announcement against the
Dilithium key, and sends a message encapsulated to that Kyber key,
addressed by id. The first message carries the sender's own Dilithium key
(if it wants to be identified) and a fresh Kyber key for the reply, so
replies are forward secret too.

## Init mode

The seed nodes are the relays. Each seed accepts sessions from
participants whose rendezvous points it is among, keyed by id, and
forwards messages between a sender's connection and the recipient's
session. A message is

```
to      recipient id (32)
from    sender id (32), or zero
nonce   24
body    Kyber-encapsulated to the recipient's Kyber key: the slate,
        channel message or zone, and its kind
sig     Dilithium signature by the sender over the above, or empty
```

so a seed learns which ids talk, when, and how much, and nothing else;
the body is opaque. Slates (`send`, `receive`, `finalize`) and channel
signing rounds go over these sessions the way they go through files
today; the wallet's `send AMOUNT FILE` gains a form that takes a name or
an id instead of a file.

Init mode exists to get the network running with no relays; it is not
private beyond the body's encryption and it relies on the seeds being up.
The switch to onion mode is a `consensus.txt` with `mode onion` that wins
the window.

## Onion mode

**Relays.** Each listed relay runs the onion service next to its node: it
holds a Dilithium key whose hash is its listed id, publishes a signed
descriptor (the Dilithium key, a Kyber key announcement rotated weekly,
the address, flags, a sequence number) that any node fetches and checks
against the id, and forwards cells. Circuit keys come from encapsulating
to the descriptor's Kyber key, so a hop's past traffic is safe once that
key rotates.

**Standing circuits.** Building a circuit costs a round trip per hop, so
no circuit is built per payment. Every participant keeps two kinds
standing:

- an *inbound* circuit to each of its three rendezvous relays, through
  two relays of its choice: `rendezvous ← relay ← relay ← participant`;
  this is the session the rendezvous relay forwards down, with the
  participant's keys announced over it;
- an *outbound* circuit through two relays of its choice to an *exit*
  relay it picks at random: `participant → relay → relay → exit`.

A payment is one message over circuits that already exist:

```
sender → relay1 → relay2 → exit → recipient's rendezvous → relay3 → relay4 → recipient
```

The exit forwards the message, addressed by the recipient's id, to one
of the recipient's rendezvous relays (which it computes from the id like
anyone); that relay forwards it down the recipient's inbound circuit.
Circuits are two-way: the rendezvous relay remembers for the exchange
which inbound session the message went to and which link it came from,
and the reply travels back the same path, so a slate's stages go back
and forth without any further setup. Six relays see a payment, each
knowing only its neighbours.

The exit is chosen at random and is not one of the sender's own
rendezvous relays: the recipient's rendezvous relay sees where messages
for the recipient arrive from, and a relay tied to the sender's id would
narrow the sender to the ids that relay serves. After a payment the
sender retires its outbound circuit and uses the next, built in the
background while the last was in use, so there is always one ready and
no two payments share a path. Inbound circuits rotate on a timer and when
a hop fails.

**Cells.** One Kyber encapsulation per hop establishes a per-hop key;
each layer of a packet is encrypted to one hop, and each hop learns only
the previous and the next. Packets are fixed-size cells padded to
`CELL_BYTES`, so a relay cannot tell a slate from a channel update from a
zone by length. The construction is a Sphinx-style packet with a
post-quantum KEM in place of Diffie-Hellman; its exact format is an open
point below.

**Rendezvous.** This is what `docs/NAMES.md` calls a name's rendezvous
points: a name resolves to an id, the id to its three rendezvous relays,
and any exit reaches one of them. Neither side learns the other's network
address; a rendezvous relay learns the id it serves (it must, to route by
it) and that a message for it came from some exit, never who sent it.

**What travels.** Slates, channel signing rounds (`sign_policy` on a
transaction's bytes passed around a factory's members), name zones for
sub-names, and anything else wallets agree on. Each is a message of a
kind inside a cell's encrypted body; relays never see kinds.

**Transition.** When the window's winner changes mode, participants
reconnect to the rendezvous points the new mode gives them at the next
keepalive; a message in flight is lost at worst and resent, since nothing
is stored anywhere.

## Decisions

Settled on 2026-11-01, before implementation.

- **Cryptography is in-house**, as the rest of the crate: ML-KEM (Kyber)
  and ML-DSA (Dilithium) per FIPS 203 and 204, checked against their
  known-answer tests; ChaCha20-Poly1305 per RFC 8439 for every symmetric
  layer (message bodies, circuit layers), checked against its vectors.
  Parameter sets: ML-KEM-768 and ML-DSA-65 (security category 3) unless
  size argues otherwise once the cells are designed.
- **The wallet's Dilithium key is derived from the seed phrase**: ML-DSA
  key generation takes a 32-byte seed, which the wallet derives from its
  master key under a domain tag, so a wallet restored from its twelve
  words has the same id and address. Ephemeral Kyber keys are random.
- **Sessions ride the chain's UDP transport**: a session layer in the
  node with keepalives, ordering and retransmission, messages of a few
  kilobytes carried as chunked transfers, used by participants towards
  their rendezvous points and by relays between each other.
- **No authority over `consensus.txt`.** The file in force is purely the
  window's winner: the hash committed by the most main-chain blocks of
  the last 144, ties to the most recent. Miners are the electorate.

## Constants

| constant | value |
|---|---|
| id | `H(DOM_ID ‖ Dilithium public key)`, 32 bytes |
| Kyber keys | ephemeral, signed by the Dilithium key; wallets rotate per session and daily, relays weekly |
| `MAX_CONSENSUS` | 1 MiB |
| `MAX_RELAYS` | 8,192 |
| `WINDOW` | 144 blocks: the most committed file over them is current |
| `KEEPALIVE` | 30 seconds between pings on a rendezvous session |
| circuit length | 2 relays plus the exit or the rendezvous relay: 6 relays end to end |
| outbound circuits | one in use, one prebuilt; retired after each payment |
| `RENDEZVOUS` | 3 points per participant, from `H(id ‖ k)` |
| `CELL_BYTES` | 1,024 |
| aux leaf 0 | `SHA-256(consensus.txt)`; zero is no vote |

## Open points

To be settled before implementation, in roughly this order.

1. **Relay descriptors.** Where a relay's keys, address and flags are
   fetched from (other relays, the seeds, the relay itself at its listed
   address) and how a changed address is found.
2. **Packet format.** The Sphinx-style construction with Kyber: header
   size per hop, the per-hop MAC, replay protection, and the reply path a
   first message carries.
3. **Relay economics.** Whether relays are paid (channels fit naturally:
   a relay is a liquidity provider's node) and how a sender proves it
   paid without being identified.
4. **Flags and selection.** What `exit`, `rendezvous` and `guard` mean,
   how senders weight relays, and whether a sender keeps long-lived
   guards as Tor does.
5. **Session limits.** How many sessions a rendezvous point holds, and
   whether holding one costs a proof of work or a payment, against a
   flood of ids.
6. **Cover traffic and timing.** Whether relays and wallets send padding
   cells, and at what rate.
7. **Ties and thin windows.** Ties go to the most recent commitment; a
   window with few votes (right after launch, or after a long quiet
   spell) may need a minimum count before a file applies.

## Implementation order

0. **Primitives.** `chacha20poly1305.rs`, `mlkem.rs` and `mldsa.rs`
   with the standard test vectors; the wallet's Dilithium key from the
   seed and its `tab1…` address (`address` at the prompt).
1. **Aux leaves.** Nodes fetch, check, keep and serve the leaves of
   blocks with a nonzero aux root; the window count of leaf-0 hashes;
   `Kind::Consensus` in the chunked transfer for the winning file;
   `consensus` at the prompt shows the current file, its hash and its
   votes in the window; miners serve their own.
2. **The file.** Parsing and validation of `consensus.txt`, the current
   file's selection by the window, and a miner's `set-leaf 0` wiring with
   a check that the file parses.
3. **Init mode.** Sessions at the seeds with keepalives, the rendezvous
   choice by id, the message format, the Dilithium key in the wallet
   (the id behind a name's value) and its ephemeral Kyber keys and
   announcements, and slates by name or id.
4. **Onion mode.** Relay service, descriptors, circuits and cells,
   rendezvous over circuits, and the wallet's use of them.
5. **Docs.** README, SECURITY.md, HARDENING.md.
