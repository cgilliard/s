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

This is the design as discussed and settled on 2026-11-01, with what
remains open listed at the end. Constants are listed before it.

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
reached (a wallet at its rendezvous points; a relay makes one per
handshake, see "Handshake"), and rotated often, so a key compromised later opens nothing sent before
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
relay ID ADDRESS
relay ID ADDRESS
...
```

Onion mode: `relay` lines list the relays, one per line: its id (a
`tab1…` address, or 64 hex digits: the hash of its Dilithium key, which
a node started with `--relay` prints) and its address (`host:port`, UDP,
the same transport as the chain's; a v6 address in brackets), and
nothing else. There are no flags and no descriptors: the system is flat,
and every listed relay may be a hop or a rendezvous point. The file
carries only the key's hash; the key itself is shown, and proven held,
in the handshake that opens a channel to the relay. A relay that changes
its address or its Dilithium key needs a new file. The relays are taken
sorted by id, whatever order they are written in. Onion mode needs at
least `MIN_RELAYS` (three) of them: two hops and a rendezvous point for
each circuit. That is enough for testing, not for privacy.

Unknown directives are ignored (forward compatibility); a file that does
not parse, is not UTF-8, exceeds the size, lists an id twice, has a
relay line with anything after the address, lists more than
`MAX_RELAYS` relays, or in onion mode fewer than `MIN_RELAYS` is invalid
and its votes count for nothing. `set-leaf 0 FILE` refuses such a file, so a miner cannot
vote for one by accident.

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

**The file.** A node fetches a file only when it needs it: one voted for
more than the file in force (below), from any peer that serves it (a miner serves
the file it committed; a node that has fetched and checked a file serves
it). The file is checked by `SHA-256(file) == hash`. It is at most
`MAX_CONSENSUS` bytes and travels through the chunked transfer the chain
uses for blocks (`Kind::Consensus`, keyed by the file's hash), so it
arrives in windows of datagrams and is checked once whole. Files that
won at any time are kept for good.

**Which file is current.** Over the last `WINDOW` (144) main-chain blocks,
count the nonzero leaf-0 hashes. Only votes for a file that has been
fetched, checked and parses count: votes for a file that is corrupt, or
that no peer serves, count for nothing. Of the files that count, the
most voted is current, ties to the one committed most recently; one vote
is enough. A file saying `mode init` counts like any other, so miners
can vote the network back into init mode. With no vote that counts in
the window the network is in init mode. A node fetches the files voted
for more than the current one, most voted first, and passes over for
ten minutes a file no live peer serves. The window moves with the
chain, so the current file follows the main chain through
reorganizations without any special case. The file is whatever the
miners choose, as with any aux leaf; in practice miners and pools agree
on it among themselves.

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

The listed relays carry the traffic, through circuits in the manner of
Tor: a participant keeps circuits standing, and messages travel over
them in fixed-size cells, each relay knowing only its neighbours.

**Handshake.** Every link is opened by one handshake, the same whether a
participant opens it to a relay or a relay to another relay, and whether
it is a channel to a neighbour or a hop added to a circuit through one:

```
initiator → relay    fresh Kyber public key, random challenge
relay → initiator    Dilithium public key, Kyber ciphertext,
                     signature over the challenge and the whole exchange
```

The initiator checks the Dilithium key against the relay's listed id
(one hash), the signature, and decapsulates; both derive their
ChaCha20-Poly1305 keys from the shared secret and the transcript. The
relay so proves it holds the key the file names, and the Kyber key is
fresh every time, so each link is forward secret on its own. A relay
opening a channel to another relay also signs the exchange with its own
key, so both ends know they talk to a listed relay; a participant does
not, and stays anonymous. In init mode the roles are the other way
round: the participant signs the seed's nonce (see "Init mode").

**Channels.** A channel is the link between two neighbours, participant
to relay or relay to relay, opened by the handshake and carrying
frames sealed with ChaCha20-Poly1305 under a sequence number. Loss is
handled hop by hop: the receiver acknowledges what arrived, and the
sender resends what was not acknowledged, so a lost datagram costs one
link's round trip, not the whole path's. Circuits are multiplexed over
channels by a circuit number per channel.

**Circuits.** A circuit is built one hop at a time: the first hop by the
handshake over the channel to it, each further hop by the same
handshake carried inside the circuit (the participant's Kyber key and
challenge go to the last hop, which passes them to the next relay, as
Tor's EXTEND), so a hop learns nothing of the keys of the hops beyond
it. A cell is `CELL_BYTES` long, padded, so a relay cannot tell a slate
from a channel update from a zone by length, and carries one layer of
encryption per hop. Relays are distinct within a circuit; two circuits
may share relays.

**Standing circuits.** Building a circuit costs a round trip per hop, so
none is built per payment. Each participant keeps a circuit to each of
its three rendezvous points, through two relays chosen at random:

```
participant → r1 → r2 → rendezvous point
```

Its keys are announced over the circuit, and the rendezvous point holds
the session for its id over it, as a seed does over a direct connection
in init mode. The same circuits carry what the participant sends:

```
S → r1 → r2 → rend(S) → rend(R) → r3 → r4 → R
```

The sender's message goes up one of its circuits to its own rendezvous
point, which forwards it, addressed by the recipient's id, relay to
relay to one of the recipient's rendezvous points (computed from the id
like anyone), which sends it down the recipient's circuit. A reply goes
back the same way, so a slate's stages go back and forth without any
further setup. Six relays see a payment, each knowing only its
neighbours. Hops are chosen at random; only rendezvous points are fixed,
by the hash of the id, so that they can be found. A circuit is rebuilt
when a hop fails, and rotated on a timer.

**Rendezvous.** This is what `docs/NAMES.md` calls a name's rendezvous
points: a name resolves to an id, the id to its three rendezvous relays.
Neither side learns the other's network address. A rendezvous point
learns the id it serves (it must, to route by it). The recipient's
rendezvous point also learns which relay a message came from: one of the
sender's rendezvous points, so it narrows the sender to the ids that
relay serves, a cost of having no exits.

**What travels.** Slates, channel signing rounds (`sign_policy` on a
transaction's bytes passed around a factory's members), name zones for
sub-names, and anything else wallets agree on. Each is a message of a
kind inside a cell's encrypted body; relays never see kinds.

**The `--relay` flag.** A node relays only when started with `--relay`.
Without it a node is a participant: it keeps its own channels and
circuits, never accepts a circuit or forwards a cell. With it the node
runs the relay service on its UDP port and forwards for anyone. The
relay's id is its wallet's id (the seed-derived Dilithium key, shown by
`address`), which is what an operator puts in the `relay` line of a
`consensus.txt`. A node started with `--relay` prints that line ready to
paste at startup, its id as a `tab1…` address with its listening
address, and logs it, so an operator can hand it to whoever is
assembling the next file. A node listed in the file but not started
with `--relay` refuses handshakes and is passed over; a node started
with `--relay` but not listed forwards for nobody, since circuits are
built only through listed relays. In init mode the same flag turns on
the rendezvous service, so the seed nodes run with it.

**Transition.** When the current file changes mode, participants
reconnect to the rendezvous points the new mode gives them at the next
keepalive; a message in flight is lost at worst and resent, since
nothing is stored anywhere.

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
- **Relaying is opt-in by `--relay`.** A node forwards for others, and
  serves as a rendezvous point, only when started with the flag; every
  other node is a participant only. The flag is the operator's consent to
  carry traffic and the only switch: being listed in `consensus.txt`
  makes a relay usable, not active.

Settled on 2026-11-01, before onion mode.

- **No descriptors.** `consensus.txt` lists a relay's id (the hash of
  its Dilithium key) and address; the key is revealed and proven held
  in the handshake. A new key or address needs a new file.
- **One handshake** (Dilithium signature over a challenge, fresh Kyber
  key exchange, then ChaCha20-Poly1305) for channels and for every hop
  of a circuit; relays authenticate to each other both ways.
- **Tor-style circuits**: built hop by hop, fixed-size cells, one layer
  per hop; loss handled hop by hop on channels by acknowledgement and
  resending.
- **A flat network**: no exit, guard or rendezvous flags. Every relay
  may be a hop or a rendezvous point; hops are random, rendezvous points
  come from the id. Participants keep circuits only to their own
  rendezvous points, and messages go rendezvous point to rendezvous
  point.
- **Votes**: one is enough. Only files fetched and valid count; the
  most voted wins, whatever its mode, so a `mode init` file is a vote
  for init; nothing that counts means init mode.

## Constants

| constant | value |
|---|---|
| id | `H(DOM_ID ‖ Dilithium public key)`, 32 bytes |
| Kyber keys | ephemeral, signed by the Dilithium key; wallets rotate per session and daily, relays weekly |
| `MAX_CONSENSUS` | 1 MiB |
| `MAX_RELAYS` | 8,192 |
| `MIN_RELAYS` | 3: two hops and a rendezvous point; an onion-mode file with fewer is invalid |
| `WINDOW` | 144 blocks: the most committed file over them is current |
| `KEEPALIVE` | 30 seconds between pings on a rendezvous session |
| circuit length | 2 random relays plus the participant's rendezvous point |
| path | sender's 2 hops, both rendezvous points, recipient's 2 hops: 6 relays |
| `RENDEZVOUS` | 3 points per participant, from `H(id ‖ k)` |
| `CELL_BYTES` | 1,024 |
| aux leaf 0 | `SHA-256(consensus.txt)`; zero is no vote |

## Open points

1. **Relay economics.** Whether relays are paid (channels fit naturally:
   a relay is a liquidity provider's node) and how a sender proves it
   paid without being identified. Unpaid for now.
2. **Session limits.** How many sessions a rendezvous point holds, and
   whether holding one costs a proof of work or a payment, against a
   flood of ids. A fixed cap for now (`MAX_SESSIONS`, 10,000).
3. **Cover traffic and timing.** Whether relays and wallets send padding
   cells, and at what rate. None for now.

## Enhancements

Found while trying the network out (2026-11-01), most pressing first.
Smaller gaps, and the details of these, are in `docs/HARDENING.md`
("Message layer").

1. **Broadcast transactions over a circuit.** Finalizing pools the
   signed transaction in the sender's own node, which announces it to
   its peers as a `TxInv` from its own address (`main.rs`, `submit`).
   The first node to announce a transaction is likely its sender, so
   the network address is tied to the payment's inputs, undoing what the
   circuits hid. Send the finished transaction up one of the wallet's
   standing circuits to its rendezvous point (a new relay message), which
   pools and announces it as its own; the wallet's node pools it only
   once a peer announces it back. In init mode, a seed does the same
   over the session.
2. **Change the file in force at epoch boundaries, with a grace
   period.** The window is counted at every tip, so a single block can
   switch the mode or the relay list, nodes switch a few seconds apart
   (each when it has fetched the file), and a reorganization can switch
   back; every switch moves rendezvous points and so drops sessions.
   Instead, with `B` a multiple of `EPOCH` (144, the window):

   - **At `B`** the file is decided once, by the rule above, from the
     window ending at `B`: votes for a file the node has not fetched,
     or that does not parse, are not counted at all; the most voted of
     the rest wins, ties to the most recent; with none left, init mode.
     Whether that is the current file, another or init depends only on
     what the other blocks voted. If it differs from the current one,
     participants start building circuits and sessions for it beside
     the old ones.
   - **From `B` to `B + GRACE − 2`** (144 to 148, `GRACE` 6) both sets
     stand: participants hold sessions under both files, relays serve
     ids that are rendezvous points under either, and in a switch
     between modes the seeds keep their init-mode service up.
   - **From `B + SWITCH`** (146, `SWITCH` 2) senders look recipients up
     under the new file first, falling back to the old one on offline
     (before then, the other way round), so a node a block ahead of or
     behind another does no harm.
   - **At `B + GRACE − 1`** (149) the old file's circuits and sessions
     are closed.

   Between boundaries nothing switches: a file that wins mid-epoch waits
   for the next one, up to a day, emergencies included. A reorganization
   that replaces block `B` decides again; within the grace period both
   sets still stand, so only one deeper than that switches for real.
   What remains subjective is whether a node holds the winning file at
   `B`: nodes fetch every file voted for more than the current one as
   the votes come in, so they normally hold it long before, but two
   nodes may still decide differently if one has not; deciding from the
   window ending a few blocks before `B` would give the file time to
   spread, at the cost of those blocks' votes.
3. **Rendezvous points that survive a change of relays.** A point is
   `H(id ‖ k)` modulo the number of relays, so adding or removing one
   relay moves the points of nearly every id. Choose them by rendezvous
   (highest random weight) hashing instead: rank the relays by
   `H(id ‖ relay id)` and take the top three, so a change of one relay
   moves only the ids that had it among their three.
4. **A relay key apart from the wallet.** A relay's listed id is now its
   operator's payment address. Give the relay its own Dilithium key
   (derived under another domain tag, or random in `DIR/relay.key`).
5. **`--no-wallet`.** Seeds and relays need no wallet and should not keep
   a phrase on a server; with 4, a relay needs none.
6. **A relay is its own wallet's rendezvous point**, held locally, rather
   than skipped (in both modes).
7. **Faster recovery.** Rotate standing circuits on a timer, notice a
   dead hop from an unanswered keepalive in seconds rather than when the
   channel gives up, and keep a spare circuit to each point.
8. **Traffic analysis.** Padding cells and cover traffic, a tag per
   layer against tagging, and a minimum number of relays (and of
   operators) before onion mode is worth calling private.
9. **Limits.** A cookie round trip before a relay's handshake work, per
   address caps on channels, hops and sessions, and a limit on the
   stage-1 slates a wallet answers per sender.

## Implementation order

0. **Primitives.** Done (2026-11-01): `chacha20poly1305.rs` (RFC 8439,
   its vectors), `keccak.rs` (SHA-3 and SHAKE, FIPS 202), `mlkem.rs`
   (ML-KEM-768) and `mldsa.rs` (ML-DSA-65), the last two checked against
   NIST's ACVP known answers in `tests/vectors/` for key generation,
   encapsulation and decapsulation (including implicit rejection and the
   modulus check), signing and verification (including each kind of
   tampered signature). ML-DSA signatures are deterministic over a message
   and a context string. The wallet derives its ML-DSA seed from the
   master key under its own domain tag (`identity_key`), its id is
   `H(DOM_ID ‖ public key)` with `DOM_ID` 18 (`address::id_of`), and
   `address` at the prompt shows the `tab1…` form and the id.
1. **Aux leaves.** Done (2026-11-01). `GetAux`/`Aux` carry a block's 16
   leaves in one datagram; a node wants the leaves of every connected
   block with a nonzero aux root within the undo window of the best
   header (the sender first, then peers in turn) and of any block of the
   last 144 it finds without them, checks them against the header
   (`Chain::put_aux_leaves`, a mismatch is a strike) and keeps them with
   the body. The window count (`consensus.rs`, `Chain::consensus_votes`)
   runs on every tip change, arrival and ten seconds; the winning hash's
   file travels as `Kind::Consensus` through the chunked transfer, named
   by its SHA-256 cut to a canonical digest (`consensus::file_id`), is
   checked by the full hash and kept for good. `set-leaf 0 FILE` keeps
   the file so the miner serves it; a node that mines a block with its
   own root keeps its own leaves. `consensus` at the prompt shows the
   window's votes, the winning file and its text. Parsing is step 2:
   until then "current" means held, not yet valid.
2. **The file.** Done (2026-11-01): `consensus::File::parse` with every
   rule above and a line-numbered error; `Chain::consensus` decides the
   mode from the window (`consensus::Current`: init unless the winner's
   file is held and valid); the node logs each change of winner or mode
   and the verdict on every file it fetches; `consensus` at the prompt
   shows the mode; `set-leaf 0 FILE` parses the file first.
3. **Init mode.** Done (2026-11-01). `onion.rs` holds the objects: an
   `Announce` (Dilithium key, Kyber key, sequence number, expiry, the
   session's nonce, signed), a `Payload` (encapsulated to the recipient's
   Kyber key, sealed with ChaCha20-Poly1305, carrying the sender's own
   announce for the reply and then signed) and `rendezvous_indexes`.
   The node's session layer (`node/sessions.rs`) rides five new messages:
   `Session` (open, and keepalive every 30 s) answered by `SessionState`
   (the nonce the announce must carry, a SipHash of the participant's
   address and id so nothing is stored per attempt, and the sequence
   number held), `GetAnnounce`, `Offer` and `Notice` (forwarded,
   offline, refused, rejected). Objects are never pushed: an `Offer`
   names one and the receiver pulls it as `Kind::Object` chunks with the
   token the offer carried, so a relay reaches a participant that is not
   in its peer table. A node started with `--relay` holds up to
   `MAX_SESSIONS` (10,000) sessions, any id in init mode (a seed cannot
   tell which seed name it is), and forwards a payload only down a live
   session. A node with a wallet keeps sessions at its points (the
   seeds, sorted by name), announcing one Kyber key at all of them,
   rotated at start, on every reconnect and after 12 hours; a retired
   key opens payloads for ten more minutes. Sequence numbers are the
   time in milliseconds, so they rise across restarts. A request left
   unanswered pings the point again, since a restarted relay has new
   tokens. At the prompt, `send AMOUNT [FEE] TO` takes a `tab1…`
   address, 64 hex digits or `@name` besides a file; the recipient's
   wallet answers a stage-1 slate at once over the reply key, and the
   sender's finalizes and pools the answer, checking it came from the
   id it was sent to (`Wallet::take_slate`); a slate that no point would
   forward is cancelled. `name-commit NAME` without a value points the
   name at the wallet's own id, so `@NAME` reaches it.
   `status` shows the sessions. In onion mode the same sessions go
   directly to the listed relays until step 4 puts circuits in between.
   Not yet: a relay's own wallet is reached only through other points
   (a point that is this node is skipped), and nothing limits who may
   send a stage-1 slate to an online wallet (open point 5).
4. **Onion mode**, done (2026-11-01), in parts:
   - 4a. Done (2026-11-01): the decisions above; the vote counts only
     files fetched and valid (`consensus::Current::decide`, which lists
     the files that do not count and why; the node fetches those voted
     for more than the current one, most voted first, and passes over
     for ten minutes one no peer serves); relay lines lose their flags.
   - 4b. Done (2026-11-01): `channel.rs` and `node/channels.rs`. The
     handshake as above: the hello (1,217 bytes) and the reply (6,349)
     and auth (5,261) travel as `Handshake` fragments of 1,152 bytes,
     each a request with the receiver's token, so a relay answers only
     an address that answered its ping; the transcript hash covers the
     channel number, the hello, the relay's key and the ciphertext, and
     the two signatures are under different contexts; keys come from
     SHAKE256 of the shared secret and the transcript, one per direction.
     Only a node started with `--relay` answers a hello. Frames: a
     sequence number, everything received below `ack` and a 64-bit
     bitmap past it, the body sealed under the nonce `0 ‖ seq` (ack-only
     frames under `1 ‖ n`), at most 1,178 bytes of body per datagram. A
     frame is resent as the very bytes first sent, after 0.4 s doubling
     to 5 s, twelve times before the channel is given up; at most 64 are
     in flight, none past the oldest unacknowledged by 64 or more;
     bodies are delivered in order; the initiator keeps the channel alive
     every 30 s, and two minutes of silence ends it. A relay takes no
     frame on a mutual channel before the auth, and the initiating relay
     resends the auth until something is acknowledged.
   - 4c. Done (2026-11-01): `circuit.rs` and `node/circuits.rs`. A cell
     is 1,024 bytes, one channel body: a circuit number, a command
     (`Create`, `Created`, `Relay`, `Destroy`) and a payload. Every hop,
     the first too, gets the channel handshake under its own transcript
     domain, carried in `Create`/`Created` cells for the first hop and
     as `Extend`/`Extended` relay messages through the circuit for the
     others; a hop extends only to a relay the file lists, at its listed
     address, opening a mutual channel to it if there is none. Each hop
     has a key per direction and counts the relay cells it passes; a
     layer is ChaCha20 under the key with the count as nonce, and the
     cell for hop `t` carries a Poly1305 tag of its body under hop `t`'s
     key, inside all the layers, so each hop knows the cells for it and
     passes the rest on, and the client knows which hop answered.
     Messages span cells (999 bytes each). Circuit numbers are per
     channel, the opener's half and the other's half apart. A channel
     that closes ends every circuit over it, and each hop passes the
     `Destroy` on; a circuit not built in 30 s is given up.
   - 4d. Done (2026-11-01): `node/rendezvous.rs`. At the last hop of a
     participant's circuit: `Session(id)` answered by `SessionState(id,
     nonce, seq)`, the nonce this relay's SipHash of the circuit and the
     id, so a session is bound to its circuit; `Announce` checked as in
     init mode and held while the circuit lives and keepalives come;
     `GetAnnounce(id)` answered by `Announce` or `Notice(offline)`;
     `Send(payload)` answered by `Notice(forwarded or offline)`, the
     recipient getting `Deliver(payload)` down its circuit. Between
     rendezvous points, `Rendezvous` cells on circuit number 0 of their
     mutual channel, taken only from a listed relay: `Lookup(id)` →
     `Found(announce)` or `Result(offline)`, `Forward(payload)` →
     `Result(forwarded or offline)`. A sender's point asks the
     recipient's points in the order the id gives them, answering at
     once when it is one of them and holds the session, and moves to
     the next on offline or after 8 s; a relay serves sessions only for
     ids whose points include it.
   - 4e. Done (2026-11-01): `node/participant.rs`. While an onion-mode
     file is in force a node with a wallet keeps a circuit to each of its
     rendezvous points, through two other listed relays chosen at
     random (fewer when too few are listed), and holds its session over
     each as in init mode: `Session` every 30 s, every 3 s while the
     point does not hold the current announce, the same Kyber key at
     every point, rotated at start, when a live session or its circuit
     is lost, and after 12 hours. A circuit that dies is built again
     after 3 s; a point that refuses is left for a minute. A send goes
     over a live circuit picked at random: `GetAnnounce` unless the
     wallet gave the recipient's announce, then `Send`, and the wallet
     is told delivered or why not (30 s at most, waiting for a circuit
     included). Delivered payloads are opened as in init mode. Back in
     init mode the circuits are closed and the init-mode sessions come
     back. The wallet's side (`send` to an address or `@name`, answering
     and finalizing) is unchanged: the node picks the mode.
5. **Docs.** Done (2026-11-01): the README's "Message layer" section
   and payments by address or `@name`; the message layer's cryptography,
   what each party learns and its gaps in `miner/SECURITY.md`; the gaps
   found while building it in `docs/HARDENING.md`.
