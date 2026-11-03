# Sub-names and rotating rendezvous points

Two message-layer features, written up 2026-11-02 to be tracked; neither
is built. Neither changes consensus: the chain keeps registering single
labels (`docs/NAMES.md`), and rendezvous points are already chosen off
chain (`docs/ONION.md`).

## 1. Sub-names

### The idea

The chain registers top-level names only: one label of 1 to 32
characters from `[a-z0-9_]`, resolving to the owner's id (the hash of
its Dilithium key). The dot is not in that alphabet, so `cool.example`
can never be a chain name. Once `example` is registered, its owner may
point sub-names under it (`cool.example`, `blah.example`) at any ids,
its own or others'. Only resolvers and the name's **sub-name server**
understand sub-names; the chain never sees them.

The reason is capacity: consensus registers at most 5 names per block
(`docs/NAMES.md`), far too few for every user to hold a top-level
name. Sub-names give one name to as many users as its owner admits,
with no chain cost; relays scale out with the number of names and
sub-names instead.

Sub-names are therefore free, unlimited and changeable at any time, and
entirely under the parent's control: whoever owns `example` (and the
server it delegates to) decides what `cool.example` means, and a new
owner of `example` starts with none. Anyone wanting an identity the
parent cannot touch registers a top-level name.

### Why a server, not a zone at the rendezvous points

The first draft had the owner publish a signed zone of every entry to
the name's rendezvous points. That scales with the number of
sub-names: a name that lets others register under it would carry a
large zone, re-sent to every point at every epoch boundary (section 2)
and stored at relays that never chose to host it. Instead the points
hold one small record per name saying who answers for it, and the
entries live with whoever runs that server.

### The sub-name server

A sub-name server is an ordinary participant, not a relay, and is
never listed in `consensus.txt`. It has its own identity key (id `S`),
runs in onion mode, and holds sessions at `S`'s rendezvous points,
moving them each epoch like any wallet. Resolvers reach it the way a
payment reaches a wallet: a query is a payload like any other (kind
`KIND_SUBNAME`), sealed to the server's announced key, through a
circuit to one of `S`'s points, which forwards it over the server's
session; the answer comes back along the query's return route. The
points carry it without reading it. It can run on a home machine with
no inbound ports.

The holder of `V`, the value of a name, publishes at `V`'s points a
**delegation**:

```text
owner key ‖ seq ‖ expiry ‖ server ids (1 to 3)
```

signed by the key whose hash is `V`. It is the id's, not one name's:
points hold one delegation per id, and every name whose value is `V`
shares its servers (a wallet owning several names pointing at its
address delegates once). Answers name their name, so a server's answer
for `example` cannot stand for another name. The owner's node sends it up its standing circuit (`Publish`)
whenever its session there goes live; that point passes it to `V`'s
other points (`Store`). Each holds it apart from the session, until
`expiry`, so it is found while the owner is offline; each keeps the
highest `seq` and takes an update at most every 10 seconds. A resolver
asks for it (`GetDelegation`) and the point it asks tries `V`'s points
in turn, as a lookup does. Points check the delegation is sound and for
an id they serve; the resolver checks it against the chain. Onion mode
only: in init mode there are no delegations, so the owner answers.

**With no delegation, the owner's own node is the server** (`S = V`):
the query is sent to `V`, as a payment is. A small name needs nothing new published; an owner who wants
sub-names to resolve while its wallet is offline delegates to an
always-on machine.

The server answers a query for `label.name` with

```text
name ‖ label ‖ type ‖ value ‖ seq ‖ expiry ‖ server key
```

signed by its own key. `type` is one byte: `none` (no such label, an
empty value) or `id` (the value is a 32-byte id to pay); a resolver
refuses types it does not know, and values are length-prefixed, so new
ones (a text value, say) can be added later without changing the
format. `expiry` is absolute Unix time, as announces use, so a cached
answer is checked without trusting when it was fetched. The server signs, not the owner, so
registrations do not need the owner's key online; the cost is that a
server can lie about an entry (point it elsewhere, or deny it) until
the owner withdraws it by publishing a delegation with a higher `seq`.
The delegation's expiry bounds that, so it should be short (about one
epoch; it is republished every epoch anyway). Several server ids give
redundancy; resolvers try or race them.

How a holder gets an entry onto a server (free, paid, first come) is
between them and the server's operator, outside the protocol. The
protocol defines only the delegation, the query and its answer.

### Example: `send cool.example 5`

| Who | Id | Rendezvous points |
|---|---|---|
| Owner of `example` | `V` | `P1, P2, P3` |
| Sub-name server | `S` | `Q1, Q2, Q3` |
| Holder of `cool.example` | `T` | `R1, R2, R3` |

Every set of points is computed from the id, the epoch and the listed
relays (`H(id ‖ epoch ‖ relay)`, section 2); no one publishes an
address.

1. The wallet splits the input into label `cool` and name `example`,
   and reads `example → V` from the chain.
2. It asks for `V`'s delegation over an outbound circuit; that
   circuit's last relay asks `V`'s points (`P1`, then the others) and
   returns it. The wallet checks the key hashes to `V`, and the
   signature and expiry. It learns `S`.
3. It sends a query for `cool.example` to `S`, as any payload: `S`'s
   announce from `Q1`, the query sealed to it, forwarded over the
   server's session. The answer comes back down the wallet's circuit;
   it checks the server's signature and learns `T`.
4. It pays `T` as any id: `T`'s announce at `R1`, then the payment.

```text
wallet ──chain──▶ example = V
wallet ──circuit──▶ P1 ──▶ delegation: servers [S]
wallet ──circuit──▶ Q1 ══session══▶ server ──▶ cool = T   (sealed)
wallet ──circuit──▶ R1 ══session══▶ holder's node   (the payment)
```

With no delegation, `P1` answers none and step 3 goes to `P1`,
over the owner's session.

### Latency

A cold resolve is three dependent circuit round trips (the last is the
payment's own), against one for a top-level name: estimated a second
or two more on real paths, likely the same order as the slate exchange
and transaction proof that follow. To be measured on `--network dev`
before designing further. Without changing the design:

- **Caching.** The delegation is good until its expiry, an entry until
  its own; a repeat send to `cool.example` goes straight to step 4.
- **Warm circuits.** Reuse an existing circuit, extending its last hop
  to each point in turn, rather than building one per step.
- **Racing.** Ask two of `V`'s points, and every listed server, at
  once; take the first valid answer.
- **Prefetching.** Resolve address-book sub-names in the background at
  startup, and as soon as the input names a sub-name.

If measurement still shows it slow, **point-side forwarding**: the
wallet asks `P1` once for `resolve(example, cool)`, and `P1`, which holds
the delegation, asks `Q1` directly (relay to relay) and returns the
delegation and the server's signed answer together, saving one
dependent round trip. The costs: `P1` learns the label, not just the
name, and relays do work for others, so it needs rate limits against
amplification. Kept as a fallback.

### Privacy

The name's points see that `V`'s delegation is asked for, as they see
lookups now. The server sees which labels are asked, but not by whom,
since queries arrive through circuits; its points see only a sealed
payload for `S`, as for a payment.

### Commands and limits

- `subname server ADDRESS…` / `subname server none`: set or clear the
  delegation of the wallet's id, for every name pointing at it; the
  wallet signs it for a day and renews it every six hours while it runs.
- `subname set LABEL.NAME TO`, `subname del LABEL.NAME`, `subnames`: the
  entries the wallet's node answers for, for its own names or any that
  delegate to it, kept in `DIR/subnames`.
- `send 5 @cool.example`: resolved as above (and anywhere `@NAME` is
  taken, as `burn`'s `FOR`).
- Labels follow the chain's alphabet and length; one level to begin
  with (nested labels later, each level delegated by its parent).
- Points take a delegation update per id at most every 10 seconds, and
  hold as many delegations as sessions at most; a server gives at most
  600 answers a minute (each costs a signature). A popular server can
  spread over several ids.

### Later: self-published sub-names

Not for now, and not in the reference implementation.

Under the design above the holder already runs its own identity: an
entry `alice → T` names alice's id, `T = H(alice's key)`, and the
server's signed answer is the parent's authorization. Alice holds the
sessions at `T`'s points, moves them each epoch and receives payments;
the parent never touches them and cannot sign as `T`. What stays with
the parent is answering lookups: every cold resolve of `alice.gmail`
reaches gmail's server, which must stay up, scale with lookups and sees
every label asked.

To take the parent out of the lookup path, its server signs a
**certificate** once and hands it to the holder:

```text
name ‖ label ‖ type ‖ value ‖ seq ‖ expiry ‖ server key        (signed by S)
```

The holder publishes it itself, at points computed from the full name,
`H("alice.gmail" ‖ epoch ‖ relay)`, and moves it each epoch like its
announce. A resolver:

1. reads `gmail → V` from the chain and gmail's delegation from `V`'s
   points (cached for its lifetime), learning `S`;
2. asks the full name's points for the certificate, and checks its
   signature by `S`, the name, the label and `not_after`;
3. pays `T`.

Here a label does get points of its own, so lookup load spreads over
the relays in proportion to the number of sub-names rather than
landing on one server. The parent's server only issues and renews
certificates. Revoking a holder means not renewing, so certificates
are short (about a delegation's lifetime); one cannot be withdrawn
before `not_after`, and a parent that wants that must keep answering
lookups itself (the design above). Resolvers that find no certificate
fall back to asking the server, so both can run side by side. The
signed answer is already such a certificate: its expiry is the
`not_after`, so the holder publishes the answer itself.

## 2. Rendezvous points that rotate by epoch

### Why

A participant's points are the listed relays ranked highest by
`H(id ‖ relay)` (`onion::rendezvous_relays`). For a fixed relay list
they never change, so a relay that ranks high for an id (by luck, or by
grinding relay keys until one does, then getting it listed) is that id's
point for good: it sees every session and lookup and can refuse service
indefinitely. Tor rotates its onion services' directories by time
period for the same reason.

### The rule

Rank by `H(id ‖ epoch ‖ relay)`, with `epoch` the counter of 144-block
windows: `epoch = height / EPOCH` for the main-chain tip's height
(`EPOCH` 144, as the consensus file uses). Init mode's seed choice
(`onion::rendezvous_indexes`) gets the same counter. The epoch depends on
height alone, never on which block is at it, so a reorganization never
moves points, and two nodes a block apart differ only within the grace
period.

144 blocks is about a day on mainnet, 2.4 minutes on `--network dev`
(a quick way to exercise the switch) and 24 minutes on `dev-recursive`.

### Switching, with grace

The same model as a change of consensus file (`docs/ONION.md`, change 2),
at the same boundaries `B` (multiples of `EPOCH`):

- **From `B` to `B + GRACE − 2`** (`GRACE` 6): participants hold sessions
  and publish their announce and delegation at both the old epoch's points
  and the new; relays serve ids that are theirs under either.
- **From `B + SWITCH`** (`SWITCH` 2): senders and resolvers ask the new
  points first and fall back to the old ones; before then, the other way
  round.
- **At `B + GRACE − 1`**: the old epoch's circuits and sessions close.

When the consensus file also changes at `B`, the two sets are (old file,
old epoch) and (new file, new epoch): still two sets, so `RelaySet` and
the existing switch code carry both changes at once.

### Costs and cautions

- Every participant now moves at every boundary, not only when the file
  changes: about one new circuit and session per participant per epoch,
  and a burst at `B`. Participants should spread their moves over the
  first blocks of the grace period (a random delay up to `SWITCH`
  blocks), so relays are not hit all at once.
- The counter is predictable, so a relay key can still be ground for a
  future epoch; it only buys one epoch in a few, not every one. Mixing in
  the hash of block `B − EPOCH` (`H(id ‖ epoch ‖ hash ‖ relay)`) would
  make that unpredictable a day ahead, at the cost of depending on which
  block is there (a reorganization deeper than the grace period would
  move points). Start with the counter alone.
- Delegations move with the announce, so the owner's node must be
  online at a boundary (or within the grace period) to republish them;
  the server's sessions move on their own.

## Implementation order

1. Epoch counter in rendezvous selection, and the epoch switch in
   `node/sessions.rs` beside the file switch; a test on `--network dev`
   crossing several boundaries with payments in flight.
   Done (2026-11-03, protocol 8): `onion::rendezvous_epoch`, the epoch
   in `rendezvous_relays` and `rendezvous_indexes`, and every boundary a
   switch in `node/sessions.rs` (`sets_of`): the set before stands
   through the grace period under the epoch before, the same file when
   it did not change. Tested by `a_switch_of_relays_keeps_messages_flowing`
   (now also across an epoch with the file unchanged) and
   `every_boundary_switches_epochs_with_a_grace_period`. Not yet: the
   random spread of moves over the grace period (with one session, a
   participant moves when the preferred set flips at `B + 2`), and the
   `--network dev` run across boundaries.
2. The delegation and the signed answer (`subnames.rs`), with tests for
   a forged, expired and other-name delegation, and a forged or expired
   answer. Done (2026-11-03): `Delegation` and `Answer` each carry the
   signer's key, so each verifies alone; both are valid at most
   `MAX_LIFETIME_SECS` (two days), which bounds how long a withdrawn
   server's answers count. Keeping the highest `seq` (stale ones) is
   the holder's job, in step 3.
3. Points hold and serve delegations and forward `GetEntry` over a
   session (`node/rendezvous.rs`); the server side in the node, with the
   wallet as its own server by default.
   Done (2026-11-03): `Publish`, `GetDelegation` and `Delegation` at the
   last hop, padded as a payment's messages are; `Store`, `Fetch`,
   `Held` and `None` between points (`node/rendezvous.rs`), delegations
   kept in the rendezvous LMDB beside announces; the participant
   publishes over its standing circuit and fetches over an outbound one
   (`node/participant.rs`); the query is a `KIND_SUBNAME` payload, so it
   needs no forwarding of its own, and the node answers it from the
   table the wallet gives (`Event::Subnames`), signed with its identity
   key (`node/sessions.rs`). Tested end to end by
   `sub_names_resolve_through_a_delegated_server`, the owner offline
   included.
4. Wallet commands, `send` resolution with caching, warm circuits and
   racing (`main.rs`, `wallet.rs`); a timing test on `--network dev`.
   Done (2026-11-03): the commands above (`main.rs`); `@LABEL.NAME`
   resolves through the delegation (cached ten minutes) and a query to
   every server at once, the first sound answer cached until it expires.
   Queries and answers are payloads of two kinds (`KIND_SUBNAME_QUERY`,
   `KIND_SUBNAME_ANSWER`), so an answer to a named sender (init mode)
   is not taken for a query. The delegation is the id's, not one name's
   (the name came out of it). Tried on `--network dev` in init mode: a
   payment to `@cool.example` from the owner's wallet and from another's,
   a missing label refused, a repeat sent from the cache. Not yet: a
   timed run in onion mode.
   Warm circuits (2026-11-03): a send's steps share one outbound circuit
   (`Outbound::group`): the delegation, the first server's query and the
   slate, the circuit kept up to 30 seconds between them and closed
   after. Its last relay sees one send, as before; the other servers'
   queries go over circuits of their own. Tested by the end-to-end test
   counting the circuits built.
5. README, and `docs/NAMES.md`'s sub-names section pointing here.
   Done (2026-11-03).

Self-published sub-names (section 1, "Later") come after, outside the
reference implementation.
