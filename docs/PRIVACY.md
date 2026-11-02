# Privacy of the message layer

A note, 2026-11-02, on what the relays of onion mode, and a payment's
recipient, learn about who pays whom: two leaks found in what was built,
their fixes, and what else would make a payer harder to follow. All six
fixes are done (2026-11-02, below).
The design is in `docs/ONION.md`; its cryptography and remaining gaps are
in `miner/SECURITY.md` and `docs/HARDENING.md`.

The message layer's main purpose is to carry slates and transactions
without loading the seeds; privacy is a second aim. Even so, the two
leaks below hand out identities for nothing, with no timing analysis or
luck needed, and both are cheap to fix before launch.

## Leak 1: sends go over the session circuit

A participant keeps a circuit to each of its three rendezvous points, and
the point at the end of each holds its session there, so it knows the
participant's id. Its sends use those same circuits:
`node/participant.rs`, `progress_onion_sends` and `progress_broadcasts`,
pick a live standing circuit. So the point receives, on the circuit it
knows is the participant's:

- the `GetAnnounce` lookup, which names the recipient's id;
- the payload, whose `to` is the recipient's id;
- the finished transaction (`Broadcast`), which it then announces.

Each of a participant's points can thus record whom it pays, when, how
much traffic each payment took, and which transaction is its. No luck is
needed: the points are fixed by the id. An attacker running a fraction
`f` of the relays holds at least one of a given participant's points with
probability `1 − (1 − f)³` (14% at 5%), and sees about a third of its
sends.

## Leak 2: a payload names its sender in the clear

`onion.rs`, `Payload`: the wire form is `to`, `from`, the Kyber
ciphertext, the nonce, the sealed body and the sender's Dilithium
signature. `from` (the sender's id) and the signature are outside the
encryption. Every relay that handles the payload reads both ids: the
sender's rendezvous point, the recipient's, and in init mode the seed.
The signature betrays the sender by itself too: announces are public
(anyone can look one up), so a relay can try the signature against known
Dilithium keys until one verifies.

So even with leak 1 fixed, the recipient's rendezvous point would read
who pays its participant off the wire.

## What makes it worse: grinding

A relay's id is the hash of its Dilithium key, and a participant's points
are the three relays that weigh most for its id. An attacker who wants to
be a given participant's point makes keys until one weighs in its top
three: about a third of the number of relays tries, a few hundred among
a thousand. The guard against it is the list itself: the relays in
`consensus.txt` are vetted by whoever maintains it.

## Fix 1: the sender inside the encryption

Done (2026-11-02): `onion.rs`, `Payload`.

The payload's wire form keeps only what routing needs in the clear:

```
to       the recipient's id (32)
ct       the Kyber ciphertext
nonce
body     sealed: kind ‖ named? ‖ [the sender's announce] ‖ [signature] ‖ inner
```

The associated data is `to ‖ ct ‖ nonce`. A named sender's signature is
over `to ‖ ct ‖ nonce ‖ kind ‖ announce ‖ inner` under the payload's
context, and travels inside the sealed body with the announce (which
carries the sender's id and Dilithium key), so only the recipient sees
either. Nothing is lost: the recipient already took the sender's id from
the announce inside. A relay then sees whom a payload is for, never whom
it is from.

## Fix 2: an outbound circuit

Done (2026-11-02): `node/participant.rs`, `Out`. One circuit is kept
ready beyond those sends are waiting for, at most eight at once, and a
ready one unused for ten minutes is replaced. With too few relays listed
for a last hop that is none of the participant's points (three relays,
as on a test network, are everyone's points), one of them ends the
circuit, and the node says so once in its log: the circuit is still the
payment's own, but its end knows the sender's id.

A participant sends over circuits that carry no session of its own: two
random hops and a random last relay that is none of its rendezvous
points. Lookups and payloads go up such a circuit; the last relay asks
the recipient's points (the rendezvous service answers `GetAnnounce`,
`Send` and `Broadcast` at the end of any circuit already, so nothing
changes on the relays' side). An outbound circuit is used for one
payment's lookup and payload and then retired, the next one built in the
background meanwhile (the one in use and one ready, as the first design
had it), so no two payments share a path; the finished transaction goes
up yet another, so the relay that announces it is not the one that saw
the payload, and cannot tie the transaction to its recipient.

Answers still come back to the participant through its rendezvous
points, over its standing circuits; with fix 1 they show the point only
that something came for its participant, from some relay.

The cost: two circuits per payment, its own and its broadcast's, three
hop handshakes each, spread over every relay: at 16 payments a second
and a thousand relays, about a tenth of a handshake a second per relay.

## Fix 3: guards and jittered keepalives

Done (2026-11-02): `node/participant.rs`. Three guards, each kept 30 to
60 days, in the file `guards` beside the peers file in the data
directory; a guard that leaves the list or whose time is up is replaced,
one whose channel failed is passed over for five minutes like any relay,
and a circuit whose last hop is the only guard left starts at any relay.
Keepalives, in onion and init mode, come every 20 to 40 s at random.

These are timing, not leaks of the same kind, but go with them.

- **Guards.** A participant's first hops are random and change with every
  circuit, so over time a hostile relay is sure to be one and see its
  network address; together with a hostile rendezvous point it can match
  the session's keepalives and tie the address to the id. A participant
  keeps its first hops, for standing and outbound circuits alike, within
  a small set (three relays) it holds for a month or two, replacing one
  that leaves the list or fails. No flag is involved: it is the client's
  own policy.
- **Jitter.** A keepalive every 30 s exactly is a rhythm easy to match.
  Its interval is drawn at random between 20 and 40 s.

## Fix 4: answers back along the payment's own path

Done (2026-11-02): `Route` and `Reply` (`circuit.rs`,
`node/rendezvous.rs`), `onion::Route` in the payload,
`node/participant.rs`. The sender holds its outbound circuit open a
minute for the answer. In init mode, which has no circuits, payloads
still name their sender and answers go to its id. A slate names the
sender only with `send … named`; otherwise the wallet keeps a secret and
the slate carries its hash, which the receipt binds (`docs/PROOFS.md`).
The recipient does not check what a slate names: a sender that names
another's address only credits that address with its own payment.
Unnamed slates are counted against the 60 a wallet answers in ten
minutes in all, not per sender, since nothing tells two unnamed senders
apart.

The recipient answers a slate today by sending it to the sender's id:
its rendezvous points route the answer, and the sender's announce
(its id, its Dilithium key, a Kyber key) is inside the payload so the
recipient can reach it and check its signature. That is the only reason
the recipient learns the sender's address, and it should not: a
recipient learns a payer's address only if the payer tells it, outside
the system or by choice.

Instead the answer goes back along the path the payment came by:

1. The sender's payload goes up an outbound circuit (fix 2). Before it,
   the sender sends the circuit's last relay `x` a `Route(token)` relay
   message with a random 16-byte token; `x` remembers, for a couple of
   minutes, that the token means this circuit.
2. Inside the sealed payload, instead of the sender's announce, go the
   return route (`x`'s relay id and the token) and a Kyber key made for
   this payment alone. No id of the sender's, and no signature: the
   payload is anonymous. Only the recipient reads the route.
3. The recipient seals its answer to that Kyber key and sends it up its
   own outbound circuit as a `Reply(x, token, payload)`; the circuit's
   end passes it to `x` relay to relay, and `x` delivers it down the
   sender's outbound circuit, which the sender keeps open the few
   seconds the exchange takes.

No id of the sender's then appears anywhere on the payment's path, its
rendezvous points no longer see answers come for it, and the recipient
cannot write to the sender later: the route is good for one answer. An
anonymous payload carries no sender's announce or signature at all, so
fix 1 then matters only for a sender that names itself: its address goes
inside the encryption.
If the outbound circuit breaks before the answer, the payment fails and
is tried again on another.

The slate itself still carries what it must (the inputs' public keys,
for the recipient to check the amounts); nothing in it names the
sender's address. A sender that wants to be known says so, by naming its
address in the slate.

This changes `docs/PROOFS.md`: the receipt binds the sender's address
only when the sender named one. Otherwise it binds the hash of a secret
the sender put in the slate, and the sender proves the payment its own
by showing the secret.

## Fix 5: a next address

Done (2026-11-02): `Wallet::next_address` and `turn_address_off`, the
node's `Event::Identity`, `address next` and `address off` at the prompt.
On a new address every standing circuit is replaced, even one to a point
the new address shares with the old, so that no point sees a circuit
move from one id to the other; the old circuits close once the new
sessions are live, or after 30 s. While the address is off a node in
onion mode still sends and broadcasts, naming no one; in init mode it
cannot send, since init mode names the sender. A pending slate keeps the
sender it named, so a payment under way finishes across the change.

A wallet's address is the hash of a Dilithium key derived from its
phrase, the same for good, so whoever is paid at it, or pays it, can
link every payment to it. A wallet gets a new one at will:

```
identity key i  =  ML-DSA key from H(DOM_IDENTITY ‖ master ‖ i)
```

with `i` a counter the wallet keeps. `address next` (a button in a
wallet with a screen) adds one to it, opens circuits and sessions at the
new address's rendezvous points, and once they are live closes those of
the old address, so the wallet is never unreachable; the old address
answers nothing from then on, so payments to it fail as offline.
Payments in flight are unaffected, since their answers come back along
their own paths (fix 4). A name that points at the old address needs a
`name-update` to follow.

Done in one step, the old sessions ending as the new ones begin, the
change could be matched in time by an adversary holding the participant's
guard and a rendezvous point of each address (about `f³`): a state
actor's attack, not a pizza parlour's. For a user who minds, it can be
done in two: `address off` closes the current address's circuits and
sessions and makes no new one (the wallet is unreachable, though it can
still pay), and `address next` later, whenever the user likes, brings it
back under a new address, with nothing to match the one to the other. The
seamless way is the default.

A restore cannot know the counter, and need not: old addresses are
abandoned, never reused, so a restored wallet starts from a fresh one
(the counter drawn at random), and any name is pointed at it again.
The relay's key (`Wallet::relay_key`) is apart from all of this.

## Fix 6: one size for every message of a payment

Done (2026-11-02): `circuit::PAYMENT_CELLS` and `circuit::is_payment`,
for relay messages; messages between rendezvous points are padded the
same.

Messages are padded to a power of two of cells (`circuit.rs`), which
hides a message's exact length but not its kind: a notice is one cell, a
lookup's answer (an announce) eight, a slate and its answer sixteen. Any
relay on the path can tell from counts alone that a circuit made a
lookup and then a payment, and what came back.

Every message of a payment (`Route`, `GetAnnounce` and the announce it
returns, `Send`, `Deliver`, `Reply`, `Notice`, `Broadcast`) is padded to
the same size, `PAYMENT_CELLS` (16, about 14 KB), or to the next power of
two above it for the rare larger one (a slate with many inputs, a large
transaction). The cost: a payment's cells grow from about 250 relay
cell-hops to about 400, some 7 MB/s on the whole network at full blocks.
Keepalives (`docs/SCALING.md`) are not payment messages and stay small.

## What remains

With the three fixes a relay that handles a payment learns only the
recipient's id (and, at the recipient's point, when it is paid); a
participant's own points never see what it sends; the first hop sees its
network address but never its id. What remains is traffic analysis:
without cover traffic, an observer of both ends of a path, or relays that
collude along it, can match a payment's cells by timing, and even at full
blocks a relay among a thousand carries a payment only every few
seconds, too few to hide in. That is the limit of any low-latency design
without cover traffic or mixing (open point 3 of `docs/ONION.md`).

With fix 4 the recipient learns nothing of the sender's unless the
sender names itself, and neither learns the other's network address. In init mode the seeds
see network addresses and, until fix 1, both ids.

## What to expect, with the fixes

The aim is stated plainly: the message layer distributes the load of
slates and transactions over many relays, with reasonable privacy, not
anonymity against every adversary. With the three fixes, at full blocks
(about 16 payments a second) and a thousand relays or more, for a payment
from S to R:

| party | learns | never learns |
|---|---|---|
| R | nothing of S's, unless S names itself (fix 4) | S's address and network address |
| S | R's address | R's network address |
| S's guard | S's network address, when S sends or receives, and how much | any id |
| a middle hop | nothing of use | |
| the end of S's outbound circuit | R's id, when, how much | who sent it |
| R's rendezvous point | R's id; when and how often R is paid | who paid |
| the relay announcing the transaction | the transaction | any id |

No single relay sees two of the sender, the recipient and a network
address.

Relays that collude, a fraction `f` of them, never learn a payer's id:
with fix 4 it is nowhere on the path. What they can link, by timing, is
a payer's network address (seen by its guard) to the recipient's id
(seen at the end of the outbound circuit, or at the recipient's
rendezvous point): for a payment at random, about `f²` to `2f²` (0.25
to 0.5% at 5%). A participant draws once, for months, since its guards
are its own choice: with probability about `f` its guard is hostile,
and then about a fraction `f` of its payments are linked to their
recipients; with about `f²` (guard and its own rendezvous point both) the
attacker ties its network address to the address it receives at, until
`address next` (fix 5). How diverse the relays in `consensus.txt` are
decides `f`.

An observer of most of the network's links (a large provider, a state)
follows most payments from sender to recipient by matching bursts, as
with Tor, a little more easily: a relay among a thousand carries a
payment only every few seconds, so few flows overlap, and payments have
one shape. More traffic does not help much, spread over more relays;
cover traffic or mixing would, at a cost in bandwidth or latency
(`docs/ONION.md`, open point 3).

So: far better than sending directly (init mode, or a provider seeing
everything), about Tor's level against a few hostile relays, weaker than
a mixnet against a global observer. That is the intended trade.

## Implementation order

1. Fix 1: the payload's wire form, `seal` and `open`, the signature
   inside; its tests, with one that the serialized payload holds no byte
   string of the sender's id or key.
2. Fix 2: outbound circuits in `node/participant.rs`, one in use and one
   ready, retired after a payment; broadcasts on a circuit of their own.
3. Fix 4: `Route` and `Reply`, the return route and a one-time Kyber key
   in the payload in place of the sender's announce, the answer down the
   outbound circuit; the receipt in `docs/PROOFS.md` adjusted.
4. Fix 5: identity keys by counter, `address next` (new sessions before
   the old close), `address off`, a fresh counter on restore.
5. Fix 6: payment messages padded to `PAYMENT_CELLS`.
6. Fix 3: guards and jittered keepalives.
7. Tests: a node test where the relays record what reaches the end of
   each circuit, checking that a participant's rendezvous points receive
   no lookup, payload, answer or transaction from it or for its
   payments, and that neither a relay nor the recipient learns a
   payment's sender; every message of a payment is the same number of
   cells; `address next` leaves the old address offline with no gap, and
   `address off` leaves the wallet unreachable until the next.
8. Docs: `docs/ONION.md` (the path, the standing and outbound circuits),
   `miner/SECURITY.md` (what each party learns), `docs/HARDENING.md`.
