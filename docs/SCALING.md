# Scaling the message layer

A note, 2026-11-02, on what the message layer of onion mode costs as the
number of wallets online grows, what dominates it, and how to make an
idle wallet nearly free. Not implemented yet. The design is in
`docs/ONION.md`; `docs/PRIVACY.md` adds guards and outbound circuits,
which this builds on.

## Payments are not the load

Blocks bound payments: at 10,000 transactions per 2 MB block, about 16 a
second, whatever the number of wallets. A payment (lookup, slate,
answer, broadcast) is about 250 relay cell-hops, some 260 KB, so full
blocks put about 4.3 MB/s on the whole network. Shared over the relays
it is nothing: 35 kbit/s each among a thousand. More wallets do not mean
more payments, only more of them idle.

## Keepalives are

Each wallet online keeps a circuit to each of its three rendezvous points
and sends a `Session` keepalive up each every 30 s, answered back: a
1,024-byte cell each way across three hops. That is about 18 KB per
wallet every 30 s, 0.6 KB/s, and it grows with every wallet online:

| wallets online | keepalive traffic | per relay, among 1,000 |
|---|---|---|
| 100,000 | 60 MB/s | 0.5 Mbit/s |
| 1,000,000 | 600 MB/s | 5 Mbit/s |
| 100,000,000 | 60 GB/s | 480 Mbit/s |

Memory grows with it too: a rendezvous point keeps each session's
announce (6.5 KB) in memory, and the relay caps (10,000 sessions, 16,384
hops, 4,096 channels) put the ceiling near a million wallets online at a
thousand relays.

## What a keepalive is for

It does three jobs, and only one needs the participant:

1. **Keeping the participant's NAT mapping open.** A home router forgets a
   UDP mapping after some 30 to 120 s without traffic. Only the link from
   the participant to its first hop needs this.
2. **Noticing a dead hop.** The relays already notice: their channels to
   each other keep themselves alive, one channel serves thousands of
   circuits so the cost is shared, and a channel that fails destroys
   every circuit over it, the `Destroy` passed back toward each
   participant (`node/circuits.rs`). A participant need not probe.
3. **Telling the rendezvous point it is still there.** A session is bound
   to its circuit and dropped when the circuit is destroyed
   (`node/rendezvous.rs`), so it lives exactly as long as the circuit.

## Changes

**1. Keepalives on the guard channel only.** The 3-hop `Session`
keepalive goes; a participant keeps its channel to its guard alive with
a small frame every 25 s (some 60 bytes and an acknowledgement), enough
for the NAT, and learns of a dead hop from the `Destroy` that reaches it.
A `Session` end to end every 10 to 20 minutes catches a path broken
without one. All of a participant's circuits share the guard channel
(`docs/PRIVACY.md`, guards), so it is one keepalive a participant, not
one a circuit. From about 600 B/s a wallet to about 5: some hundred
times less. It also ends the 30 s rhythm a hostile first hop and point
could match (`docs/PRIVACY.md`).

**2. One standing session, not three.** A participant keeps a session at
one of its three points, the first that is alive, rather than all three;
senders already try the points in turn, and a lookup at one without the
session costs a hop or two more. Three times fewer circuits, sessions and
announces held, at the cost of a moment unreachable while that circuit is
rebuilt. A dead hop is noticed when the relays' channel to it fails:
within about 45 s on the side that sends the channel's keepalives (a
frame unanswered for 15 s), within two minutes on the side that only
listens (two minutes of silence), then rebuilt at once. Shortening the
relays' own channel timeouts would bring that down, at a cost shared by
every circuit over the channel.

**3. Announces on disk.** A point needs a session's announce only to
answer lookups; it can keep it in its database rather than in memory,
with the circuit link and the sequence number in memory. The caps on
sessions, hops and channels become settings, sized to the relay's
memory, rather than constants.

**4. Channels between relays on demand.** At a thousand relays each may
hold a channel to every other; at a hundred thousand that is too many.
Relays open a channel to another when a circuit or a rendezvous message
needs it, as now, and close one idle for some minutes, as a participant's
unused channels are closed.

**5. Reachable only when expecting to be paid.** A wallet that is only
spending needs no session between payments, and one that receives can be
reachable while it expects a payment. Many users will sit behind
always-on gateways (merchants, exchanges, wallet services) that receive
for them. Hundreds of millions of wallets need not mean hundreds of
millions of sessions.

## Sizing

With changes 1 to 3, the load is in proportion to the wallets online per
relay, `W / R`. Each online wallet costs:

| | where | per wallet |
|---|---|---|
| guard keepalive | its guard | ~0.08 packets/s, ~5 B/s |
| session | its point | 1 announce (6.5 KB, on disk) |
| hop state | three relays | 3 hops |
| circuit handshakes | three relays | ~1 an hour (replacement every 2 to 4 hours, three hops) |
| payments | outbound circuits | ~6 handshakes a payment |

So each relay carries, for `W / R` wallets each:

| `W / R` | packets/s as guard | sessions (announces on disk) | hops |
|---|---|---|---|
| 1,000 | 80 | 1,000 (6.5 MB) | 3,000 |
| 10,000 | 800 | 10,000 (65 MB) | 30,000 |
| 100,000 | 8,000 | 100,000 (650 MB) | 300,000 |

A relay on a modest server is comfortable at ten thousand wallets online,
and a good one at a hundred thousand. The rule is then to keep the
number of relays roughly in line with the wallets online: a hundred
million online wants a few thousand relays at least, ten thousand to be
comfortable. The relay list in `consensus.txt` (at most `MAX_RELAYS`,
8,192, today) grows with them; raising that bound is a change to one
constant, the file's size limit (1 MiB, about 10,000 lines) with it.

## Implementation order

1. Guards (`docs/PRIVACY.md`, fix 3) and the guard channel's keepalive;
   the 3-hop `Session` keepalive down to every 10 to 20 minutes.
2. One standing session per participant.
3. Announces in the relay's database; the caps as settings.
4. Idle channels between relays closed.
5. Tests: a participant whose hop dies learns of it by `Destroy` and
   rebuilds without a keepalive; a node test counting the packets a
   participant sends while idle.
6. Docs: `docs/ONION.md` (keepalives, one session), the constants.
