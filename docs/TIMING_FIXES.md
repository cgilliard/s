# Timing fixes

How tabminer and the fam node and wallet decide that something is slow,
lost or dead, and how to depend less on fixed timeouts: tell instead of
wait, measure instead of guess, and notify instead of poll. From an
audit of every timer in both (2026-11-13: tabminer at `029ecb0`), with
what it found broken. Brought here from other lists, which now point
here: `docs/NODE_ENHANCEMENTS.md` item 20 (waiting instead of polling)
and the timing parts of items 4 and 22, and two entries of
`docs/HARDENING.md` (a channel closed while handshaking; a dead relay
taking 30 s however fast the link).

The intermittent failures of the last weeks were all here: the onion
tests' sessions not up in time (a channel closed silently, then 20 to
30 s waited out), a payment never reaching a restarted node (its host's
entries held by its own old ports), the tabminer CI flake on standing
circuits (a test's 10 s against a 30 s liveness timer).

## 1. The approach

Silence cannot be told from slowness on a network that loses datagrams,
so some timer always remains; the aim is that it decides only that case
(a crash, a cable pulled), quickly where the link is fast and patiently
where it is slow, and that nothing else waits on a clock. In order of
payoff:

1. **Tell, don't let the other side wait.** Most stalls are one side
   having lost state the other still holds (a channel closed, a circuit
   gone, a node restarted, a body not kept) while the other waits out a
   timer. The side that knows says so, and the other acts in one round
   trip: an unknown-channel notice, a DESTROY for an unknown circuit, a
   refusal with its reason, "not held", a goodbye on shutdown (section
   3).
2. **Liveness from the measured round trip.** Retransmission already
   follows RFC 6298 (`srtt`, `rttvar`) in tabminer's channels and the
   wallet's links. "Dead" should too: a number of unanswered probes,
   each a few resend timeouts, bounded (say 5 to 30 s), so a LAN notices
   in seconds and a satellite keeps its allowance.
3. **Any sign of life restarts the clock.** A timer that decides "unused"
   or "idle" counts from the last thing heard, not from when the thing
   was made.
4. **Redundancy over fast detection.** Three rendezvous sessions
   (2026-11-13), several peers for a batch, a spare circuit ready: when
   one fails another already carries on, and the timer's value matters
   less.
5. **Notify, don't poll.** What a wallet waits on (a block, a
   transaction's fate, the node's state) comes as an event when it
   happens (section 2), and a loop sleeps until its next deadline or an
   event, not a fixed second.
6. **Tests wait on conditions and inject faults.** No fixed sleeps that
   race; a generous guard only against a hang; the fault under test made
   to happen (an auth held back, a reply dropped, a node stopped), not
   10% random loss whose victims depend on thread timing (section 7).

Policy timers (a ban's hour, a key's rotation, a rate limit) stay fixed
constants: they decide nothing about liveness.

## 2. Notify instead of poll

### Waiting instead of polling: blocks, transactions, payments

*(Was `docs/NODE_ENHANCEMENTS.md` item 20.)*

The wallet's tabs and panels refresh at different times, because
everything is polled: the wallet asks the node's `/v1/status` every 4 s
(`wallet.fam`'s `wtick`), scans when the tip has moved and sends the
page a `tip` event, but the page only shows the new height from it
(`wm.html`: the status line); each panel's contents are fetched when it
is opened or asked for, so the balance, Activity, names and proofs can
each be as of a different block, and a block takes up to 4 s to be
noticed at all.

The one thing a wallet needs to wait on is a new block: everything it
shows changes only with one (or with its own requests, which answer for
themselves).

- **The node: waiting for a block.** It has one already: `GET
  /v1/tip?after=<id>` answers when the tip moves from `id`, or after
  30 s with the tip unchanged (`api.fam`'s `atip`, `awake`; 8 waiting at
  most). It stays, and becomes a case of the events below.
- **The wallet: a thread that waits for blocks.** A thread (with
  variables of its own: `pthread`, `docs/OS.md`) whose loop is
  `/v1/tip?after=<last>`: on a new tip it hands the block to the
  wallet's main loop (shared memory and `wake`, the main loop's poll
  woken by a pipe), which scans it and then refreshes everything at
  once. The 4 s poll goes; the main loop stays free for the page's
  requests and the message layer while the thread waits.
- **The page: one update per block.** On each block the wallet sends
  one event carrying, or followed by, everything the panels show
  (balance, Activity, names, provable payments, the overview), all as
  of that block, and every panel redraws from it, whichever tab is
  open. A panel opened later shows the latest it was sent, so no tab
  shows a different block from another. The `tip` event and per-panel
  fetches merge into this (with item 9's status model: "synced to
  height N").
- **Between blocks:** a payment sent or received off-chain (an online
  slate, a message) is the wallet's own event and updates its panels at
  once, as now; only chain state waits for the block.

#### Everything else that is polled, or never noticed

Besides blocks, what a wallet waits on today it learns only by asking
again, or not at all:

| What | Today | With a hook |
|---|---|---|
| A sent transaction's fate in the node: pooled, **dropped** (evicted for a better fee, expired after 14 days, conflicted by another spend), **replaced** (a bump or cancel), **mined** at a height, back in the pool after a reorganization | `POST /v1/tx`'s answer, then nothing until a block's scan shows it mined; a dropped transaction is never noticed, and the payment looks pending for good | told at once: "dropped from the pool: fee below the minimum; bump it?" |
| Confirmations | counted at each scan | from the block events |
| The node's state: syncing, synced, no peers, the store full | `/v1/status` when asked | told when it changes (item 9's status model) |
| Fee estimates | `/v1/fees` when the Send tab asks | sent with each block, and when the pool's minimum moves |
| The message layer's mode and relays (`/v1/consensus`, every 10 s: `wmcons`) | polled | changes only at a block: from the block events |

**One mechanism in the node: an event stream.** Rather than an
endpoint to wait on per thing, the node numbers what happens and keeps
the recent events in a ring (a few thousand):

- **`GET /v1/events?after=<n>`:** the events numbered after `n`, at
  once if there are any, else waiting until one comes (or 30 s, an
  empty answer); a wallet keeps one such request open and loses
  nothing between them. `after` older than the ring holds answers
  "reset": the wallet asks for the state afresh (`/v1/status`, a scan)
  and goes on from the newest.
- **The events:** `block` (connected: height, id) and `undone` (a
  reorganization), `tx` (an id and its new state: pooled, dropped and
  why, replaced by which, mined at which height, back in the pool),
  `status` (syncing, synced, peers, a problem), `fees` (the pool's
  minimum moved).
- **Filtering:** `?tx=<id>,<id>` for the events of those transactions
  only (with blocks and status always), so a wallet is not woken for
  every transaction the node sees.
- **No more waiting connections than needed:** one per wallet (and the
  page has none: it hears from its wallet), each held by the node at
  the cost of a socket, so the 8 waiting requests become a limit sized
  to the wallets a machine runs, refused with a clear answer past it.

#### The wallet's events to the page

The wallet already pushes to the page over its WebSocket, but as text
(`'event':'message'`, a line in Activity): the page cannot tell a
payment's progress from any other line. Instead structured events, each
naming the payment (its Activity entry's id) and its new state, so the
page can show a notification and update that entry in place:

- **An online payment:** sent, reached the recipient's point, answered
  (the slate back), finalized, in the node's pool, mined, confirmed (n),
  or failed and why (the recipient offline, no answer in time, refused,
  dropped from the pool).
- **A payment received:** offered (an online slate in), answered, seen
  mined, confirmed.
- **Names:** committed, the reveal's window open, revealed, registered;
  a renewal due.
- **The wallet's own state:** scanning (to a height), synced, the node
  unreachable.

The message layer is already event driven in the wallet (`poll` on its
socket); the node's events come by the block thread's request (now
`/v1/events` rather than `/v1/tip`). With item 5's spinners and item
9's status model, these are what the UI shows: a payment's line moving
from "sent" to "confirmed" by itself, and a notification when it does.

**Tests:** in oscheck's wallet tests (no timing), a block mined: one
update event from the wallet with every panel's values at the new
height, no further request needed; two blocks in quick succession:
both seen, in order; a reorganization: the update at the new tip, the
lost payment gone from Activity. In the node's API test: `/v1/events`
answering a block, a transaction pooled, then evicted by a better-paying
one (its `dropped` event, with why), and replaced by a bump; a request
waiting while nothing happens answered when something does; `after`
past the ring answered "reset". In the wallet: an online payment's
events in order from sent to confirmed, and a dropped one's.

### The wallet's view of the node (from item 22)

The wallet learns about the node only by asking `/v1/status` every 4 s
(`wallet.fam`'s `wtick`), with no timeout on the request (`hask`, below):
a node that is busy, restarting or absent shows as a frozen window or
as "synced" (item 22's report). With the event stream, the node's state
(`status` events: starting, syncing at height h of H, synced, no peers)
comes when it changes; and the wallet's connection to the node is its
own state with a timeout per request and retries with backoff (5 s, then
up to 30 s), shown as "cannot connect to the node" with the time of the
next try (item 22 keeps the display).

### The node's short fixed waits (from item 4)

`phdrs` (rounds of 0.5 s of quiet, four of them) and `pping` (80 turns
of 0.1 s) wait in iterations rather than time, and every datagram from
another peer ends an iteration (section 5, the node's first cause), so
under traffic a healthy peer is taken for silent. Both become waits to a
deadline (headers: tabminer's 15 s `HEADER_TIMEOUT`, or a few round
trips), through others' datagrams; and `pping` before a sync uses the
status `pkeep` already holds when it is fresh rather than asking again.

## 3. Explicit signals to add

Each replaces a wait with a message from the side that knows. Old nodes
ignore what they do not understand, so each can be rolled out alone.

| Signal | Sent by, when | Replaces | Where |
|---|---|---|---|
| **Unknown channel** | a relay, for a frame on a channel it does not have, from an address it has handshaken | the sender's 30 s `DEAD_AFTER` (20 s `TIMEOUT` in tests), then 300 s of `AVOID` for a healthy relay | tabminer `node/channels.rs:492` (dropped silently now); the wallet's `owfrin` |
| **Goodbye on shutdown** | every node on `Event::Stop`: DESTROY its circuits, CLOSE its channels (a new frame kind), a "going away" to its peers | 30 to 60 s (channels), 120 s (a relay's `TIMEOUT` for a participant), 180 s (`PEER_TIMEOUT`): today a restart or an upgrade looks like a crash | tabminer `node.rs:1172`; the fam node and wallet on exit |
| **Idle close notice** | the side closing an idle channel (`IDLE_TIMEOUT` 300 s) | the other side's next send waiting 30 s, then avoiding the relay | `node/channels.rs:272` |
| **DESTROY for an unknown circuit** | a relay, for a relay cell on a hop it does not have, and for a CREATE it drops (not a relay, a duplicate, no relay key) | the session keepalive (15 min + 30 s) or `SEND_TIMEOUT` 120 s; `BUILD_TIMEOUT` 60 s | `node/circuits.rs:419`, `:372`, `:391` |
| **"Next hop unreachable" in a DESTROY** | a relay whose EXTEND failed | the participant picking the same dead relay again on its rebuild | `node/circuits.rs` |
| **Handshake refused, with why** | a relay refusing a hello (channels full, per host, rate) | 8 s of hellos, then 300 s of `AVOID` for a relay that only said "busy" | `node/channels.rs:389-406` |
| **Rendezvous REFUSED** | an asked relay that does not list the asker, or is not a relay | `ASK_TIMEOUT` 40 s per point | `node/rendezvous.rs:924` |
| **OFFLINE at once when a recipient's circuit goes** | a rendezvous point whose circuit to the recipient is destroyed while a delivery waits | `ACK_WAIT` 30 s per point (`rendezvous_link_gone` clears asks and routes, not `delivering`) | `node/rendezvous.rs:455` |
| **Not held** | a peer asked for chunks (a body, a transaction, a part, a file) or aux leaves it does not have | 8 retries, then 600 s passed over (`FETCH_BACKOFF`); `AUX_MAX_TRIES` 16; `FILE_BACKOFF` | tabminer `node.rs:2568`, `:2216`; the fam node's `pgive`, `paux` |
| **A peer's first answer** | (exists: the Pong) | the fam node's fixed 30 s `nidle`, the wallet's hello and send steps checked each tick | `main.fam:256`, `wopart.fam:624`, `wnet.fam:394` |

## 4. The timers, side by side

Where tabminer and the fam node or wallet do the same thing, their
values. Classes: R retransmission, L liveness, C cleanup, W waiting for
an answer, P policy. "Adaptive" follows a measured round trip; the rest
are constants.

| What | tabminer | fam node / wallet | Class | Change |
|---|---|---|---|---|
| A frame resent | RFC 6298, 0.4-5 s (`channel.rs:62`) | the same (`wopart.fam:121`) | R, adaptive | keep; the wallet's 1 s poll quantises it (section 5) |
| A channel dead | 30 s from a frame's first send (`DEAD_AFTER`, `channel.rs:72`), checked only when a resend falls due | 12 tries or 30 s (`wopart.fam:632`) | L | ~10 resend timeouts, 5-30 s, checked every poll |
| Keepalive on a quiet channel | 25 s (5 s in tests) | 25 s | L, NAT | keep |
| Nothing heard | 120 s (20 s in tests: tests decide on another timer than production) | 120 s | L | keep as a backstop; same value in tests |
| Hello retries | 1 s × 8 | 1 s × 8, the ping wait counted in them (8 s in all, against tabminer's 30 s ping wait + 8 hellos) | R/W | the wallet: count hellos only once sent; hello on the Pong |
| Unused channel (relay) | 15 s from the first hello (3 s in tests) | — | C | from the last activity; the auth, a hello again and a frame refused before the auth count |
| Idle channel | 300 s | the wallet keeps a link with no circuit and reuses it after the relay closed it | C | notice on close; the wallet closes its own at ~240 s |
| Circuit build | 60 s | 60 s, but marks it dead without DESTROY and rebuilds at once | W | DESTROY; the wallet through `owsfail` |
| Standing circuit dead | 30 s after an unanswered SESSION (`participant.rs:91`) | 30 s | L | the circuit's own round trip, 5-30 s; a re-ask at a third; any cell counts |
| Rebuild after a failure | 3 s, no backoff | 3 s | R | backoff per point, 3 s to 60 s |
| SESSION keepalive (onion) | 15 min ± ⅓ | 15 min | L | keep (privacy); rely on DESTROY and notices |
| Old circuit retired | on live, **or** after 30 s even if the new one is not live | — | C | on live, or the new one failing; ceiling 5 min |
| Send overall | 120 s (`SEND_TIMEOUT`) | 120 s, the circuit build and the offline window out of the same budget | W | a wait per step, a retry on a fresh circuit, a budget that covers 3 points |
| Offline: ask again | every 3 s for 60 s | the same | R/W | keep as a backstop |
| Rendezvous: next point | 40 s (`ASK_TIMEOUT`; 12 s in tests) | init mode: **8 s** per point (`wnet.fam:395`) | W | the wallet 40 s, resend within the step; tabminer: from the channel's round trip, floor above `ACK_WAIT` |
| Delivery acknowledged | 30 s (`ACK_WAIT`; 5 s in tests) | — | W | OFFLINE at once on link gone |
| Init-mode session lost | 90 s since the last answer | 90 s; one point lost makes a new key for all | L | after K unanswered asks |
| Init-mode send, next point | 40 s (`POINT_TIMEOUT`) | 8 s | W | match at 40 s |
| Peer ping | 30 s; 2, 4, 8, 16 s before the first pong | the same | L/R | keep |
| Peer dead | 180 s silent (`PEER_TIMEOUT`), live meanwhile | 180 s "lost", kept, still announced to and advertised | L | not live after 2 missed pongs; the node excludes lost peers from `pann` and `ppeers` |
| A host's silent entry gives way | 60 s (`HOST_STALE`, 2026-11-13) | 60 s (2026-11-13) | P/C | keep |
| Chunks asked again | RFC 6298, 0.1-**1 s** | 3 × one SRTT for all peers, 0.3-4 s; a sample taken after a resend (Karn broken) | R | tabminer: ceiling 5 s and backoff (satellite); the node: per peer, Karn |
| A download given up | 8 retries without progress (0.8 s on a LAN), then passed over 600 s | max(30 s, 20 × SRTT) with no chunk, per peer: a block can cost 16 × 30 s | W | both: a few seconds without progress and a minimum rate; "not held" ends it at once |
| Passed over | 600 s (`FETCH_BACKOFF`) | 60 s, in the same field as a ban | P | the node: its own field, 600 s |
| Headers asked | 4 s a batch, retried once (`BATCH_TIMEOUT`); 15 s for a claim | 4 rounds of 0.5 s quiet, cut by others' datagrams | W | a deadline; tabminer: from the round trip, at most 4 s |
| Transactions announced again | to a new peer, 256 at most (2026-11-13) | to every peer each minute; on a new peer, the whole pool to everyone | P | the node: to the new peer only |
| The wallet's poll of the node | — | `/v1/status` every 4 s, `/v1/consensus` every 10 s, no timeout on the request | W | events (section 2); a deadline per request |
| A slate never answered | `ANSWER_WAIT` 180 s, then released | onion: 180 s, silent, coins stay reserved; init: none | W | an event, and an offer to cancel |

## 5. What the audit found broken

Bugs, not just constants to tune; each with where.

**tabminer**
- `UNUSED_TIMEOUT` counts from the first hello and is not restarted by
  the auth, a repeated hello or a frame refused before the auth; the
  relay closes silently; the initiator waits 30 s, then avoids a healthy
  relay for 300 s and may mark its guard down (`node/channels.rs:283`,
  `:311-316`; `participant.rs:991`). The lossy onion tests' flake.
- `DEAD_AFTER` is checked only when a frame's resend falls due, so it
  fires up to 5 s late; an idle channel notices a dead peer after
  25 + 30 + 5 s (`channel.rs:562`).
- A standing circuit whose session is live is not asked again inside
  its 30 s: one lost reply kills it; cells delivered on it do not count
  (`participant.rs:756`, `:773`).
- `RETIRE_WAIT` closes the old circuit after 30 s whether or not the
  session is live on the new one: a window with no session
  (`participant.rs:723`, `:740`).
- `rendezvous_link_gone` does not clear `delivering`: a delivery to a
  recipient whose circuit is already gone costs `ACK_WAIT`
  (`rendezvous.rs:455`).
- A delegation updated twice within `DELEGATION_EVERY` (10 s) loses the
  second (refused, not queued as certificates are) (`rendezvous.rs:674`).
- No send step has its own wait: a send on an outbound circuit that
  stalled waits the whole 120 s; and the budget is smaller than three
  points' `ASK_TIMEOUT` for lookup and again for delivery
  (`participant.rs:1560`).
- The chunk retry ceiling (1 s) is below a satellite's loaded round
  trip, and eight retries make 0.8 s on a LAN enough to pass a peer over
  for ten minutes (`net.rs:884`, `:886`).
- `HOST_STALE` and the ban checks read `Instant::now()` rather than the
  `now` passed in, so tests with synthetic time cannot drive them
  (`net.rs:1395`, `:1696`, `:1383`, `:1682`).

**The fam node**
- **Others' datagrams count as timeouts.** `pwait` returns 0 for a
  datagram from any peer but the current one (`p2p.fam:497`), so every
  loop that stops on 0 is cut short by others' traffic: `pfetch`,
  `phdrs`, `pping`, `cxask`, `pfollow`. In `pfetch` it also re-asks the
  whole window and takes the next chunk, an answer to the earlier
  request, as the round trip: Karn's rule broken, SRTT driven down, more
  needless resends.
- **Upkeep starved while working.** `pkeep` (pings), `pdisc`, `nrelay`,
  `nrean`, `cxrun` and the API's `awake` run only from `nstep` and
  `nidle`: during a sync, a batch (`nrun`), `vwait`/`cwait`, `cxask` or a
  DNS lookup, no pings go out and long polls are not answered.
- **A ban cut to a minute.** "Passed over" and a ban share the peer
  record's `B4`; `nstep` writes `secs + 60` into the current peer's
  after `ncatch` connected nothing, which may have just banned it for an
  hour (`sync.fam:838`; `p2p.fam:430`, `:438`).
- **A block can cost up to 16 × 30 s.** In a batch, each silent peer
  gets the full `pidl` (30 s at least) before the next is asked; a
  silent peer is not remembered for the run's other slots; a failed
  prefetch is retried at the same peer first (`sync.fam:400-420`).
- **`cxask` blocks** up to 16 × 4 × 0.5 = 32 s, every 10 s, the API not
  watched, failures not remembered (`cons.fam:99-115`, `:313`).
- **The API has no deadline per request**: a client sending a byte every
  1.9 s holds the single-threaded node for hours; writes block on a
  client that does not read (`api.fam:99`, `:84-91`).
- `wsendto` sleeps 0.1 s and tries again, without end, when the send
  queue is full (`p2p.fam:89`).
- `nrean` and `nidle` and the API's long poll count by the date
  (`ntime`), not `secs`: a clock set back stalls them.
- Lost peers are still sent TxInvs and advertised in Peers (`pann`,
  `ppeers` check only the answered flag).

**The fam wallet**
- `hask` (its HTTP to the node) has **no timeout**: the window freezes
  as long as the node is busy (`wallet.fam:252`).
- `nodeok` returns to "reached" only when the tip moves: a node restarted
  at the same tip shows "not reached" until the next block
  (`wallet.fam:457-469`).
- The init-mode send gives a point 8 s (tabminer 40 s), without resending
  within the step, then cancels the slate (`wmcanc`) while a slow point
  may still deliver (`wnet.fam:395`; `wallet.fam:2047`).
- The onion link's hello tries are spent waiting for the relay's Pong
  (8 s in all) (`wopart.fam:624`).
- A circuit build that times out is marked dead without DESTROY and
  rebuilt at once; `owsfail`'s backoff never runs (`wopart.fam:655`).
- A link left without circuits is reused after the relay closed it as
  idle: the send fails with "the circuit failed" (`wopart.fam:162`).
- A send's circuit dying fails the send at once; the circuit build and
  the offline window share the 120 s; an answer never coming expires
  silently, the coins kept reserved (`wopart.fam:559-585`).
- `mnms` reads the 32-bit time register (10 MHz): blocked more than
  429 s, every timer is wrong (`wnet.fam:52`).
- The main poll waits a fixed 1 s, not the next deadline, so every
  resend and stall timer is rounded to a second (`wallet.fam:2241`).

## 6. Where timers add up

| Case | Sum today |
|---|---|
| A lossy handshake | unused 15 s (relay) + the initiator's 30-35 s + rebuild 3 s; the relay avoided 300 s. Tests: 3 + 20 + 3 s, twice past the lossy test's 60 s |
| A dead middle relay | keepalive 25 s + dead 30-35 s before the DESTROY reaches the participant, + 3 s, + 8 s (or 30 s ping wait) if the dead relay is picked again, + 3 s and the build: **75-100 s**, past the sender's 60 s offline window |
| Sending to a recipient whose point is dead | lookup up to 3 × 40 s, delivery up to 3 × 30-40 s: past the 120 s send budget |
| A recipient's circuit already gone | 30 s `ACK_WAIT` per point |
| A silent peer | live for 180 s; each block, header batch or channel to it pays 0.8-8 s, 4 + 4 s, 15 s or 8-30 s, then 600 s passed over |
| The node's sync start | 8 s `pping` per silent peer + 6 s DNS per name + 30 s `nidle`, per round |
| One block in a batch | up to 16 peers × 30 s |
| The wallet's init-mode send | 8 s per point where each may need 30-40 s |
| The wallet behind a busy node | `hask` with no timeout × `cxask`'s 32 s, `pping`'s 8 s, a slow API client |

## 7. Tests

**tabminer's waiting tests** (`node.rs`, `guard(secs)`, three times in a
debug build): most wait on a condition with a guard against a hang
(fine). These race:
- a fixed sleep then a positive assertion or a count: the sub-name and
  delegation tests (`node.rs:6519`, `:6559`, `:6572`, `:6669`, `:6688`,
  `:6708`, `:6796-6802`, `:6899-6902`);
- a fixed sleep tied to a production timer:
  `a_fresh_node_fast_syncs_when_its_first_peer_comes_late` (11 s against
  the 10 s alone window), `standing_circuits_are_replaced_and_rebuilt`
  (13 s);
- deadlines not scaled by `guard`:
  `a_claim_of_work_alone_does_not_hold_the_miner`,
  `sessions_come_back_after_the_relay_restarts` (70 s against init
  mode's 30 s keepalive);
- `an_idle_participant_is_quiet_and_learns_of_a_dead_hop` counts frames
  over a fixed 15 s.

**Random loss** (`messages_meet_over_a_lossy_network`, its reordering
twin, `a_fresh_node_fast_syncs_over_a_lossy_network`): 10% from a fixed
seed, but which datagram is lost depends on thread timing, so a failure
does not repeat. In their place, a drop filter by message kind
(`loss: Fn(&Message) -> bool`) and a test for each fault: the auth held
past the unused window; one SESSION_STATE lost on a live circuit; a
relay cell lost at the middle hop; one header batch lost; a peer
answering "not held"; a node stopped gracefully against killed. The
random tests stay, as a soak.

**The node's scripts** (`waitlib.sh`: no deadline, a test fails when
nothing changes for its idle window) are mostly sound. These race:
`stalltest.sh:109-117` (the status must be read before `pidl`'s 30 s
gives the held block up); `msgtest.sh:234`, `onitest.sh:264`,
`paytest.sh:334` (a name's reveal sent again each 5 s of a slow miner);
`oscheck.sh:1036`, `:1447-1508` (fixed 60 s loops), `:1111` (fixed
sleeps against the shell); the block-count deadlines of the message
tests (30 blocks, about 3 minutes, which one failed 120 s send and a
retry can pass).

## 8. Plan

In phases; each item is a commit with its test. Old and new nodes work
together throughout: nothing removes a message, and a signal not
understood is ignored.

**Phase 1: the bugs that stall users now**
1. tabminer channels: the unused timer from the last activity (the auth,
   a hello again, a frame refused before the auth); the unknown-channel
   notice; no `AVOID` on such a close. Test: the auth held back past
   the window. (The lossy flake.) **Done (2026-11-13):** `ChannelGone`
   (message type 23), answered within 64 a second to a frame on a
   channel not held, the sender closing at once without avoiding the
   relay; the fam wallet's links too (`owgone`); tests
   `a_channel_waits_for_an_auth_held_back` and
   `a_channel_the_other_end_lost_is_closed_at_once`, with a drop filter
   by message kind (`Node::drop_out`, section 7's first step).
2. The fam node: others' datagrams no longer count as timeouts (`pwait`
   says whose; `pfetch`, `phdrs`, `pping`, `cxask` wait to a deadline);
   Karn's rule in `pfetch`; RTT per peer. **Done (2026-11-13):** `pwaitc`
   (a wait for the current peer to a deadline in ticks, others'
   datagrams dealt with on the way; still woken by the API and the
   worker); the round trip in each peer's record (`C0`; the record now
   `D0` bytes); no sample from a round that asks again. Test:
   `stalltest.sh` syncs with another address chattering at the node
   every 10 ms and the miner's answers 100 ms late.
3. The fam node: upkeep while working (`pkeep`, `nrelay`, `awake` from
   `cwait`, `vwait` and between a batch's blocks); `cxask` one ask a
   turn, failures remembered. **Done (2026-11-13):** `pkeep` (pings,
   discovery) in `cwait`, `vwait` and each round of `pfetch` (a batch's
   blocks all go through `cwait`), `awake` in both waits; a turn of
   `cxrun` stops at the first peer that does not answer GetAux, passed
   over for it ten minutes. `nrelay` stays in `nstep` (it fetches, and a
   fetch cannot nest in one): TxInvs wait in their queue (16) meanwhile.
4. The fam node: the ban's own field; "passed over" 600 s; a batch's
   silent peer dropped for the run, give-up after a few seconds without
   progress, no duplicate retry. **Done (2026-11-13):** "passed over" in
   the record's `C4`, the ban keeping `B4`; kept at a minute, not 600 s
   (the node often has one or two peers: passing over its only one ten
   minutes would stall it); a peer that sends nothing for a block (a
   prefetch included) is skipped for the rest of the run (`nsil`), so
   it is asked once, not once a slot; and `pfetch` gives up after 24
   round trips, 10 to 30 s, rather than 30 s at least.
5. The fam wallet: a deadline on `hask`; `nodeok` on any answer; the
   init-mode send 40 s a point with a resend, no cancel on "did not
   answer"; hellos counted once sent; the build timeout through
   `owsfail`; idle links closed before the relay's 300 s. **Done
   (2026-11-13):** `hask` gives up after 12 s silent (`hready`, poll);
   `nodeok` set by any status answered; a point given 40 s, its lookup
   asked again each 3 s (not the offer: a payload twice), and a slate
   whose payload was offered kept reserved when no point answered (it
   may still arrive) rather than cancelled; the Pong waited for 30 s on
   its own, the eight tries for hellos sent; a build's 60 s through
   `owsfail` (DESTROY, the 3 s wait) or `owclose`; a link no circuit uses
   closed after 240 s without a body (`+78`).
6. tabminer: `RETIRE_WAIT` closes on live only (or the new one
   failing); OFFLINE at once on link gone; delegations queued. **Done
   (2026-11-13):** the old circuit closed when the session is live on
   the new one, or after 5 minutes (was 30 s whatever its state); a
   delivery waiting on a recipient's circuit answered OFFLINE as soon as
   the circuit goes (`rendezvous_link_gone`); a delegation newer than the
   one held but within `DELEGATION_EVERY` held back and applied after
   (`delegation_pending`), as certificates were.
7. The API: a deadline per request and non-blocking writes. **Done
   (2026-11-13):** the header read within 5 s in all, the body within
   10 s, the response written 512 bytes at a time once the socket has
   room (a TCP write waits until all of it is queued) and given up 10 s
   after it began (`adl`, `awr`).

**Phase 2: tell instead of wait** (section 3)
8. Goodbye on shutdown (DESTROY, CLOSE, going away), both. **Done
   (2026-11-13):** tabminer, stopping (`quit`, or SIGINT/SIGTERM on Unix,
   caught without a crate), sends `ChannelGone` on every channel (the
   other end closes it, and every circuit through it both ways, at once:
   no DESTROY of its own needed) and `Goodbye` (type 24, the token the
   receiver gave it) to every live peer, which drops it from its table;
   the fam node takes a `Goodbye` (the peer not answering, lost, until
   its next Pong) and the fam wallet tells its links' relays on exit
   (`owbye`). The fam node itself has no goodbye: it is stopped with its
   machine. Test: `a_node_stopping_tells_its_channels_and_peers`.
9. DESTROY for unknown circuits and dropped CREATEs; "next hop
   unreachable"; handshake refused with why; rendezvous REFUSED. **Done
   (2026-11-13), but for the reason in a DESTROY:** a relay cell on a hop
   not held answered DESTROY (never a DESTROY with one); a CREATE at a
   node that does not relay, or without its key, answered DESTROY; a
   hello refused (channels full, its host's four, too many lately, no
   key) answered `ChannelGone`, the initiator failing that handshake at
   once (the relay avoided a while) rather than after eight hellos; and a
   rendezvous LOOKUP or FORWARD from an asker not listed, or at a node
   that does not relay, answered RESULT REFUSED, the asker trying the
   next point at once. Left: "next hop unreachable" in a DESTROY. A
   circuit failing as a hop is added already avoids that hop
   (`drop_mine`); for one already built, the DESTROY is made again at
   each hop on its way back, so which hop failed would need more than a
   byte.
10. "Not held" for chunks and aux leaves, both. **Done (2026-11-13), for
    chunks:** `NotHeld` (type 25: the kind, the id), from tabminer's
    `serve_chunks` and the fam node's `pgive` for a transaction not in
    the pool, a body or snapshot not kept (the fam node not while its
    worker holds the store, when it cannot look), a consensus file not
    held; on it the asker's download from that peer is given up at once
    (tabminer: the stall's path, so a block's peer is passed over and a
    snapshot's marked unserved; the fam node: `pfetch` ends, the batch
    asks its next peer). Not for aux leaves: they are named by the
    block's id, which a block's download shares; tabminer asks for them
    apart from everything else, and the fam node's `cxrun` stops at a
    peer that does not answer (item 3).

**Phase 3: measure instead of guess**
11. A channel's death from its round trip (about ten resend timeouts,
    5-30 s), checked every poll; the same in the wallet's links. **Done
    (2026-11-13):** a frame unanswered 30 s still ends the channel; under
    that, once its window has passed (ten resend timeouts of the
    channel's measured round trip, 5 to 30 s; 30 s before one is
    measured), with nothing at all heard from the other end meanwhile
    and eight sends of it, its resends capped at a quarter of the window
    so that the eight fit: a LAN notices a dead relay in about 7.5 s, a
    satellite keeps its allowance. Checked every poll, not only when a
    resend falls due. Time alone was not enough: in the lossy test (10%
    each way) a frame alone in flight, resent 5 s apart, went five sends
    unanswered among thousands, so the rule asks for silence and eight
    sends (one in six hundred thousand at that loss). tabminer's
    `channel.rs` and the fam wallet's `owlink` alike. Test:
    `a_dead_channel_is_noticed_from_its_round_trip`.
    **The floor back to 30 s (2026-11-13):** 5 s took a busy end for a
    dead one: eight nodes in one process on a loaded Windows runner
    (`relays_learn_nothing_of_the_sender`) closed channels whose other
    end went on sending, and a fam node holds its loop ~5 s checking a
    header's proof of work. A dead channel is noticed at 30 s again,
    as before; the checks every poll and the capped resends stay.
12. A circuit's from its own round trip (SESSION to SESSION_STATE), a
    re-ask at a third of the window, any cell as activity; rebuild
    backoff per point. **Done (2026-11-13), tabminer:** each standing
    circuit's round trip measured from an ask answered at its first
    sending (Karn's rule), smoothed; given up at 30 s unanswered, or once
    its window (twenty round trips, 5 to 30 s) has passed with three asks
    unanswered, asked again a quarter of the window apart meanwhile (it
    waited for the next keepalive, minutes, so one lost cell ended a
    live circuit at 30 s); anything coming down the circuit counts as an
    answer; and its rebuild waits 3 s, doubling with each failure in a
    row at its point to 60 s, back to 3 s once its session is live. The
    fam wallet's standing sessions (`owstick`: 3 s until live, 15 minutes
    after, 30 s unanswered) are not changed yet.
    **The floor back to 30 s (2026-11-13),** as item 11's: a dead
    circuit is given up at 30 s again; the re-asks while unanswered,
    anything down it counting, and the rebuild backoff stay.
13. A peer not live after two missed pongs; tabminer's chunk retries up
    to 5 s with backoff; the node's per peer. **Done (2026-11-13):** a
    peer silent 65 s (two pings unanswered, `LIVE_SILENCE`) is not live
    in tabminer, nor picked for anything, though kept until
    `PEER_TIMEOUT`; the fam node marks it lost at 65 s too, and no longer
    announces to or advertises a lost peer; tabminer's chunk retry
    ceiling 5 s (was 1 s), each retry without progress doubling the wait
    to eight times (eight retries about 5 s on a LAN, not 0.8 s), blocks
    and snapshot parts alike; and a snapshot part's download takes
    `NotHeld` too (item 10 had missed its own table). The fam node's
    round trips were made per peer in item 2.
14. Send budgets per step, each from the round trip with a floor; the
    120 s as the outer bound. **Done (2026-11-13), simpler than planned:**
    with items 9 and 11 a dead hop on an outbound circuit is now told
    (DESTROY) or noticed in seconds, and the job moves to a fresh
    circuit, so what remained was the budget: a send's whole is 240 s (it
    was 120 s, under the worst lookup alone: three points at 40 s), in
    tabminer and the fam wallet; and a lookup unanswered 130 s is taken
    for a stalled circuit and asked again over a fresh one, once. Not a
    delivery: its payload may already have reached the recipient, and a
    slate sent twice is answered twice.

**Phase 4: notify instead of poll** (section 2)
15. The node's event stream (`/v1/events`), the wallet's block thread,
    the wallet's events to the page, the node's status as events.
    **The node's part done (2026-11-13):** `events.fam`, a ring of the
    last 2,048 events (block, undone, a transaction's state, the node's
    state on a change), `GET /v1/events?after=<n>[&tx=<ids>]` answering
    at once or waiting (30 s; 16 requests), `reset` for a number not
    kept; tested in `apitest.sh` (the blocks, the state, a transaction
    pooled then mined while waited for, a filter, a reset). No `fees`
    event: the fam pool's minimum does not move yet.
    **The wallet's block thread done (2026-11-13):** `wallet.fam`'s
    `wbstart`, a thread with variables and buffers of its own, keeps a
    `/v1/events` request open (44 s answer window) and writes to a pipe
    the main loop polls: something happened (a block connected or
    undone, the node's state, a reset, the node back), and the loop asks
    and scans (`wtick`) as before, no longer every 4 s; or the node not
    reached, asked again after 5 s doubling to 30 s. Without a thread
    (no pipe, no room) the 4 s poll stays. The overview says which
    (`watch`: `events`, `poll`); `paytest.sh` checks `events` and a
    block told to the page with nothing asked.
    **One update a block done (2026-11-13):** the wallet sends a `block`
    event (height, hash, and the overview, activity and names as their
    requests answer, as of that block) once the tip moves, after the
    request at hand is answered; the page redraws the open panel among
    those three from it, only its list (a form's typing kept), with no
    request; a panel opened later asks as before. `node` events say the
    node unreachable (with the seconds to the next try, shown on the
    status line) and reached again. `paytest.sh` checks the event's
    panels (the 2.5 received in the activity, the balance), and
    `wallettest.sh` its shape.
    **A payment's fate done (2026-11-13):** the wallet watches its
    payments not yet landed (the first four) through the node's events:
    the block thread asks with their ids (`tx=`) and wakes the main
    loop on theirs too, which reads them (`/v1/events?wait=0`, the
    node's new way to answer at once) and tells the page a `payment`
    event: pooled, replaced by which, evicted, mined at a height,
    conflicted, back. A payment made or replaced reads them first, then
    watches the new list (a bumped one leaves it). The page says it on
    the status line ("dropped from the pool ...: bump it") and redraws
    Activity. `paytest.sh`: the burn replaced by its bump, the bump
    mined, the cancelled burn replaced by its cancel.
    **An online payment's steps done (2026-11-13):** `payment` events by
    the slate's id beside the messages saying them: the payer's sent,
    delivered, unanswered (its coins reserved), undelivered (cancelled),
    finalized; the payee's answered. The page shows each on the status
    line. `msgtest.sh` and `onitest.sh` check them (the 2.5 answered;
    the 1 sent, then finalized, by one slate).
    **Names' steps done (2026-11-13):** each block event's names against
    the last one's, a name whose state changed told after it (`name`:
    ready, the reveal's window open; revealed; owned; offered;
    transferred); the first block after a start only notes them. The
    page says it on the status line. `nametest.sh`: famwallet told
    ready, then owned. Not done of item 15: a renewal due.
16. Loops sleep to their next deadline (the wallet's poll, the node's
    `nstep`), not a fixed second; `secs` rather than the date.
    **The node's part done (2026-11-13):** its deadlines on the
    monotonic `secs`, not the date (`/proc/time`, a file opened each
    time, and moved by a clock set): `aserve`, `nidle`, the pool's
    announcing again, the API's waiting requests; the date stays for
    headers' timestamps. `nstep` waits (`nnext`) to the first thing
    due: a peer's ping or the end of its pass-over or ban, discovery,
    the announcing, the message layer's check, a waiting request's end;
    a second at least, 4 at most (a wait is one word of nanoseconds),
    a datagram or the API waking it sooner. `nidle`, before a sync,
    keeps its second.
    **The wallet's part done (2026-11-13):** offline, its loop waits
    for a line or the block thread's word (item 15), the 4 s poll only
    without the thread. Online in onion mode, it waits until a link's
    frame is due again (`ownext`: its last send and resend wait, a
    hello each second), a second at most: a resend goes when due, not
    at the next second, and a timer not counted is no later than
    before. The message layer's other timers (some 70, in `wopart.fam`
    and `wnet.fam`) still run on that second: a wait longer than it
    would need every one counted, for one wakeup a second saved.

**Phase 5: tests**
17. The drop filter by message kind and a test per fault (section 7);
    the racing tests made to wait on conditions; the same timer values
    in tests as in production wherever a test decides on one.
    **A stall fault (2026-11-13), first:** the drop filter tests a dead
    peer, never a busy one, and a busy one taken for dead was what items
    11 and 12's 5 s floors did. `Event::TestStall(d)` holds a node's
    loop (datagrams queue for it, as behind a long block's checking);
    `a_busy_relay_keeps_its_channel` (a relay busy 10 s, a body sent to
    it each second: the channel kept, every body delivered after, the
    same channel on) and `busy_relays_keep_the_standing_circuits` (every
    relay busy 10 s: no standing circuit given up, `Stats::standing_lost`,
    the sessions live again, a message through). Both fail with the 5 s
    floors (the channel given up at 9 s; all three circuits) and pass
    with 30 s.
    **One header batch lost:** `a_lost_header_batch_is_asked_again`, the
    first `Headers` the peer sends dropped (`drop_out`), its heights
    noted: they are sent again, and the fresh node fast-syncs (about
    4 s), its peer kept live.
    **A peer answering "not held":** `a_not_held_answer_ends_the_fetch`,
    a hand-driven peer announcing a transaction, then answering the
    node's request NotHeld: not asked again in 3 s, where one never
    answered (the control) is asked again at least twice.
    **A node killed, against stopped gracefully:** beside
    `a_node_stopping_tells_its_channels_and_peers` (told: the channel
    closed within 5 s), `a_node_killed_is_noticed_by_its_silence`
    (`Event::TestKill`, no goodbye; slow, a CI job of its own): the
    channel still held 5 s on, given up by the channel's silence (19 s
    here), the peer not live after its 65 s.
