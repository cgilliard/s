# Node enhancements

Work planned for the fam OS node (`node/`) and its wallet, beyond what
`docs/NODE.md` and `docs/GUI_WALLET.md` describe as built. Item 1 is a
requirement before any `consensus.txt` lists more than 16 relays; the
rest are in no particular order.

## 1. As many relays as tabminer takes (required past 16 relays)

tabminer reads a `consensus.txt` of up to 8,192 relays and 1 MiB
(`consensus::MAX_RELAYS`, `MAX_CONSENSUS`). The fam node and its wallet
keep far fewer, and past their limits they do not degrade gracefully:

| Where | Limit | Past it |
|---|---|---|
| `node/cons.fam`: `CXMAX`, `CXFMAX` | 64 relays, a 64 KiB file | the file counts as **invalid**: the node skips it and decides the next file voted for, or init mode, while tabminer takes it, so the node's wallets are in the wrong mode |
| `wallet.fam`: `wmcons` (`wmrids`, `wmrads`) | 16 relays read from `/v1/consensus` | the wallet keeps the first 16 by id |
| `node/wopart.fam`: `OWRN` | 16 relays | as above |

The wallet's limit is the more urgent one. A participant's rendezvous
points are the three heaviest of **all** listed relays (`onion::
rendezvous_relays`, `wonion.fam`'s `oxpts`). A wallet that weighs only 16
of 20 relays computes different points from every other node: its points
refuse its session (a relay serves only ids whose points include it) and
its lookups go to the wrong relays. **A file listing more than 16 relays
breaks the fam wallet in onion mode until this is done.**

What it takes:

1. **The node: take every file tabminer takes.** Raise `CXFMAX` to 1 MiB
   and the relay count to 8,192. A set kept as now (320 bytes a relay,
   288 of them the address field) would be 2.6 MB, and the node keeps the
   current set, the previous one and one being parsed: about 8 MB of the
   128 MiB budget. Keep addresses packed (NUL-ended, one after another,
   an offset table beside the sorted ids), or in the store rather than
   in memory: about 40 bytes a relay, 330 KB a set.
2. **The API: the relay list without sending it all every time.**
   `/v1/consensus` now lists every relay, and the wallet asks every ten
   seconds; at 8,192 relays that is over a megabyte each time. Give the
   list's hash (the file's) and its count in the summary, and the relays
   in pages (`/v1/consensus/relays?set=current&from=N`), so a wallet
   fetches them only when the hash changes.
3. **The wallet: every id, few addresses.** Rendezvous points need every
   relay's id (32 bytes each: 256 KB at 8,192). Addresses are needed only
   for the relays a circuit uses: the first hop is the only one the
   wallet connects to (later hops are extended by their relays, which
   look up the address themselves). So `wopart.fam` keeps all ids and
   fetches an address from the node when it picks a first hop.
4. **Rendezvous points at scale.** `oxpts` hashes every relay
   (`hash_domain(21, id, epoch, relay)`) for each id it places: once for
   our own points an epoch, and once per recipient in a send (its
   announce lookup goes to the last hop, which places it, so the wallet
   places only itself and the full names of sub-names it publishes).
   Measure it at 8,192 relays in the OS before deciding whether it needs
   to be faster (the hash in assembly, as `chacha.fam`'s were).
5. **Tests.** A consensus file of 8,192 relays through `constest.sh` (the
   node's decision matching tabminer's, the file valid), and `oxpts`
   against tabminer's `rendezvous_relays` on a large list (a vector in
   `wonion_vectors.fam`). `onitest.sh` with more than 16 relays pinned
   would need that many tabminer relays; 20 is enough to cross today's
   limit.

## 2. The node in place of `server.py`

The fam node already serves the image it booted (`docs/TABERNACLE.md`,
"The node serving its image"; `docs/NODE.md`, step 9): `p2p.fam` answers
`Ping`, `GetPeers`, `GetImages` and `GetImage` as `server.py` does, from
`/dev/image`, and `scripts/imagetest.sh` boots a tabernacle from a node
with no `server.py` anywhere. What `server.py` still does that the node
does not, before the seeds can run a node alone:

- **More than one version.** `server.py` serves several images
  (`VERSION=FILE ...`), so tabernacles built for an older image still
  boot while the network moves to a newer one. The node serves only the
  version it booted. It should keep the images of other versions it has
  (fetched from peers, as tabernacle fetches, or put on its disk) and
  serve each, so an upgrade does not strand the tabernacles of the old
  version.
- **Validation.** `server.py` checks nothing ("tabernacle checks what it
  gets"); a node serving images it did not boot must check each before
  serving it: its size and Gimli-Hash against what a tabernacle for that
  version expects (the values `build.sh` patches in), so a node never
  hands out an image that every tabernacle will then refuse.
- **Peers to hand out.** `server.py --peer` lists fixed addresses; the
  node hands out the peers that answered it. On a seed that is what is
  wanted, but it should be checked at scale: enough peers, and ones that
  serve the image.
- **Tried on a seed.** Run a node on a seed in place of `server.py`, with
  tabernacles booting from it alone, from it and other nodes, and with a
  peer serving a corrupted image (the case `server.py` was tried with,
  `docs/TABERNACLE.md`), before `server.py` becomes only the backup.

## 3. More than one node on a host

`scripts/makenode.sh` and `scripts/node.sh` default to one node:
the disk `node/data/node.img`, the built-in seeds, and QEMU's defaults
for the MAC and the forwarded ports. `--disk`, `--mac` and `--hostfwd`
exist, but running several nodes means choosing each by hand, and a
mistake (two nodes on one disk, or on one forwarded port) fails late and
unclearly. What it takes:

- **An instance name.** `makenode.sh --name=N` and `node.sh --name=N`:
  the disk `node/data/N/node.img`, a MAC derived from the name, and the
  node's ports forwarded to host ports given once (`--port=P`: UDP P for
  the p2p port, TCP P+1 for wm, P+2 for the API, as the node's
  `api-port`), written to
  `node/data/N/config` by `makenode.sh` so `node.sh --name=N` needs
  nothing else. With no name, today's defaults.
- **Refuse a clash at start.** `node.sh` takes a lock on the instance's
  directory (QEMU locks the disk too, but its message is unclear) and
  checks that its host ports are free before booting.
- **A test.** Two or three instances from `makenode.sh`, booted together
  and syncing from each other (no test runs more than one fam node
  today: `peertest.sh` runs one with two tabminers).


## 4. Nothing blocks the node's loop

The node is one loop (`main.fam`: `aserve`, the network, sync and the
API in turn), so whatever runs inline stops everything else: peers go
unanswered, the API times out, and a large block freezes the node for as
long as it takes. Proof checking already runs elsewhere: `nodev`
(`vmain.fam`), a process of its own, with the node serving the network
and the API while it waits (`sync.fam`'s `vwait`). The rest of a block
runs inline:

- **A header's proof of work.** The work is over the 1.29 MB seed file;
  the dev network's logs show 4 to 10 s per header (`the best's work
  checked in 9.85 s`), and a sync checks many.
- **A block's body.** Fetched in chunks, the node waiting on them.
- **The state.** Its spends, outputs and names applied, the manifest
  and snapshot parts written, in one store transaction: grows with the
  block's size.
- **The store's commit**, and pruning.
- Likely others: a snapshot's install in fast sync, a pool rebuilt after
  a reorganization, a large API answer written at once.

What it takes:

1. **Find every place.** Time each step of a block and of every request
   (the node's log already times a block's steps: `fetch`, `body`,
   `state`, `proof`, `store`), and a probe that pings the node and asks
   the API throughout a sync of large blocks: the longest it goes
   unanswered is the measure. Fix every step over, say, 100 ms.
2. **Move work out or cut it up.** Pure computation goes to `nodev` (or
   a second worker) as proofs did: the proof of work first. Work on the
   store is cut into steps of bounded size the loop takes in turn (the
   block's outputs a few hundred at a time), with the state readable as
   of the last block meanwhile (transactions of their own, as `vwait`
   already keeps the API's).
3. **A test.** A chain of large blocks (the most outputs and names a
   block takes), synced while a probe pings and asks the API: no answer
   later than the bound.

## 5. The wallet shows what is in progress

The wallet's page (`wm.html`) sends a request (`wask`) and shows nothing
until the answer comes: a long one (an online send, which waits on the
recipient; `@label.name` resolving; a rescan; a name commit or reveal;
the first sync after unlocking) looks stuck, and a button pressed again
sends it twice. The wallet process blocks too while it works (a
Dilithium signature, a slate, a rescan), so its WebSocket stops
answering for that time.

- **A spinner on each request in progress:** on its button (disabled
  meanwhile, so it is not sent twice) from the request until its answer,
  and on its line in Activity for the long ones until their final event
  (an online send until finalized or failed, a resolve until paid).
- **Progress where it is known:** a rescan's height of the tip, the
  blocks a name commit has left before its reveal, the step of an online
  send (sent, reached the recipient's point, answered, finalized).
- **The wallet itself answering meanwhile:** its long work cut into
  steps between which it reads its WebSocket, as item 4 for the node,
  so the page can show the spinner and stay usable rather than freeze.

## 6. A node at height 0 (the seeds)

Run as a seed, a node may start before the chain has a block past its
genesis, or with no peer that has one. Today (`main.fam`), a node with
no chain in its store syncs first and only then starts the API:

- While every peer is at height 0 it says "nothing to sync yet" and
  sleeps 30 s between tries; a plain sleep serves nothing, so for that
  time no ping, no peer list and no image is answered, and there is no
  API at all.
- With no peer (none given, none of the seeds' names resolving) it
  exits; a first sync that stops (no peer answering, another chain, a
  bad block) exits too.

What it should do: start the API and serve the network at once, at
whatever height it has (0 with only the genesis); keep asking its peers,
and taking new ones, from the loop rather than before it; and never exit
for want of a peer or a block. A seed is then useful from its first
second (peers, images, its tip), and a wallet on a node still at height
0 sees "height 0, syncing" rather than no node. To check: `/v1/status`
and the p2p replies from a node started alone on a fresh chain, then
from two seeds started together before any block is mined, the first
block then reaching both.

## 7. How the wallet is set up

The OS is for running the node and its wallet, but the wallet comes to
exist only when a user opens its window and presses **Create a wallet**
(or restores from a phrase in Settings). Until then the machine has no
keys, so nothing can be paid to it, and its message layer has no id.

Decided: the wallet is made at the first boot, at the console, with the
user's account (item 17, The first boot): restored from a phrase typed
there, or made new and its 12 words shown there to be written down. It
belongs to that account, and is unlocked by its login (no password of
its own). The **Create a wallet** button goes: the wallet is there when
the window opens. Still to settle: what a second account (`adduser`)
gets, a wallet of its own or none.

## 8. The wallet's window: payments by address first

The window (`wm.html`, built into `wm.fam` by `scripts/wmpage.py`) has
the tabs Overview, Receive, Send, Activity, Proofs, Names and Settings,
and puts paying by slate (copy and paste, or a file in your home) beside
paying online. Paying by address, online, is what most users want; the
slate flows are for when the recipient is offline or unreachable.

**First, `wm.html` is behind `wm.fam`.** The phase 2 and 3 screens (online
sends, name offers and transfers, sub-names) were written straight into
`wm.fam`'s string literals and never brought back to `wm.html`, so
running `wmpage.py` after editing `wm.html` would drop them silently.
Bring `wm.html` up to date from `wm.fam` (and make `wmpage.py` refuse to
overwrite a `wm.fam` whose page differs from what `wm.html` would give,
unless told to) before changing the layout.

The layout:

- **Overview:** the balance; this wallet's address to receive at, with a
  copy button; its names beside the address (from the Names tab's "Your
  names"); the node's state.
- **Send:** online, to an address, `@name` or `@label.name`.
- **Activity**, **Proofs**, **Names** (registering, offers and transfers,
  sub-names; no longer "Your names"), **Settings**: as now.
- **Burn:** a tab of its own (it is under Send now).
- **Advanced:** every slate flow, in one tab: paying by slate,
  answering one, finalizing an answer, each by copy and paste or a file
  in your home (the Receive tab's and Send tab's slate sections today).
  Most users never use slates, so none of them appears elsewhere. The
  Receive tab goes: its address moves to Overview.

## 9. The wallet's status: one model

The strip beside the tabs (`w.st`) shows whatever came last: "Tip N" on
each block, "Scanned N of M" during a scan; the content area shows
"Unlocking...", "Locked: ..." or "[no wallet: the server has none
free]" in place of a tab. Each is right when shown, but together they
read as noise: a tip that moves while nothing else does, a scan's
progress replaced by the next tip, a lock message where a tab should be.

Work out one model of what the wallet is doing, and show it in one
place:

- **The wallet's state:** no wallet, locked, unlocking, scanning (to
  height N of M), syncing (the node behind), ready; and online in init
  or onion mode, or not reachable (no session at a rendezvous point).
- **Work in progress:** item 5's spinners, listed (an online send
  waiting on the recipient, a sub-name resolving).
- **What shows where:** the state in the strip, words a user knows
  ("Ready", "Catching up: 1,204 of 1,310 blocks"), not the raw tip; the
  tip and the node's details in Overview's node section; errors where
  the action was taken, and in Activity.

## 10. Activity: every entry read as a user

Activity lists sent and received payments, burns and name operations,
and the wallet's events (each `wmev` and `'event':'message'` text in
`wallet.fam`: about twenty, such as "answered a slate of 2.5 coins from
a payer; it is paid once the payer sends it", "the slate reached a
rendezvous point of the recipient; waiting for the answer", "the
message was not delivered: ..."). Many were written for tests and
debugging.

- **Each message read as a user would:** whether it says what happened
  and what, if anything, to do; in plain words (no "rendezvous point",
  "slate" or "stage" where the user does not need them); one style
  throughout; and whether it belongs in Activity at all (a transient
  step may only update the entry it belongs to, its spinner, item 5).
- **One entry per thing:** an online send is one entry that moves
  through its steps (sent, reached the recipient, answered, finalized,
  confirmed, or failed and why), not a message per step.
- **What is missing:** for instance a received online payment as an
  entry from the moment it is answered (not only once mined), a
  sub-name given or withdrawn, a certificate held, a name offer
  received or taken, a payment cancelled or bumped, the wallet going
  online or offline, a failed resolve; and each entry's details on a
  click (the transaction, the fee). Proofs are not shown here: item 11.

## 11. Proofs: the payments that have one, in the Proofs tab

Payment proofs (`docs/PROOFS.md`) belong in the Proofs tab, not as an
action on an Activity entry. The tab today checks a proof given to it;
it should also list this wallet's own, below that, scrolling:

- **What can be listed.** A proof is made against the state as it stood
  at the paying block, which a node rebuilds only within its undo window
  (1,008 blocks, about a week, by default; any block on an archive
  node). So the wallet makes and keeps a proof when the payment confirms;
  once made, checking it needs only the header, for good. The list is
  every sent payment and burn with a proof kept, newest first; each
  shows its amount, recipient (or the burn's purpose), date, and its
  proof to copy or save, as text or a file in your home.
- **One not made yet.** A payment confirmed while the wallet was offline
  has no proof until the wallet makes one, and can be made only while
  its block is in the node's undo window. List those first, with how
  long is left ("can be proven for 5 more days"), made at once when the
  wallet is online; one past its window is listed as no longer provable,
  and why.
- **Check the fam node's side.** That the fam wallet makes and keeps the
  proof at confirmation as tabminer's does (`wrcpt+` keeps the receipt;
  the path is the node's), what the fam node's undo window is, and that
  a proof the fam wallet makes checks in tabminer's `proof verify` and
  the other way round.


## 12. Wallet usability, from a review of the window

A read of the wallet window as it is (`wm.fam`'s page; `wm.html` is
behind, item 8) and of the wallet behind it, 2026-11-12. Items 5 and
7 to 11 are not repeated here.

### Big ones

1. **The wallet runs only while its window is open.** wm starts a
   `wallet` process for each `/wallet` WebSocket, and it exits when the
   connection closes (its input ends). Close the browser tab or log out
   and the wallet stops: it cannot be paid online, its standing session
   at its rendezvous point drops, and it stops publishing its sub-names.
   On an OS meant to run a node and its wallet, the wallet should be a
   service that keeps running, the window a view of it (with item 7).
2. **A dropped connection makes the window vanish.** When the WebSocket
   closes after it was up, the page closes the wallet window, with no
   message and no reconnecting. It should say so and reconnect. (A local
   `onitest.sh` run lost the wallet this way, with no word of why.)
3. **Nothing irreversible is confirmed.** Burn, Send online, signing a
   name over and Cancel each go on one click. Show what will happen
   first: the amount, the fee, the total and the recipient, and a button
   to confirm.
4. **A name is paid without showing whom it resolves to.** For `@name`
   and `@label.name` the user never sees the address before the coins
   go. Show it in the confirmation (3).
5. **An online send's result is lost.** "Paid ..." or "Error ..." goes
   only to the strip beside the tabs, and the next block's "Tip N"
   replaces it. It belongs on the send's Activity entry (item 10) and
   where the send was made.

### Clarity

6. **Five balances, none explained:** Confirmed, Pending, Unverified,
   Reserved, Locked. A user wants what is available to spend and what
   is on its way; the rest belongs in details, each with a line saying
   what it means.
7. **Amounts are raw:** ten decimals, no unit, no thousands separators,
   and no total of amount and fee anywhere.
8. **Activity's rows are raw:** the kind, the amount, the state, the
   height and the transaction id's first 16 hex digits. No date, no
   counterparty (address or name), no fee.
9. **The speed menu gives a bare rate** ("hour: 10, about 60 min"),
   without saying what 10 is. Show the fee this payment would pay.
10. **Names use jargon.** The value is "a tab1 address or 64 hex
    digits" (the confusion of an id and an address, met in a live test);
    it should default to this wallet's address. A name's value is listed
    as 16 raw hex digits.
11. **Overview's "Online" line** is jargon and ungrammatical
    ("reachable at 1 rendezvous points").
12. **Settings is unclear.** "Show the phrase" asks for "Password"
    without saying which one; Restore sits just below with no warning
    that it replaces this wallet; "Scan again" is under Restore, with no
    word of what it does; a phrase shown stays on the screen.

### Behavior

13. **Any event redraws Overview or Activity:** an open proof closes,
    the scroll goes back to the top, and a form being typed in is wiped
    when the unlock event comes.
14. **Some speeds cannot be chosen:** Bump always pays for "block",
    Reveal and Update for "hour", while Commit has a menu.
15. **A name is revealed by hand:** the user must come back 12 blocks
    later and press Reveal. The wallet could reveal it when ready, if
    the user agreed at the commit.
16. **The sub-name form takes the name as free text;** it should offer
    the names this wallet owns that point at it. Its heading ("answered
    while online") is wrong in onion mode, where the certificate is
    published.
17. **No "send all", and no balance beside the amount;** fields are
    checked only once submitted.
18. **Enter submits nothing,** and labels are not tied to their fields
    (clicking a label does not focus its field; screen readers).
19. **Copy says nothing:** it should show "Copied".
20. **"[no wallet: the server has none free]" is cryptic:** it means
    every wallet slot is taken.
21. **Burn's success message points at Activity for its proof,** which
    item 11 moves to the Proofs tab.

### Smaller

22. **No QR code** for the address.
23. **The full transaction id is never shown,** and an Activity entry
    has no details to open.
24. **No recent recipients or address book.**

## 13. A laptop asleep, and other interruptions (node and tabminer)

Neither the fam node nor tabminer has been tried on a machine that
sleeps, loses its network or changes it, and both keep state that
assumes time runs on and peers stay where they were: links dead after
30 s, sessions and circuits, rendezvous routes, a mining template, the
wallet's WebSocket. To try each, for both, and fix what does not come
back by itself:

- **Sleep and wake** (a laptop's lid closed, low power, hibernation),
  for a minute, an hour and a day. After waking: peers found again,
  sync to the new tip, mining on the new tip (not a stale template; and
  the mining policy's pause only on verified headers), the onion
  session and circuits rebuilt, the wallet's page reconnecting, payments
  in flight finished or failed with a clear message rather than hanging.
- **The clock.** The node's date (`wnet.fam`'s `mnunix`) is the date at
  its start plus the time register's elapsed time, and the register may
  stop while the host sleeps: to check whether the node's date falls
  behind by the time asleep, and what then depends on it (block
  timestamps accepted or mined, the consensus file's timing, a slate's
  expiry). `mnms` also assumes it is called at least every 400 s (the
  32-bit register wraps): to check across a sleep. tabminer: what uses
  `Instant` (which may or may not count time asleep, by platform) and
  what uses the system clock. The host's clock stepped by NTP, either
  way, too.
- **Low power without sleep:** a throttled CPU on battery, so the
  proof of work and proofs run several times slower; nothing should time
  out because of it (the timeouts in `ONION.md` already allow for slow
  links, not for a slow machine).
- **The network:** cable out and back, Wi-Fi to another network (a new
  address, a new NAT whose mappings are gone), offline for a long time,
  a captive portal. Peers and the wallet's sessions should come back
  without a restart.
- **Power lost or killed mid-write:** the store (the node's and
  tabminer's) opened cleanly afterwards at the last committed block,
  the wallet's keys and records intact.
- **The disk full:** a clear message and a stop, not a corrupt store.

**Tests:** a sleep can be simulated by stopping the process (QEMU or
tabminer) with `SIGSTOP` and resuming it with `SIGCONT` after a while,
the network by a namespace taken down and up, a mid-write kill by
`SIGKILL` during a sync. Each test checks the state reached after the
interruption (the new tip mined on, a payment that completes), not how
quickly. Then the real thing by hand: a laptop on each platform (Linux,
macOS, Windows) closed and opened during a sync, during mining and
during an online payment.

## 14. Large blocks, and fast sync of a large set of outputs

The chains the node is tested on are small: oscheck's state test is
312 blocks of a few outputs, its snapshot test a few parts, and the
dev networks' blocks are mostly empty. Mainnet allows blocks of 2 MB
(`ChainParams::max_block_size`), and the set of unspent outputs only
grows. Neither has been tried at size, on the node or on tabminer, and
the node has a fixed 128 MiB of memory. Known limits to check:

- **The dirty groups** a block touches are kept in a sorted list of
  16,384 at most (`docs/NODE.md`, step 5: "fine for now"): a full block,
  or a disconnect of several, may pass it.
- **One block's work inline** (item 4): the state, its manifest and
  snapshot parts and the store's commit, all growing with the block.
- **The body fetched in chunks** and held whole before it is checked;
  a 2 MB body next to the store's cache and the API in 128 MiB.
- **Fast sync's parts:** up to 16,384 unspent outputs each, every part
  checked and installed, then the whole against S's state root. With
  millions of outputs, that is hundreds of parts: their fetch (retries,
  a peer that stops serving midway, parts from several peers), the
  memory held between parts, the time, and a restart partway through
  (resumed or started again, never a half-installed state taken as
  whole).
- **Serving them:** the node building the snapshot parts it serves
  (every block's manifest, whole every 64th) and answering parts of a
  large set without stalling its loop.
- **tabminer too:** its block assembly, connect and snapshot at the
  same sizes, and its memory with the set at, say, 10 and 100 million
  outputs.

**Tests:** a generator for a chain of full blocks (the most outputs,
spends and names a block takes) on the dev network, and for a state of
millions of unspent outputs; then, on both the node and tabminer:

1. A sync of a run of full blocks: every root matching tabminer's,
   memory under the budget, and (with item 4) the node answering
   throughout.
2. Full blocks disconnected and connected again (a reorganization of
   several).
3. A fast sync from a snapshot of the large set, from tabminer and from
   another fam node, with one restart in the middle and one peer that
   stops serving.
4. The numbers recorded (time per block, per part, peak memory) in
   `docs/NODE.md`, so a regression shows.

## 15. A full mempool: 15 to 20 transactions a second

Neither the node nor tabminer has been run with a steady stream of
transactions. At 15 to 20 a second, a 600 s block interval sees 9,000
to 12,000 transactions, far more than a 2 MB block takes, so the pools
fill and stay full: the fee policy (`docs/FEES.md`: the rolling
minimum, the protected oldest, the aged reserve, eviction of the
lowest-paying) works all the time, not only at the edges. To check:

- **Keeping up.** Every transaction arriving is decoded and its
  signatures checked (Dilithium; the node's `pool.fam`, `xverify` per
  input) before it is taken or refused. On the node, inside its one
  loop (item 4) on an emulated 32-bit CPU: whether it checks 20 a second
  at all, and what it drops, delays or stops answering when it cannot.
  Refusing cheaply first (the fee below the minimum, an input already
  spent in the pool, a duplicate) before any signature.
- **The sizes.** tabminer's pool holds 64 MiB (`DEFAULT_CAPACITY`); the
  node's 512 transactions and 4 MiB (`QSLOTS`, `QBYTES`), so it is full
  in under a minute and evicts from then on. Its eviction, the
  minimum fee it then reports, and its fee estimates should agree
  with tabminer's closely enough that a wallet on either pays a fee
  that confirms.
- **Relay.** Each transaction announced to and fetched by every peer:
  the bandwidth, the duplicates, and that a transaction one node evicted
  is not fetched again from the next peer straight away (a loop).
- **Blocks meanwhile.** A new block removes hundreds of transactions
  and makes others invalid (their inputs spent): the pool's rebuild at
  that size, and on a reorganization the transactions returned to it.
  tabminer's block assembly from a full pool, the template refreshed
  without stalling mining.
- **The wallet.** A payment made while the pool is full: its fee
  estimate, a bump (replace by fee) when it does not confirm, and its
  status shown correctly while it waits (item 9).

**Tests:** a generator on the dev network (many wallets, or one with
many outputs, spending at a set rate with varied fees) feeding tabminer
and a fam node, several of each, for an hour or more. Checked: every
node's pool consistent with the fee policy, the highest-paying
transactions confirmed first, nothing valid lost from every pool at
once, the node answering pings and the API throughout, memory within
its budget; the rate each sustains recorded in `docs/NODE.md`. Then the
same at twice the rate, to see what gives first.

## 16. An option to build the 64 MB dataset, for faster proof-of-work checks

Today the node holds no dataset: it computes each of a header's 128
items from the seed file (255 Poseidon2 permutations each), about 2.2 s
a header on one hart (`docs/NODE.md`, Proof-of-work), so 5.3 minutes
for a fast sync's 145 headers and 2.2 s of every new block (item 4).
With the dataset (2^20 items of 64 bytes, as tabminer builds it) a
header is 128 item reads and the 64 windows of the seed file: a few
milliseconds.

An option (in `/etc/node/config`, off by default) to build the dataset
and check headers from it:

- **The seed file stays required.** Each access still reads its window
  of the file directly, so the dataset speeds the check without
  replacing the file (`docs/NODE.md`, The seed file); the node keeps
  the whole file either way.
- **Where it lives.** 64 MB is half of the node's 128 MiB budget, so on
  the disk, in the store's region or a file of its own, read 64 bytes at
  a time (128 reads a header), not in memory; or in memory for a node
  given more, the budget raised for that node only.
- **Building it.** 2^20 items × 255 permutations ≈ 267 million
  permutations: about 3 hours on one hart at 41 µs each, shared across
  harts (each item is independent), done in the background, a few items
  at a time between the loop's other work (item 4), the node checking
  headers from the seed file until it is complete, and resumed after a
  restart rather than started again.
- **Or taken from tabminer.** tabminer saves the dataset it builds; the
  node could take that file (copied into its disk or fetched from a
  peer) instead of computing it, checked the way tabminer checks a
  saved one (sampled items against items computed from the seed file)
  before use.
- **Kept correct.** A dataset item read from disk that is wrong (a bad
  sector, a changed file) must not make the node accept or refuse a
  header tabminer would not: a sampled check at start, a header refused
  from the dataset checked again from the seed file before it is
  refused, and the dataset rebuilt when it fails.

**Tests:** the same headers checked both ways, with the same verdicts
(oscheck's proof-of-work vectors, and a header with each byte changed);
a dataset with one item changed caught; the build interrupted and
resumed; the time per header with each, recorded in `docs/NODE.md`.

## 17. Logging in at the console; the desktop by a link

Today `init` keeps a root shell on the console (or runs `login` when
`/etc/init` says so), and wm's page asks for a name and password before
the desktop (`docs/GUI_WALLET.md`, Logging in). Instead, one login at
the console, one password, and a link that opens the desktop once.

### The first boot

After `scripts/node.sh` starts a fresh disk, the console asks, before
anything else:

1. **Set password:** the password of the machine's user account (a
   fixed name, as `ubuntu` on Ubuntu; the name to choose), typed twice.
   The account is an ordinary user, not root, and root gets **no
   password**: it cannot log in, and administration goes through `sudo`
   (item 18), as on most systems now.
2. **Recover a wallet?** Yes: the 12 words typed at the console,
   checked (the checksum), and the wallet rescans the chain once the
   node has synced. No: a new phrase made and its 12 words shown,
   written down, and confirmed ("I have written them down") before
   going on. Either way the phrase is stored encrypted under the
   password from step 1, so the wallet is ready before wm starts.
3. **The link:** the account logged in, and
   `http://127.0.0.1:8080/?<token>` shown (The desktop by a one-time
   link, below).

### Later boots and logins

`login` on the console at every boot, so nothing runs as root unasked:
the account's name and password, then a new link. No setup questions;
the wallet unlocks from that login.

### One password: the user's login

The password typed at the console is the only one the user has. It:

- **logs them in** at the console;
- **unlocks the wallet:** `login` derives the wallet's key from it (as
  wm does today from its form) and hands key and user to wm for the
  session, so the wallet needs no password of its own;
- **is asked again only to view the recovery phrase,** in the page's
  own tab for it (Recovery phrase): the password typed there, the
  phrase shown until the tab is left. The phrase is the one thing that
  gives the whole wallet away, so a stolen session cookie or a
  malicious page holding the session still cannot reach it without the
  password. Wrong tries slowed (each check takes the key's derivation,
  about 1.4 s, and a few wrong ones in a row add a wait). The page never
  shows the phrase unasked: a new one is shown once, at the console, at
  the first boot. Changing the password (`passwd`) asks the old one too,
  as any `passwd` does, and re-encrypts the phrase in the same step;
- **is the one `sudo` asks** (item 18).

### The desktop by a one-time link

After the console login, the user is shown
`http://127.0.0.1:8080/?<token>`:

1. **The token:** 128 bits or more from the kernel's random source,
   made for that login and given to wm with the wallet's key.
2. **Used once:** the first request carrying it swaps it for a session
   cookie and redirects to plain `/`; the token is spent. The same URL
   again (browser history, a copy, anyone else) gets "log in at the
   console". wm's login form (`wm-login.html`) goes.
3. **The session:** the cookie serves reloads and new tabs until logout
   or 30 minutes idle; then cookie and wallet key are dropped from
   memory, and a console login gives a new link.
4. **Other web pages in the same browser** can send requests to
   `127.0.0.1:8080`, a WebSocket included, and the session holds an
   unlocked wallet. So wm sets the cookie `HttpOnly; SameSite=Strict`,
   refuses a request whose `Host` is not exactly `127.0.0.1:<port>` (DNS
   rebinding), and refuses a WebSocket whose `Origin` is not its own
   page.

### The port forwarded by default

`scripts/node.sh` forwards the host's `127.0.0.1:8080` to wm's port 80
unless told otherwise (an option for another host port, and for none),
bound to localhost only since the page travels in plain HTTP. The host
port is passed into the guest (the boot's configuration, or QEMU's
firmware configuration) so the printed link carries the port that
actually reaches wm. With more than one node on a host (item 3), each
its own port.

### Checking a password

The check exists: `crypto/passwd.fam`'s `pwfind` (a user's line of
`/etc/passwd`) and `pwok` (a password against its hash), which `login`
and wm use. What a program run by a user lacks is the right to use it:
only root reads `/etc/passwd`, and only root writes `/proc/self/user`.

- **The recovery phrase needs nothing new.** The wallet process, run
  as the user, derives the key from the password the page sends and
  decrypts the phrase (ChaCha20-Poly1305): the tag checking is the
  password checked. No `/etc/passwd`, no root.
- **`su`, `sudo` and a user's own `passwd` need root:** a **setuid bit.** A
  file marked so, and owned by root, runs as root (the kernel, at
  `spawn`, sets the process's user to the file's owner; `chmod` sets the
  mark, root only). Only `su`, `sudo` (item 18) and `passwd` have it, each written to
  trust nothing from its caller but the typed password.
- **`su NAME`:** NAME's password asked and checked (`pwfind`, `pwok`),
  then NAME's shell until it exits, back to the first user; root is not
  asked. Root has no password, so `su` cannot become root: `sudo -s`
  does.
- **`passwd`** with no name: the user's own, the old password asked
  first; `passwd NAME` stays root's.

### Tests

In oscheck: a first boot that sets the password, makes a wallet (and
one that recovers a given phrase, the same address as tabminer's from
it) and prints the link; root refused at `login`; a later boot that
logs in at the console and prints a new link; the
page opened with that token gets the desktop as that user, unlocked; the
same token a second time, no token, or a wrong one gets nothing; a
request with another `Host`, or a WebSocket from another `Origin`,
refused; the link's port the one forwarded; `su` to another user and
back, refused with a wrong password; the Recovery phrase tab showing
it with the password and refusing a wrong one; a user's `passwd` changing their password and the
wallet still opening with the new one; a program without the setuid
mark refused `/etc/passwd` as now.

## 18. `sudo`

Root has no password (item 17): it cannot log in, and `su` cannot
become it. Administration goes through `sudo`, as on most systems now:

- **`sudo COMMAND [ARGS...]`:** the caller's own password asked and
  checked (`pwfind`, `pwok`), then COMMAND run as root, waited for, its
  status `sudo`'s. **`sudo -s`:** a root shell.
- **Who may:** the members of an `admin` group (`/etc/group`); the
  account made at the first boot is one, an account from `adduser` is
  not unless added. Anyone else refused, and the refusal logged.
- **How:** setuid (item 17, Checking a password): `sudo` is owned by
  root and marked, so it runs as root, reads `/etc/passwd` and
  `/etc/group`, and becomes root's child for COMMAND (as `runas` does).
  It trusts nothing from its caller but the typed password: the
  command run by its full path or looked up in a fixed path, not the
  caller's.
- **Remembered for a while:** after a right password, the same user on
  the same terminal is not asked again for 5 minutes, as `sudo`
  usually does; `sudo -k` forgets it.
- **Wrong tries:** each check takes the password's derivation (about
  1.4 s), three wrong ones end `sudo` with a wait, and every refusal is
  logged.
- **A lost password:** with no root password, nothing on the machine
  resets it. The way back is a new disk (`scripts/makenode.sh`) and the
  wallet recovered from its phrase at the first boot; said in the docs
  where the password is set.

**Tests:** in oscheck, the first account's `sudo` running a command as
root (`id` showing root) with the right password, refused with a wrong
one; a second account, not in `admin`, refused with its right one; the
5 minutes taken (a second `sudo` not asking), and `sudo -k` asking
again; `sudo -s` and exit back to the user.

## 19. `node.sh` as a node program, not a QEMU wrapper

`scripts/node.sh`'s options are QEMU's: `--disk`, `--mac`,
`--hostfwd=udp::3737-:3737`, `--smp`, a boot program's path. To run a
node a user has to know QEMU's networking, the guest's ports and which
to forward; the defaults leave the node unreachable (nothing forwarded,
so no peer can reach it and the host cannot reach its API or wm) and on
one hart. It should read like `tabminer`: options about the node, QEMU
an implementation detail.

- **Options in the node's terms**, mapped to QEMU and to the guest's
  `/etc/node/config` by the script:

  | Option | Default | What it does |
  |---|---|---|
  | `--name=N` | none | the instance (item 3): its directory, disk, MAC, ports, config |
  | `--network=mainnet\|dev\|dev-recursive` | mainnet | as tabminer's |
  | `--p2p-port=P` | 3737 | UDP P on the host to the node's p2p port, so peers can reach it; `--no-listen` for outbound only |
  | `--api-port=P` | 3738 | the node's API on the host's `127.0.0.1:P`; `--api-bind=ADDR` to expose it |
  | `--wm-port=P` | 8080 | the desktop on `127.0.0.1:P` (item 17), passed in for the link |
  | `--peer=HOST:PORT`, `--seed=...`, `--no-seeds` | the built-in seeds | as now and as tabminer's |
  | `--threads=N` | the host's cores, up to the kernel's limit | harts (QEMU's `-smp`) |
  | `--datadir=DIR` | `node/data` (or `~/.famnode` once installed) | where instances live |

  `--hostfwd`, `--mac` and the boot program stay, as advanced options.
- **A config file on the host** (`DIR/N/config`, as item 3), the same
  options one a line, so a node started once is started again with
  `node.sh --name=N` or nothing; command-line options override it.
- **Checked before booting:** QEMU present and new enough, the image
  built (or fetched, item 2), the ports free (a tabminer on 3737 is the
  common clash: a clear message naming the port and `--p2p-port`), the
  instance not already running (item 3).
- **A clean stop.** Ctrl-C (or SIGTERM) today kills QEMU at once,
  possibly mid-write of the store. Instead the script asks the node to
  stop (the guest's `/proc/halt` after the node commits, e.g. through
  the API or the console), waits for QEMU to exit, and kills it only if
  it does not within a bound. Item 13's mid-write kill test covers the
  case where this cannot happen.
- **Its output:** the console is the user's (item 17's login), so the
  script's own lines are short and few: the instance, the ports, where
  the log is; the node's log written to `DIR/N/node.log` as well as the
  console, rather than lost in the console's scroll.
- **Help and errors** worded for a node's user (`--help` listing the
  options above, not QEMU's), and a `--version`.
- **Maybe a name of its own:** `famnode` (installed, or a symlink) in
  place of `scripts/node.sh`; the script kept for development.

Not a daemon: the node runs in the foreground of its terminal, as now;
a user who wants it in the background uses their system's means
(`systemd`, `tmux`).

**Tests:** `node.sh --help` and a bad option; a start with a taken
port refused with its message; two instances by `--name` on one host
(with item 3); the forwarded ports reaching the node (a ping on the p2p
port, `/v1/status` on the API); a SIGTERM during a sync leaving a store
that opens at the last committed block.

## 20. Waiting instead of polling: blocks, transactions, payments

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

### Everything else that is polled, or never noticed

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

### The wallet's events to the page

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
