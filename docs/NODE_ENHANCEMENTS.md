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

Progress:

- (2026-11-12) Threads with variables of their own (`pthread`,
  `docs/OS.md`), for the worker that will connect blocks: one process,
  each thread with its own copy of fam's variables.
- (2026-11-12) The API answered while a block, a snapshot's manifest or
  part, or a relayed transaction is fetched (`sync.fam`'s `nfetch`:
  `pfetch` stops when a connection waits and goes on after), and
  `/v1/status` says what the node is doing (`activity`). Checked by
  `scripts/stalltest.sh`, timing-free: a proxy holds a block's chunks,
  and the API, asked meanwhile, must say the node is fetching it.
- (2026-11-12) The API from the start (item 6).
- (2026-11-12) A worker thread (`sync.fam`'s `cwstart`) connects and
  undoes blocks: the body decoded and its commitment checked, the state,
  the chain proof (checked there, not by `nodev`), the store's writes and
  commit, while the node serves (`cwait`). It makes its own copy of
  every buffer `sconnect` and `sundo` reach (traced: 286 words, some 80
  buffers; `cwinit`), sharing only tables that are read (the squares,
  the empty subtrees' hashes, the chain's constants, the verifier's
  program, genesis's mix); undoing is the worker's too, as the manifest
  keeps the last block's parts between blocks. Its heap: 1.8 of 3 MiB.
  Checked by `reorgtest.sh` (blocks connected, the node killed and
  resumed, four blocks undone onto a heavier branch) and `stalltest.sh`.
- (2026-11-12) A fast sync's snapshot by the worker too: its manifest,
  S's chain proof, each part and the whole (`nsnman`, `nsver`,
  `nspart`, `nsfin`), the snapshot's state the worker's from first to
  last. Found on the way: the pool reads what `sconnect` leaves of the
  block (`bout`, `bnout`, `sfirst`; `qconfs`, `qmvblk`), which were the
  worker's copies; the worker now hands them back.
- (2026-11-12) The next block fetched while the worker connects one
  (`npfetch`, `nbget`). A mainnet catch-up (the 144 blocks after a fast
  sync's S) went from about 4.5 s a block to 3.3 s, the fetch hidden.
  More harts were slower, not faster: 8 min on one, 8 min 50 s on two,
  10 min 45 s on four, the worker's proof checks 20 to 50% slower beside
  idle harts. `node.sh` stays at one hart until that is understood:
  suspects are the kernel's lock (one for the whole scheduler), PMP
  reloads by software interrupt on every hart running the process when
  `malloc` maps or unmaps (the fetches allocate per block), and QEMU's
  multi-threaded TCG itself.
  Left: the pool's recheck after a block (`qcheck`, `qreturn`); API
  requests answered one at a time; blocks' chunks not served to peers
  while the worker has a job (`pnest`, kept from the single thread).
- (2026-11-13, `docs/TIMING_FIXES.md` items 2, 3, 7 and 16) The short
  waits for headers and a first ping are waits to a deadline through
  others' datagrams (`pwaitc`); the node's upkeep (pings, relay, the
  API's long polls: `pkeep`, `nrelay`, `awake`) goes on while it waits
  on the worker, `nodev` or a fetch; each API request has a deadline and
  its writes do not block; the loop sleeps to its next deadline
  (`nnext`), not a fixed turn. Still left from the list above: the
  pool's recheck, API requests one at a time, chunks not served while
  the worker has a job.
- (2026-11-13) The probe (step 1): the node times its own loop, from
  each point the API can be answered (`aaccept`, or a wait watching its
  listener) to the next (`p2p.fam`'s `pmark`); each hold over a second
  is logged ("the loop held N ms (height, activity)"), the longest given
  by `/v1/status` (`stall_ms`, `stall_height`, `stall_activity`), and
  `nstep`'s steps over a second are named (`nslow`: following the peers,
  relaying, announcing the pool, saving it, the consensus scan). For
  finding stalls, never asserted; it changes nothing the node does.
  Its first numbers, a fresh mainnet node: 6.2 s saving the headers to
  S (`nsave`, on the loop); 3.4 to 5.1 s of every 10 s in the consensus
  scan once synced; about 10 s for each page of 1,000 outputs a scan
  asks for from the host (the answer written 512 bytes at a time).
- (2026-11-13) A hang found with it, in the kernel: the node answering
  a request its wallet had given up on (12 s) wrote to a connection the
  wallet had closed; the closed side kept the bytes, unread, until its
  ring was full, its window stayed 0, and the node's write waited for
  good (a scan's page of outputs is far more than the 12 KiB the two
  rings hold): the node served nothing more, the wallet "cannot reach
  the node". Bytes for a socket whose descriptors are closed now reset
  the connection (`net.fam`'s `cother`), so the write is refused
  (oscheck's `tcp_loop`). Not covered: a peer on another machine that
  goes silent with its window at 0 (no persist timer, no deadline on a
  write under way).

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

Progress (2026-11-13, `docs/TIMING_FIXES.md` item 15): the wallet tells
the page as things happen, so the progress is known: an online send's
steps (`payment` events with `step`: sent, delivered, unanswered,
undelivered, finalized, answered), a payment's fate (pooled, replaced
and by which, evicted, mined, conflicted, back), a name's (its commit
old enough to reveal, revealed, owned, offered, transferred), a scan's
height. The page shows each in the strip (one line, the last). Left:
the spinners and disabled buttons, progress on the Activity entry
rather than the strip, and the wallet's own long work in steps.

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

**Done (2026-11-12), but for the two-seed test:** the node starts its
socket and API before anything else (`main.fam`), whatever its height;
a first sync that stops for any reason is tried again every 30 s while
serving (`sync.fam`'s `nidle`; the store made afresh if the sync had
written to it), and a node that found no peer looks for the
configuration's peers and seeds again each time (`mfind`), taking any
peer that pinged it meanwhile. Checked by `scripts/stalltest.sh`: the
node started before the miner's first block answers `/v1/status` at
height 0, then syncs on its next try.

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
**Done (2026-11-13, 4e96e9c), but for the refusal:** the two had parted
both ways (these screens only in `wm.fam`, TIMING_FIXES' phase 4 events
only in `wm.html`, never served: oscheck's wallet check failed on it);
`wm.html` now holds both and `wm.fam` is made from it. `wmpage.py`
refuses a `//` comment (the page is joined into one line), not yet a
`wm.fam` edited by hand.

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

The node's own states (not reached, starting, syncing, no peers) are
item 22.

Progress (2026-11-13): the strip no longer shows "Tip N": a block event
shows "Synced to height N", the node unreached "Cannot reach the node;
trying again in N s", and item 5's steps. Still one line, whatever came
last; the model above is not built.

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
   where the send was made. (2026-11-13: the send's steps now come as
   events, item 5, but still only to the strip, replaced by the next.)

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
11. **Overview's "Online" line** is jargon ("reachable: sessions at 3
    of 3 rendezvous points" since 2026-11-13, a session at each point).
12. **Settings is unclear.** "Show the phrase" asks for "Password"
    without saying which one; Restore sits just below with no warning
    that it replaces this wallet; "Scan again" is under Restore, with no
    word of what it does; a phrase shown stays on the screen.

### Behavior

13. **Any event redraws Overview or Activity:** an open proof closes,
    the scroll goes back to the top, and a form being typed in is wiped
    when the unlock event comes. (2026-11-13: a block event redraws
    the open panel from the event's own values, no request, and the
    node's, names' and payments' events only set the strip; a payment
    event and a message still redraw Activity whole, the unlock event
    the window.)
14. **Some speeds cannot be chosen:** Bump always pays for "block",
    Reveal and Update for "hour", while Commit has a menu.
15. **A name is revealed by hand:** the user must come back 12 blocks
    later and press Reveal. The wallet could reveal it when ready, if
    the user agreed at the commit. (2026-11-13: the wallet tells when
    it is ready, a `name` event "reveal it now"; the reveal is still by
    hand.)
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

Progress (2026-11-13, `docs/TIMING_FIXES.md`): the groundwork, not the
item. A peer is given up by its silence (channels 30 s, peers 65 s),
never by a short floor: a slow or throttled machine, or a peer busy
for seconds, is not taken for dead (`a_busy_relay_keeps_its_channel`,
`busy_relays_keep_the_standing_circuits`); a node stopping says so
(goodbye) and one killed is noticed by its silence
(`a_node_killed_is_noticed_by_its_silence`); a relay's goodbye takes it
out of new paths at once. Pauses by `SIGSTOP` run in imagetest and
paytest (tabminer stopped and resumed). Not tried: sleep and wake, the
clock across a sleep, the network changing, power lost, a full disk.

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

Moved to `docs/TIMING_FIXES.md`, section 2 (2026-11-13), with the rest
of the work on timers, polling and explicit signals.

## 21. Catching up by batches: one proof checked for 16 blocks, before they are applied

Catching up after a fast sync (the 144 blocks after S) or after time
offline, the node connects each block with its chain proof checked:
about 2.5 s of 3.3 s a block on mainnet (with the next block fetched
meanwhile), so 144 blocks take eight minutes, most of it proofs.

Neither every header's full proof of work (2.2 s each, natively) nor
every block's proof is needed. A block's chain proof binds its parent's
header (its hash is among the proof's public values, NODE.md's "the
chain proof binds the headers"), attests its parent's work (the true
`mix`), and is recursive: block B's proof attests B and every block
before it, and the work of every header before B. The header sync has
linked the headers by their parents' ids, each one's quick proof of
work checked (two permutations), and the tip's full proof of work
checked natively (as the fast sync does today: 5.3 s on mainnet). So
once B's proof passes, connecting a block up to B needs only the checks
made today besides its proof: its body matches its header's commitment,
and applying it gives its header's state root. The root commits to
every output and name, so a body that lands on an attested root gives
the true state: no forged spend or payment can be shown. The proof is
checked first, so no block is applied, shown, announced or served
before it is attested, and nothing is ever undone.

**An honest block cannot be spoiled by the peer serving it.** The
header's body commitment covers the chain proof too (`bcommit` packs
`bpr`), so a wrong body or a wrong proof for an honest header fails the
commitment check as it is fetched: its sender banned, the block fetched
from another, no proof checked. A batch's proof fails only on a branch
that is itself invalid; a peer can lead the node onto one only by its
headers, and the branch's tip needs a full proof of work at the current
difficulty to be the best header: a real block's work for each try.

**A batch** (n blocks, n = 16: 144 blocks are 9 proofs, about 23 s
against 6 minutes; 32 would save about 10 s more, but show progress in
steps twice as long and download twice as much of a bad branch):
1. **The bodies:** fetched (as now, the next while one is handled),
   each one's commitment checked against its header (the worker's
   `sbody`, the next block fetched meanwhile), its outputs counted, held
   in memory (a batch is cut short at 8 MiB), so none is served. Each
   one's sender recorded.
2. **The proof of the batch's last block B,** once. Its public values
   need the output counter before B: the counter at the batch's start
   (S's from the snapshot, or the state's) plus what step 1 counted
   (each block's outputs and its names' operations of type 1, as
   `sconn1` and `sverify` count), and B−1's header given to `sstmt`
   (`spar`) rather than read from the store (`sbproof`).
3. **The blocks connected** from disk, in order, up to B−1: parsed, the
   state changed and its root compared, stored; no proof, no commitment
   again. Each is shown, announced and served as it is connected. B's
   validity is attested but its own work is not (its proof attests its
   parent's), so B is held and connected as the first block of the next
   batch, whose proof covers its work; the last batch ends at the tip,
   whose work is checked in full, and the tip is connected with it.

**The peers serving a batch:** up to 16, one block from each, chosen at
random among the live peers at or above the batch's height (as
tabminer's `PeerTable::sample`: a partial shuffle, not the table's
first), peers that are not seeds first, seeds only to make up the
number (or when no other answers). One bad peer then serves at most one
block of a batch, the seeds are spared the load of every catch-up, and
no peer can count on serving a given block. A block whose peer does not
answer in time is asked of another of the batch's peers. (Neither the
node nor tabminer has this rule yet: the node fetches from one peer at
a time; tabminer samples live peers at random, seeds among them, and
never bans a seed, which here is only passed over for the batch.)

**A batch whose proof fails:** a block in it is invalid. Bisected:
the proof of the middle block checked, then of the half's middle,
and so on (each proof attests everything before it), so the first bad
block is found in four proofs for 16 (about 10 s); the blocks before it
connected; from the bad block on, each block connected as before, its
proof checked (so the verdict is always today's code's, and a fault in
the batch's counting costs time, never a valid block); the block refused
and every header after it on its branch marked invalid, so the best
header falls back to the honest branch. Banned at once (`pban`; nothing
honest is refused, as above): the block's sender (an honest node serves
only bodies of blocks it has connected) and, for a failed proof, the
peer that gave the branch's headers. Seeds are never banned (as
tabminer): passed over for the batch. The next batch is fetched
and checked as usual, so a few bad peers cost a few batches, then are
gone. **If a root does not match in step 3** (a fault of ours: the proof
passed on other data), the batch stops there and is connected block by
block, each proof checked as today.

**Only while catching up:** a batch is formed when 2 or more blocks are
behind; a shorter last batch as the tip is reached; every block at the
tip checked on its own, as now.

Expected: about 1.3 s a block (the body about 1 s, the state, the
store) and 2.5 s a batch: about 3.5 minutes for 144 blocks against 8.
The bodies' commitments could later be checked on several harts (item
4's measurements first).

**Memory:** a batch's bodies are small on mainnet (about 250 KB a
block, the chain proof most of it); a batch is cut short once it holds
8 MiB, so 2 MB blocks make batches of four (item 14's large blocks to
try it).

**Tests:** a clean catch-up, a proof a batch, its time against block by
block; a branch forged from its fifth block (its tip with real work): the
batch bisected to the fifth, the four before connected, the headers'
peer and the bodies' senders banned, the honest branch followed after,
the wallet never shown the forged state; a wrong body or proof for an
honest block: refused as fetched, its sender banned, fetched from
another; the counter right across blocks with name operations (wrong,
the batch would fail and be bisected).

**Built (2026-11-13):** `sync.fam`'s `nrun` (both the fast sync's
blocks after S and `ncatch`), `connect.fam`'s `sbody` and `sbproof`,
`proofs.fam`'s `spar`, `p2p.fam`'s `pban` and the seeds' addresses
(`psdadd`, `pisseed`). Left: the forged-branch test, a large-block try.
**Lite blocks (2026-11-13):** a batch's blocks but its last are fetched
without their proof (`Kind::Lite`: the header, the body up to its proof,
the proof's 32-byte hash, which the body commitment binds), so a batch
moves about a proof's size per block less (16 blocks: 24.3 s to 5.6 s on
the dev network); a lie in a lite block fails the commitment, its sender
banned, the block asked of another (`litetest.sh`). Protocol version 1.

## 22. The wallet tells what the node is doing

(The connection's timeouts, retries and the node's state as events:
`docs/TIMING_FIXES.md`, section 2; this item keeps what is shown.)

The wallet's status says "synced" whenever the node answers
(`nodeok`: the last request to the node had an answer), so it says
"synced" all through a sync, even with the node at height 0 and a long
chain ahead; and a node it cannot reach shows only as "not reached" on
the Overview, nothing in the strip.

- **The wallet started before the node is synced,** or before the node
  is up (they start in any order): the states told apart and shown in
  the strip (item 9's model):
  - **cannot connect to the node:** no answer; tried again every few
    seconds (5 s, then up to 30 s while it keeps failing), the time of
    the next try shown; not an error in Activity each time;
  - **the node starting:** it answers but has no tip yet (loading its
    headers, finding peers);
  - **the node syncing:** headers (its best header's height), the fast
    sync's snapshot (parts of the total), then blocks ("Catching up:
    block 1,204 of 1,310"), from `/v1/status` (its height, best header,
    activity); the wallet's balance shown as of that height, marked not
    final;
  - **the node with no peers:** it answers, but has none to sync from;
  - **ready:** the node at its best header and peers to hear from.
- **What the wallet does meanwhile:** no scan until the node is synced
  (or a scan to the node's height, again as it moves); sends refused
  with the reason ("the node is still catching up"), not attempted.
- **Tests:** the wallet started first, then the node: "cannot connect"
  then syncing then ready; the node stopped under an open wallet:
  "cannot connect", and back to ready when it returns; a long sync with
  the wallet open the whole time, its state right at each step.

Progress (2026-11-13, `docs/TIMING_FIXES.md` items 4 and 15): the
connection is done. Each request to the node has a 12 s deadline; the
block thread waits on `/v1/events` and, the node not reached, tries
again after 5 s, doubling to 30 s, the page told "Cannot reach the node;
trying again in N s", then "The node reached again"; a busy or stopped
node no longer freezes the window. The node sends `status` events
(synced, syncing with its best header's height, no peers). Left: the
wallet showing them (Overview still says "synced" whenever the node
answers, `wovf`'s `nodeok`), "starting", the catch-up's progress, and
what the wallet does meanwhile (no scan, sends refused with the reason).
