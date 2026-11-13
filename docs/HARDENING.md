# Hardening backlog

Known gaps not yet closed, as a fresh list (2026-11-12): what has been
fixed is in the history (the review of 2026-10-31 and the batches since,
up to `adf2c3f`), not here. Each entry says where the problem is, why it
matters, and the fix as far as it was thought through. Items are grouped
by area and ordered by how much they matter within the group.

Not code, or for launch: the independent circuit review, the soundness
conjecture, a checkpoint per release, seeds, genesis regeneration, the
small-VPS and full-size sync tests. Accepted as they are: no coinbase
maturity, PBKDF2, unrecoverable policy outputs, file slates' recipients,
name parts checked at the end (a design change), side blocks stored
before their proofs, the shared leaf/node hash domain, IPv4 only. Open but
not planned: pricing unnamed slates (a fee or proof of work per slate).

## Consensus and chain

- **No coinbase maturity, by decision.** A reward can be spent in the
  next block; a reorganization then invalidates the whole chain of spends,
  which only the shelf can rescue. Left to mining pools to hold back
  payouts. A consensus rule would have to go in the circuit (a
  fast-syncing node could not check it otherwise); a pool policy (do not
  pool a spend of an output younger than N blocks) remains an option.
- **Side blocks are stored without proof verification.** `chain.rs`,
  `apply_block`: a block with valid proof of work on a side branch is kept
  (header and up to 2 MB body) and served to peers before its proof is
  checked. Bounded by the work needed to make one; bodies are pruned at
  the window edge. Accepted: the proof's statement needs the block's
  first output position, which the header does not carry and only
  executing the branch gives. Noted so nobody relies on a stored body
  being valid.

## Networking and sync

- **Fast-sync name parts are checked only at the end.** A name part's
  hash in the manifest is not bound to the state root, so a lying peer's
  manifest is found out when the rebuilt trie's root fails the final
  check, after every part is fetched; the install then restarts. Output
  parts fail per part. Fix: verify a sample of each part's records by
  trie proof against the name root as they arrive, or have the manifest's
  part hashes cross-checked among peers before fetching.

- **A whole part cache miss costs a 1.2 MB encode.** `snapshot_bytes`
  keeps `SERVED_SNAPSHOTS` (64) parts; a node serving several fast syncs
  at once re-reads and re-encodes parts it dropped. Serving is otherwise
  bounded: chunks come from shared cached bytes, and each peer is served
  at most 8 MB/s (`SERVE_RATE`). Fix if it shows: a larger cache while
  serving many.

- **Eclipse resistance rests on the two seeds.** The peer table takes
  at most 8 entries per network group (a /16) and 4 per host, so one
  network cannot fill it. IPv6 is not supported, by decision: its
  addresses are cheap in bulk, which would weaken the group limit, and
  every node and seed has IPv4; an IPv6-only host cannot run a node. Still to do once the chain is
  live: hard-code a checkpoint or an `assumevalid` header hash per
  release.
- **Sync peer usage: tabminer and the fam node not reviewed together.**
  Which peers each asks for headers, blocks, snapshot parts and proofs,
  and how the load is spread: tabminer samples live peers at random
  (`PeerTable::sample`), seeds among them, and never bans a seed; the fam
  node fetches from one peer at a time, its catch-up by batches (NODE_
  ENHANCEMENTS item 21) from up to 16 at random, peers that are not seeds
  first. To review both: the same rules (seeds last, random among the
  rest, a failed or slow peer replaced), and the seeds not carrying
  every node's sync. Tabminer left as it is until then.
- **Untested paths.** No test for: the `drop_carry` path; a deferred
  move or restart while parts are with the applier; the header batch
  retry; clock-skew logging; strikes leading to a ban at node level;
  peers-file poisoning; NAT.

- **The fam node checks a body's commitment slowly: about 1 s a block.**
  A batch of 16 (NODE_ENHANCEMENTS item 21) spends about 17 s fetching
  and checking its bodies against their headers, against 2 s for its one
  chain proof (mainnet, 2026-11-13). The commitment is consensus's
  Poseidon2 (`Body::commitment`, `proof_hash`): the body's roughly 205 KB
  chain proof packed 3 bytes a field element (about 70,000) and absorbed 8
  at a time, about 8,700 permutations, at about 41 µs each under QEMU
  (0.35 s), the packing and Montgomery conversion in fam words besides
  (`state.fam`'s `bcommit`, `pow.fam`'s `pack3`). To do: time the parts;
  one assembly-level word that packs, converts and absorbs straight into
  the sponge (as `perm16`), with no 270 KB buffer (about half the time
  expected); bodies checked on several harts once the multi-hart slowdown
  (item 4) is understood.

## Wallet

- **Unnamed slates share one answering limit.** A wallet answers at most
  5 slates per sender and 60 in all per ten minutes (`onion::SlateLimit`);
  an unnamed sender (the default, `docs/PRIVACY.md` fix 4) cannot be told
  from another, so a flood of unnamed slates uses up the 60 and honest
  payers wait. A small fee or proof of work per slate would price it.

- **A payment that lands and is spent while the wallet is far behind gets
  no proof.** After a gap (a fast sync, a long time offline) `sync_wallet`
  finds payments' outputs in the UTXO set by commitment and memo
  (`find_payments`); one the recipient already spent is not there, and
  `payments` says "not in a block yet". Fix: keep an index of spent
  outputs' commitments within the undo window, or ask the recipient.
- **A file slate's recipient is whoever signs its receipt.** Over the
  message layer the receipt must be the id the slate was sent to; a file
  slate has no such id, so `finalize` prints the receipt's address and the
  user must check it is the one meant. A recipient who gives the sender a
  wrong address gains nothing (the coins go to its output either way),
  but the proof then names that address.

- **Policy outputs are not recoverable from the seed.** A multisig,
  HTLC or channel output is found again only from the policy the parties
  agreed, which the wallet stores (`policies` table); a wallet restored
  from its phrase alone has none of them. This is the Lightning
  situation and a reference wallet accepts it. Fix for user wallets:
  back up channel state with the counterparty or a watchtower, or derive
  shared memos the wallet can scan for and fetch policies from the
  counterparty.

- **The wallet password's key is PBKDF2, not memory-hard.** 200,000
  rounds of HMAC-SHA512 (about a quarter of a second) cost a GPU attacker
  holding the wallet directory little per guess; a weak password falls.
  Argon2 would cost more per guess. Only the phrase and seed are
  encrypted: outputs, nonces, payments and names are readable from the
  directory (a privacy loss, not a theft), as is a `--password-file`.
- **A wallet-directory rollback is caught only through the pool.** After a
  backup restore or a VM snapshot the wallet may take a used leaf for
  unused; before every command it skips leaves that pooled spends of its
  outputs signed from (`observe_signatures`). A cancellation that left
  the pool (replaced, expired, or never seen by this node) is not caught.
  The rest would need a leaf-use journal outside the directory.
- **Two restored copies share leaves 8 to 15.** Each starts at a random
  leaf, so two copies spending the same output collide with probability
  1/8 on their first spends, as the module doc admits; a copy that sees
  the other's spend pooled skips its leaf (above). Document; or derive
  the start from something both copies agree on only when they are the
  same copy (a per-restore random salt stored on chain in the first spend's
  memo).
- **A message to a wallet just started can be lost.** Until its new
  session is live, its rendezvous point may still hold the session of
  the process before and pass a message there. A send now waits for the
  session, so an answer to it is not lost; a slate someone else sends
  in that window is (the sender's slate stays pending until cancelled).
  Fix: a rendezvous point holds messages for a session whose datagrams
  stopped until the new one takes over, or end-to-end acknowledgements.
## Proof system

- **The circuit has not been independently reviewed.** Fast sync trusts
  the chain proof for ownership, the state's history and names; nothing
  replays history to catch a circuit bug. The supply no longer rests on
  it: amounts are public and every node, fast-synced or not, checks that
  the unspent amounts sum to what was issued (`docs/AMOUNTS.md`). A
  circuit bug could still let someone spend outputs that are not theirs,
  but not mint unseen. This is the largest remaining trust gap. `block_air.rs` (SMT
  empty-leaf handling on insert, XMSS digit decomposition, carry between
  segments) was only spot-checked in the review.
- **What the circuit audits leave.** The freedom audit
  (`stark::freedom_audit`, `run_audit`), the rule-by-rule attacks
  (`stark::refuse`, `broken_rules_are_rejected_by_the_constraints`,
  `broken_name_rules_are_rejected_by_the_constraints`), the comparison
  with the chain on random blocks and the fuzzers are done and run in CI;
  their limits are what is open:
  1. Freedoms that span rows of different types are not searched (the
     audit works within a row type's row pairs).
  2. Each attack checks the trace a cheater would naturally write, not
     every trace for it.
  3. The verifiers' field sweep changes one `u32` at a time; failures
     that need several fields changed together are left to reading and
     random mutation.
- **Zero knowledge is argued, not simulated.** `zero_knowledge_tables`
  checks that two proofs differ and counts what a real proof opens of a
  column against the blinding rows; `zero_knowledge_configurations_blind_enough`
  checks every zk configuration in use. No test simulates a proof from
  the statement alone.
- **Leaf hash and node compress share a domain.** `poseidon2.rs`:
  benign because every verifier fixes the path length. Accepted: a tag on
  `compress` would change every circuit, the built-in mainnet plan and
  genesis.
- **Soundness rests on the ethSTARK conjecture at |K| = 2^123.6**; the
  near-capacity failures of 2026 are acknowledged in SECURITY.md, with
  margin left. Revisit when the constants in those results are known.

## Message layer

- **With few relays listed, guards are most of them.** With three relays
  every relay is everyone's guard, rendezvous point and last hop: the
  privacy fixes take effect with tens of relays, not three.


- **ML-DSA signing is constant-time as far as checked** (x86-64, rustc
  1.95: branchless reductions, no hardware divide, the relay key signing
  in FIPS 204's hedged mode). What remains:
  1. **riscv64 not inspected.** Check the generated code there once
     (`cargo rustc --release --lib -- --emit asm`, look for `div`/`rem`
     in `mldsa`/`mlkem` and for branches in `SecretKey::sign`).
  2. **The compiler may change its mind.** Nothing pins the branchless
     source to branchless code; a new rustc could turn a mask back into a
     branch. Re-check on toolchain upgrades, or add `core::hint::black_box`
     barriers.
  3. **What FIPS 204 lets show.** The number of attempts, and
     `sample_in_ball`'s rejection sampling on each attempt's challenge
     (public for the accepted attempt, a function of the masked `w1` for
     the rejected ones).
  4. **Keep the handshake limits.** The per-host caps on channels
     (`node/channels.rs`, 32 a host, unused ones closed after 15 s) slow
     the collection of samples; a rate per host would slow it more.

- **Timers: liveness, waits, polling.** A relay closing a channel still
  handshaking without telling the other end (the lossy onion tests'
  flake), a dead relay taking 30 s however fast the link, and the rest
  of an audit of every timer in tabminer and the fam node and wallet:
  `docs/TIMING_FIXES.md`.
- **Flow control is a budget, not a window.** `node/circuits.rs`: a
  hop ends a circuit whose client sends more than 1024 cells at once or
  128 a second after, and drops hops idle for an hour; cells toward the
  client are not limited per circuit (a sender flooding a recipient is
  bounded by the slate limits). A per-circuit window (Tor's SENDME)
  would pace rather than cut.
- **A lost acknowledgement duplicates a payload.** A recipient's point
  reports a delivery offline when `Received` does not come back within
  30 s, and the sender's point tries the recipient's next point; if the
  payload did arrive, the recipient may get it twice. Harmless for
  slates: a stage-1 slate is answered twice, the sender finalizes the
  first answer and refuses the second, whose output `prune` removes.
- **A wallet on a relay skips that relay as a rendezvous point,** in
  both modes, so it is reachable only through its other points (with one
  seed, not at all). By design: run relays with `--no-wallet`.

- **Windows writes are slow.** On GitHub's Windows arm64 runners a 20M
  output set took 987 s to store against 36 s to compute, its fast sync
  26 minutes, a full block 2 to 4 minutes (Windows x64: 22 s a block;
  Linux: 7 s). Defender scanning the database file is the first suspect:
  `scale.yml` excludes the data directory to tell. If that is it, the
  README should tell Windows operators to exclude theirs; if not, LMDB's
  file growth and flush on Windows is next.
- **Fast sync's time follows the parts, not the bytes.** With outputs
  one in five positions apart, 2M outputs take 621 parts and 30 s locally
  against 17 s for 133 dense parts, with a slow tail. Suspects: the
  syncing node's commit per part, and 32 part downloads starving each
  other at one peer's serving limit (they could be paced to it).

## Deployment and operations

- **Seeds** need the current binary at every format change (now protocol
  10, chain format 14, wallet format 8, slate format `tabslt05`), started
  with `--relay`, and wiped data directories. Fresh nodes cannot sync
  until then.
- **Genesis regeneration at launch**, with `--hashrate` set to the
  expected network rate (README, Genesis).
- **Single-core and small-VPS tests.** Dataset build on one core is about
  six minutes, during which headers are checked at 30 ms each; on a 1 GB
  machine a 12 GB state lives on disk and each full block is bound by
  random-read speed.
- **A real 170M-output fast sync**: the nightly `scale.yml` measures one
  on GitHub's runners (one peer, so bound by its 8 MB/s serving limit);
  the seeds' VPS still to be measured the same way.
- **The fam node's heap reserve is a guess** (`connect.fam`'s `stinit`,
  from `adf2c3f`): 32 MiB `malloc`ed and freed at start, so its arena
  holds the heap within a process's 4 map slots (small arenas from
  64 KiB would fill them at about half a MiB). With no MMU it is physical
  memory, kept for good (the last arena is never unmapped): of about
  121 MiB free in the 128 MiB machine, the node's start region 24, this
  32, the store's cache 16, `nodev` 8, each wallet 8, leaving about 33
  with one wallet. It fits (paytest, onitest), but was never measured.
  Fix: the node's peak heap measured (a fast sync with a snapshot, a
  full block, a full pool, the worker's copy of the state's buffers),
  the reserve that and a margin; or the reserve folded into the start
  region, which takes no map slot. Likely a few MiB, the rest back to
  the store's cache and wallets.
## Features deferred

- Cover for the address a transaction is first sent from, in init mode:
  onion mode hands it to a relay over a circuit (`docs/ONION.md`,
  enhancement 1), but in init mode the node announces it itself.
