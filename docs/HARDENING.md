# Hardening backlog

Gaps found in the review of 2026-10-31 and not yet closed. Each entry says
where the problem is, why it matters, and the fix as far as it was thought
through. Items are grouped by area and ordered by how much they matter
within the group. The fixes already made from that review (miner size and
timestamp rules, request tokens, per-host peer limits, strike policy, slate
checks, fee policy, dust, blind rows, the dataset checksum) are in the
history and the README; this file holds what is left.

## Progress

Closed in batches since the design docs were built (bb8738c); 56 entries
then, 28 now. Most that remain are accepted, for launch, or tests; some were narrowed rather than removed, and a few narrower ones added:

| Batch | Area | Commit |
|---|---|---|
| 1 | Pool and chain: conflicts by position, reorg relocation, pool kept across restarts, `resend`, unchecked-data marker, wrap-height assert | c00641b |
| 2 | Wallet: password-locked phrase, 0700 directory, cancel undoes name ops, orphaned rewards, payments found after a gap | c00641b |
| 3 | Side channels: constant-time ML-DSA signing, hedged relay key, hourly Kyber rotation | bf39007 |
| 4 | Networking and sync: non-blocking snapshot changes, slow vs unserving peers, fast-sync fallback, clock skew, header retry, serving limits, peer groups | 23f0a39 |
| 5 | Message layer: failing guards replaced, key-mismatched relays avoided, handshake rate, idle hops and cell budgets, keepalives both ways between relays, delivery acknowledgements, wide-block backward layers (protocol 7) | 10b5007 |
| 6 | Wallet and chain: relay keeps only `relay.key`, leaf reuse after a rollback caught from the pool, slate outputs shown as unverified, batched part commits | 28846da |
| 7 | Tests: proofs through `Chain::connect` with the real verifier (stale, tampered, other body), proof tests in the default release suite, zero-knowledge openings counted, fast sync over a lossy network and after a late first peer, garbage datagrams, recovered-output spends through the pool, malformed slates | 84792e7 |
| 8 | CI and what it found: tests on Linux, macOS and Windows (x64, arm64), release with overflow checks, a debug build, the dev feature, the slow tests and the chain constants one job each; binary tests through the prompt (`miner/tests/wallet.rs`: a payment, a name, sub-names through the switch to onion mode, exit while mining, reorganizations); the name circuit's position in 30-bit limbs; Windows (OS randomness, LF checkouts, LMDB without TLS); the miner waits on verified headers only, never a claim; an init-mode "no delegation" not cached; outputs lost to a reorganization hidden, then forgotten; headers ahead of their parent no fault; first pings retried; fast sync and the message layer over lossy and reordering networks; a restored wallet beside its original; fast sync's edge cases (a manifest that does not fit the proof, no snapshot served with and without a peer keeping every block, a reorganization past the snapshot, a heavier branch below the floor), which found an abandoned snapshot falling through to a replay from genesis and such a branch holding the node off its own chain (now set aside, its peers not struck, an announcer asked for the block it announced); crash injection at each step of a payment (`TABMINER_CRASH_AT`, `dev` builds), the change record now written with the reservation, and a send waiting for the wallet's rendezvous session so the answer is not lost after a start | 4830361 on |
| 9 | Scale: `--debug-fill-outputs` (a set of any size made behind genesis, staged a part at a time) and `--debug-genesis-outputs` (its genesis alone, to fast-sync it); a full block on a large set and a fresh node fast-syncing it, as binary tests (`miner/tests/scale.rs`) at 2M outputs every push and 170M nightly on every platform but Windows arm64 (`scale.yml`), timings as `SCALE` lines; found a peer at its serving limit taken for one that does not serve the snapshot (dense parts), now counted slow, and a miner calling its blocks lost when its node took over a minute to apply them (it waits for the verdict now, and hears of a refusal that leaves no record); a miner thread ended for good by a pooled transaction its own last block had spent, before the node revalidated the pool (now a fresh start, and any error restarts the miner); the fill spaces its outputs (one in five by default) and block application is timed phase by phase (`applied in` lines, `SCALE … apply_<phase>_secs`) | 37d5c94 on |

Still to do, as code: the untested paths listed below (the rest of
fast sync's, and of the network's). CI (`.github/workflows/test.yml`) runs the suite in release
with overflow checks on five platforms, a debug build and the `dev`
feature on Linux, and each test marked slow (the proving round trips,
the multi-node and binary tests, the chain constants) as a job of its
own; the proof tests that take seconds are skipped in debug builds.

Not code, or for launch: the independent circuit review, the soundness
conjecture, a checkpoint per release, seeds, genesis regeneration, the
small-VPS and full-size sync tests. Accepted as they are: no coinbase
maturity, PBKDF2, unrecoverable policy outputs, file slates' recipients,
name parts checked at the end (a design change), side blocks stored
before their proofs, the shared leaf/node hash domain, IPv4 only. Open but not
planned: pricing unnamed slates (a fee or proof of work per slate).

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
- **Untested paths.** No test for: the `drop_carry` path; a deferred
  move or restart while parts are with the applier; the header batch
  retry; clock-skew logging; strikes leading to a ban at node level;
  peers-file poisoning; NAT. (Tested: loss and reordering, a fast
  sync and the message layer with a tenth of datagrams lost or almost a
  third delivered after the next; a manifest that does not fit the
  snapshot block's proof; no peer serving the snapshot, with a peer
  keeping every block (validated from genesis) and without (kept
  trying); a reorganization past the snapshot during the sync; a heavier
  branch forking below the floor after the install.)

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
- **Tested through the binary** (`miner/tests/wallet.rs`): a
  reorganization's lost rewards and payments; a restored wallet finding
  and spending beside its original; a crash after the inputs are
  reserved, while the answer is signed, and after it is signed but
  before the pool has it (`cancel` frees the first two, `resend` sends
  the third).

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

Found while building it (2026-11-01).

- **ML-DSA signing is constant-time as far as checked.** `mldsa.rs`:
  reductions, `centered`, `decompose`, `make_hint` and the norms are
  branchless (mask arithmetic, divisions by constants), every check of an
  attempt runs in full and the attempt is accepted or rejected once; the
  relay key, which signs whatever anyone asks, signs in FIPS 204's hedged
  mode (fresh randomness per signature), the wallet's identity key
  deterministically. The x86-64 code (rustc 1.95, release) has no
  hardware divide in ML-DSA, ML-KEM, Keccak or ChaCha, and the one
  data-dependent branch in an attempt is the final accept/reject, with
  the maxima as `cmov`. What remains:
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

- **Flow control is a budget, not a window.** `node/circuits.rs`: a
  hop ends a circuit whose client sends more than 1024 cells at once or
  128 a second after, and drops hops idle for an hour; cells toward the
  client are not limited per circuit (a sender flooding a recipient is
  bounded by the slate limits). A per-circuit window (Tor's SENDME)
  would pace rather than cut.
- **A lost acknowledgement duplicates a payload.** A recipient's point
  reports a delivery offline when `Received` does not come back within
  5 s, and the sender's point tries the recipient's next point; if the
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
## Features deferred

- Cover for the address a transaction is first sent from, in init mode:
  onion mode hands it to a relay over a circuit (`docs/ONION.md`,
  enhancement 1), but in init mode the node announces it itself.
