# Hardening backlog

Gaps found in the review of 2026-10-31 and not yet closed. Each entry says
where the problem is, why it matters, and the fix as far as it was thought
through. Items are grouped by area and ordered by how much they matter
within the group. The fixes already made from that review (miner size and
timestamp rules, request tokens, per-host peer limits, strike policy, slate
checks, fee policy, dust, blind rows, the dataset checksum) are in the
history and the README; this file holds what is left.

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
  the window edge. Acceptable; noted so nobody relies on a stored body
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
  at most 8 entries per network group (a /16, or a /32 for IPv6) and 2
  per host, so one network cannot fill it. Still to do once the chain is
  live: hard-code a checkpoint or an `assumevalid` header hash per
  release.
- **Untested paths.** No test for: a reorganization past the snapshot
  during a fast sync; a reorganization below the floor after install; the
  "no peer serves" and `drop_carry` paths; the bad-manifest path; the
  genesis fallback and "keep trying" paths of `restart_snapshot`; a
  deferred move or restart while parts are with the applier; a fresh node
  going back to fast sync when its first peer appears after 10 s; the
  header batch retry; clock-skew logging; any lossy
  or reordering network (every test is clean loopback); strikes leading to
  a ban at node level; malformed datagrams reaching the node; peers-file
  poisoning; IPv6; NAT.

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
- **A wallet-directory rollback reuses XMSS leaves** (a backup restore, a
  VM snapshot) and nothing detects it. Inherent to few-time signatures;
  the README should warn loudly, and the wallet could keep a leaf-use
  journal outside the directory (or refuse to sign when the chain shows a
  signature from a leaf it believes unused).
- **Two restored copies share leaves 8 to 15.** Each starts at a random
  leaf, so two copies spending the same output collide with probability
  1/8 on their first spends, as the module doc admits. Document; or derive
  the start from something both copies agree on only when they are the
  same copy (a per-restore random salt stored on chain in the first spend's
  memo).
- **A fake stage-1 slate inflates the recipient's pending balance** until
  pruned: `receive_slate` trusts `slate.amount` and the inputs. Expected of
  a slate design; show "unconfirmed, unverifiable until it lands" rather
  than counting it, or verify the inputs against the UTXO set when the
  recipient's node has it. Over the message layer an online wallet
  answers stage-1 slates by itself, at most 5 per sender and 60 in all per
  10 minutes (`onion::SlateLimit`): a sender with many ids still gets 60.
- **Minor.** `wallet.rs`: `send` writes the change record in a separate
  transaction before reserving the inputs, leaving an orphan record on a
  crash between them (`prune` removes it).
- **Untested.** The `sync_wallet` fork walk and stale positions after a
  reorganization; crash injection between the steps of `send`;
  concurrent original and restored wallets; the restore-scan thread;
  pool acceptance of a recovered-output (leaf 8 to 15) spend end to end;
  `Slate::from_bytes` on malformed input beyond the stage and change
  bounds. There are no integration tests (`miner/tests` does not exist).

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
- **Negative end-to-end tests are all `#[ignore]`.** No non-ignored test
  pushes a tampered chain proof (wrong statement, height, plan membership,
  stale proof) through `Chain::connect` with the real verifier. Add a
  small-parameter configuration that proves in seconds so these can run in
  the default suite.
- **Zero knowledge is argued, not tested.** `zero_knowledge_tables` only
  checks that two proofs differ. A simulatability test is hard; at least
  check that the number of opened values per column is below the blind
  rows for every configuration with `zk`.
- **Leaf hash and node compress share a domain.** `poseidon2.rs`:
  benign because every verifier fixes the path length, but a domain tag
  on `compress` costs nothing.
- **Soundness rests on the ethSTARK conjecture at |K| = 2^123.6**; the
  near-capacity failures of 2026 are acknowledged in SECURITY.md, with
  margin left. Revisit when the constants in those results are known.

## Message layer

- **Guards are not replaced for failing.** A guard whose channel fails is
  passed over for five minutes and tried again; one that fails for days
  stays a guard until its time is up or it leaves the list, its circuits
  starting at other relays meanwhile. Tor drops a guard that has been
  unreachable for a while; doing so here needs a record of failures over
  time, kept with the guards.
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

- **A relay whose key does not match its listed id is not penalized.**
  `node/channels.rs`, `on_reply`: a handshake that fails with `WrongKey`
  is logged and the channel dropped, but the address takes no strike,
  since the client's consensus file may be the stale one and the address
  an honest chain peer. A relay at that address can make clients retry
  it forever. Fix: remember the (address, expected id) pair as failed for
  a while and skip it when choosing hops, and strike only if the same
  peer fails against the id that the current file names and that file is
  recent.
- **Handshakes cost a relay work no one pays for.** `node/channels.rs`:
  each hello costs a Kyber encapsulation and a Dilithium signature. An
  address must have answered the relay's ping, a host holds at most 32
  channels and an unused one goes after 15 s, but a host can open them as
  fast as they close. Fix: a rate per host, or a proof of work in the
  hello under load.

- **Cells toward the client are checked only at the end.** `circuit.rs`:
  toward the far end every layer is tagged and a flipped bit is caught by
  the next hop, but toward the client only the originating hop's tag is
  checked, by the client: a hop that flips bits there ends the circuit
  without being found, and a hop toward the far end that colludes with
  the client's first hop learns, from the circuit ending, that they share
  it. Fix: tag the backward layers too, with fillers as forward, or a
  wide-block cipher per layer (Tor's counter galois onion).
- **Idle hops live as long as their channels.** `node/circuits.rs`: a
  relay drops a hop only on `Destroy` or when a channel under it
  closes. A participant's channel holds at most 64, but a relay's is not
  limited, and there is no flow control per circuit: one circuit can
  fill a channel's queue. Fix: drop hops idle for an hour, and window
  cells per circuit.

- **A message down a dead circuit is lost, and reported delivered.**
  A rendezvous point answers forwarded once it sends a payload down the
  recipient's circuit; if a hop of that circuit is down and the recipient
  has not noticed yet (below), the payload is lost and the sender's
  wallet still hears "delivered". A slate then waits for an answer that
  never comes, until cancelled. Fix: an end-to-end acknowledgement from
  the recipient's node, and a resend over another of its points.
- **A dead hop is noticed when the relays' channel to it fails.** A
  participant learns of it from the `Destroy` passed back
  (`docs/SCALING.md`): about 40 s after the hop goes down when the relay
  before it opened their channel, up to two minutes when the hop did
  (the listening side waits out two minutes of silence). With one
  session, the wallet is unreachable meanwhile, and a payload delivered
  down the dying circuit is lost though reported delivered. A relay that
  a circuit failed to extend to is avoided as a hop for five minutes.
  Fix: keepalives on relay channels from both ends, so the listening
  side notices as soon; or keep a spare circuit to the point, through
  other hops, and switch to it at once.
- **A wallet on a relay skips that relay as a rendezvous point,** in
  both modes, so it is reachable only through its other points (with one
  seed, not at all). By design: run relays with `--no-wallet`.

## Deployment and operations

- **A relay keeps a phrase on its server.** `--no-wallet --relay` still
  opens the wallet, only to derive the relay key from its phrase, so the
  phrase sits on an exposed machine. It should hold no funds. Fix if it
  matters: keep only the derived relay seed in `DIR/relay.key`, written
  once from the phrase.

- **Seeds** need the current binary at every format change (now protocol
  6, chain format 14, wallet format 8, slate format `tabslt05`), started
  with `--relay`, and wiped data directories. Fresh nodes cannot sync
  until then.
- **Genesis regeneration at launch**, with `--hashrate` set to the
  expected network rate (README, Genesis).
- **Single-core and small-VPS tests.** Dataset build on one core is about
  six minutes, during which headers are checked at 30 ms each; on a 1 GB
  machine a 12 GB state lives on disk and each full block is bound by
  random-read speed.
- **A real 170M-output fast sync** to turn the scaled 20 to 30 minute
  estimate into a measurement.
- **Batch the per-part and per-header-batch LMDB commits** (each waits on
  the disk; about 60,000 commits at ten-year scale).

## Features deferred

- Cover for the address a transaction is first sent from, in init mode:
  onion mode hands it to a relay over a circuit (`docs/ONION.md`,
  enhancement 1), but in init mode the node announces it itself.
