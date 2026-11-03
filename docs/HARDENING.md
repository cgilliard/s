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

- **One slow peer is taken for no peer.** `node.rs`,
  `check_snapshot_target`: a part download abandoned for slowness marks
  its peer unserving, and with a single peer that moves the snapshot. Fix:
  back off and retry the only peer; move only when it refuses or drops
  the snapshot.

- **The staging drain blocks the network thread.** `node.rs`,
  `drain_staging`: a blocking `recv` while the applier stages up to 32
  parts or applies a block. No pongs go out meanwhile and the event queue
  can fill and drop datagrams. Fix: make the move or restart a state the
  tick advances when the applier reports idle, instead of waiting inline.
- **"No peer serves the snapshot" never counts as a failed attempt.**
  `node.rs`, `check_snapshot_target`: with the chain less than an interval
  past the target, the node cycles the same peers indefinitely instead of
  counting towards the fallback. Fix: count it in `snap_attempts`.
- **A fresh node silently gives up fast sync after 10 s without peers.**
  `node.rs`, `header_sync`: it drops to `Normal` and replays from genesis
  for good. Slow seed resolution is enough to trigger it. Fix: keep
  retrying the handshake, and only start from genesis when told to (a
  flag), or go back to `Headers` mode when the first peer appears.
- **Clock skew is blamed on peers.** `TimestampTooNew` is silent; with
  our clock more than two hours behind, every header batch is dropped and
  each peer is passed over with "sent no headers for the work it claims".
  Fix: count `TimestampTooNew` per tick and log "this node's clock may be
  behind" when several peers hit it; do not pass peers over for it.
- **Header batches can mark honest peers as liars.** A complete batch
  waiting more than 15 s behind slower ones (the dataset still building,
  or a late batch at the front) hits `expire_header_requests`. And a
  batch has no per-header retransmit: one lost datagram makes it late,
  two in a row pass the peer over. Fix: clear `headers_asked` when a
  batch arrives complete, not only when it is verified; re-ask for the
  missing heights of a batch before giving it up.
- **Local errors strike peers.** `node.rs`, part staging: any `Err`
  including an LMDB or storage error strikes the serving peer. Fix: strike
  only on a part that fails its root check.
- **Serving cost is unbounded per peer.** `serve_chunks` clones a whole
  block per request; a snapshot part costs two range reads and a 1.2 MB
  encode per cache miss with an 8-entry cache; there is no per-peer
  request rate limit. Fix: serve chunks from the cached bytes without a
  clone (an `Arc<Vec<u8>>`), bound requests per peer per second, and
  consider a larger part cache during a sync.
- **IPv6 addresses learned from peer lists are pinged forever** from a v4
  socket, consuming the unverified-ping budget. Fix: drop addresses of a
  family the socket cannot reach when they are learned.
- **`--peer` keeps only the first resolved address;** `GetPeers` always
  goes to the first live peer in table order; `RETRY` is a fixed 400 ms so
  paths with a longer round trip re-send every window and stay at the
  minimum window. Fixes: keep every resolved address; pick the peer at
  random; estimate the round trip from ping to pong and set the retry to a
  multiple of it.
- **A max-work liar with a high height is picked first by `block_source`**
  for every block, costing a few seconds and a `syncing` flip every ten
  minutes. Fix: prefer peers that have delivered.
- **Eclipse resistance rests on the two seeds.** Hard-code a checkpoint
  or an `assumevalid` header hash per release once the chain is live, and
  prefer outbound peers from distinct /16 (or /32 for v6) groups.
- **Untested paths.** No test for: a reorganization past the snapshot
  during a fast sync; a reorganization below the floor after install; the
  "no peer serves" and `drop_carry` paths; the bad-manifest path; the
  genesis fallback and "keep trying" paths of `restart_snapshot`; any lossy
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

- **ML-DSA signing is not constant-time.** `mldsa.rs`, `sign_internal`:
  the bound checks on `z` and `ct0` stop at the first coefficient over
  the bound (`iter().any`), so a rejected attempt takes a time that
  depends on where, which depends on the secret key; `centered`,
  `decompose`, `make_hint` and the `r0_max` computation branch on values
  derived from `s2` and `t0` (`if r0 > GAMMA2`, `if r - r0 == Q - 1`), in
  accepted signatures too. Deterministic signing makes the same input
  take exactly the same path, so measurements can be repeated and
  averaged. The relay key is the exposed one: anyone can make a relay
  sign as often as it likes, every channel hello and every circuit hop a
  signature over a transcript that includes the requester's own data. Over
  the internet the differences are small beside network jitter; a
  co-tenant on the same host (a VPS) measures far finer. A recovered relay
  key lets an attacker pass for that relay (sit in circuits and sessions
  through it, drop or follow traffic), not touch funds, and it says
  nothing of the phrase (it is derived under its own domain tag). The
  wallet's identity key signs rarely and not on demand (announces, and
  receipts once `docs/PROOFS.md` is built), but is worth more: it could
  announce an attacker's Kyber key for the wallet's address and take its
  slates; `address next` (`docs/PRIVACY.md`, fix 5) bounds how long a
  leaked one serves. Kyber is in better shape: decapsulation compares in
  constant time (the implicit-rejection mask) and `compress` divides by
  the constant `Q`, which optimized builds turn into a multiply (no
  KyberSlash), and its keys are short-lived. XMSS and the prover hash
  secrets in fixed patterns; funds are not at stake. Fixes:
  1. **Constant-time attempts.** Evaluate every norm and hint check in
     full, with mask arithmetic instead of branches (`centered`,
     `decompose`, `make_hint`, the norms), and decide to accept or reject
     once, at the end. The number of attempts may still show, which FIPS
     204 accepts. The ACVP known answers check the result.
  2. **Hedged signing for the relay key.** FIPS 204's hedged mode mixes
     32 fresh random bytes into each signature (`rnd` in
     `sign_internal`, zero today), so identical inputs no longer take
     identical paths and repeated measurements cannot be averaged.
     Signatures verify the same. Only the relay key: the wallet keeps
     deterministic signing.
  3. **Keep the handshake limits.** The per-host caps on channels
     (`node/channels.rs`, 32 a host, unused ones closed after 15 s) slow
     the collection of samples; a rate per host would slow it more.
  4. **Check the machine code.** Inspect the generated assembly of the
     signing and decapsulation paths on x86-64 and riscv64 once, for
     divisions and data-dependent branches the source does not show.
- **A participant's session Kyber key lives up to 12 hours.** The key a
  participant announces at its rendezvous points (`node/sessions.rs`,
  `node/participant.rs`) is replaced on a reconnect and otherwise after
  half the announce's lifetime (`ROTATE_AFTER`, 12 hours of
  `onion::ANNOUNCE_LIFETIME_SECS`'s day). Unlike the handshake keys, which
  decapsulate once, it decapsulates every payload anyone sends to the
  address meanwhile: chosen ciphertexts against one key, for a timing
  attack on decapsulation. The implementation shows no known leak (the
  implicit-rejection comparison is constant-time, `compress` divides by
  the constant `Q`), and a recovered key reads only the slates sent until
  the next rotation (it cannot redirect payments, the announce being
  signed by the identity key). Fix: rotate it every hour, with the
  announce's lifetime cut to match (two hours, say); a retired key still
  opens payloads for its ten minutes' grace (`KEY_GRACE`). The cost is one
  re-announce an hour, a Dilithium signature for each rendezvous point
  (one, with `docs/SCALING.md`'s single session).

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
