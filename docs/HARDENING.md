# Hardening backlog

Gaps found in the review of 2026-10-31 and not yet closed. Each entry says
where the problem is, why it matters, and the fix as far as it was thought
through. Items are grouped by area and ordered by how much they matter
within the group. The fixes already made from that review (miner size and
timestamp rules, request tokens, per-host peer limits, strike policy, slate
checks, fee policy, dust, blind rows, the dataset checksum) are in the
history and the README; this file holds what is left.

## Consensus and chain

- **Pooled transactions die on a reorganization that moves their inputs.**
  `mempool.rs`, the shelf: a shelved transaction is restored only if its
  input is unspent at the *same* position. After a reorganization that
  recreates an output at a new position the transaction is never
  restored, and peers' copies are refused as `UnknownInput`. The wallet
  corrects its own records (`wallet.rs`, `relocate`) but nothing
  re-positions and re-pools a transaction already signed. Positions are
  unsigned precisely so this is possible. Fix: when a shelved transaction
  is re-checked, look its input commitments up near their old positions
  (the outputs of the reorganized blocks are known: walk the undo window),
  rewrite the positions and re-insert. Also let the wallet resend a
  payment from `sent` (store the signed transaction in `Sent`) rather than
  only cancel it.
- **The pool is not persisted.** `node.rs`: a restart drops every pending
  payment, which then shows as "locked" in the wallet until cancelled.
  Fix: write the pool to `DIR/mempool` on exit and every few minutes, and
  reload it through `insert` at start (which re-checks everything).
- **No coinbase maturity.** A reward can be spent in the next block; a
  reorganization then invalidates the whole chain of spends, which only
  the shelf can rescue. A Rust-only rule would be one more thing a
  fast-syncing node cannot check, so it would have to go in the circuit
  (the segment knows the input's position, and the block's first output
  position; a height per output is not stored). Decide whether it is
  wanted at all; a pool policy (do not pool a spend of an output younger
  than N blocks, judged by position against recent blocks' first output
  positions) gets most of the benefit without touching consensus.
- **Duplicate commitments confuse the pool.** `mempool.rs`, `spends`:
  conflicts are keyed by commitment, the chain spends by position. Two
  distinct unspent outputs with the same key hash and amount (anyone can
  make them) are treated as one: a transaction spending both is
  `Malformed`, and a spend of one looks like a conflict with a pooled spend
  of the other. No double spend gets through, but it is wrong. Fix: key
  `spends` by position.
- **Side blocks are stored without proof verification.** `chain.rs`,
  `apply_block`: a block with valid proof of work on a side branch is kept
  (header and up to 2 MB body) and served to peers before its proof is
  checked. Bounded by the work needed to make one; bodies are pruned at
  the window edge. Acceptable; noted so nobody relies on a stored body
  being valid.
- **Intermediate headers' state roots are verified by nobody on a fast
  sync.** The chain proof binds state transitions, not headers: a
  fast-syncing node checks proof of work, difficulty and timestamps of
  every header, and the statement pins the snapshot block's parent state
  root and its own, but the state roots of headers below that are
  unverified data, and historic block sizes are never checked. Not
  exploitable (the proof chain is still needed), but document it in the
  README, which says "nothing about the past is taken on trust".
- **`--debug-no-validate-proofs` is live in release builds** and also
  disables snapshot verification. Gate it behind a feature or
  `cfg(debug_assertions)` before launch, or at least refuse it when the
  data directory already holds a verified chain.
- **Every segment count's wrap is assumed to have the same table
  heights.** `aggregate.rs`: the chain-step program takes its heights from
  `plan(1)`. A segment count whose wrap came out a different height would
  fail at mining time with a digest mismatch, not at planning. Assert it
  in `mainnet_chain_constants` over every count.

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

- **Policy outputs are not recoverable from the seed.** A multisig,
  HTLC or channel output is found again only from the policy the parties
  agreed, which the wallet stores (`policies` table); a wallet restored
  from its phrase alone has none of them. This is the Lightning
  situation and a reference wallet accepts it. Fix for user wallets:
  back up channel state with the counterparty or a watchtower, or derive
  shared memos the wallet can scan for and fetch policies from the
  counterparty.

- **Cancelling a carried name operation leaves its wallet state pending.**
  `cancel` on a transaction that carried a reveal or an update pays the
  inputs back but the name entry stays "revealed, awaiting the chain" or
  "update pending" with the leaf consumed; the user must re-issue the
  operation (a new reveal re-signs nothing; a new update takes another
  leaf). Fix: have `cancel_sent` revert the entries of the operations the
  transaction carried (reveal: back to a pending commit; update: drop the
  pending nonce).

- **Seed and entropy are stored in plaintext LMDB**, and `restore` reads
  the phrase and passphrase with terminal echo. Fix: encrypt the seed at
  rest under a passphrase (a PBKDF2 or Argon2 key, XChaCha or a Poseidon
  stream), read it without echo, and set the wallet directory mode to 0700.
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
- **Orphaned rewards and side-block rewards linger as "pending".** A
  reward of a side block that never wins is kept forever; `--no-prompt`
  exit and crashes skip the in-flight forget. Fix: forget a reward when its
  block leaves the undo window without becoming main; run the in-flight
  check on every start.
- **A fake stage-1 slate inflates the recipient's pending balance** until
  pruned: `receive_slate` trusts `slate.amount` and the inputs. Expected of
  a slate design; show "unconfirmed, unverifiable until it lands" rather
  than counting it, or verify the inputs against the UTXO set when the
  recipient's node has it. Over the message layer an online wallet
  answers stage-1 slates by itself, at most 5 per sender and 60 in all per
  10 minutes (`onion::SlateLimit`): a sender with many ids still gets 60.
- **Minor.** `wallet.rs`: `cancel_sent` does not check the inputs are
  still held (the prompt filters through `sent`, the library does not);
  `cancel ID` prefix match takes the first hit; `send` writes the change
  record in a separate transaction before reserving the inputs, leaving an
  orphan record on a crash between them.
- **Untested.** The `sync_wallet` fork walk and stale positions after a
  reorganization; crash injection between the steps of `send`;
  concurrent original and restored wallets; the restore-scan thread;
  pool acceptance of a recovered-output (leaf 8 to 15) spend end to end;
  `Slate::from_bytes` on malformed input beyond the stage and change
  bounds. There are no integration tests (`miner/tests` does not exist).

## Proof system

- **The circuit has not been independently reviewed.** Fast sync trusts
  the chain proof completely; nothing replays history to catch a circuit
  bug. This is the largest remaining trust gap. `block_air.rs` (SMT
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

Found while building it (2026-11-01).

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
- **A dead relay is noticed at the next keepalive.** A participant
  takes a circuit for dead 10 s after a `Session` keepalive goes
  unanswered (`node/participant.rs`), so up to 40 s after a hop goes
  down; a channel goes 15 s after a frame is first left unacknowledged;
  a relay whose channel failed, or that a circuit failed to extend to,
  is avoided as a hop for five minutes. Rebuilt paths are random, so a
  few may still try the dead relay first. Fix: keep a spare circuit to
  each point, through other hops, and switch to it at once.
- **A wallet on a relay skips that relay as a rendezvous point,** in
  both modes, so it is reachable only through its other points (with one
  seed, not at all). By design: run relays with `--no-wallet`.

## Deployment and operations

- **A relay keeps a phrase on its server.** `--no-wallet --relay` still
  opens the wallet, only to derive the relay key from its phrase, so the
  phrase sits on an exposed machine. It should hold no funds. Fix if it
  matters: keep only the derived relay seed in `DIR/relay.key`, written
  once from the phrase.

- **Seeds** run an old binary. They need the current one, started with
  `--relay` so that wallets hold their init-mode sessions there (protocol v5,
  wallet format 6 (keys carry a tree height; slate format 3), chain format 13 (a snapshot manifest for every block in the undo window; output leaves carry the creation height; policy inputs, keys of any height to 20), new genesis id (17980c69…, the header carries 32 aux bytes under the proof of work), new `MAINNET_CHAIN`) and wiped data
  directories. Fresh nodes cannot sync until then.
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

- Payment proofs: the transaction, a Merkle path to the header, and a
  signature with the output's key over an agreed message.
- Cover for the address a transaction is first sent from, in init mode:
  onion mode hands it to a relay over a circuit (`docs/ONION.md`,
  enhancement 1), but in init mode the node announces it itself.
