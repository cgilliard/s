# A GUI wallet in the window manager

A wallet with a window of its own on wm's desktop (`docs/OS.md`, section
7): balances, payments, receiving, names and the recovery phrase, without
a terminal. It runs beside the fam node (`docs/NODE.md`) in the same OS,
and is the same wallet as tabminer's: the same phrase finds the same
coins, and either can pay the other.

Status: a design, partly decided (2026-11-09); see Decided and To
decide.

## Decided

1. **In the OS** (`wallet`, in fam: The shape, below). A wallet icon in
   wm's dock, beside the terminal's, opens the user's wallet in a window.
2. **One wallet per OS user:** the icon opens that user's; there is no
   choosing among several.
3. **Logging in unlocks it:** wm asks for a name and password before it
   shows the desktop (Logging in, below), and that password is the
   wallet's: no second password to remember or type.
4. **The message layer in phase 3:** slates by file until then. The
   message layer is the onion routing of payments (`docs/ONION.md`):
   the sender reaches the recipient's rendezvous point over a circuit
   of three hops, and neither learns the other's address. Its other use
   comes with it: until then the wallet's own transactions go to the
   node's pool through the API and are relayed by the node to its peers
   from its address, as everyone's are; tabminer in onion mode hands
   them to a relay over a circuit instead.

## What is fixed already

By tabminer's wallet (`README.md`, Wallet; `miner/src/wallet.rs`), which
this one must interoperate with:
- **The phrase:** 12 BIP39 words (128 bits, the standard PBKDF2 seed, an
  optional passphrase), shown once at creation and again on request.
- **Keys:** every output its own one-time XMSS key, H(master, nonce)
  with a random nonce; no key indices. 16 one-time leaves a key: 0 to 7
  for the wallet's own outputs (a spend and up to seven cancellations),
  8 to 15, from a random start, for outputs found by a restore.
- **Outputs on chain:** a commitment and a 20-byte memo (the nonce and a
  tag from the phrase); amounts public (`docs/AMOUNTS.md`). A wallet
  finds its outputs by scanning memos; no key or address is on chain
  (`docs/PRIVACY.md`).
- **Payments:** a slate passed between the two wallets: the sender's
  inputs and change, the recipient's output and its receipt (signed by
  the recipient's address key, Dilithium), then the sender's signatures.
  Over the message layer (`docs/ONION.md`) when both are online, or as
  files. `cancel` and `bump` replace a payment before it confirms.
- **Addresses:** `tab1…`, the id of a Dilithium key; names (`@alice`) point
  at addresses (`docs/NAMES.md`, `docs/SUBNAMES.md`).
- **At rest:** the phrase and seed encrypted under a password
  (ChaCha20-Poly1305, a PBKDF2 key); the rest readable by the wallet's
  owner only.
- **Fees:** the node's suggestions (`/v1/fees`: a block, an hour, a day,
  economy), as tabminer's `fees`.

By the OS and the node:
- wm serves one page, the desktop, over HTTP; each window today is a
  terminal on a WebSocket (`/tty`) with a program on a pty behind it.
- The node's API (`/v1/...`, JSON over HTTP on 3738, a token in
  `/etc/node/token`) gives the chain and the pool: outputs from a
  position, spends since a height, output and name proofs, fees, the
  pool, transactions in, the tip by long poll.
- Keys never reach the node (`docs/NODE.md`, The API).

## The shape proposed

Three parts:

1. **`wallet`, a program in the OS** (fam), one per user: the keys,
   the wallet's records (a store tree in the user's home, `wallet`), the
   transactions built and signed. It reads the chain through the node's
   API and gives it transactions. It is the only part that holds the
   phrase or a key.
2. **A wallet window in wm's page:** HTML and plain JavaScript, as the
   page is now, on a WebSocket of its own (`/wallet`). wm starts
   `wallet` for it, on a pipe rather than a pty, and passes JSON both
   ways: the window asks (the balance, a payment, an address), the
   program answers and tells (a payment arrived, the tip moved). The
   window keeps nothing: closing it loses nothing, and a password typed
   in it goes to `wallet` and no further.
3. **The node**, as it is: the chain, the pool, the network. The wallet
   asks the API for what it needs; scanning for its outputs is the
   heaviest (every output's memo since its last scan, `/v1/outputs`).

So the browser shows the wallet but never holds it; the OS does, as it
holds the node.

## Logging in

wm shows a login form first; the desktop, its terminals and the wallet
come after, as the user who logged in.
- **Passwords kept as hashes:** `/etc/passwd` holds each password in
  plain text today (`docs/OS.md`, step 5; only root reads it). It will
  hold a salt and a slow hash (PBKDF2, as tabminer's wallet uses), for
  `login` and wm alike.
- **wm checks the password** as `login` does, then runs each window's
  program (the shell, `wallet`) as that user, in that user's home.
- **The wallet's key comes from the same password:** the phrase and
  seed stored encrypted (ChaCha20-Poly1305) under a key derived from the
  login password with a salt of the wallet's own, a different
  derivation from the login's hash, so neither gives the other. wm
  keeps the password in memory for the session only (the wallet may be
  opened any time after logging in), hands it to `wallet` on its pipe
  when it starts it, and forgets it at logout.
- **Changing the password** re-encrypts the wallet's phrase in the same
  step; a wallet created before a password, or restored, takes the
  login password at once.
- **A session** ends at logout, or after 30 minutes idle (no request
  and no typing in its windows; wm's idle seconds); the wallet locks
  with it (its keys out of memory).
- **Limits:** the page and its form travel in plain HTTP, so until wm
  has TLS the desktop is reached only from the host itself (the forward
  bound to localhost); root can read any process's memory, as on any
  OS.

## The wallet's messages

Between the wallet window and `wallet`, through wm (phase 1; built
2026-11-10, with `wallet` a stub answering fixed data until the real one
is written).
- **The way:** the window opens `GET /wallet`, a WebSocket that needs the
  session's cookie as `/tty` does (403 without). wm starts `wallet` as
  the session's user in the user's home (`runas USER GROUP wallet`) on
  two pipes, its errors nowhere, and relays: each text frame from the
  window a line on the wallet's input (any newline in it made a space),
  each line the wallet writes a text frame. One JSON object a frame and a
  line, at most 3,800 bytes. Either side closing ends the other: the
  window closed, the wallet's input ends and it exits; the wallet gone,
  wm closes the WebSocket. Logging out, or the session idle past its
  time, closes it as it does the terminals. One wallet window a session
  (the dock's icon focuses it if open).
- **Unlocking:** wm writes the first line itself,
  `{"op":"unlock","password":"..."}`, the password as typed at logging
  in (kept in the session's record in wm's memory until the session
  ends; JSON-escaped). The wallet answers `{"op":"unlock","ok":true,
  "wallet":true}` (`"wallet":false`: none made yet), or `"ok":false` and
  an `"error"`; wm relays the answer to the window like any other. Only
  the first line unlocks: a later `unlock` is refused, so a page cannot
  try passwords.
- **Requests and answers:** the window asks `{"id":N,"op":"...",...}`;
  each answer carries the same `"id"`, `"ok":true` and its fields, or
  `"ok":false` and `"error"` (a sentence to show). Answers may come out
  of order. Amounts are strings in coins as tabminer prints them (up to
  ten decimal places): a 64-bit amount does not fit a JavaScript number.
  Files are paths in the user's home.

  | op | asks | answers |
  |---|---|---|
  | `overview` | | `confirmed`, `pending`, `unverified`, `reserved`, `locked`; `height`, the tip; `node`, its state |
  | `receive` | | `address` (`tab1…`); `name`, a name pointing at it, if any |
  | `answer` | `slate`, a file sent by a payer | `slate`, the answer written; `amount` |
  | `fees` | | `speeds`: each a `speed` (`block`, `hour`, `day`, `economy`), its `rate` as `/v1/fees` gives it, `wait` in seconds |
  | `send` | `to` (an address or `@name`), `amount`, `speed`, `slate`, the file to write | `slate`; `fee` |
  | `finalize` | `slate`, the recipient's answer | `tx`, the transaction sent to the pool; `fee` |
  | `activity` | | `items`: each `tx`, `kind` (`sent`, `received`, `burn`), `amount`, `state` (`pending`, `confirmed`, `cancelled`), `height` (0 unconfirmed) |
  | `cancel` | `tx` | `tx`, the replacement |
  | `bump` | `tx`, `speed` | `tx`, the replacement |
  | `create` | | `words`, the new phrase (shown once) |
  | `phrase` | `password`, typed again | `words` |
  | `restore` | `words`, `passphrase` | nothing more; a scan follows |
  | `scan` | | nothing more; `scan` events follow |
- **Events,** unasked, with `"event"` in place of an id: `tip`
  (`height`, `hash`) when the tip moves; `payment` (`tx`, `kind`,
  `amount`, `state`) when one arrives or changes state; `scan` (`height`,
  `of`) as a scan goes; `locked` when the wallet locks itself.

## What it does

As tabminer's wallet commands, in screens:
- **Overview:** confirmed, pending, unverified, reserved and locked
  funds; the tip and the node's state.
- **Receive:** this wallet's address (and a name pointing at it); slates
  answered as they come; a slate file to answer.
- **Send:** to an address, a `@name`, or a slate file; the fee as a
  speed (a block, an hour, a day, economy) with its rate and wait;
  `finalize` for a file answered.
- **Activity:** payments sent and received, burns; each one's state;
  `cancel` and `bump` while unconfirmed; a payment's proof.
- **Names:** register, update, sub-names.
- **Settings:** the phrase (behind the password), the password, restore
  from a phrase (`scan`).

## What has to be built

In fam, each ported from tabminer and checked against vectors it writes
(as the node's modules are):
- **BIP39:** the word list, the checksum, the seed (PBKDF2-HMAC-SHA512,
  2,048 rounds). SHA-512 is new to the OS.
- **Keys:** H(master, nonce) (Poseidon2, which the node has), the memo
  and its tag, and recognising an output by its memo.
- **XMSS signing:** a key's tree and a leaf's signature. The node has
  verification (`xmss.fam`); signing and the leaf bookkeeping (never a
  leaf twice, written before a signature leaves) are new.
- **Transactions and slates:** building, encoding, the checks
  `finalize` makes; the wallet's records, written in one store
  transaction with the signatures they hold (as tabminer's).
- **Dilithium (ML-DSA):** receipts signed (receiving) and checked (sending); the
  address. New, and heavier than anything the node runs.
- **ChaCha20-Poly1305 and PBKDF2:** the phrase at rest.
- **The message layer** (online payments): Kyber (ML-KEM), circuits,
  rendezvous sessions (`docs/ONION.md`). The largest part; tabminer's
  `onion.rs`, `node/participant.rs` and `channel.rs` together.
- **wm:** the login form and the session (passwords as salted PBKDF2
  hashes in `/etc/passwd`, `login` the same); the wallet icon, the
  `/wallet` WebSocket on a pipe, the window kind, its page.

The node needs little: what it serves already, perhaps a way to scan
memos faster than every output in order.

## Phases proposed

0. **Logging in:** passwords hashed, wm's login form and sessions, the
   programs run as the user. Needed whatever the wallet. Done
   (2026-11-09, `docs/OS.md`: steps 8 and 10's notes); the session's
   password kept for the wallet came with phase 1.
1. **A wallet of its own, by files:** create or restore from a phrase,
   scan, balance and activity; receive and send by slate files; fees;
   cancel and bump. Everything but the message layer. A tabminer wallet
   and this one pay each other by files. wm's side done (2026-11-10:
   the wallet's icon and window, `/wallet`, the password kept; The
   wallet's messages), with `wallet` a stub (`src/user/wallet.fam`).
   The primitives so far (2026-11-10, each checked in oscheck against
   vectors): SHA-256 and BIP39 (`crypto/bip39.fam`, `/lib/bip39`);
   ChaCha20-Poly1305 (`crypto/chacha.fam`, RFC 8439); XMSS signing
   (`node/xsign.fam`: a 16-leaf key about 2.3 s, a signature about
   0.1 s under QEMU); Dilithium and SHA-3 (`crypto/dilithium.fam`,
   `crypto/keccak.fam`: ML-DSA-65, deterministic signing as tabminer's;
   keys about 0.1 s, a signature 0.1 to 0.4 s); the keys and memos
   (`node/wkeys.fam`: the master, an output's key seed, memo and
   commitment, a memo recognised, the identity's seed, id and `tab1…`
   address; checked against a tabminer wallet restored from the same
   phrase). Left: transactions and slates, the wallet program.
2. **Payments and names in full:** proofs of payment, burns, names and
   sub-names.
3. **Online payments:** the message layer, so `send` to an address or a
   name needs no file.

Each phase ends with tests as the node's: vectors from tabminer for every
primitive, then a tabminer wallet and this one paying each other on the
recursive dev network, in both directions.
