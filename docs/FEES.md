# Fees

Written 2026-11-05 to be tracked; not built. A proposal for fees that
adjust with time and demand, in the pool and the reference miner. All of
it is policy, not consensus: no block-validity rule changes, so it can be
tuned after launch without a fork, and a miner may always do otherwise.
The aim is a default that serves both: users can pay the floor and wait,
and miners are paid for urgency when blocks are full.

## Today

- A fixed minimum fee per byte (`MIN_FEE_PER_BYTE`, 10 base units at ten
  decimals: 10^-9 coins) and a dust limit derived from it (the fee of
  spending an input: 23,770 base units).
- A replacement must add `REPLACEMENT_FEE_PER_BYTE` per byte of its own
  size over what it replaces (how a wallet cancels or bumps a payment).
- When the pool is full, a new transaction with a higher fee per byte
  evicts the lowest.
- The miner takes transactions by fee per byte (`Mempool::select`).
- A pooled transaction stays until mined, evicted, or invalidated; the
  wallet's `resend` puts one back after a restart dropped it.

## Background: what Bitcoin did

- **Priority** (removed around 2016): a transaction's priority was the sum
  of input value times coin age, over its size, and each block reserved a
  slice (50 KB by default) for the highest priority, whatever the fee. Old
  coins could move cheaply or free. It was dropped because it made fee
  estimation hard to reason about, and miners stopped honouring the slice
  since it cost them revenue.
- **The rolling minimum fee** (current): when the pool is full and evicts,
  the fee to enter it rises to what was evicted, then decays back with a
  12-hour half-life. It is the pool's entry price that decays with time,
  not each transaction's.

## The idea: the price of inclusion decays as a transaction waits

A minimum that decays per transaction does nothing alone. Miners take
transactions by fee rate: when blocks are not full everything above the
floor is taken anyway, and when they are full a waiting low-fee
transaction loses to every newer one paying more. Age only counts if some
of each block is given to age. So the proposal has three parts.

### 1. A floor that never decays

The relay minimum per byte stays fixed while a node runs: below it a
transaction is neither pooled nor relayed, so filling the pool, the
blocks and the output set always costs something. The dust limit stays
derived from it. It is a node setting (default `MIN_FEE_PER_BYTE`, 10
base units a byte), so operators can follow what the network settles on
without a release: each node's pool is its own policy. A node whose floor
is above its peers' simply does not take what they relay below it.

### 2. A rolling admission minimum under pressure

When the pool is full and evicts, its minimum for new transactions rises
to the evicted rate plus the replacement increment, then decays back
toward the floor with a half-life of 12 hours, as Bitcoin's (shorter
while the pool is under half full); the half-life is a node setting. Under a flood the pool's price goes up and then
relaxes; nobody has to watch it. Peers learn a node's current minimum, so
they do not send what it would refuse.

### 3. An aged reserve in every block

The reference miner fills a share of each block, proposed 10% of its
size, with the longest-waiting transactions that pay at least the floor,
oldest first (by age alone, so a user can predict the wait); the rest by
fee rate, as now. In numbers: 10% of a full 2 MB block is 200 KB, about
65 simple payments (3 KB each) taken by age whatever they pay. So:

- **Users.** A transaction paying the floor confirms within a bounded
  wait even when blocks are full: about the floor-paying backlog ahead of
  it divided by the reserve (650 ahead at 65 a block: 10 blocks, about
  1 h 40). Paying more buys speed, not admission. At a share of 0 this is
  Bitcoin's model since 2016: under congestion a floor-paying
  transaction may wait until demand falls.
- **Miners.** At most that share of fee revenue is given up, and only
  when blocks are full; when they are not, the reserve costs nothing,
  since everything above the floor fits.

This is the "minimum fee decays with time" in a form a miner can carry
out: a transaction's claim on the block grows with its wait.

### Age

- Measured locally, from when the transaction first reached this node:
  nodes differ by seconds to minutes, which is fine for an order of hours.
  A claimed age cannot be trusted, so none is relayed.
- Kept across restarts: the saved pool stores each transaction's arrival
  time.
- A replacement starts a new age: bumping a fee is a choice of speed over
  waiting.

### Expiry

A pooled transaction older than a limit, 14 days by default and a node
setting, is dropped, so
stale ones do not hold pool space for ever. Its sender's wallet, which
still holds its inputs as spent, sees it unconfirmed and can `resend` or
`cancel` it.

## The wallet

- **Fee estimation**: a suggested rate from the fee rates of recent
  blocks and the pool's depth, for confirmation within about a block, an
  hour, or a day.
- **Economy**: pay the floor and wait for the reserve; the prompt says
  roughly how long, from the pool's backlog.
- **Speeding up**: a replacement at a higher fee, as `cancel` does today
  for paying the inputs back; a `bump` command paying the same recipient
  more is the natural companion.

## Cost of a transaction to a miner

A block's real cost to its miner is proving time, not bytes: the block's
STARK proof covers every transaction in it, and proving time grows with
a transaction's trace rows (the rows of the circuit's execution table).
A transaction's rows follow its inputs (an XMSS signature each) and
outputs, and the signatures dominate both its size and its rows, so a fee
per byte tracks proving work closely enough for now. Transactions with
policy conditions (`docs/ELTOO.md`: thresholds, state numbers, timelocks)
can add rows (each threshold signer is another signature check) at a
different rate than bytes; if they became common and cheap in bytes for
their rows, a fee per byte would underprice them. A fee per trace row is
the exact measure, and the node can count a transaction's rows before
mining it, but it is less familiar and harder for wallets to estimate.
Per byte for now; revisit if policy transactions become a large share.

## Decisions

- Fees stay policy, not consensus.
- The relay floor is a node setting, defaulting to 10 base units a byte
  (10^-9 coins, set with the move to ten decimals); the dust limit
  follows it.
- The rolling minimum decays with a 12-hour half-life, as Bitcoin's; a
  node setting.
- Pooled transactions expire after 14 days; a node setting.
- Inclusion follows waiting time through an aged reserve in each block,
  in the reference miner, ordered by age alone.
- Fees are per byte; per trace row is to be revisited if transactions
  with many policy conditions become common.

## Open

1. The reserve's share: 10% proposed; more shortens waits at the floor,
   less keeps miners' revenue under congestion (0 is Bitcoin's model).
   Likely a miner setting too, with the default the decision.

## Implementation order

1. Node settings for the relay floor, the half-life and the expiry.
   Arrival times in the pool, kept in the saved pool; expiry.
2. The rolling admission minimum, and peers told it.
3. The aged reserve in `Mempool::select`.
4. Wallet: fee estimation, an economy option, `bump`.
5. Tests: a pool under a flood (the minimum rises and decays back); full
   blocks with a backlog at the floor, each confirmed within the bound;
   restart keeping ages; expiry.
