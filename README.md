# s

A proof-of-work chain whose blocks carry only output commitments and a
zero-knowledge validity proof. `miner/` holds the node, the prover and the
wallet; `miner/SECURITY.md` analyses the proofs.

## Build

```
cd miner
cargo build --release
```

## Run

```
tabminer [mine] [--data DIR] [--blocks N] [--jobs N] [--no-mine] [options]
tabminer node [--data DIR] [options]
tabminer show [--data DIR]
tabminer restore [--data DIR]

options: [--listen ADDR] [--peer ADDR]... [--seed HOST:PORT]... [--verbose] [--no-prompt]
```

`tabminer` with no command mines: it syncs to the heaviest chain its peers
know, then builds blocks from the pooled transactions plus a reward paying
the subsidy and their fees to its wallet, proves them, mines them and
announces them, starting over whenever the network delivers a better tip.
`tabminer node` (or `--no-mine`) follows the chain and relays without
mining. Both listen on UDP port 7417 by default, contact the seed nodes in
`miner/src/node.rs` and any `--peer`, and keep the peers they found in
`DIR/peers` for next time. `show` prints the main chain.

Logs go to `DIR/tabminer.log`; the terminal shows a prompt (`help` lists
the commands). `--no-prompt` logs to the terminal instead, for scripts.

Every node starts from the fixed mainnet genesis in `ChainParams::MAINNET`.

## Wallet

Each node has a wallet in `DIR/wallet`. It is created on first run with a
12-word BIP39 recovery phrase, shown once in the terminal and again with
`phrase`. Every output the wallet creates has its own one-time key, derived
from the phrase and a random nonce, and carries a 32-byte memo on chain that
only the phrase can read: it holds the nonce and the encrypted amount.

To recover a wallet from its phrase:

```
tabminer restore --data DIR2       # asks for the phrase and an optional passphrase
tabminer --data DIR2               # sync, then at the prompt:
> scan                             # finds the wallet's unspent outputs from their memos
```

Each output's key has 16 one-time signing leaves. A wallet signs its own
outputs from leaves 0 to 7 (a spend and up to seven cancellations, the last
one flagged); outputs found by `scan` sign from leaves 8 to 15, from a random
start, so a restored copy never signs with a leaf the original used.

Payments use slate files passed between the two wallets by any channel:

```
> send 10 0.5 /tmp/pay.slate        # sender: 10 coins, 0.5 fee; reserves inputs
> receive /tmp/pay.slate            # recipient: adds their output, writes /tmp/pay.slate.received
> finalize /tmp/pay.slate.received  # sender: signs and pools the transaction
> cancel ID                         # sender: replace it, before it confirms, with
                                    # one paying the inputs back at a higher fee
```

`balance` shows confirmed, pending (incoming), reserved (held for a slate)
and locked (signed and being sent) funds; `outputs`, `slates`, `sent`,
`mempool`, `peers` and `status` show the rest. The reward of a mined block goes to the miner's wallet.

To try two nodes on one machine:

```
tabminer mine --data /tmp/a --listen 127.0.0.1:7417
tabminer node --data /tmp/b --listen 127.0.0.1:7418 --peer 127.0.0.1:7417
```
