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
tabminer [mine] [--data DIR] [--blocks N] [--txs N] [--jobs N] [--no-mine] [net options]
tabminer node [--data DIR] [net options]
tabminer show [--data DIR]

net options: [--listen ADDR] [--peer ADDR]... [--seed HOST:PORT]... [--verbose]
```

`tabminer` with no command mines: it syncs to the heaviest chain its peers
know, then builds, proves, mines and announces blocks on the tip, starting
over whenever the network delivers a better tip. `tabminer node` follows the
chain without mining, as does `--no-mine`. Both listen on UDP port 7417 by default, contact the
seed nodes in `miner/src/node.rs` and any `--peer`, and keep the peers they
found in `DIR/peers` for next time. `show` prints the main chain.

Every node starts from the fixed mainnet genesis in `ChainParams::MAINNET`.

To try two nodes on one machine:

```
tabminer mine --data /tmp/a --listen 127.0.0.1:7417 --txs 0
tabminer node --data /tmp/b --listen 127.0.0.1:7418 --peer 127.0.0.1:7417
```
