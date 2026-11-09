#!/bin/sh
# pooltest.sh — a transaction from tabminer's wallet relayed by the fam node
# and mined (docs/NODE.md, step 7).  On the host: a tabminer mining the
# recursive dev network (UDP 3747, a fresh data directory, no seeds) to 12
# blocks; then stopped, its directory copied for a second tabminer, which
# does not mine (3748) and keeps the wallet, and the miner started again.
# The two never meet: each has only the node for a peer.  The node boots
# (src/user/node/relay_test.fam), syncs from the miner and pings the
# wallet's node; once that one has the node for a live peer, the wallet
# burns a coin.  The wallet's node announces the transaction to the node,
# which fetches it, pools it and announces it to the miner, which fetches
# it from the node and mines it; the node follows and sees it leave its
# pool.  Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/pooltest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/pooltest
N=src/user/node
[ -x "$MINER" ] || { echo "pooltest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/kernel ] || { echo "pooltest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"

./tools/fam --user -o "$T/trl.bin" $N/arith.fam $N/poseidon2.fam $N/difficulty.fam $N/pow.fam $N/headers.fam \
	$N/chainver.fam $N/state.fam $N/proofs.fam $N/connect.fam $N/snap.fam $N/xmss.fam $N/tx.fam $N/pool.fam \
	$N/p2p.fam $N/sync.fam $N/relay_test.fam
sh scripts/mkimage.sh "$T/rl.img" bin/kernel init="$T/trl.bin":24576 akjv.txt.gz=../resources/akjv.txt.gz:0 \
	chainver=$N/chainver_dev.bin:0 devchain=$N/devchain.bin:0
dd if=/dev/zero of="$T/rl.disk" bs=1 count=0 seek=268435456 2>/dev/null

MP=; WP=; QP=
trap 'st=$?; exec 3>&- 2>/dev/null; for p in $QP $WP $MP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
mine() {
	TABMINER_THREADS=${TABMINER_THREADS:-8} "$MINER" mine --network dev-recursive --data "$T/miner" --no-seeds \
		--listen 127.0.0.1:3747 --no-prompt >> "$T/miner.out" 2>&1 &
	MP=$!
}
# wait_for FILE PATTERN SECONDS WHAT
wait_for() {
	i=0
	until grep -qE "$2" "$1" 2>/dev/null; do
		[ $i -lt "$3" ] || { echo "pooltest.sh: $4: not in $3 s" >&2; exit 1; }
		sleep 2; i=$((i + 2))
	done
}

echo "pooltest.sh: mining 12 blocks (about ten seconds each)"
mine
wait_for "$T/miner.out" 'is the tip at height 12$' 600 "the miner's 12 blocks"
kill $MP; wait $MP 2>/dev/null || true
cp -r "$T/miner" "$T/wallet"
mine
mkfifo "$T/wallet.in"
"$MINER" mine --no-mine --network dev-recursive --data "$T/wallet" --no-seeds --listen 127.0.0.1:3748 \
	< "$T/wallet.in" > "$T/wallet.out" 2>&1 &
WP=$!
exec 3> "$T/wallet.in"

echo "pooltest.sh: the node syncing"
./tools/q32 --net --disk="$T/rl.disk" "$T/rl.img" > "$T/node.out" 2>&1 &
QP=$!
wait_for "$T/node.out" '^wallet peer: |^sync: -' 900 "the sync"
grep -E "^(sync|wallet peer):" "$T/node.out"
grep -q '^wallet peer: answered' "$T/node.out" || { echo "pooltest.sh: no sync or no wallet peer" >&2; exit 1; }
# The wallet's node takes the node for a live peer once the node answers
# its Ping, and logs the peer then.
wait_for "$T/wallet/tabminer.log" 'peer 127\.0\.0\.1:[0-9]+ \(height' 60 "the wallet's node taking the node for a peer"
echo "burn 1 pooltest" >&3
wait_for "$T/node.out" '^left the pool:' 600 "the transaction mined"
kill $QP; wait $QP 2>/dev/null || true; QP=
grep -E "^(pool|left the pool):" "$T/node.out"
grep -q '^pool: 0 ' "$T/node.out" || { echo "pooltest.sh: the node did not pool the transaction" >&2; exit 1; }
grep -E 'transaction from 127\.0\.0\.1:[0-9]+ .* pooled' "$T/miner/tabminer.log" \
	|| { echo "pooltest.sh: the miner did not take the transaction from the node" >&2; exit 1; }
# The block that mined it: one with an input (a block's reward is a
# transaction of none).
grep -E 'block [0-9]+ on .*: [0-9]+ txs \([1-9][0-9]* in' "$T/miner/tabminer.log" | head -1 | grep . \
	|| { echo "pooltest.sh: no block of the miner's spent an input" >&2; exit 1; }
echo "pooltest.sh: relayed and mined"
