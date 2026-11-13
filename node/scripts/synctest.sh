#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# synctest.sh — the fam node syncing from a tabminer over UDP (docs/NODE.md,
# step 6).  A tabminer mining the recursive dev network runs on the host
# (UDP 37471, a fresh data directory, no seeds); once it has 12 blocks, the
# node boots (src/user/node/sync_test.fam) and fast-syncs from the
# snapshot 4 blocks below its best header: headers, the full proof of work
# from there up, the block and its snapshot, its chain proof, the blocks
# after it each with their proofs.  Then it follows the tip for two more
# blocks.  Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/synctest.sh [blocks]   (12 by default)
set -e
cd "$(dirname "$0")/.."
WANT=${1:-12}
MINER=../miner/target/release/tabminer
T=tmp/synctest
N=src/user/node
[ -x "$MINER" ] || { echo "synctest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/kernel ] || { echo "synctest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"

./tools/fam --user -o "$T/tsy.bin" src/user/crypto/sha256.fam $N/arith.fam $N/poseidon2.fam $N/difficulty.fam $N/pow.fam $N/headers.fam \
	$N/chainver.fam $N/state.fam $N/proofs.fam $N/manifest.fam $N/connect.fam $N/query.fam $N/serve.fam $N/snap.fam $N/xmss.fam $N/tx.fam $N/wkeys.fam $N/events.fam $N/pool.fam $N/p2p.fam $N/cons.fam $N/api.fam $N/sync.fam $N/sync_test.fam
sh scripts/mkimage.sh "$T/sy.img" bin/kernel init="$T/tsy.bin":24576 akjv.txt.gz=../resources/akjv.txt.gz:0 \
	chainver=$N/chainver_dev.bin:0 devchain=$N/devchain.bin:0
dd if=/dev/zero of="$T/sy.disk" bs=1 count=0 seek=268435456 2>/dev/null

TABMINER_THREADS=${TABMINER_THREADS:-8} "$MINER" mine --network dev-recursive --data "$T/miner" --no-seeds \
	--listen 127.0.0.1:37471 --no-prompt > "$T/miner.out" 2>&1 &
MP=$!
trap 'st=$?; kill $MP 2>/dev/null; wait $MP 2>/dev/null || true; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
echo "synctest.sh: mining $WANT blocks (about ten seconds each)"
. scripts/waitlib.sh
wait_for "$T/miner.out" "is the tip at height $WANT\$" 600 "the miner's $WANT blocks"
echo "synctest.sh: syncing"
./tools/q32 --net --disk="$T/sy.disk" "$T/sy.img" > "$T/node.out" 2>&1 &
QP=$!
ended() { grep -q '^kernel: init ended' "$T/node.out" || ! kill -0 $QP 2>/dev/null; }
wait_while_busy 900 "the node's sync" ended
kill $QP 2>/dev/null; wait $QP 2>/dev/null || true
cat "$T/node.out" | grep -E "^(sync|state root|followed):"
grep -q '^sync: 0 ' "$T/node.out" || { echo "synctest.sh: the sync failed" >&2; exit 1; }
grep -q '^state root: the tip.s$' "$T/node.out" || { echo "synctest.sh: the state root is not the tip's" >&2; exit 1; }
grep -qE '^followed: [1-9]' "$T/node.out" || { echo "synctest.sh: no block followed" >&2; exit 1; }
echo "synctest.sh: synced and followed"
