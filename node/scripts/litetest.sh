#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# litetest.sh — a batch's blocks fetched lite (docs/NODE.md: without their
# proofs, which the batch's last block's chain proof attests), and a peer
# serving lite blocks that are not the block's.  A tabminer mining the
# recursive dev network to 12 blocks; then stopped, its directory copied
# for a second, which does not mine and serves every lite block with a
# byte of its proof's hash changed (TABMINER_TEST_LIE_LITE); the miner
# started again.  The node (src/user/node/sync_test.fam, given the second
# as /lib/peer2) fast-syncs from both: the blocks after its snapshot in one
# batch, all but the last lite.  Each lite block from the liar is refused
# for its body commitment and asked of the other; the sync ends on the
# tip's state root and follows the tip.  Needs tabminer built with the dev
# networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/litetest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/litetest
N=src/user/node
[ -x "$MINER" ] || { echo "litetest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/kernel ] || { echo "litetest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
./tools/fam --user -o "$T/tsy.bin" src/user/crypto/sha256.fam $N/arith.fam $N/poseidon2.fam $N/difficulty.fam $N/pow.fam $N/headers.fam \
	$N/chainver.fam $N/state.fam $N/proofs.fam $N/manifest.fam $N/connect.fam $N/query.fam $N/serve.fam $N/snap.fam $N/xmss.fam $N/tx.fam $N/wkeys.fam $N/events.fam $N/pool.fam $N/p2p.fam $N/cons.fam $N/api.fam $N/sync.fam $N/sync_test.fam
printf '37472\0' > "$T/peer2"
sh scripts/mkimage.sh "$T/sy.img" bin/kernel init="$T/tsy.bin":24576 akjv.txt.gz=../resources/akjv.txt.gz:0 \
	chainver=$N/chainver_dev.bin:0 devchain=$N/devchain.bin:0 peer2="$T/peer2":0
dd if=/dev/zero of="$T/sy.disk" bs=1 count=0 seek=268435456 2>/dev/null
MP=; LP=; QP=
trap 'st=$?; for p in $QP $LP $MP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
mine() {
	TABMINER_THREADS=${TABMINER_THREADS:-8} "$MINER" mine --network dev-recursive --data "$T/miner" --no-seeds \
		--listen 127.0.0.1:37471 --no-prompt >> "$T/miner.out" 2>&1 &
	MP=$!
}
. scripts/waitlib.sh
echo "litetest.sh: mining 12 blocks (about ten seconds each)"
mine
wait_for "$T/miner.out" 'is the tip at height 12$' 600 "the miner's 12 blocks"
kill $MP; wait $MP 2>/dev/null || true
cp -r "$T/miner" "$T/liar"
mine
TABMINER_TEST_LIE_LITE=1 "$MINER" mine --no-mine --network dev-recursive --data "$T/liar" --no-seeds \
	--listen 127.0.0.1:37472 --no-prompt > "$T/liar.out" 2>&1 &
LP=$!
echo "litetest.sh: syncing from both"
./tools/q32 --net --disk="$T/sy.disk" "$T/sy.img" > "$T/node.out" 2>&1 &
QP=$!
ended() { grep -q '^kernel: init ended' "$T/node.out" || ! kill -0 $QP 2>/dev/null; }
wait_while_busy 900 "the node's sync" ended
kill $QP 2>/dev/null; wait $QP 2>/dev/null || true; QP=
grep -E "^(sync|state root|followed):|refused|blocks [0-9]+ to" "$T/node.out" || true
grep -q '^sync: 0 ' "$T/node.out" || { echo "litetest.sh: the sync failed" >&2; wdump; exit 1; }
grep -q '^state root: the tip.s$' "$T/node.out" || { echo "litetest.sh: the state root is not the tip's" >&2; exit 1; }
grep -q 'from peer 10\.0\.2\.2:37472 refused' "$T/node.out" || { echo "litetest.sh: no lite block of the liar's refused" >&2; exit 1; }
! grep -q 'from peer 10\.0\.2\.2:37471 refused' "$T/node.out" || { echo "litetest.sh: the honest miner's block refused" >&2; exit 1; }
grep -qE '^followed: [1-9]' "$T/node.out" || { echo "litetest.sh: no block followed" >&2; exit 1; }
echo "litetest.sh: the liar's lite blocks refused, synced from the other"
