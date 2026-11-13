#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# blocktest.sh — the node (bin/img's, run from its shell) serving and
# relaying blocks (docs/NODE.md, step 10).  On the host, tabminer A mines
# the recursive dev network (UDP 37471) to 6 blocks; its data is copied
# for tabminer C, which does not mine and whose only peer is the node (its
# UDP port forwarded from the host).  The node syncs from A (not mining
# then); A mines to 9 and the node follows.  Then C starts, three blocks
# behind: it pings the node (which takes it as a peer) and catches up
# from it alone, the node answering its requests for headers (GetHeaders,
# GetHeadersFrom) and blocks' chunks; then each block A mines reaches C
# through the node, which announces its tip once connected (its work
# checked in full).
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/blocktest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/blocktest
PA=${BLOCKTEST_A:-37471}; PC=${BLOCKTEST_C:-37478}; FWD=${BLOCKTEST_FWD:-37379}
[ -x "$MINER" ] || { echo "blocktest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "blocktest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; CP=; QP=
trap 'st=$?; exec 3>&- 2>/dev/null; for p in $QP $CP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
minera() {
	TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
		--listen 127.0.0.1:$PA --no-prompt "$@" >> "$T/a.out" 2>&1 &
	AP=$!
}
stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null || true; }
# wait_for FILE PATTERN SECONDS WHAT
. scripts/waitlib.sh

echo "blocktest.sh: A mining 6 blocks"
minera
wait_for "$T/a.out" 'is the tip at height 6$' 600 "A's 6 blocks"
stop $AP; AP=
cp -r "$T/a" "$T/c"
minera --no-mine

echo "blocktest.sh: the node syncing from A"
mkfifo "$T/in"
./tools/q32 --net --hostfwd=udp::$FWD-:3737 --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
echo "node -n devrec 10.0.2.2:$PA &" >&3
wait_own "$T/os.out" '^node: .* synced, height 6' 900 "the node's sync"
stop $AP; AP=
minera
echo "blocktest.sh: A mining to 9, the node following"
wait_for "$T/os.out" '^node: .* height 9  \(' 600 "the node at 9"
stop $AP; AP=

echo "blocktest.sh: C, at 6, its only peer the node"
"$MINER" mine --no-mine --network dev-recursive --data "$T/c" --no-seeds --listen 127.0.0.1:$PC \
	--peer 127.0.0.1:$FWD --no-prompt >> "$T/c.out" 2>&1 &
CP=$!
wait_for "$T/os.out" '^node: .* pinged us' 120 "C pinging the node"
grep 'pinged us' "$T/os.out"
wait_for "$T/c/tabminer.log" 'is the tip at height 9$' 600 "C catching up to 9 from the node"
grep -E 'is the tip at height (7|8|9)$' "$T/c/tabminer.log"
minera
echo "blocktest.sh: A mining on"
wait_for "$T/c/tabminer.log" 'is the tip at height 10$' 600 "C taking block 10"
grep -E 'is the tip at height 10$' "$T/c/tabminer.log"
grep -E '^node: .* relayed' "$T/os.out" | tail -2
grep -qE "block from 127\\.0\\.0\\.1:$FWD .* is the tip at height 10$" "$T/c/tabminer.log" \
	|| { echo "blocktest.sh: C's block 10 not from the node" >&2; exit 1; }
echo "blocktest.sh: C caught up from the node, then took A's next block through it"
