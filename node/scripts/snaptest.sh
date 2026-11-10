#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# snaptest.sh — a tabminer fast-syncing from the node (docs/NODE.md, step
# 10): the node (bin/img's, run from its shell) serves headers, blocks,
# and snapshots' manifests and parts.  On the host, tabminer A mines the
# recursive dev network (UDP 37471), its wallet's prompt open; the node
# syncs and follows; A's wallet burns a coin, mined at height m; once the
# node is at m + 2, A stops.  Then tabminer D, new (no data), its only
# peer the node (its UDP port forwarded) and --sync-point 4, fast-syncs:
# the state after block m - 2, before the burn, so the output part with
# the coin it spends must hold it (spent since, rebuilt from the node's
# record of it); D checks each part's root, the whole against the block's
# state root, and follows to the node's tip.
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/snaptest.sh
set -e
cd "$(dirname "$0")/.."
MINER=${SNAPTEST_MINER:-../miner/target/release/tabminer}
T=tmp/snaptest
PA=${SNAPTEST_A:-37471}; PD=${SNAPTEST_D:-37480}; FWD=${SNAPTEST_FWD:-37382}
[ -x "$MINER" ] || { echo "snaptest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "snaptest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; DP=; QP=
trap 'st=$?; exec 3>&- 4>&- 2>/dev/null; for p in $QP $DP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
. scripts/waitlib.sh
tip() { sed -n 's/.* is the tip at height \([0-9]*\)$/\1/p' "$1/tabminer.log" | tail -1; }

echo "snaptest.sh: A mining, its prompt open"
mkfifo "$T/a.in"
TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
	--listen 127.0.0.1:$PA < "$T/a.in" >> "$T/a.out" 2>&1 &
AP=$!
exec 4> "$T/a.in"
wait_for "$T/a/tabminer.log" 'is the tip at height 6$' 600 "A's 6 blocks"

echo "snaptest.sh: the node syncing from A"
mkfifo "$T/in"
./tools/q32 --net --hostfwd=udp::$FWD-:3737 --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
echo "node -n devrec 10.0.2.2:$PA &" >&3
wait_for "$T/os.out" '^node: .* synced' 900 "the node's sync"

echo "snaptest.sh: A's wallet burning a coin"
echo "burn 1 snap-test" >&4
wait_for "$T/os.out" 'pool: 0 ' 120 "the node pooling the burn"
wait_for "$T/os.out" '^node: .* the pool: 0 held, 1 out' 300 "the burn mined"
m=$(grep -E '^node: .* (height [0-9]+  \(|the pool: 0 held, 1 out)' "$T/os.out" | grep -B1 'the pool: 0 held, 1 out' | head -1 | sed -n 's/.* height \([0-9]*\)  (.*/\1/p')
echo "snaptest.sh: the burn mined at $m"
wait_for "$T/os.out" "^node: .* height $((m + 2))  \\(" 300 "the node at $((m + 2))"
echo "quit" >&4; exec 4>&-
wait $AP 2>/dev/null || true; AP=
t=$(grep '^node: .* height [0-9]*  (' "$T/os.out" | tail -1 | sed -n 's/.* height \([0-9]*\)  (.*/\1/p')
echo "snaptest.sh: A stopped; the node's tip $t"

echo "snaptest.sh: D, new, fast-syncing from the node alone (--sync-point 4)"
"$MINER" mine --no-mine --network dev-recursive --data "$T/d" --no-seeds --listen 127.0.0.1:$PD \
	--peer 127.0.0.1:$FWD --sync-point 4 --no-prompt >> "$T/d.out" 2>&1 &
DP=$!
wait_for "$T/d/tabminer.log" 'fast sync: installed the state after block' 900 "D's fast sync"
grep -E 'fast sync: (installed|.*refused|.*does not fit)' "$T/d/tabminer.log"
s=$(sed -n 's/.*fast sync: installed the state after block \([0-9]*\) .*/\1/p' "$T/d/tabminer.log" | tail -1)
[ "$s" -lt "$m" ] || { echo "snaptest.sh: D's snapshot ($s) not before the burn ($m)" >&2; exit 1; }
wait_for "$T/d/tabminer.log" "is the tip at height $t\$" 600 "D at the node's tip ($t)"
! grep -qE 'fast sync: .*(refused|does not fit)' "$T/d/tabminer.log" || { echo "snaptest.sh: a part or manifest refused" >&2; exit 1; }
echo "snaptest.sh: D fast-synced from the node (the state after block $s, before the burn at $m) and followed to $t"
