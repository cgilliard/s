#!/bin/sh
# reorgtest.sh — the node (bin/img's, run from its shell) resuming and
# reorganizing (docs/NODE.md, step 10).  On the host, tabminer A mines the
# recursive dev network (UDP 37471) to 6 blocks and stops; its data is
# copied for tabminer B.  A mines again; in the OS, `node 10.0.2.2:37471`
# syncs and follows; it is killed (/proc/<pid>/kill) and run again: it
# resumes from its store (no new sync) and follows with every proof checked.
# Then A stops at height a, and B (UDP 37476, no peers) mines its own
# branch from 6 to a + 2; A is started again, not mining, with B as its
# peer: A reorganizes onto B's branch and the node, following A, must too:
# its blocks above 6 undone, B's connected, up to B's tip.
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/reorgtest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/reorgtest
[ -x "$MINER" ] || { echo "reorgtest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "reorgtest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; BP=; QP=
trap 'st=$?; exec 3>&- 2>/dev/null; for p in $QP $BP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
# minera [args...], minerb: the two tabminers, in the background
minera() {
	TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
		--listen 127.0.0.1:37471 --no-prompt "$@" >> "$T/a.out" 2>&1 &
	AP=$!
}
minerb() {
	TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/b" --no-seeds \
		--listen 127.0.0.1:37476 --no-prompt >> "$T/b.out" 2>&1 &
	BP=$!
}
stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null || true; }
# wait_for FILE PATTERN SECONDS WHAT
wait_for() {
	i=0
	until grep -qE "$2" "$1" 2>/dev/null; do
		[ $i -lt "$3" ] || { echo "reorgtest.sh: $4: not in $3 s" >&2; exit 1; }
		sleep 2; i=$((i + 2))
	done
}
# tip FILE — the last height a tabminer's log has as its tip
tip() { sed -n 's/.* is the tip at height \([0-9]*\)$/\1/p' "$1" | tail -1; }
# heights — how many blocks the node has said it followed
heights() { grep -c '^node: .* height [0-9]*  (' "$T/os.out" || true; }

echo "reorgtest.sh: A mining 6 blocks"
minera
wait_for "$T/a.out" 'is the tip at height 6$' 600 "A's 6 blocks"
stop $AP; AP=
cp -r "$T/a" "$T/b"
minera

echo "reorgtest.sh: the node syncing from A"
mkfifo "$T/in"
./tools/q32 --net --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
echo "node 10.0.2.2:37471 &" >&3
wait_for "$T/os.out" '^node: .* height [0-9]+  \(' 900 "the node following A"
PID=$(sed -n 's/^\$* *\[\([0-9]*\)\]$/\1/p' "$T/os.out" | head -1)
echo "reorgtest.sh: the node (pid $PID) killed, and run again"
echo "echo 1 > /proc/$PID/kill" >&3
wait_for "$T/os.out" "\[$PID\] done" 30 "the node ending"
n=$(heights)
echo "node 10.0.2.2:37471 &" >&3
wait_for "$T/os.out" '^node: .* resumed at height|^node: .* syncing from.*$' 120 "the node starting again"
[ "$(grep -c 'syncing from' "$T/os.out")" = 1 ] || { echo "reorgtest.sh: the node synced again rather than resume" >&2; exit 1; }
i=0; until [ "$(heights)" -gt "$n" ]; do [ $i -lt 300 ] || { echo "reorgtest.sh: no block followed after resuming" >&2; exit 1; }; sleep 2; i=$((i + 2)); done
grep '^node: .* resumed at' "$T/os.out"
grep '^node: .* height [0-9]*  (' "$T/os.out" | tail -1 | grep -qv 'proof 0\.00' \
	|| { echo "reorgtest.sh: a block followed after resuming without its proof checked" >&2; exit 1; }

a=$(tip "$T/a.out")
stop $AP; AP=
echo "reorgtest.sh: A stopped at $a; B mining its own branch from 6 to $((a + 2))"
minerb
wait_for "$T/b.out" "is the tip at height $((a + 2))\$" 600 "B's branch"
echo "reorgtest.sh: A again, not mining, B its peer"
minera --no-mine --peer 127.0.0.1:37476
wait_for "$T/a.out" 'reorganized onto' 300 "A reorganizing"
grep 'reorganized onto' "$T/a.out" | tail -1
wait_for "$T/os.out" '^node: .* reorganizing' 300 "the node reorganizing"
b=$(tip "$T/b.out")
wait_for "$T/os.out" "^node: .* height $b  \\(" 600 "the node at B's tip ($b)"
grep -E '^node: .* (reorganizing|undone|height|refused|cannot)' "$T/os.out" | tail -12
! grep -qE '^node: .* (refused|cannot undo)' "$T/os.out" || { echo "reorgtest.sh: a block refused, or one not undone" >&2; exit 1; }
echo "reorgtest.sh: the node resumed, and reorganized onto the longer branch"
