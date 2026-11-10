#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# peertest.sh — the node (bin/img's, run from its shell) finding peers and
# keeping to the chain when one goes (docs/NODE.md, step 10).  On the host,
# tabminers A (UDP 37471) and B (37477) mine the recursive dev network
# together, each the other's peer.  In the OS, `node 10.0.2.2:37471` is
# given A only: it syncs from A and learns of B, either told of it by A
# (GetPeers: as 127.0.0.1, its host's, 10.0.2.2 from the guest) or pinged
# by B, which A told of the node; it pings B.  Then A is killed: the node
# follows B, B's blocks connected to past where A stopped.
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/peertest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/peertest
PA=${PEERTEST_A:-37471}; PB=${PEERTEST_B:-37477}
[ -x "$MINER" ] || { echo "peertest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "peertest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; BP=; QP=
trap 'st=$?; exec 3>&- 2>/dev/null; for p in $QP $BP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
# miner NAME PORT OTHER: a tabminer mining, the other its peer
miner() {
	TABMINER_THREADS=${TABMINER_THREADS:-2} "$MINER" mine --network dev-recursive --data "$T/$1" --no-seeds \
		--listen 127.0.0.1:$2 --peer 127.0.0.1:$3 --no-prompt >> "$T/$1.out" 2>&1 &
}
# wait_for FILE PATTERN SECONDS WHAT
wait_for() {
	i=0
	until grep -qE "$2" "$1" 2>/dev/null; do
		[ $i -lt "$3" ] || { echo "peertest.sh: $4: not in $3 s" >&2; exit 1; }
		sleep 2; i=$((i + 2))
	done
}
tip() { sed -n 's/.* is the tip at height \([0-9]*\)$/\1/p' "$1" | tail -1; }

echo "peertest.sh: A and B mining together to 6"
miner a $PA $PB; AP=$!
miner b $PB $PA; BP=$!
wait_for "$T/a.out" 'is the tip at height 6$' 600 "A at 6"

echo "peertest.sh: the node, given A only"
mkfifo "$T/in"
./tools/q32 --net --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
echo "node 10.0.2.2:$PA &" >&3
wait_for "$T/os.out" '^node: .* (synced|resumed)' 900 "the node's sync"
# B told of by A (GetPeers), or B, told of the node by A, pinging it first
wait_for "$T/os.out" "^node: .* peer 10\\.0\\.2\\.2:$PB (told of|pinged us)" 180 "the node learning of B"
grep -E "told of|pinged us" "$T/os.out"

a=$(tip "$T/a.out")
kill $AP; wait $AP 2>/dev/null || true; AP=
echo "peertest.sh: A killed at $a; B mining on"
wait_for "$T/os.out" "^node: .* following peer 10\\.0\\.2\\.2:$PB" 300 "the node following B"
grep "following peer" "$T/os.out"
b=$((a + 2))
wait_for "$T/os.out" "^node: .* height $b  \\(" 600 "the node at $b, from B"
grep -E '^node: .* (height|refused|passed over|lost)' "$T/os.out" | tail -6
echo "peertest.sh: the node found B through A, and followed it with A gone"
