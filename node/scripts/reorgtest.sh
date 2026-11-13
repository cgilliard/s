#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# reorgtest.sh — the node (bin/img's, run from its shell) resuming and
# reorganizing (docs/NODE.md, step 10).  On the host, tabminer A mines the
# recursive dev network (UDP 37471) to 6 blocks and stops; its data is
# copied for tabminer B.  A mines again, its wallet's prompt open; in the
# OS, `node 10.0.2.2:37471` syncs and follows; it is killed
# (/proc/<pid>/kill) and run again: it resumes from its store (no new sync)
# and follows with every proof checked.  A's wallet burns a coin (block 1's
# reward: the wallet spends the oldest of equal coins): the node pools the
# transaction, and when A mines it, shelves it.  Then A stops at height a,
# and B (UDP 37476, no peers, its pool empty) mines its own branch from 6
# until it outweighs A's (more work, not more blocks: B's may come at a
# lower difficulty); A is started again, not mining, with B as its peer: A
# reorganizes onto B's branch and the node, following A, must too: its
# blocks above 6 undone, B's connected, up to B's tip; and the burn, mined
# on no block of B's branch and its input unspent there, back in its pool.
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/reorgtest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/reorgtest
PA=${REORGTEST_A:-37471}; PB=${REORGTEST_B:-37476}   # the two tabminers' UDP ports
[ -x "$MINER" ] || { echo "reorgtest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "reorgtest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; BP=; QP=
trap 'st=$?; exec 3>&- 4>&- 2>/dev/null; for p in $QP $BP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
# minera [args...], minerb: the two tabminers, in the background
minera() {
	TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
		--listen 127.0.0.1:$PA --no-prompt "$@" >> "$T/a.out" 2>&1 &
	AP=$!
}
# minerp: A mining with its prompt read from $T/a.in (written on fd 4)
minerp() {
	TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
		--listen 127.0.0.1:$PA < "$T/a.in" >> "$T/a.out" 2>&1 &
	AP=$!
}
minerb() {
	TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/b" --no-seeds \
		--listen 127.0.0.1:$PB --no-prompt "$@" >> "$T/b.out" 2>&1 &
	BP=$!
}
stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null || true; }
# wait_for FILE PATTERN SECONDS WHAT
. scripts/waitlib.sh
# tip DIR — the last height a tabminer's log (its data directory's: with
# its prompt open it says little on its output) has as its tip
tip() { sed -n 's/.* is the tip at height \([0-9]*\)$/\1/p' "$1/tabminer.log" | tail -1; }
# heights — how many blocks the node has said it followed
heights() { grep -c '^node: .* height [0-9]*  (' "$T/os.out" || true; }

echo "reorgtest.sh: A mining 6 blocks"
minera
wait_for "$T/a.out" 'is the tip at height 6$' 600 "A's 6 blocks"
stop $AP; AP=
cp -r "$T/a" "$T/b"
mkfifo "$T/a.in"
minerp
exec 4> "$T/a.in"

echo "reorgtest.sh: the node syncing from A"
mkfifo "$T/in"
./tools/q32 --net --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
echo "node -n devrec 10.0.2.2:$PA &" >&3
wait_for "$T/os.out" '^node: .* height [0-9]+  \(' 900 "the node following A"
PID=$(sed -n 's/^\$* *\[\([0-9]*\)\]$/\1/p' "$T/os.out" | head -1)
echo "reorgtest.sh: the node (pid $PID) killed, and run again"
echo "echo 1 > /proc/$PID/kill" >&3
wait_for "$T/os.out" "\[$PID\] done" 30 "the node ending"
n=$(heights)
echo "node -n devrec 10.0.2.2:$PA &" >&3
wait_for "$T/os.out" '^node: .* resumed at height|^node: .* syncing from.*$' 120 "the node starting again"
[ "$(grep -c 'syncing from' "$T/os.out")" = 1 ] || { echo "reorgtest.sh: the node synced again rather than resume" >&2; exit 1; }
more() { [ "$(heights)" -gt "$n" ]; }
wait_while_busy 300 "a block followed after resuming" more
grep '^node: .* resumed at' "$T/os.out"
# (blocks are connected by batches, one proof checked for each: the
# batch's line gives its time, NODE_ENHANCEMENTS.md item 21)
grep '^node: .* blocks [0-9]* to [0-9]*: ' "$T/os.out" | tail -1 | grep -q "the last one's proof in [0-9.]* s" \
	&& ! grep '^node: .* blocks [0-9]* to [0-9]*: ' "$T/os.out" | tail -1 | grep -q "proof in 0\.00 s" \
	|| { echo "reorgtest.sh: a block followed after resuming without its proof checked" >&2; exit 1; }

echo "reorgtest.sh: A's wallet burning a coin"
echo "burn 1 reorg-test" >&4
wait_for "$T/a.out" 'pooled; broadcasting' 60 "A's burn"
wait_for "$T/os.out" 'pool: 0 ' 120 "the node pooling the burn"
wait_for "$T/os.out" '^node: .* the pool: 0 held, 1 out' 300 "the burn mined, and shelved by the node"
grep -E 'pool: 0 |the pool: 0 held, 1 out' "$T/os.out"
a=$(tip "$T/a")
echo "quit" >&4; exec 4>&-
wait $AP 2>/dev/null || true; AP=
echo "reorgtest.sh: A stopped at $a; B mining its own branch from 6 until it outweighs A's"
minerb
# The heavier branch wins, not the longer: B's blocks may come at a lower
# difficulty than A's did (a slower machine, longer gaps), so B mines
# until its blocks above 6 hold a quarter more work than A's, each
# block's work as its miner logged it.
outweighs() {
	python3 - "$T/a/tabminer.log" "$T/b/tabminer.log" <<'PYEOF'
import re, sys
def work(log):
    t = open(log, errors='replace').read()
    mined = {m.group(1): 2 ** float(m.group(2)) for m in re.finditer(r'mined ([0-9a-f]{16}) after \d+ hashes in [\d.]+s \(work 2\^([\d.]+)\)', t)}
    tips = {m.group(1): int(m.group(2)) for m in re.finditer(r'our block ([0-9a-f]{16}) is the tip at height (\d+)', t)}
    return sum(w for h, w in mined.items() if tips.get(h, 0) > 6)
a, b = work(sys.argv[1]), work(sys.argv[2])
sys.exit(0 if a > 0 and b > 1.25 * a else 1)
PYEOF
}
wait_while_busy 600 "B's branch outweighing A's" outweighs
grep -E 'mined .*\(work 2\^' "$T/b/tabminer.log" | tail -3
# B's branch fixed from here (B serving, not mining): the waits below see
# a stall as one (B's mining kept the logs growing, so a reorganization
# that never came was waited for until CI's limit), and the burn is not
# mined on B's branch.
stop $BP; BP=
minerb --no-mine
echo "reorgtest.sh: A again, not mining, B its peer"
minera --no-mine --peer 127.0.0.1:$PB
wait_for "$T/a.out" 'reorganized onto' 300 "A reorganizing"
grep 'reorganized onto' "$T/a.out" | tail -1
wait_for "$T/os.out" '^node: .* reorganizing' 300 "the node reorganizing"
b=$(tip "$T/b")
wait_for "$T/os.out" "^node: .* height $b  \\(" 600 "the node at B's tip ($b)"
wait_for "$T/os.out" '^node: .* the pool: 1 held, .* 1 back' 120 "the burn back in the node's pool"
grep -E '^node: .* (reorganizing|undone|height|refused|cannot|the pool)' "$T/os.out" | tail -14
! grep -qE '^node: .* (refused|cannot undo)' "$T/os.out" || { echo "reorgtest.sh: a block refused, or one not undone" >&2; exit 1; }
# The pool kept across a restart: B stopped (and A not mining), so nothing
# mines the burn; once the node has B's last block, what it holds is
# final; killed and run again, it takes the same back.
stop $BP; BP=
b=$(tip "$T/b")
wait_for "$T/os.out" "^node: .* height $b  \\(" 600 "the node at B's last tip ($b)"
held=$(grep -E '^node: .* the pool: [0-9]+ held' "$T/os.out" | tail -1 | sed -n 's/.* the pool: \([0-9]*\) held.*/\1/p')
PID=$(sed -n 's/^\$* *\[\([0-9]*\)\]$/\1/p' "$T/os.out" | tail -1)
echo "reorgtest.sh: B stopped; the node (pid $PID, $held pooled) killed, and run again"
# (pids are used again: the first run's "[3] done" is no sign of this one's)
dones=$(grep -c "\[$PID\] done" "$T/os.out")
echo "echo 1 > /proc/$PID/kill" >&3
ended() { [ "$(grep -c "\[$PID\] done" "$T/os.out")" -gt "$dones" ]; }
wait_while_busy 30 "the node ending" ended
# (the API comes up at once; the pool is taken back once the node has
# resumed from its store: waited for by its line, "resumed at height")
res=$(grep -c '^node: .* resumed at height' "$T/os.out" || true)
kept=$(grep -c '^node: .* kept from before taken back' "$T/os.out" || true)
echo "node -n devrec 10.0.2.2:$PA &" >&3
resumed() { [ "$(grep -c '^node: .* resumed at height' "$T/os.out")" -gt "$res" ]; }
wait_while_busy 300 "the node resuming" resumed
if [ "$held" -gt 0 ]; then
	taken() { [ "$(grep -c '^node: .* kept from before taken back' "$T/os.out")" -gt "$kept" ]; }
	wait_while_busy 120 "the pool taken back after the restart" taken
	grep -E '^node: .* kept from before taken back' "$T/os.out" | tail -1 | grep -q " the pool: $held of $held kept" \
		|| { echo "reorgtest.sh: the pool not taken back after the restart ($held held before)" >&2; exit 1; }
fi
echo "reorgtest.sh: the node resumed, reorganized onto the longer branch, took the burn back into its pool, and kept its pool across a restart"
