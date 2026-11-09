#!/bin/sh
# windowtest.sh — the node (bin/img's, run from its shell) holding only a
# window of the headers (docs/NODE.md, step 10).  On the host, tabminer A
# mines the recursive dev network (UDP 37471) to 8 blocks.  In the OS,
# `node -w 16 10.0.2.2:37471` (16 headers' room, not 16,384) syncs, then
# follows to 26: those below the newest go to the store alone (several
# times).  Then:
# - the API (forwarded from the host) answers header 3, held no more,
#   from the store: its id A's block 3's; and the same asked for by its id
#   (the store's index of ids);
# - the node, killed and run again, resumes from the store's last 8
#   headers (a root, not block 1 up) and follows on, proofs checked.
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/windowtest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/windowtest
PA=${WINDOWTEST_A:-37471}; HP=${WINDOWTEST_API:-37381}
[ -x "$MINER" ] || { echo "windowtest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "windowtest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; QP=
trap 'st=$?; exec 3>&- 2>/dev/null; for p in $QP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
wait_for() {
	i=0
	until grep -qE "$2" "$1" 2>/dev/null; do
		[ $i -lt "$3" ] || { echo "windowtest.sh: $4: not in $3 s" >&2; exit 1; }
		sleep 2; i=$((i + 2))
	done
}
heights() { grep -c '^node: .* height [0-9]*  (' "$T/os.out" || true; }

echo "windowtest.sh: A mining 8 blocks"
TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
	--listen 127.0.0.1:$PA --no-prompt >> "$T/a.out" 2>&1 &
AP=$!
wait_for "$T/a.out" 'is the tip at height 8$' 600 "A's 8 blocks"

echo "windowtest.sh: node -w 16, syncing and following to 26"
mkfifo "$T/in"
./tools/q32 --net --hostfwd=tcp::$HP-:3738 --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
echo "node -w 16 10.0.2.2:$PA &" >&3
wait_for "$T/os.out" '^node: .* synced' 900 "the node's sync"
wait_for "$T/os.out" '^node: .* height 26  \(' 900 "the node at 26"
grep 'now only in the store' "$T/os.out" | tail -3
[ "$(grep -c 'now only in the store' "$T/os.out")" -ge 2 ] || { echo "windowtest.sh: the headers were not moved to the store" >&2; exit 1; }

TOKEN=$(sed -n 's/^node: .* the API on port 3738, token \([0-9a-f]*\)$/\1/p' "$T/os.out" | head -1)
ID3=$(sed -n 's/.*our block \([0-9a-f]*\) is the tip at height 3$/\1/p' "$T/a.out" | tail -1)
python3 - "$HP" "$TOKEN" "$ID3" <<'EOF'
import json, sys, urllib.request
port, token, id3 = sys.argv[1:4]
def ask(path):
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}')
    req.add_header('Authorization', f'Bearer {token}')
    with urllib.request.urlopen(req, timeout=40) as r:
        return r.read()
h = json.loads(ask('/v1/header/3'))
ok = h['height'] == 3 and h['id'].startswith(id3)
print(f'host: header 3 from the store: id {h["id"][:16]}, A\'s {id3}: {"ok" if ok else "FAILED"}')
raw = ask('/v1/header/3?raw')
print(f'host: raw, {len(raw)} bytes: {"ok" if len(raw) == 204 else "FAILED"}')
by_id = json.loads(ask('/v1/header/' + h['id']))
print(f'host: header 3 by its id, from the store\'s index: {"ok" if by_id == h else "FAILED"}')
sys.exit(0 if ok and len(raw) == 204 and by_id == h else 1)
EOF

PID=$(sed -n 's/^\$* *\[\([0-9]*\)\]$/\1/p' "$T/os.out" | head -1)
echo "windowtest.sh: the node (pid $PID) killed, and run again"
echo "echo 1 > /proc/$PID/kill" >&3
wait_for "$T/os.out" "\[$PID\] done" 30 "the node ending"
n=$(heights)
echo "node -w 16 10.0.2.2:$PA &" >&3
wait_for "$T/os.out" '^node: .* resumed at height' 120 "the node resuming"
grep -E '^node: .* (loading|resumed)' "$T/os.out" | tail -2
grep -E '^node: .* loading 8 headers' "$T/os.out" > /dev/null || { echo "windowtest.sh: not resumed from a window" >&2; exit 1; }
i=0; until [ "$(heights)" -ge $((n + 2)) ]; do [ $i -lt 300 ] || { echo "windowtest.sh: no blocks followed after resuming" >&2; exit 1; }; sleep 2; i=$((i + 2)); done
grep '^node: .* height [0-9]*  (' "$T/os.out" | tail -2
grep '^node: .* height [0-9]*  (' "$T/os.out" | tail -1 | grep -qv 'proof 0\.00' || { echo "windowtest.sh: a block followed without its proof checked" >&2; exit 1; }
echo "windowtest.sh: headers moved to the store and served from it, and resumed from a window"
