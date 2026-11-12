#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# stalltest.sh — the node answers its API while it works on a block
# (docs/NODE_ENHANCEMENTS.md, item 4), with no clock in the test: the
# node's only peer, a tabminer mining the recursive dev network, is
# reached through a UDP proxy (below) that can hold back the chunks of
# blocks.  The node syncs to 4; the chunks are held; the miner mines block
# 5; once the node has asked for its chunks (the proxy holding them), the
# API is asked for the status, and must answer that the node is fetching
# block 5 (a node that did not answer until the fetch gave up would say
# otherwise).  Then the chunks go through and the node connects block 5.
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/stalltest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/stalltest
PA=${STALLTEST_A:-37491}; PX=${STALLTEST_PROXY:-37492}; HP=${STALLTEST_API:-37493}
[ -x "$MINER" ] || { echo "stalltest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "stalltest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; XP=; QP=
trap 'st=$?; exec 3>&- 2>/dev/null; for p in $QP $XP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
minera() {
	TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
		--listen 127.0.0.1:$PA --no-prompt "$@" >> "$T/a.out" 2>&1 &
	AP=$!
}
stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null || true; }
# wait_for FILE PATTERN SECONDS WHAT
. scripts/waitlib.sh

# The proxy: datagrams from the node (the first address other than the
# miner's to send) to the miner and back; while $T/hold exists, the
# miner's Chunks (type 9) kept back, $T/held written at the first; once
# it is gone, those kept sent on.
python3 -u - "$PX" "$PA" "$T" > "$T/proxy.out" 2>&1 <<'EOF' &
import os, select, socket, sys
px, pa, t = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
miner = ('127.0.0.1', pa)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', px))
node, kept = None, []
print('proxy: up', flush=True)
while True:
    if kept and not os.path.exists(f'{t}/hold'):
        for d in kept:
            s.sendto(d, node)
        print(f'proxy: {len(kept)} chunks let through', flush=True)
        kept = []
    if not select.select([s], [], [], 0.2)[0]:
        continue
    d, a = s.recvfrom(2048)
    if a == miner:
        if node is None:
            continue
        if len(d) > 4 and d[:4] == b'TAB1' and d[4] == 9 and os.path.exists(f'{t}/hold'):
            if not kept:
                open(f'{t}/held', 'w').close()
                print('proxy: holding chunks', flush=True)
            kept.append(d)
        else:
            s.sendto(d, node)
    else:
        node = a
        s.sendto(d, miner)
EOF
XP=$!
wait_for "$T/proxy.out" '^proxy: up' 30 "the proxy"

echo "stalltest.sh: the node started while the chain has no block yet"
minera --no-mine
mkfifo "$T/in"
./tools/q32 --net --hostfwd=tcp::$HP-:3738 --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
echo "node -n devrec 10.0.2.2:$PX &" >&3
wait_for "$T/os.out" '^node: .* nothing to sync yet' 900 "the node waiting for a block"
python3 - "$HP" <<'EOF2'
import json, sys, urllib.request
with urllib.request.urlopen(f'http://127.0.0.1:{sys.argv[1]}/v1/status', timeout=120) as r:
    s = json.loads(r.read())
print(f'host: the status before any block: height {s["height"]}, activity {s.get("activity")}')
if s['height'] != 0:
    sys.exit('stalltest.sh: the status before any block is not at height 0')
EOF2

echo "stalltest.sh: the miner mining 4 blocks; the node syncing through the proxy"
stop $AP; AP=
minera
wait_for "$T/a.out" 'is the tip at height 4$' 600 "the miner's 4 blocks"
stop $AP; AP=
minera --no-mine
# (the node syncs on its next try, maybe while the miner still mines, and
# follows it from there: waited for at the miner's last block)
H=$(sed -n 's/.* is the tip at height \([0-9]*\)$/\1/p' "$T/a.out" | tail -1)
wait_for "$T/os.out" "^node: .* (synced, height $H\$|height $H  \\()" 900 "the node's sync to $H"
N=$((H + 1))

echo "stalltest.sh: chunks held; the miner mining block $N (and on)"
touch "$T/hold"
stop $AP; AP=
minera
wait_while_busy 600 "the node asking for block $N's chunks" test -e "$T/held"
python3 - "$HP" "$N" <<'EOF2'
import json, sys, urllib.request
with urllib.request.urlopen(f'http://127.0.0.1:{sys.argv[1]}/v1/status', timeout=120) as r:
    s = json.loads(r.read())
print(f'host: the status while the chunks are held: activity {s.get("activity")}, block {s.get("activity_height")}, height {s["height"]}')
if s.get('activity') != 'fetching' or s.get('activity_height') != int(sys.argv[2]):
    sys.exit(f'stalltest.sh: the API was not answered while the node fetched block {sys.argv[2]}')
EOF2
rm "$T/hold"
wait_for "$T/os.out" "^node: .* height $N  \\(" 600 "the node connecting block $N"
grep -E "^node: .* height $N  \\(" "$T/os.out"
echo "stalltest.sh: the API answered before any block, and while the node fetched one"
