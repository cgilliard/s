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
# Last, a block served while the node connects one (below).
# Before that, the sync to 4 runs with another address chattering at the
# node (junk datagrams every 10 ms) and the miner's answers 100 ms late:
# the node's waits for its peer must not end at others' datagrams
# (docs/TIMING_FIXES.md, Phase 1 item 2; they did, and the headers' rounds
# ran out: the sync stopped -3).
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/stalltest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/stalltest
PA=${STALLTEST_A:-37491}; PX=${STALLTEST_PROXY:-37492}; HP=${STALLTEST_API:-37493}; PU=${STALLTEST_UDP:-37494}
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
# it is gone, those kept sent on.  While $T/chatter exists, the miner's
# datagrams reach the node 100 ms late, and a second socket (another
# peer, to the node) sends it a junk datagram every 10 ms.
python3 -u - "$PX" "$PA" "$T" > "$T/proxy.out" 2>&1 <<'EOF' &
import os, select, socket, sys, time
px, pa, t = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
miner = ('127.0.0.1', pa)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', px))
other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
other.bind(('127.0.0.1', 0))
node, kept, late, chat, chats = None, [], [], 0.0, 0
print('proxy: up', flush=True)
while True:
    now = time.monotonic()
    chatter = os.path.exists(f'{t}/chatter')
    while late and (late[0][0] <= now or not chatter):
        s.sendto(late.pop(0)[1], node)
    if chatter and node is not None and now >= chat:
        other.sendto(b'TAB1\x63', node)
        chat, chats = now + 0.01, chats + 1
        if chats % 1000 == 1:
            print(f'proxy: chattering ({chats})', flush=True)
    if kept and not os.path.exists(f'{t}/hold'):
        for d in kept:
            s.sendto(d, node)
        print(f'proxy: {len(kept)} chunks let through', flush=True)
        kept = []
    if not select.select([s], [], [], 0.005 if chatter else 0.2)[0]:
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
        elif chatter:
            late.append((time.monotonic() + 0.1, d))
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
./tools/q32 --net --hostfwd=tcp::$HP-:3738,hostfwd=udp::$PU-:3737 --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
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

echo "stalltest.sh: the miner mining 4 blocks; the node syncing through the proxy, another address chattering at it"
touch "$T/chatter"
stop $AP; AP=
minera
wait_for "$T/a.out" 'is the tip at height 4$' 600 "the miner's 4 blocks"
stop $AP; AP=
minera --no-mine
# (the node syncs on its next try, maybe while the miner still mines, and
# follows it from there: waited for at the miner's last block)
H=$(sed -n 's/.* is the tip at height \([0-9]*\)$/\1/p' "$T/a.out" | tail -1)
wait_own "$T/os.out" "^node: .* (synced, height $H\$|height $H  \\()" 900 "the node's sync to $H"
rm "$T/chatter"
grep -q '^proxy: chattering' "$T/proxy.out" || { echo "stalltest.sh: the proxy never chattered" >&2; exit 1; }
! grep -q 'the sync stopped: -3' "$T/os.out" || { echo "stalltest.sh: the headers' waits ended at others' datagrams (the sync stopped -3)" >&2; exit 1; }
N=$((H + 1))

echo "stalltest.sh: chunks held; the miner mining block $N (and on)"
touch "$T/hold"
stop $AP; AP=
minera
wait_while_busy 600 "the node asking for block $N's chunks" test -e "$T/held"
# Asked until it says so: the chunks stay held, so the node fetches block
# $N throughout (its 30 s for the block given up, it asks again), and a
# status read just as one fetch ends and the next starts is asked again
# rather than failed.  An API not answered while the node fetches still
# fails: each read has its 120 s.
python3 - "$HP" "$N" <<'EOF2'
import json, sys, time, urllib.request
for i in range(20):
    with urllib.request.urlopen(f'http://127.0.0.1:{sys.argv[1]}/v1/status', timeout=120) as r:
        s = json.loads(r.read())
    print(f'host: the status while the chunks are held: activity {s.get("activity")}, block {s.get("activity_height")}, height {s["height"]}')
    if s.get('activity') == 'fetching' and s.get('activity_height') == int(sys.argv[2]):
        sys.exit(0)
    time.sleep(1)
sys.exit(f'stalltest.sh: the status never said the node was fetching block {sys.argv[2]}')
EOF2
rm "$T/hold"
wait_for "$T/os.out" "^node: .* height $N  \\(" 600 "the node connecting block $N"
grep -E "^node: .* height $N  \\(" "$T/os.out"
# A block's chunks served while the worker connects one (sync.fam's
# cwait).  No clock here either: the status says "connecting" only when
# it is answered from that wait, so a chunk of our tip's block asked for
# after a status that says the node is connecting block B, and had
# before another that says the same, was served in it.  Tried at each
# block the miner mines until it holds once (a round whose datagram is
# lost, or whose block is connected before the chunk is asked for, is
# only another round); a node that serves no block while it connects
# never has one, and fails at the 12th block.
echo "stalltest.sh: a block's chunk asked for while the node connects the miner's blocks"
python3 - "$HP" "$PU" "$N" <<'EOF2'
import json, os, socket, struct, sys, time, urllib.request
hp, pu, n = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
node = ('127.0.0.1', pu)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
def status():
    with urllib.request.urlopen(f'http://127.0.0.1:{hp}/v1/status', timeout=120) as r:
        return json.loads(r.read())
def answer(want):
    # the node's datagram that want() takes, or None (2 s with none)
    try:
        while True:
            d = s.recvfrom(2048)[0]
            if d[:4] == b'TAB1' and want(d):
                return d
    except socket.timeout:
        return None
def pong(ours):
    # the node's status, for a Ping with ours
    for i in range(30):
        nonce = os.urandom(8)
        s.sendto(b'TAB1\x01' + nonce + ours, node)
        d = answer(lambda d: d[4] == 2 and d[5:13] == nonce)
        if d is not None:
            return d[13:]
    sys.exit('stalltest.sh: the node answered none of 30 Pings')
def token():
    # a peer's chunks are served, not a stranger's: pinged with the
    # node's own status as ours (its genesis: a pinger on its chain is
    # taken as a peer; never answering its Pings, we are not followed);
    # its token for this address
    return pong(pong(bytes(132)))[4:12]
tok = token()
rounds = asked = 0
while True:
    rounds += 1
    s1 = status()
    if s1['height'] > n + 12:
        sys.exit(f'stalltest.sh: no chunk of a block served while the node connected one, in {rounds} rounds to height {s1["height"]} ({asked} asked for while it was connecting)')
    if s1.get('activity') != 'connecting':
        time.sleep(0.02)
        continue
    asked += 1
    # GetChunks: of the block (kind 0) that is the node's tip, one run of
    # chunks: the first
    tip = bytes.fromhex(s1['tip'])
    s.sendto(b'TAB1\x08' + tok + b'\x00' + tip + b'\x01' + struct.pack('<HH', 0, 1), node)
    d = answer(lambda d: d[4] == 9 and d[5] == 0 and d[6:38] == tip)
    s2 = status()
    if d is not None and s2.get('activity') == 'connecting' and s2.get('activity_height') == s1.get('activity_height'):
        print(f'host: a chunk of block {s1["height"]} served while the node connected block {s1["activity_height"]} (round {rounds}, the {asked}th asked for while it was connecting)')
        sys.exit(0)
    if d is None:
        tok = token()
EOF2
echo "stalltest.sh: the API answered before any block and while the node fetched one; a block served while it connected one"
