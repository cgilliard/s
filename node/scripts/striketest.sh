#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# striketest.sh — the node (bin/img's, run from its shell) striking and
# banning a peer that misbehaves (docs/NODE.md, step 10), as tabminer's
# Peers::strike.  On the host, tabminer A mines the recursive dev network
# (UDP 37471); a fake peer (Python, below, UDP 37479) answers Pings as a
# peer on A's chain far ahead of it, and every request for headers from a
# height with a malformed one of that height.  The node, given both, syncs from A, goes to the
# fake for its claimed height, strikes it for the header and passes it
# over for a minute; at its fifth strike, bans it for an hour; and keeps
# following A throughout.
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/striketest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/striketest
PA=${STRIKETEST_A:-37471}; PF=${STRIKETEST_F:-37479}
[ -x "$MINER" ] || { echo "striketest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "striketest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; FP=; QP=
trap 'st=$?; exec 3>&- 2>/dev/null; for p in $QP $FP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
# wait_for FILE PATTERN SECONDS WHAT
wait_for() {
	i=0
	until grep -qE "$2" "$1" 2>/dev/null; do
		[ $i -lt "$3" ] || { echo "striketest.sh: $4: not in $3 s" >&2; exit 1; }
		sleep 2; i=$((i + 2))
	done
}

echo "striketest.sh: A mining 4 blocks"
TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
	--listen 127.0.0.1:$PA --no-prompt >> "$T/a.out" 2>&1 &
AP=$!
wait_for "$T/a.out" 'is the tip at height 4$' 600 "A's 4 blocks"

python3 - "$PA" "$PF" > "$T/fake.out" 2>&1 <<'EOF' &
import os, socket, struct, sys
pa, pf = int(sys.argv[1]), int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', pf))
a = ('127.0.0.1', pa)
def status_of_a():
    nonce = os.urandom(8)
    s.sendto(b'TAB1\x01' + nonce + bytes(132), a)
    while True:
        d, f = s.recvfrom(2048)
        if f == a and d[4] == 2 and d[5:13] == nonce:
            return d[5:]
st = status_of_a()
print('ready', flush=True)
token = os.urandom(8)
while True:
    d, f = s.recvfrom(2048)
    if f == a or d[:4] != b'TAB1':
        continue
    kind, body = d[4], d[5:]
    if kind == 1 and len(body) >= 140:
        # our status: their nonce, A's version, our token, A's genesis, a
        # height far ahead, A's tip, more work
        h = 1000
        pong = body[:8] + st[8:12] + token + st[20:52] + struct.pack('<II', h, h + 1) + st[60:92] + b'\xff' * 32 + st[124:140]
        s.sendto(b'TAB1\x02' + pong, f)
    elif kind == 11 and body[:8] == token and len(body) >= 12:
        # the height asked for, so it is taken up, and every digest not a
        # field element: malformed
        hdr = bytearray(b'\xff' * 204)
        hdr[32:36] = body[8:12]
        print('headers asked', flush=True)
        s.sendto(b'TAB1\x06' + bytes([1]) + bytes(hdr), f)
EOF
FP=$!
wait_for "$T/fake.out" '^ready' 30 "the fake peer"

echo "striketest.sh: the node, given A and the fake"
mkfifo "$T/in"
./tools/q32 --net --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
echo "node -n devrec 10.0.2.2:$PA 10.0.2.2:$PF &" >&3
wait_for "$T/os.out" '^node: .* synced' 900 "the node's sync"
wait_for "$T/os.out" "^node: .* peer 10\\.0\\.2\\.2:$PF struck \\(1 of 5\\)" 300 "the fake struck"
wait_for "$T/os.out" "^node: .* peer 10\\.0\\.2\\.2:$PF banned" 600 "the fake banned"
grep -E "struck|banned|passed over" "$T/os.out"
n=$(grep -c '^node: .* height [0-9]*  (' "$T/os.out")
i=0; until [ "$(grep -c '^node: .* height [0-9]*  (' "$T/os.out")" -gt "$n" ]; do
	[ $i -lt 300 ] || { echo "striketest.sh: no block from A after the ban" >&2; exit 1; }
	sleep 2; i=$((i + 2))
done
grep '^node: .* height [0-9]*  (' "$T/os.out" | tail -2
echo "striketest.sh: the fake struck five times and banned; A followed throughout"
