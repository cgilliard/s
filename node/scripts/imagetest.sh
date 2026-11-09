#!/bin/sh
# imagetest.sh — the node serving its image to tabernacles (docs/NODE.md,
# step 9; docs/TABERNACLE.md), with no tools/server.py.  On the host: a
# tabminer mining the recursive dev network (UDP 37471, a fresh data
# directory, no seeds) to 12 blocks.  The node (src/user/node/api_test.fam:
# it syncs, then serves its peers and the API) in an image of its own, with
# its version as /lib/version, booted by q32 with its UDP port forwarded
# from the host; a tabernacle patched for that image (scripts/buildlib.sh's
# patch_config, as build.sh patches bin/tabernacle).  Once the node is
# synced, the miner is stopped, so the node verifies nothing while it
# serves (a block's proofs hold its one loop a few seconds: docs/NODE.md,
# step 8, not yet), and:
# - On the host, a client (below) speaks to the node over UDP: Ping and its
#   Pong; GetImages and GetPeers with the token; GetImage, the chunks byte
#   for byte the image's, 64 an ask at most; nothing for a wrong token or
#   another version (each followed by a Ping, whose Pong must come first).
# - A second machine runs the tabernacle (scripts/node.sh) with an empty
#   disk and the node as its only seed: it fetches the image from the node,
#   checks it against its hash and runs it.  The miner is started again and
#   the node it booted syncs from it too.
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/imagetest.sh
set -e
cd "$(dirname "$0")/.."
. scripts/buildlib.sh
MINER=../miner/target/release/tabminer
T=tmp/imagetest
N=src/user/node
HP=${IMAGETEST_PORT:-37370}
[ -x "$MINER" ] || { echo "imagetest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/tabernacle.uncompressed ] && [ -f bin/fampack ] && [ -f bin/gen_hash ] || { echo "imagetest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"

./tools/fam --user -o "$T/tnode.bin" $N/arith.fam $N/poseidon2.fam $N/difficulty.fam $N/pow.fam $N/headers.fam \
	$N/chainver.fam $N/state.fam $N/proofs.fam $N/connect.fam $N/query.fam $N/snap.fam $N/xmss.fam $N/tx.fam \
	$N/pool.fam $N/p2p.fam $N/sync.fam $N/api.fam $N/api_test.fam
printf '0\n' > "$T/version"
sh scripts/mkimage.sh "$T/node.img" bin/kernel init="$T/tnode.bin":24576 \
	akjv.txt.gz=../resources/akjv.txt.gz:0 chainver=$N/chainver_dev.bin:0 devchain=$N/devchain.bin:0 version="$T/version":0
cp bin/tabernacle.uncompressed "$T/tabernacle.uncompressed"
patch_config "$T/tabernacle.uncompressed" "$T/node.img" 0
pack "$T/tabernacle.uncompressed" "$T/tabernacle"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null
dd if=/dev/zero of="$T/booted.disk" bs=1 count=0 seek=268435456 2>/dev/null

MP=; QP=; BP=
# node.sh's QEMU stopped first: a shell runs its trap only once its child ends.
trap 'st=$?; [ -n "$BP" ] && pkill -P $BP 2>/dev/null; for p in $BP $QP $MP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; rm -f "$T"/*.gh*.* "$T"/*.new.* "$T"/*.in.*; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
mine() {
	TABMINER_THREADS=${TABMINER_THREADS:-8} "$MINER" mine --network dev-recursive --data "$T/miner" --no-seeds \
		--listen 127.0.0.1:37471 --no-prompt >> "$T/miner.out" 2>&1 &
	MP=$!
}
# wait_for FILE PATTERN SECONDS WHAT
wait_for() {
	i=0
	until grep -qE "$2" "$1" 2>/dev/null; do
		[ $i -lt "$3" ] || { echo "imagetest.sh: $4: not in $3 s" >&2; exit 1; }
		sleep 2; i=$((i + 2))
	done
}

echo "imagetest.sh: mining 12 blocks (about ten seconds each)"
mine
wait_for "$T/miner.out" 'is the tip at height 12$' 600 "the miner's 12 blocks"
echo "imagetest.sh: the node syncing"
./tools/q32 --net --hostfwd=udp::$HP-:3737 --disk="$T/node.disk" "$T/node.img" > "$T/node.out" 2>&1 &
QP=$!
wait_for "$T/node.out" '^api: listening|^sync: -' 900 "the sync"
grep -E '^sync:' "$T/node.out"
grep -q '^api: listening' "$T/node.out" || { echo "imagetest.sh: the node did not sync" >&2; exit 1; }
kill $MP; wait $MP 2>/dev/null || true; MP=

python3 - "$HP" "$T/node.img" <<'EOF'
import os, socket, struct, sys
port, imgfile = int(sys.argv[1]), sys.argv[2]
img = open(imgfile, 'rb').read()
node = ('127.0.0.1', port)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(30)
def check(what, cond):
    print(f'host: {what}: {"ok" if cond else "FAILED"}')
    if not cond:
        sys.exit(1)
def send(kind, payload):
    s.sendto(b'TAB1' + bytes([kind]) + payload, node)
def recv():
    while True:
        d, a = s.recvfrom(2048)
        if a == node and d[:4] == b'TAB1':
            return d[4], d[5:]
def ping():
    nonce = os.urandom(8)
    send(1, nonce + bytes(132))
    return nonce
def pong_next(what):
    # A Ping after a request: if the request were answered, its answer would
    # come first (the node takes datagrams in order).
    nonce = ping()
    kind, body = recv()
    check(what, kind == 2 and body[:8] == nonce)
nonce = ping()
kind, body = recv()
check('a Ping answered with our nonce', kind == 2 and len(body) == 140 and body[:8] == nonce)
token = body[12:20]
send(64, bytes(8))
pong_next('GetImages with another token: no answer')
send(64, token)
kind, body = recv()
check(f'GetImages: {body.hex()}', kind == 65 and body == bytes([1]) + struct.pack('<II', 0, len(img)))
send(3, token)
kind, body = recv()
peers = [(socket.inet_ntoa(body[1 + 6 * i:5 + 6 * i]), struct.unpack_from('<H', body, 5 + 6 * i)[0]) for i in range(body[0])]
check(f'GetPeers: {peers}', kind == 4 and ('10.0.2.2', 37471) in peers)
chunks = (len(img) + 1023) // 1024
def chunk_ok(body, i):
    v, size, idx, n = struct.unpack_from('<IIHH', body)
    want = img[i * 1024:(i + 1) * 1024]
    return v == 0 and size == len(img) and idx == i and n == len(want) and body[12:] == want
send(66, token + struct.pack('<IB', 0, 2) + struct.pack('<HH', 0, 2) + struct.pack('<HH', chunks - 1, 5))
got = [recv() for _ in range(3)]
check(f'GetImage: chunks 0, 1 and the last ({chunks - 1}, {len(img) - (chunks - 1) * 1024} bytes) as the image',
      all(k == 67 for k, _ in got) and chunk_ok(got[0][1], 0) and chunk_ok(got[1][1], 1) and chunk_ok(got[2][1], chunks - 1))
pong_next('nothing past the end')
send(66, token + struct.pack('<IB', 0, 1) + struct.pack('<HH', 100, 100))
got = [recv() for _ in range(64)]
check('100 asked: the first 64 as the image', all(k == 67 and chunk_ok(b, 100 + i) for i, (k, b) in enumerate(got)))
pong_next('and no more')
send(66, token + struct.pack('<IB', 1, 1) + struct.pack('<HH', 0, 4))
pong_next('another version: nothing')
send(66, bytes(8) + struct.pack('<IB', 0, 1) + struct.pack('<HH', 0, 4))
pong_next('another token: nothing')
EOF

echo "imagetest.sh: a tabernacle booting from the node"
sh scripts/node.sh --disk="$T/booted.disk" --no-seeds --seed=10.0.2.2:$HP --mac=52:54:00:12:34:57 \
	"$T/tabernacle" < /dev/null > "$T/booted.out" 2>&1 &
BP=$!
wait_for "$T/booted.out" '^kernel: |^tabernacle: no peer' 120 "the tabernacle"
grep '^tabernacle:' "$T/booted.out"
grep -q "^tabernacle: fetching from 10.0.2.2:$HP" "$T/booted.out" && ! grep -q '^tabernacle: \(bad\|wrong\|no\)' "$T/booted.out" \
	&& grep -q '^kernel: ' "$T/booted.out" || { echo "imagetest.sh: the tabernacle did not boot from the node" >&2; exit 1; }
grep '^kernel: ' "$T/booted.out" | head -1
mine
wait_for "$T/booted.out" '^api: listening|^sync: -' 900 "the booted node's sync"
grep -E '^sync:' "$T/booted.out"
grep -q '^api: listening' "$T/booted.out" || { echo "imagetest.sh: the booted node did not sync" >&2; exit 1; }
echo "imagetest.sh: a tabernacle booted from the node, and the node it booted synced"
