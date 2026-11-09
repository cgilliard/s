#!/bin/sh
# apitest.sh — the node's API (docs/NODE.md, step 8).  On the host: a
# tabminer mining the recursive dev network (UDP 37471, a fresh data
# directory, no seeds) to 12 blocks; then stopped, its directory copied for
# a second tabminer with the wallet and no peers, which burns a coin twice
# and quits, its pool saved (the two transactions, made by tabminer's
# wallet, never sent anywhere); the miner started again.  The node boots
# (src/user/node/api_test.fam) with one transaction as /lib/tx, syncs from
# the miner and starts its API (port 3738, forwarded from the host).
# - In the OS, /bin/apicli (src/user/node/apicli.fam) asks for the status
#   without the token (401), then with it; a header; outputs; and sends its
#   transaction without the token (401), then with it.
# - On the host, a client (below) does the same with the other
#   transaction, and reads every endpoint; waits for the tip to move (long
#   polling); waits until both transactions are mined (the pool empty, the
#   miner's log saying it took both from the node); makes a new token, the
#   old one refused after.
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/apitest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/apitest
N=src/user/node
HP=${APITEST_PORT:-37380}
[ -x "$MINER" ] || { echo "apitest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/kernel ] || { echo "apitest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"

./tools/fam --user -o "$T/tapi.bin" $N/arith.fam $N/poseidon2.fam $N/difficulty.fam $N/pow.fam $N/headers.fam \
	$N/chainver.fam $N/state.fam $N/proofs.fam $N/connect.fam $N/query.fam $N/snap.fam $N/xmss.fam $N/tx.fam \
	$N/pool.fam $N/p2p.fam $N/sync.fam $N/api.fam $N/api_test.fam
./tools/fam --user -o "$T/apicli.bin" $N/apicli.fam

MP=; WP=; QP=
trap 'st=$?; exec 3>&- 2>/dev/null; for p in $QP $WP $MP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
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
		[ $i -lt "$3" ] || { echo "apitest.sh: $4: not in $3 s" >&2; exit 1; }
		sleep 2; i=$((i + 2))
	done
}

echo "apitest.sh: mining 12 blocks (about ten seconds each)"
mine
wait_for "$T/miner.out" 'is the tip at height 12$' 600 "the miner's 12 blocks"
kill $MP; wait $MP 2>/dev/null || true
cp -r "$T/miner" "$T/wallet"
mine

# The wallet: two burns, pooled where it is (it has no peers), then quit.
mkfifo "$T/wallet.in"
"$MINER" mine --no-mine --network dev-recursive --data "$T/wallet" --no-seeds --listen 127.0.0.1:37472 \
	< "$T/wallet.in" > "$T/wallet.out" 2>&1 &
WP=$!
exec 3> "$T/wallet.in"
echo "burn 1 api-host" >&3
echo "burn 1 api-guest" >&3
echo "quit" >&3
exec 3>&-
wait $WP || true; WP=
grep -c 'pooled; broadcasting' "$T/wallet.out" | grep -qx 2 || { echo "apitest.sh: the wallet did not make two transactions: $(tail -c 400 "$T/wallet.out")" >&2; exit 1; }
python3 - "$T/wallet/mempool" "$T" <<'EOF'
import struct, sys
b = open(sys.argv[1], 'rb').read()
assert b[:4] == b'POL2', 'not a saved pool'
n = struct.unpack_from('<I', b, 4)[0]
assert n == 2, f'{n} transactions saved'
o = 8
for k in (1, 2):
    o += 8
    m = struct.unpack_from('<I', b, o)[0]; o += 4
    open(f'{sys.argv[2]}/tx{k}.bin', 'wb').write(b[o:o + m]); o += m
EOF

sh scripts/mkimage.sh "$T/api.img" bin/kernel init="$T/tapi.bin":24576 apicli="$T/apicli.bin":1024 \
	akjv.txt.gz=../resources/akjv.txt.gz:0 chainver=$N/chainver_dev.bin:0 devchain=$N/devchain.bin:0 tx="$T/tx2.bin":0
dd if=/dev/zero of="$T/api.disk" bs=1 count=0 seek=268435456 2>/dev/null
echo "apitest.sh: the node syncing"
./tools/q32 --net --hostfwd=tcp::$HP-:3738 --disk="$T/api.disk" "$T/api.img" > "$T/node.out" 2>&1 &
QP=$!
wait_for "$T/node.out" '^api: listening|^sync: -' 900 "the sync"
grep -E '^sync:' "$T/node.out"
TOKEN=$(sed -n 's/^api: listening, token \([0-9a-f]*\)$/\1/p' "$T/node.out")
[ ${#TOKEN} = 64 ] || { echo "apitest.sh: no API" >&2; exit 1; }
wait_for "$T/node.out" '^cli: done' 120 "the program in the OS"
grep -E '^cli:' "$T/node.out"
grep -q '^cli: status without the token 401' "$T/node.out" && grep -q '^cli: status 200 {"height":' "$T/node.out" \
	&& grep -q '^cli: header 1 200 {"height":1,' "$T/node.out" && grep -q '^cli: outputs 200 {"outputs":\[' "$T/node.out" \
	&& grep -q '^cli: tx without the token 401' "$T/node.out" && grep -q '^cli: tx 200 {"accepted":true' "$T/node.out" \
	|| { echo "apitest.sh: the program in the OS was not answered as expected" >&2; exit 1; }

python3 - "$HP" "$TOKEN" "$T/tx1.bin" "$T/miner/tabminer.log" <<'EOF'
import json, sys, time, urllib.request, urllib.error, re
port, token, txfile, minerlog = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
base = f'http://127.0.0.1:{port}'
def ask(path, data=None, tok=token, timeout=40):
    req = urllib.request.Request(base + path, data=data, method='POST' if data is not None else 'GET')
    if tok:
        req.add_header('Authorization', f'Bearer {tok}')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
def check(what, cond):
    print(f'host: {what}: {"ok" if cond else "FAILED"}')
    if not cond:
        sys.exit(1)
def j(path, **kw):
    st, body = ask(path, **kw)
    check(f'{path} 200', st == 200)
    return json.loads(body)
st, body = ask('/v1/status', tok=None)
check('without the token 401, nothing else', st == 401 and body == b'')
st, body = ask('/v1/status', tok='0' * 64)
check('another token 401', st == 401)
st, _ = ask('/v1/tx', data=open(txfile, 'rb').read(), tok=None)
check('a transaction without the token 401', st == 401)
s = j('/v1/status')
h = s['height']
check(f'status: height {h}, {s["peers"]} peers', h >= 12 and len(s['tip']) == 64)
hd = j(f'/v1/header/{h}')
check('the tip\'s header by height', hd['height'] == h and hd['id'] == s['tip'])
check('the same by id', j(f'/v1/header/{s["tip"]}') == hd)
st, raw = ask(f'/v1/header/{h}?raw')
check('its 204 bytes', st == 200 and len(raw) == 204)
b = j(f'/v1/block/{h}')
check(f'the tip\'s block: {len(b["outputs"])} outputs, a proof of {b["proof_bytes"]} bytes', b['header'] == hd and b['proof_bytes'] > 0)
o = j('/v1/outputs?from=0&count=5')
check(f'outputs from 0: {len(o["outputs"])}', len(o['outputs']) > 0 and all(len(x['commitment']) == 64 for x in o['outputs']))
p = o['outputs'][0]['position']
pr = j(f'/v1/proof/output/{p}')
check('an output\'s proof: 40 siblings', len(pr['siblings']) == 40 and pr['commitment'] == o['outputs'][0]['commitment'])
sp = j('/v1/spent?from=0')
check(f'spent: {len(sp["spent"])} blocks kept', isinstance(sp['spent'], list))
n = j('/v1/name/nobody')
check('a name not registered: no record, a proof', n['record'] is None and 'siblings' in n['proof'])
check('fees', j('/v1/fees')['minimum'] == 10)
m = j('/v1/mempool')
check(f'the pool: {m["count"]} (the program in the OS sent one)', m['count'] == 1)
st, body = ask('/v1/tx', data=b'\x01\x02')
r = json.loads(body)
check(f'bytes that do not decode refused: {r["reason"]}', st == 400 and r['accepted'] is False and r['code'] == -1)
st, body = ask('/v1/tx', data=open(txfile, 'rb').read())
r = json.loads(body)
check(f'our transaction accepted: {r.get("id", "")[:16]}', st == 200 and r['accepted'] is True)
st, body = ask('/v1/tx', data=open(txfile, 'rb').read())
check('again: already in the pool', st == 400 and json.loads(body)['code'] == -10)
t0 = time.time()
tip = j('/v1/status')['tip']
moved = j(f'/v1/tip?after={tip}', timeout=60)
check(f'the tip waited for: height {moved["height"]} after {time.time() - t0:.0f} s', moved['tip'] != tip or time.time() - t0 >= 25)
for _ in range(60):
    if j('/v1/mempool')['count'] == 0:
        break
    time.sleep(5)
check('both mined: the pool empty', j('/v1/mempool')['count'] == 0)
took = re.findall(r'transaction from 127\.0\.0\.1:\d+ \S+ pooled', open(minerlog).read())
check(f'the miner took both from the node', len(took) == 2)
new = j('/v1/token', data=b'')['token']
check('a new token', len(new) == 64 and new != token)
st, _ = ask('/v1/status')
check('the old one refused', st == 401)
st, _ = ask('/v1/status', tok=new)
check('the new one taken', st == 200)
EOF
echo "apitest.sh: the API answered in the OS and on the host"
