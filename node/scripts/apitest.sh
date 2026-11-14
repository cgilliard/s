#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# apitest.sh — the node's API (docs/NODE.md, step 8).  On the host: a
# tabminer mining the recursive dev network (UDP 37471, a fresh data
# directory, no seeds) to 12 blocks; then stopped, its directory copied for
# a second tabminer with the wallet and no peers, which burns a coin twice
# and quits, its pool saved (the two transactions, made by tabminer's
# wallet, never sent anywhere); the miner started again.  The node boots
# (src/user/node/api_test.fam) with one transaction as /lib/tx, syncs from
# the miner and starts its API (port 3738, forwarded from the host).
# - In the OS, /bin/apicli (src/user/node/apicli.fam) asks, without the
#   token as a user's wallet does, for the status, a header and outputs; a
#   new token (401: that alone needs the token); and sends its transaction.
# - On the host, a client (below) reads every endpoint without the token,
#   sends the other transaction without it; waits for the tip to move (long
#   polling); reads the events (GET /v1/events: the blocks, the state, the
#   transaction pooled; a filter, a reset) and waits on them, a request at
#   a time, until the transaction is mined; waits until both are mined (the pool empty, the
#   miner's log saying it took both from the node); makes a new token, the
#   old one refused after.
# - Past paths (/v1/proof/output/<position>?at=<height>): the wallet's
#   tabminer, run again and synced, gives each burn's proof (burn-proof);
#   its path, made by tabminer's Chain::output_proof_at at the block that
#   made the burn, must be the node's sibling for sibling, with that
#   block's state root; at the block before, no output; at the tip, the
#   tip's path; a height not kept refused (400).
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

./tools/fam --user -o "$T/tapi.bin" src/user/crypto/sha256.fam $N/arith.fam $N/poseidon2.fam $N/difficulty.fam $N/pow.fam $N/headers.fam \
	$N/chainver.fam $N/state.fam $N/proofs.fam $N/manifest.fam $N/connect.fam $N/query.fam $N/serve.fam $N/snap.fam $N/xmss.fam $N/tx.fam \
	$N/wkeys.fam $N/events.fam $N/pool.fam $N/p2p.fam $N/cons.fam $N/api.fam $N/sync.fam $N/api_test.fam
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
. scripts/waitlib.sh

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
# (the thread is what is tested: without it the loop answers all, as before it)
grep -q '^api: answered by a thread of its own' "$T/node.out" || { echo "apitest.sh: the API's thread did not start" >&2; exit 1; }
wait_for "$T/node.out" '^cli: done' 120 "the program in the OS"
grep -E '^cli:' "$T/node.out"
grep -q '^cli: status 200 {"height":' "$T/node.out" \
	&& grep -q '^cli: header 1 200 {"height":1,' "$T/node.out" && grep -q '^cli: outputs 200 {"outputs":\[' "$T/node.out" \
	&& grep -q '^cli: token without the token 401' "$T/node.out" && grep -q '^cli: tx 200 {"accepted":true' "$T/node.out" \
	|| { echo "apitest.sh: the program in the OS was not answered as expected" >&2; exit 1; }

python3 - "$HP" "$TOKEN" "$T/tx1.bin" "$T/miner/tabminer.log" <<'EOF'
import json, os, sys, time, urllib.request, urllib.error, re
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
check('the status without the token', st == 200 and body.startswith(b'{"height":'))
st, body = ask('/v1/token', data=b'', tok=None)
check('a new token without the token 401, nothing else', st == 401 and body == b'')
st, body = ask('/v1/token', data=b'', tok='0' * 64)
check('with another token 401', st == 401)
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
st, body = ask('/v1/tx', data=open(txfile, 'rb').read(), tok=None)
r = json.loads(body)
check(f'our transaction accepted, without the token: {r.get("id", "")[:16]}', st == 200 and r['accepted'] is True)
st, body = ask('/v1/tx', data=open(txfile, 'rb').read())
check('again: already in the pool', st == 400 and json.loads(body)['code'] == -10)
t0 = time.time()
tip = j('/v1/status')['tip']
moved = j(f'/v1/tip?after={tip}', timeout=60)
check(f'the tip waited for: height {moved["height"]} after {time.time() - t0:.0f} s', moved['tip'] != tip or time.time() - t0 >= 25)
# The events (docs/TIMING_FIXES.md, item 15): from the start, the blocks
# the node connected, its state and our transaction pooled; another's
# filter not woken by ours; a number past the newest a reset; then, one
# request waiting at a time, until ours is mined.
txid = r['id']
evs, nx = [], 0
while True:
    e = j(f'/v1/events?after={nx}', timeout=60)
    evs += e['events']
    nx = e['next']
    if len(e['events']) < 64:
        break
st = j('/v1/status')
check(f'events from the start: {len(evs)}, numbered in order', [x['n'] for x in evs] == sorted(x['n'] for x in evs) and evs[-1]['n'] == nx)
check('a block event for every height up to the tip, each its id', all(any(x['kind'] == 'block' and x['height'] == k for x in evs) for k in range(h - 1, h + 1))
      and all(x['id'] == j(f'/v1/header/{x["height"]}')['id'] for x in evs if x['kind'] == 'block'))
check('the node\'s state: synced', any(x['kind'] == 'status' and x['state'] == 'synced' for x in evs))
check('our transaction pooled', any(x['kind'] == 'tx' and x['id'] == txid and x['state'] == 'pooled' for x in evs))
other = j(f'/v1/events?after=0&tx={"0" * 64}')
check('another\'s filter: blocks and the state, no transaction', all(x['kind'] != 'tx' for x in other['events']) and len(other['events']) > 0)
check('a number past the newest: a reset', j(f'/v1/events?after={nx + 1000}').get('reset') is True)
mined, t0 = None, time.time()
while mined is None and time.time() - t0 < 900:
    e = j(f'/v1/events?after={nx}&tx={txid}', timeout=60)
    check('no reset while waiting', not e.get('reset'))
    for x in e['events']:
        if x['kind'] == 'tx' and x['id'] == txid:
            print(f'host: (our transaction: {x["state"]})')
            if x['state'] == 'mined':
                mined = x
    nx = e['next']
check(f'our transaction\'s event: mined at {mined and mined["height"]}, a block of the chain', mined is not None
      and j(f'/v1/block/{mined["height"]}')['header']['height'] == mined['height'])
# Until both are mined: waited for as long as the miner is getting on
# (its log growing), failed after 300 s with nothing new.
last, idle = os.path.getsize(minerlog), 0
while j('/v1/mempool')['count'] != 0 and idle < 300:
    time.sleep(5)
    size = os.path.getsize(minerlog)
    idle = 0 if size != last else idle + 5
    last = size
check('both mined: the pool empty', j('/v1/mempool')['count'] == 0)
f = j('/v1/fees')
check(f'both seen confirmed, for the estimates: {f["confirmations"]}', f['confirmations'] == 2)
check('too few seen to estimate: the minimum', all(f['estimates'][t] == {'rate': 10, 'estimated': False} for t in ('block', 'hour', 'day')))
took = re.findall(r'transaction from 127\.0\.0\.1:\d+ \S+ pooled', open(minerlog).read())
check(f'the miner took both from the node', len(took) == 2)
new = j('/v1/token', data=b'')['token']
check('a new token', len(new) == 64 and new != token)
st, _ = ask('/v1/token', data=b'')
check('the old one refused', st == 401)
new2 = j('/v1/token', data=b'', tok=new)['token']
check('the new one taken', len(new2) == 64 and new2 != new)
EOF

# Past paths (?at=): the wallet's tabminer again, syncing from the miner,
# its prompt open: its burn-proof of each burn holds the path tabminer's
# own Chain::output_proof_at made, at the block that made the burn; the
# node's /v1/proof/output/<position>?at=<height> must give the same
# siblings and that block's state root.
echo "apitest.sh: past paths, against tabminer's proofs of burn"
mkfifo "$T/wallet2.in"
"$MINER" mine --no-mine --network dev-recursive --data "$T/wallet" --no-seeds --listen 127.0.0.1:37472 \
	--peer 127.0.0.1:37471 < "$T/wallet2.in" >> "$T/wallet2.out" 2>&1 &
WP=$!
exec 3> "$T/wallet2.in"
python3 - "$HP" "$T" <<'EOF' || { wdump; exit 1; }
import base64, json, os, re, sys, time, urllib.request, urllib.error
port, T = sys.argv[1], sys.argv[2]
base = f'http://127.0.0.1:{port}'
def ask(path):
    try:
        with urllib.request.urlopen(base + path, timeout=40) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
def check(what, cond):
    print(f'host: {what}: {"ok" if cond else "FAILED"}')
    if not cond:
        sys.exit(1)
fifo = open(f'{T}/wallet2.in', 'w')
def out():
    return open(f'{T}/wallet2.out', errors='replace').read()
def progress():
    return sum(os.path.getsize(p) for p in (f'{T}/wallet2.out', f'{T}/miner/tabminer.log', f'{T}/wallet/tabminer.log') if os.path.exists(p))
ids = re.findall(r'\(transaction ([0-9a-f]{16})\); burn-proof', open(f'{T}/wallet.out', errors='replace').read())
check(f'the two burns made: {ids}', len(ids) == 2)
tip = json.loads(ask('/v1/status')[1])['height']
for tx in ids:
    # asked until the wallet, synced, has the burn landed and its path
    last, idle, text = progress(), 0, None
    while text is None:
        n0 = len(out())
        fifo.write(f'burn-proof {tx}\n'); fifo.flush()
        time.sleep(4)
        m = re.search(r'-----BEGIN TAB BURN PROOF-----(.*?)-----END TAB BURN PROOF-----', out()[n0:], re.S)
        if m:
            text = m.group(1)
            break
        now = progress()
        idle = 0 if now != last else idle + 4
        last = now
        if idle >= 300:
            check(f'tabminer\'s burn-proof {tx}: nothing new for 300 s', False)
    b = base64.b64decode(''.join(text.split()))
    height = int.from_bytes(b[1:5], 'little'); position = int.from_bytes(b[5:13], 'little')
    path = b[73:73 + 40 * 32]
    st, body = ask(f'/v1/proof/output/{position}?at={height}')
    check(f'burn {tx}: position {position} at height {height}: 200{"" if st == 200 else f" (got {st}: {body[:200]})"}', st == 200)
    pr = json.loads(body)
    got = bytes.fromhex(''.join(pr['siblings']))
    check(f'burn {tx}: the path as tabminer\'s, sibling for sibling', got == path)
    hd = json.loads(ask(f'/v1/header/{height}')[1])
    check(f'burn {tx}: the state root that block\'s', pr['state_root'] == hd['state_root'] and pr['height'] == height and pr['created'] == height)
    st, body = ask(f'/v1/proof/output/{position}?at={height - 1}')
    check(f'burn {tx}: at the block before, no output there', st == 200 and json.loads(body)['commitment'] is None)
    now = json.loads(ask(f'/v1/proof/output/{position}')[1])
    at = json.loads(ask(f'/v1/proof/output/{position}?at={now["height"]}')[1])
    check(f'burn {tx}: at the tip, the tip\'s path', at['siblings'] == now['siblings'] and at['state_root'] == now['state_root'])
st, body = ask(f'/v1/proof/output/0?at={tip + 100000}')
check('a height not kept: 400', st == 400)
fifo.write('quit\n'); fifo.flush()
EOF
exec 3>&-
wait $WP 2>/dev/null || true; WP=
echo "apitest.sh: the API answered in the OS and on the host"
