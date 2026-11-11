#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# paytest.sh — tabminer's wallet and the OS's paying each other
# (docs/GUI_WALLET.md, phase 1, step 4), the OS's wallet driven as its
# window drives it: over wm's /wallet WebSocket, logged in.  On the host,
# tabminer mines the recursive dev network (UDP 37493), its prompt read
# from a pipe; in the OS (bin/img), the node follows it and wm serves
# (forwarded).  Then:
# - tabminer pays the OS's wallet 2.5: `send-file 2.5 s1.txt` (a slate as
#   text), the wallet answers it pasted, tabminer finalizes the answer (a
#   file); once mined, the wallet holds 2.5 confirmed;
# - the OS's wallet pays tabminer 1: a slate made as text, tabminer
#   `receive`s it (a file) and writes its answer, the wallet finalizes it
#   pasted; once mined, tabminer holds a confirmed output of 1 and the
#   wallet 2.5 - 1 - its fee.
# No wait has a deadline: each fails only when nothing under its directory
# has changed for its idle window (scripts/waitlib.sh's rule).
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/paytest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/paytest
PA=${PAYTEST_PORT:-37493}; WP=${PAYTEST_WM:-37394}
[ -x "$MINER" ] || { echo "paytest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "paytest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; QP=
trap 'st=$?; exec 3>&- 4>&- 2>/dev/null; for p in $QP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
. scripts/waitlib.sh

echo "paytest.sh: tabminer mining, its prompt open"
mkfifo "$T/a.in"
TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
	--listen 127.0.0.1:$PA < "$T/a.in" >> "$T/a.out" 2>&1 &
AP=$!
exec 4> "$T/a.in"
wait_for "$T/a/tabminer.log" 'is the tip at height 3$' 600 "tabminer's first 3 blocks"

echo "paytest.sh: the node following it, wm serving"
mkfifo "$T/in"
./tools/q32 --net --hostfwd=tcp::$WP-:80 --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
{
	echo "node -n devrec 10.0.2.2:$PA &"
	echo 'mkdir /etc'
	echo 'echo root:paypw:0:0:/:sh > /etc/passwd'
	echo 'wm 80 &'
} >&3
wait_for "$T/os.out" '^node: .* (synced, height [0-9]+$|height [0-9]+  \()' 900 "the node in sync"
wait_for "$T/os.out" 'wm: port 80' 60 "wm"

echo "paytest.sh: the two wallets paying each other"
python3 - "$WP" "$T" <<'EOF'
import base64, hashlib, json, os, re, socket, struct, sys, time
port, T = int(sys.argv[1]), sys.argv[2]
G = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
fifo = open(f'{T}/a.in', 'w')
def tab(cmd):
    fifo.write(cmd + '\n'); fifo.flush()
def aout():
    return open(f'{T}/a.out', errors='replace').read()
def progress():
    return sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(T) for f in fs if f.endswith(('.out', '.log')))
def wait(what, cond, idle=300):
    last, still = progress(), 0
    while True:
        r = cond()
        if r:
            return r
        time.sleep(2)
        now = progress()
        if now != last:
            last, still = now, 0
        else:
            still += 2
            if still >= idle:
                print(f'paytest: {what}: nothing new for {idle} s'); sys.exit(1)
def check(what, cond):
    print(f'paytest: {what}: {"ok" if cond else "FAILED"}')
    if not cond:
        sys.exit(1)
# logged in, the wallet's WebSocket
def http(req):
    c = socket.create_connection(("127.0.0.1", port), timeout=60)
    c.sendall(req); body = b""
    while True:
        d = c.recv(65536)
        if not d: break
        body += d
    return body
form = b"name=root&password=paypw"
good = http(b"POST /login HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + str(len(form)).encode() + b"\r\n\r\n" + form)
ck = [l for l in good.split(b"\r\n") if l.startswith(b"Set-Cookie: wm=")]
check('logged in to wm', bool(ck))
cookie = b"Cookie: " + ck[0][12:].split(b";")[0] + b"\r\n"
s = socket.create_connection(("127.0.0.1", port), timeout=5)
key = base64.b64encode(os.urandom(16))
s.sendall(b"GET /wallet HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" + cookie + b"Sec-WebSocket-Key: " + key + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
h = b""
while b"\r\n\r\n" not in h:
    h += s.recv(1)
check('the wallet\'s WebSocket', b" 101 " in h.split(b"\r\n")[0])
buf = b""; msgs = []
def wsend(obj):
    data = json.dumps(obj).encode(); m = os.urandom(4); n = len(data)
    hdr = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else bytes([0xFE]) + struct.pack(">H", n))
    s.sendall(hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(data)))
def pumpone():
    global buf
    try:
        d = s.recv(65536)
    except socket.timeout:
        return
    if not d:
        print('paytest: the wallet closed'); sys.exit(1)
    buf += d
    while len(buf) >= 2:
        n = buf[1] & 127; hl = 2
        if n == 126:
            if len(buf) < 4: break
            n = struct.unpack(">H", buf[2:4])[0]; hl = 4
        if len(buf) < hl + n: break
        op = buf[0] & 15; p = buf[hl:hl + n]; buf = buf[hl + n:]
        if op == 1:
            msgs.append(json.loads(p))
nid = [0]
def ask(op, **a):
    nid[0] += 1; i = nid[0]
    a['op'] = op; a['id'] = i; wsend(a)
    def got():
        pumpone()
        return next((m for m in msgs if m.get('id') == i), None)
    return wait(f'the wallet\'s answer to {op}', got)
wait('the wallet unlocked', lambda: pumpone() or any(m.get('op') == 'unlock' for m in msgs))
check('a wallet made', ask('create')['ok'])
addr = ask('receive')['address']
check(f'its address {addr[:16]}...', addr.startswith('tab1'))
def confirmed():
    return ask('overview')['confirmed']

# tabminer pays the wallet 2.5
tab(f'send-file 2.5 {T}/s1.txt')
wait('tabminer\'s slate', lambda: 'written to' in aout() and os.path.exists(f'{T}/s1.txt'))
s1 = open(f'{T}/s1.txt').read()
check(f'tabminer\'s slate as text ({len(s1)} characters)', s1.startswith('-----BEGIN TAB SLATE-----'))
a = ask('answer', text=s1)
check(f'the wallet answered it pasted: {a.get("amount", a.get("error"))}', a['ok'] and a['amount'] == '2.5000000000')
open(f'{T}/s1.ans.txt', 'w').write(a['text'])
n0 = aout().count('pooled; broadcasting it')
tab(f'finalize {T}/s1.ans.txt')
wait('tabminer\'s finalize', lambda: aout().count('pooled; broadcasting it') > n0 or 'refused' in aout()[-2000:])
check('tabminer finalized the answer and pooled it', aout().count('pooled; broadcasting it') > n0)
got = wait('the 2.5 confirmed in the wallet', lambda: (time.sleep(3), confirmed() == '2.5000000000')[1])
check('the wallet holds 2.5 confirmed', got)

# the wallet pays tabminer 1
p = ask('send', to='', amount='1', speed='hour', text=True)
check(f'the wallet made a slate as text: fee {p.get("fee", p.get("error"))}', p['ok'] and p['text'].startswith('-----BEGIN TAB SLATE-----'))
open(f'{T}/s2.txt', 'w').write(p['text'])
tab(f'receive {T}/s2.txt {T}/s2.ans.txt')
wait('tabminer\'s answer', lambda: os.path.exists(f'{T}/s2.ans.txt') and os.path.getsize(f'{T}/s2.ans.txt') > 0 and 'return it to the sender' in aout())
s2 = open(f'{T}/s2.ans.txt').read()
check(f'tabminer answered in text ({len(s2)} characters)', s2.startswith('-----BEGIN TAB SLATE-----'))
f = ask('finalize', text=s2)
check(f'the wallet finalized it pasted: {f.get("tx", f.get("error"))}', f['ok'] and len(f['tx']) == 64)
fee = int(p['fee'].replace('.', ''))
want = 25 * 10**9 - 10**10 - fee
want = f'{want // 10**10}.{want % 10**10:010d}'
def tab_has():
    tab('outputs'); time.sleep(3)
    return re.search(r'\b1\.0000000000  confirmed', aout()) is not None
check('tabminer holds the 1 confirmed', wait('the 1 confirmed at tabminer', tab_has))
check(f'the wallet holds 2.5 - 1 - fee = {want}', wait('the wallet\'s change confirmed', lambda: (time.sleep(3), confirmed() == want)[1]))
acts = ask('activity')['items']
check('its activity: received 2.5, sent 1, both confirmed',
      any(i['kind'] == 'received' and i['amount'] == '2.5000000000' and i['state'] == 'confirmed' for i in acts)
      and any(i['kind'] == 'sent' and i['amount'] == '1.0000000000' and i['tx'] == f['tx'] and i['state'] == 'confirmed' for i in acts))
EOF
echo "paytest.sh: tabminer's wallet and the OS's paid each other, both ways, by slates as text"
