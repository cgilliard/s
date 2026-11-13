#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# msgtest.sh — the message layer in init mode (docs/ONION.md;
# docs/GUI_WALLET.md, phase 3): payments with no file between tabminer's
# wallet and the OS's, through a relay that is the network's one seed.
#
# tabminer A mines the recursive dev network (UDP 37511), its prompt read
# from a fifo, with R (37512) as its seed; R is a tabminer node started
# --relay, following A.  The OS (QEMU) runs the node following A and wm;
# the wallet's /etc/wallet/config names R (10.0.2.2:37512) its seed.  The
# script logs in to wm and drives the wallet over its WebSocket:
# - the wallet made, reachable: a session live at R (the overview's reach);
# - A pays the wallet 2.5 by its address (`send 2.5 tab1...`): the slate
#   goes through R, the wallet answers it by itself, A finalizes; once
#   mined, the wallet holds 2.5 confirmed;
# - the wallet pays A 1 online (send-online to A's address): A answers by
#   itself, the wallet finalizes the answer (an event); once mined, A holds
#   1 confirmed and the wallet 2.5 - 1 - its fee;
# - names (docs/SUBNAME_CERT.md, init mode): the wallet registers famwal, A
#   tabname; the wallet pays @tabname; A gives ex1.tabname to itself and
#   the wallet pays @ex1.tabname (its query to A, the certificate checked
#   against the chain); the wallet gives w1.famwal to itself and A pays
#   @w1.famwal, the wallet answering A's query.
# Waits as the node's scripts: no deadline, each fails when nothing new
# has changed for its idle window (scripts/waitlib.sh's rule).
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/msgtest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/msgtest; PA=37511; PR=37512; WP=37411; HP=37391
[ -x "$MINER" ] || { echo "msgtest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "msgtest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; QP=; RP=
trap 'st=$?; exec 3>&- 4>&- 2>/dev/null; for p in $QP $RP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
. scripts/waitlib.sh

echo "msgtest.sh: tabminer mining, its prompt open"
mkfifo "$T/a.in"
TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
	--seed 127.0.0.1:$PR --listen 127.0.0.1:$PA < "$T/a.in" >> "$T/a.out" 2>&1 &
AP=$!
exec 4> "$T/a.in"
wait_for "$T/a/tabminer.log" 'is the tip at height 3$' 600 "tabminer's first 3 blocks"

echo "msgtest.sh: the relay, the one seed (init mode), following the miner"
TABMINER_THREADS=1 "$MINER" node --network dev-recursive --data "$T/r" --no-seeds --relay --no-prompt \
	--listen 127.0.0.1:$PR --peer 127.0.0.1:$PA > "$T/r.out" 2>&1 &
RP=$!

echo "msgtest.sh: the node following it, wm serving"
mkfifo "$T/in"
./tools/q32 --net --hostfwd=tcp::$WP-:80,hostfwd=tcp::$HP-:3738 --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
{
	echo "node -n devrec 10.0.2.2:$PA &"
	echo 'mkdir /etc'
	echo 'mkdir /etc/wallet'
	echo "echo seed 10.0.2.2:$PR > /etc/wallet/config"
	echo 'echo root:paypw:0:0:/:sh > /etc/passwd'
	echo 'wm 80 &'
} >&3
wait_own "$T/os.out" '^node: .* (synced, height [0-9]+$|height [0-9]+  \()' 900 "the node in sync"
wait_os "$T/os.out" 'wm: port 80' 60 "wm"

echo "msgtest.sh: the wallets paying each other online, through the relay"
python3 -u - "$WP" "$T" "messages" "$HP" "$AP" <<'EOF' || { wdump; exit 1; }
import base64, hashlib, json, os, re, socket, struct, sys, time, urllib.request
port, T, part, api, apid = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
G = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
fifo = open(f'{T}/a.in', 'w')
def tab(cmd):
    fifo.write(cmd + '\n'); fifo.flush()
def aout():
    return open(f'{T}/a.out', errors='replace').read()
def progress():
    return sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(T) for f in fs if f.endswith(('.out', '.log')))
def blocks():
    # its log: with its prompt open, tabminer writes these there only
    return open(f'{T}/a/tabminer.log', errors='replace').read().count('is the tip at height')
def wait(what, cond, idle=300):
    # The miner mines throughout, so its logs always grow: a wait fails
    # when nothing new comes for the idle window, or when 30 blocks pass
    # without what it waits for (blocks are the clock here).
    last, still, b0 = progress(), 0, blocks()
    told = b0
    while True:
        r = cond()
        if r:
            return r
        time.sleep(2)
        # a line every five blocks, so a long wait shows in the log
        if blocks() >= told + 5:
            told = blocks()
            print(f'msgtest: ({what}: {told - b0} blocks so far)')
        if blocks() > b0 + 30:
            print(f'msgtest: {what}: not in 30 blocks'); sys.exit(1)
        now = progress()
        if now != last:
            last, still = now, 0
        else:
            still += 2
            if still >= idle:
                print(f'msgtest: {what}: nothing new for {idle} s'); sys.exit(1)
def check(what, cond):
    print(f'msgtest: {what}: {"ok" if cond else "FAILED"}')
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
    data = json.dumps(obj, separators=(",", ":")).encode(); m = os.urandom(4); n = len(data)
    hdr = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else bytes([0xFE]) + struct.pack(">H", n))
    s.sendall(hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(data)))
def pumpone():
    global buf
    try:
        d = s.recv(65536)
    except socket.timeout:
        return
    if not d:
        print('msgtest: the wallet closed'); sys.exit(1)
    buf += d
    while len(buf) >= 2:
        n = buf[1] & 127; hl = 2
        if n == 126:
            if len(buf) < 4: break
            n = struct.unpack(">H", buf[2:4])[0]; hl = 4
        if len(buf) < hl + n: break
        op = buf[0] & 15; p = buf[hl:hl + n]; buf = buf[hl + n:]
        if op == 1:
            try:
                msgs.append(json.loads(p))
                if msgs[-1].get('event') == 'message':
                    print('msgtest: (the wallet: ' + str(msgs[-1].get('text', msgs[-1])) + ')')
            except ValueError:
                print('msgtest: not JSON from the wallet: ' + p.decode(errors='replace')[:2000]); raise
nid = [0]
def ask(op, **a):
    nid[0] += 1; i = nid[0]
    a['op'] = op; a['id'] = i; wsend(a)
    def got():
        pumpone()
        return next((m for m in msgs if m.get('id') == i), None)
    return wait(f'the wallet\'s answer to {op}', got)
wait('the wallet unlocked', lambda: pumpone() or any(m.get('op') == 'unlock' for m in msgs))
c = ask('create')
check(f'a wallet made {"" if c["ok"] else c}', c['ok'])
addr = ask('receive')['address']
check(f'its address {addr[:16]}...', addr.startswith('tab1'))
def confirmed():
    return ask('overview')['confirmed']

def reach():
    time.sleep(3)
    return ask('overview').get('reach', 0) >= 1
check('the wallet reachable: a session live at the relay', wait('the wallet\'s session at the relay', reach))
def events(kind):
    return [m for m in msgs if m.get('event') == kind]

# A pays the wallet 2.5 by its address, through R
def tab_addr():
    tab('address'); time.sleep(3)
    return re.search(r'(tab1[0-9a-z]{58})$', aout(), re.M)
ma = wait('A\'s address', tab_addr).group(1)
tab(f'send 2.5 {addr}')
got = wait('the 2.5 confirmed in the wallet', lambda: (pumpone(), time.sleep(3), confirmed() == '2.5000000000')[2])
check('A sent the slate online, the wallet answered it by itself, A finalized it: 2.5 confirmed', got)
check('the wallet told of the answer', any('answered a slate of 2.5000000000' in m.get('text', '') for m in events('message')))

# the wallet pays A 1 online
p = ask('send-online', to=ma, amount='1', speed='hour')
check(f'the wallet sent a slate online: fee {p.get("fee", p.get("error"))}', p['ok'] and p.get('online'))
def fin():
    pumpone(); time.sleep(1)
    return next((m for m in events('message') if 'tx' in m or (m.get('ok') is False and 'error' in m)), None)
f = wait('the wallet finalizing A\'s answer', fin)
check(f'A answered by itself, the wallet finalized it: {f.get("tx", f.get("error"))}', f.get('ok') and len(f.get('tx', '')) == 64)
fee = int(p['fee'].replace('.', ''))
want = 25 * 10**9 - 10**10 - fee
want = f'{want // 10**10}.{want % 10**10:010d}'
def tab_has():
    tab('outputs'); time.sleep(3)
    return re.search(r'\b1\.0000000000  confirmed', aout()) is not None
check('A holds the 1 confirmed', wait('the 1 confirmed at A', tab_has))
check(f'the wallet holds 2.5 - 1 - fee = {want}', wait('the wallet\'s change confirmed', lambda: (time.sleep(3), confirmed() == want)[1]))

# names: the wallet's famwal, A's tabname; payments to @name and @label.name
def settled():
    time.sleep(3)
    o = ask('overview')
    return o['pending'] == '0.0000000000' and o['reserved'] == '0.0000000000'
c = ask('name-commit', name='famwal', speed='hour')
check(f'the wallet commits to famwal: {c.get("tx", c.get("error"))}', c['ok'])
tab('name-commit tabname')
wait('A\'s commit', lambda: 'committed to tabname' in aout())
def wstate(name, state):
    def f():
        time.sleep(3)
        it = [i for i in ask('names').get('items', []) if i['name'] == name]
        return it[0] if it and it[0]['state'] == state else None
    return f
wait('the wallet\'s commit old enough (3 blocks)', wstate('famwal', 'ready'))
r = ask('name-reveal', name='famwal', speed='hour')
check(f'the wallet reveals famwal: {r.get("tx", r.get("error"))}', r['ok'])
def tab_reveal():
    tab('name-reveal tabname'); time.sleep(5)
    return 'revealing tabname' in aout()
wait('A revealing tabname', tab_reveal)
wait('famwal the wallet\'s on chain', wstate('famwal', 'owned'))
def found(name):
    def f():
        time.sleep(3)
        l = ask('name-lookup', name=name)
        return l if l['ok'] and l['found'] else None
    return f
wait('tabname on chain', found('tabname'))
def finalized(n0):
    def f():
        pumpone(); time.sleep(1)
        done = [m for m in events('message') if 'tx' in m or (m.get('ok') is False and 'error' in m)]
        return done[n0] if len(done) > n0 else None
    return f
def nfinal():
    return len([m for m in events('message') if 'tx' in m or (m.get('ok') is False and 'error' in m)])

# the wallet pays @tabname
wait('the wallet\'s coins settled', settled)
n0 = nfinal()
p = ask('send-online', to='@tabname', amount='0.1', speed='hour')
check(f'the wallet sends to @tabname online: {p.get("fee", p.get("error"))}', p['ok'])
f = wait('the payment to @tabname finalized', finalized(n0))
check(f'@tabname (A) answered, the wallet finalized it: {f.get("tx", f.get("error"))}', f.get('ok') and len(f.get('tx', '')) == 64)

# A gives ex1.tabname to itself; the wallet pays @ex1.tabname (a query to A, its certificate checked)
tab(f'subname set ex1.tabname {ma}')
wait('the wallet\'s coins settled again', settled)
n0 = nfinal()
p = ask('send-online', to='@ex1.tabname', amount='0.1', speed='hour')
check(f'the wallet asks the owner of tabname for ex1: {p}', p['ok'] and p.get('resolving'))
f = wait('the payment to @ex1.tabname finalized', finalized(n0))
check(f'ex1.tabname resolved through its owner, paid, finalized: {f.get("tx", f.get("error"))}', f.get('ok') and len(f.get('tx', '')) == 64)

# the wallet gives w1.famwal to itself; A pays @w1.famwal (its query answered by the wallet)
g = ask('subname-set', name='famwal', label='w1', to=addr)
check(f'the wallet gives w1.famwal to itself: {g.get("error", "ok")}', g['ok'])
subs = ask('subnames')['items']
check(f'its sub-names: {subs}', any(i['sub'] == 'w1.famwal' and i['holder'] == addr for i in subs))
na = len([m for m in events('message') if 'answered a slate of 0.0500000000' in m.get('text', '')])
tab('send 0.05 @w1.famwal')
def answered():
    pumpone(); time.sleep(1)
    return len([m for m in events('message') if 'answered a slate of 0.0500000000' in m.get('text', '')]) > na
check('A resolved @w1.famwal by asking the wallet, and paid it: the wallet answered its slate', wait('A paying @w1.famwal', answered))
EOF
echo "msgtest.sh: done"
