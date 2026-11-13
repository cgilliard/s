#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# onitest.sh — the message layer in onion mode (docs/ONION.md; docs/GUI_WALLET.md,
# phase 3): payments with no file between tabminer's wallet and the OS's,
# over circuits of three relays, each send unnamed with a route back.
#
# Three tabminer relays (UDP 37532-37534) are started once for their ids;
# a consensus file lists them (onion mode), pinned as if in force with
# --test-relays (dev builds; no 144-block boundary to wait for) at tabminer
# A (mining, UDP 37531, its prompt from a fifo) and the relays (following
# A), and at the OS's node (the configuration's test-relays, the same file
# as the OS reaches them: 10.0.2.2).  The script drives the OS's wallet over
# wm's WebSocket:
# - the wallet in onion mode, a session live at each of its three points;
# - A pays the wallet 2.5 by its address: the slate up an outbound circuit
#   of A's, the wallet answering it along its route, A finalizing; once
#   mined, the wallet holds 2.5 confirmed;
# - the wallet pays A 1 online: A answers along the wallet's route, the
#   wallet finalizes; once mined, A holds 1 confirmed and the wallet 2.5 -
#   1 - its fee;
# - names (docs/SUBNAME_CERT.md, onion mode): the wallet registers famwal,
#   A tabname; the wallet pays @tabname; A gives ex1.tabname to itself and
#   the wallet pays @ex1.tabname (the certificate fetched from the full
#   name's points over a circuit, checked against the chain); the wallet
#   gives w1.famwal to itself, publishing it at its points, and A pays
#   @w1.famwal; A gives ex2.tabname to the wallet, which holds the
#   certificate sent to it.
# Waits as the node's scripts: no deadline, each fails when nothing new
# has changed for its idle window (scripts/waitlib.sh's rule).
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/onitest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/onitest; PA=37531; R1=37532; R2=37533; R3=37534; WP=37421; HP=37394
[ -x "$MINER" ] || { echo "onitest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "onitest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; QP=; RPS=
trap 'st=$?; exec 3>&- 4>&- 2>/dev/null; for p in $QP $RPS $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
. scripts/waitlib.sh

echo "onitest.sh: the three relays' ids (each started once, its line read)"
for k in 1 2 3; do
	eval P=\$R$k
	"$MINER" node --network dev-recursive --data "$T/r$k" --no-seeds --relay --no-prompt --listen 127.0.0.1:$P > "$T/r$k.first" 2>&1 &
	p=$!
	wait_for "$T/r$k/tabminer.log" '^.* relay tab1[0-9a-z]* 127' 300 "relay $k's line"
	kill $p; wait $p 2>/dev/null || true
done
# the file: as the tabminers see the relays, and as the OS does (10.0.2.2)
{ echo "mode onion"; for k in 1 2 3; do eval P=\$R$k; echo "relay $(sed -n 's/.* relay \(tab1[0-9a-z]*\) 127.*/\1/p' "$T/r$k/tabminer.log" | head -1) 127.0.0.1:$P"; done; } > "$T/relays.txt"
sed 's/127\.0\.0\.1:/10.0.2.2:/' "$T/relays.txt" > "$T/relays-os.txt"
cat "$T/relays.txt"

echo "onitest.sh: tabminer mining, its prompt open, the relays in force (a test)"
mkfifo "$T/a.in"
TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
	--test-relays "$T/relays.txt" --listen 127.0.0.1:$PA < "$T/a.in" >> "$T/a.out" 2>&1 &
AP=$!
exec 4> "$T/a.in"
wait_for "$T/a/tabminer.log" 'is the tip at height 3$' 600 "tabminer's first 3 blocks"
echo "onitest.sh: the relays again, following the miner"
for k in 1 2 3; do
	eval P=\$R$k
	TABMINER_THREADS=1 "$MINER" node --network dev-recursive --data "$T/r$k" --no-seeds --relay --no-prompt \
		--test-relays "$T/relays.txt" --listen 127.0.0.1:$P --peer 127.0.0.1:$PA > "$T/r$k.out" 2>&1 &
	RPS="$RPS $!"
done

echo "onitest.sh: the node following it, wm serving"
mkfifo "$T/in"
./tools/q32 --net --hostfwd=tcp::$WP-:80,hostfwd=tcp::$HP-:3738 --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
{
	echo 'mkdir /etc'
	echo 'mkdir /etc/node'
	# (each line in two pieces: the console takes lines of 63 bytes at most)
	while read -r l; do
		echo "echo -n $(echo "$l" | cut -c1-40) >> /etc/node/relays.txt"
		echo "echo $(echo "$l" | cut -c41-) >> /etc/node/relays.txt"
	done < "$T/relays-os.txt"
	echo 'echo test-relays /etc/node/relays.txt > /etc/node/config'
	echo "node -n devrec 10.0.2.2:$PA &"
	echo 'mkdir /etc'
	echo 'mkdir /etc/wallet'
	echo "echo seed 10.0.2.2:$R1 > /etc/wallet/config"
	echo 'echo root:paypw:0:0:/:sh > /etc/passwd'
	echo 'wm 80 &'
} >&3
wait_own "$T/os.out" '^node: .* (synced, height [0-9]+$|height [0-9]+  \()' 900 "the node in sync"
wait_for "$T/os.out" 'wm: port 80' 60 "wm"

echo "onitest.sh: the wallets paying each other in onion mode, over circuits"
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
            print(f'onitest: ({what}: {told - b0} blocks so far)')
        if blocks() > b0 + 30:
            print(f'onitest: {what}: not in 30 blocks'); sys.exit(1)
        now = progress()
        if now != last:
            last, still = now, 0
        else:
            still += 2
            if still >= idle:
                print(f'onitest: {what}: nothing new for {idle} s'); sys.exit(1)
def check(what, cond):
    print(f'onitest: {what}: {"ok" if cond else "FAILED"}')
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
        print('onitest: the wallet closed; its last messages:')
        for m in msgs[-3:]:
            print(f'  {str(m)[:300]}')
        print(f'  (unparsed: {buf[-200:]!r})')
        sys.exit(1)
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
                    print('onitest: (the wallet: ' + str(msgs[-1].get('text', msgs[-1])) + ')')
            except ValueError:
                print('onitest: not JSON from the wallet: ' + p.decode(errors='replace')[:2000]); raise
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
    o = ask('overview')
    # a session at each of its three points (three relays: all of them)
    return o if o.get('mode') == 'onion' and o.get('points') == 3 and o.get('reach', 0) == 3 else None
check('the wallet in onion mode, its sessions live at its three points', wait('the wallet\'s standing sessions', reach))
def events(kind):
    return [m for m in msgs if m.get('event') == kind]

# A pays the wallet 2.5 by its address, over circuits
def tab_addr():
    tab('address'); time.sleep(3)
    return re.search(r'(tab1[0-9a-z]{58})$', aout(), re.M)
ma = wait('A\'s address', tab_addr).group(1)
tab(f'send 2.5 {addr}')
got = wait('the 2.5 confirmed in the wallet', lambda: (pumpone(), time.sleep(3), confirmed() == '2.5000000000')[2])
check('A sent the slate over a circuit, the wallet answered along its route, A finalized it: 2.5 confirmed', got)

# the wallet pays A 1 online
p = ask('send-online', to=ma, amount='1', speed='hour')
check(f'the wallet sent a slate in onion mode: fee {p.get("fee", p.get("error"))}', p['ok'] and p.get('online'))
def fin():
    pumpone(); time.sleep(1)
    return next((m for m in events('message') if 'tx' in m or (m.get('ok') is False and 'error' in m)), None)
f = wait('the wallet finalizing A\'s answer', fin)
check(f'A answered along the route, the wallet finalized it: {f.get("tx", f.get("error"))}', f.get('ok') and len(f.get('tx', '')) == 64)
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

# A gives ex1.tabname to itself; the wallet pays @ex1.tabname (the certificate fetched from its points, checked)
tab(f'subname set ex1.tabname {ma}')
wait('the wallet\'s coins settled again', settled)
n0 = nfinal()
p = ask('send-online', to='@ex1.tabname', amount='0.1', speed='hour')
check(f'the wallet asks the points of ex1.tabname for its certificate: {p}', p['ok'] and p.get('resolving'))
f = wait('the payment to @ex1.tabname finalized', finalized(n0))
check(f'ex1.tabname resolved at its points, paid, finalized: {f.get("tx", f.get("error"))}', f.get('ok') and len(f.get('tx', '')) == 64)

# the wallet gives w1.famwal to itself and publishes it; A pays @w1.famwal (fetched from the points)
g = ask('subname-set', name='famwal', label='w1', to=addr)
check(f'the wallet gives w1.famwal to itself: {g.get("error", "ok")}', g['ok'])
subs = ask('subnames')['items']
check(f'its sub-names: {subs}', any(i['sub'] == 'w1.famwal' and i['holder'] == addr for i in subs))
na = len([m for m in events('message') if 'answered a slate of 0.0500000000' in m.get('text', '')])
tab('send 0.05 @w1.famwal')
def answered():
    pumpone(); time.sleep(1)
    return len([m for m in events('message') if 'answered a slate of 0.0500000000' in m.get('text', '')]) > na
check('A fetched w1.famwal from its points (the wallet published it), and paid it: the wallet answered its slate', wait('A paying @w1.famwal', answered))

# A gives ex2.tabname to the wallet: the certificate sent to its holder, held
tab(f'subname set ex2.tabname {addr}')
def held():
    pumpone(); time.sleep(1)
    return any('ex2.tabname: its certificate held' in m.get('text', '') for m in events('message'))
check('A sent the wallet the certificate for ex2.tabname; the wallet checked and holds it', wait('the wallet holding ex2.tabname', held))
EOF
echo "onitest.sh: done"
