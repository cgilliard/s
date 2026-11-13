#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# paytest.sh — tabminer's wallet and the OS's paying each other
# (docs/GUI_WALLET.md, phase 1, step 4), the OS's wallet driven as its
# window drives it: over wm's /wallet WebSocket, logged in.  On the host,
# tabminer mines the recursive dev network (UDP 37493), its prompt read
# from a pipe; in the OS (bin/img), the node follows it and wm serves
# (forwarded).  Then:
# - tabminer pays the OS's wallet 2.5: `send-file 2.5 s1.slate` (a slate as
#   text), the wallet answers it pasted, tabminer finalizes the answer (a
#   file); once mined, the wallet holds 2.5 confirmed;
# - the OS's wallet pays tabminer 1: a slate made as text, tabminer
#   `receive`s it (a file) and writes its answer, the wallet finalizes it
#   pasted; once mined, tabminer holds a confirmed output of 1 and the
#   wallet 2.5 - 1 - its fee;
# - bump and cancel, tabminer stopped (SIGSTOP) while the wallet replaces:
#   a burn bumped, then landed; another cancelled, its coins back less the
#   cancel's fee, to the base unit;
# - proofs of payment each way: the wallet's checked by tabminer's
#   verify-proof, tabminer's by the wallet; a burn each way, the same;
# - names: the wallet registers famwallet (commit, the reveal 3 blocks
#   on: dev-recursive's window) and tabminer finds it pointing at the wallet; tabminer registers
#   tabname and the wallet finds it (its proof checked), and proves
#   nosuchname absent; the wallet updates famwallet, both see the value;
#   transfers by offers as text: famwallet to tabminer, tabname to the
#   wallet (its offer written to a file in its home, then given again).
# No wait has a deadline: each fails only when nothing under its directory
# has changed for its idle window (scripts/waitlib.sh's rule), or blocks
# pass without it.  But while tabminer is stopped no blocks come and the
# node's lines still do, so those waits (the wallet told of its own
# replacement, seconds) fail after 120 s.
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/paytest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
# PART: payments (paytest.sh), proofs (prooftest.sh), names (nametest.sh):
# one each, a CI job each; each its own directory and ports.
PART=${PART:-payments}
case $PART in
	payments) T=tmp/paytest; PA=37493; WP=37394; HP=37386 ;;
	proofs) T=tmp/prooftest; PA=37497; WP=37396; HP=37387 ;;
	names) T=tmp/nametest; PA=37499; WP=37398; HP=37388 ;;
	*) echo "paytest.sh: PART is payments, proofs or names" >&2; exit 1 ;;
esac
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
./tools/q32 --net --hostfwd=tcp::$WP-:80,hostfwd=tcp::$HP-:3738 --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
{
	echo "node -n devrec 10.0.2.2:$PA &"
	echo 'mkdir /etc'
	echo 'mkdir /etc/wallet'
	echo 'echo messages off > /etc/wallet/config'
	echo 'echo root:paypw:0:0:/:sh > /etc/passwd'
	echo 'wm 80 &'
} >&3
wait_own "$T/os.out" '^node: .* (synced, height [0-9]+$|height [0-9]+  \()' 900 "the node in sync"
wait_os "$T/os.out" 'wm: port 80' 60 "wm"

echo "paytest.sh: the two wallets paying each other"
python3 -u - "$WP" "$T" "$PART" "$HP" "$AP" <<'EOF' || { wdump; exit 1; }
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
def wait(what, cond, idle=300, most=None):
    # The miner mines throughout, so its logs always grow: a wait fails
    # when nothing new comes for the idle window, or when 30 blocks pass
    # without what it waits for (blocks are the clock here).
    last, still, b0 = progress(), 0, blocks()
    told, t0 = b0, time.time()
    while True:
        r = cond()
        if r:
            return r
        time.sleep(2)
        # a line every five blocks, so a long wait shows in the log
        if blocks() >= told + 5:
            told = blocks()
            print(f'paytest: ({what}: {told - b0} blocks so far)')
        # 30 blocks, but never under 600 s: fast blocks (dev-recursive's
        # 6 s) made that about 3 minutes, under a send's 240 s and its
        # retry (docs/TIMING_FIXES.md, section 7)
        if blocks() > b0 + 30 and time.time() - t0 >= 600:
            print(f'paytest: {what}: not in 30 blocks (and 600 s)'); sys.exit(1)
        if most is not None and time.time() - t0 > most:
            print(f'paytest: {what}: not in {most} s (tabminer stopped)'); sys.exit(1)
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
            try:
                msgs.append(json.loads(p))
            except ValueError:
                print('paytest: not JSON from the wallet: ' + p.decode(errors='replace')[:2000]); raise
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

# tabminer pays the wallet 2.5
tab(f'send-file 2.5 {T}/s1.slate')
wait('tabminer\'s slate', lambda: 'written to' in aout() and os.path.exists(f'{T}/s1.slate'))
s1 = open(f'{T}/s1.slate').read()
check(f'tabminer\'s slate as text ({len(s1)} characters)', s1.startswith('-----BEGIN TAB SLATE-----'))
a = ask('answer', text=s1)
check(f'the wallet answered it pasted: {a.get("amount", a.get("error"))}', a['ok'] and a['amount'] == '2.5000000000')
open(f'{T}/s1.answer', 'w').write(a['text'])
n0 = aout().count('pooled; broadcasting it')
tab(f'finalize {T}/s1.answer')
wait('tabminer\'s finalize', lambda: aout().count('pooled; broadcasting it') > n0 or 'refused' in aout()[-2000:])
check('tabminer finalized the answer and pooled it', aout().count('pooled; broadcasting it') > n0)
got = wait('the 2.5 confirmed in the wallet', lambda: (time.sleep(3), confirmed() == '2.5000000000')[1])
check('the wallet holds 2.5 confirmed', got)
# It follows the node by its events (docs/TIMING_FIXES.md, item 15): the
# block thread, and a block told the page with nothing asked meanwhile,
# carrying every panel as of it (the overview's balance, the activity
# with the 2.5 received, the names).
check('the wallet follows the node by its events', ask('overview')['watch'] == 'events')
n0 = len([m for m in msgs if m.get('event') == 'block'])
wait('a block told, nothing asked', lambda: pumpone() or len([m for m in msgs if m.get('event') == 'block']) > n0)
b = [m for m in msgs if m.get('event') == 'block'][-1]
check(f'the block event at {b["height"]}: the overview, the activity, the names as of it',
      b['overview']['height'] == b['height'] and b['overview']['confirmed'] == '2.5000000000'
      and any(x['kind'] == 'received' and x['amount'] == '2.5000000000' for x in b['activity']['items'])
      and isinstance(b['names']['items'], list))

if part in ('payments', 'proofs'):
    # the wallet pays tabminer 1
    p = ask('send', to='', amount='1', speed='hour', text=True)
    check(f'the wallet made a slate as text: fee {p.get("fee", p.get("error"))}', p['ok'] and p['text'].startswith('-----BEGIN TAB SLATE-----'))
    open(f'{T}/s2.slate', 'w').write(p['text'])
    tab(f'receive {T}/s2.slate {T}/s2.answer')
    wait('tabminer\'s answer', lambda: os.path.exists(f'{T}/s2.answer') and os.path.getsize(f'{T}/s2.answer') > 0 and 'return it to the sender' in aout())
    s2 = open(f'{T}/s2.answer').read()
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
    check('its activity: received 2.5 (spent), sent 1 (confirmed), no row for the change',
          any(i['kind'] == 'received' and i['amount'] == '2.5000000000' and i['state'] == 'spent' for i in acts)
          and not any(i['kind'] == 'received' and i['amount'] == want for i in acts)
          and any(i['kind'] == 'sent' and i['amount'] == '1.0000000000' and i['tx'] == f['tx'] and i['state'] == 'confirmed' for i in acts))

if part == 'payments':
    # bump and cancel (docs/FEES.md): tabminer stopped (SIGSTOP) while the
    # wallet sends and replaces, so nothing is mined between; each
    # replacement then lands, the coins counted to the base unit
    import signal
    def units(a):
        w, f = a.split('.'); return int(w) * 10**10 + int(f)
    def coins(u):
        return f'{u // 10**10}.{u % 10**10:010d}'
    def in_acts(tx):
        return [i for i in ask('activity')['items'] if i['tx'] == tx]
    have = units(want)
    os.kill(apid, signal.SIGSTOP)
    try:
        b = ask('burn', amount='0.5', purpose='bumped', speed='hour')
        check(f'the wallet burns 0.5: {b.get("tx", b.get("error"))}', b['ok'])
        bb = ask('bump', tx=b['tx'], speed='block')
        check(f'the wallet bumps it: fee {b["fee"]} then {bb.get("fee", bb.get("error"))}', bb['ok'] and bb['tx'] != b['tx'] and units(bb['fee']) > units(b['fee']))
        check('its activity: the bump pending in the burn\'s place', [i['state'] for i in in_acts(bb['tx'])] == ['pending'] and not in_acts(b['tx']))
        # the node's word on it (docs/TIMING_FIXES.md, item 15): the burn
        # replaced by its bump, told to the page
        def told(tx, state, **kw):
            return lambda: pumpone() or any(m.get('event') == 'payment' and m.get('tx') == tx and m.get('state') == state
                                            and all(m.get(k) == v for k, v in kw.items()) for m in msgs)
        check('the burn told replaced by its bump', wait('the burn\'s payment event', told(b['tx'], 'replaced', by=bb['tx']), most=120))
    finally:
        os.kill(apid, signal.SIGCONT)
    have -= 5 * 10**9 + units(bb['fee'])
    check(f'the bump lands: the wallet holds {coins(have)}', wait('the bump in a block', lambda: (time.sleep(3), confirmed() == coins(have))[1]))
    check('its activity: the bump confirmed', [i['state'] for i in in_acts(bb['tx'])] == ['confirmed'])
    check('the bump told mined', wait('the bump\'s payment event', told(bb['tx'], 'mined')))
    os.kill(apid, signal.SIGSTOP)
    try:
        c = ask('burn', amount='0.25', purpose='cancelled', speed='hour')
        check(f'the wallet burns 0.25: {c.get("tx", c.get("error"))}', c['ok'])
        cc = ask('cancel', tx=c['tx'])
        check(f'the wallet cancels it: fee {cc.get("fee", cc.get("error"))}', cc['ok'] and cc['tx'] != c['tx'])
        check('its activity: the burn gone', not in_acts(c['tx']))
        check('the burn told replaced by its cancel', wait('the cancelled burn\'s payment event', told(c['tx'], 'replaced', by=cc['tx']), most=120))
        k = ask('bump', tx=c['tx'])
        check(f'a cancelled burn is not bumped: {k.get("error")}', not k['ok'])
    finally:
        os.kill(apid, signal.SIGCONT)
    have -= units(cc['fee'])
    check(f'the cancel lands: the wallet holds {coins(have)}', wait('the cancel in a block', lambda: (time.sleep(3), confirmed() == coins(have))[1]))

if part == 'proofs':
    # proofs (docs/PROOFS.md): each side's checked by the other
    pp = ask('proof', tx=f['tx'])
    check(f'the wallet proves its payment {"" if pp["ok"] else pp}', pp['ok'] and pp['proof'].startswith('-----BEGIN TAB PAYMENT PROOF-----'))
    open(f'{T}/fp.txt', 'w').write(pp['proof'])
    n0 = aout().count('payment proof holds') + aout().count('does not hold')
    tab(f'verify-proof {T}/fp.txt')
    wait('tabminer checking the wallet\'s proof', lambda: aout().count('payment proof holds') + aout().count('does not hold') > n0)
    check('tabminer finds it holds: 1 coin to its own address', re.search(r'payment proof holds: 1\.0000000000 coins from an unnamed sender', aout()) is not None)
    tid = re.findall(r'transaction ([0-9a-f]{16}) pooled', aout())[0]
    tab(f'payment-proof {tid} {T}/tp.txt')
    wait('tabminer\'s proof of its payment', lambda: os.path.exists(f'{T}/tp.txt') and 'proof written to' in aout())
    v = ask('verify', text=open(f'{T}/tp.txt').read())
    check(f'the wallet finds tabminer\'s proof holds: {v}', v['ok'] and v['valid'] and v['kind'] == 'payment' and v['amount'] == '2.5000000000' and v['to'] == addr)
    # burns: the wallet's, checked by tabminer; tabminer's (for the wallet), checked by the wallet
    bw = ask('burn', amount='0.5', purpose='credit', speed='hour')
    check(f'the wallet burns 0.5 for itself: {bw.get("tx", bw.get("error"))}', bw['ok'])
    bp = wait('the burn in a block, its proof', lambda: (time.sleep(3), (lambda r: r if r['ok'] else None)(ask('proof', tx=bw['tx'])))[1])
    open(f'{T}/fb.txt', 'w').write(bp['proof'])
    n0 = aout().count('proof of burn holds') + aout().count('does not hold')
    tab(f'verify-proof {T}/fb.txt')
    wait('tabminer checking the wallet\'s burn', lambda: aout().count('proof of burn holds') + aout().count('does not hold') > n0)
    check('tabminer finds the burn holds: 0.5 for the wallet, purpose credit', f'proof of burn holds: 0.5000000000 coins burned for {addr}, purpose "credit"' in aout())
    tab(f'burn 0.25 grant {addr}')
    bid = wait('tabminer\'s burn', lambda: (lambda m: m.group(1) if m else None)(re.search(r'burn-proof ([0-9a-f]{16}) once', aout())))
    def tab_burn_proof():
        tab(f'burn-proof {bid} {T}/tb.txt'); time.sleep(3)
        return os.path.exists(f'{T}/tb.txt')
    wait('tabminer\'s burn in a block, its proof', tab_burn_proof)
    v = ask('verify', text=open(f'{T}/tb.txt').read())
    check(f'the wallet finds tabminer\'s burn holds, for it, its purpose grant: {v}', v['ok'] and v['valid'] and v['kind'] == 'burn' and v['amount'] == '0.2500000000' and v['for'] == addr and v.get('purpose') == 'grant')
    t = open(f'{T}/tb.txt').read().replace('-----BEGIN TAB BURN PROOF-----', '-----BEGIN TAB PAYMENT PROOF-----').replace('-----END TAB BURN PROOF-----', '-----END TAB PAYMENT PROOF-----')
    v = ask('verify', text=t)
    check(f'a burn passed off as a payment refused: {v.get("error", v.get("reason"))}', not v['ok'] or not v['valid'])

if part == 'names':
    # names (docs/NAMES.md): the wallet's, looked up by tabminer; tabminer's, by the wallet
    c = ask('name-commit', name='famwallet', speed='hour')
    check(f'the wallet commits to famwallet: {c.get("tx", c.get("error"))}', c['ok'])
    seen = {}
    def named_any(name, state):
        def f():
            time.sleep(3)
            r = ask('names')
            it = [i for i in r.get('items', []) if i['name'] == name]
            now = it[0] if it else r
            if seen.get(name) != now:
                seen[name] = now
                print(f'paytest: (names: {name} {now})')
                try:
                    print('paytest: (the node: ' + urllib.request.urlopen(f'http://127.0.0.1:{api}/v1/name/{name}', timeout=30).read().decode()[:1500] + ')')
                except Exception as e:
                    print(f'paytest: (the node: {e})')
            return it[0] if it and it[0]['state'] == state else None
        return f
    def named(state):
        return named_any('famwallet', state)
    wait('the commit old enough (3 blocks)', named('ready'))
    r = ask('name-reveal', name='famwallet', speed='hour')
    check(f'the wallet reveals it: {r.get("tx", r.get("error"))}', r['ok'])
    wait('the name the wallet\'s on chain', named('owned'))
    # its steps as events (docs/TIMING_FIXES.md, item 15): the reveal's
    # window open, then owned, each told when a block moved it
    def name_told(state):
        return lambda: pumpone() or any(m.get('event') == 'name' and m.get('name') == 'famwallet' and m.get('state') == state for m in msgs)
    check('famwallet told ready, then owned', wait('famwallet\'s ready event', name_told('ready')) and wait('famwallet\'s owned event', name_told('owned')))
    def tab_name(name, has):
        def f():
            n0 = aout().count(f'value ') + aout().count('is not registered')
            tab(f'name {name}'); time.sleep(3)
            return has in aout()
        return f
    check('tabminer finds famwallet pointing at the wallet', wait('tabminer looking famwallet up', tab_name('famwallet', f'      {addr}')))
    tab('name-commit tabname')
    wait('tabminer\'s commit', lambda: 'committed to tabname' in aout())
    # asked once, its answer waited for (revealing, or an error: the commit not
    # old enough yet), and asked again only after that error and a new block:
    # never a second ask while a slow tabminer still works on the first
    rv = {}
    def tab_reveal():
        a = aout()
        if 'revealing tabname' in a:
            return True
        if not rv or (a.count('error: ') > rv['errs'] and blocks() > rv['b']):
            rv.update(errs=a.count('error: '), b=blocks())
            tab('name-reveal tabname')
        time.sleep(1)
        return False
    wait('tabminer revealing tabname', tab_reveal)
    def fam_found():
        time.sleep(3)
        l = ask('name-lookup', name='tabname')
        return l if l['ok'] and l['found'] else None
    l = wait('the wallet finding tabname', fam_found)
    check(f'the wallet finds tabname, checked against the state root: {l["address"][:16]}...', l['address'].startswith('tab1') and l['address'] != addr)
    l = ask('name-lookup', name='nosuchname')
    check('the wallet finds no nosuchname, its absence proven', l['ok'] and not l['found'])
    nv = '00' * 31 + '07'
    u = ask('name-update', name='famwallet', value=nv, speed='hour')
    check(f'the wallet updates famwallet: {u.get("tx", u.get("error"))}', u['ok'])
    def fam_value():
        time.sleep(3)
        l = ask('name-lookup', name='famwallet')
        return l if l['ok'] and l['found'] and l['value'] == nv else None
    wait('the update on chain', fam_value)
    check('tabminer sees the new value', wait('tabminer looking famwallet up again', tab_name('famwallet', f'value {nv}')))
    # transfers (offers as text): famwallet to tabminer, tabname to the wallet
    tab(f'name-offer famwallet {T}/off1.txt')
    wait('tabminer\'s offer', lambda: os.path.exists(f'{T}/off1.txt') and 'the offer for famwallet written' in aout())
    o1 = open(f'{T}/off1.txt').read()
    check('tabminer\'s offer is text', o1.startswith('-----BEGIN TAB NAME OFFER-----'))
    x = ask('name-transfer', text=o1, speed='hour')
    check(f'the wallet signs famwallet over: {x.get("tx", x.get("error"))}', x['ok'] and x['name'] == 'famwallet')
    check('tabminer holds famwallet', wait('the transfer to tabminer', tab_name('famwallet', "(this wallet's)")))
    of = ask('name-offer', name='tabname', file='tabname.offer')
    check(f'the wallet offers for tabname, to a file in its home: {of.get("file", of.get("error"))}', of['ok'] and of['file'] == 'tabname.offer')
    o2 = ask('name-offer', name='tabname')
    check('asked again, the wallet gives the same offer as text', o2['ok'] and o2['text'].startswith('-----BEGIN TAB NAME OFFER-----'))
    ns = [i['state'] for i in ask('names')['items'] if i['name'] == 'tabname']
    check(f'tabname offered in the wallet: {ns}', ns == ['offered'])
    open(f'{T}/off2.txt', 'w').write(o2['text'])
    n0 = aout().count('transferring tabname')
    tab(f'name-transfer {T}/off2.txt')
    wait('tabminer signing tabname over', lambda: aout().count('transferring tabname') > n0 or 'Error' in aout()[-300:])
    check('tabminer transfers tabname', aout().count('transferring tabname') > n0)
    wait('tabname the wallet\'s', named_any('tabname', 'owned'))
EOF
echo "paytest.sh ($PART): done"
