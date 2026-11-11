#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# wallettest.sh — the OS's wallet (docs/GUI_WALLET.md, phase 1) finding its
# coins through the node.  On the host, tabminer restores a known phrase
# and mines the recursive dev network (UDP 37491) into it to 4 blocks, then
# serves without mining.  In the OS (bin/img), `node 10.0.2.2:37491` syncs;
# then `wallet < /w.req`, as root in /: wm's unlock, a restore of the same
# phrase (the scan follows), the overview, the address.  Every output in
# the set is the miner's, so the wallet's confirmed balance must be their
# sum, read on the host from the node's API (forwarded, no token).  Run
# again, unlocked from its records, it finds the same.  Then a payment by
# file between two wallets in the OS: A (the miner's phrase, in /) sends
# 1.5 coins (/p.slate); B (a new wallet, in /b) answers it
# (/p.slate.received); A finalizes it and the node takes the transaction
# and relays it to tabminer, mining meanwhile, until the node's pool is
# empty: it is in a block.
# B's confirmed balance is then 1.5; A's every output's but B's; A's
# activity shows the payment, B's the output it received.  The slate files
# are text (.txt: base64 between markers, as tabminer writes them).  Then
# by copy and paste: A makes a slate as text in its answer, B answers it
# pasted (its answer, text too, about 7,600 characters, too long to type
# back into the console: finalizing from pasted text is the window's).
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/wallettest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/wallettest
PA=${WALLETTEST_PORT:-37491}; HP=${WALLETTEST_API:-37392}
PHRASE="legal winner thank year wave sausage worth useful legal winner thank yellow"
[ -x "$MINER" ] || { echo "wallettest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "wallettest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; QP=
trap 'st=$?; exec 3>&- 2>/dev/null; for p in $QP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
. scripts/waitlib.sh
miner() {
	TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
		--listen 127.0.0.1:$PA --no-prompt "$@" >> "$T/a.out" 2>&1 &
	AP=$!
}
stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null || true; }

echo "wallettest.sh: tabminer restoring the phrase and mining 4 blocks into it"
printf '%s\n\n' "$PHRASE" | "$MINER" restore --network dev-recursive --data "$T/a" > "$T/restore.out" 2>&1
miner
wait_for "$T/a.out" 'is the tip at height 4$' 600 "4 blocks"
stop $AP; AP=
miner --no-mine

echo "wallettest.sh: the node syncing, then the wallet"
mkfifo "$T/in"
./tools/q32 --net --hostfwd=tcp::$HP-:3738 --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
echo "node -n devrec 10.0.2.2:$PA &" >&3
tip=$(sed -n 's/.* is the tip at height \([0-9]*\)$/\1/p' "$T/a/tabminer.log" | tail -1)
wait_for "$T/os.out" "^node: .* (synced, height $tip\$|height $tip  \\()" 900 "the node at the miner's tip ($tip)"
wait_for "$T/os.out" '^node: .* the API on port' 120 "the node's API"
{
	echo 'echo {"op":"unlock","password":"wpw"} > /w.req'
	echo "echo {\"id\":1,\"op\":\"restore\",\"words\":\"$PHRASE\",\"passphrase\":\"\"} >> /w.req"
	echo 'echo {"id":2,"op":"overview"} >> /w.req'
	echo 'echo {"id":3,"op":"receive"} >> /w.req'
	echo 'echo {"op":"unlock","password":"wpw"} > /w2.req'
	echo 'echo {"id":4,"op":"overview"} >> /w2.req'
	echo 'wallet < /w.req'
} >&3
wait_for "$T/os.out" '^\{"id":3,' 600 "the wallet's first run"
echo 'wallet < /w2.req' >&3
wait_for "$T/os.out" '^\{"id":4,' 300 "the wallet run again"
# the set's total now, for the balance the wallet saw (all the miner's)
settotal() {
	python3 - "$HP" <<'PYEOF'
import json, sys, urllib.request
total, frm = 0, 0
while True:
    body = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{sys.argv[1]}/v1/outputs?from={frm}&count=1000', timeout=60).read())
    total += sum(o['amount'] for o in body['outputs'])
    if len(body['outputs']) < 1000:
        break
    frm = body['next']
print(total)
PYEOF
}
settotal > "$T/total1"

echo "wallettest.sh: A paying B 1.5 by file, the miner mining meanwhile"
stop $AP; AP=
miner
{
	echo 'echo {"op":"unlock","password":"wpw"} > /s.req'
	echo 'echo {"id":5,"op":"fees"} >> /s.req'
	echo 'echo {"id":6,"op":"send","to":"","amount":"1.5","speed":"hour","slate":"/p.slate.txt"} >> /s.req'
	echo 'wallet < /s.req'
} >&3
wait_for "$T/os.out" '^\{"id":6,' 600 "A's slate"
{
	echo 'mkdir /b'
	echo 'cd /b'
	echo 'echo {"op":"unlock","password":"bpw"} > /b/r.req'
	echo 'echo {"id":7,"op":"create"} >> /b/r.req'
	echo 'echo {"id":8,"op":"answer","slate":"/p.slate.txt"} >> /b/r.req'
	echo 'wallet < /b/r.req'
} >&3
wait_for "$T/os.out" '^\{"id":8,' 600 "B's answer"
{
	echo 'cd /'
	echo 'echo {"op":"unlock","password":"wpw"} > /f.req'
	echo 'echo {"id":9,"op":"finalize","slate":"/p.slate.txt.received"} >> /f.req'
	echo 'wallet < /f.req'
} >&3
wait_for "$T/os.out" '^\{"id":9,' 600 "A's finalize"
# mined: the node's pool empty again (it held the payment)
mined() {
	python3 -c "import json,sys,urllib.request; sys.exit(0 if json.loads(urllib.request.urlopen('http://127.0.0.1:$HP/v1/mempool', timeout=30).read())['count'] == 0 else 1)"
}
wait_while_busy 600 "the payment mined" mined
stop $AP; AP=
miner --no-mine
tip=$(sed -n 's/.* is the tip at height \([0-9]*\)$/\1/p' "$T/a/tabminer.log" | tail -1)
wait_for "$T/os.out" "^node: .* (synced, height $tip\$|height $tip  \\()" 900 "the node at the miner's tip ($tip)"
{
	echo 'echo {"op":"unlock","password":"wpw"} > /o.req'
	echo 'echo {"id":10,"op":"overview"} >> /o.req'
	echo 'echo {"id":11,"op":"activity"} >> /o.req'
	echo 'wallet < /o.req'
	echo 'cd /b'
	echo 'echo {"op":"unlock","password":"bpw"} > /b/o.req'
	echo 'echo {"id":12,"op":"overview"} >> /b/o.req'
	echo 'echo {"id":13,"op":"activity"} >> /b/o.req'
	echo 'wallet < /b/o.req'
	echo 'cd /'
} >&3
wait_for "$T/os.out" '^\{"id":13,' 600 "the wallets after the payment"

echo "wallettest.sh: a slate by copy and paste: A makes one as text, B answers it pasted"
{
	echo 'echo {"op":"unlock","password":"wpw"} > /t.req'
	echo 'echo {"id":14,"op":"send","to":"","amount":"0.25","speed":"hour","text":true} >> /t.req'
	echo 'wallet < /t.req'
} >&3
wait_for "$T/os.out" '^\{"id":14,' 600 "A's slate as text"
# the text pasted in B's request, its newlines as JSON's
txt=$(grep '^{"id":14,' "$T/os.out" | tail -1 | sed 's/.*"text":"\([^"]*\)".*/\1/')
{
	echo 'cd /b'
	echo 'echo {"op":"unlock","password":"bpw"} > /b/t.req'
	echo "echo {\"id\":15,\"op\":\"answer\",\"text\":\"$txt\"} >> /b/t.req"
	echo 'wallet < /b/t.req'
	echo 'cd /'
} >&3
wait_for "$T/os.out" '^\{"id":15,' 600 "B's answer as text"
grep -E '^\{"(id|op|event)"' "$T/os.out"

settotal > "$T/total2"
python3 - "$HP" "$T/os.out" "$(cat "$T/total1")" "$(cat "$T/total2")" <<'EOF'
import json, sys, urllib.request
port, out = sys.argv[1], sys.argv[2]
total = int(sys.argv[3])
want = f'{total // 10**10}.{total % 10**10:010d}'
lines = [json.loads(l) for l in open(out, errors='replace').read().splitlines() if l.startswith('{"')]
def answer(i):
    return next(l for l in lines if l.get('id') == i)
def check(what, cond):
    print(f'wallettest: {what}: {"ok" if cond else "FAILED"}')
    if not cond:
        sys.exit(1)
check('restored', answer(1)['ok'])
check(f'the confirmed balance is every output\'s: {want}', answer(2)['confirmed'] == want and total > 0)
check('the tip told, with its hash', any(l.get('event') == 'tip' and len(l.get('hash', '')) == 64 for l in lines))
check('an address', answer(3)['address'].startswith('tab1') and len(answer(3)['address']) == 62)
check('run again, unlocked from its records: the same', answer(4)['confirmed'] == want)
# the payment
check(f'the fees: {[s["rate"] for s in answer(5)["speeds"]]}', answer(5)['ok'] and len(answer(5)['speeds']) == 4)
check(f'A sent by file (a text one, .txt): fee {answer(6).get("fee")}', answer(6)['ok'] and answer(6)['slate'] == '/p.slate.txt')
check('B created', answer(7)['ok'])
check('B answered', answer(8)['ok'] and answer(8)['slate'] == '/p.slate.txt.received' and answer(8)['amount'] == '1.5000000000')
check(f'A finalized: {answer(9).get("tx", answer(9).get("error"))}', answer(9)['ok'] and len(answer(9)['tx']) == 64)
total = int(sys.argv[4])
paid = 15 * 10**9
a = total - paid
check(f'B confirmed 1.5', answer(12)['confirmed'] == '1.5000000000')
check(f'A confirmed every output but B\'s: {a // 10**10}.{a % 10**10:010d}', answer(10)['confirmed'] == f'{a // 10**10}.{a % 10**10:010d}')
check('A\'s activity: the payment sent, confirmed', any(i['kind'] == 'sent' and i['tx'] == answer(9)['tx'] and i['amount'] == '1.5000000000' and i['state'] == 'confirmed' for i in answer(11)['items']))
check('B\'s activity: the output received, confirmed', any(i['kind'] == 'received' and i['amount'] == '1.5000000000' and i['state'] == 'confirmed' for i in answer(13)['items']))
# by copy and paste: the texts decode to slates, stage 1 then 2
import base64
def slate_of(text):
    b = text.split('-----BEGIN TAB SLATE-----')[1].split('-----END TAB SLATE-----')[0]
    return base64.b64decode(''.join(b.split()))
s1 = slate_of(answer(14)['text']); s2 = slate_of(answer(15)['text'])
check(f'A\'s slate as text: {len(answer(14)["text"])} characters, stage 1', answer(14)['ok'] and s1[:8] == b'tabslt05' and s1[72] == 1)
check(f'B\'s answer as text, pasted: {len(answer(15)["text"])} characters, stage 2, 0.25', answer(15)['ok'] and answer(15)['amount'] == '0.2500000000' and s2[:8] == b'tabslt05' and s2[72] == 2 and s2[8:40] == s1[8:40])
EOF
echo "wallettest.sh: the wallet found the miner's coins through the node, and paid another wallet by file"
