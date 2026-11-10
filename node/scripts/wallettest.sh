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
# again, unlocked from its records, it finds the same.
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
wait_for "$T/os.out" "^node: .* height $tip  \\(" 900 "the node at the miner's tip ($tip)"
wait_for "$T/os.out" '^api: listening' 120 "the node's API"
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
grep -E '^\{"(id|op|event)"' "$T/os.out"

python3 - "$HP" "$T/os.out" <<'EOF'
import json, sys, urllib.request
port, out = sys.argv[1], sys.argv[2]
total, frm = 0, 0
while True:
    body = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{port}/v1/outputs?from={frm}&count=1000', timeout=60).read())
    total += sum(o['amount'] for o in body['outputs'])
    if len(body['outputs']) < 1000:
        break
    frm = body['next']
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
check('the tip told', any(l.get('event') == 'tip' for l in lines))
check('an address', answer(3)['address'].startswith('tab1') and len(answer(3)['address']) == 62)
check('run again, unlocked from its records: the same', answer(4)['confirmed'] == want)
EOF
echo "wallettest.sh: the wallet found the miner's coins through the node"
