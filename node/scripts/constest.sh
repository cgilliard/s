#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# constest.sh — the node following the network's consensus.txt
# (docs/ONION.md; src/user/node/cons.fam).  tabminer mines the recursive dev
# network (UDP 37521), its prompt read from a fifo; the OS's node follows it
# (its API forwarded from 37393).  tabminer votes (`set-leaf 0`) for a file
# putting the network in onion mode with three relays, listed out of order;
# its blocks carry the vote in their aux leaves.  The node must fetch each
# block's leaves (checked against its header), the file (checked by its
# SHA-256), and tell /v1/consensus:
# - "running" (the window ending at the tip) onion, the three relays sorted
#   by id, the file's hash; "current" still init (no boundary passed: the
#   first is at 144).
# Waits as the node's scripts: no deadline, each fails when nothing new
# has changed for its idle window (scripts/waitlib.sh's rule).
# Needs tabminer built with the dev networks:
#   (cd ../miner && cargo build --release --features dev)
# Usage: scripts/constest.sh
set -e
cd "$(dirname "$0")/.."
MINER=../miner/target/release/tabminer
T=tmp/constest; PA=37521; HP=37393
[ -x "$MINER" ] || { echo "constest.sh: build tabminer first: (cd ../miner && cargo build --release --features dev)" >&2; exit 1; }
[ -f bin/img ] || { echo "constest.sh: run scripts/build.sh first" >&2; exit 1; }
rm -rf "$T"; mkdir -p "$T"
dd if=/dev/zero of="$T/node.disk" bs=1 count=0 seek=268435456 2>/dev/null

AP=; QP=
trap 'st=$?; exec 3>&- 4>&- 2>/dev/null; for p in $QP $AP; do kill $p 2>/dev/null; wait $p 2>/dev/null || true; done; exit $st' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
. scripts/waitlib.sh

# the file: onion mode, three relays out of order (ids as 64 hex digits)
cat > "$T/consensus.txt" <<EOT
# a test network's relays
mode onion
relay 0300000000000000000000000000000000000000000000000000000000000000 relay-c.example:3737
relay 0100000000000000000000000000000000000000000000000000000000000000 10.0.0.1:3737   # the first
relay 0200000000000000000000000000000000000000000000000000000000000000 relay-b.example:4000
EOT

echo "constest.sh: tabminer mining, its prompt open"
mkfifo "$T/a.in"
TABMINER_THREADS=${TABMINER_THREADS:-4} "$MINER" mine --network dev-recursive --data "$T/a" --no-seeds \
	--listen 127.0.0.1:$PA < "$T/a.in" >> "$T/a.out" 2>&1 &
AP=$!
exec 4> "$T/a.in"
wait_for "$T/a/tabminer.log" 'is the tip at height 3$' 600 "tabminer's first 3 blocks"
echo "set-leaf 0 $T/consensus.txt" >&4

echo "constest.sh: the node following it"
mkfifo "$T/in"
./tools/q32 --net --hostfwd=tcp::$HP-:3738 --disk="$T/node.disk" bin/img < "$T/in" > "$T/os.out" 2>&1 &
QP=$!
exec 3> "$T/in"
wait_for "$T/os.out" '^\$ ' 60 "the shell"
echo "node -n devrec 10.0.2.2:$PA &" >&3
wait_for "$T/os.out" '^node: .* (synced, height [0-9]+$|height [0-9]+  \()' 900 "the node in sync"

python3 -u - "$T" "$HP" "$(sha256sum "$T/consensus.txt" | cut -c1-64)" <<'EOF' || { wdump; exit 1; }
import json, os, sys, time, urllib.request
T, api, fhash = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def blocks():
    return open(f'{T}/a/tabminer.log', errors='replace').read().count('is the tip at height')
def progress():
    return sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(T) for f in fs if f.endswith(('.out', '.log')))
def wait(what, cond, idle=300):
    # blocks are the clock: 30 without it fails; so does nothing new for the idle window
    last, still, b0 = progress(), 0, blocks()
    told = b0
    while True:
        r = cond()
        if r:
            return r
        time.sleep(2)
        if blocks() >= told + 5:
            told = blocks()
            print(f'constest: ({what}: {told - b0} blocks so far)')
        if blocks() > b0 + 30:
            print(f'constest: {what}: not in 30 blocks'); sys.exit(1)
        now = progress()
        if now != last:
            last, still = now, 0
        else:
            still += 2
            if still >= idle:
                print(f'constest: {what}: nothing new for {idle} s'); sys.exit(1)
def check(what, cond):
    print(f'constest: {what}: {"ok" if cond else "FAILED"}')
    if not cond:
        sys.exit(1)
seen = [None]
def cons():
    try:
        c = json.loads(urllib.request.urlopen(f'http://127.0.0.1:{api}/v1/consensus', timeout=30).read())
    except Exception as e:
        c = {'error': str(e)}
    if c != seen[0]:
        seen[0] = c
        print(f'constest: (the node: {json.dumps(c)[:600]})')
    return c
def onion():
    time.sleep(3)
    c = cons()
    r = c.get('running')
    return c if r and r.get('mode') == 'onion' else None
c = wait('the node following the vote', onion)
r = c['running']
want = [('01' + '00' * 31, '10.0.0.1:3737'), ('02' + '00' * 31, 'relay-b.example:4000'), ('03' + '00' * 31, 'relay-c.example:3737')]
check(f'the running decision: onion, the file {r["hash"][:16]}...', r['hash'] == fhash)
check('its three relays, sorted by id', [(x['id'], x['address']) for x in r['relays']] == want)
check('the decision in force still init (no boundary passed)', c['current']['mode'] == 'init' and c['current']['hash'] is None and c['previous'] is None)
check(f'the height {c["height"]}, epoch {c["epoch"]}, into {c["into"]}', c['epoch'] == 0 and c['into'] == c['height'])
EOF
echo "constest.sh: done"
