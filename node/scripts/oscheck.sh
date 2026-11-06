#!/bin/sh
# oscheck.sh — the OS's checks (docs/OS.md); run after scripts/build.sh.
#
# The kernel's own tests (the Test blocks in src/kernel.fam), a fault in the
# kernel reported rather than hung on, and the image booting: by itself
# under q32, and through tabernacle from a disk holding it.  Every run has a
# time limit; one that should keep running (the booted kernel) passes when
# the limit ends it.

cd "$(dirname "$0")/.." || exit 1
T=tmp/oscheck
rm -rf "$T"; mkdir -p "$T"
FAILS=0; N=0

# lim SECONDS CMD... — as in scripts/check.sh: CMD killed after SECONDS with
# everything it started (exit 124), its stdin /dev/null.
lim() {
	perl -e '
		$t = shift;
		$p = fork // die "fork: $!";
		if (!$p) { setpgrp(0, 0); exec @ARGV or die "exec: $!" }
		$SIG{ALRM} = sub { kill "KILL", -$p; waitpid($p, 0); exit 124 };
		alarm $t;
		waitpid($p, 0);
		exit($? & 127 ? 128 + ($? & 127) : $? >> 8);
	' "$@" < /dev/null
}

fail() { echo "FAIL $1: $2"; FAILS=$((FAILS + 1)); }

# expect NAME EXIT PATTERN SECONDS CMD... — CMD exits EXIT (124: still
# running when the time was up) and its output matches PATTERN.
expect() {
	name=$1; want=$2; pat=$3; secs=$4; shift 4
	N=$((N + 1))
	lim "$secs" "$@" > "$T/$name.out" 2>&1; rc=$?
	[ "$rc" = "$want" ] || { fail "$name" "exit $rc, expected $want: $(head -c 300 "$T/$name.out")"; return; }
	grep -q -- "$pat" "$T/$name.out" || fail "$name" "output $(head -c 300 "$T/$name.out"), expected /$pat/"
}

[ -f bin/img ] && [ -f bin/tabernacle ] || { echo "oscheck.sh: run scripts/build.sh first" >&2; exit 1; }

expect kernel_tests 0 'passed' 120 ./tools/fam --test src/kernel.fam

printf 'trapinit 0 lit @ drop bye\n' > "$T/fault.fam"
./tools/fam -o "$T/fault.bin" src/kernel.fam "$T/fault.fam" > "$T/fault.build" 2>&1 \
	|| fail fault_build "$(head -c 300 "$T/fault.build")"
expect fault 1 'kernel: trap 00000005 at .* (00000000)' 30 ./tools/q32 "$T/fault.bin"

expect boot 124 'kernel: [0-9]* pages free' 3 ./tools/q32 bin/img

scripts/makenode.sh --disk="$T/disk.img" > /dev/null
expect boot_disk 124 'tabernacle: from disk' 5 scripts/node.sh --disk="$T/disk.img" --no-seeds
grep -q 'kernel: [0-9]* pages free' "$T/boot_disk.out" \
	|| fail boot_disk "no kernel banner: $(head -c 300 "$T/boot_disk.out")"
rm -f "$T/disk.img"

echo "$((N - FAILS)) of $N checks passed"
[ "$FAILS" = 0 ]
