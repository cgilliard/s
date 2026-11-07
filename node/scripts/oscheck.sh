#!/bin/sh
# oscheck.sh — the OS's checks (docs/OS.md); run after scripts/build.sh.
#
# The kernel's own tests (the Test blocks in src/kernel.fam) on 1, 2, 8 and
# 64 harts; a fault in the kernel reported rather than hung on; the image
# booting, by itself under q32 and through tabernacle from a disk holding
# it, on one hart and on several, and running init in user mode; and
# programs in user mode that touch the kernel's memory, write their own
# code, or make bad system calls: each ended or refused, the system going
# on.  Every run has a time limit; one
# that should keep running (the booted kernel) passes when the limit ends it.

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

for n in 1 2 8 64; do
	expect "kernel_tests_$n" 0 "harts: $n" 120 ./tools/fam --test --smp=$n src/kernel.fam
done

printf 'trapinit 0 lit @ drop bye\n' > "$T/fault.fam"
./tools/fam -o "$T/fault.bin" src/kernel.fam "$T/fault.fam" > "$T/fault.build" 2>&1 \
	|| fail fault_build "$(head -c 300 "$T/fault.build")"
expect fault 1 'kernel: hart 0 trap 00000005 at .* (00000000)' 30 ./tools/q32 "$T/fault.bin"

expect boot 124 'kernel: init ended: 0' 3 ./tools/q32 bin/img
grep -q 'kernel: 1 hart, [0-9]* pages free' "$T/boot.out" && grep -q 'init: hello from user mode' "$T/boot.out" \
	|| fail boot "no banner or no init: $(head -c 300 "$T/boot.out")"
expect boot_6 124 'kernel: 6 harts' 5 ./tools/q32 --smp=6 bin/img

# uprog NAME SOURCE — a program in user mode, run as init in an image of its
# own: $T/NAME.img.
uprog() {
	printf '%s\n' "$2" > "$T/$1.fam"
	./tools/fam --user -o "$T/$1.bin" "$T/$1.fam" > "$T/$1.build" 2>&1 \
		&& sh scripts/mkimage.sh "$T/$1.img" bin/kernel init="$T/$1.bin" 2>> "$T/$1.build" \
		|| fail "$1" "build: $(head -c 300 "$T/$1.build")"
}
uprog ufault '80000000 lit @ drop "not reached" puts bye'
expect ufault 124 'kernel: process killed: trap 00000005 at .* (80000000)' 4 ./tools/q32 --smp=2 "$T/ufault.img"
grep -q 'kernel: init ended: -1' "$T/ufault.out" || fail ufault "init did not end -1: $(head -c 300 "$T/ufault.out")"
uprog ucode '0 lit "abc" c! "not reached" puts bye'
expect ucode 124 'kernel: process killed: trap 00000007' 4 ./tools/q32 "$T/ucode.img"
uprog usys '1 lit 80000000 lit 10 lit 11 lit sys . 2C lit putc
1 lit 0 lit 0 lit 63 lit sys . 2C lit putc
5 lit "x" 1 lit 11 lit sys . 2C lit putc
40 lit alloc dup 41 lit swap c! 1 lit swap 1 lit 11 lit sys . 0A lit putc
bye'
expect usys 124 '^-14,-38,-9,A1$' 4 ./tools/q32 "$T/usys.img"
grep -q 'kernel: init ended: 0' "$T/usys.out" || fail usys "init did not end 0: $(head -c 300 "$T/usys.out")"

scripts/makenode.sh --disk="$T/disk.img" > /dev/null
expect boot_disk 124 'tabernacle: from disk' 5 scripts/node.sh --disk="$T/disk.img" --no-seeds
grep -q 'init: hello from user mode' "$T/boot_disk.out" \
	|| fail boot_disk "no init: $(head -c 300 "$T/boot_disk.out")"
expect boot_disk_64 124 'kernel: 64 harts' 15 scripts/node.sh --disk="$T/disk.img" --no-seeds --smp=64
rm -f "$T/disk.img"

echo "$((N - FAILS)) of $N checks passed"
[ "$FAILS" = 0 ]
