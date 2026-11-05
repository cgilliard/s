#!/bin/sh
# check.sh — the compiler's regression checks; run after scripts/build.sh.
#
# Programs that must not compile, programs that must trap (and with which
# mcause), and programs, tests and benches that must run.  Every run has a
# time limit: a hang is a failure, not a stuck job.

cd "$(dirname "$0")/.." || exit 1
T=tmp/check
rm -rf "$T"; mkdir -p "$T"
FAILS=0; N=0

# lim SECONDS CMD... — run CMD, killed after SECONDS with everything it started
# (exit 124).  Perl, as macOS has no `timeout`; a watchdog that kills the
# process group, as an alarm alone would reach only QEMU, which ignores it.
lim() {
	perl -e '
		$t = shift;
		$p = fork // die "fork: $!";
		if (!$p) { setpgrp(0, 0); exec @ARGV or die "exec: $!" }
		$SIG{ALRM} = sub { kill "KILL", -$p; waitpid($p, 0); exit 124 };
		alarm $t;
		waitpid($p, 0);
		exit($? & 127 ? 128 + ($? & 127) : $? >> 8);
	' "$@"
}

fail() { echo "FAIL $1: $2"; FAILS=$((FAILS + 1)); }

src() { printf '%s\n' "$2" > "$T/$1.fam"; N=$((N + 1)); }

# no_compile NAME SOURCE [FLAGS] — the compiler must refuse it.
no_compile() {
	src "$1" "$2"
	if lim 30 ./tools/fam $3 -o "$T/$1.bin" "$T/$1.fam" > "$T/$1.out" 2>&1; then
		fail "$1" "compiled; expected a compile error"
	elif ! grep -q "compile error" "$T/$1.out"; then
		fail "$1" "no compile error: $(head -c 200 "$T/$1.out")"
	fi
}

# runs NAME SOURCE EXIT PATTERN — compiles, runs, exits EXIT, output matches PATTERN.
runs() {
	src "$1" "$2"
	if ! lim 30 ./tools/fam -o "$T/$1.bin" "$T/$1.fam" > "$T/$1.out" 2>&1; then
		fail "$1" "did not compile: $(head -c 200 "$T/$1.out")"; return
	fi
	lim 30 ./tools/q32 "$T/$1.bin" > "$T/$1.run" 2>&1; rc=$?
	[ "$rc" = "$3" ] || { fail "$1" "exit $rc, expected $3: $(head -c 200 "$T/$1.run")"; return; }
	grep -q -- "$4" "$T/$1.run" || fail "$1" "output $(head -c 200 "$T/$1.run"), expected /$4/"
}

# suite NAME SOURCE MODE EXIT PATTERN — --test or --bench: exits EXIT, output matches.
suite() {
	src "$1" "$2"
	lim 30 ./tools/fam "$3" -o "$T/$1.bin" "$T/$1.fam" > "$T/$1.out" 2>&1; rc=$?
	[ "$rc" = "$4" ] || { fail "$1" "exit $rc, expected $4: $(head -c 200 "$T/$1.out")"; return; }
	grep -q -- "$5" "$T/$1.out" || fail "$1" "output $(head -c 200 "$T/$1.out"), expected /$5/"
}

FIB=': fib
dup 2 lit u< if else dup 1 lit - fib swap 2 lit - fib + then ;
: phex dup A lit u< if 30 lit + putc else A lit - 41 lit + putc then ;
8 lit 0 lit do i fib phex 20 lit putc loop A lit putc bye
Test {
	fib0 { 0 lit fib 0 lit asrt_eq }
	fib7 { 7 lit fib D lit asrt_eq }
}'

# --- must run ---
runs fib "$FIB" 0 '0 1 1 2 3 5 8 D'
runs leftover '1 lit 2 lit 41 lit putc A lit putc bye' 0 'A'
runs loops '20 lit 0 lit do 20 lit 0 lit do 20 lit 0 lit do loop loop loop 4F lit putc 4B lit putc A lit putc bye' 0 'OK'
suite fib_tests "$FIB" --test 0 '2 passed'
suite failing 'Test { x { 1 lit 2 lit asrt_eq } }' --test 1 'FAILED'
suite defs_in_test 'Test { x { : g 5 lit ; g 5 lit asrt_eq } }' --test 0 '1 passed'
suite bench 'Bench { b { 10 lit 0 lit do loop } }' --bench 0 '1 benches'

# --- must trap: ?trap <mcause>, exit 1 ---
runs rstack_overflow ': r r ;
r bye' 1 '?trap 00000003'
runs underflow_bye 'drop bye' 1 '?trap 00000005'
runs underflow_read '+ bye' 1 '?trap 00000005'
runs underflow_write 'drop drop 5 lit bye' 1 '?trap 00000007'
suite rstack_in_test ': r r ; Test { x { r } }' --test 1 '?trap 00000003'

# --- must not compile ---
no_compile undefined 'nosuchword bye'
no_compile bad_hex 'XYZ lit bye'
no_compile unclosed_paren '( never closed'
no_compile stray_semi '; bye'
no_compile stray_then 'then bye'
no_compile redefined ': a 1 lit ; : a 2 lit ; bye'
no_compile unclosed_def ': foo 1 lit'
no_compile unclosed_imm ':I foo 13000000 ,'
no_compile if_no_then '1 lit if 2 lit drop bye'
no_compile if_no_then_def ': f 1 lit if 2 lit ; bye'
no_compile if_no_then_test 'Test { x { 1 lit if 2 lit drop } }' --test
no_compile begin_alone_test 'Test { x { begin } }' --test

echo "$((N - FAILS)) of $N checks passed"
[ "$FAILS" = 0 ]
