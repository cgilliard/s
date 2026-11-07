#!/bin/sh
# oscheck.sh — the OS's checks (docs/OS.md); run after scripts/build.sh.
#
# The kernel's own tests (the Test blocks in src/ksys.fam) on 1, 2, 8 and
# 64 harts; a fault in the kernel reported rather than hung on; the image
# booting, by itself under q32 and through tabernacle from a disk holding
# it, on one hart and on several, and running init in user mode; and
# programs in user mode that touch the kernel's memory, write their own
# code, or make bad system calls: each ended or refused, the system going
# on; and processes and threads: threads counting under a lock, a child
# spawned and waited for, sleep, await and wake, a process killed with a
# thread running on another hart, and the lottery's shares; memory: map and
# unmap under PMP, malloc and free on four threads; and descriptors, /proc
# and the shell, typed into on the console.  Every run has a time
# limit; one that should keep running (the booted kernel) passes when the
# limit ends it.  And the store: scripts/storetest.sh, and trees from user
# mode on a disk.

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
	expect "kernel_tests_$n" 0 "harts: $n" 120 ./tools/fam --test --smp=$n src/kernel.fam src/store.fam src/ksys.fam
done

# The store's benchmark (scripts/storebench.sh) builds beside the kernel:
# its words and the kernel's share one name space.
N=$((N + 1))
./tools/fam -o "$T/storebench.bin" src/kernel.fam src/store.fam src/ksys.fam src/storebench.fam > "$T/storebench.build" 2>&1 \
	|| fail storebench_build "$(head -c 300 "$T/storebench.build")"

printf 'trapinit 0 lit @ drop bye\n' > "$T/fault.fam"
./tools/fam -o "$T/fault.bin" src/kernel.fam src/store.fam src/ksys.fam "$T/fault.fam" > "$T/fault.build" 2>&1 \
	|| fail fault_build "$(head -c 300 "$T/fault.build")"
expect fault 1 'kernel: hart 0 trap 00000005 at .* (00000000)' 30 ./tools/q32 "$T/fault.bin"

expect boot 124 'init: starting the shell' 3 ./tools/q32 bin/img
grep -q 'kernel: 1 hart, [0-9]* pages free' "$T/boot.out" && grep -q '^\$ $' "$T/boot.out" \
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

# has NAME PATTERN — the output of check NAME matches PATTERN too.
has() { grep -q -- "$2" "$T/$1.out" || fail "$1" "output $(head -c 300 "$T/$1.out"), expected /$2/ too"; }
# usrc NAME SOURCE — a program in user mode: $T/NAME.bin.
usrc() {
	printf '%s\n' "$2" > "$T/$1.fam"
	./tools/fam --user -o "$T/$1.bin" "$T/$1.fam" > "$T/$1.build" 2>&1 || fail "$1" "build: $(head -c 300 "$T/$1.build")"
}
# uimage NAME KERNEL PROG=SRC[:KiB] ... — an image of programs built by usrc.
uimage() {
	img=$1; k=$2; shift 2
	specs=""
	for a in "$@"; do specs="$specs ${a%%=*}=$T/${a#*=}"; done
	specs=$(echo "$specs" | sed 's/=\([^ :]*\)/=\1.bin/g')
	sh scripts/mkimage.sh "$T/$img.img" "$k" $specs 2> "$T/$img.mk" || fail "$img" "mkimage: $(cat "$T/$img.mk")"
}

# Processes and threads (step 5).
usrc tthr ': cnt variable ;  : mtx variable ;  : tc variable ;  : tids variable ;
0 lit cnt !  0 lit mtx !  10 lit alloc tids !
tcode[ 3E8 lit 0 lit do mtx lock cnt @ 1 lit + cnt ! mtx unlock loop 7 lit texit ]tcode tc !
4 lit 0 lit do tc @ 4000 lit alloc 4000 lit + i thread i 2 lit lshift tids @ + ! loop
0 lit 4 lit 0 lit do i 2 lit lshift tids @ + @ join + loop
"joined: " puts u. " count: " puts cnt @ u. 0A lit putc bye'
uimage thr bin/kernel init=tthr:256
for n in 1 4; do expect "threads_$n" 124 'joined: 28 count: 4000' 10 ./tools/q32 --smp=$n "$T/thr.img"; done
usrc tspawn ': st variable ;
"child" spawn dup "spawned " puts u. 0A lit putc
st wait "waited " puts u. " status " puts st @ u. 0A lit putc
"nosuch" spawn "nosuch: " puts . 0A lit putc
FFFFFFFF lit st wait "no child: " puts . 0A lit putc bye'
usrc child '7 lit exit'
uimage spawn bin/kernel init=tspawn child=child
expect spawn_wait 124 'waited 2 status 7' 6 ./tools/q32 --smp=2 "$T/spawn.img"
has spawn_wait 'nosuch: -2'; has spawn_wait 'no child: -10'; has spawn_wait 'kernel: init ended: 0'
usrc tsync ': flag variable ;  0 lit flag !
tcode[ 2FAF080 lit sleep 1 lit flag ! flag 1 lit wake drop ]tcode
4000 lit alloc 4000 lit + 0 lit thread drop
flag 0 lit 0 lit await "await: " puts . " flag " puts flag @ u. 0A lit putc
flag 1 lit 989680 lit await "timed: " puts . 0A lit putc bye'
uimage sync bin/kernel init=tsync:128
for n in 1 4; do expect "sleep_await_$n" 124 'await: 0 flag 1' 6 ./tools/q32 --smp=$n "$T/sync.img"; has "sleep_await_$n" 'timed: -110'; done
usrc tkill 'tcode[ begin 0 lit until ]tcode 4000 lit alloc 4000 lit + 0 lit thread drop
5F5E100 lit sleep 80000000 lit @ drop'
uimage kill bin/kernel init=tkill:128
expect kill_threads 124 'kernel: process killed: trap 00000005' 6 ./tools/q32 --smp=4 "$T/kill.img"
has kill_threads 'kernel: init ended: -1'
# The lottery: two programs spinning, 300 and 100 tickets, on one hart for
# 2 s; their ticks must come out between 2:1 and 4.5:1.
usrc spin 'begin 0 lit until'
printf '%s\n' 'kboot
"spin" 12C lit kspawn drop  "spin" 64 lit kspawn drop
1312D00 lit hrunfor
0 lit thn C4 lit + @  1 lit thn C4 lit + @
"share: " puts over u. " to " puts dup u. 0A lit putc
over over 1 lit lshift u< 0=  2 lit pick 1 lit lshift 2 lit pick 9 lit * u> 0= and
nip nip if 0 lit else 1 lit then halt' > "$T/share.fam"
./tools/fam -o "$T/sharek.bin" src/kernel.fam src/store.fam src/ksys.fam "$T/share.fam" > "$T/share.build" 2>&1 || fail lottery "build: $(head -c 300 "$T/share.build")"
uimage share "$T/sharek.bin" spin=spin
expect lottery 0 'share: ' 20 ./tools/q32 "$T/share.img"

# Memory (step 6): map and unmap under PMP; malloc and free on threads.
usrc tmap ': a variable ;  : b variable ;  : c variable ;  : d variable ;
1000 lit map a !  3000 lit map b !  10000 lit map c !  1 lit map d !
"maps: " puts a @ 0= b @ 0= or c @ 0= or d @ 0= or if "missing" else "four" then puts
" fifth " puts 1 lit map u.
7 lit a @ !  9 lit c @ FFFC lit + !  a @ @ c @ FFFC lit + @ + " sum " puts u.
b @ unmap " again " puts 1 lit map if "yes" else "no" then puts
" bad " puts 12345000 lit 0 lit 0 lit E lit sys . 0A lit putc
c @ unmap  c @ @ drop "not reached" puts bye'
uimage map bin/kernel init=tmap
expect map 124 'maps: four fifth 0 sum 16 again yes bad -22' 4 ./tools/q32 --smp=2 "$T/map.img"
has map 'kernel: process killed: trap 00000005'; has map 'kernel: init ended: -1'
# Four threads, 5,000 steps each, twice: each holds up to 16 blocks of 4
# to 8192 bytes, each filled with its own pattern and checked when freed;
# after each round the heap is whole again (one block, one arena), and a
# block larger than an arena gets one of its own, given back when freed.
usrc tmalloc ': st variable ;  : tc variable ;  : stk variable ;  : bad variable ;
: xs  dup @ dup D lit lshift xor dup 11 lit rshift xor dup 5 lit lshift xor tuck swap ! ;
: tslot  2 lit lshift + 4 lit + ;
: tsize  2 lit lshift + 44 lit + ;
: fill  -rot 2 lit rshift 0 lit do 2dup i 2 lit lshift + ! loop 2drop ;
: chk  -rot 2 lit rshift 1 lit swap 0 lit do over i 2 lit lshift + @ 3 lit pick = and loop nip nip ;
: tfree
2dup tslot @  2 lit pick 2 lit pick tsize @  3 lit pick 3 lit pick + chk 0= if 1 lit bad ! then
2dup tslot @ free
tslot 0 lit swap ! ;
: tnew
dup malloc dup 0= if "null" puts 0A lit putc 1 lit exit then
2dup swap 5 lit pick 5 lit pick + fill
3 lit pick 3 lit pick tslot !
-rot tsize ! ;
: step
dup xs dup F lit and
2 lit pick over tslot @ if nip tfree else swap 8 lit rshift 1FFC lit and 4 lit + tnew then ;
: heap
0 lit 0 lit freelist @ begin ?dup while dup @ rot + swap rot 1 lit + -rot 4 lit + @ repeat
swap "blocks " puts u. " free " puts u. " mapped " puts mbytes @ u. ;
tcode[
	8 lit lshift st @ + dup 9E3779B9 lit xor over !
	1388 lit 0 lit do dup step loop
	10 lit 0 lit do dup i tslot @ if dup i tfree then loop
	drop 0 lit texit
]tcode tc !
400 lit alloc st !  20000 lit alloc stk !  0 lit bad !
2 lit 0 lit do
	4 lit 0 lit do tc @ stk @ i 1 lit + F lit lshift + i thread loop
	4 lit 0 lit do join drop loop
	"round " puts i u. ": " puts heap 0A lit putc
loop
32000 lit malloc "big: " puts heap 0A lit putc free "after: " puts heap 0A lit putc
bad @ if "corrupt" else "intact" then puts 0A lit putc bye'
uimage malloc bin/kernel init=tmalloc:512
for n in 1 4; do
	expect "malloc_$n" 124 '^intact$' 10 ./tools/q32 --smp=$n "$T/malloc.img"
	for r in 'round 0' 'round 1' 'after'; do has "malloc_$n" "^$r: blocks 1 free \([0-9]*\) mapped \1\$"; done
	has "malloc_$n" '^big: blocks 2 '
done

# Descriptors, the console, init and a shell (step 7).  Calls: poll timing
# out, then readable, then hung up; a pipe read to its end; the errors; 16
# descriptors at most; a child killed through /proc/<pid>/kill.
usrc tdesc ': pf variable ;  : ent variable ;  : b variable ;  : st variable ;  : fds variable ;  : path variable ;
: sp  20 lit putc ;
8 lit alloc pf !  8 lit alloc ent !  10 lit alloc b !  10 lit alloc fds !  20 lit alloc path !
pf @ pipe "pipe " puts . sp
pf @ @ ent @ !  1 lit ent @ 4 lit + !
ent @ 1 lit 2FAF080 lit poll "idle " puts . sp
pf @ 4 lit + @ "x" 1 lit write drop
ent @ 1 lit 0 lit poll "ready " puts . sp ent @ 6 lit + h@ u. sp
pf @ 4 lit + @ close drop
pf @ @ b @ 10 lit read "read " puts . sp
pf @ @ b @ 10 lit read "eof " puts . sp
ent @ 1 lit 0 lit poll "hup " puts . sp ent @ 6 lit + h@ u. 0A lit putc
"/nosuch" 0 lit open "open " puts . sp
9 lit b @ 1 lit read "badfd " puts . sp
"/proc/1/status" 1 lit open "ro " puts . sp
"/proc/99/status" 0 lit open "nopid " puts . sp
0 lit 10 lit 0 lit do "/dev/null" 0 lit open 0< if 1 lit + then loop "full " puts . 0A lit putc
10 lit 3 lit do i close drop loop
pf @ pipe drop
2 lit fds @ !  pf @ @ fds @ 4 lit + !  FFFFFFFF lit fds @ 8 lit + !
"cat" 0 lit fds @ spawnv
pf @ @ close drop
path @ "/proc/" scpy over snum "/kill" scpy 0 lit swap c!
path @ 1 lit open dup "1" 1 lit write drop close drop
st wait drop "killed " puts st @ . 0A lit putc bye'
sh scripts/mkimage.sh "$T/desc.img" bin/kernel init="$T/tdesc.bin" cat=bin/user/cat 2> "$T/desc.mk" || fail desc "mkimage: $(cat "$T/desc.mk")"
expect desc 124 '^pipe 0 idle -110 ready 1 1 read 1 eof 0 hup 1 17$' 5 ./tools/q32 --smp=2 "$T/desc.img"
has desc '^open -2 badfd -9 ro -13 nopid -2 full 4$'; has desc '^killed -9$'
# The shell from the console: the image's programs and one writing 100 KiB,
# commands typed a line at a time, on one hart and on four.
usrc big ': buf variable ;
400 lit alloc buf !  400 lit 0 lit do 61 lit buf @ i + c! loop  A lit buf @ 3FF lit + c!
64 lit 0 lit do 1 lit buf @ 400 lit write drop loop bye'
progs=""; for p in bin/user/*; do progs="$progs $(basename "$p")=$p"; done
sh scripts/mkimage.sh "$T/shell.img" bin/kernel $progs big="$T/big.bin" 2> "$T/shell.mk" || fail shell "mkimage: $(cat "$T/shell.mk")"
printf '%s\n' 'echo hello world' 'ps' 'echo one two three | wc' 'big | cat | wc' 'cat /proc/self/cmd' \
	'echo 7 > /proc/2/tickets' 'cat < /proc/2/tickets' 'nosuch' 'a |' 'exit' > "$T/shell.in"
# feed SECS FILE CMD... — CMD run with FILE's lines typed into it, 0.3 s
# apart, 3 s after one running big (typed ahead, a line is echoed among the
# output).
feed() {
	secs=$1; in=$2; shift 2
	lim "$secs" sh -c 'in=$1; shift; { sleep 1; while IFS= read -r l; do printf "%s\n" "$l"; sleep 0.3; case $l in big*) sleep 3 ;; esac; done < "$in"; sleep 3; } | "$@"' feed "$in" "$@"
}
for n in 1 4; do
	N=$((N + 1)); o="$T/shell_$n.out"
	feed 14 "$T/shell.in" ./tools/q32 --smp=$n "$T/shell.img" > "$o" 2>&1
	for pat in '^hello world$' '^PID PPID S THR KIB TICKS CMD$' '^1 0 S 1 64 [0-9]* init$' '^2 1 S 1 64 [0-9]* sh$' \
		'^3 2 R 1 64 [0-9]* ps$' '^1 3 14$' '^100 100 102400$' '^cat /proc/self/cmd$' '^7$' \
		'^sh: nosuch: not found$' '^sh: a command is missing$' '^init: the shell ended; again$'; do
		grep -q -- "$pat" "$o" || { fail "shell_$n" "no /$pat/ in: $(head -c 600 "$o")"; break; }
	done
done

# The store (step 8): its own checks on a bare machine (a new store, the
# same found again, QEMU killed in its commits six times and the last
# commit found whole); then trees from user mode on a disk, on one hart
# and then on four: a counter that outlives the reboot between, a long
# transaction in one tree while twenty commit in another, the calls' errors.
N=$((N + 1))
lim 900 sh scripts/storetest.sh > "$T/storetest.out" 2>&1 || fail storetest "$(tail -c 400 "$T/storetest.out")"
grep -q 'storetest: the last commit whole is' "$T/storetest.out" || fail storetest "no crash rounds: $(tail -c 400 "$T/storetest.out")"
usrc tstore ': fda variable ;  : fdb variable ;  : fdc variable ;  : b variable ;  : v variable ;
: bigdone variable ;  : smalls variable ;  : early variable ;  : stk variable ;
: chk  dup 0< if "error " puts . 0A lit putc 1 lit exit then ;      \ ( r -- r )
200 lit alloc b !  200 lit alloc v !  0 lit bigdone !  0 lit smalls !  0 lit early !
\ a counter that outlives a reboot
"/t-count" TREE CREATE or 2 lit or open chk fda !
fda @ 1 lit txbegin chk
dup "n" 1 lit b @ 4 lit txget 4 lit = if b @ @ else 0 lit then 1 lit + dup "count " puts u. 0A lit putc
b @ !  dup "n" 1 lit b @ 4 lit txput chk drop  txcommit chk drop
\ a long transaction on one tree while short ones commit on another
"/t-big" TREE CREATE or 2 lit or open chk fdb !
"/t-small" TREE CREATE or 2 lit or open chk fdc !
tcode[
	drop fdb @ 1 lit txbegin chk
	BB8 lit 0 lit do
		i v @ !  dup v @ 4 lit v @ 1F4 lit txput chk drop
	loop
	txcommit chk drop  1 lit bigdone !
]tcode
8000 lit alloc 8000 lit + 0 lit thread stk !
2FAF080 lit sleep
14 lit 0 lit do
	fdc @ 1 lit txbegin chk
	i b @ !  dup b @ 4 lit b @ 4 lit txput chk drop  txcommit chk drop
	smalls @ 1 lit + smalls !
	bigdone @ 0= if early @ 1 lit + early ! then
loop
stk @ join drop
"small commits " puts smalls @ u. ", while the long one was open " puts early @ u. 0A lit putc
\ the long one whole, in a reader
fdb @ 0 lit txbegin chk stk !
0 lit BB8 lit 0 lit do i v @ ! stk @ v @ 4 lit b @ 1F4 lit txget 1F4 lit = if b @ @ i = if 1 lit + then then loop
"long keys whole " puts u. 0A lit putc stk @ txcommit drop
\ errors, and a walk with next
"errors " puts
"/t-big" 0 lit open . 20 lit putc
"/nope" TREE open . 20 lit putc
1 lit 0 lit txbegin . 20 lit putc
fdc @ 0 lit txbegin dup stk !  "k" 1 lit "v" 1 lit txput . 20 lit putc
stk @ "absent" 6 lit b @ 10 lit txget . 20 lit putc
0 lit 0 lit begin stk @ b @ 2 lit pick b @ txnext dup 0< 0= while nip swap 1 lit + swap repeat drop drop
"next " puts u. 0A lit putc  stk @ txcommit drop
bye'
uimage store bin/kernel init=tstore
rm -f "$T/store.disk"; dd if=/dev/zero of="$T/store.disk" bs=1 count=0 seek=268435456 2>/dev/null
for n in 1 4; do
	expect "store_$n" 124 '^small commits 20, while the long one was open 20$' 30 ./tools/q32 --smp=$n --disk="$T/store.disk" "$T/store.img"
	has "store_$n" '^long keys whole 3000$'; has "store_$n" '^errors -22 -2 -9 -9 -2 next 20$'
done
has store_1 '^count 1$'; has store_4 '^count 2$'
rm -f "$T/store.disk"

# Files (step 8, part 4): 100,000 bytes written and read back, seek, a
# write in the middle, appending, the errors, on one hart and on four;
# then the shell on a disk booted twice, a file it wrote read back after.
usrc tfile ': buf variable ;  : fd variable ;  : ok variable ;  : tot variable ;  : base variable ;
: sp  20 lit putc ;
: pat   dup 5 lit rshift + FF lit and ;                                   \ ( i -- byte ) byte i of the file
: fill  0 lit do dup i + pat buf @ i + c! loop drop ;                     \ ( base n -- )
: vfy   -rot 0 lit do dup i + pat 2 lit pick buf @ + i + c@ <> if 0 lit ok ! then loop 2drop ;   \ ( base n off -- )
1000 lit alloc buf !  1 lit ok !  0 lit base !
\ 100,000 bytes written 1000 at a time, read back 777 at a time
"/big" 601 lit open fd !
64 lit 0 lit do base @ 3E8 lit fill fd @ buf @ 3E8 lit write drop base @ 3E8 lit + base ! loop
fd @ close drop
"/big" 0 lit open fd !  0 lit tot !
begin fd @ buf @ 309 lit read dup 0< 0= over and while tot @ over 0 lit vfy tot @ + tot ! repeat drop
"read " puts tot @ u. " whole " puts ok @ u. sp
\ the end, by seek
fd @ FFFFFFF6 lit 2 lit seek u. sp
fd @ buf @ A lit read u. sp  1 lit ok !  18696 lit A lit 0 lit vfy ok @ u. 0A lit putc
fd @ close drop
\ 3000 bytes of AA written at 5000, read back with what is on each side
"/big" 2 lit open fd !  fd @ 1388 lit 0 lit seek drop
BB8 lit 0 lit do AA lit buf @ i + c! loop  "mid " puts fd @ buf @ BB8 lit write u. sp
fd @ 0 lit 2 lit seek u. sp
fd @ 1384 lit 0 lit seek drop  fd @ buf @ BC0 lit read u. sp
1 lit ok !  1384 lit 4 lit 0 lit vfy  1F40 lit 4 lit BBC lit vfy
BB8 lit 0 lit do buf @ i 4 lit + + c@ AA lit <> if 0 lit ok ! then loop
ok @ u. 0A lit putc  fd @ close drop
\ appending
"/big" A01 lit open fd !  fd @ "tail" 4 lit write drop  fd @ 0 lit 1 lit seek u. sp fd @ close drop
\ the errors
"errors " puts
"/" 1 lit open . sp  "/" mkdir . sp  "/x/y" mkdir . sp  "/" remove . sp  "/nope" 0 lit open . sp
"/d" mkdir . sp  "/d/f" 601 lit open close drop  "/d" remove . sp  "/d/f" remove . sp  "/d" remove . sp
"/big" remove . sp  "/big" 0 lit open . 0A lit putc
bye'
uimage files bin/kernel init=tfile
rm -f "$T/files.disk"; dd if=/dev/zero of="$T/files.disk" bs=1 count=0 seek=268435456 2>/dev/null
for n in 1 4; do
	expect "files_$n" 124 '^read 100000 whole 1 99990 10 1$' 20 ./tools/q32 --smp=$n --disk="$T/files.disk" "$T/files.img"
	has "files_$n" '^mid 3000 100000 3008 1$'; has "files_$n" '^100004 errors -21 -17 -2 -16 -2 0 -39 0 0 0 -2$'
done
printf '%s\n' 'mkdir /home' 'cd /home' 'echo hello files > notes' 'echo a second line >> notes' 'ls /' 'pwd' > "$T/fs1.in"
printf '%s\n' 'cat /home/notes' 'cd /home' 'wc < notes' 'rm notes' 'ls' 'cat notes' > "$T/fs2.in"
N=$((N + 1))
feed 12 "$T/fs1.in" ./tools/q32 --disk="$T/files.disk" bin/img > "$T/fs1.out" 2>&1
feed 12 "$T/fs2.in" ./tools/q32 --disk="$T/files.disk" bin/img > "$T/fs2.out" 2>&1
for pat in '^home/$' '^/home$'; do grep -q -- "$pat" "$T/fs1.out" || fail fs_boot1 "no /$pat/ in: $(head -c 600 "$T/fs1.out")"; done
for pat in '^hello files$' '^a second line$' '^2 5 26$' '^cat: cannot open notes$'; do grep -q -- "$pat" "$T/fs2.out" || fail fs_boot2 "no /$pat/ in: $(head -c 600 "$T/fs2.out")"; done
rm -f "$T/files.disk"

# Users (step 8, part 5): a disk booted twice.  First as root (no
# /etc/init yet): /etc/passwd and /etc/init written, a home for alice
# hers alone.  Then init runs login: a wrong password refused; alice in,
# her user and home, her file, root's file and the root directory closed
# to her; root in after her, everything open to it.
printf '%s\n' 'mkdir /etc' 'echo root:rootpw:0:0:/:sh > /etc/passwd' 'echo alice:apw:1:1:/home/alice:sh >> /etc/passwd' \
	'chmod 600 /etc/passwd' 'mkdir /home' 'mkdir /home/alice' 'chown 1 1 /home/alice' 'chmod 700 /home/alice' \
	'echo restart 0 100 login > /etc/init' 'id' 'ls /etc' > "$T/u1.in"
printf '%s\n' 'alice' 'wrong' 'alice' 'apw' 'id' 'pwd' 'echo mine > f' 'cat f' 'cat /etc/passwd' 'mkdir /tmp2' 'ls /home' \
	'exit' 'root' 'rootpw' 'id' 'cat /etc/passwd' 'ls /home/alice' > "$T/u2.in"
rm -f "$T/users.disk"; dd if=/dev/zero of="$T/users.disk" bs=1 count=0 seek=268435456 2>/dev/null
N=$((N + 1))
feed 15 "$T/u1.in" ./tools/q32 --disk="$T/users.disk" bin/img > "$T/u1.out" 2>&1
feed 18 "$T/u2.in" ./tools/q32 --disk="$T/users.disk" bin/img > "$T/u2.out" 2>&1
for pat in '^0 0$' '^init$' '^passwd$'; do grep -q -- "$pat" "$T/u1.out" || fail users_boot1 "no /$pat/ in: $(head -c 800 "$T/u1.out")"; done
for pat in '^init: /etc/init: 1 programs$' '^login incorrect$' '^1 1$' '^/home/alice$' '^mine$' '^cat: cannot open /etc/passwd$' \
	'^mkdir: cannot make /tmp2: -13$' '^alice/$' '^root:rootpw:0:0:/:sh$' '^f$'; do
	grep -q -- "$pat" "$T/u2.out" || fail users_boot2 "no /$pat/ in: $(head -c 900 "$T/u2.out")"
done
[ "$(grep -c '0 0$' "$T/u2.out")" = 1 ] || fail users_boot2 "root's id not once after alice's: $(head -c 900 "$T/u2.out")"
rm -f "$T/users.disk"

scripts/makenode.sh --disk="$T/disk.img" > /dev/null
expect boot_disk 124 'tabernacle: from disk' 5 scripts/node.sh --disk="$T/disk.img" --no-seeds
grep -q 'init: starting the shell' "$T/boot_disk.out" \
	|| fail boot_disk "no init: $(head -c 300 "$T/boot_disk.out")"
expect boot_disk_64 124 'kernel: 64 harts' 15 scripts/node.sh --disk="$T/disk.img" --no-seeds --smp=64
rm -f "$T/disk.img"

echo "$((N - FAILS)) of $N checks passed"
[ "$FAILS" = 0 ]
