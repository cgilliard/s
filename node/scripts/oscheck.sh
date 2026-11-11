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
# No check has a deadline: each time limit below is an idle window,
# pushed back whenever anything under $T changes (the checks' output, the
# guests' disks, which the store writes), so a slower machine only takes
# longer and a stuck check still ends.  WPROG: prog(), a sum of the times
# and sizes of everything under $WT.
WPROG='use File::Find; sub prog { my $s = 0; find(sub { my @st = lstat($_); $s += $st[9] + $st[7] if @st }, $ENV{WT}); return $s }'
lim() {
	WT="$T" perl -e "$WPROG"'
		$t = shift;
		$p = fork // die "fork: $!";
		if (!$p) { setpgrp(0, 0); exec @ARGV or die "exec: $!" }
		$last = prog(); $end = time + $t; $scan = time + 2;
		while (waitpid($p, 1) == 0) {
			if (time >= $end) { kill "KILL", -$p; waitpid($p, 0); exit 124 }
			select(undef, undef, undef, 0.25);
			if (time >= $scan) { $scan = time + 2; $n = prog(); if ($n != $last) { $last = $n; $end = time + $t } }
		}
		exit($? & 127 ? 128 + ($? & 127) : $? >> 8);
	' "$@" < /dev/null
}

# upto SECS CMD... — as lim, but a machine running a test program as init
# is stopped as soon as the kernel says init ended, the whole line (nothing
# follows it):
# exit 124 then, as if the time ran out, so a slow machine only takes
# longer, and a fast one doesn't wait out SECS.
upto() {
	WT="$T" perl -e "$WPROG"'
		$t = shift;
		pipe(R, W) or die "pipe: $!";
		$p = fork // die "fork: $!";
		if (!$p) { close R; setpgrp(0, 0); open STDOUT, ">&W"; open STDERR, ">&W"; exec @ARGV or die "exec: $!" }
		close W;
		$end = time + $t; $buf = ""; $rin = ""; vec($rin, fileno(R), 1) = 1; $eof = 0;
		$last = prog(); $scan = time + 2;
		while (time < $end) {
			if (time >= $scan) { $scan = time + 2; $g = prog(); if ($g != $last) { $last = $g; $end = time + $t } }
			if (select($rout = $rin, undef, undef, 0.25)) {
				$n = sysread(R, $d, 65536);
				if (!$n) { $eof = 1; last }
				syswrite(STDOUT, $d); $buf .= $d;  $end = time + $t;
				if ($buf =~ /^kernel: init ended: \S+\r?\n/m) { kill "KILL", -$p; waitpid($p, 0); exit 124 }
			}
		}
		if (!$eof) { kill "KILL", -$p; waitpid($p, 0); exit 124 }
		waitpid($p, 0);
		exit($? & 127 ? 128 + ($? & 127) : $? >> 8);
	' "$@" < /dev/null
}
fail() { echo "FAIL $1: $2"; FAILS=$((FAILS + 1)); }
# served FILE NAME — waits until a host server started in the background
# has written "ready" to FILE (bound, and listening): a guest's first
# packet to it is otherwise lost to the race.  30 s at most.
served() {
	i=0
	until grep -q ready "$1" 2>/dev/null; do
		i=$((i + 1)); [ "$i" -gt 300 ] && { fail "$2" "the host's echo server did not start"; return; }
		sleep 0.1
	done
}
# boots NAME REGEX SECS CMD... — CMD run (its own process group, stdin
# /dev/null) until its output matches REGEX (Perl's, multi-line), then
# stopped; or after SECS with nothing new under $T.  Fails if it never
# matched.
boots() {
	name=$1; pat=$2; secs=$3; shift 3
	N=$((N + 1))
	WT="$T" perl -e "$WPROG"'
		($f, $pat, $t) = splice(@ARGV, 0, 3);
		$p = fork // die "fork: $!";
		if (!$p) {
			setpgrp(0, 0);
			open STDIN, "<", "/dev/null"; open STDOUT, ">", $f; open STDERR, ">&STDOUT";
			exec @ARGV or die "exec: $!";
		}
		$end = time + $t; $last = prog(); $scan = time + 2;
		while (time < $end) {
			select(undef, undef, undef, 0.25);
			if (time >= $scan) { $scan = time + 2; $g = prog(); if ($g != $last) { $last = $g; $end = time + $t } }
			open F, "<", $f; local $/; $c = <F>; close F;
			last if $c =~ /$pat/m;
			last if waitpid($p, 1) > 0;
		}
		kill "KILL", -$p; waitpid($p, 0);
	' "$T/$name.out" "$pat" "$secs" "$@"
	perl -e 'local $/; $c = <STDIN>; exit($c =~ /$ARGV[0]/m ? 0 : 1)' "$pat" < "$T/$name.out" \
		|| fail "$name" "no /$pat/, nothing new for $secs s: $(head -c 300 "$T/$name.out")"
}

# expect NAME EXIT PATTERN SECONDS CMD... — CMD exits EXIT and its output
# matches PATTERN.  124: ended for it, when its guest's init ended, or
# after six times SECONDS with nothing new under $T (the guest idle).
expect() {
	name=$1; want=$2; pat=$3; secs=$4; shift 4
	N=$((N + 1))
	if [ "$want" = 124 ]; then upto "$((secs * 6))" "$@" > "$T/$name.out" 2>&1; rc=$?
	else lim "$secs" "$@" > "$T/$name.out" 2>&1; rc=$?; fi
	[ "$rc" = "$want" ] || { fail "$name" "exit $rc, expected $want: $(head -c 300 "$T/$name.out")"; return; }
	grep -q -- "$pat" "$T/$name.out" || fail "$name" "output $(head -c 300 "$T/$name.out"), expected /$pat/"
}

# has NAME PATTERN — the output of check NAME matches PATTERN too.
has() { grep -q -- "$2" "$T/$1.out" || fail "$1" "output $(head -c 300 "$T/$1.out"), expected /$2/ too"; }

[ -f bin/img ] && [ -f bin/tabernacle ] || { echo "oscheck.sh: run scripts/build.sh first" >&2; exit 1; }

for n in 1 2 8 64; do
	expect "kernel_tests_$n" 0 "harts: $n" 600 ./tools/fam --test --smp=$n src/kernel.fam src/store.fam src/net.fam src/ksys.fam
done

# The node's arithmetic and Poseidon2 (docs/NODE.md, steps 1 and 2), and
# targets, ASERT and work (step 4), against tabminer's values.
expect arith 0 '7 passed' 120 ./tools/fam --test src/user/node/arith.fam src/user/node/arith_vectors.fam
expect poseidon2 0 '3 passed' 120 ./tools/fam --test src/user/node/arith.fam src/user/node/poseidon2.fam src/user/node/poseidon2_vectors.fam
expect difficulty 0 '3 passed' 120 ./tools/fam --test src/user/node/arith.fam src/user/node/difficulty.fam src/user/node/difficulty_vectors.fam
# The chain proof's verifier (step 3), a program for the OS: tabminer's
# compiled verifier (/lib/chainver) on a real mainnet chain proof
# (/lib/chainproof), accepted, then refused with a byte changed at 24 places
# and with another output.
ND=src/user/node
./tools/fam --user -o "$T/tcv.bin" $ND/arith.fam $ND/poseidon2.fam $ND/chainver.fam $ND/chainver_test.fam > "$T/tcv.build" 2>&1 || fail chainver "build: $(head -c 300 "$T/tcv.build")"
sh scripts/mkimage.sh "$T/cv.img" bin/kernel init="$T/tcv.bin":8192 chainver=$ND/chainver.bin:0 chainproof=$ND/chainproof.bin:0 2> "$T/cv.mk" || fail chainver "mkimage: $(cat "$T/cv.mk")"
expect chainver 124 'refused with another output' 60 ./tools/q32 "$T/cv.img"
has chainver '^accepted'; has chainver '^refused 24 of 24 changed'
# The proof of work (step 4), a program for the OS with the seed file
# (/lib/akjv.txt.gz): windows, items, hashimoto, a header's hashes and its
# proof of work, against tabminer's values.
printf '"pow: " puts vpass @ u. " passed, " puts vfail @ u. " failed" puts 0A lit putc\nbye\n' > "$T/pow_tail.fam"
./tools/fam --user -o "$T/tpow.bin" $ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/pow_test.fam $ND/pow_vectors.fam "$T/pow_tail.fam" > "$T/tpow.build" 2>&1 || fail pow "build: $(head -c 300 "$T/tpow.build")"
sh scripts/mkimage.sh "$T/pow.img" bin/kernel init="$T/tpow.bin":4096 akjv.txt.gz=../resources/akjv.txt.gz:0 2> "$T/pow.mk" || fail pow "mkimage: $(cat "$T/pow.mk")"
expect pow 124 '^pow: 43 passed, 0 failed' 60 ./tools/q32 "$T/pow.img"
# Headers (step 4): a dev network's header chain, each verdict tabminer's
# Chain::accept_headers gave, fork choice by work, every rule refused.
printf '"headers: " puts vpass @ u. " passed, " puts vfail @ u. " failed" puts 0A lit putc\nbye\n' > "$T/hdr_tail.fam"
./tools/fam --user -o "$T/thdr.bin" $ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/headers.fam $ND/headers_test.fam $ND/headers_vectors.fam "$T/hdr_tail.fam" > "$T/thdr.build" 2>&1 || fail headers "build: $(head -c 300 "$T/thdr.build")"
sh scripts/mkimage.sh "$T/hdr.img" bin/kernel init="$T/thdr.bin":4096 akjv.txt.gz=../resources/akjv.txt.gz:0 2> "$T/hdr.mk" || fail headers "mkimage: $(cat "$T/hdr.mk")"
expect headers 124 '^headers: 25 passed, 0 failed' 120 ./tools/q32 "$T/hdr.img"
# The state (step 5), a program for the OS with a disk: a dev chain's
# blocks (/lib/statechain), each verdict and state root tabminer's; every
# block disconnected to genesis, each root its parent's; all connected again.
# Then (step 10) the snapshot after its block 150 as the node serves it,
# its manifest and every part, against tabminer's (/lib/statesnap).  And the
# same chain from just below 2^32 (statechain40.bin, the counter given as
# /lib/statefirst: miner/src/fam_vectors.rs's FIRST40), its positions
# crossing it: every verdict, root and undo as tabminer's.
./tools/fam --user -o "$T/tst.bin" $ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/headers.fam $ND/chainver.fam $ND/state.fam $ND/proofs.fam $ND/manifest.fam $ND/connect.fam $ND/query.fam $ND/serve.fam $ND/state_test.fam > "$T/tst.build" 2>&1 || fail state "build: $(head -c 300 "$T/tst.build")"
sh scripts/mkimage.sh "$T/st.img" bin/kernel init="$T/tst.bin":8192 statechain=$ND/statechain.bin:0 statesnap=$ND/statesnap.bin:0 2> "$T/st.mk" || fail state "mkimage: $(cat "$T/st.mk")"
rm -f "$T/st.disk"; dd if=/dev/zero of="$T/st.disk" bs=1 count=0 seek=268435456 2>/dev/null
expect state 124 '^connected again: 302 right, 0 wrong' 180 ./tools/q32 --disk="$T/st.disk" "$T/st.img"
has state '^connected: 312 as tabminer, 0 not'; has state '^disconnected: 302 roots right, 0 wrong'
has state '^served: [1-9][0-9]* as tabminer, 0 not'
printf '\350\377\377\377\000\000\000\000' > "$T/first40"
sh scripts/mkimage.sh "$T/st40.img" bin/kernel init="$T/tst.bin":8192 statechain=$ND/statechain40.bin:0 statefirst="$T/first40":0 2> "$T/st40.mk" || fail state40 "mkimage: $(cat "$T/st40.mk")"
rm -f "$T/st.disk"; dd if=/dev/zero of="$T/st.disk" bs=1 count=0 seek=268435456 2>/dev/null
expect state40 124 '^connected again: 302 right, 0 wrong' 180 ./tools/q32 --disk="$T/st.disk" "$T/st40.img"
has state40 '^connected: 312 as tabminer, 0 not'; has state40 '^disconnected: 302 roots right, 0 wrong'
rm -f "$T/st.disk"
# Chain proofs (step 6): the recursive dev network's first blocks, from a
# tabminer that mined them (/lib/devchain), each proof checked against the
# statement the node makes of its block; a block with a changed proof is
# refused for its body commitment, and with a header committing to it, for
# its proof.
./tools/fam --user -o "$T/tpr.bin" $ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/chainver.fam $ND/state.fam $ND/proofs.fam $ND/manifest.fam $ND/connect.fam $ND/proofs_test.fam > "$T/tpr.build" 2>&1 || fail proofs "build: $(head -c 300 "$T/tpr.build")"
sh scripts/mkimage.sh "$T/pr.img" bin/kernel init="$T/tpr.bin":16384 akjv.txt.gz=../resources/akjv.txt.gz:0 chainver=$ND/chainver_dev.bin:0 devchain=$ND/devchain.bin:0 2> "$T/pr.mk" || fail proofs "mkimage: $(cat "$T/pr.mk")"
rm -f "$T/pr.disk"; dd if=/dev/zero of="$T/pr.disk" bs=1 count=0 seek=268435456 2>/dev/null
expect proofs 124 '^proofs: 8 as expected, 0 not' 120 ./tools/q32 --disk="$T/pr.disk" "$T/pr.img"
rm -f "$T/pr.disk"
# A snapshot (step 6): the state after block 150 of the state test's chain
# as tabminer serves it (/lib/statesnap): a changed manifest, a changed part
# and finishing early refused; installed with the block's state root; then
# the chain's later blocks, every root right.
./tools/fam --user -o "$T/tsn.bin" $ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/chainver.fam $ND/state.fam $ND/proofs.fam $ND/manifest.fam $ND/connect.fam $ND/snap.fam $ND/snap_test.fam > "$T/tsn.build" 2>&1 || fail snap "build: $(head -c 300 "$T/tsn.build")"
sh scripts/mkimage.sh "$T/sn.img" bin/kernel init="$T/tsn.bin":16384 statesnap=$ND/statesnap.bin:0 statechain=$ND/statechain.bin:0 2> "$T/sn.mk" || fail snap "mkimage: $(cat "$T/sn.mk")"
rm -f "$T/sn.disk"; dd if=/dev/zero of="$T/sn.disk" bs=1 count=0 seek=268435456 2>/dev/null
expect snap 124 '^after it: 152 connected, 0 not' 120 ./tools/q32 --disk="$T/sn.disk" "$T/sn.img"
has snap '^snapshot: 9 as expected, 0 not'
rm -f "$T/sn.disk"
# The manifests' output parts (manifest.fam): 34,000 outputs put straight
# into the store, parts split, merged and emptied; each block's manifest,
# made from its parent's, the same as one made from the outputs alone; one
# rebuilt from the last kept whole and the changes since.
./tools/fam --user -o "$T/tmf.bin" $ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/chainver.fam $ND/state.fam $ND/proofs.fam $ND/manifest.fam $ND/connect.fam $ND/manifest_test.fam > "$T/tmf.build" 2>&1 || fail manifest "build: $(head -c 300 "$T/tmf.build")"
sh scripts/mkimage.sh "$T/mf.img" bin/kernel init="$T/tmf.bin":8192 2> "$T/mf.mk" || fail manifest "mkimage: $(cat "$T/mf.mk")"
rm -f "$T/mf.disk"; dd if=/dev/zero of="$T/mf.disk" bs=1 count=0 seek=268435456 2>/dev/null
expect manifest 124 '^manifest: [0-9]* as expected, 0 not' 120 ./tools/q32 --disk="$T/mf.disk" "$T/mf.img"
rm -f "$T/mf.disk"
# The pool (step 7): a dev chain whose outputs pay known keys (/lib/pool),
# transactions offered with tabminer's pool's verdict on each and their
# ids, policy inputs through each kind of leaf, blocks mining some and the
# pool after each; proofs of outputs and names (step 8) as tabminer's; and
# XMSS signatures of
# other heights, verified and refused.
./tools/fam --user -o "$T/tpo.bin" $ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/headers.fam $ND/chainver.fam $ND/state.fam $ND/proofs.fam $ND/manifest.fam $ND/connect.fam $ND/query.fam $ND/xmss.fam $ND/tx.fam $ND/pool.fam $ND/pool_test.fam > "$T/tpo.build" 2>&1 || fail pool "build: $(head -c 300 "$T/tpo.build")"
sh scripts/mkimage.sh "$T/po.img" bin/kernel init="$T/tpo.bin":16384 pool=$ND/pool.bin:0 2> "$T/po.mk" || fail pool "mkimage: $(cat "$T/po.mk")"
rm -f "$T/po.disk"; dd if=/dev/zero of="$T/po.disk" bs=1 count=0 seek=268435456 2>/dev/null
expect pool 124 '^pool: 102 as tabminer, 0 not' 120 ./tools/q32 --disk="$T/po.disk" "$T/po.img"
rm -f "$T/po.disk"
# The pool's fee estimates (pool.fam's qest, qsugg, qrate), as tabminer's
# estimates_follow_what_confirmed has them (fees_test.fam).
./tools/fam --user -o "$T/tfe.bin" $ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/headers.fam $ND/chainver.fam $ND/state.fam $ND/proofs.fam $ND/manifest.fam $ND/connect.fam $ND/query.fam $ND/serve.fam $ND/snap.fam $ND/xmss.fam $ND/tx.fam $ND/pool.fam $ND/fees_test.fam > "$T/tfe.build" 2>&1 || fail fees "build: $(head -c 300 "$T/tfe.build")"
sh scripts/mkimage.sh "$T/fe.img" bin/kernel init="$T/tfe.bin":8192 2> "$T/fe.mk" || fail fees "mkimage: $(cat "$T/fe.mk")"
expect fees 124 '^fees: 11 as expected, 0 not' 60 ./tools/q32 "$T/fe.img"
# XMSS signing (docs/GUI_WALLET.md, phase 1): keys from seeds and signatures
# at several leaves, as tabminer's (/lib/xsign), each verified with xverify.
./tools/fam --user -o "$T/txs.bin" $ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/state.fam $ND/xmss.fam $ND/xsign.fam $ND/xsign_test.fam > "$T/txs.build" 2>&1 || fail xsign "build: $(head -c 300 "$T/txs.build")"
sh scripts/mkimage.sh "$T/xs.img" bin/kernel init="$T/txs.bin":8192 xsign=$ND/xsign_vectors.bin:0 2> "$T/xs.mk" || fail xsign "mkimage: $(cat "$T/xs.mk")"
expect xsign 124 '^xsign: 28 as expected, 0 not' 60 ./tools/q32 "$T/xs.img"
# A wallet's keys and memos (wkeys.fam): from a phrase, the master, the
# identities (Dilithium seed, id, tab1 address) and outputs (key seed,
# memo, public key, commitment; memos recognised, strangers' not), as a
# tabminer wallet restored from the same phrase.
./tools/fam --user -o "$T/twk.bin" src/user/crypto/sha512.fam src/user/crypto/sha256.fam src/user/crypto/bip39.fam src/user/crypto/keccak.fam src/user/crypto/dilithium.fam \
	$ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/state.fam $ND/xmss.fam $ND/xsign.fam $ND/wkeys.fam $ND/wkeys_test.fam > "$T/twk.build" 2>&1 || fail wkeys "build: $(head -c 300 "$T/twk.build")"
sh scripts/mkimage.sh "$T/wk.img" bin/kernel init="$T/twk.bin":8192 bip39=../resources/bip39-english.txt:0 wkeys=$ND/wkeys_vectors.bin:0 2> "$T/wk.mk" || fail wkeys "mkimage: $(cat "$T/wk.mk")"
expect wkeys 124 '^wkeys: 35 as expected, 0 not' 60 ./tools/q32 "$T/wk.img"
# Slates and transactions (wslate.fam): a payment as tabminer makes it, the
# stage-1 slate, the answer and its receipt, the body hash, the signed
# transaction and a sender tag byte for byte; finalize's checks.
./tools/fam --user -o "$T/tws.bin" src/user/crypto/keccak.fam src/user/crypto/dilithium.fam \
	$ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/state.fam $ND/xmss.fam $ND/xsign.fam $ND/wkeys.fam $ND/wslate.fam $ND/wslate_test.fam > "$T/tws.build" 2>&1 || fail wslate "build: $(head -c 300 "$T/tws.build")"
sh scripts/mkimage.sh "$T/ws.img" bin/kernel init="$T/tws.bin":8192 wslate=$ND/wslate_vectors.bin:0 2> "$T/ws.mk" || fail wslate "mkimage: $(cat "$T/ws.mk")"
expect wslate 124 '^wslate: 23 as expected, 0 not' 60 ./tools/q32 "$T/ws.img"
# Payment proofs and proofs of burn (wproof.fam): proofs tabminer made,
# parsed, checked (each altered one refused for tabminer's reason), as
# text both ways, built from their parts; bytes that do not parse refused.
./tools/fam --user -o "$T/twp.bin" src/user/crypto/keccak.fam src/user/crypto/dilithium.fam \
	$ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/state.fam $ND/xmss.fam $ND/xsign.fam $ND/wkeys.fam $ND/wslate.fam $ND/wproof.fam $ND/wproof_test.fam > "$T/twp.build" 2>&1 || fail wproof "build: $(head -c 300 "$T/twp.build")"
sh scripts/mkimage.sh "$T/wp.img" bin/kernel init="$T/twp.bin":8192 wproof=$ND/wproof_vectors.bin:0 2> "$T/wp.mk" || fail wproof "mkimage: $(cat "$T/wp.mk")"
expect wproof 124 '^wproof: 48 as expected, 0 not' 60 ./tools/q32 "$T/wp.img"
# Names (wname.fam): names' rules, hashes and keys; a registration (owner
# key, salt, commit, memo, record), the commit, reveal and update
# operations and their digests; transactions carrying them; trie proofs,
# members and absent names, refused when altered: as tabminer's.
./tools/fam --user -o "$T/twn.bin" src/user/crypto/sha512.fam src/user/crypto/sha256.fam src/user/crypto/bip39.fam src/user/crypto/chacha.fam src/user/crypto/keccak.fam src/user/crypto/dilithium.fam \
	$ND/arith.fam $ND/poseidon2.fam $ND/difficulty.fam $ND/pow.fam $ND/state.fam $ND/xmss.fam $ND/xsign.fam $ND/wkeys.fam $ND/wslate.fam $ND/wname.fam $ND/wname_test.fam > "$T/twn.build" 2>&1 || fail wname "build: $(head -c 300 "$T/twn.build")"
sh scripts/mkimage.sh "$T/wn.img" bin/kernel init="$T/twn.bin":8192 wname=$ND/wname_vectors.bin:0 2> "$T/wn.mk" || fail wname "mkimage: $(cat "$T/wn.mk")"
expect wname 124 '^wname: 98 as expected, 0 not' 60 ./tools/q32 "$T/wn.img"

# The store's benchmark (scripts/storebench.sh) builds beside the kernel:
# its words and the kernel's share one name space.
N=$((N + 1))
./tools/fam -o "$T/storebench.bin" src/kernel.fam src/store.fam src/net.fam src/ksys.fam src/storebench.fam > "$T/storebench.build" 2>&1 \
	|| fail storebench_build "$(head -c 300 "$T/storebench.build")"

printf 'trapinit 0 lit @ drop bye\n' > "$T/fault.fam"
./tools/fam -o "$T/fault.bin" src/kernel.fam src/store.fam src/net.fam src/ksys.fam "$T/fault.fam" > "$T/fault.build" 2>&1 \
	|| fail fault_build "$(head -c 300 "$T/fault.build")"
expect fault 1 'kernel: hart 0 trap 00000005 at .* (00000000)' 30 ./tools/q32 "$T/fault.bin"

boots boot '^\$ ' 60 ./tools/q32 bin/img
grep -q 'kernel: 1 hart, [0-9]* pages free' "$T/boot.out" && grep -q '^\$ $' "$T/boot.out" \
	|| fail boot "no banner or no init: $(head -c 300 "$T/boot.out")"
boots boot_6 'kernel: 6 harts' 60 ./tools/q32 --smp=6 bin/img

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
./tools/fam -o "$T/sharek.bin" src/kernel.fam src/store.fam src/net.fam src/ksys.fam "$T/share.fam" > "$T/share.build" 2>&1 || fail lottery "build: $(head -c 300 "$T/share.build")"
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

# A process that ends with memory still mapped (malloc's arenas, never
# freed): its blocks given back whole, five times over, /proc/mem the same
# after (after a first run, which takes the kernel's one-time 16 KiB;
# pfinish once freed from the process's state word instead).
usrc tleak '20000 lit malloc 0= if "null" puts 0A lit putc then bye'
usrc tleakp ': st variable ;  : b variable ;
: mem  "/proc/mem" 0 lit open dup b @ 20 lit read drop close drop b @ atoi ;
40 lit alloc b !
"leak" spawn st wait drop  mem  5 lit 0 lit do "leak" spawn st wait drop loop  mem
= if "mapped freed" else "mapped leaked" then puts 0A lit putc bye'
uimage leak bin/kernel init=tleakp leak=tleak
for n in 1 4; do expect "mapexit_$n" 124 '^mapped freed$' 6 ./tools/q32 --smp=$n "$T/leak.img"; done

# Descriptors, the console, init and a shell (step 7).  Calls: poll timing
# out, then readable, then hung up; a pipe read to its end; the errors; 32
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
0 lit 20 lit 0 lit do "/dev/null" 0 lit open 0< if 1 lit + then loop "full " puts . 0A lit putc
20 lit 3 lit do i close drop loop
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
# Randomness: /dev/random from virtio-rng (node step 0).  Two reads of 32
# bytes that differ, the rest of the device's 256, the next 256 (a new
# request, waited for), a write refused (opened to read).
usrc trnd ': b variable ;  : c variable ;  : f variable ;
: sp  20 lit putc ;
100 lit alloc b !  100 lit alloc c !
"/dev/random" 0 lit open dup f ! 0< if "random bad" else "random ok" then puts sp
f @ b @ 20 lit read "read " puts . sp
f @ c @ 20 lit read . sp
0 lit 20 lit 0 lit do b @ i + c@ c @ i + c@ <> if 1 lit + then loop 8 lit u> if "differ yes" else "differ no" then puts sp
f @ c @ 100 lit read "rest " puts . sp
f @ c @ 100 lit read "next " puts . sp
f @ "x" 1 lit write "write " puts . 0A lit putc
f @ close drop bye'
sh scripts/mkimage.sh "$T/rnd.img" bin/kernel init="$T/trnd.bin" 2> "$T/rnd.mk" || fail rnd "mkimage: $(cat "$T/rnd.mk")"
expect rnd 124 '^random ok read 32 32 differ yes rest 192 next 256 write -9$' 5 ./tools/q32 --smp=2 "$T/rnd.img"
# The image this machine booted: /dev/image (node step 9), its size the
# image's, its bytes the image's (its first word, its last 8 bytes, the
# table's offset and "PROG", read after seeking), to read only; seeking a
# device that is not a file still refused; /dev's listing names it.
usrc timg ': b variable ;  : f variable ;  : sp  20 lit putc ;
100 lit alloc b !
"/dev/image" 0 lit open dup f ! 0< if "image bad" else "image ok" then puts sp
f @ 0 lit 2 lit seek dup "size " puts . sp
8 lit - f @ swap 0 lit seek drop  f @ b @ 10 lit read "tail " puts . sp  b @ @ u. sp  0 lit b @ 8 lit + c!  b @ 4 lit + puts sp
f @ 0 lit 0 lit seek drop  f @ b @ 4 lit read drop  "first " puts b @ @ u. sp
f @ 4 lit 1 lit seek "here " puts . sp
"/dev/image" 1 lit open "write " puts . sp
"/dev/null" 0 lit open 0 lit 0 lit seek "null " puts . 0A lit putc
"/dev" 0 lit open dup b @ 100 lit read b @ + 0 lit swap c! close drop b @ puts
f @ close drop bye'
uimage img bin/kernel init=timg
set -- $(od -An -tu4 -N4 "$T/img.img") $(od -An -tu4 -j$(($(wc -c < "$T/img.img") - 8)) -N4 "$T/img.img")
expect image 124 "^image ok size $(wc -c < "$T/img.img" | tr -d ' ') tail 8 $2 PROG first $1 here 8 write -13 null -29\$" 5 ./tools/q32 "$T/img.img"
has image '^image$'
# The time register read in user mode (rdtime, no call: the node times its
# blocks with it), on every hart: it moves on across a sleep.
usrc ttime ':M ticks
1301C1FF ,   \ addi sp,sp,-4
F32710C0 ,   \ rdtime a5
2320F100 ,   \ sw a5,0(sp)
;
: t0 variable ;
ticks t0 !  989680 lit sleep  ticks t0 @ - 0 lit > if "rdtime ok" else "rdtime stuck" then puts 0A lit putc bye'
uimage time bin/kernel init=ttime
for n in 1 4; do expect "rdtime_$n" 124 '^rdtime ok$' 5 ./tools/q32 --smp=$n "$T/time.img"; done
# The date: /proc/time from QEMU's real-time clock (node step 6), within a
# minute of the host's, and in the /proc listing.
usrc ttime ': b variable ;  20 lit alloc b !
"/proc/time" 0 lit open dup b @ 20 lit read b @ + 0 lit swap c! close drop
"time " puts b @ puts bye'
sh scripts/mkimage.sh "$T/time.img" bin/kernel init="$T/ttime.bin" 2> "$T/time.mk" || fail time "mkimage: $(cat "$T/time.mk")"
expect time 124 '^time [0-9]' 5 ./tools/q32 "$T/time.img"
GT=$(sed -n 's/^time \([0-9]*\).*/\1/p' "$T/time.out" | head -1); HT=$(date +%s)
[ -n "$GT" ] && [ $((GT - HT)) -lt 60 ] && [ $((HT - GT)) -lt 60 ] || fail time "guest $GT, host $HT"
# The shell from the console: the image's programs and one writing 100 KiB,
# commands typed a line at a time, on one hart and on four; one in the
# background (&: its pid shown, then told done), and & before a line's end;
# ls of /proc, /dev, /bin and a process's directory (the root's, with a
# store, in the wm test); the search path shown, a command by its path,
# one not found with /bin left out of the path, found again with it back;
# dev and proc/... found from the root as relative paths; halt stopping it.
usrc big ': buf variable ;
400 lit alloc buf !  400 lit 0 lit do 61 lit buf @ i + c! loop  A lit buf @ 3FF lit + c!
64 lit 0 lit do 1 lit buf @ 400 lit write drop loop bye'
progs=""; for p in bin/user/*; do progs="$progs $(basename "$p")=$p"; done
sh scripts/mkimage.sh "$T/shell.img" bin/kernel $progs big="$T/big.bin" 2> "$T/shell.mk" || fail shell "mkimage: $(cat "$T/shell.mk")"
printf '%s\n' 'echo hello world' 'ps' 'echo one two three | wc' 'big | cat | wc' 'cat /proc/self/cmd' \
	'echo 7 > /proc/2/tickets' 'cat < /proc/2/tickets' 'nosuch' 'a |' 'cat &' 'echo after' 'echo x & echo y' 'ls /proc' 'ls dev' 'cat proc/../proc/self' 'ls /proc/1' 'ls /bin' 'path' '/bin/echo by its path' 'path /none' 'echo x' 'path /none:/bin' 'echo found' 'exit' 'halt' > "$T/shell.in"
# feed SECS FILE CMD... — CMD run with FILE's lines typed into it, each once
# the program prompts for it (scripts/feed.py: so a slow machine doesn't get
# a line typed ahead, echoed among the output), SECS at most.
feed() { python3 scripts/feed.py "$@"; }
for n in 1 4; do
	N=$((N + 1)); o="$T/shell_$n.out"
	feed 120 "$T/shell.in" ./tools/q32 --smp=$n "$T/shell.img" > "$o" 2>&1
	for pat in '^hello world$' '^PID PPID S THR KIB TICKS CMD$' '^1 0 S 1 64 [0-9]* init$' '^2 1 S 1 64 [0-9]* sh$' \
		'^3 2 R 1 64 [0-9]* ps$' '^1 3 14$' '^100 100 102400$' '^cat /proc/self/cmd$' '^7$' \
		'^sh: nosuch: not found$' '^sh: a command is missing$' '^init: the shell exited; halting$' \
		'^\(\$ \)*\[[0-9]*\]$' '\[[0-9]*\] done$' '^sh: & only ends a line$' \
		'^uptime$' '^tty/$' '^tickets$' '^runas$' '^/bin$' '^by its path$' '^sh: echo: not found$' '^found$' '^halt$' '^kernel: halted$'; do
		grep -q -- "$pat" "$o" || { fail "shell_$n" "no /$pat/ in: $(head -c 600 "$o")"; break; }
	done
done

# Programs from the store, with a disk: /bin made by init (the image's
# programs listed in it too), cd into /proc and a process's directory; an
# image program read as /bin/echo and copied to a file, refused without an x
# bit, then run by its path, by a relative one, and (copied into /bin) by
# the search path; writing over /bin/echo refused; twenty runs of it
# freeing what they took; halt.  On one hart and on four.
sh scripts/mkimage.sh "$T/exec.img" bin/kernel $progs 2> "$T/exec.mk" || fail exec "mkimage: $(cat "$T/exec.mk")"
{ printf '%s\n' 'ls /' 'cd /proc' 'pwd' 'cd 1' 'cat status' 'cd /' 'mkdir /home' 'cat /bin/echo > /home/e' \
	'/home/e no x bit' 'chmod 755 /home/e' '/home/e from a file' 'cd /home' './e relative' 'cd /' \
	'cat /bin/echo > /bin/myecho' 'chmod 755 /bin/myecho' 'myecho by the path' 'ls /bin' 'echo x > /bin/echo' 'cat /proc/mem'
  i=0; while [ $i -lt 20 ]; do echo "/home/e run $i"; i=$((i + 1)); done
  printf '%s\n' 'cat /proc/mem' 'halt'; } > "$T/exec.in"
for n in 1 4; do
	N=$((N + 1)); o="$T/exec_$n.out"
	rm -f "$T/exec.disk"; dd if=/dev/zero of="$T/exec.disk" bs=1 count=0 seek=268435456 2>/dev/null
	feed 180 "$T/exec.in" ./tools/q32 --smp=$n --disk="$T/exec.disk" "$T/exec.img" > "$o" 2>&1
	for pat in '^bin/$' '^/proc$' '^1 0 S 1 64 [0-9]* init$' 'sh: /home/e: not allowed$' '^from a file$' '^relative$' \
		'^by the path$' '^myecho$' '^sh: /bin/echo: cannot open$' '^run 19$' '^kernel: halted$'; do
		grep -q -- "$pat" "$o" || { fail "exec_$n" "no /$pat/ in: $(tail -c 600 "$o")"; break; }
	done
	m=$(grep -x '[0-9][0-9][0-9][0-9]*' "$o" | sed -n '1p;$p' | sort -u | wc -l | tr -d " \t")
	[ "$m" = 1 ] || fail "exec_$n" "memory not given back: $(grep -x '[0-9][0-9][0-9][0-9]*' "$o" | tr '\n' ' ')"
done

# vi (step 11), on the console with a disk: a new file typed (Esc then o
# straight after), written and quit; opened again, its lines swapped (dd
# p), written; opened again, a byte taken out, :q refused (E37), :q!; the
# file seen with cat after each (its escape sequences stripped).
cat > "$T/vi.feed" <<'VIEOF'
vi /t.txt
#wait [New]
#raw ihello world\x1bosecond line\x1b:wq\r
cat /t.txt
vi /t.txt
#wait 2 lines
#raw ddp:wq\r
cat /t.txt
vi /t.txt
#wait 2 lines
#raw x:q\r
#wait E37
#raw :q!\r
cat /t.txt
halt
VIEOF
for n in 1 4; do
	N=$((N + 1)); o="$T/vi_$n.out"
	rm -f "$T/vi.disk"; dd if=/dev/zero of="$T/vi.disk" bs=1 count=0 seek=268435456 2>/dev/null
	feed 120 "$T/vi.feed" ./tools/q32 --smp=$n --disk="$T/vi.disk" "$T/exec.img" > "$o" 2>&1
	r=$(python3 -c '
import re, sys
t = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "\n", open(sys.argv[1], errors="replace").read()).replace("\r", "")
cats = ["/".join(b.split("\n")[1:3]) for b in t.split("$ cat /t.txt")[1:]]
print("|".join(["e37" if "E37: No write since last change" in t else "no-e37"] + cats))' "$o")
	[ "$r" = "e37|hello world/second line|second line/hello world|second line/hello world" ] || fail "vi_$n" "$r"
done

# Programs built inside the OS (step 11), with a disk: hello.fam written in
# vi, built with fam (famc: bin/fam unchanged, a machine program whose UART
# and test finisher the kernel stands in for) and run; vi.fam (a data file
# here, /lib/vi.fam) built and the same, byte for byte, as /bin/vi, built
# on the host; a file with a word not known: the error said, no program
# left.
sh scripts/mkimage.sh "$T/build.img" bin/kernel $progs famc=bin/fam.uncompressed:8192:m stdlib.fam=lib/stdlib.fam:0 \
	user.fam=lib/user.fam:0 build.fam=lib/build.fam:0 vi.fam=src/user/vi.fam:0 2> "$T/build.mk" || fail build "mkimage: $(cat "$T/build.mk")"
cat > "$T/build.feed" <<'BUILDEOF'
vi /h.fam
#wait [New]
#raw i: greet  "hello, " puts puts 0A lit putc ;\r"world" greet\rbye\x1b:wq\r
fam /h.fam
/h
fam -o /vi2 /lib/vi.fam
cmp /vi2 /bin/vi
echo 1 lit nosuchword bye > /bad.fam
fam /bad.fam
ls /
halt
BUILDEOF
for n in 1 4; do
	N=$((N + 1)); o="$T/build_$n.out"
	rm -f "$T/build.disk"; dd if=/dev/zero of="$T/build.disk" bs=1 count=0 seek=268435456 2>/dev/null
	feed 240 "$T/build.feed" ./tools/q32 --smp=$n --disk="$T/build.disk" "$T/build.img" > "$o" 2>&1
	for pat in '^hello, world' '^same' 'fam: compile error (a word not known' '^vi2' '^kernel: halted'; do
		tr -d '\r' < "$o" | grep -q -- "$pat" || { fail "build_$n" "no /$pat/ in: $(tr -d '\r' < "$o" | tail -c 500)"; break; }
	done
	tr -d '\r' < "$o" | grep -qx 'bad' && fail "build_$n" "a program left after a compile error"
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
feed 60 "$T/fs1.in" ./tools/q32 --disk="$T/files.disk" bin/img > "$T/fs1.out" 2>&1
feed 60 "$T/fs2.in" ./tools/q32 --disk="$T/files.disk" bin/img > "$T/fs2.out" 2>&1
for pat in '^home/$' '^/home$'; do grep -q -- "$pat" "$T/fs1.out" || fail fs_boot1 "no /$pat/ in: $(head -c 600 "$T/fs1.out")"; done
for pat in '^hello files$' '^a second line$' '^2 5 26$' '^cat: cannot open notes$'; do grep -q -- "$pat" "$T/fs2.out" || fail fs_boot2 "no /$pat/ in: $(head -c 600 "$T/fs2.out")"; done
rm -f "$T/files.disk"

# The crypto modules (src/user/crypto/): SHA-512, HMAC and PBKDF2 against
# Python's hashlib (BIP39's own case among them); then the passwords kept
# in /etc/passwd as PBKDF2 hashes, made, checked (hashlib's too), set;
# BIP39; ChaCha20-Poly1305; Dilithium.
./tools/fam --user -o "$T/t5.bin" src/user/crypto/sha512.fam src/user/crypto/sha512_test.fam > "$T/t5.build" 2>&1 || fail sha512 "build: $(head -c 300 "$T/t5.build")"
sh scripts/mkimage.sh "$T/t5.img" bin/kernel init="$T/t5.bin":1024 2> "$T/t5.mk" || fail sha512 "mkimage: $(cat "$T/t5.mk")"
expect sha512 124 '^sha512: 10 as expected, 0 not' 60 ./tools/q32 "$T/t5.img"
./tools/fam --user -o "$T/tpw.bin" src/user/crypto/sha512.fam src/user/crypto/passwd.fam src/user/crypto/passwd_test.fam > "$T/tpw.build" 2>&1 || fail passwd "build: $(head -c 300 "$T/tpw.build")"
sh scripts/mkimage.sh "$T/tpw.img" bin/kernel init="$T/tpw.bin":1024 2> "$T/tpw.mk" || fail passwd "mkimage: $(cat "$T/tpw.mk")"
rm -f "$T/tpw.disk"; dd if=/dev/zero of="$T/tpw.disk" bs=1 count=0 seek=268435456 2>/dev/null
expect passwd 124 '^passwd: 12 as expected, 0 not' 60 ./tools/q32 --disk="$T/tpw.disk" "$T/tpw.img"
rm -f "$T/tpw.disk"
# BIP39 (the wallet's phrase): SHA-256, phrases, entropy, seeds against
# Python's standard computation (the word list as /lib/bip39).
./tools/fam --user -o "$T/tb3.bin" src/user/crypto/sha512.fam src/user/crypto/sha256.fam src/user/crypto/bip39.fam src/user/crypto/bip39_test.fam > "$T/tb3.build" 2>&1 || fail bip39 "build: $(head -c 300 "$T/tb3.build")"
sh scripts/mkimage.sh "$T/tb3.img" bin/kernel init="$T/tb3.bin":1024 bip39=../resources/bip39-english.txt:0 2> "$T/tb3.mk" || fail bip39 "mkimage: $(cat "$T/tb3.mk")"
expect bip39 124 '^bip39: 29 as expected, 0 not' 60 ./tools/q32 "$T/tb3.img"
# ChaCha20-Poly1305 (the wallet's phrase at rest): RFC 8439's vectors and
# Python's cryptography, tampering refused.
./tools/fam --user -o "$T/tcc.bin" src/user/crypto/chacha.fam src/user/crypto/chacha_test.fam > "$T/tcc.build" 2>&1 || fail chacha "build: $(head -c 300 "$T/tcc.build")"
sh scripts/mkimage.sh "$T/tcc.img" bin/kernel init="$T/tcc.bin":1024 2> "$T/tcc.mk" || fail chacha "mkimage: $(cat "$T/tcc.mk")"
expect chacha 124 '^chacha: 29 as expected, 0 not' 60 ./tools/q32 "$T/tcc.img"
# Dilithium (ML-DSA-65, receipts and addresses) and SHA-3: keys, signatures
# and verdicts (tampered ones among them) as tabminer's mldsa.rs.
./tools/fam --user -o "$T/tdl.bin" src/user/crypto/keccak.fam src/user/crypto/dilithium.fam src/user/crypto/dilithium_vectors.fam src/user/crypto/dilithium_test.fam > "$T/tdl.build" 2>&1 || fail dilithium "build: $(head -c 300 "$T/tdl.build")"
sh scripts/mkimage.sh "$T/tdl.img" bin/kernel init="$T/tdl.bin":1024 2> "$T/tdl.mk" || fail dilithium "mkimage: $(cat "$T/tdl.mk")"
expect dilithium 124 '^dilithium: 108 as expected, 0 not' 60 ./tools/q32 "$T/tdl.img"
# Kyber (ML-KEM-768, the message layer's key encapsulation): keys,
# encapsulations, decapsulations (tampered ciphertexts among them) and the
# key check as tabminer's mlkem.rs.
./tools/fam --user -o "$T/tky.bin" src/user/crypto/keccak.fam src/user/crypto/kyber.fam src/user/crypto/kyber_vectors.fam src/user/crypto/kyber_test.fam > "$T/tky.build" 2>&1 || fail kyber "build: $(head -c 300 "$T/tky.build")"
sh scripts/mkimage.sh "$T/tky.img" bin/kernel init="$T/tky.bin":1024 2> "$T/tky.mk" || fail kyber "mkimage: $(cat "$T/tky.mk")"
expect kyber 124 '^kyber: 50 as expected, 0 not' 60 ./tools/q32 "$T/tky.img"

# The wallet (docs/GUI_WALLET.md, phase 1), driven as wm drives it
# (src/user/tests/walletrun.fam: requests on a pipe, each answer printed):
# none at first; one created, its phrase shown, its address; made again
# refused; its phrase only for its password; a second unlock refused; run
# again with another password locked, with its own the same address; in
# another directory, phrases refused for their reasons, one restored (case
# and spacing its own), given back normalized.
./tools/fam --user -o "$T/twr.bin" src/user/tests/walletrun.fam > "$T/twr.build" 2>&1 || fail wallet "build: $(head -c 300 "$T/twr.build")"
cat > "$T/wreq" <<'WREQEOF'
{"op":"unlock","password":"pw\"1\\x"}
{"id":1,"op":"overview"}
{"id":2,"op":"create"}
{"id":3,"op":"receive"}
{"id":4,"op":"create"}
{"id":5,"op":"phrase","password":"nope"}
{"id":6,"op":"phrase","password":"pw\"1\\x"}
{"id":7,"op":"unlock","password":"x"}
{"id":8,"op":"overview"}
---
{"op":"unlock","password":"other"}
{"id":9,"op":"receive"}
---
{"op":"unlock","password":"pw\"1\\x"}
{"id":10,"op":"receive"}
{"id":11,"op":"restore","words":"abandon abandon","passphrase":""}
--- /r
{"op":"unlock","password":"rpw"}
{"id":12,"op":"restore","words":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon","passphrase":""}
{"id":13,"op":"restore","words":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandonx","passphrase":""}
{"id":14,"op":"restore","words":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"}
{"id":15,"op":"restore","words":"  Abandon abandon ABANDON abandon abandon abandon abandon abandon abandon abandon abandon about ","passphrase":"TREZOR"}
{"id":16,"op":"phrase","password":"rpw"}
WREQEOF
sh scripts/mkimage.sh "$T/twr.img" bin/kernel init="$T/twr.bin":1024 wallet=bin/user/wallet:4096 bip39=../resources/bip39-english.txt:0 wreq="$T/wreq":0 2> "$T/twr.mk" || fail wallet "mkimage: $(cat "$T/twr.mk")"
rm -f "$T/twr.disk"; dd if=/dev/zero of="$T/twr.disk" bs=1 count=0 seek=268435456 2>/dev/null
expect wallet 124 '^walletrun: done' 120 ./tools/q32 --disk="$T/twr.disk" "$T/twr.img"
W="$T/wallet.out"
for pat in '^w: {"op":"unlock","ok":true,"wallet":false}$' '^w: {"id":1,"ok":false,"error":"no wallet yet: create or restore one"}$' \
	'^w: {"id":2,"ok":true,"words":"\([a-z]\{3,8\} \)\{11\}[a-z]\{3,8\}"}$' '^w: {"id":3,"ok":true,"address":"tab1[02-9ac-hj-np-z]\{58\}"}$' \
	'^w: {"id":4,"ok":false,"error":"there is a wallet already"}$' '^w: {"id":5,"ok":false,"error":"not the password"}$' \
	'^w: {"id":7,"ok":false,"error":"unlocked already"}$' '^w: {"id":8,"ok":true,"confirmed":"0.0000000000","pending":"0.0000000000","unverified":"0.0000000000","reserved":"0.0000000000","locked":"0.0000000000","height":0,"node":"not reached"}$' \
	'^w: {"op":"unlock","ok":false,"error":"the wallet is sealed under another password than the session"}$' \
	'^w: {"id":9,"ok":false,"error":"locked"}$' '^w: {"op":"unlock","ok":true,"wallet":true}$' \
	'^w: {"id":11,"ok":false,"error":"there is a wallet already"}$' \
	'^w: {"id":12,"ok":false,"error":"the checksum of the words does not match: a word is wrong"}$' \
	'^w: {"id":13,"ok":false,"error":"a word is not in the list"}$' '^w: {"id":14,"ok":false,"error":"a phrase is 12 words"}$' \
	'^w: {"id":15,"ok":true}$' '^w: {"id":16,"ok":true,"words":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}$'; do
	grep -q -- "$pat" "$W" || fail wallet_answers "no /$pat/ in: $(grep '^w: ' "$W" | head -c 1500)"
done
[ "$(sed -n 's/^w: {"id":2,"ok":true,"words":"\(.*\)"}$/\1/p' "$W")" = "$(sed -n 's/^w: {"id":6,"ok":true,"words":"\(.*\)"}$/\1/p' "$W")" ] \
	|| fail wallet_answers "the phrase given back is not the one made"
[ "$(sed -n 's/^w: {"id":3,"ok":true,"address":"\(.*\)"}$/\1/p' "$W")" = "$(sed -n 's/^w: {"id":10,"ok":true,"address":"\(.*\)"}$/\1/p' "$W")" ] \
	|| fail wallet_answers "the address changed when run again"
rm -f "$T/twr.disk"

# Users (step 8, part 5): a disk booted twice.  First as root (no
# /etc/init yet): /etc/passwd and /etc/init written, a home for alice
# hers alone.  Then init runs login: a wrong password refused; alice in,
# her user and home, her file, root's file and the root directory closed
# to her; root in after her, everything open to it; root adds bob
# (adduser), who logs in next, his user 1000, his home.  The passwords were
# written in plain text: each is kept hashed after its first use
# (crypto/passwd.fam), as root's cat of /etc/passwd shows.
printf '%s\n' 'mkdir /etc' 'echo root:rootpw:0:0:/:sh > /etc/passwd' 'echo alice:apw:1:1:/home/alice:sh >> /etc/passwd' \
	'chmod 600 /etc/passwd' 'mkdir /home' 'mkdir /home/alice' 'chown 1 1 /home/alice' 'chmod 700 /home/alice' \
	'echo restart 0 100 login > /etc/init' 'id' 'ls /etc' > "$T/u1.in"
printf '%s\n' 'alice' 'wrong' 'alice' 'apw' 'id' 'pwd' 'echo mine > f' 'cat f' 'cat /etc/passwd' 'mkdir /tmp2' 'ls /home' \
	'exit' 'root' 'rootpw' 'id' 'cat /etc/passwd' 'ls /home/alice' 'adduser bob' 'bobpw1' 'bobpw1' 'ls /home' \
	'exit' 'bob' 'bobpw1' 'id' 'pwd' > "$T/u2.in"
rm -f "$T/users.disk"; dd if=/dev/zero of="$T/users.disk" bs=1 count=0 seek=268435456 2>/dev/null
N=$((N + 1))
feed 60 "$T/u1.in" ./tools/q32 --disk="$T/users.disk" bin/img > "$T/u1.out" 2>&1
feed 180 "$T/u2.in" ./tools/q32 --disk="$T/users.disk" bin/img > "$T/u2.out" 2>&1
for pat in '^\([$] \)*0 0$' '^\([$] \)*init$' '^\([$] \)*passwd$'; do grep -q -- "$pat" "$T/u1.out" || fail users_boot1 "no /$pat/ in: $(head -c 800 "$T/u1.out")"; done
for pat in '^init: /etc/init: 1 programs$' '^login incorrect$' '^1 1$' '^/home/alice$' '^mine$' '^cat: cannot open /etc/passwd$' \
	'^mkdir: cannot make /tmp2: -13$' '^alice/$' '^f$' \
	'^root:[$]p5[$]4e20[$][0-9a-f]\{32\}[$][0-9a-f]\{64\}:0:0:/:sh$' \
	'^alice:[$]p5[$]4e20[$][0-9a-f]\{32\}[$][0-9a-f]\{64\}:1:1:/home/alice:sh$' \
	'^adduser: bob, user 1000, home /home/bob$' '^bob/$' '^1000 1000$' '^/home/bob$'; do
	grep -q -- "$pat" "$T/u2.out" || fail users_boot2 "no /$pat/ in: $(head -c 900 "$T/u2.out")"
done
[ "$(grep -c '0 0$' "$T/u2.out")" = 1 ] || fail users_boot2 "root's id not once after alice's: $(head -c 900 "$T/u2.out")"
# typed passwords never shown (the terminal raw while they are read)
! grep -qE 'wrong|apw|rootpw|bobpw1' "$T/u2.out" || fail users_boot2 "a password shown as typed: $(grep -E 'wrong|apw|rootpw|bobpw1' "$T/u2.out" | head -3)"
rm -f "$T/users.disk"

# The network (step 9): UDP.  A program asks an echo server on the host
# (10.0.2.2 under QEMU's user networking), waiting until ARP has found the
# gateway; then connected, write, poll and read; and the errors: another
# kind, not a socket, a port taken.
UP=$((20000 + $$ % 20000)); UPX=$(printf %X "$UP")
usrc tudp ': b variable ;  : from variable ;  : s variable ;  : ent variable ;  : sp  20 lit putc ;
40 lit alloc b !  8 lit alloc from !  8 lit alloc ent !
1 lit socket s !
0 lit begin drop s @ "hello" 5 lit A000202 lit '"$UPX"' lit sendto dup FFFFFF8F lit = while 5F5E100 lit sleep repeat
"sent " puts . sp
s @ b @ 40 lit from @ recvfrom dup "got " puts . sp
b @ + 0 lit swap c!  b @ puts sp  from @ @ u.x sp  from @ 4 lit + @ . 0A lit putc
s @ 2 lit A000202 lit '"$UPX"' lit net "connect " puts . sp
s @ "again" 5 lit write "write " puts . sp
s @ ent @ !  1 lit ent @ 4 lit + !
ent @ 1 lit 0 lit poll "poll " puts . sp
s @ b @ 40 lit read dup "read " puts . sp b @ + 0 lit swap c! b @ puts 0A lit putc
3 lit socket "kind " puts . sp  0 lit b @ 1 lit 0 lit recvfrom "notsock " puts . sp
1 lit socket dup 1 lit 0 lit 1234 lit net drop  1 lit socket 1 lit 0 lit 1234 lit net "taken " puts . sp
close drop  s @ close "close " puts . 0A lit putc bye'
sh scripts/mkimage.sh "$T/udp.img" bin/kernel init="$T/tudp.bin" 2> "$T/udp.mk" || fail udp "mkimage: $(cat "$T/udp.mk")"
python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
print("ready", flush=True)
while True:
    d, a = s.recvfrom(2048)
    s.sendto(b"echo:" + d, a)
' "$UP" > "$T/udpecho.ready" & EP=$!
served "$T/udpecho.ready" udp
for n in 1 4; do
	expect "udp_$n" 124 '^sent 5 got 10 echo:hello 0A000202 '"$UP"'$' 6 ./tools/q32 --smp=$n --net "$T/udp.img"
	has "udp_$n" '^connect 0 write 5 poll 1 read 10 echo:again$'
	has "udp_$n" '^kind -22 notsock -88 taken -98 close 0$'
done
kill $EP

# TCP (step 9).  A client: connected to an echo server on the host,
# written, read, closed; a port no one listens on refused.  Then 400 KiB
# sent to a host server that checks them, on a kernel losing 16 frames in
# a row (ndrop: the acknowledgments of what is in flight), so what was sent
# goes again (/proc/net counts it) and the socket is freed after.
TP=$((UP + 1)); TPX=$(printf %X "$TP")
usrc ttcp ': b variable ;  : s variable ;  : sp  20 lit putc ;
100 lit alloc b !
2 lit socket s !
s @ 2 lit A000202 lit '"$TPX"' lit net "connect " puts . sp
s @ "hello tcp" 9 lit write "write " puts . sp
s @ b @ 100 lit read dup "read " puts . sp b @ + 0 lit swap c! b @ puts 0A lit putc
s @ close "close " puts . sp
2 lit socket dup 2 lit A000202 lit 3 lit net "refused " puts . sp close drop 0A lit putc bye'
usrc tup ': b variable ;  : s variable ;  : sp  20 lit putc ;
400 lit alloc b !  400 lit 0 lit do i 3F lit and 30 lit + b @ i + c! loop
2 lit socket s !
s @ 2 lit A000202 lit '"$TPX"' lit net "connect " puts . sp
0 lit 190 lit 0 lit do s @ b @ 400 lit write + loop "wrote " puts . sp
s @ b @ 100 lit read dup "read " puts . sp b @ + 0 lit swap c! b @ puts 0A lit putc
s @ close drop 3B9ACA00 lit sleep
"/proc/net" 0 lit open dup b @ 100 lit read b @ + 0 lit swap c! close drop b @ puts bye'
printf '%s\n' kboot '28 lit ndrop !' '"init" 64 lit kspawn drop' hloop > "$T/lossy.fam"
./tools/fam -o "$T/lossyk.bin" src/kernel.fam src/store.fam src/net.fam src/ksys.fam "$T/lossy.fam" > "$T/lossy.build" 2>&1 \
	|| fail tcp_lossy "build: $(head -c 300 "$T/lossy.build")"
sh scripts/mkimage.sh "$T/tcp.img" bin/kernel init="$T/ttcp.bin" 2> "$T/tcp.mk" || fail tcp "mkimage: $(cat "$T/tcp.mk")"
sh scripts/mkimage.sh "$T/up.img" "$T/lossyk.bin" init="$T/tup.bin" 2> "$T/up.mk" || fail tcp_lossy "mkimage: $(cat "$T/up.mk")"
python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(5)
print("ready", flush=True)
pat = bytes(48 + (i & 63) for i in range(1024)) * 400
while True:
    c, a = s.accept(); got = b""
    while True:
        d = c.recv(65536)
        if not d: break
        got += d
        if got == b"hello tcp": c.sendall(b"echo:" + got); got = b""
        if len(got) >= len(pat): break
    if got: c.sendall(b"got %d %s" % (len(got), b"intact" if got == pat else b"BAD"))
    c.close()
' "$TP" > "$T/tcpecho.ready" & EP=$!
served "$T/tcpecho.ready" tcp
for n in 1 4; do
	expect "tcp_$n" 124 '^connect 0 write 9 read 14 echo:hello tcp$' 6 ./tools/q32 --smp=$n --net "$T/tcp.img"
	has "tcp_$n" '^close 0 refused -111 $'
done
expect tcp_lossy 124 '^connect 0 wrote 409600 read 17 got 409600 intact$' 20 ./tools/q32 --net "$T/up.img"
has tcp_lossy '^tcp 0 retransmits [1-9]'
# TCP to this machine (docs/OS.md, loopback): a listener, a connection to
# 127.0.0.1 and one to 10.0.2.15 accepted, written each way.
usrc tloop ': b variable ;  : l variable ;  : c variable ;  : a variable ;  : sp  20 lit putc ;
: once
2 lit socket c !  c @ 2 lit rot E9A lit net "connect " puts . sp
l @ accept a !  "accept " puts a @ 0< . sp
c @ "hello loop" A lit write "write " puts . sp
a @ b @ 100 lit read dup "read " puts . sp b @ + 0 lit swap c! b @ puts sp
a @ "back" 4 lit write drop
c @ b @ 100 lit read dup "reply " puts . sp b @ + 0 lit swap c! b @ puts 0A lit putc
c @ close drop  a @ close drop ;
100 lit alloc b !
2 lit socket l !  l @ 1 lit 0 lit E9A lit net "bind " puts . sp  l @ 3 lit 0 lit 0 lit net "listen " puts . 0A lit putc
7F000001 lit once  A00020F lit once  bye'
uimage loop bin/kernel init=tloop
for n in 1 4; do
	expect "tcp_loop_$n" 124 'kernel: init ended: 0' 6 ./tools/q32 --smp=$n --net "$T/loop.img"
	[ "$(grep -c '^connect 0 accept 0 write 10 read 10 hello loop reply 4 back$' "$T/tcp_loop_$n.out")" = 2 ] \
		|| fail "tcp_loop_$n" "$(head -c 300 "$T/tcp_loop_$n.out")"
done
kill $EP

# A web server: httpd (src/user/httpd.fam) serving files from the store,
# fetched by the host through a forwarded port: a page, 100 KiB (whole),
# a 404, and 40 fetches one after another (more than TCP's 32 sockets).
usrc thttp ': b variable ;  : st variable ;
400 lit alloc b !
"/index.html" 201 lit open dup "<h1>hello from the guest</h1>" dup strlen write drop close drop
400 lit 0 lit do i 3F lit and 30 lit + b @ i + c! loop
"/big" 201 lit open 64 lit 0 lit do dup b @ 400 lit write drop loop close drop
"httpd" spawn drop  st wait drop bye'
sh scripts/mkimage.sh "$T/http.img" bin/kernel init="$T/thttp.bin" httpd=bin/user/httpd 2> "$T/http.mk" || fail httpd "mkimage: $(cat "$T/http.mk")"
python3 -c 'import sys; sys.stdout.buffer.write(bytes(48 + (i & 63) for i in range(1024)) * 100)' > "$T/big.want"
for n in 1 4; do
	N=$((N + 1))
	HP=$((TP + n))
	rm -f "$T/http.disk"; dd if=/dev/zero of="$T/http.disk" bs=1 count=0 seek=268435456 2>/dev/null
	./tools/q32 --smp=$n --net --hostfwd=tcp::$HP-:80 --disk="$T/http.disk" "$T/http.img" < /dev/null > "$T/httpd_$n.out" 2>&1 &
	QP=$!                          # q32 execs QEMU: this is QEMU
	i=0; while [ $i -lt 120 ] && ! grep -q 'httpd: port 80' "$T/httpd_$n.out"; do sleep 0.5; i=$((i + 1)); done
	page=$(curl -s -m 30 "http://127.0.0.1:$HP/")
	curl -s -m 60 -o "$T/big_$n.got" "http://127.0.0.1:$HP/big"
	nf=$(curl -s -m 30 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HP/nosuch")
	ok=0; for j in $(seq 40); do [ "$(curl -s -m 20 "http://127.0.0.1:$HP/index.html")" = "<h1>hello from the guest</h1>" ] && ok=$((ok + 1)); done
	kill $QP 2>/dev/null; wait $QP 2>/dev/null
	[ "$page" = "<h1>hello from the guest</h1>" ] || fail "httpd_$n" "page: $page; $(head -c 300 "$T/httpd_$n.out")"
	cmp -s "$T/big.want" "$T/big_$n.got" || fail "httpd_$n" "100 KiB not whole: $(wc -c < "$T/big_$n.got") bytes"
	[ "$nf" = 404 ] || fail "httpd_$n" "no 404: $nf"
	[ "$ok" = 40 ] || fail "httpd_$n" "$ok of 40 fetches"
done
rm -f "$T/http.disk"

# Terminals (step 10).  A pty: what is typed echoed and edited (backspace),
# the slave reading the line, its newlines shown as CR LF; /dev/tty/0; a
# shell on the slave end running echo, ended by ^D, the master then at its
# end.
usrc tpty ': b variable ;  : fds variable ;  : m variable ;  : sl variable ;  : n variable ;  : st variable ;  : cv variable ;  : path variable ;
: sp  20 lit putc ;
\ show ( n -- )  the bytes at b, control bytes as ^X
: show  0 lit do b @ i + c@ dup 20 lit u< if 5E lit putc 40 lit + then putc loop ;
100 lit alloc b !  10 lit alloc fds !  10 lit alloc cv !  20 lit alloc path !
fds @ pty "pty " puts . sp  fds @ @ m !  fds @ 4 lit + @ sl !
m @ "abx" 3 lit write drop  cv @ 7F lit over c! 63 lit over 1 lit + c! D lit swap 2 lit + c!  m @ cv @ 3 lit write drop
sl @ b @ 100 lit read dup "line " puts . sp show sp
sl @ "out" 3 lit write drop  sl @ cv @ 2 lit + 1 lit write drop  A lit cv @ c!  sl @ cv @ 1 lit write drop
m @ b @ 100 lit read dup "shown " puts . sp show 0A lit putc
path @ "/dev/tty/" scpy 0 lit snum 0 lit swap c!
path @ 2 lit open dup "tty " puts . sp dup "y" 1 lit write drop  dup cv @ 1 lit write drop close drop
m @ b @ 100 lit read dup "via " puts . sp show 0A lit putc
3 lit fds @ !  sl @ fds @ 4 lit + !  sl @ fds @ 8 lit + !  sl @ fds @ C lit + !
"sh" 0 lit fds @ spawnv drop  sl @ close drop
m @ "echo hi" 7 lit write drop  m @ cv @ 2 lit + 1 lit write drop
0 lit n !  begin m @ b @ n @ + 100 lit n @ - read dup 0 lit > if n @ + n ! else drop then n @ 11 lit u< 0= until
"sh: " puts n @ show 0A lit putc
4 lit cv @ c!  m @ cv @ 1 lit write drop  FFFFFFFF lit st wait drop "ended " puts st @ . sp
m @ b @ 100 lit read drop m @ b @ 100 lit read "eof " puts . 0A lit putc
bye'
sh scripts/mkimage.sh "$T/pty.img" bin/kernel init="$T/tpty.bin" sh=bin/user/sh echo=bin/user/echo 2> "$T/pty.mk" || fail pty "mkimage: $(cat "$T/pty.mk")"
for n in 1 4; do
	expect "pty_$n" 124 '^pty 0 line 4 abc^J shown 15 abx^H ^Hc^M^Jout^M^M^J$' 6 ./tools/q32 --smp=$n "$T/pty.img"
	has "pty_$n" '^tty 5 via 3 y^M^J$'
	has "pty_$n" '^sh: .*hi^M^J'
	has "pty_$n" '^ended 0 eof 0$'
done
# Raw mode (tty, call 39), for the editor.  The console: its size not
# known (0), raw: each byte as typed, not echoed (an arrow's escape
# sequence and ^D among them), then lines again with an arrow's sequence
# dropped; a descriptor not open -9.  A pty: its size set and read through
# the other end, raw (not echoed), then lines with an arrow dropped.
usrc traw ': b variable ;
20 lit alloc b !
0 lit 2 lit 0 lit tty "size " puts . 0A lit putc
0 lit 1 lit 1 lit tty "raw " puts . 0A lit putc
0 lit 0 lit 0 lit tty "mode " puts . 0A lit putc
6 lit 0 lit do 0 lit b @ 1 lit read drop b @ c@ . loop 0A lit putc
0 lit 1 lit 0 lit tty drop
"line: " puts 0 lit b @ 20 lit read . b @ c@ . 0A lit putc
9 lit 0 lit 0 lit tty "notty " puts . 0A lit putc
bye'
usrc tpraw ': fds variable ;  : b variable ;  : m variable ;  : s variable ;
: key  b @ c!  m @ b @ 1 lit write drop ;     \ ( c -- )  typed on the terminal
8 lit alloc fds !  40 lit alloc b !
fds @ pty drop  fds @ @ m !  fds @ 4 lit + @ s !
s @ 3 lit 180050 lit tty drop  m @ 2 lit 0 lit tty "size " puts dup 10 lit rshift . FFFF lit and . 0A lit putc
s @ 1 lit 1 lit tty drop  m @ 0 lit 0 lit tty "mode " puts . 0A lit putc
71 lit key  s @ b @ 40 lit read "raw read " puts . b @ c@ . 0A lit putc
s @ 1 lit 0 lit tty drop
61 lit key  1B lit key  5B lit key  41 lit key  7A lit key  D lit key
s @ b @ 40 lit read "line " puts dup . 1 lit b @ rot write drop
m @ b @ 40 lit read "shown " puts . 0A lit putc
bye'
uimage raw bin/kernel init=traw
uimage praw bin/kernel init=tpraw
for n in 1 4; do
	expect "rawcons_$n" 124 '^97982791654$' 8 sh -c '{ sleep 1; printf "ab\033[A\004"; sleep 1; printf "x\033[Dy\n"; sleep 4; } | ./tools/q32 --smp='$n' "$1"' raw "$T/raw.img"
	has "rawcons_$n" '^size 0$'; has "rawcons_$n" '^mode 1$'; has "rawcons_$n" '^3120$'; has "rawcons_$n" '^notty -9$'
	expect "rawpty_$n" 124 '^size 2480$' 5 ./tools/q32 --smp=$n "$T/praw.img"
	has "rawpty_$n" '^mode 1$'; has "rawpty_$n" '^raw read 1113$'; has "rawpty_$n" '^line 3az$'; has "rawpty_$n" '^shown 4$'
done

# The window manager: wm (src/user/wm.fam) serving its page and, over a
# WebSocket, a shell on a terminal, from the host through a forwarded
# port.  The disk's /etc/passwd written first (root's password in plain
# text), wm started from the shell.  Logging in: the login form without a
# session, /tty refused (403), a wrong password sent to /?bad, the right
# one a cookie; then the page, the handshake's key, the prompt, a
# directory made and seen by ls, root's password kept hashed (cat
# /etc/passwd), a ping answered, exit closing it; a second terminal
# closed by logging out, the cookie refused after.  With node 22 or later, the
# desktop page's own script too, on a stub DOM: two terminals from the
# dock, typing (a backspace among it), minimize and restore from the
# taskbar, maximize, exit and the close button each closing a window, then
# thirteen at once (twelve, the last told none is free) and no zombie left;
# escape sequences fed to a window; vi in one (typed, written, the shell's
# screen back after).  The wallet's WebSocket (/wallet, the wallet,
# src/user/wallet.fam, behind it): refused without a session; with one,
# wm's unlock answered, a request answered with its id, and logging out
# closing it; on the page, its window from the dock (no wallet yet; one
# created, its words shown; a second click focusing it, not a second
# window), the Receive screen's address, its program ending when its
# window closes.  Files (the home to and from the browser): refused
# without a session; uploaded, listed with its size, downloaded the same,
# deleted; a bad name, a missing file, past 64 KiB refused; 40 KiB taken;
# on the page, its window from the dock, a file uploaded through its
# picker (its name made safe) and deleted from its row.
cat > "$T/wsc.py" <<'WSCEOF'
import socket, base64, hashlib, os, sys, time, struct
port = int(sys.argv[1])
G = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
def http(req):
    c = socket.create_connection(("127.0.0.1", port), timeout=60)
    c.sendall(req); body = b""
    while True:
        d = c.recv(65536)
        if not d: break
        body += d
    return body
def post(path, form, cookie=b""):
    return http(b"POST " + path + b" HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + str(len(form)).encode() + b"\r\n" + cookie + b"\r\n" + form)
def wsopen(cookie, path=b"/tty"):
    c = socket.create_connection(("127.0.0.1", port), timeout=30)
    key = base64.b64encode(os.urandom(16))
    c.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" + cookie + b"Sec-WebSocket-Key: " + key + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    h = b""
    while b"\r\n\r\n" not in h:
        d = c.recv(1)
        if not d: break
        h += d
    return c, h, base64.b64encode(hashlib.sha1(key + G).digest())
body = http(b"GET / HTTP/1.0\r\n\r\n")
print("login form", body.split(b"\r\n")[0].decode(), b"action=/login" in body and b"new WebSocket" not in body)
c0, h0, _ = wsopen(b""); print("tty refused", h0.split(b"\r\n")[0].decode())
bad = post(b"/login", b"name=root&password=nope")
print("bad", b"Location: /?bad" in bad and b"Set-Cookie" not in bad)
good = post(b"/login", b"name=root&password=wm%21pw")
ck = [l for l in good.split(b"\r\n") if l.startswith(b"Set-Cookie: wm=")]
cookie = b"Cookie: " + ck[0][12:].split(b";")[0] + b"\r\n" if ck else b""
print("cookie", len(cookie) == 8 + 3 + 32 + 2)
body = http(b"GET / HTTP/1.0\r\n" + cookie + b"\r\n")
print("page", body.split(b"\r\n")[0].decode(), b"new WebSocket" in body)
s, h, want = wsopen(cookie)
print("upgrade", h.split(b"\r\n")[0].decode(), (b"Sec-WebSocket-Accept: " + want) in h)
buf = b""; out = b""; closed = False
def send(data, op=2):
    m = os.urandom(4); n = len(data)
    hdr = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0xFE]) + struct.pack(">H", n))
    s.sendall(hdr + m + bytes(b ^ m[i & 3] for i, b in enumerate(data)))
def pump(until, secs=30):
    global buf, out, closed
    end = time.time() + secs
    while until not in out and time.time() < end and not closed:
        try: d = s.recv(65536)
        except socket.timeout: continue
        if not d: closed = True; break
        buf += d
        while len(buf) >= 2:
            n = buf[1] & 127; hl = 2
            if n == 126:
                if len(buf) < 4: break
                n = struct.unpack(">H", buf[2:4])[0]; hl = 4
            if len(buf) < hl + n: break
            op = buf[0] & 15; p = buf[hl:hl + n]; buf = buf[hl + n:]
            if op == 8: closed = True; out += b"[close]"
            elif op == 10: out += b"[pong:" + p + b"]"
            else: out += p
    return until in out
print("prompt", pump(b"$ "))
send(b"mkdir /d\r")
pump(b"$ mkdir"); out = b""
send(b"ls /\r"); ok = pump(b"d/\r\n")
print("ls", ok, repr(out[-60:]))
out = b""; send(b"cat /etc/passwd\r"); print("hashed", pump(b":0:0:/:sh") and b"root:$p5$4e20$" in out)
send(b"hi", 9); print("ping", pump(b"[pong:hi]"))
send(b"exit\r"); print("exit", pump(b"[close]"))
# logging out closes a terminal of the session; the cookie is no good after
s, h, want = wsopen(cookie); buf = b""; out = b""; closed = False
pump(b"$ ")
lo = post(b"/logout", b"", cookie)
print("logout", b"Location: /" in lo and pump(b"[close]", 30))
c2, h2, _ = wsopen(cookie); print("after", h2.split(b"\r\n")[0].decode())
# the wallet: refused without a session; with one, its answer to wm's
# unlock, a request answered with its id; logging out closes it
c3, h3, _ = wsopen(b"", b"/wallet"); print("wallet refused", h3.split(b"\r\n")[0].decode())
good = post(b"/login", b"name=root&password=wm%21pw")
ck = [l for l in good.split(b"\r\n") if l.startswith(b"Set-Cookie: wm=")]
cookie = b"Cookie: " + ck[0][12:].split(b";")[0] + b"\r\n" if ck else b""
s, h, want = wsopen(cookie, b"/wallet"); buf = b""; out = b""; closed = False
print("wallet upgrade", h.split(b"\r\n")[0].decode(), (b"Sec-WebSocket-Accept: " + want) in h)
print("unlock", pump(b'{"op":"unlock","ok":true'))
out = b""; send(b'{"op":"overview","id":7}', 1)
print("overview", pump(b'"}') and out.startswith(b'{"id":7,"ok":'))
lo = post(b"/logout", b"", cookie)
print("wallet logout", b"Location: /" in lo and pump(b"[close]", 30))
# Files: the home to and from the browser (the session's cookie needed);
# names checked; 64 KiB at most; uploaded, listed, downloaded, deleted
import json
def req(method, path, body=b"", ck=b""):
    r = http(method + b" " + path + b" HTTP/1.0\r\n" + ck + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    head, _, rest = r.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]) if head.startswith(b"HTTP/") else 0, rest
print("files refused", req(b"GET", b"/files")[0])
good = post(b"/login", b"name=root&password=wm%21pw")
ck = [l for l in good.split(b"\r\n") if l.startswith(b"Set-Cookie: wm=")]
cookie = b"Cookie: " + ck[0][12:].split(b";")[0] + b"\r\n" if ck else b""
data = os.urandom(300)
st, b = req(b"POST", b"/files?name=t1.slate", data, cookie)
print("files upload", st == 200 and json.loads(b)["ok"])
st, b = req(b"GET", b"/files", b"", cookie)
ls = json.loads(b)["files"] if st == 200 else []
print("files list", any(f["name"] == "t1.slate" and f["size"] == 300 for f in ls) and not any(f["name"].startswith(".") for f in ls))
st, b = req(b"GET", b"/files?name=t1.slate", b"", cookie)
print("files download", st == 200 and b == data)
print("files bad name", req(b"POST", b"/files?name=.x", b"a", cookie)[0] == 400 and req(b"GET", b"/files?name=a/b", b"", cookie)[0] == 400)
print("files missing", req(b"GET", b"/files?name=nope", b"", cookie)[0] == 404)
big = os.urandom(40960)
st, b = req(b"POST", b"/files?name=big.bin", big, cookie)
st2, b2 = req(b"GET", b"/files?name=big.bin", b"", cookie)
print("files big", st == 200 and st2 == 200 and b2 == big)
c = socket.create_connection(("127.0.0.1", port), timeout=60)
c.sendall(b"POST /files?name=huge.bin HTTP/1.0\r\n" + cookie + b"Content-Length: 70000\r\n\r\n")
r = b""
while True:
    d = c.recv(65536)
    if not d: break
    r += d
print("files too large", r.split(b"\r\n")[0] == b"HTTP/1.0 413 Payload Too Large")
st, b = req(b"DELETE", b"/files?name=t1.slate", b"", cookie)
st2, b2 = req(b"GET", b"/files", b"", cookie)
print("files delete", st == 200 and st2 == 200 and not any(f["name"] == "t1.slate" for f in json.loads(b2)["files"]))
req(b"DELETE", b"/files?name=big.bin", b"", cookie)
WSCEOF
cat > "$T/page.js" <<'PAGEEOF'
// Run the page wm serves: its script, with a small stub DOM; the dock's
// terminal button clicked, keys typed as a browser would.
const port = process.argv[2];
(async () => {
  const lr = await fetch(`http://127.0.0.1:${port}/login`, { method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'name=root&password=wm%21pw' });
  const cookie = (lr.headers.get('set-cookie') || '').split(';')[0];
  const html = await (await fetch(`http://127.0.0.1:${port}/`, { headers: { Cookie: cookie } })).text();
  const js = html.split('<script>')[1].split('</script>')[0];
  const byId = {};
  class El {
    constructor(tag) { this.tag = tag; this.kids = []; this.parent = null; this.style = {}; this.textContent = ''; this.innerHTML = ''; this.className = '';
      this.scrollTop = 0; this.clientHeight = 0; this.scrollHeight = 0; this.offsetLeft = 0; this.offsetTop = 0; this.ls = {};
      const self = this;
      this.classList = {
        has: (c) => self.className.split(' ').includes(c),
        add: (c) => { if (!self.classList.has(c)) self.className = (self.className + ' ' + c).trim(); },
        remove: (c) => { self.className = self.className.split(' ').filter((x) => x && x !== c).join(' '); },
        contains: (c) => self.classList.has(c),
        toggle: (c) => { if (self.classList.has(c)) self.classList.remove(c); else self.classList.add(c); },
      };
    }
    appendChild(e) { e.parent = this; this.kids.push(e); return e; }
    remove() { if (this.parent) this.parent.kids = this.parent.kids.filter((k) => k !== this); this.parent = null; }
    addEventListener(t, f) { this.ls[t] = f; }
    focus() { if (doc.active !== this) { doc.active = this; if (this.onfocus) this.onfocus(); } }
  }
  const doc = { active: null, createElement: (t) => new El(t), addEventListener() {}, removeEventListener() {},
    getElementById: (id) => byId[id] || (byId[id] = new El('div')) };
  globalThis.document = doc;
  globalThis.window = globalThis;
  const WSS = []; const RW = globalThis.WebSocket; globalThis.WebSocket = class extends RW { constructor(u) { super(u, { headers: { Cookie: cookie } }); WSS.push(this); } };
  globalThis.location = { protocol: 'http:', host: `127.0.0.1:${port}` };
  // the page's fetches (Files) relative to wm, with the session's cookie
  const RF = globalThis.fetch;
  globalThis.fetch = (u, o = {}) => RF(u.startsWith('/') ? `http://127.0.0.1:${port}${u}` : u, { ...o, headers: { ...(o.headers || {}), Cookie: cookie } });
  new Function(js)();
  const all = (e, c, out = []) => { if (e.classList && e.classList.has(c)) out.push(e); e.kids.forEach((k) => all(k, c, out)); return out; };
  const desk = byId.desk, tasks = byId.tasks;
  const key = (t, k, ctrl) => t.onkeydown({ key: k, ctrlKey: !!ctrl, metaKey: false, altKey: false, preventDefault() {} });
  const type = (t, s) => { for (const ch of s) key(t, ch === '\r' ? 'Enter' : ch); };
  const wait = (f, ms) => new Promise((ok) => { const end = Date.now() + ms; const iv = setInterval(() => { if (f() || Date.now() > end) { clearInterval(iv); ok(!!f()); } }, 50); });
  const prompt = /\$ █$/;

  byId.newt.onclick(); byId.newt.onclick();
  const wins = all(desk, 'win'), terms = all(desk, 'term');
  console.log('windows', wins.length === 2 && all(tasks, 'task').length === 2);
  const [t1, t2] = terms;
  console.log('prompt', await wait(() => prompt.test(t1.plain) && prompt.test(t2.plain), 60000));
  console.log('focused', doc.active === t2 && wins[0].classList.has('off') && !wins[1].classList.has('off'));
  type(t2, 'mkdir /e\r'); await wait(() => /mkdir \/e\n\$ █$/.test(t2.plain), 60000);
  type(t2, 'ls /x'); key(t2, 'Backspace'); type(t2, '\r');
  console.log('ls', await wait(() => /e\/\netc\/\ndev\/\nproc\/\n\$ █$/.test(t2.plain), 60000) && !/ls/.test(t1.plain));
  // the second minimized from its button: hidden, the first focused; restored from the taskbar
  all(wins[1], 'wb')[0].onclick({ stopPropagation() {} });
  const k2 = all(tasks, 'task')[1];
  console.log('minimize', wins[1].style.display === 'none' && k2.classList.has('min') && doc.active === t1);
  k2.onclick();
  console.log('restore', wins[1].style.display === 'flex' && !k2.classList.has('min') && doc.active === t2);
  all(wins[1], 'wb')[1].onclick({ stopPropagation() {} });
  console.log('maximize', wins[1].classList.has('max'));
  // exit closes the shell's window and its taskbar button
  type(t1, 'exit\r');
  console.log('exit', await wait(() => all(desk, 'win').length === 1 && all(tasks, 'task').length === 1, 60000));
  // the close button
  all(wins[1], 'wb')[2].onclick({ stopPropagation() {} });
  console.log('closed', all(desk, 'win').length === 0 && all(tasks, 'task').length === 0);
  console.log(JSON.stringify(t2.plain));
  // the emulator: escape sequences fed to the first window's terminal
  const E = String.fromCharCode(27), feedw = (ws, s) => ws.onmessage({ data: new TextEncoder().encode(s).buffer });
  feedw(WSS[0], E + '[2J' + E + '[H' + 'top' + E + '[3;5HX' + E + '[1;2H' + E + '[K');
  await new Promise((r) => setTimeout(r, 100));
  const scr = t1.plain.split(String.fromCharCode(10));
  console.log('ansi', scr[0] === 't█' && scr[2] === '    X');
  feedw(WSS[0], E + '[?1049h' + E + '[Halt' + E + '[31mred' + E + '[0m');
  await new Promise((r) => setTimeout(r, 100));
  const alt = t1.plain;
  feedw(WSS[0], E + '[?1049l');
  await new Promise((r) => setTimeout(r, 100));
  console.log('altscreen', alt.startsWith('altred') && !/X/.test(alt) && t1.plain.split(String.fromCharCode(10))[2] === '    X');
  // thirteen at once: twelve terminals (wm's limit), the last told none is
  // free; all closed, the shells reaped (none left a zombie in ps)
  for (let i = 0; i < 13; i++) byId.newt.onclick();
  const ts = () => all(desk, 'term');
  console.log('full', await wait(() => ts().filter((t) => prompt.test(t.plain)).length === 12 && ts().filter((t) => /none free/.test(t.plain)).length === 1, 60000));
  all(desk, 'win').forEach((w) => all(w, 'wb')[2].onclick({ stopPropagation() {} }));
  // a new window, once the server has freed the slots of those closed (a
  // window told none is free closed and opened again), a minute at most
  let t3 = null;
  for (let k = 0; k < 60 && !t3; k++) {
    byId.newt.onclick(); const t = ts()[ts().length - 1];
    await wait(() => prompt.test(t.plain) || /none free/.test(t.plain), 20000);
    if (prompt.test(t.plain)) t3 = t;
    else { all(desk, 'win').forEach((w) => all(w, 'wb')[2].onclick({ stopPropagation() {} })); await new Promise((r) => setTimeout(r, 1000)); }
  }
  console.log('reopened', !!t3);
  // ps until the closed shells are gone (each ends when its window closes;
  // a slow machine takes longer), a minute at most
  let reaped = false;
  const heads = () => (t3.plain.match(/CMD/g) || []).length;
  let last = '';
  for (let k = 0; k < 60 && !reaped; k++) {
    const n0 = heads(); type(t3, 'ps\r');
    await wait(() => heads() > n0 && prompt.test(t3.plain), 20000);
    last = t3.plain.slice(t3.plain.lastIndexOf('CMD'));
    // one shell left (its runas above it, wm's way of running it as the user)
    reaped = !/ Z /.test(last) && (last.match(/^(?!.*runas).* sh$/gm) || []).length === 1;
    if (!reaped) await new Promise((r) => setTimeout(r, 1000));
  }
  console.log('reaped', reaped);
  if (!reaped) console.log(JSON.stringify(last));
  // vi in a window: its screen (the alternate one), typed and written, the
  // shell's screen back as it was when it quits, the file as typed
  type(t3, 'vi /v.txt\r'); console.log('vi', await wait(() => /\[New\]/.test(t3.plain), 60000));
  type(t3, 'ihi there'); key(t3, 'Escape'); type(t3, ':wq\r');
  console.log('vi back', await wait(() => /\$ vi \/v\.txt\n\$ █$/.test(t3.plain), 60000));
  type(t3, 'cat /v.txt\r'); console.log('vi wrote', await wait(() => /\nhi there\n\$ █$/.test(t3.plain), 60000));
  console.log(JSON.stringify(t3.plain));
  // the wallet: its window from the dock, none yet once wm has unlocked
  // it; one created (its twelve words shown); a second click focuses it
  // (no second window); the Receive screen, its address; closed from its
  // button, its program gone (ps)
  const text = (e) => [e.textContent].concat(e.kids.map(text)).join(' ');
  const wal = () => all(desk, 'wal');
  byId.neww.onclick();
  console.log('wallet', await wait(() => wal().length === 1 && /No wallet yet/.test(text(wal()[0])), 60000));
  all(wal()[0], 'wgo').find((b) => b.textContent === 'Create a wallet').onclick();
  console.log('wallet created', await wait(() => /Write these words down, in order: ([a-z]+ ){11}[a-z]+/.test(text(wal()[0])), 120000));
  const running = () => /wallet$/m.test(t3.plain.slice(t3.plain.lastIndexOf('CMD')));
  { const n0 = heads(); type(t3, 'ps\r'); await wait(() => heads() > n0 && prompt.test(t3.plain), 20000); }
  console.log('wallet running', running());
  t3.focus(); byId.neww.onclick();
  console.log('wallet once', wal().length === 1 && all(tasks, 'task').filter((k) => k.textContent === 'Wallet').length === 1 && doc.active === wal()[0]);
  all(wal()[0], 'wtab')[1].onclick();
  console.log('wallet receive', await wait(() => /Address\s+tab1[02-9ac-hj-np-z]{58}/.test(text(wal()[0])), 60000));
  // phase 2's tabs: Proofs (a proof to check), Names (registering, looking up)
  all(wal()[0], 'wtab')[4].onclick();
  console.log('wallet proofs', await wait(() => /Check a proof/.test(text(wal()[0])), 30000));
  all(wal()[0], 'wtab')[5].onclick();
  console.log('wallet names', await wait(() => /Register a name/.test(text(wal()[0])) && /Look up a name/.test(text(wal()[0])), 30000));
  all(all(desk, 'win').find((d) => all(d, 'wal').length), 'wb')[2].onclick({ stopPropagation() {} });
  console.log('wallet closed', wal().length === 0 && !all(tasks, 'task').some((k) => k.textContent === 'Wallet'));
  let gone = false;
  for (let k = 0; k < 60 && !gone; k++) {
    const n0 = heads(); type(t3, 'ps\r');
    await wait(() => heads() > n0 && prompt.test(t3.plain), 20000);
    gone = !running();
    if (!gone) await new Promise((r) => setTimeout(r, 1000));
  }
  console.log('wallet ended', gone);
  // Files: its window from the dock (once: a second click focuses it); a
  // file uploaded through its picker (the name made safe) and listed;
  // deleted from its row, gone from the listing
  const fil = () => all(desk, 'fil');
  byId.newf.onclick();
  console.log('files window', await wait(() => fil().length === 1 && /Your home/.test(text(fil()[0])), 60000));
  byId.newf.onclick();
  console.log('files once', fil().length === 1 && all(tasks, 'task').filter((k) => k.textContent === 'Files').length === 1);
  const pick = () => { const f = []; const walk = (e) => { if (e.tag === 'input' && e.type === 'file') f.push(e); e.kids.forEach(walk); }; walk(fil()[0]); return f[0]; };
  const inp = pick();
  inp.files = [new File([new Uint8Array([1, 2, 3, 4, 5])], 'my slate.txt')];
  inp.onchange();
  console.log('files uploaded', await wait(() => /my_slate\.txt\s+5 B/.test(text(fil()[0])), 60000));
  const row = (e) => { let r = null; const walk = (x) => { if (x.className === 'wrow' && /my_slate\.txt/.test(text(x))) r = x; x.kids.forEach(walk); }; walk(e); return r; };
  all(row(fil()[0]), 'wgo').find((b) => b.textContent === 'Delete').onclick();
  console.log('files deleted', await wait(() => /Your home/.test(text(fil()[0])) && !/my_slate/.test(text(fil()[0])), 60000));
  process.exit(0);
})();
PAGEEOF
sh scripts/mkimage.sh "$T/wm.img" bin/kernel init=bin/user/sh wm=bin/user/wm runas=bin/user/runas wallet=bin/user/wallet:4096 bip39=../resources/bip39-english.txt:0 sh=bin/user/sh ls=bin/user/ls mkdir=bin/user/mkdir echo=bin/user/echo ps=bin/user/ps vi=bin/user/vi cat=bin/user/cat 2> "$T/wm.mk" || fail wm "mkimage: $(cat "$T/wm.mk")"
for n in 1 4; do
	N=$((N + 1))
	WP=$((TP + 2 + n))
	rm -f "$T/wm.disk"; dd if=/dev/zero of="$T/wm.disk" bs=1 count=0 seek=268435456 2>/dev/null
	rm -f "$T/wm.in"; mkfifo "$T/wm.in"
	./tools/q32 --smp=$n --net --hostfwd=tcp::$WP-:80 --disk="$T/wm.disk" "$T/wm.img" < "$T/wm.in" > "$T/wm_$n.out" 2>&1 &
	QP=$!
	exec 5> "$T/wm.in"
	i=0; while [ $i -lt 120 ] && ! grep -q '[$] ' "$T/wm_$n.out"; do sleep 0.5; i=$((i + 1)); done
	printf '%s\n' 'mkdir /etc' 'echo root:wm!pw:0:0:/:sh > /etc/passwd' 'wm &' >&5
	i=0; while [ $i -lt 120 ] && ! grep -q 'wm: port 80' "$T/wm_$n.out"; do sleep 0.5; i=$((i + 1)); done
	lim 300 python3 "$T/wsc.py" $WP > "$T/wsc_$n.out" 2>&1
	if command -v node > /dev/null && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ]; then
		lim 900 node "$T/page.js" $WP > "$T/page_$n.out" 2>&1
		for pat in '^windows true$' '^prompt true$' '^focused true$' '^ls true$' '^minimize true$' '^restore true$' '^maximize true$' '^exit true$' '^closed true$' '^full true$' '^reopened true$' '^reaped true$' '^ansi true$' '^altscreen true$' '^vi true$' '^vi back true$' '^vi wrote true$' \
			'^wallet true$' '^wallet created true$' '^wallet running true$' '^wallet once true$' '^wallet receive true$' '^wallet proofs true$' '^wallet names true$' '^wallet closed true$' '^wallet ended true$' \
			'^files window true$' '^files once true$' '^files uploaded true$' '^files deleted true$'; do grep -q -- "$pat" "$T/page_$n.out" || fail "wm_$n" "page script: $(head -c 300 "$T/page_$n.out")"; done
	fi
	exec 5>&-; kill $QP 2>/dev/null; wait $QP 2>/dev/null
	for pat in '^login form HTTP/1.0 200 OK True$' '^tty refused HTTP/1.0 403 Forbidden$' '^bad True$' '^cookie True$' \
		'^page HTTP/1.0 200 OK True$' '^upgrade HTTP/1.1 101 Switching Protocols True$' '^prompt True$' '^ls True' '^hashed True$' \
		'^ping True$' '^exit True$' '^logout True$' '^after HTTP/1.0 403 Forbidden$' \
		'^wallet refused HTTP/1.0 403 Forbidden$' '^wallet upgrade HTTP/1.1 101 Switching Protocols True$' '^unlock True$' \
		'^overview True$' '^wallet logout True$' '^files refused 403$' '^files upload True$' '^files list True$' '^files download True$' \
		'^files bad name True$' '^files missing True$' '^files big True$' '^files too large True$' '^files delete True$'; do
		grep -q -- "$pat" "$T/wsc_$n.out" || { fail "wm_$n" "no /$pat/: $(head -c 400 "$T/wsc_$n.out")"; break; }
	done
done
rm -f "$T/wm.disk"
# A session idle past wm's idle time (8 seconds here, `wm 80 8`) ends: a
# terminal left untouched closed by wm, the cookie refused after.
cat > "$T/idle.py" <<'IDLEEOF'
import socket, base64, os, sys, time
port = int(sys.argv[1])
def http(req):
    c = socket.create_connection(("127.0.0.1", port), timeout=60); c.sendall(req); b = b""
    while True:
        d = c.recv(65536)
        if not d: break
        b += d
    return b
f = b"name=root&password=pw"
g = http(b"POST /login HTTP/1.0\r\nContent-Length: " + str(len(f)).encode() + b"\r\n\r\n" + f)
ck = [l for l in g.split(b"\r\n") if l.startswith(b"Set-Cookie: wm=")]
cookie = b"Cookie: " + ck[0][12:].split(b";")[0] + b"\r\n" if ck else b""
def ws():
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    c.sendall(b"GET /tty HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" + cookie + b"Sec-WebSocket-Key: " + base64.b64encode(os.urandom(16)) + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    return c
s = ws(); t0 = time.time(); got = b""; closed = False
# nothing typed: wm closes it once the session is idle (the frames shown,
# the close or the end of the connection the sign), within a minute
while time.time() < t0 + 60 and not closed:
    try: d = s.recv(4096)
    except socket.timeout: continue
    if not d: closed = True
    got += d
    if b"\x88" in got.split(b"$ ", 1)[-1]: closed = True
print("idle", closed and time.time() - t0 >= 8, round(time.time() - t0))
h = ws().recv(200); print("after", h.split(b"\r\n")[0].decode())
IDLEEOF
N=$((N + 1))
WP=$((TP + 7))
rm -f "$T/wm.disk" "$T/wm.in"; dd if=/dev/zero of="$T/wm.disk" bs=1 count=0 seek=268435456 2>/dev/null; mkfifo "$T/wm.in"
./tools/q32 --net --hostfwd=tcp::$WP-:80 --disk="$T/wm.disk" "$T/wm.img" < "$T/wm.in" > "$T/wm_idle.out" 2>&1 &
QP=$!
exec 5> "$T/wm.in"
i=0; while [ $i -lt 120 ] && ! grep -q '[$] ' "$T/wm_idle.out"; do sleep 0.5; i=$((i + 1)); done
printf '%s\n' 'mkdir /etc' 'echo root:pw:0:0:/:sh > /etc/passwd' 'wm 80 8 &' >&5
i=0; while [ $i -lt 120 ] && ! grep -q 'wm: port 80' "$T/wm_idle.out"; do sleep 0.5; i=$((i + 1)); done
lim 300 python3 "$T/idle.py" $WP > "$T/idle.out" 2>&1
exec 5>&-; kill $QP 2>/dev/null; wait $QP 2>/dev/null
for pat in '^idle True' '^after HTTP/1.0 403 Forbidden$'; do grep -q -- "$pat" "$T/idle.out" || { fail wm_idle "no /$pat/: $(head -c 400 "$T/idle.out")"; break; }; done
rm -f "$T/wm.disk"

scripts/makenode.sh --disk="$T/disk.img" > /dev/null
boots boot_disk 'init: starting the shell' 60 scripts/node.sh --disk="$T/disk.img" --no-seeds
grep -q 'tabernacle: from disk' "$T/boot_disk.out" \
	|| fail boot_disk "not from disk: $(head -c 300 "$T/boot_disk.out")"
boots boot_disk_64 'kernel: 64 harts' 120 scripts/node.sh --disk="$T/disk.img" --no-seeds --smp=64
rm -f "$T/disk.img"

echo "$((N - FAILS)) of $N checks passed"
[ "$FAILS" = 0 ]
