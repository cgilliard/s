#!/bin/sh
# build.sh — rebuild the fam compiler from the 168-byte seed under QEMU (fam0,
# checked against the seed, then fam and fampack), then gen_hash, the node
# image (the OS: the kernel, src/kernel.fam, src/store.fam, src/net.fam and src/ksys.fam, src/boot.fam, and the
# programs in src/user and the node, src/user/node, put together by scripts/mkimage.sh) and tabernacle,
# patched for that image (docs/TABERNACLE.md).  Linux and macOS (on Windows, WSL2), as
# tools/q32.
# Runs from anywhere: it works in the tree it belongs to.
set -e
cd "$(dirname "$0")/.."
# The temporary files (a compile's input, <out>.in.$$; gen_hash's and the
# patch's, <tab>.gh*.$$ and .new.$$) sit next to their outputs in bin/, and
# go however the build ends: Ctrl-C, a closed terminal and kill included.
trap 'rm -f bin/*.$$' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

. scripts/buildlib.sh
IMAGE_VERSION=0   # the node image's version, patched into tabernacle and
                  # carried in the image as /lib/version (docs/NODE.md, step 9)

run() {
	out=$1; asm=$2; shift 2
	disk_args=""; disk=""
	if [ "$1" = "--disk" ]; then
		disk=$2
		disk_args="-drive file=$disk,format=raw,if=none,id=hd0 \
-device virtio-blk-device,drive=hd0"
		shift 2
	fi
	[ $# -gt 0 ] && echo "Building $* → $out" >&2
	stream="$out.in.$$"
	([ $# -gt 0 ] && cat "$@"; printf '\004') > "$stream"
	serial_qemu "$stream" "$out" \
		-device loader,file="$asm",addr=0x80000000 \
		$disk_args
	rm -f "$stream"
	# A compile error leaves the compiler's message, not a program (whose
	# first word is the q32 magic; fam0 alone, the seed's own, has none):
	# stop here rather than build on it.
	if [ $# -gt 0 ] && [ "$out" != bin/fam0 ] && [ "$(head -c 4 "$out" | od -An -tx1 | tr -d ' \n')" != "13000000" ]; then
		echo "build.sh: $out: compile error: $(head -c 80 "$out" | tr -d '\0')" >&2
		exit 1
	fi
}

run bin/fam0 fam0.seed src/fam0.fam0
cmp ./bin/fam0 ./fam0.seed
run bin/fam.uncompressed bin/fam0 src/fam.fam0
run bin/fampack bin/fam.uncompressed lib/stdlib.fam lib/mach.fam lib/asm.fam src/fampack.fam
pack bin/fam.uncompressed bin/fam
run bin/gen_hash bin/fam lib/stdlib.fam lib/mach.fam lib/asm.fam src/gen_hash.fam
run bin/kernel bin/fam lib/stdlib.fam lib/mach.fam lib/build.fam src/kernel.fam src/store.fam src/net.fam src/ksys.fam src/boot.fam
mkdir -p bin/user
progs=""
# A program may name modules of src/user/ it needs, before its own code,
# in lines "\ uses: crypto/sha512.fam" (src/user/crypto/: SHA-512, HMAC,
# PBKDF2); and its memory to start with, in KiB, in a line
# "\ memory: 4096" (64 unless given).
for prog in src/user/*.fam; do
	name=$(basename "$prog" .fam)
	uses=$(sed -n 's|^\\ uses: *||p' "$prog" | tr ' ' '\n' | sed '/^$/d; s|^|src/user/|' | tr '\n' ' ')
	echo "Building $prog → bin/user/$name (user mode)" >&2
	./tools/fam --user -o "bin/user/$name" $uses "$prog" || { echo "build.sh: $prog did not build" >&2; exit 1; }
	mem=$(sed -n 's|^\\ memory: *\([0-9]*\).*|\1|p' "$prog" | head -1)
	progs="$progs $name=bin/user/$name${mem:+:$mem}"
done
# The node (docs/NODE.md): its modules in order, then its main, as one
# program with 24 MiB to start; and the data files it reads: the seed text
# as shipped (the proof of work reads it whole), the chain verifier and
# the network's constants and genesis.  The recursive dev network's for
# now: there is no mainnet chain yet.
N=src/user/node
echo "Building $N → bin/user/node (user mode)" >&2
./tools/fam --user -o bin/user/node src/user/crypto/sha256.fam $N/arith.fam $N/poseidon2.fam $N/difficulty.fam $N/pow.fam $N/headers.fam \
	$N/chainver.fam $N/state.fam $N/proofs.fam $N/manifest.fam $N/connect.fam $N/query.fam $N/serve.fam $N/snap.fam $N/xmss.fam $N/tx.fam \
	$N/wkeys.fam $N/events.fam $N/pool.fam $N/p2p.fam $N/cons.fam $N/api.fam $N/sync.fam $N/dns.fam $N/main.fam || { echo "build.sh: the node did not build" >&2; exit 1; }
# nodev, its verifier: a process of its own (src/user/node/vmain.fam).
echo "Building $N/vmain.fam → bin/user/nodev (user mode)" >&2
./tools/fam --user -o bin/user/nodev $N/arith.fam $N/poseidon2.fam $N/difficulty.fam $N/pow.fam $N/chainver.fam \
	$N/vmain.fam || { echo "build.sh: nodev did not build" >&2; exit 1; }
progs="$progs node=bin/user/node:24576 nodev=bin/user/nodev:8192 akjv.txt.gz=../resources/akjv.txt.gz:0 chainver=$N/chainver.bin:0 chainverdev=$N/chainver_dev.bin:0 netmain=$N/net_main.bin:0 netdevrec=$N/net_devrec.bin:0"
# The compiler too (famc: bin/fam, unpacked and unchanged, as a machine
# program with 8 MiB: the kernel stands in for its UART and test finisher),
# and the libraries it compiles a program with (data files, read as
# /lib/<name>: docs/OS.md, step 11).
# Its version, which the node serves it as (/lib/version, in decimal), and
# BIP39's word list (/lib/bip39: the wallet's phrases).
printf '%s\n' "$IMAGE_VERSION" > bin/version
progs="$progs famc=bin/fam.uncompressed:8192:m stdlib.fam=lib/stdlib.fam:0 user.fam=lib/user.fam:0 build.fam=lib/build.fam:0"
progs="$progs version=bin/version:0 bip39=../resources/bip39-english.txt:0"
sh scripts/mkimage.sh bin/img bin/kernel $progs
run bin/tabernacle.uncompressed bin/fam0 src/tabernacle.fam0
patch_config bin/tabernacle.uncompressed bin/img "$IMAGE_VERSION"
pack bin/tabernacle.uncompressed bin/tabernacle
