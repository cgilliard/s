#!/bin/sh
# build.sh — rebuild the fam compiler from the 168-byte seed under QEMU (fam0,
# checked against the seed, then fam and fampack), then gen_hash, the node
# image (the OS: the kernel, src/kernel.fam, src/store.fam, src/net.fam and src/ksys.fam, src/boot.fam, and the
# programs in src/user, put together by scripts/mkimage.sh) and tabernacle,
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
for prog in src/user/*.fam; do
	name=$(basename "$prog" .fam)
	echo "Building $prog → bin/user/$name (user mode)" >&2
	./tools/fam --user -o "bin/user/$name" "$prog" || { echo "build.sh: $prog did not build" >&2; exit 1; }
	progs="$progs $name=bin/user/$name"
done
# The compiler too (famc: bin/fam, unpacked and unchanged, as a machine
# program with 8 MiB: the kernel stands in for its UART and test finisher),
# and the libraries it compiles a program with (data files, read as
# /lib/<name>: docs/OS.md, step 11).
# Its version, which the node serves it as (/lib/version, in decimal).
printf '%s\n' "$IMAGE_VERSION" > bin/version
progs="$progs famc=bin/fam.uncompressed:8192:m stdlib.fam=lib/stdlib.fam:0 user.fam=lib/user.fam:0 build.fam=lib/build.fam:0"
progs="$progs version=bin/version:0"
sh scripts/mkimage.sh bin/img bin/kernel $progs
run bin/tabernacle.uncompressed bin/fam0 src/tabernacle.fam0
patch_config bin/tabernacle.uncompressed bin/img "$IMAGE_VERSION"
pack bin/tabernacle.uncompressed bin/tabernacle
