#!/bin/sh
# build.sh — rebuild the fam compiler from the 168-byte seed under QEMU (fam0,
# checked against the seed, then fam and fampack), then gen_hash, the node
# image (src/img.fam, a placeholder for now) and tabernacle, patched for that
# image (docs/TABERNACLE.md).  Linux and macOS (on Windows, WSL2), as tools/q32.
# Runs from anywhere: it works in the tree it belongs to.
set -e
cd "$(dirname "$0")/.."

CPU="rv32,zicsr=true,m=false,a=false,f=false,d=false,c=false,\
zawrs=false,zfa=false,zfh=false,zfhmin=false,zcb=false,\
zcd=false,zcf=false,zcmp=false,zcmt=false,zifencei=false"
MEM="128M"    # the virt default; lib/stdlib.fam's init lays the stacks out for exactly this
IMAGE_VERSION=0   # the node image's version, patched into tabernacle

serial_qemu() {  # serial_qemu INFILE OUTFILE [extra qemu args...]
	sin=$1; sout=$2; shift 2
	qemu-system-riscv32 \
		-machine virt -m "$MEM" -cpu "$CPU" \
		-display none -bios none \
		-chardev file,id=ser0,path="$sout",input-path="$sin" \
		-serial chardev:ser0 \
		"$@"
}

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
}

# fsize FILE — size in bytes.  Portable: GNU stat spells it `-c %s`, BSD/macOS
# `-f %z`; `wc -c` works everywhere (tr strips BSD wc's leading padding).
fsize() { wc -c < "$1" | tr -d ' \t'; }

# le32 N — N as 4 raw bytes, little-endian.
le32() {
	printf "$(printf '\\%03o' $(($1 & 255)) $((($1 >> 8) & 255)) $((($1 >> 16) & 255)) $((($1 >> 24) & 255)))"
}

pack() {
	in=$1; out=$2
	echo "Packing $in → $out" >&2
	N=$(fsize "$in")
	stream="$out.in.$$"
	{ printf "$(printf '\\%03o' $((N&255)) $(((N>>8)&255)) $(((N>>16)&255)) $(((N>>24)&255)))"
	  cat "$in"
	} > "$stream"
	serial_qemu "$stream" "$out" -device loader,file=bin/fampack,addr=0x80000000
	rm -f "$stream"
}

# patch_config TABERNACLE IMAGE VERSION — the image's version, size and
# Gimli-Hash into the last 40 bytes of TABERNACLE, which src/tabernacle.S
# leaves zero.  gen_hash reads [N (4, LE)] [N bytes] loaded at 0x80800000 and
# prints the digest on the serial port: eight words, each MSB first.
patch_config() {
	tab=$1; image=$2; version=$3
	echo "Patching $tab (version $version: $image)" >&2
	N=$(fsize "$image")
	if [ "$N" -eq 0 ] || [ "$N" -gt 67108864 ]; then
		echo "build.sh: $image is $N bytes; an image is 1 byte to 64 MiB" >&2
		exit 1
	fi
	gin="$tab.ghin.$$"; gout="$tab.ghout.$$"; gnul="$tab.ghnul.$$"; new="$tab.new.$$"
	{ le32 "$N"; cat "$image"; } > "$gin"
	: > "$gnul"
	serial_qemu "$gnul" "$gout" \
		-device loader,file=bin/gen_hash,addr=0x80000000 \
		-device loader,file="$gin",addr=0x80800000,force-raw=on
	HASH=$(cat "$gout")
	rm -f "$gin" "$gout" "$gnul"
	[ "$(echo $HASH | wc -w)" -eq 8 ] || { echo "build.sh: gen_hash failed" >&2; exit 1; }
	S=$(fsize "$tab")
	{
		head -c $((S - 40)) "$tab"
		le32 "$version"
		le32 "$N"
		for word in $HASH; do
			echo "$word" | sed 's/\(..\)\(..\)\(..\)\(..\)/\4\3\2\1/' | xxd -r -p
		done
	} > "$new"
	mv "$new" "$tab"
}

run bin/fam0 fam0.seed src/fam0.fam0
cmp ./bin/fam0 ./fam0.seed
run bin/fam.uncompressed bin/fam0 src/fam.fam0
run bin/fampack bin/fam.uncompressed lib/stdlib.fam lib/asm.fam src/fampack.fam
pack bin/fam.uncompressed bin/fam
run bin/gen_hash bin/fam lib/stdlib.fam lib/asm.fam src/gen_hash.fam
run bin/img bin/fam lib/stdlib.fam src/img.fam
run bin/tabernacle.uncompressed bin/fam0 src/tabernacle.fam0
patch_config bin/tabernacle.uncompressed bin/img "$IMAGE_VERSION"
pack bin/tabernacle.uncompressed bin/tabernacle
