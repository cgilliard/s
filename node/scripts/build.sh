#!/bin/sh
# build.sh — rebuild the fam compiler from the 168-byte seed under QEMU (fam0,
# checked against the seed, then fam and fampack).  Linux and macOS (on
# Windows, WSL2), as tools/q32.
set -e

CPU="rv32,zicsr=true,m=false,a=false,f=false,d=false,c=false,\
zawrs=false,zfa=false,zfh=false,zfhmin=false,zcb=false,\
zcd=false,zcf=false,zcmp=false,zcmt=false,zifencei=false"
MEM="128M"    # the virt default; lib/stdlib.fam's init lays the stacks out for exactly this

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

run bin/fam0 fam0.seed src/fam0.fam0
cmp ./bin/fam0 ./fam0.seed
run bin/fam.uncompressed bin/fam0 src/fam.fam0
run bin/fampack bin/fam.uncompressed lib/stdlib.fam lib/asm.fam src/fampack.fam
pack bin/fam.uncompressed bin/fam
