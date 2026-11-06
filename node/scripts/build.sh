#!/bin/sh
set -e

CPU="rv32,zicsr=true,m=false,a=false,f=false,d=false,c=false,\
zawrs=false,zfa=false,zfh=false,zfhmin=false,zcb=false,\
zcd=false,zcf=false,zcmp=false,zcmt=false,zifencei=false"
MEM="128M"    # the virt default; lib/stdlib.fam's init lays the stacks out for exactly this
STEP_LIMIT=${STEP_LIMIT:-300}  # seconds a socket-serial step may take
calls=0

serial_qemu() {  # serial_qemu INFILE OUTFILE [extra qemu args...]
	sin=$1; sout=$2; shift 2
	sock=0
	case "$(uname -s)" in MINGW*|MSYS*) sock=1 ;; esac
	[ "$FAM_SERIAL" = "socket" ] && sock=1
	if [ "$sock" = 1 ]; then
		# A fresh port each step: reusing the last one's, on Windows, risks
		# a connection that never comes.
		calls=$((calls + 1))
		port=$((20000 + ($$ * 8 + calls) % 20000))
		qemu-system-riscv32 \
			-machine virt -m "$MEM" -cpu "$CPU" \
			-display none -bios none \
			-chardev socket,id=ser0,host=127.0.0.1,port=$port,server=on,wait=on \
			-serial chardev:ser0 \
			"$@" &
		qpid=$!
		# A step takes seconds; a stuck one is killed with what it got,
		# rather than holding the build until the CI's timeout.
		# (A polling loop, which ends with qemu: no sleeper left behind.)
		( t=0
		  while kill -0 $qpid 2>/dev/null; do
			sleep 1; t=$((t + 1))
			if [ "$t" -ge "$STEP_LIMIT" ]; then
				echo "build.sh: qemu still running after ${STEP_LIMIT}s, killed ($(fsize "$sout" 2>/dev/null || echo 0) bytes out)" >&2
				kill $qpid 2>/dev/null
				exit 1
			fi
		  done ) &
		dog=$!
		if ! tools/serial_pump "$port" "$sin" "$sout"; then
			kill $qpid 2>/dev/null
			wait $dog 2>/dev/null
			exit 1
		fi
		# QEMU exits 0 on SIGTERM: the watchdog's status says it was killed.
		status=0
		wait $qpid || status=$?
		wait $dog || exit 1
		[ "$status" = 0 ] || { echo "build.sh: qemu exited $status" >&2; exit 1; }
	else
		qemu-system-riscv32 \
			-machine virt -m "$MEM" -cpu "$CPU" \
			-display none -bios none \
			-chardev file,id=ser0,path="$sout",input-path="$sin" \
			-serial chardev:ser0 \
			"$@"
	fi
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
