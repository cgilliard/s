#!/bin/sh
# slow: one job each in .github/workflows/test.yml (node-slow).
# storetest.sh — the store's checks (docs/OS.md, step 8): src/storetest.fam
# (after the kernel: src/kernel.fam, src/store.fam, src/ksys.fam) on a bare
# machine, on one disk file in tmp/: a new store and its checks; the same
# store found again and checked as the first run left it; then six times,
# QEMU killed while the store commits as fast as it can, and the store
# found holding the last commit whole.  Exits 0 when every run passes.
# Linux and macOS.
#
# Usage: storetest.sh [--size=BYTES]  the disk's size (default 256 MiB;
# sparse, so 26843545600, the node's 25 GB, costs no more).

cd "$(dirname "$0")/.." || exit 1
CPU="rv32,zicsr=true,m=false,a=false,f=false,d=false,c=false,\
zawrs=false,zfa=false,zfh=false,zfhmin=false,zcb=false,\
zcd=false,zcf=false,zcmp=false,zcmt=false,zifencei=false"
SIZE=268435456
for arg in "$@"; do
	case "$arg" in
		--size=*) SIZE="${arg#--size=}" ;;
		*) echo "storetest.sh: unknown argument: $arg" >&2; exit 1 ;;
	esac
done
mkdir -p tmp
DISK=tmp/storetest.img
rm -f "$DISK"
dd if=/dev/zero of="$DISK" bs=1 count=0 seek="$SIZE" 2>/dev/null || exit 1
trap 'rm -f "$DISK" tmp/storetest_*.fam tmp/storetest_*.bin' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

for m in 0 1 2 3; do
	sed "s/^RUN /$m lit /" src/storetest.fam > tmp/storetest_$m.fam
	./tools/fam -o tmp/storetest_$m.bin src/kernel.fam src/store.fam src/net.fam src/ksys.fam tmp/storetest_$m.fam || exit 1
done

# killafter SECS CMD... — CMD, killed (SIGKILL, exit 137) after SECS, which
# may have a fraction.  Perl, as macOS has no `timeout`.
killafter() {
	perl -MTime::HiRes=alarm -e '
		$t = shift;
		$p = fork // die "fork: $!";
		if (!$p) { exec @ARGV or die "exec: $!" }
		$SIG{ALRM} = sub { kill "KILL", $p; waitpid($p, 0); exit 137 };
		alarm $t;
		waitpid($p, 0);
		exit($? & 127 ? 128 + ($? & 127) : $? >> 8);
	' "$@"
}

# run MODE [SECONDS] — the test in that mode; killed (as a power cut would)
# after SECONDS if given.
run() {
	killafter "${2:-300}" qemu-system-riscv32 -machine virt -m 128M -cpu "$CPU" -nographic -bios none \
		-global virtio-mmio.force-legacy=true \
		-device loader,file=tmp/storetest_$1.bin,addr=0x80000000 \
		-drive file="$DISK",format=raw,if=none,id=d0 \
		-device virtio-blk-device,drive=d0 \
		-serial stdio -monitor none < /dev/null
}
run 1 || exit 1
run 0 || exit 1
for t in 1.3 1.9 2.6 3.2 3.9 4.7; do
	run 2 "$t"; echo
	run 3 || exit 1
done
