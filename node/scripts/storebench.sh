#!/bin/sh
# storebench.sh — the store's benchmark (docs/OS.md, step 2): src/storebench.fam
# on a bare machine, against a fresh 1 GiB disk file in tmp/.  Linux and macOS.
#
# Usage: storebench.sh [--direct]
#   --direct  the disk without the host's page cache (cache=none, O_DIRECT):
#             writes and flushes cost what the host's disk makes them cost.
#             Without it QEMU writes into the host's cache, and the numbers
#             are the store's own, the disk all but free.

cd "$(dirname "$0")/.." || exit 1
CPU="rv32,zicsr=true,m=false,a=false,f=false,d=false,c=false,\
zawrs=false,zfa=false,zfh=false,zfhmin=false,zcb=false,\
zcd=false,zcf=false,zcmp=false,zcmt=false,zifencei=false"
CACHE=writeback
case "$1" in
	--direct) CACHE=none ;;
	"") ;;
	*) echo "Usage: storebench.sh [--direct]" >&2; exit 1 ;;
esac

mkdir -p tmp
./tools/fam -o tmp/storebench.bin src/kernel.fam src/store.fam src/storebench.fam || exit 1
DISK=tmp/storebench.img
rm -f "$DISK"
dd if=/dev/zero of="$DISK" bs=1 count=0 seek=1073741824 2>/dev/null || exit 1
trap 'rm -f "$DISK"' EXIT
echo "disk: cache=$CACHE"
qemu-system-riscv32 -machine virt -m 128M -cpu "$CPU" -nographic -bios none \
	-global virtio-mmio.force-legacy=true \
	-device loader,file=tmp/storebench.bin,addr=0x80000000 \
	-drive file="$DISK",format=raw,if=none,id=d0,cache=$CACHE \
	-device virtio-blk-device,drive=d0 \
	-serial stdio -monitor none
