#!/bin/sh
# node.sh — run a node: tabernacle (docs/TABERNACLE.md) under QEMU, with the
# disk it boots the image from and user-mode networking for fetching it.
# Linux and macOS (on Windows, WSL2), as tools/q32.
#
# Usage: node.sh [--disk=FILE] [--seed=IP:PORT ...] [--mac=ADDR]
#                [--hostfwd=SPEC] TABERNACLE
#   --disk=FILE     the disk (default node.img), created empty if missing
#   --seed=IP:PORT  a seed (repeatable; IPv4).  10.0.2.2 is this host.
#   --mac=ADDR      the virtio-net MAC (give each node on a host its own)
#   --hostfwd=SPEC  expose a guest port, e.g. udp::3737-:3737
#
# The seeds go to tabernacle as a small file loaded at 0x87FFF000: a count
# byte, then 4 address bytes and a port (u16 LE) each.

CPU="rv32,zicsr=true,m=false,a=false,f=false,d=false,c=false,\
zawrs=false,zfa=false,zfh=false,zfhmin=false,zcb=false,\
zcd=false,zcf=false,zcmp=false,zcmt=false,zifencei=false"
DISK=node.img
DISK_SIZE=268435456     # 256 MiB, sparse
SEEDS=""
MAC=""
HOSTFWD=""
TAB=""

for arg in "$@"; do
	case "$arg" in
		--disk=*) DISK="${arg#--disk=}" ;;
		--seed=*) SEEDS="$SEEDS ${arg#--seed=}" ;;
		--mac=*) MAC=",mac=${arg#--mac=}" ;;
		--hostfwd=*) HOSTFWD=",hostfwd=${arg#--hostfwd=}" ;;
		--help|-h) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		--*) echo "node.sh: unknown option: $arg" >&2; exit 1 ;;
		*) TAB="$arg" ;;
	esac
done
[ -n "$TAB" ] || { echo "Usage: node.sh [--disk=FILE] [--seed=IP:PORT ...] TABERNACLE" >&2; exit 1; }
[ -f "$TAB" ] || { echo "node.sh: $TAB not found" >&2; exit 1; }

if [ ! -e "$DISK" ]; then
	dd if=/dev/zero of="$DISK" bs=1 count=0 seek=$DISK_SIZE 2>/dev/null \
		|| { echo "node.sh: cannot create $DISK" >&2; exit 1; }
fi

# byte N — N as one raw byte.
byte() { printf "$(printf '\\%03o' "$1")"; }

SEEDFILE="$DISK.seeds.$$"
trap 'rm -f "$SEEDFILE"' EXIT
n=0
for s in $SEEDS; do n=$((n + 1)); done
[ "$n" -le 255 ] || { echo "node.sh: too many seeds" >&2; exit 1; }
{
	byte $n
	for s in $SEEDS; do
		ip=${s%:*}; port=${s##*:}
		case "$ip.$port" in
			*[!0-9.]*|.*) echo "node.sh: not IPv4:PORT: $s" >&2; exit 1 ;;
		esac
		old_ifs=$IFS; IFS=.; set -- $ip; IFS=$old_ifs
		[ $# = 4 ] || { echo "node.sh: not IPv4:PORT: $s" >&2; exit 1; }
		for o in "$@"; do byte "$o"; done
		byte $((port & 255)); byte $((port >> 8))
	done
} > "$SEEDFILE" || exit 1

qemu-system-riscv32 \
	-machine virt -m 128M -cpu "$CPU" -nographic -bios none \
	-global virtio-mmio.force-legacy=true \
	-device loader,file="$TAB",addr=0x80000000 \
	-device loader,file="$SEEDFILE",addr=0x87FFF000,force-raw=on \
	-drive file="$DISK",format=raw,if=none,id=d0 \
	-device virtio-blk-device,drive=d0 \
	-netdev user,id=n0$HOSTFWD \
	-device virtio-net-device,netdev=n0$MAC \
	-serial stdio -monitor none 2>/dev/null
