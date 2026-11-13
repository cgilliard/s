#!/bin/sh
# node.sh — run a node: tabernacle (docs/TABERNACLE.md) under QEMU, with the
# disk it boots the image from and user-mode networking for fetching it.
# Linux and macOS (on Windows, WSL2), as tools/q32.
#
# Usage: node.sh [--disk=FILE] [--seed=HOST:PORT ...] [--no-seeds]
#                [--mac=ADDR] [--hostfwd=SPEC] [--smp=N] [TABERNACLE]
#   --disk=FILE       the disk (default node/data/node.img, wherever this
#                     is run from), created empty if missing
#   --seed=HOST:PORT  another seed (repeatable): an IPv4 address or a name
#                     with one.  10.0.2.2 is this host.
#   --no-seeds        not the built-in seeds (SEEDS), only those given
#   --mac=ADDR        the virtio-net MAC (give each node on a host its own)
#   --hostfwd=SPEC    expose a guest port, e.g. udp::3737-:3737
#   --smp=N           N harts (default 1: more are slower for now)
#   TABERNACLE        the boot program (default node/bin/tabernacle, as
#                     scripts/build.sh leaves it)
#
# The seeds' names are resolved here, each to its first IPv4 address (one
# that does not resolve is skipped), and go to tabernacle as a small file
# loaded at 0x87FFF000: a count byte, then 4 address bytes and a port
# (u16 LE) each.

CPU="rv32,zicsr=true,m=false,a=false,f=false,d=false,c=false,\
zawrs=false,zfa=false,zfh=false,zfhmin=false,zcb=false,\
zcd=false,zcf=false,zcmp=false,zcmt=false,zifencei=false"
SEEDS="tabernacle1.root.sx:3737 tabernacle2.root.sx:3737"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DISK="$ROOT/data/node.img"
DISK_SIZE=26843545600   # 25 GB, sparse (docs/NODE.md)
EXTRA=""
NO_SEEDS=0
MAC=""
HOSTFWD=""
# one hart: more are slower for now (docs/NODE_ENHANCEMENTS.md, item 4:
# a mainnet catch-up of 144 blocks took 8 min on 1, 8 min 50 s on 2,
# 10 min 45 s on 4)
SMP=1
TAB="$ROOT/bin/tabernacle"

for arg in "$@"; do
	case "$arg" in
		--disk=*) DISK="${arg#--disk=}" ;;
		--seed=*) EXTRA="$EXTRA ${arg#--seed=}" ;;
		--no-seeds) NO_SEEDS=1 ;;
		--mac=*) MAC=",mac=${arg#--mac=}" ;;
		--hostfwd=*) HOSTFWD=",hostfwd=${arg#--hostfwd=}" ;;
		--smp=*) SMP="${arg#--smp=}" ;;
		--help|-h) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		--*) echo "node.sh: unknown option: $arg" >&2; exit 1 ;;
		*) TAB="$arg" ;;
	esac
done
[ -f "$TAB" ] || { echo "node.sh: $TAB not found (run scripts/build.sh)" >&2; exit 1; }
[ "$NO_SEEDS" = 1 ] && SEEDS=""
SEEDS="$SEEDS$EXTRA"

if [ ! -e "$DISK" ]; then
	mkdir -p "$(dirname "$DISK")"
	dd if=/dev/zero of="$DISK" bs=1 count=0 seek=$DISK_SIZE 2>/dev/null \
		|| { echo "node.sh: cannot create $DISK" >&2; exit 1; }
fi

# byte N — N as one raw byte.
byte() { printf "$(printf '\\%03o' "$1")"; }

# ipv4 HOST — HOST if it is an address, else its first IPv4 address (nothing
# if it has none): getent on Linux, dscacheutil on macOS.
ipv4() {
	case "$1" in
		*[!0-9.]*) ;;
		*) echo "$1"; return ;;
	esac
	if command -v getent >/dev/null 2>&1; then
		getent ahostsv4 "$1" 2>/dev/null | awk 'NR == 1 { print $1 }'
	elif command -v dscacheutil >/dev/null 2>&1; then
		dscacheutil -q host -a name "$1" 2>/dev/null | awk '/^ip_address:/ { print $2; exit }'
	fi
}

RESOLVED=""
for s in $SEEDS; do
	host=${s%:*}; port=${s##*:}
	case "$port" in
		''|*[!0-9]*) echo "node.sh: not HOST:PORT: $s" >&2; exit 1 ;;
	esac
	ip=$(ipv4 "$host")
	if [ -z "$ip" ]; then
		echo "node.sh: seed $host has no IPv4 address; skipped" >&2
		continue
	fi
	RESOLVED="$RESOLVED $ip:$port"
done
SEEDS=$RESOLVED

SEEDFILE="$DISK.seeds.$$"
trap 'rm -f "$SEEDFILE"' EXIT                 # however it ends (Ctrl-C too)
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
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
	-machine virt -m 128M -cpu "$CPU" -smp "$SMP" -nographic -bios none \
	-global virtio-mmio.force-legacy=true \
	-device loader,file="$TAB",addr=0x80000000 \
	-device loader,file="$SEEDFILE",addr=0x87FFF000,force-raw=on \
	-drive file="$DISK",format=raw,if=none,id=d0 \
	-device virtio-blk-device,drive=d0 \
	-device virtio-rng-device \
	-netdev user,id=n0$HOSTFWD \
	-device virtio-net-device,netdev=n0$MAC \
	-serial stdio -monitor none 2>/dev/null
