#!/bin/sh
# makenode.sh — a disk with the node image already on it, so tabernacle boots
# from disk (docs/TABERNACLE.md) without fetching: bin/img written at the
# start of the disk, as the node will write itself once it runs.  Run after
# scripts/build.sh; from anywhere.
#
# Usage: makenode.sh [--disk=FILE]
#   --disk=FILE  the disk (default node/data/node.img); created if missing
#                (25 GB, sparse, as node.sh makes it), else its start is
#                overwritten and the rest kept

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DISK="$ROOT/data/node.img"
DISK_SIZE=26843545600   # as scripts/node.sh
IMG="$ROOT/bin/img"

for arg in "$@"; do
	case "$arg" in
		--disk=*) DISK="${arg#--disk=}" ;;
		--help|-h) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) echo "makenode.sh: unknown argument: $arg" >&2; exit 1 ;;
	esac
done
[ -f "$IMG" ] || { echo "makenode.sh: $IMG not found (run scripts/build.sh)" >&2; exit 1; }

mkdir -p "$(dirname "$DISK")" || exit 1
if [ ! -e "$DISK" ]; then
	dd if=/dev/zero of="$DISK" bs=1 count=0 seek=$DISK_SIZE 2>/dev/null \
		|| { echo "makenode.sh: cannot create $DISK" >&2; exit 1; }
fi
dd if="$IMG" of="$DISK" conv=notrunc 2>/dev/null \
	|| { echo "makenode.sh: cannot write $DISK" >&2; exit 1; }
echo "$DISK: $(wc -c < "$IMG" | tr -d ' \t') bytes of $IMG at its start"
