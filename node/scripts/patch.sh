#!/bin/sh
# patch.sh — make a tabernacle for one node image (docs/TABERNACLE.md):
# its version, size and Gimli-Hash into the last 40 bytes, which
# src/tabernacle.S leaves zero.  The hash is bin/gen_hash's, run under QEMU.
#
# Usage: scripts/patch.sh TABERNACLE IMAGE VERSION OUT
#   e.g. scripts/patch.sh bin/tabernacle bin/node.bin 0 bin/tabernacle.0
set -e

[ $# = 4 ] || { echo "Usage: patch.sh TABERNACLE IMAGE VERSION OUT" >&2; exit 1; }
tab=$1; image=$2; version=$3; out=$4
GEN_HASH="$(cd "$(dirname "$0")/.." && pwd)/bin/gen_hash"

# fsize FILE — size in bytes (as build.sh's).
fsize() { wc -c < "$1" | tr -d ' \t'; }
# le32 N — N as 4 raw bytes, little-endian.
le32() {
	printf "$(printf '\\%03o' $(($1 & 255)) $((($1 >> 8) & 255)) $((($1 >> 16) & 255)) $((($1 >> 24) & 255)))"
}

N=$(fsize "$image")
[ "$N" -gt 0 ] || { echo "patch.sh: $image is empty" >&2; exit 1; }
[ "$N" -le 67108864 ] || { echo "patch.sh: $image is over 64 MiB (chunk indexes are u16)" >&2; exit 1; }
[ -f "$GEN_HASH" ] || { echo "patch.sh: bin/gen_hash missing (run scripts/build.sh)" >&2; exit 1; }
echo "Patching $out: version $version, $N bytes of $image" >&2

# gen_hash reads [N (4, LE)] [N bytes] loaded at 0x80800000 and prints the
# digest on the serial port: eight words, each MSB first.
tmp="$out.patch.$$"
trap 'rm -f "$tmp".*' EXIT
{ le32 "$N"; cat "$image"; } > "$tmp.in"
: > "$tmp.nul"
qemu-system-riscv32 -machine virt -m 128M -cpu rv32 -display none -bios none \
	-chardev file,id=ser0,path="$tmp.out",input-path="$tmp.nul" \
	-serial chardev:ser0 \
	-device loader,file="$GEN_HASH",addr=0x80000000 \
	-device loader,file="$tmp.in",addr=0x80800000,force-raw=on 2>/dev/null
HASH=$(cat "$tmp.out")
[ "$(echo $HASH | wc -w)" -eq 8 ] || { echo "patch.sh: gen_hash failed" >&2; exit 1; }

S=$(fsize "$tab")
head -c $((S - 40)) "$tab" > "$tmp.tab"
{
	le32 "$version"
	le32 "$N"
	for word in $HASH; do
		echo "$word" | sed 's/\(..\)\(..\)\(..\)\(..\)/\4\3\2\1/' | xxd -r -p
	done
} >> "$tmp.tab"
[ "$(fsize "$tmp.tab")" = "$S" ] || { echo "patch.sh: patching went wrong" >&2; exit 1; }
mv "$tmp.tab" "$out"
