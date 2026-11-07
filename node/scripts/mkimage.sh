#!/bin/sh
# mkimage.sh — the node image (docs/OS.md, section 1): the kernel followed by
# the programs it carries, all one file under tabernacle's hash.
#
# Usage: scripts/mkimage.sh OUT KERNEL NAME=FILE[:KiB] ...
#   KERNEL   the kernel, as fam built it (bin/kernel)
#   NAME     a program's name (at most 15 bytes), FILE its binary (built with
#            `tools/fam --user`), KiB the memory it starts with (default 64)
#
# The layout: the kernel; each program (4-byte aligned); the table (a count,
# then for each program its name in 16 bytes, its offset in the image, its
# length and its memory, little-endian); zeros to the end of a page but 8
# bytes; then the table's offset and "PROG".  The image ends on a page
# boundary, where its stdlib (lib/mach.fam's init) puts its return ids, so
# the kernel finds the table's offset 8 bytes below that (s10), and the
# kernel's own end, which fam set (the gp its start loads, at bytes 16-23),
# is moved to the image's: nothing the kernel puts past its end lands on the
# programs.
set -e

[ $# -ge 2 ] || { echo "Usage: mkimage.sh OUT KERNEL NAME=FILE[:KiB] ..." >&2; exit 1; }
out=$1; kernel=$2; shift 2

fsize() { wc -c < "$1" | tr -d ' \t'; }
le32() {
	printf "$(printf '\\%03o' $(($1 & 255)) $((($1 >> 8) & 255)) $((($1 >> 16) & 255)) $((($1 >> 24) & 255)))"
}
zeros() { [ "$1" -gt 0 ] && head -c "$1" /dev/zero; return 0; }
pad4() { zeros $(( (4 - $(fsize "$1") % 4) % 4 )) >> "$1"; }

tmp="$out.mk.$$"
trap 'rm -f "$tmp" "$tmp.table"' EXIT
cp "$kernel" "$tmp"
pad4 "$tmp"
: > "$tmp.table"
n=0
for spec in "$@"; do
	name=${spec%%=*}; rest=${spec#*=}
	file=${rest%%:*}; kib=64
	case "$rest" in *:*) kib=${rest##*:} ;; esac
	[ -f "$file" ] || { echo "mkimage.sh: $file not found" >&2; exit 1; }
	len=$(printf '%s' "$name" | wc -c | tr -d ' \t')
	[ "$len" -ge 1 ] && [ "$len" -le 15 ] || { echo "mkimage.sh: name $name: 1 to 15 bytes" >&2; exit 1; }
	off=$(fsize "$tmp")
	cat "$file" >> "$tmp"
	pad4 "$tmp"
	{ printf '%s' "$name"; zeros $((16 - len)); le32 "$off"; le32 "$(fsize "$file")"; le32 $((kib * 1024)); } >> "$tmp.table"
	n=$((n + 1))
done
toff=$(fsize "$tmp")
le32 "$n" >> "$tmp"
cat "$tmp.table" >> "$tmp"
zeros $(( (4096 - ($(fsize "$tmp") + 8) % 4096) % 4096 )) >> "$tmp"
le32 "$toff" >> "$tmp"
printf 'PROG' >> "$tmp"
end=$(fsize "$tmp")

# The kernel's start: auipc gp,%hi(off) at 16 and addi gp,gp,%lo(off) at 20,
# off from the auipc to the end.
set -- $(od -An -tu4 -j16 -N8 "$tmp")
[ $(($1 & 4095)) = 407 ] && [ $(($2 & 1048575)) = 98707 ] \
	|| { echo "mkimage.sh: $kernel does not start as fam's output does" >&2; exit 1; }
d=$((end - 16))
hi=$(( ((d + 2048) >> 12) & 1048575 ))
lo=$(( d & 4095 ))
{ le32 $(( (hi << 12) | 407 )); le32 $(( (lo << 20) | 98707 )); } \
	| dd of="$tmp" bs=1 seek=16 conv=notrunc 2>/dev/null
mv "$tmp" "$out"
echo "$out: $end bytes, $n programs" >&2
