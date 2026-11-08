#!/usr/bin/env python3
"""asm2fam.py FILE.s: assemble RV32I (riscv64-unknown-elf-as) and print fam
words, one an instruction, with the source line as the comment (labels as
their own comment lines), as the kernel's raw words are written.  No
macros: each source line must be one instruction."""
import re, subprocess, sys, tempfile, os

src = open(sys.argv[1]).read()
with tempfile.TemporaryDirectory() as d:
    s = os.path.join(d, "a.s"); o = os.path.join(d, "a.o")
    open(s, "w").write(".option norvc\n" + src)
    subprocess.run(["riscv64-unknown-elf-as", "-march=rv32i", "-mabi=ilp32", "-o", o, s], check=True)
    dump = subprocess.run(["riscv64-unknown-elf-objdump", "-d", "-M", "no-aliases", o],
                          capture_output=True, text=True, check=True).stdout
words = []
for line in dump.splitlines():
    m = re.match(r"\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)$", line)
    if m:
        words.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3).split("<")[0].strip()))
# source lines without labels/comments, in order, to pair with words
lines = []
for raw in src.splitlines():
    t = raw.split("#")[0].rstrip()
    comment = raw.split("#", 1)[1].strip() if "#" in raw else ""
    lab = re.match(r"\s*([A-Za-z_.][\w.]*):\s*(.*)$", t)
    if lab:
        lines.append(("label", lab.group(1), comment))
        t = lab.group(2)
    if t.strip() and not t.strip().startswith("."):
        lines.append(("ins", t.strip(), comment))
i = 0
for kind, text, comment in lines:
    if kind == "label":
        print(f"\\ {text}:")
        continue
    addr, w, dis = words[i]; i += 1
    b = w.to_bytes(4, "little").hex().upper()
    c = f"   ( {comment} )" if comment else ""
    print(f"{b} ,   \\ {text}{c}")
assert i == len(words), (i, len(words))
