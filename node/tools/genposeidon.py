#!/usr/bin/env python3
"""Generates the assembly of src/user/node/poseidon2.fam's perm16: the
Poseidon2 permutation of width 16 over BabyBear (x^7, 8 full and 13 partial
rounds), as tabminer's miner/src/poseidon2.rs, whose round constants it reads.
tools/asm2fam.py turns it into fam words:

    python3 tools/genposeidon.py > p.s && python3 tools/asm2fam.py p.s

perm16 ( s base -- ): the 16 Montgomery words at s permuted in place; base is
arith.fam's table (sqt @).  Registers: a4 the state, a7 the table, ra the
link; the product subroutine uses a0-a3 and t0-t6; the S-box keeps x in a5
and its link in a6.
"""
import os, re, sys
sys.path.insert(0, os.path.dirname(__file__))
from genarith import qs, redc

P = 0x78000001
R = 1 << 32
SRC = os.path.join(os.path.dirname(__file__), "../../miner/src/poseidon2.rs")


def constants():
    src = open(SRC).read()
    def block(name):
        i = src.index(f"pub const {name}")
        j = src.index("];\n", i)
        return [int(x, 0) for x in re.findall(r"Fp::new\((0x[0-9a-f]+|\d+)\)", src[i:j])]
    ext_i, ext_f, internal = block("RC_EXTERNAL_INITIAL"), block("RC_EXTERNAL_FINAL"), block("RC_INTERNAL")
    assert len(ext_i) == 64 and len(ext_f) == 64 and len(internal) == 13
    return [ext_i[16 * r:16 * r + 16] for r in range(4)], internal, [ext_f[16 * r:16 * r + 16] for r in range(4)]


def mont(v):
    return v * R % P


n = [0]
def lab(base):
    n[0] += 1
    return f"{base}{n[0]}"


def li(reg, v):
    """reg = v (32 bits): lui and addi."""
    v &= 0xFFFFFFFF
    lo = v & 0xFFF
    if lo >= 0x800:
        lo -= 0x1000
    hi = ((v - lo) >> 12) & 0xFFFFF
    return [f"lui {reg},{hi:#x}", f"addi {reg},{reg},{lo}"]


def fadd(x, y, r, p="a5"):
    """r = x + y mod p, p in a register."""
    l = lab("fa")
    return [f"add {r},{x},{y}", f"bltu {r},{p},{l}", f"sub {r},{r},{p}", f"{l}:"]


def mm():
    """a0 = a0 a1 / R mod p (Montgomery); uses a1-a3, t0-t6."""
    out = [
        "srli a2,a0,16        # a's high half",
        "slli a0,a0,16",
        "srli a0,a0,16        # a's low half",
        "srli a3,a1,16        # b's high half",
        "slli a1,a1,16",
        "srli a1,a1,16        # b's low half",
    ]
    out += qs("a0", "a1", "t3")
    out += qs("a0", "a3", "t4")
    out += qs("a2", "a1", "t5")
    out += qs("a2", "a3", "t6")
    out += [
        "add t4,t4,t5         # the middle (no carry: halves of values below p)",
        "slli t0,t4,16",
        "add a0,t3,t0         # lo",
        "sltu t1,a0,t3",
        "srli t0,t4,16",
        "add a1,t6,t0",
        "add a1,a1,t1         # hi",
    ]
    out += [l.replace("redc_done", "mm_rd") for l in redc("a0", "a1", "a0")]
    return out + ["jalr zero,0(ra)"]


def sbox():
    """a0 = a0^7: x^2, x^3, x^6, x^7."""
    return [
        "addi a6,ra,0         # the link",
        "addi a5,a0,0         # x",
        "addi a1,a0,0",
        "jal ra,p2_mm         # x^2",
        "addi a1,a5,0",
        "jal ra,p2_mm         # x^3",
        "addi a1,a0,0",
        "jal ra,p2_mm         # x^6",
        "addi a1,a5,0",
        "jal ra,p2_mm         # x^7",
        "jalr zero,0(a6)",
    ]


def ext():
    """The external layer on the state at a4: M4 on each block of four, then
    each element plus its column's sum.  Uses a0-a3, a5 (p), t0-t6."""
    out = li("a5", P)
    for b in range(4):
        o = 16 * b
        out += [f"lw a0,{o}(a4)", f"lw a1,{o+4}(a4)", f"lw a2,{o+8}(a4)", f"lw a3,{o+12}(a4)"]
        out += fadd("a0", "a1", "t0")          # t01
        out += fadd("a2", "a3", "t1")          # t23
        out += fadd("t0", "t1", "t2")          # t0123
        out += fadd("t2", "a1", "t3")          # t01123
        out += fadd("t2", "a3", "t4")          # t01233
        out += fadd("a0", "a0", "t5")          # 2 x0
        out += fadd("t4", "t5", "t5")          # x3' = t01233 + 2 x0
        out += [f"sw t5,{o+12}(a4)"]
        out += fadd("a2", "a2", "t6")          # 2 x2
        out += fadd("t3", "t6", "t6")          # x1' = t01123 + 2 x2
        out += [f"sw t6,{o+4}(a4)"]
        out += fadd("t3", "t0", "t5")          # x0' = t01123 + t01
        out += [f"sw t5,{o}(a4)"]
        out += fadd("t4", "t1", "t6")          # x2' = t01233 + t23
        out += [f"sw t6,{o+8}(a4)"]
    for k in range(4):
        out += [f"lw a0,{4*k}(a4)", f"lw a1,{4*k+16}(a4)", f"lw a2,{4*k+32}(a4)", f"lw a3,{4*k+48}(a4)"]
        out += fadd("a0", "a1", "t0") + fadd("a2", "a3", "t1") + fadd("t0", "t1", "t2")   # the column
        for j, r in enumerate(["a0", "a1", "a2", "a3"]):
            out += fadd(r, "t2", r) + [f"sw {r},{4*k+16*j}(a4)"]
    return out + ["jalr zero,0(ra)"]


def half(r):
    """r = r / 2 mod p (a5 = p)."""
    l = lab("h")
    return ["andi t0,{0},1".format(r), f"beq t0,zero,{l}", f"add {r},{r},a5", f"{l}:", f"srli {r},{r},1"]


def neg(r):
    l = lab("ng")
    return [f"beq {r},zero,{l}", f"sub {r},a5,{r}", f"{l}:"]


def times(r, k):
    """r = k r mod p for a small k >= 1, by doubling and adding (t1 the
    running power, t2 the sum)."""
    assert k >= 1
    out = [f"addi t1,{r},0", "li t2,0"]
    first = True
    while k:
        if k & 1:
            out += ["addi t2,t1,0"] if first else fadd("t2", "t1", "t2")
            first = False
        k >>= 1
        if k:
            out += fadd("t1", "t1", "t1")
    return out + [f"addi {r},t2,0"]


def diag(i, r):
    """r = V[i] r, V the internal diagonal: -2 1 2 1/2 3 4 -1/2 -3 -4 1/2^8
    1/4 1/8 1/2^27 -1/2^8 -1/16 -1/2^27 (1/2^27 = -15: p = 15 2^27 + 1)."""
    spec = [("t", 2, True), None, ("t", 2, False), ("h", 1, False), ("t", 3, False), ("t", 4, False),
            ("h", 1, True), ("t", 3, True), ("t", 4, True), ("h", 8, False), ("h", 2, False), ("h", 3, False),
            ("t", 15, True), ("h", 8, True), ("h", 4, True), ("t", 15, False)][i]
    if spec is None:
        return []
    kind, k, negate = spec
    out = times(r, k) if kind == "t" else sum((half(r) for _ in range(k)), [])
    return out + (neg(r) if negate else [])


def internal():
    """The internal layer: s[i] = V[i] s[i] + sum(s).  a3 the sum."""
    out = li("a5", P) + ["lw a3,0(a4)"]
    for i in range(1, 16):
        out += [f"lw a0,{4*i}(a4)"] + fadd("a3", "a0", "a3")
    for i in range(16):
        out += [f"lw a0,{4*i}(a4)"] + diag(i, "a0") + fadd("a0", "a3", "a0") + [f"sw a0,{4*i}(a4)"]
    return out + ["jalr zero,0(ra)"]


def full_round(rc):
    out = li("a5", P)
    for i in range(16):
        out += [f"lw a0,{4*i}(a4)"] + li("a1", mont(rc[i])) + fadd("a0", "a1", "a0")
        out += ["jal ra,p2_sbox", f"sw a0,{4*i}(a4)"]
        if i < 15:
            out += li("a5", P)
    return out + ["jal ra,p2_ext"]


def partial_round(c):
    return (li("a5", P) + ["lw a0,0(a4)"] + li("a1", mont(c)) + fadd("a0", "a1", "a0")
            + ["jal ra,p2_sbox", "sw a0,0(a4)", "jal ra,p2_int"])


def perm16():
    ext_i, internal_rc, ext_f = constants()
    out = [
        "lw a7,0(sp)          # the table",
        "lw a4,4(sp)          # the state",
        "addi sp,sp,8",
        "jal ra,p2_ext        # the first external layer",
    ]
    for rc in ext_i:
        out += full_round(rc)
    for c in internal_rc:
        out += partial_round(c)
    for rc in ext_f:
        out += full_round(rc)
    out += ["jal zero,p2_done", "p2_mm:"] + mm() + ["p2_sbox:"] + sbox() + ["p2_ext:"] + ext()
    out += ["p2_int:"] + internal() + ["p2_done:"]
    return "\n".join(out)


if __name__ == "__main__":
    print(perm16())
