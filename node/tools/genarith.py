#!/usr/bin/env python3
"""Generates the assembly of src/user/node/arith.fam's raw words (um*,
fmul, f+, f-, fneg, e4mul, ud%: udmod); tools/asm2fam.py turns each into fam words:

    python3 tools/genarith.py fmul > fmul.s && python3 tools/asm2fam.py fmul.s
"""
import sys

def qs(u, v, r, base="a7"):
    """r = u*v for u, v < 2^16 by quarter squares: S[u+v] - S[|u-v|]."""
    return [
        f"add t0,{u},{v}         # u+v",
        f"sub t1,{u},{v}         # u-v",
        "srai t2,t1,31",
        "xor t1,t1,t2",
        "sub t1,t1,t2         # |u-v|",
        "slli t0,t0,2",
        "slli t1,t1,2",
        f"add t0,t0,{base}",
        f"add t1,t1,{base}",
        "lw t0,0(t0)          # S[u+v]",
        "lw t1,0(t1)          # S[|u-v|]",
        f"sub {r},t0,t1",
    ]

def product(a, b, lo, hi):
    """lo:hi = a*b (32x32), a7 the table; uses a2-a6, t0-t6."""
    out = [
        f"srli a2,{a},16      # a's high half",
        f"slli a3,{a},16",
        "srli a3,a3,16        # a's low half",
        f"srli a4,{b},16      # b's high half",
        f"slli a5,{b},16",
        "srli a5,a5,16        # b's low half",
    ]
    out += qs("a3", "a5", "t3")   # low*low
    out += qs("a3", "a4", "t4")   # a low * b high
    out += qs("a2", "a5", "t5")   # a high * b low
    out += qs("a2", "a4", "t6")   # high*high
    out += [
        "add t4,t4,t5         # the middle",
        "sltu t5,t4,t5        # its carry (2^48)",
        "slli t0,t4,16",
        f"add {lo},t3,t0",
        f"sltu t1,{lo},t3",
        "srli t0,t4,16",
        f"add {hi},t6,t0",
        "slli t5,t5,16",
        f"add {hi},{hi},t5",
        f"add {hi},{hi},t1",
    ]
    return out

def redc(lo, hi, r):
    """r = lo:hi / 2^32 mod p (Montgomery, R = 2^32), for lo:hi < 2^32 p."""
    return [
        f"slli t0,{lo},31     # m = lo * -1/p mod 2^32 = lo(2^31 - 2^27 - 1)",
        f"slli t1,{lo},27",
        "sub t0,t0,t1",
        f"sub t0,t0,{lo}      # m",
        "slli t1,t0,31        # m p = m 2^31 - m 2^27 + m: its high word",
        "slli t2,t0,27",
        "sltu t3,t1,t2",
        "sub t1,t1,t2",
        "srli t4,t0,1",
        "srli t5,t0,5",
        "sub t4,t4,t5",
        "sub t4,t4,t3",
        "add t1,t1,t0",
        "sltu t6,t1,t0",
        "add t4,t4,t6         # (m p) >> 32",
        f"sltu t0,zero,{lo}   # the low words' carry: lo + (m p mod 2^32) = 2^32 unless lo is 0",
        f"add {r},{hi},t4",
        f"add {r},{r},t0",
        "lui t1,0x78000",
        "addi t1,t1,1         # p",
        f"bltu {r},t1,redc_done",
        f"sub {r},{r},t1",
        "redc_done:",
    ]

def umul():
    # ( a b base -- lo hi )
    return "\n".join([
        "lw a7,0(sp)          # the table",
        "lw a1,4(sp)          # b",
        "lw a0,8(sp)          # a",
        "addi sp,sp,4",
    ] + product("a0", "a1", "a6", "a1") + [
        "sw a6,4(sp)          # lo",
        "sw a1,0(sp)          # hi",
    ])

def fmul():
    # ( a b base -- a*b/R mod p )
    return "\n".join([
        "lw a7,0(sp)",
        "lw a1,4(sp)",
        "lw a0,8(sp)",
        "addi sp,sp,8",
    ] + product("a0", "a1", "a6", "a1") + redc("a6", "a1", "a0") + [
        "sw a0,0(sp)",
    ])

if __name__ == "__main__" and sys.argv[1] in ("umul", "fmul"):
    print({"umul": umul, "fmul": fmul}[sys.argv[1]]())

def fadd_regs(x, y, r):
    """r = x + y mod p (x, y < p)."""
    return [f"add {r},{x},{y}", "lui t6,0x78000", "addi t6,t6,1", f"bltu {r},t6,fa_{r}_{x}_{y}_{fadd_regs.n}",
            f"sub {r},{r},t6", f"fa_{r}_{x}_{y}_{fadd_regs.n}:"]
fadd_regs.n = 0

def fadd_lab(x, y, r):
    fadd_regs.n += 1
    return fadd_regs(x, y, r)

def e4mul():
    # ( a b c base -- ): c = a b in Fp[x]/(x^4 - 11).  Scratch below sp:
    # -4 a, -8 b, -12 c, then the 16 products P[i][j] at -16 - 4(4i+j).
    out = [
        "lw a7,0(sp)          # the table",
        "lw t0,4(sp)          # c",
        "lw t1,8(sp)          # b",
        "lw t2,12(sp)         # a",
        "addi sp,sp,16",
        "sw t2,-4(sp)",
        "sw t1,-8(sp)",
        "sw t0,-12(sp)",
    ]
    for i in range(4):
        for j in range(4):
            out += [
                "lw t0,-4(sp)",
                f"lw a0,{4*i}(t0)     # a{i}",
                "lw t0,-8(sp)",
                f"lw a1,{4*j}(t0)     # b{j}",
                "jal ra,e4m_mm",
                f"sw a0,{-16 - 4*(4*i + j)}(sp)   # P{i}{j}",
            ]
    P = lambda i, j: f"{-16 - 4*(4*i + j)}(sp)"
    def load(reg, i, j):
        return [f"lw {reg},{P(i, j)}"]
    def eleven(x):
        # x = 11 x: a0 2x, a1 4x -> 8x
        return (fadd_lab(x, x, "a0") + fadd_lab("a0", "a0", "a1") + fadd_lab("a1", "a1", "a1")
                + fadd_lab("a1", "a0", "a1") + fadd_lab("a1", x, x))
    terms = {
        0: ([(0, 0)], [(1, 3), (2, 2), (3, 1)]),
        1: ([(0, 1), (1, 0)], [(2, 3), (3, 2)]),
        2: ([(0, 2), (1, 1), (2, 0)], [(3, 3)]),
        3: ([(0, 3), (1, 2), (2, 1), (3, 0)], []),
    }
    for k in range(4):
        plain, wrapped = terms[k]
        code = []
        if wrapped:
            code += load("a2", *wrapped[0])
            for t in wrapped[1:]:
                code += load("a3", *t) + fadd_lab("a2", "a3", "a2")
            code += eleven("a2")
        else:
            code += ["li a2,0"]
        for t in plain:
            code += load("a3", *t) + fadd_lab("a2", "a3", "a2")
        code += ["lw t0,-12(sp)", f"sw a2,{4*k}(t0)   # c{k}"]
        out += code
    out += ["jal zero,e4m_done", "e4m_mm:"]
    out += product("a0", "a1", "a6", "a1") + [l.replace("redc_done", "e4m_rd") for l in redc("a6", "a1", "a0")]
    out += ["jalr zero,0(ra)", "e4m_done:"]
    return "\n".join(out)

def fadd():
    return "\n".join(["lw t0,0(sp)", "lw t1,4(sp)", "addi sp,sp,4"] + fadd_regs("t1", "t0", "t0") + ["sw t0,0(sp)"])

def fsub():
    return "\n".join(["lw t0,0(sp)          # b", "lw t1,4(sp)          # a", "addi sp,sp,4",
                      "sub t2,t1,t0", "bgeu t1,t0,fs_done", "lui t6,0x78000", "addi t6,t6,1", "add t2,t2,t6",
                      "fs_done:", "sw t2,0(sp)"])

def fneg():
    return "\n".join(["lw t0,0(sp)", "beq t0,zero,fn_done", "lui t6,0x78000", "addi t6,t6,1", "sub t0,t6,t0",
                      "fn_done:", "sw t0,0(sp)"])

def udmod():
    # ( lo hi d -- r ): hi:lo mod d, a bit at a time.
    return """lw t0,0(sp)          # d
lw t1,4(sp)          # hi
lw t2,8(sp)          # lo
addi sp,sp,8
li t3,0              # the remainder
li t4,64             # bits
udm_loop:
srli t5,t1,31        # hi:lo's top bit, into the remainder
slli t1,t1,1
srli t6,t2,31
or t1,t1,t6
slli t2,t2,1
srli a0,t3,31        # the bit the remainder shifts out
slli t3,t3,1
or t3,t3,t5
bne a0,zero,udm_sub
bltu t3,t0,udm_next
udm_sub:
sub t3,t3,t0
udm_next:
addi t4,t4,-1
bne t4,zero,udm_loop
sw t3,0(sp)"""

if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] in ("e4mul", "fadd", "fsub", "fneg", "udmod"):
    print({"e4mul": e4mul, "fadd": fadd, "fsub": fsub, "fneg": fneg, "udmod": udmod}[sys.argv[1]]())
