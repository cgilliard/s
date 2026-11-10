#!/usr/bin/env python3
"""Generates the assembly of the raw words of src/user/crypto/keccak.fam and
src/user/crypto/dilithium.fam (RV32I: no multiply, no divide).  Through
tools/asm2fam.py, one word at a time:

    tools/gendilithium.py kcraw > /tmp/k.s && tools/asm2fam.py /tmp/k.s

The words (their stack effects; the data stack is sp, its top at 0(sp)):

kcraw ( st rc -- )  Keccak-f[1600] on the 25 lanes at st (each two words,
    the low one first: the 200 bytes in FIPS 202's order), with the 24
    round constants at rc (two words each, the low first).
dlmtab ( tbl -- )  the table of products: the halfword at tbl + 2(256a + b)
    is a*b, for bytes a and b (128 KiB).
dlmmr ( x y tbl -- x*y mod q )  for x and y below q.
dlnttr ( p z tbl -- )  the NTT of the polynomial at p (256 words, each
    below q), in place, with the 256 powers of zeta at z (bit-reversed
    order, as tabminer's zetas()).
dlinttr ( p z tbl -- )  its inverse (the factor 1/256 included).
dlpmacr ( acc a b tbl -- )  acc[i] = acc[i] + a[i]*b[i] mod q, for the 256.

Products mod q: x*y = P0 + 2^8 P1 + 2^16 P2 with Pm = x * (byte m of y),
each a sum of three looked-up byte products (below 2^31); Horner's rule
from P2 down, a reduction after each step: 2^23 = 2^13 - 1 (mod q), so
x = hi 2^23 + lo is lo + 8191 hi, below 2q for x below 2^32, then less
q once if it is not below q.  Registers: a0-a7 and t0-t6, and ra (fam's
calls leave it alone)."""
import sys

Q = 8380417


def csub(x, m, t):
    """x = x - q if x >= q (x below 2q); m and t scratch."""
    return [f"lui {t},0x7FE", f"addi {t},{t},1", f"sub {t},{x},{t}", f"srai {m},{t},31",
            f"xor {x},{x},{t}", f"and {x},{x},{m}", f"xor {x},{x},{t}"]


def red(x, b, t):
    """x (below 2^32) reduced to [0, q); b and t scratch."""
    return [f"srli {b},{x},23", f"slli {x},{x},9", f"srli {x},{x},9", f"slli {t},{b},13", f"sub {t},{t},{b}",
            f"add {x},{x},{t}"] + csub(x, b, t)


def addq(x, m, t):
    """x = x + q if x < 0 (signed; x above -q); m and t scratch."""
    return [f"srai {m},{x},31", f"lui {t},0x7FE", f"addi {t},{t},1", f"and {m},{m},{t}", f"add {x},{x},{m}"]


def bases(x, tbl, z, t):
    """z (three registers) = tbl + 512 * (byte m of x), m = 0, 1, 2."""
    z0, z1, z2 = z
    return [f"andi {t},{x},255", f"slli {t},{t},9", f"add {z0},{tbl},{t}",
            f"srli {t},{x},8", f"andi {t},{t},255", f"slli {t},{t},9", f"add {z1},{tbl},{t}",
            f"srli {t},{x},16", f"slli {t},{t},9", f"add {z2},{tbl},{t}"]


def mulmod(y, acc, b, t, z):
    """acc = x*y mod q, x's bases at z (bases()); y consumed; b, t scratch."""
    z0, z1, z2 = z
    out = []

    def terms(first):
        o = []
        for zi, sh in ((z0, 0), (z1, 8), (z2, 16)):
            if first and zi == z0:
                o += [f"add {acc},{zi},{b}", f"lhu {acc},0({acc})"]
            else:
                o += [f"add {t},{zi},{b}", f"lhu {t},0({t})"]
                if sh:
                    o.append(f"slli {t},{t},{sh}")
                o.append(f"add {acc},{acc},{t}")
        return o

    out += [f"srli {b},{y},16", f"slli {b},{b},1"] + terms(True) + red(acc, b, t)
    out += [f"srli {b},{y},8", f"andi {b},{b},255", f"slli {b},{b},1", f"slli {acc},{acc},8"] + terms(False) + red(acc, b, t)
    out += [f"andi {b},{y},255", f"slli {b},{b},1", f"slli {acc},{acc},8"] + terms(False) + red(acc, b, t)
    return out


ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]


def rotl(dst, src, n, t):
    """dst (lo, hi) = src (lo, hi) rotated left by n (not 0 nor 32)."""
    lo, hi = src
    if n > 32:
        lo, hi, n = hi, lo, n - 32
    dl, dh = dst
    return [f"slli {dl},{lo},{n}", f"srli {t},{hi},{32 - n}", f"or {dl},{dl},{t}",
            f"slli {dh},{hi},{n}", f"srli {t},{lo},{32 - n}", f"or {dh},{dh},{t}"]


def kcraw():
    st = "ra"
    out = ["lw t0,0(sp)          # rc", "lw ra,4(sp)          # st", "addi t1,t0,192", "sw t1,4(sp)          # rc's end", "round:"]
    bc = [("a0", "a1"), ("a2", "a3"), ("a4", "a5"), ("a6", "a7"), ("t0", "t1")]
    # theta
    for x in range(5):
        lo, hi = bc[x]
        out += [f"lw {lo},{8 * x}({st})", f"lw {hi},{8 * x + 4}({st})"]
        for y in range(1, 5):
            o = 8 * (x + 5 * y)
            out += [f"lw t5,{o}({st})", f"lw t6,{o + 4}({st})", f"xor {lo},{lo},t5", f"xor {hi},{hi},t6"]
    for x in range(5):
        out += rotl(("t2", "t3"), bc[(x + 1) % 5], 1, "t4")
        pl, ph = bc[(x + 4) % 5]
        out += [f"xor t2,t2,{pl}", f"xor t3,t3,{ph}"]
        for y in range(5):
            o = 8 * (x + 5 * y)
            out += [f"lw t5,{o}({st})", f"lw t6,{o + 4}({st})", "xor t5,t5,t2", "xor t6,t6,t3",
                    f"sw t5,{o}({st})", f"sw t6,{o + 4}({st})"]
    # rho and pi: t moves along the cycle
    cur, nxt = ("a0", "a1"), ("a2", "a3")
    out += [f"lw a0,8({st})", f"lw a1,12({st})"]
    for i in range(24):
        j = PILN[i]
        out += [f"lw {nxt[0]},{8 * j}({st})", f"lw {nxt[1]},{8 * j + 4}({st})"]
        out += rotl(("a4", "a5"), cur, ROTC[i], "t4")
        out += [f"sw a4,{8 * j}({st})", f"sw a5,{8 * j + 4}({st})"]
        cur, nxt = nxt, cur
    # chi
    regs = [("a0", "a1"), ("a2", "a3"), ("a4", "a5"), ("a6", "a7"), ("t0", "t1")]
    for y in range(5):
        for x in range(5):
            o = 8 * (5 * y + x)
            out += [f"lw {regs[x][0]},{o}({st})", f"lw {regs[x][1]},{o + 4}({st})"]
        for x in range(5):
            o = 8 * (5 * y + x)
            for h in range(2):
                b0, b1, b2 = regs[x][h], regs[(x + 1) % 5][h], regs[(x + 2) % 5][h]
                out += [f"xori t2,{b1},-1", f"and t2,t2,{b2}", f"xor t2,t2,{b0}", f"sw t2,{o + 4 * h}({st})"]
    # iota, and the next round
    out += ["lw t5,0(sp)", "lw t2,0(t5)", "lw t3,4(t5)", f"lw t4,0({st})", "xor t4,t4,t2", f"sw t4,0({st})",
            f"lw t4,4({st})", "xor t4,t4,t3", f"sw t4,4({st})", "addi t5,t5,8", "sw t5,0(sp)", "lw t6,4(sp)",
            "beq t5,t6,done", "j round", "done:", "addi sp,sp,8"]
    return out


def dlmtab():
    return ["lw a0,0(sp)          # tbl", "addi sp,sp,4", "li a1,0", "li a4,256",
            "rowa:", "li a2,0", "li a3,256",
            "rowb:", "sh a2,0(a0)", "addi a0,a0,2", "add a2,a2,a1", "addi a3,a3,-1", "bnez a3,rowb",
            "addi a1,a1,1", "bne a1,a4,rowa"]


def dlmm():
    z = ("t4", "t5", "t6")
    out = ["lw a2,0(sp)          # tbl", "lw t0,4(sp)          # y", "lw a0,8(sp)          # x", "addi sp,sp,8"]
    out += bases("a0", "a2", z, "t3") + mulmod("t0", "t1", "t2", "t3", z) + ["sw t1,0(sp)"]
    return out


def dlntt():
    z = ("t4", "t5", "t6")
    out = ["lw a2,0(sp)          # tbl", "lw a1,4(sp)          # z", "lw a0,8(sp)          # p", "addi sp,sp,12",
           "addi a6,a0,1024      # p's end", "li a3,512            # len, in bytes",
           "stage:", "mv a4,a0",
           "block:", "addi a1,a1,4", "lw a7,0(a1)"]
    out += bases("a7", "a2", z, "t3")
    out += ["add a5,a4,a3", "add a7,a4,a3",
            "bfly:", "lw t0,0(a7)"]
    out += mulmod("t0", "t1", "t2", "t3", z)
    out += ["lw ra,0(a4)", "sub t0,ra,t1"] + addq("t0", "t2", "t3") + ["sw t0,0(a7)"]
    out += ["add t1,ra,t1"] + csub("t1", "t2", "t3") + ["sw t1,0(a4)"]
    out += ["addi a4,a4,4", "addi a7,a7,4", "bne a4,a5,bfly",
            "mv a4,a7", "bne a4,a6,block",
            "srli a3,a3,1", "sltiu t0,a3,4", "beqz t0,stage"]
    return out


def dlintt():
    z = ("t4", "t5", "t6")
    out = ["lw a2,0(sp)          # tbl", "lw a1,4(sp)          # z", "lw a0,8(sp)          # p", "addi sp,sp,12",
           "addi a6,a0,1024      # p's end", "addi a1,a1,1024     # z, from its end", "li a3,4              # len, in bytes",
           "stage:", "mv a4,a0",
           "block:", "addi a1,a1,-4", "lw a7,0(a1)",
           "lui t0,0x7FE", "addi t0,t0,1", "sub a7,t0,a7      # -zeta"]
    out += bases("a7", "a2", z, "t3")
    out += ["add a5,a4,a3", "add a7,a4,a3",
            "bfly:", "lw ra,0(a4)", "lw t0,0(a7)",
            "add t1,ra,t0"] + csub("t1", "t2", "t3") + ["sw t1,0(a4)", "sub t0,ra,t0"] + addq("t0", "t2", "t3")
    out += mulmod("t0", "t1", "t2", "t3", z) + ["sw t1,0(a7)"]
    out += ["addi a4,a4,4", "addi a7,a7,4", "bne a4,a5,bfly",
            "mv a4,a7", "bne a4,a6,block",
            "slli a3,a3,1", "li t0,1024", "bne a3,t0,stage"]
    # times 256^-1
    inv = 8347681
    out += [f"lui a7,{(inv + 0x800) >> 12}", f"addi a7,a7,{inv - (((inv + 0x800) >> 12) << 12)}"]
    out += bases("a7", "a2", z, "t3")
    out += ["mv a4,a0", "scale:", "lw t0,0(a4)"] + mulmod("t0", "t1", "t2", "t3", z)
    out += ["sw t1,0(a4)", "addi a4,a4,4", "bne a4,a6,scale"]
    return out


def dlpmac():
    z = ("t4", "t5", "t6")
    out = ["lw a2,0(sp)          # tbl", "lw a5,4(sp)          # b", "lw a4,8(sp)          # a", "lw a3,12(sp)         # acc",
           "addi sp,sp,16", "addi a6,a3,1024",
           "each:", "lw a7,0(a4)"]
    out += bases("a7", "a2", z, "t3")
    out += ["lw t0,0(a5)"] + mulmod("t0", "t1", "t2", "t3", z)
    out += ["lw t0,0(a3)", "add t1,t1,t0"] + csub("t1", "t2", "t3")
    out += ["sw t1,0(a3)", "addi a3,a3,4", "addi a4,a4,4", "addi a5,a5,4", "bne a3,a6,each"]
    return out


WORDS = {"kcraw": kcraw, "dlmtab": dlmtab, "dlmmr": dlmm, "dlnttr": dlntt, "dlinttr": dlintt, "dlpmacr": dlpmac}

if __name__ == "__main__":
    print("\n".join(WORDS[sys.argv[1]]()))
