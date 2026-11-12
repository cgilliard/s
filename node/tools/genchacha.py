#!/usr/bin/env python3
"""Generates the assembly of src/user/crypto/chacha.fam's raw words, one at
a time (the argument names which); tools/asm2fam.py turns it into fam
words:

    python3 tools/genchacha.py c2raw > /tmp/c.s && python3 tools/asm2fam.py /tmp/c.s

c2raw ( st out -- ): ChaCha20's block function: the 16 words at st (the
state) through 20 rounds, plus st, at out; st's word 12 (the counter) one
more.  The working words in a0..a7, t0..t6 and ra; s0 the rotations'
temporary, s1 st (both saved on the data stack and put back).

p1raw ( h r c x -- ): Poly1305's step for one block, as the fam words
p1add/p1blk did (TweetNaCl's 17 limbs of 8 bits): h += c, then h = h r
mod 2^130 - 5 partly reduced, x the scratch (17 words each).  A product
by shifts and adds (RV32I has no multiply): over the bits of h's limb.

c2xr ( src ks dst n -- ): n bytes of src XORed with the bytes at ks, at
dst.

fam's calls leave ra alone, so a raw word may use it."""
import sys

QR = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
      (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]
REG = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
       "t0", "t1", "t2", "t3", "t4", "t5", "t6", "ra"]


def c2raw():
    out = [
        "addi sp,sp,-8",
        "sw s0,0(sp)",
        "sw s1,4(sp)",
        "lw s1,12(sp)         # st",
    ]
    out += [f"lw {REG[i]},{4 * i}(s1)" for i in range(16)]

    def rotl(x, n):
        return [f"slli s0,{x},{n}", f"srli {x},{x},{32 - n}", f"or {x},{x},s0"]

    for _ in range(10):
        for a, b, c, d in QR:
            a, b, c, d = REG[a], REG[b], REG[c], REG[d]
            out += [f"add {a},{a},{b}", f"xor {d},{d},{a}"] + rotl(d, 16)
            out += [f"add {c},{c},{d}", f"xor {b},{b},{c}"] + rotl(b, 12)
            out += [f"add {a},{a},{b}", f"xor {d},{d},{a}"] + rotl(d, 8)
            out += [f"add {c},{c},{d}", f"xor {b},{b},{c}"] + rotl(b, 7)
    # out = x + st: x0 stored first, a0 then the temporary; x0's sum last
    out += ["lw s0,8(sp)          # out", "sw a0,0(s0)"]
    for i in range(1, 16):
        out += [f"lw a0,{4 * i}(s1)", f"add {REG[i]},{REG[i]},a0", f"sw {REG[i]},{4 * i}(s0)"]
    out += ["lw a0,0(s0)", "lw a1,0(s1)", "add a0,a0,a1", "sw a0,0(s0)"]
    out += ["lw a0,48(s1)         # the counter", "addi a0,a0,1", "sw a0,48(s1)"]
    out += ["lw s0,0(sp)", "lw s1,4(sp)", "addi sp,sp,16"]
    return out


def p1raw():
    out = [
        "lw a3,0(sp)          # x",
        "lw a2,4(sp)          # c",
        "lw a1,8(sp)          # r",
        "lw a0,12(sp)         # h",
        "addi sp,sp,16",
        "li t0,0              # h += c, carried",
    ]
    for i in range(17):
        out += [f"lw t1,{4 * i}(a2)", f"lw t2,{4 * i}(a0)", "add t0,t0,t1", "add t0,t0,t2",
                "andi t1,t0,255", f"sw t1,{4 * i}(a0)", "srli t0,t0,8"]
    # x[i] = sum over j of h[j] r[i-j] (j <= i) or h[j] 320 r[i+17-j]
    out += [
        "li a4,0              # i",
        "li a7,17",
        "p1o:",
        "li a5,0              # x[i]",
        "li a6,0              # j",
        "p1i:",
        "slli t0,a6,2",
        "add t0,t0,a0",
        "lw t1,0(t0)          # h[j]",
        "sub t2,a4,a6",
        "bge a4,a6,p1n",
        "addi t2,t2,17",
        "slli t3,t2,2",
        "add t3,t3,a1",
        "lw t3,0(t3)",
        "slli t4,t3,8",
        "slli t3,t3,6",
        "add t3,t3,t4         # 320 r[i+17-j]",
        "j p1m",
        "p1n:",
        "slli t3,t2,2",
        "add t3,t3,a1",
        "lw t3,0(t3)          # r[i-j]",
        "p1m:",
        "beqz t1,p1e",
        "andi t4,t1,1",
        "beqz t4,p1s",
        "add a5,a5,t3",
        "p1s:",
        "slli t3,t3,1",
        "srli t1,t1,1",
        "j p1m",
        "p1e:",
        "addi a6,a6,1",
        "blt a6,a7,p1i",
        "slli t0,a4,2",
        "add t0,t0,a3",
        "sw a5,0(t0)",
        "addi a4,a4,1",
        "blt a4,a7,p1o",
        "li t0,0              # h = x, the low 16 limbs carried",
    ]
    for i in range(16):
        out += [f"lw t1,{4 * i}(a3)", "add t0,t0,t1", "andi t1,t0,255", f"sw t1,{4 * i}(a0)", "srli t0,t0,8"]
    out += ["lw t1,64(a3)", "add t0,t0,t1", "andi t1,t0,3", "sw t1,64(a0)",
            "srli t0,t0,2", "slli t1,t0,2", "add t0,t0,t1        # (u >> 2) 5"]
    for i in range(16):
        out += [f"lw t1,{4 * i}(a0)", "add t0,t0,t1", "andi t1,t0,255", f"sw t1,{4 * i}(a0)", "srli t0,t0,8"]
    out += ["lw t1,64(a0)", "add t0,t0,t1", "sw t0,64(a0)"]
    return out


def c2xr():
    return [
        "lw t3,0(sp)          # n",
        "lw t2,4(sp)          # dst",
        "lw t1,8(sp)          # ks",
        "lw t0,12(sp)         # src",
        "addi sp,sp,16",
        "c2xl:",
        "beqz t3,c2xe",
        "lbu t4,0(t0)",
        "lbu t5,0(t1)",
        "xor t4,t4,t5",
        "sb t4,0(t2)",
        "addi t0,t0,1",
        "addi t1,t1,1",
        "addi t2,t2,1",
        "addi t3,t3,-1",
        "j c2xl",
        "c2xe:",
        "addi zero,zero,0",
    ]


if __name__ == "__main__":
    print("\n".join({"c2raw": c2raw, "p1raw": p1raw, "c2xr": c2xr}[sys.argv[1]]()))
