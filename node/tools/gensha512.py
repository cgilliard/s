#!/usr/bin/env python3
"""Generates the assembly of src/user/crypto/sha512.fam's raw word h5raw
( blk st k s -- ): SHA-512's compression of the 128-byte block at blk into
the state at st (8 values), with the round constants at k (80) and a
scratch area at s (0x7C4 bytes).  A 64-bit value is two words, the high
one first.  Through tools/asm2fam.py:

    tools/gensha512.py > /tmp/h5.s && tools/asm2fam.py /tmp/h5.s

The scratch: W, the schedule (80 values, at s); A and E (84 values each,
at s+0x280 and s+0x520), the working variables as two sequences: at round
t, a b c d are A[t+3] A[t+2] A[t+1] A[t] and e f g h are E[t+3] .. E[t];
a round writes A[t+4] = T1 + T2 and E[t+4] = d + T1, so nothing moves;
and the state's address (s+0x7C0).  Registers: a0 A's pointer, a1 E's,
a2 K's, a3 W's, a4 the end of K; a5 a6 and a7 ra two accumulators; t0 to
t6 temporaries.  fam's calls leave ra alone, so a raw word may use it."""


def rot(dst, hi, lo, n, tmp):
    """dst (two registers) = (hi, lo) rotated right by n, 0 < n < 64, n != 32."""
    if n > 32:
        hi, lo, n = lo, hi, n - 32
    dh, dl = dst
    return [
        f"srli {dh},{hi},{n}", f"slli {tmp},{lo},{32 - n}", f"or {dh},{dh},{tmp}",
        f"srli {dl},{lo},{n}", f"slli {tmp},{hi},{32 - n}", f"or {dl},{dl},{tmp}",
    ]


def shr(dst, hi, lo, n, tmp):
    """dst = (hi, lo) shifted right by n, 0 < n < 32."""
    dh, dl = dst
    return [f"srli {dh},{hi},{n}", f"srli {dl},{lo},{n}", f"slli {tmp},{hi},{32 - n}", f"or {dl},{dl},{tmp}"]


def xorin(acc, part):
    return [f"xor {acc[0]},{acc[0]},{part[0]}", f"xor {acc[1]},{acc[1]},{part[1]}"]


def add(acc, x, tmp):
    """acc += x (pairs), the carry from the low words."""
    ah, al = acc
    xh, xl = x
    return [f"add {al},{al},{xl}", f"sltu {tmp},{al},{xl}", f"add {ah},{ah},{xh}", f"add {ah},{ah},{tmp}"]


def load(pair, base, off):
    return [f"lw {pair[0]},{off}({base})", f"lw {pair[1]},{off + 4}({base})"]


def store(pair, base, off):
    return [f"sw {pair[0]},{off}({base})", f"sw {pair[1]},{off + 4}({base})"]


def sigma(acc, hi, lo, r1, r2, last, shift):
    """acc = rotr(r1) ^ rotr(r2) ^ (shr or rotr)(last) of (hi, lo); t2..t6 free."""
    out = rot(acc, hi, lo, r1, "t6")
    out += rot(("t2", "t3"), hi, lo, r2, "t6") + xorin(acc, ("t2", "t3"))
    out += (shr if shift else rot)(("t2", "t3"), hi, lo, last, "t6") + xorin(acc, ("t2", "t3"))
    return out


def gen():
    out = [
        "lw a3,0(sp)          # s: W",
        "lw a2,4(sp)          # k",
        "lw t0,8(sp)          # st",
        "lw t1,12(sp)         # blk",
        "addi sp,sp,16",
        "sw t0,0x7C0(a3)      # st kept",
        "addi a0,a3,0x280     # A",
        "addi a1,a3,0x520     # E",
    ]
    # W[0..15], big-endian, from the block
    for i in range(32):
        out += [f"lbu t2,{4 * i}(t1)", "slli t2,t2,24"]
        for j, sh in ((1, 16), (2, 8)):
            out += [f"lbu t3,{4 * i + j}(t1)", f"slli t3,t3,{sh}", "or t2,t2,t3"]
        out += [f"lbu t3,{4 * i + 3}(t1)", "or t2,t2,t3", f"sw t2,{4 * i}(a3)"]
    # W[16..79]: s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]
    out += ["addi t1,a3,128      # &W[16]", "addi a4,a3,640      # &W[80]", "h5_sched:"]
    out += ["lw t0,-16(t1)", "lw t4,-12(t1)        # W[t-2]"]
    out += sigma(("a5", "a6"), "t0", "t4", 19, 61, 6, True)
    out += ["lw t0,-56(t1)", "lw t4,-52(t1)        # W[t-7]"] + add(("a5", "a6"), ("t0", "t4"), "t5")
    out += ["lw t0,-120(t1)", "lw t4,-116(t1)      # W[t-15]"]
    out += sigma(("a7", "ra"), "t0", "t4", 1, 8, 7, True)
    out += add(("a5", "a6"), ("a7", "ra"), "t5")
    out += ["lw t0,-128(t1)", "lw t4,-124(t1)      # W[t-16]"] + add(("a5", "a6"), ("t0", "t4"), "t5")
    out += ["sw a5,0(t1)", "sw a6,4(t1)", "addi t1,t1,8", "bne t1,a4,h5_sched"]
    # A[0..3] = d c b a, E[0..3] = h g f e
    out += ["lw t1,0x7C0(a3)      # st"]
    for i, src in enumerate((3, 2, 1, 0)):
        out += load(("t2", "t3"), "t1", 8 * src) + store(("t2", "t3"), "a0", 8 * i)
    for i, src in enumerate((7, 6, 5, 4)):
        out += load(("t2", "t3"), "t1", 8 * src) + store(("t2", "t3"), "a1", 8 * i)
    out += ["addi a4,a2,640       # the end of K", "h5_round:"]
    # T1 = h + S1(e) + Ch(e, f, g) + K[t] + W[t], in a5 a6
    out += load(("t0", "t1"), "a1", 24) + ["# e"]
    out += sigma(("a5", "a6"), "t0", "t1", 14, 18, 41, False)
    out += load(("t2", "t3"), "a1", 16) + load(("t4", "t5"), "a1", 8)   # f, g
    out += ["xor t2,t2,t4", "xor t3,t3,t5", "and t2,t2,t0", "and t3,t3,t1", "xor t2,t2,t4", "xor t3,t3,t5"]
    out += add(("a5", "a6"), ("t2", "t3"), "t6")
    out += load(("t2", "t3"), "a1", 0) + add(("a5", "a6"), ("t2", "t3"), "t6")      # h
    out += load(("t2", "t3"), "a2", 0) + add(("a5", "a6"), ("t2", "t3"), "t6")      # K[t]
    out += load(("t2", "t3"), "a3", 0) + add(("a5", "a6"), ("t2", "t3"), "t6")      # W[t]
    # E[t+4] = d + T1
    out += load(("t2", "t3"), "a0", 0) + add(("t2", "t3"), ("a5", "a6"), "t6") + store(("t2", "t3"), "a1", 32)
    # T2 = S0(a) + Maj(a, b, c), in a7 ra
    out += load(("t0", "t1"), "a0", 24)
    out += sigma(("a7", "ra"), "t0", "t1", 28, 34, 39, False)
    out += load(("t2", "t3"), "a0", 16) + load(("t4", "t5"), "a0", 8)   # b, c
    out += ["or t6,t0,t2", "and t6,t6,t4", "and t2,t2,t0", "or t2,t2,t6",
            "or t6,t1,t3", "and t6,t6,t5", "and t3,t3,t1", "or t3,t3,t6"]
    out += add(("a7", "ra"), ("t2", "t3"), "t6")
    # A[t+4] = T1 + T2
    out += add(("a7", "ra"), ("a5", "a6"), "t6") + store(("a7", "ra"), "a0", 32)
    out += ["addi a0,a0,8", "addi a1,a1,8", "addi a2,a2,8", "addi a3,a3,8", "bne a2,a4,h5_round"]
    # the state += a b c d (A[83..80]), e f g h (E[83..80]); a0 a1 at A[80] E[80]
    out += ["addi a3,a3,-640      # W again", "lw t1,0x7C0(a3)      # st"]
    for i in range(8):
        base, off = ("a0", 8 * (3 - i)) if i < 4 else ("a1", 8 * (7 - i))
        out += load(("t2", "t3"), "t1", 8 * i) + load(("t4", "t5"), base, off)
        out += add(("t2", "t3"), ("t4", "t5"), "t6") + store(("t2", "t3"), "t1", 8 * i)
    return "\n".join(out)


if __name__ == "__main__":
    print(gen())
