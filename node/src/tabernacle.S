# MIT License
#
# Copyright (c) 2026 Christopher Gilliard
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# tabernacle -- the fam node's boot program (docs/TABERNACLE.md).
#
# Runs the node image from the virtio-blk disk if the disk holds it, else
# fetches it from the network, one peer at a time; either way only an image
# of the patched-in size and Gimli-Hash is run.  The image is placed at
# 0x80000000, where q32 would load it, so tabernacle first moves itself to
# RELOC (its code is position-independent) and runs from there.
#
# Converted to src/tabernacle.fam0 by tools/s2fam0_fam.py, which prepends
# the q32 magic (a nop): this file's first instruction runs at 0x80000004.
#
# Registers kept throughout:
#   s0 = VARS   s1 = virtio-net base (0: none)   s2 = time discovery began
#   s3 = now (read once a pass of the main loop)  s4 = the patched config
# Functions take a0-a2, return a0, and may clobber t0-t6 and a0-a5; one that
# uses s5-s11 saves them.  Calls are jal ra / ret; sp is a small stack.
# ---------------------------------------------------------------------------

.option norelax
.altmacro

.macro LOAD_ADDRESS reg, label
_base\@:
        .equ _offset\@, (\label - _base\@)
        auipc   \reg, %hi(_offset\@)
        addi    \reg, \reg, %lo(_offset\@)
.endm

.macro PUSH r0, r1=zero, r2=zero, r3=zero
        addi    sp, sp, -16
        sw      \r0, 0(sp)
        sw      \r1, 4(sp)
        sw      \r2, 8(sp)
        sw      \r3, 12(sp)
.endm

.macro POP r0, r1=zero, r2=zero, r3=zero
        lw      \r0, 0(sp)
        .ifnc \r1, zero
        lw      \r1, 4(sp)
        .endif
        .ifnc \r2, zero
        lw      \r2, 8(sp)
        .endif
        .ifnc \r3, zero
        lw      \r3, 12(sp)
        .endif
        addi    sp, sp, 16
.endm

# --- memory -----------------------------------------------------------------
.equ IMAGE,     0x80000000      # the node image, where q32 would load it
.equ RELOC,     0x87F00000      # tabernacle, moved
.equ RXQ,       0x87F10000      # virtqueues: two pages each (legacy layout)
.equ TXQ,       0x87F12000
.equ BLKQ,      0x87F14000
.equ RXBUF,     0x87F16000      # QN receive buffers of 2 KiB
.equ TXBUF,     0x87F1A000      # one transmit buffer
.equ BLKHDR,    0x87F1A800      # a disk request's header; its status at +16
.equ PEERS,     0x87F1B000      # MAXPEERS entries of 32 bytes
.equ VARS,      0x87F1C000
.equ STACK,     0x87F20000
.equ SEEDS,     0x87FFF000      # from scripts/node.sh: count u8, then
                                # 4 address bytes and a port (u16 LE) each

# --- devices (QEMU virt) ----------------------------------------------------
.equ UART,      0x10000000
.equ FINISHER,  0x00100000
.equ MTIME,     0x0200BFF8      # 10 MHz
.equ VIRTIO,    0x10001000      # 8 virtio-mmio slots, 0x1000 apart
.equ QN,        8               # entries per virtqueue

# --- network ----------------------------------------------------------------
.equ MYIP,      0x0F02000A      # 10.0.2.15, QEMU user networking's guest
.equ GWIP,      0x0202000A      # 10.0.2.2, its gateway
.equ PORT,      3737
.equ MAGIC,     0x31424154      # "TAB1"
.equ T_PING, 1
.equ T_PONG, 2
.equ T_GET_PEERS, 3
.equ T_PEERS, 4
.equ T_GET_IMAGES, 64
.equ T_IMAGES, 65
.equ T_GET_IMAGE, 66
.equ T_IMAGE_CHUNK, 67
.equ PAYLOAD,   TXBUF + 52      # virtio header 10, Ethernet 14, IP 20, UDP 8
.equ MAXPEERS,  64
.equ BATCH,     32              # chunks asked for at once
.equ TICK,      10000000        # 1 s: retries, and a download's patience
.equ WAIT,      100000000       # 10 s before the seeds are asked for the image

# --- VARS -------------------------------------------------------------------
.equ V_MAC, 0           # ours (6)
.equ V_GW, 8            # the gateway's (6)
.equ V_GWOK, 16         # nonzero once known
.equ V_RXSEEN, 20       # used receive entries handled
.equ V_RXAV, 24         # receive buffers handed to the device
.equ V_TXAV, 28         # frames sent
.equ V_ARPT, 32         # when ARP last asked for the gateway
.equ V_NPEERS, 36
.equ V_CUR, 40          # the peer downloading from (0: none)
.equ V_BASE, 44         # first chunk of the batch
.equ V_MASK, 48         # chunks of the batch arrived
.equ V_N, 52            # chunks in the batch
.equ V_LAST, 56         # when the batch last moved
.equ V_STRIKES, 60      # times it did not, in a row
.equ V_NCHUNKS, 64
.equ V_BLK, 68          # virtio-blk base (0: none)
.equ V_BLKAV, 72        # disk requests made
.equ V_RAND, 76         # rand_peer's state, stirred by each frame's arrival time
.equ V_HS, 80           # the hash state (48)
.equ V_SIZE, 128

# --- a peer -----------------------------------------------------------------
.equ P_IP, 0            # 4 address bytes, as get32le reads them
.equ P_PORT, 4          # u16
.equ P_SEED, 6          # 1 for a seed
.equ P_STATE, 7         # 0 pinging, 1 asking, 2 has our image, 3 done, 4 dropped
.equ P_TOKEN, 8         # what its Pong gave us (8)
.equ P_LAST, 16         # when last asked
.equ P_TRIES, 20

# ===========================================================================
# Harts other than 0 wait, before anything else (docs/OS.md, section 3; the
# same sequence, word for word, as lib/stdlib.fam's): each copies the wait
# loop to 0x87FF1F00, marks its mailbox word (0x87FF1000 + 4*hartid) present,
# and sleeps there until the OS writes it a record to go to.  Hart 0 boots.
_start:
        csrr    t0, mhartid
        beqz    t0, park_go
park_here:
        auipc   t1, 0
        addi    t1, t1, 96              # park_code (the assembler takes no
        li      t2, 0x87FF1F00          #   forward difference here)
        li      t3, 10                  # its words
1:      lw      t4, 0(t1)
        sw      t4, 0(t2)
        addi    t1, t1, 4
        addi    t2, t2, 4
        addi    t3, t3, -1
        bnez    t3, 1b
        li      t2, 0x87FF1F00
        li      t1, 960
        bgeu    t0, t1, park_many
        slli    t0, t0, 2               # its mailbox word
        li      t1, 0x87FF1000
        add     t0, t0, t1
        li      t1, 1                   # present
        sw      t1, 0(t0)
        fence
        jr      t2
park_many:
        addi    t2, t2, 32              # a hart id past the mailboxes: sleep
        jr      t2
park_code:                              # (copied to 0x87FF1F00)
        li      t1, 8                   # software interrupts wake wfi
        csrs    mie, t1
2:      wfi
        lw      a0, 0(t0)
        li      t1, 1
        bgeu    t1, a0, 2b              # 0 or 1: not released yet
        lw      t1, 0(a0)               # the record's first word: where to go
        jr      t1
park_dead:
        wfi
        j       park_dead
park_go:
# Move to RELOC and go on there.
        LOAD_ADDRESS t0, _start
        addi    t0, t0, -4              # where we were loaded (the magic)
        LOAD_ADDRESS t4, main
        sub     t4, t4, t0
        li      t2, RELOC
        add     t4, t4, t2              # main, moved
        LOAD_ADDRESS t1, _end
1:      lw      t3, 0(t0)
        sw      t3, 0(t2)
        addi    t0, t0, 4
        addi    t2, t2, 4
        bltu    t0, t1, 1b
        jr      t4

main:
        li      sp, STACK
        li      s0, VARS
        li      s1, 0
        mv      a0, s0
        li      a1, V_SIZE
        jal     zero_bytes
        jal     settle
        LOAD_ADDRESS s4, cfg_version
        lw      t0, 4(s4)
        LOAD_ADDRESS a0, msg_unpatched
        beqz    t0, fail                # size 0: never patched
        addi    t0, t0, 1023
        srli    t0, t0, 10
        sw      t0, V_NCHUNKS(s0)

# --- the disk ----------------------------------------------------------------
        li      a0, 2                   # virtio-blk
        jal     find_dev
        sw      a0, V_BLK(s0)
        beqz    a0, net
        jal     dev_init
        lw      a0, V_BLK(s0)
        li      a1, 0
        li      a2, BLKQ
        jal     queue_init
        lw      a0, V_BLK(s0)
        jal     dev_ok
        jal     disk_read
        bnez    a0, net
        jal     check_image
        beqz    a0, net
        LOAD_ADDRESS a0, msg_disk
        jal     puts
        j       run

# --- the network -------------------------------------------------------------
net:
        li      a0, 1                   # virtio-net
        jal     find_dev
        mv      s1, a0
        LOAD_ADDRESS a0, msg_nonet
        beqz    s1, fail
        jal     net_init
        jal     now
        mv      s2, a0
        mv      s3, a0
        sw      a0, V_RAND(s0)          # QEMU's start-up jitter: the seeds' order
        li      a0, SEEDS
        li      a1, 1
        jal     add_peers
        jal     arp_request
loop:
        jal     poll_rx
        jal     now
        mv      s3, a0
        lw      t0, V_GWOK(s0)
        bnez    t0, 1f
        lw      t1, V_ARPT(s0)          # no gateway yet: ask again each second
        sub     t1, s3, t1
        li      t2, TICK
        bltu    t1, t2, loop
        jal     arp_request
        j       loop
1:      jal     discover
        jal     download
        j       loop

# Hand over: devices reset (so nothing more is written to memory), the
# registers as QEMU's reset leaves them but t0, and on to the image.
run:
        beqz    s1, 1f
        sw      zero, 0x70(s1)
1:      lw      t0, V_BLK(s0)
        beqz    t0, 2f
        sw      zero, 0x70(t0)
2:      li      ra, 0
        li      sp, 0
        li      gp, 0
        li      tp, 0
        li      t1, 0
        li      t2, 0
        li      s0, 0
        li      s1, 0
        li      a0, 0
        li      a1, 0
        li      a2, 0
        li      a3, 0
        li      a4, 0
        li      a5, 0
        li      a6, 0
        li      a7, 0
        li      s2, 0
        li      s3, 0
        li      s4, 0
        li      s5, 0
        li      s6, 0
        li      s7, 0
        li      s8, 0
        li      s9, 0
        li      s10, 0
        li      s11, 0
        li      t3, 0
        li      t4, 0
        li      t5, 0
        li      t6, 0
        li      t0, IMAGE
        jr      t0

# a0 = message: print it and exit 1.
fail:
        jal     puts
        li      t0, FINISHER
        li      t1, 0x13333             # exit 1
        sw      t1, 0(t0)
        j       .

# ===========================================================================
# Discovery: each peer still being asked is asked again each second, three
# times at most: a Ping until its Pong gives us its token, then GetPeers and
# GetImages until its Images says whether it has our image.  In table order,
# which add_peers keeps shuffled: the first to answer gets the download, so
# no peer is always asked first.
discover:
        PUSH    ra, s5, s6
        li      s5, PEERS
        lw      s6, V_NPEERS(s0)
        slli    s6, s6, 5
        add     s6, s6, s5
1:      bgeu    s5, s6, 9f
        lbu     t0, P_STATE(s5)
        li      t1, 2
        bgeu    t0, t1, 8f              # asked enough
        lw      t1, P_LAST(s5)
        sub     t1, s3, t1
        li      t2, TICK
        bltu    t1, t2, 8f
        lw      t1, P_TRIES(s5)
        li      t2, 3
        bltu    t1, t2, 2f
        li      t1, 3                   # no answer: done with it
        sb      t1, P_STATE(s5)
        j       8f
2:      addi    t1, t1, 1
        sw      t1, P_TRIES(s5)
        sw      s3, P_LAST(s5)
        mv      a0, s5
        bnez    t0, 3f
        jal     send_ping
        j       8f
3:      li      a1, T_GET_PEERS
        jal     send_token
        mv      a0, s5
        li      a1, T_GET_IMAGES
        jal     send_token
8:      addi    s5, s5, 32
        j       1b
9:      POP     ra, s5, s6
        ret

# The download: from a peer that has our image, the non-seeds first; the
# seeds once WAIT has passed and no other has it.  Nobody left to ask, and
# nobody still being asked: fail.
download:
        PUSH    ra
        lw      a0, V_CUR(s0)
        beqz    a0, 2f
        lw      t1, V_LAST(s0)          # downloading: has it stalled?
        sub     t1, s3, t1
        li      t2, TICK
        bltu    t1, t2, 9f
        lw      t1, V_STRIKES(s0)
        addi    t1, t1, 1
        sw      t1, V_STRIKES(s0)
        li      t2, 4
        bltu    t1, t2, 1f
        LOAD_ADDRESS a0, msg_silent
        jal     drop
        j       9f
1:      jal     ask_batch               # ask again for what is missing
        j       9f
2:      li      a1, 0
        jal     find_cand
        bnez    a0, 3f
        sub     t1, s3, s2
        li      t2, WAIT
        bltu    t1, t2, 9f
        li      a1, 1
        jal     find_cand
        bnez    a0, 3f
        jal     pending
        bnez    a0, 9f
        LOAD_ADDRESS a0, msg_none
        j       fail
3:      sw      a0, V_CUR(s0)
        sw      zero, V_BASE(s0)
        sw      zero, V_MASK(s0)
        sw      zero, V_STRIKES(s0)
        LOAD_ADDRESS a0, msg_from
        jal     puts
        lw      a0, V_CUR(s0)
        jal     put_peer
        jal     ask_batch
9:      POP     ra
        ret

# a1 = 0 for a non-seed, 1 for a seed: a0 = the first such peer with our
# image (the table is shuffled), or 0.
find_cand:
        li      a0, PEERS
        lw      t0, V_NPEERS(s0)
        slli    t0, t0, 5
        add     t0, t0, a0
1:      bgeu    a0, t0, 2f
        lbu     t1, P_STATE(a0)
        li      t2, 2
        bne     t1, t2, 3f
        lbu     t1, P_SEED(a0)
        beq     t1, a1, 9f
3:      addi    a0, a0, 32
        j       1b
2:      li      a0, 0
9:      ret

# a0 = a peer picked at random (PEERS itself while there is none): xorshift32
# over V_RAND, masked to a power of two and drawn again past the table, as
# there is no division.  Not for secrets: for spreading the load.  Leaves
# a1-a2, t3 and t6 alone.
rand_peer:
        lw      t2, V_NPEERS(s0)
        li      a0, PEERS
        beqz    t2, 9f
        addi    t5, t2, -1
        li      t4, 0                   # a mask covering t2 - 1
1:      bgeu    t4, t5, 3f
        slli    t4, t4, 1
        addi    t4, t4, 1
        j       1b
3:      lw      t0, V_RAND(s0)
        bnez    t0, 4f
        li      t0, 0x2545F491          # xorshift never leaves 0
4:      slli    t1, t0, 13
        xor     t0, t0, t1
        srli    t1, t0, 17
        xor     t0, t0, t1
        slli    t1, t0, 5
        xor     t0, t0, t1
        sw      t0, V_RAND(s0)
        and     t1, t0, t4
        bgeu    t1, t2, 3b              # past the table: draw again
        slli    t1, t1, 5
        add     a0, a0, t1
9:      ret

# a0 = 1 while some peer is still being asked.
pending:
        li      t3, PEERS
        lw      t0, V_NPEERS(s0)
        slli    t0, t0, 5
        add     t0, t0, t3
        li      a0, 1
1:      bgeu    t3, t0, 2f
        lbu     t1, P_STATE(t3)
        li      t2, 2
        bltu    t1, t2, 9f
        addi    t3, t3, 32
        j       1b
2:      li      a0, 0
9:      ret

# a0 = message: drop the peer downloading from, and say why.
drop:
        PUSH    ra
        lw      t0, V_CUR(s0)
        li      t1, 4
        sb      t1, P_STATE(t0)
        jal     puts
        lw      a0, V_CUR(s0)
        sw      zero, V_CUR(s0)
        jal     put_peer
        POP     ra
        ret

# Ask the peer downloading from for the batch's chunks, from the first one
# still missing to the batch's end.
ask_batch:
        PUSH    ra, s5
        lw      t0, V_BASE(s0)
        lw      t1, V_NCHUNKS(s0)
        sub     t1, t1, t0
        li      t2, BATCH
        bltu    t1, t2, 1f
        mv      t1, t2
1:      sw      t1, V_N(s0)             # n = min(BATCH, chunks left)
        lw      t2, V_MASK(s0)
        li      t3, 0                   # the first missing
2:      bgeu    t3, t1, 3f
        srl     t4, t2, t3
        andi    t4, t4, 1
        beqz    t4, 3f
        addi    t3, t3, 1
        j       2b
3:      sub     s5, t1, t3              # how many from there
        add     t3, t0, t3
        slli    s5, s5, 16
        or      s5, s5, t3              # start | len << 16
        sw      s3, V_LAST(s0)
        li      a0, T_GET_IMAGE
        jal     put_head
        lw      a0, V_CUR(s0)
        jal     put_token
        li      a0, PAYLOAD + 13
        lw      a1, 0(s4)               # our version
        jal     put32le
        li      t0, PAYLOAD + 17
        li      t1, 1                   # one range
        sb      t1, 0(t0)
        li      a0, PAYLOAD + 18
        mv      a1, s5
        jal     put32le                 # start, len (u16 LE each)
        lw      a0, V_CUR(s0)
        li      a1, 22
        jal     udp_send
        POP     ra, s5
        ret

# ===========================================================================
# Received frames, until none is waiting.
poll_rx:
        PUSH    ra, s5, s6
1:      li      t0, RXQ + 4096          # used ring
        lhu     t1, 2(t0)
        lw      t2, V_RXSEEN(s0)
        slli    t3, t2, 16
        srli    t3, t3, 16
        beq     t1, t3, 9f
        andi    t3, t2, QN - 1
        slli    t3, t3, 3
        add     t3, t3, t0
        lw      s5, 4(t3)               # the buffer's descriptor
        lw      a1, 8(t3)               # bytes written
        addi    t2, t2, 1
        sw      t2, V_RXSEEN(s0)
        slli    s6, s5, 11
        li      t0, RXBUF
        add     a0, s6, t0
        jal     on_frame
        li      t0, RXQ + 16 * QN       # hand the buffer back
        lw      t1, V_RXAV(s0)
        andi    t2, t1, QN - 1
        slli    t2, t2, 1
        add     t2, t2, t0
        sh      s5, 4(t2)
        fence
        addi    t1, t1, 1
        sw      t1, V_RXAV(s0)
        sh      t1, 2(t0)
        fence
        sw      zero, 0x50(s1)          # QueueNotify: receive
        j       1b
9:      POP     ra, s5, s6
        ret

# a0 = buffer (the virtio header first), a1 = its length.
on_frame:
        PUSH    ra, s5, s6
        li      t0, MTIME               # its arrival time into rand_peer's state
        lw      t0, 0(t0)
        lw      t1, V_RAND(s0)
        xor     t1, t1, t0
        sw      t1, V_RAND(s0)
        addi    s5, a0, 10              # the Ethernet frame
        addi    s6, a1, -10
        addi    a0, s5, 12
        jal     get16be
        li      t0, 0x0806
        beq     a0, t0, on_arp
        li      t0, 0x0800
        bne     a0, t0, 9f
        mv      a0, s5
        mv      a1, s6
        jal     on_ip
9:      POP     ra, s5, s6
        ret

# The gateway's answer gives its address; a question for ours is answered.
# (Jumped to from on_frame, s5 = the frame, in on_frame's frame.)
on_arp:
        addi    a0, s5, 20
        jal     get16be                 # op
        mv      s6, a0
        addi    a0, s5, 28
        jal     get32le                 # sender's address
        li      t0, 2
        bne     s6, t0, 1f
        li      t0, GWIP
        bne     a0, t0, 9b
        addi    a0, s0, V_GW
        addi    a1, s5, 22
        li      a2, 6
        jal     copy
        li      t0, 1
        sw      t0, V_GWOK(s0)
        j       9b
1:      li      t0, 1
        bne     s6, t0, 9b
        mv      s6, a0
        addi    a0, s5, 38
        jal     get32le                 # the address asked about
        li      t0, MYIP
        bne     a0, t0, 9b
        li      a0, 2
        addi    a1, s5, 22
        mv      a2, s6
        jal     arp_send
        j       9b

# a0 = frame, a1 = its length: a UDP datagram to us from a peer we know.
on_ip:
        PUSH    ra, s5, s6, s7
        addi    s5, a0, 14              # IP header
        add     s7, a0, a1              # the frame's end
        lbu     t0, 0(s5)
        srli    t1, t0, 4
        li      t2, 4
        bne     t1, t2, 9f
        andi    t0, t0, 15
        slli    t0, t0, 2               # header length
        lbu     t1, 9(s5)
        li      t2, 17
        bne     t1, t2, 9f
        add     s6, s5, t0              # UDP header
        addi    a0, s5, 16
        jal     get32le
        li      t0, MYIP
        bne     a0, t0, 9f
        addi    a0, s6, 2
        jal     get16be
        li      t0, PORT
        bne     a0, t0, 9f
        addi    a0, s6, 4
        jal     get16be
        addi    a0, a0, -8              # payload length
        li      t0, 5
        blt     a0, t0, 9f
        addi    t1, s6, 8
        add     t1, t1, a0
        bltu    s7, t1, 9f              # past the frame
        mv      s7, a0
        addi    a0, s5, 12
        jal     get32le
        mv      s5, a0                  # source address
        mv      a0, s6
        jal     get16be                 # source port
        mv      a1, a0
        mv      a0, s5
        jal     find_peer
        beqz    a0, 9f
        mv      s5, a0                  # the peer
        addi    s6, s6, 8               # the payload
        mv      a0, s6
        jal     get32le
        li      t0, MAGIC
        bne     a0, t0, 9f
        mv      a0, s5
        mv      a1, s6
        mv      a2, s7
        lbu     t0, 4(s6)
        li      t1, T_PONG
        beq     t0, t1, on_pong
        li      t1, T_PEERS
        beq     t0, t1, on_peers
        li      t1, T_IMAGES
        beq     t0, t1, on_images
        li      t1, T_IMAGE_CHUNK
        beq     t0, t1, on_chunk
9:      POP     ra, s5, s6, s7
        ret

# The message handlers: a0 = peer, a1 = payload, a2 = its length; jumped to
# from on_ip, and back to its end.

# A Pong: the peer's token for us.  Ask it at once.
on_pong:
        li      t0, 145
        bne     a2, t0, 9b
        lbu     t0, P_STATE(a0)
        bnez    t0, 9b
        li      t0, 1
        sb      t0, P_STATE(a0)
        sw      zero, P_TRIES(a0)
        li      t0, TICK
        sub     t0, s3, t0
        sw      t0, P_LAST(a0)
        addi    a0, a0, P_TOKEN
        addi    a1, a1, 17
        li      a2, 8
        jal     copy
        j       9b

# Peers: more to ask.
on_peers:
        lbu     t0, 5(a1)
        slli    t1, t0, 1
        add     t1, t1, t0
        slli    t1, t1, 1
        addi    t1, t1, 6
        bne     a2, t1, 9b              # 6 + 6 a peer
        addi    a0, a1, 5
        li      a1, 0
        jal     add_peers
        j       9b

# Images: whether the peer has our version, at our size.
on_images:
        lbu     t0, P_STATE(a0)
        li      t1, 1
        bne     t0, t1, 9b
        lbu     t0, 5(a1)
        slli    t1, t0, 3
        addi    t1, t1, 6
        bne     a2, t1, 9b              # 6 + 8 a version
        li      t1, 3
        sb      t1, P_STATE(a0)         # unless we find it
        addi    s6, a1, 6
        slli    t0, t0, 3
        add     s7, s6, t0
1:      bgeu    s6, s7, 9b
        mv      a0, s6
        jal     get32le
        lw      t0, 0(s4)
        bne     a0, t0, 2f
        addi    a0, s6, 4
        jal     get32le
        lw      t0, 4(s4)
        bne     a0, t0, 9b              # our version at another size: not ours
        li      t1, 2
        sb      t1, P_STATE(s5)
        j       9b
2:      addi    s6, s6, 8
        j       1b

# An ImageChunk from the peer downloading from: kept if it is the size it
# should be and in the batch.  A whole batch asks for the next; the last
# checks the image.
on_chunk:
        lw      t0, V_CUR(s0)
        bne     a0, t0, 9b
        li      t0, 17
        bltu    a2, t0, 9b
        mv      s6, a1
        mv      s7, a2
        addi    a0, s6, 5
        jal     get32le
        lw      t0, 0(s4)
        bne     a0, t0, 9b              # another version
        addi    a0, s6, 9
        jal     get32le
        lw      t0, 4(s4)
        bne     a0, t0, 5f              # another size: not our image
        addi    a0, s6, 15
        jal     get16le                 # the chunk's length
        addi    t0, a0, 17
        bne     s7, t0, 9b
        mv      s7, a0
        addi    a0, s6, 13
        jal     get16le                 # its index
        lw      t0, V_BASE(s0)
        sub     t1, a0, t0
        lw      t2, V_N(s0)
        bgeu    t1, t2, 9b              # not in the batch
        mv      s5, t1
        lw      t0, V_NCHUNKS(s0)       # the length it must have
        addi    t0, t0, -1
        li      t1, 1024
        bne     a0, t0, 1f
        slli    t2, a0, 10
        lw      t1, 4(s4)
        sub     t1, t1, t2
1:      bne     s7, t1, 5f
        slli    a0, a0, 10
        li      t0, IMAGE
        add     a0, a0, t0
        addi    a1, s6, 17
        mv      a2, s7
        jal     copy
        li      t0, 1
        sll     t0, t0, s5
        lw      t1, V_MASK(s0)
        or      t1, t1, t0
        sw      t1, V_MASK(s0)
        sw      s3, V_LAST(s0)
        sw      zero, V_STRIKES(s0)
        lw      t2, V_N(s0)             # the batch whole?
        li      t3, -1
        li      t4, 32
        beq     t2, t4, 2f
        li      t3, 1
        sll     t3, t3, t2
        addi    t3, t3, -1
2:      bne     t1, t3, 9b
        lw      t0, V_BASE(s0)
        add     t0, t0, t2
        sw      t0, V_BASE(s0)
        sw      zero, V_MASK(s0)
        lw      t1, V_NCHUNKS(s0)
        bgeu    t0, t1, 3f
        jal     ask_batch
        j       9b
3:      jal     check_image
        beqz    a0, 4f
        j       run
4:      LOAD_ADDRESS a0, msg_bad
        jal     drop
        j       9b
5:      LOAD_ADDRESS a0, msg_size
        jal     drop
        j       9b

# ===========================================================================
# a0 = count byte, then 6-byte entries (4 address bytes, a u16 LE port), as
# in a Peers message; a1 = 1 if they are seeds.  Adds those not yet known,
# each swapped with an entry picked at random (an inside-out Fisher-Yates
# shuffle), so the table is always in random order and peers are asked, and
# taken, in no fixed order.
add_peers:
        PUSH    ra, s5, s6, s7
        lbu     s6, 0(a0)
        addi    s5, a0, 1
        mv      s7, a1
1:      beqz    s6, 9f
        addi    s6, s6, -1
        mv      a0, s5
        jal     get32le
        mv      t5, a0
        addi    a0, s5, 4
        jal     get16le
        mv      a1, a0
        addi    s5, s5, 6
        mv      a0, t5
        beqz    a0, 1b
        beqz    a1, 1b
        PUSH    a0, a1
        jal     find_peer
        POP     t5, t6
        bnez    a0, 1b                  # known
        lw      t0, V_NPEERS(s0)
        li      t1, MAXPEERS
        bgeu    t0, t1, 9f              # no room
        addi    t1, t0, 1
        sw      t1, V_NPEERS(s0)
        slli    t0, t0, 5
        li      t1, PEERS
        add     t0, t0, t1
        sw      t5, P_IP(t0)
        sh      t6, P_PORT(t0)
        sb      s7, P_SEED(t0)
        sb      zero, P_STATE(t0)
        sw      zero, P_TRIES(t0)
        li      t1, TICK                # due at once
        sub     t1, s3, t1
        sw      t1, P_LAST(t0)
        mv      t6, t0
        jal     rand_peer               # where it goes
        lw      t1, V_CUR(s0)           # the download's peer moves with its entry
        bne     t1, a0, 2f
        sw      t6, V_CUR(s0)
2:      li      t3, 0                   # swap the two
3:      add     t0, a0, t3
        add     t1, t6, t3
        lw      t2, 0(t0)
        lw      t4, 0(t1)
        sw      t4, 0(t0)
        sw      t2, 0(t1)
        addi    t3, t3, 4
        li      t2, 32
        bltu    t3, t2, 3b
        j       1b
9:      POP     ra, s5, s6, s7
        ret

# a0 = address, a1 = port: a0 = the peer, or 0.
find_peer:
        li      t0, PEERS
        lw      t1, V_NPEERS(s0)
        slli    t1, t1, 5
        add     t1, t1, t0
1:      bgeu    t0, t1, 2f
        lw      t2, P_IP(t0)
        lhu     t3, P_PORT(t0)
        bne     t2, a0, 3f
        beq     t3, a1, 9f
3:      addi    t0, t0, 32
        j       1b
2:      li      t0, 0
9:      mv      a0, t0
        ret

# ===========================================================================
# Sending.  A message is built at PAYLOAD; udp_send puts the headers on.

# a0 = type: "TAB1" and the type at PAYLOAD.
put_head:
        li      t0, PAYLOAD
        li      t1, MAGIC
        sw      t1, 0(t0)
        sb      a0, 4(t0)
        ret

# a0 = peer: its token at PAYLOAD + 5.
put_token:
        addi    a1, a0, P_TOKEN
        li      a0, PAYLOAD + 5
        li      a2, 8
        j       copy

# a0 = peer: a Ping, all zeros (we are not on any chain: tabminer answers
# with a Pong, and takes us for no peer).
send_ping:
        PUSH    ra, a0
        li      a0, PAYLOAD + 5
        li      a1, 140
        jal     zero_bytes
        li      a0, T_PING
        jal     put_head
        POP     ra, a0
        li      a1, 145
        j       udp_send

# a0 = peer, a1 = type: a request carrying only the token.
send_token:
        PUSH    ra, a0
        mv      a0, a1
        jal     put_head
        lw      a0, 4(sp)
        jal     put_token
        POP     ra, a0
        li      a1, 13
        j       udp_send

# a0 = peer, a1 = payload length.
udp_send:
        PUSH    ra, s5, s6, s7
        mv      s5, a0
        mv      s6, a1
        li      s7, TXBUF + 10          # the Ethernet frame
        mv      a0, s7
        addi    a1, s0, V_GW
        li      a2, 6
        jal     copy
        li      a0, 0x0800
        jal     put_eth_src
        addi    a0, s7, 14              # IP
        li      a1, 0x45                # version 4, header 20; length below
        jal     put32le
        addi    a0, s7, 16
        addi    a1, s6, 28
        jal     put16be
        addi    a0, s7, 18
        li      a1, 0x00400000          # id 0; don't fragment
        jal     put32le
        addi    a0, s7, 22
        li      a1, 0x1140              # TTL 64, UDP; checksum 0 for now
        jal     put32le
        addi    a0, s7, 26
        li      a1, MYIP
        jal     put32le
        addi    a0, s7, 30
        lw      a1, P_IP(s5)
        jal     put32le
        li      t3, 0                   # the header checksum
        li      t4, 0
1:      add     a0, s7, t4
        addi    a0, a0, 14
        jal     get16be
        add     t3, t3, a0
        addi    t4, t4, 2
        li      t0, 20
        bltu    t4, t0, 1b
        srli    t0, t3, 16
        slli    t3, t3, 16
        srli    t3, t3, 16
        add     t3, t3, t0
        srli    t0, t3, 16
        add     t3, t3, t0
        not     a1, t3
        addi    a0, s7, 24
        jal     put16be
        addi    a0, s7, 34              # UDP
        li      a1, PORT
        jal     put16be
        addi    a0, s7, 36
        lhu     a1, P_PORT(s5)
        jal     put16be
        addi    a0, s7, 38
        addi    a1, s6, 8
        jal     put16be
        addi    a0, s7, 40
        li      a1, 0                   # no UDP checksum
        jal     put16be
        addi    a0, s6, 42
        jal     send_frame
        POP     ra, s5, s6, s7
        ret

# a0 = ethertype: our address as the frame's source, and the type.
put_eth_src:
        PUSH    ra, a0
        li      a0, TXBUF + 16
        addi    a1, s0, V_MAC
        li      a2, 6
        jal     copy
        POP     ra, a1
        li      a0, TXBUF + 22
        j       put16be

# Ask for the gateway's address.
arp_request:
        sw      s3, V_ARPT(s0)
        li      a0, 1
        LOAD_ADDRESS a1, broadcast
        li      a2, GWIP
        # fall through

# a0 = op, a1 = the Ethernet address to send to (also the target's), a2 =
# the target's IP address.
arp_send:
        PUSH    ra, s5, s6, s7
        mv      s5, a0
        mv      s6, a1
        mv      s7, a2
        li      a0, TXBUF + 10
        li      a2, 6
        jal     copy
        li      a0, 0x0806
        jal     put_eth_src
        li      a0, TXBUF + 24          # Ethernet, IPv4, 6, 4
        li      a1, 0x00080100
        jal     put32le
        li      a0, TXBUF + 28
        li      a1, 0x0406
        jal     put16le
        li      a0, TXBUF + 30
        mv      a1, s5
        jal     put16be
        li      a0, TXBUF + 32          # sender: us
        addi    a1, s0, V_MAC
        li      a2, 6
        jal     copy
        li      a0, TXBUF + 38
        li      a1, MYIP
        jal     put32le
        li      a0, TXBUF + 42          # target
        mv      a1, s6
        li      a2, 6
        jal     copy
        li      a0, TXBUF + 48
        mv      a1, s7
        jal     put32le
        li      a0, 42
        jal     send_frame
        POP     ra, s5, s6, s7
        ret

# a0 = the frame's length: send TXBUF (the virtio header, zero, first) and
# wait until the device has taken it.
send_frame:
        li      t0, TXQ                 # descriptor 0
        li      t1, TXBUF
        sw      t1, 0(t0)
        sw      zero, 4(t0)
        addi    t1, a0, 10
        sw      t1, 8(t0)
        sw      zero, 12(t0)
        li      t0, TXQ + 16 * QN       # available ring
        lw      t1, V_TXAV(s0)
        andi    t2, t1, QN - 1
        slli    t2, t2, 1
        add     t2, t2, t0
        sh      zero, 4(t2)
        fence
        addi    t1, t1, 1
        sw      t1, V_TXAV(s0)
        sh      t1, 2(t0)
        fence
        li      t2, 1
        sw      t2, 0x50(s1)            # QueueNotify: transmit
        slli    t1, t1, 16
        srli    t1, t1, 16
        li      t0, TXQ + 4096
1:      lhu     t2, 2(t0)
        bne     t2, t1, 1b
        ret

# ===========================================================================
# Devices.

# a0 = device id: a0 = the virtio-mmio slot that has it, or 0.
find_dev:
        li      t0, VIRTIO
        li      t1, VIRTIO + 0x8000
        li      t2, 0x74726976          # "virt"
1:      lw      t3, 0(t0)
        bne     t3, t2, 2f
        lw      t3, 8(t0)
        beq     t3, a0, 9f
2:      addi    t0, t0, 0x7FF
        addi    t0, t0, 0x7FF
        addi    t0, t0, 2
        bltu    t0, t1, 1b
        li      t0, 0
9:      mv      a0, t0
        ret

# a0 = device: reset, acknowledged, no features, 4 KiB pages (legacy).
dev_init:
        sw      zero, 0x70(a0)
        li      t0, 1
        sw      t0, 0x70(a0)
        li      t0, 3
        sw      t0, 0x70(a0)
        sw      zero, 0x20(a0)
        li      t0, 4096
        sw      t0, 0x28(a0)
        ret

# a0 = device: running.
dev_ok:
        li      t0, 7
        sw      t0, 0x70(a0)
        ret

# a0 = device, a1 = queue, a2 = its two pages.
queue_init:
        sw      a1, 0x30(a0)
        li      t0, QN
        sw      t0, 0x38(a0)
        li      t0, 4096
        sw      t0, 0x3C(a0)
        srli    t0, a2, 12
        sw      t0, 0x40(a0)
        ret

net_init:
        PUSH    ra
        mv      a0, s1
        jal     dev_init
        mv      a0, s1
        li      a1, 0
        li      a2, RXQ
        jal     queue_init
        mv      a0, s1
        li      a1, 1
        li      a2, TXQ
        jal     queue_init
        li      t0, RXQ                 # every receive buffer to the device
        li      t1, RXBUF
        li      t3, RXQ + 16 * QN
        li      t4, 0
1:      sw      t1, 0(t0)
        sw      zero, 4(t0)
        li      t2, 2048
        sw      t2, 8(t0)
        li      t2, 2                   # device writes it
        sw      t2, 12(t0)
        slli    t2, t4, 1
        add     t2, t2, t3
        sh      t4, 4(t2)
        addi    t0, t0, 16
        li      t2, 2048
        add     t1, t1, t2
        addi    t4, t4, 1
        li      t2, QN
        bltu    t4, t2, 1b
        sw      t4, V_RXAV(s0)
        fence
        sh      t4, 2(t3)
        li      a0, TXBUF               # the virtio header we send: zero
        li      a1, 12
        jal     zero_bytes
        addi    a0, s0, V_MAC           # our address, from the config space
        addi    a1, s1, 0x100
        li      a2, 6
        jal     copy
        mv      a0, s1
        jal     dev_ok
        sw      zero, 0x50(s1)          # buffers to receive into
        POP     ra
        ret

# Read the image's size from the start of the disk to IMAGE, 64 KiB a
# request: a0 = 0 if it all read.
disk_read:
        PUSH    ra, s5, s6, s7
        lw      s6, 4(s4)
        addi    s6, s6, 511
        srli    s6, s6, 9               # sectors
        li      s5, 0
1:      bgeu    s5, s6, 8f
        sub     s7, s6, s5
        li      t0, 128
        bltu    s7, t0, 2f
        mv      s7, t0
2:      li      t0, BLKHDR              # read, at sector s5
        sw      zero, 0(t0)
        sw      zero, 4(t0)
        sw      s5, 8(t0)
        sw      zero, 12(t0)
        li      t1, 0xFF
        sb      t1, 16(t0)
        li      t1, BLKQ                # header -> data -> status
        sw      t0, 0(t1)
        sw      zero, 4(t1)
        li      t2, 16
        sw      t2, 8(t1)
        li      t2, 0x00010001          # next, then descriptor 1
        sw      t2, 12(t1)
        slli    t2, s5, 9
        li      t3, IMAGE
        add     t2, t2, t3
        sw      t2, 16(t1)
        sw      zero, 20(t1)
        slli    t2, s7, 9
        sw      t2, 24(t1)
        li      t2, 0x00020003          # next and written, then 2
        sw      t2, 28(t1)
        addi    t2, t0, 16
        sw      t2, 32(t1)
        sw      zero, 36(t1)
        li      t2, 1
        sw      t2, 40(t1)
        li      t2, 2                   # written
        sw      t2, 44(t1)
        li      t0, BLKQ + 16 * QN
        lw      t1, V_BLKAV(s0)
        andi    t2, t1, QN - 1
        slli    t2, t2, 1
        add     t2, t2, t0
        sh      zero, 4(t2)
        fence
        addi    t1, t1, 1
        sw      t1, V_BLKAV(s0)
        sh      t1, 2(t0)
        fence
        lw      t0, V_BLK(s0)
        sw      zero, 0x50(t0)
        slli    t1, t1, 16
        srli    t1, t1, 16
        li      t0, BLKQ + 4096
3:      lhu     t2, 2(t0)
        bne     t2, t1, 3b
        li      t0, BLKHDR
        lbu     a0, 16(t0)
        bnez    a0, 9f
        add     s5, s5, s7
        j       1b
8:      li      a0, 0
9:      POP     ra, s5, s6, s7
        ret

# The other harts all leave 0x80000000 (where they started, and where the
# image will be written) on their way to wait at 0x87FF1F00, each marking
# its mailbox as it goes; under QEMU, with more harts than the host has
# cores, one may take a while to be run at all, and one that runs only
# after the image is written there runs a half-written image and is lost.
# So wait for all of them: as many as the device tree QEMU puts at
# 0x87E00000 has cpu@ nodes (the kernel's fdtharts), up to 960 (harts past
# the mailboxes make no mark), for 60 s at most against a hang.  With no
# device tree, until 100 ms pass with no new mark (a slow host can make
# that too short; QEMU always gives one).
settle:
        jal     t6, fdt_harts           # a4 = the harts, 0 if no tree
        li      t0, 960
        bleu    a4, t0, 5f
        mv      a4, t0
5:      addi    a4, a4, -1              # marks to wait for (hart 0 makes none)
        li      t5, MTIME
        lw      a5, 0(t5)               # when the wait began
        lw      t6, 0(t5)               # since the last new mark
        li      a2, 0                   # marks seen
1:      li      t0, 0x87FF1000
        li      t1, 0x87FF1F00
        li      a3, 0
2:      lw      t2, 0(t0)
        addi    t2, t2, -1
        bnez    t2, 3f
        addi    a3, a3, 1
3:      addi    t0, t0, 4
        bltu    t0, t1, 2b
        bltz    a4, 6f                  # no tree: the quiet rule
        bgeu    a3, a4, 7f              # every hart marked
        lw      t4, 0(t5)
        sub     t4, t4, a5
        li      t3, TICK * 60
        bltu    t4, t3, 1b
7:      ret
6:      beq     a3, a2, 4f
        mv      a2, a3
        lw      t6, 0(t5)
4:      lw      t4, 0(t5)
        sub     t4, t4, t6
        li      t3, TICK / 10
        bltu    t4, t3, 1b
        ret

# fdt_harts (returns through t6): a4 = the cpu@ nodes of the device tree
# at 0x87E00000 (big-endian tokens: 1 begin node, its name NUL-ended and
# padded to 4; 3 a property, its length, name offset and value padded to 4;
# 9 the end), or 0 when there is no tree there.  t0..t4 used.
fdt_harts:
        li      a4, 0
        li      t0, 0x87E00000
        mv      t3, t0
        jal     t2, fdt_be
        li      t1, 0xD00DFEED
        bne     t4, t1, 9f
        addi    t3, t0, 8
        jal     t2, fdt_be              # off_dt_struct
        add     t0, t0, t4
1:      mv      t3, t0
        jal     t2, fdt_be
        li      t1, 9
        beq     t4, t1, 9f
        li      t1, 1
        bne     t4, t1, 3f
        addi    t0, t0, 4               # a node: is its name cpu@...?
        lbu     t1, 0(t0)
        li      t3, 0x63
        bne     t1, t3, 2f
        lbu     t1, 1(t0)
        li      t3, 0x70
        bne     t1, t3, 2f
        lbu     t1, 2(t0)
        li      t3, 0x75
        bne     t1, t3, 2f
        lbu     t1, 3(t0)
        li      t3, 0x40
        bne     t1, t3, 2f
        addi    a4, a4, 1
2:      lbu     t1, 0(t0)               # past the name and its NUL, to 4
        addi    t0, t0, 1
        bnez    t1, 2b
        addi    t0, t0, 3
        andi    t0, t0, -4
        j       1b
3:      li      t1, 3
        bne     t4, t1, 4f
        addi    t3, t0, 4               # a property: past its value
        jal     t2, fdt_be
        addi    t4, t4, 3
        andi    t4, t4, -4
        addi    t0, t0, 12
        add     t0, t0, t4
        j       1b
4:      addi    t0, t0, 4               # anything else: one token
        j       1b
9:      jr      t6

# fdt_be (returns through t2): t4 = the big-endian word at t3.  t1 used.
fdt_be:
        lbu     t4, 0(t3)
        slli    t4, t4, 8
        lbu     t1, 1(t3)
        or      t4, t4, t1
        slli    t4, t4, 8
        lbu     t1, 2(t3)
        or      t4, t4, t1
        slli    t4, t4, 8
        lbu     t1, 3(t3)
        or      t4, t4, t1
        jr      t2

# a0 = time (MTIME's low word).
now:
        li      t0, MTIME
        lw      a0, 0(t0)
        ret

# ===========================================================================
# The Gimli-Hash of the image (as src/gen_hash.fam computes it): a0 = 1 if it
# is the patched one.
check_image:
        PUSH    ra, s5, s6, s7
        addi    s7, s0, V_HS
        mv      a0, s7
        li      a1, 48
        jal     zero_bytes
        li      s5, IMAGE
        lw      s6, 4(s4)
1:      li      t0, 16                  # whole blocks
        bltu    s6, t0, 2f
        li      t0, 0
3:      add     t1, s5, t0
        lw      t1, 0(t1)
        add     t2, s7, t0
        lw      t3, 0(t2)
        xor     t3, t3, t1
        sw      t3, 0(t2)
        addi    t0, t0, 4
        li      t1, 16
        bltu    t0, t1, 3b
        mv      a0, s7
        jal     gimli
        addi    s5, s5, 16
        addi    s6, s6, -16
        j       1b
2:      li      t0, 0                   # the rest, and the padding
4:      bgeu    t0, s6, 5f
        add     t1, s5, t0
        lbu     t1, 0(t1)
        add     t2, s7, t0
        lbu     t3, 0(t2)
        xor     t3, t3, t1
        sb      t3, 0(t2)
        addi    t0, t0, 1
        j       4b
5:      add     t2, s7, s6
        lbu     t3, 0(t2)
        xori    t3, t3, 1
        sb      t3, 0(t2)
        lbu     t3, 15(s7)
        xori    t3, t3, 0x80
        sb      t3, 15(s7)
        lbu     t3, 47(s7)
        xori    t3, t3, 1
        sb      t3, 47(s7)
        li      s6, 0                   # differences
        addi    s5, s4, 8               # the patched hash
        jal     6f
        jal     6f
        seqz    a0, s6
        POP     ra, s5, s6, s7
        ret
6:      PUSH    ra                      # squeeze 16 bytes, compare them
        mv      a0, s7
        jal     gimli
        li      t0, 0
7:      add     t1, s7, t0
        lw      t1, 0(t1)
        add     t2, s5, t0
        lw      t2, 0(t2)
        xor     t1, t1, t2
        or      s6, s6, t1
        addi    t0, t0, 4
        li      t1, 16
        bltu    t0, t1, 7b
        addi    s5, s5, 16
        POP     ra
        ret

# a0 = the 12-word state: the Gimli permutation.
gimli:
        li      a1, 24
1:      mv      a2, a0
        addi    a3, a0, 16
2:      lw      t0, 0(a2)               # x = s[c] <<< 24
        slli    t3, t0, 24
        srli    t0, t0, 8
        or      t0, t0, t3
        lw      t1, 16(a2)              # y = s[4 + c] <<< 9
        slli    t3, t1, 9
        srli    t1, t1, 23
        or      t1, t1, t3
        lw      t2, 32(a2)              # z = s[8 + c]
        slli    t3, t2, 1               # x ^ (z << 1) ^ ((y & z) << 2)
        and     t4, t1, t2
        slli    t4, t4, 2
        xor     t3, t3, t4
        xor     t3, t3, t0
        sw      t3, 32(a2)
        or      t4, t0, t2              # y ^ x ^ ((x | z) << 1)
        slli    t4, t4, 1
        xor     t4, t4, t1
        xor     t4, t4, t0
        sw      t4, 16(a2)
        and     t4, t0, t1              # z ^ y ^ ((x & y) << 3)
        slli    t4, t4, 3
        xor     t4, t4, t2
        xor     t4, t4, t1
        sw      t4, 0(a2)
        addi    a2, a2, 4
        bltu    a2, a3, 2b
        andi    t0, a1, 3
        bnez    t0, 3f
        lw      t1, 0(a0)               # small swap, and the round constant
        lw      t2, 4(a0)
        li      t3, 0x9E377900
        or      t3, t3, a1
        xor     t2, t2, t3
        sw      t2, 0(a0)
        sw      t1, 4(a0)
        lw      t1, 8(a0)
        lw      t2, 12(a0)
        sw      t2, 8(a0)
        sw      t1, 12(a0)
        j       4f
3:      li      t1, 2
        bne     t0, t1, 4f
        lw      t1, 0(a0)               # big swap
        lw      t2, 8(a0)
        sw      t2, 0(a0)
        sw      t1, 8(a0)
        lw      t1, 4(a0)
        lw      t2, 12(a0)
        sw      t2, 4(a0)
        sw      t1, 12(a0)
4:      addi    a1, a1, -1
        bnez    a1, 1b
        ret

# ===========================================================================
# Bytes.  These clobber only t0-t1 (and a0).

# a0 = destination, a1 = source, a2 = count.
copy:
        beqz    a2, 9f
        lbu     t0, 0(a1)
        sb      t0, 0(a0)
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        j       copy
9:      ret

# a0 = address, a1 = count.
zero_bytes:
        beqz    a1, 9f
        sb      zero, 0(a0)
        addi    a0, a0, 1
        addi    a1, a1, -1
        j       zero_bytes
9:      ret

get16be:
        lbu     t0, 0(a0)
        lbu     t1, 1(a0)
        slli    t0, t0, 8
        or      a0, t0, t1
        ret

get16le:
        lbu     t0, 0(a0)
        lbu     t1, 1(a0)
        slli    t1, t1, 8
        or      a0, t0, t1
        ret

get32le:
        lbu     t0, 3(a0)
        lbu     t1, 2(a0)
        slli    t0, t0, 8
        or      t0, t0, t1
        lbu     t1, 1(a0)
        slli    t0, t0, 8
        or      t0, t0, t1
        lbu     t1, 0(a0)
        slli    t0, t0, 8
        or      a0, t0, t1
        ret

# a0 = address, a1 = value.
put16be:
        srli    t0, a1, 8
        sb      t0, 0(a0)
        sb      a1, 1(a0)
        ret

put16le:
        sb      a1, 0(a0)
        srli    t0, a1, 8
        sb      t0, 1(a0)
        ret

put32le:
        sb      a1, 0(a0)
        srli    t0, a1, 8
        sb      t0, 1(a0)
        srli    t0, a1, 16
        sb      t0, 2(a0)
        srli    t0, a1, 24
        sb      t0, 3(a0)
        ret

# ===========================================================================
# The serial port.

# a0 = a NUL-terminated string.
puts:
        li      t0, UART
1:      lbu     t1, 0(a0)
        beqz    t1, 9f
        sb      t1, 0(t0)
        addi    a0, a0, 1
        j       1b
9:      ret

# a0 = a number below 100,000, in decimal.
put_dec:
        li      t0, UART
        LOAD_ADDRESS t1, tens
        li      t4, 0                   # a digit printed yet
1:      lw      t2, 0(t1)
        beqz    t2, 9f
        li      t3, 0
2:      bltu    a0, t2, 3f
        sub     a0, a0, t2
        addi    t3, t3, 1
        j       2b
3:      or      t4, t4, t3
        li      t5, 1
        beq     t2, t5, 4f              # the last digit, even 0
        beqz    t4, 5f
4:      addi    t3, t3, '0'
        sb      t3, 0(t0)
5:      addi    t1, t1, 4
        j       1b
9:      ret

# a0 = peer: "a.b.c.d:port" and a newline.
put_peer:
        PUSH    ra, s5, s6
        mv      s5, a0
        li      s6, 0
1:      add     t0, s5, s6
        lbu     a0, P_IP(t0)
        jal     put_dec
        li      t0, UART
        li      t1, '.'
        li      t2, 3
        bne     s6, t2, 2f
        li      t1, ':'
2:      sb      t1, 0(t0)
        addi    s6, s6, 1
        li      t2, 4
        bltu    s6, t2, 1b
        lhu     a0, P_PORT(s5)
        jal     put_dec
        li      t0, UART
        li      t1, '\n'
        sb      t1, 0(t0)
        POP     ra, s5, s6
        ret

# ===========================================================================
# Constants.
tens:           .word   10000, 1000, 100, 10, 1, 0
broadcast:      .word   0xFFFFFFFF, 0xFFFFFFFF
msg_disk:       .asciz  "tabernacle: from disk\n"
        .balign 4, 0
msg_from:       .asciz  "tabernacle: fetching from "
        .balign 4, 0
msg_bad:        .asciz  "tabernacle: bad image from "
        .balign 4, 0
msg_size:       .asciz  "tabernacle: wrong size from "
        .balign 4, 0
msg_silent:     .asciz  "tabernacle: no answer from "
        .balign 4, 0
msg_none:       .asciz  "tabernacle: no peer has the image\n"
        .balign 4, 0
msg_nonet:      .asciz  "tabernacle: no network device\n"
        .balign 4, 0
msg_unpatched:  .asciz  "tabernacle: no image patched in\n"
        .balign 4, 0

# The patched values (scripts/build.sh, patch_config): the last 40 bytes.
cfg_version:    .word   0
cfg_size:       .word   0
cfg_hash:       .word   0, 0, 0, 0, 0, 0, 0, 0
_end:
