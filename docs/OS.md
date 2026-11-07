# The node's operating system

Written 2026-11-06 to be tracked; not built. The node image that
tabernacle boots (`docs/TABERNACLE.md`) becomes an operating system: it
owns the machine, runs programs as processes with threads, keeps a
transactional key/value store on the disk, and starts the full node as
a daemon. The programs it runs at first are all ours, built into the
image under its Gimli-Hash: the node, a wallet, a shell, `ls`, `pwd`, a
text editor, and the window manager, an HTTP/WebSocket server that is
the main way in.

## Its shape

Unix-like, and light enough for the hardware: about what MINIX offers,
on RV32I with Zicsr. Processes and threads, a shell, files and
directories, users and permissions, terminals, the familiar small
tools; nothing that needs an MMU, atomics or more than a modest
machine. The whole system, the full node included, is to run in
QEMU's default 128 MiB.

There is no third-party software to admit: no app store, no signed
packages, nothing fetched to run. What there is instead is the fam
compiler, as one of the programs, beside the editor and the shell:
anyone can write a program, build it and run it from the shell, and
send it to whoever they like. That is all; the OS treats such a
program as any other a user runs.

## The machine

RV32I with Zicsr, as everything here: no multiply, no atomics, no
compressed instructions, no MMU. What the OS uses beyond the base set
is the privileged architecture every such core has: machine and user
modes, and physical memory protection (PMP). QEMU's `virt` machine:
RAM from `0x80000000` (128 MiB by default; `-m` gives more), the UART,
the CLINT (its timer and software interrupts, one of each per hart),
and virtio disk and network devices.

## Decisions so far

### 1. The image carries its programs

The image is the kernel followed by a table of programs (each one's
name, offset and length, and the memory a process running it starts
with) and the programs themselves, all covered by the one hash
tabernacle checks. Tabernacle loads the whole image at `0x80000000`, so
the programs are already in
memory, verified: a process runs its program's code where it lies (the
code read-only and shared by every process running it), with only its
data and stacks its own. The proof-of-work seed data the node needs
(1.29 MB) is part of the image the same way, so the first image will be
about 3 MB; fam's islands keep any size compilable, and the protocol
carries images up to 64 MiB.

### 2. Isolation: user mode and PMP, no MMU

The kernel runs in machine mode; programs in user mode, where PMP
grants each process exactly its memory and nothing else (no device, no
kernel memory, no other process): its code read and execute, its data,
heap and stacks read and write, never both. A process's memory is one
contiguous physical region to start with, and the few blocks it maps
later (section 10), so a handful of PMP entries describe it (QEMU has
16), and switching processes rewrites them. No virtual memory: a
program learns its region's bounds when it starts.

This matters even with only our programs and users' own: a user's
program, or one somebody sent them, runs on the same machine as the
node and its keys, and a mistake in it (or worse) must not reach them.

Processes are made by **spawn** (a program from the table or the
store, with arguments), never fork, which without virtual memory would
mean copying and relocating a whole address space. A process has
threads; threads share the process's region and PMP entries, each with
its own stack in it.

### 3. Every hart there is, without atomics

The OS uses however many harts the CPU has: 4 on a small RISC-V chip, 6
on this laptop under QEMU, and 32, 64 or more should simply work; no
count is built in. What RV32I with Zicsr lacks is the A extension
(LR/SC and atomic memory operations), so harts coordinate through plain
loads and stores ordered by `fence` (which is in RV32I), under RISC-V's
memory model:

- **Locks without atomics.** Lamport's bakery lock needs nothing more,
  but costs time linear in the number of harts at every acquisition:
  fine for 4, poor for 64. A tournament of two-hart (Peterson) locks
  costs logarithmic time instead: about 6 steps for 64 harts. Better
  still is to need few locks: each hart keeps its own run queue and its
  own state, and harts pass work through single-writer queues (one
  hart writes, another reads), which need only fences, no lock. Locks
  are then for what is truly shared (the store's writer, the network
  device), held briefly.
- **Waking a hart**: the CLINT's software interrupt (each hart's `msip`
  word), the inter-processor interrupt.
- **Time slices**: each hart has its own timer compare register in the
  CLINT, so each preempts its own threads.
- **Booting them, and counting them.** With no firmware, QEMU starts
  *every* hart at `0x80000000` at once. Tabernacle must keep all but
  hart 0 waiting: each marks its mailbox (a word in a page reserved for
  them, indexed by hart id) to say it is there, then sleeps in `wfi`;
  the OS counts the marked mailboxes to learn how many harts it has,
  and releases each by writing an entry address to its mailbox and
  raising its software interrupt; the kernel then schedules threads on
  every hart. This is a change to tabernacle (a few instructions), and
  the handoff is a contract between it and every image, so it goes in
  before the first image that uses a second hart. (The device tree QEMU
  passes in `a1` says the same, but reading it means a parser; the
  mailboxes need none.)

### 4. Scheduling: preemptive, by lottery

Each hart's timer interrupt ends a thread's slice; the next thread is
drawn by lottery, each holding tickets, so a thread's share of the CPU
follows its tickets: a daemon such as the node gets a steady share, an
interactive program a fair one, and nothing starves. The draw needs a
random number below the tickets in play without division: a mask and
redraw, as tabernacle picks peers. A thread blocked (on input, a
timer, another thread) holds no tickets until it wakes.

### 5. System calls, and /proc

As few calls as possible. What only inspects or configures the system
is not a call but a key under `/proc` (and devices under `/dev`), read
and written like any file, as on Unix: `ps` and `top` are loops over
`/proc/<pid>/status`, a lottery share is a write to
`/proc/<pid>/tickets`.

The calling convention is Linux's on RISC-V: the number in `a7`, the
arguments in `a0`-`a5`, the result in `a0`, negative for an error. The
kernel checks every pointer against the caller's memory.

| # | call | |
|---|------|---|
| 1 | `exit(code)` | ends the process, every thread |
| 2 | `spawn(path, argv, fds)` → pid | runs a program (from the image's table or the store); `fds` maps the child's 0, 1, 2… to the caller's descriptors, which is how the shell redirects and pipes without fork or dup |
| 3 | `wait(pid, &status)` → pid | a child's end (-1: any child) |
| 4 | `thread(entry, stack, arg)` → tid | a thread in this process, on a stack it allocated |
| 5 | `thread_exit(code)` | |
| 6 | `join(tid)` → code | |
| 7 | `yield()` | |
| 8 | `sleep(ns)` | |
| 9 | `lock(addr)` | a mutex named by an address in the process, made atomic by the kernel |
| 10 | `unlock(addr)` | |
| 11 | `await(addr, expected, ns)` | sleeps while the word at `addr` is `expected` (a futex) |
| 12 | `wake(addr, n)` | wakes up to `n` threads waiting at `addr` |
| 13 | `map(bytes)` → addr | a new block of pages for this process (section 10) |
| 14 | `unmap(addr)` | gives one back |
| 15 | `open(path, flags)` → fd | a file, a tree (`TREE`, and `CREATE` to make one), a `/proc` or `/dev` key |
| 16 | `read(fd, buf, n)` | |
| 17 | `write(fd, buf, n)` | |
| 18 | `seek(fd, offset, whence)` | |
| 19 | `close(fd)` | |
| 20 | `pipe(fds)` | |
| 21 | `pty(fds)` | a terminal pair: the window manager holds one end, the shell the other |
| 22 | `poll(fds, n, ns)` | waits for any of several descriptors |
| 23 | `begin(fd, flags)` → txn | a transaction on the tree open as `fd` (section 6): a read-only snapshot, or its writer |
| 24 | `commit(txn)` | |
| 25 | `abort(txn)` | |
| 26 | `get(txn, key, buf, n)` → length | |
| 27 | `put(txn, key, value, n)` | |
| 28 | `del(txn, key)` | |
| 29 | `next(txn, key, buf)` → key | the key after `key`: walks a prefix (`ls`) |
| 30 | `socket(kind)` → fd | UDP or TCP |
| 31 | `net(fd, op, ip, port)` | bind, connect or listen |
| 32 | `accept(fd)` → fd | |
| 33 | `sendto(fd, buf, n, ip, port)` | UDP; TCP uses `read` and `write` |
| 34 | `recvfrom(fd, buf, n, &from)` | |

Mutexes come both ways: the kernel's (9-12) when a thread should sleep
while it waits, and a program's own (a bakery or Peterson lock in its
memory, with `fence` between the steps when it has threads on several
harts) when spinning briefly is cheaper than a call. A program may use
both: spin a little, then `await`.

Not calls:

- **Time**: the kernel lets user mode read the `time` register
  (`mcounteren`), so `rdtime` gives monotonic time with no call; the
  date is `/proc/time`, from QEMU's real-time clock.
- **`/proc`**: `self` (the caller's pid); per process `status` (state,
  user, memory, CPU time), `cmd`, `threads`, `fds`, `tickets` (written
  to set the share), `kill` (written to end it; signals start minimal:
  Ctrl-C on a terminal ends its foreground process) and `user`
  (written only by root: how `login` becomes the user it checked; a
  child inherits its parent's); and system-wide `harts`, `mem`,
  `uptime`, `time`, `net/…` (interfaces, sockets, peers), `store/…`
  (pages, free space, and each tree's size, writer and readers) and
  `sys/…` (settings such as the host name, written by root).
- **`/dev`**: `console`, `null`, and `tty/N` (the pty pairs).

### 6. The store: transactional B+ trees, after LMDB

The key/value store on the disk is everything a program keeps, and the
node's chain state too. It follows LMDB, which the miner uses
and which has served it well: a B+ tree of 4 KiB pages (the page size
of QEMU and of most RV32 hardware), copy-on-write, so a transaction
writes new pages and commits by writing one of two alternating meta
pages; nothing is overwritten in place, so a crash leaves the last
commit whole, and readers see a consistent snapshot while one writer
works. Freed pages are reused once no reader can still see them.

It must be fast enough for the node to verify and apply blocks natively
within the block time: disk-bound, perhaps a little slower than the
miner's `apply_block`, but keeping up with the chain. Prototypes have
done this; it takes the same care here (few pages touched per update,
large sequential writes, the page cache sized to the 128 MiB).

**Trees are files.** The store is any number of B+ trees, each with
its own root, its own meta pages and its own writer, and each is a file:
its header says it is a tree, and its value points to the tree's meta
pages. Any program can make one, as any program on Unix can make a file
or open an LMDB environment: `open(path, TREE | CREATE)` makes it,
`open(path, TREE)` opens it, and the descriptor is what `begin` takes.
Its owner and mode govern it like any file's, checked once at `open`.
The kernel knows how to keep trees, never what is in them: the node is
just a program that keeps its chain state in one (`/var/node/chain`,
owned by a `node` user, mode `0700`), as a user might keep an index of
their own under their home directory.

- **The file system is the first tree**, made by the kernel at the
  first boot: its keys are what `ls`, `pwd` and the shell show as files
  and directories (a key such as `/home/chris/notes.txt`, a directory
  being a prefix). Each value starts with a small header (section 11):
  owner, group, mode, size, creation and modification times, and what
  it is (a file, a directory, a tree).
- **The kernel's own records** are a tree under a path only root may
  open. Nothing is hidden by prefix: what is private is a tree others
  may not open.

Two ways in. Files through descriptors (`open`, `read`, `write`): each
`write` its own small transaction in the file system's tree,
permissions checked against the header. The store calls (`begin` …
`next`) on a tree: faster (whole values, many changes in one commit)
and transactional as LMDB is: `begin` takes a read-only snapshot or
the tree's write transaction, `put` and `del` change pages
copy-on-write, `commit` makes them all durable at once and `abort` (or
a crash) leaves the last commit as it was. The node applies each block
as one transaction in its tree. An append (a value extended without
rewriting it, for logs and growing files) is wanted later.

**No one waits on a block.** Applying a block takes the node 10 to 60
seconds, nearly all of it storing the sparse state tree (verifying the
block is about a second). As in LMDB, a writer holds its tree's write
lock for its whole transaction, not only the commit (and the commit is
where the dirty pages are written, so most of that time is the
commit). Readers never wait, each on its own snapshot; but with one
tree for everything, every write in the OS (a file saved, a setting
changed) would wait out the block. Splitting a block into short
transactions would free the writer between them, at the cost of the
block's atomicity and a recovery scheme of the node's own. With a
writer per tree, a block holds only the chain's: a file save never
waits for it, nor a block for a file. What is given up is a commit
spanning trees, which nothing needs: a block's changes are all in the
chain's tree.

What the kernel keeps for this, all of it general:

- the pool of disk pages the trees share, taken from under a short lock
  of its own;
- the B+ tree itself, copy-on-write, with each tree's meta pages, its
  writer's lock and the pages it freed, reused once its own readers are
  past them;
- each tree's open readers, which say when that is.

The disk is still shared: while the node writes out a large commit, a
small save's writes queue behind its at the device, so the kernel
interleaves small requests with large ones rather than letting one
commit hold the queue. `/proc/store` shows each tree (its size, its
writer, its readers), so a commit in progress can be watched.

### 7. The window manager, and terminals

The main way in is the window manager: an HTTP and WebSocket server (a
program of ours, so it runs in user mode like any other), reached from
a browser through QEMU's forwarded port. It opens terminals, each a tty
of its own, the shell running in one; the shell can also run on the
serial console. Being served over TCP, it needs TCP in the network
stack, where the node so far has only used UDP.

### 8. Init, and the node as a daemon

The kernel starts one program: `init`. Init reads a configuration file
(as `/etc/init`) listing what runs at boot (each program, its
arguments, its user, its tickets, and whether to restart it when it
ends) and starts them. The full node is one of these, a daemon with its
own tickets and its own tree in the store; the window manager another.
What starts is configuration, changed by editing a file, not by a new
image.

### 9. Updates

As `docs/TABERNACLE.md` settles them: each release is an image and the
tabernacle patched for it (its version, size and hash). A node may go
on serving older versions, and old ones can be retired in time.

### 10. Memory

Two allocators, neither of which exists yet:

- **The kernel's, of physical memory** in 4 KiB pages: the regions of
  processes, the store's page cache and the kernel's own records come
  from it, and go back to it. A list of free ranges, first fit,
  neighbours merged when freed: small, and little waste. (A buddy
  allocator would give power-of-two blocks, which suit PMP, but can
  waste half of each: a 40 MiB node would take 64 MiB.)
- **Each program's `malloc` and `free`**, in the stdlib header programs
  for the OS are built with. Today's bump allocator suits the compiler,
  which runs once; the node, the window manager and the shell run for
  good, allocating and freeing as blocks, connections and commands come
  and go, so they need one that reuses what is freed (free lists by
  size, and a path for large blocks).

A process starts with the memory its program's table entry asks for
(the node much, `ls` little); its `malloc` asks for more with `map`, in
large blocks, and gives them back with `unmap`. Nothing moves, so
nothing needs an MMU. Each block costs PMP entries, so a process holds
only a handful beyond its code and its first region (about six, with
16 entries). A thread's stack is memory the program allocates and
passes to `thread`.

The 128 MiB, then: the image (about 3 MiB, its programs' code shared by
every process running them), the store's page cache (the largest share,
sized at boot, and the setting to tune), the node, and small regions
for everything else. Prototypes have fitted the node.

### 11. Users and permissions

Unix's, in its basic form: users and groups, each with a number; every
process runs as a user (`/proc/<pid>/user`, set only by root, inherited
by children); every file has an owner, a group and a mode (read, write
and execute for its owner, its group and others), checked when it is
opened. Root may do anything. The header on each file-system value
holds them: owner, group, mode, size, its creation and modification
times, and its type (a file, a directory, or a tree: section 6). Users
and groups are themselves files (as `/etc/passwd` and `/etc/group`),
which `login` reads.

## What this asks of the other pieces

- **Tabernacle**: harts other than 0 marked present and asleep in
  `wfi`, and released by the OS (section 3).
- **Fam programs in user mode**: built with `lib/user.fam` in place of
  `lib/mach.fam` (step 4): I/O through system calls, stacks within the
  memory given; `malloc` and `free` (section 10) still to come. The
  compiler itself does not change.
- **The network stack**: TCP beside UDP, for the window manager.
- **The disk**: larger than `node.sh`'s 256 MiB once it holds a chain.

## Open questions

None left before the implementation order: the remaining choices (the
store's format on disk, the stdlib for programs, the system calls'
exact arguments) are made as each part is built.

## Implementation order

Each step ends in something that boots under tabernacle and is tested
under QEMU, as `node/scripts/check.sh` tests the compiler. The kernel is
written in fam, with raw instruction words where it must (traps, CSRs,
PMP), as the stdlib is. Performance and every hart come early: the
store decides whether the node keeps up, and several harts shape the
kernel too much to add at the end.

1. **The kernel's skeleton, on one hart.** It boots from tabernacle in
   place of `src/img.fam`: a trap handler, the console, the timer's
   interrupt, the page allocator. Done when it boots and its timer
   ticks steadily. Done (2026-11-06): `src/kernel.fam` and
   `src/boot.fam` are the image. One trap entry saves x1-x31 (by way of
   `mscratch`) and calls `ktrap`, on the kernel's own stacks; the timer
   ticks 100 times a second, each tick set a period after the last; an
   exception in the kernel prints its cause and address and stops; the
   pages are a sorted table of free ranges (first fit, merged when
   freed); 126 MiB of 128 come up free. `scripts/oscheck.sh` (in CI
   beside `check.sh`): the kernel's tests (the allocator, also over 1000
   random takes and gives back; 20 ticks none early; a long computation
   interrupted throughout coming out the same), a fault reported, and
   the image booting under q32 and through tabernacle from disk.
2. **The store's benchmark.** Beside the kernel, a bare-metal program
   (as `gen_hash` is) with virtio-blk and the copy-on-write B+ tree's
   core, timing its basic operations. The store (step 8) grows from it.
   Done (2026-11-06): `src/store.fam` (virtio-blk with flushes and
   multi-page requests, a 32 MiB page cache by clock, the tree of 4 KiB
   pages: 42 entries a leaf, 113 a branch, split up to a new root;
   alternating meta pages; freed pages reused two commits on) and
   `src/storebench.fam`, run by `scripts/storebench.sh [--direct]`.
   100,000 entries (32-byte keys, 64-byte values), every value read back
   checked; under QEMU on this laptop's NVMe, with the host's cache
   bypassed: puts 22,000-24,000 a second (10,000 a commit), cached gets
   66,000, gets from the disk 15,000, overwrites and deletes 7,500 (100 a
   commit), a scan 2.6 million entries a second, a commit of one put
   0.9 ms (both flushes real). The store's own time leads, not the
   disk's (a cached get is 15 microseconds, nearly the same either way):
   that is where to optimize. Still to come in step 8: keys and values
   of any size, several trees, readers' snapshots, aborts, the free list
   on disk, recovery, and merging leaves deletes leave low.
3. **Every hart.** Tabernacle's change (harts other than 0 mark their
   mailbox and sleep in `wfi`, released by the OS); the kernel counting
   and releasing them, a timer and a run queue per hart, software
   interrupts between them, locks without atomics (a tournament of
   Peterson locks) and single-writer queues. Done when `-smp 1` to
   `-smp 64` boot, and a stress test of the locks and queues on every
   hart finds nothing wrong. Done (2026-11-06), but for the run queues
   (step 5). The contract, in `lib/stdlib.fam` and `src/tabernacle.S`,
   the same instructions in both: every hart but 0 copies a ten-word
   wait loop to `0x87FF1F00`, writes 1 ("present") to its mailbox word
   `0x87FF1000 + 4*hartid` (ids below 960), and sleeps there with only
   software interrupts enabled; the OS releases it by writing the
   address of a record (where to go, then the hart's stacks, trap area
   and trap entry) to its mailbox and raising its `msip`. The stdlib
   does it too, so a fam program started by QEMU on several harts
   (`q32 --smp=N`) behaves as one booted by tabernacle; and fampack's
   unpacking stub keeps the other harts until hart 0 has unpacked. The
   kernel (`hstart`) counts the marked mailboxes once 100 ms pass with no
   new one, gives each hart 36 KiB (record, stacks, a heap it must not
   use), and starts it; each runs `hmain`: its own timer, then the jobs
   hart 0 asks of it. Locks: a tournament of two-hart Peterson locks,
   log2 of the harts in steps, a `fence` between a hart's write of its
   flag and its read of the other's. Queues: head and tail moved by one
   side each, fences between. Found on the way: under QEMU, with 64
   harts on six host cores, a hart could still be running its first
   instructions at `0x80000000` when tabernacle wrote the image there;
   tabernacle now waits for the marks to settle (100 ms) first.
   `scripts/oscheck.sh`: the kernel's tests on 1, 2, 8 and 64 harts
   (1000 counts each under the lock, every one kept: without the lock
   counts are lost; numbers through each hart's queue, all in order),
   and the image booting on 6 harts and, through tabernacle, on 64.
   Real hardware without Zifencei must run code it copied (the wait
   loop, tabernacle moved, an image unpacked) only where nothing was
   cached from before: QEMU needs no such care.
4. **User mode and the first program.** The program table, PMP for one
   process, `ecall` with the fewest calls (`exit`, a console `write`),
   and the stdlib header for programs of the OS (their output through
   `ecall`, their stacks within their region). Done when a program
   prints and exits, and one that touches the kernel's memory is ended
   while the system goes on. Done (2026-11-06). The stdlib is split:
   `lib/stdlib.fam` the language, `lib/mach.fam` what owned the machine
   (I/O to the UART, the finisher, `init`, the harts kept waiting: put
   after it for every program as before) and `lib/user.fam` for programs
   of the OS (`tools/fam --user`: `putc`, `puts`, `bye`, `getc` and `sys`
   as system calls; stacks, return ids and variables in the memory the
   kernel gives, a0 to a1). `scripts/mkimage.sh` makes the image: the
   kernel, the programs in `src/user`, a table (name, offset, length,
   memory), its offset and "PROG" in the last 8 bytes of a page, and the
   kernel's end (the gp its start loads) moved past it all. `prun` runs a
   program to its end on the hart it is called on: its code run where it
   lies in the image (PMP: read and execute), its memory pages zeroed
   (read and write), nothing else reachable; the trap entry takes a trap
   from user mode on the kernel's stacks and, when the process ends (exit,
   or an exception: killed and reported), goes on where `prun` left off.
   Calls 1 `exit` and 17 `write` (fds 1 and 2, the buffer checked to be
   the process's), others -38. The kernel runs `init` at boot. Checked:
   init's hello; a program reading kernel memory killed (load fault) and
   one writing its own code (store fault), the system going on; writes of
   kernel memory refused (-14), an unknown call (-38), a bad fd (-9).
5. **Processes and threads, on every hart.** `spawn`, `wait`,
   `thread`, `join`, `yield`, `sleep`; the lottery on each hart's
   timer; `lock`, `await`, `wake`; `/proc/<pid>/tickets`. Done when
   programs share every hart in the proportion of their tickets.
   Done (2026-11-06), but for `/proc` (step 7: a process's tickets are
   its parent's, or what the kernel gives the processes it starts). A
   thread's control block is its trap area while it runs; every hart
   runs `hloop`: a thread drawn by lottery among those ready (one draw
   over all of them, under the kernel's lock, rather than a queue per
   hart), run in user mode until it traps back to stay (its 10 ms slice
   over, a call that waits, its end), then the next. System calls 1-12
   and 17 as section 5 lists them, `lib/user.fam` wrapping each, and
   `tcode[ ... ]tcode` for a thread's code (fam has no function
   pointers: it compiles the code where it is and leaves its address).
   A process ends with `exit`, a fault, or its last thread; its threads
   on other harts are stopped by a software interrupt, its memory freed
   once none is still on a hart; a parent's `wait` takes a child's
   status, and the kernel says on the console when one it started ends.
   Checked (`scripts/oscheck.sh`, on 1 to 8 harts): four threads adding
   1000 each under a lock (4000), joined; a child spawned and waited for
   (status 7), and the errors for no such program and no child; sleep,
   await and wake, and a wait timed out; a process killed by a fault
   while its other thread spins on another hart; two programs of 300 and
   100 tickets on one hart getting about 3:1 of it (150:51 typically).
   Found on the way: a thread that blocks, or ends, is still on its hart
   while the trap unwinds, and its block holds that hart's way back, so
   it is not run elsewhere (even woken) nor its slot reused until the
   hart is off it; the result of a call goes where its first argument
   came (a0), so it is set only once the arguments are read; the
   lottery's generator is seeded at boot (xorshift never leaves 0);
   loops over the tables stop at the slots ever used; and
   `scripts/build.sh` now stops on a compile error rather than building
   on the compiler's message.
6. **Memory.** `map` and `unmap`; `malloc` and `free` in the stdlib.
   Done when a long test allocating and freeing on several threads
   holds steady. Done (2026-11-06). Call 13 `map(bytes)` gives a block
   of zeroed pages in one of a process's 4 slots (PMP entries 5-12):
   its first byte, or 0, since an address has its high bit set and an
   error cannot be told by sign. Call 14 `unmap(addr)` gives one back
   (-22 if it is not one). The other harts running the process's
   threads reload their PMP by a software interrupt, and an unmapped
   block's pages go back only once every one has, so none can reach
   them once they are another's. `malloc` and `free` (`lib/user.fam`):
   one free list sorted by address, first fit, split, neighbours merged
   but never across an arena's start; arenas mapped as needed (at least
   64 KiB, and at least what is mapped already, so 4 slots go far) and
   unmapped when wholly free unless the last; the kernel's mutex guards
   it, since threads share the heap (a thread allocates with `malloc`,
   never `alloc`, whose `gp` is its own). Not yet the size classes and
   large-block path of section 10: one list served the tests, and they
   come when a program's profile asks. Checked: four blocks mapped,
   written and read, a fifth refused, one unmapped and mapped again, a
   bad unmap refused, a read of an unmapped block killed; four threads
   of 5,000 steps, twice, each holding up to 16 blocks of 4 to 8192
   bytes filled with its own pattern and checked when freed, all
   intact, and the heap whole after each round (one block, one arena);
   a 200 KiB block given an arena of its own, and back. On 4 harts the
   contended allocator is no faster than on one. Found on the way:
   QEMU runs code an instruction at a time in a page that a PMP range
   covers only in part (it cannot cache the translation), hundreds of
   times slower, and what looked like threads deadlocking was this.
   Programs now begin on a page of the image and are padded to the
   next, and their code's range is whole pages. QEMU also takes a TOR
   range's end as the bound less one, so an empty slot's `[0, 0)`
   opened all of memory to user mode; an empty slot's entry is now off.
   And hart 0 never enabled software interrupts, so a thread there was
   neither stopped when its process ended nor told to reload its PMP.
7. **Descriptors, the console, init and a shell.** `open`, `read`,
   `write`, `close`, `pipe`, `poll`; `/dev/console` and `/dev/null`;
   `/proc`'s basics; `init`, a first shell on the console, and `ps`.
   Done when `ps` and a pipe work from the serial console.
   Done (2026-11-06). The kernel keeps a table of open files (the
   console, null, a pipe's end, a `/proc` key), and each process has 16
   descriptors on them. A process the kernel starts has the console as
   0, 1 and 2. `spawn(name, args, fds)` gives the child its arguments
   (packed strings, kept at 20 KiB into its memory, where
   `lib/user.fam`'s `arg` finds them) and its descriptors (a count, then
   which of the caller's are its 0 to n-1, or none: the caller's 0, 1
   and 2). A pipe is a page holding 2 KiB; `write` writes all it is
   given, waiting for room; `read` gets what is there, or 0 once no
   writer is left. A call that must wait goes back onto its own `ecall`
   and runs again from the start when woken, so whatever wakes it only
   has to name what changed; `poll` keeps its deadline across those
   runs. The console is polled by hart 0 at each tick (and while idle):
   typed bytes echoed into a 1 KiB line buffer, backspace, Enter ending
   the line (`read` gets whole lines), ^D ending the input. `/proc`:
   `self`, `harts`, `mem`, `uptime`, and per process `status` (one line:
   pid, parent, state, threads, KiB, ticks, its arguments), `cmd`,
   `tickets` (written to set them) and `kill` (written to end it, -9);
   its text is made when opened. Programs in `src/user`: `init` keeps a
   shell running; `sh` runs pipelines with `<` and `>`, and `exit`;
   `ps`, `echo`, `cat`, `wc`. Checked: `poll` timing out, ready, and
   hung up; a pipe read to its end; the errors (no such path, a bad
   descriptor, a key not to be written, no such process, 16 descriptors
   at most); a child killed through `/proc`; and, typed into the console
   a line at a time on one hart and on four, `ps`, `echo … | wc`, 100 KiB
   through `big | cat | wc`, `/proc` read and written through `<` and
   `>`, an unknown program, a missing command, and `exit` with `init`
   starting the shell again. Not yet: ^C (QEMU's `-serial stdio` takes
   it itself), `seek` and files (step 8), `/proc`'s other keys, `rdtime`
   from user mode. Found on the way: the kernel's range check missed
   mapped blocks (a `malloc`ed buffer could not be written out), and a
   `lock` could be taken on a word of the program's own code.
8. **The store.** From step 2's core: the file system's tree, files
   through descriptors, `ls`, `pwd`, `cat`, `mkdir`, `rm`, `/etc/init`;
   users, permissions and `login`; trees (`open(path, TREE)`) and the
   store calls. Done when files outlive a reboot, killing QEMU in a
   commit leaves the last one whole, and a block-sized transaction in
   one tree runs while files are saved without either waiting.
   The plan (2026-11-06), in parts each tested before the next:
   1. **Waiting inside the kernel.** Every thread has its own kernel
      stacks, so a call can sleep halfway (waiting for the disk, or for
      a lock a store writer holds) while its hart runs other threads,
      and go on where it was when woken. The disk interrupts through
      the PLIC when a request is done. Interrupts in machine mode are
      taken only where a hart idles, never while it holds a lock. A
      process ending lets a thread asleep in a call finish the call
      first, so no store lock is left held.
   2. **The engine.** Step 2's tree made general. Any number of trees,
      each with its own meta pages and writer; keys of up to 255 bytes,
      values up to 1 KiB; readers' snapshots; abort; deletes that free
      emptied pages; recovery from the newest whole meta pages at boot.
      Free space: each tree's freed pages are a list on the disk,
      written with its commit, and reused once its readers are past
      them. New pages come from the pool in 1 MiB chunks, the pool's
      mark written before a chunk is used. A crash can leak the rest of
      a chunk and the lost transaction's pages, about 1 MiB a tree,
      which a sweep can take back later. The store begins 64 MiB into
      the disk, after the room tabernacle's image may take.
   3. **Trees and the store calls**, 23 to 29, on a tree opened as a
      descriptor, and `/proc/store`. Checked: a value outlives a reboot,
      QEMU killed in a commit leaves the last one whole, and a long
      transaction in one tree does not hold up another's.
   4. **Files.** The file system's tree: a file's header (owner, group,
      mode, size, times, type) at its path, its bytes in 1 KiB values
      at the path, a NUL and the chunk's number; a directory, a path
      ending in `/`. Files through `open`, `read`, `write`, `seek` and
      `close`; a working directory; `ls`, `pwd`, `cd`, `cat`, `mkdir`,
      `rm`.
   5. **Users.** `/etc/passwd` and `/etc/group`, the checks at `open`,
      `/proc/<pid>/user`, `login`, and `init` reading `/etc/init`.
   Parts 1 to 3 done (2026-11-06). The kernel is now three files in
   order: `src/kernel.fam` (its base), `src/store.fam`, `src/ksys.fam`
   (the calls, the traps, boot). Every thread has 16 KiB of kernel
   stacks. A call begins on them empty; `ksleep` saves where it is and
   gives the hart back to its loop, and `trun` resumes it there (its
   `mepc` kept, `mstatus` set). Kernel mutexes (`kmlock`) sleep; `klk`
   stays a brief spin lock. Machine mode takes interrupts only while a
   hart idles in `hstep`. The disk interrupts hart 0 through the PLIC,
   and a call waiting on it sleeps. The store
   begins 64 MiB into the disk, and `kboot` mounts it when there is a
   disk. Its trees have keys of 1 to 255 bytes and values up to 1 KiB,
   in slotted pages. A leaf or branch that fills splits by bytes; one a
   delete empties is freed, and a root left with one child gives way
   to it. A meta page holds its tree's root, entries, free list and
   chunk, checksummed. The free list is written backward, last page
   first, so a commit rewrites only what changed. There is a shared
   32 MiB page cache with pins, and a writer per tree. Readers are
   snapshots whose pages are not reused while they last. `open(path,
   TREE | CREATE)` keeps a tree's meta page in a 32-byte header at its
   path in the file system's tree. Calls 23 to 29 are `begin`
   (`txbegin`), `commit`, `abort`, `get`, `put`, `del` and `next`. A
   process's open transactions are undone when it ends, and its trees
   closed, by a hart between threads (`kdefer`).
   Checked, by `scripts/storetest.sh` on a bare machine: 4,000 keys of
   2 to 60 bytes with values of 1 to 1000 bytes put, read back and
   walked in order with `next`; a third deleted and some put again; an
   abort leaving nothing; a second tree; everything found again after
   a reboot, the pool's size steady over three rounds of deleting and
   putting back. Then six times, QEMU killed while commits run as fast
   as they can, and each time the last commit is found whole. In the
   OS, by `scripts/oscheck.sh` on one hart and on four: a counter
   outliving a reboot; twenty commits in one tree while a 3,000-put
   transaction is open in another, every one done before it; the
   calls' errors. The benchmark (`scripts/storebench.sh`, 100,000
   32-byte keys with 64-byte values) now gives about 12,500 puts a
   second, 26,000 cached gets, 9,400 gets from the disk, 5,800
   overwrites at 100 a commit, 690 one-put commits and 27,000 keys a
   second walked with `next`. That is about half of step 2's
   fixed-size core for puts, and a third for gets, with room left to
   win back. Found on the way: the tree records outgrew their
   64 bytes, so a field of one fell on the next's free list (they are
   128 bytes now); and a raw word typed by hand was wrong, as before.
9. **The network.** virtio-net, IP, UDP sockets (the node's protocol,
   in fam), then TCP. Done when a program fetches over UDP and the host
   reads a page served from the guest.
10. **Terminals and the window manager.** `pty`, `/dev/tty/N`, and the
    HTTP and WebSocket server with terminals in the browser. Done when
    a browser opens a shell and runs `ls`.
11. **The tools.** The editor, and the fam compiler as a program (its
    I/O through system calls, a larger heap). Done when a program is
    written, built and run inside the OS.
12. **The node as a daemon.** A document of its own: the chain's logic
    in fam (verification, the state tree, sync, the protocol), its seed
    data in the image, started by `/etc/init`.
