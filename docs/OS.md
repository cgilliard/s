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
- **Fam programs in user mode**: today a program owns the machine (the
  stdlib writes the UART directly and lays its stacks out over all of
  RAM). A program for the OS is built with another header: its I/O
  through system calls, its heap (`malloc` and `free`, section 10) and
  stacks within the memory it is given. The compiler itself does not
  change.
- **The network stack**: TCP beside UDP, for the window manager.
- **The disk**: larger than `node.sh`'s 256 MiB once it holds a chain.

## Open questions

None left before the implementation order: the remaining choices (the
store's format on disk, the stdlib for programs, the system calls'
exact arguments) are made as each part is built.

## Implementation order

To be written once the system calls are settled.
