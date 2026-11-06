# Minimal boot

Written 2026-11-06. How to run a node with nothing but QEMU and the
tabernacle binary (`docs/TABERNACLE.md`): no repository, no scripts, no
Python. `node/scripts/node.sh` is the normal way and does all of this
for you; this is the proof that it is not needed, for anyone who wants
to see every part of what runs.

Tried with local seeds (`node/tools/server.py`), one and two, at the
offsets below: tabernacle fetched the image from each.

## What you need

- QEMU: `qemu-system-riscv32`, and `qemu-img` (it comes with it) or any
  other way to make an empty file.
- `tabernacle`, the binary, about 4 KB. Nothing else: it carries the
  size and hash of the one version of the node image it boots, fetches
  that image from the network the first time, and after that the node
  keeps itself on the disk. (The project makes it with
  `node/scripts/build.sh`; a user only needs the file.)

## 1. A disk

Once:

```sh
qemu-img create -f raw node.img 256M
```

The node image goes at its start, and the node's data after it. It
starts empty; the file is sparse, so it takes little real space.

## 2. Run

```sh
qemu-system-riscv32 -machine virt -cpu rv32 -nographic -bios none \
  -global virtio-mmio.force-legacy=true \
  -device loader,file=tabernacle,addr=0x80000000 \
  -device loader,addr=0x87FFF000,data=2,data-len=1 \
  -device loader,addr=0x87FFF001,data=0xBEAC369F,data-len=4 \
  -device loader,addr=0x87FFF005,data=3737,data-len=2 \
  -device loader,addr=0x87FFF007,data=0x7CE6EB92,data-len=4 \
  -device loader,addr=0x87FFF00B,data=3737,data-len=2 \
  -drive file=node.img,format=raw,if=none,id=d0 \
  -device virtio-blk-device,drive=d0 \
  -netdev user,id=n0 -device virtio-net-device,netdev=n0
```

The first boot prints `tabernacle: fetching from …` (after about 10 s
when only the seeds have the image: they are asked last), then the node
runs. Once the node has written itself to the disk, later boots print
`tabernacle: from disk` and need no network to start. Ctrl-A then X
quits QEMU.

Line by line:

- `-machine virt -cpu rv32 -nographic -bios none`: QEMU's generic RISC-V
  board, a 32-bit CPU (tabernacle and the node use only RV32I, so any
  will do), the serial port on the terminal, and no firmware: the CPU
  starts at `0x80000000`. Its memory, 128 MiB, is the default.
- `force-legacy=true`: tabernacle drives the original (legacy) virtio
  interface.
- `loader,file=tabernacle,addr=0x80000000`: the program, where the CPU
  starts.
- The five `data=` lines: the seeds (below).
- `-drive …` and `virtio-blk-device`: the disk.
- `-netdev user` and `virtio-net-device`: the network, through QEMU's
  own NAT: the guest is `10.0.2.15`, the host `10.0.2.2`. Only outgoing
  UDP is used, so no root, bridge, tap device or forwarded port is
  needed.

## The seeds

Tabernacle reads its seeds at `0x87FFF000`: a count (1 byte), then each
seed's IPv4 address (4 bytes) and UDP port (2 bytes, little-endian), as
in a `Peers` message. `-device loader` with `data=` writes such values
straight into memory, little-endian, so no file is needed: one line for
the count, and two for each seed, the k-th (from 0) at
`0x87FFF001 + 6k` (its address) and `0x87FFF005 + 6k` (its port).

An address `a.b.c.d` is the 4-byte value `0x` `dd` `cc` `bb` `aa` in hex
(its bytes in reverse, as little-endian stores them in order): 10.0.2.2
is `0x0202000A`, 159.54.172.190 is `0xBEAC369F`.

The values above are the seeds `tabernacle1.root.sx` (159.54.172.190)
and `tabernacle2.root.sx` (146.235.230.124), port 3737, as of this
writing. The seeds are reached by name, so their addresses can change:
look them up (`getent hosts`, `nslookup`, `dig`) if a boot finds no
peer. `node.sh` does that on every start. One seed:

```sh
  -device loader,addr=0x87FFF000,data=1,data-len=1 \
  -device loader,addr=0x87FFF001,data=0xBEAC369F,data-len=4 \
  -device loader,addr=0x87FFF005,data=3737,data-len=2 \
```

## Notes

- Windows: untested. Tabernacle only writes to the serial port, never
  reads it, so the input loss that kept the fam compiler off Windows
  does not arise; output cut short when QEMU exits might.
- Real RV32I hardware would need the same: tabernacle at the start of
  RAM, the seeds where it reads them, a virtio disk and network (or
  drivers for what it has instead, which tabernacle does not carry).
