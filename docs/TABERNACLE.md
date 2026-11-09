# Tabernacle

Written 2026-11-06; the boot program, `server.py` and `node.sh` built the
same day (see the implementation order). `tabernacle` is the fam
node's boot program: a few kilobytes (4,498 bytes, packed) that run the
node image from disk if it is there and correct, and otherwise fetch it
from the peer-to-peer network, check it, and run it. The node image
itself (the full node, written in fam) is everything else; this
document covers only how it is found, checked and started.

Written as `node/src/tabernacle.S` for convenience and converted to
`node/src/tabernacle.fam0` with `tools/s2fam0_fam.py`, as `fam.S` is:
`bin/fam0` builds it, so it needs no assembler to rebuild. (The
converter now keeps runs of zero words, which objdump otherwise elides:
the placeholder below is one; `fam.fam0` is unchanged by it.)

## The trusted values

A tabernacle binary is built for exactly one version of the node image,
and fetches only that version. At its end, `scripts/build.sh` patches in
(`patch_config`, as the old build's did) for `bin/img`, the node image
(the OS, `docs/OS.md`: the kernel, `src/kernel.fam` and `src/boot.fam`,
with the programs in `src/user`, by `scripts/mkimage.sh`), at
`IMAGE_VERSION`:

```text
… code … ‖ version (4, LE) ‖ size (4, LE) ‖ Gimli-Hash of the image (32)
```

The source leaves these 40 bytes as zeros, a placeholder. `bin/gen_hash`
(`src/gen_hash.fam`) computes the hash under QEMU (the image loaded at
`0x80800000`, its length first; the digest out on the serial port as
eight hex words); the size is the image's length in bytes. The old
`patch_config` (in e110232's parent) had the chunk count where the
version now is: the stub derives it from the size. The first release is
version 0. An image is at most 64 MiB (chunk indexes are 16 bits).

Nothing else is trusted: what a peer sends is checked against these
values, and so is the disk.

## Booting

0. **Other harts.** Every hart starts at `0x80000000`. All but hart 0
   wait (docs/OS.md, section 3: they mark their mailboxes in the page at
   `0x87FF1000` and sleep in a loop copied to its end) until the OS
   releases them; hart 0 waits until 100 ms pass with no new hart
   marking, so that none is still running where the image will go.
1. **Disk.** Read `size` bytes from the start of the virtio-blk disk
   (the image is stored there as is, no header) and hash them. If the
   hash matches, run it.
2. **Discovery, while downloading.** Otherwise bring up virtio-net and
   send `Ping` and `GetPeers` to every seed at once. Every address a
   `Peers` brings is pinged in turn, and every peer that answers is
   asked `GetImages`. A peer that lists our version is a candidate.
   Discovery goes on in the same loop as the download, so the first
   candidate is used at once and later ones queue behind it: a test
   network with a peer or two is not held up waiting for more.
   Requests go out one after another, so the peer asked first tends to
   answer first; the peer table is kept in random order (each new peer
   swapped with one picked at random, an inside-out Fisher-Yates
   shuffle), so no peer is always first and the load spreads, the
   quickest to answer (likely the least loaded) still winning. The
   randomness is the 10 MHz timer, mixed at start and by each frame's
   arrival time, stirred by xorshift32: not for secrets. Tried: three
   peers listed by a seed served 17, 23 and 20 of 60 boots; two seeds
   alone, 20 and 20 of 40.
3. **Download, one peer at a time.** From a candidate, fetch our version
   in chunks. A peer that reports a size other than ours, whose image
   does not hash to ours, or that stops answering is dropped, and the
   next candidate is tried. Chunks from different peers are never mixed:
   a bad image could then not be blamed on anyone.
4. **The seeds last.** The seeds are asked for the image only once every
   other candidate has failed and 10 s have passed since discovery
   began, so they are not the network's download server. They are tried
   the same way, one at a time.
5. **Failure.** If the seeds fail too, print why on the serial port and
   exit 1.
6. **Run.** Reset the devices (so nothing more is written to memory),
   clear the registers and jump to the image at `0x80000000`, where q32
   would load it: a packed image (`fampack`) reads its header there. So
   that the disk and the download can put it there directly, tabernacle
   first moves itself to `0x87F00000` (its code is position-independent)
   and keeps its buffers just above.

The node image, once running, writes itself to the disk if what is
there is not it. Tabernacle never writes the disk.

## The wire

The stub speaks the existing protocol (`miner/src/net.rs`) in the clear:
`Ping`/`Pong` and `GetPeers`/`Peers`, each request carrying the token
the peer gave in its `Pong`. Neither needs the onion layer's handshake,
so no ML-KEM or ML-DSA goes in the stub. Its `Ping` is all zeros:
tabminer answers any ping with a `Pong` (carrying the token), and takes
one on no chain for no peer, so the stub stays out of peer tables and
needs no genesis id.

The download is two new message pairs, with type bytes of their own
(from 64 up, clear of tabminer's), the same token rule as every other
request, and the chunking `GetChunks` and `Chunk` use (1,024 bytes a
chunk, index ranges asked for), integers little-endian:

| type | message      | payload                                             |
|------|--------------|-----------------------------------------------------|
| 64   | `GetImages`  | token                                               |
| 65   | `Images`     | count (1), then version (4) and size (4) each       |
| 66   | `GetImage`   | token, version (4), count (1), then start (2) and length (2) each |
| 67   | `ImageChunk` | version (4), size (4), index (2), length (2), bytes |

A node may serve a range of versions. The stub asks for 32 chunks at a
time (from the first still missing to the batch's end), again each
second while they do not come, and drops a peer after four seconds with
none.

There is no capabilities field to set: `Status` carries none today
(nonce, version, token, genesis, height, oldest, tip, work, fees), and
none is needed. Asking `GetImages` is how the stub finds out: a node
answers, and tabminer drops a type it does not know as it drops any
datagram that is not a message (`node.rs`, `handle_packet`: logged,
nobody struck). So tabminer does not change. Its peers give the stub
addresses through `Peers` as they do anyone. (Tried against two local
tabminer nodes: each answered the ping and `GetPeers`, the stub went on
to the peer it was given, and the image requests were logged and
dropped.)

## The QEMU setup: `scripts/node.sh`

Not q32: `node.sh` creates the disk file if missing (`node/data/node.img`
by default, `node/data` being ignored by git; sparse, large enough for
the image and the node's data after it) and starts QEMU with
tabernacle loaded at `0x80000000`, the disk as virtio-blk, and
virtio-net in user mode (the guest is `10.0.2.15`, the host
`10.0.2.2`), forwarding the node's UDP port. The seeds are built in
(`tabernacle1.root.sx:3737` and `tabernacle2.root.sx:3737`, as tabminer's),
plus any given with `--seed` (`--no-seeds` leaves out the built-in ones);
`node.sh` resolves each name to its first IPv4 address (`getent` on
Linux, `dscacheutil` on macOS; one that does not resolve is skipped) and
writes them to a small file loaded at a fixed address, `0x87FFF000`
(`-device loader`, as `gen_hash` takes its input): a count byte, then
four address bytes and a port (2, LE) each, as in a `Peers` message. So
a tabernacle is not rebuilt to point it elsewhere, and a seed that moves
needs only its DNS changed.

```text
node.sh [--disk=FILE] [--seed=HOST:PORT ...] [--no-seeds] [--mac=ADDR]
        [--hostfwd=SPEC] [TABERNACLE]
```

TABERNACLE defaults to `bin/tabernacle`, as `build.sh` leaves it.

The same with QEMU alone, no script: `docs/MINIMAL_BOOT.md`.

`scripts/makenode.sh [--disk=FILE]` writes `bin/img` at the start of the
disk (the same default, created if missing), as the node will once it
runs, to try the boot from disk: `makenode.sh` then `node.sh` prints
`tabernacle: from disk`.

## The node serving its image

The fam node serves its image (`docs/NODE.md`, step 9, done
2026-11-09): `src/user/node/p2p.fam` answers anyone's `Ping` (a `Pong`
with a token for the asker's address, a keyed hash of it, as tabminer
gives tokens), and, with that token, `GetPeers` (the peers that answered
it), `GetImages` (its version and size) and `GetImage` (64 chunks an ask
at most, as `server.py`). The image is the one the machine booted, read
from `/dev/image` (`docs/OS.md`), so it is exactly what this tabernacle
checked; its version is the image's own `/lib/version`, which
`build.sh` writes from `IMAGE_VERSION`. `scripts/imagetest.sh` boots a
tabernacle from a node with no `server.py` anywhere.

## A stand-in node: `tools/server.py`

`server.py` plays a node, on the seeds, until the fam node runs there,
and stays after as a backup: it serves an image without a node behind
it. It is the old one
(`GET_HOSTS`/`GET_BIN` on its own `TBRN` magic, one image named by its
hash) brought to this protocol and to versions:

```text
server.py [--peer=IP:PORT ...] PORT [VERSION=FILE ...]
```

- Serves each FILE as its VERSION on UDP PORT: `Ping` answered with a
  `Pong` (all zeros but the nonce and token, so a tabminer node that
  hears of it takes it for no peer), `GetPeers` with the `--peer`
  addresses (none by default; at most 32),
  `GetImages` with its versions and sizes, `GetImage` with the chunks
  asked for (at most 64 an ask).
- With `--peer` and no images it plays a seed that only hands out
  peers; with both, a seed that also has the image (used last). Tried:
  a seed with the image listing two peers, the first serving a corrupted
  image: tabernacle fetched from the first, dropped it, took the image
  from the second, and never used the seed, all in about 0.05 s.
- Tokens as a node gives them: an HMAC of the asker's address under a
  key made at start, so nothing is sent to a forged address.
- A file is re-read when its mtime changes, so a build can be replaced
  without a restart.
- Checks nothing: the stub does. It prints each file's Gimli-Hash when
  it loads it, to compare with what `build.sh` patched into tabernacle.

## Open questions

- **Updates.** A tabernacle fetches its own version, and a node may
  serve several. When a release is out, how a running node learns that
  a newer version is genuine, and writes the matching tabernacle for
  the next boot, is for later: `Images` already carries the versions.
- **The hash.** `gen_hash.fam` pads as `0x01` after the message, `0x80`
  in byte 15 and `0x01` in byte 47, not as the reference Gimli-Hash
  (`0x1F` after the message, `0x80` in byte 47). The old tabernacle and
  `server.py` hashed the same way, so it is deliberate; the stub, the
  node and `server.py` must all keep to it.

## Implementation order

1. `src/gen_hash.fam` built by `build.sh`; `patch_config` back, for the
   node image. Done (2026-11-06).
2. `tools/server.py`. Done (2026-11-06).
3. `src/tabernacle.S` and its `.fam0`: the disk check; virtio-net, ARP
   and UDP; discovery and download in one loop; the seeds last; the
   jump. Done (2026-11-06).
4. `scripts/node.sh`. Done (2026-11-06). Tried by hand: the image from
   disk; from a seed (after the 10 s); none to be had (exit 1 after
   10 s); a bad image dropped for a good one, and a peer listing another
   size passed over; a non-seed peer a seed listed, used at once (1 s)
   though a seed had the image too; a 200 KiB image (several batches, a
   short last chunk).
5. A test in `check.sh` (or beside it) doing the same, for CI.
   `node/scripts/imagetest.sh` boots a tabernacle from a fam node
   (2026-11-09); the cases above with a corrupt peer are still by hand.
