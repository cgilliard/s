# Node enhancements

Work planned for the fam OS node (`node/`) and its wallet, beyond what
`docs/NODE.md` and `docs/GUI_WALLET.md` describe as built. Item 1 is a
requirement before any `consensus.txt` lists more than 16 relays; the
rest are in no particular order.

## 1. As many relays as tabminer takes (required past 16 relays)

tabminer reads a `consensus.txt` of up to 8,192 relays and 1 MiB
(`consensus::MAX_RELAYS`, `MAX_CONSENSUS`). The fam node and its wallet
keep far fewer, and past their limits they do not degrade gracefully:

| Where | Limit | Past it |
|---|---|---|
| `node/cons.fam`: `CXMAX`, `CXFMAX` | 64 relays, a 64 KiB file | the file counts as **invalid**: the node skips it and decides the next file voted for, or init mode, while tabminer takes it, so the node's wallets are in the wrong mode |
| `wallet.fam`: `wmcons` (`wmrids`, `wmrads`) | 16 relays read from `/v1/consensus` | the wallet keeps the first 16 by id |
| `node/wopart.fam`: `OWRN` | 16 relays | as above |

The wallet's limit is the more urgent one. A participant's rendezvous
points are the three heaviest of **all** listed relays (`onion::
rendezvous_relays`, `wonion.fam`'s `oxpts`). A wallet that weighs only 16
of 20 relays computes different points from every other node: its points
refuse its session (a relay serves only ids whose points include it) and
its lookups go to the wrong relays. **A file listing more than 16 relays
breaks the fam wallet in onion mode until this is done.**

What it takes:

1. **The node: take every file tabminer takes.** Raise `CXFMAX` to 1 MiB
   and the relay count to 8,192. A set kept as now (320 bytes a relay,
   288 of them the address field) would be 2.6 MB, and the node keeps the
   current set, the previous one and one being parsed: about 8 MB of the
   128 MiB budget. Keep addresses packed (NUL-ended, one after another,
   an offset table beside the sorted ids), or in the store rather than
   in memory: about 40 bytes a relay, 330 KB a set.
2. **The API: the relay list without sending it all every time.**
   `/v1/consensus` now lists every relay, and the wallet asks every ten
   seconds; at 8,192 relays that is over a megabyte each time. Give the
   list's hash (the file's) and its count in the summary, and the relays
   in pages (`/v1/consensus/relays?set=current&from=N`), so a wallet
   fetches them only when the hash changes.
3. **The wallet: every id, few addresses.** Rendezvous points need every
   relay's id (32 bytes each: 256 KB at 8,192). Addresses are needed only
   for the relays a circuit uses: the first hop is the only one the
   wallet connects to (later hops are extended by their relays, which
   look up the address themselves). So `wopart.fam` keeps all ids and
   fetches an address from the node when it picks a first hop.
4. **Rendezvous points at scale.** `oxpts` hashes every relay
   (`hash_domain(21, id, epoch, relay)`) for each id it places: once for
   our own points an epoch, and once per recipient in a send (its
   announce lookup goes to the last hop, which places it, so the wallet
   places only itself and the full names of sub-names it publishes).
   Measure it at 8,192 relays in the OS before deciding whether it needs
   to be faster (the hash in assembly, as `chacha.fam`'s were).
5. **Tests.** A consensus file of 8,192 relays through `constest.sh` (the
   node's decision matching tabminer's, the file valid), and `oxpts`
   against tabminer's `rendezvous_relays` on a large list (a vector in
   `wonion_vectors.fam`). `onitest.sh` with more than 16 relays pinned
   would need that many tabminer relays; 20 is enough to cross today's
   limit.

## 2. The node in place of `server.py`

The fam node already serves the image it booted (`docs/TABERNACLE.md`,
"The node serving its image"; `docs/NODE.md`, step 9): `p2p.fam` answers
`Ping`, `GetPeers`, `GetImages` and `GetImage` as `server.py` does, from
`/dev/image`, and `scripts/imagetest.sh` boots a tabernacle from a node
with no `server.py` anywhere. What `server.py` still does that the node
does not, before the seeds can run a node alone:

- **More than one version.** `server.py` serves several images
  (`VERSION=FILE ...`), so tabernacles built for an older image still
  boot while the network moves to a newer one. The node serves only the
  version it booted. It should keep the images of other versions it has
  (fetched from peers, as tabernacle fetches, or put on its disk) and
  serve each, so an upgrade does not strand the tabernacles of the old
  version.
- **Validation.** `server.py` checks nothing ("tabernacle checks what it
  gets"); a node serving images it did not boot must check each before
  serving it: its size and Gimli-Hash against what a tabernacle for that
  version expects (the values `build.sh` patches in), so a node never
  hands out an image that every tabernacle will then refuse.
- **Peers to hand out.** `server.py --peer` lists fixed addresses; the
  node hands out the peers that answered it. On a seed that is what is
  wanted, but it should be checked at scale: enough peers, and ones that
  serve the image.
- **Tried on a seed.** Run a node on a seed in place of `server.py`, with
  tabernacles booting from it alone, from it and other nodes, and with a
  peer serving a corrupted image (the case `server.py` was tried with,
  `docs/TABERNACLE.md`), before `server.py` becomes only the backup.

## 3. More than one node on a host

`scripts/makenode.sh` and `scripts/node.sh` default to one node:
the disk `node/data/node.img`, the built-in seeds, and QEMU's defaults
for the MAC and the forwarded ports. `--disk`, `--mac` and `--hostfwd`
exist, but running several nodes means choosing each by hand, and a
mistake (two nodes on one disk, or on one forwarded port) fails late and
unclearly. What it takes:

- **An instance name.** `makenode.sh --name=N` and `node.sh --name=N`:
  the disk `node/data/N/node.img`, a MAC derived from the name, and the
  node's ports forwarded to host ports given once (`--port=P`: UDP P for
  the p2p port, TCP P+1 for wm, P+2 for the API, as the node's
  `api-port`), written to
  `node/data/N/config` by `makenode.sh` so `node.sh --name=N` needs
  nothing else. With no name, today's defaults.
- **Refuse a clash at start.** `node.sh` takes a lock on the instance's
  directory (QEMU locks the disk too, but its message is unclear) and
  checks that its host ports are free before booting.
- **A test.** Two or three instances from `makenode.sh`, booted together
  and syncing from each other (no test runs more than one fam node
  today: `peertest.sh` runs one with two tabminers).

