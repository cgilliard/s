# Node enhancements

Work planned for the fam OS node (`node/`) and its wallet, beyond what
`docs/NODE.md` and `docs/GUI_WALLET.md` describe as built.

## 1. As many relays as tabminer takes

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
