# Sub-names by certificate

Written 2026-11-05 to be tracked; not built. It replaces the server model
of `docs/SUBNAMES.md` section 1 (a sub-name server answering every
lookup) with certificates: the name's owner signs one per sub-name, and
the holder publishes it itself. Section 2 there (rendezvous points that
rotate by epoch) stays as it is and is used here. Nothing changes in
consensus: the chain still registers single labels (`docs/NAMES.md`).

## Why

Under the server model every cold resolve of `cool.example` reaches
`example`'s server. So:

- **Availability.** If the server is down, no sub-name under `example`
  resolves, though every holder is up.
- **Scale.** All lookups for every label land on one machine (at most
  600 answers a minute, each a signature). A large name (a wallet
  provider's, say) needs a well-run server.
- **Privacy.** The server sees every label anyone asks for.
- **Latency.** Three dependent round trips: the delegation, the query,
  the payment.

With certificates the parent signs once a day per sub-name and is out of
the lookup path. Lookups for `cool.example` go to rendezvous points of
its own, which rotate by epoch, so load spreads over the relays with the
number of sub-names. A resolve is two round trips: the certificate, then
the payment.

## The certificate

```text
name ‖ label ‖ type ‖ value ‖ seq ‖ expiry ‖ issuer key ‖ signature
```

The fields of today's `Answer` (`miner/src/subnames.rs`), the server key
renamed issuer key:

- `type` is `id` (the value is the holder's 32-byte id, `T`) or `none`
  (no such sub-name; an empty value). Values are length-prefixed and a
  resolver refuses types it does not know, so others can be added later.
- `seq` orders certificates for one full name; the highest valid one
  wins.
- `expiry` is absolute Unix time, at most `MAX_LIFETIME_SECS` (two days)
  ahead. Issued for a day and renewed every six hours.

### Who may issue

The certificate is valid for `label.name` when its issuer key either:

1. hashes to `V`, the value of `name` on chain: the owner signed it
   itself; or
2. is one of the issuers in `V`'s **delegation**, which keeps its
   current form (`owner key ‖ seq ‖ expiry ‖ ids`, signed by `V`'s key,
   held at `V`'s points), its ids now naming issuers rather than servers.

Case 1 needs nothing but the chain. Case 2 lets an owner keep its key
offline and leave renewals to an always-on issuer, as delegating to a
server did. A resolver needs the delegation only when the issuer key
does not hash to `V`.

## Where it is published

At the **full name's points**: the rendezvous points of
`N = H("subname" ‖ label ‖ "." ‖ name)`, ranked as any id's are,
`H(N ‖ epoch ‖ relay)` (`onion::rendezvous_relays`). They rotate each
epoch with the same grace as sessions (`docs/SUBNAMES.md` section 2).

The holder's node publishes its certificate over its standing circuit
(`Publish`, as delegations are), at both sets of points during a grace
period. The point that takes it passes it to `N`'s other points
(`Store`). Each point:

- checks the signature, the expiry, that `N` is computed from the
  certificate's own name and label, and that it serves `N`;
- checks the issuer against its chain: the key hashes to `name`'s value
  (case 1), or is in `V`'s delegation (case 2; the point fetches the
  delegation from `V`'s points, as a server does today when it moves);
- keeps the highest `seq` per `N` until its expiry, taking an update at
  most every 10 seconds per `N`.

Anyone holding a valid certificate may publish it: the holder normally,
but also the owner or its issuer, which is how revocation works (below).
A forged certificate fails the issuer check, so it cannot push a genuine
one out with a higher `seq`.

## Resolving `send 5 @cool.example`

1. Read `example → V` from the chain.
2. Ask `N`'s points for the certificate (`GetCert`), over an outbound
   circuit; the last relay tries `N`'s points in turn, as a lookup does.
3. Check it: the signature, the expiry, the name and label, and the
   issuer against `V` (fetching `V`'s delegation only in case 2). Learn
   `T`.
4. Pay `T` as any id: `T`'s announce at its own points, then the slate.

```text
wallet ──chain──▶ example = V
wallet ──circuit──▶ N's point ──▶ certificate: cool.example = T (signed by V's key)
wallet ──circuit──▶ T's point ══session══▶ holder's node   (the payment)
```

A certificate is cached until its expiry, so a repeat send goes straight
to step 4. No certificate, or a `none` one, means no such sub-name.

## Issuing, renewing and revoking

- **Issue.** The owner's wallet keeps the table of its sub-names
  (`subname set cool.example T`, as now). For each entry its node signs a
  certificate for a day and sends it to `T` as a payload of a new kind
  (`KIND_SUBNAME_CERT`), through `T`'s points as a payment's messages go.
  The holder's node keeps it and publishes it.
- **Renew.** Every six hours while the issuer runs, the same: a new
  certificate with a higher `seq`. An owner whose wallet comes online
  about daily keeps its sub-names alive; one that does not delegates to
  an always-on issuer.
- **Revoke.** `subname del cool.example`: the issuer signs a `none`
  certificate with a higher `seq` and publishes it at `N`'s points
  itself. It takes effect at once, without waiting for the old
  certificate to expire. Caches still hold the old one until its expiry
  or a refresh; a resolver sending a payment refetches if its cached
  certificate is older than an hour.
- **Change.** Pointing `cool.example` at another id is a new certificate
  with a higher `seq`, published by the issuer as a revocation is, and
  sent to the new holder.

The parent stays in control of its namespace, as before: whoever owns
`example` decides what `cool.example` means, and can override a holder
at any time. Anyone wanting a name the parent cannot touch registers a
top-level one.

## What goes away

The server path of `docs/SUBNAMES.md` section 1: `KIND_SUBNAME_QUERY`
and `KIND_SUBNAME_ANSWER`, the node answering queries from its table
(`subnames::answer`, `Zone`), the 600-answers-a-minute limit, and
`subname server` as a setting of servers (it becomes `subname issuer`).
`Delegation` stays, naming issuers. `Answer` becomes `Cert`.

## Privacy

- `N`'s points see that `cool.example` is asked for, but not by whom
  (lookups come through circuits), and they rotate each epoch. No single
  party sees every label under `example`, as the server did.
- The owner learns nothing about lookups.
- A certificate is public to anyone who asks for the full name, as the
  server's answer was: it says `cool.example` is `T`, nothing more.

## Costs and limits

- **Holders do work.** A holder publishes at the full name's points each
  epoch, beside its announce: one more `Publish` per sub-name per epoch,
  over the circuit it already holds.
- **Relays store certificates.** One small record per active sub-name,
  held until expiry (at most two days), checked against the chain before
  it is kept. A point holds at most as many certificates as it holds
  sessions and delegations together, oldest-expiring dropped first.
- **Issuers sign per sub-name per renewal.** About four signatures a day
  per sub-name; a name with 100,000 sub-names is 400,000 a day (a few
  seconds of signing an hour), sent as that many payloads. Large issuers
  may renew less often, with lifetimes up to the two-day cap.
- **Cached certificates outlive a revocation** by up to an hour for
  payments (the refetch rule above) and to their expiry otherwise.

## Open decisions

1. **The holder's announce at the full name's points too.** The holder
   could also hold a session at `N`'s points, so the point that returns
   the certificate could forward the payment at once: one round trip
   instead of two. It costs every holder a second session per sub-name
   per epoch, and couples the name's points to the payment. Proposed:
   not now; measure two round trips on `--network dev` first.
2. **Delegated issuers.** Case 2 keeps owners' keys offline but brings
   back the delegation and a second fetch (for points and for some
   resolvers). Proposed: keep it; the cost falls only on names that use
   it.
3. **Renewal by message.** Proposed above: the issuer pushes each renewal
   to the holder as a payload. The alternative is the holder fetching it
   from the issuer, which needs the issuer reachable when the holder
   asks; pushing needs only the holder reachable, which it must be to be
   paid.

## Implementation order

1. `Cert` in `subnames.rs` (from `Answer`): make, verify against a name's
   value and an optional delegation, bytes; tests for forged, expired,
   other-name, other-label and unauthorized-issuer certificates, and the
   highest-`seq` rule.
2. Points: `Publish`/`Store`/`GetCert` for certificates at `N`'s points,
   the issuer checked against the chain (fetching delegations when
   needed), kept in the rendezvous LMDB beside announces and delegations;
   carried across epoch boundaries as delegations are.
3. The holder: `KIND_SUBNAME_CERT` received and kept, published at `N`'s
   points every epoch and on renewal.
4. The issuer: certificates signed from the wallet's table and sent on
   `subname set` and every six hours; `none` certificates on
   `subname del`; `subname issuer` for delegation.
5. Resolution in `send`: fetch, check, cache, pay; the server path
   removed (`KIND_SUBNAME_QUERY`, `KIND_SUBNAME_ANSWER`, `answer`,
   `Zone`).
6. Tests: the end-to-end tests of sub-names reworked (resolve with the
   owner offline, through a delegated issuer, after an epoch rotation,
   after a revocation and a change), and a timed run on `--network dev`
   in onion mode.
7. `docs/SUBNAMES.md` section 1 replaced by a pointer here; README and
   `docs/NAMES.md` updated.
