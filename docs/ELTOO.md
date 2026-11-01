# Payment channels

The protocol primitives for eltoo payment channels, multi-party channels
and channel factories, so that the bulk of payments happen off chain
between users and liquidity providers, and between providers, with the
chain settling disputes and rare reallocations. This note covers the
building blocks and their rules, not how wallets talk to each other: the
reference wallet exercises the primitives, and user wallets, provider
tooling and watchtowers are built outside it.

This is the design as settled on 2026-11-01. Constants are listed at the
end.

## Model

An output stays what it is today: a 32-byte commitment and a 32-byte
memo, 64 bytes on chain, with the amount and the spending conditions
hidden. What changes is what a commitment commits to and what a spend
reveals to the prover.

A commitment is `H(policy ‖ amount)`. A plain output's policy is the hash
of its XMSS public key, exactly as now, so a plain output is the
degenerate case and nothing on chain distinguishes a channel from a
payment. A spend reveals the policy's preimage and the data satisfying
it to the block prover, who proves the spend valid; the chain and every
other node see only the spent position.

The output leaf gains the output's creation height:
`H(commitment, memo, height)`. The proof reads the height from the
state-tree path, so relative timelocks need no word of the prover's.
This is a state-tree format change (leaves, fast-sync parts, wallet
scanning) and a genesis regeneration.

Transactions still travel only to the block prover, who already learns
amounts. With policies the prover also learns which inputs are channel
spends. Nobody else does.

## Policies

A policy is a Merkle tree of leaves; a spend reveals one leaf and its
path, in zero knowledge. A leaf is the conjunction of up to `LEAF_CONDS`
conditions. Disjunction is separate leaves. A plain output is a tree of
one leaf with one signature condition.

| condition | satisfied when | bounds |
|---|---|---|
| `thresh(m, keys)` | `m` valid signatures by distinct keys of the `n` listed | `n ≤ MAX_KEYS`, `1 ≤ m ≤ n` |
| `hash(h)` | the spender reveals `p` with `H(p) = h` (Poseidon) | 32-byte preimage |
| `after(h)` | the block's height is at least `h` (CLTV) | |
| `older(d)` | the block's height is at least the output's creation height plus `d` (CSV) | |
| `state(n)` | the spending transaction's state number exceeds `n` | |
| `outputs(list)` | the spend's covered run of the transaction's outputs is exactly the list (commitment and memo each); the leaf holds the run's digest | up to `MAX_COVENANT` outputs |

`thresh` takes a signing mode: `body`, the signature covers the body
hash as plain inputs do; or `rebindable`, the signature covers
`H(DOM_REBIND, channel id ‖ state number ‖ digest of the covered run)`
and not the position spent, so one signed update spends the funding output or any
earlier state of the same channel. The channel id is the funding
output's commitment. The output list is the outputs the update must
create; covering a list rather than one output gives splicing, fee
inputs and factory membership changes without further machinery.

`outputs` makes a covenant. Settlement by covenant needs no signature
and no key after the last update, and settles a factory of `k` members
into `k` channel outputs in one transaction. The covenant commits to
memos as well as commitments so a publisher cannot garble them. The
output amounts are witnesses the circuit checks against the spent
amount, as for any transaction; the publisher's fee comes from an input
of its own.

Conditions are evaluated by the block circuit as part of proving the
input. A plain input costs what it costs now; a policy input adds the
leaf path, the conditions, and one XMSS verification per signature
checked.

## Signatures

Signatures remain XMSS. Keys may have any tree height up to
`MAX_HEIGHT` (20); the height is part of the hashed public key, since
the root alone does not fix it. Plain outputs keep 4-level keys (16
leaves); channel keys use 16 by default and up to 20, for 65 thousand
to a million states. The circuit's XMSS fragment verifies any height up
to the maximum with inactive rows padded, at two rows per level, so the
ceiling costs every signature about 3% over today's fragment.

Signature size grows 32 bytes per level: 2,312 bytes at 4 levels, 2,824
at 20. Generating a key computes every leaf: seconds at 16 levels, a
minute or two at 20 on a desktop, so wallets generate channel keys in
the background.

Rule: a rebindable signature for state `n` uses leaf index `n` of the
signer's channel key, and the circuit checks it. A stateful key can
then never reuse a leaf within a channel, and each party can verify the
other used the right leaf. Parties not party to a state skip that index.

## Inputs and transactions

An input is one of two kinds.

| kind | reveals to the prover | signs |
|---|---|---|
| plain | public key, amount, position | the body hash, as now |
| policy | policy preimage, amount, position, the leaf and its path, the data satisfying each condition, the state number if any | per the leaf's `thresh` mode |

A transaction may mix kinds: the broadcaster of a channel update adds a
plain input for the fee and a change output, and the circuit requires
only that the update's covered outputs are present. Plain inputs sign
the whole body, including the policy inputs' positions, so a fee input
cannot be moved to another update.

The body hash and the transaction id are unchanged for plain-only
transactions. A policy input's contribution to the body is its position
and a digest of its revealed data.

## Weight

The scarce resource is signature verification in the circuit, about
1,150 trace rows each; everything else in an input is small. Block
capacity and the minimum fee are by weight: a plain input weighs 1, a
policy input weighs the number of signatures its leaf checks, outputs
and name operations weigh as today. A published factory update with 32
signatures weighs 32 inputs and pays for them; cooperative paths and
covenant settlements stay cheap.

## Channels

How the primitives compose, at the protocol level.

**Two-party channel.** The funding output's policy has three leaves:
update, `thresh(2, {A, B}, rebindable) ∧ state(0)`; settlement,
`older(delay) ∧ outputs(refunds)`; cooperative close,
`thresh(2, {A, B}, body)`. Because settlement is a covenant, the funding
transaction needs no pre-signed companions: either side can exit from
the moment it confirms. State `n` is an output with the same leaves,
`state(n)` and a covenant for the balances at `n`. A payment is a new
state signed by both with leaf index `n`, never broadcast. A unilateral
close publishes the latest update, then after the delay anyone publishes
the covenant settlement; a stale state published by one party is
replaced by anyone holding a newer signed update, which a watchtower
can do with no key.

**HTLC.** An output of two leaves: `hash(h) ∧ thresh(1, {B})` and
`after(t) ∧ thresh(1, {A})`. In-flight HTLCs are entries in a state's
settlement covenant, so `MAX_COVENANT` bounds them per channel.

**Multi-party channel.** `n` parties: update `thresh(n, keys, rebindable)
∧ state(k)`, settlement a covenant into `n` outputs. Every update needs
every signature, since a state is one allocation of everyone's funds; an
offline member blocks reallocation but never exit, as anyone can force
settlement after the delay.

**Channel factory.** A multi-party channel whose settlement covenant
pays into two-party channel outputs between the provider and each
member. Payments run in the inner channels with two signatures; the
group signs only to add or remove members or move liquidity. Payments
between members route through the provider in two hops. Factories nest,
since covenant outputs are arbitrary policy commitments; groups of a few
dozen keep each published update within block capacity.

The settlement delay is a channel parameter, not a protocol constant: it
must exceed how long the chain can be congested, so the default is
conservative (144 blocks) and parties may choose longer.

## Light verification

Any block's chain proof verifies all history, and the state tree gives
Merkle proofs of outputs. A client holding headers and one chain proof
verifies its own outputs and watches spent positions, which are public,
without trusting a node. Nodes serve state proofs over the protocol;
user wallets and provider tooling build on that rather than on a node
per user. This exists today and only needs exposing.

## Deferred

- **Partial updates.** A condition that the new state's allocation equals
  the old except for the signers' balances, which change by equal and
  opposite amounts, would let two members of a group pay each other
  directly with two signatures. It needs a sequencer for state numbers
  and forgoes the provider's liquidity; factories serve the intended
  model, so this waits for demand. It is one more condition in the same
  circuit.
- **A policy segment.** For factories far beyond a few dozen members,
  policy satisfaction can be proven in its own segment, aggregated into
  the block proof like the name segment, so the block pays a fixed cost
  per input regardless of signatures. The policy circuit is designed as
  its own AIR so this is packaging, not redesign.
- **Cross-chain hash locks.** A second hash function in the circuit for
  atomic swaps with other chains. Expensive; out until wanted.

## Constants

| constant | value |
|---|---|
| output on chain | 64 bytes, unchanged |
| leaf | `H(commitment, memo, height)` |
| `LEAF_CONDS`, conditions per leaf | 4 |
| `MAX_KEYS`, keys per threshold | 32 (about 27 may sign one spend: a policy spend is proven in one segment) |
| `MAX_COVENANT`, outputs per covenant | 128 |
| `MAX_HEIGHT`, XMSS tree height | 20 (plain keys 4, channel keys 16 by default) |
| signature | 2,312 bytes at 4 levels, 32 more per level |
| XMSS fragment | 3 + 67 × 17 + 2 × height rows: 1,150 at 4, 1,182 at 20 |
| policy inputs per transaction | 1, the transaction proven whole in one segment |
| weight of a policy input | its signatures checked |
| default settlement delay | 144 blocks, a channel parameter |
| rebindable message | `H(DOM_REBIND, channel id ‖ state ‖ output list)` |
| rebindable leaf index | the state number |

## Implementation order

1. **Leaf height.** Done (2026-11-01): the leaf is
   `compress(compress(commitment, memo), [height, 0, …])`, one more
   Poseidon2 permutation per leaf; the output store records the creation
   height (68-byte records), the spent log keeps it for undo, fast-sync
   output parts carry it, and the transaction segment hashes a second
   leaf row per input (the height a witness the path authenticates) and
   per output (the block's height, now a public input of every segment
   that the root binds to the statement's); the name segment does the
   same for commit outputs with the commit's height. Circuit: BlockAir
   768 columns, 1,880 constraints; NameAir 996, 3,265. Chain format 13;
   `MAINNET_CHAIN` regenerated; the genesis header is unchanged (no
   outputs). Wallets need nothing: the prover reads heights from its own
   store.
2. **Policies and encoding.** Done (2026-11-01): XMSS keys carry their
   tree height (1 to 20) in the public key and its hash, signatures are
   variable size and parsed by the key's height, payment keys stay at 4
   levels; `policy.rs` has the conditions, leaves, the policy tree
   (depth 4), their hashing (`DOM_POLICY_LEAF`, `DOM_HASHLOCK`,
   `DOM_REBIND`), encodings, bounds, and `PolicyInput` with its
   node-side `check` (threshold signatures in both modes with leaf index
   equal to the state, hash lock, CLTV, CSV from the creation height,
   state ordering, covenant run); transactions carry `policy_inputs`
   after the plain inputs, in the body hash as `[policy] [0, 0, 0, 0,
   amount, 1]`, in the encoding, in spent positions and totals, with
   `weight()` the signatures checked. The pool checks policy inputs but
   refuses them until step 3 makes them provable.
3. **Circuit.** Done (2026-11-01). The XMSS fragment verifies any key
   height up to 20: a one-hot height register hashed into the key hash,
   tree tweaks keyed by level index and height, the walk stopping at the
   key's last level (2 rows per level). The transaction segment evaluates
   one policy input per transaction, after its plain inputs: a start row
   loading the state number, covered run, creation height and rebindable
   message; the leaf hashed one block per row with each condition read
   off its rows (threshold header and channel, listed keys with selected
   ones absorbed into a keys sponge, hash lock from its preimage row,
   CLTV/CSV/state as 31-bit non-negative differences, the covenant's
   digest); the policy path; each signature's fragment and key hash
   absorbed into a signers sponge that must equal the keys sponge with
   exactly `m` signatures; then the commitment, leaf, removal and body
   rows as a plain input, the body block `[policy] [0, 0, 0, 0, amount,
   1]`. Outputs in the covered run feed a covered sponge; at the run's end
   the rebindable message is recomputed and compared, and the covenant's
   digest checked; a transaction needing a run must complete it. A
   transaction with a policy input is proven whole in one segment (its
   registers are not carried), which bounds a spend to about 27
   signatures of 16-level keys; the pool refuses more. BlockAir 991
   columns, 2,708 constraints; NameAir 1,049 and 3,407; soundness 120
   bits unchanged; `MAINNET_CHAIN` regenerated. Tests: multisig, HTLC,
   eltoo update and covenant settlement satisfy the constraints and a
   tampered state fails; a multisig output funded in one proven block is
   spent through the pool in the next.
4. **Chain and pool.** Done (2026-11-01): the pool checks policy inputs
   against the live state (creation heights from the output store) and
   refuses more than one per transaction or a spend that does not fit a
   segment; packing counts each item's rows (a policy spend's signatures
   included) and keeps a policy transaction whole; fees stay by size,
   which grows with the signatures carried; claims per position are
   unchanged, policy positions included.
5. **Reference wallet.** Done (2026-11-01): `wallet.rs` derives channel
   keys of any height from the seed by nonce (`channel-key [HEIGHT]` at
   the prompt prints a fresh nonce and key hash), tracks policy outputs
   the wallet is party to with its keys among the policy's (`policies`
   lists them; they come from the parties' agreement, not the seed, so
   they are kept like channel state), funds arbitrary outputs from its
   coins (`fund`), builds a policy spend through a leaf with a state
   number and covered run (`policy_spend`), signs it with every listed
   key of its own in body or rebindable mode, leaf index equal to the
   state and never going back (`sign_policy`, passing the transaction's
   bytes between parties), and records the spend (`policy_sent`). Tested
   end to end between three wallets: funding, an update signed by both,
   a cooperative close, a covenant settlement after the delay, a
   three-party factory settling into channel outputs, and a 2-of-3
   multisig. The signing rounds themselves (transport, ordering) are
   left to wallets built on this one.
6. **Light proofs.** Done (2026-11-01): `GetProof { position }` is
   answered with two `Proof` datagrams carrying the output at the
   position (commitment, memo, creation height; zero when spent or
   unassigned) and its 40 siblings against the sender's tip, which a
   client holding headers verifies with `node::verify_proof` against that
   header's state root: an unspent output's existence, or a position's
   emptiness, in 1.3 KB without trusting the node. A node receiving one
   verifies it against the header it names and counts it.
7. **Docs.** Done (2026-11-01): README (policies and channels, state
   proofs), SECURITY.md (policy rows, variable-height fragment, the
   one-segment bound), HARDENING.md (policy outputs and recovery), this
   note's steps and constants.

Steps 1 to 3 each change the chain format or genesis; they ship together.
Everything above was implemented on 2026-11-01 against chain format 13.
