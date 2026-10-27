# Security of tabminer's proofs

This note estimates the soundness of the block proof: the segment proofs, the
recursive node proofs and the zero-knowledge wrap proof a block carries. It
covers the parameters in `AggregatorParams::MAINNET`. All numbers come from
`tools/soundness.py`, run on `tools/soundness_mainnet.json`; the table
dimensions in that file are printed by the ignored test
`aggregate::tests::soundness_parameters`.

A forged block needs one forged proof somewhere in the tree. Each proof is a
separate Fiat-Shamir argument with its own transcript. The level of the whole
is therefore the level of the weakest proof type: an attacker gains nothing
by attacking many proofs at once that it would not gain by attacking one.

## Summary

| proof | ethSTARK formula (queries only) | conjectured, every round | proven (Johnson regime) |
|---|---|---|---|
| segment (2^15 rows, rate 1/4, 42 queries, 16 grinding bits) | 99 | 95 | 54 |
| node (up to 2^18 + 2^16 rows, rate 1/4, 42 + 16) | 99 | 93 | 52 |
| wrap (2^16 + 2^14 rows, rate 1/32, 16 + 20) | 99 | 92 | 52 |

All figures are bits of classical security against a prover that may make
2^λ hash queries. Against a quantum attacker, Grover search over transcripts
roughly halves every figure, grinding included: about 46 to 50 bits
conjectured.

- **ethSTARK formula.** This is the number usually quoted for STARKs:
  λ ≥ min(grinding + R·s, log2|K|) − 1, from the ethSTARK documentation
  v1.2, equation 19. Here R = log2(1/rate) and s is the query count. It
  counts the query phase only.
- **Conjectured, every round.** This model keeps the conjecture for the query
  phase. It adds the soundness error of every earlier Fiat-Shamir challenge:
  - the lookup challenges γ and δ;
  - the constraint combination α;
  - the out-of-domain point ζ;
  - the batching challenge β;
  - the FRI folding challenges.

  Each of these errors is degree over |K| (Schwartz–Zippel, list size one).
  Grinding does not help any of them, because it is applied only before the
  queries. With |K| = 2^123.6 they are not negligible.
- **Proven.** This applies the round-by-round theorem of the ethSTARK
  documentation (Theorem 5, from BCIKS20 in the Johnson regime), maximised
  over its parameter m.

## The field and the hash

- **Field.** BabyBear, p = 2^31 − 2^27 + 1. All challenges come from its
  quartic extension K, with |K| = p^4 ≈ 2^123.6. This one number caps every
  algebraic round.
- **Hash.** Poseidon2 with Plonky3's `default_babybear_poseidon2_16`
  parameters: width 16, x^7 S-box, 8 full and 13 partial rounds, Plonky3's
  constants. It is checked against Plonky3's known-answer test. Digests are 8
  elements, about 247 bits. That gives:
  - Merkle and commitment collisions at about 2^124 classically, and about
    2^82 quantumly (Brassard–Høyer–Tapp, with impractical quantum memory);
  - preimages at about 2^247 classically and about 2^124 quantumly.

  The compiler of [BCS16] needs digests of at least 2λ + 3 bits, which allows
  λ up to 122. The hash is not the limiting factor.
- **Signatures.** XMSS signatures (W-OTS+, w = 16, tweakable Poseidon2
  hashing, 247-bit digests) are far above 100 bits classical and above 100
  bits quantum. Their security reduces to second preimages of the tweaked
  hash.

## Round by round, current parameters

Each entry is bits per attempt, −log2 of the error.

| round | segment | node | wrap |
|---|---|---|---|
| lookup challenges (LogUp) | none | 98.6 | 100.6 |
| constraint combination (powers of α) | 112.9 | 114.5 | 114.5 |
| out-of-domain point ζ (DEEP) | 107.0 | 103.1 | 104.3 |
| batching (powers of β) | **96.1** | **93.6** | **92.5** |
| FRI folding (first round, arity 4) | 104.6 | 101.6 | 100.6 |
| queries, toy-problem conjecture | 100.0 | 100.0 | 100.0 |
| queries, list-decoding-capacity radius | 98.4 | 98.4 | 98.8 |

- **Batching is the weakest round.** All committed columns are combined with
  powers of one challenge β, as in Plonky3, rather than with independent
  coefficients. The combination is then a curve of degree L, where L is the
  number of opened polynomials: 1,440 for a segment, 1,030 for a node and
  1,118 for the wrap. BCIKS20's bound for curves multiplies the line error
  by the curve degree, giving roughly L·|D|/|K|. That costs about 10 bits
  against |K|.
- **The lookup term** is the degree of the LogUp identity in (γ, δ):
  rows × Σ(tuple length + 1), over |K|.
- **The folding term** is arity × domain over |K|, per round.
- **DEEP** is (quotient degree + n)/|K|, summed over the tables.

This problem is not specific to tabminer. A 2026 audit of OpenVM by Cantina
found the same effect for BabyBear^4. There the commit phase reached 99.5
bits against a 100-bit claim, and OpenVM added a grinding step before
sampling ζ.

## The 2025 counterexamples

The query phase's "R bits per query" rests on proximity gaps for
Reed–Solomon codes holding up to capacity. Crites and Stewart (ePrint
2025/2046) and Diamond and Gruen (ePrint 2025/2010) disproved the
up-to-capacity versions of the correlated-agreement and list-decoding
conjectures. Later work (ePrint 2026/782, arXiv 2604.09724) shows failures
within O(1/log n) of capacity over prime fields.

The repaired conjectures stop at the list-decoding capacity radius δ, with
H_q(δ) = 1 − ρ. Our FRI codewords are over K, so q = 2^123.6, and that radius
costs very little: 1.96 instead of 2 bits per query at rate 1/4, and 4.92
instead of 5 at rate 1/32. That is the "list-decoding capacity" row of the
round-by-round table, 1 to 1.6 bits below the toy-problem figure.

Whether the O(1/log n) failures cost more in practice is not settled. Their
constants are not known to us, so leave a few bits of margin above the
target.

## Proven security

In the Johnson regime, BCIKS20's correlated-agreement error is
(m + ½)^7·|D|² / (3ρ^{3/2}|K|). The |D|² factor alone leaves 50 to 60 bits
over a 124-bit field, and queries give only log2(1/(√ρ(1 + 1/2m))) bits each.
Proven 100 bits would need several hundred queries and a larger field. No
deployed STARK on a 31-bit field claims proven security at these sizes;
Block et al. (ePrint 2024/1161) find provable levels 21 to 63 bits below the
conjectured ones.

## Raising the level

There are two independent levers:

- **Commit-phase grinding.** A proof-of-work step before each challenge of
  the commit phase: the lookup challenges, ζ, β and every folding challenge.
  Each g-bit step adds g bits to its round for 2^g permutations of prover
  work. At 16 bits that is about 35 ms per challenge, roughly 0.3 s per proof
  for about ten challenges. The verifier checks one hash per step, in the
  recursion circuit as well. This alone makes every round reach the query
  phase's level.
- **More queries.** These grow the recursive verifier, and so the node and
  wrap tables.

Modelled levels:

| configuration | segment | node | wrap |
|---|---|---|---|
| current | 95 | 93 | 92 |
| current + 16-bit commit grinding | 99 | 99 | 99 |
| 50 queries (wrap 20 at 16 bits) + 20-bit commit grinding | 112 | 112 | 111 |

The last row is held below 116 by the batching term. Getting past it needs
either about 24 bits of grinding before β (several seconds per proof), or
independent batching coefficients, or a larger extension field. The quintic
extension of BabyBear, about 2^155, would add about 31 bits to every
algebraic round, but the recursive machine works in Fp4 words.

## Measured cost of 116-bit query parameters

These measurements come from `aggregate::tests::security_configs`: mainnet
blocks of output-only segments, proven and verified on the development
laptop, with two segment provers at a time.

| configuration | node / wrap tables | 1-segment block | 16-segment block | proof | verify |
|---|---|---|---|---|---|
| current: 42 queries + 16 bits; wrap 16 + 20 | 2^18 / 2^16 | 13.4 s | 60.5 s (wrap 10.4 s) | 149–151 KB | 9.5 ms |
| 50 + 16; wrap 20 + 16 | 2^19 / 2^17 | 13.2 s | 77.1 s (wrap 21.9 s) | 179–189 KB | 12 ms |
| 48 + 20; wrap 20 + 16 | 2^19 / 2^17 | 14.2 s | 79.5 s (wrap 19.7 s) | 178–189 KB | 12 ms |

At 116 bits, the node verifier passes 2^18 rows and the wrap passes 2^16 rows
once a block has more than a few segments. The wrap therefore doubles, the
proof grows by about a quarter, and a full block takes about 30% longer. A
single-segment block is unaffected: its root still fits.

## References

- ethSTARK Documentation v1.2, StarkWare, ePrint 2021/582. Equation 19
  (conjectured), Theorem 5 and Section 7.1.1 (round by round), Theorem 7
  (BCS).
- Ben-Sasson, Carmon, Ishai, Kopparty, Saraf: Proximity Gaps for
  Reed–Solomon Codes (BCIKS20).
- Block et al.: Fiat–Shamir Security of FRI and Related SNARKs, ePrint
  2024/1161.
- Crites, Stewart: On Reed–Solomon Proximity Gaps Conjectures, ePrint
  2025/2046; Diamond, Gruen, ePrint 2025/2010.
- Failure of proximity gaps close to capacity, ePrint 2026/782; Proximity
  Gaps Conjecture Fails Near Capacity over Prime Fields, arXiv 2604.09724.
- Cantina, OpenVM v1.5.0 security review (2026): commit-phase grinding
  before ζ for BabyBear^4.
