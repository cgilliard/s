# Security of tabminer's proofs

This note estimates the soundness of the block proof: the segment proofs, the
recursive node proofs and the zero-knowledge wrap proof a block carries. It
covers the parameters in `AggregatorParams::MAINNET`. All numbers come from
`tools/soundness.py`, run on `tools/soundness_mainnet.json`. The table
dimensions in that file, and the grinding schedule the code derives, are
printed by the ignored test `aggregate::tests::soundness_parameters`.

A forged block needs one forged proof somewhere in the tree. Each proof is a
separate Fiat-Shamir argument with its own transcript. The level of the whole
is therefore the level of the weakest proof type: an attacker gains nothing
by attacking many proofs at once that it would not gain by attacking one.

## Summary

The target is 120 bits of conjectured classical security for every proof:
every Fiat-Shamir round of every proof has an error below 2^-121 per attempt.

| proof | queries | conjectured, every round | quantum | proven (Johnson regime) |
|---|---|---|---|---|
| segment (2^15 rows, rate 1/4) | 54 + 16 grinding bits | 120.0 | about 60 | 68 |
| node (up to 2^19 + 2^17 rows, rate 1/4) | 54 + 16 | 120.1 | about 60 | 67 |
| wrap (up to 2^17 + 2^15 rows, rate 1/32) | 22 + 16 | 120.3 | about 60 | 68 |

All figures are bits of classical security against a prover that may make
2^λ hash queries. Against a quantum attacker, Grover search over transcripts
roughly halves every figure, grinding included.

How the figures are counted:

- **Conjectured, every round.** The query phase uses the toy-problem
  conjecture of the ethSTARK documentation (v1.2, section 5.9): R bits per
  query, with R = log2(1/rate), plus the grinding. The model also counts
  every earlier Fiat-Shamir challenge:
  - the lookup challenges γ and δ;
  - the constraint combination α;
  - the out-of-domain point ζ;
  - the DEEP batching coefficients;
  - the FRI folding challenges.

  Each of those has an error of degree over |K| (Schwartz–Zippel, list size
  one). With |K| = 2^123.6 they are not negligible: at the parameters of
  2025 they held the proofs to 92–95 bits. The prover therefore grinds
  before each of them, as many bits as its error falls short of 121
  (`StarkConfig::commit_bits`, below). The result is the smallest round minus
  one, as in the documentation's equation 19.
- **ethSTARK formula.** The number usually quoted for STARKs counts the
  queries only: min(grinding + R·s, log2|K|) − 1, which is 122.6 here, the
  cap set by the field.
- **Proven.** This applies the round-by-round theorem of the ethSTARK
  documentation (Theorem 5, from BCIKS20 in the Johnson regime), with the
  same grinding, maximised over its parameter m.

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

## Round by round

Each entry is bits per attempt (−log2 of the error), with the grinding bits
before the challenge in parentheses.

| round | segment | node | wrap |
|---|---|---|---|
| lookup challenges (LogUp) | none | 121.6 (24) | 121.6 (22) |
| constraint combination (powers of α) | 121.9 (9) | 121.5 (7) | 121.5 (7) |
| out-of-domain point ζ (DEEP) | 121.0 (14) | 121.1 (19) | 121.3 (18) |
| batching (independent coefficients) | 121.6 (15) | 121.3 (19) | 121.3 (20) |
| FRI folding, first round (later rounds need 2 bits less each) | 121.6 (17) | 121.6 (21) | 121.6 (22) |
| queries, toy-problem conjecture | 124.0 | 124.0 | 126.0 |
| queries, list-decoding-capacity radius | 122.0 | 122.0 | 124.3 |

Without grinding and with powers of one challenge for the batching, the
same rounds gave the following bits (the parameters of 2025: 42 queries,
and a wrap of 16 queries plus 20 bits):

| round | segment | node | wrap |
|---|---|---|---|
| lookup challenges | none | 98.6 | 100.6 |
| constraint combination | 112.9 | 114.5 | 114.5 |
| out-of-domain point | 107.0 | 103.1 | 104.3 |
| batching | 96.1 | 93.6 | 92.5 |
| first fold | 104.6 | 101.6 | 100.6 |

What each error term counts:

- **Batching** uses one independent coefficient per committed column and
  per quotient chunk, sampled from the transcript after the openings
  (`stark::Deep`). BCIKS20's bound for affine spaces then gives the line
  error, |D|/|K| per FRI input, whatever the number of polynomials. Each
  column is opened at ζ and gζ through one quotient by (x − ζ)(x − gζ), so
  a row of the recursive verifier still costs one product per column; the
  verifier samples a few hundred extension elements more. Until this
  change the columns were combined with powers of one challenge β, as in
  Plonky3. The combination is then a curve of degree L, the number of
  opened polynomials (1,440 for a segment, 1,030 for a node, 1,118 for the
  wrap), and BCIKS20's bound for curves multiplies the line error by L.
  That cost about 10 bits, made batching the weakest round, and at 121 bits
  would have needed 25 to 30 bits of grinding, minutes per proof.
- **The lookup term** is the degree of the LogUp identity in (γ, δ):
  rows × Σ(tuple length + 1), over |K|.
- **The folding term** is arity × domain over |K|, per round.
- **DEEP** is (quotient degree + n)/|K|, summed over the tables.

This problem is not specific to tabminer. A 2026 audit of OpenVM by Cantina
found the same effect for BabyBear^4. There the commit phase reached 99.5
bits against a 100-bit claim, and OpenVM added a grinding step before
sampling ζ.

## Commit-phase grinding

Before each challenge of the commit phase, the prover finds a witness w such
that, after observing w, the transcript's next sample has its low g bits
zero. The verifier checks this with one permutation. The number of bits g is
computed in `fri::grinding_bits`: the smallest g that brings the challenge's
error term (above) to `commit_bits`. It is computed with integer arithmetic
only (the logarithms are fixed-point), so every verifier derives the same
schedule. The prover, the native verifier and the recursive verifier all
compute the schedule with `stark::grinding_of`, and FRI computes it per round
with `fri::fold_grinding`.

The cost is 2^g permutations per challenge, about 1 s at 21 bits on the
development laptop, all cores. Measured end to end at 121 bits, grinding
adds about 6 s to a one-segment block and about 78 s to a 16-segment block
(five nodes at about 10 s each, mostly the 24 bits before the lookup
challenges); at 113 bits it added 2.7 s and 6 s.

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
round-by-round table, 1.5 to 1.9 bits below the toy-problem figure, and
still above the 121-bit rounds.

Whether the O(1/log n) failures cost more in practice is not settled. Their
constants are not known to us, so leave a few bits of margin above the
target.

## Proven security

In the Johnson regime, BCIKS20's correlated-agreement error is
(m + ½)^7·|D|² / (3ρ^{3/2}|K|). The |D|² factor leaves about 42 to 47 bits
before grinding over a 124-bit field (about 63 with it), and queries give
only log2(1/(√ρ(1 + 1/2m))) bits each.
Proven 100 bits would need several hundred queries and a larger field. No
deployed STARK on a 31-bit field claims proven security at these sizes;
Block et al. (ePrint 2024/1161) find provable levels 21 to 63 bits below the
conjectured ones.

## Going further

Getting past 120 bits is held back by the field. |K| = 2^123.6 caps the
ethSTARK figure at 122.6, and every algebraic round at 123.6 minus its
degree, so at most two more bits are available, each doubling all the
grinding (the lookup challenges of a node already take 8 s). Beyond that:

- a larger extension field. The quintic extension of BabyBear, about 2^155,
  would add about 31 bits to every algebraic round, but the recursive
  machine works in Fp4 words;
- then the digest. The BCS compiler allows λ up to 122 with 247-bit
  digests, and collisions cost 2^124. A width-24 Poseidon2 (Plonky3's other
  BabyBear instance, 8 full and 21 partial rounds) with a 10-element digest
  gives 310 bits.

## Measured cost

These measurements come from `aggregate::tests::security_configs`: mainnet
blocks of output-only segments, proven and verified on the development
laptop, with two segment provers at a time.

The first three rows batch with powers of β (2025); the last two with
independent coefficients.

| configuration | node / wrap tables | 1-segment block | 16-segment block | proof | verify |
|---|---|---|---|---|---|
| 42 queries + 16 bits; wrap 16 + 20 (about 92 bits) | 2^18 / 2^16 | 13.4 s | 60.5 s (wrap 10.4 s) | 149–151 KB | 9.5 ms |
| 50 + 16; wrap 20 + 16; no commit grinding (about 97 bits) | 2^19 / 2^17 | 13.2 s | 77.1 s (wrap 21.9 s) | 179–189 KB | 12 ms |
| 50 + 16; wrap 20 + 16; commit grinding to 113 (112 bits) | 2^19 / 2^17 | 15.9 s | 83.4 s (wrap 21.8 s) | 177–191 KB | 12 ms |
| 54 + 16; wrap 22 + 16; no commit grinding (about 101 bits) | 2^19 / 2^17 | 23.1 s | 92.5 s (wrap 18.9 s) | 204–207 KB | 13 ms |
| **mainnet: 54 + 16; wrap 22 + 16; commit grinding to 121 (120 bits)** | 2^19 / 2^17 | 29.0 s | 170 s (wrap 22.2 s) | 202–207 KB | 13 ms |

The grinding dominates the step from 112 to 120 bits: each challenge needs
8 more bits, 256 times the work, and a node's lookup challenges alone take
2^24 permutations, about 8 s. A 16-segment block proves five nodes.

At 54 queries, a node of four children still passes 2^19 rows and the wrap
over it 2^17, as at 50. The verifier of a single segment passes 2^17 rows
and its wrap 2^17 as well: at 50 queries that wrap fit 2^16, so the
single-segment block's wrap doubled, from about 10 s to 22 s. The published
proof is the wrap's, so its size hardly depends on the block.

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
