#!/usr/bin/env python3
"""Soundness estimates for tabminer's STARK proofs (see SECURITY.md).

Every Fiat-Shamir round of a proof gets a soundness error per attempt;
a proof's security is the smallest -log2 of them, with grinding counted
only for the round it precedes (the queries). Two models:

* conjectured: the ethSTARK toy-problem conjecture (ethSTARK docs v1.2,
  section 5.9, eq. 19) for the query phase, and degree / |K| for the
  algebraic rounds (Schwartz-Zippel, list size one, the up-to-capacity
  correlated-agreement bound for batching and folding);
* proven: the round-by-round bounds of ethSTARK Theorem 5 (from
  BCIKS20, Johnson regime), adapted to powers instead of independent
  coefficients (BCIKS20's curve version: error times the curve degree),
  maximised over m.

Run: python3 tools/soundness.py
"""

from math import log2, sqrt

P = 2013265921  # BabyBear
LOG_K = 4 * log2(P)  # quartic extension, about 123.6
DIGEST_BITS = 8 * log2(P)  # Poseidon2 digests, about 247


def h_q(x, log_q):
    """q-ary entropy with log2 q = log_q."""
    if x <= 0:
        return 0.0
    # x log_q(q - 1) is x to within 2^-log_q.
    return x + (-x * log2(x) - (1 - x) * log2(1 - x)) / log_q


def list_capacity_radius(rho, log_q):
    """delta with H_q(delta) = 1 - rho: the list-decoding capacity bound the
    2025 counterexamples (Crites-Stewart, Diamond-Gruen) leave open."""
    lo, hi = 0.0, 1 - rho
    for _ in range(200):
        mid = (lo + hi) / 2
        if h_q(mid, log_q) < 1 - rho:
            lo = mid
        else:
            hi = mid
    return lo


class Table:
    def __init__(self, name, log_n, width, pre, degree, constraints, terms, tuple_lens, group, zk=False):
        self.name, self.log_n, self.width, self.pre = name, log_n, width, pre
        self.degree, self.constraints, self.terms, self.tuple_lens, self.group = (
            degree, constraints, terms, tuple_lens, group)
        self.zk = zk

    def chunks(self):
        q = max(self.degree - 1, 1)
        log_q = (q - 1).bit_length()
        return 1 << (log_q + (1 if self.zk else 0))

    def aux_cols(self):
        if self.terms == 0:
            return 0
        return 4 * (-(-self.terms // self.group) + 1 + (2 if self.zk else 0))

    def lookup_constraints(self):
        if self.terms == 0:
            return 0
        return -(-self.terms // self.group) + 3 + (2 if self.zk else 0)

    def width_committed(self):
        return self.width + (8 if self.zk else 0)

    def batched(self):
        """Polynomials in the DEEP combination: each column at two points,
        quotient chunks at one."""
        return 2 * (self.width_committed() + self.aux_cols() + self.pre) + 4 * self.chunks()


class Proof:
    def __init__(self, name, tables, log_blowup, queries, pow_bits, commit_pow=0):
        self.name, self.tables = name, tables
        # Grinding before every challenge of the commit phase (lookup,
        # out-of-domain, batching and folding challenges), if any.
        self.commit_pow = commit_pow
        self.R, self.s, self.pow = log_blowup, queries, pow_bits
        self.rho = 2.0 ** -log_blowup
        self.log_N = max(t.log_n for t in tables) + log_blowup

    def rounds_conjectured(self):
        K = 2 ** LOG_K
        r = {}
        lu = sum((1 << t.log_n) * (sum(l + 1 for l in t.tuple_lens)) for t in self.tables)
        if lu:
            r["lookup challenges (LogUp)"] = lu / K
        r["constraint combination"] = sum(t.constraints + t.lookup_constraints() for t in self.tables) / K
        r["out-of-domain point (DEEP)"] = sum((t.chunks() + 1) << t.log_n for t in self.tables) / K
        r["batching (powers)"] = sum(t.batched() for t in self.tables) * 2 ** self.log_N / K
        r["FRI folding (first round)"] = 4 * 2 ** self.log_N / K
        return r

    def query_bits(self, model):
        if model == "toy":
            per = self.R
        elif model == "list-capacity":
            per = -log2(1 - list_capacity_radius(self.rho, LOG_K))
        else:
            raise ValueError(model)
        return per * self.s + self.pow

    def rounds_proven(self, m):
        rho, K = self.rho, 2 ** LOG_K
        n = 2 ** self.log_N
        ell = 2 * m / rho
        r = {}
        lu = sum((1 << t.log_n) * (sum(l + 1 for l in t.tuple_lens)) for t in self.tables)
        if lu:
            r["lookup challenges (LogUp)"] = ell * lu / K
        r["constraint combination"] = ell * sum(t.constraints + t.lookup_constraints() for t in self.tables) / K
        d_max = max(t.chunks() << t.log_n for t in self.tables)
        r["out-of-domain point (DEEP)"] = (d_max + n + 4) * ell ** 2 / (K - 4 * n)
        e3 = (m + 0.5) ** 7 * n ** 2 / (3 * rho ** 1.5 * K)
        r["batching (powers)"] = sum(t.batched() for t in self.tables) * e3
        r["FRI folding (first round)"] = 3 * e3 + (2 * m + 1) * (n + 1) * 4 / (K * sqrt(rho))
        r["queries"] = (sqrt(rho) * (1 + 1 / (2 * m))) ** self.s * 2.0 ** -self.pow
        return r


def bits(eps):
    return -log2(eps)


def report(proof):
    g = proof.commit_pow
    print(f"\n## {proof.name}: rate 1/{2 ** proof.R}, {proof.s} queries, {proof.pow} grinding bits, "
          f"{g} commit-phase grinding bits, largest domain 2^{proof.log_N}")
    c = {k: v * 2.0 ** -(0 if k == "constraint combination" else g) for k, v in proof.rounds_conjectured().items()}
    q_toy = proof.query_bits("toy")
    q_cap = proof.query_bits("list-capacity")
    print("  conjectured, per round (bits):")
    for k, v in c.items():
        print(f"    {k:32s} {bits(v):6.1f}")
    print(f"    {'queries (toy problem)':32s} {q_toy:6.1f}")
    print(f"    {'queries (list-decoding capacity)':32s} {q_cap:6.1f}")
    print(f"    ethSTARK eq. 19: min(grinding + R s, log2 |K|) - 1 = {min(q_toy, LOG_K) - 1:.1f}")
    algebraic = min(bits(v) for v in c.values())
    print(f"    => {min(algebraic, q_toy) - 1:.1f} (toy) / {min(algebraic, q_cap) - 1:.1f} (capacity), "
          f"quantum about half")
    best = None
    for m in range(3, 40):
        r = {k: v * 2.0 ** -(0 if k in ("constraint combination", "queries") else g)
             for k, v in proof.rounds_proven(m).items()}
        b = min(bits(v) for v in r.values())
        if best is None or b > best[0]:
            best = (b, m, r)
    b, m, r = best
    print(f"  proven (Johnson regime, best m = {m}):")
    for k, v in r.items():
        print(f"    {k:32s} {bits(v):6.1f}")
    print(f"    => {b - 1:.1f}")


def tables(spec, zk=False):
    return [Table(*t, zk=zk) for t in spec]


if __name__ == "__main__":
    import json
    import sys
    params = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else None
    print(f"|K| = 2^{LOG_K:.2f}; Poseidon2 digests {DIGEST_BITS:.0f} bits "
          f"(collisions 2^{DIGEST_BITS / 2:.0f}, BCS needs digest >= 2 lambda + 3)")
    for p in params:
        report(Proof(p["name"], tables(p["tables"], p.get("zk", False)), p["log_blowup"], p["queries"], p["pow"],
                     p.get("commit_pow", 0)))
