//! Fiat-Shamir transcript: a duplex sponge over the Poseidon2 permutation.
//!
//! Observed elements are buffered and added into the rate eight at a time
//! (a partial buffer is flushed, zero padded, before any sample); samples
//! are read from the rate in order after a permutation, and a new
//! permutation is run when the rate is exhausted. Observing anything
//! discards unread output, so a sample always depends on everything
//! observed before it. Addition-based absorption and in-order squeezing make
//! every transcript step an `absorb` row of the hash machine, which is what
//! lets a verifier circuit replay it.

use crate::ext::{DEGREE, Fp4};
use crate::poseidon2::{BatchState, DIGEST, Fp, LANES, RATE, WIDTH, permute_batch, permute_in_place};

#[derive(Clone, Debug)]
pub struct Challenger {
    state: [Fp; WIDTH],
    input: Vec<Fp>,
    /// Number of rate elements already squeezed since the last permutation;
    /// `RATE` means none are available.
    squeezed: usize,
}

impl Default for Challenger {
    fn default() -> Self {
        Self::new()
    }
}

impl Challenger {
    pub fn new() -> Challenger {
        Challenger { state: [Fp::ZERO; WIDTH], input: Vec::with_capacity(RATE), squeezed: RATE }
    }

    /// Adds the buffered input into the rate and permutes.
    fn duplex(&mut self) {
        for (i, x) in self.input.drain(..).enumerate() {
            self.state[i] = self.state[i].add(&x);
        }
        permute_in_place(&mut self.state);
        self.squeezed = 0;
    }

    /// The sponge state, for circuits replaying the transcript.
    pub fn state(&self) -> &[Fp; WIDTH] {
        &self.state
    }

    pub fn observe(&mut self, x: Fp) {
        self.squeezed = RATE;
        self.input.push(x);
        if self.input.len() == RATE {
            self.duplex();
            self.squeezed = RATE;
        }
    }

    pub fn observe_slice(&mut self, xs: &[Fp]) {
        for &x in xs {
            self.observe(x);
        }
    }

    pub fn observe_ext(&mut self, x: &Fp4) {
        self.observe_slice(&x.0);
    }

    pub fn observe_digest(&mut self, d: &[Fp; DIGEST]) {
        self.observe_slice(d);
    }

    pub fn sample(&mut self) -> Fp {
        if !self.input.is_empty() || self.squeezed == RATE {
            self.duplex();
        }
        let x = self.state[self.squeezed];
        self.squeezed += 1;
        x
    }

    pub fn sample_ext(&mut self) -> Fp4 {
        let mut c = [Fp::ZERO; DEGREE];
        for x in c.iter_mut() {
            *x = self.sample();
        }
        Fp4(c)
    }

    /// A uniform-ish integer with `bits` bits (`bits <= 27`), taken from the
    /// low bits of a sampled element.
    pub fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits <= 27, "at most 27 bits per sample");
        (self.sample().to_canonical() as usize) & ((1usize << bits) - 1)
    }

    /// For each of `LANES` candidate values, whether observing it and then
    /// calling `sample_bits(bits)` would return zero; the transcript is not
    /// changed. Used to grind proof-of-work witnesses eight at a time.
    pub fn zero_bits_after(&self, candidates: &[Fp; LANES], bits: usize) -> [bool; LANES] {
        assert!(bits <= 27, "at most 27 bits per sample");
        // `observe` appends to the buffer and duplexes when it fills; the
        // sample then permutes again (no input, nothing left to squeeze).
        let k = self.input.len();
        let mut base = self.state;
        for (i, x) in self.input.iter().enumerate() {
            base[i] = base[i].add(x);
        }
        let mut s: BatchState = core::array::from_fn(|i| [base[i].to_mont(); LANES]);
        for (l, w) in candidates.iter().enumerate() {
            s[k][l] = base[k].add(w).to_mont();
        }
        permute_batch(&mut s);
        if k + 1 == RATE {
            permute_batch(&mut s);
        }
        let mask = (1u32 << bits) - 1;
        core::array::from_fn(|l| Fp::from_mont(s[0][l]).to_canonical() & mask == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_sensitive() {
        let mut a = Challenger::new();
        let mut b = Challenger::new();
        a.observe(Fp::new(1));
        b.observe(Fp::new(1));
        assert_eq!(a.sample(), b.sample());
        let mut c = Challenger::new();
        c.observe(Fp::new(2));
        let mut d = Challenger::new();
        d.observe(Fp::new(1));
        assert_ne!(c.sample(), d.sample());
        // Observing after sampling changes subsequent samples.
        let mut e = a.clone();
        e.observe(Fp::new(5));
        assert_ne!(a.sample(), e.sample());
    }

    #[test]
    fn samples_are_not_repeated() {
        let mut ch = Challenger::new();
        ch.observe_slice(&(0..20).map(Fp::new).collect::<Vec<_>>());
        let xs: Vec<Fp> = (0..40).map(|_| ch.sample()).collect();
        for i in 0..xs.len() {
            for j in 0..i {
                assert_ne!(xs[i], xs[j]);
            }
        }
        for _ in 0..100 {
            assert!(ch.sample_bits(10) < 1024);
        }
        assert_eq!(ch.sample_bits(0), 0);
    }

    #[test]
    fn batched_bit_check_matches_sampling() {
        let ws: [Fp; LANES] = core::array::from_fn(|i| Fp::new(i as u32 * 7 + 3));
        // Every buffer fill, including the one that makes `observe` duplex.
        for pending in 0..RATE {
            let mut ch = Challenger::new();
            ch.observe_slice(&(0..9 + pending as u32).map(Fp::new).collect::<Vec<_>>());
            for bits in [0, 1, 3] {
                let got = ch.zero_bits_after(&ws, bits);
                for (l, w) in ws.iter().enumerate() {
                    let mut c = ch.clone();
                    c.observe(*w);
                    assert_eq!(got[l], c.sample_bits(bits) == 0, "pending {pending} bits {bits} lane {l}");
                }
            }
        }
    }
}
