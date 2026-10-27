//! Quartic extension field `Fp4 = Fp[x] / (x^4 - 11)` over BabyBear.
//!
//! `x^4 - 11` is irreducible because 11 is a non-square modulo p and
//! `p = 1 (mod 4)`. This is the same binomial extension Plonky3 uses for
//! BabyBear, so elements are represented identically: four coefficients,
//! lowest degree first. The extension has about 124 bits, which is what
//! FRI and the STARK composition need for soundness.

use core::fmt;

use crate::poseidon2::Fp;

/// The binomial constant: `x^4 = W`.
pub const W: Fp = Fp::new(11);

/// `W^((p-1)/4)`, a primitive fourth root of unity; `x^p = Z * x`.
const Z: Fp = Fp::new(1_728_404_513);

/// Extension degree.
pub const DEGREE: usize = 4;

/// An element of `Fp4`, coefficients lowest degree first. Laid out as its
/// four coefficients, so a row of base values can be read as extension
/// values in place ([`as_fp4`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Fp4(pub [Fp; DEGREE]);

/// Base values, four per element, read as extension values.
pub fn as_fp4(v: &[Fp]) -> &[Fp4] {
    assert!(v.len().is_multiple_of(DEGREE), "not a whole number of extension values");
    // SAFETY: `Fp4` is `repr(transparent)` over `[Fp; 4]`, so it has the
    // size and alignment of four consecutive `Fp`.
    unsafe { core::slice::from_raw_parts(v.as_ptr().cast::<Fp4>(), v.len() / DEGREE) }
}

impl Fp4 {
    pub const ZERO: Fp4 = Fp4([Fp::ZERO; DEGREE]);
    pub const ONE: Fp4 = Fp4([Fp::ONE, Fp::ZERO, Fp::ZERO, Fp::ZERO]);
    /// The generator `x` of the extension.
    pub const X: Fp4 = Fp4([Fp::ZERO, Fp::ONE, Fp::ZERO, Fp::ZERO]);

    pub const fn new(c: [Fp; DEGREE]) -> Fp4 {
        Fp4(c)
    }

    pub const fn from_base(a: Fp) -> Fp4 {
        Fp4([a, Fp::ZERO, Fp::ZERO, Fp::ZERO])
    }

    pub const fn is_zero(&self) -> bool {
        self.0[0].is_zero() && self.0[1].is_zero() && self.0[2].is_zero() && self.0[3].is_zero()
    }

    /// `Some(a)` if this element lies in the base field.
    pub const fn as_base(&self) -> Option<Fp> {
        if self.0[1].is_zero() && self.0[2].is_zero() && self.0[3].is_zero() { Some(self.0[0]) } else { None }
    }

    #[inline(always)]
    pub const fn add(&self, b: &Fp4) -> Fp4 {
        let a = &self.0;
        let b = &b.0;
        Fp4([a[0].add(&b[0]), a[1].add(&b[1]), a[2].add(&b[2]), a[3].add(&b[3])])
    }

    #[inline(always)]
    pub const fn sub(&self, b: &Fp4) -> Fp4 {
        let a = &self.0;
        let b = &b.0;
        Fp4([a[0].sub(&b[0]), a[1].sub(&b[1]), a[2].sub(&b[2]), a[3].sub(&b[3])])
    }

    #[inline(always)]
    pub const fn neg(&self) -> Fp4 {
        Fp4([self.0[0].neg(), self.0[1].neg(), self.0[2].neg(), self.0[3].neg()])
    }

    #[inline(always)]
    pub const fn double(&self) -> Fp4 {
        self.add(self)
    }

    /// Multiplication by a base field element.
    #[inline(always)]
    pub const fn mul_base(&self, b: &Fp) -> Fp4 {
        let a = &self.0;
        Fp4([a[0].mul(b), a[1].mul(b), a[2].mul(b), a[3].mul(b)])
    }

    #[inline(always)]
    pub const fn mul(&self, b: &Fp4) -> Fp4 {
        let a = &self.0;
        let b = &b.0;
        // c_k = sum_{i+j=k} a_i b_j + W * sum_{i+j=k+4} a_i b_j
        let c0 = a[0].mul(&b[0]).add(&W.mul(&a[1].mul(&b[3]).add(&a[2].mul(&b[2])).add(&a[3].mul(&b[1]))));
        let c1 = a[0].mul(&b[1]).add(&a[1].mul(&b[0])).add(&W.mul(&a[2].mul(&b[3]).add(&a[3].mul(&b[2]))));
        let c2 = a[0].mul(&b[2]).add(&a[1].mul(&b[1])).add(&a[2].mul(&b[0])).add(&W.mul(&a[3].mul(&b[3])));
        let c3 = a[0].mul(&b[3]).add(&a[1].mul(&b[2])).add(&a[2].mul(&b[1])).add(&a[3].mul(&b[0]));
        Fp4([c0, c1, c2, c3])
    }

    #[inline(always)]
    pub const fn square(&self) -> Fp4 {
        self.mul(self)
    }

    /// `self^(p^k)`: multiplies coefficient `i` by `Z^(i*k)`.
    pub const fn frobenius(&self, k: usize) -> Fp4 {
        let z = Z.pow(k as u64);
        let z2 = z.square();
        let z3 = z2.mul(&z);
        Fp4([self.0[0], self.0[1].mul(&z), self.0[2].mul(&z2), self.0[3].mul(&z3)])
    }

    /// Multiplicative inverse, or `None` for zero. Uses the norm:
    /// `a^-1 = (a^p a^p^2 a^p^3) / N(a)` with `N(a)` in the base field.
    pub const fn inverse(&self) -> Option<Fp4> {
        if self.is_zero() {
            return None;
        }
        let t = self.frobenius(1).mul(&self.frobenius(2)).mul(&self.frobenius(3));
        let norm = self.mul(&t);
        debug_assert!(norm.0[1].is_zero() && norm.0[2].is_zero() && norm.0[3].is_zero());
        match norm.0[0].inverse() {
            Some(n_inv) => Some(t.mul_base(&n_inv)),
            None => None,
        }
    }

    pub const fn pow(&self, mut e: u64) -> Fp4 {
        let mut base = *self;
        let mut acc = Fp4::ONE;
        while e != 0 {
            if e & 1 == 1 {
                acc = acc.mul(&base);
            }
            base = base.square();
            e >>= 1;
        }
        acc
    }
}

impl fmt::Debug for Fp4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fp4({}, {}, {}, {})", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl From<Fp> for Fp4 {
    fn from(a: Fp) -> Fp4 {
        Fp4::from_base(a)
    }
}

impl From<u32> for Fp4 {
    fn from(a: u32) -> Fp4 {
        Fp4::from_base(Fp::from_u32(a))
    }
}

macro_rules! binop {
    ($tr:ident, $m:ident, $tra:ident, $ma:ident, $f:ident) => {
        impl core::ops::$tr for Fp4 {
            type Output = Fp4;
            fn $m(self, rhs: Fp4) -> Fp4 {
                Fp4::$f(&self, &rhs)
            }
        }
        impl core::ops::$tra for Fp4 {
            fn $ma(&mut self, rhs: Fp4) {
                *self = Fp4::$f(self, &rhs);
            }
        }
    };
}
binop!(Add, add, AddAssign, add_assign, add);
binop!(Sub, sub, SubAssign, sub_assign, sub);
binop!(Mul, mul, MulAssign, mul_assign, mul);

impl core::ops::Mul<Fp> for Fp4 {
    type Output = Fp4;
    fn mul(self, rhs: Fp) -> Fp4 {
        self.mul_base(&rhs)
    }
}

impl core::ops::Neg for Fp4 {
    type Output = Fp4;
    fn neg(self) -> Fp4 {
        Fp4::neg(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::P;
    use crate::test_util::Rng;

    #[test]
    fn generator_satisfies_binomial() {
        assert_eq!(Fp4::X.pow(4), Fp4::from_base(W));
        assert_eq!(Fp4::X.square().square(), Fp4::from_base(W));
        assert_eq!(Z.pow(4), Fp::ONE);
        assert_eq!(Z.square(), -Fp::ONE);
        assert_eq!(W.pow(((P - 1) / 4) as u64), Z);
    }

    #[test]
    fn ring_axioms_on_random_elements() {
        let mut rng = Rng::new(1);
        for _ in 0..50 {
            let a = rng.fp4();
            let b = rng.fp4();
            let c = rng.fp4();
            assert_eq!(a * b, b * a);
            assert_eq!((a * b) * c, a * (b * c));
            assert_eq!(a * (b + c), a * b + a * c);
            assert_eq!(a + b - b, a);
            assert_eq!(a * Fp4::ONE, a);
            assert_eq!(a * Fp4::ZERO, Fp4::ZERO);
            assert_eq!(-a + a, Fp4::ZERO);
            assert_eq!(a.double(), a + a);
            let s = rng.fp();
            assert_eq!(a * s, a * Fp4::from_base(s));
        }
    }

    #[test]
    fn frobenius_is_power_p() {
        let mut rng = Rng::new(2);
        for _ in 0..5 {
            let a = rng.fp4();
            assert_eq!(a.frobenius(1), a.pow(P as u64));
            assert_eq!(a.frobenius(2), a.frobenius(1).frobenius(1));
            assert_eq!(a.frobenius(4), a);
            // Base field elements are fixed by Frobenius.
            let b = Fp4::from_base(rng.fp());
            assert_eq!(b.frobenius(1), b);
        }
    }

    #[test]
    fn inverse() {
        assert!(Fp4::ZERO.inverse().is_none());
        assert_eq!(Fp4::ONE.inverse(), Some(Fp4::ONE));
        let mut rng = Rng::new(3);
        for _ in 0..50 {
            let a = rng.fp4();
            let inv = a.inverse().unwrap();
            assert_eq!(a * inv, Fp4::ONE);
        }
        let b = Fp::new(12345);
        assert_eq!(Fp4::from_base(b).inverse().unwrap().as_base(), b.inverse());
        assert!(Fp4::X.as_base().is_none());
    }
}
