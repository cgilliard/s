//! A minimal field abstraction so AIR constraints can be evaluated both over
//! the base field (by the prover, on the low-degree extension) and over the
//! extension field (by the verifier, at the out-of-domain point).

use core::fmt::Debug;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::ext::Fp4;
use crate::poseidon2::Fp;

pub trait Field:
    Copy
    + PartialEq
    + Eq
    + Debug
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
    + From<Fp>
    + 'static
{
    const ZERO: Self;
    const ONE: Self;

    fn from_u32(v: u32) -> Self {
        Fp::from_u32(v).into()
    }

    /// Multiplication by a base field element.
    fn scale(self, b: Fp) -> Self;

    /// `e * self`, with the result in the extension field.
    fn mul_ext(self, e: Fp4) -> Fp4;

    fn inv(self) -> Option<Self>;

    fn exp(self, e: u64) -> Self {
        let mut base = self;
        let mut acc = Self::ONE;
        let mut e = e;
        while e != 0 {
            if e & 1 == 1 {
                acc *= base;
            }
            base *= base;
            e >>= 1;
        }
        acc
    }
}

impl Field for Fp {
    const ZERO: Fp = Fp::ZERO;
    const ONE: Fp = Fp::ONE;

    fn scale(self, b: Fp) -> Fp {
        Fp::mul(&self, &b)
    }

    fn mul_ext(self, e: Fp4) -> Fp4 {
        e.mul_base(&self)
    }

    fn inv(self) -> Option<Fp> {
        Fp::inverse(&self)
    }
}

impl Field for Fp4 {
    const ZERO: Fp4 = Fp4::ZERO;
    const ONE: Fp4 = Fp4::ONE;

    fn scale(self, b: Fp) -> Fp4 {
        Fp4::mul_base(&self, &b)
    }

    fn mul_ext(self, e: Fp4) -> Fp4 {
        Fp4::mul(&e, &self)
    }

    fn inv(self) -> Option<Fp4> {
        Fp4::inverse(&self)
    }
}

/// Polynomial-degree tracker: a pseudo-field whose "values" are degrees.
/// Addition takes the maximum, multiplication adds, constants are degree
/// zero. Evaluating an AIR over it bounds the degree of every constraint.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Deg(pub u32);

macro_rules! deg_ops {
    ($tr:ident, $m:ident, $tra:ident, $ma:ident, $f:expr) => {
        impl core::ops::$tr for Deg {
            type Output = Deg;
            fn $m(self, rhs: Deg) -> Deg {
                Deg($f(self.0, rhs.0))
            }
        }
        impl core::ops::$tra for Deg {
            fn $ma(&mut self, rhs: Deg) {
                self.0 = $f(self.0, rhs.0);
            }
        }
    };
}
deg_ops!(Add, add, AddAssign, add_assign, u32::max);
deg_ops!(Sub, sub, SubAssign, sub_assign, u32::max);
deg_ops!(Mul, mul, MulAssign, mul_assign, |a, b| a + b);

impl core::ops::Neg for Deg {
    type Output = Deg;
    fn neg(self) -> Deg {
        self
    }
}

impl From<Fp> for Deg {
    fn from(_: Fp) -> Deg {
        Deg(0)
    }
}

impl Field for Deg {
    const ZERO: Deg = Deg(0);
    const ONE: Deg = Deg(0);

    fn scale(self, _: Fp) -> Deg {
        self
    }

    fn mul_ext(self, e: Fp4) -> Fp4 {
        e
    }

    fn inv(self) -> Option<Deg> {
        Some(self)
    }
}

/// Inverts every element with Montgomery's trick (three multiplications per
/// element plus one inversion). All elements must be non-zero.
pub fn batch_inverse<F: Field>(v: &[F]) -> Vec<F> {
    let mut prefix = Vec::with_capacity(v.len());
    let mut acc = F::ONE;
    for x in v {
        prefix.push(acc);
        acc *= *x;
    }
    let mut inv = acc.inv().expect("batch_inverse: zero element");
    let mut out = vec![F::ZERO; v.len()];
    for i in (0..v.len()).rev() {
        out[i] = inv * prefix[i];
        inv *= v[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::Rng;

    #[test]
    fn batch_inverse_matches_individual() {
        let mut rng = Rng::new(40);
        let xs: Vec<Fp> = (0..17).map(|_| rng.fp()).collect();
        for (x, inv) in xs.iter().zip(batch_inverse(&xs)) {
            assert_eq!(*x * inv, Fp::ONE);
        }
        let ys: Vec<Fp4> = (0..9).map(|_| rng.fp4()).collect();
        for (y, inv) in ys.iter().zip(batch_inverse(&ys)) {
            assert_eq!(*y * inv, Fp4::ONE);
        }
        assert!(batch_inverse::<Fp>(&[]).is_empty());
        assert_eq!(Fp::from_u32(3).exp(4), Fp::new(81));
        assert_eq!(Fp4::from_u32(2).exp(10), Fp4::from_u32(1024));
    }
}
