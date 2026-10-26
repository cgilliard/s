//! Byte encoding helpers shared by proof and block serialization. All
//! integers are little-endian; field elements use their canonical 4-byte
//! form and are validated on read.

use crate::ext::Fp4;
use crate::poseidon2::{DIGEST, Fp};

pub type Digest = [Fp; DIGEST];

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn with_capacity(n: usize) -> Writer {
        Writer(Vec::with_capacity(n))
    }

    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub fn fp(&mut self, x: &Fp) {
        self.0.extend_from_slice(&x.to_le_bytes());
    }

    pub fn fps(&mut self, xs: &[Fp]) {
        for x in xs {
            self.fp(x);
        }
    }

    pub fn fp4(&mut self, x: &Fp4) {
        self.fps(&x.0);
    }

    pub fn digest(&mut self, d: &Digest) {
        self.fps(d);
    }

    /// Length-prefixed list of field elements.
    pub fn fp_vec(&mut self, xs: &[Fp]) {
        self.u32(xs.len() as u32);
        self.fps(xs);
    }

    pub fn fp4_vec(&mut self, xs: &[Fp4]) {
        self.u32(xs.len() as u32);
        for x in xs {
            self.fp4(x);
        }
    }

    pub fn digest_vec(&mut self, ds: &[Digest]) {
        self.u32(ds.len() as u32);
        for d in ds {
            self.digest(d);
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// A length prefix bounded by the bytes remaining, to reject absurd
    /// allocations before reading.
    pub fn len(&mut self, item_size: usize) -> Option<usize> {
        let n = self.u32()? as usize;
        if n.checked_mul(item_size.max(1))? > self.0.len() {
            return None;
        }
        Some(n)
    }

    pub fn fp(&mut self) -> Option<Fp> {
        Fp::from_le_bytes(self.take(4)?.try_into().unwrap())
    }

    pub fn fp4(&mut self) -> Option<Fp4> {
        Some(Fp4([self.fp()?, self.fp()?, self.fp()?, self.fp()?]))
    }

    pub fn digest(&mut self) -> Option<Digest> {
        let mut d = [Fp::ZERO; DIGEST];
        for x in d.iter_mut() {
            *x = self.fp()?;
        }
        Some(d)
    }

    pub fn fp_vec(&mut self) -> Option<Vec<Fp>> {
        let n = self.len(4)?;
        (0..n).map(|_| self.fp()).collect()
    }

    pub fn fp4_vec(&mut self) -> Option<Vec<Fp4>> {
        let n = self.len(16)?;
        (0..n).map(|_| self.fp4()).collect()
    }

    pub fn digest_vec(&mut self) -> Option<Vec<Digest>> {
        let n = self.len(32)?;
        (0..n).map(|_| self.digest()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rejection() {
        let mut w = Writer::default();
        w.u32(7);
        w.u64(u64::MAX);
        w.fp4(&Fp4([Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)]));
        w.fp_vec(&[Fp::new(9), Fp::new(10)]);
        w.digest_vec(&[[Fp::new(5); DIGEST]]);
        let bytes = w.finish();
        let mut r = Reader(&bytes);
        assert_eq!(r.u32(), Some(7));
        assert_eq!(r.u64(), Some(u64::MAX));
        assert_eq!(r.fp4(), Some(Fp4([Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)])));
        assert_eq!(r.fp_vec(), Some(vec![Fp::new(9), Fp::new(10)]));
        assert_eq!(r.digest_vec(), Some(vec![[Fp::new(5); DIGEST]]));
        assert!(r.is_empty());
        assert_eq!(r.u32(), None);
        // Non-canonical element and oversized length prefix are rejected.
        let mut r = Reader(&0x7800_0001u32.to_le_bytes());
        assert_eq!(r.fp(), None);
        let mut r = Reader(&u32::MAX.to_le_bytes());
        assert_eq!(r.fp_vec(), None);
    }
}
