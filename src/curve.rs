use std::convert::TryFrom;
use std::iter::Sum;
use std::ops::{Add, Sub};

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::traits::Identity;
use num_bigint::BigUint;
use serde::{Serialize, Deserialize};

use crate::{CryptoError, Scalar};

const K: u32 = 10;


pub fn to_scalar(s: BigUint) -> Result<Scalar, CryptoError> {
    let mut s = s.to_bytes_le();
    s.resize(32, 0);
    let bytes = <[u8; 32]>::try_from(s.as_slice()).map_err(|_| CryptoError::Decoding)?;
    Ok(Scalar::from_bytes_mod_order(bytes))
}

pub fn to_biguint(s: Scalar) -> BigUint {
    BigUint::from_bytes_le(s.as_bytes())
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct CurveElem(RistrettoPoint);

impl CurveElem {
    pub fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        *self.0.compress().as_bytes()
    }

    pub fn as_biguint(&self) -> BigUint {
        BigUint::from_bytes_be(&self.as_bytes())
    }

    pub fn as_base64(&self) -> String {
        base64::encode(&self.as_bytes())
    }


    pub fn decoded(&self) -> BigUint {
        let adjusted = Scalar::from_bytes_mod_order(self.0.compress().to_bytes());
        BigUint::from_bytes_le(adjusted.as_bytes()) / 2u32.pow(K)
    }

    pub fn scaled(&self, other: &Scalar) -> Self {
        Self(self.0 * other)
    }

    pub fn generator() -> Self {
        Self(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
    }
}

impl Add for CurveElem {
    type Output = CurveElem;

    fn add(self, rhs: Self) -> Self::Output {
        CurveElem(self.0 + rhs.0)
    }
}

impl Sub for CurveElem {
    type Output = CurveElem;

    fn sub(self, rhs: Self) -> Self::Output {
        CurveElem(self.0 - rhs.0)
    }
}

impl Add for &CurveElem {
    type Output = CurveElem;

    fn add(self, rhs: Self) -> Self::Output {
        CurveElem(self.0 + rhs.0)
    }
}

impl Sub for &CurveElem {
    type Output = CurveElem;

    fn sub(self, rhs: Self) -> Self::Output {
        CurveElem(self.0 - rhs.0)
    }
}

impl Sum for CurveElem {
    fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
        iter.fold(Self::identity(), |acc, x| acc + x)
    }
}

impl TryFrom<Scalar> for CurveElem {
    type Error = CryptoError;

    fn try_from(s: Scalar) -> Result<Self, CryptoError> {
        // Can encode at most 252 - K bits
        let bits = to_biguint(s.clone()).bits();
        if bits > (252 - K) as usize {
            return Err(CryptoError::Encoding);
        }

        let buffer = Scalar::from(2u32.pow(K));
        let s = s * buffer;
        let mut d = Scalar::zero();
        loop {
            if let Some(p) = CompressedRistretto((s + d).to_bytes()).decompress() {
                return Ok(Self(p));
            }

            d += &Scalar::one();
            if d - buffer == Scalar::zero() {
                return Err(CryptoError::Encoding);
            }
        }
    }
}

impl TryFrom<BigUint> for CurveElem {
    type Error = CryptoError;

    fn try_from(n: BigUint) -> Result<Self, CryptoError> {
        to_scalar(n).and_then(|s| Self::try_from(s))
    }
}

impl TryFrom<&[u8]> for CurveElem {
    type Error = CryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(BigUint::from_bytes_be(value))
    }
}

impl TryFrom<u32> for CurveElem {
    type Error = CryptoError;

    fn try_from(n: u32) -> Result<Self, CryptoError> {
        Self::try_from(BigUint::from(n))
    }
}

impl TryFrom<u64> for CurveElem {
    type Error = CryptoError;

    fn try_from(n: u64) -> Result<Self, CryptoError> {
        Self::try_from(BigUint::from(n))
    }
}

#[cfg(test)]
mod tests {
    use crate::{elgamal, curve};

    #[test]
    fn test_biguint_scalar() {
        let mut ctx = elgamal::CryptoContext::new();
        for _ in 0..10 {
            let s = ctx.random_power().unwrap();
            assert_eq!(s, curve::to_scalar(curve::to_biguint(s)).unwrap());
        }
    }
}