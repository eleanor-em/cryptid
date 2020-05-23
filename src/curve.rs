use std::convert::TryFrom;
use std::iter::Sum;
use std::ops::{Add, Sub};

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::traits::Identity;
use num_bigint::BigUint;
use serde::{Serialize, Deserialize};

use crate::{CryptoError, Scalar, DalekScalar};
use crate::elgamal::CryptoContext;

const K: u32 = 12;

pub fn scalar_max_size_bytes() -> usize {
    ((252 - K) / 8) as usize
}

pub fn try_to_scalar(bytes: &Vec<u8>) -> Result<Scalar, CryptoError> {
    if bytes.len() > 32 {
        Err(CryptoError::Decoding)
    } else {
        let mut bytes = bytes.clone();
        bytes.resize(32, 0);

        Ok(<[u8; 32]>::try_from(bytes.as_ref()).unwrap().into())
    }
}

pub fn to_scalar(s: BigUint) -> Scalar {
    let mut s = s.to_bytes_le();
    s.resize(32, 0);
    // Below should never fail
    try_to_scalar(&s).unwrap()
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

    pub fn as_base64(&self) -> String {
        base64::encode(&self.as_bytes())
    }


    pub fn decoded(&self) -> Result<Scalar, CryptoError> {
        let adjusted = Scalar::from(self.0.compress().to_bytes());
        let x = BigUint::from_bytes_le(adjusted.as_bytes()) / 2u32.pow(K);
        if x.bits() > scalar_max_size_bytes() * 8 + K as usize + 4 {
            Err(CryptoError::Decoding)
        } else {
            Ok(to_scalar(x))
        }
    }

    pub fn scaled(&self, other: &Scalar) -> Self {
        Self(other.0 * self.0)
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
        let bits = to_biguint(s).bits();

        let mut s = s.0;
        if bits > (252 - K) as usize {
            return Err(CryptoError::Encoding);
        }

        let buffer = DalekScalar::from(2u32.pow(K));
        s *= buffer;
        let mut d = DalekScalar::zero();
        loop {
            if let Some(p) = CompressedRistretto((s + d).to_bytes()).decompress() {
                return Ok(Self(p));
            }

            d += DalekScalar::one();
            if d - buffer == DalekScalar::zero() {
                return Err(CryptoError::Encoding);
            }
        }
    }
}

impl TryFrom<BigUint> for CurveElem {
    type Error = CryptoError;

    fn try_from(n: BigUint) -> Result<Self, CryptoError> {
        Self::try_from(to_scalar(n))
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

#[derive(Debug)]
pub struct Polynomial {
    k: usize,
    n: usize,
    x_i: Scalar,
    ctx: CryptoContext,
    coefficients: Vec<DalekScalar>,
}

impl Polynomial {
    pub fn random(ctx: &mut CryptoContext, k: usize, n: usize) -> Result<Polynomial, CryptoError> {
        let mut ctx = ctx.cloned();
        let x_i = ctx.random_power()?;
        let mut coefficients = Vec::with_capacity(k);
        coefficients.push(x_i.0);
        for _ in 1..k {
            coefficients.push(ctx.random_power()?.0);
        }

        Ok(Polynomial { k, n, x_i, ctx, coefficients })
    }

    pub fn get_pubkey_share(&self) -> CurveElem {
        self.ctx.g_to(&self.x_i)
    }

    pub fn get_public_params(&self) -> Vec<CurveElem> {
        self.coefficients.iter()
            .map(|coeff| self.ctx.g_to(&Scalar(coeff.clone())))
            .collect()
    }

    pub fn evaluate(&self, i: u32) -> Scalar {
        Scalar((0..self.k).map(|l| {
            self.coefficients[l] * DalekScalar::from(i.pow(l as u32))
        }).sum())
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
            assert_eq!(s, curve::to_scalar(curve::to_biguint(s)));
        }
    }
}