use crate::curve::CurveElem;
use crate::{base64_serde, AsBase64, CryptoError};
use curve25519_dalek::scalar::Scalar as InternalDalekScalar;
use num_bigint::BigUint;
use std::convert::{TryFrom, TryInto};
use std::iter::{Product, Sum};
use std::ops::{Add, Mul, Neg};

pub(crate) type DalekScalar = InternalDalekScalar;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Scalar(pub(crate) DalekScalar);

impl Scalar {
    pub fn zero() -> Self {
        Self::from(0u8)
    }

    pub fn one() -> Self {
        Self::from(1u8)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl AsBase64 for Scalar {
    type Error = CryptoError;

    fn as_base64(&self) -> String {
        base64::encode(self.as_bytes())
    }

    fn try_from_base64(encoded: &str) -> Result<Self, Self::Error> {
        let bytes = base64::decode(encoded).map_err(|_| CryptoError::Decoding)?;
        if bytes.len() != 32 {
            Err(CryptoError::Decoding)
        } else {
            let mut buf = [0; 32];
            buf.copy_from_slice(&bytes);
            Ok(Scalar::from(buf))
        }
    }
}

base64_serde!(crate::Scalar);

impl Add<Scalar> for Scalar {
    type Output = Self;

    fn add(self, rhs: Scalar) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Self::Output {
        Scalar(-self.0)
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Self::Output {
        Scalar(-self.0)
    }
}

impl Sum<Scalar> for Scalar {
    fn sum<I: Iterator<Item = Scalar>>(iter: I) -> Self {
        iter.fold(Scalar(DalekScalar::zero()), |a, b| a + b)
    }
}

impl Product<Scalar> for Scalar {
    fn product<I: Iterator<Item = Scalar>>(iter: I) -> Self {
        iter.fold(Scalar(DalekScalar::one()), |a, b| a * b)
    }
}

impl From<u8> for Scalar {
    fn from(n: u8) -> Self {
        Self(n.into())
    }
}

impl From<u16> for Scalar {
    fn from(n: u16) -> Self {
        Self(n.into())
    }
}

impl From<u32> for Scalar {
    fn from(n: u32) -> Self {
        Self(n.into())
    }
}

impl From<u64> for Scalar {
    fn from(n: u64) -> Self {
        Self(n.into())
    }
}

impl From<u128> for Scalar {
    fn from(n: u128) -> Self {
        Self(n.into())
    }
}

impl From<[u8; 32]> for Scalar {
    fn from(bytes: [u8; 32]) -> Self {
        Self(DalekScalar::from_bytes_mod_order(bytes).reduce())
    }
}

impl From<[u8; 64]> for Scalar {
    fn from(bytes: [u8; 64]) -> Self {
        Self(DalekScalar::from_bytes_mod_order_wide(&bytes).reduce())
    }
}

impl TryFrom<Vec<u8>> for Scalar {
    type Error = CryptoError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() > 64 {
            Err(CryptoError::Decoding)
        } else {
            let max = bytes.len().min(64);
            let mut buf = [0; 64];
            for i in 0..max {
                buf[i] = bytes[i];
            }

            Ok(buf.into())
        }
    }
}

impl From<CurveElem> for Scalar {
    fn from(value: CurveElem) -> Self {
        Self::from(value.as_bytes())
    }
}

impl From<&CurveElem> for Scalar {
    fn from(value: &CurveElem) -> Self {
        Self::from(value.as_bytes())
    }
}

impl From<BigUint> for Scalar {
    fn from(s: BigUint) -> Self {
        let mut s = s.to_bytes_le();
        s.resize(32, 0);
        // Below should never fail
        s.try_into().unwrap()
    }
}

impl Into<BigUint> for Scalar {
    fn into(self) -> BigUint {
        BigUint::from_bytes_le(self.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use crate::elgamal::CryptoContext;
    use num_bigint::BigUint;

    #[test]
    fn test_biguint_scalar() {
        let ctx = CryptoContext::new().unwrap();
        for _ in 0..10 {
            let s = ctx.random_scalar();
            let x: BigUint = s.clone().into();
            assert_eq!(s, x.into());
        }
    }

    #[test]
    fn test_scalar_serde() {
        let ctx = CryptoContext::new().unwrap();
        let s = ctx.random_scalar();

        let encoded = serde_json::to_string(&s).unwrap();
        let decoded = serde_json::from_str(&encoded).unwrap();
        assert_eq!(s, decoded);
    }
}
