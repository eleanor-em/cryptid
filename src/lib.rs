mod util;

use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::ops::{Add, Mul};

use curve25519_dalek::scalar::Scalar as InternalDalekScalar;
use num_bigint::BigUint;
use ring::digest;

use crate::curve::CurveElem;
pub use crate::util::AsBase64;
use crate::util::SCALAR_MAX_BYTES;

type DalekScalar = InternalDalekScalar;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Scalar(DalekScalar);

impl Scalar {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn truncated(&self) -> Self {
        let mut vec = self.0.as_bytes().to_vec();
        vec.truncate(SCALAR_MAX_BYTES);
        BigUint::from_bytes_le(&vec).into()
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

#[derive(Clone)]
pub struct Hasher(digest::Context);

impl Hasher {
    pub fn sha_256() -> Self {
        Self(digest::Context::new(&digest::SHA256))
    }

    pub fn sha_512() -> Self {
        Self(digest::Context::new(&digest::SHA512))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(&data);
    }

    pub fn and_update(mut self, data: &[u8]) -> Self {
        self.update(&data);
        self
    }

    pub fn finish(self) -> Digest {
        self.0.finish()
    }

    // NOTE: this will truncate the bytes of the hash. Use with care.
    pub fn finish_scalar(self) -> Scalar {
        let mut bytes = self.finish_vec();
        bytes.truncate(SCALAR_MAX_BYTES);
        bytes.try_into().unwrap()
    }

    pub fn finish_vec(self) -> Vec<u8> {
        self.finish().as_ref().to_vec()
    }
}

pub type Digest = digest::Digest;

#[derive(Clone, Copy, Debug)]
pub enum CryptoError {
    Unspecified(ring::error::Unspecified),
    KeyRejected(ring::error::KeyRejected),
    TooLarge,
    Encoding,
    Decoding,
    Misc,
    InvalidId,
    CommitmentDuplicated,
    CommitmentMissing,
    CommitmentPartMissing,
    ShareDuplicated,
    ShareRejected,
    KeygenMissing,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for CryptoError {}

pub mod elgamal;
mod curve;
pub mod zkp;
pub mod threshold;

#[cfg(test)]
mod tests {
    use crate::{Hasher, elgamal};
    use crate::curve::CurveElem;
    use num_bigint::BigUint;

    #[test]
    fn test_hash_encoding() {
        let msg = b"hello world";
        let scalar = Hasher::sha_256().and_update(msg).finish_scalar();
        CurveElem::try_encode(scalar.truncated()).unwrap();
    }

    #[test]
    fn test_biguint_scalar() {
        let mut ctx = elgamal::CryptoContext::new();
        for _ in 0..10 {
            let s = ctx.random_power().unwrap();
            let x: BigUint = s.clone().into();
            assert_eq!(s, x.into());
        }
    }

    #[test]
    fn test_scalar_serde() {
        let mut ctx = elgamal::CryptoContext::new();
        let s = ctx.random_power().unwrap();

        let encoded = serde_json::to_string(&s).unwrap();
        let decoded = serde_json::from_str(&encoded).unwrap();
        assert_eq!(s, decoded);

    }
}