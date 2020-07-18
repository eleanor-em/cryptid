use std::fmt::{Display, Formatter};
use std::error::Error;

use ring::digest;
use curve25519_dalek::scalar::Scalar as InternalDalekScalar;
use serde::{Serialize, Deserialize};
use num_bigint::BigUint;
use crate::curve::to_scalar;
use std::ops::{Add, Mul};

type DalekScalar = InternalDalekScalar;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scalar(DalekScalar);

impl Scalar {
    pub fn as_base64(&self) -> String {
        base64::encode(self.as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn max_size_bytes() -> usize {
        curve::scalar_max_size_bytes()
    }

    pub fn truncated(&self) -> Self {
        let mut vec = self.0.as_bytes().to_vec();
        vec.truncate(Scalar::max_size_bytes());
        to_scalar(BigUint::from_bytes_le(&vec))
    }
}

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
        bytes.truncate(Scalar::max_size_bytes());
        curve::try_to_scalar(&bytes).unwrap()
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
    AuthTagRejected,
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
    use crate::Hasher;
    use crate::curve::CurveElem;
    use std::convert::TryFrom;

    #[test]
    fn test_hash_encoding() {
        let msg = b"hello world";
        let scalar = Hasher::sha_256().and_update(msg).finish_scalar();
        CurveElem::try_from(scalar.truncated()).unwrap();
    }
}