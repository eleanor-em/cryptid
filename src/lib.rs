use std::fmt::{Display, Formatter};
use std::error::Error;

use ring::digest;
use num_bigint::BigUint;
use curve25519_dalek::scalar::Scalar as InternalDalekScalar;
use serde::{Serialize, Deserialize};
use std::convert::TryFrom;
use std::ops::{Mul, Add, AddAssign, Sub};
use std::iter::Sum;
use curve25519_dalek::ristretto::RistrettoPoint;

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

    fn zero() -> Self {
        Self(DalekScalar::zero())
    }

    fn one() -> Self {
        Self(DalekScalar::one())
    }
}

impl From<u32> for Scalar {
    fn from(n: u32) -> Self {
        Self(n.into())
    }
}

impl From<[u8; 32]> for Scalar {
    fn from(bytes: [u8; 32]) -> Self {
        Self(DalekScalar::from_bytes_mod_order(bytes).reduce())
    }
}

pub struct Hasher(digest::Context);

impl Hasher {
    pub fn new() -> Self {
        Self(digest::Context::new(&digest::SHA512))
    }

    pub fn update(mut self, data: &[u8]) -> Self {
        self.0.update(&data);
        self
    }

    pub fn finish(self) -> Digest {
        self.0.finish()
    }

    pub fn finish_scalar(self) -> Result<Scalar, CryptoError> {
        curve::to_scalar(BigUint::from_bytes_be(self.finish().as_ref()))
            .map_err(|_| CryptoError::Misc)
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
