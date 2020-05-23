use std::fmt::{Display, Formatter};
use std::error::Error;

use ring::digest;
use num_bigint::BigUint;
use curve25519_dalek::scalar::Scalar as DalekScalar;

pub type Scalar = DalekScalar;

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

    pub fn finish_biguint(self) -> BigUint {
        let bytes = self.finish();
        BigUint::from_bytes_be(bytes.as_ref())
    }

    pub fn finish_scalar(self) -> Result<Scalar, CryptoError> {
        curve::to_scalar(self.finish_biguint())
            .map_err(|_| CryptoError::Misc)
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
