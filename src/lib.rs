pub mod commit;
pub mod elgamal;
pub mod shuffle;
pub mod threshold;
pub mod zkp;
mod scalar;
mod curve;
mod util;

use std::convert::TryInto;
use std::error::Error;
use std::fmt::{Display, Formatter};

use ring::digest;

pub use crate::scalar::Scalar;
pub use crate::util::AsBase64;

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

    pub fn finish_scalar(self) -> Scalar {
        // hash cannot be bigger than 64 bytes
        self.finish_vec().try_into().unwrap()
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
    InvalidGenCount,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for CryptoError {}
