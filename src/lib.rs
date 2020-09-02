pub mod commit;
pub mod elgamal;
pub mod shuffle;
pub mod threshold;
pub mod util;
pub mod zkp;
mod scalar;
mod curve;

use std::convert::TryInto;
use std::error::Error;
use std::fmt::{Display, Formatter};

use ring::digest;

pub use crate::scalar::Scalar;
pub use crate::util::AsBase64;

#[derive(Clone)]
pub struct Hasher {
    ctx: digest::Context,
    is_512: bool,
}

impl Hasher {
    pub fn sha_256() -> Self {
        Self {
            ctx: digest::Context::new(&digest::SHA256),
            is_512: false,
        }
    }

    pub fn sha_512() -> Self {
        Self {
            ctx: digest::Context::new(&digest::SHA512),
            is_512: true,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(&data);
    }

    pub fn and_update(mut self, data: &[u8]) -> Self {
        self.update(&data);
        self
    }

    pub fn finish(self) -> Digest {
        self.ctx.finish()
    }

    pub fn finish_64_bytes(self) -> Option<[u8; 64]> {
        if self.is_512 {
            let mut bytes = [0; 64];
            bytes.copy_from_slice(&self.finish_vec());
            Some(bytes)
        } else {
            None
        }
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
    EmptyShuffle,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for CryptoError {}
