use serde::{Deserialize, Serialize};
use std::fmt::{Formatter, Display};
use rust_elgamal::{RistrettoPoint, EncryptionKey};

mod init;
mod sharing;
mod complete;
mod verifying;

pub use init::InitGuardian;
pub use sharing::SharingGuardian;
pub use verifying::VerifyingGuardian;
pub use complete::Guardian;

pub mod zkp {
    pub use super::init::GuardianCommitProof;
    pub use super::complete::PartialDecryptionProof;
}

#[derive(Debug, Copy, Clone)]
pub enum GuardianError {
    InvalidIndex,
    InvalidProof,
    InvalidProofLength,
}

impl Display for GuardianError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Hash)]
pub struct GuardianParams {
    pub threshold_count: usize,
    pub total_count: usize,
    pub base_hash: Vec<u8>,
}

impl GuardianParams {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = self.base_hash.clone();
        bytes.extend_from_slice(&self.threshold_count.to_le_bytes());
        bytes.extend_from_slice(&self.total_count.to_le_bytes());
        bytes
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GuardianCommit {
    commitments: Vec<RistrettoPoint>,
    enc_key: EncryptionKey,
}
