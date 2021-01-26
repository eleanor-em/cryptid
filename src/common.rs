use rust_elgamal::{RistrettoPoint, Scalar, Ciphertext, EncryptionKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionProof {
    point: RistrettoPoint,
    nonce: Scalar,
    ct: Ciphertext,
}

impl EncryptionProof {
    pub fn new(point: RistrettoPoint, nonce: Scalar, ct: Ciphertext) -> Self {
        Self {
            point,
            nonce,
            ct,
        }
    }

    pub fn point(&self) -> &RistrettoPoint {
        &self.point
    }

    pub fn ct(&self) -> &Ciphertext {
        &self.ct
    }

    pub fn verify(&self, key: EncryptionKey) -> bool {
        key.encrypt_with(self.point, self.nonce) == self.ct
    }
}
