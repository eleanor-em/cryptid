use rust_elgamal::{EncryptionKey, Scalar, RistrettoPoint, Ciphertext};
use rand_core::{CryptoRng, RngCore};

pub struct PartialDecryptionProof {
    _ct: Ciphertext,
    _share: RistrettoPoint,
    // TODO: ZKP
}

pub struct Guardian {
    pub(crate) enc_key: EncryptionKey,
    pub(crate) dec_share: Scalar,
    pub(crate) base_hash: RistrettoPoint,
}

impl Guardian {
    pub fn encrypt<R: CryptoRng + RngCore>(&self, m: RistrettoPoint, rng: R) -> Ciphertext {
        self.enc_key.encrypt(m, rng)
    }

    pub fn encrypt_with(&self, m: RistrettoPoint, r: Scalar) -> Ciphertext {
        self.enc_key.encrypt_with(m, r)
    }

    pub fn decrypt_part(&self, ct: Ciphertext) -> PartialDecryptionProof {
        let share = self.dec_share * ct.inner().0;
        PartialDecryptionProof {
            _ct: ct,
            _share: share,
        }
    }

    pub fn base_hash(&self) -> &RistrettoPoint {
        &self.base_hash
    }
}