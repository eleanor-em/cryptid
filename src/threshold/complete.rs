use rust_elgamal::{EncryptionKey, Scalar, RistrettoPoint, Ciphertext, CompressedRistretto, GENERATOR_POINT};
use rand_core::{CryptoRng, RngCore};
use crate::threshold::GuardianParams;
use std::collections::HashMap;
use crate::threshold::complete::partial_decrypt::Transcript;

pub struct Guardian {
    pub(crate) index: usize,
    pub(crate) params: GuardianParams,
    pub(crate) enc_key: EncryptionKey,
    pub(crate) enc_key_shares: HashMap<usize, RistrettoPoint>,
    pub(crate) dec_key_share: Scalar,
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
        let share = self.dec_key_share * ct.inner().0;
        let mut transcript = Transcript::new(PARTIAL_DECRYPT_TAG);
        let (proof, points) = partial_decrypt::prove_compact(
            &mut transcript,
            partial_decrypt::ProveAssignments {
                s: &self.dec_key_share,
                A: &ct.inner().0,
                B: &ct.inner().1,
                M: &share,
                K: &self.enc_key_shares[&self.index],
                G: &GENERATOR_POINT
            }
        );

        PartialDecryptionProof {
            share: points.M,
            proof,
        }
    }

    pub fn params(&self) -> &GuardianParams {
        &self.params
    }

    pub fn base_hash(&self) -> &RistrettoPoint {
        &self.base_hash
    }
}

const PARTIAL_DECRYPT_TAG: &'static [u8] = b"CRYPTID_PARTIAL_DECRYPT";

define_proof! {
    partial_decrypt,
    "Proof of Discrete Logarithm Equality for Partial Decryption",
    (s),        // dec key share
    (A, B, M, K),  // ciphertext parts, partial decryption, public key share
    (G) :       // group generator
    M = (s * A),
    K = (s * G)
}

pub struct PartialDecryptionProof {
    share: CompressedRistretto,
    proof: partial_decrypt::CompactProof,
}

impl PartialDecryptionProof {

}
