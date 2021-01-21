#![allow(non_snake_case)]

use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::scalar::Scalar as NgScalar;
use curve25519_dalek::ristretto::CompressedRistretto as NgCompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint as NgRistrettoPoint;
use rand_core::{RngCore, CryptoRng};
use rust_elgamal::{DecryptionKey, Scalar};
use rust_elgamal::util::random_scalar;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zkp::Transcript;

define_proof! {
    coeff_knowledge,
    "Proof of Knowledge of Coefficients",
    (a),            // coefficient
    (K, Q),         // commitment and base hash respectively
    (G) :           // group generator
    K = (a * G)
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

pub struct Guardian {
    params: GuardianParams,
    key: DecryptionKey,
    coefficients: Vec<Scalar>,
}

impl Guardian {
    pub fn new<R: RngCore + CryptoRng>(params: GuardianParams, mut rng: R) -> Self {
        if params.threshold_count > params.total_count {
            panic!("Threshold count must be less than or equal to the total number of guardians.")
        }

        // Private share
        let key = DecryptionKey::new(&mut rng);

        // Polynomial coefficients
        let mut coefficients = Vec::with_capacity(params.total_count);
        coefficients.push(key.as_ref().clone());
        for _ in 1..params.total_count {
            coefficients.push(random_scalar(&mut rng));
        }

        // Key for communication
        let key = DecryptionKey::new(&mut rng);
        Guardian { params, key,  coefficients }
    }

    /// Generate commitments to the scalar polynomial coefficients, and prove knowledge of them.
    pub fn gen_commitments(&self) -> GuardianCommit {
        let base_hash = NgRistrettoPoint::hash_from_bytes::<Sha512>(&self.params.to_vec());

        let mut proofs = Vec::with_capacity(self.coefficients.len());
        let mut commitments = Vec::with_capacity(self.coefficients.len());

        for coeff in self.coefficients.iter() {
            // what's going on with ng???
            let coeff = NgScalar::from_bits(coeff.to_bytes());
            let commit = &coeff * &dalek_constants::RISTRETTO_BASEPOINT_TABLE;

            let mut transcript = Transcript::new(b"KEYGEN_COMMIT");
            let (proof, points) = coeff_knowledge::prove_batchable(
                &mut transcript,
                coeff_knowledge::ProveAssignments{
                    a: &coeff,
                    K: &commit,
                    Q: &base_hash,
                    G: &dalek_constants::RISTRETTO_BASEPOINT_POINT,
                },
            );
            proofs.push(proof);
            commitments.push(points.K);
        }


        GuardianCommit { params: self.params.clone(), proofs, commitments }
    }
}

#[derive(Serialize, Deserialize)]
pub struct GuardianCommit {
    params: GuardianParams,
    commitments: Vec<NgCompressedRistretto>,
    proofs: Vec<coeff_knowledge::BatchableProof>,
}

impl GuardianCommit {
    pub fn len(&self) -> usize {
        self.params.total_count
    }

    pub fn params(&self) -> GuardianParams {
        self.params.clone()
    }

    pub fn verify(self) -> bool {
        if self.params.total_count != self.commitments.len()
        || self.params.total_count != self.proofs.len() {
            return false;
        }

        // Fold threshold parameters into hash
        let base_hash = NgRistrettoPoint::hash_from_bytes::<Sha512>(&self.params.to_vec())
            .compress();
        let base_hashes = vec![base_hash; self.len()];

        let tx = Transcript::new(b"KEYGEN_COMMIT");
        let mut transcripts = vec![tx; self.len()];

        coeff_knowledge::batch_verify(
            &self.proofs,
            transcripts.iter_mut().collect(),
            coeff_knowledge::BatchVerifyAssignments {
                K: self.commitments,
                Q: base_hashes,
                G: dalek_constants::RISTRETTO_BASEPOINT_COMPRESSED,
            }
        ).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use crate::threshold::{Guardian, GuardianParams};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn create_and_verify() {
        let mut rng = StdRng::from_entropy();
        let params = GuardianParams {
            threshold_count: 10,
            total_count: 20,
            base_hash: b"hello world".to_vec(),
        };
        let guardian = Guardian::new(params, &mut rng);
        let commit = guardian.gen_commitments();
        assert!(commit.verify());
    }
}
