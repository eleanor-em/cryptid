#![allow(non_snake_case)]
use rand_core::{RngCore, CryptoRng};
use rust_elgamal::{DecryptionKey, Scalar, RistrettoPoint, CompressedRistretto, EncryptionKey, GENERATOR_POINT, GENERATOR_POINT_COMPRESSED, GENERATOR_TABLE};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zkp::Transcript;
use std::collections::HashMap;
use crate::threshold::{GuardianParams, GuardianError, GuardianCommit};
use crate::threshold::sharing::SharingGuardian;

pub struct InitGuardian {
    pub(crate) index: usize,
    pub(crate) params: GuardianParams,
    pub(crate) key: DecryptionKey,
    pub(crate) coefficients: Vec<Scalar>,
    pub(crate) commits: HashMap<usize, GuardianCommit>,
}

impl InitGuardian {
    pub fn new<R: RngCore + CryptoRng>(index: usize, params: GuardianParams, mut rng: R) -> Self {
        if params.threshold_count > params.total_count {
            panic!("Threshold count must be less than or equal to the total number of guardians.")
        }
        if index == 0 || index > params.total_count {
            panic!("Index must be between `1` and `total_count`, inclusive.")
        }

        // Private share
        let key = DecryptionKey::new(&mut rng);

        // Polynomial coefficients
        let mut coefficients = Vec::with_capacity(params.threshold_count);
        coefficients.push(key.as_ref().clone());
        for _ in 1..params.threshold_count {
            coefficients.push(Scalar::random(&mut rng));
        }

        // Key for communication
        let key = DecryptionKey::new(&mut rng);
        let commits = HashMap::new();
        InitGuardian { index, params, key, coefficients, commits }
    }

    /// Generate commitments to the scalar polynomial coefficients, and prove knowledge of them.
    pub fn get_commit(&mut self) -> GuardianCommitProof {
        let base_hash = RistrettoPoint::hash_from_bytes::<Sha512>(&self.params.to_vec());

        let mut proofs = Vec::with_capacity(self.coefficients.len());
        let mut commitments = Vec::with_capacity(self.coefficients.len());
        let mut decompressed_commits = Vec::with_capacity(self.coefficients.len());

        for coeff in self.coefficients.iter() {
            let commit = coeff * &GENERATOR_TABLE;

            let mut transcript = Transcript::new(COEFF_KNOWLEDGE_TAG);
            let (proof, points) = coeff_knowledge::prove_batchable(
                &mut transcript,
                coeff_knowledge::ProveAssignments {
                    a: &coeff,
                    K: &commit,
                    Q: &base_hash,
                    G: &GENERATOR_POINT,
                },
            );
            proofs.push(proof);
            commitments.push(points.K);
            decompressed_commits.push(commit);
        }

        self.commits.insert(self.index, GuardianCommit {
            commitments: decompressed_commits,
            enc_key: self.key.encryption_key().clone(),
        });

        GuardianCommitProof {
            params: self.params.clone(),
            proofs,
            commitments,
            enc_key: self.key.encryption_key().clone()
        }
    }

    /// Register another guardian's commitment, checking if the index is valid and if the proof is
    /// valid first.
    pub fn register_commit(&mut self, index: usize, commit: GuardianCommitProof) -> Result<(), GuardianError> {
        if index == 0 || index > self.params.total_count || index == self.index {
            Err(GuardianError::InvalidIndex)
        } else {
            self.commits.insert(index, commit.verify()?);
            Ok(())
        }
    }

    pub fn is_complete(&self) -> bool {
        self.commits.len() == self.params.total_count
    }

    pub fn finalise<R: RngCore + CryptoRng>(self, rng: R) -> Option<SharingGuardian> {
        if self.is_complete() {
            Some(SharingGuardian::new(self, rng))
        } else {
            None
        }
    }
}


define_proof! {
    coeff_knowledge,
    "Proof of Knowledge of Coefficients",
    (a),            // coefficient
    (K, Q),         // commitment and base hash respectively
    (G) :           // group generator
    K = (a * G)
}

const COEFF_KNOWLEDGE_TAG: &'static [u8] = b"CRYPTID_KEYGEN_COMMIT";

#[derive(Serialize, Deserialize, Clone)]
pub struct GuardianCommitProof {
    params: GuardianParams,
    proofs: Vec<coeff_knowledge::BatchableProof>,
    commitments: Vec<CompressedRistretto>,
    enc_key: EncryptionKey,
}

impl GuardianCommitProof {
    pub fn len(&self) -> usize {
        self.params.threshold_count
    }

    pub fn params(&self) -> GuardianParams {
        self.params.clone()
    }

    pub fn verify(self) -> Result<GuardianCommit, GuardianError> {
        if self.params.threshold_count != self.commitments.len()
            || self.params.threshold_count != self.proofs.len() {
            Err(GuardianError::InvalidProofLength)
        } else {
            // Fold init parameters into hash
            let base_hash = RistrettoPoint::hash_from_bytes::<Sha512>(&self.params.to_vec())
                .compress();
            let base_hashes = vec![base_hash; self.len()];

            let tx = Transcript::new(COEFF_KNOWLEDGE_TAG);
            let mut transcripts = vec![tx; self.len()];

            if let Ok(_) = coeff_knowledge::batch_verify(
                &self.proofs,
                transcripts.iter_mut().collect(),
                coeff_knowledge::BatchVerifyAssignments {
                    K: self.commitments.clone(),
                    Q: base_hashes,
                    G: GENERATOR_POINT_COMPRESSED,
                }
            ) {
                let commitments = self.commitments
                    .into_iter()
                    // Decompressing will always succeed if the proof passes
                    .map(|pt| pt.decompress().unwrap())
                    .collect();
                Ok(GuardianCommit { commitments, enc_key: self.enc_key })
            } else {
                Err(GuardianError::InvalidProof)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::threshold::init::InitGuardian;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use crate::threshold::GuardianParams;

    #[test]
    fn create_and_verify() {
        let mut rng = StdRng::from_entropy();
        let params = GuardianParams {
            threshold_count: 10,
            total_count: 20,
            base_hash: b"hello world".to_vec(),
        };
        let mut guardian = InitGuardian::new(1, params, &mut rng);
        let commit = guardian.get_commit();
        assert!(commit.verify().is_ok());
    }

    #[test]
    fn create_and_convert() {
        let mut rng = StdRng::from_entropy();
        let params = GuardianParams {
            threshold_count: 10,
            total_count: 20,
            base_hash: b"hello world".to_vec(),
        };

        // Create guardians
        let mut guardians: Vec<_> = (1..(params.total_count + 1))
            .into_iter()
            .map(|i| InitGuardian::new(i, params.clone(), &mut rng))
            .collect();

        // Generate commitments
        let commits: Vec<_> = guardians
            .iter_mut()
            .map(InitGuardian::get_commit)
            .collect();

        for i in 1..(params.total_count + 1) {
            for j in 1..(params.total_count + 1) {
                if i != j {
                    assert!(guardians[i - 1].register_commit(j, commits[j - 1].clone()).is_ok());
                }
            }
        }

        for guardian in guardians {
            assert!(guardian.finalise(&mut rng).is_some());
        }
    }
}
