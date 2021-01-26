use crate::threshold::{GuardianParams, GuardianCommit, SharingGuardian, GuardianError, Guardian};
use rust_elgamal::{DecryptionKey, Scalar, RistrettoPoint, MultiscalarMul};
use std::collections::{HashMap, HashSet};
use crate::threshold::sharing::EncryptedShares;
use crate::common::EncryptionProof;
use sha2::{Digest, Sha512};

pub struct VerifyingGuardian {
    index: usize,
    params: GuardianParams,
    key: DecryptionKey,
    dec_share: Scalar,
    commits: HashMap<usize, GuardianCommit>,
    shares: EncryptedShares,
    share_points: HashMap<usize, RistrettoPoint>,
    share_nonces: HashMap<usize, Scalar>,
    unverified: HashSet<usize>,
}

impl VerifyingGuardian {
    pub(crate) fn new(from: SharingGuardian) -> Self {
        let mut result = Self {
            index: from.index,
            params: from.params,
            key: from.key,
            dec_share: from.dec_share,
            commits: from.commits,
            shares: from.shares,
            share_points: from.share_points,
            share_nonces: from.share_nonces,
            unverified: HashSet::new(),
        };

        // All shares MUST have been received.
        if result.shares.len() != result.params.total_count.pow(2) {
            panic!("VerifyingGuardian constructed without complete set of encrypted shares");
        }

        // Verify the shares sent to us
        for from in 1..(result.params.total_count + 1) {
            // Equation on ElectionGuard Spec v0.95, page 13
            let lhs = result.key.decrypt(result.shares.get(from, result.index).unwrap().clone());
            let rhs_powers = (0..result.params.threshold_count).map(|j| {
                Scalar::from(result.index.pow(j as u32) as u64)
            });
            let rhs = RistrettoPoint::multiscalar_mul(rhs_powers, &result.commits[&from].commitments);

            if lhs != rhs {
                result.unverified.insert(from);
            }
        }

        result
    }

    pub fn unverified(&self) -> &HashSet<usize> {
        &self.unverified
    }

    pub fn reveal_share(&mut self, to: usize) -> EncryptionProof {
        if to == 0 || to > self.params.total_count {
            panic!("Index must be between `1` and `total_count`, inclusive.")
        } else {
            let point = self.share_points[&to];
            let nonce = self.share_nonces[&to];
            // Assertion in creation guarantees this exists
            let ct = self.shares.get(self.index, to).unwrap().clone();
            EncryptionProof::new(point, nonce, ct)
        }
    }

    pub fn verify_share(&self, from: usize, to: usize, proof: EncryptionProof) -> Result<(), GuardianError> {
        if from == 0 || from > self.params.total_count
            || to == 0 || to > self.params.total_count {
            Err(GuardianError::InvalidIndex)
        } else if proof.ct() != self.shares.get(from, to).unwrap() {
            // Check the ciphertext is the same one that was published
            Err(GuardianError::InvalidProof)
        } else if !proof.verify(self.commits[&from].enc_key) {
            // Check the encryption proof
            Err(GuardianError::InvalidProof)
        } else {
            Ok(())
        }
    }

    pub fn is_complete(&self) -> bool {
        self.unverified.len() <= self.params.total_count - self.params.threshold_count
    }

    pub fn finalise(mut self) -> Option<Guardian> {
        if self.is_complete() {
            let enc_key = self.commits.iter()
                .map(|(_, commit)| commit.commitments[0])
                .sum::<RistrettoPoint>()
                .into();

            let mut hasher = sha2::Sha512::new()
                .chain(&self.params.base_hash);
            for i in 1..(self.params.total_count + 1) {
                for commit in self.commits.remove(&i).unwrap().commitments {
                    hasher.update(commit.compress().as_bytes());
                }
            }
            let base_hash = RistrettoPoint::hash_from_bytes::<Sha512>(hasher.finalize().as_slice());

            Some(Guardian {
                params: self.params,
                enc_key,
                dec_share: self.dec_share,
                base_hash,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::threshold::{GuardianParams, InitGuardian, VerifyingGuardian};
    use rand::rngs::StdRng;
    use rand_core::{SeedableRng, CryptoRng, RngCore};

    fn create_guardians<R: CryptoRng + RngCore>(params: GuardianParams, mut rng: R) -> Vec<VerifyingGuardian> {
        // Create guardians
        let mut guardians: Vec<_> = (1..(params.total_count + 1))
            .into_iter()
            .map(|i| InitGuardian::new(i, params.clone(), &mut rng))
            .collect();

        // Generate commitments
        let commits: Vec<_> = guardians.iter_mut()
            .map(InitGuardian::get_commit)
            .collect();

        for i in 1..(params.total_count + 1) {
            for j in 1..(params.total_count + 1) {
                if i != j {
                    assert!(guardians[i - 1].register_commit(j, commits[j - 1].clone()).is_ok());
                }
            }
        }

        let mut guardians: Vec<_> = guardians.into_iter()
            .map(|guardian| guardian.finalise(&mut rng).unwrap())
            .collect();

        for from in 1..(guardians.len() + 1) {
            for to in 1..(guardians.len() + 1) {
                let share = guardians[from - 1].get_share(to);
                for i in 1..(guardians.len() + 1) {
                    assert!(guardians[i - 1].register_share(from, to, share).is_ok());
                }
            }
        }

        guardians.into_iter()
            .map(|guardian| guardian.finalise().unwrap())
            .collect()
    }

    #[test]
    fn verify_well_behaved() {
        let mut rng = StdRng::from_entropy();
        let params = GuardianParams {
            threshold_count: 10,
            total_count: 20,
            base_hash: b"hello world".to_vec(),
        };

        let guardians = create_guardians(params, &mut rng);
        for guardian in guardians {
            assert_eq!(guardian.unverified().len(), 0);
        }
    }

    #[test]
    fn verify_and_convert() {
        let mut rng = StdRng::from_entropy();
        let params = GuardianParams {
            threshold_count: 10,
            total_count: 20,
            base_hash: b"hello world".to_vec(),
        };

        let guardians = create_guardians(params, &mut rng);
        for guardian in guardians {
            assert!(guardian.finalise().is_some());
        }
    }
}