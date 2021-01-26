use crate::threshold::{GuardianParams, GuardianCommit, GuardianError, InitGuardian};
use rust_elgamal::{DecryptionKey, Scalar, RistrettoPoint, Ciphertext, GENERATOR_TABLE};
use std::collections::HashMap;
use rand_core::{CryptoRng, RngCore};
use rust_elgamal::util::random_scalar;
use crate::threshold::verifying::VerifyingGuardian;

pub(crate) struct EncryptedShares(HashMap<(usize, usize), Ciphertext>);

impl EncryptedShares {
    pub fn new() -> Self {
        EncryptedShares(HashMap::new())
    }

    pub fn insert(&mut self, from: usize, to: usize, share: Ciphertext) {
        self.0.insert((from, to), share);
    }

    pub fn get(&self, from: usize, to: usize) -> Option<&Ciphertext> {
        self.0.get(&(from, to))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct SharingGuardian {
    pub(crate) index: usize,
    pub(crate) params: GuardianParams,
    pub(crate) key: DecryptionKey,
    pub(crate) dec_share: Scalar,
    pub(crate) commits: HashMap<usize, GuardianCommit>,
    pub(crate) shares: EncryptedShares,
    pub(crate) share_points: HashMap<usize, RistrettoPoint>,
    pub(crate) share_nonces: HashMap<usize, Scalar>,
}

impl SharingGuardian {
    pub(crate) fn new<R: CryptoRng + RngCore>(
        from: InitGuardian,
        mut rng: R
    ) -> Self {
        let mut result = SharingGuardian {
            index: from.index,
            params: from.params,
            key: from.key,
            dec_share: from.coefficients[0],
            commits: from.commits,
            shares: EncryptedShares::new(),
            share_points: HashMap::new(),
            share_nonces: HashMap::new(),
        };

        // All commits MUST have been received
        if result.commits.len() != result.params.total_count {
            panic!("SharingGuardian constructed without complete set of commits");
        }

        // Generate this guardian's shares
        for index in 1..(result.params.total_count + 1) {
            let x = index as u64;
            // Equation on ElectionGuard Spec v0.95, page 12
            let scalar = from.coefficients.iter()
                .enumerate()
                .map(|(j, coeff)| coeff * Scalar::from(x.pow(j as u32)))
                .sum();
            let point = &scalar * &GENERATOR_TABLE;
            let nonce = random_scalar(&mut rng);
            result.shares.insert(result.index, index, result.commits[&index].enc_key.encrypt_with(point, nonce));
            result.share_points.insert(index, point);
            result.share_nonces.insert(index, nonce);
        }

        result
    }

    pub fn get_share(&self, to: usize) -> Ciphertext {
        if to == 0 || to > self.params.total_count {
            panic!("Index must be between `1` and `total_count`, inclusive.")
        } else {
            self.shares.get(self.index, to).unwrap().clone()
        }
    }

    pub fn register_share(&mut self, from: usize, to: usize, share: Ciphertext) -> Result<(), GuardianError> {
        if from == 0 || from > self.params.total_count
            || to == 0 || to > self.params.total_count {
            Err(GuardianError::InvalidIndex)
        } else {
            self.shares.insert(from, to, share);
            Ok(())
        }
    }

    pub fn is_complete(&self) -> bool {
        self.shares.len() == self.params.total_count.pow(2)
    }

    pub fn finalise(self) -> Option<VerifyingGuardian> {
        if self.is_complete() {
            Some(VerifyingGuardian::new(self))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::threshold::{SharingGuardian, GuardianParams, InitGuardian};
    use rand::rngs::StdRng;
    use rand_core::{SeedableRng, CryptoRng, RngCore};

    fn create_guardians<R: CryptoRng + RngCore>(params: GuardianParams, mut rng: R) -> Vec<SharingGuardian> {
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

        guardians.into_iter()
            .map(|guardian| guardian.finalise(&mut rng).unwrap())
            .collect()
    }

    #[test]
    fn share_and_convert() {
        let mut rng = StdRng::from_entropy();
        let params = GuardianParams {
            threshold_count: 2,
            total_count: 3,
            base_hash: b"hello world".to_vec(),
        };
        let mut guardians = create_guardians(params, &mut rng);

        for from in 1..(guardians.len() + 1) {
            for to in 1..(guardians.len() + 1) {
                let share = guardians[from - 1].get_share(to);
                for i in 1..(guardians.len() + 1) {
                    assert!(guardians[i - 1].register_share(from, to, share).is_ok());
                }
            }
        }

        for guardian in guardians {
            assert!(guardian.finalise().is_some())
        }
    }
}
