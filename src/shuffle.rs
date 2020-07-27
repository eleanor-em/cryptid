use std::collections::HashMap;
use crate::elgamal::{CryptoContext, Ciphertext, PublicKey};
use ring::rand::SecureRandom;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use crate::{CryptoError, Scalar};

// See https://fc17.ifca.ai/voting/papers/voting17_HLKD17.pdf

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permutation {
    map: HashMap<usize, usize>,
}

impl Permutation {
    pub fn new(rng: &mut ChaCha20Rng, n: usize) -> Result<Self, CryptoError> {
        let mut map = HashMap::new();

        let mut nums: Vec<_> = (0..n).collect();

        for i in 0..n {
            let k = rng.gen_range(i, n);
            map.insert(i, nums[k]);
            nums[k] = nums[i];
        }

        Ok(Self { map })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shuffle {
    input: Vec<Ciphertext>,
    output: Vec<Ciphertext>,
    factors: Vec<Scalar>,
    perm: Permutation,
}

impl Shuffle {
    pub fn new(mut ctx: CryptoContext, input: Vec<Ciphertext>, pubkey: PublicKey) -> Result<Self, CryptoError> {
        // The ring RNG doesn't let us generate in a range, so create a chacha20 generator
        let mut rng = {
            let rng = ctx.rng();
            let rng = rng.lock().unwrap();
            let mut buf = [0; 32];
            rng.fill(&mut buf).map_err(|e|  CryptoError::Unspecified(e))?;
            ChaCha20Rng::from_seed(buf)
        };

        let perm = Permutation::new(&mut rng, input.len())?;
        let mut new_cts = Vec::new();
        let mut factors = Vec::new();
        for ct in input.iter() {
            let r = ctx.random_power()?;
            new_cts.push(pubkey.rerand(&ctx, &ct, &r));
            factors.push(r);
        }
        let output = (0..input.len()).map(|i| new_cts[perm.map[&i]].clone()).collect();

        Ok(Self { input, output, factors, perm })
    }
}

#[cfg(test)]
mod tests {
    use crate::elgamal::{CryptoContext, PublicKey};
    use crate::shuffle::Shuffle;

    #[test]
    fn test_shuffle() {
        let mut ctx = CryptoContext::new();
        let pubkey = PublicKey::new(ctx.random_elem().unwrap());
        let n = 10;

        let factors: Vec<_> = (0..n).map(|_| ctx.random_power().unwrap()).collect();
        let messages: Vec<_> = (0..n).map(|_| ctx.random_elem().unwrap()).collect();
        let cts: Vec<_> = messages.iter().zip(factors).map(|(m, r)| pubkey.encrypt(&ctx, &m, &r)).collect();

        let shuffle1 = Shuffle::new(ctx.clone(), cts.clone(), pubkey.clone()).unwrap();
        let shuffle2 = Shuffle::new(ctx.clone(), cts.clone(), pubkey.clone()).unwrap();

        assert_ne!(shuffle1, shuffle2);
    }
}