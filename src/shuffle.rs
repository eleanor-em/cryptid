use std::collections::HashMap;
use crate::elgamal::{CryptoContext, Ciphertext, PublicKey};
use ring::rand::SecureRandom;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use crate::{CryptoError, Scalar, Hasher};
use crate::commit::PedersenCtx;
use serde::{Serialize, Deserialize};
use crate::curve::CurveElem;

// See https://fc17.ifca.ai/voting/papers/voting17_HLKD17.pdf

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    fn commit(&self,
                  ctx: &mut CryptoContext,
                  commit_ctx: &PedersenCtx
    ) -> Result<(Vec<CurveElem>, Vec<Scalar>), CryptoError> {
        let n = self.map.len();
        if commit_ctx.len() < n {
            return Err(CryptoError::InvalidGenCount);
        }

        let mut cs = HashMap::new();
        let mut rs = HashMap::new();
        for i in 0..n {
            let r_i = ctx.random_power()?;
            cs.insert(self.map[&i], ctx.g_to(&r_i) + commit_ctx.generators[i]);
            rs.insert(self.map[&i], r_i);
        }

        Ok(((0..n).map(|i| cs[&i]).collect(),
            (0..n).map(|i| rs[&i]).collect()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shuffle {
    inputs: Vec<Ciphertext>,
    outputs: Vec<Ciphertext>,
    factors: Vec<Scalar>,
    perm: Permutation,
}

impl Shuffle {
    pub fn new(
        mut ctx: CryptoContext,
        input: Vec<Ciphertext>,
        pubkey: &PublicKey
    ) -> Result<Self, CryptoError> {
        // The ring RNG doesn't let us generate within a range, so create a chacha20 generator
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

        Ok(Self { inputs: input, outputs: output, factors, perm })
    }

    pub fn gen_proof(&self,
                     ctx: &mut CryptoContext,
                     commit_ctx: &PedersenCtx,      // secondary auxiliary generators
                     pubkey: &PublicKey
    ) -> Result<ShuffleProof, CryptoError> {
        let n = self.perm.map.len();
        let h = &commit_ctx.generators[n];
        if commit_ctx.len() < n + 1 {
            return Err(CryptoError::InvalidGenCount);
        }
        let (commitments, rs) = self.perm.commit(ctx, commit_ctx)?;

        // Generate challenges
        let challenges: Vec<_> = (0..n).map(|i| {
            let mut hash = Hasher::sha_256();
            for ct in self.inputs.iter() {
                hash.update(&ct.c1.as_bytes());
                hash.update(&ct.c2.as_bytes());
            }
            for ct in self.outputs.iter() {
                hash.update(&ct.c1.as_bytes());
                hash.update(&ct.c2.as_bytes());
            }
            for commit in commitments.iter() {
                hash.update(&commit.as_bytes());
            }
            hash.update(&i.to_be_bytes());
            hash.finish_scalar()
        }).collect();

        let perm_challenges: Vec<_> = (0..n).map(|i| {
            challenges[self.perm.map[&i]].clone()
        }).collect();

        let chain = CommitChain::new(ctx, &h, &perm_challenges)?;

        // Generate randomness
        let r_bar = rs.clone().into_iter().sum();
        let mut vs: Vec<Scalar> = (0..n).map(|_| Scalar::one()).collect();
        for i in (0..(n - 1)).rev() {
            vs[i] = perm_challenges[i + 1] * vs[i + 1];
        }

        let r_hat = (0..n).map(|i| chain.rs[i] * vs[i]).sum();
        let r_tilde = (0..n).map(|i| rs[i] * challenges[i]).sum();
        let r_prime = (0..n).map(|i| self.factors[i] * challenges[i]).sum();

        let mut omegas = Vec::new();
        omegas.push(ctx.random_power()?);
        omegas.push(ctx.random_power()?);
        omegas.push(ctx.random_power()?);
        omegas.push(ctx.random_power()?);

        let mut omega_hats = Vec::new();
        let mut omega_primes = Vec::new();
        for _ in 0..n {
            omega_hats.push(ctx.random_power()?);
            omega_primes.push(ctx.random_power()?);
        }

        // Generate commitments
        let t_1 = ctx.g_to(&omegas[0]);
        let t_2 = ctx.g_to(&omegas[1]);
        let t_3 = ctx.g_to(&omegas[2])
            + (0..n).map(|i| commit_ctx.generators[i].scaled(&omega_primes[i])).sum();
        // The paper has a mistake
        let t_4_1 = ctx.g_to(&-omegas[3])
            + (0..n).map(|i| self.outputs[i].c1.scaled(&omega_primes[i])).sum();
        let t_4_2 = pubkey.y.scaled(&-omegas[3])
            + (0..n).map(|i| self.outputs[i].c2.scaled(&omega_primes[i])).sum();

        let mut t_hats = Vec::new();
        let mut last_commit = h;
        for i in 0..n {
            t_hats.push(ctx.g_to(&omega_hats[i]) + last_commit.scaled(&omega_primes[i]));
            last_commit = &chain.commits[i];
        }

        // Generate challenge
        let mut hash = Hasher::sha_256();
        for ct in self.inputs.iter() {
            hash.update(&ct.c1.as_bytes());
            hash.update(&ct.c2.as_bytes());
        }
        for ct in self.outputs.iter() {
            hash.update(&ct.c1.as_bytes());
            hash.update(&ct.c2.as_bytes());
        }
        for commit in commitments.iter() {
            hash.update(&commit.as_bytes());
        }
        for commit in chain.commits.iter() {
            hash.update(&commit.as_bytes());
        }
        hash = hash.and_update(&pubkey.y.as_bytes())
            .and_update(&t_1.as_bytes())
            .and_update(&t_2.as_bytes())
            .and_update(&t_3.as_bytes())
            .and_update(&t_4_1.as_bytes())
            .and_update(&t_4_2.as_bytes());
        for t_hat in t_hats.iter() {
            hash.update(&t_hat.as_bytes());
        }
        let c = hash.finish_scalar();

        // Complete commitments
        let s_1 = omegas[0] + c * r_bar;
        let s_2 = omegas[1] + c * r_hat;
        let s_3 = omegas[2] + c * r_tilde;
        let s_4 = omegas[3] + c * r_prime;

        let mut s_hats = Vec::new();
        let mut s_primes = Vec::new();
        for i in 0..n {
            s_hats.push(omega_hats[i] + c * chain.rs[i]);
            s_primes.push(omega_primes[i] + c * perm_challenges[i]);
        }

        Ok(ShuffleProof {
            t_1,
            t_2,
            t_3,
            t_4_1,
            t_4_2,
            t_hats,
            s_1,
            s_2,
            s_3,
            s_4,
            s_hats,
            s_primes,
            commitments,
            chain
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShuffleProof {
    t_1: CurveElem,
    t_2: CurveElem,
    t_3: CurveElem,
    t_4_1: CurveElem,
    t_4_2: CurveElem,
    t_hats: Vec<CurveElem>,
    s_1: Scalar,
    s_2: Scalar,
    s_3: Scalar,
    s_4: Scalar,
    s_hats: Vec<Scalar>,
    s_primes: Vec<Scalar>,
    commitments: Vec<CurveElem>,
    chain: CommitChain,
}

impl ShuffleProof {
    pub fn verify(&self,
                  ctx: &CryptoContext,
                  commit_ctx: &PedersenCtx,      // secondary auxiliary generators
                  inputs: &[Ciphertext],
                  outputs: &[Ciphertext],
                  pubkey: &PublicKey
    ) -> bool {
        if inputs.len() != outputs.len() {
            panic!("Shuffle input and output lengths do not match");
        }
        let n = inputs.len();
        let h = &commit_ctx.generators[n];

        let challenges: Vec<_> = (0..n).map(|i| {
            let mut hash = Hasher::sha_256();
            for ct in inputs.iter() {
                hash.update(&ct.c1.as_bytes());
                hash.update(&ct.c2.as_bytes());
            }
            for ct in outputs.iter() {
                hash.update(&ct.c1.as_bytes());
                hash.update(&ct.c2.as_bytes());
            }
            for commit in self.commitments.iter() {
                hash.update(&commit.as_bytes());
            }
            hash.update(&i.to_be_bytes());
            hash.finish_scalar()
        }).collect();

        let c_bar = self.commitments.clone().into_iter().sum::<CurveElem>()
            - (0..n).map(|i| commit_ctx.generators[i]).sum::<CurveElem>();
        let u = challenges.clone().into_iter().product();
        let c_hat = self.chain.commits.last().unwrap() - &h.scaled(&u);
        let c_tilde: CurveElem = (0..n).map(|i| self.commitments[i].scaled(&challenges[i])).sum();
        let a_prime: CurveElem = (0..n).map(|i| inputs[i].c1.scaled(&challenges[i])).sum();
        let b_prime: CurveElem = (0..n).map(|i| inputs[i].c2.scaled(&challenges[i])).sum();

        let mut hash = Hasher::sha_256();
        for ct in inputs.iter() {
            hash.update(&ct.c1.as_bytes());
            hash.update(&ct.c2.as_bytes());
        }
        for ct in outputs.iter() {
            hash.update(&ct.c1.as_bytes());
            hash.update(&ct.c2.as_bytes());
        }
        for commit in self.commitments.iter() {
            hash.update(&commit.as_bytes());
        }
        for commit in self.chain.commits.iter() {
            hash.update(&commit.as_bytes());
        }
        hash = hash.and_update(&pubkey.y.as_bytes())
            .and_update(&self.t_1.as_bytes())
            .and_update(&self.t_2.as_bytes())
            .and_update(&self.t_3.as_bytes())
            .and_update(&self.t_4_1.as_bytes())
            .and_update(&self.t_4_2.as_bytes());
        for t_hat in self.t_hats.iter() {
            hash.update(&t_hat.as_bytes());
        }
        let c = hash.finish_scalar();

        let t_1_prime = c_bar.scaled(&-c)
            + ctx.g_to(&self.s_1);
        let t_2_prime = c_hat.scaled(&-c)
            + ctx.g_to(&self.s_2);
        let t_3_prime = c_tilde.scaled(&-c)
            + ctx.g_to(&self.s_3)
            + (0..n).map(|i| commit_ctx.generators[i].scaled(&self.s_primes[i])).sum();
        let t_4_1_prime = a_prime.scaled(&-c)
            + ctx.g_to(&-self.s_4)
            + (0..n).map(|i| outputs[i].c1.scaled(&self.s_primes[i])).sum();
        let t_4_2_prime = b_prime.scaled(&-c)
            + pubkey.y.scaled(&-self.s_4)
            + (0..n).map(|i| outputs[i].c2.scaled(&self.s_primes[i])).sum();

        let mut t_hat_primes = Vec::new();
        let mut last_commit = h;
        for i in 0..n {
            t_hat_primes.push(self.chain.commits[i].scaled(&-c) + ctx.g_to(&self.s_hats[i]) + last_commit.scaled(&self.s_primes[i]));
            last_commit = &self.chain.commits[i];
        }

        t_1_prime == self.t_1 &&
            t_2_prime == self.t_2 &&
            t_3_prime == self.t_3 &&
            t_4_1_prime == self.t_4_1 &&
            t_4_2_prime == self.t_4_2 &&
            t_hat_primes == self.t_hats
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitChain {
    commits: Vec<CurveElem>,
    rs: Vec<Scalar>,
}

impl CommitChain {
    fn new(
        ctx: &mut CryptoContext,
        initial: &CurveElem,
        challenges: &[Scalar]
    ) -> Result<Self, CryptoError> {
        let mut commits = Vec::new();
        let mut rs = Vec::new();
        let mut last_commit = initial.clone();

        for i in 0..challenges.len() {
            let r_i = ctx.random_power()?;
            let c_i = ctx.g_to(&r_i) + last_commit.scaled(&challenges[i]);
            last_commit = c_i.clone();
            rs.push(r_i);
            commits.push(c_i);
        }

        Ok(Self {
            commits,
            rs
        })
    }
}


#[cfg(test)]
mod tests {
    use crate::elgamal::{CryptoContext, PublicKey};
    use crate::shuffle::Shuffle;
    use crate::commit::PedersenCtx;
    use ring::rand::SecureRandom;

    #[test]
    fn test_shuffle_random() {
        let mut ctx = CryptoContext::new();
        let pubkey = PublicKey::new(ctx.random_elem().unwrap());
        let n = 4;

        let factors: Vec<_> = (0..n).map(|_| ctx.random_power().unwrap()).collect();
        let messages: Vec<_> = (0..n).map(|_| ctx.random_elem().unwrap()).collect();
        let cts: Vec<_> = messages.iter().zip(factors).map(|(m, r)| pubkey.encrypt(&ctx, &m, &r)).collect();

        let shuffle1 = Shuffle::new(ctx.clone(), cts.clone(), &pubkey).unwrap();
        let shuffle2 = Shuffle::new(ctx.clone(), cts.clone(), &pubkey).unwrap();

        assert_ne!(shuffle1, shuffle2);
    }

    #[test]
    fn test_shuffle_complete() {
        let mut ctx = CryptoContext::new();
        let rng = ctx.rng();
        let mut seed = [0; 64];
        {
            let rng = rng.lock().unwrap();
            rng.fill(&mut seed).unwrap();
        }
        let pubkey = PublicKey::new(ctx.random_elem().unwrap());
        let n = 100;

        let factors: Vec<_> = (0..n).map(|_| ctx.random_power().unwrap()).collect();
        let messages: Vec<_> = (0..n).map(|_| ctx.random_elem().unwrap()).collect();
        let cts: Vec<_> = messages.iter().zip(factors).map(|(m, r)| pubkey.encrypt(&ctx, &m, &r)).collect();

        let shuffle = Shuffle::new(ctx.clone(), cts.clone(), &pubkey).unwrap();

        let commit_ctx = PedersenCtx::new(&seed, ctx.clone(), n + 1);
        let proof = shuffle.gen_proof(&mut ctx, &commit_ctx, &pubkey).unwrap();
        assert!(proof.verify(&mut ctx, &commit_ctx, &shuffle.inputs, &shuffle.outputs, &pubkey));
    }

    #[test]
    fn test_shuffle_sound() {
        let mut ctx = CryptoContext::new();
        let rng = ctx.rng();
        let mut seed = [0; 64];
        {
            let rng = rng.lock().unwrap();
            rng.fill(&mut seed).unwrap();
        }
        let pubkey = PublicKey::new(ctx.random_elem().unwrap());
        let n = 100;

        let factors: Vec<_> = (0..n).map(|_| ctx.random_power().unwrap()).collect();
        let messages: Vec<_> = (0..n).map(|_| ctx.random_elem().unwrap()).collect();
        let cts: Vec<_> = messages.iter().zip(factors).map(|(m, r)| pubkey.encrypt(&ctx, &m, &r)).collect();

        let shuffle = Shuffle::new(ctx.clone(), cts.clone(), &pubkey).unwrap();
        let shuffle2 = Shuffle::new(ctx.clone(), cts.clone(), &pubkey).unwrap();

        let commit_ctx = PedersenCtx::new(&seed, ctx.clone(), n + 1);
        let proof = shuffle2.gen_proof(&mut ctx, &commit_ctx, &pubkey).unwrap();
        assert!(!proof.verify(&mut ctx, &commit_ctx, &shuffle.inputs, &shuffle.outputs, &pubkey));
    }
}