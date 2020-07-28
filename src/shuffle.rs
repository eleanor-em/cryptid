use rayon::prelude::*;
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
    map: Vec<usize>,
}

impl Permutation {
    pub fn new(rng: &mut ChaCha20Rng, n: usize) -> Result<Self, CryptoError> {
        let mut map = Vec::with_capacity(n);
        let mut nums: Vec<_> = (0..n).collect();

        for i in 0..n {
            let k = rng.gen_range(i, n);
            map.push(nums[k]);
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
            cs.insert(self.map[i], ctx.g_to(&r_i) + commit_ctx.generators[i]);
            rs.insert(self.map[i], r_i);
        }

        Ok(((0..n).map(|i| cs[&i]).collect(),
            (0..n).map(|i| rs[&i]).collect()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shuffle {
    inputs: Vec<Vec<Ciphertext>>,
    outputs: Vec<Vec<Ciphertext>>,
    factors: Vec<Scalar>,
    perm: Permutation,
}

impl Shuffle {
    pub fn new(
        mut ctx: CryptoContext,
        inputs: Vec<Vec<Ciphertext>>,
        pubkey: &PublicKey
    ) -> Result<Self, CryptoError> {
        let n = inputs.len();
        // The ring RNG doesn't let us generate within a range, so create a chacha20 generator
        let mut rng = {
            let rng = ctx.rng();
            let rng = rng.lock().unwrap();
            let mut buf = [0; 32];
            rng.fill(&mut buf).map_err(|e|  CryptoError::Unspecified(e))?;
            ChaCha20Rng::from_seed(buf)
        };

        let perm = Permutation::new(&mut rng, n)?;
        let factors: Vec<_> = (0..n).map(|_| ctx.random_power()).collect::<Result<_, _>>()?;
        let new_cts: Vec<Vec<_>> = (&inputs, &factors).into_par_iter().map(|(cts, r)| {
            cts.iter().map(|ct| pubkey.rerand(&ctx, &ct, &r)).collect()
        }).collect();
        let outputs = (0..n).map(|i| new_cts[perm.map[i]].clone()).collect();

        Ok(Self { inputs, outputs, factors, perm })
    }

    pub fn inputs(&self) -> &[Vec<Ciphertext>] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[Vec<Ciphertext>] {
        &self.outputs
    }

    pub fn gen_proof(&self,
                     ctx: &mut CryptoContext,
                     commit_ctx: &PedersenCtx,      // secondary auxiliary generators
                     pubkey: &PublicKey
    ) -> Result<ShuffleProof, CryptoError> {
        let n = self.perm.map.len();
        let m = self.inputs[0].len();
        let h = &commit_ctx.generators[n];
        if commit_ctx.len() < n + 1 {
            return Err(CryptoError::InvalidGenCount);
        }
        let (commitments, rs) = self.perm.commit(ctx, commit_ctx)?;
        let mut ct_commit_bytes = Vec::new();
        ct_commit_bytes.par_extend(
            (&self.inputs, &self.outputs, &commitments).into_par_iter().map(|(cts1, cts2, comm)| {
                let mut bytes: Vec<u8> = Vec::with_capacity(32 * 2 * cts1.len() * 2 + 32);
                for ct in cts1 {
                    bytes.extend(&ct.c1.as_bytes());
                    bytes.extend(&ct.c2.as_bytes());
                }
                for ct in cts2 {
                    bytes.extend(&ct.c1.as_bytes());
                    bytes.extend(&ct.c2.as_bytes());
                }
                bytes.extend(&comm.as_bytes());
                bytes
            })
        );
        let ct_commit_bytes = ct_commit_bytes.concat();

        // Generate challenges
        let base_hasher = Hasher::sha_256()
            .and_update(&ct_commit_bytes);
        let challenges: Vec<_> = (0..n).into_par_iter().map(|i| {
            base_hasher.clone()
                .and_update(&i.to_be_bytes())
                .finish_scalar()
        }).collect();

        let perm_challenges: Vec<_> = (0..n).map(|i| {
            challenges[self.perm.map[i]].clone()
        }).collect();

        let chain = CommitChain::new(ctx, &h, &perm_challenges)?;

        // Generate randomness
        let r_bar = rs.clone().into_par_iter().sum();
        let mut vs: Vec<Scalar> = (0..n).map(|_| Scalar::one()).collect();
        for i in (0..(n - 1)).rev() {
            vs[i] = perm_challenges[i + 1] * vs[i + 1];
        }

        let r_hat = (0..n).into_par_iter().map(|i| chain.rs[i] * vs[i]).sum();
        let r_tilde = (0..n).into_par_iter().map(|i| rs[i] * challenges[i]).sum();
        let r_prime = (0..n).into_par_iter().map(|i| self.factors[i] * challenges[i]).sum();

        let mut omegas = Vec::new();
        omegas.push(ctx.random_power()?);
        omegas.push(ctx.random_power()?);
        omegas.push(ctx.random_power()?);
        for _ in 0..m {
            omegas.push(ctx.random_power()?);
        }

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
            + (&commit_ctx.generators, &omega_primes).into_par_iter()
            .map(|(h, w)| h.scaled(&w))
            .sum();

        let mut t_4s = Vec::new();
        for j in 0..m {
            let (sum_a, sum_b) = (&self.outputs, &omega_primes).into_par_iter()
                .map(|(cts, omega_prime)| {
                    (cts[j].c1.scaled(&omega_prime), cts[j].c2.scaled(&omega_prime))
                })
                .reduce(|| (CurveElem::identity(), CurveElem::identity()), |(a, b), (c_a, c_b)| (a + c_a, b + c_b));

            let t_4_1 = ctx.g_to(&-omegas[j + 3]) + sum_a;
            let t_4_2 = pubkey.y.scaled(&-omegas[j + 3]) + sum_b;

            t_4s.push((t_4_1, t_4_2));
        }

        let t_hats: Vec<_> = (0..n).into_par_iter().map(|i| {
            let last_commit = if i == 0 { h } else { &chain.commits[i - 1] };
            ctx.g_to(&omega_hats[i]) + last_commit.scaled(&omega_primes[i])
        }).collect();

        // Generate challenge
        let mut hash = base_hasher;
        for commit in chain.commits.iter() {
            hash.update(&commit.as_bytes());
        }
        hash = hash.and_update(&pubkey.y.as_bytes())
            .and_update(&t_1.as_bytes())
            .and_update(&t_2.as_bytes())
            .and_update(&t_3.as_bytes());
        for (t_4_1, t_4_2) in t_4s.iter() {
            hash.update(&t_4_1.as_bytes());
            hash.update(&t_4_2.as_bytes());
        }
        for t_hat in t_hats.iter() {
            hash.update(&t_hat.as_bytes());
        }
        let c = hash.finish_scalar();

        // Complete commitments
        let s_1 = omegas[0] + c * r_bar;
        let s_2 = omegas[1] + c * r_hat;
        let s_3 = omegas[2] + c * r_tilde;

        let s_4s: Vec<_> = (0..m)
            .map(|i| omegas[i + 3] + c * r_prime)
            .collect();

        let s_hats = (0..n)
            .map(|i| omega_hats[i] + c * chain.rs[i])
            .collect();

        let s_primes = (0..n)
            .map(|i| omega_primes[i] + c * perm_challenges[i])
            .collect();

        Ok(ShuffleProof {
            t_1,
            t_2,
            t_3,
            t_4s,
            t_hats,
            s_1,
            s_2,
            s_3,
            s_4s,
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
    t_4s: Vec<(CurveElem, CurveElem)>,
    t_hats: Vec<CurveElem>,
    s_1: Scalar,
    s_2: Scalar,
    s_3: Scalar,
    s_4s: Vec<Scalar>,
    s_hats: Vec<Scalar>,
    s_primes: Vec<Scalar>,
    commitments: Vec<CurveElem>,
    chain: CommitChain,
}

impl ShuffleProof {
    pub fn verify(&self,
                  ctx: &CryptoContext,
                  commit_ctx: &PedersenCtx,      // secondary auxiliary generators
                  inputs: &[Vec<Ciphertext>],
                  outputs: &[Vec<Ciphertext>],
                  pubkey: &PublicKey
    ) -> bool {
        if inputs.len() != outputs.len() {
            panic!("Shuffle input and output lengths do not match");
        }
        let n = inputs.len();
        let m = inputs[0].len();
        let h = &commit_ctx.generators[n];
        let mut ct_commit_bytes = Vec::new();
        ct_commit_bytes.par_extend(
            (inputs, outputs, &self.commitments).into_par_iter().map(|(cts1, cts2, comm)| {
                let mut bytes: Vec<u8> = Vec::with_capacity(32 * 2 * cts1.len() * 2 + 32);
                for ct in cts1 {
                    bytes.extend(&ct.c1.as_bytes());
                    bytes.extend(&ct.c2.as_bytes());
                }
                for ct in cts2 {
                    bytes.extend(&ct.c1.as_bytes());
                    bytes.extend(&ct.c2.as_bytes());
                }
                bytes.extend(&comm.as_bytes());
                bytes
            })
        );
        let ct_commit_bytes = ct_commit_bytes.concat();

        let base_hasher = Hasher::sha_256()
                .and_update(&ct_commit_bytes);
        let challenges: Vec<_> = (0..n).into_par_iter().map(|i| {
            base_hasher.clone()
                .and_update(&i.to_be_bytes())
                .finish_scalar()
        }).collect();

        let c_bar: CurveElem = (&self.commitments, &commit_ctx.generators).into_par_iter()
            .map(|(c, h)| c - h)
            .sum();

        let u = challenges.clone().into_par_iter().product();
        let c_hat = self.chain.commits.last().unwrap() - &h.scaled(&u);
        let c_tilde: CurveElem = (&self.commitments, &challenges).into_par_iter()
            .map(|(c, u)| c.scaled(&u))
            .sum();

        let scaled_cts: Vec<_> = (0..m).map(|j| {
            (&challenges, inputs).into_par_iter()
                .map(|(u, cts)| (cts[j].c1.scaled(&u), cts[j].c2.scaled(&u)))
                .reduce(|| (CurveElem::identity(), CurveElem::identity()), |(a, b), (c_a, c_b)| (a + c_a, b + c_b))
        }).collect();

        let mut hash = base_hasher;
        for commit in self.chain.commits.iter() {
            hash.update(&commit.as_bytes());
        }
        hash = hash.and_update(&pubkey.y.as_bytes())
            .and_update(&self.t_1.as_bytes())
            .and_update(&self.t_2.as_bytes())
            .and_update(&self.t_3.as_bytes());
        for (t_4_1, t_4_2) in self.t_4s.iter() {
            hash.update(&t_4_1.as_bytes());
            hash.update(&t_4_2.as_bytes());
        }
        for t_hat in self.t_hats.iter() {
            hash.update(&t_hat.as_bytes());
        }
        let c = hash.finish_scalar();

        let t_1_prime = c_bar.scaled(&-c) + ctx.g_to(&self.s_1);
        let t_2_prime = c_hat.scaled(&-c) + ctx.g_to(&self.s_2);

        let t_3_prime = c_tilde.scaled(&-c) + ctx.g_to(&self.s_3)
            + (&commit_ctx.generators, &self.s_primes).into_par_iter()
            .map(|(h, s_prime)| h.scaled(&s_prime))
            .sum();

        let mut t_4_primes = Vec::new();
        for j in 0..m {
            let (sum_a, sum_b) = (outputs, &self.s_primes).into_par_iter()
                .map(|(cts, s_prime)| {
                    (cts[j].c1.scaled(&s_prime), cts[j].c2.scaled(&s_prime))
                })
                .reduce(|| (CurveElem::identity(), CurveElem::identity()), |(a, b), (c_a, c_b)| (a + c_a, b + c_b));

            let t_4_1_prime = scaled_cts[j].0.scaled(&-c)
                + ctx.g_to(&-self.s_4s[j])
                + sum_a;

            let t_4_2_prime = scaled_cts[j].1.scaled(&-c)
                + pubkey.y.scaled(&-self.s_4s[j])
                + sum_b;

            t_4_primes.push((t_4_1_prime, t_4_2_prime));
        }

        let t_hat_primes: Vec<_> = (0..n).into_par_iter().map(|i| {
            let last_commit = if i == 0 { h } else { &self.chain.commits[i - 1] };
            self.chain.commits[i].scaled(&-c) + ctx.g_to(&self.s_hats[i]) + last_commit.scaled(&self.s_primes[i])
        }).collect();

        t_1_prime == self.t_1 &&
            t_2_prime == self.t_2 &&
            t_3_prime == self.t_3 &&
            t_4_primes == self.t_4s &&
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
    use crate::curve::CurveElem;
    use crate::Scalar;

    #[test]
    fn test_shuffle_random() {
        let mut ctx = CryptoContext::new();
        let pubkey = PublicKey::new(ctx.random_elem().unwrap());
        let n = 4;
        let m = 3;

        let factors: Vec<_> = (0..n).map(|_| ctx.random_power().unwrap()).collect();
        let cts: Vec<_> = factors.iter().map(|r| {
            let message = ctx.random_elem().unwrap();
            (0..m).map(|_| pubkey.encrypt(&ctx, &message, &r)).collect()
        }).collect();

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
        let m = 5;

        let factors: Vec<_> = (0..n).map(|_| ctx.random_power().unwrap()).collect();
        let cts: Vec<_> = factors.iter().map(|r| {
            (0..m).map(|_| pubkey.encrypt(&ctx, &CurveElem::try_encode(Scalar::from(16u32)).unwrap(), &r)).collect()
        }).collect();

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
        let m = 3;

        let factors: Vec<_> = (0..n).map(|_| ctx.random_power().unwrap()).collect();
        let cts: Vec<_> = factors.iter().map(|r| {
            (0..m).map(|_| pubkey.encrypt(&ctx, &CurveElem::try_encode(Scalar::from(16u32)).unwrap(), &r)).collect()
        }).collect();

        let shuffle = Shuffle::new(ctx.clone(), cts.clone(), &pubkey).unwrap();
        let shuffle2 = Shuffle::new(ctx.clone(), cts.clone(), &pubkey).unwrap();

        let commit_ctx = PedersenCtx::new(&seed, ctx.clone(), n + 1);
        let proof = shuffle2.gen_proof(&mut ctx, &commit_ctx, &pubkey).unwrap();
        assert!(!proof.verify(&mut ctx, &commit_ctx, &shuffle.inputs, &shuffle.outputs, &pubkey));
    }
}