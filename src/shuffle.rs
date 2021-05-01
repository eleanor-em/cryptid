use crate::commit::PedersenCtx;
use crate::curve::CurveElem;
use crate::curve::GENERATOR;
use crate::elgamal::{Ciphertext, PublicKey};
use crate::{CryptoError, Hasher, Scalar};
use rand::{CryptoRng, Rng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};

// See https://fc17.ifca.ai/voting/papers/voting17_HLKD17.pdf

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permutation {
    map: Vec<usize>,
}

impl Permutation {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R, n: usize) -> Result<Self, CryptoError> {
        let mut map = Vec::with_capacity(n);
        let mut nums: Vec<_> = (0..n).collect();

        for i in 0..n {
            let k = rng.gen_range(i..n);
            map.push(nums[k]);
            nums[k] = nums[i];
        }

        Ok(Self { map })
    }

    // Produces a commitment to the permutation matrix
    fn commit<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        commit_ctx: &PedersenCtx,
        generators: &[CurveElem],
    ) -> Result<(Vec<CurveElem>, Vec<Scalar>), CryptoError> {
        let n = self.map.len();
        if generators.len() < n {
            return Err(CryptoError::InvalidGenCount);
        }

        let mut cs = HashMap::new();
        let mut rs = HashMap::new();
        for i in 0..n {
            let r_i = Scalar::random(rng);
            cs.insert(self.map[i], commit_ctx.g.scaled(&r_i) + generators[i]);
            rs.insert(self.map[i], r_i);
        }

        Ok((
            (0..n).map(|i| cs[&i]).collect(),
            (0..n).map(|i| rs[&i]).collect(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shuffle {
    inputs: Vec<Vec<Ciphertext>>,
    outputs: Vec<Vec<Ciphertext>>,
    factors: Vec<Vec<Scalar>>,
    perm: Permutation,
}

const SHUFFLE_TAG: &'static str = "SHUFFLE_PROOF";

impl Shuffle {
    pub fn new<R: Rng + CryptoRng>(
        rng: &mut R,
        inputs: Vec<Vec<Ciphertext>>,
        pubkey: &PublicKey,
    ) -> Result<Self, CryptoError> {
        let n = inputs.len();
        if n == 0 {
            return Err(CryptoError::EmptyShuffle);
        }
        let m = inputs[0].len();

        let perm = { Permutation::new(rng, n)? };

        let factors: Vec<Vec<_>> = (0..n)
            .map(|_| (0..m).map(|_| Scalar::random(rng)).collect())
            .collect();

        let new_cts: Vec<Vec<_>> = (&inputs, &factors)
            .into_par_iter()
            .map(|(cts, rs)| {
                cts.iter()
                    .zip(rs)
                    .map(|(ct, r)| pubkey.rerand(&ct, &r))
                    .collect()
            })
            .collect();
        let outputs = (0..n).map(|i| new_cts[perm.map[i]].clone()).collect();

        Ok(Self {
            inputs,
            outputs,
            factors,
            perm,
        })
    }

    pub fn inputs(&self) -> &[Vec<Ciphertext>] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[Vec<Ciphertext>] {
        &self.outputs
    }

    pub fn gen_proof<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        commit_ctx: &PedersenCtx,
        generators: &[CurveElem],
        pubkey: &PublicKey,
    ) -> Result<ShuffleProof, CryptoError> {
        // Convenience shortcuts for parameters
        let n = self.perm.map.len();
        if n == 0 {
            return Err(CryptoError::EmptyShuffle);
        }
        let m = self.inputs[0].len();
        let h = &commit_ctx.h;
        if generators.len() < n {
            return Err(CryptoError::InvalidGenCount);
        }

        // Generate a vector of commitments to the permutation matrix
        let (commitments, rs) = self.perm.commit(rng, commit_ctx, generators)?;

        // Generate challenges via the Fiat-Shamir transform
        let mut initial_bytes = Vec::new();
        initial_bytes.par_extend(
            (&self.inputs, &self.outputs, &commitments, generators)
                .into_par_iter()
                .map(|(cts1, cts2, comm, gen)| {
                    // 32 * 2 bytes per ciphertext, cts1.len() * 2 ciphertexts, 32 bytes for commitment,
                    // 32 bytes for commitment params
                    let mut bytes: Vec<u8> = Vec::with_capacity(32 * 2 * cts1.len() * 2 + 32 + 32);
                    for ct in cts1 {
                        bytes.extend(&ct.c1.as_bytes());
                        bytes.extend(&ct.c2.as_bytes());
                    }
                    for ct in cts2 {
                        bytes.extend(&ct.c1.as_bytes());
                        bytes.extend(&ct.c2.as_bytes());
                    }
                    bytes.extend(&comm.as_bytes());
                    bytes.extend(&gen.as_bytes());
                    bytes
                }),
        );
        let initial_bytes = initial_bytes.concat();

        let base_hasher = Hasher::sha_256()
            .and_update(&initial_bytes)
            .and_update(&pubkey.y.as_bytes())
            .and_update(&commit_ctx.g.as_bytes())
            .and_update(&commit_ctx.h.as_bytes())
            .and_update(&GENERATOR.as_bytes())
            .and_update(SHUFFLE_TAG.as_bytes());

        let challenges: Vec<_> = (0..n)
            .into_par_iter()
            .map(|i| {
                base_hasher
                    .clone()
                    .and_update(&i.to_be_bytes())
                    .finish_scalar()
            })
            .collect();

        let perm_challenges: Vec<_> = (0..n)
            .map(|i| challenges[self.perm.map[i]].clone())
            .collect();

        let chain = CommitChain::new(rng, commit_ctx, &perm_challenges)?;

        // Generate randomness
        let r_bar = rs.clone().into_par_iter().sum();
        let mut vs: Vec<Scalar> = (0..n).map(|_| Scalar::one()).collect();
        for i in (0..(n - 1)).rev() {
            vs[i] = perm_challenges[i + 1] * vs[i + 1];
        }

        let r_hat = (0..n).into_par_iter().map(|i| chain.rs[i] * vs[i]).sum();
        let r_tilde = (0..n).into_par_iter().map(|i| rs[i] * challenges[i]).sum();
        let r_primes: Vec<_> = (0..m)
            .map(|j| {
                (0..n)
                    .into_par_iter()
                    .map(|i| self.factors[i][j] * challenges[i])
                    .sum()
            })
            .collect();

        let mut omegas = Vec::new();
        omegas.push(Scalar::random(rng));
        omegas.push(Scalar::random(rng));
        omegas.push(Scalar::random(rng));
        for _ in 0..m {
            omegas.push(Scalar::random(rng));
        }

        let mut omega_hats = Vec::new();
        let mut omega_primes = Vec::new();
        for _ in 0..n {
            omega_hats.push(Scalar::random(rng));
            omega_primes.push(Scalar::random(rng));
        }

        // Generate commitments
        let t_1 = commit_ctx.g.scaled(&omegas[0]);
        let t_2 = commit_ctx.g.scaled(&omegas[1]);
        let t_3 = commit_ctx.g.scaled(&omegas[2])
            + (generators, &omega_primes)
                .into_par_iter()
                .map(|(h, w)| h.scaled(&w))
                .sum();

        let mut t_4s = Vec::new();
        for j in 0..m {
            let (sum_a, sum_b) = (&self.outputs, &omega_primes)
                .into_par_iter()
                .map(|(cts, omega_prime)| {
                    (
                        cts[j].c1.scaled(&omega_prime),
                        cts[j].c2.scaled(&omega_prime),
                    )
                })
                .reduce(
                    || (CurveElem::identity(), CurveElem::identity()),
                    |(a, b), (c_a, c_b)| (a + c_a, b + c_b),
                );

            let t_4_1 = GENERATOR.scaled(&-omegas[j + 3]) + sum_a;
            let t_4_2 = pubkey.y.scaled(&-omegas[j + 3]) + sum_b;

            t_4s.push((t_4_1, t_4_2));
        }

        let t_hats: Vec<_> = (0..n)
            .into_par_iter()
            .map(|i| {
                let last_commit = if i == 0 { h } else { &chain.commits[i - 1] };
                commit_ctx.g.scaled(&omega_hats[i]) + last_commit.scaled(&omega_primes[i])
            })
            .collect();

        // Generate challenge
        let mut hash = base_hasher;
        for commit in chain.commits.iter() {
            hash.update(&commit.as_bytes());
        }
        hash = hash
            .and_update(&pubkey.y.as_bytes())
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

        // Compute responses
        let s_1 = omegas[0] + c * r_bar;
        let s_2 = omegas[1] + c * r_hat;
        let s_3 = omegas[2] + c * r_tilde;

        let s_4s: Vec<_> = (0..m).map(|i| omegas[i + 3] + c * r_primes[i]).collect();

        let s_hats = (0..n).map(|i| omega_hats[i] + c * chain.rs[i]).collect();

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
            chain,
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
    pub fn verify(
        &self,
        commit_ctx: &PedersenCtx,
        generators: &[CurveElem],
        inputs: &[Vec<Ciphertext>],
        outputs: &[Vec<Ciphertext>],
        pubkey: &PublicKey,
    ) -> bool {
        if inputs.len() != outputs.len() {
            panic!("Shuffle input and output lengths do not match");
        }

        // Convenience shortcuts for parameters
        let n = inputs.len();
        // Empty shuffle is trivially correct
        if n == 0 {
            return true;
        }

        let m = inputs[0].len();
        let h = &commit_ctx.h;

        // Generate challenges
        let mut initial_bytes = Vec::new();
        initial_bytes.par_extend(
            (inputs, outputs, &self.commitments, generators)
                .into_par_iter()
                .map(|(cts1, cts2, comm, gen)| {
                    let mut bytes: Vec<u8> = Vec::with_capacity(32 * 2 * cts1.len() * 2 + 32 + 32);
                    for ct in cts1 {
                        bytes.extend(&ct.c1.as_bytes());
                        bytes.extend(&ct.c2.as_bytes());
                    }
                    for ct in cts2 {
                        bytes.extend(&ct.c1.as_bytes());
                        bytes.extend(&ct.c2.as_bytes());
                    }
                    bytes.extend(&comm.as_bytes());
                    bytes.extend(&gen.as_bytes());
                    bytes
                }),
        );
        let initial_bytes = initial_bytes.concat();

        let base_hasher = Hasher::sha_256()
            .and_update(&initial_bytes)
            .and_update(&pubkey.y.as_bytes())
            .and_update(&commit_ctx.g.as_bytes())
            .and_update(&commit_ctx.h.as_bytes())
            .and_update(&GENERATOR.as_bytes())
            .and_update(SHUFFLE_TAG.as_bytes());

        let challenges: Vec<_> = (0..n)
            .into_par_iter()
            .map(|i| {
                base_hasher
                    .clone()
                    .and_update(&i.to_be_bytes())
                    .finish_scalar()
            })
            .collect();

        let c_bar: CurveElem = (&self.commitments, generators)
            .into_par_iter()
            .map(|(c, h)| c - h)
            .sum();

        let u = challenges.clone().into_par_iter().product();
        let c_hat = self.chain.commits.last().unwrap() - &h.scaled(&u);
        let c_tilde: CurveElem = (&self.commitments, &challenges)
            .into_par_iter()
            .map(|(c, u)| c.scaled(&u))
            .sum();

        let scaled_cts: Vec<_> = (0..m)
            .map(|j| {
                (&challenges, inputs)
                    .into_par_iter()
                    .map(|(u, cts)| (cts[j].c1.scaled(&u), cts[j].c2.scaled(&u)))
                    .reduce(
                        || (CurveElem::identity(), CurveElem::identity()),
                        |(a, b), (c_a, c_b)| (a + c_a, b + c_b),
                    )
            })
            .collect();

        let mut hash = base_hasher;
        for commit in self.chain.commits.iter() {
            hash.update(&commit.as_bytes());
        }
        hash = hash
            .and_update(&pubkey.y.as_bytes())
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

        let t_1_prime = c_bar.scaled(&-c) + commit_ctx.g.scaled(&self.s_1);
        let t_2_prime = c_hat.scaled(&-c) + commit_ctx.g.scaled(&self.s_2);

        let t_3_prime = c_tilde.scaled(&-c)
            + commit_ctx.g.scaled(&self.s_3)
            + (generators, &self.s_primes)
                .into_par_iter()
                .map(|(h, s_prime)| h.scaled(&s_prime))
                .sum();

        let mut t_4_primes = Vec::new();
        for j in 0..m {
            let (sum_a, sum_b) = (outputs, &self.s_primes)
                .into_par_iter()
                .map(|(cts, s_prime)| (cts[j].c1.scaled(&s_prime), cts[j].c2.scaled(&s_prime)))
                .reduce(
                    || (CurveElem::identity(), CurveElem::identity()),
                    |(a, b), (c_a, c_b)| (a + c_a, b + c_b),
                );

            let t_4_1_prime =
                scaled_cts[j].0.scaled(&-c) + GENERATOR.scaled(&-self.s_4s[j]) + sum_a;

            let t_4_2_prime = scaled_cts[j].1.scaled(&-c) + pubkey.y.scaled(&-self.s_4s[j]) + sum_b;

            t_4_primes.push((t_4_1_prime, t_4_2_prime));
        }

        let t_hat_primes: Vec<_> = (0..n)
            .into_par_iter()
            .map(|i| {
                let last_commit = if i == 0 {
                    h
                } else {
                    &self.chain.commits[i - 1]
                };
                self.chain.commits[i].scaled(&-c)
                    + commit_ctx.g.scaled(&self.s_hats[i])
                    + last_commit.scaled(&self.s_primes[i])
            })
            .collect();

        t_1_prime == self.t_1
            && t_2_prime == self.t_2
            && t_3_prime == self.t_3
            && t_4_primes == self.t_4s
            && t_hat_primes == self.t_hats
    }
}

impl Display for ShuffleProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct CommitChain {
    commits: Vec<CurveElem>,
    rs: Vec<Scalar>,
}

impl CommitChain {
    fn new<R: Rng + CryptoRng>(
        rng: &mut R,
        commit_ctx: &PedersenCtx,
        challenges: &[Scalar],
    ) -> Result<Self, CryptoError> {
        let mut commits = Vec::new();
        let mut rs = Vec::new();
        let mut last_commit = commit_ctx.h.clone();

        for i in 0..challenges.len() {
            let r_i = Scalar::random(rng);
            let c_i = commit_ctx.g.scaled(&r_i) + last_commit.scaled(&challenges[i]);
            last_commit = c_i.clone();
            rs.push(r_i);
            commits.push(c_i);
        }

        Ok(Self { commits, rs })
    }
}

#[cfg(test)]
mod tests {
    use crate::commit::PedersenCtx;
    use crate::curve::CurveElem;
    use crate::elgamal::{CryptoContext, PublicKey};
    use crate::shuffle::Shuffle;
    use crate::Scalar;
    use rand::RngCore;

    #[test]
    fn test_shuffle_random() {
        let mut rng = rand::thread_rng();
        let ctx = CryptoContext::new().unwrap();
        let pubkey = PublicKey::new(ctx.random_elem());
        let n = 4;
        let m = 3;

        let factors: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let cts: Vec<_> = factors
            .iter()
            .map(|r| {
                let message = ctx.random_elem();
                (0..m).map(|_| pubkey.encrypt(&message, &r)).collect()
            })
            .collect();

        let shuffle1 = Shuffle::new(&mut rng, cts.clone(), &pubkey).unwrap();
        let shuffle2 = Shuffle::new(&mut rng, cts.clone(), &pubkey).unwrap();

        assert_ne!(shuffle1, shuffle2);
    }

    #[test]
    fn test_shuffle_complete() {
        let mut rng = rand::thread_rng();

        let ctx = CryptoContext::new().unwrap();
        let pubkey = PublicKey::new(ctx.random_elem());
        let n = 100;
        let m = 5;

        let factors: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let cts: Vec<_> = factors
            .iter()
            .map(|r| {
                (0..m)
                    .map(|_| {
                        pubkey.encrypt(&CurveElem::try_encode(Scalar::from(16u32)).unwrap(), &r)
                    })
                    .collect()
            })
            .collect();

        let shuffle = Shuffle::new(&mut rng, cts.clone(), &pubkey).unwrap();

        let mut seed = [0; 64];
        rng.fill_bytes(&mut seed);
        let (commit_ctx, generators) = PedersenCtx::with_generators(&seed, n);
        let proof = shuffle
            .gen_proof(&mut rng, &commit_ctx, &generators, &pubkey)
            .unwrap();

        assert!(proof.verify(
            &commit_ctx,
            &generators,
            &shuffle.inputs,
            &shuffle.outputs,
            &pubkey
        ));
    }

    #[test]
    fn test_shuffle_sound() {
        let mut rng = rand::thread_rng();
        let ctx = CryptoContext::new().unwrap();
        let pubkey = PublicKey::new(ctx.random_elem());
        let n = 100;
        let m = 3;

        let factors: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let cts: Vec<_> = factors
            .iter()
            .map(|r| {
                (0..m)
                    .map(|_| {
                        pubkey.encrypt(&CurveElem::try_encode(Scalar::from(16u32)).unwrap(), &r)
                    })
                    .collect()
            })
            .collect();

        let shuffle = Shuffle::new(&mut rng, cts.clone(), &pubkey).unwrap();
        let shuffle2 = Shuffle::new(&mut rng, cts.clone(), &pubkey).unwrap();

        let mut seed = [0; 64];
        rng.fill_bytes(&mut seed);
        let (commit_ctx, generators) = PedersenCtx::with_generators(&seed, n);
        let proof = shuffle
            .gen_proof(&mut rng, &commit_ctx, &generators, &pubkey)
            .unwrap();
        assert!(!proof.verify(
            &commit_ctx,
            &generators,
            &shuffle2.inputs,
            &shuffle2.outputs,
            &pubkey
        ));
    }
}
