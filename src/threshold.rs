use std::collections::HashMap;
use std::convert::identity;

use serde::{Serialize, Deserialize};

use crate::curve::{ CurveElem, Polynomial };
use crate::elgamal::{CryptoContext, AuthCiphertext, PublicKey};
use crate::{zkp, CryptoError, Scalar, DalekScalar};

pub trait Threshold {
    type Error;
    type Destination;

    fn is_complete(&self) -> bool;
    fn finish(&self) -> Result<Self::Destination, Self::Error>;
}

// Threshold ElGamal encryption after Pedersen's protocol. This type represents one party to the
// key generation and decryption protocol.
//
// See https://link.springer.com/content/pdf/10.1007/3-540-46416-6_47.pdf for details.
pub struct ThresholdGenerator {
    ctx: CryptoContext,
    id: u32,
    k: u32,
    n: u32,
    polynomial: Polynomial,
    shares: HashMap<u32, DalekScalar>,
    commitments: HashMap<u32, Vec<CurveElem>>,
    pk_parts: Vec<CurveElem>,
}

impl ThresholdGenerator {
    // Create a new party with a given ID (unique and nonzero).
    // k = the minimum number for decryption
    // n = the total number of parties
    pub fn new(ctx: &mut CryptoContext, id: usize, k: usize, n: usize)
               -> Result<Self, CryptoError> {
        if id > 0 && id <= n {
            let mut ctx = ctx.cloned();
            let f_i = Polynomial::random(&mut ctx, k, n)?;
            let id = id as u32;
            let k = k as u32;
            let n = n as u32;

            let shares = HashMap::new();
            let commitments = HashMap::new();
            let pk_parts = Vec::new();

            Ok(Self { ctx, id, polynomial: f_i, k, n, shares, commitments, pk_parts })
        } else {
            Err(CryptoError::InvalidId)
        }
    }

    // Returns the commitment vector to be shared publicly.
    pub fn get_commitment(&self) -> Vec<CurveElem> {
        self.polynomial.get_public_params()
    }

    // Returns the polynomial secret share for the given id -- not to be shared publicly.
    pub fn get_polynomial_share(&self, id: u32) -> Result<Scalar, CryptoError> {
        if id > 0 && id <= self.n {
            Ok(self.polynomial.evaluate(id))
        } else {
            Err(CryptoError::InvalidId)
        }
    }

    // Receives a commitment from a particular party.
    pub fn receive_commitment(&mut self, sender_id: u32, commitment: &Vec<CurveElem>)
                              -> Result<(), CryptoError>{
        if sender_id > 0 && sender_id <= self.n {
            if self.commitments.insert(sender_id, commitment.clone()).is_none() {
                Ok(())
            } else {
                Err(CryptoError::CommitmentDuplicated)
            }
        } else {
            Err(CryptoError::InvalidId)
        }
    }

    // Receives a share from a particular party.
    pub fn receive_share(&mut self, sender_id: u32, share: &Scalar) -> Result<(), CryptoError> {
        if sender_id > 0 && sender_id <= self.n {
            // Check what the commitment is meant to be
            let lhs = self.ctx.g_to(share);
            let commitment = self.commitments.get(&sender_id)
                .ok_or(CryptoError::CommitmentMissing)?;

            // Verify the commitment
            let rhs = (0..self.k).map(|l| {
                let power = Scalar::from(self.id.pow(l));
                let base = commitment.get(l as usize).ok_or(CryptoError::CommitmentPartMissing)?;
                Ok(base.scaled(&power))
            }).collect::<Result<Vec<_>, _>>()?;
            let rhs = rhs.into_iter().sum();

            if lhs == rhs {
                if self.shares.insert(sender_id, share.0.clone()).is_none() {
                    self.pk_parts.push(commitment[0]);
                    Ok(())
                } else {
                    Err(CryptoError::ShareDuplicated)
                }
            } else {
                Err(CryptoError::ShareRejected)
            }
        } else {
            Err(CryptoError::InvalidId)
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn k(&self) -> u32 {
        self.k
    }

    pub fn n(&self) -> u32 {
        self.n
    }
}

impl Threshold for ThresholdGenerator {
    type Error = CryptoError;
    type Destination = ThresholdParty;

    fn is_complete(&self) -> bool {
        self.shares.len() == self.n as usize
    }

    // Returns a completed object if the key generation is done, otherwise None.
    fn finish(&self) -> Result<ThresholdParty, CryptoError> {
        if self.is_complete() {
            let s_i = Scalar(self.shares.values().sum());
            let h_i = self.ctx.g_to(&s_i);

            let pubkey = PublicKey::new(self.pk_parts.clone().into_iter().sum());

            Ok(ThresholdParty {
                ctx: self.ctx.cloned(),
                id: self.id,
                k: self.k,
                n: self.n,
                s_i,
                h_i,
                pubkey,
            })
        } else {
            Err(CryptoError::KeygenMissing)
        }
    }
}

pub struct ThresholdParty {
    ctx: CryptoContext,
    id: u32,
    k: u32,
    n: u32,
    s_i: Scalar,
    h_i: CurveElem,
    pubkey: PublicKey,
}

impl ThresholdParty {
    pub fn cloned(&self) -> Self {
        Self {
            ctx: self.ctx.cloned(),
            id: self.id,
            k: self.k,
            n: self.n,
            s_i: self.s_i.clone(),
            h_i: self.h_i.clone(),
            pubkey: self.pubkey.clone(),
        }
    }

    pub fn pubkey(&self) -> PublicKey {
        self.pubkey
    }

    // Returns this party's share of the public key.
    pub fn pubkey_share(&self) -> CurveElem {
        self.h_i.scaled(&Scalar(lambda(1..self.n + 1, self.id)))
    }

    // Returns this party's share of a decryption.
    pub fn decrypt_share(&mut self, ct: &AuthCiphertext) -> Result<DecryptShare, CryptoError> {
        let c1 = ct.contents.c1;

        let a_i = c1.scaled(&self.s_i);
        let g = self.ctx.generator();

        let proof = zkp::PrfEqDlogs::new(
            &mut self.ctx,
            &g,
            &c1,
            &self.h_i,
            &a_i,
            &self.s_i)?;

        Ok(DecryptShare { a_i, proof })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn k(&self) -> u32 {
        self.k
    }

    pub fn n(&self) -> u32 {
        self.n
    }
}

// Lagrange coefficient calculation
fn lambda<I: Iterator<Item=u32>>(parties: I, j: u32) -> DalekScalar {
    let mut numerator = 1;
    let mut denominator = 1;
    for l in parties {
        let l = l as i32;
        let j = j as i32;
        if l != j {
            numerator *= l;
            denominator *= l - j;
        }
    }

    let result = numerator / denominator;

    // Convert signed int to scalar
    if result < 0 {
        -DalekScalar::from((-result) as u32)
    } else {
        DalekScalar::from(result as u32)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptShare {
    a_i: CurveElem,
    proof: zkp::PrfEqDlogs,
}

#[derive(Debug)]
pub struct Decryption {
    k: u32,
    ctx: CryptoContext,
    ct: AuthCiphertext,
    pubkeys: HashMap<u32, CurveElem>,
    a: HashMap<u32, DecryptShare>,
}

impl Decryption {
    pub fn new(k: u32, ctx: &CryptoContext, ct: &AuthCiphertext) -> Self {
        Self {
            k,
            ctx: ctx.cloned(),
            ct: ct.clone(),
            pubkeys: HashMap::new(),
            a: HashMap::new(),
        }
    }

    pub fn add_share(&mut self, party: &ThresholdParty, share: &DecryptShare){
        self.a.insert(party.id, share.clone());
        self.pubkeys.insert(party.id, party.h_i.clone());
    }

    fn verify(&self) -> Result<bool, CryptoError> {
        let results = self.a.keys()
            .map(|id| (&self.a[id], &self.pubkeys[id]))
            .map(|(share, h_i)| {
                let proof = &share.proof;

                // Verify the proof, and that the parameters are what they're supposed to be
                Ok(proof.verify()?
                    && proof.f == self.ctx.generator()
                    && proof.h == self.ct.contents.c1
                    && proof.v == *h_i
                    && proof.w == share.a_i)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(self.is_complete() && results.into_iter().all(identity))
    }
}

impl Threshold for Decryption {
    type Error = CryptoError;
    type Destination = Scalar;

    fn is_complete(&self) -> bool {
        self.a.len() as u32 >= self.k
    }

    fn finish(&self) -> Result<Scalar, CryptoError> {
        if self.is_complete() {
            if self.verify()? {
                let a = self.a.keys()
                    .map(|id| (id, &self.a[id]))
                    .map(|(id, share)| {
                        let participants = self.a.keys().map(|&id| id);
                        let l_i = Scalar(lambda(participants, *id));
                        share.a_i.scaled(&l_i)
                    })
                    .sum();
                let plaintext = self.ct.contents.c2 - a;
                if self.ct.verify(&plaintext) {
                    plaintext.decoded()
                } else {
                    Err(CryptoError::AuthTagRejected)
                }
            } else {
                Err(CryptoError::ShareRejected)
            }
        } else {
            Err(CryptoError::KeygenMissing)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::threshold::{ThresholdGenerator, Decryption, ThresholdParty, Threshold};
    use crate::elgamal::{CryptoContext, CurveElem};
    use std::collections::HashMap;

    fn run_generation(ctx: &mut CryptoContext) -> Vec<ThresholdGenerator> {
        const K: usize = 3;
        const N: usize = 5;

        // Generate N parties
        let mut generators: Vec<_> = (1..N + 1)
            .map(|i| ThresholdGenerator::new(ctx, i, K, N).unwrap())
            .collect();

        // Generate the commitments
        let mut commitments = HashMap::new();
        generators.iter().for_each(|party| {
            commitments.insert(party.id, party.get_commitment());
        });

        // Send the commitments
        commitments.iter().for_each(|(&sender_id, commitment)| {
            generators.iter_mut().for_each(|receiver| {
                receiver.receive_commitment(sender_id, commitment).unwrap()
            });
        });

        // Generate the shares
        let mut shares = HashMap::new();
        generators.iter().for_each(|receiver| {
            let mut receiver_shares = HashMap::new();
            generators.iter().for_each(|sender| {
                let share = sender.get_polynomial_share(receiver.id).unwrap();
                receiver_shares.insert(sender.id, share);
            });
            shares.insert(receiver.id, receiver_shares);
        });

        // Send the shares
        shares.iter().for_each(|(&receiver_id, share_set)| {
            share_set.iter().for_each(|(&sender_id, share)| {
                generators[(receiver_id - 1) as usize]
                    .receive_share(sender_id, share)
                    .expect(&format!("{} rejected share from {}", receiver_id, sender_id));
            });
        });

        generators
    }

    fn complete_parties(generators: Vec<ThresholdGenerator>) -> Vec<ThresholdParty> {
        generators.iter()
            .map(|p| p.finish().unwrap())
            .collect()
    }

    fn get_parties(ctx: &mut CryptoContext) -> Vec<ThresholdParty> {
        complete_parties(run_generation(ctx))
    }

    #[test]
    fn test_keygen() {
        let mut ctx = CryptoContext::new();
        let generators = run_generation(&mut ctx);

        // Store the intended public key
        let pubkey: CurveElem = generators.iter().map(|party| {
            ctx.g_to(&party.polynomial.x_i)
        }).sum();
        let parties = complete_parties(generators);

        // Compute the final public key
        let y: CurveElem = parties.iter()
            .map(|party| party.pubkey_share())
            .sum();

        assert_eq!(pubkey, y);
        parties.iter().for_each(|party| {
            assert_eq!(pubkey.as_base64(), party.pubkey.as_base64());
        });
    }

    #[test]
    fn test_decrypt() {
        let mut ctx = CryptoContext::new();
        let mut parties = get_parties(&mut ctx);
        let pk = parties.first().unwrap().pubkey();

        let r = ctx.random_power().unwrap();
        let m_r = ctx.random_power().unwrap();
        let m = ctx.g_to(&m_r);
        let ct = pk.encrypt_auth(&ctx, &m, &r);

        let mut decrypted = Decryption::new(parties.first().unwrap().k, &ctx, &ct);

        parties.iter_mut()
            .for_each(|party| {
                let share = party.decrypt_share(&ct).unwrap();
                decrypted.add_share(&party, &share);
            });

        assert!(decrypted.verify().unwrap());
        assert_eq!(decrypted.finish().unwrap().as_base64(), m.decoded().unwrap().as_base64());
    }

    #[test]
    fn test_decrypt_partial() {
        let mut ctx = CryptoContext::new();
        let mut parties = get_parties(&mut ctx);
        let pk = parties.first().unwrap().pubkey();

        let r = ctx.random_power().unwrap();
        let m_r = ctx.random_power().unwrap();
        let m = ctx.g_to(&m_r);
        let ct = pk.encrypt_auth(&ctx, &m, &r);

        let k = parties.first().unwrap().k;
        parties.truncate(k as usize);

        let mut decrypted = Decryption::new(k, &ctx, &ct);
        parties.iter_mut()
            .for_each(|party| {
                let share = party.decrypt_share(&ct).unwrap();
                decrypted.add_share(&party, &share);
            });

        assert!(decrypted.verify().unwrap());
        assert_eq!(decrypted.finish().unwrap().as_base64(), m.decoded().unwrap().as_base64());
    }

    #[test]
    fn test_decrypt_not_enough() {
        let mut ctx = CryptoContext::new();
        let mut parties = get_parties(&mut ctx);
        let pk = parties.first().unwrap().pubkey();

        let r = ctx.random_power().unwrap();
        let m_r = ctx.random_power().unwrap();
        let m = ctx.g_to(&m_r);
        let ct = pk.encrypt_auth(&ctx, &m, &r);

        let k = parties.first().unwrap().k;
        parties.truncate((k - 1) as usize);

        let mut decrypted = Decryption::new(k, &ctx, &ct);
        parties.iter_mut()
            .for_each(|party| {
                let share = party.decrypt_share(&ct).unwrap();
                decrypted.add_share(&party, &share);
            });

        assert!(!decrypted.verify().unwrap());
        assert!(decrypted.finish().is_err())
    }
}