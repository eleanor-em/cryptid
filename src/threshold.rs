use std::collections::HashMap;

use num_bigint::BigUint;
use serde::{Serialize, Deserialize};

use crate::elgamal::{Polynomial, KeyPair, CryptoContext, PublicKey, Ciphertext, CryptoError};
use crate::sign::{SigningKeyPair, SigningPubKey, Signature};
use crate::curve::{Scalar, CurveElem};
use crate::zkp;
use std::convert::identity;

pub struct ThresholdContext {
    ctx: CryptoContext,
    id: u32,
    k: u32,
    n: u32,
    polynomial: Polynomial,
    signing: SigningKeyPair,
    encryption: KeyPair,
    shares: HashMap<u32, Scalar>,
    commitments: HashMap<u32, Vec<CurveElem>>,
}

impl ThresholdContext {
    // See https://link.springer.com/content/pdf/10.1007/3-540-46416-6_47.pdf
    pub fn new(ctx: &mut CryptoContext, id: usize, k: usize, n: usize) -> Result<Self, CryptoError> {
        let mut ctx = ctx.cloned();
        let f_i = ctx.random_polynomial(k, n)?;
        let id = id as u32;
        let k = k as u32;
        let n = n as u32;

        let signing = ctx.gen_ed25519_key_pair()?;
        let encryption = ctx.gen_elgamal_key_pair()?;
        let s_j = HashMap::new();
        let commitments = HashMap::new();

        Ok(Self { ctx, id, polynomial: f_i, k, n, signing, encryption, shares: s_j, commitments })
    }

    pub fn get_signing_pubkey(&self) -> SigningPubKey {
        self.signing.pub_key()
    }

    pub fn get_encryption_pubkey(&self) -> PublicKey {
        self.encryption.pk
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    pub fn decrypt(&self, ct: Ciphertext) -> BigUint {
        ct.decrypt(&self.encryption.x_i).decoded()
    }

    pub fn get_commitment(&self) -> Vec<CurveElem> {
        self.polynomial.get_public_params()
    }

    pub fn get_polynomial_share(&self, id: u32) -> Scalar {
        self.polynomial.evaluate(id)
    }

    pub fn receive_commitment(&mut self, sender_id: u32, commitment: &Vec<CurveElem>) {
        self.commitments.insert(sender_id, commitment.clone());
    }

    pub fn receive_share(&mut self, sender_id: u32, share: &Scalar) -> Result<(), CryptoError> {
        self.shares.insert(sender_id, share.clone());
        let lhs = self.ctx.g_to(share);
        let commitment = self.commitments.get(&sender_id).ok_or(CryptoError::CommitmentMissing)?;

        // Verify the commitment
        let rhs = (0..self.k).map(|l| {
            let power = Scalar::from(self.id.pow(l));
            let base = commitment.get(l as usize).ok_or(CryptoError::CommitmentPartMissing)?;
            Ok(base.scaled(&power))
        }).collect::<Result<Vec<_>, _>>()?;

        let rhs = rhs.into_iter().sum();
        if lhs == rhs {
            Ok(())
        } else {
            Err(CryptoError::ShareRejected)
        }
    }

    pub fn complete(&self) -> bool {
        self.shares.len() == self.n as usize
    }

    fn get_secret_share(&self) -> Option<Scalar> {
        if self.complete() {
            Some(self.shares.values().sum())
        } else {
            None
        }
    }

    pub fn get_pubkey_share(&self) -> Option<CurveElem> {
        self.get_secret_share()
            .map(|s_i| self.ctx.g_to(&s_i).scaled(&lambda(self.n, self.id)))
    }

    pub fn get_decrypt_share(&mut self, ct: &Ciphertext) -> Result<DecryptShare, CryptoError> {
        let s_i = self.get_secret_share();
        let y_i = self.get_pubkey_share();
        if let (Some(s_i), Some(y_i)) = (s_i, y_i) {
            let l_i = &s_i * lambda(self.n, self.id);
            let a_i = ct.c1.scaled(&l_i);
            let g = self.ctx.generator();
            let proof = zkp::PrfEqDlogs::new(
                &mut self.ctx,
                &g,
                &ct.c1,
                &y_i,
                &a_i,
                &l_i)?;
            Ok(DecryptShare { a_i, proof })
        } else {
            Err(CryptoError::KeygenMissing)
        }
    }
}

// Lagrange coefficient calculation
fn lambda(n: u32, j: u32) -> Scalar {
    // let mut prod = 1.0;
    let mut numerator = 1;
    let mut denominator = 1;
    for l in 1..n + 1 {
        let l = l as i32;
        let j = j as i32;
        if l != j {
            numerator *= l;
            denominator *= l - j;
        }
    }

    // let result = prod as i32;
    let result = numerator / denominator;
    // Convert signed int to scalar
    if result < 0 {
        -Scalar::from((-result) as u32)
    } else {
        Scalar::from(result as u32)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptShare {
    a_i: CurveElem,
    proof: zkp::PrfEqDlogs,
}

#[derive(Debug)]
pub struct Decryption {
    n: usize,
    ctx: CryptoContext,
    ct: Ciphertext,
    pubkeys: Vec<CurveElem>,
    a: Vec<DecryptShare>,
}

impl Decryption {
    pub fn new(n: usize, ctx: &CryptoContext, ct: &Ciphertext) -> Self {
        Self {
            n,
            ctx: ctx.cloned(),
            ct: ct.clone(),
            pubkeys: Vec::new(),
            a: Vec::new(),
        }
    }

    pub fn complete(&self) -> bool {
        self.a.len() == self.n
    }

    pub fn add_share(&mut self, share: &DecryptShare, pubkey: &CurveElem) {
        self.a.push(share.clone());
        self.pubkeys.push(pubkey.clone());
    }

    pub fn verify(&self) -> Result<bool, CryptoError> {
        let results = self.a.iter().zip(&self.pubkeys)
            .map(|(share, y_i)| {
                let proof = &share.proof;

                // Verify the proof, and that the parameters are what they're supposed to be
                Ok(proof.verify()?
                    && proof.f == self.ctx.generator()
                    && proof.h == self.ct.c1
                    && proof.v == *y_i
                    && proof.w == share.a_i)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results.into_iter().all(identity))
    }

    pub fn result(&self) -> Option<BigUint> {
        if self.complete() {
            let a = self.a.iter().map(|share| share.a_i).sum();
            Some((self.ct.c2 - a).decoded())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use crate::threshold::{ThresholdContext, Decryption};
    use crate::elgamal::{CryptoContext, CurveElem, PublicKey};
    use std::collections::HashMap;

    fn generate_parties(ctx: &mut CryptoContext) -> Vec<ThresholdContext> {
        const K: usize = 3;
        const N: usize = 5;

        // Generate N parties
        let mut parties: Vec<_> = (1..N + 1)
            .map(|i| ThresholdContext::new(ctx, i, K, N).unwrap())
            .collect();

        // Generate the commitments
        let mut commitments = HashMap::new();
        parties.iter().for_each(|party| {
            commitments.insert(party.id, party.get_commitment());
        });

        // Send the commitments
        commitments.iter().for_each(|(&sender_id, commitment)| {
            parties.iter_mut().for_each(|receiver| receiver.receive_commitment(sender_id, commitment));
        });

        // Generate the shares
        let mut shares = HashMap::new();
        parties.iter().for_each(|receiver| {
            let mut receiver_shares = HashMap::new();
            parties.iter().for_each(|sender| {
                receiver_shares.insert(sender.id, sender.get_polynomial_share(receiver.id));
            });
            shares.insert(receiver.id, receiver_shares);
        });

        // Send the shares
        shares.iter().for_each(|(&receiver_id, share_set)| {
            share_set.iter().for_each(|(&sender_id, share)| {
                parties.get_mut((receiver_id - 1) as usize).unwrap()
                    .receive_share(sender_id, share)
                    .expect(&format!("{} rejected share from {}", receiver_id, sender_id));
            });
        });

        parties
    }

    #[test]
    fn test_keygen() {
        let mut ctx = CryptoContext::new();
        let parties = generate_parties(&mut ctx);

        // Store the intended public key
        let pubkey: CurveElem = parties.iter().map(|party| party.polynomial.get_pubkey_share()).sum();

        // Compute the final public key
        let y: CurveElem = parties.iter()
            .map(|party| party.get_pubkey_share().unwrap())
            .sum();

        assert_eq!(pubkey, y);
    }

    #[test]
    fn test_decrypt() {
        let mut ctx = CryptoContext::new();
        let mut parties = generate_parties(&mut ctx);

        let pks: Vec<_> = parties.iter()
            .map(|p| p.get_pubkey_share().unwrap())
            .collect();
        let pk = PublicKey::new(pks.clone().into_iter().sum());

        let r = ctx.random_power().unwrap();
        let m_r = ctx.random_power().unwrap();
        let m = ctx.g_to(&m_r);
        let ct = pk.encrypt(&ctx, &m, &r).unwrap();

        let mut decrypted = Decryption::new(parties.len(), &ctx, &ct);
        let shares: Vec<_> = parties.iter_mut()
            .map(|p| p.get_decrypt_share(&ct).unwrap())
            .collect();
        pks.iter().zip(&shares).for_each(|(pk, share)| decrypted.add_share(&share, &pk));

        assert!(decrypted.verify().unwrap());
        assert_eq!(decrypted.result().unwrap().to_str_radix(32),
                   m.decoded().to_str_radix(32));
    }
}