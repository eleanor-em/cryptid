use std::collections::HashMap;
use std::convert::{identity, TryFrom};
use std::error::Error;
use std::fmt;
use std::fmt::Display;

use serde::{Serialize, Deserialize};
use serde::export::Formatter;

use crate::curve::{ CurveElem, Polynomial };
use crate::elgamal::{CryptoContext, PublicKey, Ciphertext};
use crate::{zkp, CryptoError, Scalar};
use crate::util::AsBase64;
use crate::scalar::DalekScalar;

#[derive(Clone, Copy, Debug)]
pub enum EncodingError {
    Base64,
    CurveElem,
    Length,
    Num,
    Verify,
}

impl Display for EncodingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for EncodingError {}

pub trait Threshold {
    type Error;
    type Destination;

    fn is_complete(&self) -> bool;
    fn finish(&self) -> Result<Self::Destination, Self::Error>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeygenCommitment {
    elems: Vec<CurveElem>,
}

impl Into<Vec<CurveElem>> for KeygenCommitment {
    fn into(self) -> Vec<CurveElem> {
        self.elems
    }
}

impl From<Vec<CurveElem>> for KeygenCommitment {
    fn from(elems: Vec<CurveElem>) -> Self {
        Self { elems }
    }
}

impl Display for KeygenCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let encoded_elems: Vec<_> = self.elems.iter().map(|elem| elem.as_base64()).collect();
        write!(f, "{}", encoded_elems.join(":"))
    }
}

impl TryFrom<String> for KeygenCommitment {
    type Error = EncodingError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut elems = Vec::new();
        for encoded in value.split(":") {
            let elem = CurveElem::try_from_base64(encoded).map_err(|_| EncodingError::CurveElem)?;
            elems.push(elem);
        }
        Ok(Self { elems })
    }
}

// Threshold ElGamal encryption after Pedersen's protocol. This type represents one party to the
// key generation and decryption protocol.
//
// See https://link.springer.com/content/pdf/10.1007/3-540-46416-6_47.pdf for details.
pub struct ThresholdGenerator {
    ctx: CryptoContext,
    index: usize,
    min_trustees: usize,
    trustee_count: usize,
    polynomial: Polynomial,
    shares: HashMap<usize, DalekScalar>,
    commitments: HashMap<usize, KeygenCommitment>,
    pk_parts: Vec<CurveElem>,
}

impl ThresholdGenerator {
    // Create a new party with a given ID (unique and nonzero).
    // k = the minimum number for decryption
    // n = the total number of parties
    pub fn new(ctx: &CryptoContext, index: usize, min_trustees: usize, trustee_count: usize) -> Self {
        if index > 0 && index <= trustee_count {
            let ctx = ctx.clone();
            let f_i = Polynomial::random(&ctx, min_trustees, trustee_count);
            let index = index as usize;
            let min_trustees = min_trustees as usize;
            let trustee_count = trustee_count as usize;

            let shares = HashMap::new();
            let commitments = HashMap::new();
            let pk_parts = Vec::new();

            Self { ctx, index, polynomial: f_i, min_trustees, trustee_count, shares, commitments, pk_parts }
        } else {
            panic!("Index must be between 1 and trustee_count inclusive.");
        }
    }

    // Returns the commitment vector to be shared publicly.
    pub fn get_commitment(&self) -> KeygenCommitment {
        self.polynomial.get_public_params().into()
    }

    // Returns the polynomial secret share for the given index -- not to be shared publicly.
    //
    // This should only be shared to recipients AFTER commitments are ready.
    pub fn get_polynomial_share(&self, index: usize) -> Result<Scalar, CryptoError> {
        if !self.received_commitments() {
            return Err(CryptoError::CommitmentMissing);
        }

        if index > 0 && index <= self.trustee_count {
            Ok(self.polynomial.evaluate(index as u32))
        } else {
            Err(CryptoError::InvalidId)
        }
    }

    // Receives a commitment from a particular party.
    pub fn receive_commitment(&mut self, sender_id: usize, commitment: &KeygenCommitment)
                              -> Result<(), CryptoError>{
        if sender_id > 0 && sender_id <= self.trustee_count {
            if self.commitments.insert(sender_id, commitment.clone()).is_none() {
                Ok(())
            } else {
                Err(CryptoError::CommitmentDuplicated)
            }
        } else {
            Err(CryptoError::InvalidId)
        }
    }

    pub fn received_commitments(&self) -> bool {
        self.commitments.len() == self.trustee_count as usize
    }

    // Receives a share from a particular party.
    pub fn receive_share(&mut self, sender_id: usize, share: &Scalar) -> Result<(), CryptoError> {
        if !self.received_commitments() {
            return Err(CryptoError::CommitmentMissing);
        }
        if sender_id == 0 || sender_id > self.trustee_count {
            return Err(CryptoError::InvalidId);
        }

        // Check what the commitment is meant to be
        let lhs = self.ctx.g_to(share);
        let commitment = self.commitments.get(&sender_id).unwrap();

        // Verify the commitment
        let rhs = (0..self.min_trustees).map(|l| {
            let power = Scalar::from((self.index as u32).pow(l as u32));
            let base = commitment.elems.get(l).ok_or(CryptoError::CommitmentPartMissing)?;
            Ok(base.scaled(&power))
        }).collect::<Result<Vec<_>, _>>()?;
        let rhs = rhs.into_iter().sum();

        if lhs == rhs {
            if self.shares.insert(sender_id, share.0.clone()).is_none() {
                // First part of the commitment is a public key share
                self.pk_parts.push(commitment.elems[0]);
                Ok(())
            } else {
                Err(CryptoError::ShareDuplicated)
            }
        } else {
            Err(CryptoError::ShareRejected)
        }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn min_trustees(&self) -> usize {
        self.min_trustees
    }

    pub fn trustee_count(&self) -> usize {
        self.trustee_count
    }
}

impl Threshold for ThresholdGenerator {
    type Error = CryptoError;
    type Destination = ThresholdParty;

    fn is_complete(&self) -> bool {
        self.shares.len() == self.trustee_count as usize
    }

    // Returns a completed object if the key generation is done, otherwise None.
    fn finish(&self) -> Result<ThresholdParty, CryptoError> {
        if self.is_complete() {
            let secret_share = Scalar(self.shares.values().sum());
            let pubkey_share = self.ctx.g_to(&secret_share);

            let pubkey = PublicKey::new(self.pk_parts.clone().into_iter().sum());

            Ok(ThresholdParty {
                ctx: self.ctx.clone(),
                index: self.index,
                min_trustees: self.min_trustees,
                trustee_count: self.trustee_count,
                secret_share,
                pubkey_share,
                pubkey,
            })
        } else {
            Err(CryptoError::KeygenMissing)
        }
    }
}

pub struct ThresholdParty {
    ctx: CryptoContext,
    index: usize,
    min_trustees: usize,
    trustee_count: usize,
    secret_share: Scalar,
    pubkey_share: CurveElem,
    pubkey: PublicKey,
}

impl Clone for ThresholdParty {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            index: self.index,
            min_trustees: self.min_trustees,
            trustee_count: self.trustee_count,
            secret_share: self.secret_share.clone(),
            pubkey_share: self.pubkey_share.clone(),
            pubkey: self.pubkey.clone(),
        }
    }
}

impl ThresholdParty {
    pub fn pubkey(&self) -> PublicKey {
        self.pubkey
    }

    // Returns this party's share of the public key, but unscaled so it can be used for proofs.
    pub fn pubkey_proof(&self) -> CurveElem {
        self.pubkey_share
    }

    // Returns this party's share of the public key, scaled with Lagrange multipliers.
    pub fn pubkey_share(&self) -> CurveElem {
        self.pubkey_share.scaled(&Scalar(lambda(1..self.trustee_count + 1, self.index)))
    }

    // Returns this party's share of a decryption.
    pub fn decrypt_share(&self, ct: &Ciphertext) -> DecryptShare {
        let dec_share = ct.c1.scaled(&self.secret_share);
        let g = self.ctx.generator();

        let proof = zkp::PrfEqDlogs::new(
            &self.ctx,
            &g,
            &ct.c1,
            &self.pubkey_share,
            &dec_share,
            &self.secret_share);

        DecryptShare { share: dec_share, proof }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn min_trustees(&self) -> usize {
        self.min_trustees
    }

    pub fn trustee_count(&self) -> usize {
        self.trustee_count
    }
}

// Lagrange coefficient calculation
fn lambda<I: Iterator<Item=usize>>(parties: I, j: usize) -> DalekScalar {
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

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DecryptShare {
    share: CurveElem,
    proof: zkp::PrfEqDlogs,
}

#[derive(Debug)]
pub struct Decryption {
    min_trustees: usize,
    ctx: CryptoContext,
    ct: Ciphertext,
    pubkeys: HashMap<usize, CurveElem>,
    dec_shares: HashMap<usize, DecryptShare>,
}

impl Decryption {
    pub fn new(min_trustees: usize, ctx: &CryptoContext, ct: &Ciphertext) -> Self {
        Self {
            min_trustees,
            ctx: ctx.clone(),
            ct: ct.clone(),
            pubkeys: HashMap::new(),
            dec_shares: HashMap::new(),
        }
    }

    pub fn add_share(&mut self, party_id: usize, party_pubkey_share: &CurveElem, share: &DecryptShare) {
        self.dec_shares.insert(party_id, share.clone());
        self.pubkeys.insert(party_id, party_pubkey_share.clone());
    }

    fn verify(&self) -> bool {
        let mut results = self.dec_shares.keys()
            .map(|index| (&self.dec_shares[index], &self.pubkeys[index]))
            .map(|(share, pubkey_share)| {
                let proof = &share.proof;

                // Verify the proof, and that the parameters are what they're supposed to be
                proof.verify()
                    && proof.base1 == self.ctx.generator()
                    && proof.base2 == self.ct.c1
                    && proof.result1 == *pubkey_share
                    && proof.result2 == share.share
            });

        self.is_complete() && results.all(identity)
    }
}

impl Threshold for Decryption {
    type Error = CryptoError;
    type Destination = CurveElem;

    fn is_complete(&self) -> bool {
        self.dec_shares.len() as usize >= self.min_trustees
    }

    fn finish(&self) -> Result<Self::Destination, Self::Error> {
        if self.is_complete() {
            if self.verify() {
                let dec_factor = self.dec_shares.keys()
                    .map(|index| (index, &self.dec_shares[index]))
                    .map(|(index, share)| {
                        let participants = self.dec_shares.keys().map(|&index| index);
                        let lagrange = Scalar(lambda(participants, *index));
                        share.share.scaled(&lagrange)
                    })
                    .sum();
                Ok(self.ct.c2 - dec_factor)
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
    use std::convert::TryInto;
    use crate::util::AsBase64;

    fn run_generation(ctx: &CryptoContext) -> Vec<ThresholdGenerator> {
        const K: usize = 3;
        const N: usize = 5;

        // Generate N parties
        let mut generators: Vec<_> = (1..N + 1)
            .map(|i| ThresholdGenerator::new(ctx, i, K, N))
            .collect();

        // Generate the commitments
        let mut commitments = HashMap::new();
        generators.iter().for_each(|party| {
            commitments.insert(party.index, party.get_commitment());
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
                let share = sender.get_polynomial_share(receiver.index).unwrap();
                receiver_shares.insert(sender.index, share);
            });
            shares.insert(receiver.index, receiver_shares);
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

    fn get_parties(ctx: &CryptoContext) -> Vec<ThresholdParty> {
        complete_parties(run_generation(ctx))
    }

    #[test]
    fn test_commitment_serde() {
        const K: usize = 3;
        const N: usize = 5;

        let ctx = CryptoContext::new().unwrap();
        let generator = ThresholdGenerator::new(&ctx, 1, K, N);
        let commit = generator.get_commitment();
        let commit_decoded = commit.to_string().try_into().unwrap();

        assert_eq!(commit, commit_decoded)
    }

    #[test]
    fn test_keygen() {
        let ctx = CryptoContext::new().unwrap();
        let generators = run_generation(&ctx);

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
        let ctx = CryptoContext::new().unwrap();
        let mut parties = get_parties(&ctx);
        let pk = parties.first().unwrap().pubkey();

        let r = ctx.random_scalar();
        let m_r = ctx.random_scalar();
        let m = ctx.g_to(&m_r);
        let ct = pk.encrypt(&ctx, &m, &r);

        let mut decrypted = Decryption::new(parties.first().unwrap().min_trustees, &ctx, &ct);

        parties.iter_mut()
            .for_each(|party| {
                let share = party.decrypt_share(&ct);
                decrypted.add_share(party.index, &party.pubkey_share, &share);
            });

        assert_eq!(decrypted.finish().unwrap().decoded().unwrap().as_base64(), m.decoded().unwrap().as_base64());
    }

    #[test]
    fn test_decrypt_partial() {
        let ctx = CryptoContext::new().unwrap();
        let mut parties = get_parties(&ctx);
        let pk = parties.first().unwrap().pubkey();

        let r = ctx.random_scalar();
        let m_r = ctx.random_scalar();
        let m = ctx.g_to(&m_r);
        let ct = pk.encrypt(&ctx, &m, &r);

        let k = parties.first().unwrap().min_trustees;
        parties.truncate(k as usize);

        let mut decrypted = Decryption::new(k, &ctx, &ct);
        parties.iter_mut()
            .for_each(|party| {
                let share = party.decrypt_share(&ct);
                decrypted.add_share(party.index, &party.pubkey_share, &share);
            });

        assert!(decrypted.verify());
        assert_eq!(decrypted.finish().unwrap().decoded().unwrap().as_base64(), m.decoded().unwrap().as_base64());
    }

    #[test]
    fn test_decrypt_not_enough() {
        let ctx = CryptoContext::new().unwrap();
        let mut parties = get_parties(&ctx);
        let pk = parties.first().unwrap().pubkey();

        let r = ctx.random_scalar();
        let m_r = ctx.random_scalar();
        let m = ctx.g_to(&m_r);
        let ct = pk.encrypt(&ctx, &m, &r);

        let k = parties.first().unwrap().min_trustees;
        parties.truncate((k - 1) as usize);

        let mut decrypted = Decryption::new(k, &ctx, &ct);
        parties.iter_mut()
            .for_each(|party| {
                let share = party.decrypt_share(&ct);
                decrypted.add_share(party.index, &party.pubkey_share, &share);
            });

        assert!(!decrypted.verify());
        assert!(decrypted.finish().is_err())
    }
}