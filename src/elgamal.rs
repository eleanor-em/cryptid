use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Formatter, Display};
use std::ops::Deref;
use std::sync::{Mutex, Arc};

use num_bigint::BigUint;
use ring::digest;
use ring::rand::SecureRandom;
use serde::{Serialize, Deserialize};

use crate::curve;
use crate::curve::{Scalar};
use crate::sign::SigningKeyPair;

#[derive(Clone, Copy, Debug)]
pub enum CryptoError {
    Unspecified(ring::error::Unspecified),
    KeyRejected(ring::error::KeyRejected),
    Misc,
    CommitmentMissing,
    CommitmentPartMissing,
    ShareRejected,
    KeygenMissing,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for CryptoError {}

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub x_i: Scalar,
    pub y_i: CurveElem,
}

impl KeyPair {
    fn new(ctx: &mut CryptoContext) -> Result<Self, CryptoError> {
        let x_i = ctx.random_power()?;
        let y_i = ctx.g_to(&x_i);
        let pk = PublicKey::new(y_i);
        Ok(Self { pk, x_i, y_i })
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    y: CurveElem,
}

impl PublicKey {
    pub fn new(value: CurveElem) -> Self {
        Self { y: value }
    }

    pub fn encrypt(&self, ctx: &CryptoContext, m: &CurveElem, r: &Scalar) -> Option<Ciphertext> {
        let c1 = ctx.g_to(r);
        let c2 = m + &self.y.scaled(r);
        Some(Ciphertext { c1, c2 })
    }

    pub fn rerand(self, ctx: &CryptoContext, ct: &Ciphertext, r: &Scalar) -> Ciphertext {
        let c1 = &ct.c1 + &ctx.g_to(r);
        let c2 = &ct.c2 + &self.y.scaled(r);
        Ciphertext { c1, c2 }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.y.as_biguint().to_str_radix(36))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    pub c1: CurveElem,
    pub c2: CurveElem,
}

impl Ciphertext {
    pub fn cloned(&self) -> Self {
        Ciphertext { c1: self.c1, c2: self.c2 }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        Ciphertext {
            c1: &self.c1 + &rhs.c1,
            c2: &self.c2 + &rhs.c2,
        }
    }

    pub fn decrypt(&self, secret_key: &Scalar) -> CurveElem {
        &self.c2 - &(self.c1.scaled(secret_key))
    }
}

impl Display for Ciphertext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})",
               self.c1.as_biguint().to_str_radix(36),
               self.c2.as_biguint().to_str_radix(36))
    }
}

// TODO: make this a proper type, add "finish_biguint" and "finish_scalar" functions
pub struct Hasher(digest::Context);

impl Hasher {
    pub fn new() -> Self {
        Self(digest::Context::new(&digest::SHA512))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(&data);
    }

    pub fn finish(self) -> Digest {
        self.0.finish()
    }

    pub fn finish_biguint(self) -> BigUint {
        let bytes = self.finish();
        BigUint::from_bytes_be(bytes.as_ref())
    }

    pub fn finish_scalar(self) -> Result<Scalar, CryptoError> {
        curve::to_scalar(self.finish_biguint())
            .map_err(|_| CryptoError::Misc)
    }
}


pub type Digest = digest::Digest;
pub type CurveElem = curve::CurveElem;

#[derive(Debug)]
pub struct CryptoContext {
    rng: Arc<Mutex<ring::rand::SystemRandom>>,
    g: CurveElem,
}

impl CryptoContext {
    pub fn new() -> Self {
        let rng = Arc::new(Mutex::new(ring::rand::SystemRandom::new()));
        let g = CurveElem::generator();
        Self {
            rng,
            g
        }
    }

    pub fn cloned(&self) -> Self {
        let rng = self.rng.clone();
        let g = self.g.clone();
        Self { rng, g }
    }

    pub fn generator(&self) -> CurveElem {
        self.g.clone()
    }

    pub fn gen_ed25519_key_pair(&mut self) -> Result<SigningKeyPair, CryptoError> {
        let rng = self.rng.lock().unwrap();
        return SigningKeyPair::try_from(rng.deref())
    }

    pub fn gen_elgamal_key_pair(&mut self) -> Result<KeyPair, CryptoError> {
        KeyPair::new(self)
    }

    pub fn random_power(&mut self) -> Result<Scalar, CryptoError> {
        let rng = self.rng.lock().unwrap();
        let mut buf = [0; 32];
        rng.fill(&mut buf)
            .map_err(|e| CryptoError::Unspecified(e))?;
        Ok(Scalar::from_bytes_mod_order(buf).reduce())
    }

    pub fn g_to(&self, power: &Scalar) -> CurveElem {
        self.g.scaled(power)
    }

    pub fn hash_bytes(&self, data: &[u8]) -> Digest {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finish()
    }

    pub fn hash_elem(&self, data: &CurveElem) -> Digest {
        let mut hasher = Hasher::new();
        hasher.update(&data.as_bytes());
        hasher.finish()
    }

    pub fn hash_bigint(&self, data: &BigUint) -> Digest {
        self.hash_bytes(&data.to_bytes_be())
    }

    pub fn random_polynomial(&mut self, k: usize, n: usize) -> Result<Polynomial, CryptoError> {
        let ctx = self.cloned();
        let x_i = self.random_power()?;
        let mut coefficients = Vec::with_capacity(k);
        coefficients.push(x_i);
        for _ in 1..k {
            coefficients.push(self.random_power()?);
        }

        Ok(Polynomial { k, n, x_i, ctx, coefficients })
    }
}

#[derive(Debug)]
pub struct Polynomial {
    k: usize,
    n: usize,
    x_i: Scalar,
    ctx: CryptoContext,
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    pub fn get_pubkey_share(&self) -> CurveElem {
        self.ctx.g_to(&self.x_i)
    }

    pub fn get_public_params(&self) -> Vec<CurveElem> {
        self.coefficients.iter()
            .map(|coeff| self.ctx.g_to(coeff))
            .collect()
    }

    pub fn evaluate(&self, i: u32) -> Scalar {
        (0..self.k).map(|l| {
            self.coefficients.get(l).unwrap() * Scalar::from(i.pow(l as u32))
        }).sum()
    }
}

#[cfg(test)]
mod test {
    use crate::elgamal::{CryptoContext, PublicKey};

    #[test]
    fn test_homomorphism() {
        let mut ctx = CryptoContext::new();

        let x = ctx.random_power().unwrap();
        let y = PublicKey::new(ctx.g_to(&x).into());

        // Construct two messages
        let r1 = &ctx.random_power().unwrap();
        let r2 = &ctx.random_power().unwrap();
        let m1 = ctx.g_to(r1);
        let m2 = ctx.g_to(r2);

        let r1 = ctx.random_power().unwrap();
        let r2 = ctx.random_power().unwrap();

        // Encrypt the messages
        let ct1 = y.encrypt(&ctx, &m1.into(), &r1).unwrap();
        let ct2 = y.encrypt(&ctx, &m2.into(), &r2).unwrap();

        // Compare the added encryption to the added messages
        let prod = ct1.add(&ct2);
        // let decryption = &prod.c2 - &(prod.c1.scaled(&x));
        let decryption = prod.decrypt(&x);

        let combined = &m1 + &m2;

        assert_eq!(combined, decryption);
    }
}