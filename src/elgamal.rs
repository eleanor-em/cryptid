use std::fmt::{Formatter, Display};
use std::error::Error;
use std::sync::{Mutex, Arc};
use std::ops::Deref;
use std::convert::TryFrom;

use ring::digest;
use ring::rand::SecureRandom;
use num_bigint::BigUint;
use serde::{Serialize, Deserialize};

use crate::curve::{CurveElem, Scalar};
use crate::sign::SigningKeypair;

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.y.as_biguint().to_str_radix(36))
    }
}

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub x_i: Scalar,
    pub y_i: CurveElem,
}

#[derive(Copy, Clone)]
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

#[derive(Serialize, Deserialize)]
pub struct Ciphertext {
    pub c1: CurveElem,
    pub c2: CurveElem,
}

impl Ciphertext {
    pub fn add(&self, rhs: &Self) -> Self {
        Ciphertext {
            c1: &self.c1 + &rhs.c1,
            c2: &self.c2 + &rhs.c2,
        }
    }
}

impl Display for Ciphertext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})",
               self.c1.as_biguint().to_str_radix(36),
               self.c2.as_biguint().to_str_radix(36))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CryptoError {
    Unspecified(ring::error::Unspecified),
    KeyRejected(ring::error::KeyRejected),
    Misc,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for CryptoError {}

// TODO: make this a proper type, add "finish_biguint" and "finish_scalar" functions
pub type Hasher = digest::Context;
pub type Digest = digest::Digest;

#[derive(Clone, Debug)]
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

    pub fn generator(&self) -> CurveElem {
        self.g.clone()
    }

    pub fn gen_ed25519_key_pair(&mut self) -> Result<SigningKeypair, CryptoError> {
        let rng = self.rng.lock().unwrap();
        return SigningKeypair::try_from(rng.deref())
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

    pub fn hasher() -> Hasher {
        digest::Context::new(&digest::SHA512)
    }

    pub fn hash_bytes(&self, data: &[u8]) -> Digest {
        let mut hasher = Self::hasher();
        hasher.update(data);
        hasher.finish()
    }

    pub fn hash_elem(&self, data: &CurveElem) -> Digest {
        let mut hasher = Self::hasher();
        hasher.update(&data.as_bytes());
        hasher.finish()
    }

    pub fn hash_bigint(&self, data: &BigUint) -> Digest {
        self.hash_bytes(&data.to_bytes_be())
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
        let decryption = &prod.c2 - &(prod.c1.scaled(&x));

        let combined = &m1 + &m2;

        assert_eq!(combined, decryption);
    }
}