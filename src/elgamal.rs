use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::sync::{Arc, Mutex};

use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};

use crate::threshold::EncodingError;
use crate::{curve, CryptoError};
use crate::{AsBase64, Scalar};
use curve::GENERATOR;
use curve25519_dalek::ristretto::RistrettoPoint;
use num_bigint::BigUint;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::ops::DerefMut;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PublicKey {
    pub(crate) y: CurveElem,
}

impl PublicKey {
    pub fn new(value: CurveElem) -> Self {
        Self { y: value }
    }

    pub fn encrypt(&self, m: &CurveElem, r: &Scalar) -> Ciphertext {
        let c1 = GENERATOR.scaled(r);
        let c2 = m + &self.y.scaled(r);
        Ciphertext { c1, c2 }
    }

    pub fn rerand(self, ct: &Ciphertext, r: &Scalar) -> Ciphertext {
        let c1 = &ct.c1 + &GENERATOR.scaled(r);
        let c2 = &ct.c2 + &self.y.scaled(r);
        Ciphertext { c1, c2 }
    }
}

impl AsBase64 for PublicKey {
    type Error = CryptoError;

    fn as_base64(&self) -> String {
        self.y.as_base64()
    }

    fn try_from_base64(encoded: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            y: CurveElem::try_from_base64(encoded)?,
        })
    }
}

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_base64().hash(state);
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.y.as_base64())
    }
}

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub x_i: Scalar,
    pub y_i: CurveElem,
}

impl KeyPair {
    fn new(ctx: &CryptoContext) -> Self {
        let x_i = ctx.random_scalar();
        let y_i = GENERATOR.scaled(&x_i);
        let pk = PublicKey::new(y_i);
        Self { pk, x_i, y_i }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ciphertext {
    pub c1: CurveElem,
    pub c2: CurveElem,
}

impl Ciphertext {
    pub fn identity() -> Self {
        Self {
            c1: CurveElem::identity(),
            c2: CurveElem::identity(),
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        Self {
            c1: &self.c1 + &rhs.c1,
            c2: &self.c2 + &rhs.c2,
        }
    }

    pub fn scaled(&self, scalar: &Scalar) -> Self {
        Self {
            c1: self.c1.scaled(scalar),
            c2: self.c2.scaled(scalar),
        }
    }

    pub fn decrypt(&self, secret_key: &Scalar) -> CurveElem {
        &self.c2 - &(self.c1.scaled(secret_key))
    }
}

impl ToString for Ciphertext {
    fn to_string(&self) -> String {
        format!("{}:{}", self.c1.as_base64(), self.c2.as_base64())
    }
}

impl TryFrom<&str> for Ciphertext {
    type Error = EncodingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut elems = Vec::new();
        for encoded in value.split(":") {
            let elem = CurveElem::try_from_base64(encoded).map_err(|_| EncodingError::CurveElem)?;
            elems.push(elem);
        }
        if elems.len() != 2 {
            Err(EncodingError::Length)
        } else {
            Ok(Self {
                c1: elems[0],
                c2: elems[1],
            })
        }
    }
}

pub type CurveElem = curve::CurveElem;

#[derive(Debug)]
pub struct CryptoContext {
    // rng: Arc<Mutex<ring::rand::SystemRandom>>,
    rng: Arc<Mutex<ChaCha20Rng>>,
    //g: CurveElem,
}

impl Clone for CryptoContext {
    fn clone(&self) -> Self {
        let rng = self.rng.clone();
        Self { rng }
    }
}

impl CryptoContext {
    pub fn new() -> Result<Self, CryptoError> {
        // Generate a ChaCha20 RNG from ring
        let rng = {
            let rng = ring::rand::SystemRandom::new();
            let mut buf = [0; 32];
            rng.fill(&mut buf)
                .map_err(|e| CryptoError::Unspecified(e))?;
            Arc::new(Mutex::new(ChaCha20Rng::from_seed(buf)))
        };

        Ok(Self { rng })
    }

    pub fn order() -> BigUint {
        BigUint::from_bytes_le(curve25519_dalek::constants::BASEPOINT_ORDER.as_bytes())
    }

    pub fn rng(&self) -> Arc<Mutex<ChaCha20Rng>> {
        self.rng.clone()
    }

    pub fn gen_elgamal_key_pair(&self) -> KeyPair {
        KeyPair::new(self)
    }

    pub fn random_scalar(&self) -> Scalar {
        // Generate 512 bit numbers and reduce mod group order
        let mut rng = self.rng.lock().unwrap();
        let mut buf = [0; 64];
        rng.fill_bytes(&mut buf);
        buf.into()
    }

    pub fn random_elem(&self) -> CurveElem {
        let mut rng = self.rng.lock().unwrap();
        curve::CurveElem(RistrettoPoint::random(rng.deref_mut()))
    }
}

#[cfg(test)]
mod test {
    use crate::curve::GENERATOR;
    use crate::elgamal::{Ciphertext, CryptoContext, PublicKey};
    use crate::util::AsBase64;
    use std::convert::TryFrom;

    #[test]
    fn test_pubkey_serde() {
        let ctx = CryptoContext::new().unwrap();
        let x = ctx.random_scalar();
        let y = PublicKey::new(GENERATOR.scaled(&x).into());

        let encoded = y.as_base64();
        let decoded = PublicKey::try_from_base64(encoded.as_str()).unwrap();
        assert_eq!(y, decoded);
    }

    #[test]
    fn test_ciphertext_serde() {
        let ctx = CryptoContext::new().unwrap();
        let x = ctx.random_scalar();
        let y = PublicKey::new(GENERATOR.scaled(&x).into());

        let r = ctx.random_scalar();
        let m = GENERATOR.scaled(&r);

        let r = ctx.random_scalar();

        let ct = y.encrypt(&m.into(), &r);

        let ct_str = ct.to_string();

        assert_eq!(ct, Ciphertext::try_from(ct_str.as_str()).unwrap());
    }

    #[test]
    fn test_homomorphism() {
        let ctx = CryptoContext::new().unwrap();
        let x = ctx.random_scalar();
        let y = PublicKey::new(GENERATOR.scaled(&x).into());

        // Construct two messages
        let r1 = ctx.random_scalar();
        let r2 = ctx.random_scalar();
        let m1 = GENERATOR.scaled(&r1);
        let m2 = GENERATOR.scaled(&r2);

        let r1 = ctx.random_scalar();
        let r2 = ctx.random_scalar();

        // Encrypt the messages
        let ct1 = y.encrypt(&m1.into(), &r1);
        let ct2 = y.encrypt(&m2.into(), &r2);

        // Compare the added encryption to the added messages
        let prod = ct1.add(&ct2);
        let decryption = prod.decrypt(&x);

        let combined = &m1 + &m2;

        assert_eq!(combined, decryption);
    }
}
