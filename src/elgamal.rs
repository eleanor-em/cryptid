use std::convert::{TryFrom, TryInto};
use std::fmt::{Formatter, Display};
use std::hash::Hash;
use std::sync::{Mutex, Arc};

use ring::rand::SecureRandom;
use serde::{Serialize, Deserialize};

use crate::Scalar;
use crate::{curve, CryptoError};
use crate::threshold::EncodingError;
use crate::util::{AsBase64, SCALAR_MAX_BYTES};
use num_bigint::BigUint;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PublicKey {
    y: CurveElem,
}

impl PublicKey {
    pub fn new(value: CurveElem) -> Self {
        Self { y: value }
    }

    pub fn encrypt(&self, ctx: &CryptoContext, m: &CurveElem, r: &Scalar) -> Ciphertext {
        let c1 = ctx.g_to(r);
        let c2 = m + &self.y.scaled(r);
        Ciphertext { c1, c2 }
    }

    pub fn rerand(self, ctx: &CryptoContext, ct: &Ciphertext, r: &Scalar) -> Ciphertext {
        let c1 = &ct.c1 + &ctx.g_to(r);
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
            y: CurveElem::try_from_base64(encoded)?
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
    fn new(ctx: &mut CryptoContext) -> Result<Self, CryptoError> {
        let x_i = ctx.random_power()?;
        let y_i = ctx.g_to(&x_i);
        let pk = PublicKey::new(y_i);
        Ok(Self { pk, x_i, y_i })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

    pub fn decrypt(&self, secret_key: &Scalar) -> CurveElem {
        &self.c2 - &(self.c1.scaled(secret_key))
    }
}

impl ToString for Ciphertext {
    fn to_string(&self) -> String {
        format!("{}:{}", self.c1.as_base64(), self.c2.as_base64())
    }
}

impl TryFrom<String> for Ciphertext {
    type Error = EncodingError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
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
    rng: Arc<Mutex<ring::rand::SystemRandom>>,
    g: CurveElem,
}

impl Clone for CryptoContext {
    fn clone(&self) -> Self {
        let rng = self.rng.clone();
        let g = self.g.clone();
        Self { rng, g }
    }
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

    pub fn order() -> BigUint {
        BigUint::from_bytes_le(curve25519_dalek::constants::BASEPOINT_ORDER.as_bytes())
    }

    pub fn rng(&self) -> Arc<Mutex<ring::rand::SystemRandom>> {
        self.rng.clone()
    }

    pub fn generator(&self) -> CurveElem {
        self.g.clone()
    }

    pub fn gen_elgamal_key_pair(&mut self) -> Result<KeyPair, CryptoError> {
        KeyPair::new(self)
    }

    pub fn random_power(&mut self) -> Result<Scalar, CryptoError> {
        let rng = self.rng.lock().unwrap();
        let mut buf = [0; 32];
        rng.fill(&mut buf)
            .map_err(|e| CryptoError::Unspecified(e))?;
        Ok(buf.into())
    }

    pub fn random_elem(&mut self) -> Result<CurveElem, CryptoError> {
        let rng = self.rng.lock().unwrap();

        let mut buf = [0; SCALAR_MAX_BYTES];
        rng.fill(&mut buf)
            .map_err(|e| CryptoError::Unspecified(e))?;

        let mut final_buf = [0u8; 32];
        for (i, byte) in buf.iter().enumerate() {
            final_buf[i] = *byte;
        }

        let s: Scalar = final_buf.into();
        s.try_into()
    }

    pub fn g_to(&self, power: &Scalar) -> CurveElem {
        self.g.scaled(power)
    }
}

#[cfg(test)]
mod test {
    use crate::elgamal::{CryptoContext, PublicKey, Ciphertext};
    use crate::util::AsBase64;
    use std::convert::TryFrom;

    #[test]
    fn test_pubkey_serde() {
        let mut ctx = CryptoContext::new();
        let x = ctx.random_power().unwrap();
        let y = PublicKey::new(ctx.g_to(&x).into());

        let encoded = y.as_base64();
        let decoded = PublicKey::try_from_base64(encoded.as_str()).unwrap();
        assert_eq!(y, decoded);
    }

    #[test]
    fn test_ciphertext_serde() {
        let mut ctx = CryptoContext::new();
        let x = ctx.random_power().unwrap();
        let y = PublicKey::new(ctx.g_to(&x).into());

        let r = ctx.random_power().unwrap();
        let m = ctx.g_to(&r);

        let r = ctx.random_power().unwrap();

        let ct = y.encrypt(&ctx, &m.into(), &r);

        assert_eq!(ct, Ciphertext::try_from(ct.to_string()).unwrap());
    }

    #[test]
    fn test_homomorphism() {
        let mut ctx = CryptoContext::new();
        let x = ctx.random_power().unwrap();
        let y = PublicKey::new(ctx.g_to(&x).into());

        // Construct two messages
        let r1 = ctx.random_power().unwrap();
        let r2 = ctx.random_power().unwrap();
        let m1 = ctx.g_to(&r1);
        let m2 = ctx.g_to(&r2);

        let r1 = ctx.random_power().unwrap();
        let r2 = ctx.random_power().unwrap();

        // Encrypt the messages
        let ct1 = y.encrypt(&ctx, &m1.into(), &r1);
        let ct2 = y.encrypt(&ctx, &m2.into(), &r2);

        // Compare the added encryption to the added messages
        let prod = ct1.add(&ct2);
        // let decryption = &prod.c2 - &(prod.c1.scaled(&x));
        let decryption = prod.decrypt(&x);

        let combined = &m1 + &m2;

        assert_eq!(combined, decryption);
    }
}