use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use serde::{Deserialize, Serialize};

use crate::threshold::EncodingError;
use crate::{curve, CryptoError};
use crate::{AsBase64, Scalar};
use curve::GENERATOR;
use rand::{CryptoRng, Rng};

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PublicKey {
    pub(crate) y: CurveElem,
}

impl PublicKey {
    pub fn new(value: CurveElem) -> Self {
        Self { y: value }
    }

    /// Encrypt a message. The message cannot have any trailing null (0u8) bytes, nor can it be over 32 bytes long
    pub fn encrypt<R: Rng + CryptoRng>(&self, rng: &mut R, message: &[u8]) -> Ciphertext {
        if message.len() != 0 && message[message.len() - 1] == 0 {
            // TODO: use a result
            panic!("Cannot encrypt message with trailing null (0u8) bytes")
        }

        let n = message.len();
        let mut array = [0; 32];
        array[..n].copy_from_slice(&message);

        let m = CurveElem::try_encode(Scalar::from(array)).unwrap();

        let r = Scalar::random(rng);

        self.encrypt_curve(&m, &r)
    }

    pub fn encrypt_curve(&self, m: &CurveElem, r: &Scalar) -> Ciphertext {
        let c1 = GENERATOR.scaled(r);
        let c2 = m + &self.y.scaled(r);
        Ciphertext { c1, c2 }
    }

    /// Re-encrypt the ciphertext, replacing the random factors in the ciphertext with `r`.
    /// The encrypted message is the same, but an outside observer cannot tell that the two ciphertexts are related.
    pub fn rerand(self, ct: &Ciphertext, r: &Scalar) -> Ciphertext {
        let c1 = ct.c1 + GENERATOR.scaled(r);
        let c2 = ct.c2 + self.y.scaled(r);
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

#[allow(clippy::derive_hash_xor_eq)]
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
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let x_i = Scalar::random(rng);
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
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }

    pub fn scaled(&self, scalar: &Scalar) -> Self {
        Self {
            c1: self.c1.scaled(scalar),
            c2: self.c2.scaled(scalar),
        }
    }

    pub fn decrypt(&self, secret_key: &Scalar) -> Vec<u8> {
        // TODO: Use Result instead of unwrap
        let decrypted =  self.decrypt_curve(secret_key).decoded().unwrap().to_bytes().to_vec();
        let trim_pos = decrypted.iter().rposition(|b| *b != 0);

        match trim_pos {
            None => vec![],
            Some(pos) => decrypted[..pos + 1].to_vec()
        }
    }

    pub fn decrypt_curve(&self, secret_key: &Scalar) -> CurveElem {
        self.c2 - (self.c1.scaled(secret_key))
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
        for encoded in value.split(':') {
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

#[cfg(test)]
mod test {
    use crate::curve::GENERATOR;
    use crate::elgamal::{Ciphertext, PublicKey};
    use crate::util::AsBase64;
    use crate::Scalar;
    use std::convert::TryFrom;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = rand::thread_rng();
        let x = Scalar::random(&mut rng);
        let y = PublicKey::new(GENERATOR.scaled(&x));

        // Construct a messages
        let message = "ABC123";

        let ciphertext = y.encrypt(&mut rng, message.as_bytes());

        let decrypted_bytes = ciphertext.decrypt(&x);
        let decrypted = std::str::from_utf8(&decrypted_bytes).unwrap();

        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_pubkey_serde() {
        let mut rng = rand::thread_rng();
        let x = Scalar::random(&mut rng);
        let y = PublicKey::new(GENERATOR.scaled(&x));

        let encoded = y.as_base64();
        let decoded = PublicKey::try_from_base64(encoded.as_str()).unwrap();
        assert_eq!(y, decoded);
    }

    #[test]
    fn test_ciphertext_serde() {
        let mut rng = rand::thread_rng();
        let x = Scalar::random(&mut rng);
        let y = PublicKey::new(GENERATOR.scaled(&x));

        let r = Scalar::random(&mut rng);
        let m = GENERATOR.scaled(&r);

        let r = Scalar::random(&mut rng);

        let ct = y.encrypt_curve(&m, &r);

        let ct_str = ct.to_string();

        assert_eq!(ct, Ciphertext::try_from(ct_str.as_str()).unwrap());
    }

    #[test]
    fn test_homomorphism() {
        let mut rng = rand::thread_rng();
        let x = Scalar::random(&mut rng);
        let y = PublicKey::new(GENERATOR.scaled(&x));

        // Construct two messages
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let m1 = GENERATOR.scaled(&r1);
        let m2 = GENERATOR.scaled(&r2);

        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);

        // Encrypt the messages
        let ct1 = y.encrypt_curve(&m1, &r1);
        let ct2 = y.encrypt_curve(&m2, &r2);

        // Compare the added encryption to the added messages
        let prod = ct1.add(&ct2);
        let decryption = prod.decrypt_curve(&x);

        let combined = m1 + m2;

        assert_eq!(combined, decryption);
    }
}
