use std::convert::TryFrom;
use std::error::Error;
use std::ops::Deref;

use ring::signature;
use ring::signature::KeyPair;

use crate::elgamal::CryptoError;

pub struct SigningPubKey<'a>(signature::UnparsedPublicKey<&'a [u8]>);

impl SigningPubKey<'_> {
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        self.0.verify(msg, signature.0.as_ref()).is_ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

pub struct SigningKeyPair {
    pkcs8: Vec<u8>,
    keypair: signature::Ed25519KeyPair,
}


impl SigningKeyPair {
    pub fn as_base64(&self) -> String {
        base64::encode(&self.pkcs8)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.keypair.sign(msg).as_ref().to_vec())
    }

    pub fn pub_key(&self) -> SigningPubKey {
        let pk = self.keypair.public_key().as_ref();
        SigningPubKey(signature::UnparsedPublicKey::new(&signature::ED25519, pk))
    }
}

impl TryFrom<&ring::rand::SystemRandom> for SigningKeyPair {
    type Error = CryptoError;

    fn try_from(rng: &ring::rand::SystemRandom) -> Result<Self, Self::Error> {
        // let rng = self.rng.lock().unwrap();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(rng.deref())
            .map(|doc| doc.as_ref().to_vec())
            .map_err(|e| CryptoError::Unspecified(e))?;

        let keypair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|e| CryptoError::KeyRejected(e))?;

        Ok(SigningKeyPair { pkcs8, keypair })
    }
}

impl TryFrom<Vec<u8>> for SigningKeyPair {
    type Error = Box<dyn Error>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let pkcs8 = base64::decode(value)?;
        let keypair = ed25519_try_from(&pkcs8)?;
        Ok(Self { pkcs8, keypair })
    }
}

fn ed25519_try_from(bytes: &[u8]) -> Result<signature::Ed25519KeyPair, CryptoError> {
    signature::Ed25519KeyPair::from_pkcs8(bytes)
        .map_err(|e| CryptoError::KeyRejected(e))
}

#[cfg(test)]
mod test {
    use crate::elgamal::CryptoContext;
    use crate::sign::SigningKeyPair;
    use std::convert::TryFrom;

    #[test]
    fn test_keypair_serde() {
        let mut ctx = CryptoContext::new();
        let message = "hello world".as_bytes();

        let keypair = ctx.gen_ed25519_key_pair().unwrap();
        let sig1 = keypair.sign(message);
        assert!(keypair.pub_key().verify(message, &sig1));

        let encoded = keypair.as_base64();
        let decoded = SigningKeyPair::try_from(encoded.into_bytes()).unwrap();
        let sig2 = decoded.sign(message);
        assert!(keypair.pub_key().verify(message, &sig2));

        assert_eq!(sig1, sig2);
    }
}