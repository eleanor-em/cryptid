use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Debug, Display};

use std::fmt::Formatter;

use crate::elgamal::{Ciphertext, CurveElem};
use crate::threshold::EncodingError;
use crate::Scalar;
use crate::{AsBase64, Hasher};
use curve25519_dalek::ristretto::RistrettoPoint;
use std::convert::TryFrom;

/// A Pedersen commitment context, composed of a pair of independent, verifiably-chosen
/// group generators.
#[derive(Clone)]
pub struct PedersenCtx {
    pub(crate) g: CurveElem,
    pub(crate) h: CurveElem,
}

impl PedersenCtx {
    /// Creates a Pedersen commitment context, with a number of additional generators for extended
    /// commitments. Returns a pair containing the context and a vector of extra generators.
    ///
    /// Generators are chosen verifiably by hashing the seed.
    pub fn with_generators(seed: &[u8], num_generators: usize) -> (PedersenCtx, Vec<CurveElem>) {
        let mut counter: usize = 0;

        let g = RistrettoPoint::from_uniform_bytes(
            &Hasher::sha_512()
                .and_update(seed)
                .and_update(&counter.to_be_bytes())
                .finish_64_bytes()
                .unwrap(),
        )
        .into();

        counter += 1;

        let h = RistrettoPoint::from_uniform_bytes(
            &Hasher::sha_512()
                .and_update(seed)
                .and_update(&counter.to_be_bytes())
                .finish_64_bytes()
                .unwrap(),
        )
        .into();
        counter += 1;

        let generators = (0..num_generators)
            .map(|_| {
                let bytes = Hasher::sha_512()
                    .and_update(seed)
                    .and_update(&counter.to_be_bytes())
                    .finish_64_bytes()
                    .unwrap();
                counter += 1;

                RistrettoPoint::from_uniform_bytes(&bytes).into()
            })
            .collect();

        let ctx = Self { g, h };
        (ctx, generators)
    }

    /// Create a new Pedersen commitment context without any extra generators.
    pub fn new(seed: &[u8]) -> Self {
        Self::with_generators(seed, 0).0
    }

    /// Commit to the chosen pair of values.
    pub fn commit(&self, x: &Scalar, r: &Scalar) -> Commitment {
        Commitment {
            g: self.g.clone(),
            h: self.h.clone(),
            value: self.g.scaled(&x) + self.h.scaled(&r),
        }
    }

    pub fn commit_ct(&self, ct: &Ciphertext, rs: &(Scalar, Scalar)) -> CtCommitment {
        CtCommitment {
            a: self.commit(&ct.c1.into(), &rs.0),
            b: self.commit(&ct.c2.into(), &rs.1),
        }
    }
}

/// A commitment to a pair of values, given a pair of generators chosen by a `PedersenCtx`.
#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Commitment {
    g: CurveElem,
    h: CurveElem,
    value: CurveElem,
}

impl Display for Commitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.g.as_base64(),
            self.h.as_base64(),
            self.value.as_base64()
        )
    }
}

impl Debug for Commitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl TryFrom<&str> for Commitment {
    type Error = EncodingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let elems: Vec<_> = value.split(":").collect();
        if elems.len() != 3 {
            return Err(EncodingError::Length);
        }

        let mut elems: Vec<_> = elems
            .into_iter()
            .map(|s| CurveElem::try_from_base64(s))
            .collect::<Result<_, _>>()
            .map_err(|_| EncodingError::Base64)?;

        // Remove in reverse order to avoid pointless clones
        let value = elems.remove(2);
        let h = elems.remove(1);
        let g = elems.remove(0);

        Ok(Self { g, h, value })
    }
}

impl Commitment {
    pub fn validate(&self, commit_ctx: &PedersenCtx, x: &Scalar, r: &Scalar) -> bool {
        self.g == commit_ctx.g
            && self.h == commit_ctx.h
            && self.value == self.g.scaled(&x) + self.h.scaled(&r)
    }
}

#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CtCommitment {
    a: Commitment,
    b: Commitment,
}

impl Display for CtCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.a.to_string(), self.b.to_string())
    }
}

impl Debug for CtCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl TryFrom<&str> for CtCommitment {
    type Error = EncodingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let elems: Vec<_> = value.split("-").collect();
        if elems.len() != 2 {
            return Err(EncodingError::Length);
        }

        let mut elems: Vec<_> = elems
            .into_iter()
            .map(|s| Commitment::try_from(s))
            .collect::<Result<_, _>>()
            .map_err(|_| EncodingError::Commitment)?;

        // Remove in reverse order to avoid pointless clones
        let b = elems.remove(1);
        let a = elems.remove(0);

        Ok(Self { a, b })
    }
}

impl CtCommitment {
    pub fn validate(
        &self,
        commit_ctx: &PedersenCtx,
        ct: &Ciphertext,
        rs: (&Scalar, &Scalar),
    ) -> bool {
        self.a.validate(commit_ctx, &ct.c1.into(), rs.0)
            && self.b.validate(commit_ctx, &ct.c2.into(), rs.1)
    }
}

#[cfg(test)]
mod tests {
    use crate::commit::{Commitment, CtCommitment, PedersenCtx};
    use crate::elgamal::{CryptoContext, PublicKey};
    use rand::RngCore;
    use std::convert::TryFrom;

    #[test]
    fn test_commit() {
        let ctx = CryptoContext::new().unwrap();
        let mut seed = [0; 64];
        let rng = ctx.rng();
        {
            let mut rng = rng.lock().unwrap();
            rng.fill_bytes(&mut seed);
        }
        let commit_ctx = PedersenCtx::new(&seed);

        let x = ctx.random_scalar();
        let r = ctx.random_scalar();
        let x_prime = ctx.random_scalar();
        let r_prime = ctx.random_scalar();
        let commitment = commit_ctx.commit(&x, &r);

        assert!(commitment.validate(&commit_ctx, &x, &r));
        assert_eq!(commitment.validate(&commit_ctx, &x_prime, &r_prime), false);
    }

    #[test]
    fn test_commit_serde() {
        let ctx = CryptoContext::new().unwrap();
        let mut seed = [0; 64];
        let rng = ctx.rng();
        {
            let mut rng = rng.lock().unwrap();
            rng.fill_bytes(&mut seed);
        }
        let commit_ctx = PedersenCtx::new(&seed);

        let x = ctx.random_scalar();
        let r = ctx.random_scalar();
        let commitment = commit_ctx.commit(&x, &r);

        let ser = commitment.to_string();
        let de = Commitment::try_from(ser.as_str()).unwrap();

        assert_eq!(commitment, de);
        assert!(de.validate(&commit_ctx, &x, &r));
    }

    #[test]
    fn test_ct_commit() {
        let ctx = CryptoContext::new().unwrap();
        let pk = PublicKey::new(ctx.random_elem());

        let mut seed = [0; 64];
        let rng = ctx.rng();
        {
            let mut rng = rng.lock().unwrap();
            rng.fill_bytes(&mut seed);
        }
        let commit_ctx = PedersenCtx::new(&seed);

        let x = ctx.random_elem();
        let r = ctx.random_scalar();
        let ct = pk.encrypt(&x, &r);

        let x_prime = ctx.random_elem();
        let r_prime = ctx.random_scalar();
        let ct_prime = pk.encrypt(&x_prime, &r_prime);

        let r1 = ctx.random_scalar();
        let r2 = ctx.random_scalar();
        let r1_prime = ctx.random_scalar();
        let r2_prime = ctx.random_scalar();

        let commitment = commit_ctx.commit_ct(&ct, &(r1, r2));

        assert!(commitment.validate(&commit_ctx, &ct, (&r1, &r2)));
        assert_eq!(
            commitment.validate(&commit_ctx, &ct_prime, (&r1_prime, &r2_prime)),
            false
        );
    }

    #[test]
    fn test_ct_commit_serde() {
        let ctx = CryptoContext::new().unwrap();
        let pk = PublicKey::new(ctx.random_elem());

        let mut seed = [0; 64];
        let rng = ctx.rng();
        {
            let mut rng = rng.lock().unwrap();
            rng.fill_bytes(&mut seed);
        }
        let commit_ctx = PedersenCtx::new(&seed);

        let x = ctx.random_elem();
        let r = ctx.random_scalar();
        let ct = pk.encrypt(&x, &r);

        let r1 = ctx.random_scalar();
        let r2 = ctx.random_scalar();
        let commitment = commit_ctx.commit_ct(&ct, &(r1, r2));

        let ser = commitment.to_string();
        let de = CtCommitment::try_from(ser.as_str()).unwrap();

        assert_eq!(commitment, de);
        assert!(de.validate(&commit_ctx, &ct, (&r1, &r2)));
    }
}
