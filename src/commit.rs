use std::fmt;
use std::fmt::{Debug, Display};

use serde::export::Formatter;

use crate::elgamal::CurveElem;
use crate::{Hasher, AsBase64};
use crate::Scalar;
use crate::threshold::EncodingError;
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

        let g = RistrettoPoint::from_uniform_bytes(&Hasher::sha_512()
            .and_update(seed)
            .and_update(&counter.to_be_bytes())
            .finish_64_bytes().unwrap())
            .into();

        counter += 1;

        let h = RistrettoPoint::from_uniform_bytes(&Hasher::sha_512()
            .and_update(seed)
            .and_update(&counter.to_be_bytes())
            .finish_64_bytes().unwrap())
            .into();
        counter += 1;

        let generators = (0..num_generators).map(|_| {
            let bytes = Hasher::sha_512()
                .and_update(seed)
                .and_update(&counter.to_be_bytes())
                .finish_64_bytes().unwrap();
            counter += 1;

            RistrettoPoint::from_uniform_bytes(&bytes).into()
        }).collect();

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
            value: self.g.scaled(&x) + self.h.scaled(&r)
        }
    }
}

/// A commitment to a pair of values, given a pair of generators chosen by a `PedersenCtx`.
#[derive(PartialEq, Eq, Clone)]
pub struct Commitment {
    g: CurveElem,
    h: CurveElem,
    value: CurveElem,
}

impl Display for Commitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.g.as_base64(), self.h.as_base64(), self.value.as_base64())
    }
}

impl Debug for Commitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl TryFrom<String> for Commitment {
    type Error = EncodingError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let elems: Vec<_> = value.split(":").collect();
        if elems.len() != 3 {
            return Err(EncodingError::Length);
        }

        let mut elems: Vec<_> = elems.into_iter()
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
    // Returns whether this commitment's parameters match the given commitment context's parameters
    pub fn matches(&self, ctx: &PedersenCtx) -> bool {
        self.g == ctx.g && self.h == ctx.h
    }

    pub fn validate(&self, x: &Scalar, r: &Scalar) -> bool {
        self.value == self.g.scaled(&x) + self.h.scaled(&r)
    }
}


#[cfg(test)]
mod tests {
    use crate::elgamal::CryptoContext;
    use crate::commit::{PedersenCtx, Commitment};
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

        assert!(commitment.validate(&x, &r));
        assert_eq!(commitment.validate(&x_prime, &r_prime), false);
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
        let de: Commitment = Commitment::try_from(ser).unwrap();

        assert_eq!(commitment, de);
        assert!(de.validate(&x, &r));
    }
}