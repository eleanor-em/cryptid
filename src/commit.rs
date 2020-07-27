use std::fmt;
use std::fmt::{Debug, Display};

use serde::{Serialize, Deserialize};
use serde::export::Formatter;

use std::convert::TryFrom;
use crate::elgamal::{CryptoContext, CurveElem};
use crate::{Hasher, AsBase64};
use crate::Scalar;
use crate::threshold::EncodingError;

#[derive(Clone)]
pub struct PedersenCtx {
    base: CurveElem,
    generators: Vec<CurveElem>,
}

impl PedersenCtx {
    pub fn new(seed: &[u8], ctx: CryptoContext, num_generators: usize) -> Self {
        let mut generators = Vec::new();
        let mut count: u128 = 0;

        while generators.len() < num_generators {
            // SHA-512 for 64 bytes of entropy
            let bytes = Hasher::sha_512()
                .and_update(seed)
                .and_update(&count.to_be_bytes())
                .finish_vec();

            let s = Scalar::try_from(bytes).unwrap();
            if let Ok(elem) = CurveElem::try_from(s) {
                generators.push(elem);
            }

            count += 1;
        }

        Self {
            base: ctx.generator(),
            generators
        }
    }

    pub fn commit(&self, xs: &[Scalar], rs: &[Scalar]) -> Option<Vec<Commitment>> {
        if xs.len() != rs.len() || xs.len() > self.generators.len() || rs.len() > self.generators.len() {
            return None;
        }

        let mut commitments = Vec::new();
        for i in 0..xs.len() {
            let h = self.generators[i];
            commitments.push(Commitment {
                index: i,
                g: self.base.clone(),
                h: h.clone(),
                value: self.base.scaled(&xs[i]) + h.scaled(&rs[i]),
            });
        }

        Some(commitments)
    }

    pub fn try_parse_commitment(&self, value: &str) -> Result<Commitment, EncodingError> {
        let elems: Vec<_> = value.split(":").collect();
        if elems.len() != 2 {
            return Err(EncodingError::Length);
        }

        let index = elems[0].parse::<usize>().map_err(|_| EncodingError::Num)?;
        if index >= self.generators.len() {
            return Err(EncodingError::Verify);
        }

        let value = CurveElem::try_from_base64(&elems[1]).map_err(|_| EncodingError::Base64)?;
        let g = self.base.clone();
        let h = self.generators[index].clone();
        Ok(Commitment { index, g, h, value })
    }
}

#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Commitment {
    index: usize,
    g: CurveElem,
    h: CurveElem,
    value: CurveElem,
}

impl Display for Commitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.index, self.value.as_base64())
    }
}

impl Debug for Commitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Commitment {
    pub fn validate(&self, x: &Scalar, r: &Scalar) -> bool {
        self.value == self.g.scaled(&x) + self.h.scaled(&r)
    }
}



#[cfg(test)]
mod tests {
    use crate::elgamal::CryptoContext;
    use crate::commit::{PedersenCtx, Commitment};
    use ring::rand::SecureRandom;

    #[test]
    fn test_commit() {
        let mut ctx = CryptoContext::new();
        let mut seed = [0; 64];
        let rng = ctx.rng();
        {
            let rng = rng.lock().unwrap();
            rng.fill(&mut seed).unwrap();
        }

        const N: usize = 5;
        let commit_ctx = PedersenCtx::new(&seed, ctx.clone(), N);
        let xs: Vec<_> = (0..N).map(|_| ctx.random_power().unwrap()).collect();
        let rs: Vec<_> = (0..N).map(|_| ctx.random_power().unwrap()).collect();

        let commitment = commit_ctx.commit(&xs, &rs).unwrap();

        assert!(commitment.iter().enumerate().all(|(i, c)| c.validate(&xs[i], &rs[i])));

        let xs: Vec<_> = (0..N).map(|_| ctx.random_power().unwrap()).collect();
        let rs: Vec<_> = (0..N).map(|_| ctx.random_power().unwrap()).collect();
        assert!(!commitment.iter().enumerate().all(|(i, c)| c.validate(&xs[i], &rs[i])));
    }

    #[test]
    fn test_commit_serde() {
        let mut ctx = CryptoContext::new();
        let mut seed = [0; 64];
        let rng = ctx.rng();
        {
            let rng = rng.lock().unwrap();
            rng.fill(&mut seed).unwrap();
        }

        const N: usize = 5;
        let commit_ctx = PedersenCtx::new(&seed, ctx.clone(), N);
        let xs: Vec<_> = (0..N).map(|_| ctx.random_power().unwrap()).collect();
        let rs: Vec<_> = (0..N).map(|_| ctx.random_power().unwrap()).collect();

        let commitment = commit_ctx.commit(&xs, &rs).unwrap();

        let ser = serde_json::to_string(&commitment).unwrap();
        let de: Vec<Commitment> = serde_json::from_str(&ser).unwrap();
        assert_eq!(commitment, de);
        assert!(de.iter().enumerate().all(|(i, c)| c.validate(&xs[i], &rs[i])));
    }
}