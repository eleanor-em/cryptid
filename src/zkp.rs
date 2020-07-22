use serde::{Serialize, Deserialize};

use crate::{CryptoError, Hasher, Scalar};
use crate::curve::CurveElem;
use crate::elgamal::CryptoContext;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PrfKnowDlog {
    pub(crate) base: CurveElem,
    result: CurveElem,
    blinded_base: CurveElem,
    r: Scalar,
}

impl PrfKnowDlog {
    fn challenge(base: &CurveElem, result: &CurveElem, blinded_base: &CurveElem) -> Scalar {
        Hasher::sha_256()
            .and_update(&base.as_bytes())
            .and_update(&result.as_bytes())
            .and_update(&blinded_base.as_bytes())
            .finish_scalar()
    }

    /// Proves that we know x such that y = g^x
    pub fn new(ctx: &mut CryptoContext, base: &CurveElem, power: &Scalar, result: &CurveElem) -> Result<Self, CryptoError> {
        // Choose random commitment
        let z = ctx.random_power()?;
        let blinded = base.scaled(&z);
        // Calculate the challenge
        let c = Self::challenge(base, result, &blinded);
        let r = Scalar(z.0 + c.0 * power.0);

        Ok(Self {
            base: base.clone(),
            result: result.clone(),
            blinded_base: blinded,
            r,
        })
    }

    pub fn verify(&self) -> Result<bool, CryptoError> {
        let c = Self::challenge(&self.base, &self.result, &self.blinded_base);
        Ok(self.base.scaled(&self.r) == &self.blinded_base + &self.result.scaled(&c))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PrfEqDlogs {
    pub result1: CurveElem,
    pub base1: CurveElem,
    pub result2: CurveElem,
    pub base2: CurveElem,
    blinded_base1: CurveElem,
    blinded_base2: CurveElem,
    r: Scalar,
}

impl PrfEqDlogs {
    fn challenge(f: &CurveElem,
                 h: &CurveElem,
                 v: &CurveElem,
                 w: &CurveElem,
                 a: &CurveElem,
                 b: &CurveElem) -> Scalar {
        Hasher::sha_256()
            .and_update(&f.as_bytes())
            .and_update(&h.as_bytes())
            .and_update(&v.as_bytes())
            .and_update(&w.as_bytes())
            .and_update(&a.as_bytes())
            .and_update(&b.as_bytes())
            .finish_scalar()
    }

    /// Prove that v = f^x and w = h^x, i.e. that dlog_f v = dlog_h w for a secret x
    pub fn new(ctx: &mut CryptoContext,
               base1: &CurveElem,
               base2: &CurveElem,
               result1: &CurveElem,
               result2: &CurveElem,
               power: &Scalar) -> Result<Self, CryptoError> {
        let z = ctx.random_power()?;
        let blinded_base1 = base1.scaled(&z);
        let blinded_base2 = base2.scaled(&z);
        let c = Self::challenge(&base1, &base2, &result1, &result2, &blinded_base1, &blinded_base2);
        let r = Scalar(z.0 + c.0 * power.0);
        Ok(Self {
            result1: result1.clone(),
            base1: base1.clone(),
            result2: result2.clone(),
            base2: base2.clone(),
            blinded_base1,
            blinded_base2,
            r
        })
    }

    pub fn verify(&self) -> Result<bool, CryptoError> {
        let c = Self::challenge(&self.base1, &self.base2, &self.result1, &self.result2, &self.blinded_base1, &self.blinded_base2);
        Ok(self.base1.scaled(&self.r) == &self.blinded_base1 + &self.result1.scaled(&c)
            && self.base2.scaled(&self.r) == &self.blinded_base2 + &self.result2.scaled(&c))
    }
}

#[cfg(test)]
mod tests {
    use crate::elgamal::CryptoContext;
    use crate::zkp::{PrfKnowDlog, PrfEqDlogs};
    use crate::{DalekScalar, Scalar};

    #[test]
    fn test_exp_sum() {
        let mut ctx = CryptoContext::new();
        let a = ctx.random_power().unwrap();
        let b = ctx.random_power().unwrap();
        let r = Scalar(a.0 + b.0);

        let x = ctx.g_to(&r);
        let y = ctx.g_to(&a) + ctx.g_to(&b);
        assert_eq!(x, y);
    }

    #[test]
    fn test_prf_know_dlog_complete() {
        let mut ctx = CryptoContext::new();
        let x = ctx.random_power().unwrap();
        let y = ctx.g_to(&x);
        let g = ctx.generator();
        let proof = PrfKnowDlog::new(&mut ctx, &g, &x, &y).unwrap();

        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_prof_know_dlog_sound() {
        let mut ctx = CryptoContext::new();
        let x = ctx.random_power().unwrap();
        let y = ctx.g_to(&x);
        let g = ctx.generator();
        let mut proof = PrfKnowDlog::new(&mut ctx, &g, &x, &y).unwrap();
        proof.r.0 += &DalekScalar::one();

        assert!(!proof.verify().unwrap());
    }

    #[test]
    fn test_prf_eq_dlogs_complete() {
        let mut ctx = CryptoContext::new();
        let x1 = ctx.random_power().unwrap();
        let f = ctx.g_to(&x1);
        let x2 = ctx.random_power().unwrap();
        let h = ctx.g_to(&x2);

        let x = ctx.random_power().unwrap();
        let v = f.scaled(&x);
        let w = h.scaled(&x);

        let proof = PrfEqDlogs::new(&mut ctx, &f, &h, &v, &w, &x).unwrap();
        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_prf_eq_dlogs_sound() {
        let mut ctx = CryptoContext::new();
        let x1 = ctx.random_power().unwrap();
        let f = ctx.g_to(&x1);
        let x2 = ctx.random_power().unwrap();
        let h = ctx.g_to(&x2);

        let x = ctx.random_power().unwrap();
        let v = f.scaled(&x);
        let w = h.scaled(&x);

        let mut proof = PrfEqDlogs::new(&mut ctx, &f, &h, &v, &w, &x).unwrap();
        proof.r.0 += &DalekScalar::one();

        assert!(!proof.verify().unwrap());
    }
}
