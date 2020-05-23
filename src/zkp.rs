use serde::{Serialize, Deserialize};

use crate::elgamal::{CryptoError, CryptoContext, Hasher};
use crate::curve::{Scalar, CurveElem};

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PrfKnowDlog {
    pub(crate) g: CurveElem,
    y: CurveElem,
    a: CurveElem,
    r: Scalar,
}

impl PrfKnowDlog {
    fn challenge(g: &CurveElem, y: &CurveElem, a: &CurveElem) -> Result<Scalar, CryptoError> {
        let mut hasher = Hasher::new();

        hasher.update(&g.as_bytes());
        hasher.update(&y.as_bytes());
        hasher.update(&a.as_bytes());

        hasher.finish_scalar()
    }

    /// Proves that we know x such that y = g^x
    pub fn new(ctx: &mut CryptoContext, g: &CurveElem, x: &Scalar, y: &CurveElem) -> Result<Self, CryptoError> {
        // Choose random commitment
        let z = ctx.random_power()?;
        let a = g.scaled(&z);
        // Calculate the challenge
        let c = Self::challenge(g, y, &a)?;
        let r = z + c * x;

        Ok(Self {
            g: g.clone(),
            y: y.clone(),
            a,
            r,
        })
    }

    pub fn verify(&self) -> Result<bool, CryptoError> {
        let c = Self::challenge(&self.g, &self.y, &self.a)?;
        Ok(self.g.scaled(&self.r) == &self.a + &self.y.scaled(&c))
    }
}

// TODO: this is a big-ass proof
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PrfEqDlogs {
    pub v: CurveElem,
    pub f: CurveElem,
    pub w: CurveElem,
    pub h: CurveElem,
    a: CurveElem,
    b: CurveElem,
    r: Scalar,
}

impl PrfEqDlogs {
    fn challenge(f: &CurveElem,
                 h: &CurveElem,
                 v: &CurveElem,
                 w: &CurveElem,
                 a: &CurveElem,
                 b: &CurveElem) -> Result<Scalar, CryptoError> {
        let mut hasher = Hasher::new();

        hasher.update(&f.as_bytes());
        hasher.update(&h.as_bytes());
        hasher.update(&v.as_bytes());
        hasher.update(&w.as_bytes());
        hasher.update(&a.as_bytes());
        hasher.update(&b.as_bytes());

        hasher.finish_scalar()
    }

    /// Prove that v = f^x and w = h^x, i.e. that dlog_f v = dlog_h w for a secret x
    pub fn new(ctx: &mut CryptoContext,
               f: &CurveElem,
               h: &CurveElem,
               v: &CurveElem,
               w: &CurveElem,
               x: &Scalar) -> Result<Self, CryptoError> {
        let z = ctx.random_power()?;
        let a = f.scaled(&z);
        let b = h.scaled(&z);
        let c = Self::challenge(&f, &h, &v, &w, &a, &b)?;
        let r = z + c * x;
        Ok(Self {
            v: v.clone(),
            f: f.clone(),
            w: w.clone(),
            h: h.clone(),
            a,
            b,
            r
        })
    }

    pub fn verify(&self) -> Result<bool, CryptoError> {
        let c = Self::challenge(&self.f, &self.h, &self.v, &self.w, &self.a, &self.b)?;
        Ok(self.f.scaled(&self.r) == &self.a + &self.v.scaled(&c)
            && self.h.scaled(&self.r) == &self.b + &self.w.scaled(&c))
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use crate::elgamal::CryptoContext;
    use crate::zkp::{PrfKnowDlog, PrfEqDlogs};

    #[test]
    fn test_exp_sane() {
        let mut ctx = CryptoContext::new();
        let a = ctx.random_power().unwrap();

        let x = ctx.g_to(&a);
        let y = ctx.g_to(&a);
        assert_eq!(x, y);
    }

    #[test]
    fn test_exp_sum() {
        let mut ctx = CryptoContext::new();
        let a = ctx.random_power().unwrap();
        let b = ctx.random_power().unwrap();
        let r = a + b;

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
        proof.r += &Scalar::one();

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
        proof.r += &Scalar::one();

        assert!(!proof.verify().unwrap());
    }
}
