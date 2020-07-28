use cryptid::elgamal::{CryptoContext, PublicKey, CurveElem};
use cryptid::commit::PedersenCtx;
use cryptid::shuffle::Shuffle;
use cryptid::Scalar;
use std::time::Instant;
use rayon::prelude::*;

fn main() {
    let then = Instant::now();
    let mut ctx = CryptoContext::new().unwrap();
    let pubkey = PublicKey::new(ctx.random_elem());
    let n = 10000;
    let m = 5;

    let factors: Vec<_> = (0..n).map(|_| ctx.random_power()).collect();
    let cts: Vec<_> = factors.par_iter().map(|r| {
        (0..m).map(|_| pubkey.encrypt(&ctx, &CurveElem::try_encode(Scalar::from(16u32)).unwrap(), &r)).collect()
    }).collect();
    let now = Instant::now();
    println!("setup in {}ms", (now - then).as_millis());

    let then = Instant::now();
    let shuffle = Shuffle::new(ctx.clone(), cts.clone(), &pubkey).unwrap();
    let now = Instant::now();
    println!("shuffled {}x{} in {}ms", n, m, (now - then).as_millis());

    let commit_ctx = PedersenCtx::from_rng(ctx.clone(), n + 1);
    let then = Instant::now();
    let proof = shuffle.gen_proof(&mut ctx, &commit_ctx, &pubkey).unwrap();
    let now = Instant::now();
    println!("produced proof of shuffle for {}x{} in {}ms", n, m, (now - then).as_millis());

    let then = Instant::now();
    assert!(proof.verify(&mut ctx, &commit_ctx, shuffle.inputs(), shuffle.outputs(), &pubkey));
    let now = Instant::now();
    println!("verified proof of shuffle for {}x{} in {}ms", n, m, (now - then).as_millis());
}