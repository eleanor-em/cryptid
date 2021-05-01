use cryptid::commit::PedersenCtx;
use cryptid::elgamal::{CryptoContext, CurveElem, PublicKey};
use cryptid::shuffle::Shuffle;
use cryptid::Scalar;
use rand::RngCore;
use rayon::prelude::*;
use std::time::Instant;

fn main() {
    let then = Instant::now();
    let ctx = CryptoContext::new().unwrap();
    let pubkey = PublicKey::new(ctx.random_elem());
    let n = 100000;
    let m = 6;

    let factors: Vec<_> = (0..n).map(|_| ctx.random_scalar()).collect();
    let cts: Vec<_> = factors
        .par_iter()
        .map(|r| {
            (0..m)
                .map(|_| pubkey.encrypt(&CurveElem::try_encode(Scalar::from(16u32)).unwrap(), &r))
                .collect()
        })
        .collect();
    let now = Instant::now();
    println!("setup in {}ms", (now - then).as_millis());

    let then = Instant::now();
    let shuffle = Shuffle::new(ctx.clone(), cts.clone(), &pubkey).unwrap();
    let now = Instant::now();
    println!("shuffled {}x{} in {}ms", n, m, (now - then).as_millis());

    let mut seed = [0; 64];
    let rng = ctx.rng();
    {
        let mut rng = rng.lock().unwrap();
        rng.fill_bytes(&mut seed);
    }
    let (commit_ctx, generators) = PedersenCtx::with_generators(&seed, n);
    let then = Instant::now();
    let proof = shuffle
        .gen_proof(&ctx, &commit_ctx, &generators, &pubkey)
        .unwrap();
    let now = Instant::now();
    println!(
        "produced proof of shuffle for {}x{} in {}ms",
        n,
        m,
        (now - then).as_millis()
    );

    let then = Instant::now();
    assert!(proof.verify(
        &commit_ctx,
        &generators,
        shuffle.inputs(),
        shuffle.outputs(),
        &pubkey
    ));
    let now = Instant::now();
    println!(
        "verified proof of shuffle for {}x{} in {}ms",
        n,
        m,
        (now - then).as_millis()
    );
}
