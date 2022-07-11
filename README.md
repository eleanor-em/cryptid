## Cryptid: threshold ElGamal in Rust

## This code is for academic purposes ONLY. DO NOT USE IT IN PRACTICE.

Cryptid implements k-out-of-n threshold ElGamal key generation, encryption, and decryption as well as associated zero-knowledge proofs in Rust. It uses [curve25519-dalek](https://doc.dalek.rs/curve25519_dalek/) to provide a fast and secure implementaton of elliptic curve operations, and implements Pedersen secret sharing ("A Threshold Cryptosystem without a Trusted Party", Pedersen 1991) to generate the key and share it between trustees.

It is worth noting the caveat on key generation: we assume that parties are not allowed to cancel their participation in order to influence the randomness used. This is a limitation of the secret sharing method used, and this assumption was appropriate for the above use case. However, an extension of this project would ideally explore more resilient methods of key generation.

### Features
Cryptid includes

* key generation (not designed to be secure against cancellation!)
* encryption
* decryption
* Pedersen commitments, optionally including extra independent generators

as well as universally verifiable proofs:

* proof of plaintext knowledge (`PrfKnowPlaintext`)
* proof of equality for discrete logarithms (`PrfEqDlogs`)
* proof of decryption (`PrfDecryption`)
* proof of shuffle (`ShuffleProof`, based on [Verificatum](https://www.verificatum.org/)'s proof)

Cryptid was written for [PaperVote](https://github.com/eleanor-em/papervote/) because there was no existing fast-performing implementation that suited its needs.
