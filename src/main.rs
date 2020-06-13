//! A modular implementation of the [DSS'20](https://eprint.iacr.org/2020/403.pdf).
//! The reason for why this is written in such a generic way is twofold: First, I
//! wanted to familiarize myself with more sophisticated Rust concepts and figured
//! that a hands-on approach would be the best way to do so. Second, the long-term
//! plan is to keep extending this to a library providing many modern cryptographic
//! primitives as time permits.

/// Chameleon hashes.
pub mod chameleon_hashing;
/// Encryption schemes.
pub mod encryption;
/// Convenience functions for hashing.
pub mod hashing;
/// Zero-knowledge proofs, Sigma protocols, Fiat-Shamir transformation, Compositions, ...
pub mod zkproofs;

use rand::thread_rng;
use sha2::Sha512;

use crate::chameleon_hashing::dss_pkc_20::DssPkc20;
use crate::chameleon_hashing::ChameleonHash;
use crate::encryption::elgamal::ElGamalMessage;

fn main() {
    let (sk, pk) = DssPkc20::key_gen(32, &mut thread_rng()).unwrap();

    let msg_original = ElGamalMessage::from_string::<Sha512>("Original".to_string());
    let (h, r) =
        DssPkc20::hash(&pk, msg_original.clone(), &mut thread_rng()).expect("Error upon hashing");
    let success = DssPkc20::check(&pk, msg_original.clone(), &r, &h);
    println!("Original hash verification success: {:?}", success);

    let msg_adapted = ElGamalMessage::from_string::<Sha512>("Adapted".to_string());
    let r_adapt = DssPkc20::adapt(&sk, &msg_original, &msg_adapted, &r, &h, &mut thread_rng())
        .expect("Error upon adapting");
    let success = DssPkc20::check(&pk, msg_adapted.clone(), &r_adapt, &h);

    println!("Adapted hash verification success: {:?}", success);
}
