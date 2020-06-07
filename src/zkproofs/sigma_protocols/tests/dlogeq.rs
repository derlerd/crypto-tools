use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use digest::Digest;
use rand::thread_rng;
use sha2::Sha512;

use crate::hashing::Hashable;
use crate::zkproofs::sigma_protocols::dlogeq::{DlogEq, DlogEqStatement, DlogEqWitness};
use crate::zkproofs::sigma_protocols::{Error, SigmaProtocol};
use crate::zkproofs::Error as ProofSystemError;
use crate::zkproofs::FsProofSystem;

pub(crate) fn create_dlogeq_statement_for_testing() -> (DlogEqStatement, DlogEqWitness) {
    let w = Scalar::random(&mut thread_rng());
    let base1 = RistrettoPoint::random(&mut thread_rng());
    let base2 = RistrettoPoint::random(&mut thread_rng());
    let mult1 = &base1 * &w;
    let mult2 = &base2 * &w;

    (DlogEqStatement::new(base1, mult1, base2, mult2), w.into())
}

fn hash_statement_for_testing(x: DlogEqStatement) -> Vec<u8> {
    let mut digest = Sha512::new();
    x.hash(&mut digest);
    digest.result().to_vec()
}

#[test]
fn test_valid_statement() {
    let (x, w) = create_dlogeq_statement_for_testing();

    assert_eq!(x.verify(&w.into()), true);
}

#[test]
fn test_invalid_statement() {
    let (x, _) = create_dlogeq_statement_for_testing();

    let w = Scalar::random(&mut thread_rng());

    assert_eq!(x.verify(&w.into()), false);
}

#[test]
fn test_hash_different_statements() {
    let (x1, _) = create_dlogeq_statement_for_testing();
    let (x2, _) = create_dlogeq_statement_for_testing();

    assert_ne!(
        hash_statement_for_testing(x1),
        hash_statement_for_testing(x2),
        "Hashing two different statements yielded the same hash"
    );
}

#[test]
fn test_commit_fail() {
    let (x, _) = create_dlogeq_statement_for_testing();
    let w = Scalar::random(&mut thread_rng());

    match DlogEq::commit(&x, &w.into(), &mut thread_rng()) {
        Err(Error::InvalidWitness) => return,
        _ => panic!("Expected Error::InvalidWitness."),
    }
}

#[test]
fn test_commit_challenge_response_check() {
    let (x, w) = create_dlogeq_statement_for_testing();

    let (com, st) = DlogEq::commit(&x, &w, &mut thread_rng()).expect("Committing failed");
    let ch = DlogEq::challenge(&mut thread_rng());
    let rsp = DlogEq::response(&x, &w, &ch, st);

    assert_eq!(DlogEq::check(&x, &com, &ch, &rsp), true);
}

#[test]
fn test_prove_fails() {
    let (x, _) = create_dlogeq_statement_for_testing();
    let w = Scalar::random(&mut thread_rng());

    match <DlogEq as FsProofSystem<Sha512>>::prove(&x, &w.into(), &mut thread_rng()) {
        Err(ProofSystemError::InvalidWitness) => return,
        _ => panic!("Expected Error::InvalidWitness"),
    }
}

#[test]
fn test_prove_and_verify() {
    let (x, w) = create_dlogeq_statement_for_testing();

    let p = <DlogEq as FsProofSystem<Sha512>>::prove(&x, &w, &mut thread_rng())
        .expect("Proving failed");

    assert_eq!(<DlogEq as FsProofSystem<Sha512>>::verify(&x, &p), true);
}
