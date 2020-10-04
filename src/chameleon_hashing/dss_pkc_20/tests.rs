use rand::thread_rng;
use sha2::Sha512;

use crate::chameleon_hashing::dss_pkc_20::{DssPkc20, DssPkc20Error};
use crate::chameleon_hashing::{ChameleonHash, Error};
use crate::encryption::elgamal::ElGamalMessage;

#[test]
fn key_gen_success() {
    let (_sk, _pk) = DssPkc20::key_gen(32, &mut thread_rng()).expect("Key generation failed");
}

#[test]
#[should_panic(expected = "Key generation failed")]
fn key_gen_failure() {
    let (_sk, _pk) = DssPkc20::key_gen(31, &mut thread_rng()).expect("Key generation failed");
}

#[test]
fn hash_validation_success() {
    let (_sk, pk) = DssPkc20::key_gen(32, &mut thread_rng()).expect("Test");

    let msg_original = ElGamalMessage::from_string::<Sha512>("Original".to_string());
    let (h, r) =
        DssPkc20::hash(&pk, msg_original.clone(), &mut thread_rng()).expect("Error upon hashing");
    let success = DssPkc20::check(&pk, msg_original.clone(), &r, &h);

    assert_eq!(
        true, success,
        "Hash validation failed: expected {} got {}.",
        true, success
    );
}

#[test]
fn hash_validation_failure() {
    let (_sk, pk) = DssPkc20::key_gen(32, &mut thread_rng()).expect("Test");

    let msg_original = ElGamalMessage::from_string::<Sha512>("Original".to_string());
    let (h, r) =
        DssPkc20::hash(&pk, msg_original.clone(), &mut thread_rng()).expect("Error upon hashing");

    let msg = ElGamalMessage::from_string::<Sha512>("Other".to_string());

    let success = DssPkc20::check(&pk, msg.clone(), &r, &h);

    assert_eq!(
        false, success,
        "Hash validation failed: expected {} got {}.",
        false, success
    );
}

#[test]
fn hash_adapt_success() {
    let (sk, pk) = DssPkc20::key_gen(32, &mut thread_rng()).unwrap();

    let msg_original = ElGamalMessage::from_string::<Sha512>("Original".to_string());
    let (h, r) =
        DssPkc20::hash(&pk, msg_original.clone(), &mut thread_rng()).expect("Error upon hashing");

    let msg_adapted = ElGamalMessage::from_string::<Sha512>("Adapted".to_string());
    let r_adapt = DssPkc20::adapt(&sk, &msg_original, &msg_adapted, &r, &h, &mut thread_rng())
        .expect("Error upon adapting");
    let success = DssPkc20::check(&pk, msg_adapted.clone(), &r_adapt, &h);

    assert_eq!(
        true, success,
        "Hash validation after adapt failed: expected {} got {}.",
        true, success
    );
}

#[test]
fn hash_adapt_invalid_hash() {
    let (sk, pk) = DssPkc20::key_gen(32, &mut thread_rng()).unwrap();

    let msg_original = ElGamalMessage::from_string::<Sha512>("Original".to_string());
    let (h, r) =
        DssPkc20::hash(&pk, msg_original.clone(), &mut thread_rng()).expect("Error upon hashing");

    let msg_adapted = ElGamalMessage::from_string::<Sha512>("Adapted".to_string());
    match DssPkc20::adapt(&sk, &msg_adapted, &msg_adapted, &r, &h, &mut thread_rng()) {
        Err(Error::ImplementationSpecificError(DssPkc20Error::InvalidHashError(_))) => {}
        _ => panic!("Hash adaption of invalid hash failed: expected `InvalidHashError`."),
    };
}

#[test]
fn hash_adapt_invalid_key() {
    let (_sk, pk) = DssPkc20::key_gen(32, &mut thread_rng()).unwrap();

    let msg_original = ElGamalMessage::from_string::<Sha512>("Original".to_string());
    let (h, r) =
        DssPkc20::hash(&pk, msg_original.clone(), &mut thread_rng()).expect("Error upon hashing");

    let msg_adapted = ElGamalMessage::from_string::<Sha512>("Adapted".to_string());

    let (sk, _pk) = DssPkc20::key_gen(32, &mut thread_rng()).unwrap();

    match DssPkc20::adapt(&sk, &msg_adapted, &msg_adapted, &r, &h, &mut thread_rng()) {
        Err(Error::ImplementationSpecificError(DssPkc20Error::InvalidHashError(_))) => {}
        _ => panic!("Hash adaption of invalid hash failed: expected `InvalidHashError`."),
    };
}
