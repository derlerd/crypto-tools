use curve25519_dalek::scalar::Scalar;

use rand::thread_rng;
use sha2::Sha512;

use crate::encryption::elgamal::{ElGamal, ElGamalMessage};
use crate::encryption::EncryptionScheme;

#[test]
fn key_gen_success() {
    let (_sk, _pk) = ElGamal::key_gen(32, &mut thread_rng()).expect("Key generation failed");
}

#[test]
#[should_panic(expected = "Key generation failed")]
fn key_gen_failure() {
    let (_sk, _pk) = ElGamal::key_gen(31, &mut thread_rng()).expect("Key generation failed");
}

#[test]
fn test_encode_message() {
    let message = "Test Message".to_string();

    let m_zl = Scalar::hash_from_bytes::<Sha512>(message.as_bytes());
    let m_group = &m_zl * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    let m = ElGamalMessage::from_string::<Sha512>(message);

    assert_eq!(m.0, m_group, "Encodings of messages do not match.");
}

#[test]
fn test_encode_message_fail() {
    let message = "Test Message".to_string();

    let m_zl = Scalar::hash_from_bytes::<Sha512>(message.as_bytes());
    let m_group = &m_zl * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    let m = ElGamalMessage::from_string::<Sha512>("Test message".to_string());

    assert_ne!(
        m,
        ElGamalMessage(m_group),
        "Encodings of two different messages match."
    );
}

#[test]
fn encrypt_decrypt_success() {
    let (sk, pk) = ElGamal::key_gen(32, &mut thread_rng()).expect("Key generation failed");

    let m = ElGamalMessage::random(&mut thread_rng());

    let c = ElGamal::encrypt(&pk, m.clone(), &mut thread_rng());

    let m_dec = ElGamal::decrypt(&sk, c);

    assert_eq!(
        m, m_dec,
        "Decrypted message does not match message which was previously encrypted."
    );
}
