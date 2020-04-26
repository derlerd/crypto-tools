use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use digest::generic_array::typenum::U64;
use digest::Digest;

use std::marker::PhantomData;

use rand::rngs::ThreadRng;
use rand::{CryptoRng, RngCore};

use crate::encryption::{PublicKey, SecretKey};

pub struct ElGamal<RNG: RngCore + CryptoRng> {
    phantom_rng: PhantomData<RNG>,
}

pub struct ElGamalSecretKey(Scalar);
pub struct ElGamalPublicKey(RistrettoPoint);
pub struct ElGamalMessage(RistrettoPoint);
pub struct ElGamalCiphertext(RistrettoPoint, RistrettoPoint);

impl<RNG: RngCore + CryptoRng> super::SecretKey<RNG> for ElGamalSecretKey {
    fn generate(key_len: u32, rng: &mut RNG) -> Option<ElGamalSecretKey> {
        if key_len != 32 {
            return None;
        }

        let s = Scalar::random(rng);
        Some(ElGamalSecretKey(s))
    }
}

impl super::PublicKey for ElGamalPublicKey {
    type SK = ElGamalSecretKey;

    fn from_secret(secret_key: &ElGamalSecretKey) -> ElGamalPublicKey {
        ElGamalPublicKey(&secret_key.0 * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
    }
}

impl<RNG: RngCore + CryptoRng> super::EncryptionScheme<RNG> for ElGamal<RNG> {
    type SK = ElGamalSecretKey;
    type PK = ElGamalPublicKey;
    type MSG = ElGamalMessage;
    type CTXT = ElGamalCiphertext;

    fn key_gen(key_len: u32, rng: &mut RNG) -> Option<(ElGamalSecretKey, ElGamalPublicKey)> {
        let sk = match ElGamalSecretKey::generate(key_len, rng) {
            Some(key) => key,
            None => return None,
        };
        let pk = ElGamalPublicKey::from_secret(&sk);
        Some((sk, pk))
    }

    fn encrypt(
        public_key: ElGamalPublicKey,
        message: ElGamalMessage,
        rng: &mut RNG,
    ) -> ElGamalCiphertext {
        ElGamal::encrypt_reveal_randomness(public_key, message, rng).0
    }

    fn decrypt(secret_key: ElGamalSecretKey, ciphertext: ElGamalCiphertext) -> ElGamalMessage {
        let sk_inv = secret_key.0;
        ElGamalMessage(&ciphertext.1 - (&sk_inv * &ciphertext.0))
    }
}

impl<RNG: RngCore + CryptoRng> ElGamal<RNG> {
    fn encrypt_reveal_randomness(
        public_key: ElGamalPublicKey,
        message: ElGamalMessage,
        rng: &mut RNG,
    ) -> (ElGamalCiphertext, Scalar) {
        let r = Scalar::random(rng);
        let c1 = &r * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let c2 = &message.0 + (&public_key.0 * &r);

        (ElGamalCiphertext(c1, c2), r)
    }
}

impl ElGamalMessage {
    pub fn from_string<D: Digest<OutputSize = U64> + Default>(message: String) -> Self {
        let m_zl = Scalar::hash_from_bytes::<D>(message.as_bytes());
        let m_group = &m_zl * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        ElGamalMessage(m_group)
    }
}

pub type ElGamalWithThreadRng = ElGamal<ThreadRng>;
