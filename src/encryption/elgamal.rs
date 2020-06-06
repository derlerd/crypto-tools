#[cfg(test)]
mod tests;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use digest::generic_array::typenum::U64;
use digest::Digest;

use std::marker::PhantomData;

use rand::{CryptoRng, RngCore};

use std::cmp::PartialEq;
use std::convert::From;

use crate::encryption::{Error, PublicKey, SecretKey};
use crate::zkproofs::sigma_protocols::dlog::{DlogStatement, DlogWitness};

pub struct ElGamal<RNG: RngCore + CryptoRng> {
    phantom_rng: PhantomData<RNG>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ElGamalSecretKey(Scalar);

#[derive(Clone, Debug, PartialEq)]
pub struct ElGamalPublicKey(RistrettoPoint);

#[derive(Clone, Debug, PartialEq)]
pub struct ElGamalMessage(RistrettoPoint);

#[derive(Clone, Debug, PartialEq)]
pub struct ElGamalCiphertext(RistrettoPoint, RistrettoPoint);

impl From<ElGamalPublicKey> for DlogStatement {
    fn from(public_key: ElGamalPublicKey) -> DlogStatement {
        DlogStatement::new(
            curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT.clone(),
            public_key.0,
        )
    }
}

impl From<&ElGamalSecretKey> for ElGamalPublicKey {
    fn from(secret_key: &ElGamalSecretKey) -> ElGamalPublicKey {
        Self::from_secret(secret_key)
    }
}

impl From<ElGamalSecretKey> for DlogWitness {
    fn from(secret_key: ElGamalSecretKey) -> DlogWitness {
        secret_key.0.into()
    }
}

impl<RNG: RngCore + CryptoRng> super::SecretKey<RNG> for ElGamalSecretKey {
    fn generate(key_len: u32, rng: &mut RNG) -> Result<ElGamalSecretKey, Error> {
        if key_len != 32 {
            return Err(Error::UnsupportedKeyLength(key_len));
        }

        let s = Scalar::random(rng);
        Ok(ElGamalSecretKey(s))
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

    fn key_gen(key_len: u32, rng: &mut RNG) -> Result<(ElGamalSecretKey, ElGamalPublicKey), Error> {
        let sk = match ElGamalSecretKey::generate(key_len, rng) {
            Ok(key) => key,
            Err(e) => return Err(e),
        };
        let pk = ElGamalPublicKey::from_secret(&sk);
        Ok((sk, pk))
    }

    fn encrypt(
        public_key: &ElGamalPublicKey,
        message: ElGamalMessage,
        rng: &mut RNG,
    ) -> ElGamalCiphertext {
        ElGamal::encrypt_reveal_randomness(public_key, &message, rng).0
    }

    fn decrypt(secret_key: &ElGamalSecretKey, ciphertext: ElGamalCiphertext) -> ElGamalMessage {
        let sk_inv = secret_key.0;
        ElGamalMessage(&ciphertext.1 - (&sk_inv * &ciphertext.0))
    }
}

impl<RNG: RngCore + CryptoRng> ElGamal<RNG> {
    pub(crate) fn encrypt_reveal_randomness(
        public_key: &ElGamalPublicKey,
        message: &ElGamalMessage,
        rng: &mut RNG,
    ) -> (ElGamalCiphertext, Scalar) {
        let r = Scalar::random(rng);
        let c1 = &r * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let c2 = &message.0 + (&public_key.0 * &r);

        (ElGamalCiphertext(c1, c2), r)
    }

    pub(crate) fn prepare_well_formedness_proof(
        public_key: ElGamalPublicKey,
        ciphertext: ElGamalCiphertext,
        message: ElGamalMessage,
    ) -> (
        (RistrettoPoint, RistrettoPoint),
        (RistrettoPoint, RistrettoPoint),
    ) {
        (
            (
                curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT,
                ciphertext.0,
            ),
            (public_key.0, (ciphertext.1 - message.0)),
        )
    }
}

#[allow(dead_code)]
impl ElGamalMessage {
    pub fn from_string<D: Digest<OutputSize = U64> + Default>(message: String) -> Self {
        let m_zl = Scalar::hash_from_bytes::<D>(message.as_bytes());
        let m_group = &m_zl * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        ElGamalMessage(m_group)
    }

    pub fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        ElGamalMessage(RistrettoPoint::random(rng))
    }
}
