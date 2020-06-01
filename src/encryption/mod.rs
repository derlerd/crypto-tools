pub mod elgamal;

use rand::{CryptoRng, RngCore};

#[derive(Debug)]
pub enum Error {
    UnsupportedKeyLength(u32),
}

pub trait SecretKey<RNG: RngCore + CryptoRng> {
    fn generate(key_len: u32, rng: &mut RNG) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait PublicKey {
    type SK;

    fn from_secret(secret_key: &Self::SK) -> Self
    where
        Self: Sized;
}

pub trait EncryptionScheme<RNG: RngCore + CryptoRng> {
    type SK;
    type PK;
    type MSG;
    type CTXT;

    fn key_gen(key_len: u32, rng: &mut RNG) -> Result<(Self::SK, Self::PK), Error>;
    fn encrypt(public_key: &Self::PK, message: Self::MSG, rng: &mut RNG) -> Self::CTXT;
    fn decrypt(secret_key: &Self::SK, ciphertext: Self::CTXT) -> Self::MSG;
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::UnsupportedKeyLength(key_len) => {
                write!(f, "Given key length ({} bytes) not supported", key_len)
            }
        }
    }
}
