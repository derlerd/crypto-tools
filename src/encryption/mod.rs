pub mod elgamal;

use rand::{CryptoRng, RngCore};

pub trait SecretKey<RNG: RngCore + CryptoRng> {
    fn generate(key_len: u32, rng: &mut RNG) -> Option<Self>
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

    fn key_gen(key_len: u32, rng: &mut RNG) -> Option<(Self::SK, Self::PK)>;
    fn encrypt(public_key: Self::PK, message: Self::MSG, rng: &mut RNG) -> Self::CTXT;
    fn decrypt(secret_key: Self::SK, ciphertext: Self::CTXT) -> Self::MSG;
}
