pub mod dss_pkc_20;

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

pub trait ChameleonHash<RNG: RngCore + CryptoRng> {
    type SK;
    type PK;
    type MSG;
    type RND;
    type CH;

    fn key_gen(key_len: u32, rng: &mut RNG) -> Option<(Self::SK, Self::PK)>;
    fn hash(public_key: &Self::PK, message: Self::MSG, rng: &mut RNG) -> (Self::CH, Self::RND);
    fn check(
        public_key: &Self::PK,
        message: Self::MSG,
        randomness: &Self::RND,
        hash: &Self::CH,
    ) -> bool;
    fn adapt(
        secret_key: &Self::SK,
        old_message: &Self::MSG,
        new_message: &Self::MSG,
        randomness: &Self::RND,
        hash: &Self::CH,
        rng: &mut RNG,
    ) -> Self::RND;
}
