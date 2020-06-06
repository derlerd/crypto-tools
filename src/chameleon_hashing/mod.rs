pub mod dss_pkc_20;

use rand::{CryptoRng, RngCore};

#[derive(Debug)]
pub enum Error<T>
where
    T: std::fmt::Debug + std::fmt::Display,
{
    UnsupportedKeyLength(u32),
    ImplementationSpecificError(T),
}

pub trait ChameleonHash {
    type SK;
    type PK;
    type MSG;
    type RND;
    type CH;
    type E: std::fmt::Debug + std::fmt::Display;

    fn key_gen<RNG: RngCore + CryptoRng>(
        key_len: u32,
        rng: &mut RNG,
    ) -> Result<(Self::SK, Self::PK), Error<Self::E>>;
    fn hash<RNG: RngCore + CryptoRng>(
        public_key: &Self::PK,
        message: Self::MSG,
        rng: &mut RNG,
    ) -> Result<(Self::CH, Self::RND), Error<Self::E>>;
    fn check(
        public_key: &Self::PK,
        message: Self::MSG,
        randomness: &Self::RND,
        hash: &Self::CH,
    ) -> bool;
    fn adapt<RNG: RngCore + CryptoRng>(
        secret_key: &Self::SK,
        old_message: &Self::MSG,
        new_message: &Self::MSG,
        randomness: &Self::RND,
        hash: &Self::CH,
        rng: &mut RNG,
    ) -> Result<Self::RND, Error<Self::E>>;
}

impl<T> std::error::Error for Error<T>
where
    T: std::fmt::Debug + std::fmt::Display,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl<T> std::fmt::Display for Error<T>
where
    T: std::fmt::Debug + std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::UnsupportedKeyLength(key_len) => {
                write!(f, "Given key length ({} bytes) not supported", key_len)
            }
            Error::ImplementationSpecificError(e) => write!(f, "{}", e),
        }
    }
}
