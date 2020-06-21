/// The fully collision-resistant chameleon hash from
/// [DSS'20](https://eprint.iacr.org/2020/403.pdf).
pub mod dss_pkc_20;

use rand::{CryptoRng, RngCore};

/// Chameleon hashing error type.
#[derive(Debug)]
pub enum Error<T>
where
    T: std::fmt::Debug + std::fmt::Display,
{
    /// The given key length in bytes is not supported by the implementation.
    UnsupportedKeyLength(u32),

    /// An wrapper for an implementation specific error of type `T`
    ImplementationSpecificError(T),
}

type ResultTuple<ResultA, ResultB, Error> = Result<(ResultA, ResultB), Error>;

/// Represents a (secret-coin) chameleon hash function. The interface follows
/// the definitions in [DSS'20](https://eprint.iacr.org/2020/403.pdf).
///
/// # Chameleon Hashes
/// Chameleon hashes are trapdoor collision resistant hash functions
/// parameterized by a public key. They are collision resistant for everyone
/// who does not know the corresponding secret key, while knowledge of the
/// secret key allows to efficiently find arbitrary collisions.
///
/// # Different Security Notions of Chameleon Hashes
/// In the literature, different security notions with different strengths
/// exist. Recently, the strongest collision resistance notion known to date
/// was presented in [DSS'20](https://eprint.iacr.org/2020/403.pdf). The
/// aforementioned paper also analyzes the relations between the existing
/// security notions and discusses practical implications.
pub trait ChameleonHash {
    /// The secret key space
    type SK;

    /// The public key space
    type PK;

    /// The message space
    type MSG;

    /// The randomness space
    type RND;

    /// The space of hash values
    type CH;

    /// An implementation specific error type
    type E: std::fmt::Debug + std::fmt::Display;

    /// Takes the desired key length `key_len` in bytes and a RNG `rng`, and
    /// generates a chameleon hashing key pair or an [Error](enum.Error.html).
    fn key_gen<RNG: RngCore + CryptoRng>(
        key_len: u32,
        rng: &mut RNG,
    ) -> ResultTuple<Self::SK, Self::PK, Error<Self::E>>;

    /// Takes a public key `public_key`, a message `message`, and a RNG `rng`,
    /// and returns a hash-randomness tuple or an [Error](enum.Error.html).
    fn hash<RNG: RngCore + CryptoRng>(
        public_key: &Self::PK,
        message: Self::MSG,
        rng: &mut RNG,
    ) -> ResultTuple<Self::CH, Self::RND, Error<Self::E>>;

    /// Takes a public key `public_key`, a message `message`, a randomness
    /// `randomness`, and a hash `hash`, and returns `true` if `hash` is
    /// considered a valid hash with respect to the other parameters and
    /// `false` otherwise.
    fn check(
        public_key: &Self::PK,
        message: Self::MSG,
        randomness: &Self::RND,
        hash: &Self::CH,
    ) -> bool;

    /// Takes a secret key `secret_key`, an old message `old_message`, a
    /// new message `new_message`, a randomness `randomness`, a valid hash
    /// `hash` for `old_message`, and an RNG `rng`. In case the given `hash`
    /// is a valid hash for `old_message` with respect to the other parameters
    /// (except `new_message`) it adapts and returns the randomness so that the
    /// given hash is a valid hash for `new_message`. Otherwise it returns
    /// an error.
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
