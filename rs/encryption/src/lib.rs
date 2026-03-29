/// The [ElGamal](https://doi.org/10.1007%2FBFb0054851) encryption scheme
pub mod elgamal;

use rand_core::{CryptoRng, RngCore};

/// Encryption error type.
#[derive(Debug)]
pub enum Error {
    /// The given key length in bytes is not supported by the implementation.
    UnsupportedKeyLength(u32),
}

/// Represents an encryption secret key.
pub trait SecretKey {
    /// Generate a secret key of the length in bytes given in the `key_len`
    /// using the given RNG `rng`. Return an [Error](enum.Error.html) in case
    /// the given key length is not supported.
    fn generate<RNG: RngCore + CryptoRng>(key_len: u32, rng: &mut RNG) -> Result<Self, Error>
    where
        Self: Sized;
}

/// Represents an encryption public key. We work under the assumption that
/// a public key is uniquely determined by the secret key.
pub trait PublicKey {
    /// The type of the corresponding secret key.
    type SK;

    /// Generate a public key from a given secret key.
    fn from_secret(secret_key: &Self::SK) -> Self
    where
        Self: Sized;
}

/// Represents a public key encryption scheme. The interface follows
/// the interface as it is commonly used in the literature (see, e.g.,
/// [KL'14](http://www.cs.umd.edu/~jkatz/imc.html))
pub trait EncryptionScheme {
    /// The secret key space
    type SK;

    /// The public key space
    type PK;

    /// The message space
    type MSG;

    /// The ciphertext space
    type CTXT;

    /// Takes a key length `key_len` and a RNG `rng` and generates an
    /// encryption key pair. It fails with an `UnsupportedKeylength`
    /// error in case the given key length is not supported.
    fn key_gen<RNG: RngCore + CryptoRng>(
        key_len: u32,
        rng: &mut RNG,
    ) -> Result<(Self::SK, Self::PK), Error>;

    /// Takes a public key `public_key`, a message `message` and a
    /// RNG `rng` and returns a ciphertext.
    fn encrypt<RNG: RngCore + CryptoRng>(
        public_key: &Self::PK,
        message: Self::MSG,
        rng: &mut RNG,
    ) -> Self::CTXT;

    /// Takes a secret key `secret_key` and a ciphertext `ciphertext`,
    /// and returns the decrypted message.
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
