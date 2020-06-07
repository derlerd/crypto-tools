#[cfg(test)]
mod tests;

use rand::{CryptoRng, RngCore};

use crate::chameleon_hashing::{ChameleonHash, Error};
use crate::encryption::elgamal::{
    ElGamal, ElGamalCiphertext, ElGamalMessage, ElGamalPublicKey, ElGamalSecretKey,
};
use crate::encryption::EncryptionScheme;
use crate::encryption::Error as EncryptionError;
use crate::zkproofs::sigma_protocols::dlog::DlogWitness;
use crate::zkproofs::sigma_protocols::Error as SigmaProtocolError;
use crate::zkproofs::Error as ProofSystemError;
use crate::zkproofs::{DlOrDlEq, FsProofSystem};

use sha2::Sha512;

pub struct DssPkc20;

#[derive(Debug)]
pub enum DssPkc20Error {
    /// Encapsulates all errors caused by failures related to the used proof system.
    ProofSystemError(ProofSystemError),
    /// Encapsulates all errors caused by failures related to the used sigma protocol system.
    SigmaProtocolError(SigmaProtocolError),
    /// Encapsulates errors related to invalid hashes returned by functions where a valid
    /// hash is a precondition.
    InvalidHashError(String),
}

impl From<EncryptionError> for Error<DssPkc20Error> {
    fn from(error: EncryptionError) -> Error<DssPkc20Error> {
        match error {
            EncryptionError::UnsupportedKeyLength(key_len) => Error::UnsupportedKeyLength(key_len),
        }
    }
}

impl From<ProofSystemError> for Error<DssPkc20Error> {
    fn from(error: ProofSystemError) -> Error<DssPkc20Error> {
        Error::ImplementationSpecificError(DssPkc20Error::ProofSystemError(error))
    }
}

impl From<SigmaProtocolError> for Error<DssPkc20Error> {
    fn from(error: SigmaProtocolError) -> Error<DssPkc20Error> {
        Error::ImplementationSpecificError(DssPkc20Error::SigmaProtocolError(error))
    }
}

impl std::fmt::Display for DssPkc20Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "daaaaamn this went wrong")
    }
}

/// Implementation of the fully collision-resistant chameleon-hash from
/// [DSS'20](https://eprint.iacr.org/2020/403.pdf). The implementation
/// is generic in the sense that is makes black-box use of the implementation 
/// of two primitives implemented within this crate:
///
/// - The [ElGamal](https://doi.org/10.1007%2FBFb0054851) encryption scheme
/// [here](../encryption/elgamal/struct.ElGamal.html). The key pair of this 
/// scheme will be an ElGamal key pair, and the hash will be an ElGamal
/// ciphertext.
///
/// - A proof system obtained by [OR-composing](https://doi.org/10.1007/3-540-48658-5_19) 
///   (1) a sigma protocol to prove knowledge of the discrete logarithm of 
///   some group element with respect to some basis, and (2) a sigma protocol 
///   to prove that two group elements contain the same discrete logarithm 
///   with respect to their bases, and applying the 
///   [Fiat-Shamir transform](https://doi.org/10.1007%2F3-540-68339-9_33) 
///   and the [FKMV'12](https://eprint.iacr.org/2012/704.pdf) compiler to it.
///   The randomness will be such an OR-composed proof.
impl ChameleonHash for DssPkc20 {
    /// The secret key of this scheme is an ElGamal secret key.
    type SK = ElGamalSecretKey;

    /// The public key of this scheme is an ElGamal public key.
    type PK = ElGamalPublicKey;

    /// The message space of this scheme is the ElGamal message space.
    type MSG = ElGamalMessage;

    /// The hashes are ElGamal ciphertexts.
    type CH = ElGamalCiphertext;

    /// The randomness are proofs from an OR-composed Fiat-Shamir transformed
    /// Sigma protocol with the FKMV'12 compiler applied.
    type RND = <DlOrDlEq as FsProofSystem<Sha512>>::P;

    /// The implementation defines a custom, implementation specific error,
    /// which is used to encapsulate the respective errors from the involved
    /// primitives.
    type E = DssPkc20Error;

    fn key_gen<RNG: RngCore + CryptoRng>(
        key_len: u32,
        rng: &mut RNG,
    ) -> Result<(ElGamalSecretKey, ElGamalPublicKey), Error<DssPkc20Error>> {
        let key_pair = ElGamal::key_gen(key_len, rng)?;

        Ok(key_pair)
    }

    fn hash<RNG: RngCore + CryptoRng>(
        public_key: &Self::PK,
        message: Self::MSG,
        rng: &mut RNG,
    ) -> Result<(Self::CH, Self::RND), Error<DssPkc20Error>> {
        let (c, r) = ElGamal::encrypt_reveal_randomness(public_key, &message, rng);

        let x1 = public_key.clone().into();

        let x2 =
            ElGamal::prepare_well_formedness_proof(public_key.clone(), c.clone(), message).into();
        let w2 = r.into();

        let x = DlOrDlEq::compile_statement(x1, x2);
        let w = DlOrDlEq::compile_witness(None, Some(w2))?;

        let p = <DlOrDlEq as FsProofSystem<Sha512>>::prove(&x, &w, rng)?;

        Ok((c, p))
    }
    fn check(
        public_key: &Self::PK,
        message: Self::MSG,
        randomness: &Self::RND,
        hash: &Self::CH,
    ) -> bool {
        let x1 = public_key.clone().into();
        let x2 = ElGamal::prepare_well_formedness_proof(public_key.clone(), hash.clone(), message)
            .into();
        let x = DlOrDlEq::compile_statement(x1, x2);

        <DlOrDlEq as FsProofSystem<Sha512>>::verify(&x, randomness)
    }
    fn adapt<RNG: RngCore + CryptoRng>(
        secret_key: &Self::SK,
        old_message: &Self::MSG,
        new_message: &Self::MSG,
        randomness: &Self::RND,
        hash: &Self::CH,
        rng: &mut RNG,
    ) -> Result<Self::RND, Error<DssPkc20Error>> {
        if Self::check(&secret_key.into(), old_message.clone(), randomness, hash) == false {
            return Err(Error::ImplementationSpecificError(
                DssPkc20Error::InvalidHashError("Hash supplied to adapt is invalid".to_string()),
            ));
        }

        let pk: ElGamalPublicKey = secret_key.into();

        let x1 = pk.clone().into();
        let x2 =
            ElGamal::prepare_well_formedness_proof(pk.clone(), hash.clone(), new_message.clone())
                .into();

        let w1: DlogWitness = secret_key.clone().into();

        let x = DlOrDlEq::compile_statement(x1, x2);
        let w = DlOrDlEq::compile_witness(Some(w1), None)?;

        let p = <DlOrDlEq as FsProofSystem<Sha512>>::prove(&x, &w, rng)?;

        Ok(p)
    }
}
