pub mod sigma_protocols;

use rand::{CryptoRng, RngCore};

use crate::zkproofs::sigma_protocols::dlog::Dlog;
use crate::zkproofs::sigma_protocols::dlogeq::DlogEq;
use crate::zkproofs::sigma_protocols::fiat_shamir::FsConvertibleSigmaProtocol;
use crate::zkproofs::sigma_protocols::or_composition::OrComposedSigmaProtocol;
use crate::zkproofs::sigma_protocols::Error as SigmaProtocolError;
use crate::zkproofs::sigma_protocols::SigmaProtocol;

use crate::hashing::Hashable;

use digest::generic_array::typenum::U64;
use digest::Digest;

#[derive(Debug)]
pub enum Error {
    /// The given witness is not a valid witness for the statement in question.
    InvalidWitness,
}

impl From<SigmaProtocolError> for Error {
    fn from(error: SigmaProtocolError) -> Error {
        match error {
            SigmaProtocolError::InvalidWitness => Error::InvalidWitness,
        }
    }
}

/// Represents a [Fiat-Shamir](https://doi.org/10.1007%2F3-540-68339-9_33) 
/// transformed proof system, which is generic over the `Digest` used withing the
/// Fiat-Shamir transform.
///
/// # Intuition of Proof Systems
/// Below we recall the basic intuition of proof systems. Let `S` 
/// be some NP-language with associated witness relation `R`, i.e., so that a 
/// statement `s` is in `S` if there exists a witness `w` so that `R(s, w) = 1`.
/// A proof system for a language `S` can be used to compute proofs that attest 
/// that a certain statement is in `S` and to verify those proofs. The concrete 
/// language a proof system works for is defined by the implementation.
pub trait FsProofSystem<DIG: Digest<OutputSize = U64>> {
    /// The space the statements to be proven live in
    type S;
    /// The space the witnesses live in
    type W;
    /// The space the proofs live in
    type P;

    /// Takes a statement `statement`, a witness `witness`, and a RNG `rng`, 
    /// and returns a proof. It fails if the witness does not attest membership
    /// of the given statement in the language. 
    fn prove<RNG: RngCore + CryptoRng>(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Result<Self::P, Error>;

    /// Takes a statement `statement` and a proof `proof`, and returns
    /// `true` if the proof is valid w.r.t. the statement and `false`
    /// otherwise.
    fn verify(statement: &Self::S, proof: &Self::P) -> bool;
}

/// A generic implementation of a `FsProofSystem` for any `SigmaProtocol` that
/// implements the `FsConvertibleSigmaProtocol` trait and its statement type
/// and its commitment type implement the hashable trait. The implementation
/// is also generic over the `Digest` used for hashing the statement and the 
/// challenge, as well as for obtaining the challenge. 
/// 
/// Note that having this generic implementation means that all `SigmaProtocols`
/// adhering to the aforementioned trait bounds can automatically be used as
/// `FsProofSystems` without any additional code. 
impl<SP, DIG> FsProofSystem<DIG> for SP
where
    DIG: Digest<OutputSize = U64>,
    SP: SigmaProtocol + FsConvertibleSigmaProtocol<SP, DIG>,
    <Self as SigmaProtocol>::S: Hashable<DIG>,
    <Self as SigmaProtocol>::COM: Hashable<DIG>,
{
    /// The statement type is the same as the statement type of the underlying
    /// sigma protocol.
    type S = SP::S;

    /// The witness type is the same as the witness type of the underlying
    /// sigma protocol.
    type W = SP::W;

    /// The proof type is defined by the proof type of the underlying 
    /// `FsConvertibleSigmaProtocol`.
    type P = SP::FSP;

    fn prove<RNG: RngCore + CryptoRng>(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Result<Self::P, Error> {
        let (com, st) = SP::commit(statement, witness, rng)?;
        let ch = SP::hash_challenge(statement, &com);
        let rsp = SP::response(statement, witness, &ch, st);

        Ok(SP::compile_proof(com, rsp))
    }

    fn verify(statement: &Self::S, proof: &Self::P) -> bool {
        let (commitment, response) = SP::unwrap_proof(proof);
        let ch = <Self as FsConvertibleSigmaProtocol<SP, DIG>>::hash_challenge(statement, &commitment);
        SP::check(statement, &commitment, &ch, &response)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidWitness => write!(
                f,
                "The given witness does not attest membership of the statement in the language."
            ),
        }
    }
}

pub(crate) type DlOrDlEq = OrComposedSigmaProtocol<Dlog, DlogEq>;
