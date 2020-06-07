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
    InvalidWitness,
}

impl From<SigmaProtocolError> for Error {
    fn from(error: SigmaProtocolError) -> Error {
        match error {
            SigmaProtocolError::InvalidWitness => Error::InvalidWitness,
        }
    }
}

pub trait FsProofSystem<DIG: Digest<OutputSize = U64>> {
    type S;
    type W;
    type P;

    fn prove<RNG: RngCore + CryptoRng>(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Result<Self::P, Error>;
    fn verify(statement: &Self::S, proof: &Self::P) -> bool;
}

impl<SP, DIG> FsProofSystem<DIG> for SP
where
    DIG: Digest<OutputSize = U64>,
    SP: SigmaProtocol + FsConvertibleSigmaProtocol<SP, DIG>,
    <Self as SigmaProtocol>::S: Hashable<DIG>,
    <Self as SigmaProtocol>::COM: Hashable<DIG>,
{
    type S = SP::S;
    type W = SP::W;
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
        let ch = SP::hash_challenge(statement, &commitment);
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
