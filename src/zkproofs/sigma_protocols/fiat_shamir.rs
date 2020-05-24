use crate::zkproofs::sigma_protocols::{Challenge, SigmaProtocol};

use rand::{CryptoRng, RngCore};

pub trait FsConvertibleSigmaProtocol<RNG, SP>
where
    RNG: RngCore + CryptoRng,
    SP: SigmaProtocol<RNG>,
{
    type FSP;

    fn hash_challenge(statement: &SP::S, commitment: &SP::COM) -> Challenge;
    fn compile_proof(commitment: SP::COM, response: SP::RSP) -> Self::FSP;
    fn unwrap_proof(proof: Self::FSP) -> (SP::COM, SP::RSP);
}
