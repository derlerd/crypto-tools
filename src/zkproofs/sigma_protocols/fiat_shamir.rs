use crate::zkproofs::sigma_protocols::{Challenge, SigmaProtocol};

use digest::generic_array::typenum::U64;
use digest::Digest;

pub trait FsConvertibleSigmaProtocol<SP, DIG>
where
    DIG: Digest<OutputSize = U64>,
    SP: SigmaProtocol,
{
    type FSP;

    fn domain_separator() -> String;
    fn hash_challenge(statement: &SP::S, commitment: &SP::COM) -> Challenge;
    fn compile_proof(commitment: SP::COM, response: SP::RSP) -> Self::FSP;
    fn unwrap_proof(proof: &Self::FSP) -> (&SP::COM, &SP::RSP);
}
