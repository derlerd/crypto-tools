use crate::zkproofs::sigma_protocols::{Challenge, SigmaProtocol};

pub trait FsConvertibleSigmaProtocol<SP>
where
    SP: SigmaProtocol,
{
    type FSP;

    fn domain_separator() -> String;
    fn hash_challenge(statement: &SP::S, commitment: &SP::COM) -> Challenge;
    fn compile_proof(commitment: SP::COM, response: SP::RSP) -> Self::FSP;
    fn unwrap_proof(proof: &Self::FSP) -> (&SP::COM, &SP::RSP);
}
