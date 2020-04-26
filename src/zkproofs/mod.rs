pub mod dlog;
pub mod dlogeq;

use rand::{CryptoRng, RngCore};

pub trait SigmaProtocol<'a, RNG> {
    type S;
    type W;
    type COM;
    type ST;
    type CH;
    type RSP;

    fn commit(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Option<(Self::COM, Self::ST)>;
    fn challenge(rng: &mut RNG) -> Self::CH;
    fn response(
        statement: &Self::S,
        witness: &Self::W,
        challenge: &Self::CH,
        state: &Self::ST,
    ) -> Self::RSP;
    fn check(
        statement: &Self::S,
        commitment: &Self::COM,
        challenge: &Self::CH,
        response: &Self::RSP,
    ) -> bool;
    fn simulate(statement: &Self::S, challenge: &Self::CH, rng: &mut RNG)
        -> (Self::COM, Self::RSP);
}

pub trait FsConvertibleSigmaProtocol<'a, RNG, SP: SigmaProtocol<'a, RNG>> {
    type P;

    fn hash_challenge(statement: &SP::S, commitment: &SP::COM) -> SP::CH;
    fn compile_proof(commitment: SP::COM, response: SP::RSP) -> Self::P;
    fn unwrap_proof(proof: Self::P) -> (SP::COM, SP::RSP);
}

pub trait ProofSystem<'a, RNG> {
    type S;
    type W;
    type P;

    fn prove(statement: &Self::S, witness: &Self::W, rng: &mut RNG) -> Option<Self::P>;
    fn verify(statement: &Self::S, proof: Self::P) -> bool;
}

impl<
        'a,
        RNG: RngCore + CryptoRng,
        SP: SigmaProtocol<'a, RNG> + FsConvertibleSigmaProtocol<'a, RNG, SP>,
    > ProofSystem<'a, RNG> for SP
{
    type S = SP::S;
    type W = SP::W;
    type P = SP::P;

    fn prove(statement: &Self::S, witness: &Self::W, rng: &mut RNG) -> Option<Self::P> {
        let (com, st) = match SP::commit(statement, witness, rng) {
            Some((com, st)) => (com, st),
            None => return None,
        };

        let ch = SP::hash_challenge(statement, &com);

        let rsp = SP::response(statement, witness, &ch, &st);

        Some(SP::compile_proof(com, rsp))
    }

    fn verify(statement: &Self::S, proof: Self::P) -> bool {
        let (commitment, response) = SP::unwrap_proof(proof);
        let ch = SP::hash_challenge(statement, &commitment);
        SP::check(statement, &commitment, &ch, &response)
    }
}
