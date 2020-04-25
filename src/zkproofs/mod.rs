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
}

pub trait FiatShamirConvertibleSigmaProtocol<'a, RNG, SP: SigmaProtocol<'a, RNG>> {
    type P;

    fn hash_challenge(statement : &SP::S, commitment : &SP::COM) -> SP::CH;
    fn compile_proof(commitment: SP::COM, challenge: SP::CH, response: SP::RSP) -> Self::P;
    fn unwrap_proof(proof: Self::P) -> (SP::COM, SP::CH, SP::RSP);
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
        SP: SigmaProtocol<'a, RNG> + FiatShamirConvertibleSigmaProtocol<'a, RNG, SP>,
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

        let ch = SP::hash_challenge(statement, &com); // TODO replace with RO challenge generation and drop challenge from proof

        let rsp = SP::response(statement, witness, &ch, &st);

        Some(SP::compile_proof(com, ch, rsp))
    }

    fn verify(statement: &Self::S, proof: Self::P) -> bool {
        let (commitment, challenge, response) = SP::unwrap_proof(proof);
        SP::check(
            statement,
            &commitment,
            &challenge, // TODO drop challenge from proof and recompute here
            &response,
        )
    }
}

