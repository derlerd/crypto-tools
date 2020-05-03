pub mod dlog;
pub mod dlogeq;

use curve25519_dalek::scalar::Scalar;

use rand::{CryptoRng, RngCore};

use std::marker::PhantomData;

pub struct Challenge(Scalar);

pub trait SigmaProtocol<'a, RNG> {
    type S;
    type W;
    type COM;
    type ST;
    type RSP;
    type STS;

    fn commit(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Option<(Self::COM, Self::ST)>;
    fn challenge(rng: &mut RNG) -> Challenge;
    fn response(
        statement: &Self::S,
        witness: &Self::W,
        challenge: &Challenge,
        state: &Self::ST,
    ) -> Self::RSP;
    fn check(
        statement: &Self::S,
        commitment: &Self::COM,
        challenge: &Challenge,
        response: &Self::RSP,
    ) -> bool;
    fn simulate(statement: &Self::S, rng: &mut RNG) -> (Self::COM, Self::STS);
}

pub trait FsConvertibleSigmaProtocol<'a, RNG, SP: SigmaProtocol<'a, RNG>> {
    type P;

    fn hash_challenge(statement: &SP::S, commitment: &SP::COM) -> Challenge;
    fn compile_proof(commitment: SP::COM, response: SP::RSP) -> Self::P;
    fn unwrap_proof(proof: Self::P) -> (SP::COM, SP::RSP);
}

pub struct OrComposedSigmaProtocol<'a, RNG, P1: SigmaProtocol<'a, RNG>, P2: SigmaProtocol<'a, RNG>>
{
    p1: PhantomData<&'a P1>,
    p2: PhantomData<&'a P2>,
    rng: PhantomData<RNG>,
}

pub enum OrComposedWitness<'a, RNG, P1: SigmaProtocol<'a, RNG>, P2: SigmaProtocol<'a, RNG>> {
    WitnessP1(P1::W),
    WitnessP2(P2::W),
    Both((P1::W, P2::W)),
}

pub enum OrProverState<'a, RNG, P1: SigmaProtocol<'a, RNG>, P2: SigmaProtocol<'a, RNG>> {
    SimulatedP1(P1::STS, P2::ST),
    SimulatedP2(P1::ST, P2::STS),
    BothHonest(P1::ST, P2::ST),
}

impl<'a, RNG: RngCore + CryptoRng, P1: SigmaProtocol<'a, RNG>, P2: SigmaProtocol<'a, RNG>>
    SigmaProtocol<'a, RNG> for OrComposedSigmaProtocol<'a, RNG, P1, P2>
{
    type S = (P1::S, P2::S);
    type W = OrComposedWitness<'a, RNG, P1, P2>;
    type COM = (P1::COM, P2::COM);
    type ST = OrProverState<'a, RNG, P1, P2>;
    type RSP = (P1::RSP, P2::RSP);
    type STS = (P1::STS, P2::STS);

    fn commit(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Option<(Self::COM, Self::ST)> {
        match witness {
            OrComposedWitness::WitnessP1(w1) => {
                let (c1, st1) = match P1::commit(&statement.0, &w1, rng) {
                    Some((com, st)) => (com, st),
                    None => return None,
                };
                let (c2, st2) = P2::simulate(&statement.1, rng);

                Some(((c1, c2), OrProverState::SimulatedP2(st1, st2)))
            }
            OrComposedWitness::WitnessP2(w2) => {
                let (c2, st2) = match P2::commit(&statement.1, &w2, rng) {
                    Some((com, st)) => (com, st),
                    None => return None,
                };
                let (c1, st1) = P1::simulate(&statement.0, rng);

                Some(((c1, c2), OrProverState::SimulatedP1(st1, st2)))
            }
            OrComposedWitness::Both((w1, w2)) => {
                let (c1, st1) = match P1::commit(&statement.0, &w1, rng) {
                    Some((com, st)) => (com, st),
                    None => return None,
                };
                let (c2, st2) = match P2::commit(&statement.1, &w2, rng) {
                    Some((com, st)) => (com, st),
                    None => return None,
                };

                Some(((c1, c2), OrProverState::BothHonest(st1, st2)))
            }
        }
    }

    fn challenge(rng: &mut RNG) -> Challenge {
        P1::challenge(rng)
    }

    fn response(
        statement: &Self::S,
        witness: &Self::W,
        challenge: &Challenge,
        state: &Self::ST,
    ) -> Self::RSP {
        match state {
            OrProverState::SimulatedP1(st1, st2) => unimplemented!(),
            OrProverState::SimulatedP2(st1, st2) => unimplemented!(),
            OrProverState::BothHonest(st1, st2) => unimplemented!(),
        }
    }

    fn check(
        statement: &Self::S,
        commitment: &Self::COM,
        challenge: &Challenge,
        response: &Self::RSP,
    ) -> bool {
        unimplemented!();
    }

    fn simulate(statement: &Self::S, rng: &mut RNG) -> (Self::COM, Self::STS) {
        unimplemented!();
    }
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
