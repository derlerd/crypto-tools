pub mod dlog;
pub mod dlogeq;

use curve25519_dalek::scalar::Scalar;

use rand::rngs::ThreadRng;
use rand::{CryptoRng, RngCore};

use std::marker::PhantomData;

use std::ops::{Add, Sub};

use crate::zkproofs::dlog::Dlog;
use crate::zkproofs::dlogeq::DlogEq;

pub struct Challenge(Scalar);

impl Sub for &Challenge {
    type Output = Challenge;

    fn sub(self, other: &Challenge) -> Challenge {
        Challenge(self.0 - other.0)
    }
}

impl Add for &Challenge {
    type Output = Challenge;

    fn add(self, other: &Challenge) -> Challenge {
        Challenge(self.0 + other.0)
    }
}

pub trait SimulatorState {
    type RSP;
    fn decompose(self) -> (Challenge, Self::RSP);
}

pub trait SigmaProtocol<RNG> {
    type S;
    type W;
    type COM;
    type ST;
    type RSP;
    type STS: SimulatorState<RSP = Self::RSP>;

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
        state: Self::ST,
    ) -> Self::RSP;
    fn check(
        statement: &Self::S,
        commitment: &Self::COM,
        challenge: &Challenge,
        response: &Self::RSP,
    ) -> bool;
    fn simulate(statement: &Self::S, rng: &mut RNG) -> (Self::COM, Self::STS);
}

pub trait FsConvertibleSigmaProtocol<RNG, SP: SigmaProtocol<RNG>> {
    type P;

    fn hash_challenge(statement: &SP::S, commitment: &SP::COM) -> Challenge;
    fn compile_proof(commitment: SP::COM, response: SP::RSP) -> Self::P;
    fn unwrap_proof(proof: Self::P) -> (SP::COM, SP::RSP);
}

pub struct OrComposedSigmaProtocol<RNG, P1: SigmaProtocol<RNG>, P2: SigmaProtocol<RNG>>
{
    p1: PhantomData<P1>,
    p2: PhantomData<P2>,
    rng: PhantomData<RNG>,
}

pub enum OrComposedWitness<RNG, P1: SigmaProtocol<RNG>, P2: SigmaProtocol<RNG>> {
    WitnessP1(P1::W),
    WitnessP2(P2::W),
    Both((P1::W, P2::W)),
}

pub enum OrProverState<RNG, P1: SigmaProtocol<RNG>, P2: SigmaProtocol<RNG>> {
    SimulatedP1(P1::STS, P2::ST),
    SimulatedP2(P1::ST, P2::STS),
}

pub struct OrComposedSimulatorState<RNG, P1: SigmaProtocol<RNG>, P2: SigmaProtocol<RNG>>
{
    sts1: P1::STS,
    sts2: P2::STS,
}

impl<RNG: RngCore + CryptoRng, P1: SigmaProtocol<RNG>, P2: SigmaProtocol<RNG>>
    SimulatorState for OrComposedSimulatorState<RNG, P1, P2>
{
    type RSP = (Challenge, P1::RSP, P2::RSP);

    fn decompose(self) -> (Challenge, (Challenge, P1::RSP, P2::RSP)) {
        let (c1, r1) = self.sts1.decompose();
        let (c2, r2) = self.sts2.decompose();
        ((&c1 + &c2), (c1, r1, r2))
    }
}

impl<RNG: RngCore + CryptoRng, P1: SigmaProtocol<RNG>, P2: SigmaProtocol<RNG>>
    OrComposedSigmaProtocol<RNG, P1, P2>
{
    pub fn compile_witness(
        w1: Option<P1::W>,
        w2: Option<P2::W>,
    ) -> Option<OrComposedWitness<RNG, P1, P2>> {
        let w = match (w1, w2) {
            (Some(w1), None) => OrComposedWitness::WitnessP1(w1),
            (None, Some(w2)) => OrComposedWitness::WitnessP2(w2),
            (Some(w1), Some(w2)) => OrComposedWitness::Both((w1, w2)),
            _ => return None,
        };

        Some(w)
    }

    pub fn compile_statement(s1: P1::S, s2: P2::S) -> (P1::S, P2::S) {
        (s1, s2)
    }
}

impl<RNG: RngCore + CryptoRng, P1: SigmaProtocol<RNG>, P2: SigmaProtocol<RNG>>
    SigmaProtocol<RNG> for OrComposedSigmaProtocol<RNG, P1, P2>
{
    type S = (P1::S, P2::S);
    type W = OrComposedWitness<RNG, P1, P2>;
    type COM = (P1::COM, P2::COM);
    type ST = OrProverState<RNG, P1, P2>;
    type RSP = (Challenge, P1::RSP, P2::RSP);
    type STS = OrComposedSimulatorState<RNG, P1, P2>;

    fn commit(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Option<(Self::COM, Self::ST)> {
        match witness {
            OrComposedWitness::WitnessP1(w1) | OrComposedWitness::Both((w1, _)) => {
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
        }
    }

    fn challenge(rng: &mut RNG) -> Challenge {
        P1::challenge(rng)
    }

    fn response(
        statement: &Self::S,
        witness: &Self::W,
        challenge: &Challenge,
        state: Self::ST,
    ) -> Self::RSP {
        match state {
            OrProverState::SimulatedP1(st1, st2) => {
                let (ch1, rsp1) = st1.decompose();
                let ch2 = challenge - &ch1;

                let w2 = match witness {
                    OrComposedWitness::WitnessP2(w2) | OrComposedWitness::Both((_, w2)) => w2,
                    _ => {
                        panic!("Expected witness for statement 2 but got witness for statement 1.")
                    }
                };

                let rsp2 = P2::response(&statement.1, w2, &ch2, st2);

                (ch1, rsp1, rsp2)
            }
            OrProverState::SimulatedP2(st1, st2) => {
                let (ch2, rsp2) = st2.decompose();
                let ch1 = challenge - &ch2;

                let w1 = match witness {
                    OrComposedWitness::WitnessP1(w1) | OrComposedWitness::Both((w1, _)) => w1,
                    _ => {
                        panic!("Expected witness for statement 1 but got witness for statement 2.")
                    }
                };

                let rsp1 = P1::response(&statement.0, w1, &ch1, st1);

                (ch1, rsp1, rsp2)
            }
        }
    }

    fn check(
        statement: &Self::S,
        commitment: &Self::COM,
        challenge: &Challenge,
        response: &Self::RSP,
    ) -> bool {
        let ch1 = &response.0;
        let ch2 = challenge - ch1;

        P1::check(&statement.0, &commitment.0, ch1, &response.1)
            && P2::check(&statement.1, &commitment.1, &ch2, &response.2)
    }

    fn simulate(statement: &Self::S, rng: &mut RNG) -> (Self::COM, Self::STS) {
        unimplemented!();
    }
}

pub trait ProofSystem<RNG> {
    type S;
    type W;
    type P;

    fn prove(statement: &Self::S, witness: &Self::W, rng: &mut RNG) -> Option<Self::P>;
    fn verify(statement: &Self::S, proof: Self::P) -> bool;
}

impl<
        RNG: RngCore + CryptoRng,
        SP: SigmaProtocol<RNG> + FsConvertibleSigmaProtocol<RNG, SP>,
    > ProofSystem<RNG> for SP
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

        let rsp = SP::response(statement, witness, &ch, st);

        Some(SP::compile_proof(com, rsp))
    }

    fn verify(statement: &Self::S, proof: Self::P) -> bool {
        let (commitment, response) = SP::unwrap_proof(proof);
        let ch = SP::hash_challenge(statement, &commitment);
        SP::check(statement, &commitment, &ch, &response)
    }
}

pub(crate) type DlOrDlEq<'a, RNG> = OrComposedSigmaProtocol<RNG, Dlog<'a, RNG>, DlogEq<'a, RNG>>;

pub type DlOrDlEqWithThreadRng<'a> = DlOrDlEq<'a, ThreadRng>;
