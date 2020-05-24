use std::marker::PhantomData;

use rand::{CryptoRng, RngCore};

use digest::Digest;

use crate::hashing::Hashable;
use crate::zkproofs::sigma_protocols::{Challenge, SigmaProtocol, SimulatorState};

pub struct OrComposedSigmaProtocol<RNG, P1, P2>
where
    RNG: RngCore + CryptoRng,
    P1: SigmaProtocol<RNG>,
    P2: SigmaProtocol<RNG>,
{
    p1: PhantomData<P1>,
    p2: PhantomData<P2>,
    rng: PhantomData<RNG>,
}

pub enum OrComposedWitness<RNG, P1, P2>
where
    RNG: RngCore + CryptoRng,
    P1: SigmaProtocol<RNG>,
    P2: SigmaProtocol<RNG>,
{
    WitnessP1(P1::W),
    WitnessP2(P2::W),
    Both((P1::W, P2::W)),
}

pub enum OrProverState<RNG, P1, P2>
where
    RNG: RngCore + CryptoRng,
    P1: SigmaProtocol<RNG>,
    P2: SigmaProtocol<RNG>,
{
    SimulatedP1(P1::STS, P2::ST),
    SimulatedP2(P1::ST, P2::STS),
}

pub struct OrComposedStatement<
    RNG: RngCore + CryptoRng,
    P1: SigmaProtocol<RNG>,
    P2: SigmaProtocol<RNG>,
>(P1::S, P2::S);
pub struct OrComposedCommitment<
    RNG: RngCore + CryptoRng,
    P1: SigmaProtocol<RNG>,
    P2: SigmaProtocol<RNG>,
>(P1::COM, P2::COM);
pub struct OrComposedResponse<
    RNG: RngCore + CryptoRng,
    P1: SigmaProtocol<RNG>,
    P2: SigmaProtocol<RNG>,
>(Challenge, P1::RSP, P2::RSP);

impl<RNG, T, P1, P2, DIG> Hashable<DIG> for OrComposedStatement<RNG, P1, P2>
where
    RNG: RngCore + CryptoRng,
    T: Hashable<DIG>,
    P1: SigmaProtocol<RNG, S = T>,
    P2: SigmaProtocol<RNG, S = T>,
    DIG: Digest,
{
    fn hash(&self, state: &mut DIG) {
        self.0.hash(state);
        self.1.hash(state);
    }
}

impl<RNG, T, P1, P2, DIG> Hashable<DIG> for OrComposedCommitment<RNG, P1, P2>
where
    RNG: RngCore + CryptoRng,
    T: Hashable<DIG>,
    P1: SigmaProtocol<RNG, COM = T>,
    P2: SigmaProtocol<RNG, COM = T>,
    DIG: Digest,
{
    fn hash(&self, state: &mut DIG) {
        self.0.hash(state);
        self.1.hash(state);
    }
}

pub struct OrComposedProof<RNG, P1, P2>
where
    RNG: RngCore + CryptoRng,
    P1: SigmaProtocol<RNG>,
    P2: SigmaProtocol<RNG>,
{
    commitment: (P1::COM, P2::COM),
    response: (Challenge, P1::RSP, P2::RSP),
}

pub struct OrComposedSimulatorState<RNG, P1, P2>
where
    RNG: RngCore + CryptoRng,
    P1: SigmaProtocol<RNG>,
    P2: SigmaProtocol<RNG>,
{
    sts1: P1::STS,
    sts2: P2::STS,
}

impl<RNG: RngCore + CryptoRng, P1: SigmaProtocol<RNG>, P2: SigmaProtocol<RNG>> SimulatorState
    for OrComposedSimulatorState<RNG, P1, P2>
{
    type RSP = OrComposedResponse<RNG, P1, P2>;

    fn decompose(self) -> (Challenge, OrComposedResponse<RNG, P1, P2>) {
        let (c1, r1) = self.sts1.decompose();
        let (c2, r2) = self.sts2.decompose();
        ((&c1 + &c2), OrComposedResponse(c1, r1, r2))
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

    pub fn compile_statement(s1: P1::S, s2: P2::S) -> OrComposedStatement<RNG, P1, P2> {
        OrComposedStatement(s1, s2)
    }
}

impl<RNG: RngCore + CryptoRng, P1: SigmaProtocol<RNG>, P2: SigmaProtocol<RNG>> SigmaProtocol<RNG>
    for OrComposedSigmaProtocol<RNG, P1, P2>
{
    type S = OrComposedStatement<RNG, P1, P2>;
    type W = OrComposedWitness<RNG, P1, P2>;
    type COM = OrComposedCommitment<RNG, P1, P2>;
    type ST = OrProverState<RNG, P1, P2>;
    type RSP = OrComposedResponse<RNG, P1, P2>;
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

                Some((
                    OrComposedCommitment(c1, c2),
                    OrProverState::SimulatedP2(st1, st2),
                ))
            }
            OrComposedWitness::WitnessP2(w2) => {
                let (c2, st2) = match P2::commit(&statement.1, &w2, rng) {
                    Some((com, st)) => (com, st),
                    None => return None,
                };
                let (c1, st1) = P1::simulate(&statement.0, rng);

                Some((
                    OrComposedCommitment(c1, c2),
                    OrProverState::SimulatedP1(st1, st2),
                ))
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

                OrComposedResponse(ch1, rsp1, rsp2)
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

                OrComposedResponse(ch1, rsp1, rsp2)
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

    fn simulate(_statement: &Self::S, _rng: &mut RNG) -> (Self::COM, Self::STS) {
        unimplemented!();
    }
}
