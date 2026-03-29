use curve25519_dalek::scalar::Scalar;

use std::marker::PhantomData;

use rand_core::{CryptoRng, RngCore};

use hybrid_array::sizes::U64;

use crate::hashing::{DomainSeparator, Hash, Hashable};
use crate::zkproofs::sigma_protocols::fiat_shamir::FsConvertibleSigmaProtocol;
use crate::zkproofs::sigma_protocols::{Challenge, Error, SigmaProtocol, SimulatorState};

pub struct OrComposedSigmaProtocol<P1, P2>
where
    P1: SigmaProtocol,
    P2: SigmaProtocol,
{
    p1: PhantomData<P1>,
    p2: PhantomData<P2>,
}

#[derive(Clone)]
pub enum OrComposedWitness<P1, P2>
where
    P1: SigmaProtocol,
    P2: SigmaProtocol,
    <P1 as SigmaProtocol>::W: Clone,
    <P2 as SigmaProtocol>::W: Clone,
{
    WitnessP1(P1::W),
    WitnessP2(P2::W),
    Both((P1::W, P2::W)),
}

#[derive(Clone)]
pub enum OrProverState<P1, P2>
where
    P1: SigmaProtocol,
    P2: SigmaProtocol,
    <P1 as SigmaProtocol>::ST: Clone,
    <P2 as SigmaProtocol>::ST: Clone,
    <P1 as SigmaProtocol>::STS: Clone,
    <P2 as SigmaProtocol>::STS: Clone,
{
    SimulatedP1(P1::STS, P2::ST),
    SimulatedP2(P1::ST, P2::STS),
}

#[derive(Clone)]
pub struct OrComposedStatement<P1, P2>
where
    P1: SigmaProtocol,
    P2: SigmaProtocol,
    <P1 as SigmaProtocol>::S: Clone,
    <P2 as SigmaProtocol>::S: Clone,
{
    s1: P1::S,
    s2: P2::S,
}

pub struct OrComposedCommitment<P1: SigmaProtocol, P2: SigmaProtocol>(P1::COM, P2::COM);

pub struct OrComposedResponse<P1: SigmaProtocol, P2: SigmaProtocol>(Challenge, P1::RSP, P2::RSP);

impl<P1, P2, H> Hashable<H> for OrComposedStatement<P1, P2>
where
    P1: SigmaProtocol,
    P2: SigmaProtocol,
    <P1 as SigmaProtocol>::S: Hashable<H> + Clone,
    <P2 as SigmaProtocol>::S: Hashable<H> + Clone,
    H: Hash,
{
    fn hash(&self, state: &mut H) {
        self.s1.hash(state);
        self.s2.hash(state);
    }
}

impl<P1, P2, H> Hashable<H> for OrComposedCommitment<P1, P2>
where
    P1: SigmaProtocol,
    P2: SigmaProtocol,
    <P1 as SigmaProtocol>::COM: Hashable<H>,
    <P2 as SigmaProtocol>::COM: Hashable<H>,
    H: Hash,
{
    fn hash(&self, state: &mut H) {
        self.0.hash(state);
        self.1.hash(state);
    }
}

pub struct OrComposedProof<P1, P2>
where
    P1: SigmaProtocol,
    P2: SigmaProtocol,
{
    commitment: OrComposedCommitment<P1, P2>,
    response: OrComposedResponse<P1, P2>,
}

pub struct OrComposedSimulatorState<P1, P2>
where
    P1: SigmaProtocol,
    P2: SigmaProtocol,
{
    sts1: P1::STS,
    sts2: P2::STS,
}

impl<P1, P2> SimulatorState for OrComposedSimulatorState<P1, P2>
where
    P1: SigmaProtocol,
    P2: SigmaProtocol,
{
    type RSP = OrComposedResponse<P1, P2>;

    fn decompose(self) -> (Challenge, OrComposedResponse<P1, P2>) {
        let (c1, r1) = self.sts1.decompose();
        let (c2, r2) = self.sts2.decompose();
        ((&c1 + &c2), OrComposedResponse(c1, r1, r2))
    }
}

impl<P1, P2> OrComposedSigmaProtocol<P1, P2>
where
    P1: SigmaProtocol,
    P2: SigmaProtocol,
    <P1 as SigmaProtocol>::S: Clone,
    <P2 as SigmaProtocol>::S: Clone,
    <P1 as SigmaProtocol>::W: Clone,
    <P2 as SigmaProtocol>::W: Clone,
{
    pub fn compile_witness(
        w1: Option<P1::W>,
        w2: Option<P2::W>,
    ) -> Result<OrComposedWitness<P1, P2>, Error> {
        let w = match (w1, w2) {
            (Some(w1), None) => OrComposedWitness::WitnessP1(w1),
            (None, Some(w2)) => OrComposedWitness::WitnessP2(w2),
            (Some(w1), Some(w2)) => OrComposedWitness::Both((w1, w2)),
            _ => return Err(Error::InvalidWitness),
        };

        Ok(w)
    }

    pub fn compile_statement(s1: P1::S, s2: P2::S) -> OrComposedStatement<P1, P2> {
        OrComposedStatement { s1, s2 }
    }
}

/// Generic implementation of an OR composition of two `SigmaProtocols` implementing
/// the `FsConvertibleSigmaProtocol` trait and satisfying the additional given trait
/// bounds.
impl<P1, P2> SigmaProtocol for OrComposedSigmaProtocol<P1, P2>
where
    P1: SigmaProtocol,
    P2: SigmaProtocol,
    <P1 as SigmaProtocol>::S: Clone,
    <P2 as SigmaProtocol>::S: Clone,
    <P1 as SigmaProtocol>::W: Clone,
    <P2 as SigmaProtocol>::W: Clone,
    <P1 as SigmaProtocol>::ST: Clone,
    <P2 as SigmaProtocol>::ST: Clone,
    <P1 as SigmaProtocol>::STS: Clone,
    <P2 as SigmaProtocol>::STS: Clone,
{
    type S = OrComposedStatement<P1, P2>;
    type W = OrComposedWitness<P1, P2>;
    type COM = OrComposedCommitment<P1, P2>;
    type ST = OrProverState<P1, P2>;
    type RSP = OrComposedResponse<P1, P2>;
    type STS = OrComposedSimulatorState<P1, P2>;

    fn commit<RNG: RngCore + CryptoRng>(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Result<(Self::COM, Self::ST), Error> {
        match witness {
            OrComposedWitness::WitnessP1(w1) | OrComposedWitness::Both((w1, _)) => {
                let (c1, st1) = match P1::commit(&statement.s1, &w1, rng) {
                    Ok((com, st)) => (com, st),
                    Err(e) => return Err(e),
                };
                let (c2, st2) = P2::simulate(&statement.s2, rng);

                Ok((
                    OrComposedCommitment(c1, c2),
                    OrProverState::SimulatedP2(st1, st2),
                ))
            }
            OrComposedWitness::WitnessP2(w2) => {
                let (c2, st2) = match P2::commit(&statement.s2, &w2, rng) {
                    Ok((com, st)) => (com, st),
                    Err(e) => return Err(e),
                };
                let (c1, st1) = P1::simulate(&statement.s1, rng);

                Ok((
                    OrComposedCommitment(c1, c2),
                    OrProverState::SimulatedP1(st1, st2),
                ))
            }
        }
    }

    fn challenge<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Challenge {
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

                let rsp2 = P2::response(&statement.s2, w2, &ch2, st2);

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

                let rsp1 = P1::response(&statement.s1, w1, &ch1, st1);

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

        P1::check(&statement.s1, &commitment.0, ch1, &response.1)
            && P2::check(&statement.s2, &commitment.1, &ch2, &response.2)
    }

    fn simulate<RNG: RngCore + CryptoRng>(
        _statement: &Self::S,
        _rng: &mut RNG,
    ) -> (Self::COM, Self::STS) {
        unimplemented!();
    }
}

/// Generic implementation of the FS conversion related functionality for the OR
/// composition of two `SigmaProtocols` implementing the `FsConvertibleSigmaProtocol`
/// trait and satisfying the additional given trait bounds.
///
/// Intuitively, one can say that if two Sigma protocols are individually FS
/// convertible then so is their OR composition.
impl<P1, P2, H> FsConvertibleSigmaProtocol<Self, H> for OrComposedSigmaProtocol<P1, P2>
where
    H: Hash<OutputSize = U64>,
    P1: SigmaProtocol + FsConvertibleSigmaProtocol<P1, H>,
    P2: SigmaProtocol + FsConvertibleSigmaProtocol<P2, H>,
    <P1 as SigmaProtocol>::S: Hashable<H> + Clone,
    <P2 as SigmaProtocol>::S: Hashable<H> + Clone,
    <P1 as SigmaProtocol>::COM: Hashable<H>,
    <P2 as SigmaProtocol>::COM: Hashable<H>,
    <P1 as SigmaProtocol>::W: Clone,
    <P2 as SigmaProtocol>::W: Clone,
    <P1 as SigmaProtocol>::ST: Clone,
    <P2 as SigmaProtocol>::ST: Clone,
    <P1 as SigmaProtocol>::STS: Clone,
    <P2 as SigmaProtocol>::STS: Clone,
{
    type FSP = OrComposedProof<P1, P2>;

    fn domain_separator() -> String {
        format!(
            "or_composition({},{})",
            P1::domain_separator(),
            P2::domain_separator()
        )
    }

    fn hash_challenge(
        statement: &OrComposedStatement<P1, P2>,
        commitment: &OrComposedCommitment<P1, P2>,
    ) -> Challenge {
        let dom_sep = DomainSeparator::from_string(Self::domain_separator());
        let mut h = H::new_with_separator(dom_sep);
        statement.hash(&mut h);
        commitment.hash(&mut h);
        Challenge(Scalar::from_hash(h))
    }

    fn compile_proof(
        commitment: OrComposedCommitment<P1, P2>,
        response: OrComposedResponse<P1, P2>,
    ) -> OrComposedProof<P1, P2> {
        OrComposedProof {
            commitment,
            response,
        }
    }

    fn unwrap_proof(
        proof: &OrComposedProof<P1, P2>,
    ) -> (&OrComposedCommitment<P1, P2>, &OrComposedResponse<P1, P2>) {
        (&proof.commitment, &proof.response)
    }
}
