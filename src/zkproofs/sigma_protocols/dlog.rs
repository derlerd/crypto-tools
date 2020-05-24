use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::ThreadRng;
use rand::{CryptoRng, RngCore};

use std::marker::PhantomData;

use digest::Digest;
use sha2::Sha512;

use crate::hashing::{DomainSeparatedHash, DomainSeparator, Hashable};
use crate::zkproofs::sigma_protocols::fiat_shamir::FsConvertibleSigmaProtocol;
use crate::zkproofs::sigma_protocols::{Challenge, SigmaProtocol, SimulatorState};

pub struct Dlog<'a, RNG>
where
    RNG: RngCore + CryptoRng,
{
    phantom_rng: PhantomData<&'a RNG>,
}

pub struct DlogStatement<'a> {
    g_1: &'a RistrettoPoint,
    h_1: &'a RistrettoPoint,
}

pub struct DlogWitness<'a> {
    x: &'a Scalar,
}

pub struct DlogCommitment {
    c1: RistrettoPoint,
}

pub struct DlogProverState(Scalar);
pub struct DlogResponse(Scalar);

pub struct DlogSimulatorState {
    challenge: Challenge,
    response: DlogResponse,
}

impl SimulatorState for DlogSimulatorState {
    type RSP = DlogResponse;

    fn decompose(self) -> (Challenge, DlogResponse) {
        (self.challenge, self.response)
    }
}

pub struct DlogProof {
    commitment: DlogCommitment,
    response: DlogResponse,
}

impl<'a> DlogStatement<'a> {
    pub fn new(g_1: &'a RistrettoPoint, h_1: &'a RistrettoPoint) -> Self {
        DlogStatement { g_1: g_1, h_1: h_1 }
    }

    fn verify(&self, witness: &DlogWitness) -> bool {
        let h_1_vfy = witness.x * self.g_1;

        if self.h_1 == &h_1_vfy {
            return true;
        }
        false
    }
}

impl<DIG> Hashable<DIG> for DlogStatement<'_>
where
    DIG: Digest,
{
    fn hash(&self, state: &mut DIG) {
        state.input(self.g_1.compress().as_bytes());
        state.input(self.h_1.compress().as_bytes());
    }
}

impl<DIG> Hashable<DIG> for DlogCommitment
where
    DIG: Digest,
{
    fn hash(&self, state: &mut DIG) {
        state.input(self.c1.compress().as_bytes());
    }
}

impl<'a> DlogWitness<'a> {
    pub fn new(x: &'a Scalar) -> Self {
        DlogWitness { x: x }
    }
}

impl<'a, RNG> SigmaProtocol<RNG> for Dlog<'a, RNG>
where
    RNG: RngCore + CryptoRng,
{
    type S = DlogStatement<'a>;
    type W = DlogWitness<'a>;
    type COM = DlogCommitment;
    type ST = DlogProverState;
    type RSP = DlogResponse;
    type STS = DlogSimulatorState;

    fn commit(
        statement: &DlogStatement,
        witness: &DlogWitness,
        rng: &mut RNG,
    ) -> Option<(DlogCommitment, DlogProverState)> {
        if statement.verify(witness) != true {
            return None;
        }

        let r = Scalar::random(rng);
        let c1 = &r * statement.g_1;

        let state = DlogProverState(r);
        let commitments = DlogCommitment { c1: c1 };

        Some((commitments, state))
    }

    fn challenge(rng: &mut RNG) -> Challenge {
        Challenge(Scalar::random(rng))
    }

    fn response(
        _statement: &DlogStatement,
        witness: &DlogWitness,
        challenge: &Challenge,
        state: DlogProverState,
    ) -> DlogResponse {
        DlogResponse(&state.0 + witness.x * &challenge.0)
    }

    fn check(
        statement: &DlogStatement,
        commitment: &DlogCommitment,
        challenge: &Challenge,
        response: &DlogResponse,
    ) -> bool {
        let g_1s = statement.g_1 * response.0;

        let g_1v = commitment.c1 + statement.h_1 * challenge.0;

        if &g_1s == &g_1v {
            //TODO verify challenge
            return true;
        }
        false
    }

    fn simulate(statement: &DlogStatement, rng: &mut RNG) -> (DlogCommitment, DlogSimulatorState) {
        let ch = Scalar::random(rng);
        let rsp = Scalar::random(rng);
        let com = statement.g_1 * rsp - statement.h_1 * &ch;

        (
            DlogCommitment { c1: com },
            DlogSimulatorState {
                challenge: Challenge(ch),
                response: DlogResponse(rsp),
            },
        )
    }
}

impl<'a, RNG> FsConvertibleSigmaProtocol<RNG, Self> for Dlog<'a, RNG>
where
    RNG: RngCore + CryptoRng,
{
    type FSP = DlogProof;

    fn hash_challenge(statement: &DlogStatement, commitment: &DlogCommitment) -> Challenge {
        let dom_sep = DomainSeparator::from_string("dlog".to_string());
        let mut h = DomainSeparatedHash::<Sha512>::new(dom_sep);
        statement.hash(&mut h);
        commitment.hash(&mut h);
        Challenge(Scalar::from_hash(h))
    }

    fn compile_proof(commitment: DlogCommitment, response: DlogResponse) -> DlogProof {
        DlogProof {
            commitment: commitment,
            response: response,
        }
    }

    fn unwrap_proof(proof: DlogProof) -> (DlogCommitment, DlogResponse) {
        (proof.commitment, proof.response)
    }
}

pub type DlogWithThreadRng<'a> = Dlog<'a, ThreadRng>;
