use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::{CryptoRng, RngCore};

use std::marker::PhantomData;

use digest::Digest;
use sha2::Sha512;

use std::convert::From;

use crate::hashing::{DomainSeparatedHash, DomainSeparator, Hashable};
use crate::zkproofs::sigma_protocols::fiat_shamir::FsConvertibleSigmaProtocol;
use crate::zkproofs::sigma_protocols::{Challenge, Error, SigmaProtocol, SimulatorState};

pub struct Dlog<RNG>
where
    RNG: RngCore + CryptoRng,
{
    phantom_rng: PhantomData<RNG>,
}

pub struct DlogStatement {
    g_1: RistrettoPoint,
    h_1: RistrettoPoint,
}

pub struct DlogWitness {
    x: Scalar,
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

impl From<Scalar> for DlogWitness {
    fn from(scalar: Scalar) -> DlogWitness {
        DlogWitness::new(scalar)
    }
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

impl DlogStatement {
    pub fn new(g_1: RistrettoPoint, h_1: RistrettoPoint) -> Self {
        DlogStatement { g_1: g_1, h_1: h_1 }
    }

    fn verify(&self, witness: &DlogWitness) -> bool {
        let h_1_vfy = witness.x * self.g_1;

        if self.h_1 == h_1_vfy {
            return true;
        }
        false
    }
}

impl<DIG> Hashable<DIG> for DlogStatement
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

impl DlogWitness {
    pub fn new(x: Scalar) -> Self {
        DlogWitness { x: x }
    }
}

impl<RNG> SigmaProtocol<RNG> for Dlog<RNG>
where
    RNG: RngCore + CryptoRng,
{
    type S = DlogStatement;
    type W = DlogWitness;
    type COM = DlogCommitment;
    type ST = DlogProverState;
    type RSP = DlogResponse;
    type STS = DlogSimulatorState;

    fn commit(
        statement: &DlogStatement,
        witness: &DlogWitness,
        rng: &mut RNG,
    ) -> Result<(DlogCommitment, DlogProverState), Error> {
        if statement.verify(witness) != true {
            return Err(Error::InvalidWitness);
        }

        let r = Scalar::random(rng);
        let c1 = &r * statement.g_1;

        let state = DlogProverState(r);
        let commitments = DlogCommitment { c1: c1 };

        Ok((commitments, state))
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

impl<RNG> FsConvertibleSigmaProtocol<RNG, Self> for Dlog<RNG>
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

    fn unwrap_proof(proof: &DlogProof) -> (&DlogCommitment, &DlogResponse) {
        (&proof.commitment, &proof.response)
    }
}
