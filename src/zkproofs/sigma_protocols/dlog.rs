use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::{CryptoRng, RngCore};

use digest::generic_array::typenum::U64;
use digest::Digest;

use std::convert::From;

use crate::hashing::{DomainSeparatedHash, DomainSeparator, Hashable};
use crate::zkproofs::sigma_protocols::fiat_shamir::FsConvertibleSigmaProtocol;
use crate::zkproofs::sigma_protocols::{Challenge, Error, SigmaProtocol, SimulatorState};

pub struct Dlog;

#[derive(Clone)]
pub struct DlogStatement {
    g_1: RistrettoPoint,
    h_1: RistrettoPoint,
}

#[derive(Clone)]
pub struct DlogWitness {
    x: Scalar,
}

pub struct DlogCommitment {
    c1: RistrettoPoint,
}

#[derive(Clone)]
pub struct DlogProverState(Scalar);

#[derive(Clone)]
pub struct DlogResponse(Scalar);

#[derive(Clone)]
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
        DlogStatement { g_1, h_1 }
    }

    pub fn verify(&self, witness: &DlogWitness) -> bool {
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
        DlogWitness { x }
    }
}

/// Implementation of a Sigma protocol for the language
/// `S = { (g_1, g_2) | ∃ x : g_1^x = g_2 }`, where `g_1` and `g_2`
/// are elements of the underlying group.
impl SigmaProtocol for Dlog {
    type S = DlogStatement;
    type W = DlogWitness;
    type COM = DlogCommitment;
    type ST = DlogProverState;
    type RSP = DlogResponse;
    type STS = DlogSimulatorState;

    fn commit<RNG: RngCore + CryptoRng>(
        statement: &DlogStatement,
        witness: &DlogWitness,
        rng: &mut RNG,
    ) -> Result<(DlogCommitment, DlogProverState), Error> {
        if !statement.verify(witness) {
            return Err(Error::InvalidWitness);
        }

        let r = Scalar::random(rng);
        let c1 = &r * statement.g_1;

        let state = DlogProverState(r);
        let commitments = DlogCommitment { c1 };

        Ok((commitments, state))
    }

    fn challenge<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Challenge {
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

        if g_1s == g_1v {
            return true;
        }
        false
    }

    fn simulate<RNG: RngCore + CryptoRng>(
        statement: &DlogStatement,
        rng: &mut RNG,
    ) -> (DlogCommitment, DlogSimulatorState) {
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

/// Implementation of the FS conversion related functionality for a Sigma protocol
/// for the language `S = { (g_1, g_2) | ∃ x : g_1^x = g_2 }`, where `g_1` and `g_2`
/// are elements of the underlying group.
impl<DIG: Digest<OutputSize = U64>> FsConvertibleSigmaProtocol<Self, DIG> for Dlog {
    type FSP = DlogProof;

    fn domain_separator() -> String {
        "dlog".to_string()
    }

    fn hash_challenge(statement: &DlogStatement, commitment: &DlogCommitment) -> Challenge {
        let dom_sep = DomainSeparator::from_string(<Self as FsConvertibleSigmaProtocol<
            Self,
            DIG,
        >>::domain_separator());
        let mut h = DomainSeparatedHash::<DIG>::new();
        h.init(dom_sep);
        statement.hash(&mut h);
        commitment.hash(&mut h);
        Challenge(Scalar::from_hash(h))
    }

    fn compile_proof(commitment: DlogCommitment, response: DlogResponse) -> DlogProof {
        DlogProof {
            commitment,
            response,
        }
    }

    fn unwrap_proof(proof: &DlogProof) -> (&DlogCommitment, &DlogResponse) {
        (&proof.commitment, &proof.response)
    }
}
