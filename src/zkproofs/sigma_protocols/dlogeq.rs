use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use hybrid_array::sizes::U64;
use rand_core::{CryptoRng, RngCore};

use std::convert::From;

use crate::hashing::{DomainSeparator, Hash, Hashable};
use crate::zkproofs::sigma_protocols::fiat_shamir::FsConvertibleSigmaProtocol;
use crate::zkproofs::sigma_protocols::{Challenge, Error, SigmaProtocol, SimulatorState};

#[derive(Clone)]
pub struct DlogEq;

#[derive(Clone)]
pub struct DlogEqStatement {
    g_1: RistrettoPoint,
    h_1: RistrettoPoint,
    g_2: RistrettoPoint,
    h_2: RistrettoPoint,
}

#[derive(Clone)]
pub struct DlogEqWitness {
    x: Scalar,
}

pub struct DlogEqCommitment {
    c1: RistrettoPoint,
    c2: RistrettoPoint,
}

#[derive(Clone)]
pub struct DlogEqProverState(Scalar);

#[derive(Clone)]
pub struct DlogEqResponse(Scalar);

pub struct DlogEqProof {
    commitment: DlogEqCommitment,
    response: DlogEqResponse,
}

#[derive(Clone)]
pub struct DlogEqSimulatorState {
    challenge: Challenge,
    response: DlogEqResponse,
}

impl
    From<(
        (RistrettoPoint, RistrettoPoint),
        (RistrettoPoint, RistrettoPoint),
    )> for DlogEqStatement
{
    fn from(
        tuple: (
            (RistrettoPoint, RistrettoPoint),
            (RistrettoPoint, RistrettoPoint),
        ),
    ) -> DlogEqStatement {
        DlogEqStatement::new((tuple.0).0, (tuple.0).1, (tuple.1).0, (tuple.1).1)
    }
}

impl From<Scalar> for DlogEqWitness {
    fn from(scalar: Scalar) -> DlogEqWitness {
        DlogEqWitness::new(scalar)
    }
}

impl SimulatorState for DlogEqSimulatorState {
    type RSP = DlogEqResponse;

    fn decompose(self) -> (Challenge, DlogEqResponse) {
        (self.challenge, self.response)
    }
}

impl DlogEqStatement {
    pub fn new(
        g_1: RistrettoPoint,
        h_1: RistrettoPoint,
        g_2: RistrettoPoint,
        h_2: RistrettoPoint,
    ) -> Self {
        DlogEqStatement { g_1, h_1, g_2, h_2 }
    }

    pub fn verify(&self, witness: &DlogEqWitness) -> bool {
        let h_1_vfy = witness.x * self.g_1;
        let h_2_vfy = witness.x * self.g_2;

        if self.h_1 == h_1_vfy && self.h_2 == h_2_vfy {
            return true;
        }
        false
    }
}

impl<H> Hashable<H> for DlogEqStatement
where
    H: Hash,
{
    fn hash(&self, state: &mut H) {
        state.input(self.g_1.compress().as_bytes());
        state.input(self.h_1.compress().as_bytes());
        state.input(self.g_2.compress().as_bytes());
        state.input(self.h_2.compress().as_bytes());
    }
}

impl<H> Hashable<H> for DlogEqCommitment
where
    H: Hash,
{
    fn hash(&self, state: &mut H) {
        state.input(self.c1.compress().as_bytes());
        state.input(self.c2.compress().as_bytes());
    }
}

impl DlogEqWitness {
    pub fn new(x: Scalar) -> Self {
        DlogEqWitness { x }
    }
}

/// Implementation of a Sigma protocol for the language
/// `S = { (g_1, g_2, h_1, h_2) | ∃ x : g_1^x = g_2 ∧ h_1^x = h_2 }`,
/// where `g_1`, g_2`, `h_1`, and `h_2` are elements of the underlying
/// group.
impl SigmaProtocol for DlogEq {
    type S = DlogEqStatement;
    type W = DlogEqWitness;
    type COM = DlogEqCommitment;
    type ST = DlogEqProverState;
    type RSP = DlogEqResponse;
    type STS = DlogEqSimulatorState;

    fn commit<RNG: RngCore + CryptoRng>(
        statement: &DlogEqStatement,
        witness: &DlogEqWitness,
        rng: &mut RNG,
    ) -> Result<(DlogEqCommitment, DlogEqProverState), Error> {
        if !statement.verify(witness) {
            return Err(Error::InvalidWitness);
        }

        let r = Scalar::random(rng);
        let c1 = &r * statement.g_1;
        let c2 = &r * statement.g_2;

        let state = DlogEqProverState(r);
        let commitments = DlogEqCommitment { c1, c2 };

        Ok((commitments, state))
    }

    fn challenge<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Challenge {
        Challenge(Scalar::random(rng))
    }

    fn response(
        _statement: &DlogEqStatement,
        witness: &DlogEqWitness,
        challenge: &Challenge,
        state: DlogEqProverState,
    ) -> DlogEqResponse {
        DlogEqResponse(&state.0 + witness.x * &challenge.0)
    }

    fn check(
        statement: &DlogEqStatement,
        commitment: &DlogEqCommitment,
        challenge: &Challenge,
        response: &DlogEqResponse,
    ) -> bool {
        let g_1s = &statement.g_1 * &response.0;
        let g_2s = &statement.g_2 * &response.0;

        let g_1v = &commitment.c1 + &statement.h_1 * &challenge.0;
        let g_2v = &commitment.c2 + &statement.h_2 * &challenge.0;

        if g_1s == g_1v && g_2s == g_2v {
            return true;
        }
        false
    }

    fn simulate<RNG: RngCore + CryptoRng>(
        statement: &DlogEqStatement,
        rng: &mut RNG,
    ) -> (DlogEqCommitment, DlogEqSimulatorState) {
        let ch = Scalar::random(rng);
        let rsp = Scalar::random(rng);
        let c1 = &statement.g_1 * &rsp - &statement.h_1 * &ch;
        let c2 = &statement.g_2 * &rsp - &statement.h_2 * &ch;

        (
            DlogEqCommitment { c1, c2 },
            DlogEqSimulatorState {
                challenge: Challenge(ch),
                response: DlogEqResponse(rsp),
            },
        )
    }
}

/// Implementation of the FS conversion related functionality for a Sigma protocol
/// for the language `S = { (g_1, g_2, h_1, h_2) | ∃ x : g_1^x = g_2 ∧ h_1^x = h_2 }`,
/// where `g_1`, g_2`, `h_1`, and `h_2` are elements of the underlying group.
impl<H: Hash<OutputSize = U64>> FsConvertibleSigmaProtocol<Self, H> for DlogEq {
    type FSP = DlogEqProof;

    fn domain_separator() -> String {
        "dlogeq".to_string()
    }

    fn hash_challenge(statement: &DlogEqStatement, commitment: &DlogEqCommitment) -> Challenge {
        let dom_sep = DomainSeparator::from_string(
            <Self as FsConvertibleSigmaProtocol<Self, H>>::domain_separator(),
        );
        let mut h = H::new_with_separator(dom_sep);
        statement.hash(&mut h);
        commitment.hash(&mut h);
        Challenge(Scalar::from_hash(h))
    }

    fn compile_proof(commitment: DlogEqCommitment, response: DlogEqResponse) -> DlogEqProof {
        DlogEqProof {
            commitment,
            response,
        }
    }

    fn unwrap_proof(proof: &DlogEqProof) -> (&DlogEqCommitment, &DlogEqResponse) {
        (&proof.commitment, &proof.response)
    }
}
