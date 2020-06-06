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

pub struct DlogEq<RNG>
where
    RNG: RngCore + CryptoRng,
{
    phantom_rng: PhantomData<RNG>,
}

pub struct DlogEqStatement {
    g_1: RistrettoPoint,
    h_1: RistrettoPoint,
    g_2: RistrettoPoint,
    h_2: RistrettoPoint,
}

pub struct DlogEqWitness {
    x: Scalar,
}

pub struct DlogEqCommitment {
    c1: RistrettoPoint,
    c2: RistrettoPoint,
}

pub struct DlogEqProverState(Scalar);
pub struct DlogEqResponse(Scalar);

pub struct DlogEqProof {
    commitment: DlogEqCommitment,
    response: DlogEqResponse,
}

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
        DlogEqStatement {
            g_1: g_1,
            h_1: h_1,
            g_2: g_2,
            h_2: h_2,
        }
    }

    fn verify(&self, witness: &DlogEqWitness) -> bool {
        let h_1_vfy = witness.x * self.g_1;
        let h_2_vfy = witness.x * self.g_2;

        if self.h_1 == h_1_vfy && self.h_2 == h_2_vfy {
            return true;
        }
        false
    }
}

impl<DIG> Hashable<DIG> for DlogEqStatement
where
    DIG: Digest,
{
    fn hash(&self, state: &mut DIG) {
        state.input(self.g_1.compress().as_bytes());
        state.input(self.h_1.compress().as_bytes());
        state.input(self.g_2.compress().as_bytes());
        state.input(self.h_2.compress().as_bytes());
    }
}

impl<DIG> Hashable<DIG> for DlogEqCommitment
where
    DIG: Digest,
{
    fn hash(&self, state: &mut DIG) {
        state.input(self.c1.compress().as_bytes());
        state.input(self.c2.compress().as_bytes());
    }
}

impl DlogEqWitness {
    pub fn new(x: Scalar) -> Self {
        DlogEqWitness { x: x }
    }
}

impl<RNG> SigmaProtocol<RNG> for DlogEq<RNG>
where
    RNG: RngCore + CryptoRng,
{
    type S = DlogEqStatement;
    type W = DlogEqWitness;
    type COM = DlogEqCommitment;
    type ST = DlogEqProverState;
    type RSP = DlogEqResponse;
    type STS = DlogEqSimulatorState;

    fn commit(
        statement: &DlogEqStatement,
        witness: &DlogEqWitness,
        rng: &mut RNG,
    ) -> Result<(DlogEqCommitment, DlogEqProverState), Error> {
        if statement.verify(witness) != true {
            return Err(Error::InvalidWitness);
        }

        let r = Scalar::random(rng);
        let c1 = &r * statement.g_1;
        let c2 = &r * statement.g_2;

        let state = DlogEqProverState(r);
        let commitments = DlogEqCommitment { c1: c1, c2: c2 };

        Ok((commitments, state))
    }

    fn challenge(rng: &mut RNG) -> Challenge {
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
        let g_1s = statement.g_1 * response.0;
        let g_2s = statement.g_2 * response.0;

        let g_1v = commitment.c1 + statement.h_1 * challenge.0;
        let g_2v = commitment.c2 + statement.h_2 * challenge.0;

        if &g_1s == &g_1v && &g_2s == &g_2v {
            //TODO verify challenge
            return true;
        }
        false
    }

    fn simulate(
        statement: &DlogEqStatement,
        rng: &mut RNG,
    ) -> (DlogEqCommitment, DlogEqSimulatorState) {
        let ch = Scalar::random(rng);
        let rsp = Scalar::random(rng);
        let c1 = statement.g_1 * rsp - statement.h_1 * &ch;
        let c2 = statement.g_2 * rsp - statement.h_2 * &ch;

        (
            DlogEqCommitment { c1: c1, c2: c2 },
            DlogEqSimulatorState {
                challenge: Challenge(ch),
                response: DlogEqResponse(rsp),
            },
        )
    }
}

impl<RNG> FsConvertibleSigmaProtocol<RNG, Self> for DlogEq<RNG>
where
    RNG: RngCore + CryptoRng,
{
    type FSP = DlogEqProof;

    fn domain_separator() -> String {
        format!("{}", "dlogeq")
    }

    fn hash_challenge(statement: &DlogEqStatement, commitment: &DlogEqCommitment) -> Challenge {
        let dom_sep = DomainSeparator::from_string(Self::domain_separator());
        let mut h = DomainSeparatedHash::<Sha512>::new(dom_sep);
        statement.hash(&mut h);
        commitment.hash(&mut h);
        Challenge(Scalar::from_hash(h))
    }

    fn compile_proof(commitment: DlogEqCommitment, response: DlogEqResponse) -> DlogEqProof {
        DlogEqProof {
            commitment: commitment,
            response: response,
        }
    }

    fn unwrap_proof(proof: &DlogEqProof) -> (&DlogEqCommitment, &DlogEqResponse) {
        (&proof.commitment, &proof.response)
    }
}
