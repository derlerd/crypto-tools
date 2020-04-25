use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::ThreadRng;
use rand::{CryptoRng, RngCore};

use std::marker::PhantomData;

pub struct Dlog<RNG: RngCore + CryptoRng> {
    phantom_rng: PhantomData<RNG>,
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
pub struct DlogChallenge(Scalar);
pub struct DlogResponse(Scalar);

pub struct DlogProof {
    commitment: DlogCommitment,
    challenge: DlogChallenge,
    response: DlogResponse,
}

impl<'a> DlogStatement<'a> {
    pub fn new(
        g_1: &'a RistrettoPoint,
        h_1: &'a RistrettoPoint
    ) -> Self {
        DlogStatement {
            g_1: g_1,
            h_1: h_1
        }
    }

    fn verify(&self, witness: &DlogWitness) -> bool {
        let h_1_vfy = witness.x * self.g_1;

        if self.h_1 == &h_1_vfy {
            return true;
        }
        false
    }
}

impl<'a> DlogWitness<'a> {
    pub fn new(x: &'a Scalar) -> Self {
        DlogWitness { x: x }
    }
}

impl<'a, RNG: RngCore + CryptoRng> super::SigmaProtocol<'a, RNG> for Dlog<RNG> {
    type S = DlogStatement<'a>;
    type W = DlogWitness<'a>;
    type COM = DlogCommitment;
    type ST = DlogProverState;
    type CH = DlogChallenge;
    type RSP = DlogResponse;

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

    fn challenge(
        statement: &DlogStatement,
        commitment: &DlogCommitment,
        rng: &mut RNG,
    ) -> DlogChallenge {
        panic!("Challenge generation not properly implemented yet!");
    }

    fn response(
        _statement: &DlogStatement,
        witness: &DlogWitness,
        challenge: &DlogChallenge,
        state: &DlogProverState,
    ) -> DlogResponse {
        DlogResponse(&state.0 + witness.x * challenge.0)
    }

    fn check(
        statement: &DlogStatement,
        commitment: &DlogCommitment,
        challenge: &DlogChallenge,
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
}

impl<RNG: RngCore + CryptoRng> super::FiatShamirConvertibleSigmaProtocol<'_, RNG, Self> for Dlog<RNG> {
    type P = DlogProof;

    fn compile_proof(
        commitment: DlogCommitment,
        challenge: DlogChallenge,
        response: DlogResponse,
    ) -> DlogProof {
        DlogProof {
            commitment: commitment,
            challenge: challenge,
            response: response,
        }
    }

    fn unwrap_proof(proof: DlogProof) -> (DlogCommitment, DlogChallenge, DlogResponse) {
        (proof.commitment, proof.challenge, proof.response)
    }
}

pub type DlogWithThreadRng = Dlog<ThreadRng>;