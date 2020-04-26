use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::ThreadRng;
use rand::{CryptoRng, RngCore};

use std::marker::PhantomData;

use crate::hashing::{DomainSeparatedHash, DomainSeparator, Hashable};
use digest::Digest;
use sha2::Sha512;

pub struct DlogEq<RNG: RngCore + CryptoRng> {
    phantom_rng: PhantomData<RNG>,
}

pub struct DlogEqStatement<'a> {
    g_1: &'a RistrettoPoint,
    h_1: &'a RistrettoPoint,
    g_2: &'a RistrettoPoint,
    h_2: &'a RistrettoPoint,
}

pub struct DlogEqWitness<'a> {
    x: &'a Scalar,
}

pub struct DlogEqCommitment {
    c1: RistrettoPoint,
    c2: RistrettoPoint,
}

pub struct DlogEqProverState(Scalar);
pub struct DlogEqChallenge(Scalar);
pub struct DlogEqResponse(Scalar);

pub struct DlogEqProof {
    commitment: DlogEqCommitment,
    response: DlogEqResponse,
}

impl<'a> DlogEqStatement<'a> {
    pub fn new(
        g_1: &'a RistrettoPoint,
        h_1: &'a RistrettoPoint,
        g_2: &'a RistrettoPoint,
        h_2: &'a RistrettoPoint,
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

        if self.h_1 == &h_1_vfy && self.h_2 == &h_2_vfy {
            return true;
        }
        false
    }
}

impl<DIG: Digest> Hashable<DIG> for DlogEqStatement<'_> {
    fn hash(&self, state: &mut DIG) {
        state.input(self.g_1.compress().as_bytes());
        state.input(self.h_1.compress().as_bytes());
        state.input(self.g_2.compress().as_bytes());
        state.input(self.h_2.compress().as_bytes());
    }
}

impl<DIG: Digest> Hashable<DIG> for DlogEqCommitment {
    fn hash(&self, state: &mut DIG) {
        state.input(self.c1.compress().as_bytes());
        state.input(self.c2.compress().as_bytes());
    }
}

impl<'a> DlogEqWitness<'a> {
    pub fn new(x: &'a Scalar) -> Self {
        DlogEqWitness { x: x }
    }
}

impl<'a, RNG: RngCore + CryptoRng> super::SigmaProtocol<'a, RNG> for DlogEq<RNG> {
    type S = DlogEqStatement<'a>;
    type W = DlogEqWitness<'a>;
    type COM = DlogEqCommitment;
    type ST = DlogEqProverState;
    type CH = DlogEqChallenge;
    type RSP = DlogEqResponse;

    fn commit(
        statement: &DlogEqStatement,
        witness: &DlogEqWitness,
        rng: &mut RNG,
    ) -> Option<(DlogEqCommitment, DlogEqProverState)> {
        if statement.verify(witness) != true {
            return None;
        }

        let r = Scalar::random(rng);
        let c1 = &r * statement.g_1;
        let c2 = &r * statement.g_2;

        let state = DlogEqProverState(r);
        let commitments = DlogEqCommitment { c1: c1, c2: c2 };

        Some((commitments, state))
    }

    fn challenge(rng: &mut RNG) -> DlogEqChallenge {
        DlogEqChallenge(Scalar::random(rng))
    }

    fn response(
        _statement: &DlogEqStatement,
        witness: &DlogEqWitness,
        challenge: &DlogEqChallenge,
        state: &DlogEqProverState,
    ) -> DlogEqResponse {
        DlogEqResponse(&state.0 + witness.x * challenge.0)
    }

    fn check(
        statement: &DlogEqStatement,
        commitment: &DlogEqCommitment,
        challenge: &DlogEqChallenge,
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
        challenge: &DlogEqChallenge,
        rng: &mut RNG,
    ) -> (DlogEqCommitment, DlogEqResponse) {
        let rsp = Scalar::random(rng);
        let c1 = statement.g_1 * rsp - statement.h_1 * challenge.0;
        let c2 = statement.g_2 * rsp - statement.h_2 * challenge.0;

        (DlogEqCommitment { c1: c1, c2: c2 }, DlogEqResponse(rsp))
    }
}

impl<RNG: RngCore + CryptoRng> super::FsConvertibleSigmaProtocol<'_, RNG, Self> for DlogEq<RNG> {
    type P = DlogEqProof;

    fn hash_challenge(
        statement: &DlogEqStatement,
        commitment: &DlogEqCommitment,
    ) -> DlogEqChallenge {
        let dom_sep = DomainSeparator::from_string("dlogeq".to_string());
        let mut h = DomainSeparatedHash::<Sha512>::new(dom_sep);
        statement.hash(&mut h);
        commitment.hash(&mut h);
        DlogEqChallenge(Scalar::from_hash(h))
    }

    fn compile_proof(commitment: DlogEqCommitment, response: DlogEqResponse) -> DlogEqProof {
        DlogEqProof {
            commitment: commitment,
            response: response,
        }
    }

    fn unwrap_proof(proof: DlogEqProof) -> (DlogEqCommitment, DlogEqResponse) {
        (proof.commitment, proof.response)
    }
}

pub type DlogEqWithThreadRng = DlogEq<ThreadRng>;
