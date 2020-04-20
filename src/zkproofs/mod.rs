use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::ThreadRng;
use rand::{CryptoRng, RngCore};
use std::marker::PhantomData;

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
    challenge: DlogEqChallenge,
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

impl<'a> DlogEqWitness<'a> {
    pub fn new(x: &'a Scalar) -> Self {
        DlogEqWitness { x: x }
    }
}

pub trait SigmaProtocol<'a, RNG> {
    type S;
    type W;
    type COM;
    type ST;
    type CH;
    type RSP;

    fn commit(
        statement: &Self::S,
        witness: &Self::W,
        rng: &mut RNG,
    ) -> Option<(Self::COM, Self::ST)>;
    fn challenge(statement: &Self::S, commitment: &Self::COM, rng: &mut RNG) -> Self::CH;
    fn response(
        statement: &Self::S,
        witness: &Self::W,
        challenge: &Self::CH,
        state: &Self::ST,
    ) -> Self::RSP;
    fn check(
        statement: &Self::S,
        commitment: &Self::COM,
        challenge: &Self::CH,
        response: &Self::RSP,
    ) -> bool;
}

pub trait FiatShamirConvertibleSigmaProtocol<'a, RNG, SP: SigmaProtocol<'a, RNG>> {
    type P;

    fn compile_proof(commitment: SP::COM, challenge: SP::CH, response: SP::RSP) -> Self::P;
    fn unwrap_proof(proof: Self::P) -> (SP::COM, SP::CH, SP::RSP);
}

impl<RNG: RngCore + CryptoRng> FiatShamirConvertibleSigmaProtocol<'_, RNG, Self> for DlogEq<RNG> {
    type P = DlogEqProof;

    fn compile_proof(
        commitment: DlogEqCommitment,
        challenge: DlogEqChallenge,
        response: DlogEqResponse,
    ) -> DlogEqProof {
        DlogEqProof {
            commitment: commitment,
            challenge: challenge,
            response: response,
        }
    }

    fn unwrap_proof(proof: DlogEqProof) -> (DlogEqCommitment, DlogEqChallenge, DlogEqResponse) {
        (proof.commitment, proof.challenge, proof.response)
    }
}

impl<'a, RNG: RngCore + CryptoRng> SigmaProtocol<'a, RNG> for DlogEq<RNG> {
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

    fn challenge(
        statement: &DlogEqStatement,
        commitment: &DlogEqCommitment,
        rng: &mut RNG,
    ) -> DlogEqChallenge {
        DlogEqChallenge(Scalar::one()) // TODO replace this with hash of challenge
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
}

pub trait ProofSystem<'a, RNG> {
    type S;
    type W;
    type P;

    fn prove(statement: &Self::S, witness: &Self::W, rng: &mut RNG) -> Option<Self::P>;
    fn verify(statement: &Self::S, proof: Self::P) -> bool;
}

impl<
        'a,
        RNG: RngCore + CryptoRng,
        SP: SigmaProtocol<'a, RNG> + FiatShamirConvertibleSigmaProtocol<'a, RNG, SP>,
    > ProofSystem<'a, RNG> for SP
{
    type S = SP::S;
    type W = SP::W;
    type P = SP::P;

    fn prove(statement: &Self::S, witness: &Self::W, rng: &mut RNG) -> Option<Self::P> {
        let (com, st) = match SP::commit(statement, witness, rng) {
            Some((com, st)) => (com, st),
            None => return None,
        };

        let ch = SP::challenge(statement, &com, rng); // TODO replace with RO challenge generation and drop challenge from proof

        let rsp = SP::response(statement, witness, &ch, &st);

        Some(SP::compile_proof(com, ch, rsp))
    }

    fn verify(statement: &Self::S, proof: Self::P) -> bool {
        let (commitment, challenge, response) = SP::unwrap_proof(proof);
        SP::check(
            statement,
            &commitment,
            &challenge, // TODO drop challenge from proof and recompute here
            &response,
        )
    }
}

pub type DlogEqWithThreadRng = DlogEq<ThreadRng>;
