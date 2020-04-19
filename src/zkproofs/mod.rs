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

pub struct DlogEqProof {
    c1: RistrettoPoint,
    c2: RistrettoPoint,
    challenge: Scalar,
    response: Scalar,
}

impl<'a> DlogEqStatement<'a> {
    pub fn new(g_1: &'a RistrettoPoint, h_1: &'a RistrettoPoint, g_2: &'a RistrettoPoint, h_2: &'a RistrettoPoint) -> Self {
        DlogEqStatement {
            g_1: g_1,
            h_1: h_1,
            g_2: g_2,
            h_2: h_2,
        }
    }

    fn verify(&self, witness : &DlogEqWitness) -> bool{
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

pub trait ProofSystem<RNG, S, W, P> {
    fn prove(statement: &S, witness: &W, rng: &mut RNG) -> Option<P>;
    fn verify(statement: &S, proof: &P) -> bool;
}

impl<RNG: RngCore + CryptoRng> ProofSystem<RNG, DlogEqStatement<'_>, DlogEqWitness<'_>, DlogEqProof>
    for DlogEq<RNG>
{
    fn prove(statement: &DlogEqStatement, witness: &DlogEqWitness, rng: &mut RNG) -> Option<DlogEqProof> {
    	if statement.verify(witness) != true {
    		return None;
    	}

        let r = Scalar::random(rng);
        let c1 = &r * statement.g_1;
        let c2 = &r * statement.g_2;

        let ch = Scalar::random(rng); // TODO replace this with hash of challenge

        let s = &r + witness.x * ch;
 
        Some(DlogEqProof { c1 : c1, c2 : c2, challenge : ch, response : s })
    }

    fn verify(statement: &DlogEqStatement, proof: &DlogEqProof) -> bool {
        let g_1s = statement.g_1 * proof.response;
        let g_2s = statement.g_2 * proof.response;

        let g_1v = proof.c1 + statement.h_1 * proof.challenge;
        let g_2v = proof.c2 + statement.h_2 * proof.challenge; 

        if &g_1s == &g_1v && &g_2s == &g_2v { //TODO verify challenge
        	return true;
        } 
        false
    }
}

pub type DlogEqWithThreadRng = DlogEq<ThreadRng>;
