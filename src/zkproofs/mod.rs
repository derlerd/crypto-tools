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
	c2: RistrettoPoint
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

pub trait SigmaProtocol<RNG, S, W, COM, ST, CH, RSP> {
  	fn commit(statement : &S, witness : &W, rng : &mut RNG) -> Option<(COM, ST)>;
  	fn challenge(statement : &S, commitment : &COM, rng : &mut RNG) -> CH;
  	fn response(statement : &S, witness : &W, challenge : &CH, state : &ST) -> RSP;
  	fn check(statement : &S, commitment : &COM, challenge : &CH, response : &RSP) -> bool;
}

impl<RNG : RngCore + CryptoRng> SigmaProtocol<RNG, DlogEqStatement<'_>, DlogEqWitness<'_>, DlogEqCommitment, DlogEqProverState, DlogEqChallenge, DlogEqResponse> for DlogEq<RNG>
{
	fn commit(statement : &DlogEqStatement, witness : &DlogEqWitness, rng : &mut RNG) -> Option<(DlogEqCommitment, DlogEqProverState)> {
		if statement.verify(witness) != true {
    		return None;
    	}
         
        let r = Scalar::random(rng);
        let c1 = &r * statement.g_1;
        let c2 = &r * statement.g_2;
    	
    	let state = DlogEqProverState(r);
    	let commitments = DlogEqCommitment { c1 : c1, c2 : c2 };

    	Some((commitments, state))
	}

	fn challenge(statement : &DlogEqStatement, commitment : &DlogEqCommitment, rng : &mut RNG) -> DlogEqChallenge {
        DlogEqChallenge(Scalar::one()) // TODO replace this with hash of challenge
	}

	fn response(_statement : &DlogEqStatement, witness : &DlogEqWitness, challenge : &DlogEqChallenge, state : &DlogEqProverState) -> DlogEqResponse {
		DlogEqResponse(&state.0 + witness.x * challenge.0)
	}

	fn check(statement : &DlogEqStatement, commitment : &DlogEqCommitment, challenge : &DlogEqChallenge, response : &DlogEqResponse) -> bool {
		let g_1s = statement.g_1 * response.0;
        let g_2s = statement.g_2 * response.0;

        let g_1v = commitment.c1 + statement.h_1 * challenge.0;
        let g_2v = commitment.c2 + statement.h_2 * challenge.0; 

        if &g_1s == &g_1v && &g_2s == &g_2v { //TODO verify challenge
        	return true;
        } 
        false
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
    	let (com, st) = match DlogEq::<RNG>::commit(statement, witness, rng) {
    		Some((com, st)) => (com, st),
    		None => return None,
    	};

        let ch = DlogEq::<RNG>::challenge(statement, &com, rng); // replace with RO challenge generation
       
        let rsp = DlogEq::<RNG>::response(statement, witness, &ch, &st);
 
        Some(DlogEqProof { commitment : com, challenge : ch, response : rsp })
    }

    fn verify(statement: &DlogEqStatement, proof: &DlogEqProof) -> bool {
      DlogEq::<RNG>::check(statement, &proof.commitment, &proof.challenge, &proof.response)
    }
}

pub type DlogEqWithThreadRng = DlogEq<ThreadRng>;
