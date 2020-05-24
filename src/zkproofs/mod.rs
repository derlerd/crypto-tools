pub mod sigma_protocols;

use rand::rngs::ThreadRng;
use rand::{CryptoRng, RngCore};

use crate::zkproofs::sigma_protocols::dlog::Dlog;
use crate::zkproofs::sigma_protocols::dlogeq::DlogEq;
use crate::zkproofs::sigma_protocols::fiat_shamir::FsConvertibleSigmaProtocol;
use crate::zkproofs::sigma_protocols::or_composition::OrComposedSigmaProtocol;
use crate::zkproofs::sigma_protocols::SigmaProtocol;

pub trait ProofSystem<RNG> {
    type S;
    type W;
    type P;

    fn prove(statement: &Self::S, witness: &Self::W, rng: &mut RNG) -> Option<Self::P>;
    fn verify(statement: &Self::S, proof: Self::P) -> bool;
}

impl<RNG, SP> ProofSystem<RNG> for SP
where
    RNG: RngCore + CryptoRng,
    SP: SigmaProtocol<RNG> + FsConvertibleSigmaProtocol<RNG, SP>,
{
    type S = SP::S;
    type W = SP::W;
    type P = SP::FSP;

    fn prove(statement: &Self::S, witness: &Self::W, rng: &mut RNG) -> Option<Self::P> {
        let (com, st) = match SP::commit(statement, witness, rng) {
            Some((com, st)) => (com, st),
            None => return None,
        };

        let ch = SP::hash_challenge(statement, &com);

        let rsp = SP::response(statement, witness, &ch, st);

        Some(SP::compile_proof(com, rsp))
    }

    fn verify(statement: &Self::S, proof: Self::P) -> bool {
        let (commitment, response) = SP::unwrap_proof(proof);
        let ch = SP::hash_challenge(statement, &commitment);
        SP::check(statement, &commitment, &ch, &response)
    }
}

pub(crate) type DlOrDlEq<'a, RNG> = OrComposedSigmaProtocol<RNG, Dlog<'a, RNG>, DlogEq<'a, RNG>>;

pub type DlOrDlEqWithThreadRng<'a> = DlOrDlEq<'a, ThreadRng>;
