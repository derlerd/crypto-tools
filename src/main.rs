mod encryption;
mod zkproofs;

use rand::thread_rng;
use sha2::Sha512;

use curve25519_dalek::scalar::Scalar;

use crate::encryption::{ElGamalMessage, ElGamalWithThreadRng, EncryptionScheme};
use crate::zkproofs::ProofSystem;
use crate::zkproofs::dlogeq::{DlogEqStatement, DlogEqWithThreadRng, DlogEqWitness};
use crate::zkproofs::dlog::{DlogStatement, DlogWithThreadRng, DlogWitness};

fn main() {
    let (sk, pk) = ElGamalWithThreadRng::key_gen(32, &mut thread_rng()).unwrap();

    let msg = ElGamalMessage::from_string::<Sha512>("test".to_string());

    let ctxt = ElGamalWithThreadRng::encrypt(pk, msg, &mut thread_rng());

    let _ptxt = ElGamalWithThreadRng::decrypt(sk, ctxt);

    let s_1 = Scalar::random(&mut thread_rng());
    let s_2 = Scalar::random(&mut thread_rng());

    let g_1 = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT.clone();
    let g_2 = &s_1 * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    let h_1 = &s_2 * &g_1;
    let h_2 = &s_2 * &g_2;

    let x = DlogEqStatement::new(&g_1, &h_1, &g_2, &h_2);
    let w = DlogEqWitness::new(&s_2);

    let p = DlogEqWithThreadRng::prove(&x, &w, &mut thread_rng());

    let success = DlogEqWithThreadRng::verify(&x, p.unwrap());

    println!("{:?}", success);

    let x = DlogStatement::new(&g_1, &h_1);
    let w = DlogWitness::new(&s_2);

    let p = DlogWithThreadRng::prove(&x, &w, &mut thread_rng());

    let success = DlogWithThreadRng::verify(&x, p.unwrap());

    println!("{:?}", success);
}
