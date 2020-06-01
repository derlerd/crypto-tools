mod chameleon_hashing;
mod encryption;
mod hashing;
mod zkproofs;

use rand::thread_rng;
use sha2::Sha512;

use curve25519_dalek::scalar::Scalar;

use crate::encryption::elgamal::{ElGamalMessage, ElGamalWithThreadRng};
use crate::encryption::EncryptionScheme;
use crate::zkproofs::sigma_protocols::dlog::{DlogStatement, DlogWithThreadRng, DlogWitness};
use crate::zkproofs::sigma_protocols::dlogeq::{
    DlogEqStatement, DlogEqWithThreadRng, DlogEqWitness,
};
use crate::zkproofs::sigma_protocols::SigmaProtocol;
use crate::zkproofs::{DlOrDlEqWithThreadRng, ProofSystem};

fn main() {
    let (sk, pk) = ElGamalWithThreadRng::key_gen(32, &mut thread_rng()).unwrap();

    let msg = ElGamalMessage::from_string::<Sha512>("test".to_string());

    let ctxt = ElGamalWithThreadRng::encrypt(&pk, msg, &mut thread_rng());

    let _ptxt = ElGamalWithThreadRng::decrypt(&sk, ctxt);

    let s_1 = Scalar::random(&mut thread_rng());
    let s_2 = Scalar::random(&mut thread_rng());

    let g_1 = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT.clone();
    let g_2 = &s_1 * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    let h_1 = &s_2 * &g_1;
    let h_2 = &s_2 * &g_2;

    let x1 = DlogEqStatement::new(g_1.clone(), h_1.clone(), g_2.clone(), h_2.clone());
    let w1 = DlogEqWitness::new(s_2.clone());

    let p1 = DlogEqWithThreadRng::prove(&x1, &w1, &mut thread_rng());

    let success = DlogEqWithThreadRng::verify(&x1, p1.unwrap());

    println!("{:?}", success);

    let x2 = DlogStatement::new(g_1.clone(), h_1.clone());
    let w2 = DlogWitness::new(s_2.clone());

    let p2 = DlogWithThreadRng::prove(&x2, &w2, &mut thread_rng());

    let success = DlogWithThreadRng::verify(&x2, p2.unwrap());

    println!("{:?}", success);

    let x = DlOrDlEqWithThreadRng::compile_statement(x2, x1);
    let w = DlOrDlEqWithThreadRng::compile_witness(Some(w2), Some(w1)).unwrap();

    let (c, st) = DlOrDlEqWithThreadRng::commit(&x, &w, &mut thread_rng()).unwrap();
    let ch = DlOrDlEqWithThreadRng::challenge(&mut thread_rng());
    let rsp = DlOrDlEqWithThreadRng::response(&x, &w, &ch, st);

    let success = DlOrDlEqWithThreadRng::check(&x, &c, &ch, &rsp);

    println!("{:?}", success);

    let p_or = DlOrDlEqWithThreadRng::prove(&x, &w, &mut thread_rng());

    let success = DlOrDlEqWithThreadRng::verify(&x, p_or.unwrap());

    println!("{:?}", success);
}
