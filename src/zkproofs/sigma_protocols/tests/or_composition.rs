use rand::thread_rng;
use sha2::Sha512;

use crate::zkproofs::sigma_protocols::dlog::Dlog;
use crate::zkproofs::sigma_protocols::dlogeq::DlogEq;
use crate::zkproofs::sigma_protocols::or_composition::{OrComposedStatement, OrComposedWitness};
use crate::zkproofs::sigma_protocols::{Error, SigmaProtocol};
use crate::zkproofs::{DlOrDlEq, FsProofSystem};
use crate::zkproofs::Error as ZkProofError;

fn get_valid_statement_witness_combinations_for_test() -> Vec<(
    OrComposedStatement<Dlog, DlogEq>,
    OrComposedWitness<Dlog, DlogEq>,
)> {
    use crate::zkproofs::sigma_protocols::tests::*;
    let (x1, w1) = dlog::create_dlog_statement_for_testing();
    let (x2, w2) = dlogeq::create_dlogeq_statement_for_testing();

    let x = DlOrDlEq::compile_statement(x1, x2);

    let wc1 = DlOrDlEq::compile_witness(Some(w1.clone()), None)
        .expect("Compiling witness (Some(w1), None) failed.");
    let wc2 = DlOrDlEq::compile_witness(None, Some(w2.clone()))
        .expect("Compiling witness (None, Some(w2)) failed.");
    let wc3 = DlOrDlEq::compile_witness(Some(w1), Some(w2))
        .expect("Compiling witness (Some(w1), Some(w2)) failed.");

    vec![(x.clone(), wc1), (x.clone(), wc2), (x, wc3)]
}

fn get_random_witness_combinations_for_test() -> Vec<OrComposedWitness<Dlog, DlogEq>> {
    use crate::zkproofs::sigma_protocols::tests::*;
    let (_, w1) = dlog::create_dlog_statement_for_testing();
    let (_, w2) = dlogeq::create_dlogeq_statement_for_testing();

    vec![
        DlOrDlEq::compile_witness(Some(w1.clone()), None)
            .expect("Compiling witness (Some(w1), None) failed."),
        DlOrDlEq::compile_witness(None, Some(w2.clone()))
            .expect("Compiling witness (None, Some(w2)) failed."),
        DlOrDlEq::compile_witness(Some(w1), Some(w2))
            .expect("Compiling witness (Some(w1), Some(w2)) failed."),
    ]
}

#[test]
fn test_bad_witness() {
    match DlOrDlEq::compile_witness(None, None) {
        Err(Error::InvalidWitness) => return,
        _ => panic!("Passed (None, None) to compile_witness but it didn't fail."),
    };
}

#[test]
fn test_commit_challenge_check() {
    for (x, w) in get_valid_statement_witness_combinations_for_test().iter() {
        let (com, st) = DlOrDlEq::commit(&x, &w, &mut thread_rng()).expect("Committing failed");
        let ch = DlOrDlEq::challenge(&mut thread_rng());
        let rsp = DlOrDlEq::response(&x, &w, &ch, st);

        assert_eq!(DlOrDlEq::check(&x, &com, &ch, &rsp), true);
    }
}

#[test]
fn test_response_with_wrong_witness() {
    for (x, w) in get_valid_statement_witness_combinations_for_test().iter() {
        let (com, st) = DlOrDlEq::commit(&x, &w, &mut thread_rng()).expect("Committing failed");
        let ch = DlOrDlEq::challenge(&mut thread_rng());

        for w_rand in get_random_witness_combinations_for_test().iter() {
            let result =
                std::panic::catch_unwind(|| DlOrDlEq::response(&x, &w_rand, &ch, st.clone()));

            match result {
                Ok(rsp) => assert_eq!(
                    DlOrDlEq::check(&x, &com, &ch, &rsp),
                    false,
                    "Check with response for random well-formed witness failed"
                ),
                Err(_) => continue,
            }
        }
    }
}

#[test]
fn test_prove_verify() {
    for (x, w) in get_valid_statement_witness_combinations_for_test().iter() {
        let p = <DlOrDlEq as FsProofSystem<Sha512>>::prove(&x, &w, &mut thread_rng())
            .expect("Proving valid statement failed");
        match <DlOrDlEq as FsProofSystem<Sha512>>::verify(&x, &p) {
            true => continue,
            _ => panic!("Expected that proof verification succeeds but it failed."),
        };
    }
}

#[test]
fn test_prove_fails() {
    for (x, _w) in get_valid_statement_witness_combinations_for_test().iter() {
    	for w in get_random_witness_combinations_for_test().iter() {
            match <DlOrDlEq as FsProofSystem<Sha512>>::prove(&x, &w, &mut thread_rng()) {
        	  Err(ZkProofError::InvalidWitness) => continue,
        	  _ => panic!("Call to prove with witness that is invalid for the given statement succeeded."),
            };
        }
    }
}