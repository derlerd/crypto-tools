use rand::thread_rng;
use sha2::Sha512;

use modern_crypto_tools::{
    chameleon_hashing::dss_pkc_20::DssPkc20, chameleon_hashing::ChameleonHash,
    encryption::elgamal::ElGamalMessage,
};

fn main() {
    let (sk, pk) = DssPkc20::key_gen(32, &mut thread_rng()).unwrap();

    let msg_original = ElGamalMessage::from_string::<Sha512>("Original".to_string());
    let (h, r) =
        DssPkc20::hash(&pk, msg_original.clone(), &mut thread_rng()).expect("Error upon hashing");
    let success = DssPkc20::check(&pk, msg_original.clone(), &r, &h);
    println!("Original hash verification success: {:?}", success);

    let msg_adapted = ElGamalMessage::from_string::<Sha512>("Adapted".to_string());
    let r_adapt = DssPkc20::adapt(&sk, &msg_original, &msg_adapted, &r, &h, &mut thread_rng())
        .expect("Error upon adapting");
    let success = DssPkc20::check(&pk, msg_adapted.clone(), &r_adapt, &h);

    println!("Adapted hash verification success: {:?}", success);
}
