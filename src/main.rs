mod encryption;

use rand::thread_rng;
use sha2::Sha512;

use crate::encryption::{ElGamalMessage, ElGamalWithThreadRng, EncryptionScheme};

fn main() {
    let (sk, pk) = ElGamalWithThreadRng::key_gen(32, &mut thread_rng()).unwrap();

    let msg = ElGamalMessage::from_string::<Sha512>("test".to_string());

    let ctxt = ElGamalWithThreadRng::encrypt(pk, msg, &mut thread_rng());

    let _ptxt = ElGamalWithThreadRng::decrypt(sk, ctxt);
}
