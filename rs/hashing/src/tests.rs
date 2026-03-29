use digest::Digest;
use sha2::Sha256;

use crate::{DomainSeparator, Hash};

fn initialize_hash_tuple<H: Hash + Digest>() -> (impl Digest, impl Hash) {
    let mut h1 = H::new();
    Digest::update(&mut h1, "4test");

    let context = DomainSeparator::from_string("test".to_string());
    let h2 = H::new_with_separator(context);

    (h1, h2)
}

#[test]
fn test_hashes_yield_same_result() {
    let (h1, h2) = initialize_hash_tuple::<Sha256>();

    assert_eq!(
        h1.chain_update("test").finalize().as_slice(),
        h2.chain_update("test").finalize().as_slice()
    );
}
