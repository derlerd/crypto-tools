use digest::{Digest, Reset};
use sha2::Sha256;

use crate::{DomainSeparator, Hash};

fn initialize_hash_tuple<H: Hash + Digest + Reset>(
    separator_string: &str,
) -> (impl Digest, impl Hash + Reset) {
    let mut h1 = H::new();
    Digest::update(
        &mut h1,
        format!("{}{}", separator_string.len(), separator_string),
    );

    let context = DomainSeparator::from_string(separator_string.to_string());
    let h2 = H::new_with_separator(context);

    (h1, h2)
}

#[test]
fn test_hashes_yield_same_result() {
    let (h1, h2) = initialize_hash_tuple::<Sha256>("test");

    assert_eq!(
        h1.chain_update("test").finalize().as_slice(),
        h2.chain_update("test").finalize().as_slice()
    );
}

#[test]
fn test_reset_hash_with_separator() {
    let separator_string = "reset_test";
    let (h1, mut h2) = initialize_hash_tuple::<Sha256>(separator_string);

    h2.update("this is a test");
    h2.reset_with_separator(DomainSeparator::from_string(separator_string.to_string()));

    assert_eq!(h1.chain_update("test").finalize().as_slice(),
        h2.chain_update("test").finalize().as_slice()
    );
}
