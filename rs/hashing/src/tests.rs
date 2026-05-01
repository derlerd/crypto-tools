use digest::{Digest, generic_array::GenericArray};
use sha2::Sha256;

use crate::{DomainSeparator, Hash};

fn initialize_hash_tuple(separator_string: &str) -> (Sha256, Sha256) {
    let mut h1 = Sha256::new();
    Digest::update(
        &mut h1,
        format!("{}{}", separator_string.len(), separator_string),
    );

    let context = DomainSeparator::from_string(separator_string.to_string());
    let h2 = Sha256::new_with_separator(context);

    (h1, h2)
}

#[test]
fn test_hashes_yield_same_result() {
    let (h1, h2) = initialize_hash_tuple("test");

    assert_eq!(
        h1.chain_update("test").finalize().as_slice(),
        h2.chain_update("test").finalize().as_slice()
    );
}

#[test]
fn test_reset_with_separator() {
    let separator_string = "reset_test";
    let (h1, mut h2) = initialize_hash_tuple(separator_string);

    h2.update("this is a test");
    h2.reset_with_separator(DomainSeparator::from_string(separator_string.to_string()));

    assert_eq!(
        h1.chain_update("test").finalize().as_slice(),
        h2.chain_update("test").finalize().as_slice()
    );
}

#[test]
fn test_finalize_reset_with_separator() {
    let separator_string = "reset_test";
    let separator = DomainSeparator::from_string(separator_string.to_string());
    let (h1, h2) = initialize_hash_tuple(separator_string);

    let h1_bytes = h1.chain_update("test").finalize();

    let mut h2 = h2.chain_update("test");
    let h2_bytes = h2.finalize_reset_with_separator(separator);
    assert_eq!(h1_bytes.as_slice(), h2_bytes.as_slice());

    assert_eq!(
        h1_bytes.as_slice(),
        h2.chain_update("test").finalize().as_slice()
    );
}

#[test]
fn test_finalize_into_reset_with_separator() {
    let separator_string = "into_reset_test";
    let separator = DomainSeparator::from_string(separator_string.to_string());
    let (h1, h2) = initialize_hash_tuple(separator_string);

    let h1_bytes = h1.chain_update("test").finalize();

    let mut h2 = h2.chain_update("test");
    let mut h2_bytes = GenericArray::default();
    h2.finalize_into_reset_with_separator(&mut h2_bytes, separator);
    assert_eq!(h1_bytes.as_slice(), h2_bytes.as_slice());

    assert_eq!(
        h1_bytes.as_slice(),
        h2.chain_update("test").finalize().as_slice()
    );
}
