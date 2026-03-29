#[cfg(test)]
mod tests;

use digest::Digest;

pub struct DomainSeparator {
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for DomainSeparator {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

/// Represents a object that can be hashed
pub trait Hashable<H: Hash> {
    /// Provide the object as input to the given hasher `state`
    fn hash(&self, state: &mut H);
}

pub trait Hash: Digest {
    fn new_with_separator(domain_separator: DomainSeparator) -> Self;
}

impl<D: Digest> Hash for D {
    fn new_with_separator(domain_separator: DomainSeparator) -> Self {
        let mut hash = D::new();
        hash.input(domain_separator);
        hash
    }
}

impl DomainSeparator {
    /// Creates a domain separator from a string `s`. The resulting
    /// domain separator is essentially the `into_bytes()` representation
    /// of the given string with its length prepended to avoid
    /// collisions between domain separators.
    pub fn from_string(s: String) -> Self {
        let dom_sep = format!("{}{}", s.len().to_string(), s);
        DomainSeparator {
            bytes: dom_sep.into_bytes(),
        }
    }
}
