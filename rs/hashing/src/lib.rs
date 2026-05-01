#[cfg(test)]
mod tests;

use digest::{Digest, FixedOutputReset, Output, Reset};

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

/// Provides several convenience methods related to domain separated hashing
pub trait Hash: Digest {
    /// Similar to `Digest::new`, but updates the digest with `domain_separator`
    fn new_with_separator(domain_separator: DomainSeparator) -> Self;

    /// Similar to `Digest::finalize_reset`, but updates the digest with `domain_separator`
    fn finalize_reset_with_separator(&mut self, domain_separator: DomainSeparator) -> Output<Self>
    where
        Self: FixedOutputReset;

    /// Similar to `Digest::finalize_into_reset`, but updates the digest with
    /// `domain_separator`
    fn finalize_into_reset_with_separator(
        &mut self,
        out: &mut Output<Self>,
        domain_separator: DomainSeparator,
    ) where
        Self: FixedOutputReset;

    /// Similar to `Digest::reset`, but updates the digest with `domain_separator`
    fn reset_with_separator(&mut self, domain_separator: DomainSeparator)
    where
        Self: Reset;
}

impl<D: Digest> Hash for D {
    fn new_with_separator(domain_separator: DomainSeparator) -> Self {
        let mut hash = D::new();
        hash.update(domain_separator);
        hash
    }

    fn finalize_reset_with_separator(&mut self, domain_separator: DomainSeparator) -> Output<Self>
    where
        Self: FixedOutputReset,
    {
        let output = digest::Digest::finalize_reset(self);
        Digest::update(self, domain_separator);
        output
    }

    fn finalize_into_reset_with_separator(
        &mut self,
        out: &mut Output<Self>,
        domain_separator: DomainSeparator,
    ) where
        Self: FixedOutputReset,
    {
        digest::Digest::finalize_into_reset(self, out);
        Digest::update(self, domain_separator);
    }

    fn reset_with_separator(&mut self, domain_separator: DomainSeparator)
    where
        Self: Reset,
    {
        digest::Reset::reset(self);
        self.update(domain_separator);
    }
}

impl DomainSeparator {
    /// Creates a domain separator from a string `s`. The resulting
    /// domain separator is essentially the `into_bytes()` representation
    /// of the given string with its length prepended to avoid
    /// collisions between domain separators.
    pub fn from_string(s: String) -> Self {
        let dom_sep = format!("{}{}", s.len(), s);
        DomainSeparator {
            bytes: dom_sep.into_bytes(),
        }
    }
}
