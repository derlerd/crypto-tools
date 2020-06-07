use digest::Digest;

use std::marker::PhantomData;

pub struct DomainSeparator {
    bytes: Vec<u8>,
}

/// Represents a object which can be hashed
pub trait Hashable<DIG: Digest> {
    /// Provide the object as input to the given hasher `state` 
    fn hash(&self, state: &mut DIG);
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

    /// Returns the domain separator as bytes so that it can be 
    /// provided as input to a `Digest`.
    pub fn to_bytes(&self) -> &Vec<u8> {
        &self.bytes
    }
}

// TODO: wrap the digest somehow to ensure that the domain separator
//       will survive reset of the digest (currently this is not an
//       issue because we never use `reset`).
pub struct DomainSeparatedHash<DIG: Digest> {
    phantom_digest: PhantomData<DIG>,
}

impl<DIG: Digest> DomainSeparatedHash<DIG> {
    /// Create a new domain separated hash. This includes obtaining an 
    /// instance of `DIG` via `DIG::new()`, providing the domain
    /// separator given in `context` as its first input and then
    /// returning the hasher state so that all hashes will out of the 
    /// box have the domain separator included. 
    pub fn new(context: DomainSeparator) -> DIG {
        let mut digest = DIG::new();
        digest.input(context.to_bytes());
        digest
    }
}
