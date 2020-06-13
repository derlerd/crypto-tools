#[cfg(test)]
mod tests;

use digest::Digest;

use digest::generic_array::GenericArray;

pub struct DomainSeparator {
    bytes: Vec<u8>,
}

/// Represents a object that can be hashed
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
    initialized: bool,
    digest: DIG,
}

impl<DIG: Digest> DomainSeparatedHash<DIG> {
    /// Initialize the DomainSeparatedHash with the domain separator
    /// given in `context` as its first input and then returning the
    /// hasher state so that all hashes will out of the box have the
    /// domain separator included.
    pub fn init(&mut self, context: DomainSeparator) {
        self.digest.input(context.to_bytes());
        self.initialized = true;
    }

    fn check_initialized(&self) {
        if self.initialized == false {
            panic!("DomainSeparatedHash not initialized");
        }
    }
}

/// Implementation of the Digest trait for a `DomainSeparatedHash`
/// wrapping some other `Digest`. Essentially this implementation
/// forwards all calls to the underlying digest and ensures that
/// for all methods a prior call to the `init` method of 
/// `DomainSeparatedHash` happened.
///
/// # Panics
/// In case one calls a method on an object of this type without
/// a prior call to `init`.
impl<DIG: Digest> Digest for DomainSeparatedHash<DIG> {
    type OutputSize = DIG::OutputSize;

    fn new() -> Self {
        DomainSeparatedHash {
            initialized: false,
            digest: DIG::new(),
        }
    }

    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.check_initialized();

        self.digest.input(data)
    }

    fn chain<B: AsRef<[u8]>>(self, data: B) -> Self
    where
        Self: Sized,
    {
        self.check_initialized();

        DomainSeparatedHash {
            initialized: self.initialized,
            digest: self.digest.chain(data),
        }
    }

    fn result(self) -> GenericArray<u8, DIG::OutputSize> {
        self.check_initialized();

        self.digest.result()
    }

    fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        self.check_initialized();

        self.initialized = false;
        self.digest.result_reset()
    }

    fn reset(&mut self) {
        self.check_initialized();

        self.initialized = false;
        self.digest.reset();
    }

    fn output_size() -> usize {
        DIG::output_size()
    }

    fn digest(_data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        panic!("Directly calling digest unsupported");
    }
}
