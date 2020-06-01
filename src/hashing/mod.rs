use digest::Digest;

use rand::{CryptoRng, RngCore};

use std::marker::PhantomData;

pub struct DomainSeparator {
    bytes: Vec<u8>,
}

pub trait Hashable<DIG: Digest> {
    fn hash(&self, state: &mut DIG);
}

#[allow(dead_code)]
impl DomainSeparator {
    pub fn from_string(s: String) -> Self {
        DomainSeparator {
            bytes: s.into_bytes(),
        }
    }

    pub fn from_bytes(b: Vec<u8>) -> Self {
        DomainSeparator { bytes: b }
    }

    pub fn random<RNG: CryptoRng + RngCore>() -> Self {
        unimplemented!();
    }

    pub fn to_bytes(&self) -> &Vec<u8> {
        &self.bytes
    }
}

pub struct DomainSeparatedHash<DIG: Digest> {
    phantom_digest: PhantomData<DIG>,
}

impl<DIG: Digest> DomainSeparatedHash<DIG> {
    pub fn new(context: DomainSeparator) -> DIG {
        let mut digest = DIG::new();
        digest.input(context.to_bytes());
        digest
    }
}
