use digest::Digest;

use std::marker::PhantomData;

pub struct DomainSeparator {
    bytes: Vec<u8>,
}

pub trait Hashable<DIG: Digest> {
    fn hash(&self, state: &mut DIG);
}

impl DomainSeparator {
    pub fn from_string(s: String) -> Self {
        let dom_sep = format!("{}{}", s.len().to_string(), s);
        DomainSeparator {
            bytes: dom_sep.into_bytes(),
        }
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
