use crate::spec_types as private_types;
use openmls_spec_types as public_types;

pub(in crate::spec_types) trait PrivateSpecType {
    type Public;
    fn from_public_unchecked(v: Self::Public) -> Self;
}

mod credential;
mod extensions;
mod hpke;
mod key_package;
mod keys;
mod proposals;
mod psk;
mod tree;

impl PrivateSpecType for private_types::Lifetime {
    type Public = public_types::Lifetime;

    fn from_public_unchecked(lifetime: public_types::Lifetime) -> Self {
        Self {
            not_before: lifetime.not_before,
            not_after: lifetime.not_after,
        }
    }
}

impl PrivateSpecType for private_types::ProtocolVersion {
    type Public = public_types::ProtocolVersion;
    fn from_public_unchecked(version: public_types::ProtocolVersion) -> Self {
        match version {
            public_types::ProtocolVersion::Mls10 => private_types::ProtocolVersion::Mls10,
            public_types::ProtocolVersion::Mls10Draft11 => {
                private_types::ProtocolVersion::Mls10Draft11
            }
        }
    }
}

impl PrivateSpecType for private_types::Ciphersuite {
    type Public = public_types::Ciphersuite;
    fn from_public_unchecked(ciphersuite: public_types::Ciphersuite) -> Self {
        Self(ciphersuite.0)
    }
}

impl PrivateSpecType for private_types::Signature {
    type Public = public_types::Signature;
    fn from_public_unchecked(signature: public_types::Signature) -> Self {
        Self {
            value: signature.value.into(),
        }
    }
}

impl PrivateSpecType for private_types::GroupEpoch {
    type Public = public_types::GroupEpoch;
    fn from_public_unchecked(group_epoch: public_types::GroupEpoch) -> Self {
        Self(group_epoch.0)
    }
}

impl PrivateSpecType for private_types::GroupId {
    type Public = public_types::GroupId;
    fn from_public_unchecked(group_id: public_types::GroupId) -> Self {
        Self {
            value: group_id.value.into(),
        }
    }
}

impl PrivateSpecType for private_types::HashReference {
    type Public = public_types::HashReference;
    fn from_public_unchecked(hash_reference: public_types::HashReference) -> Self {
        Self {
            value: hash_reference.value.into(),
        }
    }
}
