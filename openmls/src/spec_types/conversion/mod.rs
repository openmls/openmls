use crate::spec_types as private_types;
use openmls_spec_types as public_types;

mod credential;
mod extensions;
mod hpke;
mod key_package;
mod keys;
mod proposals;
mod psk;
mod tree;

impl private_types::Lifetime {
    pub(in crate::spec_types) fn from_public(lifetime: public_types::Lifetime) -> Self {
        Self {
            not_before: lifetime.not_before,
            not_after: lifetime.not_after,
        }
    }
}

impl private_types::ProtocolVersion {
    pub(in crate::spec_types) fn from_public(version: public_types::ProtocolVersion) -> Self {
        match version {
            public_types::ProtocolVersion::Mls10 => private_types::ProtocolVersion::Mls10,
            public_types::ProtocolVersion::Mls10Draft11 => {
                private_types::ProtocolVersion::Mls10Draft11
            }
        }
    }
}

impl private_types::Ciphersuite {
    pub(in crate::spec_types) fn from_public(ciphersuite: public_types::Ciphersuite) -> Self {
        Self(ciphersuite.0)
    }
}

impl private_types::Signature {
    pub(in crate::spec_types) fn from_public(signature: public_types::Signature) -> Self {
        Self {
            value: signature.value.into(),
        }
    }
}

impl private_types::GroupEpoch {
    pub(in crate::spec_types) fn from_public(group_epoch: public_types::GroupEpoch) -> Self {
        Self(group_epoch.0)
    }
}

impl private_types::GroupId {
    pub(in crate::spec_types) fn from_public(group_id: public_types::GroupId) -> Self {
        Self {
            value: group_id.value.into(),
        }
    }
}

impl private_types::HashReference {
    pub(in crate::spec_types) fn from_public(hash_reference: public_types::HashReference) -> Self {
        Self {
            value: hash_reference.value.into(),
        }
    }
}
