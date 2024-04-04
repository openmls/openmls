use crate::spec_types as private_types;
use openmls_spec_types as public_types;

impl private_types::keys::InitKey {
    pub(in crate::spec_types) fn from_public(init_key: public_types::keys::InitKey) -> Self {
        Self {
            key: private_types::hpke::HpkePublicKey::from_public(init_key.key),
        }
    }
}

impl private_types::keys::EncryptionKey {
    pub(in crate::spec_types) fn from_public(
        encryption_key: public_types::keys::EncryptionKey,
    ) -> Self {
        Self {
            key: private_types::hpke::HpkePublicKey::from_public(encryption_key.key),
        }
    }
}

impl private_types::keys::SignaturePublicKey {
    pub(in crate::spec_types) fn from_public(
        signature_key: public_types::keys::SignaturePublicKey,
    ) -> Self {
        Self {
            value: signature_key.value.into(),
        }
    }
}
