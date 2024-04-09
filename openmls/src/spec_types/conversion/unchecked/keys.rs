use crate::spec_types as private_types;
use crate::spec_types::conversion::unchecked::PrivateSpecType;
use openmls_spec_types as public_types;

impl PrivateSpecType for private_types::keys::InitKey {
    type Public = public_types::keys::InitKey;
    fn from_public_unchecked(init_key: public_types::keys::InitKey) -> Self {
        Self {
            key: private_types::hpke::HpkePublicKey::from_public_unchecked(init_key.key),
        }
    }
}

impl PrivateSpecType for private_types::keys::EncryptionKey {
    type Public = public_types::keys::EncryptionKey;
    fn from_public_unchecked(encryption_key: public_types::keys::EncryptionKey) -> Self {
        Self {
            key: private_types::hpke::HpkePublicKey::from_public_unchecked(encryption_key.key),
        }
    }
}

impl PrivateSpecType for private_types::keys::SignaturePublicKey {
    type Public = public_types::keys::SignaturePublicKey;
    fn from_public_unchecked(signature_key: public_types::keys::SignaturePublicKey) -> Self {
        Self {
            value: signature_key.value.into(),
        }
    }
}
