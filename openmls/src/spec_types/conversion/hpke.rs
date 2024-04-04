use crate::spec_types as private_types;
use openmls_spec_types as public_types;

impl private_types::hpke::HpkePublicKey {
    pub(in crate::spec_types) fn from_public(
        public_key: public_types::hpke::HpkePublicKey,
    ) -> Self {
        Self(public_key.into())
    }
}

impl private_types::hpke::HpkePrivateKey {
    pub(in crate::spec_types) fn from_public(
        private_key: public_types::hpke::HpkePrivateKey,
    ) -> Self {
        Self(private_key.0.into())
    }
}

impl private_types::hpke::HpkeKeyPair {
    pub(in crate::spec_types) fn from_public(key_pair: public_types::hpke::HpkeKeyPair) -> Self {
        Self {
            private: private_types::hpke::HpkePrivateKey::from_public(key_pair.private),
            public: private_types::hpke::HpkePublicKey::from_public(key_pair.public),
        }
    }
}
