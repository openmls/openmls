use crate::spec_types as private_types;
use crate::spec_types::conversion::unchecked::PrivateSpecType;
use openmls_spec_types as public_types;

impl PrivateSpecType for private_types::hpke::HpkePublicKey {
    type Public = public_types::hpke::HpkePublicKey;
    fn from_public_unchecked(public_key: Self::Public) -> Self {
        Self(public_key.0)
    }
}

impl PrivateSpecType for private_types::hpke::HpkePrivateKey {
    type Public = public_types::hpke::HpkePrivateKey;
    fn from_public_unchecked(private_key: Self::Public) -> Self {
        Self(private_key.0.into())
    }
}

impl PrivateSpecType for private_types::hpke::HpkeKeyPair {
    type Public = public_types::hpke::HpkeKeyPair;
    fn from_public_unchecked(key_pair: Self::Public) -> Self {
        Self {
            private: private_types::hpke::HpkePrivateKey::from_public_unchecked(key_pair.private),
            public: private_types::hpke::HpkePublicKey::from_public_unchecked(key_pair.public),
        }
    }
}
