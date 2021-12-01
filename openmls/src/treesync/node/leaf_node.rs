use serde::{Deserialize, Serialize};

use crate::{
    ciphersuite::{HpkePrivateKey, HpkePublicKey},
    prelude::KeyPackage,
};

#[cfg(test)]
use openmls_traits::OpenMlsCryptoProvider;

#[cfg(test)]
use crate::{
    ciphersuite::Ciphersuite,
    credentials::{CredentialBundle, CredentialType::Basic},
    key_packages::KeyPackageBundle,
};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct LeafNode {
    key_package: KeyPackage,
    private_key_option: Option<HpkePrivateKey>,
}

impl LeafNode {
    pub(crate) fn public_key(&self) -> &HpkePublicKey {
        self.key_package.hpke_init_key()
    }

    pub(crate) fn private_key(&self) -> &Option<HpkePrivateKey> {
        &self.private_key_option
    }

    pub(crate) fn set_private_key(&mut self, private_key: HpkePrivateKey) {
        self.private_key_option = Some(private_key)
    }

    pub(crate) fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    #[cfg(test)]
    pub fn random(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> (Self, CredentialBundle) {
        let cb = CredentialBundle::new(
            "test".into(),
            Basic,
            ciphersuite.signature_scheme(),
            backend,
        )
        .expect("error creating CB");
        let kpb = KeyPackageBundle::new(&[ciphersuite.name()], &cb, backend, vec![])
            .expect("error creating KPB");
        let (kp, _leaf_secret, private_key) = kpb.into_parts();
        (
            LeafNode {
                key_package: kp,
                private_key_option: Some(private_key),
            },
            cb,
        )
    }
}

impl From<KeyPackage> for LeafNode {
    fn from(key_package: KeyPackage) -> Self {
        LeafNode {
            key_package,
            private_key_option: None,
        }
    }
}
