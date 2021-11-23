use serde::{Deserialize, Serialize};

use crate::{
    ciphersuite::{HpkePrivateKey, HpkePublicKey},
    prelude::KeyPackage,
};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub(crate) struct LeafNode {
    key_package: KeyPackage,
    private_key_option: Option<HpkePrivateKey>,
}

impl LeafNode {
    pub(crate) fn public_key(&self) -> &HpkePublicKey {
        &self.key_package.hpke_init_key()
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
}

impl From<KeyPackage> for LeafNode {
    fn from(key_package: KeyPackage) -> Self {
        LeafNode {
            key_package,
            private_key_option: None,
        }
    }
}
