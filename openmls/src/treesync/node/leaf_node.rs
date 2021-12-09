//! This module contains the [`LeafNode`] struct and its implementation.
use serde::{Deserialize, Serialize};

use crate::{
    ciphersuite::{HpkePrivateKey, HpkePublicKey},
    key_packages::{KeyPackage, KeyPackageBundle},
};

/// This struct implements the MLS leaf node and contains a [`KeyPackage`] and
/// potentially a corresponding [`HpkePrivateKey`].
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct LeafNode {
    key_package: KeyPackage,
    private_key_option: Option<HpkePrivateKey>,
}

impl LeafNode {
    /// Return a reference to the `public_key` of the [`KeyPackage`] in this
    /// node.
    pub(crate) fn public_key(&self) -> &HpkePublicKey {
        self.key_package.hpke_init_key()
    }

    /// Return a reference to the `private_key` corresponding to the
    /// [`KeyPackage`] in this node.
    pub(in crate::treesync) fn private_key(&self) -> &Option<HpkePrivateKey> {
        &self.private_key_option
    }

    /// Set the private key in this node.
    pub(in crate::treesync) fn set_private_key(&mut self, private_key: HpkePrivateKey) {
        self.private_key_option = Some(private_key)
    }

    /// Return a reference to the `key_package` of this node.
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

impl From<KeyPackageBundle> for LeafNode {
    fn from(key_package_bundle: KeyPackageBundle) -> Self {
        LeafNode {
            key_package: key_package_bundle.key_package,
            private_key_option: Some(key_package_bundle.private_key),
        }
    }
}
