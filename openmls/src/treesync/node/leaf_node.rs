//! This module contains the [`LeafNode`] struct and its implementation.
use serde::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafIndex,
    ciphersuite::{HpkePrivateKey, HpkePublicKey},
    key_packages::{KeyPackage, KeyPackageBundle},
};

/// This struct implements the MLS leaf node and contains a [`KeyPackage`] and
/// potentially a corresponding `HpkePrivateKey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafNode {
    // TODO[FK]: The entire leaf node will change as part of #819
    /// The position of this leaf in the tree.
    /// Note that this can be `None` when the leaf is not in the tree yet.
    leaf_index: Option<LeafIndex>,
    key_package: KeyPackage,
    private_key_option: Option<HpkePrivateKey>,
}

// When comparing leaf nodes we ignore the key package reference.
// Sometimes it's not set yet. This might be remedied in #731.
// Note that the key package reference is computed deterministically from the
// key package such that there no additional value in comparing it.
impl PartialEq for LeafNode {
    fn eq(&self, other: &Self) -> bool {
        self.key_package == other.key_package && self.private_key_option == other.private_key_option
    }
}

impl LeafNode {
    /// Build a new [`LeafNode`] from a [`KeyPackage`].
    pub(crate) fn new(key_package: KeyPackage) -> Self {
        Self {
            key_package,
            private_key_option: None,
            leaf_index: None,
        }
    }

    /// Build a new [`LeafNode`] from a [`KeyPackageBundle`].
    pub(crate) fn new_from_bundle(key_package_bundle: KeyPackageBundle) -> Self {
        let key_package = key_package_bundle.key_package;
        let private_key_option = Some(key_package_bundle.private_key);
        Self {
            key_package,
            private_key_option,
            leaf_index: None,
        }
    }

    /// Return a reference to the `public_key` of the [`KeyPackage`] in this
    /// node.
    pub(crate) fn public_key(&self) -> &HpkePublicKey {
        self.key_package.hpke_init_key()
    }

    /// Return a reference to the `private_key` corresponding to the
    /// [`KeyPackage`] in this node.
    #[cfg(not(any(feature = "test-utils", test)))]
    pub(in crate::treesync) fn private_key(&self) -> Option<&HpkePrivateKey> {
        self.private_key_option.as_ref()
    }

    /// Return a reference to the `private_key` corresponding to the
    /// [`KeyPackage`] in this node.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn private_key(&self) -> Option<&HpkePrivateKey> {
        self.private_key_option.as_ref()
    }

    /// Set the private key in this node.
    pub(in crate::treesync) fn set_private_key(&mut self, private_key: HpkePrivateKey) {
        self.private_key_option = Some(private_key)
    }

    /// Return a reference to the `key_package` of this node.
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }
}

impl From<KeyPackage> for LeafNode {
    fn from(key_package: KeyPackage) -> Self {
        LeafNode {
            key_package,
            private_key_option: None,
            leaf_index: None,
        }
    }
}
