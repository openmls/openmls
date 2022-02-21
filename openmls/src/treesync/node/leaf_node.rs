//! This module contains the [`LeafNode`] struct and its implementation.
use openmls_traits::crypto::OpenMlsCrypto;
use serde::{Deserialize, Serialize};

use crate::{
    ciphersuite::{hash_ref::KeyPackageRef, HpkePrivateKey, HpkePublicKey},
    error::LibraryError,
    key_packages::{KeyPackage, KeyPackageBundle},
};

/// This struct implements the MLS leaf node and contains a [`KeyPackage`] and
/// potentially a corresponding `HpkePrivateKey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafNode {
    key_package_ref: Option<KeyPackageRef>,
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
    pub(crate) fn new(
        key_package: KeyPackage,
        backend: &impl OpenMlsCrypto,
    ) -> Result<Self, LibraryError> {
        let key_package_ref = Some(key_package.hash_ref(backend)?);
        Ok(Self {
            key_package_ref,
            key_package,
            private_key_option: None,
        })
    }

    /// Build a new [`LeafNode`] from a [`KeyPackage`] and the corresponding
    /// [`KeyPackageRef`].
    pub(crate) fn new_with_ref(
        key_package: KeyPackage,
        key_package_ref: Option<KeyPackageRef>,
    ) -> Self {
        Self {
            key_package_ref,
            key_package,
            private_key_option: None,
        }
    }

    /// Build a new [`LeafNode`] from a [`KeyPackageBundle`].
    pub(crate) fn new_from_bundle(
        key_package_bundle: KeyPackageBundle,
        backend: &impl OpenMlsCrypto,
    ) -> Result<Self, LibraryError> {
        let key_package = key_package_bundle.key_package;
        let private_key_option = Some(key_package_bundle.private_key);
        let key_package_ref = Some(key_package.hash_ref(backend)?);
        Ok(Self {
            key_package_ref,
            key_package,
            private_key_option,
        })
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

    /// Return a [`KeyPackageRef`] of this node('s key package).
    /// Note that this returns `None` if the key package reference has not been
    /// set explicitly with [`Self::set_key_package_ref()`].
    pub(crate) fn key_package_ref(&self) -> Option<&KeyPackageRef> {
        self.key_package_ref.as_ref()
    }

    /// Set the [`KeyPackageRef`] for this leaf node.
    pub(crate) fn set_key_package_ref(
        &mut self,
        backend: &impl OpenMlsCrypto,
    ) -> Result<(), LibraryError> {
        self.key_package_ref = Some(self.key_package.hash_ref(backend)?);
        Ok(())
    }
}

impl From<KeyPackage> for LeafNode {
    fn from(key_package: KeyPackage) -> Self {
        LeafNode {
            key_package_ref: None,
            key_package,
            private_key_option: None,
        }
    }
}
