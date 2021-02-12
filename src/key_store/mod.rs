//! A storage solution for private key material.
//!
//! This module provides access to the `KeyStore` struct, which manages the
//! storage of `CredentialBundle` and `KeyPackageBundle` instances. The
//! development of this module is tracked in #337, which also includes a
//! roadmap.
//!
//! The current key store enables the storage of `CredentialBundle` instances,
//! and grants access to `CredentialBundle` references via the
//! `SignaturePublicKey` of the corresponding `Credential`.
//!
//! A `KeyStore` is meant to be used across multiple `ManagedGroup` instances to
//! allow sharing the same `CredentialBundle`. If this is not desired, multiple
//! `KeyStore` instances can be used across groups.
//!
//! # Example
//!
//! A simple example for the generation and the retrieval of a
//! `CredentialBundle`.
//!
//! ``` let mut key_store = KeyStore::default();
//!
//! // Generate credential bundles
//! let alice_credential = key_store
//!     .generate_credential(
//!         "Alice".into(),
//!         CredentialType::Basic,
//!         SignatureScheme::ED25519,
//!     )
//!     .unwrap()
//!     .clone();
//!
//! let alice_credential_bundle = key_store
//!     .get_credential_bundle(alice_credential.signature_key())
//!     .unwrap();
//! ```
use std::{
    cell::{Ref, RefCell},
    collections::HashMap,
};

use crate::{
    ciphersuite::{CiphersuiteName, SignaturePublicKey, SignatureScheme},
    credentials::{Credential, CredentialBundle, CredentialType},
    extensions::Extension,
    key_packages::{KeyPackage, KeyPackageBundle},
};

pub mod errors;
//pub mod test;
//pub mod test2;

#[cfg(test)]
mod test_key_store;

pub use errors::KeyStoreError;

#[derive(Debug, Default)]
/// The `KeyStore` contains `CredentialBundle`s and `KeyPackageBundle`s and
/// makes them available via information in the corresponding `Credential` and
/// `KeyPackage` instances.
pub struct KeyStore {
    // Map from signature public keys to credential bundles
    credential_bundles: RefCell<HashMap<SignaturePublicKey, RefCell<CredentialBundle>>>,
    init_key_package_bundles: RefCell<HashMap<Vec<u8>, KeyPackageBundle>>,
}

impl KeyStore {
    /// Retrieve a `KeyPackageBundle` from the key store given the hash of the
    /// corresponding `KeyPackage`. This removes the `KeyPackageBundle` from the
    /// store. Returns an error if no `KeyPackageBundle` can be found
    /// corresponding to the given `KeyPackage` hash. TODO: This is not in use
    /// yet, because the groups are not yet refactored to use the key store for
    /// KeyPackageBundles.
    pub(crate) fn _get_key_package_bundle(
        &mut self,
        kp_hash: &[u8],
    ) -> Result<KeyPackageBundle, KeyStoreError> {
        let mut kpbs = self.init_key_package_bundles.borrow_mut();
        let kpb = kpbs
            .remove(kp_hash)
            .ok_or(KeyStoreError::NoMatchingKeyPackageBundle)?;
        Ok(kpb)
    }

    /// Retrieve a `CredentialBundle` reference from the key store given the
    /// `SignaturePublicKey` of the corresponding `Credential`. Returns an error
    /// if no `CredentialBundle` can be found corresponding to the given
    /// `SignaturePublicKey`. TODO: This is currently public, because the groups
    /// are not yet refactored to use the key store for KeyPackageBundles and
    /// thus in tests we need to access the credential bundle to create
    /// KeyPackageBundles ad-hoc.
    pub fn get_credential_bundle<'key_store>(
        &'key_store self,
        signature_public_key: &'key_store SignaturePublicKey,
    ) -> Option<Ref<'_, RefCell<CredentialBundle>>> {
        let cbs_ref = self.credential_bundles.borrow();
        if !cbs_ref.contains_key(signature_public_key) {
            return None;
        }
        Some(Ref::map(self.credential_bundles.borrow(), |cbs| {
            cbs.get(&signature_public_key).unwrap()
        }))
    }

    /// Generate a fresh `KeyPackageBundle` with the given parameters, store it
    /// in the `KeyStore` and return the corresponding `KeyPackage`. Throws an
    /// error if no `CredentialBundle` can be found in the `KeyStore`
    /// corresponding to the given `Credential` or if an error occurred during
    /// the creation of the `KeyPackageBundle`.
    pub fn generate_key_package(
        &mut self,
        ciphersuites: &[CiphersuiteName],
        credential: &Credential,
        extensions: Vec<Box<dyn Extension>>,
    ) -> Result<&KeyPackage, KeyStoreError> {
        let credential_bundle = self
            .get_credential_bundle(credential.signature_key())
            .ok_or(KeyStoreError::NoMatchingCredentialBundle)?;
        let kpb = KeyPackageBundle::new(ciphersuites, &credential_bundle.borrow(), extensions)?;
        let kp_hash = kpb.key_package().hash();
        let kpbs = self.init_key_package_bundles.borrow_mut();
        kpbs.insert(kp_hash.clone(), kpb);
        let kp = kpbs.get(&kp_hash).unwrap();
        Ok(&kp.key_package())
    }

    /// Generate a fresh `CredentialBundle` with the given parameters and store
    /// it in the `KeyStore`. Returns the corresponding `Credential` or an error
    /// if the creation of the `CredentialBundle` fails.
    pub fn generate_credential(
        &mut self,
        identity: Vec<u8>,
        credential_type: CredentialType,
        signature_scheme: SignatureScheme,
    ) -> Result<&Credential, KeyStoreError> {
        let cb = CredentialBundle::new(identity, credential_type, signature_scheme)?;
        let signature_key = cb.credential().signature_key().clone();
        let cbs = self.credential_bundles.borrow();
        cbs.insert(signature_key.clone(), RefCell::new(cb));
        let cb_ref = cbs.get(&signature_key).unwrap().borrow();
        let credential = cb_ref.credential();
        Ok(credential)
    }
}
