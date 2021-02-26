//! A storage solution for cryptographic key material.
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
//! ```
//! use openmls::prelude::*;
//!
//! let key_store = KeyStore::default();
//!
//! // Generate a credential bundle.
//! let alice_credential = key_store
//!     .generate_credential(
//!         "Alice".into(),
//!         CredentialType::Basic,
//!         SignatureScheme::ED25519,
//!     )
//!     .unwrap();
//!
//! // Generate a key package bundle with a matching ciphersuite.
//! let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
//!
//! let alice_key_package = key_store
//!     .generate_key_package(&[ciphersuite_name], &alice_credential, vec![])
//!     .unwrap();
//!
//! // Create a group with the previously generated credential and key package.
//! let managed_group_config = ManagedGroupConfig::new(
//!     HandshakeMessageFormat::Plaintext,
//!     UpdatePolicy::default(),
//!     0,
//!     0,
//!     ManagedGroupCallbacks::default(),
//! );
//!
//! let alice_group = ManagedGroup::new(
//!     &key_store,
//!     &managed_group_config,
//!     GroupId::from_slice(b"Test Group"),
//!     &alice_key_package.hash(),
//! )
//! .unwrap();
//! ```
use std::{
    collections::HashMap,
    sync::{RwLock, RwLockReadGuard},
};

use crate::{
    ciphersuite::{CiphersuiteName, SignaturePublicKey, SignatureScheme},
    credentials::{Credential, CredentialBundle, CredentialType},
    extensions::Extension,
    key_packages::{KeyPackage, KeyPackageBundle},
};

pub mod errors;

#[cfg(test)]
mod test_key_store;

pub use errors::KeyStoreError;

#[derive(Debug, Default)]
/// The `KeyStore` contains `CredentialBundle`s and `KeyPackageBundle`s and
/// makes them available via information in the corresponding `Credential` and
/// `KeyPackage` instances.
pub struct KeyStore {
    // Map from signature public keys to credential bundles
    credential_bundles: RwLock<HashMap<SignaturePublicKey, CredentialBundle>>,
    init_key_package_bundles: RwLock<HashMap<Vec<u8>, KeyPackageBundle>>,
}

/// This guard struct for a `CredentialBundle` implements `Deref`, such that the
/// underlying `RwLock<CredentialBundle>` can be obtained for read or write
/// access to the credential.
pub struct CBGuard<'a> {
    cbs: RwLockReadGuard<'a, HashMap<SignaturePublicKey, CredentialBundle>>,
    index: &'a SignaturePublicKey,
}

use std::ops::Deref;

impl<'b> Deref for CBGuard<'b> {
    type Target = CredentialBundle;

    fn deref(&self) -> &CredentialBundle {
        // We can unwrap here, as we checked if the entry is present before
        // creating the guard. Also, since we hold a read lock on the `HashMap`,
        // the entry can't have been removed in the meantime.
        self.cbs.get(self.index).unwrap()
    }
}

impl KeyStore {
    /// Retrieve a `KeyPackageBundle` from the key store given the hash of the
    /// corresponding `KeyPackage`. This removes the `KeyPackageBundle` from the
    /// store. Returns an error if no `KeyPackageBundle` can be found
    /// corresponding to the given `KeyPackage` hash.
    pub fn take_key_package_bundle(&self, kp_hash: &[u8]) -> Option<KeyPackageBundle> {
        // We unwrap here, because the two functions claiming write locks (this
        // one and `generate_key_package`) only hold the lock very briefly and
        // should not panic during that period.
        let mut kpbs = self.init_key_package_bundles.write().unwrap();
        kpbs.remove(kp_hash)
    }

    /// Retrieve a `CBGuard` from the key store given the `SignaturePublicKey`
    /// of the corresponding `Credential`. The `CBGuard` can be dereferenced to
    /// obtain an `RwLock` on the desired `CredentialBundle`. Returns an error
    /// if no `CredentialBundle` can be found corresponding to the given
    /// `SignaturePublicKey`.
    pub(crate) fn get_credential_bundle<'key_store>(
        &'key_store self,
        signature_public_key: &'key_store SignaturePublicKey,
    ) -> Option<CBGuard> {
        let cbs = self.credential_bundles.read().unwrap();
        if !cbs.contains_key(signature_public_key) {
            return None;
        }
        Some(CBGuard {
            cbs,
            index: signature_public_key,
        })
    }

    /// Generate a fresh `KeyPackageBundle` with the given parameters, store it
    /// in the `KeyStore` and return the corresponding `KeyPackage`. Throws an
    /// error if no `CredentialBundle` can be found in the `KeyStore`
    /// corresponding to the given `Credential` or if an error occurred during
    /// the creation of the `KeyPackageBundle`.
    pub fn generate_key_package(
        &self,
        ciphersuites: &[CiphersuiteName],
        credential: &Credential,
        extensions: Vec<Box<dyn Extension>>,
    ) -> Result<KeyPackage, KeyStoreError> {
        let credential_bundle = self
            .get_credential_bundle(credential.signature_key())
            .ok_or(KeyStoreError::NoMatchingCredentialBundle)?;
        let kpb = KeyPackageBundle::new(ciphersuites, &credential_bundle, extensions)?;
        let kp_hash = kpb.key_package().hash();
        // We unwrap here, because the two functions claiming write locks (this
        // one and `take_key_package_bundle`) only hold the lock very briefly
        // and should not panic during that period.
        let mut kpbs = self.init_key_package_bundles.write().unwrap();
        kpbs.insert(kp_hash.clone(), kpb);
        let kp = kpbs.get(&kp_hash).unwrap().key_package().clone();
        Ok(kp)
    }

    /// Generate a fresh `CredentialBundle` with the given parameters and store
    /// it in the `KeyStore`. Returns the corresponding `Credential` or an error
    /// if the creation of the `CredentialBundle` fails.
    pub fn generate_credential(
        &self,
        identity: Vec<u8>,
        credential_type: CredentialType,
        signature_scheme: SignatureScheme,
    ) -> Result<Credential, KeyStoreError> {
        let cb = CredentialBundle::new(identity, credential_type, signature_scheme)?;
        let signature_key = cb.credential().signature_key().clone();
        let mut cbs = self.credential_bundles.write().unwrap();
        cbs.insert(signature_key.clone(), cb);
        let cb_ref = cbs.get(&signature_key).unwrap();
        let credential = cb_ref.credential().clone();
        Ok(credential)
    }
}
