//! A storage solution for cryptographic key material used in OpenMLS groups.
//!
//! This module provides access to the `KeyStore` struct, which manages the
//! storage of `CredentialBundle` and `KeyPackageBundle` instances for use in
//! one or more `ManagedGroup` instances. The development of this module is
//! tracked in #337, which also includes a roadmap.
//!
//! # Key Store API
//!
//! All functions accessible via the `KeyStore` API are thread safe, allowing
//! multiple concurrent read locks, on any category of stored key material (e.g.
//! `CredentialBundle` instances, "init" `KeyPackageBundle` instance).
//!
//! ## `CredentialBundle` Instances
//!
//! The API of the `KeyStore` allows the generation of `Credential` instances
//! via `generate_credential`, such that it stores the corresponding
//! `CredentialBundle`. After storing them, references to `CredentialBundle`
//! instances can be retrieved via `get_credential_bundle` using the
//! `SignaturePublicKey` of the corresponding `Credential` as index.
//!
//! ## Init `KeyPackageBundle` Instances
//!
//! Similarly, the `KeyStore` can generate "init" `KeyPackage` instances via
//! `generate_key_package` and store the corresponding `KeyPackageBundle`. Init
//! `KeyPackage` instances are meant to be published so other parties can use
//! them to add the publishing party to groups.
//!
//! ### `KeyPackageBundle` Ownership
//!
//! In contrast to the functions providing access to `CredentialBundle`
//! instances, the function to retrieve `KeyPackageBundle` instances deletes
//! them from the `KeyStore`. This is because each `ManagedGroup` currently owns
//! the `KeyPackageBundle` in its leaf, so upon creation of the group, it needs
//! to consume a `KeyPackageBundle` instance. Note, that in contrast to
//! `CredentialBundle` instances, `KeyPackageBundle` instances should not be
//! used across groups.
//!
//! This design is temporary and only until the `ManagedGroup` is refactored to
//! access its `KeyPackageBundle` via the `KeyStore`. Once this is the case, the
//! `take_key_package_bundle` will be deprecated in favor of a
//! `get_key_package_bundle`, which only returns a reference to the
//! `KeyPackageBundle`.
//!
//! # Example
//!
//! A simple example for the generation and the retrieval of a
//! `CredentialBundle` and a `KeyPackageBundle`.
//!
//! ```
//! use openmls::prelude::*;
//!
//! let key_store = KeyStore::default();
//!
//! let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
//!
//! // Generate a credential bundle with the matching signature scheme.
//! let alice_credential = key_store
//!     .generate_credential(
//!         "Alice".into(),
//!         CredentialType::Basic,
//!         SignatureScheme::from(ciphersuite_name),
//!     )
//!     .unwrap();
//!
//! // Generate a key package bundle.
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
//!
//! # Future Work
//!
//! A more detailed roadmap can be found in issue #337, but generally the plan is to
//! * move ownership of all `KeyPackageBundle` instances into the `KeyStore` and
//!   change the API from `take_` to `get_`
//! * keep track of which key material is (still) in use and where, as well as if it expires and when
//! * extend the API to allow for deletion of unused key material, expired or otherwise
//! * add a persistence layer

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
pub struct CbGuard<'a> {
    cbs: RwLockReadGuard<'a, HashMap<SignaturePublicKey, CredentialBundle>>,
    index: &'a SignaturePublicKey,
}

use std::ops::Deref;

impl<'b> Deref for CbGuard<'b> {
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
        // We unwrap here, because the two functions claiming a write lock on
        // `init_key_package_bundles` (this one and `generate_key_package`) only
        // hold the lock very briefly and should not panic during that period.
        let mut kpbs = self.init_key_package_bundles.write().unwrap();
        kpbs.remove(kp_hash)
    }

    /// Retrieve a `CbGuard` from the key store given the `SignaturePublicKey`
    /// of the corresponding `Credential`. The `CbGuard` can be dereferenced to
    /// obtain an `RwLock` on the desired `CredentialBundle`. Returns an error
    /// if no `CredentialBundle` can be found corresponding to the given
    /// `SignaturePublicKey`.
    pub(crate) fn get_credential_bundle<'key_store>(
        &'key_store self,
        signature_public_key: &'key_store SignaturePublicKey,
    ) -> Option<CbGuard> {
        let cbs = self.credential_bundles.read().unwrap();
        if !cbs.contains_key(signature_public_key) {
            return None;
        }
        Some(CbGuard {
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
        let kp = kpb.key_package().clone();
        // We unwrap here, because the two functions claiming write locks on
        // `init_key_package_bundles` (this one and `take_key_package_bundle`)
        // only hold the lock very briefly and should not panic during that
        // period.
        let mut kpbs = self.init_key_package_bundles.write().unwrap();
        kpbs.insert(kp.hash().clone(), kpb);
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
        let credential = cb.credential().clone();
        // We unwrap here, because this is the only function claiming a write
        // lock on `credential_bundles`. It only holds the lock very briefly and
        // should not panic during that period.
        let mut cbs = self.credential_bundles.write().unwrap();
        cbs.insert(credential.signature_key().clone(), cb);
        Ok(credential)
    }
}
