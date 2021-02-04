use std::collections::HashMap;

use crate::{
    ciphersuite::{CiphersuiteName, SignaturePublicKey, SignatureScheme},
    credentials::{Credential, CredentialBundle, CredentialType},
    extensions::Extension,
    key_packages::{KeyPackage, KeyPackageBundle},
};

pub mod errors;

pub use errors::KeyStoreError;

#[derive(Debug, Default)]
/// The `KeyStore` contains private key material of `Credentials` and
/// `KeyPackage`s.
pub struct KeyStore {
    // Map from signature public keys to credential bundles
    credentials: HashMap<SignaturePublicKey, CredentialBundle>,
    key_packages: HashMap<Vec<u8>, KeyPackageBundle>,
}

impl KeyStore {
    /// Retrieve a `KeyPackageBundle` from the key store given the hash of the
    /// corresponding `KeyPackage`. Returns an error if no `KeyPackageBundle`
    /// can be found corresponding to the given `KeyPackage` hash. TODO: This is
    /// not in use yet, because the groups are not yet refactored to use the key
    /// store for KeyPackageBundle.
    pub(crate) fn _key_package_bundle(
        &self,
        kp_hash: &[u8],
    ) -> Result<&KeyPackageBundle, KeyStoreError> {
        self.key_packages
            .get(kp_hash)
            .ok_or(KeyStoreError::NoMatchingKeyPackageBundle)
    }

    /// Retrieve a `CredentialBundle` from the key store given the
    /// `SignaturePublicKey` of the corresponding `Credential`. Returns an error
    /// if no `CredentialBundle` can be found corresponding to the given
    /// `SignaturePublicKey`.
    /// TODO: This is currently public, because the groups are not yet
    /// refactored to use the key store for KeyPackageBundle.
    pub fn credential_bundle(
        &self,
        cred_pk: &SignaturePublicKey,
    ) -> Result<&CredentialBundle, KeyStoreError> {
        self.credentials
            .get(cred_pk)
            .ok_or(KeyStoreError::NoMatchingCredentialBundle)
    }

    /// Generate a fresh `KeyPackageBundle` with the given parameters, store it
    /// in the `KeyStore` and return the corresponding `KeyPackage`. Throws an
    /// error if no `CredentialBundle` can be found in the `KeyStore`
    /// corresponding to the given `Credential` or if an error occurred during
    /// the creation of the `KeyPackageBundle`.
    pub fn fresh_key_package(
        &mut self,
        ciphersuites: &[CiphersuiteName],
        credential: &Credential,
        extensions: Vec<Box<dyn Extension>>,
    ) -> Result<KeyPackage, KeyStoreError> {
        let credential_bundle = self.credential_bundle(credential.signature_key())?;
        let kpb = KeyPackageBundle::new(ciphersuites, credential_bundle, extensions)?;
        let kp = kpb.key_package().clone();
        let kp_hash = kp.hash();
        self.key_packages.insert(kp_hash, kpb);
        Ok(kp)
    }

    /// Generate a fresh `CredentialBundle` with the given parameters and store
    /// it in the `KeyStore`. Returns the corresponding `Credential`.
    pub fn fresh_credential(
        &mut self,
        identity: Vec<u8>,
        credential_type: CredentialType,
        signature_scheme: SignatureScheme,
    ) -> Result<Credential, KeyStoreError> {
        let cb = CredentialBundle::new(identity, credential_type, signature_scheme)?;
        let credential = cb.credential().clone();
        self.credentials
            .insert(credential.signature_key().clone(), cb);
        Ok(credential)
    }
}
