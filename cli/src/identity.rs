use std::mem::replace;

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme, OpenMlsCryptoProvider};

pub struct Identity {
    pub(crate) kpb: KeyPackageBundle,
    pub(crate) credential: CredentialBundle,
}

/// Stores KeyPackageBundle in the crypto_backend's keystore with the hash of
/// the keypackage as the key.
fn store_key_package_bundle_in_keystore(
    crypto_backend: &OpenMlsRustCrypto,
    key_package_bundle: &KeyPackageBundle,
) {
    crypto_backend
        .key_store()
        .store(
            key_package_bundle
                .key_package()
                .hash_ref(crypto_backend.crypto())
                .expect("Failed to hash KeyPackage.")
                .as_slice(),
            key_package_bundle,
        )
        .expect("Failed to store KeyPackage in keystore.");
}

/// Stores CredentialBundle in the crypto_backend's keystore with the
/// signature_key of the Credential as the key.
fn store_credential_bundle_in_keystore(
    crypto_backend: &OpenMlsRustCrypto,
    credential_bundle: &CredentialBundle,
) {
    crypto_backend
        .key_store()
        .store(
            &credential_bundle
                .credential()
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key"),
            credential_bundle,
        )
        .expect("Failed to store CredentialBundle in keystore.");
}

impl Identity {
    pub(crate) fn new(ciphersuite: Ciphersuite, crypto: &OpenMlsRustCrypto, id: &[u8]) -> Self {
        let credential_bundle = CredentialBundle::new(
            id.to_vec(),
            CredentialType::Basic,
            SignatureScheme::from(ciphersuite),
            crypto,
        )
        .unwrap();
        let key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite],
            &credential_bundle,
            crypto,
            Extensions::empty(),
        )
        .unwrap();

        store_key_package_bundle_in_keystore(crypto, &key_package_bundle);
        store_credential_bundle_in_keystore(crypto, &credential_bundle);
        Self {
            kpb: key_package_bundle,
            credential: credential_bundle,
        }
    }

    /// Update the key package bundle in this identity.
    /// The function returns the old `KeyPackageBundle`.
    pub fn update(&mut self, crypto: &OpenMlsRustCrypto) -> KeyPackageBundle {
        let ciphersuite = self.kpb.key_package().ciphersuite();
        let key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite],
            &self.credential,
            crypto,
            Extensions::empty(),
        )
        .unwrap();

        store_key_package_bundle_in_keystore(crypto, &key_package_bundle);

        replace(&mut self.kpb, key_package_bundle)
    }

    /// Get the plain credential as byte vector.
    pub fn credential(&self) -> &[u8] {
        self.credential.credential().identity()
    }
}
