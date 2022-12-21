use std::mem::replace;

use openmls::prelude::{config::CryptoConfig, *};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme, OpenMlsCryptoProvider};

pub struct Identity {
    pub(crate) kp: KeyPackage,
    pub(crate) credential: CredentialBundle,
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

        let key_package = KeyPackage::create(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            crypto,
            &credential_bundle,
            vec![],
            vec![],
        )
        .unwrap();

        store_credential_bundle_in_keystore(crypto, &credential_bundle);
        Self {
            kp: key_package,
            credential: credential_bundle,
        }
    }

    /// Update the key package in this identity.
    /// The function returns the old `KeyPackage`.
    pub fn update(&mut self, crypto: &OpenMlsRustCrypto) -> KeyPackage {
        let ciphersuite = self.kp.ciphersuite();

        let key_package = KeyPackage::create(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            crypto,
            &self.credential,
            vec![],
            vec![],
        )
        .unwrap();

        replace(&mut self.kp, key_package)
    }

    /// Get the plain credential as byte vector.
    pub fn credential(&self) -> &[u8] {
        self.credential.credential().identity()
    }
}
