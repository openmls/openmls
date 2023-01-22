//! A couple of simple tests on how to interact with the key store.
use openmls::{prelude::*, test_utils::*, *};
use openmls_basic_credential::BasicCredential;
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme};

#[apply(ciphersuites_and_backends)]
fn test_store_key_package(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // ANCHOR: key_store_store
    // First we generate a credential and key package for our user.
    let credential = Credential::new(b"User ID".to_vec(), CredentialType::Basic).unwrap();
    let signature_keys = BasicCredential::new(ciphersuite.into(), backend.crypto()).unwrap();

    let key_package = KeyPackage::builder()
        .build(
            config::CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            backend,
            &signature_keys,
            signature_keys.public().clone().into(),
            credential,
        )
        .unwrap();
    // ANCHOR_END: key_store_store

    // ANCHOR: key_store_delete
    // Delete the key package
    key_package
        .delete(backend)
        .expect("Error deleting key package");
    // ANCHOR_END: key_store_delete
}
