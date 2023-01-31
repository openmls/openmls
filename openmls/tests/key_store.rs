//! A couple of simple tests on how to interact with the key store.
use openmls::{prelude::*, test_utils::*, *};
use openmls_basic_credential::SignatureKeyPair;

#[apply(ciphersuites_and_backends)]
fn test_store_key_package(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // ANCHOR: key_store_store
    // First we generate a credential and key package for our user.
    let credential = Credential::new(b"User ID".to_vec(), CredentialType::Basic).unwrap();
    let signature_keys = SignatureKeyPair::new(ciphersuite.into()).unwrap();

    let key_package = KeyPackage::builder()
        .build(
            CryptoConfig::with_default_version(ciphersuite),
            backend,
            &signature_keys,
            CredentialWithKey {
                credential,
                signature_key: signature_keys.to_public_vec().into(),
            },
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
