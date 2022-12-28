//! A couple of simple tests on how to interact with the key store.
use openmls::{prelude::*, test_utils::*, *};
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme};

#[apply(ciphersuites_and_backends)]
fn test_store_key_package(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // ANCHOR: key_store_store
    // First we generate a credential and key package for our user.
    let credential_bundle = CredentialBundle::new(
        b"User ID".to_vec(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite),
        backend,
    )
    .unwrap();

    let key_package = KeyPackage::create(
        config::CryptoConfig {
            ciphersuite,
            version: ProtocolVersion::default(),
        },
        backend,
        &credential_bundle,
        vec![],
        vec![],
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

#[apply(ciphersuites_and_backends)]
fn test_read_credential_bundle(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // First we generate a credential bundle
    let credential_bundle_to_store = CredentialBundle::new(
        b"User ID".to_vec(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite),
        backend,
    )
    .unwrap();

    let credential = credential_bundle_to_store.credential();

    let id = credential
        .signature_key()
        .tls_serialize_detached()
        .expect("Error serializing the credential's public key.");

    // Now we can store the credential_bundle.
    backend
        .key_store()
        .store(id.as_slice(), &credential_bundle_to_store)
        .expect("Failed to store credential in keystore.");

    // ANCHOR: key_store_read
    // In order to read something from the key store we need to define an ID.
    // Here we simply take the serialized public key of the credential.
    let id = credential
        .signature_key()
        .tls_serialize_detached()
        .expect("Error serializing the credential's public key.");

    let credential_bundle: CredentialBundle = backend
        .key_store()
        .read(&id)
        .expect("Error retrieving the credential bundle");
    // ANCHOR_END: key_store_read

    assert_eq!(credential_bundle, credential_bundle_to_store);
}
