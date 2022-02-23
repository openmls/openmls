//! A couple of simple tests on how to interact with the key store.
use openmls::{prelude::*, test_utils::*, *};
use openmls_traits::{key_store::OpenMlsKeyStore, types::SignatureScheme};

#[apply(ciphersuites_and_backends)]
fn test_store_key_package_bundle(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // ANCHOR: key_store_store
    // First we generate a credential and key package for our user.
    let credential_bundle = CredentialBundle::new(
        b"User ID".to_vec(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite),
        backend,
    )
    .unwrap();
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &credential_bundle, backend, vec![])
            .expect("Error generating new key package bundle.");

    // In order to store something in the key store we need to define an ID.
    // Here we simply take the key package reference.
    let id = key_package_bundle
        .key_package()
        .hash_ref(backend.crypto())
        .expect("Failed to hash KeyPackage.");

    // Now we can store the key_package_bundle.
    backend
        .key_store()
        .store(id.as_slice(), &key_package_bundle)
        .expect("Failed to store key package bundle in keystore.");
    // ANCHOR_END: key_store_store

    // ANCHOR: key_store_delete
    // Delete the key package bundle.
    backend
        .key_store()
        .delete(id.as_slice())
        .expect("Error deleting key package bundle");
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
