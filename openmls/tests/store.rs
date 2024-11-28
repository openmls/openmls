//! A couple of simple tests on how to interact with the key store.
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;

#[openmls_test]
fn test_store_key_package() {
    // ANCHOR: store_store
    // First we generate a credential and key package for our user.
    let credential = BasicCredential::new(b"User ID".to_vec());
    let signature_keys = SignatureKeyPair::new(ciphersuite.into()).unwrap();

    // This key package includes the private init and encryption key as well.
    // See [`KeyPackageBundle`].
    let key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signature_keys.to_public_vec().into(),
            },
        )
        .unwrap();
    // ANCHOR_END: store_store

    // ANCHOR: hash_ref
    // Build the hash reference.
    // This is the key for key packages.
    let hash_ref = key_package
        .key_package()
        .hash_ref(provider.crypto())
        .unwrap();
    // ANCHOR_END: hash_ref

    // ANCHOR: store_read
    // Read the key package
    let read_key_package: Option<KeyPackageBundle> = provider
        .storage()
        .key_package(&hash_ref)
        .expect("Error reading key package");
    assert_eq!(
        read_key_package.unwrap().key_package(),
        key_package.key_package()
    );
    // ANCHOR_END: store_read

    // ANCHOR: store_delete
    // Delete the key package
    let hash_ref = key_package
        .key_package()
        .hash_ref(provider.crypto())
        .unwrap();
    provider
        .storage()
        .delete_key_package(&hash_ref)
        .expect("Error deleting key package");
    // ANCHOR_END: store_delete
}
