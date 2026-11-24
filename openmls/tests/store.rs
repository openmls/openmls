//! A couple of simple tests on how to interact with the key store.
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;

#[openmls_test]
fn test_store_key_package() {
    let provider = &Provider::default();

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

// A stored value that fails to deserialize must surface as an error from
// `MlsGroup::load`, never as a panic.
#[test]
fn load_group_with_corrupted_memory_storage() {
    use openmls_rust_crypto::{MemoryStorage, MemoryStorageError, OpenMlsRustCrypto};

    let provider = OpenMlsRustCrypto::default();
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"alice".to_vec()).into(),
        signature_key: signer.public().into(),
    };
    let group = MlsGroup::new(
        &provider,
        &signer,
        &MlsGroupCreateConfig::default(),
        credential,
    )
    .unwrap();
    let group_id = group.group_id().clone();
    drop(group);

    let stored = provider.storage().values.read().unwrap().clone();
    assert!(MlsGroup::load(provider.storage(), &group_id)
        .unwrap()
        .is_some());

    let mut rejected = 0;
    for key in stored.keys() {
        for corrupted in [b"[44251]".as_slice(), b"{}", b"\"x\"", b"["] {
            let storage = MemoryStorage {
                values: std::sync::RwLock::new(stored.clone()),
            };
            storage
                .values
                .write()
                .unwrap()
                .insert(key.clone(), corrupted.to_vec());

            // Values that `load` doesn't read (e.g. epoch key pairs) go
            // unnoticed here. All others must be reported as an error.
            match MlsGroup::load(&storage, &group_id) {
                Ok(Some(_)) => {}
                Err(MemoryStorageError::SerializationError) => rejected += 1,
                other => panic!(
                    "unexpected result for key {key:?}, value {corrupted:?}: {:?}",
                    other.map(|group| group.is_some())
                ),
            }
        }
    }
    assert!(rejected > 0);
}
