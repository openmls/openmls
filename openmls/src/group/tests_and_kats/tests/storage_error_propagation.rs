//! Regression tests for https://github.com/openmls/openmls/issues/2212 —
//! a storage failure while framing an outgoing handshake message must
//! surface as a real storage error, not a misleading
//! `LibraryError::custom("Malformed plaintext")`.

use std::{cell::RefCell, collections::HashMap};

use crate::group::{
    errors::CommitBuilderStageError,
    mls_group::tests_and_kats::utils::{setup_alice_group, setup_client},
    tests_and_kats::utils::storage_error::{TestProvider, TestStorageError, TestStorageProvider},
};

#[openmls_test::openmls_test]
fn stage_commit_surfaces_storage_error_instead_of_malformed_plaintext() {
    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    // A commit that will be framed as ciphertext (the branch that calls
    // `self.encrypt(...)` inside `content_to_mls_message`) needs
    // `write_message_secrets` to be the storage call that fails.
    let test_storage = TestStorageProvider {
        delegate: provider.storage(),
        errors: RefCell::new(HashMap::from([(
            "write_message_secrets",
            vec![TestStorageError::Injected("writing message secrets")],
        )])),
    };
    let test_provider = TestProvider {
        storage: &test_storage,
        crypto: provider.crypto(),
        rand: provider.rand(),
    };

    let create_commit_result = group
        .commit_builder()
        .load_psks(provider.storage())
        .unwrap()
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .unwrap();

    let err = create_commit_result
        .stage_commit(&test_provider)
        .expect_err("expected the injected storage error to surface");

    // Before the fix: this was `CommitBuilderStageError::LibraryError(_)`
    // wrapping "Malformed plaintext", discarding the real cause. After the
    // fix, the error is flattened into the pre-existing `KeyStoreError`
    // variant, matching the shape the issue itself expects.
    match err {
        CommitBuilderStageError::KeyStoreError(TestStorageError::Injected(reason)) => {
            assert_eq!(reason, "writing message secrets");
        }
        other => {
            panic!("expected a KeyStoreError carrying the injected cause, got: {other:?}")
        }
    }
}

#[openmls_test::openmls_test]
fn propose_add_member_surfaces_storage_error_instead_of_malformed_plaintext() {
    use crate::group::errors::ProposeAddMemberError;

    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);
    let (_, bob_pkb, _, _) = setup_client("Bob", ciphersuite, &Provider::default());

    let test_storage = TestStorageProvider {
        delegate: provider.storage(),
        errors: RefCell::new(HashMap::from([(
            "write_message_secrets",
            vec![TestStorageError::Injected("writing message secrets")],
        )])),
    };
    let test_provider = TestProvider {
        storage: &test_storage,
        crypto: provider.crypto(),
        rand: provider.rand(),
    };

    let err = group
        .propose_add_member(&test_provider, &signer, bob_pkb.key_package())
        .expect_err("expected the injected storage error to surface");

    match err {
        ProposeAddMemberError::StorageError(TestStorageError::Injected(reason)) => {
            assert_eq!(reason, "writing message secrets");
        }
        other => {
            panic!("expected a StorageError carrying the injected cause, got: {other:?}")
        }
    }
}

#[openmls_test::openmls_test]
fn create_message_surfaces_storage_error_instead_of_malformed_plaintext() {
    use crate::group::errors::CreateMessageError;
    // Only needed to match the vc-draft build's `CreateMessageError` below,
    // whose `MessageEncryptionError` variant predates this branch (it is
    // untouched by the flattening fix, which is scoped to the non-vc
    // `CreateMessageError`) and is therefore still nested.
    #[cfg(feature = "virtual-clients-draft")]
    use crate::framing::errors::MessageEncryptionError;

    let provider = &Provider::default();
    let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);

    let test_storage = TestStorageProvider {
        delegate: provider.storage(),
        errors: RefCell::new(HashMap::from([(
            "write_message_secrets",
            vec![TestStorageError::Injected("writing message secret")],
        )])),
    };
    let test_provider = TestProvider {
        storage: &test_storage,
        crypto: provider.crypto(),
        rand: provider.rand(),
    };

    let err = group
        .create_message(&test_provider, &signer, b"hello")
        .expect_err("expected the injected storage error to surface");

    match err {
        #[cfg(not(feature = "virtual-clients-draft"))]
        CreateMessageError::StorageError(TestStorageError::Injected(reason)) => {
            assert_eq!(reason, "writing message secret");
        }
        #[cfg(feature = "virtual-clients-draft")]
        CreateMessageError::MessageEncryptionError(MessageEncryptionError::StorageError(
            TestStorageError::Injected(reason),
        )) => {
            assert_eq!(reason, "writing message secret");
        }
        other => panic!("expected a CreateMessageError::StorageError carrying the injected cause, got: {other:?}"),
    }
}
