//! Regression tests for https://github.com/openmls/openmls/issues/2212 —
//! a storage failure while framing an outgoing handshake message must
//! surface as a real storage error, not a misleading
//! `LibraryError::custom("Malformed plaintext")`.

use std::{cell::RefCell, collections::HashMap};

use crate::{
    framing::errors::MessageEncryptionError,
    group::{
        errors::CommitBuilderStageError,
        mls_group::tests_and_kats::utils::{setup_alice_group, setup_client},
        tests_and_kats::utils::storage_error::{
            TestProvider, TestStorageError, TestStorageProvider,
        },
    },
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
    // fix, the error surfaces via the new `MessageEncryptionError` variant
    // (added alongside the pre-existing `KeyStoreError` variant, not in
    // place of it), which carries the real storage error underneath.
    match err {
        CommitBuilderStageError::MessageEncryptionError(MessageEncryptionError::StorageError(
            TestStorageError::Injected(reason),
        )) => {
            assert_eq!(reason, "writing message secrets");
        }
        other => {
            panic!("expected a MessageEncryptionError carrying the injected cause, got: {other:?}")
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
        ProposeAddMemberError::MessageEncryptionError(MessageEncryptionError::StorageError(
            TestStorageError::Injected(reason),
        )) => {
            assert_eq!(reason, "writing message secrets");
        }
        other => {
            panic!("expected a MessageEncryptionError carrying the injected cause, got: {other:?}")
        }
    }
}
