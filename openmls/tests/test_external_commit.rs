use openmls::{prelude::*, test_utils::*, *};

fn create_alice_group(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    use_ratchet_tree_extension: bool,
) -> MlsGroup {
    let group_config = MlsGroupConfigBuilder::new()
        .use_ratchet_tree_extension(use_ratchet_tree_extension)
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    let alice_cb = {
        let alice_cb = CredentialBundle::new(
            b"Alice".to_vec(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("Creation of credential bundle failed.");

        let index = alice_cb
            .credential()
            .signature_key()
            .tls_serialize_detached()
            .expect("Serialization of signature public key failed.");

        backend
            .key_store()
            .store(&index, &alice_cb)
            .expect("Storing of signature public key failed.");

        alice_cb
    };

    MlsGroup::new(
        backend,
        &group_config,
        alice_cb.credential().signature_key(),
    )
    .expect("An unexpected error occurred.")
}

#[apply(ciphersuites_and_backends)]
fn test_external_commit(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Alice creates a new group ...
    let alice_group = create_alice_group(ciphersuite, backend, false);

    // ... and exports a group info (with ratchet_tree).
    let verifiable_group_info = {
        let group_info = alice_group.export_group_info(backend, true).unwrap();

        let serialized_group_info = group_info.tls_serialize_detached().unwrap();

        let mls_message_out =
            MlsMessageOut::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap();

        mls_message_out.into_group_info().unwrap()
    };

    let verifiable_group_info_broken = {
        let group_info = alice_group.export_group_info(backend, true).unwrap();

        let serialized_group_info = {
            let mut tmp = group_info.tls_serialize_detached().unwrap();

            // Simulate a bit-flip in the signature.
            let last = tmp.len().checked_sub(1).unwrap();
            tmp[last] ^= 1;

            tmp
        };

        let mls_message_out =
            MlsMessageOut::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap();

        mls_message_out.into_group_info().unwrap()
    };

    // ---------------------------------------------------------------------------------------------

    // Now, Bob wants to join Alice' group by an external commit. (Positive case.)
    {
        let bob_cb = CredentialBundle::new(
            b"Bob".to_vec(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("Creation of credential bundle failed.");

        let (_bob_group, _) = MlsGroup::join_by_external_commit(
            backend,
            None,
            verifiable_group_info,
            &MlsGroupConfigBuilder::new()
                .crypto_config(CryptoConfig::with_default_version(ciphersuite))
                .build(),
            b"",
            &bob_cb,
        )
        .unwrap();
    }

    // Now, Bob wants to join Alice' group by an external commit. (Negative case, broken signature.)
    {
        let bob_cb = CredentialBundle::new(
            b"Bob".to_vec(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            backend,
        )
        .expect("Creation of credential bundle failed.");

        let got_error = MlsGroup::join_by_external_commit(
            backend,
            None,
            verifiable_group_info_broken,
            &MlsGroupConfigBuilder::new()
                .crypto_config(CryptoConfig::with_default_version(ciphersuite))
                .build(),
            b"",
            &bob_cb,
        )
        .unwrap_err();

        assert_eq!(got_error, ExternalCommitError::InvalidGroupInfoSignature);
    }
}

#[apply(ciphersuites_and_backends)]
fn test_group_info(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Alice creates a new group ...
    let mut alice_group = create_alice_group(ciphersuite, backend, true);

    // Self update Alice's to get a group info from a commit
    let (.., group_info) = alice_group.self_update(backend).unwrap();
    alice_group.merge_pending_commit(backend).unwrap();

    // Bob wants to join
    let bob_cb = CredentialBundle::new(
        b"Bob".to_vec(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("Creation of credential bundle failed.");
    let index = bob_cb
        .credential()
        .signature_key()
        .tls_serialize_detached()
        .expect("Serialization of signature public key failed.");
    backend
        .key_store()
        .store(&index, &bob_cb)
        .expect("Storing of signature public key failed.");

    let verifiable_group_info = {
        let serialized_group_info = group_info.unwrap().tls_serialize_detached().unwrap();

        VerifiableGroupInfo::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap()
    };
    let (mut bob_group, msg) = MlsGroup::join_by_external_commit(
        backend,
        None,
        verifiable_group_info,
        &MlsGroupConfigBuilder::new()
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .build(),
        b"",
        &bob_cb,
    )
    .map(|(group, msg)| (group, MlsMessageIn::from(msg)))
    .unwrap();
    bob_group.merge_pending_commit(backend).unwrap();

    // let alice process bob's new client
    let msg = alice_group
        .process_message(backend, msg)
        .unwrap()
        .into_content();
    match msg {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            alice_group.merge_staged_commit(backend, *commit).unwrap();
        }
        _ => panic!("Unexpected message type"),
    }

    // bob sends a message to alice
    let message: MlsMessageIn = bob_group
        .create_message(backend, b"Hello Alice")
        .unwrap()
        .into();

    let msg = alice_group.process_message(backend, message).unwrap();
    let decrypted = match msg.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => msg.into_bytes(),
        _ => panic!("Not an ApplicationMessage"),
    };
    assert_eq!(decrypted, b"Hello Alice");
}

#[apply(ciphersuites_and_backends)]
fn test_not_present_group_info(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Alice creates a new group ...
    let mut alice_group = create_alice_group(ciphersuite, backend, false);

    // Self update Alice's to get a group info from a commit
    let (.., group_info) = alice_group.self_update(backend).unwrap();
    alice_group.merge_pending_commit(backend).unwrap();

    assert!(group_info.is_none());
}
