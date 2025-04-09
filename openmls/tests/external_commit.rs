use openmls::{
    credentials::test_utils::new_credential,
    messages::group_info::VerifiableGroupInfo,
    prelude::{tls_codec::*, *},
    treesync::LeafNodeParameters,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;

fn create_alice_group(
    ciphersuite: Ciphersuite,
    provider: &impl openmls::storage::OpenMlsProvider,
    use_ratchet_tree_extension: bool,
) -> (MlsGroup, CredentialWithKey, SignatureKeyPair) {
    let group_config = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(use_ratchet_tree_extension)
        .ciphersuite(ciphersuite)
        .build();

    let (credential_with_key, signature_keys) =
        new_credential(provider, b"Alice", ciphersuite.signature_algorithm());

    let group = MlsGroup::new(
        provider,
        &signature_keys,
        &group_config,
        credential_with_key.clone(),
    )
    .expect("An unexpected error occurred.");

    (group, credential_with_key, signature_keys)
}

#[openmls_test]
fn test_external_commit() {
    // Alice creates a new group ...
    let (alice_group, _, alice_signer) = create_alice_group(ciphersuite, provider, false);

    // ... and exports a group info (with ratchet_tree).
    let verifiable_group_info = {
        let group_info = alice_group
            .export_group_info(provider, &alice_signer, true)
            .unwrap();

        let serialized_group_info = group_info.tls_serialize_detached().unwrap();

        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap();

        mls_message_in.into_verifiable_group_info().unwrap()
    };

    let verifiable_group_info_broken = {
        let group_info = alice_group
            .export_group_info(provider, &alice_signer, true)
            .unwrap();

        let serialized_group_info = {
            let mut tmp = group_info.tls_serialize_detached().unwrap();

            // Simulate a bit-flip in the signature.
            let last = tmp.len().checked_sub(1).unwrap();
            tmp[last] ^= 1;

            tmp
        };

        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap();

        mls_message_in.into_verifiable_group_info().unwrap()
    };

    // ---------------------------------------------------------------------------------------------

    // Now, Bob wants to join Alice' group by an external commit. (Positive case.)
    {
        let (bob_credential, bob_signature_keys) =
            new_credential(provider, b"Bob", ciphersuite.signature_algorithm());

        let (_bob_group, _, _) = MlsGroup::join_by_external_commit(
            provider,
            &bob_signature_keys,
            None,
            verifiable_group_info,
            &MlsGroupJoinConfig::default(),
            None,
            None,
            b"",
            bob_credential,
        )
        .unwrap();
    }

    // Now, Bob wants to join Alice' group by an external commit. (Negative case, broken signature.)
    {
        let (bob_credential, bob_signature_keys) =
            new_credential(provider, b"Bob", ciphersuite.signature_algorithm());

        let got_error = MlsGroup::join_by_external_commit(
            provider,
            &bob_signature_keys,
            None,
            verifiable_group_info_broken,
            &MlsGroupJoinConfig::default(),
            None,
            None,
            b"",
            bob_credential,
        )
        .unwrap_err();

        assert!(matches!(
            got_error,
            ExternalCommitError::PublicGroupError(
                CreationFromExternalError::InvalidGroupInfoSignature
            )
        ));
    }
}

#[openmls_test]
fn test_group_info() {
    // Alice creates a new group ...
    let (mut alice_group, _, alice_signer) = create_alice_group(ciphersuite, provider, true);

    // Self update Alice's to get a group info from a commit
    let group_info = alice_group
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .unwrap()
        .into_group_info();
    alice_group.merge_pending_commit(provider).unwrap();

    // Bob wants to join
    let (bob_credential, bob_signature_keys) =
        new_credential(provider, b"Bob", ciphersuite.signature_algorithm());

    let verifiable_group_info = {
        let serialized_group_info = group_info.unwrap().tls_serialize_detached().unwrap();

        VerifiableGroupInfo::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap()
    };
    let (mut bob_group, msg, group_info) = MlsGroup::join_by_external_commit(
        provider,
        &bob_signature_keys,
        None,
        verifiable_group_info,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
        None,
        None,
        b"",
        bob_credential,
    )
    .map(|(group, msg, group_info)| (group, MlsMessageIn::from(msg), group_info))
    .unwrap();
    bob_group.merge_pending_commit(provider).unwrap();

    // let alice process bob's new client
    let msg = alice_group
        .process_message(provider, msg.try_into_protocol_message().unwrap())
        .unwrap()
        .into_content();
    match msg {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            alice_group.merge_staged_commit(provider, *commit).unwrap();
        }
        _ => panic!("Unexpected message type"),
    }

    // bob sends a message to alice
    let message: MlsMessageIn = bob_group
        .create_message(provider, &bob_signature_keys, b"Hello Alice")
        .unwrap()
        .into();

    let msg = alice_group
        .process_message(provider, message.try_into_protocol_message().unwrap())
        .unwrap();
    let decrypted = match msg.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => msg.into_bytes(),
        _ => panic!("Not an ApplicationMessage"),
    };
    assert_eq!(decrypted, b"Hello Alice");

    // check that the returned group info from the external join is valid
    // Bob wants to join with another client
    let (bob_credential, bob_signature_keys) =
        new_credential(provider, b"Bob 2", ciphersuite.signature_algorithm());
    let verifiable_group_info = {
        let serialized_group_info = group_info.unwrap().tls_serialize_detached().unwrap();

        VerifiableGroupInfo::tls_deserialize(&mut serialized_group_info.as_slice()).unwrap()
    };
    let (mut bob_group, ..) = MlsGroup::join_by_external_commit(
        provider,
        &bob_signature_keys,
        None,
        verifiable_group_info,
        &MlsGroupJoinConfig::default(),
        None,
        None,
        b"",
        bob_credential,
    )
    .unwrap();
    bob_group.merge_pending_commit(provider).unwrap();
}

#[openmls_test]
fn test_not_present_group_info(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Alice creates a new group ...
    let (mut alice_group, _, alice_signer) = create_alice_group(ciphersuite, provider, false);

    // Self update Alice's to get a group info from a commit
    let group_info = alice_group
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .unwrap()
        .into_group_info();
    alice_group.merge_pending_commit(provider).unwrap();

    assert!(group_info.is_none());
}
