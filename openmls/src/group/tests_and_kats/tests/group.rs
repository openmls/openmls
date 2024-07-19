use crate::{
    framing::*,
    group::{tests_and_kats::utils::generate_key_package, *},
    schedule::psk::store::ResumptionPskStore,
    test_utils::*,
    *,
};
use group::tests_and_kats::utils::generate_credential_with_key;
use mls_group::tests_and_kats::utils::{setup_alice_bob_group, setup_client};
use treesync::LeafNodeParameters;

#[openmls_test::openmls_test]
fn create_commit_optional_path(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    let group_aad = b"Alice's test group";
    // Framing parameters
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    // Define identities
    let alice_credential_with_keys = generate_credential_with_key(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        provider,
    );
    let bob_credential_with_keys =
        generate_credential_with_key(b"Bob".to_vec(), ciphersuite.signature_algorithm(), provider);

    // Generate Bob's KeyPackage
    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        bob_credential_with_keys,
    );

    // Alice creates a group
    let mut group_alice = CoreGroup::builder(
        GroupId::random(provider.rand()),
        ciphersuite,
        alice_credential_with_keys.credential_with_key,
    )
    .build(provider, &alice_credential_with_keys.signer)
    .expect("Error creating CoreGroup.");

    // Alice proposes to add Bob with forced self-update
    // Even though there are only Add Proposals, this should generated a path field
    // on the Commit
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            bob_key_package.key_package().clone(),
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    group_alice.proposal_store_mut().empty();
    group_alice.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .unwrap(),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .build();
    let create_commit_result = match group_alice.create_commit(
        params, /* No PSK fetcher */
        provider,
        &alice_credential_with_keys.signer,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {e:?}"),
    };
    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
        _ => panic!(),
    };
    assert!(commit.has_path());

    // Alice adds Bob without forced self-update
    // Since there are only Add Proposals, this does not generate a path field on
    // the Commit Creating a second proposal to add the same member should
    // not fail, only committing that proposal should fail
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            bob_key_package.key_package().clone(),
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    group_alice.proposal_store_mut().empty();
    group_alice.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .unwrap(),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .force_self_update(false)
        .build();
    let create_commit_result =
        match group_alice.create_commit(params, provider, &alice_credential_with_keys.signer) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {e:?}"),
        };
    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
        _ => panic!(),
    };
    assert!(!commit.has_path());

    // Alice applies the Commit without the forced self-update
    group_alice
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging pending commit");
    let ratchet_tree = group_alice.public_group().export_ratchet_tree();

    // Bob creates group from Welcome
    let group_bob = StagedCoreWelcome::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        bob_key_package,
        provider,
        ResumptionPskStore::new(1024),
    )
    .and_then(|staged_join| staged_join.into_core_group(provider))
    .unwrap_or_else(|e| panic!("Error creating group from Welcome: {e:?}"));

    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_bob.public_group().export_ratchet_tree()
    );

    // Alice updates
    let mut alice_new_leaf_node = group_alice.own_leaf_node().unwrap().clone();
    alice_new_leaf_node
        .update(
            ciphersuite,
            provider,
            &alice_credential_with_keys.signer,
            group_alice.group_id().clone(),
            group_alice.own_leaf_index(),
            LeafNodeParameters::default(),
        )
        .unwrap();
    let alice_update_proposal = group_alice
        .create_update_proposal(
            framing_parameters,
            alice_new_leaf_node,
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    group_alice.proposal_store_mut().empty();
    group_alice.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            alice_update_proposal,
        )
        .unwrap(),
    );

    // Only UpdateProposal
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .force_self_update(false)
        .build();
    let create_commit_result =
        match group_alice.create_commit(params, provider, &alice_credential_with_keys.signer) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {e:?}"),
        };
    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
        _ => panic!(),
    };
    assert!(commit.has_path());

    // Apply UpdateProposal
    group_alice
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging pending commit");
}

#[openmls_test::openmls_test]
fn basic_group_setup() {
    let (mut alice_group, alice_signer, _, _, _) = setup_alice_bob_group(ciphersuite, provider);

    let _result =
        match alice_group.self_update(provider, &alice_signer, LeafNodeParameters::default()) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {e:?}"),
        };
}

/// This test simulates various group operations like Add, Update, Remove in a
/// small group
///  - Alice creates a group
///  - Alice adds Bob
///  - Alice sends a message to Bob
///  - Bob updates and commits
///  - Alice updates and commits
///  - Bob updates and Alice commits
///  - Bob adds Charlie
///  - Charlie sends a message to the group
///  - Charlie updates and commits
///  - Charlie removes Bob
#[openmls_test::openmls_test]
fn group_operations() {
    // Create group with alice and bob
    let (mut alice_group, alice_signer, mut bob_group, bob_signer, _) =
        setup_alice_bob_group(ciphersuite, provider);

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // Make sure that both groups have the same group context
    if alice_group.export_group_context() != bob_group.export_group_context() {
        panic!("Different group contexts");
    }

    // === Alice sends a message to Bob ===
    let message_alice = [1, 2, 3];
    let mls_cipertext_alice = alice_group
        .create_message(provider, &alice_signer, &message_alice)
        .expect("An unexpected error occurred.");

    let processed_message = bob_group
        .process_message(
            provider,
            mls_cipertext_alice.into_protocol_message().unwrap(),
        )
        .unwrap();

    match processed_message.content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            assert_eq!(message, &ApplicationMessage::new(message_alice.to_vec()));
        }
        _ => panic!("Wrong content type"),
    }

    // === Bob updates and commits ===
    let (commit_message, welcome_option, _) = bob_group
        .self_update(provider, &bob_signer, LeafNodeParameters::default())
        .expect("Error updating group");

    // Check that there is a path
    let commit = match &commit_message.body {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        },
        _ => panic!("Wrong message type"),
    };
    assert!(commit.has_path());
    // Check there is no Welcome message
    assert!(welcome_option.is_none());

    bob_group
        .merge_pending_commit(provider)
        .expect("error merging commit");

    let processed_message = alice_group
        .process_message(provider, commit_message.into_protocol_message().unwrap())
        .unwrap();
    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            alice_group
                .merge_staged_commit(provider, *staged_commit)
                .expect("error merging commit");
        }
        _ => panic!("Wrong content type"),
    }

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === Alice updates and commits ===
    let (commit_message, _, _) = alice_group
        .self_update(provider, &alice_signer, LeafNodeParameters::default())
        .expect("Error updating group");

    let commit = match &commit_message.body {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        },
        _ => panic!("Wrong message type"),
    };

    // Check that there is a path
    assert!(commit.has_path());

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging commit");

    let processed_message = bob_group
        .process_message(provider, commit_message.into_protocol_message().unwrap())
        .unwrap();

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            bob_group
                .merge_staged_commit(provider, *staged_commit)
                .expect("error merging commit");
        }
        _ => panic!("Wrong content type"),
    }

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === Bob updates and Alice commits ===
    let (bob_update_proposal, _) = bob_group
        .propose_self_update(provider, &bob_signer, LeafNodeParameters::default())
        .expect("Error proposing update");

    match alice_group
        .process_message(
            provider,
            bob_update_proposal.into_protocol_message().unwrap(),
        )
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::ProposalMessage(proposal) => {
            alice_group
                .store_pending_proposal(provider.storage(), *proposal)
                .unwrap();
        }
        _ => panic!("Wrong content type"),
    }

    let (commit_message, _, _) = alice_group
        .commit_to_pending_proposals(provider, &alice_signer)
        .unwrap();

    let commit = match &commit_message.body {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        },
        _ => panic!("Wrong message type"),
    };

    // Check that there is a path
    assert!(commit.has_path());

    alice_group.merge_pending_commit(provider).unwrap();

    match bob_group.process_message(provider, commit_message.into_protocol_message().unwrap()) {
        Ok(processed_message) => match processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                bob_group
                    .merge_staged_commit(provider, *staged_commit)
                    .expect("error merging commit");
            }
            _ => panic!("Wrong content type"),
        },
        Err(e) => panic!("Error processing message: {e:?}"),
    }

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === Bob adds Charlie ===
    let (_charlie_credential_with_key, charlie_kpb, charlie_signer, _charlie_sig_pk) =
        setup_client("Charlie", ciphersuite, provider);

    let (commit_message, welcome, _) = bob_group
        .add_members(provider, &bob_signer, &[charlie_kpb.key_package().clone()])
        .expect("Could not create add commit.");

    bob_group.merge_pending_commit(provider).unwrap();

    match alice_group.process_message(provider, commit_message.into_protocol_message().unwrap()) {
        Ok(processed_message) => match processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                alice_group
                    .merge_staged_commit(provider, *staged_commit)
                    .expect("error merging commit");
            }
            _ => panic!("Wrong content type"),
        },
        Err(e) => panic!("Error processing message: {e:?}"),
    }

    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let ratchet_tree = alice_group.export_ratchet_tree();
    let mut charlie_group = StagedWelcome::new_from_welcome(
        provider,
        &config,
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .unwrap()
    .into_group(provider)
    .unwrap();

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // === Charlie sends a message to the group ===
    let message_charlie = [1, 2, 3];
    let mls_ciphertext_charlie = charlie_group
        .create_message(provider, &charlie_signer, &message_charlie)
        .expect("An unexpected error occurred.");

    let processed_message = alice_group
        .process_message(
            provider,
            mls_ciphertext_charlie
                .clone()
                .into_protocol_message()
                .unwrap(),
        )
        .unwrap();

    assert!(matches!(
        processed_message.content(),
            ProcessedMessageContent::ApplicationMessage(message) if message == &ApplicationMessage::new(message_charlie.to_vec())));

    let processed_message = bob_group
        .process_message(
            provider,
            mls_ciphertext_charlie.into_protocol_message().unwrap(),
        )
        .unwrap();

    assert!(matches!(
        processed_message.content(),
            ProcessedMessageContent::ApplicationMessage(message) if message == &ApplicationMessage::new(message_charlie.to_vec())));

    // === Charlie updates and commits ===
    let (commit_message, _, _) = charlie_group
        .self_update(provider, &charlie_signer, LeafNodeParameters::default())
        .expect("Error updating group");

    let commit = match &commit_message.body {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        },
        _ => panic!("Wrong message type"),
    };

    assert!(commit.has_path());

    charlie_group
        .merge_pending_commit(provider)
        .expect("error merging commit");

    match alice_group
        .process_message(
            provider,
            commit_message.clone().into_protocol_message().unwrap(),
        )
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            alice_group
                .merge_staged_commit(provider, *staged_commit)
                .expect("error merging commit");
        }
        _ => panic!("Wrong content type"),
    };

    match bob_group
        .process_message(provider, commit_message.into_protocol_message().unwrap())
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            bob_group
                .merge_staged_commit(provider, *staged_commit)
                .expect("error merging commit");
        }
        _ => panic!("Wrong content type"),
    };

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // === Charlie removes Bob ===
    let (commit_message, _, _) = charlie_group
        .remove_members(provider, &charlie_signer, &[bob_group.own_leaf_index()])
        .expect("Could not create remove commit.");

    let commit = match &commit_message.body {
        MlsMessageBodyOut::PublicMessage(pm) => match pm.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => panic!("Wrong content type"),
        },
        _ => panic!("Wrong message type"),
    };

    assert!(commit.has_path());

    charlie_group
        .merge_pending_commit(provider)
        .expect("error merging commit");

    match alice_group
        .process_message(
            provider,
            commit_message.clone().into_protocol_message().unwrap(),
        )
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            alice_group
                .merge_staged_commit(provider, *staged_commit)
                .expect("error merging commit");
        }
        _ => panic!("Wrong content type"),
    };

    match bob_group
        .process_message(provider, commit_message.into_protocol_message().unwrap())
        .unwrap()
        .into_content()
    {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            bob_group
                .merge_staged_commit(provider, *staged_commit)
                .expect("error merging commit");
        }
        _ => panic!("Wrong content type"),
    };

    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // Make sure all groups export the same key
    let alice_exporter = alice_group.epoch_authenticator();
    let charlie_exporter = charlie_group.epoch_authenticator();
    assert_eq!(alice_exporter, charlie_exporter);

    // Now alice tries to derive an exporter with too large of a key length.
    let exporter_length: usize = u16::MAX.into();
    let exporter_length = exporter_length + 1;
    let alice_exporter = alice_group.export_secret(provider, "export test", &[], exporter_length);
    assert!(alice_exporter.is_err())
}
