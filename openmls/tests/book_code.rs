use openmls::{
    prelude::{tls_codec::*, CustomProposal, *},
    test_utils::{storage_state::GroupStorageState, *},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use openmls_traits::{signatures::Signer, types::SignatureScheme};
use treesync::LeafNodeParameters;

#[test]
fn create_provider_rust_crypto() {
    // ANCHOR: create_provider_rust_crypto
    let provider: OpenMlsRustCrypto = OpenMlsRustCrypto::default();
    // ANCHOR_END: create_provider_rust_crypto

    // Suppress warning.
    let _provider = provider;
}

fn generate_credential(
    identity: Vec<u8>,
    signature_algorithm: SignatureScheme,
    provider: &impl crate::storage::OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    // ANCHOR: create_basic_credential
    let credential = BasicCredential::new(identity);
    // ANCHOR_END: create_basic_credential
    // ANCHOR: create_credential_keys
    let signature_keys = SignatureKeyPair::new(signature_algorithm).unwrap();
    signature_keys.store(provider.storage()).unwrap();
    // ANCHOR_END: create_credential_keys

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        },
        signature_keys,
    )
}

fn generate_key_package(
    ciphersuite: Ciphersuite,
    credential_with_key: CredentialWithKey,
    extensions: Extensions,
    provider: &impl crate::storage::OpenMlsProvider,
    signer: &impl Signer,
) -> KeyPackageBundle {
    // ANCHOR: create_key_package
    // Create the key package
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
    // ANCHOR_END: create_key_package
}

/// This test simulates various group operations like Add, Update, Remove in a
/// small group
///  - Alice creates a group
///  - Alice adds Bob
///  - Alice sends a message to Bob
///  - Bob updates and commits
///  - Alice updates and commits
///  - Bob adds Charlie
///  - Charlie sends a message to the group
///  - Charlie updates and commits
///  - Charlie removes Bob
///  - Alice removes Charlie and adds Bob
///  - Bob leaves
///  - Test saving the group state
#[openmls_test]
fn book_operations() {
    // Generate credentials with keys
    let (alice_credential, alice_signature_keys) =
        generate_credential("Alice".into(), ciphersuite.signature_algorithm(), provider);

    let (bob_credential, bob_signature_keys) =
        generate_credential("Bob".into(), ciphersuite.signature_algorithm(), provider);

    let (charlie_credential, charlie_signature_keys) = generate_credential(
        "Charlie".into(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    let (dave_credential, dave_signature_keys) =
        generate_credential("Dave".into(), ciphersuite.signature_algorithm(), provider);

    // Generate KeyPackages
    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential.clone(),
        Extensions::default(),
        provider,
        &bob_signature_keys,
    );

    // Define the MlsGroup configuration
    // delivery service credentials
    let (ds_credential_with_key, ds_signature_keys) = generate_credential(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    // ANCHOR: mls_group_create_config_example
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            10,   // out_of_order_tolerance
            2000, // maximum_forward_distance
        ))
        .with_group_context_extensions(Extensions::single(Extension::ExternalSenders(vec![
            ExternalSender::new(
                ds_credential_with_key.signature_key.clone(),
                ds_credential_with_key.credential.clone(),
            ),
        ])))
        .expect("error adding external senders extension to group context extensions")
        .ciphersuite(ciphersuite)
        // we need to specify the non-default extension here
        .capabilities(Capabilities::new(
            None, // Defaults to the group's protocol version
            None, // Defaults to the group's ciphersuite
            Some(&[ExtensionType::Unknown(0xff00)]),
            None, // Defaults to all basic extension types
            Some(&[CredentialType::Basic]),
        ))
        // Example leaf extension
        .with_leaf_node_extensions(Extensions::single(Extension::Unknown(
            0xff00,
            UnknownExtension(vec![0, 1, 2, 3]),
        )))
        .expect("failed to configure leaf extensions")
        .use_ratchet_tree_extension(true)
        .build();
    // ANCHOR_END: mls_group_create_config_example

    // ANCHOR: alice_create_group
    let mut alice_group = MlsGroup::new(
        provider,
        &alice_signature_keys,
        &mls_group_create_config,
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");
    // ANCHOR_END: alice_create_group

    {
        // ANCHOR: alice_create_group_with_group_id
        // Some specific group ID generated by someone else.
        let group_id = GroupId::from_slice(b"123e4567e89b");

        let mut alice_group = MlsGroup::new_with_group_id(
            provider,
            &alice_signature_keys,
            &mls_group_create_config,
            group_id,
            alice_credential.clone(),
        )
        .expect("An unexpected error occurred.");
        // ANCHOR_END: alice_create_group_with_group_id

        // Silence "unused variable" and "does not need to be mutable" warnings.
        let _ignore_mut_warning = &mut alice_group;

        let external_senders_list = vec![];

        // ANCHOR: alice_create_group_with_builder_with_extensions
        // we are adding an external senders list as an example.
        let extensions =
            Extensions::from_vec(vec![Extension::ExternalSenders(external_senders_list)])
                .expect("failed to create extensions list");

        let mut alice_group = MlsGroup::builder()
            .padding_size(100)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                10,   // out_of_order_tolerance
                2000, // maximum_forward_distance
            ))
            .with_group_context_extensions(extensions) // NB: the builder method returns a Result
            .expect("failed to apply group context extensions")
            .use_ratchet_tree_extension(true)
            .build(provider, &alice_signature_keys, alice_credential.clone())
            .expect("An unexpected error occurred.");
        // ANCHOR_END: alice_create_group_with_builder_with_extensions

        // Silence "unused variable" and "does not need to be mutable" warnings.
        let _ignore_mut_warning = &mut alice_group;

        // ANCHOR: alice_create_group_with_builder
        let mut alice_group = MlsGroup::builder()
            .padding_size(100)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                10,   // out_of_order_tolerance
                2000, // maximum_forward_distance
            ))
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .build(provider, &alice_signature_keys, alice_credential.clone())
            .expect("An unexpected error occurred.");
        // ANCHOR_END: alice_create_group_with_builder

        // Silence "unused variable" and "does not need to be mutable" warnings.
        let _ignore_mut_warning = &mut alice_group;
    }

    let group_id = alice_group.group_id().clone();

    // === Alice adds Bob ===
    // ANCHOR: alice_adds_bob
    let (mls_message_out, welcome, group_info) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Could not add members.");
    // ANCHOR_END: alice_adds_bob

    // Suppress warning
    let _mls_message_out = mls_message_out;
    let _group_info = group_info;

    // Check that we received the correct proposals
    if let Some(staged_commit) = alice_group.pending_commit() {
        let add = staged_commit
            .add_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was added
        assert_eq!(
            add.add_proposal().key_package().leaf_node().credential(),
            &bob_credential.credential
        );
        // Check that Alice added Bob
        assert!(matches!(
            add.sender(),
            Sender::Member(member) if *member == alice_group.own_leaf_index()
        ));
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Check that the group now has two members
    assert_eq!(alice_group.members().count(), 2);

    // Check that Alice & Bob are the members of the group
    let members = alice_group.members().collect::<Vec<Member>>();
    let id0 = members[0].credential.serialized_content();
    let id1 = members[1].credential.serialized_content();
    assert_eq!(id0, b"Alice");
    assert_eq!(id1, b"Bob");

    // ANCHOR: mls_group_config_example
    let mls_group_config = MlsGroupJoinConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            10,   // out_of_order_tolerance
            2000, // maximum_forward_distance
        ))
        .use_ratchet_tree_extension(true)
        .build();
    // ANCHOR_END: mls_group_config_example

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    // ANCHOR: bob_joins_with_welcome
    let staged_join = StagedWelcome::new_from_welcome(provider, &mls_group_config, welcome, None)
        .expect("Error constructing staged join");
    let mut bob_group = staged_join
        .into_group(provider)
        .expect("Error joining group from StagedWelcome");
    // ANCHOR_END: bob_joins_with_welcome

    // ANCHOR: alice_exports_group_info
    let verifiable_group_info = alice_group
        .export_group_info(provider, &alice_signature_keys, true)
        .expect("Cannot export group info")
        .into_verifiable_group_info()
        .expect("Could not get group info");
    // ANCHOR_END: alice_exports_group_info

    // ANCHOR: charlie_joins_external_commit
    let (mut dave_group, _out, _group_info) = MlsGroup::join_by_external_commit(
        provider,
        &dave_signature_keys,
        None, // No ratchtet tree extension
        verifiable_group_info,
        &mls_group_config,
        None, // No special capabilities
        None, // No special extensions
        &[],
        dave_credential,
    )
    .expect("Error joining from external commit");
    dave_group
        .merge_pending_commit(provider)
        .expect("Cannot merge commit");
    // ANCHOR_END: charlie_joins_external_commit

    // Make sure that both groups have the same members
    assert!(alice_group.members().eq(bob_group.members()));

    // Make sure that both groups have the same epoch authenticator
    assert_eq!(
        alice_group.epoch_authenticator().as_slice(),
        bob_group.epoch_authenticator().as_slice()
    );

    // === Alice sends a message to Bob ===
    // ANCHOR: create_application_message
    let message_alice = b"Hi, I'm Alice!";
    let mls_message_out = alice_group
        .create_message(provider, &alice_signature_keys, message_alice)
        .expect("Error creating application message.");
    // ANCHOR_END: create_application_message

    // Message serialization

    let bytes = mls_message_out
        .to_bytes()
        .expect("Could not serialize message.");

    // ANCHOR: mls_message_in_from_bytes
    let mls_message =
        MlsMessageIn::tls_deserialize_exact(bytes).expect("Could not deserialize message.");
    // ANCHOR_END: mls_message_in_from_bytes

    // ANCHOR: process_message
    let protocol_message: ProtocolMessage = mls_message
        .try_into_protocol_message()
        .expect("Expected a PublicMessage or a PrivateMessage");
    let processed_message = bob_group
        .process_message(provider, protocol_message)
        .expect("Could not process message.");
    // ANCHOR_END: process_message

    // Check that we received the correct message
    // ANCHOR: inspect_application_message
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        // Check the message
        assert_eq!(application_message.into_bytes(), b"Hi, I'm Alice!");
    }
    // ANCHOR_END: inspect_application_message
    else {
        unreachable!("Expected an ApplicationMessage.");
    }

    // ANCHOR: set_aad
    alice_group.set_aad(b"Additional Authenticated Data".to_vec());

    assert_eq!(alice_group.aad(), b"Additional Authenticated Data");
    // ANCHOR_END: set_aad

    let message_alice = b"Hi, I'm Alice!";
    let mls_message_out = alice_group
        .create_message(provider, &alice_signature_keys, message_alice)
        .expect("Error creating application message.");

    let bytes = mls_message_out
        .to_bytes()
        .expect("Could not serialize message.");

    let mls_message =
        MlsMessageIn::tls_deserialize_exact(bytes).expect("Could not deserialize message.");

    let protocol_message: ProtocolMessage = mls_message
        .try_into_protocol_message()
        .expect("Expected a PublicMessage or a PrivateMessage");

    // ANCHOR: inspect_aad
    let processed_message = bob_group
        .process_message(provider, protocol_message)
        .expect("Could not process message.");

    assert_eq!(processed_message.aad(), b"Additional Authenticated Data");
    // ANCHOR_END: inspect_aad

    // === Bob updates and commits ===
    // ANCHOR: self_update
    let (mls_message_out, welcome_option, _group_info) = bob_group
        .self_update(provider, &bob_signature_keys, LeafNodeParameters::default())
        .expect("Could not update own key package.")
        .into_contents();
    // ANCHOR_END: self_update

    let alice_processed_message = alice_group
        .process_message(
            provider,
            mls_message_out
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that we received the correct message
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        // Merge staged Commit
        alice_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging staged commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    bob_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Check we didn't receive a Welcome message
    assert!(welcome_option.is_none());

    // Check that both groups have the same state
    assert_eq!(
        alice_group.export_secret(provider, "", &[], 32).unwrap(),
        bob_group.export_secret(provider, "", &[], 32).unwrap()
    );

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === Alice updates and commits ===
    // ANCHOR: propose_self_update
    let (mls_message_out, _proposal_ref) = alice_group
        .propose_self_update(
            provider,
            &alice_signature_keys,
            LeafNodeParameters::default(),
        )
        .expect("Could not create update proposal.");
    // ANCHOR_END: propose_self_update

    let bob_processed_message = bob_group
        .process_message(
            provider,
            mls_message_out
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that we received the correct proposals
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        bob_processed_message.into_content()
    {
        if let Proposal::Update(ref update_proposal) = staged_proposal.proposal() {
            // Check that Alice updated
            assert_eq!(
                update_proposal.leaf_node().credential(),
                &alice_credential.credential
            );
            // Store proposal
            alice_group
                .store_pending_proposal(provider.storage(), *staged_proposal.clone())
                .unwrap();
        } else {
            unreachable!("Expected a Proposal.");
        }

        // Check that Alice sent the proposal
        assert!(matches!(
            staged_proposal.sender(),
            Sender::Member(member) if *member == alice_group.own_leaf_index()
        ));
        bob_group
            .store_pending_proposal(provider.storage(), *staged_proposal)
            .unwrap();
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    // ANCHOR: commit_to_proposals
    let (mls_message_out, welcome_option, _group_info) = alice_group
        .commit_to_pending_proposals(provider, &alice_signature_keys)
        .expect("Could not commit to pending proposals.");
    // ANCHOR_END: commit_to_proposals

    // Suppress warning
    let _welcome_option = welcome_option;

    let bob_processed_message = bob_group
        .process_message(
            provider,
            mls_message_out
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Check that we received the correct message
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        let authenticator_bob = staged_commit
            .epoch_authenticator()
            .expect("Couldn't get authenticator.");
        let authenticator_alice = alice_group.epoch_authenticator();
        assert_eq!(authenticator_bob.as_slice(), authenticator_alice.as_slice());
        bob_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging staged commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that both groups have the same state
    assert_eq!(
        alice_group.export_secret(provider, "", &[], 32).unwrap(),
        bob_group.export_secret(provider, "", &[], 32).unwrap()
    );

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === Bob adds Charlie ===
    let charlie_key_package = generate_key_package(
        ciphersuite,
        charlie_credential.clone(),
        Extensions::default(),
        provider,
        &charlie_signature_keys,
    );

    let (queued_message, welcome, _group_info) = bob_group
        .add_members(
            provider,
            &bob_signature_keys,
            &[charlie_key_package.key_package().clone()],
        )
        .unwrap();

    let alice_processed_message = alice_group
        .process_message(
            provider,
            queued_message
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    bob_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging staged commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let mut charlie_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(bob_group.export_ratchet_tree().into()),
    )
    .expect("Error building StagedWelcome")
    .into_group(provider)
    .expect("Error creating group from Welcome");

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree(),
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // Check that Alice, Bob & Charlie are the members of the group
    let members = alice_group.members().collect::<Vec<Member>>();
    let credential0 = members[0].credential.serialized_content();
    let credential1 = members[1].credential.serialized_content();
    let credential2 = members[2].credential.serialized_content();
    assert_eq!(credential0, b"Alice");
    assert_eq!(credential1, b"Bob");
    assert_eq!(credential2, b"Charlie");
    assert_eq!(members.len(), 3);

    // === Charlie sends a message to the group ===
    let message_charlie = b"Hi, I'm Charlie!";
    let queued_message = charlie_group
        .create_message(provider, &charlie_signature_keys, message_charlie)
        .expect("Error creating application message");

    let _alice_processed_message = alice_group
        .process_message(
            provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    let _bob_processed_message = bob_group
        .process_message(
            provider,
            queued_message
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // === Charlie updates and commits ===
    let (queued_message, welcome_option, _group_info) = charlie_group
        .self_update(
            provider,
            &charlie_signature_keys,
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_contents();

    let alice_processed_message = alice_group
        .process_message(
            provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    let bob_processed_message = bob_group
        .process_message(
            provider,
            queued_message
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    charlie_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging staged commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        bob_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging staged commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check we didn't receive a Welcome message
    assert!(welcome_option.is_none());

    // Check that all groups have the same state
    assert_eq!(
        alice_group.export_secret(provider, "", &[], 32).unwrap(),
        bob_group.export_secret(provider, "", &[], 32).unwrap()
    );
    assert_eq!(
        alice_group.export_secret(provider, "", &[], 32).unwrap(),
        charlie_group.export_secret(provider, "", &[], 32).unwrap()
    );

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree(),
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // ANCHOR: retrieve_members
    let charlie_members = charlie_group.members().collect::<Vec<Member>>();
    // ANCHOR_END: retrieve_members

    let bob_member = charlie_members
        .iter()
        .find(
            |Member {
                 index: _,
                 credential,
                 ..
             }| { credential.serialized_content() == b"Bob" },
        )
        .expect("Couldn't find Bob in the list of group members.");

    // Make sure that this is Bob's actual KP reference.
    let bob_cred = bob_member.credential.serialized_content();
    let bob_group_cred = bob_group
        .own_leaf()
        .unwrap()
        .credential()
        .serialized_content();
    assert_eq!(bob_cred, bob_group_cred);

    // === Charlie removes Bob ===
    // ANCHOR: charlie_removes_bob
    let (mls_message_out, welcome_option, _group_info) = charlie_group
        .remove_members(provider, &charlie_signature_keys, &[bob_member.index])
        .expect("Could not remove Bob from group.");
    // ANCHOR_END: charlie_removes_bob

    // Check that Bob's group is still active
    assert!(bob_group.is_active());

    let alice_processed_message = alice_group
        .process_message(
            provider,
            mls_message_out
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that alice can use the member list to check if the message is
    // actually from Charlie.
    let mut alice_members = alice_group.members();
    let sender_leaf_index = match alice_processed_message.sender() {
        Sender::Member(index) => index,
        _ => panic!("Sender should have been a member"),
    };
    let sender_credential = alice_processed_message.credential();

    assert!(alice_members.any(|Member { index, .. }| &index == sender_leaf_index));
    drop(alice_members);

    assert_eq!(sender_credential, &charlie_credential.credential);

    let bob_processed_message = bob_group
        .process_message(
            provider,
            mls_message_out
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    let charlies_leaf_index = charlie_group.own_leaf_index();
    charlie_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Check that we receive the correct proposal for Alice
    // ANCHOR: inspect_staged_commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        // We expect a remove proposal
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(
            remove.remove_proposal().removed(),
            bob_group.own_leaf_index()
        );
        // Check that Charlie removed Bob
        assert!(matches!(
            remove.sender(),
            Sender::Member(member) if *member == charlies_leaf_index
        ));
        // Merge staged commit
        alice_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging staged commit.");
    }
    // ANCHOR_END: inspect_staged_commit
    else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that we receive the correct proposal for Bob
    // ANCHOR: remove_operation
    // ANCHOR: getting_removed
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        let remove_proposal = staged_commit
            .remove_proposals()
            .next()
            .expect("An unexpected error occurred.");

        // We construct a RemoveOperation enum to help us interpret the remove operation
        let remove_operation = RemoveOperation::new(remove_proposal, &bob_group)
            .expect("An unexpected Error occurred.");

        match remove_operation {
            RemoveOperation::WeLeft => unreachable!(),
            // We expect this variant, since Bob was removed by Charlie
            RemoveOperation::WeWereRemovedBy(member) => {
                assert!(matches!(member, Sender::Member(member) if member == charlies_leaf_index));
            }
            RemoveOperation::TheyLeft(_) => unreachable!(),
            RemoveOperation::TheyWereRemovedBy(_) => unreachable!(),
            RemoveOperation::WeRemovedThem(_) => unreachable!(),
        }

        // Merge staged Commit
        bob_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging staged commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }
    // ANCHOR_END: remove_operation

    // Check we didn't receive a Welcome message
    assert!(welcome_option.is_none());

    // Check that Bob's group is no longer active
    assert!(!bob_group.is_active());
    let members = bob_group.members().collect::<Vec<Member>>();
    assert_eq!(members.len(), 2);
    let credential0 = members[0].credential.serialized_content();
    let credential1 = members[1].credential.serialized_content();
    assert_eq!(credential0, b"Alice");
    assert_eq!(credential1, b"Charlie");
    // ANCHOR_END: getting_removed

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // Make sure the group only contains two members
    assert_eq!(alice_group.members().count(), 2);

    // Check that Alice & Charlie are the members of the group
    let members = alice_group.members().collect::<Vec<Member>>();
    let credential0 = members[0].credential.serialized_content();
    let credential1 = members[1].credential.serialized_content();
    assert_eq!(credential0, b"Alice");
    assert_eq!(credential1, b"Charlie");

    // Check that Bob can no longer send messages
    assert!(bob_group
        .create_message(provider, &bob_signature_keys, b"Should not go through")
        .is_err());

    // === Alice removes Charlie and re-adds Bob ===

    // Create a new KeyPackageBundle for Bob
    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential.clone(),
        Extensions::default(),
        provider,
        &bob_signature_keys,
    );

    // Create RemoveProposal and process it
    // ANCHOR: propose_remove
    let (mls_message_out, _proposal_ref) = alice_group
        .propose_remove_member(
            provider,
            &alice_signature_keys,
            charlie_group.own_leaf_index(),
        )
        .expect("Could not create proposal to remove Charlie.");
    // ANCHOR_END: propose_remove

    let charlie_processed_message = charlie_group
        .process_message(
            provider,
            mls_message_out
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that we received the correct proposals
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        charlie_processed_message.into_content()
    {
        if let Proposal::Remove(ref remove_proposal) = staged_proposal.proposal() {
            // Check that Charlie was removed
            assert_eq!(remove_proposal.removed(), charlie_group.own_leaf_index());
            // Store proposal
            charlie_group
                .store_pending_proposal(provider.storage(), *staged_proposal.clone())
                .unwrap();
        } else {
            unreachable!("Expected a Proposal.");
        }

        // Check that Alice removed Charlie
        assert!(matches!(
            staged_proposal.sender(),
            Sender::Member(member) if *member == alice_group.own_leaf_index()
        ));
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    // Create AddProposal and remove it
    // ANCHOR: rollback_proposal_by_ref
    let (_mls_message_out, proposal_ref) = alice_group
        .propose_add_member(
            provider,
            &alice_signature_keys,
            bob_key_package.key_package(),
        )
        .expect("Could not create proposal to add Bob");
    alice_group
        .remove_pending_proposal(provider.storage(), &proposal_ref)
        .expect("The proposal was not found");
    // ANCHOR_END: rollback_proposal_by_ref

    // Create AddProposal and process it
    // ANCHOR: propose_add
    let (mls_message_out, _proposal_ref) = alice_group
        .propose_add_member(
            provider,
            &alice_signature_keys,
            bob_key_package.key_package(),
        )
        .expect("Could not create proposal to add Bob");
    // ANCHOR_END: propose_add

    let charlie_processed_message = charlie_group
        .process_message(
            provider,
            mls_message_out
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that we received the correct proposals
    // ANCHOR: inspect_add_proposal
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        charlie_processed_message.into_content()
    {
        // In the case we received an Add Proposal
        if let Proposal::Add(add_proposal) = staged_proposal.proposal() {
            // Check that Bob was added
            assert_eq!(
                add_proposal.key_package().leaf_node().credential(),
                &bob_credential.credential
            );
        } else {
            panic!("Expected an AddProposal.");
        }

        // Check that Alice added Bob
        assert!(matches!(
            staged_proposal.sender(),
            Sender::Member(member) if *member == alice_group.own_leaf_index()
        ));
        // Store proposal
        charlie_group
            .store_pending_proposal(provider.storage(), *staged_proposal)
            .unwrap();
    }
    // ANCHOR_END: inspect_add_proposal
    else {
        unreachable!("Expected a QueuedProposal.");
    }

    // Commit to the proposals and process it
    let (queued_message, welcome_option, _group_info) = alice_group
        .commit_to_pending_proposals(provider, &alice_signature_keys)
        .expect("Could not flush proposals");

    let charlie_processed_message = charlie_group
        .process_message(
            provider,
            queued_message
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Merge Commit
    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        charlie_processed_message.into_content()
    {
        charlie_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging staged commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Make sure the group contains two members
    assert_eq!(alice_group.members().count(), 2);

    // Check that Alice & Bob are the members of the group
    let members = alice_group.members().collect::<Vec<Member>>();

    let credential0 = members[0].credential.serialized_content();
    let credential1 = members[1].credential.serialized_content();
    assert_eq!(credential0, b"Alice");
    assert_eq!(credential1, b"Bob");

    let welcome: MlsMessageIn = welcome_option.expect("Welcome was not returned").into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    // Bob creates a new group
    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating StagedWelcome")
    .into_group(provider)
    .expect("Error creating group from StagedWelcome");

    // Make sure the group contains two members
    assert_eq!(alice_group.members().count(), 2);

    // Check that Alice & Bob are the members of the group
    let members = alice_group.members().collect::<Vec<Member>>();
    let credential0 = members[0].credential.serialized_content();
    let credential1 = members[1].credential.serialized_content();
    assert_eq!(credential0, b"Alice");
    assert_eq!(credential1, b"Bob");

    // Make sure the group contains two members
    assert_eq!(bob_group.members().count(), 2);

    // Check that Alice & Bob are the members of the group
    let members = bob_group.members().collect::<Vec<Member>>();
    let credential0 = members[0].credential.serialized_content();
    let credential1 = members[1].credential.serialized_content();
    assert_eq!(credential0, b"Alice");
    assert_eq!(credential1, b"Bob");

    // === Alice sends a message to the group ===
    let message_alice = b"Hi, I'm Alice!";
    let queued_message = alice_group
        .create_message(provider, &alice_signature_keys, message_alice)
        .expect("Error creating application message");

    let bob_processed_message = bob_group
        .process_message(
            provider,
            queued_message
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Get sender information
    // As provided by the processed message
    let sender_cred_from_msg = bob_processed_message.credential().clone();

    // As provided by looking up the sender manually via the `member()` function
    // ANCHOR: member_lookup
    let sender_cred_from_group =
        if let Sender::Member(sender_index) = bob_processed_message.sender() {
            bob_group
                .member(*sender_index)
                .expect("Could not find sender in group.")
                .clone()
        } else {
            unreachable!("Expected sender type to be `Member`.")
        };
    // ANCHOR_END: member_lookup

    // Check that we received the correct message
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        bob_processed_message.into_content()
    {
        // Check the message
        assert_eq!(application_message.into_bytes(), message_alice);
        // Check that Alice sent the message
        assert_eq!(sender_cred_from_msg, sender_cred_from_group);
        assert_eq!(
            &sender_cred_from_msg,
            alice_group.credential().expect("Expected a credential.")
        );
    } else {
        unreachable!("Expected an ApplicationMessage.");
    }

    // === Bob leaves the group ===

    // ANCHOR: leaving
    let queued_message = bob_group
        .leave_group(provider, &bob_signature_keys)
        .expect("Could not leave group");
    // ANCHOR_END: leaving

    let alice_processed_message = alice_group
        .process_message(
            provider,
            queued_message
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Store proposal
    if let ProcessedMessageContent::ProposalMessage(staged_proposal) =
        alice_processed_message.into_content()
    {
        // Store proposal
        alice_group
            .store_pending_proposal(provider.storage(), *staged_proposal)
            .unwrap();
    } else {
        unreachable!("Expected a QueuedProposal.");
    }

    // Should fail because you cannot remove yourself from a group
    assert!(matches!(
        bob_group.commit_to_pending_proposals(provider, &bob_signature_keys),
        Err(CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::CannotRemoveSelf
        ))
    ));

    let (queued_message, _welcome_option, _group_info) = alice_group
        .commit_to_pending_proposals(provider, &alice_signature_keys)
        .expect("Could not commit to proposals.");

    // Check that Bob's group is still active
    assert!(bob_group.is_active());

    // Check that we received the correct proposals
    if let Some(staged_commit) = alice_group.pending_commit() {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(
            remove.remove_proposal().removed(),
            bob_group.own_leaf_index()
        );
        // Check that Bob removed himself
        assert!(matches!(
            remove.sender(),
            Sender::Member(member) if *member == bob_group.own_leaf_index()
        ));
        // Merge staged Commit
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge Commit.");

    let bob_processed_message = bob_group
        .process_message(
            provider,
            queued_message
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that we received the correct proposals
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(
            remove.remove_proposal().removed(),
            bob_group.own_leaf_index()
        );
        // Check that Bob removed himself
        assert!(matches!(
            remove.sender(),
            Sender::Member(member) if *member == bob_group.own_leaf_index()
        ));
        assert!(staged_commit.self_removed());
        // Merge staged Commit
        bob_group
            .merge_staged_commit(provider, *staged_commit)
            .expect("Error merging staged commit.");
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that Bob's group is no longer active
    assert!(!bob_group.is_active());

    // Make sure the group contains one member
    assert_eq!(alice_group.members().count(), 1);

    // Check that Alice is the only member of the group
    let members = alice_group.members().collect::<Vec<Member>>();
    let credential0 = members[0].credential.serialized_content();
    assert_eq!(credential0, b"Alice");

    // === Re-Add Bob with external Add proposal ===

    // Create a new KeyPackageBundle for Bob
    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential.clone(),
        Extensions::default(),
        provider,
        &bob_signature_keys,
    );

    // ANCHOR: external_join_proposal
    let proposal =
        JoinProposal::new::<<Provider as openmls_traits::OpenMlsProvider>::StorageProvider>(
            bob_key_package.key_package().clone(),
            alice_group.group_id().clone(),
            alice_group.epoch(),
            &bob_signature_keys,
        )
        .expect("Could not create external Add proposal");
    // ANCHOR_END: external_join_proposal

    // ANCHOR: decrypt_external_join_proposal
    let alice_processed_message = alice_group
        .process_message(
            provider,
            proposal
                .into_protocol_message()
                .expect("Unexpected message type."),
        )
        .expect("Could not process message.");
    match alice_processed_message.into_content() {
        ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
            alice_group
                .store_pending_proposal(provider.storage(), *proposal)
                .unwrap();
            let (_commit, welcome, _group_info) = alice_group
                .commit_to_pending_proposals(provider, &alice_signature_keys)
                .expect("Could not commit");
            assert_eq!(alice_group.members().count(), 1);
            alice_group
                .merge_pending_commit(provider)
                .expect("Could not merge commit");
            assert_eq!(alice_group.members().count(), 2);

            let welcome: MlsMessageIn = welcome.expect("Welcome was not returned").into();
            let welcome = welcome
                .into_welcome()
                .expect("expected the message to be a welcome message");

            let bob_group = StagedWelcome::new_from_welcome(
                provider,
                mls_group_create_config.join_config(),
                welcome,
                None,
            )
            .expect("Bob could not stage the the group join")
            .into_group(provider)
            .expect("Bob could not join the group");
            assert_eq!(bob_group.members().count(), 2);
        }
        _ => unreachable!(),
    }
    // ANCHOR_END: decrypt_external_join_proposal

    // get Bob's index
    let bob_index = alice_group
        .members()
        .find_map(|member| {
            let credential = member.credential.serialized_content();
            if credential == b"Bob" {
                Some(member.index)
            } else {
                None
            }
        })
        .unwrap();

    // ANCHOR: external_remove_proposal
    let proposal = ExternalProposal::new_remove::<Provider>(
        bob_index,
        alice_group.group_id().clone(),
        alice_group.epoch(),
        &ds_signature_keys,
        SenderExtensionIndex::new(0),
    )
    .expect("Could not create external Remove proposal");
    // ANCHOR_END: external_remove_proposal

    // ANCHOR: decrypt_external_join_proposal
    let alice_processed_message = alice_group
        .process_message(
            provider,
            proposal
                .into_protocol_message()
                .expect("Unexpected message type."),
        )
        .expect("Could not process message.");
    match alice_processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => {
            alice_group
                .store_pending_proposal(provider.storage(), *proposal)
                .unwrap();
            assert_eq!(alice_group.members().count(), 2);
            alice_group
                .commit_to_pending_proposals(provider, &alice_signature_keys)
                .expect("Could not commit");
            alice_group
                .merge_pending_commit(provider)
                .expect("Could not merge commit");
            assert_eq!(alice_group.members().count(), 1);
        }
        _ => unreachable!(),
    }
    // ANCHOR_END: decrypt_external_join_proposal

    // === Save the group state ===

    // Create a new KeyPackageBundle for Bob
    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential,
        Extensions::default(),
        provider,
        &bob_signature_keys,
    );

    // Add Bob to the group
    let (_queued_message, welcome, _group_info) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Could not add Bob");

    // Merge Commit
    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let bob_staged_welcome = StagedWelcome::new_from_welcome(
        provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Could not create StagedWelcome from Welcome");

    // Bob can inspect the staged welcome here

    let mut bob_group = bob_staged_welcome
        .into_group(provider)
        .expect("Could not create group from StagedWelcome");

    assert_eq!(
        alice_group
            .export_secret(provider, "before load", &[], 32)
            .unwrap(),
        bob_group
            .export_secret(provider, "before load", &[], 32)
            .unwrap()
    );

    bob_group = MlsGroup::load(provider.storage(), &group_id)
        .expect("An error occurred while loading the group")
        .expect("No group with provided group id exists");

    // Make sure the state is still the same
    assert_eq!(
        alice_group
            .export_secret(provider, "after load", &[], 32)
            .unwrap(),
        bob_group
            .export_secret(provider, "after load", &[], 32)
            .unwrap()
    );
}

#[openmls_test]
fn test_empty_input_errors() {
    let group_id = GroupId::from_slice(b"Test Group");

    // Generate credentials with keys
    let (alice_credential, alice_signature_keys) =
        generate_credential("Alice".into(), ciphersuite.signature_algorithm(), provider);

    // Define the MlsGroup configuration
    let mls_group_config = MlsGroupCreateConfig::test_default(ciphersuite);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signature_keys,
        &mls_group_config,
        group_id,
        alice_credential,
    )
    .expect("An unexpected error occurred.");

    assert!(matches!(
        alice_group
            .add_members(provider, &alice_signature_keys, &[])
            .expect_err("No EmptyInputError when trying to pass an empty slice to `add_members`."),
        AddMembersError::EmptyInput(EmptyInputError::AddMembers)
    ));
    assert!(matches!(
        alice_group
            .remove_members(provider, &alice_signature_keys, &[])
            .expect_err(
                "No EmptyInputError when trying to pass an empty slice to `remove_members`."
            ),
        RemoveMembersError::EmptyInput(EmptyInputError::RemoveMembers)
    ));
}

#[openmls_test]
fn custom_proposal_usage(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Generate credentials with keys
    let (alice_credential_with_key, alice_signer) =
        generate_credential(b"alice".into(), ciphersuite.signature_algorithm(), provider);

    let (bob_credential_with_key, bob_signer) =
        generate_credential(b"bob".into(), ciphersuite.signature_algorithm(), provider);

    // ANCHOR: custom_proposal_type
    // Define a custom proposal type
    let custom_proposal_type = 0xFFFF;

    // Define capabilities supporting the custom proposal type
    let capabilities = Capabilities::new(
        None,
        None,
        None,
        Some(&[ProposalType::Custom(custom_proposal_type)]),
        None,
    );

    // Generate KeyPackage that signals support for the custom proposal type
    let bob_key_package = KeyPackageBuilder::new()
        .leaf_node_capabilities(capabilities.clone())
        .build(ciphersuite, provider, &bob_signer, bob_credential_with_key)
        .unwrap();

    // Create a group that supports the custom proposal type
    let mut alice_group = MlsGroup::builder()
        .with_capabilities(capabilities.clone())
        .ciphersuite(ciphersuite)
        .build(provider, &alice_signer, alice_credential_with_key)
        .unwrap();
    // ANCHOR_END: custom_proposal_type

    // Add Bob
    let (_mls_message, welcome, _group_info) = alice_group
        .add_members(
            provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .unwrap();

    alice_group.merge_pending_commit(provider).unwrap();

    let staged_welcome = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap();

    let mut bob_group = staged_welcome.into_group(provider).unwrap();

    // ANCHOR: custom_proposal_usage
    // Create a custom proposal based on an example payload and the custom
    // proposal type defined above
    let custom_proposal_payload = vec![0, 1, 2, 3];
    let custom_proposal =
        CustomProposal::new(custom_proposal_type, custom_proposal_payload.clone());

    let (custom_proposal_message, _proposal_ref) = alice_group
        .propose_custom_proposal_by_reference(provider, &alice_signer, custom_proposal.clone())
        .unwrap();

    // Have bob process the custom proposal.
    let processed_message = bob_group
        .process_message(
            provider,
            custom_proposal_message.into_protocol_message().unwrap(),
        )
        .unwrap();

    let ProcessedMessageContent::ProposalMessage(proposal) = processed_message.into_content()
    else {
        panic!("Unexpected message type");
    };

    bob_group
        .store_pending_proposal(provider.storage(), *proposal)
        .unwrap();

    // Commit to the proposal
    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(provider, &alice_signer)
        .unwrap();

    let processed_message = bob_group
        .process_message(provider, commit.into_protocol_message().unwrap())
        .unwrap();

    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => staged_commit,
        _ => panic!("Unexpected message type"),
    };

    // Check that the proposal is present in the staged commit
    assert!(staged_commit.queued_proposals().any(|qp| {
        let Proposal::Custom(custom_proposal) = qp.proposal() else {
            return false;
        };
        custom_proposal.proposal_type() == custom_proposal_type
            && custom_proposal.payload() == custom_proposal_payload
    }));

    // ANCHOR_END: custom_proposal_usage
}

#[openmls_test]
fn commit_builder() {
    // Generate credentials with keys
    let (alice_credential, alice_signature_keys) =
        generate_credential("Alice".into(), ciphersuite.signature_algorithm(), provider);

    let (bob_credential, bob_signature_keys) =
        generate_credential("Bob".into(), ciphersuite.signature_algorithm(), provider);

    // Generate KeyPackages
    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential.clone(),
        Extensions::default(),
        provider,
        &bob_signature_keys,
    );

    // Define the MlsGroup configuration
    // delivery service credentials
    let (ds_credential_with_key, _) = generate_credential(
        "delivery-service".into(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            10,   // out_of_order_tolerance
            2000, // maximum_forward_distance
        ))
        .with_group_context_extensions(Extensions::single(Extension::ExternalSenders(vec![
            ExternalSender::new(
                ds_credential_with_key.signature_key.clone(),
                ds_credential_with_key.credential.clone(),
            ),
        ])))
        .expect("error adding external senders extension to group context extensions")
        .ciphersuite(ciphersuite)
        // we need to specify the non-default extension here
        .capabilities(Capabilities::new(
            None, // Defaults to the group's protocol version
            None, // Defaults to the group's ciphersuite
            Some(&[ExtensionType::Unknown(0xff00)]),
            None, // Defaults to all basic extension types
            Some(&[CredentialType::Basic]),
        ))
        // Example leaf extension
        .with_leaf_node_extensions(Extensions::single(Extension::Unknown(
            0xff00,
            UnknownExtension(vec![0, 1, 2, 3]),
        )))
        .expect("failed to configure leaf extensions")
        .use_ratchet_tree_extension(true)
        .build();

    let mut alice_group = MlsGroup::new(
        provider,
        &alice_signature_keys,
        &mls_group_create_config,
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===
    // ANCHOR: alice_adds_bob_with_commit_builder
    let message_bundle = alice_group
        .commit_builder()
        .propose_adds(Some(bob_key_package.key_package().clone()))
        .load_psks(provider.storage())
        .expect("error loading psks")
        .build(
            provider.rand(),
            provider.crypto(),
            &alice_signature_keys,
            |_proposal| true,
        )
        .expect("error validating data and building commit")
        .stage_commit(provider)
        .expect("error staging commit");

    let (mls_message_out, welcome, group_info) = message_bundle.into_contents();
    // ANCHOR_END: alice_adds_bob_with_commit_builder
    _ = (mls_message_out, welcome, group_info)
}

#[openmls_test]
fn reject_commit_add() {
    let group_id = GroupId::from_slice(b"Test Group");

    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Generate credentials with keys
    let (alice_credential, alice_signature_keys) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let (bob_credential, bob_signature_keys) = generate_credential(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signature_keys,
        &mls_group_create_config,
        group_id.clone(),
        alice_credential,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential.clone(),
        Extensions::default(),
        bob_provider,
        &bob_signature_keys,
    );

    let state_before = GroupStorageState::from_storage(alice_provider.storage(), &group_id);

    // === Alice adds Bob ===
    //ANCHOR: reject_commit_add_setup
    let (_mls_message_out, _welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_signature_keys,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Could not add members.");
    //ANCHOR_END: reject_commit_add_setup

    assert_ne!(
        provider.storage().group_state(&group_id).unwrap(),
        Some(MlsGroupState::Operational)
    );

    // === Commit rejected by delivery service ===
    // Will need to clean up

    assert_eq!(alice_group.members().count(), 1);
    //ANCHOR: reject_commit_add
    // clear pending commit and reset state
    alice_group
        .clear_pending_commit(alice_provider.storage())
        .unwrap();
    //ANCHOR_END: reject_commit_add
    let state_after = GroupStorageState::from_storage(alice_provider.storage(), &group_id);
    assert!(state_before == state_after);
}

#[openmls_test]
fn reject_commit_update() {
    let provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credentials with keys
    let (alice_credential, alice_signer) =
        generate_credential("Alice".into(), ciphersuite.signature_algorithm(), provider);

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_create_config,
        group_id.clone(),
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    // === Alice new credential ===
    let basic_credential = BasicCredential::new("Alice".into());
    let new_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    //new_signer.store(provider.storage()).unwrap();
    let new_credential = CredentialWithKey {
        credential: basic_credential.into(),
        signature_key: new_signer.to_public_vec().into(),
    };

    // Check alice credential
    let own_leaf_node_before = alice_group.own_leaf_node().unwrap().clone();
    assert_eq!(
        own_leaf_node_before.credential(),
        &alice_credential.credential
    );
    // Check alice signature key
    assert_eq!(
        own_leaf_node_before.signature_key(),
        &alice_credential.signature_key
    );
    let own_leaf_nodes_before: Vec<LeafNode> = provider
        .storage()
        .own_leaf_nodes(&group_id)
        .expect("could not get leaf nodes");

    // NOTE: the list of own leaf nodes in the storage provider is empty.
    // TODO: is this correct?
    assert_eq!(own_leaf_nodes_before.len(), 0);

    // save the storage state
    let state_before = GroupStorageState::from_storage(provider.storage(), &group_id);

    // === Alice updates ===
    // Alice updates own credential
    // HPKE encryption key is also updated by the commit

    let leaf_node_parameters = LeafNodeParameters::builder()
        .with_credential_with_key(new_credential)
        .build();
    //ANCHOR: reject_commit_update_setup
    let commit_message_bundle = alice_group
        .self_update(provider, &new_signer, leaf_node_parameters)
        .expect("failed to update own leaf node");
    //ANCHOR_END: reject_commit_update_setup
    assert_ne!(
        provider.storage().group_state(&group_id).unwrap(),
        Some(MlsGroupState::Operational)
    );

    // Ensure own leaf node credential is still the same as before
    let own_leaf_node_after = alice_group.own_leaf_node().unwrap();
    assert_eq!(
        own_leaf_node_after.credential(),
        own_leaf_node_before.credential(),
    );
    // Ensure own leaf node signature key is still the same as before
    assert_eq!(
        own_leaf_node_after.signature_key(),
        own_leaf_node_before.signature_key(),
    );
    // Ensure own leaf node encryption key is still the same as before
    assert_eq!(
        own_leaf_node_after.encryption_key(),
        own_leaf_node_before.encryption_key(),
    );

    let own_leaf_nodes_after: Vec<LeafNode> = provider
        .storage()
        .own_leaf_nodes(&group_id)
        .expect("could not get leaf nodes");
    assert_eq!(own_leaf_nodes_after.len(), 0);

    // Ensure that leaf nodes same in storage
    assert_eq!(own_leaf_nodes_before, own_leaf_nodes_after);

    let commit: &MlsMessageOut = commit_message_bundle.commit();

    // === Commit rejected by delivery service ===
    //ANCHOR: reject_commit_update
    // clear pending commit and reset state
    alice_group
        .clear_pending_commit(provider.storage())
        .unwrap();

    // also delete the unused signature key pair,
    // if it was stored in the storage provider earlier.
    // This is not part of OpenMLS.
    SignatureKeyPair::delete(
        provider.storage(),
        new_signer.public(),
        ciphersuite.signature_algorithm(),
    )
    .expect("Could not delete signature key pair from storage");
    //ANCHOR_END: reject_commit_update

    let state_after = GroupStorageState::from_storage(provider.storage(), &group_id);
    assert!(state_before == state_after);
}

#[openmls_test]
fn not_join_group() {
    let group_id = GroupId::from_slice(b"Test Group");

    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Generate credentials with keys
    let (alice_credential, alice_signature_keys) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let (bob_credential, bob_signature_keys) = generate_credential(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signature_keys,
        &mls_group_create_config,
        group_id.clone(),
        alice_credential,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential.clone(),
        Extensions::default(),
        bob_provider,
        &bob_signature_keys,
    );

    // === Alice adds Bob ===
    let (_mls_message_out, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_signature_keys,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Could not add members.");

    let welcome: MlsMessageIn = welcome.into();

    let group_context: Option<GroupContext> =
        bob_provider.storage().group_context(&group_id).unwrap();
    assert!(group_context.is_none());
    let confirmation_tag: Option<ConfirmationTag> =
        bob_provider.storage().confirmation_tag(&group_id).unwrap();
    assert!(confirmation_tag.is_none());

    let state_before = GroupStorageState::from_storage(bob_provider.storage(), &group_id);
    //ANCHOR: not_join_group_welcome
    let welcome = match welcome.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => unimplemented!("Handle other message types"),
    };
    //ANCHOR_END: not_join_group_welcome

    //ANCHOR: not_join_group_welcome_inspect
    for _secret in welcome.secrets() {
        // TODO: check secret
    }
    //ANCHOR_END: not_join_group_welcome_inspect

    //ANCHOR: not_join_group_processed_welcome
    let join_config = MlsGroupJoinConfig::default();
    let processed_welcome = ProcessedWelcome::new_from_welcome(bob_provider, &join_config, welcome)
        .expect("Error constructing processed welcome");
    //ANCHOR_END: not_join_group_processed_welcome

    //ANCHOR: not_join_group_processed_welcome_inspect
    let _unverified_psks = processed_welcome.psks();
    let _unverified_group_info = processed_welcome.unverified_group_info();
    //ANCHOR_END: not_join_group_processed_welcome_inspect

    //ANCHOR: not_join_group_staged_welcome
    let staged_welcome: StagedWelcome = processed_welcome
        .into_staged_welcome(bob_provider, None)
        .expect("Error constructing staged welcome");
    //ANCHOR_END: not_join_group_staged_welcome

    // check storage state after staging welcome
    let own_leaf_nodes: Vec<LeafNode> = bob_provider.storage().own_leaf_nodes(&group_id).unwrap();
    // TODO: is this correct?
    assert!(own_leaf_nodes.is_empty());

    let own_leaf_index: Option<LeafNodeIndex> =
        bob_provider.storage().own_leaf_index(&group_id).unwrap();

    // TODO: is this correct?
    assert!(own_leaf_index.is_none());

    //ANCHOR: not_join_group_welcome_sender
    let welcome_sender: &LeafNode = staged_welcome
        .welcome_sender()
        .expect("Welcome sender could not be retrieved");

    // Inspect sender's credential...
    let _credential = welcome_sender.credential();
    // Inspect sender's signature public key...
    let _signature_key = welcome_sender.signature_key();
    // Inspect sender's encryption public key...
    let _encryption_key = welcome_sender.encryption_key();
    //ANCHOR_END: not_join_group_welcome_sender

    //ANCHOR: not_join_group_group_context
    // Inspect group context...
    let group_context = staged_welcome.group_context();

    // Inspect protocol version...
    let _protocol_version: ProtocolVersion = group_context.protocol_version();
    // Inspect extensions...
    let extensions: &Extensions = group_context.extensions();

    // Can check which extensions are enabled
    let _has_ratchet_extension = extensions.ratchet_tree().is_some();

    // Inspect required capabilities...
    if let Some(capabilities) = group_context.required_capabilities() {
        // Inspect extension types...
        let _extension_types: &[ExtensionType] = capabilities.extension_types();
        // Inspect proposal types...
        let _proposal_types: &[ProposalType] = capabilities.proposal_types();
        // Inspect credential types...
        let _credential_types: &[CredentialType] = capabilities.credential_types();
    }
    //ANCHOR_END: not_join_group_group_context

    //ANCHOR: not_join_group_members
    // Inspect the group members
    for member in staged_welcome.members() {
        // leaf node index
        let _leaf_node_index = member.index;
        // credential
        let _credential = member.credential;
        // encryption public key
        let _encryption_key = member.encryption_key;
        // signature public key
        let _signature_key = member.signature_key;
    }
    //ANCHOR_END: not_join_group_members

    //ANCHOR: not_join_group_cleanup
    // clean up storage provider
    PublicGroup::delete(bob_provider.storage(), &group_id).unwrap();
    // drop staged welcome
    drop(staged_welcome);
    //ANCHOR_END: not_join_group_cleanup

    let state_after = GroupStorageState::from_storage(bob_provider.storage(), &group_id);
    assert!(state_before == state_after);
}
