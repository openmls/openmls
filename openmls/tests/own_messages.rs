//! Test that processing a PrivateMessage authored by this client surfaces as
//! `OwnPrivateMessage` instead of failing. The groups here do not register
//! emulation state, so this also holds under the `virtual-clients-draft`
//! feature whenever the message cannot be decrypted (the dual-use ratchet
//! there still decrypts own messages whose secrets are retained).
use openmls::prelude::*;
use openmls_test::openmls_test;
use test_utils::new_credential;

#[openmls_test]
fn own_messages_surface_as_own_private_message() {
    let group_id = GroupId::from_slice(b"Test Group");

    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Generate credentials with keys
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    // Generate KeyPackage for Bob
    let bob_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(
            ciphersuite,
            bob_provider,
            &bob_signer,
            bob_credential.clone(),
        )
        .unwrap()
        .key_package()
        .to_owned();

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        group_id.clone(),
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===
    let welcome = match alice_group.add_members(alice_provider, &alice_signer, &[bob_key_package]) {
        Ok((_, welcome, _)) => welcome,
        Err(e) => panic!("Could not add member to group: {e:?}"),
    };

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
        assert!(
            matches!(add.sender(), Sender::Member(member) if *member == alice_group.own_leaf_index())
        );
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");

    // Check that the group now has two members
    assert_eq!(alice_group.members().count(), 2);

    // Check that Alice & Bob are the members of the group
    let members = alice_group.members().collect::<Vec<Member>>();
    let credential0 = members[0].credential.serialized_content();
    let credential1 = members[1].credential.serialized_content();
    assert_eq!(credential0, b"Alice");
    assert_eq!(credential1, b"Bob");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating StagedWelcome from Welcome")
    .into_group(bob_provider)
    .expect("Error creating group from StagedWelcome");

    // === Alice sends a message to Bob ===
    let message_alice = b"Hi, I'm Alice!";
    let queued_message = alice_group
        .create_message(alice_provider, &alice_signer, message_alice)
        .expect("Error creating application message");

    let processed_message = bob_group
        .process_message(
            bob_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    let sender = processed_message.credential().clone();

    // Check that Bob can decrypt the message
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        // Check the message
        assert_eq!(application_message.into_bytes(), message_alice);
        // Check that Alice sent the message
        assert_eq!(
            &sender,
            alice_group
                .credential()
                .expect("An unexpected error occurred.")
        );
    } else {
        unreachable!("Expected an ApplicationMessage.");
    }

    // === Alice processes her own echoed application message ===
    let processed_message = alice_group
        .process_message(
            alice_provider,
            queued_message
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Expected processing own message to succeed.");

    assert!(
        matches!(
            processed_message.content(),
            ProcessedMessageContent::OwnPrivateMessage
        ),
        "Expected OwnPrivateMessage, got {:?}",
        processed_message.content()
    );
    assert!(
        matches!(
            processed_message.sender(),
            Sender::Member(idx) if *idx == alice_group.own_leaf_index()
        ),
        "Expected sender to be Alice's leaf index"
    );
    assert_eq!(processed_message.epoch(), alice_group.epoch());
    assert_eq!(
        processed_message.credential(),
        alice_group
            .credential()
            .expect("An unexpected error occurred.")
    );
}

/// Test that an own PrivateMessage Commit (echoed back by the DS) surfaces as
/// `OwnPrivateMessage`, not `OwnPendingCommit`. Under the
/// `virtual-clients-draft` feature the commit's encryption secret is still
/// retained, so the echo decrypts and surfaces as `OwnPendingCommit` instead.
/// TODO 2102: This will be fixed in a follow-up PR.
#[openmls_test]
fn own_private_commit_surfaces_as_own_private_message() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    let bob_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(
            ciphersuite,
            bob_provider,
            &bob_signer,
            bob_credential.clone(),
        )
        .unwrap()
        .key_package()
        .to_owned();

    // Use a pure-ciphertext policy so commits are sent as PrivateMessage.
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build();

    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    let (_, welcome, _) = alice_group
        .add_members(alice_provider, &alice_signer, &[bob_key_package])
        .expect("Could not add member to group");

    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");

    let welcome_in: MlsMessageIn = welcome.into();
    let welcome_in = welcome_in
        .into_welcome()
        .expect("expected the message to be a welcome message");
    let _bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome_in,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating StagedWelcome from Welcome")
    .into_group(bob_provider)
    .expect("Error creating group from StagedWelcome");

    // Now have Alice create another commit as PrivateMessage while Bob is in group.
    let (commit_msg2, _, _) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_signer)
        .expect("Could not commit");

    let echoed_commit2: MlsMessageIn = commit_msg2.clone().into();

    // Process the echoed commit BEFORE merging the pending commit.
    let processed = alice_group
        .process_message(
            alice_provider,
            echoed_commit2
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Expected processing own private commit to succeed.");

    // The commit is a PrivateMessage, so it cannot be decrypted/verified;
    // it surfaces as OwnPrivateMessage, NOT OwnPendingCommit.
    #[cfg(not(feature = "virtual-clients-draft"))]
    assert!(
        matches!(
            processed.content(),
            ProcessedMessageContent::OwnPrivateMessage
        ),
        "Expected OwnPrivateMessage for own private commit, got {:?}",
        processed.content()
    );
    // With the `virtual-clients-draft` feature, the dual-use ratchet still
    // retains the commit's handshake encryption secret (only application
    // secrets are confirmed), so the echo decrypts and matches the pending
    // commit.
    // TODO 2102: This will be fixed in a follow-up PR.
    #[cfg(feature = "virtual-clients-draft")]
    assert!(
        matches!(
            processed.content(),
            ProcessedMessageContent::OwnPendingCommit
        ),
        "Expected OwnPendingCommit for own private commit, got {:?}",
        processed.content()
    );

    // Merging the pending commit still works after processing the echo.
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("merge_pending_commit failed after processing own private commit echo");
}
