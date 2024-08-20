use core::panic;

use frankenstein::{FrankenFramedContentBody, FrankenPublicMessage};
use mls_group::tests_and_kats::utils::{
    flip_last_byte, setup_alice_bob, setup_alice_bob_group, setup_client,
};
use tls_codec::Serialize;

use crate::{
    binary_tree::*,
    ciphersuite::{signable::Signable, AeadNonce},
    credentials::*,
    framing::*,
    group::{errors::*, *},
    key_packages::*,
    messages::{group_info::GroupInfoTBS, *},
    prelude::LeafNodeParameters,
    schedule::psk::{ExternalPsk, PreSharedKeyId, Psk},
    test_utils::*,
    treesync::errors::ApplyUpdatePathError,
};

#[openmls_test::openmls_test]
fn failed_groupinfo_decryption(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    let epoch = 123;
    let group_id = GroupId::random(provider.rand());
    let tree_hash = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let confirmed_transcript_hash = vec![1, 1, 1];
    let extensions = Extensions::empty();
    let confirmation_tag = ConfirmationTag(Mac {
        mac_value: vec![1, 2, 3, 4, 5, 6, 7, 8, 9].into(),
    });

    // Create credentials and keys
    let (alice_credential_with_key, alice_signature_keys) =
        test_utils::new_credential(provider, b"Alice", ciphersuite.signature_algorithm());

    let key_package_bundle = KeyPackageBundle::generate(
        provider,
        &alice_signature_keys,
        ciphersuite,
        alice_credential_with_key,
    );

    let group_info_tbs = {
        let group_context = GroupContext::new(
            ciphersuite,
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            Extensions::empty(),
        );

        GroupInfoTBS::new(
            group_context,
            extensions,
            confirmation_tag,
            LeafNodeIndex::new(0),
        )
    };

    // Generate key and nonce for the symmetric cipher.
    let welcome_key = AeadKey::random(ciphersuite, provider.rand());
    let welcome_nonce = AeadNonce::random(provider.rand());

    // Generate receiver key pair.
    let receiver_key_pair = provider
        .crypto()
        .derive_hpke_keypair(
            ciphersuite.hpke_config(),
            Secret::random(ciphersuite, provider.rand())
                .expect("Not enough randomness.")
                .as_slice(),
        )
        .expect("error deriving receiver hpke key pair");
    let hpke_context = b"group info welcome test info";
    let group_secrets = b"these should be the group secrets";
    let mut encrypted_group_secrets = hpke::encrypt_with_label(
        receiver_key_pair.public.as_slice(),
        "Welcome",
        hpke_context,
        group_secrets,
        ciphersuite,
        provider.crypto(),
    )
    .unwrap();

    let group_info = group_info_tbs
        .sign(&alice_signature_keys)
        .expect("Error signing group info");

    // Mess with the ciphertext by flipping the last byte.
    flip_last_byte(&mut encrypted_group_secrets);

    let broken_secrets = vec![EncryptedGroupSecrets::new(
        key_package_bundle
            .key_package
            .hash_ref(provider.crypto())
            .expect("Could not hash KeyPackage."),
        encrypted_group_secrets,
    )];

    // Encrypt the group info.
    let encrypted_group_info = welcome_key
        .aead_seal(
            provider.crypto(),
            &group_info
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
            &[],
            &welcome_nonce,
        )
        .expect("An unexpected error occurred.");

    // Now build the welcome message.
    let broken_welcome = Welcome::new(ciphersuite, broken_secrets, encrypted_group_info);

    let error = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        broken_welcome,
        None,
    )
    .and_then(|staged_join| staged_join.into_group(provider))
    .expect_err("Creation of mls group from a broken Welcome was successful.");

    assert!(matches!(
        error,
        WelcomeError::GroupSecrets(GroupSecretsError::DecryptionFailed)
    ))
}

/// Test what happens if the KEM ciphertext for the receiver in the UpdatePath
/// is broken.
#[openmls_test::openmls_test]
fn update_path() {
    // === Alice creates a group with her and Bob ===
    let (
        mut group_alice,
        _alice_signature_keys,
        mut group_bob,
        bob_signature_keys,
        _bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, provider);

    // === Bob updates and commits ===
    let mut bob_new_leaf_node = group_bob.own_leaf_node().unwrap().clone();
    bob_new_leaf_node
        .update(
            ciphersuite,
            provider,
            &bob_signature_keys,
            group_bob.group_id().clone(),
            group_bob.own_leaf_index(),
            LeafNodeParameters::default(),
        )
        .unwrap();

    let (update_bob, _welcome_option, _group_info_option) = group_bob
        .self_update(provider, &bob_signature_keys, LeafNodeParameters::default())
        .expect("Could not create proposal.");

    // Now we break Alice's HPKE ciphertext in Bob's commit by breaking
    // apart the commit, manipulating the ciphertexts and the piecing it
    // back together.
    let pm = match update_bob.body {
        mls_group::MlsMessageBodyOut::PublicMessage(pm) => pm,
        _ => panic!("Wrong message type"),
    };

    let franken_pm = FrankenPublicMessage::from(pm.clone());
    let mut content = franken_pm.content.clone();
    let FrankenFramedContentBody::Commit(ref mut commit) = content.body else {
        panic!("Unexpected content type");
    };
    let Some(ref mut path) = commit.path else {
        panic!("No path in commit.");
    };

    for node in &mut path.nodes {
        for eps in &mut node.encrypted_path_secrets {
            let mut eps_ctxt_vec = Vec::<u8>::from(eps.ciphertext.clone());
            eps_ctxt_vec[0] ^= 0xff;
            eps.ciphertext = eps_ctxt_vec.into();
        }
    }

    // Rebuild the PublicMessage with the new content
    let group_context = group_bob.export_group_context().clone();
    let membership_key = group_bob.message_secrets().membership_key().as_slice();

    let broken_message = FrankenPublicMessage::auth(
        provider,
        ciphersuite,
        &bob_signature_keys,
        content,
        Some(&group_context.into()),
        Some(membership_key),
        Some(pm.confirmation_tag().unwrap().0.mac_value.clone()),
    );

    let protocol_message =
        ProtocolMessage::PublicMessage(PublicMessage::from(broken_message).into());

    let result = group_alice.process_message(provider, protocol_message);
    assert_eq!(
        result.expect_err("Successful processing of a broken commit."),
        ProcessMessageError::InvalidCommit(StageCommitError::UpdatePathError(
            ApplyUpdatePathError::UnableToDecrypt
        ))
    );
}

// Test several scenarios when PSKs are used in a group
#[openmls_test::openmls_test]
fn psks() {
    // Basic group setup.
    let (
        alice_credential_with_key,
        alice_signature_keys,
        bob_key_package_bundle,
        bob_signature_keys,
    ) = setup_alice_bob(ciphersuite, provider);

    // === Alice creates a group with a PSK ===
    let psk_id = vec![1u8, 2, 3];

    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let external_psk = ExternalPsk::new(psk_id);
    let preshared_key_id =
        PreSharedKeyId::new(ciphersuite, provider.rand(), Psk::External(external_psk))
            .expect("An unexpected error occured.");
    preshared_key_id.store(provider, secret.as_slice()).unwrap();
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(provider, &alice_signature_keys, alice_credential_with_key)
        .expect("Error creating group.");

    // === Alice creates a PSK proposal ===
    log::info!(" >>> Creating psk proposal ...");
    let (_psk_proposal, _proposal_ref) = alice_group
        .propose_external_psk(provider, &alice_signature_keys, preshared_key_id)
        .expect("Could not create PSK proposal");

    // === Alice adds Bob (and commits to PSK proposal) ===
    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[bob_key_package_bundle.key_package().clone()],
        )
        .expect("Could not create commit");

    log::info!(" >>> Merging commit ...");

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");

    let ratchet_tree = alice_group.export_ratchet_tree();

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Could not stage welcome")
    .into_group(provider)
    .expect("Could not create group from welcome");

    // === Bob updates and commits ===
    let (_commit, _welcome_option, _group_info_option) = bob_group
        .self_update(provider, &bob_signature_keys, LeafNodeParameters::default())
        .expect("An unexpected error occurred.");
}

// Test several scenarios when PSKs are used in a group
#[openmls_test::openmls_test]
fn staged_commit_creation(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Basic group setup.
    let (alice_credential_with_key, alice_signature_keys, bob_key_package_bundle, _) =
        setup_alice_bob(ciphersuite, provider);

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(provider, &alice_signature_keys, alice_credential_with_key)
        .expect("Error creating group.");

    // === Alice adds Bob ===
    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[bob_key_package_bundle.key_package().clone()],
        )
        .expect("Could not create commit");

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");

    let ratchet_tree = alice_group.export_ratchet_tree();

    let bob_group = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Could not stage welcome")
    .into_group(provider)
    .expect("Could not create group from welcome");

    // Let's make sure we end up in the same group state.
    assert_eq!(
        bob_group.epoch_authenticator(),
        alice_group.epoch_authenticator()
    );
    assert_eq!(
        bob_group.export_ratchet_tree(),
        alice_group.export_ratchet_tree()
    )
}

// Test processing of own commits
#[openmls_test::openmls_test]
fn own_commit_processing(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // Basic group setup.
    let (alice_credential_with_key, alice_signature_keys) =
        test_utils::new_credential(provider, b"Alice", ciphersuite.signature_algorithm());

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(provider, &alice_signature_keys, alice_credential_with_key)
        .expect("Error creating group.");

    // Alice creates a commit
    let (commit_out, _welcome_option, _group_info_option) = alice_group
        .self_update(
            provider,
            &alice_signature_keys,
            LeafNodeParameters::default(),
        )
        .expect("Could not create commit");

    let commit_in = MlsMessageIn::from(commit_out);

    // Alice attempts to process her own commit
    let error = alice_group
        .process_message(provider, commit_in.into_protocol_message().unwrap())
        .expect_err("no error while processing own commit");
    assert_eq!(
        error,
        ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)
    );
}

#[openmls_test::openmls_test]
fn proposal_application_after_self_was_removed(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // We're going to test if proposals are still applied, even after a client
    // notices that it was removed from a group.  We do so by having Alice
    // create a group, add Bob and then create a commit where Bob is removed and
    // Charlie is added in a single commit (by Alice). We then check if
    // everyone's membership list is as expected.

    // Basic group setup.
    let (alice_credential_with_key, _, alice_signature_keys, _pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_, bob_kpb, _, _) = setup_client("Bob", ciphersuite, provider);
    let (_, charlie_kpb, _, _) = setup_client("Charlie", ciphersuite, provider);

    let join_group_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(provider, &alice_signature_keys, alice_credential_with_key)
        .expect("Error creating group.");

    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[bob_kpb.key_package().clone()],
        )
        .expect("Could not create commit");

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");

    let ratchet_tree = alice_group.export_ratchet_tree();

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        &join_group_config,
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Could not stage welcome")
    .into_group(provider)
    .expect("Could not create group from welcome");

    // Alice adds Charlie and removes Bob in the same commit.
    // She first creates a proposal to remove Bob
    let bob_index = alice_group
        .members()
        .find(
            |Member {
                 index: _,
                 credential,
                 ..
             }| { credential.serialized_content() == b"Bob" },
        )
        .expect("Couldn't find Bob in tree.")
        .index;

    assert_eq!(bob_index.u32(), 1);

    let (bob_remove_proposal, _bob_remove_proposal_ref) = alice_group
        .propose_remove_member(provider, &alice_signature_keys, bob_index)
        .expect("Could not create proposal");

    // Bob processes the proposal
    let processed_message = bob_group
        .process_message(
            provider,
            bob_remove_proposal.into_protocol_message().unwrap(),
        )
        .unwrap();

    let staged_proposal = match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => *proposal,
        _ => panic!("Wrong message type"),
    };

    bob_group
        .store_pending_proposal(provider.storage(), staged_proposal)
        .expect("Error storing proposal");

    // Alice then commit to the proposal and at the same time adds Charlie
    let (commit, welcome, _group_info_option) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[charlie_kpb.key_package().clone()],
        )
        .expect("Could not create commit");

    // Alice merges her own commit
    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");

    // Bob processes the commit
    println!("Bob processes the commit");
    let processed_message = bob_group
        .process_message(provider, commit.into_protocol_message().unwrap())
        .unwrap();

    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => *commit,
        _ => panic!("Wrong message type"),
    };

    bob_group
        .merge_staged_commit(provider, staged_commit)
        .expect("Error merging commit.");

    // Charlie processes the welcome
    println!("Charlie processes the commit");
    let ratchet_tree = alice_group.export_ratchet_tree();

    let charlie_group = StagedWelcome::new_from_welcome(
        provider,
        &join_group_config,
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Error staging welcome.")
    .into_group(provider)
    .expect("Error creating group from welcome.");

    // We can now check that Bob correctly processed his commit and applied the changes
    // to his tree after he was removed by comparing membership lists. In
    // particular, Bob's list should show that he was removed and Charlie was
    // added.
    let alice_members = alice_group.members();

    let bob_members = bob_group.members();

    let charlie_members = charlie_group.members();

    for (alice_member, (bob_member, charlie_member)) in
        alice_members.zip(bob_members.zip(charlie_members))
    {
        // Note that we can't compare encryption keys for Bob because they
        // didn't get updated.
        assert_eq!(alice_member.index, bob_member.index);

        let alice_id = alice_member.credential.serialized_content();
        let bob_id = bob_member.credential.serialized_content();
        let charlie_id = charlie_member.credential.serialized_content();
        assert_eq!(alice_id, bob_id);
        assert_eq!(alice_member.signature_key, bob_member.signature_key);
        assert_eq!(charlie_member.index, bob_member.index);
        assert_eq!(charlie_id, bob_id);
        assert_eq!(charlie_member.signature_key, bob_member.signature_key);
        assert_eq!(charlie_member.encryption_key, alice_member.encryption_key);
    }

    let mut bob_members = bob_group.members();

    let member = bob_members.next().unwrap();
    let bob_next_id = member.credential.serialized_content();
    assert_eq!(bob_next_id, b"Alice");
    let member = bob_members.next().unwrap();
    let bob_next_id = member.credential.serialized_content();
    assert_eq!(bob_next_id, b"Charlie");
}

#[openmls_test::openmls_test]
fn proposal_application_after_self_was_removed_ref(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
    // We're going to test if proposals are still applied, even after a client
    // notices that it was removed from a group.  We do so by having Alice
    // create a group, add Bob and then create a commit where Bob is removed and
    // Charlie is added in a single commit (by Alice). We then check if
    // everyone's membership list is as expected.

    // Basic group setup.
    let (alice_credential_with_key, _, alice_signature_keys, _pk) =
        setup_client("Alice", ciphersuite, provider);
    let (_, bob_kpb, _, _) = setup_client("Bob", ciphersuite, provider);
    let (_, charlie_kpb, _, _) = setup_client("Charlie", ciphersuite, provider);

    let join_group_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(provider, &alice_signature_keys, alice_credential_with_key)
        .expect("Error creating group.");

    let (_commit, welcome, _group_info_option) = alice_group
        .add_members(
            provider,
            &alice_signature_keys,
            &[bob_kpb.key_package().clone()],
        )
        .expect("Could not create commit");

    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");

    let ratchet_tree = alice_group.export_ratchet_tree();

    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        &join_group_config,
        welcome.into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Could not stage welcome")
    .into_group(provider)
    .expect("Could not create group from welcome");

    // Alice adds Charlie and removes Bob in the same commit.
    // She first creates a proposal to remove Bob
    let bob_index = alice_group
        .members()
        .find(
            |Member {
                 index: _,
                 credential,
                 ..
             }| { credential.serialized_content() == b"Bob" },
        )
        .expect("Couldn't find Bob in tree.")
        .index;

    assert_eq!(bob_index.u32(), 1);

    let (bob_remove_proposal, _bob_remove_proposal_ref) = alice_group
        .propose_remove_member(provider, &alice_signature_keys, bob_index)
        .expect("Could not create proposal");

    let (charlie_add_proposal, _charlie_add_proposal_ref) = alice_group
        .propose_add_member(provider, &alice_signature_keys, charlie_kpb.key_package())
        .expect("Could not create proposal");

    // Bob processes the proposals
    let processed_message = bob_group
        .process_message(
            provider,
            bob_remove_proposal.into_protocol_message().unwrap(),
        )
        .unwrap();

    let staged_proposal = match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => *proposal,
        _ => panic!("Wrong message type"),
    };

    bob_group
        .store_pending_proposal(provider.storage(), staged_proposal)
        .expect("Error storing proposal");

    let processed_message = bob_group
        .process_message(
            provider,
            charlie_add_proposal.into_protocol_message().unwrap(),
        )
        .unwrap();

    let staged_proposal = match processed_message.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => *proposal,
        _ => panic!("Wrong message type"),
    };

    bob_group
        .store_pending_proposal(provider.storage(), staged_proposal)
        .expect("Error storing proposal");

    // Alice then commits to the proposal and at the same time adds Charlie
    alice_group.print_ratchet_tree("Alice's tree before commit\n");
    let alice_rt_before = alice_group.export_ratchet_tree();
    let (commit, welcome, _group_info_option) = alice_group
        .commit_to_pending_proposals(provider, &alice_signature_keys)
        .expect("Could not create commit");

    // Alice merges her own commit
    alice_group
        .merge_pending_commit(provider)
        .expect("Could not merge commit");
    alice_group.print_ratchet_tree("Alice's tree after commit\n");

    // Bob processes the commit
    println!("Bob processes the commit");
    bob_group.print_ratchet_tree("Bob's tree before processing the commit\n");
    let bob_rt_before = bob_group.export_ratchet_tree();
    assert_eq!(alice_rt_before, bob_rt_before);
    let processed_message = bob_group
        .process_message(provider, commit.into_protocol_message().unwrap())
        .unwrap();
    println!("Bob finished processesing the commit");

    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => *commit,
        _ => panic!("Wrong message type"),
    };

    bob_group
        .merge_staged_commit(provider, staged_commit)
        .expect("Error merging commit.");

    // Charlie processes the welcome
    println!("Charlie processes the commit");
    let ratchet_tree = alice_group.export_ratchet_tree();

    let charlie_group = StagedWelcome::new_from_welcome(
        provider,
        &join_group_config,
        welcome.unwrap().into_welcome().unwrap(),
        Some(ratchet_tree.into()),
    )
    .expect("Error staging welcome.")
    .into_group(provider)
    .expect("Error creating group from welcome.");

    // We can now check that Bob correctly processed his and applied the changes
    // to his tree after he was removed by comparing membership lists. In
    // particular, Bob's list should show that he was removed and Charlie was
    // added.
    let alice_members = alice_group.members();

    let bob_members = bob_group.members();

    let charlie_members = charlie_group.members();

    for (alice_member, (bob_member, charlie_member)) in
        alice_members.zip(bob_members.zip(charlie_members))
    {
        // Note that we can't compare encryption keys for Bob because they
        // didn't get updated.
        assert_eq!(alice_member.index, bob_member.index);

        let alice_id = alice_member.credential.serialized_content();
        let bob_id = bob_member.credential.serialized_content();
        let charlie_id = charlie_member.credential.serialized_content();
        assert_eq!(alice_id, bob_id);
        assert_eq!(alice_member.signature_key, bob_member.signature_key);
        assert_eq!(charlie_member.index, bob_member.index);
        assert_eq!(charlie_id, bob_id);
        assert_eq!(charlie_member.signature_key, bob_member.signature_key);
        assert_eq!(charlie_member.encryption_key, alice_member.encryption_key);
    }

    let mut bob_members = bob_group.members();

    let member = bob_members.next().unwrap();
    let bob_next_id = member.credential.serialized_content();
    assert_eq!(bob_next_id, b"Alice");
    let member = bob_members.next().unwrap();
    let bob_next_id = member.credential.serialized_content();
    assert_eq!(bob_next_id, b"Charlie");
}
