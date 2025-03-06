use openmls::{prelude::*, schedule::psk::*, test_utils::storage_state::GroupStorageState, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use openmls_traits::{signatures::Signer, types::SignatureScheme};
use treesync::LeafNodeParameters;

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
#[openmls_test]
fn discard_commit_add() {
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
    //ANCHOR: discard_commit_add_setup
    let (_mls_message_out, _welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_signature_keys,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Could not add members.");
    //ANCHOR_END: discard_commit_add_setup

    assert_ne!(
        provider.storage().group_state(&group_id).unwrap(),
        Some(MlsGroupState::Operational)
    );

    // === Commit rejected by delivery service ===
    // Will need to clean up

    assert_eq!(alice_group.members().count(), 1);
    //ANCHOR: discard_commit_add
    // clear pending commit and reset state
    alice_group
        .clear_pending_commit(alice_provider.storage())
        .unwrap();
    //ANCHOR_END: discard_commit_add
    let state_after = GroupStorageState::from_storage(alice_provider.storage(), &group_id);
    assert!(state_before == state_after);
}

#[openmls_test]
fn discard_commit_update() {
    let alice_provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credentials with keys
    let (alice_credential, alice_signer) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
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

    // === Alice new credential ===
    let basic_credential = BasicCredential::new("Alice".into());
    let new_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let new_credential = CredentialWithKey {
        credential: basic_credential.into(),
        signature_key: new_signer.to_public_vec().into(),
    };

    // store new credential
    new_signer.store(alice_provider.storage()).unwrap();

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
    let own_leaf_nodes_before: Vec<LeafNode> = alice_provider
        .storage()
        .own_leaf_nodes(&group_id)
        .expect("could not get leaf nodes");

    assert_eq!(own_leaf_nodes_before.len(), 0);

    // save the storage state
    let state_before = GroupStorageState::from_storage(alice_provider.storage(), &group_id);

    // check that alice signer was stored
    let alice_signer_still_stored = SignatureKeyPair::read(
        alice_provider.storage(),
        alice_signer.public(),
        ciphersuite.signature_algorithm(),
    )
    .is_some();
    assert_eq!(alice_signer_still_stored, true);
    // check that the signer was stored
    let new_signer_still_stored = SignatureKeyPair::read(
        alice_provider.storage(),
        new_signer.public(),
        ciphersuite.signature_algorithm(),
    )
    .is_some();
    assert_eq!(new_signer_still_stored, true);

    // === Alice updates ===
    // Alice updates own credential
    // HPKE encryption key is also updated by the commit

    let leaf_node_parameters = LeafNodeParameters::builder()
        .with_credential_with_key(new_credential)
        .build();
    //ANCHOR: discard_commit_update_setup
    let commit_message_bundle = alice_group
        .self_update(alice_provider, &new_signer, leaf_node_parameters)
        .expect("failed to update own leaf node");
    //ANCHOR_END: discard_commit_update_setup

    // Unused
    let _commit_message_bundle = commit_message_bundle;

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

    // === Commit rejected by delivery service ===
    //ANCHOR: discard_commit_update
    // delete the unused signature key pair from the storage provider,
    // if it was stored there earlier
    SignatureKeyPair::delete(
        alice_provider.storage(),
        new_signer.public(),
        ciphersuite.signature_algorithm(),
    )
    .expect("Could not delete unused signature key pair");

    // clear pending commit and reset state
    alice_group
        .clear_pending_commit(alice_provider.storage())
        .unwrap();
    //ANCHOR_END: discard_commit_update

    // check that alice signer still stored
    let alice_signer_still_stored = SignatureKeyPair::read(
        alice_provider.storage(),
        alice_signer.public(),
        ciphersuite.signature_algorithm(),
    )
    .is_some();
    assert_eq!(alice_signer_still_stored, true);

    let new_signer_still_stored = SignatureKeyPair::read(
        alice_provider.storage(),
        new_signer.public(),
        ciphersuite.signature_algorithm(),
    )
    .is_some();
    assert_eq!(new_signer_still_stored, false);

    let state_after = GroupStorageState::from_storage(alice_provider.storage(), &group_id);
    assert!(state_before == state_after);
}

#[openmls_test]
fn discard_commit_remove() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credentials with keys
    let (alice_credential, alice_signer) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let (bob_credential, bob_signer) = generate_credential(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );
    // Create a new KeyPackageBundle for Bob
    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential,
        Extensions::default(),
        bob_provider,
        &bob_signer,
    );

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
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
    let (_mls_message_out, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Could not add members.");

    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let staged_join = StagedWelcome::new_from_welcome(
        bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        None,
    )
    .expect("Error constructing staged join");
    let mut bob_group = staged_join
        .into_group(bob_provider)
        .expect("Error joining group from StagedWelcome");

    // save the storage state
    let state_before = GroupStorageState::from_storage(bob_provider.storage(), &group_id);

    // Bob removes Alice

    let alice_member = bob_group
        .members()
        .find(
            |Member {
                 index: _,
                 credential,
                 ..
             }| { credential.serialized_content() == b"Alice" },
        )
        .expect("Couldn't find Alice in the list of group members.");

    let alice_leaf_node_index = alice_member.index;
    let (_mls_message_out, _welcome, _group_info) = bob_group
        .remove_members(bob_provider, &bob_signer, &[alice_leaf_node_index])
        .expect("Could not remove Alice");

    // === Delivery service rejected the commit ===

    // Discard the commit
    //ANCHOR: discard_commit_remove
    bob_group
        .clear_pending_commit(bob_provider.storage())
        .expect("Could not clear pending commit");
    //ANCHOR_END: discard_commit_remove

    let state_after = GroupStorageState::from_storage(bob_provider.storage(), &group_id);
    assert!(state_before == state_after);
}

#[openmls_test]
fn discard_commit_psk() {
    let alice_provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credentials with keys
    let (alice_credential, alice_signer) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
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

    // save the storage state
    let state_before = GroupStorageState::from_storage(alice_provider.storage(), &group_id);

    let psk_bytes = vec![1; 32];
    let psk = Psk::External(ExternalPsk::new(psk_bytes.clone()));
    let psk_id = PreSharedKeyId::new(ciphersuite, alice_provider.rand(), psk.clone()).unwrap();

    // store
    // TODO: is this correct?
    psk_id
        .store(alice_provider, &psk_bytes)
        .expect("Could not store psk in storage provider");

    assert_eq!(alice_group.pending_proposals().count(), 0);

    // Create commit including propose external psk
    let (_message_out, _proposal_ref) = alice_group
        .propose_external_psk(alice_provider, &alice_signer, psk_id)
        .expect("Could not propose adding an external psk");

    assert_eq!(alice_group.pending_proposals().count(), 1);

    let (_commit, _welcome, _group_info) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_signer)
        .unwrap();

    // === Delivery service rejected the commit ===

    //ANCHOR: discard_commit_psk
    // clear the psk that was stored earlier, if necessary
    alice_provider
        .storage()
        .delete_psk(&psk)
        .expect("Could not delete stored psk");

    // clear pending commit and reset state
    alice_group
        .clear_pending_commit(alice_provider.storage())
        .expect("Could not clear pending commit");
    //ANCHOR_END: discard_commit_psk

    // also delete the proposals so the state can be compared to the previous state
    alice_group
        .clear_pending_proposals(alice_provider.storage())
        .expect("Could not clear pending proposals");

    let state_after = GroupStorageState::from_storage(alice_provider.storage(), &group_id);
    assert!(state_before == state_after);
}

/*
#[openmls_test]
fn discard_commit_reinit() {
    let alice_provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credentials with keys
    let (alice_credential, alice_signer) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
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

    // save the storage state
    let state_before = GroupStorageState::from_storage(alice_provider.storage(), &group_id);

    // TODO: is there a way to create this using the public API?
    let reinit_proposal = todo!();

    alice_group
        .commit_builder()
        .add_proposal(Proposal::ReInit(reinit_proposal))
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signer,
            |_| true,
        )
        .unwrap();
    // === Delivery service rejected the commit ===

    //ANCHOR: discard_commit_reinit
    // Discard the commit
    alice_group
        .clear_pending_commit(alice_provider.storage())
        .expect("Could not clear pending commit");
    //ANCHOR_END: discard_commit_reinit

    // also delete the proposals so the state can be compared to the previous state
    alice_group
        .clear_pending_proposals(alice_provider.storage())
        .expect("Could not clear pending proposals");

    let state_after = GroupStorageState::from_storage(alice_provider.storage(), &group_id);
    assert!(state_before == state_after);
}
*/

#[openmls_test]
fn discard_commit_external_join() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credentials with keys
    let (alice_credential, alice_signer) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let (bob_credential, bob_signer) = generate_credential(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        group_id.clone(),
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    // export the group info so Bob can join
    let group_info_msg_out = alice_group
        .export_group_info(
            alice_provider,
            &alice_signer,
            true, // with ratchet tree
        )
        .expect("Could not export group info");
    let group_info_msg_in: MlsMessageIn = group_info_msg_out.into();

    let verifiable_group_info = match group_info_msg_in.extract() {
        MlsMessageBodyIn::GroupInfo(info) => info,
        _ => unimplemented!(),
    };

    // save the storage state
    let bob_state_before = GroupStorageState::from_storage(bob_provider.storage(), &group_id);

    let aad = vec![0; 32];

    let (mut bob_group, _message, _group_info) = MlsGroup::join_by_external_commit(
        bob_provider,
        &bob_signer,
        None,
        verifiable_group_info,
        &MlsGroupJoinConfig::default(),
        None,
        None,
        &aad,
        bob_credential,
    )
    .expect("could not create external join commit");

    // === Delivery service rejected the commit ===

    //ANCHOR: discard_commit_external_join
    // delete the `MlsGroup`
    bob_group
        .delete(bob_provider.storage())
        .expect("Could not delete the group");
    //ANCHOR_END: discard_commit_external_join

    let bob_state_after = GroupStorageState::from_storage(bob_provider.storage(), &group_id);
    assert!(bob_state_before == bob_state_after);
}

#[openmls_test]
fn discard_commit_group_context_extensions() {
    let alice_provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credentials with keys
    let (alice_credential, alice_signer) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let unknown_extension_type = 1;

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
        .capabilities(Capabilities::new(
            None,
            None,
            Some(&[ExtensionType::Unknown(unknown_extension_type)]),
            None,
            None,
        ))
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

    // save the storage state
    let state_before = GroupStorageState::from_storage(alice_provider.storage(), &group_id);

    let extensions = Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(unknown_extension_type)],
            &[],
            &[],
        )),
        Extension::Unknown(unknown_extension_type, UnknownExtension(Vec::new())),
    ])
    .unwrap();

    let (_message, _proposal_ref) = alice_group
        .propose_group_context_extensions(alice_provider, extensions, &alice_signer)
        .expect("Could not propose group context extensions");

    let (_commit, _welcome, _group_info) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_signer)
        .unwrap();

    // === Delivery service rejected the commit ===

    //ANCHOR: discard_commit_group_context_extensions
    // Discard the commit
    alice_group
        .clear_pending_commit(alice_provider.storage())
        .expect("Could not clear pending commit");
    //ANCHOR_END: discard_commit_group_context_extensions

    // also delete the proposals so the state can be compared to the previous state
    alice_group
        .clear_pending_proposals(alice_provider.storage())
        .expect("Could not clear pending proposals");

    let state_after = GroupStorageState::from_storage(alice_provider.storage(), &group_id);
    assert!(state_before == state_after);
}

#[openmls_test]
fn discard_commit_self_remove() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credentials with keys
    let (alice_credential, alice_signer) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let (bob_credential, bob_signer) = generate_credential(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );
    // Create a new KeyPackageBundle for Bob
    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential,
        Extensions::default(),
        bob_provider,
        &bob_signer,
    );

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
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
    let (_mls_message_out, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Could not add members.");

    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let staged_join = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        None,
    )
    .expect("Error constructing staged join");
    let mut bob_group = staged_join
        .into_group(bob_provider)
        .expect("Error joining group from StagedWelcome");

    // save the storage state
    let state_before = GroupStorageState::from_storage(bob_provider.storage(), &group_id);

    // Bob removes self

    let _mls_message_out = bob_group
        .leave_group_via_self_remove(bob_provider, &bob_signer)
        .expect("Error leaving group via self remove");

    // === Delivery service rejected the commit ===

    // Discard the commit
    bob_group
        .clear_pending_commit(bob_provider.storage())
        .expect("Could not clear pending commit");

    // also delete the proposals so the state can be compared to the previous state
    bob_group
        .clear_pending_proposals(bob_provider.storage())
        .expect("Could not clear pending proposals");

    let state_after = GroupStorageState::from_storage(bob_provider.storage(), &group_id);
    assert!(state_before == state_after);
}

/*
#[openmls_test]
fn discard_commit_app_ack() {

    // TODO: AppAck proposal not supported yet
}
*/

#[openmls_test]
fn discard_commit_custom_proposal() {
    let alice_provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credentials with keys
    let (alice_credential, alice_signer) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let custom_proposal_type = 0;

    let capabilities = Capabilities::new(
        None,
        None,
        None,
        Some(&[ProposalType::Custom(custom_proposal_type)]),
        None,
    );

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::builder()
        .with_capabilities(capabilities.clone())
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential.clone())
        .expect("An unexpected error occurred.");

    // save the storage state
    let state_before = GroupStorageState::from_storage(alice_provider.storage(), &group_id);

    let payload = vec![0; 100];
    let custom_proposal = CustomProposal::new(custom_proposal_type, payload);

    let (_mls_msg_out, _proposal_ref) = alice_group
        .propose_custom_proposal_by_value(alice_provider, &alice_signer, custom_proposal)
        .expect("could not propose custom proposal");

    assert_eq!(alice_group.pending_proposals().count(), 1);

    let (_commit, _welcome, _group_info) = alice_group
        .commit_to_pending_proposals(alice_provider, &alice_signer)
        .unwrap();

    // === Delivery service rejected the commit ===

    alice_group
        .clear_pending_commit(alice_provider.storage())
        .expect("Could not clear pending commit");

    let state_after = GroupStorageState::from_storage(alice_provider.storage(), &group_id);
    assert!(state_before == state_after);
}
