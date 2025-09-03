use openmls::{
    prelude::*,
    schedule::psk::*,
    test_utils::{single_group_test_framework::*, storage_state::GroupStorageState},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use openmls_traits::types::SignatureScheme;

fn generate_credential(
    identity: Vec<u8>,
    signature_algorithm: SignatureScheme,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity);
    let signature_keys = SignatureKeyPair::new(signature_algorithm).unwrap();

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        },
        signature_keys,
    )
}

// Utility function for checking commit
fn clear_pending_commit_and_assert_storage_state<Provider: OpenMlsProvider>(
    member_state: &mut MemberState<'_, Provider>,
    state_before: GroupStorageState,
) {
    member_state
        .group
        .clear_pending_commit(member_state.party.core_state.provider.storage())
        .expect("Could not clear pending commit");

    member_state.assert_non_proposal_group_storage_state_matches(state_before);
}

fn alice_group<Provider: OpenMlsProvider>(
    alice_party: &CorePartyState<Provider>,
    ciphersuite: Ciphersuite,
    create_config: MlsGroupCreateConfig,
) -> GroupState<'_, Provider> {
    let group_id = GroupId::from_slice(b"Test Group");

    let group_state = GroupState::new_from_party(
        group_id,
        alice_party.generate_pre_group(ciphersuite),
        create_config,
    )
    .unwrap();
    group_state
}

fn alice_bob_group<'a, Provider: OpenMlsProvider>(
    alice_party: &'a CorePartyState<Provider>,
    bob_party: &'a CorePartyState<Provider>,
    ciphersuite: Ciphersuite,
    create_config: MlsGroupCreateConfig,
) -> GroupState<'a, Provider> {
    let join_config = create_config.join_config().clone();
    let mut group_state = alice_group(alice_party, ciphersuite, create_config);

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_party.generate_pre_group(ciphersuite)],
            join_config,
            tree: None,
        })
        .expect("Could not add member");

    group_state
}

#[openmls_test]
fn discard_commit_add() {
    let alice_party = CorePartyState::<Provider>::new("alice");

    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let mut group_state = alice_group(&alice_party, ciphersuite, create_config);

    let bob_party = CorePartyState::<Provider>::new("bob");
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    let bob_key_package = bob_pre_group.key_package_bundle.key_package().clone();

    let [alice] = group_state.members_mut(&["alice"]);
    let state_before = alice.group_storage_state();
    let alice_group = &mut alice.group;
    let alice_provider = &alice_party.provider;
    let alice_signer = &alice.party.signer;

    // === Alice adds Bob ===
    let (_mls_message_out, _welcome, _group_info) = alice_group
        .add_members(alice_provider, alice_signer, &[bob_key_package])
        .expect("Could not add members.");

    assert_ne!(
        alice_provider
            .storage()
            .group_state(alice_group.group_id())
            .unwrap(),
        Some(MlsGroupState::Operational)
    );

    // === Commit rejected by delivery service ===
    // Will need to clean up

    assert_eq!(alice_group.members().count(), 1);
    //ANCHOR: discard_commit_example
    // clear pending commit and reset state
    alice_group
        .clear_pending_commit(alice_provider.storage())
        .unwrap();
    //ANCHOR_END: discard_commit_example
    alice.assert_non_proposal_group_storage_state_matches(state_before);
}

#[openmls_test]
fn discard_commit_update_with_new_signer() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);

    // Set up a group with one member (Alice)
    let mut group_state = alice_group(&alice_party, ciphersuite, create_config);
    let group_id = group_state.group_id();

    let [alice] = group_state.members_mut(&["alice"]);
    let alice_provider = &alice_party.provider;
    let alice_credential = &alice.party.credential_with_key;

    // === Alice new credential ===
    let new_credential = BasicCredential::new("alice2".into());
    let new_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let new_credential = CredentialWithKey {
        credential: new_credential.into(),
        signature_key: new_signer.to_public_vec().into(),
    };

    // Check alice credential
    let own_leaf_node_before = alice.group.own_leaf_node().unwrap().clone();
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

    // save the storage state for comparison later
    let state_before = alice.group_storage_state();

    let old_signer = &alice.party.signer;

    // check that alice signer was stored
    assert!(alice.get_storage_signature_key_pair().is_some());

    let alice_group = &mut alice.group;
    let alice_provider = &alice_party.provider;

    // === Alice updates ===
    // Alice updates own credential
    // HPKE encryption key is also updated by the commit

    let signer_bundle = NewSignerBundle {
        signer: &new_signer,
        credential_with_key: new_credential,
    };
    let _commit_message_bundle = alice_group
        .self_update_with_new_signer(
            alice_provider,
            old_signer,
            signer_bundle,
            LeafNodeParameters::default(),
        )
        .expect("failed to update own leaf node");

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

    // assert that the new signer is not in the StorageProvider yet
    assert!(SignatureKeyPair::read(
        alice_provider.storage(),
        new_signer.public(),
        ciphersuite.signature_algorithm(),
    )
    .is_none());

    // === Commit rejected by delivery service ===

    // clear pending commit and reset state
    alice_group
        .clear_pending_commit(alice_provider.storage())
        .unwrap();

    // check that alice signer still stored
    let alice_stored_signer = alice
        .get_storage_signature_key_pair()
        .expect("should still be stored");

    // check that the stored signer's public key is the old signer's public key
    assert_eq!(alice_stored_signer.public(), old_signer.public());
    // check that the stored signer's public key is not the old signer's public key
    assert_ne!(alice_stored_signer.public(), new_signer.public());

    // assert that the new signer is not in the StorageProvider (does not need to be cleaned up)
    assert!(SignatureKeyPair::read(
        alice_provider.storage(),
        new_signer.public(),
        ciphersuite.signature_algorithm(),
    )
    .is_none());

    // check that own leaf node in storage does not contain wrong credential
    let own_leaf_nodes_before: Vec<LeafNode> = alice_provider
        .storage()
        .own_leaf_nodes(&group_id)
        .expect("could not get leaf nodes");
    assert_eq!(own_leaf_nodes_before.len(), 0);

    alice.assert_group_storage_state_matches(state_before);
}

#[openmls_test]
fn discard_commit_remove() {
    // set up group with two members
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let mut group_state = alice_bob_group(&alice_party, &bob_party, ciphersuite, create_config);

    let [bob] = group_state.members_mut(&["bob"]);

    // save the storage state
    let state_before = bob.group_storage_state();

    let bob_group = &mut bob.group;
    let bob_provider: &Provider = &bob.party.core_state.provider;
    let bob_signer: &SignatureKeyPair = &bob.party.signer;

    // Bob removes Alice

    let alice_member = bob_group
        .members()
        .find(
            |Member {
                 index: _,
                 credential,
                 ..
             }| { credential.serialized_content() == b"alice" },
        )
        .expect("Couldn't find Alice in the list of group members.");

    let alice_leaf_node_index = alice_member.index;
    let (_mls_message_out, _welcome, _group_info) = bob_group
        .remove_members(bob_provider, bob_signer, &[alice_leaf_node_index])
        .expect("Could not remove Alice");

    // === Delivery service rejected the commit ===

    clear_pending_commit_and_assert_storage_state(bob, state_before);
}

#[openmls_test]
fn discard_commit_psk() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let mut group_state = alice_group(&alice_party, ciphersuite, create_config);

    let [alice] = group_state.members_mut(&["alice"]);
    let state_before = alice.group_storage_state();

    let alice_group = &mut alice.group;
    let alice_provider = &alice_party.provider;
    let alice_signer = &alice.party.signer;

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
        .propose_external_psk(alice_provider, alice_signer, psk_id)
        .expect("Could not propose adding an external psk");

    assert_eq!(alice_group.pending_proposals().count(), 1);

    let (_commit, _welcome, _group_info) = alice_group
        .commit_to_pending_proposals(alice_provider, alice_signer)
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

    alice.assert_non_proposal_group_storage_state_matches(state_before);
}

#[openmls_test]
fn discard_commit_external_join() {
    let bob_provider = &Provider::default();
    let (bob_credential, bob_signer) =
        generate_credential("bob".into(), ciphersuite.signature_algorithm());

    let group_id = GroupId::from_slice(b"Test Group");

    let alice_party = CorePartyState::<Provider>::new("alice");
    let create_config = MlsGroupCreateConfig::test_default_from_ciphersuite(ciphersuite);
    let mut group_state = alice_group(&alice_party, ciphersuite, create_config);

    let [alice] = group_state.members_mut(&["alice"]);

    let alice_group = &mut alice.group;
    let alice_provider = &alice_party.provider;
    let alice_signer = &alice.party.signer;

    // export the group info so Bob can join
    let group_info_msg_out = alice_group
        .export_group_info(
            alice_provider.crypto(),
            alice_signer,
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

    let (mut bob_group, _bundle) = MlsGroup::external_commit_builder()
        .with_aad(aad)
        .build_group(bob_provider, verifiable_group_info, bob_credential)
        .unwrap()
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_signer,
            |_| true,
        )
        .unwrap()
        .finalize(bob_provider)
        .unwrap();

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
    // set up group with one member

    let alice_party = CorePartyState::<Provider>::new("alice");
    let mut group_state = alice_group(&alice_party, ciphersuite, mls_group_create_config);

    let [alice] = group_state.members_mut(&["alice"]);
    // save the storage state
    let state_before = alice.group_storage_state();

    let alice_group = &mut alice.group;
    let alice_provider = &alice_party.provider;
    let alice_signer = &alice.party.signer;

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
        .propose_group_context_extensions(alice_provider, extensions, alice_signer)
        .expect("Could not propose group context extensions");

    let (_commit, _welcome, _group_info) = alice_group
        .commit_to_pending_proposals(alice_provider, alice_signer)
        .unwrap();

    // === Delivery service rejected the commit ===

    clear_pending_commit_and_assert_storage_state(alice, state_before);
}

#[openmls_test]
fn discard_commit_custom_proposal() {
    let alice_provider = &Provider::default();

    let group_id = GroupId::from_slice(b"Test Group");
    // Generate credentials with keys
    let (alice_credential, alice_signer) =
        generate_credential("alice".into(), ciphersuite.signature_algorithm());

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
