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

use std::collections::HashMap;
type Identity = &'static str;

// This is a sketch of additional test suite functionality
// TODO: move to separate file or combine with existing test framework
pub(crate) struct TestingGroups<Provider: OpenMlsProvider + Default> {
    // data for all groups
    group_id: GroupId,
    create_config: MlsGroupCreateConfig, // TODO: revisit
    // map credentials to (StorageProvider, MlsGroup)
    // store separately for borrowing reasons
    groups: HashMap<Identity, MlsGroup>,
    providers: HashMap<Identity, Provider>,
    signers: HashMap<Identity, SignatureKeyPair>,
    state: TestingGroupsState,
}

#[derive(Debug)]
enum TestingGroupsState {
    Ready,
    PendingWelcomeFor {
        identity: Identity,
        sender: Identity,
        welcome: MlsMessageOut,
        commit: MlsMessageOut,
    },
    ReadyToApplyCommit {
        commit: MlsMessageOut,
        sender: Identity,
        welcome_receiver: Option<Identity>,
    },
}

impl<Provider: OpenMlsProvider + Default> TestingGroups<Provider> {
    pub(crate) fn add_member(&mut self, adder: Identity, to_add: Identity) {
        self.stage_commit_add_member(adder, to_add);
        self.apply_welcome(None);
        self.apply_sent_commit();
    }
    pub(crate) fn stage_commit_add_member(
        &mut self,
        adder: Identity,
        to_add: Identity,
        //TODO: more config, e.g. Option<KeyPackage>
    ) {
        let ciphersuite = self.create_config.ciphersuite();
        let to_add_provider = Provider::default();

        // Generate credentials with keys
        let (credential, to_add_signer) = generate_credential(
            to_add.into(),
            ciphersuite.signature_algorithm(),
            &to_add_provider,
        );

        // Generate KeyPackages
        let key_package = generate_key_package(
            ciphersuite,
            credential.clone(),
            Extensions::default(),
            &to_add_provider,
            &to_add_signer,
        );

        let adder_group = self.groups.get_mut(&adder).unwrap();
        let adder_provider = self.providers.get_mut(&adder).unwrap();
        let adder_signer = self.signers.get_mut(&adder).unwrap();

        let (commit, welcome, _group_info) = adder_group
            .add_members(
                adder_provider,
                adder_signer,
                &[key_package.key_package().clone()],
            )
            .expect("Could not add members.");

        // keep track of new member info
        self.providers.insert(to_add, to_add_provider);
        self.signers.insert(to_add, to_add_signer);

        self.state = TestingGroupsState::PendingWelcomeFor {
            identity: to_add,
            sender: adder,
            welcome,
            commit: commit.clone(),
        };
    }
    pub(crate) fn apply_welcome(&mut self, join_config: Option<MlsGroupJoinConfig>) {
        if let TestingGroupsState::PendingWelcomeFor {
            identity,
            sender,
            welcome,
            commit,
        } = &self.state
        {
            assert!(self.signers.contains_key(identity));
            assert!(!self.groups.contains_key(identity));

            let provider = self.providers.get(identity).unwrap();

            let welcome: MlsMessageIn = welcome.clone().into();
            let welcome = welcome
                .into_welcome()
                .expect("expected the message to be a welcome message");

            let staged_join = StagedWelcome::new_from_welcome(
                provider,
                &join_config.unwrap_or_default(),
                welcome,
                None,
            )
            .expect("Error constructing staged join");
            let group = staged_join
                .into_group(provider)
                .expect("Error joining group from StagedWelcome");

            self.groups.insert(identity, group);

            // update state
            self.state = TestingGroupsState::ReadyToApplyCommit {
                sender,
                welcome_receiver: Some(identity),
                commit: commit.clone(),
            };
        } else {
            panic!("Cannot apply Welcome: no Welcome sent");
        }
    }
    pub(crate) fn apply_sent_commit(&mut self) {
        if let TestingGroupsState::ReadyToApplyCommit {
            sender,
            welcome_receiver,
            commit,
        } = &self.state
        {
            for (member_identity, group) in self.groups.iter_mut() {
                match (welcome_receiver, member_identity) {
                    (Some(identity), member_identity) if identity == member_identity => {}
                    (_, member_identity) if member_identity == sender => {
                        let provider = self.providers.get(member_identity).unwrap();
                        group.merge_pending_commit(provider).unwrap();
                    }
                    (_, member_identity) => {
                        //apply the commit
                        let provider = self.providers.get(member_identity).unwrap();

                        let processed_message = group
                            .process_message(
                                provider,
                                commit.clone().into_protocol_message().unwrap(),
                            )
                            .unwrap();

                        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                            processed_message.into_content()
                        {
                            group.merge_staged_commit(provider, *staged_commit).unwrap();
                        } else {
                            panic!("Message is incorrect");
                        }
                    }
                }
            }
        } else {
            panic!("No commit sent");
        }

        self.state = TestingGroupsState::Ready;
    }
    pub(crate) fn single_from_identity(
        group_id: GroupId,
        identity: Identity,
        create_config: MlsGroupCreateConfig,
    ) -> Self {
        let mut groups = HashMap::new();
        let mut providers = HashMap::new();
        let mut signers = HashMap::new();

        let provider = Provider::default();

        let ciphersuite = create_config.ciphersuite();

        // Generate credentials with keys
        let (credential, signer) = generate_credential(
            identity.into(),
            ciphersuite.signature_algorithm(),
            &provider,
        );

        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &create_config,
            group_id.clone(),
            credential.clone(),
        )
        .expect("An unexpected error occurred.");

        groups.insert(identity, group);
        providers.insert(identity, provider);
        signers.insert(identity, signer);

        Self {
            group_id,
            groups,
            providers,
            signers,
            create_config,
            state: TestingGroupsState::Ready,
        }
    }
    pub(crate) fn get_group_storage_state(&self, identity: Identity) -> GroupStorageState {
        let provider = self.providers.get(&identity).unwrap();

        GroupStorageState::from_storage(provider.storage(), &self.group_id)
    }
}

#[openmls_test]
fn discard_commit_add() {
    let group_id = GroupId::from_slice(b"Test Group");

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
        .build();

    let mut testing_groups =
        TestingGroups::single_from_identity(group_id.clone(), "Alice", mls_group_create_config);

    let state_before = testing_groups.get_group_storage_state("Alice");

    let alice_group = testing_groups.groups.get_mut("Alice").unwrap();
    let alice_provider: &Provider = testing_groups.providers.get("Alice").unwrap();
    let alice_signature_keys = testing_groups.signers.get("Alice").unwrap();

    let bob_provider = &Provider::default();

    let (bob_credential, bob_signature_keys) = generate_credential(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    // Generate KeyPackages
    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential.clone(),
        Extensions::default(),
        bob_provider,
        &bob_signature_keys,
    );

    // === Alice adds Bob ===
    //ANCHOR: discard_commit_add_setup
    let (_mls_message_out, _welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            alice_signature_keys,
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
    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
        .build();
    let group_id = GroupId::from_slice(b"Test Group");

    // set up group with two members
    let mut groups =
        TestingGroups::single_from_identity(group_id, "Alice", mls_group_create_config);
    groups.add_member("Alice", "Bob");

    // save the storage state
    let state_before = groups.get_group_storage_state("Bob");

    let bob_group = groups.groups.get_mut("Bob").unwrap();
    let bob_provider: &Provider = groups.providers.get("Bob").unwrap();
    let bob_signer: &SignatureKeyPair = groups.signers.get("Bob").unwrap();

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
        .remove_members(bob_provider, bob_signer, &[alice_leaf_node_index])
        .expect("Could not remove Alice");

    // === Delivery service rejected the commit ===

    // Discard the commit
    //ANCHOR: discard_commit_remove
    bob_group
        .clear_pending_commit(bob_provider.storage())
        .expect("Could not clear pending commit");
    //ANCHOR_END: discard_commit_remove

    let state_after = groups.get_group_storage_state("Bob");
    assert!(state_before == state_after);
}

#[openmls_test]
fn discard_commit_psk() {
    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
        .build();
    let group_id = GroupId::from_slice(b"Test Group");

    // set up group with two members
    let mut testing_groups =
        TestingGroups::single_from_identity(group_id, "Alice", mls_group_create_config);

    let alice_provider: &Provider = testing_groups.providers.get("Alice").unwrap();
    let alice_signer = testing_groups.signers.get("Alice").unwrap();

    let state_before = testing_groups.get_group_storage_state("Alice");

    let psk_bytes = vec![1; 32];
    let psk = Psk::External(ExternalPsk::new(psk_bytes.clone()));
    let psk_id = PreSharedKeyId::new(ciphersuite, alice_provider.rand(), psk.clone()).unwrap();

    let alice_group = testing_groups.groups.get_mut("Alice").unwrap();
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

    let state_after = testing_groups.get_group_storage_state("Alice");
    assert!(state_before.non_proposal_state == state_after.non_proposal_state);
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

    let state_after = GroupStorageState::from_storage(alice_provider.storage(), &group_id);
    assert!(state_before.non_proposal_state == state_after.non_proposal_state);
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

    let state_after = GroupStorageState::from_storage(alice_provider.storage(), &group_id);
    assert!(state_before.non_proposal_state == state_after.non_proposal_state);
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

    let state_after = GroupStorageState::from_storage(bob_provider.storage(), &group_id);
    assert!(state_before.non_proposal_state == state_after.non_proposal_state);
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
