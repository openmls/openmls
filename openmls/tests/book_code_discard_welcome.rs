use openmls::{
    prelude::*, test_utils::single_group_test_framework::*,
    test_utils::storage_state::GroupStorageState, *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use openmls_traits::{signatures::Signer, types::SignatureScheme};

#[allow(dead_code)]
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

#[allow(dead_code)]
fn generate_key_package(
    ciphersuite: Ciphersuite,
    credential_with_key: CredentialWithKey,
    extensions: Extensions<KeyPackage>,
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
fn not_join_group() {
    // Set up Alice group
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);

    let group_id = GroupId::from_slice(b"Test Group");

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true) // NOTE: important
        .build();

    let mut group_state =
        GroupState::new_from_party(group_id.clone(), alice_pre_group, mls_group_create_config)
            .unwrap();
    // Generate KeyPackages
    let bob_key_package = bob_pre_group.key_package_bundle.key_package().clone();

    let [alice] = group_state.members_mut(&["alice"]);

    // === Alice adds Bob ===
    let (_commit, welcome, _group_info) = alice
        .group
        .add_members(
            &alice_party.provider,
            &alice.party.signer,
            &[bob_key_package],
        )
        .expect("Could not add Bob");

    let welcome: MlsMessageIn = welcome.into();

    let bob_provider = &bob_party.provider;

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

    //ANCHOR: not_join_group_processed_welcome
    let join_config = MlsGroupJoinConfig::default();
    // This deletes the keys used to decrypt the welcome, except if it is a last resort key
    // package.
    let processed_welcome = ProcessedWelcome::new_from_welcome(bob_provider, &join_config, welcome)
        .expect("Error constructing processed welcome");
    //ANCHOR_END: not_join_group_processed_welcome

    //ANCHOR: not_join_group_processed_welcome_inspect
    // unverified pre-shared keys (`&[PreSharedKeyId]`)
    let _unverified_psks = processed_welcome.psks();

    // unverified group info (`VerifiableGroupInfo`)
    let unverified_group_info = processed_welcome.unverified_group_info();

    // From the unverified group info, the ciphersuite, group_id, and other information
    // can be retrieved.
    let _ciphersuite = unverified_group_info.ciphersuite();
    let _group_id = unverified_group_info.group_id();
    let _epoch = unverified_group_info.epoch();

    // Can also retrieve any available extensions
    let extensions = unverified_group_info.extensions();

    // Retrieving the ratchet tree extension
    let ratchet_tree_extension = extensions
        .ratchet_tree()
        .expect("No ratchet tree extension");
    // The (unverified) ratchet tree itself can also be inspected
    let _ratchet_tree = ratchet_tree_extension.ratchet_tree();
    //ANCHOR_END: not_join_group_processed_welcome_inspect

    //ANCHOR: not_join_group_staged_welcome
    let staged_welcome: StagedWelcome = processed_welcome
        .into_staged_welcome(bob_provider, None)
        .expect("Error constructing staged welcome");
    //ANCHOR_END: not_join_group_staged_welcome

    // check storage state after staging welcome
    let own_leaf_nodes: Vec<LeafNode> = bob_provider.storage().own_leaf_nodes(&group_id).unwrap();
    assert!(own_leaf_nodes.is_empty());

    let own_leaf_index: Option<LeafNodeIndex> =
        bob_provider.storage().own_leaf_index(&group_id).unwrap();

    assert!(own_leaf_index.is_none());

    //ANCHOR: not_join_group_welcome_sender
    let welcome_sender: &LeafNode = staged_welcome
        .welcome_sender()
        .expect("Welcome sender could not be retrieved");

    // Inspect sender's credential...
    let _credential = welcome_sender.credential();
    // Inspect sender's signature public key...
    let _signature_key = welcome_sender.signature_key();
    //ANCHOR_END: not_join_group_welcome_sender

    //ANCHOR: not_join_group_group_context
    // Inspect group context...
    let group_context = staged_welcome.group_context();

    // inspect protocol version...
    let _protocol_version = group_context.protocol_version();
    // Inspect ciphersuite...
    let _ciphersuite = group_context.ciphersuite();
    // Inspect extensions...
    let extensions: &Extensions<GroupContext> = group_context.extensions();

    // Can check which extensions are enabled
    let _has_ratchet_extension = extensions.ratchet_tree().is_some();

    // Inspect required capabilities...
    if let Some(capabilities) = group_context.required_capabilities() {
        // Inspect required extension types...
        let _extension_types: &[ExtensionType] = capabilities.extension_types();
        // Inspect required proposal types...
        let _proposal_types: &[ProposalType] = capabilities.proposal_types();
        // Inspect required credential types...
        let _credential_types: &[CredentialType] = capabilities.credential_types();
    }
    // Additional information from the `GroupContext`
    let _group_id = group_context.group_id();
    let _epoch = group_context.epoch();
    let _tree_hash = group_context.tree_hash();
    let _confirmed_transcript_hash = group_context.confirmed_transcript_hash();

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

    let state_after = GroupStorageState::from_storage(bob_provider.storage(), &group_id);
    assert!(state_before == state_after);
}
