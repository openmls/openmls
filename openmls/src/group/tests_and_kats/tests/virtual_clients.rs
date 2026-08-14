use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{
    signatures::Signer, storage::StorageProvider as _, types::Ciphersuite, OpenMlsProvider,
};
use tls_codec::Serialize as _;

use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    ciphersuite::Secret,
    component::{ComponentId, ComponentType, ComponentsList},
    components::{
        vc_commit_data::{VcEpochUsage, VirtualClientAction, VirtualClientCommitData},
        vc_derivation_info::{
            load_vc_epoch_state_and_tree, register_vc_derivation_epoch, EpochId,
            RegisteredVcDerivationEpoch, VcDerivationEpochParams, VcDerivationEpochState,
            VcEmulationBindings, VirtualClientOperationType, VC_COMPONENT_ID,
        },
        vc_retention::VcEpochRefs,
    },
    credentials::test_utils::new_credential,
    extensions::{
        AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType, Extensions,
    },
    framing::{MlsMessageIn, ProcessedMessageContent},
    group::{
        GroupContext, GroupEpoch, GroupId, MlsGroup, MlsGroupCreateConfig,
        MlsGroupCreateConfigBuilder, StagedWelcome, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    key_packages::KeyPackage,
    messages::PathSecret,
    prelude::{Capabilities, LeafNode, LeafNodeParameters},
    schedule::application_export_tree::{ApplicationExportTree, ApplicationExportTreeError},
};

/// Emulation group suite. Its KDF hash (SHA-384) differs from the
/// higher-level group's (SHA-256), so a derivation that skips the import into
/// the target ciphersuite, or imports under the wrong one, silently produces
/// different bytes rather than erroring out -- which is exactly what these
/// tests detect.
const EMULATION_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519;
/// Higher-level group suite: the target ciphersuite of the derivations under
/// test.
const GROUP_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// `Capabilities` declaring `AppDataDictionary` support.
fn vc_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::AppDataDictionary])
        .build()
}

/// The `AppDataDictionary` leaf-node extension a VC-sending leaf must carry:
/// an `AppComponents` entry listing `VC_COMPONENT_ID`.
fn vc_leaf_extensions() -> Extensions<LeafNode> {
    let supported_components: Vec<u16> = vec![VC_COMPONENT_ID];
    let app_components_body = supported_components
        .tls_serialize_detached()
        .expect("serialize AppComponents body");
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(
        ComponentId::from(ComponentType::AppComponents),
        app_components_body,
    );
    let ext = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
    Extensions::from_vec(vec![ext]).expect("build leaf-node Extensions")
}

fn vc_config_builder(ciphersuite: Ciphersuite) -> MlsGroupCreateConfigBuilder {
    MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
}

fn vc_group_config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
    vc_config_builder(ciphersuite).build()
}

/// Like [`vc_group_config`], but marking the group as an emulation group, so
/// derivation epochs are registered implicitly.
fn emulation_group_config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
    vc_config_builder(ciphersuite).emulation_group(true).build()
}

/// A full-size, unpunctured export tree seeded with `fill` repeated over the
/// ciphersuite's hash length. Two trees built with the same `fill` derive the
/// same secrets, which is what a retried Welcome join rebuilds.
fn fresh_export_tree(ciphersuite: Ciphersuite, fill: u8) -> ApplicationExportTree {
    ApplicationExportTree::new_with_size(
        Secret::from_slice(&vec![fill; ciphersuite.hash_length()]),
        TreeSize::from_leaf_count(u16::MAX as u32),
    )
}

/// Found a single-member emulation group on `provider`. Creating it registers
/// the initial epoch as a derivation epoch. Returns the group alongside the
/// [`EpochId`] the tests derive their reference values from.
fn registered_derivation_epoch<P: OpenMlsProvider>(provider: &P) -> (MlsGroup, EpochId) {
    let (credential, signer) = new_credential(
        provider,
        b"Emulator",
        EMULATION_CIPHERSUITE.signature_algorithm(),
    );
    let emulator_group = MlsGroup::new(
        provider,
        &signer,
        &emulation_group_config(EMULATION_CIPHERSUITE),
        credential,
    )
    .expect("create emulation group");
    let epoch_id = emulator_group
        .newest_vc_derivation_epoch(provider.storage())
        .expect("read newest derivation epoch")
        .expect("group creation registers a derivation epoch");
    (emulator_group, epoch_id)
}

/// A VC commit's update-path material (the leaf encryption key and the
/// `path_secret` for the first parent node) must derive from the
/// `target_operation_secret`: the `leaf_node` operation secret imported into
/// the higher-level group's ciphersuite, with that ciphersuite and the
/// group's id bound into the import context.
#[openmls_test::openmls_test]
fn vc_commit_path_material_imports_into_group_ciphersuite() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (emulator_group, epoch_id) = registered_derivation_epoch(provider);

    // Higher-level group: the VC leaf plus one regular member, so the VC
    // commit's update path contains a parent node.
    let (alice_credential, alice_signer) = new_credential(
        provider,
        b"Alice (VC)",
        GROUP_CIPHERSUITE.signature_algorithm(),
    );
    let mut main_group = MlsGroup::new(
        provider,
        &alice_signer,
        &vc_group_config(GROUP_CIPHERSUITE),
        alice_credential,
    )
    .expect("create main group");

    let (bob_credential, bob_signer) = new_credential(
        bob_provider,
        b"Bob",
        GROUP_CIPHERSUITE.signature_algorithm(),
    );
    let bob_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(GROUP_CIPHERSUITE, bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    main_group
        .add_members(provider, &alice_signer, &[bob_key_package])
        .expect("add bob");
    main_group
        .merge_pending_commit(provider)
        .expect("merge add");

    // Reference derivation per spec, from a scratch copy of the operation
    // tree. The scratch copy advances in memory only and is dropped without
    // being persisted, so the commit below consumes the same generation.
    let (state, mut scratch_tree) =
        load_vc_epoch_state_and_tree(provider, &epoch_id).expect("load vc epoch state");
    let (emulation_leaf_index, _epoch_encryption_key, emulation_ciphersuite) = state.into_parts();
    assert_eq!(emulation_ciphersuite, EMULATION_CIPHERSUITE);
    let (generation, operation_secret) = scratch_tree
        .next_operation_secret(
            provider.crypto(),
            EMULATION_CIPHERSUITE,
            &epoch_id,
            emulation_leaf_index,
            VirtualClientOperationType::LeafNode,
            main_group.group_id().as_slice(),
        )
        .expect("derive reference operation secret");
    assert_eq!(generation, 0);
    drop(scratch_tree);

    let target_operation_secret = operation_secret
        .derive_target_operation_secret(provider.crypto(), GROUP_CIPHERSUITE, main_group.group_id())
        .expect("derive reference target operation secret");
    let expected_leaf_keypair = target_operation_secret
        .derive_encryption_key_secret(provider.crypto(), GROUP_CIPHERSUITE)
        .expect("derive reference encryption key secret")
        .generate_encryption_key_pair(provider.crypto(), GROUP_CIPHERSUITE)
        .expect("generate reference leaf keypair");
    let expected_parent_keypair = PathSecret::from(
        target_operation_secret
            .derive_path_generation_secret(provider.crypto(), GROUP_CIPHERSUITE)
            .expect("derive reference path generation secret"),
    )
    .derive_key_pair(provider.crypto(), GROUP_CIPHERSUITE)
    .expect("derive reference parent keypair");

    // Actual: send the VC commit.
    main_group
        .commit_builder()
        .vc_emulation(
            provider.crypto(),
            provider.storage(),
            emulator_group.group_id(),
        )
        .expect("vc_emulation")
        .load_psks(provider.storage())
        .expect("load psks")
        .build(provider.rand(), provider.crypto(), &alice_signer, |_| true)
        .expect("build vc commit")
        .stage_commit(provider)
        .expect("stage vc commit");
    main_group
        .merge_pending_commit(provider)
        .expect("merge vc commit");

    assert_eq!(
        main_group
            .own_leaf_node()
            .expect("own leaf")
            .encryption_key(),
        expected_leaf_keypair.public_key(),
        "the leaf encryption key secret must derive from the operation \
         secret imported into the group's ciphersuite"
    );
    let ratchet_tree = main_group.export_ratchet_tree();
    let root = ratchet_tree.parents().next().expect("one parent node");
    assert_eq!(
        root.encryption_key(),
        expected_parent_keypair.public_key(),
        "the path generation secret must derive from the operation secret \
         imported into the group's ciphersuite"
    );
}

/// The creator leaf of a VC-created group derives its encryption key from
/// the per-KeyPackage seed (dedicated `key_package` operation, index 0),
/// imported into the created group's ciphersuite. The encryption key secret
/// and the "Group Creation" epoch secret both derive from that seed under
/// the created group's ciphersuite.
#[openmls_test::openmls_test]
fn vc_group_creation_leaf_key_imports_into_group_ciphersuite() {
    let provider = &Provider::default();

    let (emulator_group, epoch_id) = registered_derivation_epoch(provider);

    // Reference derivation per spec, from a scratch copy of the operation
    // tree (dropped unpersisted, so the builder consumes the same
    // generation).
    let (state, mut scratch_tree) =
        load_vc_epoch_state_and_tree(provider, &epoch_id).expect("load vc epoch state");
    let (emulation_leaf_index, _epoch_encryption_key, emulation_ciphersuite) = state.into_parts();
    assert_eq!(emulation_ciphersuite, EMULATION_CIPHERSUITE);
    let (generation, operation_secret) = scratch_tree
        .next_operation_secret(
            provider.crypto(),
            EMULATION_CIPHERSUITE,
            &epoch_id,
            emulation_leaf_index,
            VirtualClientOperationType::KeyPackage,
            b"",
        )
        .expect("derive reference operation secret");
    assert_eq!(generation, 0);
    drop(scratch_tree);

    let expected_leaf_keypair = operation_secret
        .derive_key_package_seed_secret(provider.crypto(), GROUP_CIPHERSUITE, 0)
        .expect("derive reference key package seed")
        .derive_encryption_key_secret(provider.crypto(), GROUP_CIPHERSUITE)
        .expect("derive reference encryption key secret")
        .generate_encryption_key_pair(provider.crypto(), GROUP_CIPHERSUITE)
        .expect("generate reference leaf keypair");

    // Actual: create the higher-level group as the virtual client.
    let (vc_credential, vc_signer) = new_credential(
        provider,
        b"Alice (VC)",
        GROUP_CIPHERSUITE.signature_algorithm(),
    );
    let main_group = MlsGroup::builder()
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(GROUP_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .with_capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .vc_emulation(emulator_group.group_id())
        .build(provider, &vc_signer, vc_credential)
        .expect("create vc group");

    assert_eq!(
        main_group
            .own_leaf_node()
            .expect("creator leaf")
            .encryption_key(),
        expected_leaf_keypair.public_key(),
        "the creator leaf's encryption key secret must derive from the \
         per-KeyPackage seed imported into the created group's ciphersuite"
    );
}

/// GroupContext extensions requiring Safe AAD framing, with no component id
/// that every member must understand.
fn safe_aad_group_context_extensions() -> Extensions<GroupContext> {
    let mut dictionary = AppDataDictionary::new();
    let body = ComponentsList::new(Vec::new())
        .tls_serialize_detached()
        .expect("serialize ComponentsList body");
    dictionary.insert(ComponentId::from(ComponentType::SafeAad), body);
    let ext = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
    Extensions::single(ext).expect("one app_data_dictionary extension is valid")
}

/// Found a two-member group that requires Safe AAD framing. Returns Alice's
/// group and signer plus Bob's group.
fn safe_aad_group_pair<P: OpenMlsProvider>(
    alice_provider: &P,
    bob_provider: &P,
) -> (MlsGroup, MlsGroup, impl Signer) {
    let config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(GROUP_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .with_group_context_extensions(safe_aad_group_context_extensions())
        .build();

    let (alice_credential, alice_signer) = new_credential(
        alice_provider,
        b"Alice (VC)",
        GROUP_CIPHERSUITE.signature_algorithm(),
    );
    let mut alice_group = MlsGroup::new(alice_provider, &alice_signer, &config, alice_credential)
        .expect("create safe-aad group");

    let (bob_credential, bob_signer) = new_credential(
        bob_provider,
        b"Bob",
        GROUP_CIPHERSUITE.signature_algorithm(),
    );
    let bob_key_package = KeyPackage::builder()
        .leaf_node_capabilities(vc_capabilities())
        .build(GROUP_CIPHERSUITE, bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build");
    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .expect("add bob");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("merge add");

    let welcome = MlsMessageIn::from(welcome)
        .into_welcome()
        .expect("welcome message");
    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("stage welcome")
    .into_group(bob_provider)
    .expect("group from staged welcome");

    (alice_group, bob_group, alice_signer)
}

/// A [`VirtualClientCommitData`] item attached to a commit's Safe AAD reaches
/// the other member and parses back to the same value.
#[openmls_test::openmls_test]
fn vc_commit_data_travels_in_commit_safe_aad() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, mut bob_group, alice_signer) =
        safe_aad_group_pair(alice_provider, bob_provider);

    let epoch_usage = VcEpochUsage::new([
        EpochId::new(b"second declared epoch".to_vec()),
        EpochId::new(b"first declared epoch".to_vec()),
    ])
    .expect("epoch ids must serialize");
    let commit_data = VirtualClientCommitData::new(
        Some(epoch_usage),
        vec![VirtualClientAction::NewDerivationEpoch],
    )
    .expect("one new_derivation_epoch action is valid");

    alice_group
        .set_safe_aad(vec![commit_data
            .to_safe_aad_item()
            .expect("serialize commit data")])
        .expect("a single item is sorted and unique");

    let commit = alice_group
        .self_update(alice_provider, &alice_signer, LeafNodeParameters::default())
        .expect("self update")
        .into_messages()
        .0;

    let processed = bob_group
        .process_message(
            bob_provider,
            MlsMessageIn::from(commit)
                .into_protocol_message()
                .expect("protocol message"),
        )
        .expect("process commit");

    let parsed = processed
        .vc_commit_data()
        .expect("the item must parse")
        .expect("the item must be present");
    assert_eq!(parsed, commit_data);
    assert!(parsed.creates_derivation_epoch());

    // Both members advance so the next commit is processed in a shared epoch.
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("merge own self update");
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("a commit must process into a staged commit");
    };
    bob_group
        .merge_staged_commit(bob_provider, *staged)
        .expect("merge staged commit");

    // A later commit without the item leaves the accessor with nothing to parse.
    let commit = alice_group
        .self_update(alice_provider, &alice_signer, LeafNodeParameters::default())
        .expect("second self update")
        .into_messages()
        .0;
    let processed = bob_group
        .process_message(
            bob_provider,
            MlsMessageIn::from(commit)
                .into_protocol_message()
                .expect("protocol message"),
        )
        .expect("process second commit");
    assert_eq!(processed.vc_commit_data(), Ok(None));
}

/// A repeated registration for the same group epoch returns the recorded
/// [`EpochId`] and consumes a fresh export tree handed to it, so a retried
/// Welcome join cannot persist a tree from which the consumed secret is still
/// derivable. Passing the already-punctured tree again is a plain no-op
/// repeat.
#[openmls_test::openmls_test]
fn repeated_registration_with_fresh_tree_punctures_it() {
    let provider = Provider::default();
    let group_id = GroupId::from_slice(b"vc retry group");
    let params = || VcDerivationEpochParams {
        group_id: &group_id,
        ciphersuite,
        group_epoch: GroupEpoch::from(5),
        own_leaf_index: LeafNodeIndex::new(0),
        tree_size: TreeSize::from_leaf_count(2),
    };

    let mut tree_a = fresh_export_tree(ciphersuite, 1);
    let id_a = register_vc_derivation_epoch(
        provider.crypto(),
        provider.storage(),
        Some(&mut tree_a),
        params(),
    )
    .expect("first registration");

    // A retried Welcome join rebuilds the same tree from the same Welcome.
    let mut tree_b = fresh_export_tree(ciphersuite, 1);
    let id_b = register_vc_derivation_epoch(
        provider.crypto(),
        provider.storage(),
        Some(&mut tree_b),
        params(),
    )
    .expect("repeated registration with a fresh tree");
    assert_eq!(id_a, id_b);
    let err = tree_b
        .safe_export_secret(provider.crypto(), ciphersuite, VC_COMPONENT_ID)
        .expect_err("the repeat must consume the fresh tree");
    assert!(matches!(err, ApplicationExportTreeError::PuncturedInput));

    // An in-process repeat with the consumed tree returns the recorded id.
    let id_c = register_vc_derivation_epoch(
        provider.crypto(),
        provider.storage(),
        Some(&mut tree_a),
        params(),
    )
    .expect("repeat with the already-punctured tree");
    assert_eq!(id_c, id_a);

    let registered: Option<RegisteredVcDerivationEpoch> = provider
        .storage()
        .registered_vc_derivation_epoch(&group_id)
        .expect("read registration record");
    assert_eq!(registered.expect("record must exist").epoch_id, id_a);
}

/// Like [`emulation_group_config`], but requiring Safe AAD framing, without
/// which a commit cannot carry the virtual-clients item and so cannot create a
/// derivation epoch or declare one.
fn safe_aad_emulation_group_config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
    vc_config_builder(ciphersuite)
        .emulation_group(true)
        .with_group_context_extensions(safe_aad_group_context_extensions())
        .build()
}

/// The signing identity of a virtual client, stored on both emulator clients so
/// either can sign for the shared higher-level leaf.
fn shared_vc_identity<P: OpenMlsProvider>(
    provider_a: &P,
    provider_b: &P,
) -> (SignatureKeyPair, crate::credentials::CredentialWithKey) {
    use crate::credentials::{BasicCredential, CredentialWithKey};

    let signer = SignatureKeyPair::new(GROUP_CIPHERSUITE.signature_algorithm())
        .expect("generate the virtual client's signature keypair");
    signer
        .store(provider_a.storage())
        .expect("store the signer on the first emulator");
    signer
        .store(provider_b.storage())
        .expect("store the signer on the second emulator");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"Alice (VC)".to_vec()).into(),
        signature_key: signer.public().into(),
    };
    (signer, credential)
}

/// Two emulator clients of one virtual client, sharing an emulation group and
/// its newest derivation epoch. The first founds the group, the second joins it
/// by Welcome, so the entry epoch is a derivation epoch on both.
fn sibling_emulators<P: OpenMlsProvider>(
    provider_a: &P,
    provider_b: &P,
) -> (MlsGroup, SignatureKeyPair, MlsGroup, SignatureKeyPair) {
    let config = safe_aad_emulation_group_config(EMULATION_CIPHERSUITE);
    let (credential_a, signer_a) = new_credential(
        provider_a,
        b"EmulatorA",
        EMULATION_CIPHERSUITE.signature_algorithm(),
    );
    let mut emulator_a = MlsGroup::new(provider_a, &signer_a, &config, credential_a)
        .expect("create the emulation group");

    let (credential_b, signer_b) = new_credential(
        provider_b,
        b"EmulatorB",
        EMULATION_CIPHERSUITE.signature_algorithm(),
    );
    let key_package_b = KeyPackage::builder()
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(EMULATION_CIPHERSUITE, provider_b, &signer_b, credential_b)
        .expect("build the second emulator's key package");
    let (_commit, welcome, _group_info) = emulator_a
        .add_members(
            provider_a,
            &signer_a,
            &[key_package_b.key_package().clone()],
        )
        .expect("add the second emulator");
    emulator_a
        .merge_pending_commit(provider_a)
        .expect("merge the add");
    let emulator_b = StagedWelcome::new_from_welcome(
        provider_b,
        config.join_config(),
        MlsMessageIn::from(welcome)
            .into_welcome()
            .expect("welcome message"),
        Some(emulator_a.export_ratchet_tree().into()),
    )
    .expect("stage the emulation-group welcome")
    .emulation_group(true)
    .into_group(provider_b)
    .expect("join the emulation group");

    (emulator_a, signer_a, emulator_b, signer_b)
}

/// The newest derivation epoch of `emulator_group`.
fn newest_epoch<P: OpenMlsProvider>(emulator_group: &MlsGroup, provider: &P) -> EpochId {
    emulator_group
        .newest_vc_derivation_epoch(provider.storage())
        .expect("read the newest derivation epoch")
        .expect("an emulation group has a derivation epoch")
}

/// Send a commit creating a derivation epoch on `emulator_group`, merge it
/// locally and return it for delivery to the sibling.
fn send_emulation_commit<P: OpenMlsProvider>(
    emulator_group: &mut MlsGroup,
    provider: &P,
    signer: &SignatureKeyPair,
) -> crate::framing::MlsMessageOut {
    let bundle = emulator_group
        .commit_builder()
        .force_self_update(true)
        .derivation_epoch(true)
        .load_psks(provider.storage())
        .expect("load psks")
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .expect("build the emulation commit")
        .stage_commit(provider)
        .expect("stage the emulation commit");
    emulator_group
        .merge_pending_commit(provider)
        .expect("merge the emulation commit");
    bundle.into_commit()
}

/// Process and merge `commit` on `receiver`.
fn process_and_merge_commit<P: OpenMlsProvider>(
    receiver: &mut MlsGroup,
    provider: &P,
    commit: crate::framing::MlsMessageOut,
) {
    let processed = receiver
        .process_message(
            provider,
            commit
                .into_protocol_message()
                .expect("commits are protocol messages"),
        )
        .expect("process the commit");
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("a commit must process into a staged commit");
    };
    receiver
        .merge_staged_commit(provider, *staged)
        .expect("merge the staged commit");
}

/// Move the emulation group one derivation epoch further per member, so every
/// older epoch leaves the baseline retention window on both clients.
fn advance_emulation_group<P: OpenMlsProvider>(
    emulator_a: &mut MlsGroup,
    provider_a: &P,
    signer_a: &SignatureKeyPair,
    emulator_b: &mut MlsGroup,
    provider_b: &P,
    signer_b: &SignatureKeyPair,
) {
    let commit = send_emulation_commit(emulator_a, provider_a, signer_a);
    process_and_merge_commit(emulator_b, provider_b, commit);
    let commit = send_emulation_commit(emulator_b, provider_b, signer_b);
    process_and_merge_commit(emulator_a, provider_a, commit);
}

/// Whether the per-epoch state of `epoch_id` is still stored.
fn epoch_state_is_stored<P: OpenMlsProvider>(provider: &P, epoch_id: &EpochId) -> bool {
    let state: Option<VcDerivationEpochState> = provider
        .storage()
        .vc_derivation_epoch_state(epoch_id)
        .expect("read the derivation epoch state");
    state.is_some()
}

/// A virtual client welcomed into a higher-level group takes the reference to
/// the derivation epoch the Welcome drew on.
///
/// The retained KeyPackage material that had been protecting the epoch is
/// consumed by the join, so without a binding in its place an emulation-group
/// commit could reap an epoch the joined group needs for every message it sends.
#[openmls_test::openmls_test]
fn a_welcome_into_a_higher_level_group_binds_its_derivation_epoch() {
    use crate::components::vc_derivation_info::{
        assemble_vc_key_package_upload, process_vc_key_package_upload,
    };

    let provider_a = &Provider::default();
    let provider_b = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut emulator_a, signer_a, mut emulator_b, signer_b) =
        sibling_emulators(provider_a, provider_b);
    let entry_epoch_id = newest_epoch(&emulator_a, provider_a);
    assert_eq!(
        entry_epoch_id,
        newest_epoch(&emulator_b, provider_b),
        "the siblings must share the entry epoch"
    );

    // The first emulator publishes one virtual-client KeyPackage from that epoch
    // and hands the upload to the second, which is where the material is
    // retained.
    let (vc_signer, vc_credential) = shared_vc_identity(provider_a, provider_b);
    let mut batch = KeyPackage::builder()
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build_vc_batch(
            GROUP_CIPHERSUITE,
            provider_a,
            &vc_signer,
            vc_credential,
            emulator_a.group_id(),
            1,
        )
        .expect("build a one-KeyPackage batch");
    assert_eq!(batch.epoch_id, entry_epoch_id);
    let generation = batch.generation;
    let (key_package_bundle, key_package_info) = batch.key_packages.remove(0);
    let upload = assemble_vc_key_package_upload(
        provider_a.storage(),
        entry_epoch_id.clone(),
        generation,
        vec![key_package_info],
    )
    .expect("assemble the upload");
    process_vc_key_package_upload(provider_b, &upload).expect("process the upload");

    // An ordinary client founds a higher-level group and welcomes the virtual
    // client into it with that KeyPackage.
    let bob_config = vc_group_config(GROUP_CIPHERSUITE);
    let (bob_credential, bob_signer) = new_credential(
        bob_provider,
        b"Bob",
        GROUP_CIPHERSUITE.signature_algorithm(),
    );
    let mut bob_group = MlsGroup::new(bob_provider, &bob_signer, &bob_config, bob_credential)
        .expect("create the higher-level group");
    let (_commit, welcome, _group_info) = bob_group
        .add_members(
            bob_provider,
            &bob_signer,
            &[key_package_bundle.key_package().clone()],
        )
        .expect("add the virtual client");
    bob_group
        .merge_pending_commit(bob_provider)
        .expect("merge the add");

    let mut vc_group = StagedWelcome::new_from_welcome(
        provider_b,
        bob_config.join_config(),
        MlsMessageIn::from(welcome)
            .into_welcome()
            .expect("welcome message"),
        Some(bob_group.export_ratchet_tree().into()),
    )
    .expect("stage the higher-level welcome")
    .into_group(provider_b)
    .expect("join the higher-level group");

    // The join binds the joined group's entry epoch to the Welcome's derivation
    // epoch and takes that binding's reference.
    let bindings: VcEmulationBindings = provider_b
        .storage()
        .vc_emulation_bindings(vc_group.group_id())
        .expect("read the emulation bindings")
        .expect("the join must install a binding");
    assert_eq!(
        bindings.get(vc_group.epoch()),
        Some(&entry_epoch_id),
        "the entry epoch must be bound to the Welcome's derivation epoch"
    );
    let refs: VcEpochRefs = provider_b
        .storage()
        .vc_epoch_refs(&entry_epoch_id)
        .expect("read the reverse reference index")
        .expect("the binding must hold a reference");
    assert!(
        refs.bindings().contains(vc_group.group_id()),
        "the reference must name the joined group"
    );

    // That reference is all that keeps the epoch once both siblings moved the
    // emulation group past it.
    advance_emulation_group(
        &mut emulator_a,
        provider_a,
        &signer_a,
        &mut emulator_b,
        provider_b,
        &signer_b,
    );
    assert!(
        epoch_state_is_stored(provider_b, &entry_epoch_id),
        "the joined group's binding must keep the epoch from being reaped"
    );

    // And the joined group still derives its reuse guard from that epoch.
    let message = vc_group
        .create_message(provider_b, &vc_signer, b"hello bob")
        .expect("send from the joined group");
    let processed = bob_group
        .process_message(
            bob_provider,
            message
                .into_protocol_message()
                .expect("application messages are protocol messages"),
        )
        .expect("process the application message");
    let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
        panic!("an application message must process into one");
    };
    assert_eq!(message.into_bytes().as_slice(), b"hello bob");
}

/// A registration record whose [`EpochId`] does not match the export tree for
/// the same group epoch is stale state from a group instance that was never
/// fully stored, for example a crashed creation under a recycled group id. The
/// registration derives fresh state and overwrites the record.
#[openmls_test::openmls_test]
fn stale_registration_record_is_overwritten() {
    let provider = Provider::default();
    let group_id = GroupId::from_slice(b"vc recycled group id");
    let params = || VcDerivationEpochParams {
        group_id: &group_id,
        ciphersuite,
        group_epoch: GroupEpoch::from(0),
        own_leaf_index: LeafNodeIndex::new(0),
        tree_size: TreeSize::from_leaf_count(1),
    };

    let mut tree_old = fresh_export_tree(ciphersuite, 2);
    let id_old = register_vc_derivation_epoch(
        provider.crypto(),
        provider.storage(),
        Some(&mut tree_old),
        params(),
    )
    .expect("registration of the crashed instance");

    let mut tree_new = fresh_export_tree(ciphersuite, 3);
    let id_new = register_vc_derivation_epoch(
        provider.crypto(),
        provider.storage(),
        Some(&mut tree_new),
        params(),
    )
    .expect("registration of the recreated instance");
    assert_ne!(id_old, id_new);

    let registered: Option<RegisteredVcDerivationEpoch> = provider
        .storage()
        .registered_vc_derivation_epoch(&group_id)
        .expect("read registration record");
    assert_eq!(registered.expect("record must exist").epoch_id, id_new);
}
