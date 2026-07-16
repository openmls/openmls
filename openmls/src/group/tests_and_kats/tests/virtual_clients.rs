use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use tls_codec::Serialize as _;

use crate::{
    component::{ComponentId, ComponentType},
    components::vc_derivation_info::{
        load_vc_epoch_state_and_tree, EpochId, VirtualClientOperationType, VC_COMPONENT_ID,
    },
    credentials::test_utils::new_credential,
    extensions::{
        AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType, Extensions,
    },
    group::{MlsGroup, MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY},
    key_packages::KeyPackage,
    messages::PathSecret,
    prelude::{Capabilities, LeafNode},
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

fn vc_group_config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build()
}

/// Found a single-member emulation group on `provider` and register an
/// emulation epoch on it.
fn registered_emulation_epoch<P: OpenMlsProvider>(provider: &P) -> EpochId {
    let (credential, signer) = new_credential(
        provider,
        b"Emulator",
        EMULATION_CIPHERSUITE.signature_algorithm(),
    );
    let mut emulator_group = MlsGroup::new(
        provider,
        &signer,
        &vc_group_config(EMULATION_CIPHERSUITE),
        credential,
    )
    .expect("create emulation group");
    emulator_group
        .register_vc_emulation_epoch(provider.crypto(), provider.storage())
        .expect("register emulation epoch")
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

    let epoch_id = registered_emulation_epoch(provider);

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
        .vc_emulation(provider.crypto(), provider.storage(), epoch_id)
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

    let epoch_id = registered_emulation_epoch(provider);

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
        .vc_emulation(epoch_id)
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
