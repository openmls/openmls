use openmls_traits::types::Ciphersuite;
use tls_codec::Serialize as _;

use crate::{
    component::{ComponentId, ComponentType},
    components::vc_derivation_info::VC_COMPONENT_ID,
    credentials::test_utils::new_credential,
    extensions::{
        AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType, Extensions,
    },
    group::{MlsGroup, MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY},
    prelude::{Capabilities, LeafNode, LeafNodeParameters},
};

/// Emulation group suite. Its KDF hash (SHA-384) differs from the
/// higher-level group's (SHA-256) which helps to detect errors like
/// mismatched KDF hash lengths.
const EMULATION_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519;

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

#[openmls_test::openmls_test]
fn register_vc_emulation_epoch_is_idempotent_per_epoch() {
    let provider = &Provider::default();
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

    let epoch_id = emulator_group
        .register_vc_emulation_epoch(provider.crypto(), provider.storage())
        .expect("first registration");

    let epoch_id_again = emulator_group
        .register_vc_emulation_epoch(provider.crypto(), provider.storage())
        .expect("repeated registration in the same epoch");
    assert_eq!(
        epoch_id, epoch_id_again,
        "a repeated registration in the same epoch must return the recorded \
         epoch id"
    );

    // Advancing the group epoch installs a fresh exporter, so a new
    // registration derives a new emulation epoch.
    emulator_group
        .self_update(provider, &signer, LeafNodeParameters::default())
        .expect("self update");
    emulator_group
        .merge_pending_commit(provider)
        .expect("merge self update");

    let next_epoch_id = emulator_group
        .register_vc_emulation_epoch(provider.crypto(), provider.storage())
        .expect("registration in the next epoch");
    assert_ne!(
        epoch_id, next_epoch_id,
        "a registration after the epoch advanced must derive a fresh \
         emulation epoch"
    );
}
