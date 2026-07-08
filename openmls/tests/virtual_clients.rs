#![cfg(feature = "virtual-clients-draft")]
use openmls::{
    components::vc_derivation_info::{EpochId, VcEmulationBindings, VC_COMPONENT_ID},
    extensions::{
        AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType, Extensions,
    },
    group::{
        MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedWelcome,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    key_packages::KeyPackage,
    prelude::{test_utils::new_credential, Capabilities, LeafNode, ProcessedMessageContent},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_test::openmls_test;
use openmls_traits::storage::StorageProvider as _;
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize as _;

mod mls_group;

/// `Capabilities` declaring `AppDataDictionary` support.
fn vc_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::AppDataDictionary])
        .build()
}

/// Build the `AppDataDictionary` leaf-node extensions a VC-sending leaf must
/// carry: an `AppComponents` entry (component id 1) whose body is the
/// TLS-encoded list `[VC_COMPONENT_ID]`. Per the mls-extensions draft,
/// `AppComponents` is a per-leaf advertisement.
fn vc_leaf_extensions() -> Extensions<LeafNode> {
    let supported_components: Vec<u16> = vec![VC_COMPONENT_ID];
    let app_components_body = supported_components
        .tls_serialize_detached()
        .expect("serialize AppComponents body");
    let mut dictionary = AppDataDictionary::new();
    // ComponentType::AppComponents == 1
    dictionary.insert(1, app_components_body);
    let ext = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
    Extensions::from_vec(vec![ext]).expect("build leaf-node Extensions")
}

/// Build an Alice + Bob group on two providers. Alice creates the group,
/// adds Bob, merges. Bob joins from the welcome. After this, `alice_group`
/// (on `alice_provider`) and `bob_group` (on `bob_provider`) both
/// represent the same MLS group at the same epoch.
fn setup_alice_bob_group<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    alice_provider: &P,
    bob_provider: &P,
) -> (MlsGroup, SignatureKeyPair, MlsGroup, SignatureKeyPair) {
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions on alice config")
        .build();

    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &group_config,
        alice_credential,
    )
    .expect("alice create group");

    let bob_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();

    let (_commit, welcome, _gi) = alice_group
        .add_members(alice_provider, &alice_signer, &[bob_key_package])
        .expect("alice add bob");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("alice merge add");

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        &join_config,
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(bob_provider))
    .expect("bob join via welcome");

    (alice_group, alice_signer, bob_group, bob_signer)
}

/// Build a single-member emulator group on `provider` with VC
/// capabilities and an `AppComponents` entry listing `VC_COMPONENT_ID`.
/// Used as the source of `safe_export_secret(VC_COMPONENT_ID)` when
/// registering an emulation epoch.
fn make_emulator_group<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider: &P,
    label: &[u8],
) -> (MlsGroup, SignatureKeyPair) {
    let (credential, signer) = new_credential(provider, label, ciphersuite.signature_algorithm());
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions on emulator config")
        .build();
    let group =
        MlsGroup::new(provider, &signer, &group_config, credential).expect("create emulator group");
    (group, signer)
}

/// Register a fresh emulation epoch on `emulator_group` (sourcing the
/// root secret from its `safe_export_secret(VC_COMPONENT_ID)`) and send
/// a VC-flavoured commit on `sender_group` referencing that epoch.
/// `register_vc_emulation_epoch` captures `own_leaf_index` of the
/// emulator group at registration time, so callers no longer pass it.
fn send_vc_commit<P: OpenMlsProvider>(
    sender_group: &mut MlsGroup,
    emulator_group: &mut MlsGroup,
    sender_provider: &P,
    sender_signer: &SignatureKeyPair,
) -> (openmls::prelude::MlsMessageOut, EpochId) {
    let epoch_id = emulator_group
        .register_vc_emulation_epoch(sender_provider.crypto(), sender_provider.storage())
        .expect("register vc epoch (sender)");
    let commit = send_vc_commit_with_epoch(
        sender_group,
        sender_provider,
        sender_signer,
        epoch_id.clone(),
    );
    (commit, epoch_id)
}

/// Send a VC-flavoured commit on `sender_group` referencing an
/// already-registered `epoch_id`. Useful for tests that want to issue
/// multiple commits against the same emulation epoch without
/// re-puncturing the emulator group's application-export tree.
fn send_vc_commit_with_epoch<P: OpenMlsProvider>(
    sender_group: &mut MlsGroup,
    sender_provider: &P,
    sender_signer: &SignatureKeyPair,
    epoch_id: EpochId,
) -> openmls::prelude::MlsMessageOut {
    let bundle = sender_group
        .commit_builder()
        .vc_emulation(
            sender_provider.crypto(),
            sender_provider.storage(),
            epoch_id,
        )
        .unwrap()
        .load_psks(sender_provider.storage())
        .unwrap()
        .build(
            sender_provider.rand(),
            sender_provider.crypto(),
            sender_signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(sender_provider)
        .unwrap();

    sender_group
        .merge_pending_commit(sender_provider)
        .expect("sender merge");

    bundle.into_commit()
}

/// The shared signing identity of a virtual client, stored in both emulator
/// clients' providers so either can sign for the shared higher-level leaf.
fn shared_vc_identity<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider_a: &P,
    provider_b: &P,
) -> (SignatureKeyPair, openmls::credentials::CredentialWithKey) {
    use openmls::credentials::{BasicCredential, CredentialWithKey};
    let vc_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("vc signer");
    vc_signer
        .store(provider_a.storage())
        .expect("store vc signer on alice_a");
    vc_signer
        .store(provider_b.storage())
        .expect("store vc signer on alice_b");
    let vc_credential = CredentialWithKey {
        credential: BasicCredential::new(b"Alice (VC)".to_vec()).into(),
        signature_key: vc_signer.public().into(),
    };
    (vc_signer, vc_credential)
}

/// Found a higher-level group on the shared virtual-client leaf.
fn new_vc_main_group<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider: &P,
    signer: &SignatureKeyPair,
    credential: openmls::credentials::CredentialWithKey,
) -> MlsGroup {
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    MlsGroup::new(provider, signer, &group_config, credential).expect("create vc main group")
}

/// The join config used by emulator clients resyncing into a higher-level
/// group: pure-plaintext framing with the ratchet tree carried inline.
fn vc_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build()
}

/// A second emulator client brought in alongside an existing one, sharing the
/// virtual client's emulation epoch.
struct SiblingEmulators {
    emulator_a: MlsGroup,
    emulator_a_signer: SignatureKeyPair,
    emulator_b: MlsGroup,
    alice_b_main: MlsGroup,
    epoch_id: EpochId,
}

/// Bring a second emulator client (alice_b) into an existing virtual client
/// without cloning storage. alice_a founds the emulation group and alice_b
/// joins it via Welcome; both register the same emulation epoch; then alice_b
/// resyncs into the higher-level group via an external commit. Returns the
/// emulator state plus that resync commit, which the caller delivers to
/// `alice_a_main` (and any other higher-level members) so they converge on
/// the new virtual-client leaf.
fn join_sibling_emulator<P: OpenMlsProvider>(
    emulator_ciphersuite: openmls_traits::types::Ciphersuite,
    alice_a_provider: &P,
    alice_b_provider: &P,
    vc_signer: &SignatureKeyPair,
    vc_credential: openmls::credentials::CredentialWithKey,
    alice_a_main: &MlsGroup,
    main_join_config: MlsGroupJoinConfig,
) -> (SiblingEmulators, openmls::prelude::MlsMessageOut) {
    use openmls::prelude::{LeafNodeParameters, MlsMessageIn};
    use tls_codec::Deserialize as _;

    // alice_a founds the emulation group; alice_b joins it via Welcome.
    let (mut emulator_a, emulator_a_signer) =
        make_emulator_group(emulator_ciphersuite, alice_a_provider, b"AliceEmulatorA");
    let (emulator_b_credential, emulator_b_signer) = new_credential(
        alice_b_provider,
        b"AliceEmulatorB",
        emulator_ciphersuite.signature_algorithm(),
    );
    let emulator_b_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(
            emulator_ciphersuite,
            alice_b_provider,
            &emulator_b_signer,
            emulator_b_credential,
        )
        .expect("emulator_b KP build")
        .key_package()
        .to_owned();
    let (_e_commit, e_welcome, _e_gi) = emulator_a
        .add_members(alice_a_provider, &emulator_a_signer, &[emulator_b_kp])
        .expect("emulator_a add alice_b");
    emulator_a
        .merge_pending_commit(alice_a_provider)
        .expect("emulator_a merge add");
    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let mut emulator_b = StagedWelcome::new_from_welcome(
        alice_b_provider,
        &join_config,
        e_welcome.into_welcome().expect("emulator welcome"),
        Some(emulator_a.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(alice_b_provider))
    .expect("alice_b join emulator group");

    // Both clients independently register the same emulation epoch.
    let epoch_id = emulator_a
        .register_vc_emulation_epoch(alice_a_provider.crypto(), alice_a_provider.storage())
        .expect("alice_a register vc epoch");
    let epoch_id_b = emulator_b
        .register_vc_emulation_epoch(alice_b_provider.crypto(), alice_b_provider.storage())
        .expect("alice_b register vc epoch");
    assert_eq!(
        epoch_id, epoch_id_b,
        "siblings must derive the same EpochId"
    );

    // alice_b resyncs into the higher-level group via an external commit.
    let verifiable_group_info = {
        let group_info_msg = alice_a_main
            .export_group_info(alice_a_provider.crypto(), vc_signer, true)
            .expect("export group info");
        let serialized = group_info_msg
            .tls_serialize_detached()
            .expect("serialize group info");
        MlsMessageIn::tls_deserialize(&mut serialized.as_slice())
            .expect("deserialize group info message")
            .into_verifiable_group_info()
            .expect("into verifiable group info")
    };
    let (alice_b_main, bundle) = MlsGroup::external_commit_builder()
        .with_config(main_join_config)
        .build_group(alice_b_provider, verifiable_group_info, vc_credential)
        .expect("build_group")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(vc_capabilities())
                .with_extensions(vc_leaf_extensions())
                .build(),
        )
        .vc_emulation(
            alice_b_provider.crypto(),
            alice_b_provider.storage(),
            epoch_id.clone(),
        )
        .expect("vc emulation")
        .load_psks(alice_b_provider.storage())
        .expect("load psks")
        .build(
            alice_b_provider.rand(),
            alice_b_provider.crypto(),
            vc_signer,
            |_| true,
        )
        .expect("build external commit")
        .finalize(alice_b_provider)
        .expect("finalize external commit");

    (
        SiblingEmulators {
            emulator_a,
            emulator_a_signer,
            emulator_b,
            alice_b_main,
            epoch_id,
        },
        bundle.into_commit(),
    )
}

/// Send an application message from `sender` and process it on `receiver`,
/// returning the processed message for inspection (e.g. the recovered
/// emulator sender leaf index).
fn send_and_process_app_message<P: OpenMlsProvider>(
    sender: &mut MlsGroup,
    sender_provider: &P,
    sender_signer: &SignatureKeyPair,
    receiver: &mut MlsGroup,
    receiver_provider: &P,
    plaintext: &[u8],
) -> openmls::prelude::ProcessedMessage {
    let app_msg = sender
        .create_message(sender_provider, sender_signer, plaintext)
        .expect("sender creates application message");
    receiver
        .process_message(receiver_provider, app_msg.into_protocol_message().unwrap())
        .expect("receiver processes application message")
}

/// Focused ratchet-persistence test: after the sender builds a VC commit,
/// the per-epoch operation secret tree must remain registered with its
/// advanced ratchet head. A *second* VC commit on the same `epoch_id` must
/// succeed and consume the next generation. That the generations are
/// consumed in order is covered behaviorally by
/// `vc_two_alice_clients_in_group_with_bob_and_charly`, where a sibling
/// processes generations 0 and 1 positionally.
#[openmls_test]
fn vc_operation_tree_persists_across_own_commits() {
    let provider = Provider::default();
    let (alice_credential, alice_signer) =
        new_credential(&provider, b"Alice", ciphersuite.signature_algorithm());
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    let mut alice = MlsGroup::new(&provider, &alice_signer, &group_config, alice_credential)
        .expect("create group");
    let (mut emulator, _emulator_signer) =
        make_emulator_group(ciphersuite, &provider, b"AliceEmulator");

    // Register the emulation epoch once; both commits reference it.
    // `safe_export_secret(VC_COMPONENT_ID)` punctures the emulator
    // group's application-export tree, so registering twice in the same
    // emulator-group epoch would fail with `PuncturedInput`. The point
    // of this test is that the per-emulation-epoch operation secret tree
    // survives, with its advanced ratchet head, across build boundaries.
    let epoch_id = emulator
        .register_vc_emulation_epoch(provider.crypto(), provider.storage())
        .expect("register vc epoch");

    let _msg1 = send_vc_commit_with_epoch(&mut alice, &provider, &alice_signer, epoch_id.clone());
    let epoch_after_first = alice.epoch();

    // A *second* VC commit on the same emulation epoch must still
    // succeed and consume generation 1. If `build` had wiped the
    // registration or failed to persist the ratchet advance, this would
    // fail at tree lookup or when the consumed generation is re-derived.
    let _msg2 = send_vc_commit_with_epoch(&mut alice, &provider, &alice_signer, epoch_id);
    assert_eq!(
        alice.epoch().as_u64(),
        epoch_after_first.as_u64() + 1,
        "second VC commit on the same emulation epoch must succeed"
    );
}

/// A non-emulator group member processes a VC commit through the normal HPKE
/// path, without holding any per-emulation-epoch VC state.
#[openmls_test]
fn non_emulator_processes_vc_commit_without_registering_state() {
    let alice_provider = Provider::default();
    let bob_provider = Provider::default();
    let (mut alice, alice_signer, mut bob, _bob_signer) =
        setup_alice_bob_group(ciphersuite, &alice_provider, &bob_provider);
    let (mut emulator, _emulator_signer) =
        make_emulator_group(ciphersuite, &alice_provider, b"AliceEmulator");

    let (commit_msg, _epoch_id) =
        send_vc_commit(&mut alice, &mut emulator, &alice_provider, &alice_signer);

    let processed = bob
        .process_message(&bob_provider, commit_msg.into_protocol_message().unwrap())
        .expect("non-emulator must process VC commit via the normal HPKE path");
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(s) => *s,
        _ => panic!("expected staged commit"),
    };
    bob.merge_staged_commit(&bob_provider, staged)
        .expect("bob merge");
    assert_eq!(alice.epoch(), bob.epoch());
}

/// A sibling-resync external commit requires VC state on the receiving
/// sibling. The receiver identifies itself as a sibling from the commit
/// shape (`Sender::NewMemberCommit` plus an inline `Remove` of its own
/// leaf), then *must* load the per-epoch operation secret tree and
/// emulation-epoch state to derive the path. If the receiver hasn't yet
/// registered the matching emulation epoch (e.g. it joined the emulator
/// group but skipped the `register_vc_emulation_epoch` step before the
/// sibling attempted the resync), processing must fail loudly with a
/// virtual-clients error rather than silently fall through to HPKE.
#[openmls_test]
fn sibling_resync_external_commit_fails_when_receiver_lacks_operation_tree() {
    use openmls::credentials::{BasicCredential, CredentialWithKey};
    use openmls::prelude::{LeafNodeParameters, MlsMessageIn};
    use tls_codec::Deserialize as _;

    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();

    // Shared VC signer + credential. Both alice clients hold a copy of the
    // signer so the external-commit auto-Remove targets the existing leaf.
    let vc_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("vc signer");
    vc_signer
        .store(alice_a_provider.storage())
        .expect("store vc signer on alice_a");
    vc_signer
        .store(alice_b_provider.storage())
        .expect("store vc signer on alice_b");
    let vc_credential = CredentialWithKey {
        credential: BasicCredential::new(b"Alice (VC)".to_vec()).into(),
        signature_key: vc_signer.public().into(),
    };

    // Emulator group with alice_a as creator and alice_b as the second
    // member (joined via Welcome).
    let (mut emulator_a, alice_emulator_a_signer) =
        make_emulator_group(ciphersuite, &alice_a_provider, b"AliceEmulatorA");
    let (alice_emulator_b_credential, alice_emulator_b_signer) = new_credential(
        &alice_b_provider,
        b"AliceEmulatorB",
        ciphersuite.signature_algorithm(),
    );
    let alice_emulator_b_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(
            ciphersuite,
            &alice_b_provider,
            &alice_emulator_b_signer,
            alice_emulator_b_credential,
        )
        .expect("alice_b emulator KP build")
        .key_package()
        .to_owned();
    let (_, e_welcome, _) = emulator_a
        .add_members(
            &alice_a_provider,
            &alice_emulator_a_signer,
            &[alice_emulator_b_kp],
        )
        .expect("emulator_a add alice_b");
    emulator_a
        .merge_pending_commit(&alice_a_provider)
        .expect("emulator_a merge add");

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let mut emulator_b = StagedWelcome::new_from_welcome(
        &alice_b_provider,
        &join_config,
        e_welcome.into_welcome().expect("welcome"),
        Some(emulator_a.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&alice_b_provider))
    .expect("alice_b join emulator group");

    // Higher-level group: alice_a is the sole VC member.
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions on higher-level config")
        .build();
    let mut alice_a_main = MlsGroup::new(
        &alice_a_provider,
        &vc_signer,
        &group_config,
        vc_credential.clone(),
    )
    .expect("alice_a create higher-level group");

    // Only alice_b registers the VC epoch. alice_a "forgets" to register
    // on her side, manufacturing the failure scenario.
    let epoch_id_b = emulator_b
        .register_vc_emulation_epoch(alice_b_provider.crypto(), alice_b_provider.storage())
        .expect("alice_b register vc epoch");

    // alice_a exports the higher-level GroupInfo for alice_b's external commit.
    let verifiable_group_info = {
        let group_info_msg = alice_a_main
            .export_group_info(alice_a_provider.crypto(), &vc_signer, true)
            .expect("export group info");
        let serialized = group_info_msg
            .tls_serialize_detached()
            .expect("serialize group info");
        MlsMessageIn::tls_deserialize(&mut serialized.as_slice())
            .expect("deserialize group info message")
            .into_verifiable_group_info()
            .expect("into verifiable group info")
    };

    // alice_b builds the resync external commit. The auto-Remove targets
    // alice_a's leaf (same signature key), so alice_a's
    // `is_sibling_vc_commit` predicate fires when processing.
    let (_alice_b_main, bundle) = MlsGroup::external_commit_builder()
        .with_config(
            MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .build(),
        )
        .build_group(&alice_b_provider, verifiable_group_info, vc_credential)
        .expect("build_group")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(vc_capabilities())
                .with_extensions(vc_leaf_extensions())
                .build(),
        )
        .vc_emulation(
            alice_b_provider.crypto(),
            alice_b_provider.storage(),
            epoch_id_b,
        )
        .expect("vc emulation")
        .load_psks(alice_b_provider.storage())
        .expect("load psks")
        .build(
            alice_b_provider.rand(),
            alice_b_provider.crypto(),
            &vc_signer,
            |_| true,
        )
        .expect("build external commit")
        .finalize(&alice_b_provider)
        .expect("finalize external commit");
    let commit_msg = bundle.into_commit();

    let err = alice_a_main
        .process_message(
            &alice_a_provider,
            commit_msg.into_protocol_message().unwrap(),
        )
        .expect_err("must fail without VC state");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("MissingEmulationEpochState")
            || msg.contains("MissingOperationTree")
            || msg.contains("VirtualClients"),
        "expected a virtual-clients error, got {msg}"
    );
}

/// End-to-end realistic VC scenario: Alice has *two* clients sharing one
/// MLS leaf in a main group with Bob and Charly. Both Alice clients also
/// share an *emulator group* (a separate two-member MLS group) used as the
/// source of `safe_export_secret(VC_COMPONENT_ID)` from which both clients
/// derive the same `EpochId`, operation secret tree, and AEAD key.
///
/// alice_b bootstraps into the higher-level group via a sibling-resync VC
/// external commit (auto-Remove targeting alice_a's existing leaf). After
/// that we exercise five commits in order:
///   1. Bob's commit: processed by alice_a, alice_b, charly via HPKE.
///   2. Charly's commit: processed by alice_a, alice_b, bob via HPKE.
///   3. alice_a's VC commit: alice_b uses own-leaf VC path, bob+charly HPKE.
///   4. alice_b's VC commit: alice_a uses own-leaf VC path, bob+charly HPKE.
///   5. alice_a's second VC commit on the same emulation epoch: alice_b
///      derives generation 1 of alice_a's ratchet positionally, having
///      derived generation 0 for commit 3.
///
/// All four parties must agree on the epoch authenticator after each
/// commit.
#[openmls_test]
fn vc_two_alice_clients_in_group_with_bob_and_charly() {
    use openmls::credentials::{BasicCredential, CredentialWithKey};
    use openmls::prelude::{LeafNodeParameters, MlsMessageIn};
    use tls_codec::Deserialize as _;

    // ---- Providers (independent storage per client) ----
    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();
    let charly_provider = Provider::default();

    // ---- Credentials ----
    // The virtual client's shared signing key. Both alice clients hold a
    // copy in their own provider storage so either can sign for the shared
    // higher-level leaf; this is also what triggers the auto-Remove of
    // alice_a's existing leaf when alice_b later joins via external commit.
    let vc_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("vc signer");
    vc_signer
        .store(alice_a_provider.storage())
        .expect("store vc signer on alice_a");
    vc_signer
        .store(alice_b_provider.storage())
        .expect("store vc signer on alice_b");
    let vc_credential = CredentialWithKey {
        credential: BasicCredential::new(b"Alice (VC)".to_vec()).into(),
        signature_key: vc_signer.public().into(),
    };
    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let (charly_credential, charly_signer) = new_credential(
        &charly_provider,
        b"Charly",
        ciphersuite.signature_algorithm(),
    );

    // ---- Main group: alice_a creates with full VC capabilities + extensions ----
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions on alice main group config")
        .build();
    let mut alice_a_main = MlsGroup::new(
        &alice_a_provider,
        &vc_signer,
        &group_config,
        vc_credential.clone(),
    )
    .expect("alice create main group");

    let bob_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    let charly_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(
            ciphersuite,
            &charly_provider,
            &charly_signer,
            charly_credential,
        )
        .expect("charly KP build")
        .key_package()
        .to_owned();

    // Single multi-add: Bob and Charly join in one welcome.
    let (_commit, welcome, _gi) = alice_a_main
        .add_members(&alice_a_provider, &vc_signer, &[bob_kp, charly_kp])
        .expect("alice add bob+charly");
    alice_a_main
        .merge_pending_commit(&alice_a_provider)
        .expect("alice merge add");

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let welcome_msg = welcome.into_welcome().expect("welcome present");
    let ratchet_tree = alice_a_main.export_ratchet_tree();
    let mut bob_main = StagedWelcome::new_from_welcome(
        &bob_provider,
        &join_config,
        welcome_msg.clone(),
        Some(ratchet_tree.clone().into()),
    )
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob join");
    let mut charly_main = StagedWelcome::new_from_welcome(
        &charly_provider,
        &join_config,
        welcome_msg,
        Some(ratchet_tree.into()),
    )
    .and_then(|s| s.into_group(&charly_provider))
    .expect("charly join");

    // ---- Emulator group: alice_a creates, alice_b joins via Welcome ----
    let (mut emulator_a, alice_emulator_a_signer) =
        make_emulator_group(ciphersuite, &alice_a_provider, b"AliceEmulatorA");
    let (alice_emulator_b_credential, alice_emulator_b_signer) = new_credential(
        &alice_b_provider,
        b"AliceEmulatorB",
        ciphersuite.signature_algorithm(),
    );
    let alice_emulator_b_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(
            ciphersuite,
            &alice_b_provider,
            &alice_emulator_b_signer,
            alice_emulator_b_credential,
        )
        .expect("alice_b emulator KP build")
        .key_package()
        .to_owned();
    let (_e_commit, e_welcome, _e_gi) = emulator_a
        .add_members(
            &alice_a_provider,
            &alice_emulator_a_signer,
            &[alice_emulator_b_kp],
        )
        .expect("emulator_a add alice_b");
    emulator_a
        .merge_pending_commit(&alice_a_provider)
        .expect("emulator_a merge add");

    let mut emulator_b = StagedWelcome::new_from_welcome(
        &alice_b_provider,
        &join_config,
        e_welcome.into_welcome().expect("emulator welcome"),
        Some(emulator_a.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&alice_b_provider))
    .expect("alice_b join emulator group");

    // ---- Both Alice clients independently register the same VC epoch ----
    let epoch_id_a = emulator_a
        .register_vc_emulation_epoch(alice_a_provider.crypto(), alice_a_provider.storage())
        .expect("alice_a register vc epoch");
    let epoch_id_b = emulator_b
        .register_vc_emulation_epoch(alice_b_provider.crypto(), alice_b_provider.storage())
        .expect("alice_b register vc epoch");
    assert_eq!(
        epoch_id_a, epoch_id_b,
        "deterministic derivation must yield the same EpochId on both Alice clients"
    );

    // ---- alice_b bootstraps into the higher-level group via VC resync
    // external commit. The auto-Remove targets alice_a's existing leaf
    // (same vc_signer). alice_a, bob, and charly process the commit and
    // converge.
    let verifiable_group_info = {
        let group_info_msg = alice_a_main
            .export_group_info(alice_a_provider.crypto(), &vc_signer, true)
            .expect("export group info");
        let serialized = group_info_msg
            .tls_serialize_detached()
            .expect("serialize group info");
        MlsMessageIn::tls_deserialize(&mut serialized.as_slice())
            .expect("deserialize group info message")
            .into_verifiable_group_info()
            .expect("into verifiable group info")
    };
    let (mut alice_b_main, bundle) = MlsGroup::external_commit_builder()
        .with_config(
            MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .build(),
        )
        .build_group(&alice_b_provider, verifiable_group_info, vc_credential)
        .expect("build_group")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(vc_capabilities())
                .with_extensions(vc_leaf_extensions())
                .build(),
        )
        .vc_emulation(
            alice_b_provider.crypto(),
            alice_b_provider.storage(),
            epoch_id_b.clone(),
        )
        .expect("vc emulation")
        .load_psks(alice_b_provider.storage())
        .expect("load psks")
        .build(
            alice_b_provider.rand(),
            alice_b_provider.crypto(),
            &vc_signer,
            |_| true,
        )
        .expect("build external commit")
        .finalize(&alice_b_provider)
        .expect("finalize external commit");
    let resync_commit = bundle.into_commit();
    for (group, provider) in [
        (&mut alice_a_main, &alice_a_provider),
        (&mut bob_main, &bob_provider),
        (&mut charly_main, &charly_provider),
    ] {
        let processed = group
            .process_message(
                provider,
                resync_commit.clone().into_protocol_message().unwrap(),
            )
            .expect("process resync commit");
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(s) => *s,
            _ => panic!("expected staged commit"),
        };
        group
            .merge_staged_commit(provider, staged)
            .expect("merge resync");
    }

    // Sanity: all four parties agree after the resync.
    fn assert_all_agree(groups: &[&MlsGroup], label: &str) {
        let mut iter = groups.iter();
        let reference = iter
            .next()
            .expect("at least one party")
            .epoch_authenticator();
        for group in iter {
            assert_eq!(
                group.epoch_authenticator(),
                reference,
                "epoch authenticator divergence at {label}"
            );
        }
    }

    let baseline_epoch = alice_a_main.epoch();
    assert_all_agree(
        &[&alice_a_main, &alice_b_main, &bob_main, &charly_main],
        "post resync",
    );

    // Helper: deliver one commit (already merged on the sender side) to a
    // single receiver group via the regular process path.
    fn deliver_commit<P: OpenMlsProvider>(
        receiver: &mut MlsGroup,
        provider: &P,
        commit_msg: &openmls::prelude::MlsMessageOut,
    ) {
        let processed = receiver
            .process_message(
                provider,
                commit_msg.clone().into_protocol_message().unwrap(),
            )
            .expect("process commit");
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(s) => *s,
            _ => panic!("expected staged commit"),
        };
        receiver
            .merge_staged_commit(provider, staged)
            .expect("merge staged commit");
    }

    // Helper: build a regular self-update commit on `sender_group`.
    fn build_regular_commit<P: OpenMlsProvider>(
        sender_group: &mut MlsGroup,
        provider: &P,
        signer: &SignatureKeyPair,
    ) -> openmls::prelude::MlsMessageOut {
        let bundle = sender_group
            .commit_builder()
            .force_self_update(true)
            .load_psks(provider.storage())
            .expect("load psks")
            .build(provider.rand(), provider.crypto(), signer, |_| true)
            .expect("build commit")
            .stage_commit(provider)
            .expect("stage commit");
        sender_group
            .merge_pending_commit(provider)
            .expect("sender merge");
        bundle.into_commit()
    }

    // ---- Commit 1: Bob's regular commit ----
    let bob_commit = build_regular_commit(&mut bob_main, &bob_provider, &bob_signer);
    deliver_commit(&mut alice_a_main, &alice_a_provider, &bob_commit);
    deliver_commit(&mut alice_b_main, &alice_b_provider, &bob_commit);
    deliver_commit(&mut charly_main, &charly_provider, &bob_commit);
    assert_all_agree(
        &[&alice_a_main, &alice_b_main, &bob_main, &charly_main],
        "post Bob commit",
    );

    // ---- Commit 2: Charly's regular commit ----
    let charly_commit = build_regular_commit(&mut charly_main, &charly_provider, &charly_signer);
    deliver_commit(&mut alice_a_main, &alice_a_provider, &charly_commit);
    deliver_commit(&mut alice_b_main, &alice_b_provider, &charly_commit);
    deliver_commit(&mut bob_main, &bob_provider, &charly_commit);
    assert_all_agree(
        &[&alice_a_main, &alice_b_main, &bob_main, &charly_main],
        "post Charly commit",
    );

    // ---- Commit 3: alice_a's VC commit ----
    // alice_a's first own LeafNode operation on this emulation epoch
    // consumes generation 0 of her emulation-leaf ratchet.
    let alice_a_vc_commit = send_vc_commit_with_epoch(
        &mut alice_a_main,
        &alice_a_provider,
        &vc_signer,
        epoch_id_a.clone(),
    );
    // alice_b processes via the own-leaf VC path, deriving generation 0 of
    // alice_a's ratchet positionally.
    deliver_commit(&mut alice_b_main, &alice_b_provider, &alice_a_vc_commit);
    // Bob and Charly process via the normal HPKE path.
    deliver_commit(&mut bob_main, &bob_provider, &alice_a_vc_commit);
    deliver_commit(&mut charly_main, &charly_provider, &alice_a_vc_commit);
    assert_all_agree(
        &[&alice_a_main, &alice_b_main, &bob_main, &charly_main],
        "post alice_a VC commit",
    );

    // ---- Commit 4: alice_b's VC commit ----
    let alice_b_vc_commit = send_vc_commit_with_epoch(
        &mut alice_b_main,
        &alice_b_provider,
        &vc_signer,
        epoch_id_b.clone(),
    );
    // alice_a processes via the own-leaf VC path.
    deliver_commit(&mut alice_a_main, &alice_a_provider, &alice_b_vc_commit);
    // Bob and Charly process via the normal HPKE path.
    deliver_commit(&mut bob_main, &bob_provider, &alice_b_vc_commit);
    deliver_commit(&mut charly_main, &charly_provider, &alice_b_vc_commit);
    assert_all_agree(
        &[&alice_a_main, &alice_b_main, &bob_main, &charly_main],
        "post alice_b VC commit",
    );

    // ---- Commit 5: alice_a's second VC commit on the same emulation
    // epoch. alice_b already derived generation 0 of alice_a's ratchet for
    // commit 3, so she now derives generation 1 positionally. This is the
    // behavioral check that two successive VC commits from the same
    // emulation epoch consume successive generations.
    let alice_a_second_vc_commit = send_vc_commit_with_epoch(
        &mut alice_a_main,
        &alice_a_provider,
        &vc_signer,
        epoch_id_a.clone(),
    );
    deliver_commit(
        &mut alice_b_main,
        &alice_b_provider,
        &alice_a_second_vc_commit,
    );
    deliver_commit(&mut bob_main, &bob_provider, &alice_a_second_vc_commit);
    deliver_commit(
        &mut charly_main,
        &charly_provider,
        &alice_a_second_vc_commit,
    );
    assert_all_agree(
        &[&alice_a_main, &alice_b_main, &bob_main, &charly_main],
        "post alice_a second VC commit",
    );

    // After five commits, the epoch counter has advanced by 5 from the
    // post-resync baseline.
    assert_eq!(
        alice_a_main.epoch().as_u64(),
        baseline_epoch.as_u64() + 5,
        "expected five-epoch advance across the five commits"
    );
}

/// Sibling-resync via VC external commit:
///
///   * `alice_a` is the existing emulator client in the higher-level group
///     (with bob). `alice_b` is a fresh emulator client that joins the
///     emulation group of `alice_a` via Welcome but has no higher-level
///     group state.
///   * Both alice clients register the same emulation epoch on their copy
///     of the emulator group (deterministic derivation from
///     `safe_export_secret(VC_COMPONENT_ID)`).
///   * `alice_b` joins the higher-level group via an external commit signed
///     by the virtual client's shared signature key. The auto-Remove
///     machinery in `build_group` picks up `alice_a`'s existing leaf
///     (same signature key) and inlines a `Remove` for it. `alice_b`
///     attaches a `vc_emulation(.., epoch_id)` so the path leaf
///     is derived from the per-commit `OperationSecret`.
///   * `alice_a` processes the external commit. The sibling-resync
///     discriminator (registered VC epoch state + `NewMemberCommit` sender
///     + `Remove(self)` in the queue) triggers: she derives the path from
///     her operation secret tree, skips the `self_removed` short-circuit,
///     and after merging
///     her `own_leaf_index` points at the joiner's new leaf. She remains
///     active.
///   * `bob` processes the same commit via the regular HPKE path.
///   * Followup commits from both `alice_b` (own-leaf VC, processed by
///     `alice_a`) and `bob` (HPKE, processed by both alices) converge.
#[openmls_test]
fn vc_sibling_emulator_resyncs_into_higher_level_group_via_external_commit() {
    use openmls::credentials::{BasicCredential, CredentialWithKey};
    use openmls::prelude::{LeafNodeParameters, MlsMessageIn};
    use tls_codec::Deserialize as _;

    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();

    // The virtual client's shared signature key + credential. Both
    // emulator clients have a copy of the signing key in their own
    // provider storage, so either can sign for the shared higher-level leaf.
    let vc_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("vc signer");
    vc_signer
        .store(alice_a_provider.storage())
        .expect("store vc signer on alice_a");
    vc_signer
        .store(alice_b_provider.storage())
        .expect("store vc signer on alice_b");
    let vc_credential = CredentialWithKey {
        credential: BasicCredential::new(b"Alice (VC)".to_vec()).into(),
        signature_key: vc_signer.public().into(),
    };

    // Emulator group: alice_a creates, adds alice_b via Welcome.
    let (mut emulator_a, alice_emulator_a_signer) =
        make_emulator_group(ciphersuite, &alice_a_provider, b"AliceEmulatorA");
    let (alice_emulator_b_credential, alice_emulator_b_signer) = new_credential(
        &alice_b_provider,
        b"AliceEmulatorB",
        ciphersuite.signature_algorithm(),
    );
    let alice_emulator_b_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(
            ciphersuite,
            &alice_b_provider,
            &alice_emulator_b_signer,
            alice_emulator_b_credential,
        )
        .expect("alice_b emulator KP build")
        .key_package()
        .to_owned();
    let (_, e_welcome, _) = emulator_a
        .add_members(
            &alice_a_provider,
            &alice_emulator_a_signer,
            &[alice_emulator_b_kp],
        )
        .expect("emulator_a add alice_b");
    emulator_a
        .merge_pending_commit(&alice_a_provider)
        .expect("emulator_a merge add");

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let mut emulator_b = StagedWelcome::new_from_welcome(
        &alice_b_provider,
        &join_config,
        e_welcome.into_welcome().expect("welcome"),
        Some(emulator_a.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&alice_b_provider))
    .expect("alice_b join emulator group");

    // Higher-level group: alice_a creates as the sole VC member,
    // signing with the VC's shared signer. Adds bob via Welcome.
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions on higher-level config")
        .build();
    let mut alice_a_main = MlsGroup::new(
        &alice_a_provider,
        &vc_signer,
        &group_config,
        vc_credential.clone(),
    )
    .expect("alice_a create higher-level group");

    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let bob_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    let (_, welcome, _) = alice_a_main
        .add_members(&alice_a_provider, &vc_signer, &[bob_kp])
        .expect("alice_a add bob");
    alice_a_main
        .merge_pending_commit(&alice_a_provider)
        .expect("alice_a merge add");
    let mut bob_main = StagedWelcome::new_from_welcome(
        &bob_provider,
        &join_config,
        welcome.into_welcome().expect("welcome"),
        Some(alice_a_main.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob join higher-level group");

    // Both alice clients register the same VC emulation epoch.
    let epoch_id_a = emulator_a
        .register_vc_emulation_epoch(alice_a_provider.crypto(), alice_a_provider.storage())
        .expect("alice_a register vc epoch");
    let epoch_id_b = emulator_b
        .register_vc_emulation_epoch(alice_b_provider.crypto(), alice_b_provider.storage())
        .expect("alice_b register vc epoch");
    assert_eq!(
        epoch_id_a, epoch_id_b,
        "deterministic derivation must yield the same EpochId on both Alice clients"
    );

    // alice_a exports the higher-level group's VerifiableGroupInfo for
    // alice_b's external commit.
    let verifiable_group_info = {
        let group_info_msg = alice_a_main
            .export_group_info(alice_a_provider.crypto(), &vc_signer, true)
            .expect("export group info");
        let serialized = group_info_msg
            .tls_serialize_detached()
            .expect("serialize group info");
        MlsMessageIn::tls_deserialize(&mut serialized.as_slice())
            .expect("deserialize group info message")
            .into_verifiable_group_info()
            .expect("into verifiable group info")
    };

    // alice_b builds the resync external commit. The auto-Remove
    // machinery picks up alice_a's existing leaf (same signature key)
    // and inlines a Remove for it.
    let (mut alice_b_main, bundle) = MlsGroup::external_commit_builder()
        .with_config(
            MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .use_ratchet_tree_extension(true)
                .build(),
        )
        .build_group(&alice_b_provider, verifiable_group_info, vc_credential)
        .expect("build_group")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(vc_capabilities())
                .with_extensions(vc_leaf_extensions())
                .build(),
        )
        .vc_emulation(
            alice_b_provider.crypto(),
            alice_b_provider.storage(),
            epoch_id_b.clone(),
        )
        .expect("vc emulation")
        .load_psks(alice_b_provider.storage())
        .expect("load psks")
        .build(
            alice_b_provider.rand(),
            alice_b_provider.crypto(),
            &vc_signer,
            |_| true,
        )
        .expect("build external commit")
        .finalize(&alice_b_provider)
        .expect("finalize external commit");
    let commit_msg = bundle.into_commit();

    let new_leaf_index = alice_b_main.own_leaf_index();
    let new_epoch = alice_b_main.epoch();

    // alice_a processes the resync external commit via the sibling-VC path.
    {
        let processed = alice_a_main
            .process_message(
                &alice_a_provider,
                commit_msg.clone().into_protocol_message().unwrap(),
            )
            .expect("alice_a process resync external commit");
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(s) => *s,
            _ => panic!("expected staged commit"),
        };
        assert!(
            !staged.self_removed(),
            "sibling-resync external commit must not mark alice_a as self-removed"
        );
        alice_a_main
            .merge_staged_commit(&alice_a_provider, staged)
            .expect("alice_a merge resync");
    }
    assert!(alice_a_main.is_active(), "alice_a must stay active");
    assert_eq!(alice_a_main.epoch(), new_epoch);
    assert_eq!(
        alice_a_main.own_leaf_index(),
        new_leaf_index,
        "alice_a's own_leaf_index must point to the joiner's new leaf"
    );
    assert_eq!(
        alice_a_main.epoch_authenticator(),
        alice_b_main.epoch_authenticator(),
        "alice_a and alice_b must agree on the epoch authenticator"
    );

    // bob processes via the normal HPKE path.
    {
        let processed = bob_main
            .process_message(&bob_provider, commit_msg.into_protocol_message().unwrap())
            .expect("bob process resync external commit");
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(s) => *s,
            _ => panic!("expected staged commit"),
        };
        bob_main
            .merge_staged_commit(&bob_provider, staged)
            .expect("bob merge resync");
    }
    assert_eq!(
        bob_main.epoch_authenticator(),
        alice_a_main.epoch_authenticator()
    );

    let mut reloaded_alice_a = MlsGroup::load(alice_a_provider.storage(), alice_a_main.group_id())
        .expect("reload alice_a after resync")
        .expect("alice_a group present after resync");
    assert_eq!(
        reloaded_alice_a.own_leaf_index(),
        new_leaf_index,
        "resync must persist alice_a's new own_leaf_index"
    );

    // alice_a must be able to send from the leaf installed by the resync.
    // This exercises the SecretTree own-ratchet index, not just epoch
    // authenticator convergence.
    let alice_a_app = reloaded_alice_a
        .create_message(&alice_a_provider, &vc_signer, b"alice_a after resync")
        .expect("alice_a create app message after resync");
    for (group, provider) in [
        (&mut alice_b_main, &alice_b_provider),
        (&mut bob_main, &bob_provider),
    ] {
        let processed = group
            .process_message(
                provider,
                alice_a_app.clone().into_protocol_message().unwrap(),
            )
            .expect("process alice_a app message after resync");
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            panic!("expected application message");
        };
        assert_eq!(message.into_bytes(), b"alice_a after resync");
    }

    // Followup VC commit from alice_b. alice_a now processes via the
    // own-leaf VC path because both Alice clients share `own_leaf_index`.
    // Bob processes via HPKE.
    let alice_b_followup = send_vc_commit_with_epoch(
        &mut alice_b_main,
        &alice_b_provider,
        &vc_signer,
        epoch_id_b.clone(),
    );
    for (group, provider) in [
        (&mut alice_a_main, &alice_a_provider),
        (&mut bob_main, &bob_provider),
    ] {
        let processed = group
            .process_message(
                provider,
                alice_b_followup.clone().into_protocol_message().unwrap(),
            )
            .expect("process alice_b followup");
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(s) => *s,
            _ => panic!("expected staged commit"),
        };
        group
            .merge_staged_commit(provider, staged)
            .expect("merge alice_b followup");
    }
    assert_eq!(
        alice_a_main.epoch_authenticator(),
        alice_b_main.epoch_authenticator()
    );
    assert_eq!(
        bob_main.epoch_authenticator(),
        alice_a_main.epoch_authenticator()
    );

    // Followup regular commit from bob. Both Alice clients process via HPKE.
    let bob_followup = {
        let bundle = bob_main
            .commit_builder()
            .force_self_update(true)
            .load_psks(bob_provider.storage())
            .expect("load psks")
            .build(
                bob_provider.rand(),
                bob_provider.crypto(),
                &bob_signer,
                |_| true,
            )
            .expect("build")
            .stage_commit(&bob_provider)
            .expect("stage");
        bob_main
            .merge_pending_commit(&bob_provider)
            .expect("bob merge own");
        bundle.into_commit()
    };
    for (group, provider) in [
        (&mut alice_a_main, &alice_a_provider),
        (&mut alice_b_main, &alice_b_provider),
    ] {
        let processed = group
            .process_message(
                provider,
                bob_followup.clone().into_protocol_message().unwrap(),
            )
            .expect("process bob followup");
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(s) => *s,
            _ => panic!("expected staged commit"),
        };
        group
            .merge_staged_commit(provider, staged)
            .expect("merge bob followup");
    }
    assert_eq!(
        alice_a_main.epoch_authenticator(),
        alice_b_main.epoch_authenticator()
    );
    assert_eq!(
        bob_main.epoch_authenticator(),
        alice_a_main.epoch_authenticator()
    );
}

/// A sibling emulator joins a higher-level group via a virtual client's
/// KeyPackage that another emulator published.
///
///   * `alice_a` and `alice_b` share an emulator group and both register the
///     same emulation epoch, so both hold its `EmulationEpochState` and
///     `OperationSecretTree`.
///   * `alice_a` builds a one-KeyPackage batch with `build_vc_batch`
///     (consuming generation 0 of its `key_package` operation ratchet) and
///     hands the resulting `KeyPackageUpload` to `alice_b`, who stores a
///     `RetainedKeyPackageMaterial` per ref via
///     `process_vc_key_package_upload`.
///   * An ordinary MLS client, `bob`, founds a higher-level group and adds the
///     virtual client using that KeyPackage, producing a Welcome and ratchet
///     tree.
///   * `alice_b` (the *sibling*, not the KeyPackage's creator) processes the
///     Welcome: the first stage rederives the init key from the operation tree
///     to decrypt the group secrets, then staging locates and validates its
///     own leaf via the derivation info and the derived encryption key.
///   * `alice_b` joins as the virtual client at the expected leaf, and an
///     application message round-trips between `bob` and `alice_b`.
#[openmls_test]
fn vc_sibling_joins_higher_level_group_via_key_package_welcome() {
    use openmls::components::vc_derivation_info::{
        assemble_vc_key_package_upload, process_vc_key_package_upload,
    };

    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();

    // Shared virtual-client signer + credential, held by both emulator
    // clients so either could sign for the shared higher-level leaf.
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    // Emulator group: alice_a creates, alice_b joins via Welcome.
    let (mut emulator_a, emulator_a_signer) =
        make_emulator_group(ciphersuite, &alice_a_provider, b"AliceEmulatorA");
    let (emulator_b_credential, emulator_b_signer) = new_credential(
        &alice_b_provider,
        b"AliceEmulatorB",
        ciphersuite.signature_algorithm(),
    );
    let emulator_b_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(
            ciphersuite,
            &alice_b_provider,
            &emulator_b_signer,
            emulator_b_credential,
        )
        .expect("emulator_b KP build")
        .key_package()
        .to_owned();
    let (_e_commit, e_welcome, _e_gi) = emulator_a
        .add_members(&alice_a_provider, &emulator_a_signer, &[emulator_b_kp])
        .expect("emulator_a add alice_b");
    emulator_a
        .merge_pending_commit(&alice_a_provider)
        .expect("emulator_a merge add");
    let mut emulator_b = StagedWelcome::new_from_welcome(
        &alice_b_provider,
        &vc_join_config(),
        e_welcome.into_welcome().expect("emulator welcome"),
        Some(emulator_a.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&alice_b_provider))
    .expect("alice_b join emulator group");

    // Both emulators register the same emulation epoch.
    let epoch_id_a = emulator_a
        .register_vc_emulation_epoch(alice_a_provider.crypto(), alice_a_provider.storage())
        .expect("alice_a register vc epoch");
    let epoch_id_b = emulator_b
        .register_vc_emulation_epoch(alice_b_provider.crypto(), alice_b_provider.storage())
        .expect("alice_b register vc epoch");
    assert_eq!(
        epoch_id_a, epoch_id_b,
        "siblings must derive the same EpochId"
    );

    // alice_a publishes a virtual-client KeyPackage and hands the upload to
    // alice_b. alice_b only learns about the KeyPackage through the upload, it
    // never stores the bundle.
    let mut batch = KeyPackage::builder()
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build_vc_batch(
            ciphersuite,
            &alice_a_provider,
            &vc_signer,
            vc_credential.clone(),
            epoch_id_a.clone(),
            1,
        )
        .expect("alice_a build_vc_batch");
    let generation = batch.generation;
    let (vc_key_package_bundle, kp_info) = batch.key_packages.remove(0);
    let upload = assemble_vc_key_package_upload(
        alice_a_provider.storage(),
        epoch_id_a.clone(),
        generation,
        vec![kp_info],
    )
    .expect("assemble upload");
    process_vc_key_package_upload(&alice_b_provider, &upload).expect("alice_b process upload");

    // Bob founds a higher-level group and adds the virtual client via the
    // published KeyPackage.
    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let bob_group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();
    let mut bob_main = MlsGroup::new(
        &bob_provider,
        &bob_signer,
        &bob_group_config,
        bob_credential,
    )
    .expect("bob create higher-level group");
    let (_commit, welcome, _gi) = bob_main
        .add_members(
            &bob_provider,
            &bob_signer,
            &[vc_key_package_bundle.key_package().clone()],
        )
        .expect("bob add virtual client");
    bob_main
        .merge_pending_commit(&bob_provider)
        .expect("bob merge add");
    let ratchet_tree = bob_main.export_ratchet_tree();

    // alice_b, the sibling that only holds the RetainedKeyPackageMaterial,
    // processes the Welcome and joins as the virtual client.
    let processed = openmls::group::ProcessedWelcome::new_from_welcome(
        &alice_b_provider,
        &vc_join_config(),
        welcome.into_welcome().expect("welcome present"),
    )
    .expect("alice_b process welcome");
    let mut alice_b_main = processed
        .into_staged_welcome(&alice_b_provider, Some(ratchet_tree.into()))
        .expect("alice_b stage welcome")
        .into_group(&alice_b_provider)
        .expect("alice_b join higher-level group");

    // alice_b's leaf carries the virtual client's signature key.
    let vc_signature_key = vc_signer.public().to_vec();
    let own_member = alice_b_main
        .members()
        .find(|m| m.index == alice_b_main.own_leaf_index())
        .expect("own member present");
    assert_eq!(
        own_member.signature_key, vc_signature_key,
        "alice_b's joined leaf must carry the virtual client's signature key"
    );
    assert_eq!(
        bob_main.epoch_authenticator(),
        alice_b_main.epoch_authenticator(),
        "bob and the joined virtual client must agree on the epoch"
    );

    // An application message round-trips both ways.
    let to_vc = send_and_process_app_message(
        &mut bob_main,
        &bob_provider,
        &bob_signer,
        &mut alice_b_main,
        &alice_b_provider,
        b"hello virtual client",
    );
    match to_vc.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => {
            assert_eq!(msg.into_bytes().as_slice(), b"hello virtual client");
        }
        _ => panic!("expected application message from bob"),
    }
    let from_vc = send_and_process_app_message(
        &mut alice_b_main,
        &alice_b_provider,
        &vc_signer,
        &mut bob_main,
        &bob_provider,
        b"hello bob",
    );
    match from_vc.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => {
            assert_eq!(msg.into_bytes().as_slice(), b"hello bob");
        }
        _ => panic!("expected application message from virtual client"),
    }
}

/// Regression test for the batch-model switch. A virtual client builds one
/// batch of KeyPackages larger than the operation tree's
/// `OUT_OF_ORDER_TOLERANCE` (32), so the old per-KeyPackage-generation model
/// would have evicted the lowest generations before they could be used at
/// Welcome time. The sibling then joins two separate higher-level groups via
/// KeyPackages from that batch, picking a HIGH batch index first and a LOW one
/// second. Both joins must succeed because the batch shares a single
/// generation and every per-index seed is pinned in the retained material at
/// upload-processing time, independent of Welcome order.
#[openmls_test]
fn vc_batch_key_packages_join_in_any_order() {
    use openmls::components::vc_derivation_info::{
        assemble_vc_key_package_upload, process_vc_key_package_upload,
    };

    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();

    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    // Emulator group: alice_a creates, alice_b joins via Welcome.
    let (mut emulator_a, emulator_a_signer) =
        make_emulator_group(ciphersuite, &alice_a_provider, b"AliceEmulatorA");
    let (emulator_b_credential, emulator_b_signer) = new_credential(
        &alice_b_provider,
        b"AliceEmulatorB",
        ciphersuite.signature_algorithm(),
    );
    let emulator_b_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(
            ciphersuite,
            &alice_b_provider,
            &emulator_b_signer,
            emulator_b_credential,
        )
        .expect("emulator_b KP build")
        .key_package()
        .to_owned();
    let (_e_commit, e_welcome, _e_gi) = emulator_a
        .add_members(&alice_a_provider, &emulator_a_signer, &[emulator_b_kp])
        .expect("emulator_a add alice_b");
    emulator_a
        .merge_pending_commit(&alice_a_provider)
        .expect("emulator_a merge add");
    let mut emulator_b = StagedWelcome::new_from_welcome(
        &alice_b_provider,
        &vc_join_config(),
        e_welcome.into_welcome().expect("emulator welcome"),
        Some(emulator_a.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&alice_b_provider))
    .expect("alice_b join emulator group");

    let epoch_id_a = emulator_a
        .register_vc_emulation_epoch(alice_a_provider.crypto(), alice_a_provider.storage())
        .expect("alice_a register vc epoch");
    let epoch_id_b = emulator_b
        .register_vc_emulation_epoch(alice_b_provider.crypto(), alice_b_provider.storage())
        .expect("alice_b register vc epoch");
    assert_eq!(
        epoch_id_a, epoch_id_b,
        "siblings must derive the same EpochId"
    );

    // One batch of 40 KeyPackages, larger than OUT_OF_ORDER_TOLERANCE (32).
    let count: u32 = 40;
    let batch = KeyPackage::builder()
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build_vc_batch(
            ciphersuite,
            &alice_a_provider,
            &vc_signer,
            vc_credential.clone(),
            epoch_id_a.clone(),
            count,
        )
        .expect("alice_a build_vc_batch");
    let generation = batch.generation;
    assert_eq!(generation, 0, "the batch consumes a single generation");
    assert_eq!(batch.key_packages.len(), count as usize);

    let kp_infos = batch
        .key_packages
        .iter()
        .map(|(_bundle, info)| info)
        .map(
            |info| openmls::components::vc_derivation_info::KeyPackageInfo {
                key_package_ref: info.key_package_ref.clone(),
                key_package_index: info.key_package_index,
            },
        )
        .collect::<Vec<_>>();
    let upload = assemble_vc_key_package_upload(
        alice_a_provider.storage(),
        epoch_id_a.clone(),
        generation,
        kp_infos,
    )
    .expect("assemble upload");
    process_vc_key_package_upload(&alice_b_provider, &upload).expect("alice_b process upload");

    // The sibling joins via a HIGH batch index first and a LOW one second,
    // each through a separate higher-level group.
    let high_bundle = batch.key_packages[(count - 1) as usize]
        .0
        .key_package()
        .clone();
    let low_bundle = batch.key_packages[0].0.key_package().clone();

    for (label, kp) in [
        (b"BobHigh".as_slice(), high_bundle),
        (b"BobLow".as_slice(), low_bundle),
    ] {
        let bob_provider = Provider::default();
        let (bob_credential, bob_signer) =
            new_credential(&bob_provider, label, ciphersuite.signature_algorithm());
        let bob_group_config = MlsGroupCreateConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .build();
        let mut bob_main = MlsGroup::new(
            &bob_provider,
            &bob_signer,
            &bob_group_config,
            bob_credential,
        )
        .expect("bob create higher-level group");
        let (_commit, welcome, _gi) = bob_main
            .add_members(&bob_provider, &bob_signer, &[kp])
            .expect("bob add virtual client");
        bob_main
            .merge_pending_commit(&bob_provider)
            .expect("bob merge add");
        let ratchet_tree = bob_main.export_ratchet_tree();

        let processed = openmls::group::ProcessedWelcome::new_from_welcome(
            &alice_b_provider,
            &vc_join_config(),
            welcome.into_welcome().expect("welcome present"),
        )
        .expect("alice_b process welcome");
        let alice_b_main = processed
            .into_staged_welcome(&alice_b_provider, Some(ratchet_tree.into()))
            .expect("alice_b stage welcome")
            .into_group(&alice_b_provider)
            .expect("alice_b join higher-level group");

        assert_eq!(
            bob_main.epoch_authenticator(),
            alice_b_main.epoch_authenticator(),
            "bob and the joined virtual client must agree on the epoch"
        );
    }
}

#[openmls_test::openmls_test]
fn processing_own_application_message() {
    let alice_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential.clone())
        .expect("An unexpected error occurred.");

    // Alice sends an application message and decrypts it herself
    let alice_message = b"Hello, this is Alice!";
    let unconfirmed = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, alice_message)
        .unwrap();
    assert!(
        unconfirmed.generation_id.is_none(),
        "a group with no emulation binding must not produce a generation id"
    );
    let ciphertext = unconfirmed.message;

    let processed_message = alice_group
        .process_message(
            alice_provider,
            ciphertext.clone().into_protocol_message().unwrap(),
        )
        .unwrap();

    let ProcessedMessageContent::ApplicationMessage(msg) = processed_message.into_content() else {
        panic!("Expected an application message.");
    };
    assert!(alice_message.as_slice() == msg.into_bytes().as_slice());

    // Processing the message again cannot decrypt it because the generation
    // has already been consumed. In a group without virtual clients this
    // surfaces as OwnPrivateMessage.
    let processed_message = alice_group
        .process_message(alice_provider, ciphertext.into_protocol_message().unwrap())
        .expect("Expected processing the same message again to succeed.");
    assert!(matches!(
        processed_message.into_content(),
        ProcessedMessageContent::OwnPrivateMessage
    ));

    // Alice sends another application message and confirms it. Its secret is
    // deleted, so processing it also surfaces as OwnPrivateMessage.
    let alice_message = b"Hello, this is Alice again!";
    let unconfirmed = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, alice_message)
        .unwrap();
    let ciphertext = unconfirmed.message;
    alice_group
        .confirm_message(alice_provider.storage(), unconfirmed.generation)
        .unwrap();

    let processed_message = alice_group
        .process_message(
            alice_provider,
            ciphertext.clone().into_protocol_message().unwrap(),
        )
        .expect("Expected processing a confirmed message to succeed.");
    assert!(matches!(
        processed_message.into_content(),
        ProcessedMessageContent::OwnPrivateMessage
    ));
}

#[openmls_test::openmls_test]
fn unconfirmed_message_decrypts_after_next_message_is_confirmed() {
    let alice_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential)
        .expect("An unexpected error occurred.");

    let first_message = b"first unconfirmed message";
    let first = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, first_message)
        .expect("Could not create first unconfirmed message.");
    assert_eq!(first.generation, 0);

    let second_message = b"second confirmed message";
    let second = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, second_message)
        .expect("Could not create second message.");
    assert_eq!(second.generation, 1);
    alice_group
        .confirm_message(alice_provider.storage(), second.generation)
        .expect("Could not confirm second message.");

    let processed_message = alice_group
        .process_message(
            alice_provider,
            first.message.into_protocol_message().unwrap(),
        )
        .expect("Expected first unconfirmed message to decrypt.");

    let ProcessedMessageContent::ApplicationMessage(msg) = processed_message.into_content() else {
        panic!("Expected an application message.");
    };
    assert_eq!(first_message.as_slice(), msg.into_bytes().as_slice());
}

#[openmls_test::openmls_test]
fn old_unconfirmed_own_message_survives_later_confirmations() {
    let alice_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential)
        .expect("An unexpected error occurred.");

    let first_message = b"first unconfirmed message";
    let first = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, first_message)
        .expect("Could not create first unconfirmed message.");

    let tolerance = alice_group
        .configuration()
        .sender_ratchet_configuration()
        .out_of_order_tolerance();

    for i in 0..tolerance + 2 {
        let later = alice_group
            .create_unconfirmed_message(
                alice_provider,
                &alice_signer,
                format!("later confirmed message {i}").as_bytes(),
            )
            .expect("Could not create later unconfirmed message.");
        alice_group
            .confirm_message(alice_provider.storage(), later.generation)
            .expect("Could not confirm later message.");
    }

    let processed_message = alice_group
        .process_message(
            alice_provider,
            first.message.into_protocol_message().unwrap(),
        )
        .expect("Expected old unconfirmed own message to decrypt.");

    let ProcessedMessageContent::ApplicationMessage(msg) = processed_message.into_content() else {
        panic!("Expected an application message.");
    };
    assert_eq!(first_message.as_slice(), msg.into_bytes().as_slice());
}

/// End-to-end recipient-side reuse-guard inversion across two sibling
/// emulators. The receiving sibling is a genuinely separate client: it joins
/// the emulation group and resyncs into the higher-level group via an
/// external commit, with no storage cloning.
#[openmls_test::openmls_test]
fn reuse_guard_recovers_emulator_leaf_index() {
    let _ = ciphersuite;
    let ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let alice_a_provider = OpenMlsRustCrypto::default();
    let alice_b_provider = OpenMlsRustCrypto::default();
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    let mut alice_a_main = new_vc_main_group(
        ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential.clone(),
    );

    let (sib, resync_commit) = join_sibling_emulator(
        ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
        &vc_signer,
        vc_credential,
        &alice_a_main,
        vc_join_config(),
    );
    let SiblingEmulators {
        emulator_a,
        mut alice_b_main,
        ..
    } = sib;
    // alice_a processes the resync and converges on the shared VC leaf.
    process_and_merge_commit(&mut alice_a_main, &alice_a_provider, resync_commit);

    // alice_a is emulation leaf 0; its reuse guard must resolve to it.
    let expected_emulation_leaf = emulator_a.own_leaf_index();

    // alice_a sends an application message; alice_b recovers alice_a's
    // emulation leaf index from the reuse guard.
    let plaintext = b"reuse-guard recovery payload";
    let processed_app = send_and_process_app_message(
        &mut alice_a_main,
        &alice_a_provider,
        &vc_signer,
        &mut alice_b_main,
        &alice_b_provider,
        plaintext,
    );

    assert_eq!(
        processed_app.emulator_sender_leaf_index(),
        Some(expected_emulation_leaf),
    );
    match processed_app.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => {
            assert_eq!(msg.into_bytes().as_slice(), plaintext);
        }
        _ => panic!("expected application message"),
    }
}

/// A group with no emulation binding returns `None` from
/// `emulator_sender_leaf_index` on application messages.
#[openmls_test::openmls_test]
fn emulator_sender_leaf_index_none_without_binding() {
    let alice_provider = Provider::default();
    let bob_provider = Provider::default();
    let (mut alice, _alice_signer, mut bob, bob_signer) =
        setup_alice_bob_group(ciphersuite, &alice_provider, &bob_provider);

    let plaintext = b"non-emulator application message";
    let bob_msg = bob
        .create_message(&bob_provider, &bob_signer, plaintext)
        .expect("bob creates application message");

    let processed = alice
        .process_message(&alice_provider, bob_msg.into_protocol_message().unwrap())
        .expect("alice processes bob's application message");

    assert_eq!(processed.emulator_sender_leaf_index(), None);
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => {
            assert_eq!(msg.into_bytes().as_slice(), plaintext);
        }
        _ => panic!("expected application message"),
    }
}

/// A higher-level group with an emulation binding must not send with a
/// random reuse guard if the bound emulation state is missing.
#[test]
fn bound_group_fails_closed_when_emulation_state_missing_on_send() {
    let ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) =
        new_credential(&provider, b"Alice", ciphersuite.signature_algorithm());

    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    let mut alice_group = MlsGroup::new(&provider, &alice_signer, &group_config, alice_credential)
        .expect("create alice group");
    let (mut emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, &provider, b"AliceEmulator");

    let (_commit_msg, epoch_id) = send_vc_commit(
        &mut alice_group,
        &mut emulator_group,
        &provider,
        &alice_signer,
    );
    let deleted = provider
        .storage()
        .delete_vc_emulation_state_if_unreferenced(&epoch_id)
        .expect("delete emulation state");
    assert!(
        deleted,
        "no retained material, so the epoch state is deleted"
    );

    let err = alice_group
        .create_message(&provider, &alice_signer, b"must not send")
        .expect_err("bound group without emulation state must fail closed");

    assert!(
        matches!(
            err,
            openmls::group::CreateMessageError::MessageEncryptionError(
                openmls::framing::errors::MessageEncryptionError::VirtualClientsError(
                    openmls::components::vc_derivation_info::VirtualClientsError::MissingEmulationEpochState
                )
            )
        ),
        "unexpected error: {err:?}"
    );
}

/// On a group bound to an emulation epoch, `create_unconfirmed_message`
/// returns a generation ID, and consecutive ratchet generations produce
/// distinct generation IDs.
#[test]
fn create_unconfirmed_message_returns_generation_id_when_bound() {
    let ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) =
        new_credential(&provider, b"Alice", ciphersuite.signature_algorithm());

    let mut alice_group =
        new_vc_main_group(ciphersuite, &provider, &alice_signer, alice_credential);
    let (mut emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, &provider, b"AliceEmulator");

    // Bind alice_group's current epoch to the emulation epoch.
    let _ = send_vc_commit(
        &mut alice_group,
        &mut emulator_group,
        &provider,
        &alice_signer,
    );

    let first = alice_group
        .create_unconfirmed_message(&provider, &alice_signer, b"first")
        .expect("create first unconfirmed message");
    let generation_id_first = first
        .generation_id
        .expect("a bound group must produce a generation id");
    assert_eq!(
        generation_id_first.as_slice().len(),
        ciphersuite.hash_length()
    );
    alice_group
        .confirm_message(provider.storage(), first.generation)
        .expect("confirm first message");

    let second = alice_group
        .create_unconfirmed_message(&provider, &alice_signer, b"second")
        .expect("create second unconfirmed message");
    let generation_id_second = second
        .generation_id
        .expect("a bound group must produce a generation id");

    assert_ne!(
        generation_id_first, generation_id_second,
        "distinct ratchet generations must yield distinct generation ids"
    );
}

/// `vc_emulation` validates the leaf configuration before allocating an
/// operation secret. A leaf that supports `AppDataDictionary` but does not
/// list `VC_COMPONENT_ID` is rejected at the builder step rather than at
/// `build`, so no generation is burned on this deterministic failure.
#[test]
fn vc_emulation_rejects_misconfigured_leaf_before_allocating() {
    let ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) =
        new_credential(&provider, b"Alice", ciphersuite.signature_algorithm());

    // The leaf advertises `AppDataDictionary` support but carries no
    // `AppComponents` entry, so `VC_COMPONENT_ID` is not listed.
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .build();
    let mut alice_group = MlsGroup::new(&provider, &alice_signer, &group_config, alice_credential)
        .expect("create alice group");
    let (mut emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, &provider, b"AliceEmulator");

    let epoch_id = emulator_group
        .register_vc_emulation_epoch(provider.crypto(), provider.storage())
        .expect("register vc epoch");

    let err = alice_group
        .commit_builder()
        .vc_emulation(provider.crypto(), provider.storage(), epoch_id)
        .expect_err("misconfigured leaf must be rejected at the builder step");

    assert!(
        matches!(
            err,
            openmls::group::CreateCommitError::VirtualClientsError(
                openmls::components::vc_derivation_info::VirtualClientsError::VcComponentNotListed
            )
        ),
        "unexpected error: {err:?}"
    );
}

/// End-to-end reuse-guard recovery with the emulator group and the
/// higher-level group on different ciphersuites with different AEAD key
/// lengths. The emulation epoch's AEAD and operation-tree material must
/// use the
/// emulation ciphersuite, while the generated update path remains in the
/// higher-level group's ciphersuite.
#[test]
fn reuse_guard_recovery_across_mismatched_ciphersuites() {
    let _ = pretty_env_logger::try_init();
    let higher_level_ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let emulator_ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    assert_ne!(higher_level_ciphersuite, emulator_ciphersuite);

    let alice_a_provider = OpenMlsRustCrypto::default();
    let alice_b_provider = OpenMlsRustCrypto::default();
    let (vc_signer, vc_credential) = shared_vc_identity(
        higher_level_ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
    );

    let mut alice_a_main = new_vc_main_group(
        higher_level_ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential.clone(),
    );

    // The emulation group runs a different ciphersuite from the higher-level
    // group, so the operation tree and reuse-guard PRP key are derived under
    // the emulation ciphersuite while the update path stays in the
    // higher-level ciphersuite.
    let (sib, resync_commit) = join_sibling_emulator(
        emulator_ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
        &vc_signer,
        vc_credential,
        &alice_a_main,
        vc_join_config(),
    );
    let SiblingEmulators {
        emulator_a,
        mut alice_b_main,
        ..
    } = sib;
    process_and_merge_commit(&mut alice_a_main, &alice_a_provider, resync_commit);

    let expected_emulation_leaf = emulator_a.own_leaf_index();

    let plaintext = b"mismatched-ciphersuite reuse-guard recovery payload";
    let processed_app = send_and_process_app_message(
        &mut alice_a_main,
        &alice_a_provider,
        &vc_signer,
        &mut alice_b_main,
        &alice_b_provider,
        plaintext,
    );

    assert_eq!(
        processed_app.emulator_sender_leaf_index(),
        Some(expected_emulation_leaf),
    );
    match processed_app.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => {
            assert_eq!(msg.into_bytes().as_slice(), plaintext);
        }
        _ => panic!("expected application message"),
    }
}

/// Process a commit on `receiver` and merge it.
fn process_and_merge_commit<P: OpenMlsProvider>(
    receiver: &mut MlsGroup,
    provider: &P,
    commit_msg: openmls::prelude::MlsMessageOut,
) {
    let processed = receiver
        .process_message(provider, commit_msg.into_protocol_message().unwrap())
        .expect("process commit");
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(s) => *s,
        _ => panic!("expected staged commit"),
    };
    receiver
        .merge_staged_commit(provider, staged)
        .expect("merge staged commit");
}

/// Emulation bindings are kept per higher-level epoch: a delayed application
/// message from a previous epoch is deprotected with the emulation epoch that
/// was bound when it was sent, even after a later VC commit re-bound the
/// group to a newer emulation epoch.
///
/// Setup mirrors `vc_two_alice_clients_in_group_with_bob_and_charly`: two
/// Alice clients share the main-group leaf and a two-member emulation group,
/// so the emulation group can advance epochs with commits the sibling
/// processes through its own leaf.
#[test]
fn vc_binding_is_kept_per_epoch_for_delayed_messages() {
    let ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let alice_a_provider = OpenMlsRustCrypto::default();
    let alice_b_provider = OpenMlsRustCrypto::default();
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    // Keep past epochs so the delayed message stays decryptable across the
    // second commit.
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(2)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    let mut alice_a_main = MlsGroup::new(
        &alice_a_provider,
        &vc_signer,
        &group_config,
        vc_credential.clone(),
    )
    .expect("alice_a create main group");
    let main_group_id = alice_a_main.group_id().clone();

    // alice_b joins the emulation group and resyncs into the higher-level
    // group. Its resync keeps two past epochs so it can still decrypt the
    // delayed message after the group advances.
    let (sib, resync_commit) = join_sibling_emulator(
        ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
        &vc_signer,
        vc_credential,
        &alice_a_main,
        MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(2)
            .build(),
    );
    let SiblingEmulators {
        mut emulator_a,
        emulator_a_signer,
        mut emulator_b,
        mut alice_b_main,
        epoch_id: epoch_id_one,
    } = sib;
    let expected_emulation_leaf = emulator_a.own_leaf_index();

    // ---- The resync is the first VC commit: it binds the new main-group
    // epoch to the first emulation epoch. alice_a converges by processing
    // it. ----
    process_and_merge_commit(&mut alice_a_main, &alice_a_provider, resync_commit);
    let first_bound_epoch = alice_a_main.epoch();

    // ---- Delayed message, sent in the first bound epoch but delivered
    // only after the second commit below. ----
    let plaintext = b"delayed across an epoch change";
    let delayed_msg = alice_a_main
        .create_message(&alice_a_provider, &vc_signer, plaintext)
        .expect("alice_a creates delayed application message");

    // ---- Advance the emulation group and register a second emulation
    // epoch on both emulator clients. ----
    let emulator_commit = {
        let bundle = emulator_a
            .commit_builder()
            .force_self_update(true)
            .load_psks(alice_a_provider.storage())
            .expect("load psks")
            .build(
                alice_a_provider.rand(),
                alice_a_provider.crypto(),
                &emulator_a_signer,
                |_| true,
            )
            .expect("build emulator commit")
            .stage_commit(&alice_a_provider)
            .expect("stage emulator commit");
        emulator_a
            .merge_pending_commit(&alice_a_provider)
            .expect("emulator_a merge");
        bundle.into_commit()
    };
    process_and_merge_commit(&mut emulator_b, &alice_b_provider, emulator_commit);

    let epoch_id_two = emulator_a
        .register_vc_emulation_epoch(alice_a_provider.crypto(), alice_a_provider.storage())
        .expect("register second vc epoch (alice_a)");
    let epoch_id_two_b = emulator_b
        .register_vc_emulation_epoch(alice_b_provider.crypto(), alice_b_provider.storage())
        .expect("register second vc epoch (alice_b)");
    assert_eq!(epoch_id_two, epoch_id_two_b);
    assert_ne!(epoch_id_one, epoch_id_two);

    // ---- Second VC commit: re-binds the group to the second emulation
    // epoch. ----
    let commit_two = send_vc_commit_with_epoch(
        &mut alice_a_main,
        &alice_a_provider,
        &vc_signer,
        epoch_id_two.clone(),
    );
    let second_bound_epoch = alice_a_main.epoch();
    process_and_merge_commit(&mut alice_b_main, &alice_b_provider, commit_two);

    // ---- Both bindings are recorded, each under its own epoch. ----
    let bindings: VcEmulationBindings = alice_b_provider
        .storage()
        .vc_emulation_bindings(&main_group_id)
        .expect("read emulation bindings")
        .expect("emulation bindings present");
    assert_eq!(bindings.get(first_bound_epoch), Some(&epoch_id_one));
    assert_eq!(bindings.get(second_bound_epoch), Some(&epoch_id_two));

    // ---- The delayed message is attributed via the first emulation
    // epoch's state. ----
    let processed_app = alice_b_main
        .process_message(
            &alice_b_provider,
            delayed_msg.into_protocol_message().unwrap(),
        )
        .expect("alice_b processes delayed application message");
    assert_eq!(
        processed_app.emulator_sender_leaf_index(),
        Some(expected_emulation_leaf),
    );
    match processed_app.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => {
            assert_eq!(msg.into_bytes().as_slice(), plaintext);
        }
        _ => panic!("expected application message"),
    }
}

/// A commit by another member leaves the virtual client's leaf untouched, so
/// the emulation binding of the previous epoch must carry forward to the new
/// epoch: the sender keeps deriving deterministic reuse guards and the
/// sibling keeps attributing them.
#[test]
fn vc_binding_carries_forward_across_foreign_commits() {
    let ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let alice_a_provider = OpenMlsRustCrypto::default();
    let alice_b_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    // alice (the virtual client) founds the group on the shared leaf and adds
    // Bob, a regular member.
    let mut alice_a_main = new_vc_main_group(
        ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential.clone(),
    );
    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let bob_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    let (_commit, welcome, _gi) = alice_a_main
        .add_members(&alice_a_provider, &vc_signer, &[bob_kp])
        .expect("alice add bob");
    alice_a_main
        .merge_pending_commit(&alice_a_provider)
        .expect("alice merge add");
    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &vc_join_config(),
        welcome.into_welcome().expect("welcome present"),
        Some(alice_a_main.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob join");

    // alice_b joins as a sibling emulator and resyncs into the group; alice_a
    // and Bob process the resync and converge on the new virtual-client leaf.
    let (sib, resync_commit) = join_sibling_emulator(
        ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
        &vc_signer,
        vc_credential,
        &alice_a_main,
        vc_join_config(),
    );
    let SiblingEmulators {
        emulator_a,
        mut alice_b_main,
        ..
    } = sib;
    let expected_emulation_leaf = emulator_a.own_leaf_index();
    process_and_merge_commit(&mut alice_a_main, &alice_a_provider, resync_commit.clone());
    process_and_merge_commit(&mut bob_group, &bob_provider, resync_commit);

    // ---- Bob commits; the VC leaf is untouched. ----
    let bob_commit = {
        let bundle = bob_group
            .commit_builder()
            .force_self_update(true)
            .load_psks(bob_provider.storage())
            .expect("load psks")
            .build(
                bob_provider.rand(),
                bob_provider.crypto(),
                &bob_signer,
                |_| true,
            )
            .expect("build bob commit")
            .stage_commit(&bob_provider)
            .expect("stage bob commit");
        bob_group
            .merge_pending_commit(&bob_provider)
            .expect("bob merge");
        bundle.into_commit()
    };
    process_and_merge_commit(&mut alice_a_main, &alice_a_provider, bob_commit.clone());
    process_and_merge_commit(&mut alice_b_main, &alice_b_provider, bob_commit);

    // ---- alice_a still derives deterministic reuse guards in the new epoch,
    // and the sibling still attributes them. ----
    let plaintext = b"carried-forward binding";
    let processed_app = send_and_process_app_message(
        &mut alice_a_main,
        &alice_a_provider,
        &vc_signer,
        &mut alice_b_main,
        &alice_b_provider,
        plaintext,
    );
    assert_eq!(
        processed_app.emulator_sender_leaf_index(),
        Some(expected_emulation_leaf),
    );
    match processed_app.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => {
            assert_eq!(msg.into_bytes().as_slice(), plaintext);
        }
        _ => panic!("expected application message"),
    }
}

/// A virtual client issues a Commit *without* an UpdatePath (an add-only
/// commit) and a sibling emulator client applies it.
///
///   * `alice_a` and `alice_b` are two emulator clients of one virtual client,
///     sharing a single leaf in a higher-level group that also contains `bob`.
///   * `alice_a` adds `charly` with `add_members_without_update`, producing a
///     commit with no UpdatePath. A Commit without an UpdatePath cannot
///     carry a virtual-clients `DerivationInfo`, so on shape alone it is
///     indistinguishable from `alice_a`'s own commit echoed back.
///   * `alice_b` (the sibling) processes it. Because the group's current epoch
///     is bound to the emulation epoch and `alice_b` holds no pending commit of
///     its own, the commit is recognized as a sibling's Commit without an
///     UpdatePath and staged as a regular commit rather than rejected as a
///     mismatched own commit. `bob` processes it through the ordinary path.
///   * All four parties converge on the same epoch authenticator, and an
///     application message round-trips from the new member to the sibling.
#[openmls_test]
fn vc_sibling_applies_commit_without_update_path() {
    use openmls::credentials::{BasicCredential, CredentialWithKey};

    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();
    let charly_provider = Provider::default();

    // The virtual client's shared signature key and credential, stored on both
    // emulator clients so either can sign for the shared higher-level leaf.
    let vc_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("vc signer");
    vc_signer
        .store(alice_a_provider.storage())
        .expect("store vc signer on alice_a");
    vc_signer
        .store(alice_b_provider.storage())
        .expect("store vc signer on alice_b");
    let vc_credential = CredentialWithKey {
        credential: BasicCredential::new(b"Alice (VC)".to_vec()).into(),
        signature_key: vc_signer.public().into(),
    };

    // alice_a founds the higher-level group and adds bob.
    let mut alice_a_main = new_vc_main_group(
        ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential.clone(),
    );
    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let bob_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    let (_, welcome, _) = alice_a_main
        .add_members(&alice_a_provider, &vc_signer, &[bob_kp])
        .expect("alice_a add bob");
    alice_a_main
        .merge_pending_commit(&alice_a_provider)
        .expect("alice_a merge add bob");
    let mut bob_main = StagedWelcome::new_from_welcome(
        &bob_provider,
        &vc_join_config(),
        welcome.into_welcome().expect("welcome"),
        Some(alice_a_main.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob join");

    // alice_b joins as a sibling emulator and resyncs into the higher-level
    // group, so both Alice clients share `own_leaf_index`.
    let (siblings, resync_commit) = join_sibling_emulator(
        ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
        &vc_signer,
        vc_credential,
        &alice_a_main,
        vc_join_config(),
    );
    let mut alice_b_main = siblings.alice_b_main;

    for (group, provider) in [
        (&mut alice_a_main, &alice_a_provider),
        (&mut bob_main, &bob_provider),
    ] {
        let processed = group
            .process_message(
                provider,
                resync_commit.clone().into_protocol_message().unwrap(),
            )
            .expect("process resync commit");
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(s) => *s,
            _ => panic!("expected staged commit"),
        };
        group
            .merge_staged_commit(provider, staged)
            .expect("merge resync commit");
    }
    assert_eq!(
        alice_a_main.own_leaf_index(),
        alice_b_main.own_leaf_index(),
        "both Alice clients must share the higher-level leaf"
    );

    // alice_a issues a Commit without an UpdatePath: an add-only commit for
    // charly.
    let (charly_credential, charly_signer) = new_credential(
        &charly_provider,
        b"Charly",
        ciphersuite.signature_algorithm(),
    );
    let charly_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(
            ciphersuite,
            &charly_provider,
            &charly_signer,
            charly_credential,
        )
        .expect("charly KP build")
        .key_package()
        .to_owned();
    let (commit, charly_welcome, _) = alice_a_main
        .add_members_without_update(&alice_a_provider, &vc_signer, &[charly_kp])
        .expect("alice_a add charly without an UpdatePath");
    let staged_pending = alice_a_main
        .pending_commit()
        .expect("alice_a has a pending commit");
    assert!(
        staged_pending.update_path_leaf_node().is_none(),
        "the add-only commit must not carry a path"
    );
    alice_a_main
        .merge_pending_commit(&alice_a_provider)
        .expect("alice_a merge add without an UpdatePath");

    // The sibling (alice_b) applies alice_a's Commit without an UpdatePath. It
    // is staged as a regular commit, not surfaced as an own pending commit.
    let processed = alice_b_main
        .process_message(
            &alice_b_provider,
            commit.clone().into_protocol_message().unwrap(),
        )
        .expect("alice_b processes sibling commit without an UpdatePath");
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(s) => *s,
        other => panic!("expected staged commit, got {other:?}"),
    };
    assert!(
        !staged.self_removed(),
        "a sibling's add-only commit must not remove alice_b"
    );
    alice_b_main
        .merge_staged_commit(&alice_b_provider, staged)
        .expect("alice_b merge sibling commit without an UpdatePath");

    // bob applies it through the ordinary path.
    let processed = bob_main
        .process_message(&bob_provider, commit.into_protocol_message().unwrap())
        .expect("bob processes commit without an UpdatePath");
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(s) => *s,
        _ => panic!("expected staged commit"),
    };
    bob_main
        .merge_staged_commit(&bob_provider, staged)
        .expect("bob merge commit without an UpdatePath");

    // charly joins from the welcome the add produced.
    let mut charly_main = StagedWelcome::new_from_welcome(
        &charly_provider,
        &vc_join_config(),
        charly_welcome.into_welcome().expect("charly welcome"),
        Some(alice_a_main.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&charly_provider))
    .expect("charly join");

    // All parties agree on the new epoch.
    let authenticator = alice_a_main.epoch_authenticator();
    assert_eq!(
        alice_b_main.epoch_authenticator(),
        authenticator,
        "sibling must converge with the committer"
    );
    assert_eq!(bob_main.epoch_authenticator(), authenticator);
    assert_eq!(charly_main.epoch_authenticator(), authenticator);

    // The new member can message the sibling that applied the commit without an
    // UpdatePath.
    let processed = send_and_process_app_message(
        &mut charly_main,
        &charly_provider,
        &charly_signer,
        &mut alice_b_main,
        &alice_b_provider,
        b"hello from charly",
    );
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => {
            assert_eq!(msg.into_bytes().as_slice(), b"hello from charly");
        }
        _ => panic!("expected application message"),
    }
}
