#![cfg(feature = "virtual-clients-draft")]
use openmls::{
    components::vc_derivation_info::{EpochId, VcEmulation, VC_COMPONENT_ID},
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
use openmls_test::openmls_test;
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
        .vc_emulation(VcEmulation { epoch_id })
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

/// Focused puncture-persistence test: after the sender stages a VC commit,
/// the per-epoch PPRF must remain registered (with its puncture state)
/// — this is verified indirectly by sending a *second* VC commit on the
/// same epoch_id and confirming it still succeeds. If `stage_commit`
/// dropped the puncture or wiped the registration, the second commit
/// would either fail at lookup or, worse, silently re-derive the same
/// secret as the first.
#[openmls_test]
fn vc_pprf_persists_across_own_commits() {
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
    // of this test is that the per-emulation-epoch *VC* PPRF survives
    // and its puncture state is persisted across stage_commit boundaries.
    let epoch_id = emulator
        .register_vc_emulation_epoch(provider.crypto(), provider.storage())
        .expect("register vc epoch");

    let _msg1 = send_vc_commit_with_epoch(&mut alice, &provider, &alice_signer, epoch_id.clone());

    // A *second* VC commit on the same emulation epoch must still
    // succeed. If `stage_commit` had wiped the registration or dropped
    // the puncture, the build would fail at PPRF lookup.
    let _msg2 = send_vc_commit_with_epoch(&mut alice, &provider, &alice_signer, epoch_id);
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
/// leaf), then *must* load the per-epoch PPRF and emulation-epoch state to
/// derive the path. If the receiver hasn't yet registered the matching
/// emulation epoch (e.g. it joined the emulator group but skipped the
/// `register_vc_emulation_epoch` step before the sibling attempted the
/// resync), processing must fail loudly with a virtual-clients error
/// rather than silently fall through to HPKE.
#[openmls_test]
fn sibling_resync_external_commit_fails_when_receiver_lacks_pprf() {
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
        .vc_emulation(VcEmulation {
            epoch_id: epoch_id_b,
        })
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
        msg.contains("MissingPprf") || msg.contains("VirtualClients") || msg.contains("Pprf"),
        "expected a virtual-clients error, got {msg}"
    );
}

/// End-to-end realistic VC scenario: Alice has *two* clients sharing one
/// MLS leaf in a main group with Bob and Charly. Both Alice clients also
/// share an *emulator group* (a separate two-member MLS group) used as the
/// source of `safe_export_secret(VC_COMPONENT_ID)` from which both clients
/// derive the same `EpochId`/PPRF/AEAD key.
///
/// alice_b bootstraps into the higher-level group via a sibling-resync VC
/// external commit (auto-Remove targeting alice_a's existing leaf). After
/// that we exercise four commits in order:
///   1. Bob's commit: processed by alice_a, alice_b, charly via HPKE.
///   2. Charly's commit: processed by alice_a, alice_b, bob via HPKE.
///   3. alice_a's VC commit: alice_b uses own-leaf VC path, bob+charly HPKE.
///   4. alice_b's VC commit: alice_a uses own-leaf VC path, bob+charly HPKE.
///
/// All four parties must agree on the epoch authenticator after each commit.
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
        .vc_emulation(VcEmulation {
            epoch_id: epoch_id_b.clone(),
        })
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
    let alice_a_vc_commit = send_vc_commit_with_epoch(
        &mut alice_a_main,
        &alice_a_provider,
        &vc_signer,
        epoch_id_a.clone(),
    );
    // alice_b processes via the own-leaf VC path.
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

    // After four commits, the epoch counter has advanced by 4 from the
    // post-resync baseline.
    assert_eq!(
        alice_a_main.epoch().as_u64(),
        baseline_epoch.as_u64() + 4,
        "expected four-epoch advance across the four commits"
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
///     attaches a `vc_emulation(VcEmulation { epoch_id })` so the path leaf
///     is derived from the per-commit `OperationSecret`.
///   * `alice_a` processes the external commit. The sibling-resync
///     discriminator (registered VC epoch state + `NewMemberCommit` sender
///     + `Remove(self)` in the queue) triggers: she derives the path from
///     her PPRF, skips the `self_removed` short-circuit, and after merging
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
        .vc_emulation(VcEmulation {
            epoch_id: epoch_id_b.clone(),
        })
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
    let (_generation, ciphertext) = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, alice_message)
        .unwrap();

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

    // Decrypting the message again should fail because the generation has
    // already been ratcheted forward.
    let _ = alice_group
        .process_message(alice_provider, ciphertext.into_protocol_message().unwrap())
        .expect_err("Expected an error when processing the same message again.");

    // Alice sends another application message and confirms it. Trying to
    // decrypt it should then fail.
    let alice_message = b"Hello, this is Alice again!";
    let (generation, ciphertext) = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, alice_message)
        .unwrap();
    alice_group
        .confirm_message(alice_provider.storage(), generation)
        .unwrap();

    let _ = alice_group
        .process_message(
            alice_provider,
            ciphertext.clone().into_protocol_message().unwrap(),
        )
        .expect_err("Expected an error when processing a confirmed message.");
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
    let (first_generation, first_ciphertext) = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, first_message)
        .expect("Could not create first unconfirmed message.");
    assert_eq!(first_generation, 0);

    let second_message = b"second confirmed message";
    let (second_generation, _second_ciphertext) = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, second_message)
        .expect("Could not create second message.");
    assert_eq!(second_generation, 1);
    alice_group
        .confirm_message(alice_provider.storage(), second_generation)
        .expect("Could not confirm second message.");

    let processed_message = alice_group
        .process_message(
            alice_provider,
            first_ciphertext.into_protocol_message().unwrap(),
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
    let (_first_generation, first_ciphertext) = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, first_message)
        .expect("Could not create first unconfirmed message.");

    let tolerance = alice_group
        .configuration()
        .sender_ratchet_configuration()
        .out_of_order_tolerance();

    for i in 0..tolerance + 2 {
        let (generation, _) = alice_group
            .create_unconfirmed_message(
                alice_provider,
                &alice_signer,
                format!("later confirmed message {i}").as_bytes(),
            )
            .expect("Could not create later unconfirmed message.");
        alice_group
            .confirm_message(alice_provider.storage(), generation)
            .expect("Could not confirm later message.");
    }

    let processed_message = alice_group
        .process_message(
            alice_provider,
            first_ciphertext.into_protocol_message().unwrap(),
        )
        .expect("Expected old unconfirmed own message to decrypt.");

    let ProcessedMessageContent::ApplicationMessage(msg) = processed_message.into_content() else {
        panic!("Expected an application message.");
    };
    assert_eq!(first_message.as_slice(), msg.into_bytes().as_slice());
}
