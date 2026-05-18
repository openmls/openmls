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
use openmls_rust_crypto::OpenMlsRustCrypto;
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

/// Sibling-emulator scenario: two `OpenMlsRustCrypto` providers each hold
/// their own copy of Alice's MLS group state and each independently
/// register the same emulation epoch from the *same* underlying
/// emulator-group state (snapshotted from the sender provider before any
/// VC mutation). The sender provider builds and stages a VC commit; the
/// receiver provider — loading the group and the emulator group from the
/// cloned storage — re-derives the path from its still-fresh PPRF and
/// processes the commit successfully.
#[openmls_test]
fn process_own_commits() {
    let _ = ciphersuite; // silence unused-var warning across feature combos.

    // Pin to a single provider type because the sibling-emulator setup relies
    // on cloning the provider's storage (test-utils' `Clone` impl for
    // `OpenMlsRustCrypto`); the sqlite test provider doesn't offer that. We
    // currently need to be able to clone, because for now it's the only way for
    // the second emulation client to bootstrap the higher-level group state.
    // TODO: When vc clients can process external commits from sibling emulator
    // clients, use that mechanism instead to onboard new emulator clients.
    let ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let sender_provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) = new_credential(
        &sender_provider,
        b"Alice",
        ciphersuite.signature_algorithm(),
    );

    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    let mut alice_sender = MlsGroup::new(
        &sender_provider,
        &alice_signer,
        &group_config,
        alice_credential,
    )
    .expect("create alice group on sender provider");
    let group_id = alice_sender.group_id().clone();

    // Build the emulator group on the sender provider too (in this
    // contrived test alice-as-sender uses her own group as her own
    // emulator; in practice this would be a separate group of emulators).
    // This can also be improved as soon as sibling emulator clients can process
    // each other's external commits.
    let (mut emulator_sender, _emulator_signer) =
        make_emulator_group(ciphersuite, &sender_provider, b"AliceEmulator");
    let emulator_group_id = emulator_sender.group_id().clone();

    // Snapshot sender's storage *before* the sender mutates anything VC-
    // related. The receiver emulator boots from this snapshot, loads the
    // emulator group from it, and independently registers the same
    // emulation epoch via `safe_export_secret`.
    let receiver_provider = sender_provider.clone();

    // Sender registers + sends.
    let (commit_msg, epoch_id_sender) = send_vc_commit(
        &mut alice_sender,
        &mut emulator_sender,
        &sender_provider,
        &alice_signer,
    );

    // Receiver loads its own copy of the emulator group and registers
    // independently. Deterministic derivation yields the same `epoch_id`
    // + AEAD key on both providers, so the wire commit decrypts cleanly.
    let mut emulator_receiver = MlsGroup::load(receiver_provider.storage(), &emulator_group_id)
        .expect("load emulator group on receiver provider")
        .expect("emulator group present on receiver provider");
    let epoch_id_receiver = emulator_receiver
        .register_vc_emulation_epoch(receiver_provider.crypto(), receiver_provider.storage())
        .expect("register vc epoch (receiver)");
    assert_eq!(
        epoch_id_sender, epoch_id_receiver,
        "deterministic derivation should produce the same EpochId on both emulators"
    );

    let mut alice_receiver = MlsGroup::load(receiver_provider.storage(), &group_id)
        .expect("load alice group on receiver provider")
        .expect("group present on receiver provider");

    let processed = alice_receiver
        .process_message(
            &receiver_provider,
            commit_msg.into_protocol_message().unwrap(),
        )
        .expect("receiver processes own VC commit");
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(s) => *s,
        _ => panic!("expected staged commit"),
    };
    alice_receiver
        .merge_staged_commit(&receiver_provider, staged)
        .expect("receiver merge");

    // Both replicas converged on the same epoch + tree hash.
    assert_eq!(alice_sender.epoch(), alice_receiver.epoch());
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

/// Own-leaf VC commit requires VC state. If the receiving emulator hasn't
/// registered the matching epoch, processing the own-leaf commit must fail.
#[openmls_test]
fn own_leaf_vc_commit_fails_when_state_missing() {
    let _ = ciphersuite;
    let ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let sender_provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) = new_credential(
        &sender_provider,
        b"Alice",
        ciphersuite.signature_algorithm(),
    );
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    let mut alice_sender = MlsGroup::new(
        &sender_provider,
        &alice_signer,
        &group_config,
        alice_credential,
    )
    .expect("create");
    let group_id = alice_sender.group_id().clone();
    let (mut emulator_sender, _emulator_signer) =
        make_emulator_group(ciphersuite, &sender_provider, b"AliceEmulator");

    // Receiver clones MLS state but does *not* register VC epoch.
    let receiver_provider = sender_provider.clone();

    let (commit_msg, _) = send_vc_commit(
        &mut alice_sender,
        &mut emulator_sender,
        &sender_provider,
        &alice_signer,
    );

    let mut alice_receiver = MlsGroup::load(receiver_provider.storage(), &group_id)
        .unwrap()
        .unwrap();
    let err = alice_receiver
        .process_message(
            &receiver_provider,
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
/// We exercise four commits in order:
///   1. Bob's commit  — processed by alice_a, alice_b, charly via HPKE.
///   2. Charly's commit — processed by alice_a, alice_b, bob via HPKE.
///   3. alice_a's VC commit — alice_b uses own-leaf VC path, bob+charly HPKE.
///   4. alice_b's VC commit — alice_a uses own-leaf VC path, bob+charly HPKE.
///
/// All four parties must agree on the epoch authenticator after each commit.
///
/// Plain `#[test]` (not `#[openmls_test]`): uses `OpenMlsRustCrypto::clone()`,
/// which is `test-utils`-gated and unavailable on the sqlite test provider.
#[test]
fn vc_two_alice_clients_in_group_with_bob_and_charly() {
    let ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // ---- Providers ----
    // alice_a_provider builds initial state; alice_b_provider is cloned
    // from it so both providers have the Alice main-group credential and
    // signer in storage.
    let alice_a_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let charly_provider = OpenMlsRustCrypto::default();

    // ---- Credentials ----
    let (alice_credential, alice_signer) = new_credential(
        &alice_a_provider,
        b"Alice",
        ciphersuite.signature_algorithm(),
    );
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
        &alice_signer,
        &group_config,
        alice_credential,
    )
    .expect("alice create main group");
    let main_group_id = alice_a_main.group_id().clone();

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
        .add_members(&alice_a_provider, &alice_signer, &[bob_kp, charly_kp])
        .expect("alice add bob+charly");
    alice_a_main
        .merge_pending_commit(&alice_a_provider)
        .expect("alice merge add");

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
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

    // ---- Emulator-group prep: stage the credentials we need on the to-be-
    // cloned provider, but do NOT yet create the emulator-group MlsGroup
    // there. If we created it before cloning, alice_b_provider would inherit
    // emulator_a's state and reject alice_b's later `StagedWelcome::join`
    // with `GroupAlreadyExists`.
    let (alice_emulator_a_credential, alice_emulator_a_signer) = new_credential(
        &alice_a_provider,
        b"AliceEmulatorA",
        ciphersuite.signature_algorithm(),
    );
    let (alice_emulator_b_credential, alice_emulator_b_signer) = new_credential(
        &alice_a_provider,
        b"AliceEmulatorB",
        ciphersuite.signature_algorithm(),
    );
    let alice_emulator_b_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(
            ciphersuite,
            &alice_a_provider,
            &alice_emulator_b_signer,
            alice_emulator_b_credential,
        )
        .expect("alice_b emulator KP build")
        .key_package()
        .to_owned();

    // ---- Snapshot alice_a_provider into alice_b_provider BEFORE the
    // emulator-group MlsGroup is created on alice_a_provider, so alice_b
    // can later join the welcome cleanly (no group-id collision). The
    // snapshot already contains: alice's main-group state + signer +
    // credential, alice_emulator_a's signer/credential, alice_emulator_b's
    // signer/credential, bob/charly KP signing chains, etc.
    let alice_b_provider = alice_a_provider.clone();

    // ---- Now actually create the emulator group on alice_a_provider ----
    let emulator_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions on emulator group config")
        .build();
    let mut emulator_a = MlsGroup::new(
        &alice_a_provider,
        &alice_emulator_a_signer,
        &emulator_config,
        alice_emulator_a_credential,
    )
    .expect("alice_a create emulator group");
    let emulator_group_id = emulator_a.group_id().clone();

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

    let emulator_welcome = e_welcome.into_welcome().expect("emulator welcome");
    let emulator_ratchet_tree = emulator_a.export_ratchet_tree();

    // alice_b joins the emulator group on her own (cloned) provider.
    let mut emulator_b = StagedWelcome::new_from_welcome(
        &alice_b_provider,
        &join_config,
        emulator_welcome,
        Some(emulator_ratchet_tree.into()),
    )
    .and_then(|s| s.into_group(&alice_b_provider))
    .expect("alice_b join emulator group");
    assert_eq!(emulator_b.group_id(), &emulator_group_id);

    // alice_b's main-group instance is loaded from cloned storage. After
    // this point, alice_a_main and alice_b_main are independent in-memory
    // MlsGroup states for the same MLS leaf, backed by separate provider
    // storages.
    let mut alice_b_main = MlsGroup::load(alice_b_provider.storage(), &main_group_id)
        .expect("load alice main group on alice_b_provider")
        .expect("alice main group present on alice_b_provider");

    // Sanity: all four parties agree (post add-members).
    fn assert_all_agree<P: OpenMlsProvider>(groups_and_providers: &[(&MlsGroup, &P)], label: &str) {
        let mut iter = groups_and_providers.iter();
        let (first_group, _) = iter.next().expect("at least one party");
        let reference = first_group.epoch_authenticator();
        for (group, _) in iter {
            assert_eq!(
                group.epoch_authenticator(),
                reference,
                "epoch authenticator divergence at {label}"
            );
        }
    }

    let baseline_epoch = alice_a_main.epoch();
    assert_all_agree(
        &[
            (&alice_a_main, &alice_a_provider),
            (&alice_b_main, &alice_b_provider),
            (&bob_main, &bob_provider),
            (&charly_main, &charly_provider),
        ],
        "post add-members",
    );

    // Helper closure: deliver one commit (already merged on the sender
    // side) to a single receiver group via the regular process path.
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

    // ---- Commit 1: Bob's regular commit ----
    let bob_commit = build_regular_commit(&mut bob_main, &bob_provider, &bob_signer);
    deliver_commit(&mut alice_a_main, &alice_a_provider, &bob_commit);
    deliver_commit(&mut alice_b_main, &alice_b_provider, &bob_commit);
    deliver_commit(&mut charly_main, &charly_provider, &bob_commit);
    assert_all_agree(
        &[
            (&alice_a_main, &alice_a_provider),
            (&alice_b_main, &alice_b_provider),
            (&bob_main, &bob_provider),
            (&charly_main, &charly_provider),
        ],
        "post Bob commit",
    );

    // ---- Commit 2: Charly's regular commit ----
    let charly_commit = build_regular_commit(&mut charly_main, &charly_provider, &charly_signer);
    deliver_commit(&mut alice_a_main, &alice_a_provider, &charly_commit);
    deliver_commit(&mut alice_b_main, &alice_b_provider, &charly_commit);
    deliver_commit(&mut bob_main, &bob_provider, &charly_commit);
    assert_all_agree(
        &[
            (&alice_a_main, &alice_a_provider),
            (&alice_b_main, &alice_b_provider),
            (&bob_main, &bob_provider),
            (&charly_main, &charly_provider),
        ],
        "post Charly commit",
    );

    // ---- Commit 3: alice_a's VC commit ----
    // (epoch_id_a was registered by alice_a's emulator group, which captured
    // her own_leaf_index there at registration time.)
    let alice_a_vc_commit = send_vc_commit_with_epoch(
        &mut alice_a_main,
        &alice_a_provider,
        &alice_signer,
        epoch_id_a.clone(),
    );
    // alice_b processes via the own-leaf VC path.
    deliver_commit(&mut alice_b_main, &alice_b_provider, &alice_a_vc_commit);
    // Bob and Charly process via the normal HPKE path.
    deliver_commit(&mut bob_main, &bob_provider, &alice_a_vc_commit);
    deliver_commit(&mut charly_main, &charly_provider, &alice_a_vc_commit);
    assert_all_agree(
        &[
            (&alice_a_main, &alice_a_provider),
            (&alice_b_main, &alice_b_provider),
            (&bob_main, &bob_provider),
            (&charly_main, &charly_provider),
        ],
        "post alice_a VC commit",
    );

    // ---- Commit 4: alice_b's VC commit ----
    // (epoch_id_b was registered by alice_b's emulator group with her own
    // leaf-1 index baked in.)
    let alice_b_vc_commit = send_vc_commit_with_epoch(
        &mut alice_b_main,
        &alice_b_provider,
        &alice_signer,
        epoch_id_b.clone(),
    );
    // alice_a processes via the own-leaf VC path.
    deliver_commit(&mut alice_a_main, &alice_a_provider, &alice_b_vc_commit);
    // Bob and Charly process via the normal HPKE path.
    deliver_commit(&mut bob_main, &bob_provider, &alice_b_vc_commit);
    deliver_commit(&mut charly_main, &charly_provider, &alice_b_vc_commit);
    assert_all_agree(
        &[
            (&alice_a_main, &alice_a_provider),
            (&alice_b_main, &alice_b_provider),
            (&bob_main, &bob_provider),
            (&charly_main, &charly_provider),
        ],
        "post alice_b VC commit",
    );

    // After four commits, the epoch counter has advanced by 4 from baseline.
    assert_eq!(
        alice_a_main.epoch().as_u64(),
        baseline_epoch.as_u64() + 4,
        "expected four-epoch advance across the four commits"
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
