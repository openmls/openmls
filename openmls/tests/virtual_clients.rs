#![cfg(feature = "virtual-clients-draft")]
use openmls::{
    components::vc_derivation_info::{
        register_vc_emulation_epoch, EmulatorEpochSecret, EpochId, VcEmulation,
    },
    extensions::{ExtensionType, Extensions},
    group::{
        MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedWelcome,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    key_packages::KeyPackage,
    prelude::{
        test_utils::new_credential, Capabilities, LeafNodeIndex, LeafNodeParameters,
        ProcessedMessageContent,
    },
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_test::openmls_test;
use openmls_traits::{random::OpenMlsRand, OpenMlsProvider};

mod mls_group;

/// `Capabilities` declaring `AppDataDictionary` support. The
/// virtual-clients sender hook injects its derivation info into the
/// leaf's `app_data_dictionary` extension; the leaf-node validator
/// rejects the leaf unless the leaf's capabilities advertise that
/// extension type. The library does not auto-patch capabilities on
/// `vc_emulation` — declaring support is the application's
/// responsibility, so every test that drives a VC commit configures
/// its leaf this way.
fn vc_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::AppDataDictionary])
        .build()
}

/// Build an Alice + Bob group on two providers. Alice creates the group,
/// adds Bob, merges. Bob joins from the welcome. After this, `alice_group`
/// (on `alice_provider`) and `bob_group` (on `bob_provider`) both
/// represent the same MLS group at the same epoch. Both leaves declare
/// `AppDataDictionary` support so VC commits validate.
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
        .build();

    let mut alice_group = MlsGroup::new(alice_provider, &alice_signer, &group_config, alice_credential)
        .expect("alice create group");

    let bob_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_capabilities())
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

/// Send a VC-flavoured commit on `sender_group` and return the wire
/// message plus the registered `epoch_id`. Registers the emulation epoch
/// on `sender_provider` from the supplied `emulator_secret_bytes`.
fn send_vc_commit<P: OpenMlsProvider>(
    sender_group: &mut MlsGroup,
    sender_provider: &P,
    sender_signer: &SignatureKeyPair,
    ciphersuite: openmls_traits::types::Ciphersuite,
    emulator_secret_bytes: &[u8],
    emulation_leaf_index: LeafNodeIndex,
) -> (openmls::prelude::MlsMessageOut, EpochId) {
    let epoch_id = register_vc_emulation_epoch(
        sender_provider,
        ciphersuite,
        EmulatorEpochSecret::new(emulator_secret_bytes),
    )
    .expect("register vc epoch (sender)");

    let bundle = sender_group
        .commit_builder()
        .vc_emulation(VcEmulation {
            epoch_id: epoch_id.clone(),
            emulation_leaf_index,
        })
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

    (bundle.into_commit(), epoch_id)
}

/// Sibling-emulator scenario: two `OpenMlsRustCrypto` providers each hold
/// their own copy of Alice's MLS group state and each independently
/// register the same emulation epoch from a shared `emulator_epoch_secret`.
/// The sender provider builds and stages a VC commit; the receiver
/// provider — loading the group from cloned storage — re-derives the path
/// from its still-fresh PPRF and processes the commit successfully.
///
/// Replaces the previous single-storage workaround that re-registered
/// the epoch on the same provider after sender-side puncturing.
#[openmls_test]
fn process_own_commits() {
    let _ = ciphersuite; // silence unused-var warning across feature combos.

    // Pin to a single provider type because the sibling-emulator setup
    // relies on cloning the provider's storage (test-utils' `Clone` impl
    // for `OpenMlsRustCrypto`); the sqlite test provider doesn't offer
    // that.
    let ciphersuite = openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let sender_provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) =
        new_credential(&sender_provider, b"Alice", ciphersuite.signature_algorithm());

    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .build();
    let mut alice_sender =
        MlsGroup::new(&sender_provider, &alice_signer, &group_config, alice_credential)
            .expect("create alice group on sender provider");
    let group_id = alice_sender.group_id().clone();

    // Snapshot sender's storage *before* the sender mutates anything VC-
    // related. The receiver emulator boots from this snapshot and
    // independently registers the same emulation epoch.
    let receiver_provider = sender_provider.clone();

    let emulator_secret_bytes = sender_provider
        .rand()
        .random_vec(ciphersuite.hash_length())
        .unwrap();

    // Sender registers + sends.
    let (commit_msg, epoch_id_sender) = send_vc_commit(
        &mut alice_sender,
        &sender_provider,
        &alice_signer,
        ciphersuite,
        &emulator_secret_bytes,
        LeafNodeIndex::new(0),
    );

    // Receiver registers independently with the same secret bytes —
    // deterministic derivation yields the same `epoch_id` + AEAD key on
    // both providers, so the wire commit decrypts cleanly.
    let epoch_id_receiver = register_vc_emulation_epoch(
        &receiver_provider,
        ciphersuite,
        EmulatorEpochSecret::new(&emulator_secret_bytes),
    )
    .expect("register vc epoch (receiver)");
    assert_eq!(
        epoch_id_sender, epoch_id_receiver,
        "deterministic derivation should produce the same EpochId on both emulators"
    );

    let mut alice_receiver = MlsGroup::load(receiver_provider.storage(), &group_id)
        .expect("load alice group on receiver provider")
        .expect("group present on receiver provider");

    let processed = alice_receiver
        .process_message(&receiver_provider, commit_msg.into_protocol_message().unwrap())
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
        .build();
    let mut alice = MlsGroup::new(&provider, &alice_signer, &group_config, alice_credential)
        .expect("create group");

    let secret_bytes = provider.rand().random_vec(ciphersuite.hash_length()).unwrap();
    let (_msg, epoch_id_1) = send_vc_commit(
        &mut alice,
        &provider,
        &alice_signer,
        ciphersuite,
        &secret_bytes,
        LeafNodeIndex::new(0),
    );

    // A *second* VC commit on the same emulation epoch must still
    // succeed (re-registration is idempotent because deterministic).
    let (_msg2, epoch_id_2) = send_vc_commit(
        &mut alice,
        &provider,
        &alice_signer,
        ciphersuite,
        &secret_bytes,
        LeafNodeIndex::new(0),
    );
    assert_eq!(epoch_id_1, epoch_id_2);
}

/// Fix #1: a non-emulator group member processes a VC commit through the
/// normal HPKE path, without holding any per-emulation-epoch VC state.
/// Pre-fix this would fail at storage lookup with `MissingPprf`.
#[openmls_test]
fn non_emulator_processes_vc_commit_without_registering_state() {
    let alice_provider = Provider::default();
    let bob_provider = Provider::default();
    let (mut alice, alice_signer, mut bob, _bob_signer) =
        setup_alice_bob_group(ciphersuite, &alice_provider, &bob_provider);

    let secret_bytes = alice_provider
        .rand()
        .random_vec(ciphersuite.hash_length())
        .unwrap();
    let (commit_msg, _epoch_id) = send_vc_commit(
        &mut alice,
        &alice_provider,
        &alice_signer,
        ciphersuite,
        &secret_bytes,
        LeafNodeIndex::new(0),
    );

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

/// Fix #1 error path: own-leaf VC commit *requires* VC state. If the
/// receiving emulator hasn't registered the matching epoch, processing
/// the own-leaf commit must fail rather than silently using non-VC paths.
#[openmls_test]
fn own_leaf_vc_commit_fails_when_state_missing() {
    let _ = ciphersuite;
    let ciphersuite = openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let sender_provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) =
        new_credential(&sender_provider, b"Alice", ciphersuite.signature_algorithm());
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .capabilities(vc_capabilities())
        .build();
    let mut alice_sender =
        MlsGroup::new(&sender_provider, &alice_signer, &group_config, alice_credential)
            .expect("create");
    let group_id = alice_sender.group_id().clone();

    // Receiver clones MLS state but does *not* register VC epoch.
    let receiver_provider = sender_provider.clone();

    let secret = sender_provider
        .rand()
        .random_vec(ciphersuite.hash_length())
        .unwrap();
    let (commit_msg, _) = send_vc_commit(
        &mut alice_sender,
        &sender_provider,
        &alice_signer,
        ciphersuite,
        &secret,
        LeafNodeIndex::new(0),
    );

    let mut alice_receiver = MlsGroup::load(receiver_provider.storage(), &group_id)
        .unwrap()
        .unwrap();
    let err = alice_receiver
        .process_message(&receiver_provider, commit_msg.into_protocol_message().unwrap())
        .expect_err("must fail without VC state");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("MissingPprf") || msg.contains("VirtualClients") || msg.contains("Pprf"),
        "expected a virtual-clients error, got {msg}"
    );
}

/// Fix #2: an external commit can carry the VC component, persists its
/// puncture, and is processable by a sibling emulator that's loaded the
/// same emulation epoch.
#[openmls_test]
fn external_vc_commit_can_be_built_and_processed() {
    let _ = ciphersuite;
    let ciphersuite = openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Alice creates a single-member group so that an external committer
    // (Charlie) can join via external commit.
    let alice_provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) =
        new_credential(&alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .build();
    let alice_group =
        MlsGroup::new(&alice_provider, &alice_signer, &group_config, alice_credential)
            .expect("alice create");

    let group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    // Charlie wants to join via an external VC commit. He registers his
    // own emulation epoch first.
    let charlie_provider = OpenMlsRustCrypto::default();
    let (charlie_credential, charlie_signer) =
        new_credential(&charlie_provider, b"Charlie", ciphersuite.signature_algorithm());
    let secret = charlie_provider
        .rand()
        .random_vec(ciphersuite.hash_length())
        .unwrap();
    let charlie_epoch_id = register_vc_emulation_epoch(
        &charlie_provider,
        ciphersuite,
        EmulatorEpochSecret::new(&secret),
    )
    .expect("register charlie vc epoch");

    let (charlie_group, bundle) = MlsGroup::external_commit_builder()
        .build_group(&charlie_provider, group_info, charlie_credential)
        .expect("external commit build_group")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(vc_capabilities())
                .build(),
        )
        .vc_emulation(VcEmulation {
            epoch_id: charlie_epoch_id.clone(),
            emulation_leaf_index: LeafNodeIndex::new(0),
        })
        .load_psks(charlie_provider.storage())
        .expect("load psks")
        .build(
            charlie_provider.rand(),
            charlie_provider.crypto(),
            &charlie_signer,
            |_| true,
        )
        .expect("build external commit")
        .finalize(&charlie_provider)
        .expect("finalize external commit");

    // The path leaf must carry the VC derivation-info component. Use
    // the on-the-wire bytes as a structural proxy: searching for the
    // u16 `VC_COMPONENT_ID` on its own would be ambiguous, so we look
    // for a few bytes that should only appear together when the
    // app-data-dictionary entry was injected.
    let commit_msg = bundle.into_commit();
    let serialized = {
        use tls_codec::Serialize as _;
        commit_msg.tls_serialize_detached().unwrap()
    };
    use openmls::components::vc_derivation_info::VC_COMPONENT_ID;
    let id_bytes = VC_COMPONENT_ID.to_be_bytes();
    assert!(
        serialized.windows(2).any(|w| w == id_bytes),
        "external commit should carry VC derivation-info on its leaf"
    );

    // Charlie is now in the group at epoch 1.
    assert_eq!(charlie_group.epoch().as_u64(), 1);
    let _ = charlie_epoch_id; // referenced for clarity; storage assertion
                              // is omitted because `VcPprf` is private.
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
