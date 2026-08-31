#![cfg(feature = "virtual-clients-draft")]
use openmls::{
    component::{ComponentData, ComponentId},
    components::vc_derivation_info::{EpochId, VcEmulationBindings, VC_COMPONENT_ID},
    credentials::NewSignerBundle,
    extensions::{
        AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType, Extensions,
    },
    framing::errors::{MessageDecryptionError, SecretTreeError},
    group::{
        AppDataUpdates, ConfirmMessageError, GroupEpoch, GroupId, MlsGroup, MlsGroupCreateConfig,
        MlsGroupJoinConfig, Propose, StageCommitError, StagedVcExternalCommitJoin, StagedWelcome,
        VcExternalCommitJoinError, MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY,
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    key_packages::KeyPackage,
    messages::{
        group_info::VerifiableGroupInfo,
        proposals::{
            AppDataUpdateOperation, AppDataUpdateProposal, AppEphemeralProposal, Proposal,
        },
    },
    prelude::{
        test_utils::new_credential, ApplyAppDataUpdateError, Capabilities, LeafNode,
        LeafNodeParameters, ProcessMessageError, ProcessedMessageContent, ProposalOrRefType,
        ProposalType, ProtocolMessage, ValidationError,
    },
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
    setup_alice_bob_group_with_policy(
        ciphersuite,
        alice_provider,
        bob_provider,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    )
}

/// Like [`setup_alice_bob_group`], but with an explicit wire format policy on
/// both the create and join configs, so tests can exercise private (ciphertext)
/// handshake framing between the two members.
fn setup_alice_bob_group_with_policy<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    alice_provider: &P,
    bob_provider: &P,
    wire_format_policy: openmls::group::WireFormatPolicy,
) -> (MlsGroup, SignatureKeyPair, MlsGroup, SignatureKeyPair) {
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(wire_format_policy)
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
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
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
        .wire_format_policy(wire_format_policy)
        .use_ratchet_tree_extension(true)
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

/// GroupContext extensions requiring Safe AAD framing, with no component id
/// that every member must understand. An emulation group needs these so that a
/// commit can carry the `new_derivation_epoch` marker.
fn safe_aad_group_context_extensions() -> Extensions<openmls::group::GroupContext> {
    use openmls::component::{ComponentType, ComponentsList};

    let body = ComponentsList::new(Vec::new())
        .tls_serialize_detached()
        .expect("serialize ComponentsList body");
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(ComponentType::SafeAad.into(), body);
    let ext = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
    Extensions::single(ext).expect("one app_data_dictionary extension is valid")
}

/// The create-config builder of an emulation group: VC capabilities, an
/// `AppComponents` entry listing `VC_COMPONENT_ID`, and the `emulation_group`
/// flag that makes OpenMLS register derivation epochs. `safe_aad` adds the
/// GroupContext extensions that require Safe AAD framing, without which a
/// commit cannot carry the `new_derivation_epoch` marker.
fn emulation_config_builder(
    ciphersuite: openmls_traits::types::Ciphersuite,
    emulation_group: bool,
    safe_aad: bool,
) -> openmls::group::MlsGroupCreateConfigBuilder {
    let builder = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions on emulator config")
        .emulation_group(emulation_group);
    if safe_aad {
        builder.with_group_context_extensions(safe_aad_group_context_extensions())
    } else {
        builder
    }
}

/// The create config of an emulation group, with Safe AAD framing.
fn emulation_group_config(
    ciphersuite: openmls_traits::types::Ciphersuite,
    emulation_group: bool,
) -> MlsGroupCreateConfig {
    emulation_config_builder(ciphersuite, emulation_group, true).build()
}

/// A KeyPackage carrying the leaf configuration a virtual-client leaf needs,
/// together with the freshly generated signature keypair it is signed with.
fn vc_key_package<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider: &P,
    label: &[u8],
) -> (KeyPackage, SignatureKeyPair) {
    let (credential, signer) = new_credential(provider, label, ciphersuite.signature_algorithm());
    let key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(ciphersuite, provider, &signer, credential)
        .expect("build vc key package")
        .key_package()
        .to_owned();
    (key_package, signer)
}

/// Build a single-member emulation group on `provider`. With `emulation_group`
/// set, creating it registers the initial epoch as a derivation epoch, whose
/// root secret comes from the group's `safe_export_secret(VC_COMPONENT_ID)`.
/// Without it, this client's copy of the group never registers one.
fn make_emulator_group<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider: &P,
    label: &[u8],
    emulation_group: bool,
) -> (MlsGroup, SignatureKeyPair) {
    let (credential, signer) = new_credential(provider, label, ciphersuite.signature_algorithm());
    let group_config = emulation_group_config(ciphersuite, emulation_group);
    let group =
        MlsGroup::new(provider, &signer, &group_config, credential).expect("create emulator group");
    (group, signer)
}

/// The newest derivation epoch of `emulator_group`.
fn newest_epoch<P: OpenMlsProvider>(emulator_group: &MlsGroup, provider: &P) -> EpochId {
    emulator_group
        .newest_vc_derivation_epoch(provider.storage())
        .expect("read newest derivation epoch")
        .expect("an emulation group has a derivation epoch")
}

/// Send a VC-flavoured commit on `sender_group` as a virtual client of
/// `emulator_group`. The commit uses the emulation group's newest derivation
/// epoch, which the caller can read with [`newest_epoch`].
fn send_vc_commit<P: OpenMlsProvider>(
    sender_group: &mut MlsGroup,
    emulator_group: &MlsGroup,
    sender_provider: &P,
    sender_signer: &SignatureKeyPair,
) -> openmls::prelude::MlsMessageOut {
    let bundle = sender_group
        .commit_builder()
        .vc_emulation(
            sender_provider.crypto(),
            sender_provider.storage(),
            emulator_group.group_id(),
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

/// Send a VC-flavoured commit on `sender_group` from the given `epoch_id`
/// instead of the emulation group's newest derivation epoch, using the
/// test-only escape hatch. Only for tests that deliberately act on a stale
/// emulation-group state, which an application must not do.
fn send_vc_commit_at_epoch<P: OpenMlsProvider>(
    sender_group: &mut MlsGroup,
    sender_provider: &P,
    sender_signer: &SignatureKeyPair,
    epoch_id: EpochId,
) -> openmls::prelude::MlsMessageOut {
    let bundle = sender_group
        .commit_builder()
        .vc_emulation_at_epoch(
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

/// A VC main group created with an explicit wire format policy. Used to frame
/// handshake messages as PrivateMessage while still accepting the incoming
/// sibling-resync external commit, which is always a PublicMessage.
fn new_vc_main_group_with_policy<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider: &P,
    signer: &SignatureKeyPair,
    credential: openmls::credentials::CredentialWithKey,
    wire_format_policy: openmls::group::WireFormatPolicy,
) -> MlsGroup {
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(wire_format_policy)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    MlsGroup::new(provider, signer, &group_config, credential).expect("create vc main group")
}

/// The join config used by emulator clients joining a higher-level group or an
/// emulation group: pure-plaintext framing with the ratchet tree carried inline.
fn vc_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build()
}

/// A second emulator client brought in alongside an existing one, sharing the
/// virtual client's derivation epoch.
struct SiblingEmulators {
    emulator_a: MlsGroup,
    emulator_a_signer: SignatureKeyPair,
    emulator_b: MlsGroup,
    alice_b_main: MlsGroup,
    epoch_id: EpochId,
}

/// Bring a second emulator client (alice_b) into an existing virtual client
/// without cloning storage. alice_a founds the emulation group and alice_b
/// joins it via Welcome. Both register the same derivation epoch, then alice_b
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
    let (mut emulator_a, emulator_a_signer) = make_emulator_group(
        emulator_ciphersuite,
        alice_a_provider,
        b"AliceEmulatorA",
        true,
    );
    let (_e_commit, emulator_b, _emulator_b_signer) = add_emulator_client(
        emulator_ciphersuite,
        &mut emulator_a,
        alice_a_provider,
        &emulator_a_signer,
        alice_b_provider,
        b"AliceEmulatorB",
    );

    // Both clients independently register the same derivation epoch.
    let epoch_id = newest_epoch(&emulator_a, alice_a_provider);
    let epoch_id_b = newest_epoch(&emulator_b, alice_b_provider);
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
            emulator_b.group_id(),
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
    let (emulator, _emulator_signer) =
        make_emulator_group(ciphersuite, &provider, b"AliceEmulator", true);

    // The emulator group stays at the epoch it was created in, so both commits
    // resolve to the same derivation epoch. The point of this test is that the
    // per-derivation-epoch operation secret tree survives, with its advanced
    // ratchet head, across build boundaries.
    let epoch_id = newest_epoch(&emulator, &provider);
    let _msg1 = send_vc_commit(&mut alice, &emulator, &provider, &alice_signer);
    let epoch_after_first = alice.epoch();

    // A *second* VC commit on the same derivation epoch must still
    // succeed and consume generation 1. If `build` had wiped the
    // registration or failed to persist the ratchet advance, this would
    // fail at tree lookup or when the consumed generation is re-derived.
    let _msg2 = send_vc_commit(&mut alice, &emulator, &provider, &alice_signer);
    let epoch_id_again = newest_epoch(&emulator, &provider);
    assert_eq!(
        epoch_id, epoch_id_again,
        "an unchanged emulator group keeps its derivation epoch"
    );
    assert_eq!(
        alice.epoch().as_u64(),
        epoch_after_first.as_u64() + 1,
        "second VC commit on the same derivation epoch must succeed"
    );
}

/// A non-emulator group member processes a VC commit through the normal HPKE
/// path, without holding any per-derivation-epoch VC state.
#[openmls_test]
fn non_emulator_processes_vc_commit_without_registering_state() {
    let alice_provider = Provider::default();
    let bob_provider = Provider::default();
    let (mut alice, alice_signer, mut bob, _bob_signer) =
        setup_alice_bob_group(ciphersuite, &alice_provider, &bob_provider);
    let (emulator, _emulator_signer) =
        make_emulator_group(ciphersuite, &alice_provider, b"AliceEmulator", true);

    let commit_msg = send_vc_commit(&mut alice, &emulator, &alice_provider, &alice_signer);

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
/// derivation-epoch state to derive the path. If the receiver hasn't yet
/// registered the matching derivation epoch (e.g. it holds the emulation group
/// without the `emulation_group` flag, so no derivation epoch was ever
/// registered on its side), processing must fail loudly with a virtual-clients
/// error rather than silently fall through to HPKE.
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
    // member (joined via Welcome). alice_a holds the group without the
    // `emulation_group` flag, so it never registers a derivation epoch.
    let (mut emulator_a, alice_emulator_a_signer) =
        make_emulator_group(ciphersuite, &alice_a_provider, b"AliceEmulatorA", false);
    let (_e_commit, emulator_b, _alice_emulator_b_signer) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &alice_a_provider,
        &alice_emulator_a_signer,
        &alice_b_provider,
        b"AliceEmulatorB",
    );

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

    // Only alice_b holds derivation-epoch state, manufacturing the failure
    // scenario.
    assert!(
        emulator_b
            .newest_vc_derivation_epoch(alice_b_provider.storage())
            .expect("read newest derivation epoch")
            .is_some(),
        "alice_b must hold the derivation epoch alice_a lacks"
    );
    assert_eq!(
        emulator_a
            .newest_vc_derivation_epoch(alice_a_provider.storage())
            .expect("read newest derivation epoch"),
        None,
        "a group without the emulation_group flag registers nothing"
    );

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
            emulator_b.group_id(),
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
        msg.contains("MissingDerivationEpochState")
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
///   5. alice_a's second VC commit on the same derivation epoch: alice_b
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
        make_emulator_group(ciphersuite, &alice_a_provider, b"AliceEmulatorA", true);
    let (_e_commit, emulator_b, _alice_emulator_b_signer) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &alice_a_provider,
        &alice_emulator_a_signer,
        &alice_b_provider,
        b"AliceEmulatorB",
    );

    // ---- Both Alice clients independently register the same VC epoch ----
    let epoch_id_a = newest_epoch(&emulator_a, &alice_a_provider);
    let epoch_id_b = newest_epoch(&emulator_b, &alice_b_provider);
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
            emulator_b.group_id(),
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
    // alice_a's first own LeafNode operation on this derivation epoch
    // consumes generation 0 of her emulation-leaf ratchet.
    let alice_a_vc_commit = send_vc_commit(
        &mut alice_a_main,
        &emulator_a,
        &alice_a_provider,
        &vc_signer,
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
    let alice_b_vc_commit = send_vc_commit(
        &mut alice_b_main,
        &emulator_b,
        &alice_b_provider,
        &vc_signer,
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

    // ---- Commit 5: alice_a's second VC commit on the same derivation
    // epoch. alice_b already derived generation 0 of alice_a's ratchet for
    // commit 3, so she now derives generation 1 positionally. This is the
    // behavioral check that two successive VC commits from the same
    // derivation epoch consume successive generations.
    let alice_a_second_vc_commit = send_vc_commit(
        &mut alice_a_main,
        &emulator_a,
        &alice_a_provider,
        &vc_signer,
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
///   * Both alice clients register the same derivation epoch on their copy
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
        make_emulator_group(ciphersuite, &alice_a_provider, b"AliceEmulatorA", true);
    let (_e_commit, emulator_b, _alice_emulator_b_signer) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &alice_a_provider,
        &alice_emulator_a_signer,
        &alice_b_provider,
        b"AliceEmulatorB",
    );

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
        &vc_join_config(),
        welcome.into_welcome().expect("welcome"),
        Some(alice_a_main.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob join higher-level group");

    // Both alice clients register the same VC derivation epoch.
    let epoch_id_a = newest_epoch(&emulator_a, &alice_a_provider);
    let epoch_id_b = newest_epoch(&emulator_b, &alice_b_provider);
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
            emulator_b.group_id(),
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
    let alice_b_followup = send_vc_commit(
        &mut alice_b_main,
        &emulator_b,
        &alice_b_provider,
        &vc_signer,
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

/// A virtual client's **second** emulator client bootstraps into a higher-level
/// group by **processing** the first emulator client's external commit.
///
/// `charly_a` joins the higher-level group (Alice + Bob) via a plain external
/// commit. Per the mls-virtual-clients draft the commit's leaf carries the
/// external init secret in its derivation info. `charly_b`, which shares the
/// derivation epoch but is not a member, runs the
/// [`VcExternalCommitJoinBuilder`] with the prior-epoch
/// GroupInfo and that commit: it rebuilds the prior-epoch public group,
/// recreates the commit path from the shared operation secret tree, and uses
/// the carried external init secret as the new epoch's external init secret
/// (it never held the previous epoch's `external_secret`). It lands on the
/// shared virtual-client leaf, and all four parties converge.
#[openmls_test]
fn vc_second_emulator_client_onboards_via_external_commit() {
    use openmls::credentials::{BasicCredential, CredentialWithKey};
    use openmls::prelude::{LeafNodeParameters, MlsMessageIn};
    use tls_codec::Deserialize as _;

    let alice_provider = Provider::default();
    let bob_provider = Provider::default();
    let charly_a_provider = Provider::default();
    let charly_b_provider = Provider::default();

    // Alice founds the higher-level group and adds Bob. Neither is the virtual
    // client; they are ordinary members who process Charly's commits via HPKE.
    let (alice_credential, alice_signer) =
        new_credential(&alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let mut alice_main = new_vc_main_group(
        ciphersuite,
        &alice_provider,
        &alice_signer,
        alice_credential,
    );
    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let bob_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    let (_, welcome, _) = alice_main
        .add_members(&alice_provider, &alice_signer, &[bob_kp])
        .expect("alice add bob");
    alice_main
        .merge_pending_commit(&alice_provider)
        .expect("alice merge add bob");
    let mut bob_main = StagedWelcome::new_from_welcome(
        &bob_provider,
        &vc_join_config(),
        welcome.into_welcome().expect("welcome"),
        Some(alice_main.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob join higher-level group");

    // Charly is one virtual client with two emulator clients. They share a
    // signing identity (stored in both providers) ...
    let vc_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("vc signer");
    vc_signer
        .store(charly_a_provider.storage())
        .expect("store vc signer on charly_a");
    vc_signer
        .store(charly_b_provider.storage())
        .expect("store vc signer on charly_b");
    let vc_credential = CredentialWithKey {
        credential: BasicCredential::new(b"Charly (VC)".to_vec()).into(),
        signature_key: vc_signer.public().into(),
    };

    // ... and a two-member emulator group from which both derive the same
    // derivation epoch (operation secret tree + AEAD key + EpochId).
    let (mut emulator_a, emulator_a_signer) =
        make_emulator_group(ciphersuite, &charly_a_provider, b"CharlyEmulatorA", true);
    let (_e_commit, emulator_b, _emulator_b_signer) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &charly_a_provider,
        &emulator_a_signer,
        &charly_b_provider,
        b"CharlyEmulatorB",
    );
    let epoch_id = newest_epoch(&emulator_a, &charly_a_provider);
    let epoch_id_b = newest_epoch(&emulator_b, &charly_b_provider);
    assert_eq!(
        epoch_id, epoch_id_b,
        "siblings must derive the same EpochId"
    );

    // Export the prior-epoch GroupInfo twice: one copy is consumed by
    // charly_a's external commit, the other is handed to charly_b so it can
    // rebuild the prior-epoch public group when bootstrapping. Both carry the
    // ratchet tree as an extension (the group uses `use_ratchet_tree_extension`).
    let export_prior_epoch_vgi = |label: &str| {
        let gi = alice_main
            .export_group_info(alice_provider.crypto(), &alice_signer, true)
            .unwrap_or_else(|_| panic!("export group info ({label})"));
        let serialized = gi.tls_serialize_detached().expect("serialize gi");
        MlsMessageIn::tls_deserialize(&mut serialized.as_slice())
            .expect("deserialize gi")
            .into_verifiable_group_info()
            .expect("into vgi")
    };
    let vgi_charly_a = export_prior_epoch_vgi("charly_a");
    let vgi_charly_b = export_prior_epoch_vgi("charly_b");
    let pre_join_message = alice_main
        .create_message(&alice_provider, &alice_signer, b"before charly joins")
        .expect("alice create pre-join app message");

    // Phase 1: charly_a (the first emulator client) joins the higher-level
    // group via an external commit. No prior Charly leaf exists, so this is a
    // plain external join, not a resync. Its leaf carries the external init
    // secret in the derivation info. Alice and Bob process it via HPKE.
    let (charly_a_main, bundle) = MlsGroup::external_commit_builder()
        .with_config(vc_join_config())
        .build_group(&charly_a_provider, vgi_charly_a, vc_credential.clone())
        .expect("build_group charly_a")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(vc_capabilities())
                .with_extensions(vc_leaf_extensions())
                .build(),
        )
        .vc_emulation(
            charly_a_provider.crypto(),
            charly_a_provider.storage(),
            emulator_a.group_id(),
        )
        .expect("vc emulation charly_a")
        .load_psks(charly_a_provider.storage())
        .expect("load psks")
        .build(
            charly_a_provider.rand(),
            charly_a_provider.crypto(),
            &vc_signer,
            |_| true,
        )
        .expect("build external commit charly_a")
        .finalize(&charly_a_provider)
        .expect("finalize charly_a join");
    let charly_a_join = bundle.into_commit();
    // A copy of charly_a's external commit for charly_b to process.
    let charly_a_commit_for_b = charly_a_join
        .clone()
        .into_protocol_message()
        .expect("charly_a commit as protocol message");
    process_and_merge_commit(&mut alice_main, &alice_provider, charly_a_join.clone());
    process_and_merge_commit(&mut bob_main, &bob_provider, charly_a_join);

    let auth_after_join = charly_a_main.epoch_authenticator();
    assert_eq!(alice_main.epoch_authenticator(), auth_after_join);
    assert_eq!(bob_main.epoch_authenticator(), auth_after_join);

    // Phase 2: charly_b bootstraps by *processing* charly_a's external commit.
    // It is not a member, so it rebuilds the prior-epoch public group from
    // `vgi_charly_b`, recreates the path from the shared operation secret tree,
    // and uses the external init secret carried in the commit. It lands on the
    // same virtual-client leaf charly_a occupies.
    let bootstrap_join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(1)
        .build();
    let mut charly_b_main = MlsGroup::vc_external_commit_join_builder()
        .with_config(bootstrap_join_config)
        .process_commit(
            &charly_b_provider,
            vgi_charly_b,
            charly_a_commit_for_b,
            epoch_id_b.clone(),
        )
        .expect("process charly_a's external commit")
        .into_group(&charly_b_provider)
        .expect("charly_b bootstraps by processing charly_a's external commit");
    let err = charly_b_main
        .process_message(
            &charly_b_provider,
            pre_join_message.into_protocol_message().unwrap(),
        )
        .expect_err("bootstrapped sibling must not retain fake prior-epoch secrets");
    let ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
        MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
    )) = err
    else {
        panic!("expected no usable past epoch secret for pre-bootstrap message");
    };

    // Both emulator clients now hold the VC's higher-level group state on one
    // shared leaf, and the whole group converges.
    assert!(charly_a_main.is_active() && charly_b_main.is_active());
    assert_eq!(
        charly_b_main.own_leaf_index(),
        charly_a_main.own_leaf_index(),
        "the bootstrapped sibling must land on the shared VC leaf"
    );
    let auth = charly_b_main.epoch_authenticator();
    assert_eq!(charly_a_main.epoch_authenticator(), auth);
    assert_eq!(alice_main.epoch_authenticator(), auth);
    assert_eq!(bob_main.epoch_authenticator(), auth);

    // The bootstrapped sibling is a working member: it decrypts an application
    // message from Alice, and a message it sends is decrypted by Alice and Bob.
    let alice_app = alice_main
        .create_message(&alice_provider, &alice_signer, b"hello charly_b")
        .expect("alice create app message");
    let processed = charly_b_main
        .process_message(
            &charly_b_provider,
            alice_app.into_protocol_message().unwrap(),
        )
        .expect("charly_b processes alice's app message");
    let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
        panic!("expected application message");
    };
    assert_eq!(message.into_bytes(), b"hello charly_b");

    let charly_b_app = charly_b_main
        .create_message(&charly_b_provider, &vc_signer, b"charly_b bootstrapped")
        .expect("charly_b create app message");
    for (group, provider) in [
        (&mut alice_main, &alice_provider),
        (&mut bob_main, &bob_provider),
    ] {
        let processed = group
            .process_message(
                provider,
                charly_b_app.clone().into_protocol_message().unwrap(),
            )
            .expect("process charly_b app message");
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            panic!("expected application message");
        };
        assert_eq!(message.into_bytes(), b"charly_b bootstrapped");
    }
}

/// The VC capabilities, extended with support for the AppEphemeral proposal
/// type. All leaves of a group need this before anyone may commit such a
/// proposal.
fn vc_app_ephemeral_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::AppDataDictionary])
        .proposals(vec![ProposalType::AppEphemeral])
        .build()
}

/// An AppEphemeral proposal attached by value to a virtual client's external
/// commit reaches both the members of the group and the committer's sibling.
///
/// `charly_a` joins the higher-level group (Alice + Bob) via an external commit
/// carrying the proposal. `charly_b` reads the payload out of that commit while
/// it is still an outsider, then bootstraps into the group with the
/// [`VcExternalCommitJoinBuilder`]. Alice and Bob find the
/// same payload in the staged commit, and all four parties converge.
#[openmls_test]
fn vc_sibling_reads_app_ephemeral_from_external_commit() {
    use openmls::component::ComponentId;
    use openmls::credentials::{BasicCredential, CredentialWithKey};
    use openmls::messages::proposals::{AppEphemeralProposal, Proposal};
    use openmls::prelude::{LeafNodeParameters, MlsMessageIn, ProtocolMessage};
    use tls_codec::Deserialize as _;

    const COMPONENT_ID: ComponentId = 7;
    const DATA: &[u8] = b"wrapped key material";

    let alice_provider = Provider::default();
    let bob_provider = Provider::default();
    let charly_a_provider = Provider::default();
    let charly_b_provider = Provider::default();

    // Alice founds the higher-level group and adds Bob. Every leaf declares
    // support for the AppEphemeral proposal type.
    let (alice_credential, alice_signer) =
        new_credential(&alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let main_group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_app_ephemeral_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    let mut alice_main = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &main_group_config,
        alice_credential,
    )
    .expect("create vc main group");

    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let bob_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_app_ephemeral_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    let (_, welcome, _) = alice_main
        .add_members(&alice_provider, &alice_signer, &[bob_kp])
        .expect("alice add bob");
    alice_main
        .merge_pending_commit(&alice_provider)
        .expect("alice merge add bob");
    let mut bob_main = StagedWelcome::new_from_welcome(
        &bob_provider,
        &vc_join_config(),
        welcome.into_welcome().expect("welcome"),
        Some(alice_main.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob join higher-level group");

    // Charly is one virtual client with two emulator clients sharing a signing
    // identity and a derivation epoch.
    let vc_signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("vc signer");
    vc_signer
        .store(charly_a_provider.storage())
        .expect("store vc signer on charly_a");
    vc_signer
        .store(charly_b_provider.storage())
        .expect("store vc signer on charly_b");
    let vc_credential = CredentialWithKey {
        credential: BasicCredential::new(b"Charly (VC)".to_vec()).into(),
        signature_key: vc_signer.public().into(),
    };

    let (mut emulator_a, emulator_a_signer) =
        make_emulator_group(ciphersuite, &charly_a_provider, b"CharlyEmulatorA", true);
    let (_e_commit, emulator_b, _emulator_b_signer) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &charly_a_provider,
        &emulator_a_signer,
        &charly_b_provider,
        b"CharlyEmulatorB",
    );
    let epoch_id = newest_epoch(&emulator_a, &charly_a_provider);
    let epoch_id_b = newest_epoch(&emulator_b, &charly_b_provider);
    assert_eq!(
        epoch_id, epoch_id_b,
        "siblings must derive the same EpochId"
    );

    // One copy of the prior-epoch GroupInfo is consumed by charly_a's external
    // commit, the other lets charly_b rebuild the prior-epoch public group.
    let export_prior_epoch_vgi = |label: &str| {
        let gi = alice_main
            .export_group_info(alice_provider.crypto(), &alice_signer, true)
            .unwrap_or_else(|_| panic!("export group info ({label})"));
        let serialized = gi.tls_serialize_detached().expect("serialize gi");
        MlsMessageIn::tls_deserialize(&mut serialized.as_slice())
            .expect("deserialize gi")
            .into_verifiable_group_info()
            .expect("into vgi")
    };
    let vgi_charly_a = export_prior_epoch_vgi("charly_a");
    let vgi_charly_b = export_prior_epoch_vgi("charly_b");

    let (charly_a_main, bundle) = MlsGroup::external_commit_builder()
        .with_config(vc_join_config())
        .build_group(&charly_a_provider, vgi_charly_a, vc_credential.clone())
        .expect("build_group charly_a")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(vc_app_ephemeral_capabilities())
                .with_extensions(vc_leaf_extensions())
                .build(),
        )
        .vc_emulation(
            charly_a_provider.crypto(),
            charly_a_provider.storage(),
            emulator_a.group_id(),
        )
        .expect("vc emulation charly_a")
        .add_proposal(Proposal::AppEphemeral(Box::new(AppEphemeralProposal::new(
            COMPONENT_ID,
            DATA.to_vec(),
        ))))
        .load_psks(charly_a_provider.storage())
        .expect("load psks")
        .build(
            charly_a_provider.rand(),
            charly_a_provider.crypto(),
            &vc_signer,
            |_| true,
        )
        .expect("build external commit charly_a")
        .finalize(&charly_a_provider)
        .expect("finalize charly_a join");
    let charly_a_join = bundle.into_commit();
    let charly_a_commit_for_b = charly_a_join
        .clone()
        .into_protocol_message()
        .expect("charly_a commit as protocol message");

    // Alice and Bob find the payload in the staged commit before merging it.
    for (group, provider) in [
        (&mut alice_main, &alice_provider),
        (&mut bob_main, &bob_provider),
    ] {
        let processed = group
            .process_message(
                provider,
                charly_a_join
                    .clone()
                    .into_protocol_message()
                    .expect("commit as protocol message"),
            )
            .expect("process charly_a external commit");
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("expected staged commit");
        };
        let staged = *staged;
        {
            let mut proposals = staged
                .staged_proposal_queue
                .app_ephemeral_proposals_for_component_id(COMPONENT_ID);
            let queued_proposal = proposals.next().expect("no AppEphemeral proposal");
            assert_eq!(queued_proposal.app_ephemeral_proposal().data(), DATA);
            assert!(proposals.next().is_none());
        }
        group
            .merge_staged_commit(provider, staged)
            .expect("merge staged commit");
    }

    // charly_b reads the payload while it is still an outsider, with no group
    // state of its own.
    let ProtocolMessage::PublicMessage(public_message) = &charly_a_commit_for_b else {
        panic!("an external commit is always a public message");
    };
    let peeked = public_message.unverified_app_ephemeral_proposals(COMPONENT_ID);
    assert_eq!(peeked.len(), 1);
    assert_eq!(peeked[0].data(), DATA);

    let bootstrap_join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(1)
        .build();
    let charly_b_main = MlsGroup::vc_external_commit_join_builder()
        .with_config(bootstrap_join_config)
        .process_commit(
            &charly_b_provider,
            vgi_charly_b,
            charly_a_commit_for_b,
            epoch_id_b.clone(),
        )
        .expect("process charly_a's external commit")
        .into_group(&charly_b_provider)
        .expect("charly_b bootstraps by processing charly_a's external commit");

    assert!(charly_a_main.is_active() && charly_b_main.is_active());
    assert_eq!(
        charly_b_main.own_leaf_index(),
        charly_a_main.own_leaf_index(),
        "the bootstrapped sibling must land on the shared VC leaf"
    );
    let auth = charly_b_main.epoch_authenticator();
    assert_eq!(charly_a_main.epoch_authenticator(), auth);
    assert_eq!(alice_main.epoch_authenticator(), auth);
    assert_eq!(bob_main.epoch_authenticator(), auth);
}

/// The VC capabilities, extended with support for the AppDataUpdate and
/// AppEphemeral proposal types. All leaves of a group need this before
/// anyone may commit such proposals.
fn vc_app_data_update_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::AppDataDictionary])
        .proposals(vec![
            ProposalType::AppDataUpdate,
            ProposalType::AppEphemeral,
        ])
        .build()
}

/// The group-context component the AppDataUpdate join tests below bump on
/// the external commit. The proposal payload deliberately differs from the
/// resulting dictionary value: the value is computed by the application from
/// the payload, not copied from it, so the tests prove the applied value
/// comes from the supplied updates.
const APP_DATA_COMPONENT_ID: ComponentId = 0xf042;
const APP_DATA_PROPOSAL_PAYLOAD: &[u8] = b"proposal payload";
const APP_DATA_DICT_VALUE: &[u8] = b"caller computed value";

/// Scenario for sibling joins of external commits carrying AppDataUpdate
/// proposals: Alice and Bob form the higher-level group (every leaf supports
/// the AppDataUpdate and AppEphemeral proposal types), and Charly is a
/// virtual client with two emulator clients sharing an emulation epoch.
struct VcAppDataScenario<P: OpenMlsProvider> {
    alice_provider: P,
    bob_provider: P,
    charly_a_provider: P,
    charly_b_provider: P,
    alice_main: MlsGroup,
    alice_signer: SignatureKeyPair,
    bob_main: MlsGroup,
    vc_signer: SignatureKeyPair,
    vc_credential: openmls::credentials::CredentialWithKey,
    emulation_group_id: GroupId,
    epoch_id: EpochId,
}

fn vc_app_data_scenario<P: OpenMlsProvider + Default>(
    ciphersuite: openmls_traits::types::Ciphersuite,
) -> VcAppDataScenario<P> {
    let alice_provider = P::default();
    let bob_provider = P::default();
    let charly_a_provider = P::default();
    let charly_b_provider = P::default();

    // Alice founds the higher-level group and adds Bob.
    let (alice_credential, alice_signer) =
        new_credential(&alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let main_group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_app_data_update_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    let mut alice_main = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &main_group_config,
        alice_credential,
    )
    .expect("create vc main group");

    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let bob_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_app_data_update_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    let (_, welcome, _) = alice_main
        .add_members(&alice_provider, &alice_signer, &[bob_kp])
        .expect("alice add bob");
    alice_main
        .merge_pending_commit(&alice_provider)
        .expect("alice merge add bob");
    let bob_main = StagedWelcome::new_from_welcome(
        &bob_provider,
        &vc_join_config(),
        welcome.into_welcome().expect("welcome"),
        Some(alice_main.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob join higher-level group");

    // Charly is one virtual client with two emulator clients sharing a
    // signing identity and a derivation epoch.
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &charly_a_provider, &charly_b_provider);
    let (mut emulator_a, emulator_a_signer) =
        make_emulator_group(ciphersuite, &charly_a_provider, b"CharlyEmulatorA", true);
    let (_e_commit, emulator_b, _emulator_b_signer) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &charly_a_provider,
        &emulator_a_signer,
        &charly_b_provider,
        b"CharlyEmulatorB",
    );
    let epoch_id = newest_epoch(&emulator_a, &charly_a_provider);
    let epoch_id_b = newest_epoch(&emulator_b, &charly_b_provider);
    assert_eq!(
        epoch_id, epoch_id_b,
        "siblings must derive the same EpochId"
    );
    let emulation_group_id = emulator_a.group_id().clone();

    VcAppDataScenario {
        alice_provider,
        bob_provider,
        charly_a_provider,
        charly_b_provider,
        alice_main,
        alice_signer,
        bob_main,
        vc_signer,
        vc_credential,
        emulation_group_id,
        epoch_id,
    }
}

impl<P: OpenMlsProvider> VcAppDataScenario<P> {
    /// Exports the prior-epoch GroupInfo (with the ratchet tree carried as an
    /// extension) for one of the parties consuming it.
    fn export_prior_epoch_vgi(&self, label: &str) -> VerifiableGroupInfo {
        use tls_codec::Deserialize as _;
        let gi = self
            .alice_main
            .export_group_info(self.alice_provider.crypto(), &self.alice_signer, true)
            .unwrap_or_else(|_| panic!("export group info ({label})"));
        let serialized = gi.tls_serialize_detached().expect("serialize gi");
        openmls::prelude::MlsMessageIn::tls_deserialize(&mut serialized.as_slice())
            .expect("deserialize gi")
            .into_verifiable_group_info()
            .expect("into vgi")
    }
}

/// charly_a joins the higher-level group via an external commit carrying a
/// by-value AppDataUpdate proposal for [`APP_DATA_COMPONENT_ID`], with the
/// dictionary value computed by the application, and optionally a by-value
/// AppEphemeral proposal. Returns charly_a's joined group and the commit for
/// the other parties to process.
fn charly_a_external_commit_with_app_data_update<P: OpenMlsProvider>(
    scenario: &VcAppDataScenario<P>,
    vgi: VerifiableGroupInfo,
    app_ephemeral: Option<AppEphemeralProposal>,
) -> (MlsGroup, openmls::prelude::MlsMessageOut) {
    let provider = &scenario.charly_a_provider;
    let mut builder = MlsGroup::external_commit_builder()
        .with_config(vc_join_config())
        .build_group(provider, vgi, scenario.vc_credential.clone())
        .expect("build_group charly_a")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(vc_app_data_update_capabilities())
                .with_extensions(vc_leaf_extensions())
                .build(),
        )
        .vc_emulation(
            provider.crypto(),
            provider.storage(),
            &scenario.emulation_group_id,
        )
        .expect("vc emulation charly_a")
        .add_app_data_update_proposal(AppDataUpdateProposal::update(
            APP_DATA_COMPONENT_ID,
            APP_DATA_PROPOSAL_PAYLOAD,
        ));
    if let Some(proposal) = app_ephemeral {
        builder = builder.add_proposal(Proposal::AppEphemeral(Box::new(proposal)));
    }
    let mut builder = builder.load_psks(provider.storage()).expect("load psks");
    let mut updater = builder.app_data_dictionary_updater();
    updater.set(ComponentData::from_parts(
        APP_DATA_COMPONENT_ID,
        APP_DATA_DICT_VALUE.to_vec().into(),
    ));
    builder.with_app_data_dictionary_updates(updater.changes());
    let (charly_a_main, bundle) = builder
        .build(
            provider.rand(),
            provider.crypto(),
            &scenario.vc_signer,
            |_| true,
        )
        .expect("build external commit charly_a")
        .finalize(provider)
        .expect("finalize charly_a join");
    (charly_a_main, bundle.into_commit())
}

/// Processes `commit` on `group`, resolves the expected AppDataUpdate
/// proposal for [`APP_DATA_COMPONENT_ID`] to [`APP_DATA_DICT_VALUE`], and
/// merges the resulting staged commit. This is the regular member-side
/// resolution flow the sibling join must reproduce.
fn resolve_and_merge_app_data_commit<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    commit: ProtocolMessage,
) {
    let processed = group
        .process_message(provider, commit)
        .expect("process app data commit");
    let ProcessedMessageContent::UnresolvedAppDataCommit(unresolved) = processed.into_content()
    else {
        panic!("expected an unresolved app data commit");
    };
    let mut updater = group.app_data_dictionary_updater();
    updater.set(ComponentData::from_parts(
        APP_DATA_COMPONENT_ID,
        APP_DATA_DICT_VALUE.to_vec().into(),
    ));
    let staged = group
        .stage_app_data_commit(provider, *unresolved, updater.changes())
        .expect("stage app data commit");
    group
        .merge_staged_commit(provider, staged)
        .expect("merge app data commit");
}

/// Reads the verified AppDataUpdate proposals from a staged sibling join,
/// checks they carry the expected payload, and computes the resolved updates
/// the join needs, the way an application's component logic would.
fn sibling_resolved_app_data_updates(
    staged: &StagedVcExternalCommitJoin,
) -> Option<AppDataUpdates> {
    let proposals: Vec<_> = staged.app_data_update_proposals().collect();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].component_id(), APP_DATA_COMPONENT_ID);
    let AppDataUpdateOperation::Update(payload) = proposals[0].operation() else {
        panic!("expected an update operation");
    };
    assert_eq!(payload.as_slice(), APP_DATA_PROPOSAL_PAYLOAD);

    // No dictionary exists in the prior-epoch group context yet, so the
    // component computes the value from the payload alone.
    let mut updater = staged.app_data_dictionary_updater();
    assert!(updater.old_value(APP_DATA_COMPONENT_ID).is_none());
    updater.set(ComponentData::from_parts(
        APP_DATA_COMPONENT_ID,
        APP_DATA_DICT_VALUE.to_vec().into(),
    ));
    updater.changes()
}

/// A sibling join of an external commit carrying an AppDataUpdate proposal:
/// the application supplies the resolved updates, the join succeeds, and the
/// joined group's context matches the committing sibling's byte for byte.
#[openmls_test]
fn vc_sibling_external_commit_join_resolves_app_data_updates() {
    let mut scenario = vc_app_data_scenario::<Provider>(ciphersuite);
    let vgi_charly_a = scenario.export_prior_epoch_vgi("charly_a");
    let vgi_charly_b = scenario.export_prior_epoch_vgi("charly_b");

    let (charly_a_main, commit) =
        charly_a_external_commit_with_app_data_update(&scenario, vgi_charly_a, None);

    // Alice and Bob resolve the commit through the regular member flow.
    resolve_and_merge_app_data_commit(
        &mut scenario.alice_main,
        &scenario.alice_provider,
        commit.clone().into_protocol_message().expect("commit"),
    );
    resolve_and_merge_app_data_commit(
        &mut scenario.bob_main,
        &scenario.bob_provider,
        commit.clone().into_protocol_message().expect("commit"),
    );

    // charly_b computes the same updates from the verified commit's
    // proposals and completes the join with them.
    let mut staged = MlsGroup::vc_external_commit_join_builder()
        .with_config(vc_join_config())
        .process_commit(
            &scenario.charly_b_provider,
            vgi_charly_b,
            commit.into_protocol_message().expect("commit"),
            scenario.epoch_id.clone(),
        )
        .expect("process charly_a's external commit");

    // The staged join exposes the group state at the epoch before the
    // commit: Alice and Bob, without the virtual-client leaf.
    let prior_epoch = staged.prior_group_context().epoch();
    assert_eq!(staged.prior_members().count(), 2);

    let updates = sibling_resolved_app_data_updates(&staged);
    staged.with_app_data_dictionary_updates(updates);
    let charly_b_main = staged
        .into_group(&scenario.charly_b_provider)
        .expect("charly_b joins with resolved app data updates");
    assert_eq!(charly_b_main.epoch().as_u64(), prior_epoch.as_u64() + 1);

    assert!(charly_a_main.is_active() && charly_b_main.is_active());
    assert_eq!(
        charly_b_main.own_leaf_index(),
        charly_a_main.own_leaf_index(),
        "the bootstrapped sibling must land on the shared VC leaf"
    );
    let auth = charly_b_main.epoch_authenticator();
    assert_eq!(charly_a_main.epoch_authenticator(), auth);
    assert_eq!(scenario.alice_main.epoch_authenticator(), auth);
    assert_eq!(scenario.bob_main.epoch_authenticator(), auth);

    // The joined group's context matches the committing sibling's byte for
    // byte, and its dictionary carries the caller-computed value.
    assert_eq!(
        charly_b_main
            .export_group_context()
            .tls_serialize_detached()
            .expect("serialize charly_b context"),
        charly_a_main
            .export_group_context()
            .tls_serialize_detached()
            .expect("serialize charly_a context"),
    );
    let dictionary = charly_b_main
        .export_group_context()
        .extensions()
        .app_data_dictionary()
        .expect("joined context carries the dictionary")
        .dictionary();
    assert_eq!(
        dictionary.get(&APP_DATA_COMPONENT_ID),
        Some(APP_DATA_DICT_VALUE)
    );
}

/// An external commit carrying both an AppDataUpdate proposal and a by-value
/// AppEphemeral proposal: the sibling reads both payloads while still an
/// outsider and the join succeeds with the resolved updates.
#[openmls_test]
fn vc_sibling_external_commit_join_with_app_data_update_and_app_ephemeral() {
    const APP_EPHEMERAL_COMPONENT_ID: ComponentId = 7;
    const APP_EPHEMERAL_DATA: &[u8] = b"wrapped key material";

    let mut scenario = vc_app_data_scenario::<Provider>(ciphersuite);
    let vgi_charly_a = scenario.export_prior_epoch_vgi("charly_a");
    let vgi_charly_b = scenario.export_prior_epoch_vgi("charly_b");

    let (charly_a_main, commit) = charly_a_external_commit_with_app_data_update(
        &scenario,
        vgi_charly_a,
        Some(AppEphemeralProposal::new(
            APP_EPHEMERAL_COMPONENT_ID,
            APP_EPHEMERAL_DATA.to_vec(),
        )),
    );

    resolve_and_merge_app_data_commit(
        &mut scenario.alice_main,
        &scenario.alice_provider,
        commit.clone().into_protocol_message().expect("commit"),
    );
    resolve_and_merge_app_data_commit(
        &mut scenario.bob_main,
        &scenario.bob_provider,
        commit.clone().into_protocol_message().expect("commit"),
    );

    // charly_b reads both payloads from the verified commit before deciding
    // to complete the join.
    let mut staged = MlsGroup::vc_external_commit_join_builder()
        .with_config(vc_join_config())
        .process_commit(
            &scenario.charly_b_provider,
            vgi_charly_b,
            commit.into_protocol_message().expect("commit"),
            scenario.epoch_id.clone(),
        )
        .expect("process charly_a's external commit");
    let app_ephemeral: Vec<_> = staged
        .app_ephemeral_proposals_for_component_id(APP_EPHEMERAL_COMPONENT_ID)
        .collect();
    assert_eq!(app_ephemeral.len(), 1);
    assert_eq!(app_ephemeral[0].data(), APP_EPHEMERAL_DATA);
    let updates = sibling_resolved_app_data_updates(&staged);
    staged.with_app_data_dictionary_updates(updates);

    let charly_b_main = staged
        .into_group(&scenario.charly_b_provider)
        .expect("charly_b joins a commit carrying AppDataUpdate and AppEphemeral");

    assert!(charly_a_main.is_active() && charly_b_main.is_active());
    assert_eq!(
        charly_b_main.own_leaf_index(),
        charly_a_main.own_leaf_index(),
        "the bootstrapped sibling must land on the shared VC leaf"
    );
    let auth = charly_b_main.epoch_authenticator();
    assert_eq!(charly_a_main.epoch_authenticator(), auth);
    assert_eq!(scenario.alice_main.epoch_authenticator(), auth);
    assert_eq!(scenario.bob_main.epoch_authenticator(), auth);
    assert_eq!(
        charly_b_main
            .export_group_context()
            .tls_serialize_detached()
            .expect("serialize charly_b context"),
        charly_a_main
            .export_group_context()
            .tls_serialize_detached()
            .expect("serialize charly_a context"),
    );
}

/// Without the resolved updates, a sibling join of an external commit
/// carrying an AppDataUpdate proposal fails cleanly before consuming an
/// operation secret generation, so the sibling can compute the updates and
/// join by processing the same commit again.
#[openmls_test]
fn vc_sibling_external_commit_join_without_app_data_updates_fails() {
    let scenario = vc_app_data_scenario::<Provider>(ciphersuite);
    let vgi_charly_a = scenario.export_prior_epoch_vgi("charly_a");
    let vgi_first_attempt = scenario.export_prior_epoch_vgi("charly_b first attempt");
    let vgi_retry = scenario.export_prior_epoch_vgi("charly_b retry");

    let (charly_a_main, commit) =
        charly_a_external_commit_with_app_data_update(&scenario, vgi_charly_a, None);

    let staged = MlsGroup::vc_external_commit_join_builder()
        .with_config(vc_join_config())
        .process_commit(
            &scenario.charly_b_provider,
            vgi_first_attempt,
            commit.clone().into_protocol_message().expect("commit"),
            scenario.epoch_id.clone(),
        )
        .expect("process charly_a's external commit");
    let err = staged
        .into_group(&scenario.charly_b_provider)
        .expect_err("joining without the resolved updates must fail");
    let VcExternalCommitJoinError::StageCommitError(StageCommitError::ApplyAppDataUpdateError(
        ApplyAppDataUpdateError::MissingAppDataUpdates,
    )) = err
    else {
        panic!("expected MissingAppDataUpdates, got {err:?}");
    };

    // The failed attempt did not consume an operation secret generation, so
    // processing the same commit again and joining with the resolved updates
    // succeeds.
    let mut staged = MlsGroup::vc_external_commit_join_builder()
        .with_config(vc_join_config())
        .process_commit(
            &scenario.charly_b_provider,
            vgi_retry,
            commit.into_protocol_message().expect("commit"),
            scenario.epoch_id.clone(),
        )
        .expect("process charly_a's external commit again");
    let updates = sibling_resolved_app_data_updates(&staged);
    staged.with_app_data_dictionary_updates(updates);
    let charly_b_main = staged
        .into_group(&scenario.charly_b_provider)
        .expect("retry with resolved updates succeeds");
    assert_eq!(
        charly_b_main.epoch_authenticator(),
        charly_a_main.epoch_authenticator()
    );
}

/// Updates that do not reproduce the committing sibling's dictionary fail
/// the join at the confirmation tag check instead of installing a diverged
/// group context.
#[openmls_test]
fn vc_sibling_external_commit_join_with_wrong_app_data_updates_fails() {
    let scenario = vc_app_data_scenario::<Provider>(ciphersuite);
    let vgi_charly_a = scenario.export_prior_epoch_vgi("charly_a");
    let vgi_charly_b = scenario.export_prior_epoch_vgi("charly_b");

    let (_charly_a_main, commit) =
        charly_a_external_commit_with_app_data_update(&scenario, vgi_charly_a, None);

    let mut staged = MlsGroup::vc_external_commit_join_builder()
        .with_config(vc_join_config())
        .process_commit(
            &scenario.charly_b_provider,
            vgi_charly_b,
            commit.into_protocol_message().expect("commit"),
            scenario.epoch_id.clone(),
        )
        .expect("process charly_a's external commit");
    let mut updater = staged.app_data_dictionary_updater();
    updater.set(ComponentData::from_parts(
        APP_DATA_COMPONENT_ID,
        b"a different value".to_vec().into(),
    ));
    let updates = updater.changes();
    staged.with_app_data_dictionary_updates(updates);
    let err = staged
        .into_group(&scenario.charly_b_provider)
        .expect_err("joining with wrong updates must fail");
    let VcExternalCommitJoinError::StageCommitError(StageCommitError::ConfirmationTagMismatch) =
        err
    else {
        panic!("expected ConfirmationTagMismatch, got {err:?}");
    };
}

/// A sibling emulator joins a higher-level group via a virtual client's
/// KeyPackage that another emulator published.
///
///   * `alice_a` and `alice_b` share an emulator group and both register the
///     same derivation epoch, so both hold its `VcDerivationEpochState` and
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
        make_emulator_group(ciphersuite, &alice_a_provider, b"AliceEmulatorA", true);
    let (_e_commit, emulator_b, _emulator_b_signer) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &alice_a_provider,
        &emulator_a_signer,
        &alice_b_provider,
        b"AliceEmulatorB",
    );

    // Both emulators register the same derivation epoch.
    let epoch_id_a = newest_epoch(&emulator_a, &alice_a_provider);
    let epoch_id_b = newest_epoch(&emulator_b, &alice_b_provider);
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
            emulator_a.group_id(),
            1,
        )
        .expect("alice_a build_vc_batch");
    assert_eq!(
        batch.epoch_id, epoch_id_a,
        "the batch must use the emulator group's newest derivation epoch"
    );
    let generation = batch.generation;
    let batch_epoch_id = batch.epoch_id.clone();
    let (vc_key_package_bundle, kp_info) = batch.key_packages.remove(0);
    let upload = assemble_vc_key_package_upload(
        alice_a_provider.storage(),
        batch_epoch_id,
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
        make_emulator_group(ciphersuite, &alice_a_provider, b"AliceEmulatorA", true);
    let (_e_commit, emulator_b, _emulator_b_signer) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &alice_a_provider,
        &emulator_a_signer,
        &alice_b_provider,
        b"AliceEmulatorB",
    );

    let epoch_id_a = newest_epoch(&emulator_a, &alice_a_provider);
    let epoch_id_b = newest_epoch(&emulator_b, &alice_b_provider);
    assert_eq!(
        epoch_id_a, epoch_id_b,
        "siblings must derive the same EpochId"
    );

    // One batch of 40 KeyPackages, larger than OUT_OF_ORDER_TOLERANCE (32).
    let count = 40;
    let batch = KeyPackage::builder()
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build_vc_batch(
            ciphersuite,
            &alice_a_provider,
            &vc_signer,
            vc_credential.clone(),
            emulator_a.group_id(),
            count,
        )
        .expect("alice_a build_vc_batch");
    assert_eq!(
        batch.epoch_id, epoch_id_a,
        "the batch must use the emulator group's newest derivation epoch"
    );
    let generation = batch.generation;
    assert_eq!(generation, 0, "the batch consumes a single generation");
    assert_eq!(batch.key_packages.len(), count);

    let kp_infos = batch
        .key_packages
        .iter()
        .map(|(_bundle, info)| info)
        .map(
            |info| openmls::components::vc_derivation_info::KeyPackageInfo {
                key_package_ref: info.key_package_ref.clone(),
                cipher_suite: info.cipher_suite,
                key_package_index: info.key_package_index,
            },
        )
        .collect::<Vec<_>>();
    let upload = assemble_vc_key_package_upload(
        alice_a_provider.storage(),
        batch.epoch_id.clone(),
        generation,
        kp_infos,
    )
    .expect("assemble upload");
    process_vc_key_package_upload(&alice_b_provider, &upload).expect("alice_b process upload");

    // The sibling joins via a HIGH batch index first and a LOW one second,
    // each through a separate higher-level group.
    let high_bundle = batch.key_packages[count - 1].0.key_package().clone();
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

    // Alice's group is bound to a derivation epoch, so the dual-use ratchet
    // retains the secrets of unconfirmed own sends.
    let mut alice_group =
        new_vc_main_group(ciphersuite, alice_provider, &alice_signer, alice_credential);
    let (emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, alice_provider, b"AliceEmulator", true);
    let _ = send_vc_commit(
        &mut alice_group,
        &emulator_group,
        alice_provider,
        &alice_signer,
    );

    // Alice sends an application message and decrypts her own echo via the
    // retained secret.
    let alice_message = b"Hello, this is Alice!";
    let unconfirmed = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, alice_message)
        .unwrap();
    assert!(
        unconfirmed.generation_id.is_some(),
        "a bound group must produce a generation id"
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

    // Processing the message again fails: the first pass consumed the
    // retained secret.
    let err = alice_group
        .process_message(alice_provider, ciphertext.into_protocol_message().unwrap())
        .expect_err("a consumed generation must not decrypt again");
    let ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
        MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError),
    )) = err
    else {
        panic!("expected a secret reuse error, got {err:?}");
    };

    // Alice sends another application message and confirms it. Its secret is
    // deleted, so its echo no longer decrypts.
    let alice_message = b"Hello, this is Alice again!";
    let unconfirmed = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, alice_message)
        .unwrap();
    let ciphertext = unconfirmed.message;
    alice_group
        .confirm_application_message(
            alice_provider.storage(),
            unconfirmed.epoch,
            unconfirmed.generation,
        )
        .unwrap();

    let err = alice_group
        .process_message(alice_provider, ciphertext.into_protocol_message().unwrap())
        .expect_err("a confirmed generation must not decrypt");
    let ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
        MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError),
    )) = err
    else {
        panic!("expected a secret reuse error, got {err:?}");
    };
}

/// Without an emulation binding, an own private message short-circuits to
/// `OwnPrivateMessage` before touching any ratchet state, regardless of
/// whether its retained secret was consumed or confirmed.
#[openmls_test::openmls_test]
fn own_echo_in_unbound_group_short_circuits() {
    let alice_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential)
        .expect("alice create group");

    let unconfirmed = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, b"no binding")
        .expect("create unconfirmed message");
    assert!(
        unconfirmed.generation_id.is_none(),
        "a group with no emulation binding must not produce a generation id"
    );

    for _ in 0..2 {
        let processed = alice_group
            .process_message(
                alice_provider,
                unconfirmed.message.clone().into_protocol_message().unwrap(),
            )
            .expect("process own echo");
        assert!(matches!(
            processed.into_content(),
            ProcessedMessageContent::OwnPrivateMessage
        ));
    }
}

/// Confirming a message deletes the secret of its own creation epoch, even
/// after the group has advanced past that epoch, and never the secret of a
/// different message that happens to share the generation number in a newer
/// epoch.
#[openmls_test::openmls_test]
fn confirm_targets_creation_epoch() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    // Alice keeps one past epoch so the secret retained at epoch N survives
    // into epoch N+1.
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(1)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &group_config,
        alice_credential,
    )
    .expect("alice create group");

    let bob_key_package = KeyPackage::builder()
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

    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        &vc_join_config(),
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(bob_provider))
    .expect("bob join");

    // Bind the group to a derivation epoch so own echoes are decryptable.
    let (emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, alice_provider, b"AliceEmulator", true);
    let binding_commit = send_vc_commit(
        &mut alice_group,
        &emulator_group,
        alice_provider,
        &alice_signer,
    );
    process_and_merge_commit(&mut bob_group, bob_provider, binding_commit);

    // Epoch N: Alice creates the first application message of the epoch.
    let msg1 = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, b"epoch N message")
        .expect("create msg1");

    // Bob commits, Alice processes and merges, moving to epoch N+1.
    let bob_commit = bob_group
        .self_update(bob_provider, &bob_signer, LeafNodeParameters::default())
        .expect("bob self-update")
        .into_commit();
    bob_group
        .merge_pending_commit(bob_provider)
        .expect("bob merge self-update");
    let processed = alice_group
        .process_message(alice_provider, bob_commit.into_protocol_message().unwrap())
        .expect("alice process bob commit");
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("expected a staged commit");
    };
    alice_group
        .merge_staged_commit(alice_provider, *staged)
        .expect("alice merge bob commit");

    // Epoch N+1: Alice creates the first application message of the epoch.
    let msg2 = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, b"epoch N+1 message")
        .expect("create msg2");

    assert_ne!(
        msg1.epoch, msg2.epoch,
        "the commit must have advanced the epoch"
    );
    assert_eq!(
        msg1.generation, msg2.generation,
        "both are the first application send of their epoch"
    );

    // Confirming msg1 at its creation epoch must not touch msg2's secret,
    // which shares the generation number in the newer epoch.
    alice_group
        .confirm_application_message(alice_provider.storage(), msg1.epoch, msg1.generation)
        .expect("confirm msg1");

    // msg2's secret is intact, so its echo decrypts.
    let processed = alice_group
        .process_message(
            alice_provider,
            msg2.message.into_protocol_message().unwrap(),
        )
        .expect("process msg2 echo");
    let ProcessedMessageContent::ApplicationMessage(app) = processed.into_content() else {
        panic!("expected msg2 to decrypt to an application message");
    };
    assert_eq!(app.into_bytes().as_slice(), b"epoch N+1 message");

    // msg1's secret was deleted, so its echo no longer decrypts.
    let err = alice_group
        .process_message(
            alice_provider,
            msg1.message.into_protocol_message().unwrap(),
        )
        .expect_err("msg1's confirmed generation must not decrypt");
    let ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
        MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError),
    )) = err
    else {
        panic!("expected a secret reuse error, got {err:?}");
    };
}

/// Confirming a message whose creation epoch has aged out of the message
/// secrets store is a no-op success.
#[openmls_test::openmls_test]
fn confirm_aged_out_epoch_is_noop() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    // Default config keeps no past epochs.
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential)
        .expect("alice create group");

    let bob_key_package = KeyPackage::builder()
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

    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(bob_provider))
    .expect("bob join");

    let msg = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, b"epoch N message")
        .expect("create msg");

    // Bob commits, Alice advances to epoch N+1. With no retained past epochs,
    // the epoch-N secret tree is dropped.
    let bob_commit = bob_group
        .self_update(bob_provider, &bob_signer, LeafNodeParameters::default())
        .expect("bob self-update")
        .into_commit();
    bob_group
        .merge_pending_commit(bob_provider)
        .expect("bob merge self-update");
    let processed = alice_group
        .process_message(alice_provider, bob_commit.into_protocol_message().unwrap())
        .expect("alice process bob commit");
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("expected a staged commit");
    };
    alice_group
        .merge_staged_commit(alice_provider, *staged)
        .expect("alice merge bob commit");

    alice_group
        .confirm_application_message(alice_provider.storage(), msg.epoch, msg.generation)
        .expect("confirming an aged-out epoch must be a no-op success");
}

/// Confirming a message whose secret was already consumed by processing its
/// own echo is a no-op success.
#[openmls_test::openmls_test]
fn confirm_after_processing_own_echo_is_noop() {
    let alice_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let mut alice_group =
        new_vc_main_group(ciphersuite, alice_provider, &alice_signer, alice_credential);
    let (emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, alice_provider, b"AliceEmulator", true);
    let _ = send_vc_commit(
        &mut alice_group,
        &emulator_group,
        alice_provider,
        &alice_signer,
    );

    let unconfirmed = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, b"echo me")
        .expect("create unconfirmed message");
    let epoch = unconfirmed.epoch;
    let generation = unconfirmed.generation;

    let processed = alice_group
        .process_message(
            alice_provider,
            unconfirmed.message.into_protocol_message().unwrap(),
        )
        .expect("process own echo");
    let ProcessedMessageContent::ApplicationMessage(app) = processed.into_content() else {
        panic!("expected the own echo to decrypt");
    };
    assert_eq!(app.into_bytes().as_slice(), b"echo me");

    alice_group
        .confirm_application_message(alice_provider.storage(), epoch, generation)
        .expect("confirming an already-consumed generation must be a no-op success");
}

/// Confirming an epoch newer than the group's current epoch errors.
#[openmls_test::openmls_test]
fn confirm_future_epoch_errors() {
    let alice_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential)
        .expect("alice create group");

    let future_epoch = GroupEpoch::from(alice_group.epoch().as_u64() + 1);
    let err = alice_group
        .confirm_application_message(alice_provider.storage(), future_epoch, 0)
        .expect_err("confirming a future epoch must error");
    assert!(matches!(err, ConfirmMessageError::FutureEpoch));
}

/// A retained own handshake secret decrypts the message's own echo, and
/// `confirm_handshake_message` deletes it.
#[openmls_test::openmls_test]
fn confirm_handshake_message_deletes_retained_secret() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let (charlie_credential, charlie_signer) = new_credential(
        alice_provider,
        b"Charlie",
        ciphersuite.signature_algorithm(),
    );
    let (dave_credential, dave_signer) =
        new_credential(alice_provider, b"Dave", ciphersuite.signature_algorithm());

    // Pure-ciphertext framing so proposals are sent and accepted as
    // PrivateMessage.
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &group_config,
        alice_credential,
    )
    .expect("alice create group");

    let bob_key_package = KeyPackage::builder()
        .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    let (_commit, _welcome, _gi) = alice_group
        .add_members(alice_provider, &alice_signer, &[bob_key_package])
        .expect("alice add bob");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("alice merge add");

    // Bind the group to a derivation epoch so own echoes are decryptable.
    let (emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, alice_provider, b"AliceEmulator", true);
    let _ = send_vc_commit(
        &mut alice_group,
        &emulator_group,
        alice_provider,
        &alice_signer,
    );

    let charlie_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            alice_provider,
            &charlie_signer,
            charlie_credential,
        )
        .expect("charlie KP build")
        .key_package()
        .to_owned();
    let dave_key_package = KeyPackage::builder()
        .build(ciphersuite, alice_provider, &dave_signer, dave_credential)
        .expect("dave KP build")
        .key_package()
        .to_owned();

    let epoch = alice_group.epoch();

    // The first handshake send of this epoch uses generation 0.
    // `propose_unconfirmed` retains the handshake secret.
    let (proposal_a, _ref_a, _confirmation_a) = alice_group
        .propose_unconfirmed(
            alice_provider,
            &alice_signer,
            Propose::Add(charlie_key_package),
            ProposalOrRefType::Reference,
        )
        .expect("propose add charlie");

    // Processing proposal A's own echo without confirming decrypts it, which
    // proves the own handshake ratchet retains the secret.
    let processed = alice_group
        .process_message(alice_provider, proposal_a.into_protocol_message().unwrap())
        .expect("process proposal A echo");
    assert!(matches!(
        processed.into_content(),
        ProcessedMessageContent::ProposalMessage(_)
    ));

    // Proposal B uses handshake generation 1.
    let (proposal_b, _ref_b, _confirmation_b) = alice_group
        .propose_unconfirmed(
            alice_provider,
            &alice_signer,
            Propose::Add(dave_key_package),
            ProposalOrRefType::Reference,
        )
        .expect("propose add dave");
    alice_group
        .confirm_handshake_message(alice_provider.storage(), epoch, 1)
        .expect("confirm proposal B");

    // Proposal B's secret was deleted, so its echo no longer decrypts.
    let err = alice_group
        .process_message(alice_provider, proposal_b.into_protocol_message().unwrap())
        .expect_err("proposal B's confirmed generation must not decrypt");
    let ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
        MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError),
    )) = err
    else {
        panic!("expected a secret reuse error, got {err:?}");
    };
}

#[openmls_test::openmls_test]
fn unconfirmed_message_decrypts_after_next_message_is_confirmed() {
    let alice_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let mut alice_group =
        new_vc_main_group(ciphersuite, alice_provider, &alice_signer, alice_credential);
    let (emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, alice_provider, b"AliceEmulator", true);
    let _ = send_vc_commit(
        &mut alice_group,
        &emulator_group,
        alice_provider,
        &alice_signer,
    );

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
        .confirm_application_message(alice_provider.storage(), second.epoch, second.generation)
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

    let mut alice_group =
        new_vc_main_group(ciphersuite, alice_provider, &alice_signer, alice_credential);
    let (emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, alice_provider, b"AliceEmulator", true);
    let _ = send_vc_commit(
        &mut alice_group,
        &emulator_group,
        alice_provider,
        &alice_signer,
    );

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
            .confirm_application_message(alice_provider.storage(), later.epoch, later.generation)
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
/// random reuse guard if the bound derivation epoch state is missing.
#[test]
fn bound_group_fails_closed_when_derivation_state_missing_on_send() {
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
    let (emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, &provider, b"AliceEmulator", true);

    let epoch_id = newest_epoch(&emulator_group, &provider);
    let _commit_msg = send_vc_commit(&mut alice_group, &emulator_group, &provider, &alice_signer);

    // The group's binding keeps the epoch state alive, so the guarded delete
    // refuses while the binding is stored.
    let bindings: VcEmulationBindings = provider
        .storage()
        .vc_emulation_bindings(alice_group.group_id())
        .expect("read emulation bindings")
        .expect("the VC commit bound the group");
    assert!(!provider
        .storage()
        .delete_vc_derivation_epoch_state_if_unreferenced(&epoch_id)
        .expect("guarded delete while bound"));

    // Drop the binding. The emulator group's registration record alone still
    // keeps the epoch state alive.
    provider
        .storage()
        .delete_vc_emulation_bindings(alice_group.group_id())
        .expect("drop emulation bindings");
    assert!(!provider
        .storage()
        .delete_vc_derivation_epoch_state_if_unreferenced(&epoch_id)
        .expect("guarded delete while registered"));

    // Drop the registration too, delete the state, then put the binding back.
    // That leaves the group bound to an epoch whose state is gone, which is
    // the situation a corrupted or partially restored store can produce.
    provider
        .storage()
        .delete_registered_vc_derivation_epoch(emulator_group.group_id())
        .expect("drop registered derivation epoch");
    let deleted = provider
        .storage()
        .delete_vc_derivation_epoch_state_if_unreferenced(&epoch_id)
        .expect("delete derivation epoch state");
    assert!(
        deleted,
        "nothing references the epoch, so the epoch state is deleted"
    );
    provider
        .storage()
        .write_vc_emulation_bindings(
            alice_group.group_id(),
            &bindings,
            &bindings.bound_epoch_ids(),
        )
        .expect("restore emulation bindings");

    let err = alice_group
        .create_message(&provider, &alice_signer, b"must not send")
        .expect_err("bound group without derivation epoch state must fail closed");

    assert!(
        matches!(
            err,
            openmls::group::CreateMessageError::MessageEncryptionError(
                openmls::framing::errors::MessageEncryptionError::VirtualClientsError(
                    openmls::components::vc_derivation_info::VirtualClientsError::MissingDerivationEpochState
                )
            )
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn aged_out_binding_releases_derivation_epoch_state() {
    let ciphersuite =
        openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) =
        new_credential(&provider, b"Alice", ciphersuite.signature_algorithm());

    let mut alice_group =
        new_vc_main_group(ciphersuite, &provider, &alice_signer, alice_credential);
    let (mut emulator_group, emulator_signer) =
        make_emulator_group(ciphersuite, &provider, b"AliceEmulator", true);

    let epoch_id_one = newest_epoch(&emulator_group, &provider);
    let _commit = send_vc_commit(&mut alice_group, &emulator_group, &provider, &alice_signer);

    // Start a second derivation epoch on the emulation group. The emulator's
    // registration record then references only the new epoch, so the group's
    // binding is all that keeps the first epoch's state alive.
    let _bundle = emulator_group
        .commit_builder()
        .derivation_epoch(true)
        .force_self_update(true)
        .load_psks(provider.storage())
        .expect("load psks")
        .build(provider.rand(), provider.crypto(), &emulator_signer, |_| {
            true
        })
        .expect("build emulator commit with marker")
        .stage_commit(&provider)
        .expect("stage emulator commit with marker");
    emulator_group
        .merge_pending_commit(&provider)
        .expect("emulator merge marker commit");
    let epoch_id_two = newest_epoch(&emulator_group, &provider);
    assert_ne!(epoch_id_one, epoch_id_two);
    assert!(!provider
        .storage()
        .delete_vc_derivation_epoch_state_if_unreferenced(&epoch_id_one)
        .expect("guarded delete while bound"));

    // The second VC commit rewrites the bindings. The group retains no past
    // message secrets, so the record keeps a single entry and the rewrite
    // drops the first epoch from the bound-epochs list.
    let _commit = send_vc_commit(&mut alice_group, &emulator_group, &provider, &alice_signer);
    let bindings: VcEmulationBindings = provider
        .storage()
        .vc_emulation_bindings(alice_group.group_id())
        .expect("read emulation bindings")
        .expect("emulation bindings present");
    assert_eq!(bindings.bound_epoch_ids(), vec![epoch_id_two.clone()]);

    // Nothing references the first epoch anymore, so its state is deletable.
    // The second epoch stays alive through the new binding.
    assert!(provider
        .storage()
        .delete_vc_derivation_epoch_state_if_unreferenced(&epoch_id_one)
        .expect("guarded delete of the aged-out epoch"));
    assert!(!provider
        .storage()
        .delete_vc_derivation_epoch_state_if_unreferenced(&epoch_id_two)
        .expect("guarded delete of the still-bound epoch"));
}

/// On a group bound to a derivation epoch, `create_unconfirmed_message`
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
    let (emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, &provider, b"AliceEmulator", true);

    // Bind alice_group's current epoch to the derivation epoch.
    let _ = send_vc_commit(&mut alice_group, &emulator_group, &provider, &alice_signer);

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
        .confirm_application_message(provider.storage(), first.epoch, first.generation)
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
    let (emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, &provider, b"AliceEmulator", true);

    let err = alice_group
        .commit_builder()
        .vc_emulation(
            provider.crypto(),
            provider.storage(),
            emulator_group.group_id(),
        )
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

/// A group that registered no derivation epoch, because it is not an emulation
/// group, cannot back a virtual-client operation. The sender-side entry points
/// resolve the epoch themselves, so this is where the mistake surfaces.
#[openmls_test]
fn vc_operations_reject_a_group_without_a_derivation_epoch() {
    use openmls::components::vc_derivation_info::VirtualClientsError;

    let provider = Provider::default();
    let (alice_credential, alice_signer) =
        new_credential(&provider, b"Alice", ciphersuite.signature_algorithm());
    let mut alice_group =
        new_vc_main_group(ciphersuite, &provider, &alice_signer, alice_credential);
    let (unregistered, _signer) =
        make_emulator_group(ciphersuite, &provider, b"AliceEmulator", false);

    let err = alice_group
        .commit_builder()
        .vc_emulation(
            provider.crypto(),
            provider.storage(),
            unregistered.group_id(),
        )
        .expect_err("a group without a derivation epoch must be rejected");
    assert!(
        matches!(
            err,
            openmls::group::CreateCommitError::VirtualClientsError(
                VirtualClientsError::NoDerivationEpoch
            )
        ),
        "unexpected error: {err:?}"
    );

    let (vc_credential, vc_signer) =
        new_credential(&provider, b"Alice (VC)", ciphersuite.signature_algorithm());
    let err = KeyPackage::builder()
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build_vc_batch(
            ciphersuite,
            &provider,
            &vc_signer,
            vc_credential,
            unregistered.group_id(),
            1,
        )
        .expect_err("a group without a derivation epoch must be rejected");
    assert!(
        matches!(
            err,
            openmls::prelude::KeyPackageNewError::VirtualClientsError(
                VirtualClientsError::NoDerivationEpoch
            )
        ),
        "unexpected error: {err:?}"
    );
}

/// End-to-end reuse-guard recovery with the emulator group and the
/// higher-level group on different ciphersuites with different AEAD key
/// lengths. The derivation epoch's AEAD and operation-tree material must
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
/// message from a previous epoch is deprotected with the derivation epoch that
/// was bound when it was sent, even after a later VC commit re-bound the
/// group to a newer derivation epoch.
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
    // epoch to the first derivation epoch. alice_a converges by processing
    // it. ----
    process_and_merge_commit(&mut alice_a_main, &alice_a_provider, resync_commit);
    let first_bound_epoch = alice_a_main.epoch();

    // ---- Delayed message, sent in the first bound epoch but delivered
    // only after the second commit below. ----
    let plaintext = b"delayed across an epoch change";
    let delayed_msg = alice_a_main
        .create_message(&alice_a_provider, &vc_signer, plaintext)
        .expect("alice_a creates delayed application message");

    // ---- Advance the emulation group with a commit that starts a second
    // derivation epoch on both emulator clients. ----
    let emulator_commit = {
        let bundle = emulator_a
            .commit_builder()
            .derivation_epoch(true)
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

    let epoch_id_two = newest_epoch(&emulator_a, &alice_a_provider);
    let epoch_id_two_b = newest_epoch(&emulator_b, &alice_b_provider);
    assert_eq!(epoch_id_two, epoch_id_two_b);
    assert_ne!(epoch_id_one, epoch_id_two);

    // ---- Second VC commit: re-binds the group to the second derivation
    // epoch. ----
    let commit_two_epoch_id = newest_epoch(&emulator_a, &alice_a_provider);
    let commit_two = send_vc_commit(
        &mut alice_a_main,
        &emulator_a,
        &alice_a_provider,
        &vc_signer,
    );
    assert_eq!(
        commit_two_epoch_id, epoch_id_two,
        "a commit must use the emulation group's newest derivation epoch"
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

    // ---- The delayed message is attributed via the first derivation
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
///     is bound to the derivation epoch and `alice_b` holds no pending commit of
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

/// Regression test: a virtual client's own VC commit fanned back by the
/// delivery service must surface as `OwnPendingCommit`, not fail while loading
/// sibling-commit material.
///
/// alice_a and alice_b are sibling emulators sharing the higher-level leaf and
/// one derivation epoch, in a group that also holds the regular member bob.
/// alice_a builds a VC commit and, before merging it, processes the copy the
/// delivery service echoed back. The commit is framed as
/// `Sender::Member(own_leaf_index)` with an UpdatePath carrying VC material, so
/// its shape is indistinguishable from a sibling's commit. Because it matches
/// alice_a's pending commit it must be reported as `OwnPendingCommit` without
/// consuming an operation-secret generation. Before the fix this failed with
/// `VirtualClientsError::OperationGenerationConsumed`.
#[openmls_test]
fn vc_own_commit_echo_surfaces_as_own_pending_commit() {
    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();

    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

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
    // group, so both Alice clients share `own_leaf_index` and the same
    // derivation epoch.
    let (siblings, resync_commit) = join_sibling_emulator(
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
        emulator_b,
        alice_b_main,
        ..
    } = siblings;
    let mut alice_b_main = alice_b_main;

    for (group, provider) in [
        (&mut alice_a_main, &alice_a_provider),
        (&mut bob_main, &bob_provider),
    ] {
        process_and_merge_commit(group, provider, resync_commit.clone());
    }
    assert_eq!(
        alice_a_main.own_leaf_index(),
        alice_b_main.own_leaf_index(),
        "both Alice clients must share the higher-level leaf"
    );

    // alice_a builds a VC commit on the shared derivation epoch but does not
    // merge it, so it is still her pending commit when the delivery service
    // fans the copy back to her.
    let bundle = alice_a_main
        .commit_builder()
        .vc_emulation(
            alice_a_provider.crypto(),
            alice_a_provider.storage(),
            emulator_a.group_id(),
        )
        .expect("alice_a bind commit to derivation epoch")
        .load_psks(alice_a_provider.storage())
        .expect("alice_a load psks")
        .build(
            alice_a_provider.rand(),
            alice_a_provider.crypto(),
            &vc_signer,
            |_| true,
        )
        .expect("alice_a build vc commit")
        .stage_commit(&alice_a_provider)
        .expect("alice_a stage vc commit");
    let commit = bundle.into_commit();

    // alice_a processes her own commit echoed back. It is framed like a
    // sibling's VC commit, but it matches her pending commit and must surface
    // as `OwnPendingCommit` without consuming an operation-secret generation.
    let processed = alice_a_main
        .process_message(
            &alice_a_provider,
            commit.clone().into_protocol_message().unwrap(),
        )
        .expect("alice_a processes her own fanned-back vc commit");
    assert!(matches!(
        processed.into_content(),
        ProcessedMessageContent::OwnPendingCommit
    ));
    alice_a_main
        .merge_pending_commit(&alice_a_provider)
        .expect("alice_a merge her own vc commit");

    // The sibling and bob apply the same commit through the ordinary staging
    // path.
    let processed = alice_b_main
        .process_message(
            &alice_b_provider,
            commit.clone().into_protocol_message().unwrap(),
        )
        .expect("alice_b processes sibling vc commit");
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(s) => *s,
        other => panic!("expected staged commit, got {other:?}"),
    };
    alice_b_main
        .merge_staged_commit(&alice_b_provider, staged)
        .expect("alice_b merge sibling vc commit");
    process_and_merge_commit(&mut bob_main, &bob_provider, commit);

    let authenticator = alice_a_main.epoch_authenticator();
    assert_eq!(
        alice_b_main.epoch_authenticator(),
        authenticator,
        "sibling must converge with the committer"
    );
    assert_eq!(
        bob_main.epoch_authenticator(),
        authenticator,
        "bob must converge with the committer"
    );

    // A second VC commit on the same derivation epoch, this time from alice_b,
    // proves the operation secret tree stayed healthy after the echo.
    let second_commit = send_vc_commit(
        &mut alice_b_main,
        &emulator_b,
        &alice_b_provider,
        &vc_signer,
    );
    process_and_merge_commit(&mut alice_a_main, &alice_a_provider, second_commit.clone());
    process_and_merge_commit(&mut bob_main, &bob_provider, second_commit);

    let authenticator = alice_b_main.epoch_authenticator();
    assert_eq!(
        alice_a_main.epoch_authenticator(),
        authenticator,
        "committer's sibling must converge after the second commit"
    );
    assert_eq!(
        bob_main.epoch_authenticator(),
        authenticator,
        "bob must converge after the second commit"
    );
}

/// Export a `VerifiableGroupInfo` for `group`, signed by `signer`, optionally
/// carrying the ratchet tree in the GroupInfo extension.
fn export_verifiable_group_info<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
    signer: &SignatureKeyPair,
    with_ratchet_tree: bool,
) -> openmls::messages::group_info::VerifiableGroupInfo {
    use openmls::prelude::MlsMessageIn;
    use tls_codec::Deserialize as _;

    let group_info_msg = group
        .export_group_info(provider.crypto(), signer, with_ratchet_tree)
        .expect("export group info");
    let serialized = group_info_msg
        .tls_serialize_detached()
        .expect("serialize group info");
    MlsMessageIn::tls_deserialize(&mut serialized.as_slice())
        .expect("deserialize group info message")
        .into_verifiable_group_info()
        .expect("into verifiable group info")
}

/// Create a higher-level group on the shared virtual-client leaf as the
/// creator, deriving the leaf and epoch-0 secret from the newest derivation
/// epoch of `emulator_group`.
fn create_vc_group<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider: &P,
    signer: &SignatureKeyPair,
    credential: openmls::credentials::CredentialWithKey,
    emulator_group: &MlsGroup,
) -> MlsGroup {
    MlsGroup::builder()
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .with_capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .vc_emulation(emulator_group.group_id())
        .build(provider, signer, credential)
        .expect("create vc group")
}

/// A virtual client creates a higher-level group and a sibling emulator client
/// reconstructs the epoch-0 state from the GroupInfo (ratchet tree carried in
/// the GroupInfo extension). Both land on the shared leaf with identical epoch
/// secrets, and the reconstructed sibling is a working member: it adds an
/// ordinary member and exchanges an application message with it.
#[openmls_test]
fn vc_sibling_joins_group_created_by_virtual_client() {
    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();

    let (emulator_a, _emulator_a_signer, _emulator_b, _emulator_b_signer) =
        sibling_emulation_group(ciphersuite, &alice_a_provider, &alice_b_provider);
    let epoch_id = newest_epoch(&emulator_a, &alice_a_provider);
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    // alice_a creates the group as the virtual client.
    let alice_a_main = create_vc_group(
        ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential.clone(),
        &emulator_a,
    );

    // alice_b reconstructs epoch-0 from the fanned-out GroupInfo.
    let verifiable_group_info =
        export_verifiable_group_info(&alice_a_main, &alice_a_provider, &vc_signer, true);
    let mut alice_b_main = MlsGroup::vc_join_at_creation(
        &alice_b_provider,
        &vc_join_config(),
        verifiable_group_info,
        None,
        epoch_id.clone(),
    )
    .expect("alice_b reconstructs the created group");

    // Both siblings hold identical epoch-0 state on the shared leaf.
    assert_eq!(alice_a_main.epoch(), alice_b_main.epoch());
    assert_eq!(
        alice_b_main.own_leaf_index(),
        alice_a_main.own_leaf_index(),
        "the sibling must land on the shared VC leaf"
    );
    assert_eq!(
        alice_a_main.epoch_authenticator(),
        alice_b_main.epoch_authenticator(),
        "reconstruction must reproduce the creator's epoch secrets"
    );
    assert_eq!(
        alice_a_main.export_ratchet_tree(),
        alice_b_main.export_ratchet_tree(),
    );

    // The reconstructed sibling is a working member: it adds Bob and exchanges
    // an application message with him.
    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let bob_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    let (_commit, welcome, _gi) = alice_b_main
        .add_members(&alice_b_provider, &vc_signer, &[bob_kp])
        .expect("alice_b adds bob");
    alice_b_main
        .merge_pending_commit(&alice_b_provider)
        .expect("alice_b merge add");
    let mut bob_main = StagedWelcome::new_from_welcome(
        &bob_provider,
        &vc_join_config(),
        welcome.into_welcome().expect("welcome"),
        Some(alice_b_main.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob joins the created group");

    let processed = send_and_process_app_message(
        &mut alice_b_main,
        &alice_b_provider,
        &vc_signer,
        &mut bob_main,
        &bob_provider,
        b"hello from the virtual client",
    );
    let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
        panic!("expected application message");
    };
    assert_eq!(message.into_bytes(), b"hello from the virtual client");
}

/// The ratchet tree may travel separately from the GroupInfo. A sibling
/// reconstructs the created group when the GroupInfo carries no ratchet tree
/// extension and the tree is supplied through the `ratchet_tree` argument.
#[openmls_test]
fn vc_group_creation_join_with_separate_ratchet_tree() {
    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();

    let (emulator_a, _emulator_a_signer, _emulator_b, _emulator_b_signer) =
        sibling_emulation_group(ciphersuite, &alice_a_provider, &alice_b_provider);
    let epoch_id = newest_epoch(&emulator_a, &alice_a_provider);
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    let alice_a_main = create_vc_group(
        ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential,
        &emulator_a,
    );

    // GroupInfo without the ratchet tree extension; tree passed separately.
    let verifiable_group_info =
        export_verifiable_group_info(&alice_a_main, &alice_a_provider, &vc_signer, false);
    let ratchet_tree = alice_a_main.export_ratchet_tree().into();
    let alice_b_main = MlsGroup::vc_join_at_creation(
        &alice_b_provider,
        &vc_join_config(),
        verifiable_group_info,
        Some(ratchet_tree),
        epoch_id,
    )
    .expect("alice_b reconstructs with a separately supplied ratchet tree");

    assert_eq!(
        alice_a_main.epoch_authenticator(),
        alice_b_main.epoch_authenticator(),
    );
}

/// A client that does not share the derivation epoch cannot reconstruct the
/// created group: it holds no `VcDerivationEpochState` for the referenced epoch.
#[openmls_test]
fn vc_group_creation_join_fails_without_derivation_state() {
    use openmls::prelude::VcGroupCreationJoinError;

    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let outsider_provider = Provider::default();

    let (emulator_a, _emulator_a_signer, _emulator_b, _emulator_b_signer) =
        sibling_emulation_group(ciphersuite, &alice_a_provider, &alice_b_provider);
    let epoch_id = newest_epoch(&emulator_a, &alice_a_provider);
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    let alice_a_main = create_vc_group(
        ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential,
        &emulator_a,
    );
    let verifiable_group_info =
        export_verifiable_group_info(&alice_a_main, &alice_a_provider, &vc_signer, true);

    let err = MlsGroup::vc_join_at_creation(
        &outsider_provider,
        &vc_join_config(),
        verifiable_group_info,
        None,
        epoch_id,
    )
    .expect_err("a non-sibling cannot reconstruct the created group");
    assert!(matches!(
        err,
        VcGroupCreationJoinError::VirtualClientsError(_)
    ));
}

/// The join is rejected when the supplied derivation epoch differs from the one
/// the creator leaf references.
#[openmls_test]
fn vc_group_creation_join_fails_on_epoch_id_mismatch() {
    use openmls::prelude::VcGroupCreationJoinError;

    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let other_a_provider = Provider::default();
    let other_b_provider = Provider::default();

    let (emulator_a, _emulator_a_signer, _emulator_b, _emulator_b_signer) =
        sibling_emulation_group(ciphersuite, &alice_a_provider, &alice_b_provider);
    let epoch_id = newest_epoch(&emulator_a, &alice_a_provider);
    // A distinct, valid derivation epoch from an unrelated emulator group.
    let (other_emulator_a, _other_signer_a, _other_emulator_b, _other_signer_b) =
        sibling_emulation_group(ciphersuite, &other_a_provider, &other_b_provider);
    let other_epoch_id = newest_epoch(&other_emulator_a, &other_a_provider);
    assert_ne!(epoch_id, other_epoch_id);
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    let alice_a_main = create_vc_group(
        ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential,
        &emulator_a,
    );
    let verifiable_group_info =
        export_verifiable_group_info(&alice_a_main, &alice_a_provider, &vc_signer, true);

    let err = MlsGroup::vc_join_at_creation(
        &alice_b_provider,
        &vc_join_config(),
        verifiable_group_info,
        None,
        other_epoch_id,
    )
    .expect_err("mismatched derivation epoch must be rejected");
    assert!(matches!(err, VcGroupCreationJoinError::EpochIdMismatch));
}

/// The join is rejected when the creator leaf is not `key_package`-sourced. A
/// virtual client's self-commit rekeys its leaf to a `commit` source, so the
/// resulting single-leaf group is no longer a group-creation leaf.
#[openmls_test]
fn vc_group_creation_join_fails_on_non_key_package_creator_leaf() {
    use openmls::prelude::VcGroupCreationJoinError;

    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();

    let (emulator_a, _emulator_a_signer, _emulator_b, _emulator_b_signer) =
        sibling_emulation_group(ciphersuite, &alice_a_provider, &alice_b_provider);
    let epoch_id = newest_epoch(&emulator_a, &alice_a_provider);
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    let mut alice_a_main = create_vc_group(
        ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential,
        &emulator_a,
    );

    // Self-commit as a virtual client: the creator leaf becomes commit-sourced
    // while the tree stays a single leaf.
    alice_a_main
        .commit_builder()
        .force_self_update(true)
        .vc_emulation(
            alice_a_provider.crypto(),
            alice_a_provider.storage(),
            emulator_a.group_id(),
        )
        .expect("vc emulation commit builder")
        .load_psks(alice_a_provider.storage())
        .expect("load psks")
        .build(
            alice_a_provider.rand(),
            alice_a_provider.crypto(),
            &vc_signer,
            |_| true,
        )
        .expect("build commit")
        .stage_commit(&alice_a_provider)
        .expect("stage commit");
    alice_a_main
        .merge_pending_commit(&alice_a_provider)
        .expect("merge self-commit");

    let verifiable_group_info =
        export_verifiable_group_info(&alice_a_main, &alice_a_provider, &vc_signer, true);
    let err = MlsGroup::vc_join_at_creation(
        &alice_b_provider,
        &vc_join_config(),
        verifiable_group_info,
        None,
        epoch_id,
    )
    .expect_err("a commit-sourced creator leaf must be rejected");
    assert!(matches!(
        err,
        VcGroupCreationJoinError::CreatorLeafNotKeyPackageSourced
    ));
}

/// The join is rejected when the ratchet tree holds more than the creator's
/// leaf.
#[openmls_test]
fn vc_group_creation_join_fails_on_multi_leaf_tree() {
    use openmls::prelude::VcGroupCreationJoinError;

    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();

    let (emulator_a, _emulator_a_signer, _emulator_b, _emulator_b_signer) =
        sibling_emulation_group(ciphersuite, &alice_a_provider, &alice_b_provider);
    let epoch_id = newest_epoch(&emulator_a, &alice_a_provider);
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    let mut alice_a_main = create_vc_group(
        ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential,
        &emulator_a,
    );

    // Add an ordinary member so the tree no longer consists of the sole leaf.
    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let bob_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    alice_a_main
        .add_members(&alice_a_provider, &vc_signer, &[bob_kp])
        .expect("alice_a adds bob");
    alice_a_main
        .merge_pending_commit(&alice_a_provider)
        .expect("alice_a merge add");

    let verifiable_group_info =
        export_verifiable_group_info(&alice_a_main, &alice_a_provider, &vc_signer, true);
    let err = MlsGroup::vc_join_at_creation(
        &alice_b_provider,
        &vc_join_config(),
        verifiable_group_info,
        None,
        epoch_id,
    )
    .expect_err("a multi-leaf tree must be rejected");
    assert!(matches!(err, VcGroupCreationJoinError::NotASingleLeafTree));
}

/// The join is rejected when the creator leaf carries no virtual-clients
/// derivation info. An ordinary (non-VC) group founder produces such a leaf:
/// it is `key_package`-sourced but has no derivation-info entry.
#[openmls_test]
fn vc_group_creation_join_fails_on_missing_derivation_info() {
    use openmls::prelude::VcGroupCreationJoinError;

    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();

    let (emulator_a, _emulator_a_signer, _emulator_b, _emulator_b_signer) =
        sibling_emulation_group(ciphersuite, &alice_a_provider, &alice_b_provider);
    let epoch_id = newest_epoch(&emulator_a, &alice_a_provider);
    let (founder_credential, founder_signer) = new_credential(
        &alice_a_provider,
        b"Founder",
        ciphersuite.signature_algorithm(),
    );
    let alice_a_main = new_vc_main_group(
        ciphersuite,
        &alice_a_provider,
        &founder_signer,
        founder_credential,
    );

    let verifiable_group_info =
        export_verifiable_group_info(&alice_a_main, &alice_a_provider, &founder_signer, true);
    let err = MlsGroup::vc_join_at_creation(
        &alice_b_provider,
        &vc_join_config(),
        verifiable_group_info,
        None,
        epoch_id,
    )
    .expect_err("a creator leaf without derivation info must be rejected");
    assert!(matches!(
        err,
        VcGroupCreationJoinError::MissingDerivationInfo
    ));
}

/// The single group-creation generation is consumed exactly once. A first join
/// succeeds and persists the advanced operation tree; a second join on the same
/// material fails because that generation is now consumed.
#[openmls_test]
fn vc_group_creation_double_join_consumes_generation() {
    use openmls::prelude::VcGroupCreationJoinError;

    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();

    let (emulator_a, _emulator_a_signer, _emulator_b, _emulator_b_signer) =
        sibling_emulation_group(ciphersuite, &alice_a_provider, &alice_b_provider);
    let epoch_id = newest_epoch(&emulator_a, &alice_a_provider);
    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    let alice_a_main = create_vc_group(
        ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential,
        &emulator_a,
    );

    let first_group_info =
        export_verifiable_group_info(&alice_a_main, &alice_a_provider, &vc_signer, true);
    MlsGroup::vc_join_at_creation(
        &alice_b_provider,
        &vc_join_config(),
        first_group_info,
        None,
        epoch_id.clone(),
    )
    .expect("first reconstruction succeeds");

    // The generation is now consumed in alice_b's persisted operation tree, so a
    // second reconstruction on the same material fails.
    let second_group_info =
        export_verifiable_group_info(&alice_a_main, &alice_a_provider, &vc_signer, true);
    let err = MlsGroup::vc_join_at_creation(
        &alice_b_provider,
        &vc_join_config(),
        second_group_info,
        None,
        epoch_id,
    )
    .expect_err("second reconstruction must fail on the consumed generation");
    assert!(matches!(
        err,
        VcGroupCreationJoinError::VirtualClientsError(_)
    ));
}

/// `propose_unconfirmed` surfaces the handshake confirmation data end to end
/// on a group bound to a derivation epoch. Confirming the proposal deletes
/// its retained handshake secret, so its own echo then fails to decrypt,
/// while an unconfirmed control proposal still decrypts back to a
/// `ProposalMessage`.
#[openmls_test::openmls_test]
fn propose_unconfirmed_confirm_flow() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let (charlie_credential, charlie_signer) = new_credential(
        alice_provider,
        b"Charlie",
        ciphersuite.signature_algorithm(),
    );
    let (dave_credential, dave_signer) =
        new_credential(alice_provider, b"Dave", ciphersuite.signature_algorithm());

    // Pure-ciphertext framing so proposals are sent as PrivateMessage.
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .build();
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &group_config,
        alice_credential,
    )
    .expect("alice create group");

    let bob_key_package = KeyPackage::builder()
        .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
        .expect("bob KP build")
        .key_package()
        .to_owned();
    let (_commit, _welcome, _gi) = alice_group
        .add_members(alice_provider, &alice_signer, &[bob_key_package])
        .expect("alice add bob");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("alice merge add");

    // Bind the group to a derivation epoch so own echoes are decryptable.
    let (emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, alice_provider, b"AliceEmulator", true);
    let _ = send_vc_commit(
        &mut alice_group,
        &emulator_group,
        alice_provider,
        &alice_signer,
    );

    let charlie_key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            alice_provider,
            &charlie_signer,
            charlie_credential,
        )
        .expect("charlie KP build")
        .key_package()
        .to_owned();
    let dave_key_package = KeyPackage::builder()
        .build(ciphersuite, alice_provider, &dave_signer, dave_credential)
        .expect("dave KP build")
        .key_package()
        .to_owned();

    let epoch = alice_group.epoch();

    // The confirmation is present for a ciphertext-framed proposal, and the
    // bound group produces a generation id.
    let (proposal_a, _ref_a, confirmation_a) = alice_group
        .propose_unconfirmed(
            alice_provider,
            &alice_signer,
            Propose::Add(charlie_key_package),
            ProposalOrRefType::Reference,
        )
        .expect("propose_unconfirmed add charlie");
    let confirmation_a = confirmation_a.expect("ciphertext-framed proposal carries confirmation");
    assert_eq!(confirmation_a.epoch, epoch);
    assert!(confirmation_a.generation_id.is_some());

    // Confirming deletes the retained handshake secret, so proposal A's own
    // echo no longer decrypts.
    alice_group
        .confirm_handshake_message(
            alice_provider.storage(),
            confirmation_a.epoch,
            confirmation_a.generation,
        )
        .expect("confirm proposal A");
    let err = alice_group
        .process_message(alice_provider, proposal_a.into_protocol_message().unwrap())
        .expect_err("proposal A's confirmed generation must not decrypt");
    let ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
        MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError),
    )) = err
    else {
        panic!("expected a secret reuse error, got {err:?}");
    };

    // A control proposal that is not confirmed retains its secret, so its echo
    // decrypts back to a ProposalMessage.
    let (proposal_b, _ref_b, _confirmation_b) = alice_group
        .propose_unconfirmed(
            alice_provider,
            &alice_signer,
            Propose::Add(dave_key_package),
            ProposalOrRefType::Reference,
        )
        .expect("propose_unconfirmed add dave");
    let processed = alice_group
        .process_message(alice_provider, proposal_b.into_protocol_message().unwrap())
        .expect("process proposal B echo");
    assert!(matches!(
        processed.into_content(),
        ProcessedMessageContent::ProposalMessage(_)
    ));
}

/// Flagship end-to-end test for private virtual-client handshake framing.
/// Two sibling emulators (alice_a, alice_b) share a virtual-client leaf
/// alongside a regular member (bob), with handshake messages framed as
/// PrivateMessage. Exercises the own-commit echo, sibling decryption, a
/// private proposal, and the ack-without-echo confirm flow.
#[openmls_test::openmls_test]
fn vc_private_commit_end_to_end() {
    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();

    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);
    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let (charlie_credential, charlie_signer) = new_credential(
        &alice_a_provider,
        b"Charlie",
        ciphersuite.signature_algorithm(),
    );

    // Mixed-ciphertext framing: handshake messages go out as PrivateMessage,
    // but the group still accepts the sibling-resync external commit, which is
    // always a PublicMessage.
    let mut alice_a_main = new_vc_main_group_with_policy(
        ciphersuite,
        &alice_a_provider,
        &vc_signer,
        vc_credential.clone(),
        MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY,
    );

    // Add bob as a regular member.
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

    let bob_join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let mut bob_main = StagedWelcome::new_from_welcome(
        &bob_provider,
        &bob_join_config,
        welcome.into_welcome().expect("welcome present"),
        Some(alice_a_main.export_ratchet_tree().into()),
    )
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob join");

    // alice_b joins as a sibling emulator and resyncs into the group.
    let main_join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let (sib, resync_commit) = join_sibling_emulator(
        ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
        &vc_signer,
        vc_credential,
        &alice_a_main,
        main_join_config,
    );
    let SiblingEmulators {
        emulator_a,
        mut alice_b_main,
        ..
    } = sib;

    // alice_a and bob process the resync external commit (PublicMessage). This
    // is what binds alice_a_main to the derivation epoch.
    process_and_merge_commit(&mut alice_a_main, &alice_a_provider, resync_commit.clone());
    process_and_merge_commit(&mut bob_main, &bob_provider, resync_commit);
    assert_eq!(
        alice_a_main.epoch_authenticator(),
        alice_b_main.epoch_authenticator()
    );
    assert_eq!(
        alice_a_main.epoch_authenticator(),
        bob_main.epoch_authenticator()
    );

    // alice_a builds a VC commit framed as PrivateMessage.
    let mut bundle = alice_a_main
        .commit_builder()
        .vc_emulation(
            alice_a_provider.crypto(),
            alice_a_provider.storage(),
            emulator_a.group_id(),
        )
        .expect("vc emulation")
        .load_psks(alice_a_provider.storage())
        .expect("load psks")
        .build(
            alice_a_provider.rand(),
            alice_a_provider.crypto(),
            &vc_signer,
            |_| true,
        )
        .expect("build commit")
        .stage_commit(&alice_a_provider)
        .expect("stage commit");
    let confirmation = bundle
        .take_confirmation()
        .expect("private VC commit carries confirmation");
    assert!(
        confirmation.generation_id.is_some(),
        "a VC-bound private commit carries a generation id"
    );
    let vc_commit = bundle.into_commit();

    // Before merging, alice_a processes her own private commit echo. The
    // retained own handshake secret decrypts it, and the own-pending-commit
    // check runs before any VC material is loaded, so it surfaces as
    // OwnPendingCommit.
    let processed = alice_a_main
        .process_message(
            &alice_a_provider,
            vc_commit.clone().into_protocol_message().unwrap(),
        )
        .expect("alice_a processes her own private VC commit echo");
    assert!(matches!(
        processed.into_content(),
        ProcessedMessageContent::OwnPendingCommit
    ));
    alice_a_main
        .merge_pending_commit(&alice_a_provider)
        .expect("alice_a merge VC commit");

    // alice_b decrypts via the shared handshake ratchet and stages via the VC
    // path; bob decrypts via the regular HPKE path.
    process_and_merge_commit(&mut alice_b_main, &alice_b_provider, vc_commit.clone());
    process_and_merge_commit(&mut bob_main, &bob_provider, vc_commit);
    assert_eq!(
        alice_a_main.epoch_authenticator(),
        alice_b_main.epoch_authenticator()
    );
    assert_eq!(
        alice_a_main.epoch_authenticator(),
        bob_main.epoch_authenticator()
    );

    // alice_a sends a private proposal; alice_b recovers the sibling emulator
    // leaf index and sees a ProposalMessage.
    let charlie_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(
            ciphersuite,
            &alice_a_provider,
            &charlie_signer,
            charlie_credential,
        )
        .expect("charlie KP build")
        .key_package()
        .to_owned();
    let (proposal_msg, _pref, proposal_confirmation) = alice_a_main
        .propose_unconfirmed(
            &alice_a_provider,
            &vc_signer,
            Propose::Add(charlie_kp),
            ProposalOrRefType::Reference,
        )
        .expect("alice_a proposes add charlie");
    assert!(proposal_confirmation
        .expect("private proposal carries confirmation")
        .generation_id
        .is_some());
    let processed_proposal = alice_b_main
        .process_message(
            &alice_b_provider,
            proposal_msg.into_protocol_message().unwrap(),
        )
        .expect("alice_b processes alice_a's private proposal");
    assert!(processed_proposal.emulator_sender_leaf_index().is_some());
    assert!(matches!(
        processed_proposal.into_content(),
        ProcessedMessageContent::ProposalMessage(_)
    ));
    // Drop the pending proposal so the next commit is a clean self-update.
    alice_a_main
        .clear_pending_proposals(alice_a_provider.storage())
        .expect("clear pending proposal");

    // Ack-without-echo: alice_a builds a second private VC commit, merges it
    // directly, and confirms it using the pre-merge epoch, which is now a past
    // epoch. This exercises the epoch-scoped confirm.
    let second_bundle = alice_a_main
        .commit_builder()
        .vc_emulation(
            alice_a_provider.crypto(),
            alice_a_provider.storage(),
            emulator_a.group_id(),
        )
        .expect("vc emulation")
        .load_psks(alice_a_provider.storage())
        .expect("load psks")
        .build(
            alice_a_provider.rand(),
            alice_a_provider.crypto(),
            &vc_signer,
            |_| true,
        )
        .expect("build second commit")
        .stage_commit(&alice_a_provider)
        .expect("stage second commit");
    let second_confirmation = second_bundle
        .confirmation()
        .expect("private VC commit carries confirmation")
        .clone();
    alice_a_main
        .merge_pending_commit(&alice_a_provider)
        .expect("merge second VC commit");
    alice_a_main
        .confirm_handshake_message(
            alice_a_provider.storage(),
            second_confirmation.epoch,
            second_confirmation.generation,
        )
        .expect("confirm second VC commit");
}

/// Two consecutive private handshake sends on a VC-bound group produce
/// generation ids that are both present and distinct.
#[openmls_test::openmls_test]
fn handshake_generation_ids_are_distinct() {
    let provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(provider, b"Alice", ciphersuite.signature_algorithm());
    let (charlie_credential, charlie_signer) =
        new_credential(provider, b"Charlie", ciphersuite.signature_algorithm());
    let (dave_credential, dave_signer) =
        new_credential(provider, b"Dave", ciphersuite.signature_algorithm());

    // Ciphertext framing so the proposals are PrivateMessages that carry a
    // generation id.
    let mut alice_group = new_vc_main_group_with_policy(
        ciphersuite,
        provider,
        &alice_signer,
        alice_credential,
        MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY,
    );
    let (emulator_group, _emulator_signer) =
        make_emulator_group(ciphersuite, provider, b"AliceEmulator", true);

    // Bind alice_group's current epoch to the derivation epoch via a VC commit.
    let _ = send_vc_commit(&mut alice_group, &emulator_group, provider, &alice_signer);

    let charlie_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, provider, &charlie_signer, charlie_credential)
        .expect("charlie KP build")
        .key_package()
        .to_owned();
    let dave_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, provider, &dave_signer, dave_credential)
        .expect("dave KP build")
        .key_package()
        .to_owned();

    let (_msg_a, _ref_a, confirmation_a) = alice_group
        .propose_unconfirmed(
            provider,
            &alice_signer,
            Propose::Add(charlie_kp),
            ProposalOrRefType::Reference,
        )
        .expect("first private proposal");
    let (_msg_b, _ref_b, confirmation_b) = alice_group
        .propose_unconfirmed(
            provider,
            &alice_signer,
            Propose::Add(dave_kp),
            ProposalOrRefType::Reference,
        )
        .expect("second private proposal");

    let generation_id_a = confirmation_a
        .expect("bound group proposal carries confirmation")
        .generation_id
        .expect("bound group proposal carries a generation id");
    let generation_id_b = confirmation_b
        .expect("bound group proposal carries confirmation")
        .generation_id
        .expect("bound group proposal carries a generation id");
    assert_ne!(
        generation_id_a, generation_id_b,
        "consecutive private handshake sends must yield distinct generation ids"
    );
}

/// `propose_unconfirmed` with `Propose::GroupContextExtensions` under ciphertext
/// framing surfaces the confirmation data, the proposal processes at a
/// receiver, and confirming the retained handshake secret succeeds.
#[openmls_test::openmls_test]
fn propose_unconfirmed_group_context_extensions_flow() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, mut bob_group, _bob_signer) =
        setup_alice_bob_group_with_policy(
            ciphersuite,
            alice_provider,
            bob_provider,
            PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        );

    let epoch = alice_group.epoch();
    let (proposal, _pref, confirmation) = alice_group
        .propose_unconfirmed(
            alice_provider,
            &alice_signer,
            Propose::GroupContextExtensions(Extensions::empty()),
            ProposalOrRefType::Reference,
        )
        .expect("propose_unconfirmed group context extensions");
    let confirmation = confirmation.expect("ciphertext-framed GCE proposal carries confirmation");
    assert_eq!(confirmation.epoch, epoch);
    assert!(confirmation.generation_id.is_none());

    let processed = bob_group
        .process_message(bob_provider, proposal.into_protocol_message().unwrap())
        .expect("bob processes the GCE proposal");
    assert!(matches!(
        processed.into_content(),
        ProcessedMessageContent::ProposalMessage(_)
    ));

    alice_group
        .confirm_handshake_message(
            alice_provider.storage(),
            confirmation.epoch,
            confirmation.generation,
        )
        .expect("confirm GCE proposal");
}

/// `propose_self_update_with_new_signer_unconfirmed` surfaces the confirmation
/// data and the proposal processes at a receiver.
#[openmls_test::openmls_test]
fn propose_self_update_with_new_signer_unconfirmed_flow() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let (mut alice_group, alice_signer, mut bob_group, _bob_signer) =
        setup_alice_bob_group_with_policy(
            ciphersuite,
            alice_provider,
            bob_provider,
            PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        );

    let epoch = alice_group.epoch();
    let (new_credential, new_signer_kp) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let new_signer = NewSignerBundle {
        signer: &new_signer_kp,
        credential_with_key: new_credential,
    };

    let (proposal, _pref, confirmation) = alice_group
        .propose_self_update_with_new_signer_unconfirmed(
            alice_provider,
            &alice_signer,
            new_signer,
            LeafNodeParameters::builder().build(),
        )
        .expect("propose_self_update_with_new_signer_unconfirmed");
    let confirmation =
        confirmation.expect("ciphertext-framed update proposal carries confirmation");
    assert_eq!(confirmation.epoch, epoch);

    let processed = bob_group
        .process_message(bob_provider, proposal.into_protocol_message().unwrap())
        .expect("bob processes the update proposal");
    assert!(matches!(
        processed.into_content(),
        ProcessedMessageContent::ProposalMessage(_)
    ));

    alice_group
        .confirm_handshake_message(
            alice_provider.storage(),
            confirmation.epoch,
            confirmation.generation,
        )
        .expect("confirm update proposal");
}

/// A two-member emulation group: `emulator_a` founds it, `emulator_b` joins via
/// Welcome. Both clients set the `emulation_group` flag, so both register the
/// same derivation epoch and hold its `VcDerivationEpochState` and
/// `OperationSecretTree`. Read the shared epoch id with [`newest_epoch`].
fn sibling_emulation_group<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider_a: &P,
    provider_b: &P,
) -> (MlsGroup, SignatureKeyPair, MlsGroup, SignatureKeyPair) {
    let (mut emulator_a, signer_a) =
        make_emulator_group(ciphersuite, provider_a, b"EmulatorA", true);
    let (_commit, emulator_b, signer_b) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        provider_a,
        &signer_a,
        provider_b,
        b"EmulatorB",
    );
    assert_eq!(
        newest_epoch(&emulator_a, provider_a),
        newest_epoch(&emulator_b, provider_b),
        "siblings must derive the same EpochId"
    );
    (emulator_a, signer_a, emulator_b, signer_b)
}

/// Add a fresh emulator client on `joiner_provider` to `emulator_a`'s emulation
/// group and return its group alongside the Add commit, so other members can be
/// advanced to the same epoch. The commit is merged on `emulator_a` only.
fn add_emulator_client<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    emulator_a: &mut MlsGroup,
    provider_a: &P,
    signer_a: &SignatureKeyPair,
    joiner_provider: &P,
    joiner_label: &[u8],
) -> (openmls::prelude::MlsMessageOut, MlsGroup, SignatureKeyPair) {
    let (key_package, signer) = vc_key_package(ciphersuite, joiner_provider, joiner_label);
    let (commit, welcome, _gi) = emulator_a
        .add_members(provider_a, signer_a, &[key_package])
        .expect("emulator_a add joiner");
    emulator_a
        .merge_pending_commit(provider_a)
        .expect("emulator_a merge add");
    let group = StagedWelcome::new_from_welcome(
        joiner_provider,
        &vc_join_config(),
        welcome.into_welcome().expect("emulator welcome"),
        Some(emulator_a.export_ratchet_tree().into()),
    )
    .map(|staged| staged.emulation_group(true))
    .and_then(|s| s.into_group(joiner_provider))
    .expect("joiner join emulation group");
    (commit, group, signer)
}

/// Send a commit on `emulator_group` with the given builder configuration
/// applied, merge it locally and return it for delivery to the other members.
fn send_emulation_commit<P: OpenMlsProvider>(
    emulator_group: &mut MlsGroup,
    provider: &P,
    signer: &SignatureKeyPair,
    new_derivation_epoch: bool,
) -> openmls::prelude::MlsMessageOut {
    let bundle = emulator_group
        .commit_builder()
        .force_self_update(true)
        .derivation_epoch(new_derivation_epoch)
        .load_psks(provider.storage())
        .expect("load psks")
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .expect("build emulation commit")
        .stage_commit(provider)
        .expect("stage emulation commit");
    emulator_group
        .merge_pending_commit(provider)
        .expect("merge emulation commit");
    bundle.into_commit()
}

/// The Welcome joiner of an emulation group registers the Welcome's output
/// epoch, which is a derivation epoch because the commit that produced it added
/// the joiner. It converges with the existing member, and that epoch is not the
/// one the group was founded on.
#[openmls_test]
fn welcome_joiner_converges_on_newest_vc_derivation_epoch() {
    let provider_a = Provider::default();
    let provider_b = Provider::default();

    let (mut emulator_a, signer_a) =
        make_emulator_group(ciphersuite, &provider_a, b"EmulatorA", true);
    let initial_epoch = newest_epoch(&emulator_a, &provider_a);

    let (_commit, emulator_b, _signer_b) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &provider_a,
        &signer_a,
        &provider_b,
        b"EmulatorB",
    );

    let after_add = newest_epoch(&emulator_a, &provider_a);
    assert_eq!(
        after_add,
        newest_epoch(&emulator_b, &provider_b),
        "the joiner and the existing member must agree on the newest derivation epoch"
    );
    assert_ne!(
        after_add, initial_epoch,
        "adding a member creates a fresh derivation epoch"
    );
}

/// An ordinary commit carries no marker and changes no membership, so the
/// newest derivation epoch stays put on both sides. Virtual-client operations
/// keep working against it after the emulation group advanced.
#[openmls_test]
fn ordinary_commit_keeps_newest_vc_derivation_epoch() {
    let provider_a = Provider::default();
    let provider_b = Provider::default();

    let (mut emulator_a, signer_a, mut emulator_b, _signer_b) =
        sibling_emulation_group(ciphersuite, &provider_a, &provider_b);
    let before = newest_epoch(&emulator_a, &provider_a);

    let (vc_signer, vc_credential) = shared_vc_identity(ciphersuite, &provider_a, &provider_b);
    let mut main_group = create_vc_group(
        ciphersuite,
        &provider_a,
        &vc_signer,
        vc_credential,
        &emulator_a,
    );

    let emulation_epoch_before = emulator_a.epoch();
    let commit = send_emulation_commit(&mut emulator_a, &provider_a, &signer_a, false);
    process_and_merge_commit(&mut emulator_b, &provider_b, commit);
    assert_ne!(
        emulator_a.epoch(),
        emulation_epoch_before,
        "the emulation group advanced"
    );

    assert_eq!(
        newest_epoch(&emulator_a, &provider_a),
        before,
        "an ordinary commit leaves the newest derivation epoch in place"
    );
    assert_eq!(newest_epoch(&emulator_b, &provider_b), before);

    // The derivation epoch is older than the emulation group's current epoch,
    // and virtual-client operations still resolve to it.
    let used_epoch = newest_epoch(&emulator_a, &provider_a);
    let _commit = send_vc_commit(&mut main_group, &emulator_a, &provider_a, &vc_signer);
    assert_eq!(used_epoch, before);
}

/// A commit marked with `new_derivation_epoch` starts a fresh derivation epoch,
/// and the sender and the receiver derive the same `EpochId` for it.
#[openmls_test]
fn marker_commit_refreshes_vc_derivation_epoch() {
    let provider_a = Provider::default();
    let provider_b = Provider::default();

    let (mut emulator_a, signer_a, mut emulator_b, _signer_b) =
        sibling_emulation_group(ciphersuite, &provider_a, &provider_b);
    let before = newest_epoch(&emulator_a, &provider_a);

    let commit = send_emulation_commit(&mut emulator_a, &provider_a, &signer_a, true);
    process_and_merge_commit(&mut emulator_b, &provider_b, commit);

    let after_a = newest_epoch(&emulator_a, &provider_a);
    let after_b = newest_epoch(&emulator_b, &provider_b);
    assert_ne!(
        after_a, before,
        "the marker starts a fresh derivation epoch"
    );
    assert_eq!(
        after_a, after_b,
        "sender and receiver must converge on the same EpochId"
    );
}

/// A membership change creates a derivation epoch even without the marker, on
/// the committer's side and on a receiver's.
#[openmls_test]
fn membership_change_creates_vc_derivation_epoch_without_marker() {
    let provider_a = Provider::default();
    let provider_b = Provider::default();
    let provider_c = Provider::default();

    let (mut emulator_a, signer_a, mut emulator_b, _signer_b) =
        sibling_emulation_group(ciphersuite, &provider_a, &provider_b);
    let before = newest_epoch(&emulator_a, &provider_a);

    let (commit, _emulator_c, _signer_c) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &provider_a,
        &signer_a,
        &provider_c,
        b"EmulatorC",
    );
    process_and_merge_commit(&mut emulator_b, &provider_b, commit);

    let after_a = newest_epoch(&emulator_a, &provider_a);
    let after_b = newest_epoch(&emulator_b, &provider_b);
    assert_ne!(after_a, before);
    assert_eq!(after_a, after_b);
}

/// A virtual-client commit built without an epoch argument uses the derivation
/// epoch the last membership change created, not the one the group was founded
/// on. The receiving sibling reads that epoch id out of the commit's leaf and
/// records it as the group's binding.
///
/// The test-only epoch-explicit entry point still reaches the older epoch, which
/// is what a delayed-processing scenario needs.
#[openmls_test]
fn vc_commit_uses_newest_derivation_epoch_after_membership_change() {
    let provider_a = Provider::default();
    let provider_b = Provider::default();
    let provider_c = Provider::default();

    let (mut emulator_a, signer_a, mut emulator_b, _signer_b) =
        sibling_emulation_group(ciphersuite, &provider_a, &provider_b);
    let old_epoch_id = newest_epoch(&emulator_a, &provider_a);

    // Both siblings sit on the one leaf of a higher-level group the virtual
    // client founded on the emulation group's initial derivation epoch.
    let (vc_signer, vc_credential) = shared_vc_identity(ciphersuite, &provider_a, &provider_b);
    let mut main_a = create_vc_group(
        ciphersuite,
        &provider_a,
        &vc_signer,
        vc_credential,
        &emulator_a,
    );
    let verifiable_group_info =
        export_verifiable_group_info(&main_a, &provider_a, &vc_signer, true);
    let mut main_b = MlsGroup::vc_join_at_creation(
        &provider_b,
        &vc_join_config(),
        verifiable_group_info,
        None,
        old_epoch_id.clone(),
    )
    .expect("sibling reconstructs the created group");

    // A third emulator client joins the emulation group. That membership change
    // creates a derivation epoch on both siblings.
    let (add_commit, _emulator_c, _signer_c) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &provider_a,
        &signer_a,
        &provider_c,
        b"EmulatorC",
    );
    process_and_merge_commit(&mut emulator_b, &provider_b, add_commit);
    let new_epoch_id = newest_epoch(&emulator_a, &provider_a);
    assert_ne!(new_epoch_id, old_epoch_id);
    assert_eq!(new_epoch_id, newest_epoch(&emulator_b, &provider_b));

    let used_epoch_id = newest_epoch(&emulator_a, &provider_a);
    let commit = send_vc_commit(&mut main_a, &emulator_a, &provider_a, &vc_signer);
    assert_eq!(
        used_epoch_id, new_epoch_id,
        "a commit must resolve to the newest derivation epoch"
    );
    let bound_epoch = main_a.epoch();
    process_and_merge_commit(&mut main_b, &provider_b, commit);
    let bindings: VcEmulationBindings = provider_b
        .storage()
        .vc_emulation_bindings(main_b.group_id())
        .expect("read emulation bindings")
        .expect("emulation bindings present");
    assert_eq!(
        bindings.get(bound_epoch),
        Some(&new_epoch_id),
        "the receiver must read the new epoch id out of the commit's leaf"
    );

    // The escape hatch still commits from the older epoch.
    let delayed_commit =
        send_vc_commit_at_epoch(&mut main_a, &provider_a, &vc_signer, old_epoch_id.clone());
    let delayed_bound_epoch = main_a.epoch();
    process_and_merge_commit(&mut main_b, &provider_b, delayed_commit);
    let bindings: VcEmulationBindings = provider_b
        .storage()
        .vc_emulation_bindings(main_b.group_id())
        .expect("read emulation bindings")
        .expect("emulation bindings present");
    assert_eq!(bindings.get(delayed_bound_epoch), Some(&old_epoch_id));
}

/// A commit that both changes membership and carries the marker registers the
/// new epoch exactly once. A second registration would try to puncture the
/// already-punctured exporter of that epoch, so a successful merge on both
/// sides is the evidence.
#[openmls_test]
fn marker_with_membership_change_registers_once() {
    let provider_a = Provider::default();
    let provider_b = Provider::default();
    let provider_c = Provider::default();

    let (mut emulator_a, signer_a, mut emulator_b, _signer_b) =
        sibling_emulation_group(ciphersuite, &provider_a, &provider_b);
    let before = newest_epoch(&emulator_a, &provider_a);

    let (key_package, _signer_c) = vc_key_package(ciphersuite, &provider_c, b"EmulatorC");

    let bundle = emulator_a
        .commit_builder()
        .propose_adds([key_package])
        .derivation_epoch(true)
        .load_psks(provider_a.storage())
        .expect("load psks")
        .build(provider_a.rand(), provider_a.crypto(), &signer_a, |_| true)
        .expect("build add commit with marker")
        .stage_commit(&provider_a)
        .expect("stage add commit with marker");
    emulator_a
        .merge_pending_commit(&provider_a)
        .expect("emulator_a merge add with marker");
    process_and_merge_commit(&mut emulator_b, &provider_b, bundle.into_commit());

    let after_a = newest_epoch(&emulator_a, &provider_a);
    assert_ne!(after_a, before);
    assert_eq!(after_a, newest_epoch(&emulator_b, &provider_b));
}

/// An external-commit resync into the emulation group changes membership, so it
/// creates a derivation epoch. The joiner and the existing member converge.
#[openmls_test]
fn external_commit_into_emulation_group_creates_vc_derivation_epoch() {
    let provider_a = Provider::default();
    let provider_c = Provider::default();

    let (mut emulator_a, signer_a) =
        make_emulator_group(ciphersuite, &provider_a, b"EmulatorA", true);
    let before = newest_epoch(&emulator_a, &provider_a);

    let verifiable_group_info =
        export_verifiable_group_info(&emulator_a, &provider_a, &signer_a, true);
    let (credential_c, signer_c) =
        new_credential(&provider_c, b"EmulatorC", ciphersuite.signature_algorithm());

    let (emulator_c, bundle) = MlsGroup::external_commit_builder()
        .with_config(vc_join_config())
        .emulation_group(true)
        .build_group(&provider_c, verifiable_group_info, credential_c)
        .expect("build external commit group")
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(vc_capabilities())
                .with_extensions(vc_leaf_extensions())
                .build(),
        )
        .load_psks(provider_c.storage())
        .expect("load psks")
        .build(provider_c.rand(), provider_c.crypto(), &signer_c, |_| true)
        .expect("build external commit")
        .finalize(&provider_c)
        .expect("finalize external commit");

    process_and_merge_commit(&mut emulator_a, &provider_a, bundle.into_commit());

    assert!(emulator_c.is_emulation_group());
    let after_a = newest_epoch(&emulator_a, &provider_a);
    let after_c = newest_epoch(&emulator_c, &provider_c);
    assert_ne!(after_a, before);
    assert_eq!(
        after_a, after_c,
        "the external joiner and the existing member must converge"
    );
}

/// Loading a group recovers whether it is an emulation group, so the
/// application only declares it once, when it enters the group.
#[openmls_test]
fn loading_a_group_recovers_the_emulation_group_flag() {
    let provider_a = Provider::default();
    let provider_b = Provider::default();

    let (emulator_a, _signer_a, emulator_b, _signer_b) =
        sibling_emulation_group(ciphersuite, &provider_a, &provider_b);
    let (plain_group, _signer) =
        make_emulator_group(ciphersuite, &provider_a, b"NotAnEmulator", false);

    for (group, provider) in [
        (&emulator_a, &provider_a),
        (&emulator_b, &provider_b),
        (&plain_group, &provider_a),
    ] {
        let loaded = MlsGroup::load(provider.storage(), group.group_id())
            .expect("load group")
            .expect("the group was stored");
        assert_eq!(loaded.is_emulation_group(), group.is_emulation_group());
    }
    assert!(emulator_a.is_emulation_group());
    assert!(emulator_b.is_emulation_group());
    assert!(!plain_group.is_emulation_group());
}

/// A group without the `emulation_group` flag writes no virtual-clients state,
/// not even across membership changes.
#[openmls_test]
fn non_emulation_group_writes_no_vc_state() {
    let alice_provider = Provider::default();
    let bob_provider = Provider::default();

    let (mut alice_group, alice_signer, mut bob_group, _bob_signer) =
        setup_alice_bob_group(ciphersuite, &alice_provider, &bob_provider);

    // Alice removes Bob again, so both a join and a removal were processed.
    let bob_index = bob_group.own_leaf_index();
    let (commit, _welcome, _gi) = alice_group
        .remove_members(&alice_provider, &alice_signer, &[bob_index])
        .expect("alice remove bob");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("alice merge remove");
    let processed = bob_group
        .process_message(&bob_provider, commit.into_protocol_message().unwrap())
        .expect("bob processes the removal");
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("expected a staged commit");
    };
    bob_group
        .merge_staged_commit(&bob_provider, *staged)
        .expect("bob merges the removal");

    for (group, provider) in [(&alice_group, &alice_provider), (&bob_group, &bob_provider)] {
        assert!(!group.is_emulation_group());
        assert_eq!(
            group
                .newest_vc_derivation_epoch(provider.storage())
                .expect("read newest derivation epoch"),
            None,
            "a non-emulation group must not register a derivation epoch"
        );
        let bindings: Option<VcEmulationBindings> = provider
            .storage()
            .vc_emulation_bindings(group.group_id())
            .expect("read emulation bindings");
        assert!(
            bindings.is_none(),
            "a non-emulation group must not write emulation bindings"
        );
    }
}

/// A commit whose virtual-clients Safe AAD item does not parse is rejected when
/// an emulation group processes it. The item decides whether the commit's output
/// epoch is a derivation epoch, so guessing is not an option.
///
/// The sender holds the same MLS group without the `emulation_group` flag, which
/// is what lets it emit the malformed item in the first place: an emulation
/// group rejects its own malformed item at build time.
#[openmls_test]
fn malformed_vc_commit_data_is_rejected_by_emulation_group() {
    let alice_provider = Provider::default();
    let bob_provider = Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(&alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &emulation_group_config(ciphersuite, false),
        alice_credential,
    )
    .expect("alice create group");

    let (bob_kp, _bob_signer) = vc_key_package(ciphersuite, &bob_provider, b"Bob");
    let (_commit, welcome, _gi) = alice_group
        .add_members(&alice_provider, &alice_signer, &[bob_kp])
        .expect("alice add bob");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("alice merge add");
    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &vc_join_config(),
        welcome.into_welcome().expect("welcome"),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .map(|staged| staged.emulation_group(true))
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob join emulation group");

    alice_group
        .set_safe_aad(vec![openmls::framing::SafeAadItem::new(
            VC_COMPONENT_ID,
            vec![0xff, 0xff, 0xff],
        )])
        .expect("a single item is sorted and unique");
    let commit = alice_group
        .self_update(
            &alice_provider,
            &alice_signer,
            LeafNodeParameters::default(),
        )
        .expect("alice self update")
        .into_messages()
        .0;

    let err = bob_group
        .process_message(&bob_provider, commit.into_protocol_message().unwrap())
        .expect_err("a malformed virtual-clients item must be rejected");
    assert!(
        matches!(
            err,
            ProcessMessageError::InvalidCommit(StageCommitError::MalformedVcCommitData(_))
        ),
        "unexpected error: {err:?}"
    );
}

/// The wire format decides: an application that stages the marker itself gets a
/// fresh derivation epoch without calling `new_derivation_epoch`. Calling both
/// keeps the rest of the application's commit data intact.
#[openmls_test]
fn app_staged_vc_marker_refreshes_vc_derivation_epoch() {
    use openmls::components::vc_commit_data::{VirtualClientAction, VirtualClientCommitData};

    let provider_a = Provider::default();
    let provider_b = Provider::default();

    let (mut emulator_a, signer_a, mut emulator_b, _signer_b) =
        sibling_emulation_group(ciphersuite, &provider_a, &provider_b);
    let before = newest_epoch(&emulator_a, &provider_a);

    // The application stages the marker itself and does not call
    // `new_derivation_epoch`.
    let commit_data = VirtualClientCommitData::new(vec![VirtualClientAction::NewDerivationEpoch])
        .expect("one new_derivation_epoch action is valid");
    emulator_a
        .set_safe_aad(vec![commit_data
            .to_safe_aad_item()
            .expect("serialize commit data")])
        .expect("a single item is sorted and unique");

    let commit = send_emulation_commit(&mut emulator_a, &provider_a, &signer_a, false);
    let processed = emulator_b
        .process_message(&provider_b, commit.into_protocol_message().unwrap())
        .expect("process commit");
    assert_eq!(
        processed
            .vc_commit_data()
            .expect("the item must parse")
            .expect("the item must be present"),
        commit_data,
        "the application's commit data reaches the sibling unchanged"
    );
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("expected a staged commit");
    };
    emulator_b
        .merge_staged_commit(&provider_b, *staged)
        .expect("merge staged commit");

    let after_a = newest_epoch(&emulator_a, &provider_a);
    assert_ne!(after_a, before);
    assert_eq!(after_a, newest_epoch(&emulator_b, &provider_b));
}

/// Asking for a new derivation epoch needs Safe AAD framing to carry the marker.
#[openmls_test]
fn new_derivation_epoch_requires_safe_aad() {
    let provider = Provider::default();

    let (credential, signer) =
        new_credential(&provider, b"Emulator", ciphersuite.signature_algorithm());
    let group_config = emulation_config_builder(ciphersuite, true, false).build();
    let mut emulator = MlsGroup::new(&provider, &signer, &group_config, credential)
        .expect("create emulation group without safe aad");

    let err = emulator
        .commit_builder()
        .derivation_epoch(true)
        .force_self_update(true)
        .load_psks(provider.storage())
        .expect("load psks")
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .expect_err("the marker cannot be carried without Safe AAD framing");
    assert!(
        matches!(
            err,
            openmls::group::CreateCommitError::NewDerivationEpochWithoutSafeAad
        ),
        "unexpected error: {err:?}"
    );
}

/// Requesting a new derivation epoch in a group that is not configured as an
/// emulation group fails: the sender would broadcast the marker without
/// registering the epoch itself.
#[openmls_test]
fn new_derivation_epoch_requires_emulation_group() {
    let provider = Provider::default();

    let (credential, signer) = new_credential(
        &provider,
        b"NotAnEmulator",
        ciphersuite.signature_algorithm(),
    );
    let group_config = emulation_group_config(ciphersuite, false);
    let mut group = MlsGroup::new(&provider, &signer, &group_config, credential)
        .expect("create group without the emulation flag");

    let err = group
        .commit_builder()
        .derivation_epoch(true)
        .force_self_update(true)
        .load_psks(provider.storage())
        .expect("load psks")
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .expect_err("the marker is only valid in an emulation group");
    assert!(
        matches!(
            err,
            openmls::group::CreateCommitError::NewDerivationEpochOutsideEmulationGroup
        ),
        "unexpected error: {err:?}"
    );
}

/// Reading a *past* epoch after a sibling-resync external commit.
///
/// The resync moves `own_leaf_index` to the joiner's new leaf
/// (`staged_commit.rs`, `if let Some(new_idx) = state.new_own_leaf_index`).
/// The secret trees of epochs before the resync were built for the *old*
/// index, so from that point on "the group's current own leaf" and "the leaf a
/// past epoch's secret tree belongs to" are two different things.
///
/// `DecryptedMessage::from_inbound_ciphertext` decides whether an inbound
/// message is the caller's own by comparing the sender's leaf index against
/// one of those two. Comparing against the current one misclassifies every
/// message in every pre-resync epoch that came from the leaf the client has
/// since moved onto -- here Dave's, who was removed before the resync and
/// whose leaf the joiner then reuses.
///
/// The tree is arranged so that the resync actually moves the leaf, which
/// needs a blank to the left of the virtual client:
///
/// ```text
///   leaf 0      leaf 1      leaf 2
///   Dave        Alice (VC)  Bob      epoch 1: Dave sends
///   -           Alice (VC)  Bob      epoch 2: Dave removed; Alice and Bob send
///   Alice (VC)  -           Bob      epoch 3: resync, Alice moves 1 -> 0
/// ```
#[openmls_test]
fn vc_past_epoch_read_survives_sibling_resync() {
    use openmls::group::PastEpochDeletionPolicy;
    use openmls::prelude::LeafNodeIndex;

    let dave_provider = Provider::default();
    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();

    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, &alice_a_provider, &alice_b_provider);

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::MaxEpochs(10))
        .build();

    // Higher-level group. Dave creates it and takes leaf 0, so that removing
    // him later leaves a blank to the left of the virtual client -- without
    // that blank the joiner reuses the virtual client's own leaf and
    // `own_leaf_index` never moves.
    //
    // The past-epoch buffer has to be large enough to still hold the epochs
    // the messages below are sent in; the default `MaxEpochs(0)` would drop
    // them at the next commit and the reads would fail for an unrelated
    // reason.
    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::MaxEpochs(10))
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions on higher-level config")
        .build();
    let (dave_credential, dave_signer) =
        new_credential(&dave_provider, b"Dave", ciphersuite.signature_algorithm());
    let mut dave_main = MlsGroup::new(&dave_provider, &dave_signer, &group_config, dave_credential)
        .expect("dave create higher-level group");
    assert_eq!(dave_main.own_leaf_index(), LeafNodeIndex::new(0));

    // Dave adds the virtual client (leaf 1) and Bob (leaf 2).
    let alice_vc_kp = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(
            ciphersuite,
            &alice_a_provider,
            &vc_signer,
            vc_credential.clone(),
        )
        .expect("alice VC KP build")
        .key_package()
        .to_owned();
    let (bob_kp, bob_signer) = vc_key_package(ciphersuite, &bob_provider, b"Bob");
    let (_, welcome, _) = dave_main
        .add_members(&dave_provider, &dave_signer, &[alice_vc_kp, bob_kp])
        .expect("dave adds alice and bob");
    dave_main
        .merge_pending_commit(&dave_provider)
        .expect("dave merge add");
    let ratchet_tree = dave_main.export_ratchet_tree();
    let mut alice_a_main = StagedWelcome::new_from_welcome(
        &alice_a_provider,
        &join_config,
        welcome.clone().into_welcome().expect("welcome"),
        Some(ratchet_tree.clone().into()),
    )
    .and_then(|s| s.into_group(&alice_a_provider))
    .expect("alice_a join higher-level group");
    let mut bob_main = StagedWelcome::new_from_welcome(
        &bob_provider,
        &join_config,
        welcome.into_welcome().expect("welcome"),
        Some(ratchet_tree.into()),
    )
    .and_then(|s| s.into_group(&bob_provider))
    .expect("bob join higher-level group");

    let dave_leaf = dave_main.own_leaf_index();
    let old_leaf_index = alice_a_main.own_leaf_index();
    assert_eq!(old_leaf_index, LeafNodeIndex::new(1));

    // Epoch 1: Dave sends from leaf 0, and alice_a leaves it unread.
    let epoch_with_dave = alice_a_main.epoch();
    let from_dave = dave_main
        .create_message(&dave_provider, &dave_signer, b"dave from leaf zero")
        .expect("dave app message");

    // Epoch 1 -> 2: Bob removes Dave, blanking leaf 0.
    let (remove_commit, _, _) = bob_main
        .remove_members(&bob_provider, &bob_signer, &[dave_leaf])
        .expect("bob removes dave");
    bob_main
        .merge_pending_commit(&bob_provider)
        .expect("bob merge remove");
    process_and_merge_commit(&mut alice_a_main, &alice_a_provider, remove_commit);

    // Epoch 2: Bob and the virtual client each send, both left unread.
    let pre_resync_epoch = alice_a_main.epoch();
    let from_bob = bob_main
        .create_message(&bob_provider, &bob_signer, b"bob before the resync")
        .expect("bob app message");
    let from_alice_a = alice_a_main
        .create_message(&alice_a_provider, &vc_signer, b"alice_a before the resync")
        .expect("alice_a app message");

    // The resync: alice_b founds the emulation group with alice_a, then joins
    // the higher-level group by external commit. The auto-Remove picks up the
    // virtual client's leaf 1, and the joiner lands on the blank leaf 0.
    let (siblings, commit_msg) = join_sibling_emulator(
        ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
        &vc_signer,
        vc_credential,
        &alice_a_main,
        join_config.clone(),
    );
    let new_leaf_index = siblings.alice_b_main.own_leaf_index();

    process_and_merge_commit(&mut alice_a_main, &alice_a_provider, commit_msg.clone());
    process_and_merge_commit(&mut bob_main, &bob_provider, commit_msg);

    assert_eq!(
        new_leaf_index, dave_leaf,
        "the joiner must land on Dave's blanked leaf, otherwise this test \
         checks nothing"
    );
    assert_ne!(
        old_leaf_index, new_leaf_index,
        "the resync must actually move the virtual client's own leaf"
    );
    assert_eq!(alice_a_main.own_leaf_index(), new_leaf_index);
    assert!(
        epoch_with_dave.as_u64() < pre_resync_epoch.as_u64()
            && pre_resync_epoch.as_u64() < alice_a_main.epoch().as_u64(),
        "both unread messages must come from epochs before the resync"
    );

    // The case this test exists for: Dave's message, sent from leaf 0 in an
    // epoch in which leaf 0 was his, read after the virtual client has moved
    // onto that same leaf 0.
    let processed = alice_a_main
        .process_message(
            &alice_a_provider,
            from_dave.into_protocol_message().unwrap(),
        )
        .expect(
            "a message from a leaf the client has since moved onto must not be \
             mistaken for the client's own",
        );
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            assert_eq!(
                app.into_bytes(),
                b"dave from leaf zero",
                "Dave's message came back with the wrong content"
            );
        }
        other => panic!("expected Dave's application message, got {other:?}"),
    }

    // Bob never moved, so his message is the control: it must read the same
    // way before and after the resync.
    let processed = alice_a_main
        .process_message(&alice_a_provider, from_bob.into_protocol_message().unwrap())
        .expect("Bob's pre-resync message must still be readable");
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            assert_eq!(app.into_bytes(), b"bob before the resync");
        }
        other => panic!("expected Bob's application message, got {other:?}"),
    }

    // The virtual client's own message, echoed back by the delivery service.
    // Its sending ratchet consumed that generation, so the echo can only be
    // recognized, not decrypted.
    let processed = alice_a_main
        .process_message(
            &alice_a_provider,
            from_alice_a.into_protocol_message().unwrap(),
        )
        .expect(
            "the echo of a message the virtual client sent from its old leaf, in \
             an epoch whose secret tree belongs to that same old leaf, must still \
             be recognized as its own rather than failing to decrypt",
        );
    assert!(
        matches!(
            processed.into_content(),
            ProcessedMessageContent::OwnPrivateMessage
        ),
        "the echo must be classified as an own message"
    );
}

#[openmls_test]
fn vc_siblings_agree_on_application_secrets() {
    use openmls::components::{
        vc_application_secret::VcApplicationSecretInfo, vc_derivation_info::VirtualClientsError,
    };
    use tls_codec::DeserializeBytes as _;

    const CONTEXT: &[u8] = b"application-defined context";

    let provider_a = Provider::default();
    let provider_b = Provider::default();

    let (emulator_a, _signer_a, emulator_b, _signer_b) =
        sibling_emulation_group(ciphersuite, &provider_a, &provider_b);
    let epoch_id = newest_epoch(&emulator_a, &provider_a);

    let (info, secret) = emulator_a
        .next_vc_application_secret(&provider_a, CONTEXT)
        .expect("alice_a takes an application secret");
    assert_eq!(info.epoch_id, epoch_id);
    assert_eq!(info.leaf_index, emulator_a.own_leaf_index());
    assert_eq!(info.generation, 0);
    assert_eq!(secret.len(), ciphersuite.hash_length());

    // The coordinates reach the sibling over the application's own channel.
    let info_bytes = info.tls_serialize_detached().expect("serialize the info");
    let info =
        VcApplicationSecretInfo::tls_deserialize_exact_bytes(&info_bytes).expect("parse the info");

    let sibling_secret = emulator_b
        .derive_vc_application_secret(&provider_b, &info, CONTEXT)
        .expect("alice_b rederives the secret");
    assert_eq!(secret, sibling_secret);

    let err = emulator_b
        .derive_vc_application_secret(&provider_b, &info, CONTEXT)
        .expect_err("the generation was consumed");
    assert_eq!(err, VirtualClientsError::OperationGenerationConsumed);

    // The sender's ratchet moved on, and the sibling follows.
    let (next_info, next_secret) = emulator_a
        .next_vc_application_secret(&provider_a, CONTEXT)
        .expect("alice_a takes a second application secret");
    assert_eq!(next_info.generation, 1);
    assert_ne!(next_secret, secret);
    assert_eq!(
        next_secret,
        emulator_b
            .derive_vc_application_secret(&provider_b, &next_info, CONTEXT)
            .expect("alice_b rederives the second secret")
    );

    // alice_b sends from its own leaf's ratchet, which is a different one.
    let (own_info, own_secret) = emulator_b
        .next_vc_application_secret(&provider_b, CONTEXT)
        .expect("alice_b takes an application secret of its own");
    assert_eq!(own_info.leaf_index, emulator_b.own_leaf_index());
    assert_ne!(own_info.leaf_index, info.leaf_index);
    assert_eq!(own_info.generation, 0);
    assert_ne!(own_secret, secret);
    assert_eq!(
        own_secret,
        emulator_a
            .derive_vc_application_secret(&provider_a, &own_info, CONTEXT)
            .expect("alice_a rederives its sibling's secret")
    );

    // Own coordinates handed back to their sender are refused instead of
    // burning that client's own ratchet head.
    let err = emulator_b
        .derive_vc_application_secret(&provider_b, &own_info, CONTEXT)
        .expect_err("alice_b must not rederive from its own leaf");
    assert_eq!(err, VirtualClientsError::OwnLeafIndex);

    // The wrong context yields different bytes and still consumes the generation.
    let (mismatch_info, mismatch_secret) = emulator_a
        .next_vc_application_secret(&provider_a, CONTEXT)
        .expect("alice_a takes a third application secret");
    let wrong_context_secret = emulator_b
        .derive_vc_application_secret(&provider_b, &mismatch_info, b"a different context")
        .expect("the wrong context still succeeds");
    assert_ne!(mismatch_secret, wrong_context_secret);
    let err = emulator_b
        .derive_vc_application_secret(&provider_b, &mismatch_info, CONTEXT)
        .expect_err("the wrong context consumed the generation");
    assert_eq!(err, VirtualClientsError::OperationGenerationConsumed);
}

#[openmls_test]
fn vc_application_secret_survives_a_new_derivation_epoch() {
    use openmls::components::{
        vc_application_secret::VcApplicationSecretInfo, vc_derivation_info::VirtualClientsError,
    };

    const CONTEXT: &[u8] = b"application-defined context";

    let provider_a = Provider::default();
    let provider_b = Provider::default();

    let (mut emulator_a, signer_a, mut emulator_b, _signer_b) =
        sibling_emulation_group(ciphersuite, &provider_a, &provider_b);
    let old_epoch = newest_epoch(&emulator_a, &provider_a);

    let (info, secret) = emulator_a
        .next_vc_application_secret(&provider_a, CONTEXT)
        .expect("alice_a takes an application secret");
    assert_eq!(info.epoch_id, old_epoch);

    // The emulation group starts a fresh derivation epoch on both sides.
    let commit = send_emulation_commit(&mut emulator_a, &provider_a, &signer_a, true);
    process_and_merge_commit(&mut emulator_b, &provider_b, commit);
    let new_epoch = newest_epoch(&emulator_a, &provider_a);
    assert_ne!(new_epoch, old_epoch);
    assert_eq!(new_epoch, newest_epoch(&emulator_b, &provider_b));

    let sibling_secret = emulator_b
        .derive_vc_application_secret(&provider_b, &info, CONTEXT)
        .expect("alice_b rederives from the previous derivation epoch");
    assert_eq!(secret, sibling_secret);

    // New secrets come from the new epoch, whose ratchets start over.
    let (next_info, _next_secret) = emulator_a
        .next_vc_application_secret(&provider_a, CONTEXT)
        .expect("alice_a takes an application secret from the new epoch");
    assert_eq!(next_info.epoch_id, new_epoch);
    assert_eq!(next_info.generation, 0);

    let unknown_epoch = VcApplicationSecretInfo {
        epoch_id: EpochId::new(b"unknown epoch".to_vec()),
        ..next_info
    };
    let err = emulator_b
        .derive_vc_application_secret(&provider_b, &unknown_epoch, CONTEXT)
        .expect_err("an unknown derivation epoch has no state");
    assert_eq!(err, VirtualClientsError::MissingDerivationEpochState);
}

#[openmls_test]
fn vc_application_secret_requires_emulation_group() {
    use openmls::components::{
        vc_application_secret::VcApplicationSecretInfo, vc_derivation_info::VirtualClientsError,
    };

    let provider = Provider::default();
    let (group, _signer) = make_emulator_group(ciphersuite, &provider, b"NotAnEmulator", false);

    let info = VcApplicationSecretInfo {
        epoch_id: EpochId::new(b"no such epoch".to_vec()),
        leaf_index: group.own_leaf_index(),
        generation: 0,
    };
    let err = group
        .derive_vc_application_secret(&provider, &info, b"ctx")
        .expect_err("a group without per-epoch state cannot rederive");
    assert_eq!(err, VirtualClientsError::MissingDerivationEpochState);

    let err = group
        .next_vc_application_secret(&provider, b"ctx")
        .expect_err("a group without a derivation epoch has no application ratchet");
    assert_eq!(err, VirtualClientsError::NoDerivationEpoch);
}
