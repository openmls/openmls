use crate::{
    ciphersuite::signable::Verifiable,
    credentials::*,
    framing::*,
    group::{tests::tree_printing::print_tree, *},
    key_packages::*,
    test_utils::*,
    tree::sender_ratchet::SenderRatchetConfiguration,
    *,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Serialize;

#[apply(ciphersuites_and_backends)]
fn create_commit_optional_path(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_aad = b"Alice's test group";
    // Framing parameters
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define identities
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Mandatory extensions, will be fixed in #164
    let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
    let mandatory_extensions: Vec<Extension> = vec![lifetime_extension];

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        mandatory_extensions.clone(),
    )
    .expect("An unexpected error occurred.");

    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &bob_credential_bundle,
        backend,
        mandatory_extensions.clone(),
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    let alice_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        mandatory_extensions,
    )
    .expect("An unexpected error occurred.");
    let alice_update_key_package = alice_update_key_package_bundle.key_package();
    assert!(alice_update_key_package.verify(backend,).is_ok());

    // Alice creates a group
    let mut group_alice = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating CoreGroup.");

    // Alice proposes to add Bob with forced self-update
    // Even though there are only Add Proposals, this should generated a path field
    // on the Commit
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .build();
    let create_commit_result =
        match group_alice.create_commit(params /* No PSK fetcher */, backend) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };
    let commit = match create_commit_result.commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!(),
    };
    assert!(commit.has_path());

    // Alice adds Bob without forced self-update
    // Since there are only Add Proposals, this does not generate a path field on
    // the Commit Creating a second proposal to add the same member should
    // not fail, only committing that proposal should fail
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = match group_alice.create_commit(params, backend) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
    let commit = match create_commit_result.commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!(),
    };
    assert!(!commit.has_path());

    // Alice applies the Commit without the forced self-update
    group_alice
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging pending commit");
    let ratchet_tree = group_alice.treesync().export_nodes();

    // Bob creates group from Welcome
    let group_bob = match CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree),
        bob_key_package_bundle,
        backend,
    ) {
        Ok(group) => group,
        Err(e) => panic!("Error creating group from Welcome: {:?}", e),
    };

    assert_eq!(
        group_alice.treesync().export_nodes(),
        group_bob.treesync().export_nodes()
    );

    // Alice updates
    let alice_update_proposal = group_alice
        .create_update_proposal(
            framing_parameters,
            &alice_credential_bundle,
            alice_update_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, alice_update_proposal)
            .expect("Could not create QueuedProposal."),
    );

    // Only UpdateProposal
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = match group_alice.create_commit(params, backend) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
    let commit = match create_commit_result.commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!(),
    };
    assert!(commit.has_path());

    // Apply UpdateProposal
    group_alice
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging pending commit");
}

#[apply(ciphersuites_and_backends)]
fn basic_group_setup(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_aad = b"Alice's test group";
    // Framing parameters
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let bob_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &bob_credential_bundle, backend, Vec::new())
            .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    // Alice creates a group
    let group_alice = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating CoreGroup.");

    // Alice adds Bob
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");

    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .build();
    let _commit = match group_alice.create_commit(params /* PSK fetcher */, backend) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
}

/// This test simulates various group operations like Add, Update, Remove in a
/// small group
///  - Alice creates a group
///  - Alice adds Bob
///  - Alice sends a message to Bob
///  - Bob updates and commits
///  - Alice updates and commits
///  - Bob updates and Alice commits
///  - Bob adds Charlie
///  - Charlie sends a message to the group
///  - Charlie updates and commits
///  - Charlie removes Bob
#[apply(ciphersuites_and_backends)]
fn group_operations(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_aad = b"Alice's test group";
    // Framing parameters
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);
    let sender_ratchet_configuration = SenderRatchetConfiguration::default();

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Mandatory extensions
    let capabilities_extension = Extension::Capabilities(CapabilitiesExtension::new(
        None,
        Some(&[ciphersuite]),
        None,
        None,
    ));
    let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
    let mandatory_extensions: Vec<Extension> = vec![capabilities_extension, lifetime_extension];

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        mandatory_extensions.clone(),
    )
    .expect("An unexpected error occurred.");

    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &bob_credential_bundle,
        backend,
        mandatory_extensions.clone(),
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    // === Alice creates a group ===
    let mut group_alice = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating CoreGroup.");

    // === Alice adds Bob ===
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = group_alice
        .create_commit(params, backend)
        .expect("Error creating commit");
    let commit = match create_commit_result.commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(!commit.has_path());
    // Check that the function returned a Welcome message
    assert!(create_commit_result.welcome_option.is_some());

    group_alice
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging own commits");
    let ratchet_tree = group_alice.treesync().export_nodes();

    let mut group_bob = match CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree),
        bob_key_package_bundle,
        backend,
    ) {
        Ok(group) => group,
        Err(e) => panic!("Error creating group from Welcome: {:?}", e),
    };

    // Make sure that both groups have the same public tree
    if group_alice.treesync().export_nodes() != group_bob.treesync().export_nodes() {
        print_tree(&group_alice, "Alice added Bob");
        panic!("Different public trees");
    }
    // Make sure that both groups have the same group context
    if group_alice.context() != group_bob.context() {
        panic!("Different group contexts");
    }

    // === Alice sends a message to Bob ===
    let message_alice = [1, 2, 3];
    let mls_ciphertext_alice = group_alice
        .create_application_message(&[], &message_alice, &alice_credential_bundle, 0, backend)
        .expect("An unexpected error occurred.");

    let mut verifiable_plaintext = group_bob
        .decrypt(
            &mls_ciphertext_alice,
            backend,
            &sender_ratchet_configuration,
        )
        .expect("An unexpected error occurred.");

    verifiable_plaintext.set_context(
        group_bob
            .context()
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
    );

    let credential = group_alice
        .treesync()
        .own_leaf_node()
        .expect("An unexpected error occurred.")
        .key_package()
        .credential();
    let mls_plaintext_bob: MlsPlaintext = verifiable_plaintext
        .verify(backend, credential)
        .expect("An unexpected error occurred.");

    assert!(matches!(
        mls_plaintext_bob.content(), 
            MlsPlaintextContentType::Application(message) if message.as_slice() == &message_alice[..]));

    // === Bob updates and commits ===
    let bob_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &bob_credential_bundle,
        backend,
        mandatory_extensions.clone(),
    )
    .expect("Could not create key package bundle.");

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            &bob_credential_bundle,
            bob_update_key_package_bundle.key_package().clone(),
            backend,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, update_proposal_bob)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&bob_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = match group_bob.create_commit(params, backend) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    // Check that there is a path
    let commit = match create_commit_result.commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(commit.has_path());
    // Check there is no Welcome message
    assert!(create_commit_result.welcome_option.is_none());

    let staged_commit = group_alice
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("Error applying commit (Alice)");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");

    group_bob
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging own commits");

    // Make sure that both groups have the same public tree
    if group_alice.treesync().export_nodes() != group_bob.treesync().export_nodes() {
        print_tree(&group_alice, "Alice added Bob");
        panic!("Different public trees");
    }

    // === Alice updates and commits ===
    let alice_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        mandatory_extensions.clone(),
    )
    .expect("Could not create key package bundle.");

    let update_proposal_alice = group_alice
        .create_update_proposal(
            framing_parameters,
            &alice_credential_bundle,
            alice_update_key_package_bundle.key_package().clone(),
            backend,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, update_proposal_alice)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result =
        match group_alice.create_commit(params /* PSK fetcher */, backend) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };

    // Check that there is a path
    assert!(commit.has_path());

    group_alice
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging own commits");
    let staged_commit = group_bob
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("Error applying commit (Bob)");
    group_bob
        .merge_commit(staged_commit)
        .expect("error merging commit");

    // Make sure that both groups have the same public tree
    if group_alice.treesync().export_nodes() != group_bob.treesync().export_nodes() {
        print_tree(&group_alice, "Alice added Bob");
        panic!("Different public trees");
    }

    // === Bob updates and Alice commits ===
    let bob_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &bob_credential_bundle,
        backend,
        mandatory_extensions.clone(),
    )
    .expect("Could not create key package bundle.");

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            &bob_credential_bundle,
            bob_update_key_package_bundle.key_package().clone(),
            backend,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, update_proposal_bob.clone())
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = match group_alice.create_commit(params, backend) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    // Check that there is a path
    assert!(commit.has_path());

    group_alice
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging own commits");

    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, update_proposal_bob)
            .expect("Could not create StagedProposal."),
    );

    let staged_commit = group_bob
        .stage_commit(
            &create_commit_result.commit,
            &proposal_store,
            &[bob_update_key_package_bundle],
            backend,
        )
        .expect("Error applying commit (Bob)");
    group_bob
        .merge_commit(staged_commit)
        .expect("error merging commit");

    // Make sure that both groups have the same public tree
    if group_alice.treesync().export_nodes() != group_bob.treesync().export_nodes() {
        print_tree(&group_alice, "Alice added Bob");
        panic!("Different public trees");
    }

    // === Bob adds Charlie ===
    let charlie_credential_bundle = CredentialBundle::new(
        "Charlie".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    let charlie_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &charlie_credential_bundle,
        backend,
        mandatory_extensions.clone(),
    )
    .expect("Could not create key package bundle.");
    let charlie_key_package = charlie_key_package_bundle.key_package().clone();

    let add_charlie_proposal_bob = group_bob
        .create_add_proposal(
            framing_parameters,
            &bob_credential_bundle,
            charlie_key_package,
            backend,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, add_charlie_proposal_bob)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&bob_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = match group_bob.create_commit(params, backend) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    // Check there is no path since there are only Add Proposals and no forced
    // self-update
    let commit = match create_commit_result.commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(!commit.has_path());
    // Make sure the is a Welcome message for Charlie
    assert!(create_commit_result.welcome_option.is_some());

    let staged_commit = group_alice
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("Error applying commit (Alice)");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");
    group_bob
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging own commits");

    let ratchet_tree = group_alice.treesync().export_nodes();
    let mut group_charlie = match CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree),
        charlie_key_package_bundle,
        backend,
    ) {
        Ok(group) => group,
        Err(e) => panic!("Error creating group from Welcome: {:?}", e),
    };

    // Make sure that all groups have the same public tree
    if group_alice.treesync().export_nodes() != group_bob.treesync().export_nodes() {
        print_tree(&group_alice, "Bob added Charlie");
        panic!("Different public trees");
    }
    if group_alice.treesync().export_nodes() != group_charlie.treesync().export_nodes() {
        print_tree(&group_alice, "Bob added Charlie");
        panic!("Different public trees");
    }

    // === Charlie sends a message to the group ===
    let message_charlie = [1, 2, 3];
    let mls_ciphertext_charlie = group_charlie
        .create_application_message(
            &[],
            &message_charlie,
            &charlie_credential_bundle,
            0,
            backend,
        )
        .expect("An unexpected error occurred.");

    // Alice decrypts and verifies
    let mut verifiable_plaintext = group_alice
        .decrypt(
            &mls_ciphertext_charlie.clone(),
            backend,
            &sender_ratchet_configuration,
        )
        .expect("An unexpected error occurred.");

    verifiable_plaintext.set_context(
        group_alice
            .context()
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
    );

    let credential = group_charlie
        .treesync()
        .own_leaf_node()
        .expect("An unexpected error occurred.")
        .key_package()
        .credential();

    let mls_plaintext_alice: MlsPlaintext = verifiable_plaintext
        .verify(backend, credential)
        .expect("An unexpected error occurred.");

    assert!(matches!(
        mls_plaintext_alice.content(), 
            MlsPlaintextContentType::Application(message) if message.as_slice() == &message_charlie[..]));

    // Bob decrypts and verifies
    let mut verifiable_plaintext = group_bob
        .decrypt(
            &mls_ciphertext_charlie,
            backend,
            &sender_ratchet_configuration,
        )
        .expect("An unexpected error occurred.");

    verifiable_plaintext.set_context(
        group_bob
            .context()
            .tls_serialize_detached()
            .expect("An unexpected error occurred."),
    );

    let credential = group_charlie
        .treesync()
        .own_leaf_node()
        .expect("An unexpected error occurred.")
        .key_package()
        .credential();
    let mls_plaintext_bob: MlsPlaintext = verifiable_plaintext
        .verify(backend, credential)
        .expect("An unexpected error occurred.");

    assert!(matches!(
        mls_plaintext_bob.content(), 
        MlsPlaintextContentType::Application(message) if message.as_slice() == &message_charlie[..]));

    // === Charlie updates and commits ===
    let charlie_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &charlie_credential_bundle,
        backend,
        mandatory_extensions,
    )
    .expect("Could not create key package bundle.");

    let update_proposal_charlie = group_charlie
        .create_update_proposal(
            framing_parameters,
            &charlie_credential_bundle,
            charlie_update_key_package_bundle.key_package().clone(),
            backend,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, update_proposal_charlie)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&charlie_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = match group_charlie.create_commit(params, backend) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    // Check that there is a new KeyPackageBundle
    let commit = match create_commit_result.commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(commit.has_path());

    let staged_commit = group_alice
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("Error applying commit (Alice)");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");
    let staged_commit = group_bob
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("Error applying commit (Bob)");
    group_bob
        .merge_commit(staged_commit)
        .expect("error merging commit");
    group_charlie
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging own commits");

    // Make sure that all groups have the same public tree
    if group_alice.treesync().export_nodes() != group_bob.treesync().export_nodes() {
        print_tree(&group_alice, "Charlie updated");
        panic!("Different public trees");
    }
    if group_alice.treesync().export_nodes() != group_charlie.treesync().export_nodes() {
        print_tree(&group_alice, "Charlie updated");
        panic!("Different public trees");
    }

    // === Charlie removes Bob ===
    let remove_bob_proposal_charlie = group_charlie
        .create_remove_proposal(
            framing_parameters,
            &charlie_credential_bundle,
            group_bob
                .key_package_ref()
                .expect("An unexpected error occurred."),
            backend,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, remove_bob_proposal_charlie)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&charlie_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result =
        match group_charlie.create_commit(params /* PSK fetcher */, backend) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };

    // Check that there is a new KeyPackageBundle
    assert!(commit.has_path());

    let staged_commit = group_alice
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("Error applying commit (Alice)");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");
    assert!(group_bob
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend,)
        .expect("Could not stage commit.")
        .self_removed());
    group_charlie
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging own commits");

    // Make sure that all groups have the same public tree
    if group_alice.treesync().export_nodes() == group_bob.treesync().export_nodes() {
        print_tree(&group_alice, "Charlie removed Bob");
        panic!("Same public trees");
    }
    if group_alice.treesync().export_nodes() != group_charlie.treesync().export_nodes() {
        print_tree(&group_alice, "Charlie removed Bob");
        panic!("Different public trees");
    }

    // Make sure all groups export the same key
    let alice_exporter = group_alice
        .export_secret(backend, "export test", &[], 32)
        .expect("An unexpected error occurred.");
    let charlie_exporter = group_charlie
        .export_secret(backend, "export test", &[], 32)
        .expect("An unexpected error occurred.");
    assert_eq!(alice_exporter, charlie_exporter);

    // Now alice tries to derive an exporter with too large of a key length.
    let exporter_length: usize = u16::MAX.into();
    let exporter_length = exporter_length + 1;
    let alice_exporter = group_alice.export_secret(backend, "export test", &[], exporter_length);
    assert!(alice_exporter.is_err())
}
