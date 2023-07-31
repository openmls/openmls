use framing::mls_content_in::FramedContentBodyIn;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::key_store::OpenMlsKeyStore;
use tests::utils::{generate_credential_with_key, generate_key_package};

use crate::{
    ciphersuite::signable::Verifiable,
    framing::*,
    group::{config::CryptoConfig, *},
    key_packages::*,
    schedule::psk::store::ResumptionPskStore,
    test_utils::*,
    tree::sender_ratchet::SenderRatchetConfiguration,
    treesync::node::leaf_node::TreeInfoTbs,
    *,
};

#[apply(ciphersuites_and_providers)]
fn create_commit_optional_path(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_aad = b"Alice's test group";
    // Framing parameters
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    // Define identities
    let alice_credential_with_keys = generate_credential_with_key(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        provider,
    );
    let bob_credential_with_keys =
        generate_credential_with_key(b"Bob".to_vec(), ciphersuite.signature_algorithm(), provider);

    // Generate Bob's KeyPackage
    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        bob_credential_with_keys,
    );

    // Alice creates a group
    let mut group_alice = CoreGroup::builder(
        GroupId::random(provider.rand()),
        CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_keys.credential_with_key,
    )
    .build(provider, &alice_credential_with_keys.signer)
    .expect("Error creating CoreGroup.");

    // Alice proposes to add Bob with forced self-update
    // Even though there are only Add Proposals, this should generated a path field
    // on the Commit
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            bob_key_package.clone(),
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .build();
    let create_commit_result = match group_alice.create_commit(
        params, /* No PSK fetcher */
        provider,
        &alice_credential_with_keys.signer,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {e:?}"),
    };
    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
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
            bob_key_package.clone(),
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result =
        match group_alice.create_commit(params, provider, &alice_credential_with_keys.signer) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {e:?}"),
        };
    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
        _ => panic!(),
    };
    assert!(!commit.has_path());

    // Alice applies the Commit without the forced self-update
    group_alice
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging pending commit");
    let ratchet_tree = group_alice.public_group().export_ratchet_tree();

    let bob_private_key = provider
        .key_store()
        .read::<HpkePrivateKey>(bob_key_package.hpke_init_key().as_slice())
        .unwrap();
    let bob_key_package_bundle = KeyPackageBundle {
        key_package: bob_key_package,
        private_key: bob_private_key,
    };

    // Bob creates group from Welcome
    let group_bob = match CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        bob_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
    ) {
        Ok(group) => group,
        Err(e) => panic!("Error creating group from Welcome: {e:?}"),
    };

    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_bob.public_group().export_ratchet_tree()
    );

    // Alice updates
    let alice_new_leaf_node = group_alice
        .own_leaf_node()
        .unwrap()
        .updated(
            CryptoConfig::with_default_version(ciphersuite),
            TreeInfoTbs::Update(group_alice.own_tree_position()),
            provider,
            &alice_credential_with_keys.signer,
        )
        .unwrap();
    let alice_update_proposal = group_alice
        .create_update_proposal(
            framing_parameters,
            alice_new_leaf_node,
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            alice_update_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );

    // Only UpdateProposal
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result =
        match group_alice.create_commit(params, provider, &alice_credential_with_keys.signer) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {e:?}"),
        };
    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
        _ => panic!(),
    };
    assert!(commit.has_path());

    // Apply UpdateProposal
    group_alice
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging pending commit");
}

#[apply(ciphersuites_and_providers)]
fn basic_group_setup(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_aad = b"Alice's test group";
    // Framing parameters
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    // Define credentials with keys
    let alice_credential_with_keys = generate_credential_with_key(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        provider,
    );
    let bob_credential_with_keys =
        generate_credential_with_key(b"Bob".to_vec(), ciphersuite.signature_algorithm(), provider);

    // Generate KeyPackages
    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        provider,
        bob_credential_with_keys,
    );

    // Alice creates a group
    let group_alice = CoreGroup::builder(
        GroupId::random(provider.rand()),
        CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_keys.credential_with_key,
    )
    .build(provider, &alice_credential_with_keys.signer)
    .expect("Error creating CoreGroup.");

    // Alice adds Bob
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            bob_key_package,
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .build();
    let _commit = match group_alice.create_commit(
        params, /* PSK fetcher */
        provider,
        &alice_credential_with_keys.signer,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {e:?}"),
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
#[apply(ciphersuites_and_providers)]
fn group_operations(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let group_aad = b"Alice's test group";
    // Framing parameters
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);
    let sender_ratchet_configuration = SenderRatchetConfiguration::default();

    // Define credentials with keys
    let alice_credential_with_keys = generate_credential_with_key(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        provider,
    );
    let bob_credential_with_keys =
        generate_credential_with_key(b"Bob".to_vec(), ciphersuite.signature_algorithm(), provider);

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        provider,
        &bob_credential_with_keys.signer,
        ciphersuite,
        bob_credential_with_keys.credential_with_key.clone(),
    );
    let bob_key_package = bob_key_package_bundle.key_package();

    // === Alice creates a group ===
    let mut group_alice = CoreGroup::builder(
        GroupId::random(provider.rand()),
        CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_keys.credential_with_key.clone(),
    )
    .build(provider, &alice_credential_with_keys.signer)
    .expect("Error creating CoreGroup.");

    // === Alice adds Bob ===
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            bob_key_package.clone(),
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = group_alice
        .create_commit(params, provider, &alice_credential_with_keys.signer)
        .expect("Error creating commit");
    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(!commit.has_path());
    // Check that the function returned a Welcome message
    assert!(create_commit_result.welcome_option.is_some());

    group_alice
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging own commits");
    let ratchet_tree = group_alice.public_group().export_ratchet_tree();

    let mut group_bob = match CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        bob_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
    ) {
        Ok(group) => group,
        Err(e) => panic!("Error creating group from Welcome: {e:?}"),
    };

    // Make sure that both groups have the same public tree
    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_bob.public_group().export_ratchet_tree()
    );

    // Make sure that both groups have the same group context
    if group_alice.context() != group_bob.context() {
        panic!("Different group contexts");
    }

    // === Alice sends a message to Bob ===
    let message_alice = [1, 2, 3];
    let mls_ciphertext_alice: PrivateMessageIn = group_alice
        .create_application_message(
            &[],
            &message_alice,
            0,
            provider,
            &alice_credential_with_keys.signer,
        )
        .expect("An unexpected error occurred.")
        .into();

    let verifiable_plaintext = group_bob
        .decrypt(
            &mls_ciphertext_alice,
            provider,
            &sender_ratchet_configuration,
        )
        .expect("An unexpected error occurred.");

    let mls_plaintext_bob: AuthenticatedContentIn = verifiable_plaintext
        .verify(
            provider.crypto(),
            &OpenMlsSignaturePublicKey::new(
                alice_credential_with_keys.signer.to_public_vec().into(),
                ciphersuite.signature_algorithm(),
            )
            .unwrap(),
        )
        .expect("An unexpected error occurred.");

    assert!(matches!(
        mls_plaintext_bob.content(),
            FramedContentBodyIn::Application(message) if message.as_slice() == &message_alice[..]));

    // === Bob updates and commits ===
    let bob_new_leaf_node = group_bob
        .own_leaf_node()
        .unwrap()
        .updated(
            CryptoConfig::with_default_version(ciphersuite),
            TreeInfoTbs::Update(group_bob.own_tree_position()),
            provider,
            &alice_credential_with_keys.signer,
        )
        .unwrap();

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            bob_new_leaf_node,
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            update_proposal_bob,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result =
        match group_bob.create_commit(params, provider, &bob_credential_with_keys.signer) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {e:?}"),
        };

    // Check that there is a path
    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(commit.has_path());
    // Check there is no Welcome message
    assert!(create_commit_result.welcome_option.is_none());

    let staged_commit = group_alice
        .read_keys_and_stage_commit(&create_commit_result.commit, &proposal_store, &[], provider)
        .expect("Error applying commit (Alice)");
    group_alice
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");

    group_bob
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging own commits");

    // Make sure that both groups have the same public tree
    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_bob.public_group().export_ratchet_tree()
    );

    // === Alice updates and commits ===
    let alice_new_leaf_node = group_alice
        .own_leaf_node()
        .unwrap()
        .updated(
            CryptoConfig::with_default_version(ciphersuite),
            TreeInfoTbs::Update(group_alice.own_tree_position()),
            provider,
            &alice_credential_with_keys.signer,
        )
        .unwrap();

    let update_proposal_alice = group_alice
        .create_update_proposal(
            framing_parameters,
            alice_new_leaf_node,
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            update_proposal_alice,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = match group_alice.create_commit(
        params, /* PSK fetcher */
        provider,
        &alice_credential_with_keys.signer,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {e:?}"),
    };

    // Check that there is a path
    assert!(commit.has_path());

    group_alice
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging own commits");
    let staged_commit = group_bob
        .read_keys_and_stage_commit(&create_commit_result.commit, &proposal_store, &[], provider)
        .expect("Error applying commit (Bob)");
    group_bob
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");

    // Make sure that both groups have the same public tree
    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_bob.public_group().export_ratchet_tree()
    );

    // === Bob updates and Alice commits ===
    let bob_new_leaf_node = group_bob
        .own_leaf_node()
        .unwrap()
        .updated(
            CryptoConfig::with_default_version(ciphersuite),
            TreeInfoTbs::Update(group_bob.own_tree_position()),
            provider,
            &bob_credential_with_keys.signer,
        )
        .unwrap();

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            bob_new_leaf_node.clone(),
            &bob_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            update_proposal_bob.clone(),
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result =
        match group_alice.create_commit(params, provider, &alice_credential_with_keys.signer) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {e:?}"),
        };

    // Check that there is a path
    assert!(commit.has_path());

    group_alice
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging own commits");

    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            update_proposal_bob,
        )
        .expect("Could not create StagedProposal."),
    );

    let staged_commit = group_bob
        .read_keys_and_stage_commit(
            &create_commit_result.commit,
            &proposal_store,
            &[bob_new_leaf_node],
            provider,
        )
        .expect("Error applying commit (Bob)");
    group_bob
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");

    // Make sure that both groups have the same public tree
    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_bob.public_group().export_ratchet_tree()
    );

    // === Bob adds Charlie ===
    let charlie_credential_with_keys = generate_credential_with_key(
        b"Charlie".to_vec(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    let charlie_key_package_bundle = KeyPackageBundle::new(
        provider,
        &charlie_credential_with_keys.signer,
        ciphersuite,
        charlie_credential_with_keys.credential_with_key.clone(),
    );
    let charlie_key_package = charlie_key_package_bundle.key_package().clone();

    let add_charlie_proposal_bob = group_bob
        .create_add_proposal(
            framing_parameters,
            charlie_key_package,
            &bob_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            add_charlie_proposal_bob,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result =
        match group_bob.create_commit(params, provider, &bob_credential_with_keys.signer) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {e:?}"),
        };

    // Check there is no path since there are only Add Proposals and no forced
    // self-update
    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(!commit.has_path());
    // Make sure this is a Welcome message for Charlie
    assert!(create_commit_result.welcome_option.is_some());

    let staged_commit = group_alice
        .read_keys_and_stage_commit(&create_commit_result.commit, &proposal_store, &[], provider)
        .expect("Error applying commit (Alice)");
    group_alice
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");
    group_bob
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging own commits");

    let ratchet_tree = group_alice.public_group().export_ratchet_tree();
    let mut group_charlie = match CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        charlie_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
    ) {
        Ok(group) => group,
        Err(e) => panic!("Error creating group from Welcome: {e:?}"),
    };

    // Make sure that all groups have the same public tree
    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_bob.public_group().export_ratchet_tree()
    );
    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_charlie.public_group().export_ratchet_tree()
    );

    // === Charlie sends a message to the group ===
    let message_charlie = [1, 2, 3];
    let mls_ciphertext_charlie: PrivateMessageIn = group_charlie
        .create_application_message(
            &[],
            &message_charlie,
            0,
            provider,
            &charlie_credential_with_keys.signer,
        )
        .expect("An unexpected error occurred.")
        .into();

    // Alice decrypts and verifies
    let verifiable_plaintext = group_alice
        .decrypt(
            &mls_ciphertext_charlie.clone(),
            provider,
            &sender_ratchet_configuration,
        )
        .expect("An unexpected error occurred.");

    let mls_plaintext_alice: AuthenticatedContentIn = verifiable_plaintext
        .verify(
            provider.crypto(),
            &OpenMlsSignaturePublicKey::new(
                charlie_credential_with_keys.signer.to_public_vec().into(),
                ciphersuite.signature_algorithm(),
            )
            .unwrap(),
        )
        .expect("An unexpected error occurred.");

    assert!(matches!(
        mls_plaintext_alice.content(),
            FramedContentBodyIn::Application(message) if message.as_slice() == &message_charlie[..]));

    // Bob decrypts and verifies
    let verifiable_plaintext = group_bob
        .decrypt(
            &mls_ciphertext_charlie,
            provider,
            &sender_ratchet_configuration,
        )
        .expect("An unexpected error occurred.");

    let mls_plaintext_bob: AuthenticatedContentIn = verifiable_plaintext
        .verify(
            provider.crypto(),
            &OpenMlsSignaturePublicKey::new(
                charlie_credential_with_keys.signer.to_public_vec().into(),
                ciphersuite.signature_algorithm(),
            )
            .unwrap(),
        )
        .expect("An unexpected error occurred.");

    assert!(matches!(
        mls_plaintext_bob.content(),
        FramedContentBodyIn::Application(message) if message.as_slice() == &message_charlie[..]));

    // === Charlie updates and commits ===
    let charlie_new_leaf_node = group_charlie
        .own_leaf_node()
        .unwrap()
        .updated(
            CryptoConfig::with_default_version(ciphersuite),
            TreeInfoTbs::Update(group_charlie.own_tree_position()),
            provider,
            &charlie_credential_with_keys.signer,
        )
        .unwrap();

    let update_proposal_charlie = group_charlie
        .create_update_proposal(
            framing_parameters,
            charlie_new_leaf_node,
            &charlie_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            update_proposal_charlie,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result =
        match group_charlie.create_commit(params, provider, &charlie_credential_with_keys.signer) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {e:?}"),
        };

    // Check that there is a new KeyPackageBundle
    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(commit.has_path());

    let staged_commit = group_alice
        .read_keys_and_stage_commit(&create_commit_result.commit, &proposal_store, &[], provider)
        .expect("Error applying commit (Alice)");
    group_alice
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");
    let staged_commit = group_bob
        .read_keys_and_stage_commit(&create_commit_result.commit, &proposal_store, &[], provider)
        .expect("Error applying commit (Bob)");
    group_bob
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");
    group_charlie
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging own commits");

    // Make sure that all groups have the same public tree
    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_bob.public_group().export_ratchet_tree()
    );
    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_charlie.public_group().export_ratchet_tree()
    );

    // === Charlie removes Bob ===
    let remove_bob_proposal_charlie = group_charlie
        .create_remove_proposal(
            framing_parameters,
            group_bob.own_leaf_index(),
            &charlie_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    proposal_store.empty();
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            remove_bob_proposal_charlie,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = match group_charlie.create_commit(
        params, /* PSK fetcher */
        provider,
        &charlie_credential_with_keys.signer,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {e:?}"),
    };

    // Check that there is a new KeyPackageBundle
    assert!(commit.has_path());

    let staged_commit = group_alice
        .read_keys_and_stage_commit(&create_commit_result.commit, &proposal_store, &[], provider)
        .expect("Error applying commit (Alice)");
    group_alice
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");
    assert!(group_bob
        .read_keys_and_stage_commit(&create_commit_result.commit, &proposal_store, &[], provider)
        .expect("Could not stage commit.")
        .self_removed());
    group_charlie
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging own commits");

    assert_ne!(
        group_alice.public_group().export_ratchet_tree(),
        group_bob.public_group().export_ratchet_tree()
    );
    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_charlie.public_group().export_ratchet_tree()
    );

    // Make sure all groups export the same key
    let alice_exporter = group_alice
        .export_secret(provider.crypto(), "export test", &[], 32)
        .expect("An unexpected error occurred.");
    let charlie_exporter = group_charlie
        .export_secret(provider.crypto(), "export test", &[], 32)
        .expect("An unexpected error occurred.");
    assert_eq!(alice_exporter, charlie_exporter);

    // Now alice tries to derive an exporter with too large of a key length.
    let exporter_length: usize = u16::MAX.into();
    let exporter_length = exporter_length + 1;
    let alice_exporter =
        group_alice.export_secret(provider.crypto(), "export test", &[], exporter_length);
    assert!(alice_exporter.is_err())
}
