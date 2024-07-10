use framing::mls_content_in::FramedContentBodyIn;
use tests::utils::{generate_credential_with_key, generate_key_package};
use treesync::LeafNodeParameters;

use crate::{
    ciphersuite::signable::Verifiable, framing::*, group::*, key_packages::*,
    schedule::psk::store::ResumptionPskStore, test_utils::*,
    tree::sender_ratchet::SenderRatchetConfiguration, *,
};

#[openmls_test::openmls_test]
fn create_commit_optional_path(
    ciphersuite: Ciphersuite,
    provider: &impl crate::storage::OpenMlsProvider,
) {
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
        ciphersuite,
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
            bob_key_package.key_package().clone(),
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    group_alice.proposal_store_mut().empty();
    group_alice.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .unwrap(),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
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
            bob_key_package.key_package().clone(),
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    group_alice.proposal_store_mut().empty();
    group_alice.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .unwrap(),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
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

    // Bob creates group from Welcome
    let group_bob = StagedCoreWelcome::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        bob_key_package,
        provider,
        ResumptionPskStore::new(1024),
    )
    .and_then(|staged_join| staged_join.into_core_group(provider))
    .unwrap_or_else(|e| panic!("Error creating group from Welcome: {e:?}"));

    assert_eq!(
        group_alice.public_group().export_ratchet_tree(),
        group_bob.public_group().export_ratchet_tree()
    );

    // Alice updates
    let mut alice_new_leaf_node = group_alice.own_leaf_node().unwrap().clone();
    alice_new_leaf_node
        .update(
            ciphersuite,
            provider,
            &alice_credential_with_keys.signer,
            group_alice.group_id().clone(),
            group_alice.own_leaf_index(),
            LeafNodeParameters::default(),
        )
        .unwrap();
    let alice_update_proposal = group_alice
        .create_update_proposal(
            framing_parameters,
            alice_new_leaf_node,
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    group_alice.proposal_store_mut().empty();
    group_alice.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            alice_update_proposal,
        )
        .unwrap(),
    );

    // Only UpdateProposal
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
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

#[openmls_test::openmls_test]
fn basic_group_setup() {
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
    let mut group_alice = CoreGroup::builder(
        GroupId::random(provider.rand()),
        ciphersuite,
        alice_credential_with_keys.credential_with_key,
    )
    .build(provider, &alice_credential_with_keys.signer)
    .expect("Error creating CoreGroup.");

    // Alice adds Bob
    let bob_add_proposal = group_alice
        .create_add_proposal(
            framing_parameters,
            bob_key_package.key_package().clone(),
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    group_alice.proposal_store_mut().empty();
    group_alice.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .unwrap(),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
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
#[openmls_test::openmls_test]
fn group_operations() {
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
    let bob_key_package_bundle = KeyPackageBundle::generate(
        provider,
        &bob_credential_with_keys.signer,
        ciphersuite,
        bob_credential_with_keys.credential_with_key.clone(),
    );
    let bob_key_package = bob_key_package_bundle.key_package();

    // === Alice creates a group ===
    let mut group_alice = CoreGroup::builder(
        GroupId::random(provider.rand()),
        ciphersuite,
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

    group_alice.proposal_store_mut().empty();
    group_alice.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            bob_add_proposal,
        )
        .unwrap(),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
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

    let mut group_bob = match StagedCoreWelcome::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        bob_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
    )
    .and_then(|staged_join| staged_join.into_core_group(provider))
    {
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
        .decrypt_message(
            provider.crypto(),
            mls_ciphertext_alice.into(),
            &sender_ratchet_configuration,
        )
        .expect("An unexpected error occurred.")
        .verifiable_content()
        .to_owned();

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
    let mut bob_new_leaf_node = group_bob.own_leaf_node().unwrap().clone();
    bob_new_leaf_node
        .update(
            ciphersuite,
            provider,
            &bob_credential_with_keys.signer,
            group_bob.group_id().clone(),
            group_bob.own_leaf_index(),
            LeafNodeParameters::default(),
        )
        .unwrap();

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            bob_new_leaf_node,
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    group_bob.proposal_store_mut().empty();
    group_bob.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            update_proposal_bob,
        )
        .unwrap(),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
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
        .read_keys_and_stage_commit(&create_commit_result.commit, &[], provider)
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
    let mut alice_new_leaf_node = group_alice.own_leaf_node().unwrap().clone();
    alice_new_leaf_node
        .update(
            ciphersuite,
            provider,
            &alice_credential_with_keys.signer,
            group_alice.group_id().clone(),
            group_alice.own_leaf_index(),
            LeafNodeParameters::default(),
        )
        .unwrap();

    let update_proposal_alice = group_alice
        .create_update_proposal(
            framing_parameters,
            alice_new_leaf_node,
            &alice_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    group_alice.proposal_store_mut().empty();
    group_alice.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            update_proposal_alice,
        )
        .unwrap(),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
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
        .read_keys_and_stage_commit(&create_commit_result.commit, &[], provider)
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
    let mut bob_new_leaf_node = group_bob.own_leaf_node().unwrap().clone();
    bob_new_leaf_node
        .update(
            ciphersuite,
            provider,
            &bob_credential_with_keys.signer,
            group_bob.group_id().clone(),
            group_bob.own_leaf_index(),
            LeafNodeParameters::default(),
        )
        .unwrap();

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            bob_new_leaf_node.clone(),
            &bob_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    group_alice.proposal_store_mut().empty();
    group_alice.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            update_proposal_bob.clone(),
        )
        .unwrap(),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
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

    let queued_proposal = QueuedProposal::from_authenticated_content_by_ref(
        ciphersuite,
        provider.crypto(),
        update_proposal_bob,
    )
    .unwrap();

    group_alice
        .proposal_store_mut()
        .add(queued_proposal.clone());

    group_bob.proposal_store_mut().add(queued_proposal);

    let staged_commit = group_bob
        .read_keys_and_stage_commit(&create_commit_result.commit, &[bob_new_leaf_node], provider)
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

    let charlie_key_package_bundle = KeyPackageBundle::generate(
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

    let queued_proposal = QueuedProposal::from_authenticated_content_by_ref(
        ciphersuite,
        provider.crypto(),
        add_charlie_proposal_bob,
    )
    .unwrap();

    group_alice.proposal_store_mut().empty();
    group_bob.proposal_store_mut().empty();

    group_alice
        .proposal_store_mut()
        .add(queued_proposal.clone());
    group_bob.proposal_store_mut().add(queued_proposal);

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
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
        .read_keys_and_stage_commit(&create_commit_result.commit, &[], provider)
        .expect("Error applying commit (Alice)");
    group_alice
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");
    group_bob
        .merge_commit(provider, create_commit_result.staged_commit)
        .expect("error merging own commits");

    let ratchet_tree = group_alice.public_group().export_ratchet_tree();
    let mut group_charlie = match StagedCoreWelcome::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        charlie_key_package_bundle,
        provider,
        ResumptionPskStore::new(1024),
    )
    .and_then(|staged_join| staged_join.into_core_group(provider))
    {
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
        .decrypt_message(
            provider.crypto(),
            mls_ciphertext_charlie.clone().into(),
            &sender_ratchet_configuration,
        )
        .expect("An unexpected error occurred.")
        .verifiable_content()
        .to_owned();

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
        .decrypt_message(
            provider.crypto(),
            mls_ciphertext_charlie.into(),
            &sender_ratchet_configuration,
        )
        .expect("An unexpected error occurred.")
        .verifiable_content()
        .to_owned();

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
    let mut charlie_new_leaf_node = group_bob.own_leaf_node().unwrap().clone();
    charlie_new_leaf_node
        .update(
            ciphersuite,
            provider,
            &charlie_credential_with_keys.signer,
            group_charlie.group_id().clone(),
            group_charlie.own_leaf_index(),
            LeafNodeParameters::default(),
        )
        .unwrap();

    let update_proposal_charlie = group_charlie
        .create_update_proposal(
            framing_parameters,
            charlie_new_leaf_node,
            &charlie_credential_with_keys.signer,
        )
        .expect("Could not create proposal.");

    group_charlie.proposal_store_mut().empty();
    group_charlie.proposal_store_mut().add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            provider.crypto(),
            update_proposal_charlie,
        )
        .unwrap(),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
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
        .read_keys_and_stage_commit(&create_commit_result.commit, &[], provider)
        .expect("Error applying commit (Alice)");
    group_alice
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");
    let staged_commit = group_bob
        .read_keys_and_stage_commit(&create_commit_result.commit, &[], provider)
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

    let queued_proposal = QueuedProposal::from_authenticated_content_by_ref(
        ciphersuite,
        provider.crypto(),
        remove_bob_proposal_charlie,
    )
    .unwrap();

    group_alice.proposal_store_mut().empty();
    group_bob.proposal_store_mut().empty();
    group_charlie.proposal_store_mut().empty();

    group_alice
        .proposal_store_mut()
        .add(queued_proposal.clone());
    group_bob.proposal_store_mut().add(queued_proposal.clone());
    group_charlie.proposal_store_mut().add(queued_proposal);

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
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
        .read_keys_and_stage_commit(&create_commit_result.commit, &[], provider)
        .expect("Error applying commit (Alice)");
    group_alice
        .merge_commit(provider, staged_commit)
        .expect("error merging commit");
    assert!(group_bob
        .read_keys_and_stage_commit(&create_commit_result.commit, &[], provider)
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
