use crate::{
    credentials::{CredentialBundle, CredentialType},
    framing::{FramingParameters, WireFormat},
    group::GroupId,
    key_packages::KeyPackageBundle,
    messages::{
        proposals::{ProposalOrRef, ProposalType},
        public_group_state::VerifiablePublicGroupState,
    },
    test_utils::*,
};

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
use tls_codec::{Deserialize, Serialize};

use super::{
    create_commit_params::CreateCommitParams,
    proposals::{ProposalStore, QueuedProposal},
    CoreGroup,
};

#[apply(ciphersuites_and_backends)]
fn test_external_init(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
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
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    let bob_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite], &bob_credential_bundle, backend, Vec::new())
            .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    // === Alice creates a group ===
    let group_id = GroupId::random(backend);

    let mut group_alice = CoreGroup::builder(group_id, alice_key_package_bundle)
        .build(backend)
        .expect("An unexpected error occurred.");

    // === Alice adds Bob ===
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
    let create_commit_result = group_alice
        .create_commit(params, backend)
        .expect("Error creating commit");

    group_alice
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging commit");
    let ratchet_tree = group_alice.treesync().export_nodes();

    let mut group_bob = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("no welcome after committing to add proposal"),
        Some(ratchet_tree),
        bob_key_package_bundle,
        backend,
    )
    .expect("An unexpected error occurred.");

    // Now set up charly and try to init externally.
    // Define credential bundles
    let charly_credential_bundle = CredentialBundle::new(
        "Charly".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Have Alice export everything that Charly needs.
    let pgs_encoded: Vec<u8> = group_alice
        .export_public_group_state(backend, &alice_credential_bundle)
        .expect("Error exporting PGS")
        .tls_serialize_detached()
        .expect("Error serializing PGS");
    let verifiable_public_group_state =
        VerifiablePublicGroupState::tls_deserialize(&mut pgs_encoded.as_slice())
            .expect("Error deserializing PGS");

    let proposal_store = ProposalStore::new();
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&charly_credential_bundle)
        .proposal_store(&proposal_store)
        .build();
    let (mut group_charly, create_commit_result) =
        CoreGroup::join_by_external_commit(backend, params, None, verifiable_public_group_state)
            .expect("Error initializing group externally.");

    // Have alice and bob process the commit resulting from external init.
    let proposal_store = ProposalStore::default();
    let staged_commit = group_alice
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");

    let staged_commit = group_bob
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_bob
        .merge_commit(staged_commit)
        .expect("error merging commit");

    // Have charly process their own staged commit
    group_charly
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging own external commit");

    assert_eq!(
        group_charly.export_secret(backend, "", &[], ciphersuite.hash_length()),
        group_bob.export_secret(backend, "", &[], ciphersuite.hash_length())
    );

    assert_eq!(
        group_charly.treesync().export_nodes(),
        group_bob.treesync().export_nodes()
    );

    // Check if charly can create valid commits
    let proposal_store = ProposalStore::default();
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&charly_credential_bundle)
        .proposal_store(&proposal_store)
        .build();
    let create_commit_result = group_charly
        .create_commit(params, backend)
        .expect("Error creating commit");

    let staged_commit = group_alice
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");

    group_charly
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging commit");

    // Now we assume that Bob somehow lost his group state and wants to add
    // themselves back through an external commit.

    // Have Alice export everything that Bob needs.
    let pgs_encoded: Vec<u8> = group_alice
        .export_public_group_state(backend, &alice_credential_bundle)
        .expect("Error exporting PGS")
        .tls_serialize_detached()
        .expect("Error serializing PGS");
    let verifiable_public_group_state =
        VerifiablePublicGroupState::tls_deserialize(&mut pgs_encoded.as_slice())
            .expect("Error deserializing PGS");
    let nodes_option = group_alice.treesync().export_nodes();

    let proposal_store = ProposalStore::new();
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&bob_credential_bundle)
        .proposal_store(&proposal_store)
        .build();
    let (mut new_group_bob, create_commit_result) = CoreGroup::join_by_external_commit(
        backend,
        params,
        Some(&nodes_option),
        verifiable_public_group_state,
    )
    .expect("Error initializing group externally.");

    // Let's make sure there's a remove in the commit.
    let contains_remove = match create_commit_result.commit.content() {
        crate::prelude_test::plaintext::MlsPlaintextContentType::Commit(commit) => commit
            .proposals
            .as_slice()
            .iter()
            .find(|&proposal| match proposal {
                ProposalOrRef::Proposal(proposal) => proposal.is_type(ProposalType::Remove),
                _ => false,
            }),
        _ => panic!("Wrong content type."),
    }
    .is_some();
    assert!(contains_remove);

    // Have alice and charly process the commit resulting from external init.
    let proposal_store = ProposalStore::default();
    let staged_commit = group_alice
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");

    let staged_commit = group_charly
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_charly
        .merge_commit(staged_commit)
        .expect("error merging commit");

    // Have Bob process his own staged commit
    new_group_bob
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging own external commit");

    assert_eq!(
        group_charly.export_secret(backend, "", &[], ciphersuite.hash_length()),
        new_group_bob.export_secret(backend, "", &[], ciphersuite.hash_length())
    );

    assert_eq!(
        group_charly.treesync().export_nodes(),
        new_group_bob.treesync().export_nodes()
    );
}

#[apply(ciphersuites_and_backends)]
fn test_external_init_single_member_group(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    // === Alice creates a group ===
    let group_id = GroupId::random(backend);

    let mut group_alice = CoreGroup::builder(group_id, alice_key_package_bundle)
        .build(backend)
        .expect("An unexpected error occurred.");

    // Now set up charly and try to init externally.
    // Define credential bundles
    let charly_credential_bundle = CredentialBundle::new(
        "Charly".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Have Alice export everything that Charly needs.
    let pgs_encoded: Vec<u8> = group_alice
        .export_public_group_state(backend, &alice_credential_bundle)
        .expect("Error exporting PGS")
        .tls_serialize_detached()
        .expect("Error serializing PGS");
    let verifiable_public_group_state =
        VerifiablePublicGroupState::tls_deserialize(&mut pgs_encoded.as_slice())
            .expect("Error deserializing PGS");
    let nodes_option = group_alice.treesync().export_nodes();

    let proposal_store = ProposalStore::new();
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&charly_credential_bundle)
        .proposal_store(&proposal_store)
        .build();
    let (mut group_charly, create_commit_result) = CoreGroup::join_by_external_commit(
        backend,
        params,
        Some(&nodes_option),
        verifiable_public_group_state,
    )
    .expect("Error initializing group externally.");

    // Have alice and bob process the commit resulting from external init.
    let proposal_store = ProposalStore::default();
    let staged_commit = group_alice
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");

    group_charly
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging own external commit");

    assert_eq!(
        group_charly.export_secret(backend, "", &[], ciphersuite.hash_length()),
        group_alice.export_secret(backend, "", &[], ciphersuite.hash_length())
    );

    assert_eq!(
        group_charly.treesync().export_nodes(),
        group_alice.treesync().export_nodes()
    );
}
