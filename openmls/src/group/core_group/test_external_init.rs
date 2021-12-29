use crate::group::GroupId;
use crate::{
    ciphersuite::Ciphersuite,
    config::Config,
    credentials::{CredentialBundle, CredentialType},
    framing::{FramingParameters, WireFormat},
    key_packages::KeyPackageBundle,
    messages::public_group_state::VerifiablePublicGroupState,
    test_utils::*,
};

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Deserialize, Serialize};

use super::{
    create_commit_params::CreateCommitParams,
    proposals::{ProposalStore, QueuedProposal},
    CoreGroup,
};

#[apply(ciphersuites_and_backends)]
fn test_external_init(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .unwrap();
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .unwrap();

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .unwrap();

    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        Vec::new(),
    )
    .unwrap();
    let bob_key_package = bob_key_package_bundle.key_package();

    // === Alice creates a group ===
    let group_id = GroupId::random(backend);

    let mut group_alice = CoreGroup::builder(group_id, alice_key_package_bundle)
        .build(backend)
        .unwrap();

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

    let staged_commit = group_alice
        .stage_commit(
            &create_commit_result.commit,
            &proposal_store,
            &[create_commit_result
                .key_package_bundle_option
                .expect("no kpb returned after self-update")],
            backend,
        )
        .expect("error staging commit");
    group_alice
        .merge_commit(staged_commit)
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
    .unwrap();

    // Now set up charly and try to init externally.
    // Define credential bundles
    let charly_credential_bundle = CredentialBundle::new(
        "Charly".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .unwrap();

    // Have Alice export everything that Charly needs.
    let pgs_encoded: Vec<u8> = group_alice
        .export_public_group_state(backend, &alice_credential_bundle)
        .expect("Error exporting PGS")
        .tls_serialize_detached()
        .expect("Error serializing PGS");
    let verifiable_public_group_state =
        VerifiablePublicGroupState::tls_deserialize(&mut pgs_encoded.as_slice())
            .expect("Error deserializing PGS")
            .into();
    let nodes_option = group_alice.treesync().export_nodes();

    let (_group_charly, create_commit_result) = CoreGroup::new_from_external_init(
        backend,
        framing_parameters,
        Some(&nodes_option),
        &charly_credential_bundle,
        &[], // proposals by reference
        &[], // proposals by value
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

    let staged_commit = group_bob
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_bob
        .merge_commit(staged_commit)
        .expect("error merging commit");

    // TODO: Charly cannot process their own commit yet. Before we can do that,
    // we'll have to refactor how own commits are processed.
}

#[apply(ciphersuites_and_backends)]
fn test_external_init_single_member_group(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .unwrap();

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .unwrap();

    // === Alice creates a group ===
    let group_id = GroupId::random(backend);

    let mut group_alice = CoreGroup::builder(group_id, alice_key_package_bundle)
        .build(backend)
        .unwrap();

    // Now set up charly and try to init externally.
    // Define credential bundles
    let charly_credential_bundle = CredentialBundle::new(
        "Charly".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .unwrap();

    // Have Alice export everything that Charly needs.
    let pgs_encoded: Vec<u8> = group_alice
        .export_public_group_state(backend, &alice_credential_bundle)
        .expect("Error exporting PGS")
        .tls_serialize_detached()
        .expect("Error serializing PGS");
    let verifiable_public_group_state =
        VerifiablePublicGroupState::tls_deserialize(&mut pgs_encoded.as_slice())
            .expect("Error deserializing PGS")
            .into();
    let nodes_option = group_alice.treesync().export_nodes();

    let (_charly_group, create_commit_result) = CoreGroup::new_from_external_init(
        backend,
        framing_parameters,
        Some(&nodes_option),
        &charly_credential_bundle,
        &[], // proposals by reference
        &[], // proposals by value
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
    // TODO: Charly cannot process their own commit yet. Before we can do that,
    // we'll have to refactor how own commits are processed.
}
