use crate::group::{GroupId, WireFormat};
use crate::{
    ciphersuite::Ciphersuite,
    config::Config,
    credentials::{CredentialBundle, CredentialType},
    messages::public_group_state::VerifiablePublicGroupState,
    prelude::{FramingParameters, KeyPackageBundle},
    test_utils::*,
};

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Deserialize, Serialize};

use super::{
    create_commit_params::CreateCommitParams,
    proposals::{ProposalStore, StagedProposal},
    MlsGroup,
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

    let mut group_alice = MlsGroup::builder(group_id, alice_key_package_bundle)
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
    let proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create StagedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .build();
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = group_alice
        .create_commit(params, backend)
        .expect("Error creating commit");

    let staged_commit = group_alice
        .stage_commit(
            &mls_plaintext_commit,
            &proposal_store,
            &[kpb_option.unwrap()],
            None,
            backend,
        )
        .expect("error staging commit");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");
    let ratchet_tree = group_alice.treesync().export_nodes();

    let mut group_bob = MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        Some(ratchet_tree),
        bob_key_package_bundle,
        None,
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

    let (_group_charly, ext_init_commit, _option_welcome, _option_kpb) =
        MlsGroup::new_from_external_init(
            framing_parameters,
            Some(&nodes_option),
            &charly_credential_bundle,
            &[], // proposals by reference
            &[], // proposals by value
            verifiable_public_group_state,
            backend,
        )
        .expect("Error initializing group externally.");

    // Have alice and bob process the commit resulting from external init.
    let proposal_store = ProposalStore::default();
    let staged_commit = group_alice
        .stage_commit(&ext_init_commit, &proposal_store, &[], None, backend)
        .expect("error staging commit");
    group_alice
        .merge_commit(staged_commit)
        .expect("error merging commit");

    let staged_commit = group_bob
        .stage_commit(&ext_init_commit, &proposal_store, &[], None, backend)
        .expect("error staging commit");
    group_bob
        .merge_commit(staged_commit)
        .expect("error merging commit");

    // TODO: Charly cannot process their own commit yet. Before we can do that,
    // we'll have to refactor how own commits are processed.
}
