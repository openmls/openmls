use tls_codec::{Deserialize, Serialize};

use crate::{
    credentials::*,
    framing::*,
    group::*,
    key_packages::*,
    messages::{public_group_state::*, *},
    test_utils::*,
};

/// Tests the creation of a `PublicGroupState` and verifies it was correctly
/// signed
#[apply(ciphersuites_and_backends)]
fn test_pgs(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
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
    let mut group_alice = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Could not create group.");

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
    let create_commit_result = match group_alice.create_commit(params, backend) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    group_alice
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging commit");

    let pgs = group_alice
        .export_public_group_state(backend, &alice_credential_bundle)
        .expect("Could not export the public group state");

    // Make sure Alice is the signer
    assert_eq!(
        &pgs.signer,
        group_alice
            .key_package_ref()
            .expect("An unexpected error occurred.")
    );

    let encoded = pgs.tls_serialize_detached().expect("Could not encode");
    let verifiable_pgs = VerifiablePublicGroupState::tls_deserialize(&mut encoded.as_slice())
        .expect("Could not decode");

    let pgs_decoded: PublicGroupState = verifiable_pgs
        .verify(backend, alice_credential_bundle.credential())
        .expect("error verifiying public group state");

    assert_eq!(pgs, pgs_decoded)
}
