use crate::{ciphersuite::Ciphersuite, test_utils::*};
use tls_codec::{Deserialize, Serialize};

use crate::{
    ciphersuite::signable::Verifiable,
    config::Config,
    credentials::{CredentialBundle, CredentialType},
    group::{
        create_commit_params::CreateCommitParams,
        proposals::{ProposalStore, StagedProposal},
        GroupId, WireFormat,
    },
    key_packages::KeyPackageBundle,
    messages::{
        public_group_state::{PublicGroupState, VerifiablePublicGroupState},
        LeafIndex, MlsGroup,
    },
    prelude::FramingParameters,
};

/// Tests the creation of a `PublicGroupState` and verifies it was correctly
/// signed
#[apply(ciphersuites_and_backends)]
fn test_pgs(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    // Alice creates a group
    let mut group_alice = MlsGroup::builder(GroupId::random(backend), alice_key_package_bundle)
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

    let proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create StagedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .build();
    let (commit, _welcome_option, kpb_option) = match group_alice.create_commit(params, backend) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    let staged_commit = group_alice
        .stage_commit(
            &commit,
            &proposal_store,
            &[kpb_option.expect("No KeyPackageBundle")],
            None,
            backend,
        )
        .expect("Could not stage Commit");
    group_alice.merge_commit(staged_commit);

    let pgs = group_alice
        .export_public_group_state(backend, &alice_credential_bundle)
        .expect("Could not export the public group state");

    // Make sure Alice is the signer
    assert_eq!(pgs.signer_index, LeafIndex::from(0u32));

    let encoded = pgs.tls_serialize_detached().expect("Could not encode");
    let verifiable_pgs = VerifiablePublicGroupState::tls_deserialize(&mut encoded.as_slice())
        .expect("Could not decode");

    let pgs_decoded: PublicGroupState = verifiable_pgs
        .verify(backend, alice_credential_bundle.credential())
        .expect("error verifiying public group state");

    assert_eq!(pgs, pgs_decoded)
}
