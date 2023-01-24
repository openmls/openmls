use crate::{
    framing::{FramingParameters, WireFormat},
    group::{
        errors::ExternalCommitError,
        test_core_group::{setup_alice_group, setup_client},
    },
    messages::proposals::{ProposalOrRef, ProposalType},
    prelude_test::test_framing::setup_alice_bob_group,
    test_utils::*,
};

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};

use super::{create_commit_params::CreateCommitParams, proposals::ProposalStore, CoreGroup};

#[apply(ciphersuites_and_backends)]
fn test_external_init(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (
        framing_parameters,
        mut group_alice,
        alice_signer,
        mut group_bob,
        bob_signer,
        bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, backend);

    // Now set up Charlie and try to init externally.
    let (charlie_credential, charlie_kpb, charlie_signer, charlie_pk) =
        setup_client("Charlie", ciphersuite, backend);

    // Have Alice export everything that Charly needs.
    let verifiable_group_info = group_alice
        .export_group_info(backend, &alice_signer, true)
        .unwrap()
        .into_verifiable_group_info();

    let proposal_store = ProposalStore::new();
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .credential_with_key(charlie_credential)
        .build();
    let (mut group_charly, create_commit_result) = CoreGroup::join_by_external_commit(
        backend,
        &charlie_signer,
        params,
        None,
        verifiable_group_info,
    )
    .expect("Error initializing group externally.");

    // Have alice and bob process the commit resulting from external init.
    let proposal_store = ProposalStore::default();
    let staged_commit = group_alice
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_alice
        .merge_commit(backend, staged_commit)
        .expect("error merging commit");

    let staged_commit = group_bob
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_bob
        .merge_commit(backend, staged_commit)
        .expect("error merging commit");

    // Have charly process their own staged commit
    group_charly
        .merge_commit(backend, create_commit_result.staged_commit)
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
        .proposal_store(&proposal_store)
        .build();
    let create_commit_result = group_charly
        .create_commit(params, backend, &charlie_signer)
        .expect("Error creating commit");

    let staged_commit = group_alice
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_alice
        .merge_commit(backend, staged_commit)
        .expect("error merging commit");

    group_charly
        .merge_commit(backend, create_commit_result.staged_commit)
        .expect("error merging commit");

    // Now we assume that Bob somehow lost his group state and wants to add
    // themselves back through an external commit.

    // Have Alice export everything that Bob needs.
    let verifiable_group_info = group_alice
        .export_group_info(backend, &alice_signer, false)
        .unwrap()
        .into_verifiable_group_info();
    let nodes_option = group_alice.treesync().export_nodes();

    let proposal_store = ProposalStore::new();
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .credential_with_key(bob_credential_with_key)
        .build();
    let (mut new_group_bob, create_commit_result) = CoreGroup::join_by_external_commit(
        backend,
        &bob_signer,
        params,
        Some(&nodes_option),
        verifiable_group_info,
    )
    .expect("Error initializing group externally.");

    // Let's make sure there's a remove in the commit.
    let contains_remove = match create_commit_result.commit.content() {
        crate::prelude_test::mls_content::FramedContentBody::Commit(commit) => commit
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
        .merge_commit(backend, staged_commit)
        .expect("error merging commit");

    let staged_commit = group_charly
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_charly
        .merge_commit(backend, staged_commit)
        .expect("error merging commit");

    // Have Bob process his own staged commit
    new_group_bob
        .merge_commit(backend, create_commit_result.staged_commit)
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
    let (mut group_alice, alice_credential_with_key, alice_signer, alice_pk) =
        setup_alice_group(ciphersuite, backend);

    // Framing parameters
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    // Now set up charly and try to init externally.
    let (charly_credential, charly_kpb, charly_signer, charly_pk) =
        setup_client("Charly", ciphersuite, backend);

    // Have Alice export everything that Charly needs.
    let verifiable_group_info = group_alice
        .export_group_info(backend, &alice_signer, false)
        .unwrap()
        .into_verifiable_group_info();
    let nodes_option = group_alice.treesync().export_nodes();

    let proposal_store = ProposalStore::new();
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .credential_with_key(charly_credential)
        .build();
    let (mut group_charly, create_commit_result) = CoreGroup::join_by_external_commit(
        backend,
        &charly_signer,
        params,
        Some(&nodes_option),
        verifiable_group_info,
    )
    .expect("Error initializing group externally.");

    // Have alice and bob process the commit resulting from external init.
    let proposal_store = ProposalStore::default();
    let staged_commit = group_alice
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    group_alice
        .merge_commit(backend, staged_commit)
        .expect("error merging commit");

    group_charly
        .merge_commit(backend, create_commit_result.staged_commit)
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

#[apply(ciphersuites_and_backends)]
fn test_external_init_broken_signature(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let (
        framing_parameters,
        group_alice,
        alice_signer,
        group_bob,
        bob_signer,
        bob_credential_with_key,
    ) = setup_alice_bob_group(ciphersuite, backend);

    // Now set up charly and try to init externally.
    let (charlie_credential, charlie_kpb, charlie_signer, charlie_pk) =
        setup_client("Charlie", ciphersuite, backend);

    let verifiable_group_info = {
        let mut verifiable_group_info = group_alice
            .export_group_info(backend, &alice_signer, true)
            .unwrap()
            .into_verifiable_group_info();
        verifiable_group_info.break_signature();
        verifiable_group_info
    };

    let proposal_store = ProposalStore::new();
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .build();
    assert_eq!(
        ExternalCommitError::InvalidGroupInfoSignature,
        CoreGroup::join_by_external_commit(
            backend,
            &charlie_signer,
            params,
            None,
            verifiable_group_info
        )
        .expect_err("Signature was corrupted. This should have failed.")
    );
}
