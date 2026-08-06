use openmls_test::openmls_test;

use crate::{
    ciphersuite::{signable::Verifiable, OpenMlsSignaturePublicKey},
    credentials::NewSignerBundle,
    framing::{ProcessedMessageContent, ProtocolMessage},
    group::{
        errors::CreateCommitError,
        tests_and_kats::utils::{generate_credential_with_key, CredentialWithKeyAndSigner},
        MlsGroup, MlsGroupJoinConfig, WireFormatPolicy, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    messages::proposals::{PreSharedKeyProposal, ProposalType},
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    treesync::node::leaf_node::{
        Capabilities, LeafNodeIn, LeafNodeParameters, TreePosition, VerifiableLeafNode,
    },
};

#[openmls_test]
fn external_commit_builder() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    let CredentialWithKeyAndSigner {
        credential_with_key: alice_credential_with_key,
        signer: alice_signer,
    } = generate_credential_with_key(
        b"alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let CredentialWithKeyAndSigner {
        credential_with_key: bob_credential_with_key,
        signer: bob_signer,
    } = generate_credential_with_key(
        b"bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let CredentialWithKeyAndSigner {
        credential_with_key: charlie_credential_with_key,
        signer: charlie_signer,
    } = generate_credential_with_key(
        b"charlie".into(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );

    // Alice creates a group.

    // Make sure we support SelfRemoves
    let capabilities = Capabilities::builder()
        .proposals(vec![ProposalType::SelfRemove])
        .build();

    // Since SelfRemoves and PSK proposals need to be sent as public
    // messages if we want to use them with an external commit, we need to
    // set the wire format policy to PURE_PLAINTEXT_WIRE_FORMAT
    const POLICY: WireFormatPolicy = PURE_PLAINTEXT_WIRE_FORMAT_POLICY;

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(POLICY)
        .with_capabilities(capabilities.clone())
        .build(alice_provider, &alice_signer, alice_credential_with_key)
        .unwrap();

    alice_group
        .ensure_persistence(alice_provider.storage())
        .unwrap();

    // Bob joins the group externally.

    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    let tree_option = alice_group.export_ratchet_tree();

    // Test some basic builder functionality.
    const PADDING_SIZE: usize = 256;

    const AAD: &[u8] = b"some additional authenticated data";

    let leaf_node_parameters = LeafNodeParameters::builder()
        .with_capabilities(capabilities.clone())
        .build();

    let join_group_config = MlsGroupJoinConfig::builder()
        .padding_size(PADDING_SIZE)
        .wire_format_policy(POLICY)
        .build();

    let (mut bob_group, commit_message_bundle) = MlsGroup::external_commit_builder()
        .with_ratchet_tree(tree_option.into())
        .with_config(join_group_config.clone())
        .with_aad(AAD.to_vec())
        .build_group(
            bob_provider,
            verifiable_group_info,
            bob_credential_with_key.clone(),
        )
        .unwrap()
        .leaf_node_parameters(leaf_node_parameters)
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_signer,
            |_| true,
        )
        .unwrap()
        .finalize(bob_provider)
        .unwrap();

    bob_group
        .ensure_persistence(bob_provider.storage())
        .unwrap();

    // Check that the padding was set correctly.
    assert_eq!(bob_group.configuration().padding_size(), PADDING_SIZE);

    let plaintext = commit_message_bundle
        .into_commit()
        .into_protocol_message()
        .unwrap();

    alice_group.set_aad(AAD.to_vec());
    let processed_message = alice_group
        .process_message(alice_provider, plaintext)
        .unwrap();

    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    else {
        panic!("Expected a staged commit message.");
    };
    alice_group
        .merge_staged_commit(alice_provider, *staged_commit)
        .unwrap();

    // Alice issues a self-remove proposal.
    let msg_out = alice_group
        .leave_group_via_self_remove(alice_provider, &alice_signer)
        .unwrap();

    let ProtocolMessage::PublicMessage(self_remove_proposal) =
        msg_out.into_protocol_message().unwrap()
    else {
        panic!("Expected a public message for the self-remove proposal.");
    };

    // Bob processes the self-remove proposal.
    let bob_processed_message = bob_group
        .process_message(bob_provider, *self_remove_proposal.clone())
        .unwrap();

    let ProcessedMessageContent::ProposalMessage(proposal) = bob_processed_message.into_content()
    else {
        panic!("Expected a proposal message.");
    };

    bob_group
        .store_pending_proposal(bob_provider.storage(), *proposal)
        .unwrap();

    let verifiable_group_info = bob_group
        .export_group_info(bob_provider.crypto(), &bob_signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    // Charlie joins the group externally and sends a PSK proposal as part of the commit.
    let psk_id_bytes = vec![0, 1, 2, 3];
    let psk_id = Psk::External(ExternalPsk::new(psk_id_bytes.clone()));
    let psk = PreSharedKeyId::new(ciphersuite, charlie_provider.rand(), psk_id).unwrap();
    let psk_value = vec![4, 5, 6, 7];
    psk.store(bob_provider, &psk_value).unwrap();
    psk.store(charlie_provider, &psk_value).unwrap();

    let (charlie_group, commit_message_bundle) = MlsGroup::external_commit_builder()
        .with_proposals(vec![*self_remove_proposal])
        .with_ratchet_tree(bob_group.export_ratchet_tree().into())
        .build_group(
            charlie_provider,
            verifiable_group_info,
            charlie_credential_with_key.clone(),
        )
        .unwrap()
        .add_psk_proposal(PreSharedKeyProposal::new(psk))
        .load_psks(charlie_provider.storage())
        .unwrap()
        .build(
            charlie_provider.rand(),
            charlie_provider.crypto(),
            &charlie_signer,
            |_| true,
        )
        .unwrap()
        .finalize(charlie_provider)
        .unwrap();

    // Bob processes Charlie's Commit.
    let plaintext = commit_message_bundle
        .into_commit()
        .into_protocol_message()
        .unwrap();

    let bob_processed_message = bob_group.process_message(bob_provider, plaintext).unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    else {
        panic!("Expected a staged commit message.");
    };
    bob_group
        .merge_staged_commit(bob_provider, *staged_commit)
        .unwrap();

    // Check that only Bob and Charlie are in the group.
    let members = bob_group.members().collect::<Vec<_>>();
    assert_eq!(members, charlie_group.members().collect::<Vec<_>>());
    assert_eq!(members.len(), 2);
    assert!(members
        .iter()
        .any(|m| m.credential == bob_credential_with_key.credential));
    assert!(members
        .iter()
        .any(|m| m.credential == charlie_credential_with_key.credential));
}

// An external commit with a consistent credential, signature key and signer
// succeeds, even when the leaf node parameters repeat the credential passed to
// the external commit builder. The generated leaf carries that credential and
// its signature verifies with the signature key stored in the leaf itself.
#[openmls_test]
fn external_commit_consistent_credential() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let CredentialWithKeyAndSigner {
        credential_with_key: alice_credential_with_key,
        signer: alice_signer,
    } = generate_credential_with_key(
        b"alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let CredentialWithKeyAndSigner {
        credential_with_key: bob_credential_with_key,
        signer: bob_signer,
    } = generate_credential_with_key(
        b"bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    // Alice's group accepts plaintext messages so she can process the
    // external commit.
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(alice_provider, &alice_signer, alice_credential_with_key)
        .unwrap();

    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    // Repeating the builder credential in the leaf node parameters is allowed.
    let leaf_node_parameters = LeafNodeParameters::builder()
        .with_credential_with_key(bob_credential_with_key.clone())
        .build();

    let (bob_group, commit_message_bundle) = MlsGroup::external_commit_builder()
        .with_ratchet_tree(alice_group.export_ratchet_tree().into())
        .build_group(
            bob_provider,
            verifiable_group_info,
            bob_credential_with_key.clone(),
        )
        .unwrap()
        .leaf_node_parameters(leaf_node_parameters)
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_signer,
            |_| true,
        )
        .unwrap()
        .finalize(bob_provider)
        .unwrap();

    // Alice can process the external commit.
    let plaintext = commit_message_bundle
        .into_commit()
        .into_protocol_message()
        .unwrap();
    let processed_message = alice_group
        .process_message(alice_provider, plaintext)
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    else {
        panic!("Expected a staged commit message.");
    };
    alice_group
        .merge_staged_commit(alice_provider, *staged_commit)
        .unwrap();

    // The generated leaf carries the credential and signature key passed to
    // the external commit builder.
    let bob_leaf = bob_group.own_leaf_node().unwrap().clone();
    assert_eq!(bob_leaf.credential(), &bob_credential_with_key.credential);
    assert_eq!(
        bob_leaf.signature_key(),
        &bob_credential_with_key.signature_key
    );

    // The leaf's signature verifies with the signature key stored in the leaf
    // itself.
    let leaf_node_in = LeafNodeIn::from(bob_leaf);
    let VerifiableLeafNode::Commit(mut verifiable_leaf) = leaf_node_in.into_verifiable_leaf_node()
    else {
        panic!("Expected a leaf node with source Commit.");
    };
    verifiable_leaf.add_tree_position(TreePosition::new(
        bob_group.group_id().clone(),
        bob_group.own_leaf_index(),
    ));
    let signature_key = OpenMlsSignaturePublicKey::from_signature_key(
        verifiable_leaf.signature_key().clone(),
        ciphersuite.signature_algorithm(),
    );
    verifiable_leaf
        .verify(bob_provider.crypto(), &signature_key)
        .expect("Leaf signature does not verify with the leaf's own signature key.");
}

// Leaf node parameters that pin a credential other than the one passed to the
// external commit builder are rejected before a commit is built.
#[openmls_test]
fn external_commit_rejects_divergent_credential() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let CredentialWithKeyAndSigner {
        credential_with_key: alice_credential_with_key,
        signer: alice_signer,
    } = generate_credential_with_key(
        b"alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let CredentialWithKeyAndSigner {
        credential_with_key: bob_credential_with_key,
        signer: bob_signer,
    } = generate_credential_with_key(
        b"bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    // A second credential and signature key, unrelated to the one passed to
    // the external commit builder.
    let CredentialWithKeyAndSigner {
        credential_with_key: other_credential_with_key,
        signer: _other_signer,
    } = generate_credential_with_key(
        b"bob-other".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential_with_key)
        .unwrap();

    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    let divergent_leaf_node_parameters = LeafNodeParameters::builder()
        .with_credential_with_key(other_credential_with_key)
        .build();

    let err = MlsGroup::external_commit_builder()
        .with_ratchet_tree(alice_group.export_ratchet_tree().into())
        .build_group(bob_provider, verifiable_group_info, bob_credential_with_key)
        .unwrap()
        .leaf_node_parameters(divergent_leaf_node_parameters)
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_signer,
            |_| true,
        )
        .unwrap_err();

    assert_eq!(err, CreateCommitError::ExternalCommitCredentialMismatch);
}

// An external committer has no old signature key to rotate, so
// `build_with_new_signer` is rejected on external commits.
#[openmls_test]
fn external_commit_rejects_new_signer() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let CredentialWithKeyAndSigner {
        credential_with_key: alice_credential_with_key,
        signer: alice_signer,
    } = generate_credential_with_key(
        b"alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let CredentialWithKeyAndSigner {
        credential_with_key: bob_credential_with_key,
        signer: bob_signer,
    } = generate_credential_with_key(
        b"bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let CredentialWithKeyAndSigner {
        credential_with_key: new_credential_with_key,
        signer: new_signer,
    } = generate_credential_with_key(
        b"bob-new".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential_with_key)
        .unwrap();

    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    let new_signer_bundle = NewSignerBundle {
        signer: &new_signer,
        credential_with_key: new_credential_with_key,
    };

    let err = MlsGroup::external_commit_builder()
        .with_ratchet_tree(alice_group.export_ratchet_tree().into())
        .build_group(bob_provider, verifiable_group_info, bob_credential_with_key)
        .unwrap()
        .load_psks(bob_provider.storage())
        .unwrap()
        .build_with_new_signer(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_signer,
            new_signer_bundle,
            |_| true,
        )
        .unwrap_err();

    assert_eq!(err, CreateCommitError::ExternalCommitWithNewSigner);
}
