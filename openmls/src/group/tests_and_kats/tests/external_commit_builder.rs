use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use openmls_traits::types::Ciphersuite;

use crate::{
    ciphersuite::{signable::Verifiable, OpenMlsSignaturePublicKey},
    credentials::{CredentialWithKey, NewSignerBundle},
    extensions::Extensions,
    framing::{
        MessageDecryptionError, MlsMessageIn, ProcessedMessageContent, ProtocolMessage,
        SecretTreeError,
    },
    group::{
        errors::CreateCommitError,
        tests_and_kats::utils::{
            generate_credential_with_key, generate_key_package, CredentialWithKeyAndSigner,
        },
        CommitMessageBundle, ExternalCommitBuilderError, MlsGroup, MlsGroupJoinConfig,
        PastEpochDeletionPolicy, ProcessMessageError, StagedWelcome, ValidationError,
        WireFormatPolicy, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    messages::{
        group_info::VerifiableGroupInfo,
        proposals::{PreSharedKeyProposal, ProposalType},
    },
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    storage::OpenMlsProvider,
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

#[openmls_test]
fn external_commit_after_self_remove() {
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

    let capabilities = Capabilities::builder()
        .proposals(vec![ProposalType::SelfRemove])
        .build();

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .with_capabilities(capabilities.clone())
        .build(
            alice_provider,
            &alice_signer,
            alice_credential_with_key.clone(),
        )
        .unwrap();

    let join_group_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let leaf_node_parameters = LeafNodeParameters::builder()
        .with_capabilities(capabilities)
        .build();

    // Bob joins the group externally.
    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    let (mut bob_group, commit_message_bundle) = MlsGroup::external_commit_builder()
        .with_config(join_group_config.clone())
        .build_group(
            bob_provider,
            verifiable_group_info,
            bob_credential_with_key.clone(),
        )
        .unwrap()
        .leaf_node_parameters(leaf_node_parameters.clone())
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

    let processed_message = alice_group
        .process_message(
            alice_provider,
            commit_message_bundle
                .into_commit()
                .into_protocol_message()
                .unwrap(),
        )
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    else {
        panic!("Expected a staged commit message.");
    };
    alice_group
        .merge_staged_commit(alice_provider, *staged_commit)
        .unwrap();

    // Bob leaves through a SelfRemove proposal, which Alice stores.
    let msg_out = bob_group
        .leave_group_via_self_remove(bob_provider, &bob_signer)
        .unwrap();
    let ProtocolMessage::PublicMessage(self_remove_proposal) =
        msg_out.into_protocol_message().unwrap()
    else {
        panic!("Expected a public message for the self-remove proposal.");
    };

    let processed_message = alice_group
        .process_message(alice_provider, *self_remove_proposal.clone())
        .unwrap();
    let ProcessedMessageContent::ProposalMessage(proposal) = processed_message.into_content()
    else {
        panic!("Expected a proposal message.");
    };
    alice_group
        .store_pending_proposal(alice_provider.storage(), *proposal)
        .unwrap();

    // Bob rejoins with the same credential, referencing his SelfRemove.
    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    let (bob_group, commit_message_bundle) = MlsGroup::external_commit_builder()
        .with_proposals(vec![*self_remove_proposal])
        .with_config(join_group_config)
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

    let processed_message = alice_group
        .process_message(
            alice_provider,
            commit_message_bundle
                .into_commit()
                .into_protocol_message()
                .unwrap(),
        )
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    else {
        panic!("Expected a staged commit message.");
    };
    alice_group
        .merge_staged_commit(alice_provider, *staged_commit)
        .unwrap();

    // Alice and Bob are the only members and Bob's signature key is in the
    // tree exactly once.
    let members = alice_group.members().collect::<Vec<_>>();
    assert_eq!(members, bob_group.members().collect::<Vec<_>>());
    assert_eq!(members.len(), 2);
    assert!(members
        .iter()
        .any(|m| m.credential == alice_credential_with_key.credential));
    assert!(members
        .iter()
        .any(|m| m.credential == bob_credential_with_key.credential));
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

// --- Helpers for the retain_past_epochs_from tests below. ---

/// Sets up the two-member group the retain-past-epochs tests start from:
/// Alice creates a group that accepts plaintext handshake messages and adds
/// Bob, who joins with `bob_join_config`. The group ends up in epoch 1.
fn alice_adds_bob<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    alice_provider: &Provider,
    bob_provider: &Provider,
    bob_join_config: &MlsGroupJoinConfig,
) -> (
    MlsGroup,
    MlsGroup,
    CredentialWithKeyAndSigner,
    CredentialWithKeyAndSigner,
) {
    let alice_credential_with_keys = generate_credential_with_key(
        b"alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let bob_credential_with_keys = generate_credential_with_key(
        b"bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(
            alice_provider,
            &alice_credential_with_keys.signer,
            alice_credential_with_keys.credential_with_key.clone(),
        )
        .unwrap();

    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        bob_provider,
        bob_credential_with_keys.clone(),
    );

    let (_message, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_credential_with_keys.signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        bob_join_config,
        welcome.into_welcome().unwrap(),
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(bob_provider)
    .unwrap();

    (
        alice_group,
        bob_group,
        alice_credential_with_keys,
        bob_credential_with_keys,
    )
}

/// Advances the group by one epoch with an empty self update, merged
/// immediately, and returns the commit for other members to process.
fn self_update_and_merge<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
) -> ProtocolMessage {
    let (commit, _welcome, _group_info) = group
        .self_update(provider, signer, LeafNodeParameters::default())
        .unwrap()
        .into_contents();
    group.merge_pending_commit(provider).unwrap();
    commit.into_protocol_message().unwrap()
}

/// Seals an application message without processing it anywhere.
fn seal_message<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
    payload: &[u8],
) -> ProtocolMessage {
    group
        .create_message(provider, signer, payload)
        .unwrap()
        .into_protocol_message()
        .unwrap()
}

/// Exports the group's `GroupInfo` with the ratchet tree included.
fn export_group_info<Provider: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
) -> VerifiableGroupInfo {
    group
        .export_group_info(provider.crypto(), signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap()
}

/// Builds and finalizes an external commit that rejoins `past_group`'s
/// member into the group described by `verifiable_group_info`, carrying the
/// past epoch secrets over.
fn rejoin_with_past_epochs<Provider: OpenMlsProvider>(
    provider: &Provider,
    past_group: MlsGroup,
    verifiable_group_info: VerifiableGroupInfo,
    join_config: MlsGroupJoinConfig,
    credential_with_key: CredentialWithKey,
    signer: &SignatureKeyPair,
) -> (MlsGroup, CommitMessageBundle) {
    MlsGroup::external_commit_builder()
        .with_config(join_config)
        .retain_past_epochs_from(past_group)
        .build_group(provider, verifiable_group_info, credential_with_key)
        .unwrap()
        .load_psks(provider.storage())
        .unwrap()
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .unwrap()
        .finalize(provider)
        .unwrap()
}

/// Processes `commit` and merges the staged commit it contains.
fn process_and_merge_commit<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    commit: ProtocolMessage,
) {
    let processed_message = group.process_message(provider, commit).unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    else {
        panic!("Expected a staged commit message.");
    };
    group.merge_staged_commit(provider, *staged_commit).unwrap();
}

/// Processes `message` and asserts that it decrypts to `expected`.
fn expect_application_message<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    message: ProtocolMessage,
    expected: &[u8],
) {
    let processed_message = group.process_message(provider, message).unwrap();
    let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    else {
        panic!("Expected an application message.");
    };
    assert_eq!(application_message.into_bytes(), expected);
}

/// Processes `message` and asserts that decryption fails with `expected`.
fn expect_decryption_error<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    message: ProtocolMessage,
    expected: MessageDecryptionError,
) {
    let err = group.process_message(provider, message).unwrap_err();
    let ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(decryption_error)) =
        err
    else {
        panic!("Expected a decryption error, got {err:?}");
    };
    assert_eq!(decryption_error, expected);
}

// A member that rejoins its group via external commit with
// `retain_past_epochs_from` keeps decrypting application messages from the
// epochs it participated in, bounded by the rejoin config's past epoch
// deletion policy measured against the epoch the rejoin creates.
#[openmls_test]
fn external_commit_retains_past_epochs() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    // Bob joins with a config that retains up to 4 past epochs.
    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(4)
        .build();
    let (mut alice_group, mut bob_group, alice_credential_with_keys, bob_credential_with_keys) =
        alice_adds_bob(ciphersuite, alice_provider, bob_provider, &join_config);
    let alice_signer = &alice_credential_with_keys.signer;
    let bob_signer = &bob_credential_with_keys.signer;
    let group_id = alice_group.group_id().clone();

    // The group is in epoch 1. Alice seals one application message per
    // epoch, which Bob does not process yet, and advances the epoch with a
    // self update, which Bob does process.
    let mut held_messages = Vec::new();
    for payload_epoch in 1u8..=3 {
        held_messages.push(seal_message(
            &mut alice_group,
            alice_provider,
            alice_signer,
            &[payload_epoch],
        ));
        let commit = self_update_and_merge(&mut alice_group, alice_provider, alice_signer);
        process_and_merge_commit(&mut bob_group, bob_provider, commit);
    }

    // The group is now in epoch 4. Bob sends a message that the delivery
    // service will echo back to him after the rejoin.
    let bob_echo = seal_message(&mut bob_group, bob_provider, bob_signer, b"bob echo");
    expect_application_message(
        &mut alice_group,
        alice_provider,
        bob_echo.clone(),
        b"bob echo",
    );

    // Alice seals one more message in epoch 4, advances to epoch 5 and
    // seals a message there, without Bob processing any of it — Bob's state
    // falls one epoch behind the group.
    held_messages.push(seal_message(
        &mut alice_group,
        alice_provider,
        alice_signer,
        &[4u8],
    ));
    self_update_and_merge(&mut alice_group, alice_provider, alice_signer);
    let epoch_5_message = seal_message(&mut alice_group, alice_provider, alice_signer, &[5u8]);

    // Bob rejoins the group in epoch 5 via an external commit, carrying his
    // past epoch secrets over. The rejoin config retains up to 3 past
    // epochs, measured against epoch 6, which the external commit creates:
    // epochs 3 and 4 stay decryptable, epochs 1 and 2 do not.
    let verifiable_group_info = export_group_info(&alice_group, alice_provider, alice_signer);
    let rejoin_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(3)
        .build();
    let (_, commit_message_bundle) = rejoin_with_past_epochs(
        bob_provider,
        bob_group,
        verifiable_group_info,
        rejoin_config,
        bob_credential_with_keys.credential_with_key.clone(),
        bob_signer,
    );
    process_and_merge_commit(
        &mut alice_group,
        alice_provider,
        commit_message_bundle
            .into_commit()
            .into_protocol_message()
            .unwrap(),
    );

    // The carried-over secrets are persisted: reload Bob's group from
    // storage before exercising them.
    let mut bob_group = MlsGroup::load(bob_provider.storage(), &group_id)
        .expect("error re-loading bob's group")
        .expect("no such group");

    // The messages from epochs 1 and 2 fall outside the rejoin config's
    // retention window and fail like any message from an epoch that aged
    // out.
    for held_message in held_messages.drain(..2) {
        expect_decryption_error(
            &mut bob_group,
            bob_provider,
            held_message,
            MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
        );
    }

    // The messages from epochs 3 and 4 decrypt across the rejoin. The epoch
    // 4 secrets were the current message secrets of Bob's previous state.
    for (payload_epoch, held_message) in (3u8..=4).zip(held_messages.drain(..)) {
        expect_application_message(&mut bob_group, bob_provider, held_message, &[payload_epoch]);
    }

    // Epoch 5 is one Bob never reached: its secrets are the placeholder the
    // merge pushed (#767), so a message sealed there fails with an AEAD
    // error rather than `TooDistantInThePast`.
    expect_decryption_error(
        &mut bob_group,
        bob_provider,
        epoch_5_message,
        MessageDecryptionError::AeadError,
    );

    // Bob's own pre-rejoin message, echoed back by the delivery service, is
    // recognised as his own rather than failing to decrypt.
    let bob_processed_message = bob_group.process_message(bob_provider, bob_echo).unwrap();
    assert!(matches!(
        bob_processed_message.into_content(),
        ProcessedMessageContent::OwnPrivateMessage
    ));

    // The rejoined group is fully operational in both directions.
    let alice_message = seal_message(&mut alice_group, alice_provider, alice_signer, b"hello bob");
    expect_application_message(&mut bob_group, bob_provider, alice_message, b"hello bob");
    let bob_message = seal_message(&mut bob_group, bob_provider, bob_signer, b"hello alice");
    expect_application_message(
        &mut alice_group,
        alice_provider,
        bob_message,
        b"hello alice",
    );
}

// If the rejoining member missed more epochs than the rejoin config's past
// epoch deletion policy retains, no valid past epochs are left at the time
// of the rejoin and nothing is carried over.
#[openmls_test]
fn external_commit_rejoin_beyond_retention_window() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(3)
        .build();
    let (mut alice_group, bob_group, alice_credential_with_keys, bob_credential_with_keys) =
        alice_adds_bob(ciphersuite, alice_provider, bob_provider, &join_config);
    let alice_signer = &alice_credential_with_keys.signer;

    // Alice seals a message in epoch 1 that Bob does not process, then
    // advances the group to epoch 5 without Bob processing any of the
    // commits.
    let held_message = seal_message(
        &mut alice_group,
        alice_provider,
        alice_signer,
        b"left behind",
    );
    for _ in 0..4 {
        self_update_and_merge(&mut alice_group, alice_provider, alice_signer);
    }

    // Bob rejoins in epoch 5. The external commit creates epoch 6; with a
    // retention window of 3 past epochs, Bob's epoch 1 secrets fall outside
    // the window and are not carried over.
    let verifiable_group_info = export_group_info(&alice_group, alice_provider, alice_signer);
    let (mut bob_group, commit_message_bundle) = rejoin_with_past_epochs(
        bob_provider,
        bob_group,
        verifiable_group_info,
        join_config,
        bob_credential_with_keys.credential_with_key.clone(),
        &bob_credential_with_keys.signer,
    );
    process_and_merge_commit(
        &mut alice_group,
        alice_provider,
        commit_message_bundle
            .into_commit()
            .into_protocol_message()
            .unwrap(),
    );

    expect_decryption_error(
        &mut bob_group,
        bob_provider,
        held_message,
        MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
    );

    // The rejoined group is operational regardless.
    let alice_message = seal_message(&mut alice_group, alice_provider, alice_signer, b"hello bob");
    expect_application_message(&mut bob_group, bob_provider, alice_message, b"hello bob");
}

// With the `KeepAll` past epoch deletion policy on the rejoin config, all of
// the rejoining member's past epoch secrets are carried over, no matter how
// many epochs it missed.
#[openmls_test]
fn external_commit_rejoin_keep_all_past_epochs() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(3)
        .build();
    let (mut alice_group, bob_group, alice_credential_with_keys, bob_credential_with_keys) =
        alice_adds_bob(ciphersuite, alice_provider, bob_provider, &join_config);
    let alice_signer = &alice_credential_with_keys.signer;

    // As in `external_commit_rejoin_beyond_retention_window`, Bob misses
    // more epochs than a bounded policy would retain.
    let held_message = seal_message(
        &mut alice_group,
        alice_provider,
        alice_signer,
        b"kept forever",
    );
    for _ in 0..4 {
        self_update_and_merge(&mut alice_group, alice_provider, alice_signer);
    }

    let verifiable_group_info = export_group_info(&alice_group, alice_provider, alice_signer);
    let rejoin_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::KeepAll)
        .build();
    let (mut bob_group, commit_message_bundle) = rejoin_with_past_epochs(
        bob_provider,
        bob_group,
        verifiable_group_info,
        rejoin_config,
        bob_credential_with_keys.credential_with_key.clone(),
        &bob_credential_with_keys.signer,
    );
    process_and_merge_commit(
        &mut alice_group,
        alice_provider,
        commit_message_bundle
            .into_commit()
            .into_protocol_message()
            .unwrap(),
    );

    expect_application_message(&mut bob_group, bob_provider, held_message, b"kept forever");
}

// A member whose state is exactly at the epoch of the `GroupInfo` rejoins
// without missing any epochs. Its current message secrets replace the
// placeholder secrets of the pre-join epoch, so messages sealed in that
// epoch remain decryptable after the rejoin.
#[openmls_test]
fn external_commit_retains_current_epoch_secrets() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(1)
        .build();
    let (mut alice_group, bob_group, alice_credential_with_keys, bob_credential_with_keys) =
        alice_adds_bob(ciphersuite, alice_provider, bob_provider, &join_config);
    let alice_signer = &alice_credential_with_keys.signer;

    // Alice seals a message in epoch 1 that Bob has not processed at the
    // time of the rejoin.
    let held_message = seal_message(
        &mut alice_group,
        alice_provider,
        alice_signer,
        b"sealed in epoch 1",
    );

    // Bob rejoins from a state that is fully caught up with the group.
    let verifiable_group_info = export_group_info(&alice_group, alice_provider, alice_signer);
    let (mut bob_group, commit_message_bundle) = rejoin_with_past_epochs(
        bob_provider,
        bob_group,
        verifiable_group_info,
        join_config,
        bob_credential_with_keys.credential_with_key.clone(),
        &bob_credential_with_keys.signer,
    );
    process_and_merge_commit(
        &mut alice_group,
        alice_provider,
        commit_message_bundle
            .into_commit()
            .into_protocol_message()
            .unwrap(),
    );

    // Without `retain_past_epochs_from`, the pre-join epoch's secrets are
    // placeholders that cannot decrypt anything (#767), and this message
    // would be lost to the rejoin.
    expect_application_message(
        &mut bob_group,
        bob_provider,
        held_message,
        b"sealed in epoch 1",
    );
}

// Under the default past epoch deletion policy — `MaxEpochs(0)` — nothing
// is retained, so nothing is carried over either: the rejoin behaves like
// one without `retain_past_epochs_from`.
#[openmls_test]
fn external_commit_retain_past_epochs_default_policy() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(1)
        .build();
    let (mut alice_group, bob_group, alice_credential_with_keys, bob_credential_with_keys) =
        alice_adds_bob(ciphersuite, alice_provider, bob_provider, &join_config);
    let alice_signer = &alice_credential_with_keys.signer;

    let held_message = seal_message(
        &mut alice_group,
        alice_provider,
        alice_signer,
        b"sealed in epoch 1",
    );

    // Bob rejoins from a fully caught up state, but with the default
    // policy: even the current epoch's secrets are discarded at the merge.
    let verifiable_group_info = export_group_info(&alice_group, alice_provider, alice_signer);
    let rejoin_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let (mut bob_group, commit_message_bundle) = rejoin_with_past_epochs(
        bob_provider,
        bob_group,
        verifiable_group_info,
        rejoin_config,
        bob_credential_with_keys.credential_with_key.clone(),
        &bob_credential_with_keys.signer,
    );
    process_and_merge_commit(
        &mut alice_group,
        alice_provider,
        commit_message_bundle
            .into_commit()
            .into_protocol_message()
            .unwrap(),
    );

    expect_decryption_error(
        &mut bob_group,
        bob_provider,
        held_message,
        MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
    );

    // The rejoined group is operational regardless.
    let alice_message = seal_message(&mut alice_group, alice_provider, alice_signer, b"hello bob");
    expect_application_message(&mut bob_group, bob_provider, alice_message, b"hello bob");
}

// A member that rejoins against a stale `GroupInfo` — one describing an
// epoch its own state had already moved past — keeps its retained secrets
// for the pre-rejoin epoch and everything before it, and drops everything
// newer. The retained tree for the pre-rejoin epoch takes the place of the
// placeholder secrets, so no duplicate entry for that epoch exists.
#[openmls_test]
fn external_commit_rejoin_from_state_ahead_of_group_info() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(2)
        .build();
    let (mut alice_group, mut bob_group, alice_credential_with_keys, bob_credential_with_keys) =
        alice_adds_bob(ciphersuite, alice_provider, bob_provider, &join_config);
    let alice_signer = &alice_credential_with_keys.signer;

    // The `GroupInfo` is exported in epoch 1 and goes stale below.
    let stale_group_info = export_group_info(&alice_group, alice_provider, alice_signer);

    // Alice seals a message in epoch 1 and one in epoch 2, which Bob does
    // not process; the commits in between he does, so his state reaches
    // epoch 3.
    let epoch_1_message = seal_message(&mut alice_group, alice_provider, alice_signer, &[1u8]);
    let commit = self_update_and_merge(&mut alice_group, alice_provider, alice_signer);
    process_and_merge_commit(&mut bob_group, bob_provider, commit);
    let epoch_2_message = seal_message(&mut alice_group, alice_provider, alice_signer, &[2u8]);
    let commit = self_update_and_merge(&mut alice_group, alice_provider, alice_signer);
    process_and_merge_commit(&mut bob_group, bob_provider, commit);

    // Bob rejoins against the stale epoch 1 `GroupInfo`, from his epoch 3
    // state. The external commit creates an epoch 2 that diverges from the
    // group Alice is in; this test only checks Bob's side.
    let rejoin_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(1)
        .build();
    let (mut bob_group, _commit_message_bundle) = rejoin_with_past_epochs(
        bob_provider,
        bob_group,
        stale_group_info,
        rejoin_config,
        bob_credential_with_keys.credential_with_key.clone(),
        &bob_credential_with_keys.signer,
    );

    // Exactly one entry for epoch 1 is retained — the real one, not the
    // placeholder, and not both.
    assert_eq!(bob_group.message_secrets_store().num_past_epoch_trees(), 1);

    // The epoch 1 message, sealed before Bob's state moved past the
    // `GroupInfo`, decrypts via the retained tree.
    expect_application_message(&mut bob_group, bob_provider, epoch_1_message, &[1u8]);

    // The epoch 2 message belongs to the epoch 2 the group moved to, not
    // the epoch 2 the rejoin created, so it fails to decrypt.
    expect_decryption_error(
        &mut bob_group,
        bob_provider,
        epoch_2_message,
        MessageDecryptionError::AeadError,
    );
}

// Chained rejoins against a stale `GroupInfo` neither accumulate duplicate
// entries for the pre-rejoin epoch nor lose its real secrets to the
// placeholder, even when the second rejoin retains fewer epochs.
#[openmls_test]
fn external_commit_chained_rejoins_from_stale_group_info() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

    let join_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(2)
        .build();
    let (mut alice_group, mut bob_group, alice_credential_with_keys, bob_credential_with_keys) =
        alice_adds_bob(ciphersuite, alice_provider, bob_provider, &join_config);
    let alice_signer = &alice_credential_with_keys.signer;

    // Two `GroupInfo`s exported in epoch 1, both stale by the time they are
    // used.
    let stale_group_info_1 = export_group_info(&alice_group, alice_provider, alice_signer);
    let stale_group_info_2 = export_group_info(&alice_group, alice_provider, alice_signer);

    let epoch_1_message = seal_message(&mut alice_group, alice_provider, alice_signer, &[1u8]);
    for _ in 0..2 {
        let commit = self_update_and_merge(&mut alice_group, alice_provider, alice_signer);
        process_and_merge_commit(&mut bob_group, bob_provider, commit);
    }

    // First rejoin from Bob's epoch 3 state.
    let rejoin_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(2)
        .build();
    let (bob_group, _commit_message_bundle) = rejoin_with_past_epochs(
        bob_provider,
        bob_group,
        stale_group_info_1,
        rejoin_config,
        bob_credential_with_keys.credential_with_key.clone(),
        &bob_credential_with_keys.signer,
    );
    assert_eq!(bob_group.message_secrets_store().num_past_epoch_trees(), 1);

    // Second rejoin, from the state the first one produced, with a tighter
    // retention window.
    let rejoin_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(1)
        .build();
    let (mut bob_group, _commit_message_bundle) = rejoin_with_past_epochs(
        bob_provider,
        bob_group,
        stale_group_info_2,
        rejoin_config,
        bob_credential_with_keys.credential_with_key.clone(),
        &bob_credential_with_keys.signer,
    );
    assert_eq!(bob_group.message_secrets_store().num_past_epoch_trees(), 1);

    // The epoch 1 message still decrypts after both rejoins.
    expect_application_message(&mut bob_group, bob_provider, epoch_1_message, &[1u8]);
}

// A state that sits on a fork of the group at the same epoch number as the
// `GroupInfo` passes the group id, ciphersuite and signature key checks,
// but its group context differs — its current secrets are not installed,
// and decryption of messages from that epoch fails closed.
#[openmls_test]
fn external_commit_retain_past_epochs_from_forked_state() {
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
    let bob_credential_with_keys = generate_credential_with_key(
        b"bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(alice_provider, &alice_signer, alice_credential_with_key)
        .unwrap();

    // A message sealed in Alice's epoch 0.
    let held_message = seal_message(
        &mut alice_group,
        alice_provider,
        &alice_signer,
        b"sealed in epoch 0",
    );

    // Bob's state under the same group id, ciphersuite and his own
    // signature key, but on a different branch: a group of his own making,
    // also at epoch 0.
    let bob_forked_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_group_id(alice_group.group_id().clone())
        .build(
            bob_provider,
            &bob_credential_with_keys.signer,
            bob_credential_with_keys.credential_with_key.clone(),
        )
        .unwrap();

    let verifiable_group_info = export_group_info(&alice_group, alice_provider, &alice_signer);
    let rejoin_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(1)
        .build();
    let (mut bob_group, commit_message_bundle) = rejoin_with_past_epochs(
        bob_provider,
        bob_forked_group,
        verifiable_group_info,
        rejoin_config,
        bob_credential_with_keys.credential_with_key.clone(),
        &bob_credential_with_keys.signer,
    );
    process_and_merge_commit(
        &mut alice_group,
        alice_provider,
        commit_message_bundle
            .into_commit()
            .into_protocol_message()
            .unwrap(),
    );

    // The forked state's secrets were not installed; epoch 0 holds the
    // placeholder and the message fails to decrypt, rather than being fed
    // to wrong-branch secrets.
    expect_decryption_error(
        &mut bob_group,
        bob_provider,
        held_message,
        MessageDecryptionError::AeadError,
    );

    // The joined group works.
    let alice_message = seal_message(
        &mut alice_group,
        alice_provider,
        &alice_signer,
        b"hello bob",
    );
    expect_application_message(&mut bob_group, bob_provider, alice_message, b"hello bob");
}

// `retain_past_epochs_from` rejects a group state that does not belong to
// the group being joined, or that belongs to a different member of it.
#[openmls_test]
fn external_commit_retain_past_epochs_rejects_wrong_group() {
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

    let alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(alice_provider, &alice_signer, alice_credential_with_key)
        .unwrap();

    // A group of Bob's own, unrelated to Alice's group.
    let bob_own_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(bob_provider, &bob_signer, bob_credential_with_key.clone())
        .unwrap();

    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    let err = MlsGroup::external_commit_builder()
        .retain_past_epochs_from(bob_own_group)
        .build_group(
            bob_provider,
            verifiable_group_info,
            bob_credential_with_key.clone(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ExternalCommitBuilderError::PastEpochsGroupIdMismatch
    ));

    // A group under the same group id but a different ciphersuite. All
    // providers in the test matrix support more than one ciphersuite.
    let other_ciphersuite = bob_provider
        .crypto()
        .supported_ciphersuites()
        .into_iter()
        .find(|&suite| suite != ciphersuite)
        .expect("provider supports only one ciphersuite");

    let CredentialWithKeyAndSigner {
        credential_with_key: bob_other_suite_credential_with_key,
        signer: bob_other_suite_signer,
    } = generate_credential_with_key(
        b"bob".into(),
        other_ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let bob_wrong_suite_group = MlsGroup::builder()
        .ciphersuite(other_ciphersuite)
        .with_group_id(alice_group.group_id().clone())
        .build(
            bob_provider,
            &bob_other_suite_signer,
            bob_other_suite_credential_with_key,
        )
        .unwrap();

    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    let err = MlsGroup::external_commit_builder()
        .retain_past_epochs_from(bob_wrong_suite_group)
        .build_group(
            bob_provider,
            verifiable_group_info,
            bob_credential_with_key.clone(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ExternalCommitBuilderError::PastEpochsCiphersuiteMismatch
    ));

    // A group under the same group id and ciphersuite, but belonging to a
    // different member: its own leaf carries another signature key than the
    // credential the external commit is built with. It lives on its own
    // provider, since `bob_provider` already stores a group under this id.
    let other_member_provider = &Provider::default();
    let CredentialWithKeyAndSigner {
        credential_with_key: other_member_credential_with_key,
        signer: other_member_signer,
    } = generate_credential_with_key(
        b"bob-other".into(),
        ciphersuite.signature_algorithm(),
        other_member_provider,
    );

    let other_member_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .with_group_id(alice_group.group_id().clone())
        .build(
            other_member_provider,
            &other_member_signer,
            other_member_credential_with_key,
        )
        .unwrap();

    let verifiable_group_info = alice_group
        .export_group_info(alice_provider.crypto(), &alice_signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    let err = MlsGroup::external_commit_builder()
        .retain_past_epochs_from(other_member_group)
        .build_group(bob_provider, verifiable_group_info, bob_credential_with_key)
        .unwrap_err();
    assert!(matches!(
        err,
        ExternalCommitBuilderError::PastEpochsSignatureKeyMismatch
    ));
}
