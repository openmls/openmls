use openmls_test::openmls_test;

use crate::{
    framing::{ProcessedMessageContent, ProtocolMessage},
    group::{
        tests_and_kats::utils::CredentialWithKeyAndSigner, MlsGroup, MlsGroupJoinConfig,
        WireFormatPolicy, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    messages::proposals::{PreSharedKeyProposal, ProposalType},
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    treesync::node::leaf_node::{Capabilities, LeafNodeParameters},
};

#[openmls_test]
fn external_commit_builder() {
    use crate::group::tests_and_kats::utils::generate_credential_with_key;

    let CredentialWithKeyAndSigner {
        credential_with_key: alice_credential_with_key,
        signer: alice_signer,
    } = generate_credential_with_key(b"alice".into(), ciphersuite.signature_algorithm(), provider);

    let CredentialWithKeyAndSigner {
        credential_with_key: bob_credential_with_key,
        signer: bob_signer,
    } = generate_credential_with_key(b"bob".into(), ciphersuite.signature_algorithm(), provider);

    let CredentialWithKeyAndSigner {
        credential_with_key: charlie_credential_with_key,
        signer: charlie_signer,
    } = generate_credential_with_key(
        b"charlie".into(),
        ciphersuite.signature_algorithm(),
        provider,
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
        .build(provider, &alice_signer, alice_credential_with_key)
        .unwrap();

    // Bob joins the group externally.

    let verifiable_group_info = alice_group
        .export_group_info(provider.crypto(), &alice_signer, false)
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
            provider,
            verifiable_group_info,
            bob_credential_with_key.clone(),
        )
        .unwrap()
        .leaf_node_parameters(leaf_node_parameters)
        .load_psks(provider.storage())
        .unwrap()
        .build(provider.rand(), provider.crypto(), &bob_signer, |_| true)
        .unwrap()
        .finalize(provider)
        .unwrap();

    // Check that the padding was set correctly.
    assert_eq!(bob_group.configuration().padding_size(), PADDING_SIZE);

    let plaintext = commit_message_bundle
        .into_commit()
        .into_protocol_message()
        .unwrap();

    alice_group.set_aad(AAD.to_vec());
    let processed_message = alice_group.process_message(provider, plaintext).unwrap();

    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    else {
        panic!("Expected a staged commit message.");
    };
    alice_group
        .merge_staged_commit(provider, *staged_commit)
        .unwrap();

    // Alice issues a self-remove proposal.
    let msg_out = alice_group
        .leave_group_via_self_remove(provider, &alice_signer)
        .unwrap();

    let ProtocolMessage::PublicMessage(self_remove_proposal) =
        msg_out.into_protocol_message().unwrap()
    else {
        panic!("Expected a public message for the self-remove proposal.");
    };

    // Bob processes the self-remove proposal.
    let bob_processed_message = bob_group
        .process_message(provider, *self_remove_proposal.clone())
        .unwrap();

    let ProcessedMessageContent::ProposalMessage(proposal) = bob_processed_message.into_content()
    else {
        panic!("Expected a proposal message.");
    };

    bob_group
        .store_pending_proposal(provider.storage(), *proposal)
        .unwrap();

    let verifiable_group_info = bob_group
        .export_group_info(provider.crypto(), &bob_signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();

    // Charlie joins the group externally and sends a PSK proposal as part of the commit.
    let psk_id_bytes = vec![0, 1, 2, 3];
    let psk_id = Psk::External(ExternalPsk::new(psk_id_bytes.clone()));
    let psk = PreSharedKeyId::new(ciphersuite, provider.rand(), psk_id).unwrap();
    let psk_value = vec![4, 5, 6, 7];
    psk.store(provider, &psk_value).unwrap();

    let (charlie_group, commit_message_bundle) = MlsGroup::external_commit_builder()
        .with_proposals(vec![*self_remove_proposal])
        .with_ratchet_tree(bob_group.export_ratchet_tree().into())
        .build_group(
            provider,
            verifiable_group_info,
            charlie_credential_with_key.clone(),
        )
        .unwrap()
        .add_psk_proposal(PreSharedKeyProposal::new(psk))
        .load_psks(provider.storage())
        .unwrap()
        .build(provider.rand(), provider.crypto(), &charlie_signer, |_| {
            true
        })
        .unwrap()
        .finalize(provider)
        .unwrap();

    // Bob processes Charlie's Commit.
    let plaintext = commit_message_bundle
        .into_commit()
        .into_protocol_message()
        .unwrap();

    let bob_processed_message = bob_group.process_message(provider, plaintext).unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    else {
        panic!("Expected a staged commit message.");
    };
    bob_group
        .merge_staged_commit(provider, *staged_commit)
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
