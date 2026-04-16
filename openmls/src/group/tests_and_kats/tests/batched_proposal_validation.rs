use crate::group::errors::{BatchedProposalValidationError, ValidationError};
use crate::group::mls_group::errors::ProposeBatchedError;
use crate::prelude::*;
use crate::test_utils::{frankenstein::*, single_group_test_framework::*};
use openmls_test::openmls_test;

fn setup<'a, Provider: OpenMlsProvider>(
    alice_party: &'a CorePartyState<Provider>,
    bob_party: &'a CorePartyState<Provider>,
    ciphersuite: Ciphersuite,
) -> GroupState<'a, Provider> {
    let capabilities = Capabilities::new(None, None, None, Some(&[ProposalType::Batched]), None);

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .capabilities(capabilities.clone())
        .use_ratchet_tree_extension(true)
        // so that proposal messages are PublicMessages, which can be
        // deserialized using the tools in test_utils::frankenstein
        .wire_format_policy(crate::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let join_config = create_config.join_config().clone();

    let alice_pre_group = alice_party.pre_group_builder(ciphersuite).build();
    let bob_pre_group = bob_party
        .pre_group_builder(ciphersuite)
        .with_leaf_node_capabilities(capabilities)
        .build();

    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"Test Group"),
        alice_pre_group,
        create_config,
    )
    .unwrap();

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config,
            tree: None,
        })
        .expect("Could not add member");

    group_state
}

/// Test the propose_batched() API
#[openmls_test]
fn test_propose_batched() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let required_capabilities_extension =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&[], &[], &[]));
    let group_context_extensions =
        Extensions::<GroupContext>::single(required_capabilities_extension.clone()).unwrap();

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // ensure that the batch may not be empty.
    let err = alice
        .group
        .batched_proposal_builder()
        .propose(&alice_party.provider, &alice.party.signer)
        .unwrap_err();

    assert!(
        matches!(
            err,
            ProposeBatchedError::BatchedProposalValidation(
                BatchedProposalValidationError::EmptyList
            )
        ),
        "unexpected error: {err:?}"
    );

    // create a new batch with a GroupContextExtensions update
    let (proposal, _) = alice
        .group
        .batched_proposal_builder()
        .group_context_extensions(group_context_extensions.clone())
        .unwrap()
        .propose(&alice_party.provider, &alice.party.signer)
        .expect("error finalizing proposal");

    // process the message for bob
    let protocol_message = MlsMessageIn::from(proposal)
        .try_into_protocol_message()
        .unwrap();

    let processed = bob
        .group
        .process_message(&bob_party.provider, protocol_message)
        .expect("error processing proposal");

    let ProcessedMessageContent::ProposalMessage(proposal) = processed.into_content() else {
        unreachable!();
    };

    bob.group
        .store_pending_proposal(bob_party.provider.storage(), *proposal)
        .expect("error storing pending proposal");

    // create a commit on Bob's side, and merge for Alice and Bob, and then
    // check that the GroupContextExtensions are expected.
    let (commit_message, _, _) = bob
        .group
        .commit_to_pending_proposals(&bob_party.provider, &bob.party.signer)
        .unwrap();

    bob.group.merge_pending_commit(&bob_party.provider).unwrap();

    // process the message for Alice
    let protocol_message = MlsMessageIn::from(commit_message)
        .try_into_protocol_message()
        .unwrap();

    let processed = alice
        .group
        .process_message(&alice_party.provider, protocol_message)
        .expect("error processing proposal");

    let ProcessedMessageContent::StagedCommitMessage(commit) = processed.into_content() else {
        unreachable!();
    };

    alice
        .group
        .merge_staged_commit(&alice_party.provider, *commit)
        .unwrap();

    // ensure that updates have been made
    assert_eq!(bob.group.extensions(), &group_context_extensions);
    assert_eq!(alice.group.extensions(), &group_context_extensions);
}

/// Test that a Batched proposal containing a nested Batched proposal is rejected
/// with `ValidationError::NestedBatchedProposal`.
#[openmls_test]
fn test_nested_batched_proposal_rejected() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // Craft a Batched proposal containing a nested Batched proposal.
    let nested_batched =
        FrankenProposal::Batched(FrankenBatchedProposalList(vec![FrankenProposal::Batched(
            FrankenBatchedProposalList(vec![]),
        )]));

    let group_context = FrankenGroupContext::from(alice.group.export_group_context().clone());

    let content = FrankenFramedContent {
        group_id: alice.group.group_id().as_slice().to_vec().into(),
        epoch: alice.group.export_group_context().epoch().as_u64(),
        sender: FrankenSender::Member(alice.group.own_leaf_index().u32()),
        authenticated_data: vec![].into(),
        body: FrankenFramedContentBody::Proposal(nested_batched),
    };

    let membership_key = alice.group.message_secrets().membership_key().as_slice();

    let franken_message = FrankenMlsMessage {
        version: 1,
        body: FrankenMlsMessageBody::PublicMessage(FrankenPublicMessage::auth(
            &alice_party.provider,
            ciphersuite,
            &alice.party.signer,
            content,
            Some(&group_context),
            Some(membership_key),
            None,
        )),
    };

    let protocol_message = MlsMessageIn::from(franken_message)
        .try_into_protocol_message()
        .expect("error converting to protocol message");

    let err = bob
        .group
        .process_message(&bob_party.provider, protocol_message)
        .expect_err("expected error for nested batched proposal");

    assert!(
        matches!(
            err,
            ProcessMessageError::ValidationError(ValidationError::BatchedProposalValidation(
                BatchedProposalValidationError::NestedBatch
            ))
        ),
        "unexpected error: {err:?}"
    );
}
