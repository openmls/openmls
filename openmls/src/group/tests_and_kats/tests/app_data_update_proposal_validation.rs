use crate::extensions::*;
use crate::prelude::*;
use crate::test_utils::{frankenstein::*, single_group_test_framework::*};
use openmls_test::openmls_test;

fn setup<'a, Provider: OpenMlsProvider>(
    alice_party: &'a CorePartyState<Provider>,
    bob_party: &'a CorePartyState<Provider>,
    ciphersuite: Ciphersuite,
    include_required_capabilities: bool,
) -> GroupState<'a, Provider> {
    // Required capabilities for leaf node
    let capabilities = Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::AppDataDictionary]),
        Some(&[ProposalType::AppDataUpdate]),
        None,
    );

    let required_capabilities_extension =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::AppDataDictionary],
            &[ProposalType::AppDataUpdate],
            &[],
        ));
    let group_context_extensions = if include_required_capabilities {
        Extensions::single(required_capabilities_extension)
    } else {
        Extensions::default()
    };

    // Set up the PreGroups with the required Capabilities
    let alice_pre_group = alice_party.pre_group_builder(ciphersuite).build();
    let bob_pre_group = bob_party
        .pre_group_builder(ciphersuite)
        .with_leaf_node_capabilities(capabilities.clone())
        .build();

    // Define the MlsGroup configuration
    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .capabilities(capabilities.clone())
        .use_ratchet_tree_extension(true)
        // so that commit messages are PublicMessages, which can be deserialized
        // using the tools in test_utils::frankenstein
        .wire_format_policy(crate::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .with_group_context_extensions(group_context_extensions)
        .unwrap()
        .build();
    let join_config = create_config.join_config().clone();

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

/// Test a simple AppDataUpdate
#[openmls_test]
fn test_app_data_update() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice sends a commit containing an AppDataUpdate proposal
    alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            16,
            AppDataUpdateOperation::Update(b"ignored".into()),
        )
        .unwrap();
    alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            16,
            AppDataUpdateOperation::Update(b"value".into()),
        )
        .unwrap();
    let (commit, _welcome, _group_info) = alice
        .group
        .commit_to_pending_proposals(&alice_party.provider, &alice.party.signer)
        .unwrap();

    let message_in: MlsMessageIn = commit.into();
    let processed_message = bob
        .group
        .process_message(
            &bob_party.provider,
            message_in.try_into_protocol_message().unwrap(),
        )
        .unwrap();

    let mut staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => commit,
        _ => panic!("Should be a processed commit with app data updates"),
    };

    // the component ids known to the application
    let component_ids = [1, 2, 3, 16];

    // retrieve the AppDataDictionary
    let dictionary = staged_commit.state.app_data_dictionary().unwrap();

    // for each of the component ids:
    for component_id in component_ids {
        // iterate over the proposals and handle each one
        for queued_proposal in staged_commit
            .staged_proposal_queue
            .app_data_update_proposals_for_id(component_id)
        {
            let operation = queued_proposal.app_data_update_proposal().operation();
            if let AppDataUpdateOperation::Update(data) = operation {
                dictionary.insert(component_id, Vec::from(data.as_ref()));
            } else if let AppDataUpdateOperation::Remove = operation {
                dictionary.remove(&component_id);
            }
        }
    }

    // check that the dictionary in the staged commit was updated correctly
    let dictionary_ext = staged_commit
        .group_context()
        .extensions()
        .app_data_dictionary()
        .unwrap();
    assert_eq!(
        dictionary_ext.dictionary().get(&16),
        Some(b"value".as_slice())
    );

    bob.group
        .merge_staged_commit(&bob_party.provider, *staged_commit)
        .unwrap();
}
/// Commit creation:
/// Test the invalid case where there are both Update and Remove AppDataUpdate proposals
/// for a single ComponentId.
#[openmls_test]
fn test_incompatible_app_data_update_proposal_types() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice] = group_state.members_mut(&["alice"]);

    // Alice sends a commit containing an AppDataUpdate proposal
    alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            16,
            AppDataUpdateOperation::Update(b"ignored".into()),
        )
        .unwrap();
    alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            16,
            AppDataUpdateOperation::Remove,
        )
        .unwrap();
    let err = alice
        .group
        .commit_to_pending_proposals(&alice_party.provider, &alice.party.signer)
        .unwrap_err();

    assert_eq!(
        err,
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::AppDataUpdateValidationError(
                AppDataUpdateValidationError::CombinedRemoveAndUpdateOperations
            )
        )
    );
}

/// Commit creation:
/// Test the invalid case where a GroupContextExtensionProposal comes after the AppDataUpdate
/// proposals.
#[openmls_test]
fn test_group_context_update_wrong_order() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice] = group_state.members_mut(&["alice"]);

    // Alice sends a commit containing an AppDataUpdate proposal
    alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            16,
            AppDataUpdateOperation::Update(b"ignored".into()),
        )
        .unwrap();

    let required_capabilities_extension =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::AppDataDictionary],
            &[ProposalType::AppDataUpdate],
            &[],
        ));

    alice
        .group
        .propose_group_context_extensions(
            &alice_party.provider,
            Extensions::from_vec(vec![required_capabilities_extension]).unwrap(),
            &alice.party.signer,
        )
        .unwrap();

    let err = alice
        .group
        .commit_to_pending_proposals(&alice_party.provider, &alice.party.signer)
        .unwrap_err();

    assert_eq!(
        err,
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::AppDataUpdateValidationError(
                AppDataUpdateValidationError::IncorrectOrder
            )
        )
    );
}
/// Commit creation:
/// Test the invalid case where a GroupContextExtensionProposal updates the AppDataDictionary.
#[openmls_test]
fn test_group_context_update_dictionary() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice] = group_state.members_mut(&["alice"]);

    let required_capabilities_extension =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::AppDataDictionary],
            &[ProposalType::AppDataUpdate],
            &[],
        ));

    let dictionary_extension = Extension::AppDataDictionary(AppDataDictionaryExtension::default());

    alice
        .group
        .propose_group_context_extensions(
            &alice_party.provider,
            Extensions::from_vec(vec![required_capabilities_extension, dictionary_extension])
                .unwrap(),
            &alice.party.signer,
        )
        .unwrap();

    // Alice sends a commit containing an AppDataUpdate proposal
    alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            16,
            AppDataUpdateOperation::Update(b"ignored".into()),
        )
        .unwrap();

    let err = alice
        .group
        .commit_to_pending_proposals(&alice_party.provider, &alice.party.signer)
        .unwrap_err();

    assert_eq!(
        err,
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::AppDataUpdateValidationError(
                AppDataUpdateValidationError::CannotUpdateDictionaryDirectly
            )
        )
    );
}

/// Commit creation:
/// Test the case where a GroupContextExtensionProposal updates the AppDataDictionary after
/// removing AppDataUpdate from the required capabilities.
#[openmls_test]
fn test_group_context_update_dictionary_after_deactivating() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice] = group_state.members_mut(&["alice"]);

    let required_capabilities_extension =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&[], &[], &[]));

    let dictionary_extension = Extension::AppDataDictionary(AppDataDictionaryExtension::default());

    alice
        .group
        .propose_group_context_extensions(
            &alice_party.provider,
            Extensions::from_vec(vec![required_capabilities_extension, dictionary_extension])
                .unwrap(),
            &alice.party.signer,
        )
        .unwrap();

    let err = alice
        .group
        .commit_to_pending_proposals(&alice_party.provider, &alice.party.signer)
        .unwrap_err();

    assert_eq!(
        err,
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::GroupContextExtensionsProposalValidationError(
                GroupContextExtensionsProposalValidationError::ExtensionNotInRequiredCapabilities
            )
        )
    );
}

// FIXME: validate that all proposal types in the commit are supported by the new GroupContextExtensions proposal
/// Commit creation:
/// Test the case where an AppDataUpdateProposal updates the AppDataDictionary after
/// removing AppDataUpdate from the required capabilities.
#[ignore]
#[openmls_test]
fn test_app_data_update_after_removing_required_capabilities() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice] = group_state.members_mut(&["alice"]);

    let required_capabilities_extension =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&[], &[], &[]));

    alice
        .group
        .propose_group_context_extensions(
            &alice_party.provider,
            Extensions::from_vec(vec![required_capabilities_extension]).unwrap(),
            &alice.party.signer,
        )
        .unwrap();

    // Alice sends a commit containing an AppDataUpdate proposal
    alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            16,
            AppDataUpdateOperation::Update(b"ignored".into()),
        )
        .unwrap();

    let err = alice
        .group
        .commit_to_pending_proposals(&alice_party.provider, &alice.party.signer)
        .unwrap_err();

    assert_eq!(
        err,
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::GroupContextExtensionsProposalValidationError(
                GroupContextExtensionsProposalValidationError::ExtensionNotInRequiredCapabilities
            )
        )
    );
}

/// Commit creation:
/// Test the invalid case where there are multiple Remove AppDataUpdate proposals
/// for a single ComponentId.
///
/// NOTE: A valid commit is produced by `MlsGroup::commit_to_pending_proposals()`,
/// since the duplicate Remove AppDataUpdate proposals are filtered out automatically.
#[openmls_test]

fn test_app_data_update_multi_remove_validate_outgoing() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice] = group_state.members_mut(&["alice"]);

    // Alice sends a commit containing an AppDataUpdate proposal
    alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            16,
            AppDataUpdateOperation::Remove,
        )
        .unwrap();
    alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            16,
            AppDataUpdateOperation::Remove,
        )
        .unwrap();

    assert_eq!(alice.group.pending_proposals().count(), 2);

    let (commit, _, _) = alice
        .group
        .commit_to_pending_proposals(&alice_party.provider, &alice.party.signer)
        .unwrap();

    // check number of proposals in commit
    let franken_commit = FrankenMlsMessage::from(commit);

    let body = match franken_commit.body {
        FrankenMlsMessageBody::PublicMessage(ref message) => message,
        _ => unimplemented!(),
    };

    let commit = match body.content.body {
        FrankenFramedContentBody::Commit(ref commit) => commit,
        _ => unimplemented!(),
    };

    // check that duplicate proposals have been filtered out
    assert_eq!(commit.proposals.len(), 1);
}

// TODO: documentation
#[openmls_test]
fn test_app_data_update_multi_remove_validate_incoming() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            16,
            AppDataUpdateOperation::Update(b"value".into()),
        )
        .unwrap();
    let (commit, _welcome, _group_info) = alice
        .group
        .commit_to_pending_proposals(&alice_party.provider, &alice.party.signer)
        .unwrap();

    let mut franken_commit = FrankenMlsMessage::from(commit);

    let body = match franken_commit.body {
        FrankenMlsMessageBody::PublicMessage(ref mut message) => message,
        _ => unimplemented!(),
    };

    let commit = match body.content.body {
        FrankenFramedContentBody::Commit(ref mut commit) => commit,
        _ => unimplemented!(),
    };

    assert_eq!(commit.proposals.len(), 1);
    // duplicate the AppDataUpdate Remove proposal
    commit.proposals.push(commit.proposals[0].clone());

    let message_in: MlsMessageIn = franken_commit.into();

    let protocol_message = message_in.try_into_protocol_message().unwrap();

    // NOTE: processing currently fails here with a ValidationError::InvalidMembershipTag.
    let _err = bob
        .group
        .process_message(&bob.party.core_state.provider, protocol_message.clone())
        .unwrap_err();
}
