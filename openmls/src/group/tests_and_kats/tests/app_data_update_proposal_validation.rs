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

    // Alice creates a commit containing an AppDataUpdate proposal
    let mut stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::update(16, b"ignored".to_vec()),
        ))])
        .load_psks(alice_party.provider.storage())
        .unwrap();

    let mut app_data_updater = stage.app_data_dictionary_updater();

    // TODO: handle in order of ComponentId
    for proposal in stage.app_data_update_proposals() {
        let operation = proposal.operation();
        let component_id = proposal.component_id();

        if let AppDataUpdateOperation::Update(data) = operation {
            let component_data = ComponentData::from_parts(component_id, data.clone());
            app_data_updater.set(component_data);
        } else if let AppDataUpdateOperation::Remove = operation {
            app_data_updater.remove(&component_id);
        }
    }

    let changes = app_data_updater.changes();
    assert_eq!(changes.as_ref().unwrap().len(), 1);

    stage.with_app_data_dictionary_updates(changes);

    let err = stage
        .build(
            alice_party.provider.rand(),
            alice_party.provider.crypto(),
            &alice.party.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&alice_party.provider)
        .unwrap_err();

    /*
    assert_eq!(
        err,
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::GroupContextExtensionsProposalValidationError(
                GroupContextExtensionsProposalValidationError::ExtensionNotInRequiredCapabilities
            )
        )
    );
    */
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
    let mut stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::remove(16))),
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::remove(16))),
        ])
        .load_psks(alice_party.provider.storage())
        .unwrap();

    let mut app_data_updater = stage.app_data_dictionary_updater();

    // TODO: handle in order of ComponentId
    for proposal in stage.app_data_update_proposals() {
        let operation = proposal.operation();
        let component_id = proposal.component_id();

        if let AppDataUpdateOperation::Remove = operation {
            app_data_updater.remove(&component_id);
        }
    }

    let changes = app_data_updater.changes();
    assert_eq!(changes.as_ref().unwrap().len(), 1);

    stage.with_app_data_dictionary_updates(changes);

    let commit_bundle = stage
        .build(
            alice_party.provider.rand(),
            alice_party.provider.crypto(),
            &alice.party.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&alice_party.provider)
        .unwrap();

    let (commit, _, _) = commit_bundle.into_contents();

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
