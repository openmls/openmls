#![cfg(feature = "extensions-draft-08")]

use openmls::extensions::*;
use openmls::prelude::*;
use openmls::test_utils::single_group_test_framework::*;
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

    // set up component logic
    let mut registered_components = RegisteredComponentsWithLogic::new();
    registered_components.register(16, |data| {
        let mut new_data = b"new_data:".to_vec();
        new_data.extend(data.to_vec());
        Ok(new_data)
    });

    let commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitWithPendingAppDataUpdates(commit) => commit,
        _ => panic!("Should be a processed commit with app data updates"),
    };
    let staged_commit = commit.apply_app_logic(&registered_components).unwrap();
    let dictionary_ext = staged_commit
        .group_context()
        .extensions()
        .app_data_dictionary()
        .unwrap();
    assert_eq!(
        dictionary_ext.dictionary().get(&16),
        Some(b"new_data:value".as_slice())
    );

    bob.group
        .merge_staged_commit(&bob_party.provider, *staged_commit)
        .unwrap();
}

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
enum Error {
    #[error("error validating the AppDataUpdate")]
    ValidateAppDataUpdateError(#[from] ValidateAppDataUpdateError),
    #[error("error creating a commit")]
    CreateCommitError(#[from] CreateCommitError),
}

fn test_case<Provider: OpenMlsProvider>(
    group_state: &mut GroupState<Provider>,
    proposals: impl IntoIterator<Item = Proposal>,
    group_context_extensions: Option<Extensions>,
    registered_components: &RegisteredComponentsWithLogic,
) -> Result<(), Error> {
    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice sends a commit containing AppDataUpdate proposals
    let mut commit_builder = alice.group.commit_builder().consume_proposal_store(false);

    if let Some(extensions) = group_context_extensions {
        commit_builder = commit_builder.propose_group_context_extensions(extensions);
    }
    let commit_message_bundle = commit_builder
        .add_proposals(proposals)
        .load_psks(alice.party.core_state.provider.storage())
        .unwrap()
        .build(
            alice.party.core_state.provider.rand(),
            alice.party.core_state.provider.crypto(),
            &alice.party.signer,
            |_| true,
        )?
        .stage_commit(&alice.party.core_state.provider)
        .unwrap();

    let message_in: MlsMessageIn = commit_message_bundle.into_commit().into();
    let processed_message = bob
        .group
        .process_message(
            &bob.party.core_state.provider,
            message_in.try_into_protocol_message().unwrap(),
        )
        .unwrap();
    let commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitWithPendingAppDataUpdates(commit) => commit,
        _ => panic!("Should be a processed commit with app data updates"),
    };
    commit.apply_app_logic(&registered_components)?;
    Ok(())
}

// TODO: split up into multiple tests
/// Test incorrect proposals
#[openmls_test]
fn test_incorrect_proposals() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    // Set up group state
    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    // Removing a ComponentId that is not registered
    let registered_components = RegisteredComponentsWithLogic::new();
    let err = test_case(
        &mut group_state,
        Some(Proposal::AppDataUpdate(AppDataUpdateProposal::remove(16))),
        None,
        &registered_components,
    )
    .unwrap_err();
    assert_eq!(
        err,
        Error::ValidateAppDataUpdateError(ValidateAppDataUpdateError::ComponentNotRegistered)
    );

    // Removing a ComponentId when there is no AppDataDictionaryExtension
    let mut registered_components = RegisteredComponentsWithLogic::new();
    registered_components.register(16, |_| Ok(vec![]));
    let err = test_case(
        &mut group_state,
        Some(Proposal::AppDataUpdate(AppDataUpdateProposal::remove(16))),
        None,
        &registered_components,
    )
    .unwrap_err();
    assert_eq!(
        err,
        Error::ValidateAppDataUpdateError(ValidateAppDataUpdateError::ComponentNotAvailable)
    );

    // Adding both remove and update proposals
    let err = test_case(
        &mut group_state,
        vec![
            Proposal::AppDataUpdate(AppDataUpdateProposal::remove(16)),
            Proposal::AppDataUpdate(AppDataUpdateProposal::update(16, vec![1, 2, 3])),
        ],
        None,
        &registered_components,
    )
    .unwrap_err();
    assert_eq!(
        err,
        Error::CreateCommitError(CreateCommitError::AppDataUpdateValidationError(
            AppDataUpdateValidationError::CombinedRemoveAndUpdateOperations
        ))
    );

    // Adding a ComponentId that is registered, but also updating the dictionary
    // directly in the GroupContextExtensions
    let required_capabilities_extension =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::AppDataDictionary],
            &[ProposalType::AppDataUpdate],
            &[],
        ));
    let err = test_case(
        &mut group_state,
        Some(Proposal::AppDataUpdate(AppDataUpdateProposal::remove(16))),
        Some(
            Extensions::from_vec(vec![
                required_capabilities_extension,
                Extension::AppDataDictionary(AppDataDictionaryExtension::default()),
            ])
            .unwrap(),
        ),
        &registered_components,
    )
    .unwrap_err();
    assert_eq!(
        err,
        Error::CreateCommitError(CreateCommitError::AppDataUpdateValidationError(
            AppDataUpdateValidationError::CannotUpdateDictionaryDirectly
        ))
    );

    // TODO: add more test cases
}
