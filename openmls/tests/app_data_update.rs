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
        // so that commit messages are PublicMessages, which can be deserialized
        // using the tools in test_utils::frankenstein
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
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
fn test_app_data_update_simple() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice produces StagedCommit to send to Bob
    //  - Stylistic: Also could move adding the proposals here
    let mut stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(16, b"ignore"))),
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(16, b"value"))),
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(16, b"value"))),
        ])
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

    let message_in: MlsMessageIn = commit.into();

    // unprotect the message
    let unverified_message = bob
        .group
        .unprotect_message(
            &bob_party.provider,
            message_in.into_protocol_message().unwrap(),
        )
        .unwrap();

    // create the AppDataUpdater for Bob
    let mut app_data_updater = bob.group.app_data_dictionary_updater();

    let proposals = unverified_message.proposals().unwrap();

    for proposal in proposals.iter() {
        // validate the proposal
        let proposal = proposal
            .clone()
            .validate(
                bob_party.provider.crypto(),
                ciphersuite,
                ProtocolVersion::Mls10,
            )
            .unwrap();

        // retrieve the proposal
        let proposal = match proposal {
            ProposalOrRef::Proposal(proposal) => Some(proposal),
            ProposalOrRef::Reference(reference) => bob
                .group
                .proposal_store()
                .proposals()
                .find(|prop| prop.proposal_reference_ref() == &*reference)
                .map(|prop| Box::new(prop.proposal().clone())),
        }
        .unwrap();

        // handle AppDataUpdate proposals only
        let Proposal::AppDataUpdate(proposal) = *proposal else {
            continue;
        };

        // handle the proposal
        // TODO: handle in order of ComponentId
        let operation = proposal.operation();
        let component_id = proposal.component_id();

        if let AppDataUpdateOperation::Update(data) = operation {
            let component_data = ComponentData::from_parts(component_id, data.clone());
            app_data_updater.set(component_data);
        } else if let AppDataUpdateOperation::Remove = operation {
            app_data_updater.remove(&component_id);
        }
    }

    // process the message after applying updates (including staging)
    let processed_message = bob
        .group
        .process_unverified_message(
            &bob_party.provider,
            unverified_message,
            app_data_updater.changes(),
        )
        .expect("error processing commit");

    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => commit,
        _ => panic!("Should be a processed commit with app data updates"),
    };

    bob.group
        .merge_staged_commit(&bob_party.provider, *staged_commit)
        .unwrap();

    alice
        .group
        .merge_pending_commit(&alice_party.provider)
        .unwrap();

    // ensure that the dictionaries match
    assert_eq!(
        bob.group.extensions().app_data_dictionary(),
        alice.group.extensions().app_data_dictionary()
    );

    // ensure that the contents are correct
    let dictionary_ext = alice.group.extensions().app_data_dictionary().unwrap();
    let dictionary = dictionary_ext.dictionary();
    assert_eq!(dictionary.get(&16), Some(b"value".as_ref()));
}

/// Test AppDataUpdates combined with an Add proposal
#[openmls_test]
fn test_app_data_update_with_welcome() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");

    let charlie_pre_group = charlie_party
        .pre_group_builder(ciphersuite)
        .with_leaf_node_capabilities(Capabilities::new(
            None,
            None,
            Some(&[ExtensionType::AppDataDictionary]),
            Some(&[ProposalType::AppDataUpdate]),
            None,
        ))
        .build();

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice produces StagedCommit to send to Bob
    let mut stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(16, b"ignore"))),
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(16, b"value"))),
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(16, b"value"))),
        ])
        .propose_adds(Some(
            charlie_pre_group.key_package_bundle.key_package().clone(),
        ))
        .load_psks(alice_party.provider.storage())
        .unwrap();

    // retrieve the update helper struct for the stage
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

    let (commit, welcome, _) = commit_bundle.into_contents();

    let message_in: MlsMessageIn = commit.into();

    // unprotect the message
    let unverified_message = bob
        .group
        .unprotect_message(
            &bob_party.provider,
            message_in.into_protocol_message().unwrap(),
        )
        .unwrap();

    // create the AppDataUpdater for Bob
    let mut app_data_updater = bob.group.app_data_dictionary_updater();

    let proposals = unverified_message.proposals().unwrap();

    for proposal in proposals.iter() {
        // validate the proposal
        let proposal = proposal
            .clone()
            .validate(
                bob_party.provider.crypto(),
                ciphersuite,
                ProtocolVersion::Mls10,
            )
            .unwrap();

        // retrieve the proposal
        let proposal = match proposal {
            ProposalOrRef::Proposal(proposal) => Some(proposal),
            ProposalOrRef::Reference(reference) => bob
                .group
                .proposal_store()
                .proposals()
                .find(|prop| prop.proposal_reference_ref() == &*reference)
                .map(|prop| Box::new(prop.proposal().clone())),
        }
        .unwrap();

        // handle AppDataUpdate proposals only
        let Proposal::AppDataUpdate(proposal) = *proposal else {
            continue;
        };

        // handle the proposal
        // TODO: handle in order of ComponentId
        let operation = proposal.operation();
        let component_id = proposal.component_id();

        if let AppDataUpdateOperation::Update(data) = operation {
            let component_data = ComponentData::from_parts(component_id, data.clone());
            app_data_updater.set(component_data);
        } else if let AppDataUpdateOperation::Remove = operation {
            app_data_updater.remove(&component_id);
        }
    }

    // process the message after applying updates (including staging)
    let processed_message = bob
        .group
        .process_unverified_message(
            &bob_party.provider,
            unverified_message,
            app_data_updater.changes(),
        )
        .expect("error processing commit");

    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => commit,
        _ => panic!("Should be a processed commit with app data updates"),
    };

    bob.group
        .merge_staged_commit(&bob_party.provider, *staged_commit)
        .unwrap();

    alice
        .group
        .merge_pending_commit(&alice_party.provider)
        .unwrap();

    // ensure that the dictionaries match
    assert_eq!(
        bob.group.extensions().app_data_dictionary(),
        alice.group.extensions().app_data_dictionary()
    );

    // ensure that the contents are correct
    let dictionary_ext = alice.group.extensions().app_data_dictionary().unwrap();
    let dictionary = dictionary_ext.dictionary();
    assert_eq!(dictionary.get(&16), Some(b"value".as_ref()));

    // charlie joins
    let charlie_group = StagedWelcome::new_from_welcome(
        &charlie_party.provider,
        &Default::default(),
        welcome.unwrap(),
        None,
    )
    .unwrap()
    .into_group(&charlie_party.provider)
    .unwrap();

    // ensure that the dictionaries match
    assert_eq!(
        charlie_group.extensions().app_data_dictionary(),
        alice.group.extensions().app_data_dictionary()
    );
}
