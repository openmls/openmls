#![cfg(feature = "extensions-draft")]

use openmls::component::*;
use openmls::extensions::*;
use openmls::group::ProposalStore;
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
        Extensions::single(required_capabilities_extension).unwrap()
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

/// Asserts that `message` carries an unresolved app data commit and returns it.
fn expect_unresolved_app_data_commit(message: ProcessedMessage) -> Box<UnresolvedAppDataCommit> {
    match message.into_content() {
        ProcessedMessageContent::UnresolvedAppDataCommit(unresolved_commit) => unresolved_commit,
        other => panic!("expected an unresolved app data commit, got {other:?}"),
    }
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

    // Technically we should handle these in order of component ID. In this case the handlers are
    // independent, so we don't bother to sort them.
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

    // process the message; the commit covers AppDataUpdate proposals, so it
    // comes back unresolved
    let processed_message = bob
        .group
        .process_message(
            &bob_party.provider,
            message_in.into_protocol_message().unwrap(),
        )
        .unwrap();

    let unresolved_commit = expect_unresolved_app_data_commit(processed_message);

    // create the AppDataUpdater for Bob
    let mut app_data_updater = bob.group.app_data_dictionary_updater();

    // the proposals are already verified, resolved and sorted by component ID
    for proposal in unresolved_commit.app_data_update_proposals() {
        let operation = proposal.operation();
        let component_id = proposal.component_id();

        if let AppDataUpdateOperation::Update(data) = operation {
            let component_data = ComponentData::from_parts(component_id, data.clone());
            app_data_updater.set(component_data);
        } else if let AppDataUpdateOperation::Remove = operation {
            app_data_updater.remove(&component_id);
        }
    }

    // stage the commit with the computed updates
    let staged_commit = bob
        .group
        .stage_app_data_commit(
            &bob_party.provider,
            *unresolved_commit,
            app_data_updater.changes(),
        )
        .expect("error staging commit");

    bob.group
        .merge_staged_commit(&bob_party.provider, staged_commit)
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

    // Technically we should handle these in order of component ID. In this case the handlers are
    // independent, so we don't bother to sort them.
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

    // process the message; the commit covers AppDataUpdate proposals, so it
    // comes back unresolved
    let processed_message = bob
        .group
        .process_message(
            &bob_party.provider,
            message_in.into_protocol_message().unwrap(),
        )
        .unwrap();

    let unresolved_commit = expect_unresolved_app_data_commit(processed_message);

    // create the AppDataUpdater for Bob
    let mut app_data_updater = bob.group.app_data_dictionary_updater();

    // the proposals are already verified, resolved and sorted by component ID
    for proposal in unresolved_commit.app_data_update_proposals() {
        let operation = proposal.operation();
        let component_id = proposal.component_id();

        if let AppDataUpdateOperation::Update(data) = operation {
            let component_data = ComponentData::from_parts(component_id, data.clone());
            app_data_updater.set(component_data);
        } else if let AppDataUpdateOperation::Remove = operation {
            app_data_updater.remove(&component_id);
        }
    }

    // stage the commit with the computed updates
    let staged_commit = bob
        .group
        .stage_app_data_commit(
            &bob_party.provider,
            *unresolved_commit,
            app_data_updater.changes(),
        )
        .expect("error staging commit");

    bob.group
        .merge_staged_commit(&bob_party.provider, staged_commit)
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

/// Builds a [`PublicGroup`] observer that tracks the same group as `alice`,
/// using her currently exported group info and ratchet tree.
fn build_public_group<Provider: OpenMlsProvider>(
    alice: &MemberState<'_, Provider>,
    alice_provider: &Provider,
    observer_provider: &Provider,
) -> PublicGroup {
    let verifiable_group_info = alice
        .group
        .export_group_info(alice_provider.crypto(), &alice.party.signer, false)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    let ratchet_tree = alice.group.export_ratchet_tree();
    let (public_group, _extensions) = PublicGroup::from_external(
        observer_provider.crypto(),
        observer_provider.storage(),
        ratchet_tree.into(),
        verifiable_group_info,
        ProposalStore::new(),
    )
    .unwrap();
    public_group
}

/// Has `alice` build and stage a commit carrying a single by-value
/// AppDataUpdate proposal for `component_id` with `proposal_payload`, while
/// setting the caller-computed dictionary value to `dict_value`. Returns the
/// commit message; the commit is left pending on `alice`.
fn alice_app_data_commit<Provider: OpenMlsProvider>(
    alice: &mut MemberState<'_, Provider>,
    alice_provider: &Provider,
    component_id: ComponentId,
    proposal_payload: &[u8],
    dict_value: &[u8],
) -> MlsMessageOut {
    let mut stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::update(component_id, proposal_payload),
        ))])
        .load_psks(alice_provider.storage())
        .unwrap();

    let mut updater = stage.app_data_dictionary_updater();
    updater.set(ComponentData::from_parts(
        component_id,
        dict_value.to_vec().into(),
    ));
    stage.with_app_data_dictionary_updates(updater.changes());

    let commit_bundle = stage
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice.party.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();

    let (commit_message, _, _) = commit_bundle.into_contents();
    commit_message
}

fn to_protocol_message(message: MlsMessageOut) -> ProtocolMessage {
    let message_in: MlsMessageIn = message.into();
    message_in.into_protocol_message().unwrap()
}

/// A `PublicGroup` observer processes a commit covering an AppDataUpdate
/// proposal committed by value. The commit comes back as
/// `UnresolvedAppDataCommit`, the caller computes the dictionary value and
/// resumes staging, and the resulting state matches a full member's.
#[openmls_test]
fn test_public_group_app_data_commit() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let observer_provider = Provider::default();

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    let mut public_group = build_public_group(alice, &alice_party.provider, &observer_provider);

    // The caller-computed dictionary value deliberately differs from the
    // proposal payload, so we can prove the applied value comes from the
    // caller, not from the raw proposal.
    let commit_message = alice_app_data_commit(
        alice,
        &alice_party.provider,
        0xf042,
        b"proposal_payload",
        b"caller_computed_value",
    );

    // The public group processes the commit and gets it back unresolved.
    let processed_message = public_group
        .process_message(
            observer_provider.crypto(),
            to_protocol_message(commit_message.clone()),
        )
        .unwrap();

    let unresolved_commit = expect_unresolved_app_data_commit(processed_message);

    let proposals: Vec<_> = unresolved_commit.app_data_update_proposals().collect();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].component_id(), 0xf042);
    assert!(matches!(
        proposals[0].operation(),
        AppDataUpdateOperation::Update(data) if data.as_slice() == b"proposal_payload"
    ));

    // The observer computes the caller value and stages the commit.
    let mut updater = public_group.app_data_dictionary_updater();
    updater.set(ComponentData::from_parts(
        0xf042,
        b"caller_computed_value".to_vec().into(),
    ));
    let staged_commit = public_group
        .stage_app_data_commit(
            observer_provider.crypto(),
            *unresolved_commit,
            updater.changes(),
        )
        .expect("error staging commit");

    // The staged commit's group context carries the caller-computed value.
    let dictionary = staged_commit
        .group_context()
        .extensions()
        .app_data_dictionary()
        .unwrap()
        .dictionary();
    assert_eq!(
        dictionary.get(&0xf042),
        Some(b"caller_computed_value".as_ref())
    );
    assert_ne!(dictionary.get(&0xf042), Some(b"proposal_payload".as_ref()));

    public_group
        .merge_commit(observer_provider.storage(), staged_commit)
        .unwrap();

    // Bob resolves the same commit via his full group state.
    let processed_message = bob
        .group
        .process_message(&bob_party.provider, to_protocol_message(commit_message))
        .unwrap();
    let unresolved_commit = expect_unresolved_app_data_commit(processed_message);
    let mut bob_updater = bob.group.app_data_dictionary_updater();
    bob_updater.set(ComponentData::from_parts(
        0xf042,
        b"caller_computed_value".to_vec().into(),
    ));
    let staged_commit = bob
        .group
        .stage_app_data_commit(
            &bob_party.provider,
            *unresolved_commit,
            bob_updater.changes(),
        )
        .expect("error staging commit");
    bob.group
        .merge_staged_commit(&bob_party.provider, staged_commit)
        .unwrap();

    assert_eq!(
        bob.group.export_group_context(),
        public_group.group_context()
    );
}

/// A `PublicGroup` observer resolves an AppDataUpdate proposal committed by
/// reference against its own proposal store.
#[openmls_test]
fn test_public_group_app_data_commit_by_reference() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let observer_provider = Provider::default();

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, _bob] = group_state.members_mut(&["alice", "bob"]);

    let mut public_group = build_public_group(alice, &alice_party.provider, &observer_provider);

    // Alice sends a standalone AppDataUpdate proposal.
    let (proposal_message, _proposal_ref) = alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            0xf042,
            AppDataUpdateOperation::Update(b"proposal_payload".to_vec().into()),
        )
        .unwrap();

    // The public group processes it and stores it in its proposal store.
    let processed = public_group
        .process_message(
            observer_provider.crypto(),
            to_protocol_message(proposal_message),
        )
        .unwrap();
    match processed.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => {
            public_group
                .add_proposal(observer_provider.storage(), *proposal)
                .unwrap();
        }
        _ => panic!("Expected a proposal message"),
    }

    // Alice commits to the pending proposal by reference, computing the
    // dictionary value herself.
    let mut stage = alice
        .group
        .commit_builder()
        .consume_proposal_store(true)
        .load_psks(alice_party.provider.storage())
        .unwrap();
    let mut alice_updater = stage.app_data_dictionary_updater();
    alice_updater.set(ComponentData::from_parts(
        0xf042,
        b"caller_computed_value".to_vec().into(),
    ));
    stage.with_app_data_dictionary_updates(alice_updater.changes());
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
    let (commit_message, _, _) = commit_bundle.into_contents();

    // The public group processes the by-reference commit.
    let processed_message = public_group
        .process_message(
            observer_provider.crypto(),
            to_protocol_message(commit_message),
        )
        .unwrap();
    let unresolved_commit = expect_unresolved_app_data_commit(processed_message);

    // The proposal was resolved from the proposal store.
    let proposals: Vec<_> = unresolved_commit.app_data_update_proposals().collect();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].component_id(), 0xf042);
    assert!(matches!(
        proposals[0].operation(),
        AppDataUpdateOperation::Update(data) if data.as_slice() == b"proposal_payload"
    ));

    let mut updater = public_group.app_data_dictionary_updater();
    updater.set(ComponentData::from_parts(
        0xf042,
        b"caller_computed_value".to_vec().into(),
    ));
    let staged_commit = public_group
        .stage_app_data_commit(
            observer_provider.crypto(),
            *unresolved_commit,
            updater.changes(),
        )
        .expect("error staging commit");

    let dictionary = staged_commit
        .group_context()
        .extensions()
        .app_data_dictionary()
        .unwrap()
        .dictionary();
    assert_eq!(
        dictionary.get(&0xf042),
        Some(b"caller_computed_value".as_ref())
    );

    public_group
        .merge_commit(observer_provider.storage(), staged_commit)
        .unwrap();
}

/// Staging an unresolved app data commit on a `PublicGroup` without supplying
/// the updates fails with `MissingAppDataUpdates`.
#[openmls_test]
fn test_public_group_stage_app_data_commit_missing_updates() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let observer_provider = Provider::default();

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, _bob] = group_state.members_mut(&["alice", "bob"]);

    let public_group = build_public_group(alice, &alice_party.provider, &observer_provider);

    let commit_message =
        alice_app_data_commit(alice, &alice_party.provider, 0xf042, b"value", b"value");

    let processed_message = public_group
        .process_message(
            observer_provider.crypto(),
            to_protocol_message(commit_message),
        )
        .unwrap();
    let unresolved_commit = expect_unresolved_app_data_commit(processed_message);

    let err = public_group
        .stage_app_data_commit(observer_provider.crypto(), *unresolved_commit, None)
        .expect_err("staging without updates should fail");

    assert!(matches!(
        err,
        StageCommitError::ApplyAppDataUpdateError(ApplyAppDataUpdateError::MissingAppDataUpdates)
    ));
}

/// A commit without AppDataUpdate proposals is returned by a `PublicGroup` as a
/// regular `StagedCommitMessage`, not as `UnresolvedAppDataCommit`.
#[openmls_test]
fn test_public_group_plain_commit_not_unresolved() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let observer_provider = Provider::default();

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, _bob] = group_state.members_mut(&["alice", "bob"]);

    let mut public_group = build_public_group(alice, &alice_party.provider, &observer_provider);

    let commit_message = alice
        .group
        .commit_builder()
        .force_self_update(true)
        .load_psks(alice_party.provider.storage())
        .unwrap()
        .build(
            alice_party.provider.rand(),
            alice_party.provider.crypto(),
            &alice.party.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&alice_party.provider)
        .unwrap()
        .into_contents()
        .0;

    let processed_message = public_group
        .process_message(
            observer_provider.crypto(),
            to_protocol_message(commit_message),
        )
        .unwrap();

    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => staged_commit,
        _ => panic!("Expected a plain staged commit message"),
    };

    public_group
        .merge_commit(observer_provider.storage(), *staged_commit)
        .unwrap();
}

/// `MlsGroup::resolve_app_data_commit` stages an unresolved app data commit
/// and returns the same message with regular `StagedCommitMessage` content,
/// preserving the message envelope (sender, credential).
#[openmls_test]
fn test_resolve_app_data_commit() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    let commit_message = alice_app_data_commit(
        alice,
        &alice_party.provider,
        0xf042,
        b"proposal_payload",
        b"caller_computed_value",
    );

    let processed_message = bob
        .group
        .process_message(&bob_party.provider, to_protocol_message(commit_message))
        .unwrap();
    let sender = processed_message.sender().clone();
    let credential = processed_message.credential().clone();

    let mut bob_updater = bob.group.app_data_dictionary_updater();
    bob_updater.set(ComponentData::from_parts(
        0xf042,
        b"caller_computed_value".to_vec().into(),
    ));
    let resolved_message = bob
        .group
        .resolve_app_data_commit(
            &bob_party.provider,
            processed_message,
            bob_updater.changes(),
        )
        .expect("error resolving commit");

    // The envelope is preserved ...
    assert_eq!(resolved_message.sender(), &sender);
    assert_eq!(resolved_message.credential(), &credential);

    // ... and the content is now a regular staged commit carrying the
    // caller-computed dictionary value.
    let staged_commit = match resolved_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => staged_commit,
        other => panic!("expected a staged commit message, got {other:?}"),
    };
    let dictionary = staged_commit
        .group_context()
        .extensions()
        .app_data_dictionary()
        .unwrap()
        .dictionary();
    assert_eq!(
        dictionary.get(&0xf042),
        Some(b"caller_computed_value".as_ref())
    );

    bob.group
        .merge_staged_commit(&bob_party.provider, *staged_commit)
        .unwrap();
    alice
        .group
        .merge_pending_commit(&alice_party.provider)
        .unwrap();
    assert_eq!(
        alice.group.extensions().app_data_dictionary(),
        bob.group.extensions().app_data_dictionary()
    );
}

/// Resolving a message that does not carry an unresolved app data commit
/// fails with `NotAnUnresolvedAppDataCommit`.
#[openmls_test]
fn test_resolve_app_data_commit_wrong_content() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // A plain self-update commit without AppDataUpdate proposals.
    let commit_message = alice
        .group
        .commit_builder()
        .force_self_update(true)
        .load_psks(alice_party.provider.storage())
        .unwrap()
        .build(
            alice_party.provider.rand(),
            alice_party.provider.crypto(),
            &alice.party.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&alice_party.provider)
        .unwrap()
        .into_contents()
        .0;

    let processed_message = bob
        .group
        .process_message(&bob_party.provider, to_protocol_message(commit_message))
        .unwrap();

    let err = bob
        .group
        .resolve_app_data_commit(&bob_party.provider, processed_message, None)
        .expect_err("resolving a plain commit should fail");
    assert!(matches!(
        err,
        ResolveAppDataCommitError::NotAnUnresolvedAppDataCommit
    ));
}

/// `PublicGroup::resolve_app_data_commit` mirrors the `MlsGroup` variant.
#[openmls_test]
fn test_public_group_resolve_app_data_commit() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let observer_provider = Provider::default();

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, _bob] = group_state.members_mut(&["alice", "bob"]);

    let mut public_group = build_public_group(alice, &alice_party.provider, &observer_provider);

    let commit_message = alice_app_data_commit(
        alice,
        &alice_party.provider,
        0xf042,
        b"proposal_payload",
        b"caller_computed_value",
    );

    let processed_message = public_group
        .process_message(
            observer_provider.crypto(),
            to_protocol_message(commit_message),
        )
        .unwrap();

    let mut updater = public_group.app_data_dictionary_updater();
    updater.set(ComponentData::from_parts(
        0xf042,
        b"caller_computed_value".to_vec().into(),
    ));
    let resolved_message = public_group
        .resolve_app_data_commit(
            observer_provider.crypto(),
            processed_message,
            updater.changes(),
        )
        .expect("error resolving commit");

    let staged_commit = match resolved_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => staged_commit,
        other => panic!("expected a staged commit message, got {other:?}"),
    };
    let dictionary = staged_commit
        .group_context()
        .extensions()
        .app_data_dictionary()
        .unwrap()
        .dictionary();
    assert_eq!(
        dictionary.get(&0xf042),
        Some(b"caller_computed_value".as_ref())
    );

    public_group
        .merge_commit(observer_provider.storage(), *staged_commit)
        .unwrap();
}
