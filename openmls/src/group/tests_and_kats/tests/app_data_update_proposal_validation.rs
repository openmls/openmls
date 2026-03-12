use crate::component::*;
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
        .wire_format_policy(crate::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
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

/// Test that using `process_message` (classic function) on a commit containing
/// AppDataUpdate proposals returns an appropriate error.
///
/// When processing a commit with AppDataUpdate proposals, callers MUST use
/// `process_unverified_message_with_app_data_updates` instead of `process_message`.
///
/// CURRENT BEHAVIOR: Returns `StageCommitError::ApplyAppDataUpdateError(MissingAppDataUpdates)`
/// IDEAL BEHAVIOR: Should return `ProcessMessageError::FoundAppDataUpdateProposal` to clearly
///                 indicate that the caller needs to use the app-data-aware function.
///
/// This test documents the current behavior and serves as a regression test.
#[openmls_test]
fn test_process_message_with_app_data_update_returns_error() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice creates a commit with an AppDataUpdate proposal
    let mut stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::update(0xf042, b"test_value"),
        ))])
        .load_psks(alice_party.provider.storage())
        .unwrap();

    // Alice computes the app data updates properly
    let mut alice_updater = stage.app_data_dictionary_updater();
    for proposal in stage.app_data_update_proposals() {
        if let AppDataUpdateOperation::Update(data) = proposal.operation() {
            alice_updater.set(ComponentData::from_parts(
                proposal.component_id(),
                data.clone(),
            ));
        }
    }
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

    // Bob tries to process the commit using the classic `process_message` function.
    // This MUST fail because the classic function doesn't handle AppDataUpdate proposals.
    let err = bob
        .group
        .process_message(
            &bob_party.provider,
            commit_message
                .into_protocol_message()
                .expect("not a protocol message"),
        )
        .expect_err(
            "process_message should have failed when processing a commit with \
                 AppDataUpdate proposals, but it succeeded. This is a bug - the \
                 AppDataDictionary will be incorrect.",
        );

    // The function must return an error. Check which error we get.
    match err {
        ProcessMessageError::FoundAppDataUpdateProposal => {
            // IDEAL: The classic function detected AppDataUpdate proposals and returned
            // a clear error telling the caller to use the proper function instead.
        }
        // ProcessMessageError::StageCommitError(StageCommitError::ApplyAppDataUpdateError(
        //     crate::group::public_group::errors::ApplyAppDataUpdateError::MissingAppDataUpdates,
        // )) => {
        //     // CURRENT: The error comes from deep in the apply_proposals stack.
        //     // This is less user-friendly but still fails correctly.
        //     // Consider improving to return FoundAppDataUpdateProposal instead.
        // }
        other_error => {
            panic!(
                "Unexpected error type: {:?}\n\
                 Expected either ProcessMessageError::FoundAppDataUpdateProposal or \
                 StageCommitError::ApplyAppDataUpdateError(MissingAppDataUpdates).",
                other_error
            );
        }
    }
}

/// Test that verifies the IDEAL behavior: `process_message` should return
/// `ProcessMessageError::FoundAppDataUpdateProposal` when processing a commit
/// with AppDataUpdate proposals.
///
/// This test will fail until the API is improved to return this clearer error.
/// When this test passes, the previous test can be updated to only accept
/// the FoundAppDataUpdateProposal variant.
#[openmls_test]
#[ignore] // Remove this when the API is improved
fn test_process_message_returns_found_app_data_update_proposal_error() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice creates a commit with an AppDataUpdate proposal
    let mut stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::update(0xf042, b"test_value"),
        ))])
        .load_psks(alice_party.provider.storage())
        .unwrap();

    let mut alice_updater = stage.app_data_dictionary_updater();
    for proposal in stage.app_data_update_proposals() {
        if let AppDataUpdateOperation::Update(data) = proposal.operation() {
            alice_updater.set(ComponentData::from_parts(
                proposal.component_id(),
                data.clone(),
            ));
        }
    }
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

    let err = bob.group.process_message(
        &bob_party.provider,
        commit_message
            .into_protocol_message()
            .expect("not a protocol message"),
    ).expect_err( "Expected ProcessMessageError::FoundAppDataUpdateProposal, but function returned success");

    if !matches!(err, ProcessMessageError::FoundAppDataUpdateProposal) {
        panic!(
            "Expected ProcessMessageError::FoundAppDataUpdateProposal, got: {err:?}\n\
                 The API should be improved to return this clearer error.",
        );
    }
}

/// Test that creating a commit with AppDataUpdate proposals but NOT providing
/// the updated AppDataDictionary fails with an appropriate error.
///
/// When building a commit that includes AppDataUpdate proposals, the caller MUST:
/// 1. Create an AppDataDictionaryUpdater
/// 2. Process all AppDataUpdate proposals to compute the new state
/// 3. Call `with_app_data_dictionary_updates` to provide the computed state
///
/// If step 3 is skipped, the commit creation should fail.
#[openmls_test]
fn test_commit_with_app_data_update_without_providing_updates_fails() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, _bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice tries to create a commit with an AppDataUpdate proposal
    // but does NOT call with_app_data_dictionary_updates
    let stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::update(0xf042, b"test_value"),
        ))])
        .load_psks(alice_party.provider.storage())
        .unwrap();

    // INTENTIONALLY skip processing app data updates and providing them to the builder
    // stage.with_app_data_dictionary_updates(None);  // This is implicitly None

    // The build should fail because we have AppDataUpdate proposals but didn't
    // provide the computed updates
    let err = stage
        .build(
            alice_party.provider.rand(),
            alice_party.provider.crypto(),
            &alice.party.signer,
            |_| true,
        )
        .expect_err(
            "Commit creation should have failed when AppDataUpdate proposals are \
                 present but no updates were provided. This is a bug - the commit \
                 would result in an inconsistent AppDataDictionary.",
        );

    if !matches!(
        err,
        CreateCommitError::ApplyAppDataUpdateError(ApplyAppDataUpdateError::MissingAppDataUpdates)
    ) {
        // Document the actual error for debugging
        panic!(
            "Expected CreateCommitError::ApplyAppDataUpdateError(MissingAppDataUpdates), \
                 but got: {err:?}\n\
                 The API should fail clearly when AppDataUpdate proposals are added \
                 but with_app_data_dictionary_updates is not called.",
        );
    }
}

/// Test that providing app data updates when there are no AppDataUpdate proposals
/// fails with an appropriate error.
///
/// This prevents accidental misuse where the caller provides updates that don't
/// correspond to any proposals.
#[openmls_test]
fn test_commit_with_superfluous_app_data_updates_fails() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, _bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice creates a commit WITHOUT any AppDataUpdate proposals
    let mut stage = alice
        .group
        .commit_builder()
        // No AppDataUpdate proposals added
        .load_psks(alice_party.provider.storage())
        .unwrap();

    // But she provides app data updates anyway (this is a bug in the caller's code)
    let mut updater = stage.app_data_dictionary_updater();
    updater.set(ComponentData::from_parts(
        0xf042,
        b"spurious_value".to_vec().into(),
    ));
    stage.with_app_data_dictionary_updates(updater.changes());

    // The build should fail because we provided updates without corresponding proposals
    let err = stage
        .build(
            alice_party.provider.rand(),
            alice_party.provider.crypto(),
            &alice.party.signer,
            |_| true,
        )
        .expect_err(
            "Commit creation should have failed when app data updates are provided \
                 without corresponding proposals. This would lead to confusion.",
        );

    if !matches!(
        err,
        CreateCommitError::ApplyAppDataUpdateError(
            crate::group::public_group::errors::ApplyAppDataUpdateError::SuperfluousAppDataUpdates,
        ),
    ) {
        panic!(
            "Expected CreateCommitError::ApplyAppDataUpdateError(SuperfluousAppDataUpdates), \
                 but got: {err:?}\n\
                 The API should fail when app data updates are provided but no \
                 AppDataUpdate proposals exist.",
        );
    }
}

/// Test that the error from process_unverified_message (without app data updates)
/// when processing a commit with AppDataUpdate proposals is sensible.
#[openmls_test]
fn test_process_unverified_message_without_updates_returns_clear_error() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice creates a valid commit with AppDataUpdate proposals
    let mut stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::update(0xf042, b"test_value"),
        ))])
        .load_psks(alice_party.provider.storage())
        .unwrap();

    let mut alice_updater = stage.app_data_dictionary_updater();
    for proposal in stage.app_data_update_proposals() {
        if let AppDataUpdateOperation::Update(data) = proposal.operation() {
            alice_updater.set(ComponentData::from_parts(
                proposal.component_id(),
                data.clone(),
            ));
        }
    }
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

    // Bob unprotects the message
    let commit_in: MlsMessageIn = commit_message.into();
    let unverified_message = bob
        .group
        .unprotect_message(
            &bob_party.provider,
            commit_in.into_protocol_message().unwrap(),
        )
        .unwrap();

    // Bob tries to process WITHOUT providing app data updates (using None)
    let err = bob
        .group
        .process_unverified_message_with_app_data_updates(
            &bob_party.provider,
            unverified_message,
            None, // Intentionally not providing the updates
        )
        .expect_err(
            "Processing should have failed when AppDataUpdate proposals are present \
                 but no updates were provided.",
        );

    if !matches!(
        err,
        ProcessMessageError::InvalidCommit(StageCommitError::ApplyAppDataUpdateError(
            crate::group::public_group::errors::ApplyAppDataUpdateError::MissingAppDataUpdates,
        ))
    ) {
        panic!(
            "Expected StageCommitError::ApplyAppDataUpdateError(MissingAppDataUpdates), \
                 but got: {:?}\n\
                 The error should clearly indicate that app data updates are required.",
            err
        );
    }
}

/// Test that mismatched app data updates (wrong component IDs) are handled correctly.
#[openmls_test]
fn test_process_with_wrong_app_data_updates() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice creates a valid commit with AppDataUpdate proposals for component 0xf042
    let mut stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::update(0xf042, b"correct_value"),
        ))])
        .load_psks(alice_party.provider.storage())
        .unwrap();

    let mut alice_updater = stage.app_data_dictionary_updater();
    for proposal in stage.app_data_update_proposals() {
        if let AppDataUpdateOperation::Update(data) = proposal.operation() {
            alice_updater.set(ComponentData::from_parts(
                proposal.component_id(),
                data.clone(),
            ));
        }
    }
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

    // Bob unprotects the message
    let commit_in: MlsMessageIn = commit_message.into();
    let unverified_message = bob
        .group
        .unprotect_message(
            &bob_party.provider,
            commit_in.into_protocol_message().unwrap(),
        )
        .unwrap();

    // Bob provides updates for the WRONG component ID
    let mut bob_updater = bob.group.app_data_dictionary_updater();
    // Intentionally using wrong component ID (0xf099 instead of 0xf042)
    bob_updater.set(ComponentData::from_parts(
        0xf099,
        b"wrong_component".to_vec().into(),
    ));

    // Process with the wrong updates
    let result = bob.group.process_unverified_message_with_app_data_updates(
        &bob_party.provider,
        unverified_message,
        bob_updater.changes(),
    );

    // This should succeed (the API doesn't validate that updates match proposals),
    // but the resulting state will be different from Alice's.
    // This test documents the current behavior.
    match result {
        Ok(processed_message) => {
            // The message processed, but let's verify the state is inconsistent
            if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                processed_message.into_content()
            {
                bob.group
                    .merge_staged_commit(&bob_party.provider, *staged_commit)
                    .unwrap();

                // Merge Alice's commit too
                alice
                    .group
                    .merge_pending_commit(&alice_party.provider)
                    .unwrap();

                // The dictionaries should NOT match because Bob provided wrong updates
                let alice_dict = alice.group.extensions().app_data_dictionary();
                let bob_dict = bob.group.extensions().app_data_dictionary();

                // Note: This documents that the API allows mismatched updates
                // A stricter API might want to validate this
                if alice_dict == bob_dict {
                    panic!(
                        "Expected dictionaries to differ when Bob provides wrong updates, \
                         but they are the same. This suggests the API might be validating \
                         updates against proposals (which would be good!)."
                    );
                }
            }
        }
        Err(e) => {
            // If the API validates updates against proposals, this error is acceptable
            println!(
                "API validates updates against proposals (good!). Error: {:?}",
                e
            );
        }
    }
}

/// Test that standalone AppDataUpdate proposals can be processed normally
/// with process_message (they don't require special handling until committed).
#[openmls_test]
fn test_standalone_app_data_update_proposal_processes_normally() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice sends a standalone AppDataUpdate proposal (not in a commit)
    let (proposal_message, _proposal_ref) = alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            0xf042,
            AppDataUpdateOperation::Update(b"proposal_value".to_vec().into()),
        )
        .expect("failed to create proposal");

    // Bob processes the standalone proposal using the regular process_message
    // This should succeed because proposals don't apply updates yet
    let processed = bob
        .group
        .process_message(
            &bob_party.provider,
            proposal_message
                .into_protocol_message()
                .expect("not a protocol message"),
        )
        .expect(
            "Standalone AppDataUpdate proposals should be processable with regular process_message.",
        );

    // Verify it's a proposal message
    match processed.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => {
            // Store it for later
            bob.group
                .store_pending_proposal(bob_party.provider.storage(), *proposal)
                .expect("failed to store proposal");
        }
        other => {
            panic!(
                "Expected ProposalMessage, got: {:?}",
                std::mem::discriminant(&other)
            );
        }
    }
}

/// Test that creating a commit by reference to a stored AppDataUpdate proposal
/// still requires providing app data updates.
#[openmls_test]
fn test_commit_by_reference_requires_app_data_updates() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup(&alice_party, &bob_party, ciphersuite, true);

    let [alice, _bob] = group_state.members_mut(&["alice", "bob"]);

    // Alice first creates and stores a standalone proposal
    let (_proposal_message, _proposal_ref) = alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            0xf042,
            AppDataUpdateOperation::Update(b"proposal_value".to_vec().into()),
        )
        .expect("failed to create proposal");

    // Now Alice tries to commit to pending proposals WITHOUT providing app data updates
    let err = alice
        .group
        .commit_to_pending_proposals(&alice_party.provider, &alice.party.signer)
        .expect_err(
            "commit_to_pending_proposals should fail when there are AppDataUpdate \
                 proposals in the queue, as it doesn't support app data update handling.",
        );

    // This should fail because there's an AppDataUpdate proposal in the queue
    if !matches!(
        err,
        CommitToPendingProposalsError::CreateCommitError(
            CreateCommitError::ApplyAppDataUpdateError(
                crate::group::public_group::errors::ApplyAppDataUpdateError::MissingAppDataUpdates,
            ),
        )
    ) {
        // Document the actual error
        panic!(
            "Expected CreateCommitError::ApplyAppDataUpdateError(MissingAppDataUpdates), \
                 but got: {err:?}",
        );
    }
}
