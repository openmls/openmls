//! # Working with AppData
//!
//! This test file contains code examples for the OpenMLS book chapter on AppData.
//! The examples demonstrate how to use AppDataUpdate proposals to efficiently
//! update application state in an MLS group.

#![cfg(feature = "extensions-draft-08")]

use openmls::prelude::*;
use openmls::test_utils::single_group_test_framework::*;
use openmls_test::openmls_test;

// ANCHOR: component_definition
/// Our counter component ID (in the private range 0x8000..0xffff)
const COUNTER_COMPONENT_ID: u16 = 0xf042;

/// The operations that can be performed on the counter
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CounterOperation {
    Increment = 0x01,
    Decrement = 0x02,
}

impl CounterOperation {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(CounterOperation::Increment),
            0x02 => Some(CounterOperation::Decrement),
            _ => None,
        }
    }

    fn to_bytes(self) -> Vec<u8> {
        vec![self as u8]
    }
}

/// Error type for counter operations
#[derive(Debug, Clone, PartialEq, Eq)]
enum CounterError {
    /// Attempted to decrement below zero
    Underflow,
    /// Invalid operation byte
    InvalidOperation,
}

/// Process a list of counter updates, returning the new counter value.
///
/// - `current_value`: The current counter value (None if not yet set)
/// - `updates`: Iterator of update payloads (each is a single byte)
///
/// Returns the new counter value, or an error if the updates are invalid.
fn process_counter_updates<'a>(
    current_value: Option<&[u8]>,
    updates: impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, CounterError> {
    // Parse current value as big-endian u32, defaulting to 0
    let mut counter: u32 = current_value
        .map(|bytes| {
            let arr: [u8; 4] = bytes.try_into().unwrap_or([0; 4]);
            u32::from_be_bytes(arr)
        })
        .unwrap_or(0);

    // Apply each update
    for update in updates {
        let op_byte = update.first().ok_or(CounterError::InvalidOperation)?;
        let op = CounterOperation::from_byte(*op_byte).ok_or(CounterError::InvalidOperation)?;

        match op {
            CounterOperation::Increment => {
                counter = counter.saturating_add(1);
            }
            CounterOperation::Decrement => {
                counter = counter.checked_sub(1).ok_or(CounterError::Underflow)?;
            }
        }
    }

    Ok(counter.to_be_bytes().to_vec())
}
// ANCHOR_END: component_definition

// ANCHOR: group_setup
/// Set up a group with AppDataUpdate support.
///
/// This creates Alice and Bob with the required capabilities and creates
/// a group where AppDataUpdate proposals are supported.
fn setup_group_with_app_data_support<'a, Provider: OpenMlsProvider>(
    alice_party: &'a CorePartyState<Provider>,
    bob_party: &'a CorePartyState<Provider>,
    ciphersuite: Ciphersuite,
) -> GroupState<'a, Provider> {
    // Define capabilities that include AppDataDictionary extension
    // and AppDataUpdate proposal support
    let capabilities = Capabilities::new(
        None, // protocol versions (default)
        None, // ciphersuites (default)
        Some(&[ExtensionType::AppDataDictionary]),
        Some(&[ProposalType::AppDataUpdate]),
        None, // credentials (default)
    );

    // The group context must require these capabilities so that
    // all members are guaranteed to support them
    let required_capabilities_extension =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::AppDataDictionary], // required extensions
            &[ProposalType::AppDataUpdate],      // required proposals
            &[],                                 // required credentials
        ));

    // Create pre-group states with the capabilities
    let alice_pre_group = alice_party
        .pre_group_builder(ciphersuite)
        .with_leaf_node_capabilities(capabilities.clone())
        .build();

    let bob_pre_group = bob_party
        .pre_group_builder(ciphersuite)
        .with_leaf_node_capabilities(capabilities.clone())
        .build();

    // Configure the group with required capabilities
    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .capabilities(capabilities)
        .use_ratchet_tree_extension(true)
        .with_group_context_extensions(
            Extensions::single(required_capabilities_extension).expect("valid extensions"),
        )
        .build();

    let join_config = create_config.join_config().clone();

    // Alice creates the group
    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"CounterGroup"),
        alice_pre_group,
        create_config,
    )
    .expect("failed to create group");

    // Alice adds Bob
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config,
            tree: None,
        })
        .expect("failed to add Bob");

    group_state
}
// ANCHOR_END: group_setup

// ANCHOR: helper_process_proposals
/// Helper function to process AppDataUpdate proposals and compute the new dictionary state.
///
/// This iterates over proposals, extracts the updates for our counter component,
/// and computes the new state using our application logic.
fn process_app_data_proposals<'a>(
    updater: &mut AppDataDictionaryUpdater<'a>,
    proposals: impl Iterator<Item = &'a AppDataUpdateProposal>,
) -> Result<(), CounterError> {
    use openmls::component::ComponentData;

    // Collect updates by component ID
    // In a real application, you might handle multiple components here
    let mut counter_updates: Vec<&[u8]> = Vec::new();

    for proposal in proposals {
        if proposal.component_id() != COUNTER_COMPONENT_ID {
            // Skip proposals for other components
            continue;
        }

        match proposal.operation() {
            AppDataUpdateOperation::Update(data) => {
                counter_updates.push(data.as_ref());
            }
            AppDataUpdateOperation::Remove => {
                // For our counter, we treat remove as resetting to 0
                // (In a real app, you might handle this differently)
                updater.remove(&COUNTER_COMPONENT_ID);
                return Ok(());
            }
        }
    }

    if counter_updates.is_empty() {
        return Ok(());
    }

    // Get the current value from the dictionary
    let current_value = updater.old_value(COUNTER_COMPONENT_ID);

    // Compute the new value
    let new_value = process_counter_updates(current_value, counter_updates.into_iter())?;

    // Store the new value
    updater.set(ComponentData::from_parts(
        COUNTER_COMPONENT_ID,
        new_value.into(),
    ));

    Ok(())
}
// ANCHOR_END: helper_process_proposals

#[openmls_test]
fn app_data_update_book_example() {
    // Set up the parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup_group_with_app_data_support(&alice_party, &bob_party, ciphersuite);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // ANCHOR: send_proposal
    // Alice sends a standalone proposal to increment the counter.
    // This proposal will be included in a later commit by reference.
    let (proposal_message, _proposal_ref) = alice
        .group
        .propose_app_data_update(
            &alice_party.provider,
            &alice.party.signer,
            COUNTER_COMPONENT_ID,
            AppDataUpdateOperation::Update(CounterOperation::Increment.to_bytes().into()),
        )
        .expect("failed to create proposal");
    // ANCHOR_END: send_proposal

    // ANCHOR: receive_proposal
    // Bob receives and stores the proposal
    let processed_proposal = bob
        .group
        .process_message(
            &bob_party.provider,
            proposal_message
                .into_protocol_message()
                .expect("failed to convert Proposal MlsMessageOut to ProtocolMessage"),
        )
        .expect("failed to process proposal");

    // Verify it's a proposal and store it
    match processed_proposal.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => {
            bob.group
                .store_pending_proposal(bob_party.provider.storage(), *proposal)
                .expect("failed to store proposal");
        }
        _ => panic!("expected a proposal message"),
    }
    // ANCHOR_END: receive_proposal

    // ANCHOR: create_commit
    // Alice creates a commit that includes:
    // - The previously sent proposal (by reference, from her proposal store)
    // - Two additional increment proposals (inline)
    let mut commit_stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![
            // Two more increments as inline proposals
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
                COUNTER_COMPONENT_ID,
                CounterOperation::Increment.to_bytes(),
            ))),
        ])
        .load_psks(alice_party.provider.storage())
        .expect("failed to load PSKs");

    // Alice must compute the resulting state before building the commit.
    // She iterates over all AppDataUpdate proposals (both from the proposal
    // store and inline proposals).
    let mut alice_updater = commit_stage.app_data_dictionary_updater();

    process_app_data_proposals(&mut alice_updater, commit_stage.app_data_update_proposals())
        .expect("failed to process proposals");

    // Provide the computed changes to the commit builder
    commit_stage.with_app_data_dictionary_updates(alice_updater.changes());

    // Build and stage the commit
    let commit_bundle = commit_stage
        .build(
            alice_party.provider.rand(),
            alice_party.provider.crypto(),
            &alice.party.signer,
            |_proposal| true, // accept all proposals
        )
        .expect("failed to build commit")
        .stage_commit(&alice_party.provider)
        .expect("failed to stage commit");

    let (commit_message, _welcome, _group_info) = commit_bundle.into_contents();
    // ANCHOR_END: create_commit

    // ANCHOR: process_commit
    // Bob receives the commit and must independently compute the same new state.

    // First, unprotect (decrypt) the message
    let commit_in: MlsMessageIn = commit_message.into();
    let unverified_message = bob
        .group
        .unprotect_message(
            &bob_party.provider,
            commit_in
                .into_protocol_message()
                .expect("not a protocol message"),
        )
        .expect("failed to unprotect message");

    // Create an updater for Bob
    let mut bob_updater = bob.group.app_data_dictionary_updater();

    // Get the proposals from the commit
    let committed_proposals = unverified_message
        .committed_proposals()
        .expect("not a commit");

    // Process each proposal, resolving references from the proposal store
    let mut app_data_updates: Vec<AppDataUpdateProposal> = Vec::new();

    for proposal_or_ref in committed_proposals.iter() {
        // Validate and potentially resolve the reference
        let validated = proposal_or_ref
            .clone()
            .validate(
                bob_party.provider.crypto(),
                ciphersuite,
                ProtocolVersion::Mls10,
            )
            .expect("invalid proposal");

        // Resolve to the actual proposal
        let proposal: Box<Proposal> = match validated {
            ProposalOrRef::Proposal(proposal) => proposal,
            ProposalOrRef::Reference(reference) => {
                // Look up the proposal in the proposal store
                bob.group
                    .proposal_store()
                    .proposals()
                    .find(|p| p.proposal_reference_ref() == &*reference)
                    .map(|p| Box::new(p.proposal().clone()))
                    .expect("proposal not found in store")
            }
        };

        // Collect AppDataUpdate proposals for processing
        if let Proposal::AppDataUpdate(app_data_proposal) = *proposal {
            app_data_updates.push(*app_data_proposal);
        }
    }

    // Process the collected proposals
    process_app_data_proposals(&mut bob_updater, app_data_updates.iter())
        .expect("failed to process proposals");

    // Now process the message with the computed updates
    let processed_message = bob
        .group
        .process_unverified_message_with_app_data_updates(
            &bob_party.provider,
            unverified_message,
            bob_updater.changes(),
        )
        .expect("failed to process commit");

    // Extract and merge the staged commit
    let staged_commit = match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => commit,
        _ => panic!("expected a staged commit"),
    };

    bob.group
        .merge_staged_commit(&bob_party.provider, *staged_commit)
        .expect("failed to merge commit");
    // ANCHOR_END: process_commit

    // Alice also merges her pending commit
    alice
        .group
        .merge_pending_commit(&alice_party.provider)
        .expect("failed to merge pending commit");

    // ANCHOR: verify_consistency
    // Both parties should now have identical state
    assert_eq!(
        alice.group.extensions().app_data_dictionary(),
        bob.group.extensions().app_data_dictionary(),
        "dictionaries should match"
    );

    // Verify the counter value is 3 (three increments)
    let alice_dict = alice
        .group
        .extensions()
        .app_data_dictionary()
        .expect("dictionary should exist");

    let counter_bytes = alice_dict
        .dictionary()
        .get(&COUNTER_COMPONENT_ID)
        .expect("counter should exist");

    let counter_value = u32::from_be_bytes(counter_bytes.try_into().expect("invalid length"));
    assert_eq!(counter_value, 2, "counter should be 2 after two increments");
    // ANCHOR_END: verify_consistency
}

#[openmls_test]
fn app_data_update_invalid_decrement() {
    // Set up the parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup_group_with_app_data_support(&alice_party, &bob_party, ciphersuite);

    let [alice, _bob] = group_state.members_mut(&["alice", "bob"]);

    // ANCHOR: invalid_update
    // Alice tries to decrement an unset counter, which should fail.
    let commit_stage = alice
        .group
        .commit_builder()
        .add_proposals(vec![Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::update(
                COUNTER_COMPONENT_ID,
                CounterOperation::Decrement.to_bytes(),
            ),
        ))])
        .load_psks(alice_party.provider.storage())
        .expect("failed to load PSKs");

    let mut alice_updater = commit_stage.app_data_dictionary_updater();

    let proposals: Vec<_> = commit_stage.app_data_update_proposals().collect();

    // This should fail because we can't decrement below zero
    let result = process_app_data_proposals(&mut alice_updater, proposals.into_iter());

    assert_eq!(
        result,
        Err(CounterError::Underflow),
        "decrementing unset counter should fail"
    );

    // Alice should not proceed with the commit since the state is invalid.
    // In a real application, you would handle this error appropriately,
    // perhaps by notifying the user or choosing different proposals.
    // ANCHOR_END: invalid_update
}

#[openmls_test]
fn app_data_update_increment_then_decrement() {
    // Test that increment followed by decrement works correctly
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let mut group_state = setup_group_with_app_data_support(&alice_party, &bob_party, ciphersuite);

    let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

    // First commit: increment twice
    {
        let mut commit_stage = alice
            .group
            .commit_builder()
            .add_proposals(vec![Proposal::AppDataUpdate(Box::new(
                AppDataUpdateProposal::update(
                    COUNTER_COMPONENT_ID,
                    CounterOperation::Increment.to_bytes(),
                ),
            ))])
            .load_psks(alice_party.provider.storage())
            .expect("failed to load PSKs");

        let mut alice_updater = commit_stage.app_data_dictionary_updater();
        let proposals: Vec<_> = commit_stage.app_data_update_proposals().collect();
        process_app_data_proposals(&mut alice_updater, proposals.into_iter())
            .expect("failed to process");
        commit_stage.with_app_data_dictionary_updates(alice_updater.changes());

        let commit_bundle = commit_stage
            .build(
                alice_party.provider.rand(),
                alice_party.provider.crypto(),
                &alice.party.signer,
                |_| true,
            )
            .expect("failed to build")
            .stage_commit(&alice_party.provider)
            .expect("failed to stage");

        let (commit_message, _, _) = commit_bundle.into_contents();

        // Bob processes
        let commit_in: MlsMessageIn = commit_message.into();
        let unverified = bob
            .group
            .unprotect_message(
                &bob_party.provider,
                commit_in.into_protocol_message().unwrap(),
            )
            .unwrap();

        let mut bob_updater = bob.group.app_data_dictionary_updater();
        let committed = unverified.committed_proposals().unwrap();

        let mut updates: Vec<AppDataUpdateProposal> = Vec::new();
        for por in committed.iter() {
            let validated = por
                .clone()
                .validate(
                    bob_party.provider.crypto(),
                    ciphersuite,
                    ProtocolVersion::Mls10,
                )
                .unwrap();
            if let ProposalOrRef::Proposal(p) = validated {
                if let Proposal::AppDataUpdate(u) = *p {
                    updates.push(*u);
                }
            }
        }
        process_app_data_proposals(&mut bob_updater, updates.iter()).unwrap();

        let processed = bob
            .group
            .process_unverified_message_with_app_data_updates(
                &bob_party.provider,
                unverified,
                bob_updater.changes(),
            )
            .unwrap();

        if let ProcessedMessageContent::StagedCommitMessage(sc) = processed.into_content() {
            bob.group
                .merge_staged_commit(&bob_party.provider, *sc)
                .unwrap();
        }
        alice
            .group
            .merge_pending_commit(&alice_party.provider)
            .unwrap();
    }

    // Verify counter is 1
    let dict = alice.group.extensions().app_data_dictionary().unwrap();
    let val = u32::from_be_bytes(
        dict.dictionary()
            .get(&COUNTER_COMPONENT_ID)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(val, 1);

    // Second commit: decrement once (should succeed, counter goes to 0)
    {
        let mut commit_stage = alice
            .group
            .commit_builder()
            .add_proposals(vec![Proposal::AppDataUpdate(Box::new(
                AppDataUpdateProposal::update(
                    COUNTER_COMPONENT_ID,
                    CounterOperation::Decrement.to_bytes(),
                ),
            ))])
            .load_psks(alice_party.provider.storage())
            .expect("failed to load PSKs");

        let mut alice_updater = commit_stage.app_data_dictionary_updater();
        let proposals: Vec<_> = commit_stage.app_data_update_proposals().collect();
        process_app_data_proposals(&mut alice_updater, proposals.into_iter())
            .expect("decrement should succeed");
        commit_stage.with_app_data_dictionary_updates(alice_updater.changes());

        let commit_bundle = commit_stage
            .build(
                alice_party.provider.rand(),
                alice_party.provider.crypto(),
                &alice.party.signer,
                |_| true,
            )
            .expect("failed to build")
            .stage_commit(&alice_party.provider)
            .expect("failed to stage");

        let (commit_message, _, _) = commit_bundle.into_contents();

        // Bob processes
        let commit_in: MlsMessageIn = commit_message.into();
        let unverified = bob
            .group
            .unprotect_message(
                &bob_party.provider,
                commit_in.into_protocol_message().unwrap(),
            )
            .unwrap();

        let mut bob_updater = bob.group.app_data_dictionary_updater();
        let committed = unverified.committed_proposals().unwrap();

        let mut updates: Vec<AppDataUpdateProposal> = Vec::new();
        for por in committed.iter() {
            let validated = por
                .clone()
                .validate(
                    bob_party.provider.crypto(),
                    ciphersuite,
                    ProtocolVersion::Mls10,
                )
                .unwrap();
            if let ProposalOrRef::Proposal(p) = validated {
                if let Proposal::AppDataUpdate(u) = *p {
                    updates.push(*u);
                }
            }
        }
        process_app_data_proposals(&mut bob_updater, updates.iter()).unwrap();

        let processed = bob
            .group
            .process_unverified_message_with_app_data_updates(
                &bob_party.provider,
                unverified,
                bob_updater.changes(),
            )
            .unwrap();

        if let ProcessedMessageContent::StagedCommitMessage(sc) = processed.into_content() {
            bob.group
                .merge_staged_commit(&bob_party.provider, *sc)
                .unwrap();
        }
        alice
            .group
            .merge_pending_commit(&alice_party.provider)
            .unwrap();
    }

    // Verify counter is 1
    let dict = alice.group.extensions().app_data_dictionary().unwrap();
    let val = u32::from_be_bytes(
        dict.dictionary()
            .get(&COUNTER_COMPONENT_ID)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(val, 0);

    // Verify both parties agree
    assert_eq!(
        alice.group.extensions().app_data_dictionary(),
        bob.group.extensions().app_data_dictionary()
    );
}
