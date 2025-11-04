use std::collections::BTreeSet;

use crate::{
    component::ComponentId,
    extensions::{AppDataDictionaryExtension, ComponentId},
    group::{
        extensions::{AppDataDictionaryExtension, ComponentId},
        mls_group::staged_commit::StagedCommitState,
        proposal_store::{ProposalQueue, QueuedAppEphemeralProposal},
        staged_commit::StagedCommitState,
    },
    messages::proposals::ProposalType,
};

impl StagedCommitState {
    /// Return a mutable reference to the [`AppDataDictionaryExtension`], if it exists
    pub fn app_data_dictionary_mut(&mut self) -> Option<&mut AppDataDictionaryExtension> {
        self.group_context_mut()
            .extensions_mut()
            .app_data_dictionary_mut()
    }
    /// Return a reference to the [`AppDataDictionaryExtension`], if it exists
    pub fn app_data_dictionary(&self) -> Option<&AppDataDictionaryExtension> {
        self.group_context().extensions().app_data_dictionary()
    }
}

impl ProposalQueue {
    /// Return an iterator over the [`QueuedAppEphemeralProposal`]s in the proposal queue,
    /// in the order they appear in the commit.
    pub fn app_ephemeral_proposals_for_component_id(
        &self,
        component_id: ComponentId,
    ) -> impl Iterator<Item = QueuedAppEphemeralProposal<'_>> {
        self.app_ephemeral_proposals()
            .filter(move |p| p.app_ephemeral_proposal().component_id() == component_id)
    }

    /// Return the list of all [`ComponentId`]s available across all
    /// [`QueuedAppEphemeralProposal`]s in the proposal queue, ordered by [`ComponentId`].
    pub fn unique_component_ids_for_app_ephemeral(&self) -> Vec<ComponentId> {
        // sort and deduplicate
        let ids: BTreeSet<_> = self
            .app_ephemeral_proposals()
            .map(|p| p.app_ephemeral_proposal().component_id())
            .collect();

        ids.into_iter().collect()
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::{
        prelude::*, test_utils::single_group_test_framework::*,
        test_utils::storage_state::GroupStorageState, *,
    };
    use openmls_test::openmls_test;

    /// Test AppEphemeral proposal handling.
    #[openmls_test]
    fn test_app_ephemeral() {
        // Set up Alice group
        let alice_party = CorePartyState::<Provider>::new("alice");
        let bob_party = CorePartyState::<Provider>::new("bob");

        let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
        let bob_pre_group = bob_party.generate_pre_group(ciphersuite);

        let group_id = GroupId::from_slice(b"Test Group");

        // Define the AppDataDictionary
        let dictionary = AppDataDictionary::builder()
            .with_entry(1, b"component data")
            .build();

        let dictionary_extension = AppDataDictionaryExtension::new(dictionary);

        // Define the MlsGroup configuration
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .with_group_context_extensions(Extensions::single(Extension::AppDataDictionary(
                dictionary_extension,
            )))
            .unwrap()
            .build();
        let mls_group_join_config = mls_group_create_config.join_config().clone();

        let mut group_state =
            GroupState::new_from_party(group_id.clone(), alice_pre_group, mls_group_create_config)
                .unwrap();
        // Generate KeyPackages
        let bob_key_package = bob_pre_group.key_package_bundle.key_package().clone();

        group_state
            .add_member(AddMemberConfig {
                adder: "alice",
                addees: vec![bob_pre_group],
                join_config: mls_group_join_config,
                tree: None,
            })
            .unwrap();

        let [alice, bob] = group_state.members_mut(&["alice", "bob"]);

        let message_bundle = alice
            .group
            .commit_builder()
            .add_proposals(vec![Proposal::AppEphemeral(Box::new(
                AppEphemeralProposal {
                    component_id: 1,
                    data: b"data".into(),
                },
            ))])
            .load_psks(alice_party.provider.storage())
            .expect("error loading psks")
            .build(
                alice_party.provider.rand(),
                alice_party.provider.crypto(),
                &alice.party.signer,
                |_| true,
            )
            .expect("error validating data and building commit")
            .stage_commit(&alice_party.provider)
            .expect("error staging commit");

        let alice_pending_commit = alice.group.pending_commit().expect("no pending commit");

        // ensure that the number of AppEphemeral proposals for the component id 1 is correct
        assert_eq!(
            alice_pending_commit
                .staged_proposal_queue
                .app_ephemeral_proposals_for_component_id(1)
                .count(),
            1
        );

        // handle proposals on Alice's side
        for queued_proposal in alice_pending_commit
            .staged_proposal_queue
            .app_ephemeral_proposals_for_component_id(1)
        {
            let AppEphemeralProposal { data, .. } = queued_proposal.app_ephemeral_proposal();
            // retrieve the component from the dictonary
            let _component = alice_pending_commit
                .state
                .app_data_dictionary()
                .unwrap()
                .dictionary()
                .get(1)
                .unwrap();

            // apply component to data here...
        }

        // handle proposals on Bob's side
        let (mls_message_out, _, _) = message_bundle.into_contents();

        let protocol_message = MlsMessageIn::from(mls_message_out)
            .try_into_protocol_message()
            .unwrap();

        let processed_message = bob
            .group
            .process_message(&bob_party.provider, protocol_message)
            .expect("could not process message");

        let bob_staged_commit = match processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => commit,
            _ => panic!("incorrect message type"),
        };

        // ensure that the number of AppEphemeral proposals for the component id 1 is correct
        assert_eq!(
            bob_staged_commit
                .staged_proposal_queue
                .app_ephemeral_proposals_for_component_id(1)
                .count(),
            1
        );

        // handle proposals on Bob's side
        for queued_proposal in bob_staged_commit
            .staged_proposal_queue
            .app_ephemeral_proposals_for_component_id(1)
        {
            let AppEphemeralProposal { data, .. } = queued_proposal.app_ephemeral_proposal();

            // retrieve the component from the dictonary
            let _component = bob_staged_commit
                .state
                .app_data_dictionary()
                .unwrap()
                .dictionary()
                .get(1)
                .unwrap();

            // apply component to data here...
        }
    }
}
