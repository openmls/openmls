use std::collections::BTreeSet;

use crate::{
    component::ComponentId,
    group::proposal_store::{ProposalQueue, QueuedAppEphemeralProposal},
};

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

    /// Return the list of all [`ComponentIds`] available across all
    /// [`QueuedAppEphemeralProposal`]s in the proposal queue.
    pub fn unique_component_ids_for_app_ephemeral(&self) -> impl Iterator<Item = ComponentId> {
        let ids: BTreeSet<_> = self
            .app_ephemeral_proposals()
            .map(|p| p.app_ephemeral_proposal().component_id())
            .collect();

        ids.into_iter()
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

        // Define the MlsGroup configuration
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .build();
        let mls_group_join_config = mls_group_create_config.join_config().clone();

        let mut group_state =
            GroupState::new_from_party(group_id.clone(), alice_pre_group, mls_group_create_config)
                .unwrap();

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

        // Inspect the component ids for all AppEphemeral proposals in the commit
        let component_ids = alice_pending_commit
            .staged_proposal_queue
            .unique_component_ids_for_app_ephemeral();
        assert_eq!(component_ids.collect::<Vec<_>>(), vec![1]);

        // handle proposals on Alice's side
        for queued_proposal in alice_pending_commit
            .staged_proposal_queue
            .app_ephemeral_proposals_for_component_id(1)
        {
            let AppEphemeralProposal { data, .. } = queued_proposal.app_ephemeral_proposal();

            // handle data here...
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

        // Inspect the component ids for all AppEphemeral proposals in the commit
        let component_ids = bob_staged_commit
            .staged_proposal_queue
            .unique_component_ids_for_app_ephemeral();
        assert_eq!(component_ids.collect::<Vec<_>>(), vec![1]);

        // handle proposals on Bob's side
        for queued_proposal in bob_staged_commit
            .staged_proposal_queue
            .app_ephemeral_proposals_for_component_id(1)
        {
            let AppEphemeralProposal { data, .. } = queued_proposal.app_ephemeral_proposal();

            // handle data here...
        }
    }
}
