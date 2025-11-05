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

    /// Return the list of all [`ComponentId`]s available across all
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

    use crate::{prelude::*, test_utils::single_group_test_framework::*};
    use openmls_test::openmls_test;

    /// Test AppEphemeral proposal handling.
    /// NOTE: The main single_group_test_framework functionality can't be used in this test,
    /// since the capabilities need to be set to include ProposalType::AppEphemeral
    #[openmls_test]
    fn test_app_ephemeral() {
        const COMPONENT_ID: ComponentId = 1;
        let group_id = GroupId::from_slice(b"Test Group");

        let alice_provider = &Provider::default();
        let bob_provider = &Provider::default();

        // Include the AppEphemeral proposal type in the LeafNode capabilities
        let capabilities =
            Capabilities::new(None, None, None, Some(&[ProposalType::AppEphemeral]), None);

        // Define the MlsGroup configuration
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            // add to leaf node capabilities
            .capabilities(capabilities.clone())
            .build();

        // Generate credentials with keys
        let (alice_credential, alice_signer) = generate_credential(
            b"Alice".to_vec(),
            ciphersuite.signature_algorithm(),
            alice_provider,
        );

        let (bob_credential, bob_signer) = generate_credential(
            b"Bob".to_vec(),
            ciphersuite.signature_algorithm(),
            bob_provider,
        );

        // Generate KeyPackage for Bob with the correct LeafNode capabilities
        let bob_key_package = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
            .unwrap();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            alice_provider,
            &alice_signer,
            &mls_group_create_config,
            group_id,
            alice_credential.clone(),
        )
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let welcome = match alice_group.add_members(
            alice_provider,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        ) {
            Ok((_, welcome, _)) => welcome,
            Err(e) => panic!("Could not add member to group: {e:?}"),
        };
        alice_group.merge_pending_commit(alice_provider).unwrap();

        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome
            .into_welcome()
            .expect("expected the message to be a welcome message");

        let mut bob_group = StagedWelcome::new_from_welcome(
            bob_provider,
            mls_group_create_config.join_config(),
            welcome,
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Error creating StagedWelcome from Welcome")
        .into_group(bob_provider)
        .expect("Error creating group from StagedWelcome");

        let message_bundle = alice_group
            .commit_builder()
            .add_proposals(vec![Proposal::AppEphemeral(Box::new(
                AppEphemeralProposal {
                    component_id: COMPONENT_ID,
                    data: b"data".into(),
                },
            ))])
            .load_psks(alice_provider.storage())
            .expect("error loading psks")
            .build(
                alice_provider.rand(),
                alice_provider.crypto(),
                &alice_signer,
                |_| true,
            )
            .expect("error validating data and building commit")
            .stage_commit(alice_provider)
            .expect("error staging commit");

        let alice_pending_commit = alice_group.pending_commit().expect("no pending commit");

        // ensure that the number of AppEphemeral proposals for the component id COMPONENT_ID is correct
        assert_eq!(
            alice_pending_commit
                .staged_proposal_queue
                .app_ephemeral_proposals_for_component_id(COMPONENT_ID)
                .count(),
            1
        );

        // handle proposals on Bob's side
        let (mls_message_out, _, _) = message_bundle.into_contents();

        let protocol_message = MlsMessageIn::from(mls_message_out)
            .try_into_protocol_message()
            .unwrap();

        let processed_message = bob_group
            .process_message(bob_provider, protocol_message)
            .expect("could not process message");

        let bob_staged_commit = match processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => commit,
            _ => panic!("incorrect message type"),
        };

        // ensure that the number of AppEphemeral proposals for the component id COMPONENT_ID is correct
        assert_eq!(
            bob_staged_commit
                .staged_proposal_queue
                .app_ephemeral_proposals_for_component_id(COMPONENT_ID)
                .count(),
            1
        );

        // Inspect the component ids for all AppEphemeral proposals in the commit
        let component_ids = bob_staged_commit
            .staged_proposal_queue
            .unique_component_ids_for_app_ephemeral();
        assert_eq!(component_ids.collect::<Vec<_>>(), vec![COMPONENT_ID]);

        // handle proposals on Bob's side
        for queued_proposal in bob_staged_commit
            .staged_proposal_queue
            .app_ephemeral_proposals_for_component_id(COMPONENT_ID)
        {
            let AppEphemeralProposal { data: _data, .. } = queued_proposal.app_ephemeral_proposal();

            // handle data here...
        }
    }
}
