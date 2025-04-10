use crate::prelude::{hash_ref::ProposalRef, past_secrets::MessageSecretsStore, *};

use crate::schedule::psk::store::ResumptionPskStore;
use crate::schedule::GroupEpochSecrets;
use crate::treesync::TreeSync;

use openmls_traits::storage::{traits::GroupId, StorageProvider, CURRENT_VERSION};

/// All state associated only with a GroupId
#[derive(PartialEq)]
pub struct NonProposalGroupStorageState {
    own_leaf_nodes: Vec<LeafNode>,
    group_config: Option<MlsGroupJoinConfig>,
    tree: Option<TreeSync>,
    confirmation_tag: Option<ConfirmationTag>,
    group_state: Option<MlsGroupState>,
    context: Option<GroupContext>,
    interim_transcript_hash: Option<Vec<u8>>,
    message_secrets: Option<MessageSecretsStore>,
    resumption_psk_secrets: Option<ResumptionPskStore>,
    own_leaf_index: Option<LeafNodeIndex>,
    group_epoch_secrets: Option<GroupEpochSecrets>,
}

impl NonProposalGroupStorageState {
    pub fn from_storage(
        store: &impl StorageProvider<CURRENT_VERSION>,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> NonProposalGroupStorageState {
        let own_leaf_nodes = store.own_leaf_nodes(group_id).unwrap();

        let group_config = store.mls_group_join_config(group_id).unwrap();

        let tree = store.tree(group_id).unwrap();
        let confirmation_tag = store.confirmation_tag(group_id).unwrap();

        let group_state = store.group_state(group_id).unwrap();

        let context = store.group_context(group_id).unwrap();

        let interim_transcript_hash = store
            .interim_transcript_hash(group_id)
            .unwrap()
            .map(|hash: InterimTranscriptHash| hash.0);

        let message_secrets = store.message_secrets(group_id).unwrap();

        let resumption_psk_secrets = store.resumption_psk_store(group_id).unwrap();
        let own_leaf_index = store.own_leaf_index(group_id).unwrap();

        let group_epoch_secrets = store.group_epoch_secrets(group_id).unwrap();

        Self {
            own_leaf_nodes,
            group_config,
            tree,
            confirmation_tag,
            group_state,
            context,
            interim_transcript_hash,
            message_secrets,
            resumption_psk_secrets,
            own_leaf_index,
            group_epoch_secrets,
        }
    }
}

/// All state associated only with a GroupId
#[derive(PartialEq)]
pub struct GroupStorageState {
    queued_proposals: Vec<(ProposalRef, QueuedProposal)>,
    non_proposal_state: NonProposalGroupStorageState,
}

impl GroupStorageState {
    pub fn non_proposal_state(&self) -> &NonProposalGroupStorageState {
        &self.non_proposal_state
    }
    pub fn from_storage(
        store: &impl StorageProvider<CURRENT_VERSION>,
        group_id: &impl GroupId<CURRENT_VERSION>,
    ) -> GroupStorageState {
        let queued_proposals = store.queued_proposals(group_id).unwrap();
        let non_proposal_state = NonProposalGroupStorageState::from_storage(store, group_id);

        GroupStorageState {
            queued_proposals,
            non_proposal_state,
        }
    }
}
