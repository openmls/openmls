use core_group::proposals::QueuedProposal;

use crate::{
    framing::mls_content::FramedContentBody,
    group::{
        errors::{MergeCommitError, StageCommitError, ValidationError},
        mls_group::errors::ProcessMessageError,
    },
};

use super::{proposals::ProposalStore, *};

impl CoreGroup {    
    /// Helper function to read decryption keypairs.
    pub(crate) fn read_decryption_keypairs(
        &self,
        provider: &impl OpenMlsProvider,
        own_leaf_nodes: &[LeafNode],
    ) -> Result<(Vec<EncryptionKeyPair>, Vec<EncryptionKeyPair>), StageCommitError> {
        // All keys from the previous epoch are potential decryption keypairs.
        let old_epoch_keypairs = self.read_epoch_keypairs(provider.storage());

        // If we are processing an update proposal that originally came from
        // us, the keypair corresponding to the leaf in the update is also a
        // potential decryption keypair.
        let leaf_node_keypairs = own_leaf_nodes
            .iter()
            .map(|leaf_node| {
                EncryptionKeyPair::read(provider, leaf_node.encryption_key())
                    .ok_or(StageCommitError::MissingDecryptionKey)
            })
            .collect::<Result<Vec<EncryptionKeyPair>, StageCommitError>>()?;

        Ok((old_epoch_keypairs, leaf_node_keypairs))
    }

    /// Merge a [StagedCommit] into the group after inspection
    pub(crate) fn merge_staged_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
        proposal_store: &mut ProposalStore,
    ) -> Result<(), MergeCommitError<Provider::StorageError>> {
        // Save the past epoch
        let past_epoch = self.context().epoch();
        // Get all the full leaves
        let leaves = self.public_group().members().collect();
        // Merge the staged commit into the group state and store the secret tree from the
        // previous epoch in the message secrets store.
        if let Some(message_secrets) = self.merge_commit(provider, staged_commit)? {
            self.message_secrets_store
                .add(past_epoch, message_secrets, leaves);
        }
        // Empty the proposal store
        proposal_store.empty();
        Ok(())
    }
}
