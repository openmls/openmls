use super::*;

impl PublicGroup {
    /// Stores the [`PublicGroup`] to storage for a migration. Called from methods creating a new group and mutating an
    /// existing group, both inside [`PublicGroup`] and in [`MlsGroup`].
    ///
    /// [`MlsGroup`]: crate::group::MlsGroup
    pub(crate) fn store_for_migration<Storage: PublicStorageProvider>(
        &self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        let group_id = self.group_context.group_id();
        storage.write_tree(group_id, self.treesync())?;
        storage.write_confirmation_tag(group_id, self.confirmation_tag())?;
        storage.write_context(group_id, self.group_context())?;
        storage.write_interim_transcript_hash(
            group_id,
            &InterimTranscriptHash(self.interim_transcript_hash.clone()),
        )?;

        // clear the proposal queue from storage, then rewrite the proposals
        // one-by-one into the store.
        storage.clear_proposal_queue::<GroupId, ProposalRef>(group_id)?;
        for proposal in self.proposal_store.proposals() {
            storage.queue_proposal(group_id, &proposal.proposal_reference(), proposal)?;
        }

        Ok(())
    }
}
