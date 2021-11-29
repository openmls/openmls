use crate::treesync::diff::StagedTreeSyncDiff;

use super::proposals::{ProposalStore, StagedProposal, StagedProposalQueue};
use super::*;
use core::fmt::Debug;

impl MlsGroup {
    /// Stages a commit message.
    /// This function does the following:
    ///  - Applies the proposals covered by the commit to the tree
    ///  - Applies the (optional) update path to the tree
    ///  - Calculates the path secrets
    ///  - Initializes the key schedule for epoch rollover
    ///  - Verifies the confirmation tag/membership tag
    /// Returns a [StagedCommit] that can be inspected and later merged
    /// into the group state with [merge_commit()]
    pub fn stage_commit(
        &mut self,
        mls_plaintext: &MlsPlaintext,
        proposal_store: &ProposalStore,
        own_key_packages: &[KeyPackageBundle],
        psk_fetcher_option: Option<PskFetcher>,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<StagedCommit, MlsGroupError> {
        let ciphersuite = self.ciphersuite();

        // Verify epoch
        if mls_plaintext.epoch() != self.group_context.epoch {
            log::error!(
                "Epoch mismatch. Got {:?}, expected {:?}",
                mls_plaintext.epoch(),
                self.group_context.epoch
            );
            return Err(StageCommitError::EpochMismatch.into());
        }

        // Extract Commit & Confirmation Tag from MlsPlaintext
        let commit = match mls_plaintext.content() {
            MlsPlaintextContentType::Commit(commit) => commit,
            _ => return Err(StageCommitError::WrongPlaintextContentType.into()),
        };

        let received_confirmation_tag = mls_plaintext
            .confirmation_tag()
            .ok_or(StageCommitError::ConfirmationTagMissing)?;

        // Build a queue with all proposals from the Commit and check that we have all
        // of the proposals by reference locally
        let proposal_queue = StagedProposalQueue::from_committed_proposals(
            ciphersuite,
            backend,
            commit.proposals.as_slice().to_vec(),
            proposal_store,
            *mls_plaintext.sender(),
        )
        .map_err(|_| StageCommitError::MissingProposal)?;

        // Create provisional tree and apply proposals
        let mut diff = self.tree().empty_diff()?;

        let apply_proposals_values = self
            .apply_staged_proposals(&mut diff, backend, &proposal_queue, own_key_packages)
            .map_err(|_| StageCommitError::OwnKeyNotFound)?;

        // Check if we were removed from the group
        if apply_proposals_values.self_removed {
            return Err(StageCommitError::SelfRemoved.into());
        }

        // Determine if Commit is own Commit
        let sender = mls_plaintext.sender_index();
        let is_own_commit = sender == self.tree().own_leaf_index();

        // Determine if Commit has a path
        let commit_secret = if let Some(path) = commit.path.clone() {
            // Verify KeyPackage and MlsPlaintext membership tag
            // Note that the signature must have been verified already.
            // TODO #106: Support external members
            let kp = &path.leaf_key_package();
            if kp.verify(backend).is_err() {
                return Err(StageCommitError::PathKeyPackageVerificationFailure.into());
            }
            let serialized_context = self.group_context.tls_serialize_detached()?;

            if is_own_commit {
                // Find the right KeyPackageBundle among the pending bundles and
                // clone out the one that we need.
                let own_kpb = own_key_packages
                    .iter()
                    .find(|kpb| &kpb.key_package() == kp)
                    .ok_or(StageCommitError::MissingOwnKeyPackage)?;
                // We can unwrap here, because we know there was a path and thus
                // a new commit secret must have been set.
                diff.re_apply_own_update_path(backend, ciphersuite, own_kpb)?
            } else {
                // Decrypt the UpdatePath
                let key_package = path.leaf_key_package();
                let (plain_path, commit_secret) = self.tree().decrypt_path(
                    backend,
                    ciphersuite,
                    &path,
                    sender,
                    &apply_proposals_values.exclusion_list(),
                    &serialized_context,
                )?;

                // Collect the new leaves' indexes so we can filter them out in the resolution
                // later.
                diff.apply_received_update_path(
                    backend,
                    ciphersuite,
                    sender,
                    key_package,
                    plain_path,
                )?;
                commit_secret
            }
        } else {
            if apply_proposals_values.path_required {
                return Err(StageCommitError::RequiredPathNotFound.into());
            }
            CommitSecret::zero_secret(ciphersuite, self.mls_version)
        };

        let joiner_secret = JoinerSecret::new(
            backend,
            &commit_secret,
            self.epoch_secrets
                .init_secret()
                .ok_or(StageCommitError::InitSecretNotFound)?,
        );

        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch;
        provisional_epoch.increment();

        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            ciphersuite,
            backend,
            // It is ok to use `unwrap()` here, because we know the MlsPlaintext contains a Commit
            &MlsPlaintextCommitContent::try_from(mls_plaintext).unwrap(),
            &self.interim_transcript_hash,
        )?;

        // TODO #186: Implement extensions
        let extensions: Vec<Extension> = Vec::new();

        let provisional_group_context = GroupContext::new(
            self.group_context.group_id.clone(),
            provisional_epoch,
            diff.compute_tree_hash(backend, ciphersuite)?,
            confirmed_transcript_hash.clone(),
            &extensions,
        )?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(
            ciphersuite,
            backend,
            joiner_secret,
            psk_output(
                ciphersuite,
                backend,
                psk_fetcher_option,
                &apply_proposals_values.presharedkeys,
            )?,
        );
        key_schedule.add_context(backend, &provisional_group_context)?;
        let provisional_epoch_secrets = key_schedule.epoch_secrets(backend, true)?;

        let mls_plaintext_commit_auth_data = MlsPlaintextCommitAuthData::try_from(mls_plaintext)
            .map_err(|_| {
                log::error!("Confirmation tag is missing in commit. This should be unreachable because we verified the tag before.");
                StageCommitError::ConfirmationTagMissing
            })?;

        let interim_transcript_hash = update_interim_transcript_hash(
            ciphersuite,
            backend,
            &mls_plaintext_commit_auth_data,
            &confirmed_transcript_hash,
        )?;

        // Verify confirmation tag
        let own_confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(backend, &confirmed_transcript_hash);
        if &own_confirmation_tag != received_confirmation_tag {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", received_confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", own_confirmation_tag);
            return Err(StageCommitError::ConfirmationTagMismatch.into());
        }

        // Create a secret_tree, consuming the `encryption_secret` in the
        // process.
        let secret_tree = provisional_epoch_secrets
            .encryption_secret()
            .create_secret_tree(diff.leaf_count());

        // Make the diff a staged diff.
        let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;

        Ok(StagedCommit {
            staged_proposal_queue: proposal_queue,
            group_context: provisional_group_context,
            epoch_secrets: provisional_epoch_secrets,
            interim_transcript_hash,
            secret_tree: RefCell::new(secret_tree),
            staged_diff,
        })
    }

    /// Merges a [`StagedCommit`] into the group state.
    pub fn merge_commit(&mut self, staged_commit: StagedCommit) {
        self.group_context = staged_commit.group_context;
        self.epoch_secrets = staged_commit.epoch_secrets;
        self.interim_transcript_hash = staged_commit.interim_transcript_hash;
        self.secret_tree = staged_commit.secret_tree;
    }
}

/// Contains the changes from a commit to the group state.
#[derive(Debug)]
pub struct StagedCommit {
    staged_proposal_queue: StagedProposalQueue,
    group_context: GroupContext,
    epoch_secrets: EpochSecrets,
    interim_transcript_hash: Vec<u8>,
    secret_tree: RefCell<SecretTree>,
    staged_diff: StagedTreeSyncDiff,
}

impl StagedCommit {
    pub fn adds(&self) -> impl Iterator<Item = &StagedProposal> {
        self.staged_proposal_queue
            .filtered_by_type(ProposalType::Add)
    }
    pub fn removes(&self) -> impl Iterator<Item = &StagedProposal> {
        self.staged_proposal_queue
            .filtered_by_type(ProposalType::Remove)
    }
    pub fn updates(&self) -> impl Iterator<Item = &StagedProposal> {
        self.staged_proposal_queue
            .filtered_by_type(ProposalType::Update)
    }
    pub fn psks(&self) -> impl Iterator<Item = &StagedProposal> {
        self.staged_proposal_queue
            .filtered_by_type(ProposalType::Presharedkey)
    }
}
