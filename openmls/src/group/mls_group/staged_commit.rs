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
        let mut provisional_tree = self.tree.borrow_mut();
        // FIXME: #424 this is a copy of the nodes in the tree to reset the original state.
        let original_nodes = provisional_tree.nodes.clone();
        let apply_proposals_values = provisional_tree
            .apply_staged_proposals(backend, &proposal_queue, own_key_packages)
            .map_err(|_| StageCommitError::OwnKeyNotFound)?;

        // Check if we were removed from the group
        if apply_proposals_values.self_removed {
            return Err(StageCommitError::SelfRemoved.into());
        }

        // Determine if Commit is own Commit
        let sender = mls_plaintext.sender_index();
        let is_own_commit = sender == provisional_tree.own_node_index();

        let zero_commit_secret = CommitSecret::zero_secret(ciphersuite, self.mls_version);
        // Determine if Commit has a path
        let commit_secret = if let Some(path) = commit.path.clone() {
            // Verify KeyPackage and MlsPlaintext membership tag
            // Note that the signature must have been verified already.
            // TODO #106: Support external members
            let kp = &path.leaf_key_package;
            if kp.verify(backend).is_err() {
                return Err(StageCommitError::PathKeyPackageVerificationFailure.into());
            }
            let serialized_context = self.group_context.tls_serialize_detached()?;

            if is_own_commit {
                // Find the right KeyPackageBundle among the pending bundles and
                // clone out the one that we need.
                let own_kpb = own_key_packages
                    .iter()
                    .find(|kpb| kpb.key_package() == kp)
                    .ok_or(StageCommitError::MissingOwnKeyPackage)?;
                // We can unwrap here, because we know there was a path and thus
                // a new commit secret must have been set.
                provisional_tree
                    .replace_private_tree(backend, own_kpb, &serialized_context)
                    .unwrap()
            } else {
                // Collect the new leaves' indexes so we can filter them out in the resolution
                // later.
                provisional_tree
                    .update_path(
                        backend,
                        sender,
                        &path,
                        &serialized_context,
                        apply_proposals_values.exclusion_list(),
                    )
                    .map_err(|e| {
                        MlsGroupError::StageCommitError(StageCommitError::DecryptionFailure(e))
                    })?
            }
        } else {
            if apply_proposals_values.path_required {
                return Err(StageCommitError::RequiredPathNotFound.into());
            }
            &zero_commit_secret
        };

        let joiner_secret = JoinerSecret::new(
            backend,
            commit_secret,
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

        let provisional_group_context = GroupContext::new(
            self.group_context.group_id.clone(),
            provisional_epoch,
            provisional_tree.tree_hash(backend),
            confirmed_transcript_hash.clone(),
            self.group_context.extensions(),
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
            // FIXME: reset nodes. This should get fixed with the tree rewrite.
            provisional_tree.nodes = original_nodes;
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", received_confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", own_confirmation_tag);
            return Err(StageCommitError::ConfirmationTagMismatch.into());
        }

        // Verify KeyPackage extensions
        if let Some(path) = &commit.path {
            if !is_own_commit {
                let parent_hash = provisional_tree.set_parent_hashes(backend, sender);
                if let Some(received_parent_hash) = path
                    .leaf_key_package
                    .extension_with_type(ExtensionType::ParentHash)
                {
                    let parent_hash_extension =
                        match received_parent_hash.as_parent_hash_extension() {
                            Ok(phe) => phe,
                            Err(_) => return Err(StageCommitError::NoParentHashExtension.into()),
                        };
                    if parent_hash != parent_hash_extension.parent_hash() {
                        return Err(StageCommitError::ParentHashMismatch.into());
                    }
                } else {
                    return Err(StageCommitError::NoParentHashExtension.into());
                }
            }
        }

        // Create a secret_tree, consuming the `encryption_secret` in the
        // process.
        let secret_tree = provisional_epoch_secrets
            .encryption_secret()
            .create_secret_tree(provisional_tree.leaf_count());

        Ok(StagedCommit {
            staged_proposal_queue: proposal_queue,
            group_context: provisional_group_context,
            epoch_secrets: provisional_epoch_secrets,
            interim_transcript_hash,
            secret_tree: RefCell::new(secret_tree),
            original_nodes,
        })
    }

    /// Merges a [`StagedCommit`] into the group state.
    pub fn merge_commit(&mut self, staged_commit: StagedCommit) {
        self.group_context = staged_commit.group_context;
        self.epoch_secrets = staged_commit.epoch_secrets;
        self.interim_transcript_hash = staged_commit.interim_transcript_hash;
        self.secret_tree = staged_commit.secret_tree;
    }

    /// This is temporary and will disappear when #424 is addressed.
    /// This is just here for completeness but won't be used anywhere.
    /// Rolls back the public tree nodes in case a Commit contained undesired proposals.
    pub fn cancel_commit(&mut self, staged_commit: StagedCommit) {
        let mut tree = self.tree.borrow_mut();
        tree.nodes = staged_commit.original_nodes;
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
    original_nodes: Vec<Node>,
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
