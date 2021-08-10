use crate::extensions::*;
use crate::framing::*;
use crate::group::mls_group::*;
use crate::group::*;
use crate::key_packages::*;
use crate::schedule::CommitSecret;

impl MlsGroup {
    pub(crate) fn apply_commit_internal(
        &mut self,
        mls_plaintext: &MlsPlaintext,
        proposals_by_reference: &[&MlsPlaintext],
        own_key_packages: &[KeyPackageBundle],
        psk_fetcher_option: Option<PskFetcher>,
    ) -> Result<(), ApplyCommitError> {
        let ciphersuite = self.ciphersuite();

        // Verify epoch
        if mls_plaintext.epoch() != &self.group_context.epoch {
            return Err(ApplyCommitError::EpochMismatch);
        }

        // Extract Commit & Confirmation Tag from MlsPlaintext
        let commit = match mls_plaintext.content() {
            MlsPlaintextContent::Commit(commit) => commit,
            _ => return Err(ApplyCommitError::WrongPlaintextContentType),
        };

        let received_confirmation_tag = mls_plaintext
            .confirmation_tag()
            .ok_or(ApplyCommitError::ConfirmationTagMissing)?;

        // Build a queue with all proposals from the Commit and check that we have all
        // of the proposals by reference locally
        let proposal_queue = match ProposalQueue::from_committed_proposals(
            ciphersuite,
            commit.proposals.as_slice(),
            proposals_by_reference,
            *mls_plaintext.sender(),
        ) {
            Ok(proposal_queue) => proposal_queue,
            Err(_) => return Err(ApplyCommitError::MissingProposal),
        };

        // Create provisional tree and apply proposals
        let mut provisional_tree = self.tree.borrow_mut();
        // FIXME: #424 this is a copy of the nodes in the tree to reset the original state.
        let original_nodes = provisional_tree.nodes.clone();
        let apply_proposals_values =
            match provisional_tree.apply_proposals(proposal_queue, own_key_packages) {
                Ok(res) => res,
                Err(_) => return Err(ApplyCommitError::OwnKeyNotFound),
            };

        // Check if we were removed from the group
        if apply_proposals_values.self_removed {
            return Err(ApplyCommitError::SelfRemoved);
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
            if kp.verify().is_err() {
                return Err(ApplyCommitError::PathKeyPackageVerificationFailure);
            }
            let serialized_context = self.group_context.tls_serialize_detached()?;

            if is_own_commit {
                // Find the right KeyPackageBundle among the pending bundles and
                // clone out the one that we need.
                let own_kpb = match own_key_packages.iter().find(|kpb| kpb.key_package() == kp) {
                    Some(kpb) => kpb,
                    None => return Err(ApplyCommitError::MissingOwnKeyPackage),
                };
                // We can unwrap here, because we know there was a path and thus
                // a new commit secret must have been set.
                provisional_tree
                    .replace_private_tree(own_kpb, &serialized_context)
                    .unwrap()
            } else {
                // Collect the new leaves' indexes so we can filter them out in the resolution
                // later.
                provisional_tree.update_path(
                    sender,
                    &path,
                    &serialized_context,
                    apply_proposals_values.exclusion_list(),
                )?
            }
        } else {
            if apply_proposals_values.path_required {
                return Err(ApplyCommitError::RequiredPathNotFound);
            }
            &zero_commit_secret
        };

        let joiner_secret = JoinerSecret::new(
            commit_secret,
            self.epoch_secrets
                .init_secret()
                .ok_or(ApplyCommitError::InitSecretNotFound)?,
        );

        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch;
        provisional_epoch.increment();

        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            ciphersuite,
            // It is ok to use `unwrap()` here, because we know the MlsPlaintext contains a Commit
            &MlsPlaintextCommitContent::try_from(mls_plaintext).unwrap(),
            &self.interim_transcript_hash,
        )?;

        // TODO #186: Implement extensions
        let extensions: Vec<Extension> = Vec::new();

        let provisional_group_context = GroupContext::new(
            self.group_context.group_id.clone(),
            provisional_epoch,
            provisional_tree.tree_hash(),
            confirmed_transcript_hash.clone(),
            &extensions,
        )?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(
            ciphersuite,
            joiner_secret,
            psk_output(
                ciphersuite,
                psk_fetcher_option,
                &apply_proposals_values.presharedkeys,
            )?,
        );
        key_schedule.add_context(&provisional_group_context)?;
        let provisional_epoch_secrets = key_schedule.epoch_secrets(true)?;

        let mls_plaintext_commit_auth_data = MlsPlaintextCommitAuthData::try_from(mls_plaintext)
            .map_err(|_| {
                log::error!("Confirmation tag is missing in commit. This should be unreachable because we verified the tag before.");
                ApplyCommitError::ConfirmationTagMissing
            })?;

        let interim_transcript_hash = update_interim_transcript_hash(
            ciphersuite,
            &mls_plaintext_commit_auth_data,
            &confirmed_transcript_hash,
        )?;

        // Verify confirmation tag
        let own_confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(&confirmed_transcript_hash);
        if &own_confirmation_tag != received_confirmation_tag {
            // FIXME: reset nodes. This should get fixed with the tree rewrite.
            provisional_tree.nodes = original_nodes;
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", received_confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", own_confirmation_tag);
            return Err(ApplyCommitError::ConfirmationTagMismatch);
        }

        // Verify KeyPackage extensions
        if let Some(path) = &commit.path {
            if !is_own_commit {
                let parent_hash = provisional_tree.set_parent_hashes(sender);
                if let Some(received_parent_hash) = path
                    .leaf_key_package
                    .extension_with_type(ExtensionType::ParentHash)
                {
                    let parent_hash_extension =
                        match received_parent_hash.as_parent_hash_extension() {
                            Ok(phe) => phe,
                            Err(_) => return Err(ApplyCommitError::NoParentHashExtension),
                        };
                    if parent_hash != parent_hash_extension.parent_hash() {
                        return Err(ApplyCommitError::ParentHashMismatch);
                    }
                } else {
                    return Err(ApplyCommitError::NoParentHashExtension);
                }
            }
        }

        // Create a secret_tree, consuming the `encryption_secret` in the
        // process.
        let secret_tree = provisional_epoch_secrets
            .encryption_secret()
            .create_secret_tree(provisional_tree.leaf_count());

        // Apply provisional tree and state to group
        self.group_context = provisional_group_context;
        self.epoch_secrets = provisional_epoch_secrets;
        self.interim_transcript_hash = interim_transcript_hash;
        self.secret_tree = RefCell::new(secret_tree);
        Ok(())
    }
}
