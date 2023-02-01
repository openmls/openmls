use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    ciphersuite::signable::Signable,
    group::{config::CryptoConfig, core_group::*, errors::CreateCommitError},
    treesync::{
        diff::TreeSyncDiff,
        node::{
            encryption_keys::EncryptionKeyPair, leaf_node::OpenMlsLeafNode,
            parent_node::PlainUpdatePathNode,
        },
        treekem::{PlaintextSecret, UpdatePath},
    },
    versions::ProtocolVersion,
};

use super::{
    create_commit_params::{CommitType, CreateCommitParams},
    proposals::ProposalQueue,
    staged_commit::{MemberStagedCommitState, StagedCommit, StagedCommitState},
};

/// A helper struct which contains the values resulting from the preparation of
/// a commit with path.
#[derive(Default)]
struct PathProcessingResult {
    commit_secret: Option<CommitSecret>,
    encrypted_path: Option<UpdatePath>,
    plain_path: Option<Vec<PlainUpdatePathNode>>,
    new_keypairs: Vec<EncryptionKeyPair>,
}

impl CoreGroup {
    pub(crate) fn create_commit<KeyStore: OpenMlsKeyStore>(
        &self,
        mut params: CreateCommitParams,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
    ) -> Result<CreateCommitResult, CreateCommitError<KeyStore::Error>> {
        let ciphersuite = self.ciphersuite();

        let sender = match params.commit_type() {
            CommitType::External => Sender::NewMemberCommit,
            CommitType::Member => Sender::build_member(self.own_leaf_index()),
        };

        // Filter proposals
        let (proposal_queue, contains_own_updates) = ProposalQueue::filter_proposals(
            ciphersuite,
            backend,
            sender.clone(),
            params.proposal_store(),
            params.inline_proposals(),
            self.own_leaf_index(),
        )
        .map_err(|e| match e {
            crate::group::errors::ProposalQueueError::LibraryError(e) => e.into(),
            crate::group::errors::ProposalQueueError::ProposalNotFound => {
                CreateCommitError::MissingProposal
            }
            crate::group::errors::ProposalQueueError::SenderError(_) => {
                CreateCommitError::WrongProposalSenderType
            }
        })?;

        // TODO: #581 Filter proposals by support
        // 11.2:
        // Proposals with a non-default proposal type MUST NOT be included in a commit
        // unless the proposal type is supported by all the members of the group that
        // will process the Commit (i.e., not including any members being added
        // or removed by the Commit).

        let proposal_reference_list = proposal_queue.commit_list();

        // Make a copy of the current tree to apply proposals safely
        let mut diff: TreeSyncDiff = self.treesync().empty_diff();

        // Validate the proposals by doing the following checks:

        // ValSem101
        // ValSem102
        // ValSem104
        // ValSem106
        self.validate_add_proposals(&proposal_queue)?;
        // ValSem107
        // ValSem108
        self.validate_remove_proposals(&proposal_queue)?;
        // Validate update proposals for member commits
        if let Sender::Member(sender_index) = &sender {
            // ValSem110
            // ValSem111
            // ValSem112
            self.validate_update_proposals(&proposal_queue, *sender_index)?;
        }

        // Apply proposals to tree
        let apply_proposals_values = self
            .apply_proposals(
                &mut diff,
                backend,
                &proposal_queue,
                &[],
                Some(self.own_leaf_index()),
            )
            .map_err(|e| match e {
                crate::group::errors::ApplyProposalsError::LibraryError(e) => {
                    CreateCommitError::LibraryError(e)
                }
                crate::group::errors::ApplyProposalsError::LeafNodeValidation(e) => {
                    CreateCommitError::LeafNodeValidation(e)
                }
            })?;
        if apply_proposals_values.self_removed && params.commit_type() != CommitType::External {
            return Err(CreateCommitError::CannotRemoveSelf);
        }

        // Update keys in the leaf.
        let external_commit_keypair_option = if params.commit_type() == CommitType::External {
            // If this is an external commit we add a fresh leaf to the diff.
            // Generate a KeyPackageBundle to generate a payload from for later
            // path generation.
            let KeyPackageCreationResult {
                key_package,
                encryption_keypair,
                // The KeyPackage is immediately put into the group. No need for
                // the init key.
                init_private_key: _,
            } = KeyPackage::builder().build_without_key_storage(
                CryptoConfig {
                    ciphersuite,
                    version: self.version(),
                },
                backend,
                signer,
                params
                    .take_credential_with_key()
                    .ok_or(CreateCommitError::MissingCredential)?,
            )?;

            let mut leaf_node: OpenMlsLeafNode = key_package.into();
            leaf_node.set_leaf_index(self.own_leaf_index());
            diff.add_leaf(leaf_node)
                .map_err(|_| LibraryError::custom("Tree full: cannot add more members"))?;
            Some(encryption_keypair)
        } else {
            None
        };

        let serialized_group_context = self
            .group_context
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let path_processing_result =
            // If path is needed, compute path values
            if apply_proposals_values.path_required
                || contains_own_updates
                || params.force_self_update()
            {
                let mut new_keypairs = if let Some(encryption_keypair) = external_commit_keypair_option {
                    // If this is an external commit, we need to add the keypair
                    // we generated earlier.
                    vec![encryption_keypair]
                } else {
                    // If we're already in the tree, we rekey our existing leaf.
                    let own_diff_leaf = diff
                        .leaf_mut(self.own_leaf_index())
                        .map_err(|_| LibraryError::custom("Unable to get own leaf from diff"))?;
                    let encryption_keypair = own_diff_leaf.rekey(
                        self.group_id(),
                        self.ciphersuite,
                        ProtocolVersion::default(), // XXX: openmls/openmls#1065
                        backend,
                        signer
                    )?;
                    vec![encryption_keypair]
                };

                // Derive and apply an update path based on the previously
                // generated new leaf.
                let (plain_path, mut new_parent_keypairs, commit_secret) = diff.apply_own_update_path(
                    backend,
                    signer,
                    ciphersuite,
                    self.group_id().clone(),
                    self.own_leaf_index()
                )?;

                new_keypairs.append(&mut new_parent_keypairs);

                // Encrypt the path to the correct recipient nodes.
                let encrypted_path = diff.encrypt_path(
                    backend,
                    self.ciphersuite(),
                    &plain_path,
                    &serialized_group_context,
                    &apply_proposals_values.exclusion_list(),
                    self.own_leaf_index()
                );
                let leaf_node = diff.leaf(self.own_leaf_index()).map_err(|_| LibraryError::custom("Couldn't find own leaf"))?.clone();
                let encrypted_path = UpdatePath::new(leaf_node.into(),  encrypted_path);
                PathProcessingResult {
                    commit_secret: Some(commit_secret),
                    encrypted_path: Some(encrypted_path),
                    plain_path: Some(plain_path),
                    new_keypairs,
                }
            } else {
                // If path is not needed, return empty path processing results
                PathProcessingResult::default()
            };

        let sender = match params.commit_type() {
            CommitType::External => Sender::NewMemberCommit,
            CommitType::Member => Sender::build_member(self.own_leaf_index()),
        };

        // Keep a copy of the update path key package
        let commit_update_leaf_node = path_processing_result
            .encrypted_path
            .as_ref()
            .map(|update| update.leaf_node().clone());

        // Create commit message
        let commit = Commit {
            proposals: proposal_reference_list,
            path: path_processing_result.encrypted_path,
        };

        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch();
        provisional_epoch.increment();

        // Build AuthenticatedContent
        let mut commit = AuthenticatedContent::commit(
            *params.framing_parameters(),
            sender,
            commit,
            self.context(),
            signer,
        )?;

        // Calculate the confirmed transcript hash
        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            ciphersuite,
            backend,
            // It is ok to a library error here, because we know the PublicMessage contains a
            // Commit
            &ConfirmedTranscriptHashInput::try_from(&commit)
                .map_err(|_| LibraryError::custom("PublicMessage did not contain a commit"))?,
            &self.interim_transcript_hash,
        )?;

        // Calculate tree hash
        let tree_hash = diff.compute_tree_hashes(backend, ciphersuite)?;

        // Calculate group context
        let provisional_group_context = GroupContext::new(
            ciphersuite,
            self.group_context.group_id().clone(),
            provisional_epoch,
            tree_hash.clone(),
            confirmed_transcript_hash.clone(),
            self.group_context.extensions().clone(),
        );

        let joiner_secret = JoinerSecret::new(
            backend,
            path_processing_result.commit_secret,
            self.group_epoch_secrets().init_secret(),
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

        // Create group secrets for later use, so we can afterwards consume the
        // `joiner_secret`.
        let plaintext_secrets = PlaintextSecret::from_plain_update_path(
            &diff,
            &joiner_secret,
            apply_proposals_values.invitation_list,
            path_processing_result.plain_path.as_deref(),
            &apply_proposals_values.presharedkeys,
            backend,
            self.own_leaf_index(),
        )?;

        // Prepare the PskSecret
        let psk_secret =
            PskSecret::new(ciphersuite, backend, &apply_proposals_values.presharedkeys)?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(ciphersuite, backend, joiner_secret, psk_secret)?;

        let serialized_provisional_group_context = provisional_group_context
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let welcome_secret = key_schedule
            .welcome(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        key_schedule
            .add_context(backend, &serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        let provisional_epoch_secrets = key_schedule
            .epoch_secrets(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        // Calculate the confirmation tag
        let confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(backend, &confirmed_transcript_hash)
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Set the confirmation tag
        commit.set_confirmation_tag(confirmation_tag.clone());

        // only computes the group info if necessary
        let group_info = if !plaintext_secrets.is_empty() || self.use_ratchet_tree_extension {
            // Create the ratchet tree extension if necessary
            let external_pub = provisional_epoch_secrets
                .external_secret()
                .derive_external_keypair(backend.crypto(), ciphersuite)
                .public;
            let external_pub_extension =
                Extension::ExternalPub(ExternalPubExtension::new(external_pub.into()));
            let other_extensions: Extensions = if self.use_ratchet_tree_extension {
                Extensions::from_vec(vec![
                    Extension::RatchetTree(RatchetTreeExtension::new(diff.export_nodes())),
                    external_pub_extension,
                ])?
            } else {
                Extensions::single(external_pub_extension)
            };

            // Create to-be-signed group info.
            let group_info_tbs = {
                let group_context = GroupContext::new(
                    ciphersuite,
                    provisional_group_context.group_id().clone(),
                    provisional_group_context.epoch(),
                    tree_hash,
                    confirmed_transcript_hash.clone(),
                    self.group_context_extensions().clone(),
                );

                GroupInfoTBS::new(
                    group_context,
                    other_extensions,
                    confirmation_tag.clone(),
                    self.own_leaf_index(),
                )
            };
            // Sign to-be-signed group info.
            Some(group_info_tbs.sign(signer)?)
        } else {
            None
        };

        // Check if new members were added and, if so, create welcome messages
        let welcome_option = if !plaintext_secrets.is_empty() {
            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) = welcome_secret
                .derive_welcome_key_nonce(backend)
                .map_err(LibraryError::unexpected_crypto_error)?;
            let encrypted_group_info = welcome_key
                .aead_seal(
                    backend,
                    group_info
                        .as_ref()
                        .ok_or_else(|| LibraryError::custom("GroupInfo was not computed"))?
                        .tls_serialize_detached()
                        .map_err(LibraryError::missing_bound_check)?
                        .as_slice(),
                    &[],
                    &welcome_nonce,
                )
                .map_err(LibraryError::unexpected_crypto_error)?;
            // Encrypt group secrets
            let secrets = plaintext_secrets
                .into_iter()
                .map(|pts| pts.encrypt(backend, ciphersuite))
                .collect();
            // Create welcome message
            let welcome = Welcome::new(
                ProtocolVersion::Mls10,
                self.ciphersuite,
                secrets,
                encrypted_group_info,
            );
            Some(welcome)
        } else {
            None
        };

        let provisional_interim_transcript_hash = update_interim_transcript_hash(
            ciphersuite,
            backend,
            &InterimTranscriptHashInput::from(&confirmation_tag),
            &confirmed_transcript_hash,
        )?;

        let (provisional_group_epoch_secrets, provisional_message_secrets) =
            provisional_epoch_secrets.split_secrets(
                serialized_provisional_group_context,
                diff.leaf_count(),
                self.own_leaf_index(),
            );

        let staged_commit_state = MemberStagedCommitState::new(
            provisional_group_context,
            provisional_group_epoch_secrets,
            provisional_message_secrets,
            provisional_interim_transcript_hash,
            diff.into_staged_diff(backend, ciphersuite)?,
            path_processing_result.new_keypairs,
            // The committer is not allowed to include their own update
            // proposal, so there is no extra keypair to store here.
            None,
        );
        let staged_commit = StagedCommit::new(
            proposal_queue,
            StagedCommitState::GroupMember(Box::new(staged_commit_state)),
            commit_update_leaf_node,
        );

        Ok(CreateCommitResult {
            commit,
            welcome_option,
            staged_commit,
            group_info: group_info.filter(|_| self.use_ratchet_tree_extension),
        })
    }

    /// Returns the leftmost free leaf index.
    ///
    /// For External Commits of the "resync" type, this returns the index
    /// of the sender.
    ///
    /// The proposals must be validated before calling this function.
    pub(crate) fn free_leaf_index<'a>(
        treesync: &TreeSync,
        mut inline_proposals: impl Iterator<Item = Option<&'a Proposal>>,
    ) -> Result<LeafNodeIndex, LibraryError> {
        // Leftmost free leaf in the tree
        let free_leaf_index = treesync.free_leaf_index();
        // Returns the first remove proposal (if there is one)
        let remove_proposal_option = inline_proposals
            .find(|proposal| match proposal {
                Some(p) => p.is_type(ProposalType::Remove),
                None => false,
            })
            .flatten();
        let leaf_index = if let Some(remove_proposal) = remove_proposal_option {
            if let Proposal::Remove(remove_proposal) = remove_proposal {
                let removed_index = remove_proposal.removed();
                if removed_index < free_leaf_index {
                    removed_index
                } else {
                    free_leaf_index
                }
            } else {
                return Err(LibraryError::custom("missing key package"));
            }
        } else {
            free_leaf_index
        };
        Ok(leaf_index)
    }
}
