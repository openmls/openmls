use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    ciphersuite::signable::Signable,
    config::Config,
    framing::*,
    group::{core_group::*, *},
    messages::*,
    treesync::{
        diff::TreeSyncDiff,
        node::parent_node::PlainUpdatePathNode,
        treekem::{PlaintextSecret, UpdatePath},
    },
};

use super::{
    create_commit_params::{CommitType, CreateCommitParams},
    proposals::ProposalQueue,
    staged_commit::{StagedCommit, StagedCommitState},
};

/// A helper struct which contains the values resulting from the preparation of
/// a commit with path.
#[derive(Default)]
struct PathProcessingResult {
    commit_secret: Option<CommitSecret>,
    encrypted_path: Option<UpdatePath>,
    plain_path: Option<Vec<PlainUpdatePathNode>>,
}

impl CoreGroup {
    pub fn create_commit(
        &self,
        params: CreateCommitParams,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<CreateCommitResult, CoreGroupError> {
        let ciphersuite = self.ciphersuite();

        // If this is an external commit, we don't have an `own_leaf_index` set
        // yet. Instead, we use the index in which we will be put in course of
        // this commit.
        let (own_leaf_index, sender_type) = match params.commit_type() {
            CommitType::External => (self.treesync().free_leaf_index()?, SenderType::NewMember),
            CommitType::Member => (self.treesync().own_leaf_index(), SenderType::Member),
        };

        // Filter proposals
        let (proposal_queue, contains_own_updates) = ProposalQueue::filter_proposals(
            ciphersuite,
            backend,
            sender_type,
            params.proposal_store(),
            params.inline_proposals(),
            own_leaf_index,
            // We can use the old leaf count here, because the proposals will
            // only affect members of the old tree.
            self.treesync().leaf_count()?,
        )?;

        // TODO: #581 Filter proposals by support
        // 11.2:
        // Proposals with a non-default proposal type MUST NOT be included in a commit
        // unless the proposal type is supported by all the members of the group that will
        // process the Commit (i.e., not including any members being added or removed by
        // the Commit).

        let proposal_reference_list = proposal_queue.commit_list();

        // Make a copy of the current tree to apply proposals safely
        let mut diff: TreeSyncDiff = self.treesync().empty_diff()?;

        // If this is not an external commit we have to set our own leaf index
        // and add our leaf. Also, we have to generate the
        // [`KeyPackageBundlePayload`] slightly differently, because we can't
        // just pull it from the tree if we're a `NewMember`.
        let key_package_bundle_payload = self.prepare_kpb_payload(backend, &params, &mut diff)?;

        // Apply proposals to tree
        let apply_proposals_values =
            self.apply_proposals(&mut diff, backend, &proposal_queue, &[])?;
        if apply_proposals_values.self_removed {
            return Err(CreateCommitError::CannotRemoveSelf.into());
        }

        let serialized_group_context = self.group_context.tls_serialize_detached()?;
        let path_processing_result =
        // If path is needed, compute path values
            if apply_proposals_values.path_required
                || contains_own_updates
                || params.force_self_update()
            {

                // Derive and apply an update path based on the previously
                // generated KeyPackageBundle.
                let (key_package, plain_path, commit_secret) = diff.apply_own_update_path(
                    backend,
                    ciphersuite,
                    key_package_bundle_payload,
                    params.credential_bundle(),
                )?;

                // Encrypt the path to the correct recipient nodes.
                let encrypted_path = diff.encrypt_path(
                    backend,
                    self.ciphersuite(),
                    &plain_path,
                    &serialized_group_context,
                    &apply_proposals_values.exclusion_list(),
                    &key_package,
                )?;
                PathProcessingResult {
                    commit_secret: Some(commit_secret),
                    encrypted_path: Some(encrypted_path),
                    plain_path: Some(plain_path),
                }
            } else {
                // If path is not needed, return empty path processing results
                PathProcessingResult::default()
            };

        // Create commit message
        let commit = Commit {
            proposals: proposal_reference_list.into(),
            path: path_processing_result.encrypted_path,
        };

        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch();
        provisional_epoch.increment();

        // Build MlsPlaintext
        let mut mls_plaintext = MlsPlaintext::commit(
            *params.framing_parameters(),
            own_leaf_index,
            commit,
            params.commit_type(),
            params.credential_bundle(),
            &self.group_context,
            backend,
        )?;

        // Calculate the confirmed transcript hash
        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            ciphersuite,
            backend,
            // It is ok to a library error here, because we know the MlsPlaintext contains a
            // Commit
            &MlsPlaintextCommitContent::try_from(&mls_plaintext)
                .map_err(|_| CoreGroupError::LibraryError)?,
            &self.interim_transcript_hash,
        )?;

        // Calculate tree hash
        let tree_hash = diff.compute_tree_hashes(backend, ciphersuite)?;

        // Calculate group context
        let provisional_group_context = GroupContext::new(
            self.group_context.group_id().clone(),
            provisional_epoch,
            tree_hash.clone(),
            confirmed_transcript_hash.clone(),
            self.group_context.extensions(),
        )?;

        let joiner_secret = JoinerSecret::new(
            backend,
            path_processing_result.commit_secret,
            self.group_epoch_secrets().init_secret(),
        )?;

        // Create group secrets for later use, so we can afterwards consume the
        // `joiner_secret`.
        let plaintext_secrets = PlaintextSecret::from_plain_update_path(
            &diff,
            &joiner_secret,
            apply_proposals_values.invitation_list,
            path_processing_result.plain_path.as_deref(),
            &apply_proposals_values.presharedkeys,
            backend,
        )?;

        // Prepare the PskSecret
        let psk_secret = PskSecret::new(
            ciphersuite,
            backend,
            apply_proposals_values.presharedkeys.psks(),
        )?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(ciphersuite, backend, joiner_secret, psk_secret)?;

        let serialized_provisional_group_context =
            provisional_group_context.tls_serialize_detached()?;

        let welcome_secret = key_schedule.welcome(backend)?;
        key_schedule.add_context(backend, &serialized_provisional_group_context)?;
        let provisional_epoch_secrets = key_schedule.epoch_secrets(backend)?;

        // Calculate the confirmation tag
        let confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(backend, &confirmed_transcript_hash)?;

        // Set the confirmation tag
        mls_plaintext.set_confirmation_tag(confirmation_tag.clone());

        // Add membership tag if it's a `Member` commit
        if params.commit_type() == CommitType::Member {
            mls_plaintext.set_membership_tag(
                backend,
                &serialized_group_context,
                self.message_secrets().membership_key(),
            )?;
        }

        // Check if new members were added and, if so, create welcome messages
        let welcome_option = if !plaintext_secrets.is_empty() {
            // Create the ratchet tree extension if necessary
            let other_extensions: Vec<Extension> = if self.use_ratchet_tree_extension {
                vec![Extension::RatchetTree(RatchetTreeExtension::new(
                    diff.export_nodes()?,
                ))]
            } else {
                Vec::new()
            };
            // Create GroupInfo object
            let group_info = GroupInfoPayload::new(
                provisional_group_context.group_id().clone(),
                provisional_group_context.epoch(),
                tree_hash,
                confirmed_transcript_hash.clone(),
                self.group_context_extensions(),
                &other_extensions,
                confirmation_tag.clone(),
                own_leaf_index,
            );
            let group_info = group_info.sign(backend, params.credential_bundle())?;

            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) = welcome_secret.derive_welcome_key_nonce(backend)?;
            let encrypted_group_info = welcome_key.aead_seal(
                backend,
                &group_info.tls_serialize_detached()?,
                &[],
                &welcome_nonce,
            )?;
            // Encrypt group secrets
            let secrets = plaintext_secrets
                .into_iter()
                .map(|pts| pts.encrypt(backend, ciphersuite))
                .collect();
            // Create welcome message
            let welcome = Welcome::new(
                Config::supported_versions()[0],
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
            &MlsPlaintextCommitAuthData::from(&confirmation_tag),
            &confirmed_transcript_hash,
        )?;

        let (provisional_group_epoch_secrets, provisional_message_secrets) =
            provisional_epoch_secrets
                .split_secrets(serialized_provisional_group_context, diff.leaf_count());

        let staged_commit_state = StagedCommitState::new(
            provisional_group_context,
            provisional_group_epoch_secrets,
            provisional_message_secrets,
            provisional_interim_transcript_hash,
            diff.into_staged_diff(backend, ciphersuite)?,
        );
        let staged_commit = StagedCommit::new(proposal_queue, Some(staged_commit_state));

        Ok(CreateCommitResult {
            commit: mls_plaintext,
            welcome_option,
            staged_commit,
        })
    }

    /// Helper function that prepares the [`KeyPackageBundlePayload`] for use in
    /// a commit depending on the [`CommitType`].
    fn prepare_kpb_payload(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        params: &CreateCommitParams,
        diff: &mut TreeSyncDiff,
    ) -> Result<KeyPackageBundlePayload, CoreGroupError> {
        let kpb_payload = if params.commit_type() == CommitType::External {
            // Generate a KeyPackageBundle to generate a payload from for later
            // path generation.
            let key_package_bundle = KeyPackageBundle::new(
                &[self.ciphersuite().name()],
                params.credential_bundle(),
                backend,
                vec![],
            )?;

            let own_leaf_index = diff.add_leaf(key_package_bundle.key_package().clone())?;
            // Set our own index in the diff.
            diff.set_own_index(own_leaf_index);

            KeyPackageBundlePayload::from_rekeyed_key_package(
                key_package_bundle.key_package(),
                backend,
            )?
        } else {
            // Create a new key package bundle payload from the existing key
            // package.
            KeyPackageBundlePayload::from_rekeyed_key_package(
                self.treesync().own_leaf_node()?.key_package(),
                backend,
            )?
        };
        Ok(kpb_payload)
    }
}
