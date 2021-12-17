use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    ciphersuite::signable::Signable,
    config::Config,
    framing::*,
    group::{mls_group::*, *},
    messages::*,
    treesync::{
        diff::TreeSyncDiff,
        node::parent_node::PlainUpdatePathNode,
        treekem::{PlaintextSecret, UpdatePath},
    },
};

use super::{
    create_commit_params::{CommitType, CreateCommitParams},
    proposals::{CreationProposalQueue, ProposalStore},
};

/// Wrapper for proposals by value and reference.
pub struct Proposals<'a> {
    pub proposals_by_reference: &'a ProposalStore,
    pub proposals_by_value: &'a [&'a Proposal],
}

/// A helper struct which contains the values resulting from the preparation of
/// a commit with path.
#[derive(Default)]
struct PathProcessingResult {
    commit_secret: Option<CommitSecret>,
    encrypted_path: Option<UpdatePath>,
    plain_path: Option<Vec<PlainUpdatePathNode>>,
    key_package_bundle: Option<KeyPackageBundle>,
}

impl MlsGroup {
    pub fn create_commit(
        &self,
        params: CreateCommitParams,
        backend: &impl OpenMlsCryptoProvider,
    ) -> CreateCommitResult {
        let ciphersuite = self.ciphersuite();

        let sender_type = match params.commit_type() {
            CommitType::External => SenderType::NewMember,
            CommitType::Member => SenderType::Member,
        };
        // Filter proposals
        let (proposal_queue, contains_own_updates) = CreationProposalQueue::filter_proposals(
            ciphersuite,
            backend,
            sender_type,
            params.proposal_store(),
            params.inline_proposals(),
            self.treesync().own_leaf_index(),
            self.treesync().leaf_count()?,
        )?;

        // TODO: #581 Filter proposals by support
        // 11.2:
        // Proposals with a non-default proposal type MUST NOT be included in a commit
        // unless the proposal type is supported by all the members of the group that will
        // process the Commit (i.e., not including any members being added or removed by
        // the Commit).

        let proposal_reference_list = proposal_queue.commit_list();

        let sender_index = self.sender_index();
        // Make a copy of the current tree to apply proposals safely
        let mut diff: TreeSyncDiff = self.treesync().empty_diff()?;

        // Apply proposals to tree
        let apply_proposals_values =
            self.apply_proposals(&mut diff, backend, proposal_queue, &[])?;
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
                // Create a new key package bundle payload from the existing key
                // package.
                let key_package_bundle_payload = KeyPackageBundlePayload::from_rekeyed_key_package(
                    self.treesync().own_leaf_node()?.key_package(),
                    backend,
                )?;

                // Derive and apply an update path based on the previously
                // generated KeyPackageBundle.
                let (key_package_bundle, plain_path, commit_secret) = diff.apply_own_update_path(
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
                    key_package_bundle.key_package(),
                )?;
                PathProcessingResult {
                    commit_secret: Some(commit_secret),
                    encrypted_path: Some(encrypted_path),
                    plain_path: Some(plain_path),
                    key_package_bundle: Some(key_package_bundle),
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
        let mut provisional_epoch = self.group_context.epoch;
        provisional_epoch.increment();

        // Build MlsPlaintext
        let mut mls_plaintext = MlsPlaintext::commit(
            *params.framing_parameters(),
            sender_index,
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
                .map_err(|_| MlsGroupError::LibraryError)?,
            &self.interim_transcript_hash,
        )?;

        // Calculate tree hash
        let tree_hash = diff.compute_tree_hashes(backend, ciphersuite)?;

        // Calculate group context
        let provisional_group_context = GroupContext::new(
            self.group_context.group_id.clone(),
            provisional_epoch,
            tree_hash.clone(),
            confirmed_transcript_hash.clone(),
            self.group_context.extensions(),
        )?;

        let joiner_secret = JoinerSecret::new(
            backend,
            path_processing_result.commit_secret,
            self.group_epoch_secrets()
                .init_secret()
                .ok_or(MlsGroupError::InitSecretNotFound)?,
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
        let provisional_epoch_secrets = key_schedule.epoch_secrets(backend, false)?;

        // Calculate the confirmation tag
        let confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(backend, &confirmed_transcript_hash)?;

        // Set the confirmation tag
        mls_plaintext.set_confirmation_tag(confirmation_tag.clone());

        // Add membership tag
        mls_plaintext.set_membership_tag(
            backend,
            &serialized_group_context,
            self.message_secrets().membership_key(),
        )?;

        // Check if new members were added and, if so, create welcome messages
        if !plaintext_secrets.is_empty() {
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
                provisional_group_context.group_id.clone(),
                provisional_group_context.epoch,
                tree_hash,
                confirmed_transcript_hash,
                self.group_context_extensions(),
                &other_extensions,
                confirmation_tag,
                sender_index,
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
            Ok((
                mls_plaintext,
                Some(welcome),
                path_processing_result.key_package_bundle,
            ))
        } else {
            Ok((
                mls_plaintext,
                None,
                path_processing_result.key_package_bundle,
            ))
        }
    }
}
