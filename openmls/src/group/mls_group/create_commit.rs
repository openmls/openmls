use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsCryptoProvider};

use crate::{
    ciphersuite::signable::Signable,
    config::Config,
    framing::*,
    group::{mls_group::*, *},
    messages::*,
};

use super::{
    create_commit_params::CreateCommitParams,
    proposals::{CreationProposalQueue, ProposalStore},
};

/// Wrapper for proposals by value and reference.
pub struct Proposals<'a> {
    pub proposals_by_reference: &'a ProposalStore,
    pub proposals_by_value: &'a [&'a Proposal],
}

impl MlsGroup {
    pub fn create_commit(
        &self,
        params: CreateCommitParams,
        backend: &impl OpenMlsCryptoProvider,
    ) -> CreateCommitResult {
        let ciphersuite = self.ciphersuite();

        // Filter proposals
        let (proposal_queue, contains_own_updates) = CreationProposalQueue::filter_proposals(
            ciphersuite,
            backend,
            params.proposal_store(),
            params.inline_proposals(),
            self.tree().own_node_index(),
            self.tree().leaf_count(),
        )?;

        let proposal_reference_list = proposal_queue.commit_list();

        let sender_index = self.sender_index();
        // Make a copy of the current tree to apply proposals safely
        let mut provisional_tree = RatchetTree::new_from_public_tree(&self.tree());

        // Apply proposals to tree
        let apply_proposals_values =
            match provisional_tree.apply_proposals(backend, proposal_queue, &[]) {
                Ok(res) => res,
                Err(_) => return Err(CreateCommitError::OwnKeyNotFound.into()),
            };
        if apply_proposals_values.self_removed {
            return Err(CreateCommitError::CannotRemoveSelf.into());
        }

        let serialized_group_context = self.group_context.tls_serialize_detached()?;
        let (path_option, kpb_option) = if apply_proposals_values.path_required
            || contains_own_updates
            || params.force_self_update()
        {
            // If path is needed, compute path values
            let (path, key_package_bundle) = provisional_tree.refresh_private_tree(
                params.credential_bundle(),
                &serialized_group_context,
                apply_proposals_values.exclusion_list(),
                backend,
            )?;
            (Some(path), Some(key_package_bundle))
        } else {
            // If path is not needed, return empty commit secret
            (None, None)
        };

        // Create commit message
        let commit = Commit {
            proposals: proposal_reference_list.into(),
            path: path_option,
        };

        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch;
        provisional_epoch.increment();

        // Build MlsPlaintext
        let mut mls_plaintext = MlsPlaintext::new_commit(
            *params.framing_parameters(),
            sender_index,
            commit,
            params.credential_bundle(),
            &self.group_context,
            backend,
        )?;

        // Calculate the confirmed transcript hash
        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            ciphersuite,
            backend,
            // It is ok to use `unwrap()` here, because we know the MlsPlaintext contains a
            // Commit
            &MlsPlaintextCommitContent::try_from(&mls_plaintext).unwrap(),
            &self.interim_transcript_hash,
        )?;

        // Calculate tree hash
        let tree_hash = provisional_tree.tree_hash(backend);

        // TODO #483: Implement extensions
        let extensions: Vec<Extension> = Vec::new();

        // Calculate group context
        let provisional_group_context = GroupContext::new(
            self.group_context.group_id.clone(),
            provisional_epoch,
            tree_hash.clone(),
            confirmed_transcript_hash.clone(),
            &extensions,
        )?;

        let joiner_secret = JoinerSecret::new(
            backend,
            provisional_tree.commit_secret(),
            self.epoch_secrets()
                .init_secret()
                .ok_or(MlsGroupError::InitSecretNotFound)?,
        );

        // Create group secrets for later use, so we can afterwards consume the
        // `joiner_secret`.
        let plaintext_secrets = PlaintextSecret::new(
            &joiner_secret,
            apply_proposals_values.invitation_list,
            &provisional_tree,
            &apply_proposals_values.presharedkeys,
            backend,
        )?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(
            ciphersuite,
            backend,
            joiner_secret,
            psk_output(
                ciphersuite,
                backend,
                *params.psk_fetcher_option(),
                &apply_proposals_values.presharedkeys,
            )?,
        );

        let welcome_secret = key_schedule.welcome(backend)?;
        key_schedule.add_context(backend, &provisional_group_context)?;
        let provisional_epoch_secrets = key_schedule.epoch_secrets(backend, false)?;

        // Calculate the confirmation tag
        let confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(backend, &confirmed_transcript_hash);

        // Set the confirmation tag
        mls_plaintext.set_confirmation_tag(confirmation_tag.clone());

        // Add membership tag
        mls_plaintext.set_membership_tag(
            backend,
            &serialized_group_context,
            self.epoch_secrets().membership_key(),
        )?;

        // Check if new members were added an create welcome message
        if !plaintext_secrets.is_empty() {
            // Create the ratchet tree extension if necessary
            let other_extensions: Vec<Extension> = if self.use_ratchet_tree_extension {
                vec![Extension::RatchetTree(RatchetTreeExtension::new(
                    provisional_tree.public_key_tree_copy(),
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
            let (welcome_key, welcome_nonce) = welcome_secret.derive_welcome_key_nonce(backend);
            let encrypted_group_info = welcome_key
                .aead_seal(
                    backend,
                    &group_info.tls_serialize_detached()?,
                    &[],
                    &welcome_nonce,
                )
                .unwrap();
            // Encrypt group secrets
            let secrets = plaintext_secrets
                .iter()
                .map(
                    |PlaintextSecret {
                         public_key,
                         group_secrets_bytes,
                         key_package_hash,
                     }| {
                        let encrypted_group_secrets = backend.crypto().hpke_seal(
                            ciphersuite.hpke_config(),
                            public_key.as_slice(),
                            &[],
                            &[],
                            group_secrets_bytes,
                        );
                        EncryptedGroupSecrets {
                            key_package_hash: key_package_hash.clone().into(),
                            encrypted_group_secrets,
                        }
                    },
                )
                .collect();
            // Create welcome message
            let welcome = Welcome::new(
                Config::supported_versions()[0],
                self.ciphersuite,
                secrets,
                encrypted_group_info,
            );
            Ok((mls_plaintext, Some(welcome), kpb_option))
        } else {
            Ok((mls_plaintext, None, kpb_option))
        }
    }
}

/// Helper struct holding values that are encryptedin the
/// `EncryptedGroupSecrets`. In particular, the `group_secrets_bytes` are
/// encrypted for the `public_key` into `encrypted_group_secrets` later.
pub(crate) struct PlaintextSecret {
    pub(crate) public_key: HpkePublicKey,
    pub(crate) group_secrets_bytes: Vec<u8>,
    pub(crate) key_package_hash: Vec<u8>,
}

impl PlaintextSecret {
    /// Prepare the `GroupSecrets` for a number of `invited_members` based on a
    /// provisional `RatchetTree`. If there are `path_secrets` in the
    /// provisional tree, we need to include a `path_secret` into the
    /// `GroupSecrets`.
    pub(crate) fn new(
        joiner_secret: &JoinerSecret,
        invited_members: Vec<(LeafIndex, AddProposal)>,
        provisional_tree: &RatchetTree,
        presharedkeys: &PreSharedKeys,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Vec<Self>, MlsGroupError> {
        let mut plaintext_secrets = vec![];
        for (index, add_proposal) in invited_members {
            let key_package = add_proposal.key_package;
            let key_package_hash = key_package.hash(backend);

            // Compute the index of the common ancestor lowest in the
            // tree of our own leaf and the given index.
            let common_ancestor_index = treemath::common_ancestor_index(
                index.into(),
                provisional_tree.own_node_index().into(),
            );

            let path_secret = provisional_tree.path_secret(common_ancestor_index);

            // Create the GroupSecrets object for the respective member.
            let group_secrets_bytes =
                GroupSecrets::new_encoded(joiner_secret, path_secret, presharedkeys)?;
            plaintext_secrets.push(PlaintextSecret {
                public_key: key_package.hpke_init_key().clone(),
                group_secrets_bytes,
                key_package_hash,
            });
        }
        Ok(plaintext_secrets)
    }
}
