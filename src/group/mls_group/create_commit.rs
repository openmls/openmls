use crate::ciphersuite::signable::Signable;
use crate::codec::*;
use crate::config::Config;
use crate::credentials::CredentialBundle;
use crate::framing::*;
use crate::group::mls_group::*;
use crate::group::*;
use crate::messages::*;

impl MlsGroup {
    pub(crate) fn create_commit_internal(
        &self,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        proposals_by_reference: &[&MLSPlaintext],
        proposals_by_value: &[&Proposal],
        force_self_update: bool,
        psk_fetcher_option: Option<PskFetcher>,
    ) -> CreateCommitResult {
        let ciphersuite = self.ciphersuite();
        // Filter proposals
        let (proposal_queue, contains_own_updates) = ProposalQueue::filter_proposals(
            ciphersuite,
            proposals_by_reference,
            proposals_by_value,
            self.tree().own_node_index(),
            self.tree().leaf_count(),
        )?;

        let proposal_reference_list = proposal_queue.commit_list();

        let sender_index = self.sender_index();
        // Make a copy of the current tree to apply proposals safely
        let mut provisional_tree = RatchetTree::new_from_public_tree(&self.tree());

        // Apply proposals to tree
        let apply_proposals_values = match provisional_tree.apply_proposals(proposal_queue, &[]) {
            Ok(res) => res,
            Err(_) => return Err(CreateCommitError::OwnKeyNotFound.into()),
        };
        if apply_proposals_values.self_removed {
            return Err(CreateCommitError::CannotRemoveSelf.into());
        }

        let (path_option, kpb_option) =
            if apply_proposals_values.path_required || contains_own_updates || force_self_update {
                // If path is needed, compute path values
                let (path, key_package_bundle) = provisional_tree.refresh_private_tree(
                    credential_bundle,
                    &self.group_context.serialized(),
                    apply_proposals_values.exclusion_list(),
                );
                (Some(path), Some(key_package_bundle))
            } else {
                // If path is not needed, return empty commit secret
                (None, None)
            };

        // Create commit message
        let commit = Commit {
            proposals: proposal_reference_list,
            path: path_option,
        };

        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch;
        provisional_epoch.increment();

        // Build MLSPlaintext
        let content = MLSPlaintextContentType::Commit(commit);
        let sender = Sender::member(sender_index);
        let mut mls_plaintext = MLSPlaintext {
            group_id: self.context().group_id.clone(),
            epoch: self.context().epoch,
            sender,
            authenticated_data: aad.to_vec(),
            content_type: ContentType::from(&content),
            content,
            signature: Signature::new_empty(),
            confirmation_tag: None,
            membership_tag: None,
        };

        // Add signature and membership tag to the MLSPlaintext
        let serialized_context = self.group_context.serialized();
        mls_plaintext.sign_from_member(credential_bundle, serialized_context)?;

        // Calculate the confirmed transcript hash
        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            &ciphersuite,
            // It is ok to use `unwrap()` here, because we know the MLSPlaintext contains a
            // Commit
            &MLSPlaintextCommitContent::try_from(&mls_plaintext).unwrap(),
            &self.interim_transcript_hash,
        )?;

        // Calculate tree hash
        let tree_hash = provisional_tree.tree_hash();

        // TODO #186: Implement extensions
        let extensions: Vec<Box<dyn Extension>> = Vec::new();

        // Calculate group context
        let provisional_group_context = GroupContext::new(
            self.group_context.group_id.clone(),
            provisional_epoch,
            tree_hash.clone(),
            confirmed_transcript_hash.clone(),
            &extensions,
        )?;

        let joiner_secret = JoinerSecret::new(
            provisional_tree.commit_secret(),
            self.epoch_secrets()
                .init_secret()
                .ok_or(GroupError::InitSecretNotFound)?,
        );

        // Create group secrets for later use, so we can afterwards consume the
        // `joiner_secret`.
        let plaintext_secrets = PlaintextSecret::new(
            &joiner_secret,
            apply_proposals_values.invitation_list,
            &provisional_tree,
            &apply_proposals_values.presharedkeys,
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

        let welcome_secret = key_schedule.welcome()?;
        key_schedule.add_context(&provisional_group_context)?;
        let provisional_epoch_secrets = key_schedule.epoch_secrets(false)?;

        // Calculate the confirmation tag
        let confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(&confirmed_transcript_hash);

        // Set the confirmation tag
        mls_plaintext.confirmation_tag = Some(confirmation_tag.clone());

        // Add membership tag
        mls_plaintext
            .add_membership_tag(serialized_context, self.epoch_secrets().membership_key())?;

        // Check if new members were added an create welcome message
        if !plaintext_secrets.is_empty() {
            // Create the ratchet tree extension if necessary
            let extensions: Vec<Box<dyn Extension>> = if self.use_ratchet_tree_extension {
                vec![Box::new(RatchetTreeExtension::new(
                    provisional_tree.public_key_tree_copy(),
                ))]
            } else {
                Vec::new()
            };
            // Create GroupInfo object
            let mut group_info = GroupInfo::new(
                provisional_group_context.group_id.clone(),
                provisional_group_context.epoch,
                tree_hash,
                confirmed_transcript_hash,
                extensions,
                confirmation_tag,
                sender_index,
            );
            group_info.set_signature(group_info.sign(credential_bundle));

            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) = welcome_secret.derive_welcome_key_nonce();
            let encrypted_group_info = welcome_key
                .aead_seal(&group_info.encode_detached().unwrap(), &[], &welcome_nonce)
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
                        let encrypted_group_secrets =
                            ciphersuite.hpke_seal(public_key, &[], &[], group_secrets_bytes);
                        EncryptedGroupSecrets {
                            key_package_hash: key_package_hash.clone(),
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
    pub(crate) public_key: HPKEPublicKey,
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
        invited_members: Vec<(NodeIndex, AddProposal)>,
        provisional_tree: &RatchetTree,
        presharedkeys: &PreSharedKeys,
    ) -> Result<Vec<Self>, GroupError> {
        // Get a Vector containing the node indices of the direct path to the
        // root from our own leaf.
        let dirpath = treemath::leaf_direct_path(
            provisional_tree.own_node_index(),
            provisional_tree.leaf_count(),
        )?;

        let mut plaintext_secrets = vec![];
        for (index, add_proposal) in invited_members {
            let key_package = add_proposal.key_package;
            let key_package_hash = key_package.hash();

            let path_secrets = provisional_tree.path_secrets();
            let path_secret = if !path_secrets.is_empty() {
                // Compute the index of the common ancestor lowest in the
                // tree of our own leaf and the given index.
                let common_ancestor_index = treemath::common_ancestor_index(
                    index,
                    provisional_tree.own_node_index().into(),
                );
                // Get the position of the node index that represents the
                // common ancestor in the direct path. We can unwrap here,
                // because the direct path must contain the shared ancestor.
                let position = dirpath
                    .iter()
                    .position(|&x| x == common_ancestor_index)
                    .unwrap();
                // We have to clone the element of the vector here to
                // preserve its order.
                let path_secret = path_secrets[position].clone();
                Some(PathSecret { path_secret })
            } else {
                None
            };

            // Create the GroupSecrets object for the respective member.
            let psks_option = if presharedkeys.psks.is_empty() {
                None
            } else {
                Some(presharedkeys)
            };

            let group_secrets_bytes =
                GroupSecrets::new_encoded(joiner_secret, path_secret, psks_option)?;
            plaintext_secrets.push(PlaintextSecret {
                public_key: key_package.hpke_init_key().clone(),
                group_secrets_bytes,
                key_package_hash,
            });
        }
        Ok(plaintext_secrets)
    }
}
