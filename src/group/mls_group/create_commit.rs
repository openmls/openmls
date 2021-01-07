use crate::ciphersuite::signable::Signable;
use crate::codec::*;
use crate::config::Config;
use crate::credentials::CredentialBundle;
use crate::extensions::*;
use crate::framing::{sender::*, *};
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
        // Determine if Commit needs path field
        let path_required =
            apply_proposals_values.path_required || contains_own_updates || force_self_update;

        let (commit_secret, path, path_secrets_option, kpb_option) = if path_required {
            // If path is needed, compute path values
            let (commit_secret, path, path_secrets, key_package_bundle) = provisional_tree
                .refresh_private_tree(
                    credential_bundle,
                    &self.group_context.serialized(),
                    apply_proposals_values.exclusion_list(),
                );
            (
                Some(commit_secret),
                Some(path),
                Some(path_secrets),
                Some(key_package_bundle),
            )
        } else {
            // If path is not needed, return empty commit secret
            (None, None, None, None)
        };
        // Create commit message
        let commit = Commit {
            proposals: proposal_reference_list,
            path,
        };
        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch;
        provisional_epoch.increment();
        // We clone the init secret here, as the `joiner_secret` is only for the
        // provisional group state.
        let joiner_secret = JoinerSecret::from_commit_and_init_secret(
            ciphersuite,
            commit_secret,
            &self.init_secret,
        );
        // Create group secrets for later use, so we can afterwards consume the
        // `joiner_secret`.
        let plaintext_secrets = joiner_secret.group_secrets(
            apply_proposals_values.invitation_list,
            &provisional_tree,
            path_secrets_option,
        )?;
        // TODO #141: Implement PSK
        let intermediate_secret = IntermediateSecret::new(ciphersuite, joiner_secret, None);
        let welcome_secret = WelcomeSecret::new(ciphersuite, &intermediate_secret);

        // Derive the welcome key material before consuming the `MemberSecret`
        // immediately afterwards.
        let (welcome_key, welcome_nonce) = welcome_secret.derive_welcome_key_nonce(ciphersuite);

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
        let serialized_context = self.context().encode_detached().unwrap();
        mls_plaintext.sign_and_mac(
            ciphersuite,
            credential_bundle,
            serialized_context,
            &self.epoch_secrets().membership_key,
        );

        // Calculate the confirmed transcript hash
        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            &ciphersuite,
            // It is ok to use `unwrap()` here, because we know the MLSPlaintext contains a
            // Commit
            &MLSPlaintextCommitContent::try_from(&mls_plaintext).unwrap(),
            &self.interim_transcript_hash,
        )?;

        let tree_hash = provisional_tree.tree_hash();
        let provisional_group_context = GroupContext::new(
            self.group_context.group_id.clone(),
            provisional_epoch,
            tree_hash.clone(),
            confirmed_transcript_hash.clone(),
        )?;

        let epoch_secret =
            EpochSecret::new(ciphersuite, intermediate_secret, &provisional_group_context);

        // The init- and encryption secrets are not used here. They come into
        // play when the provisional group state is applied in `apply_commit`.
        let (provisional_epoch_secrets, _provisional_init_secret, _provisional_encryption_secret) =
            EpochSecrets::derive_epoch_secrets(&ciphersuite, epoch_secret);

        // Calculate the confirmation tag
        let confirmation_tag = ConfirmationTag::new(
            &ciphersuite,
            &provisional_epoch_secrets.confirmation_key(),
            &confirmed_transcript_hash,
        );
        // Set the confirmation tag
        mls_plaintext.confirmation_tag = Some(confirmation_tag.clone());

        // Check if new members were added an create welcome message
        if !plaintext_secrets.is_empty() {
            let extensions: Vec<Box<dyn Extension>> = if self.add_ratchet_tree_extension {
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
