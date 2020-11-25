use crate::ciphersuite::signable::Signable;
use crate::codec::*;
use crate::config::Config;
use crate::creds::CredentialBundle;
use crate::extensions::*;
use crate::framing::*;
use crate::group::mls_group::*;
use crate::group::*;
use crate::messages::*;
use crate::tree::treemath;
use crate::utils::*;

impl MlsGroup {
    pub(crate) fn create_commit_internal(
        &self,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        proposals: Vec<MLSPlaintext>,
        force_self_update: bool,
    ) -> CreateCommitResult {
        let ciphersuite = self.ciphersuite();
        // Filter proposals
        let (proposal_queue, contains_own_updates) = ProposalQueue::filtered_proposals(
            ciphersuite,
            proposals,
            LeafIndex::from(self.tree().get_own_node_index()),
            self.tree().leaf_count(),
        );

        let proposal_id_list = proposal_queue.get_proposal_id_list();

        let sender_index = self.sender_index();
        // Make a copy of the current tree to apply proposals safely
        let mut provisional_tree = RatchetTree::new_from_public_tree(&self.tree());

        // Apply proposals to tree
        let (path_required_by_commit, self_removed, invited_members) =
            match provisional_tree.apply_proposals(&proposal_id_list, proposal_queue, &[]) {
                Ok(res) => res,
                Err(_) => return Err(CreateCommitError::OwnKeyNotFound),
            };
        if self_removed {
            return Err(CreateCommitError::CannotRemoveSelf);
        }
        // Determine if Commit needs path field
        let path_required = path_required_by_commit || contains_own_updates || force_self_update;

        let (commit_secret, path, path_secrets_option, kpb_option) = if path_required {
            // If path is needed, compute path values
            let (commit_secret, path, path_secrets, key_package_bundle) = provisional_tree
                .refresh_private_tree(
                    ciphersuite,
                    credential_bundle,
                    &self.group_context.serialize(),
                );
            (
                commit_secret,
                Some(path),
                Some(path_secrets),
                Some(key_package_bundle),
            )
        } else {
            // If path is not needed, return empty commit secret
            let commit_secret = Secret::from(zero(self.ciphersuite().hash_length()));
            (commit_secret, None, None, None)
        };
        // Create commit message
        let commit = Commit {
            proposals: proposal_id_list,
            path,
        };
        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch;
        provisional_epoch.increment();
        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            self.ciphersuite(),
            &MLSPlaintextCommitContent::new(&self.group_context, sender_index, commit.clone()),
            &self.interim_transcript_hash,
        );
        let tree_hash = provisional_tree.compute_tree_hash();
        let provisional_group_context = GroupContext {
            group_id: self.group_context.group_id.clone(),
            epoch: provisional_epoch,
            tree_hash: tree_hash.clone(),
            confirmed_transcript_hash: confirmed_transcript_hash.clone(),
        };
        let mut provisional_epoch_secrets = self.epoch_secrets.clone();
        let epoch_secret = provisional_epoch_secrets.get_new_epoch_secrets(
            &ciphersuite,
            commit_secret,
            None,
            &provisional_group_context,
        );
        // Compute confirmation tag
        let confirmation_tag = ConfirmationTag::new(
            &ciphersuite,
            &provisional_epoch_secrets.confirmation_key(),
            &confirmed_transcript_hash,
        );
        // Create MLSPlaintext
        let content = MLSPlaintextContentType::Commit((commit, confirmation_tag.clone()));
        let mls_plaintext = MLSPlaintext::new(
            sender_index,
            aad,
            content,
            credential_bundle,
            &self.context(),
        );
        // Check if new members were added an create welcome message
        if !invited_members.is_empty() {
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
                confirmation_tag.to_vec(),
                sender_index,
            );
            group_info.set_signature(group_info.sign(credential_bundle));
            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) =
                compute_welcome_key_nonce(ciphersuite, &epoch_secret);
            let encrypted_group_info = welcome_key
                .aead_seal(&group_info.encode_detached().unwrap(), &[], &welcome_nonce)
                .unwrap();
            // Create group secrets
            let mut plaintext_secrets = vec![];
            for (index, add_proposal) in invited_members.clone() {
                let key_package = add_proposal.key_package;
                let key_package_hash = ciphersuite.hash(&key_package.encode_detached().unwrap());
                let path_secret = if path_required {
                    let common_ancestor_index = treemath::common_ancestor_index(
                        index,
                        provisional_tree.get_own_node_index(),
                    );
                    let dirpath = treemath::direct_path_root(
                        provisional_tree.get_own_node_index(),
                        provisional_tree.leaf_count(),
                    )
                    .expect("create_commit_internal: TreeMath error when computing direct path.");
                    let position = dirpath
                        .iter()
                        .position(|&x| x == common_ancestor_index)
                        .unwrap();
                    let path_secrets = path_secrets_option.clone().unwrap();
                    let path_secret = path_secrets[position].clone();
                    Some(PathSecret { path_secret })
                } else {
                    None
                };
                let group_secrets = GroupSecrets::new(epoch_secret.clone(), path_secret);
                let group_secrets_bytes = group_secrets.encode_detached().unwrap();
                plaintext_secrets.push((
                    key_package.hpke_init_key().clone(),
                    group_secrets_bytes,
                    key_package_hash,
                ));
            }
            // Encrypt group secrets
            let secrets = plaintext_secrets
                .iter()
                .map(|(init_key, bytes, key_package_hash)| {
                    let encrypted_group_secrets = ciphersuite.hpke_seal(init_key, &[], &[], bytes);
                    EncryptedGroupSecrets {
                        key_package_hash: key_package_hash.clone(),
                        encrypted_group_secrets,
                    }
                })
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
