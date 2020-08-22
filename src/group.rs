// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::ciphersuite::{signable::*, *};
use crate::client::*;
use crate::codec::*;
use crate::creds::*;
use crate::extensions::*;
use crate::framing::*;
use crate::key_packages::*;
use crate::messages::*;
use crate::schedule::*;
use crate::tree::astree::*;
use crate::tree::treemath;
use crate::tree::*;
use crate::utils::*;
use rayon::prelude::*;

pub enum WelcomeError {
    CiphersuiteMismatch,
    JoinerSecretNotFound,
    TreeHashMismatch,
    SelfNotInTree,
    ConfirmationTagMismatch,
    InvalidRatchetTree,
    InvalidGroupInfoSignature,
}
pub enum ProposalError {}
pub enum CommitError {}
pub enum MlsPlaintextError {}
pub enum ProposalPolicyError {}
pub enum CommitPolicyError {}

pub type WelcomeValidationResult = Result<(), WelcomeError>;
pub type ProposalValidationResult = Result<(), ProposalError>;
pub type CommitValidationResult = Result<(), CommitError>;
pub type MlsPlaintextValidationResult = Result<(), MlsPlaintextError>;
pub type ProposalPolicyValidationResult = Result<(), ProposalPolicyError>;
pub type CommitPolicyValidationResult = Result<(), CommitPolicyError>;

pub trait GroupOps {
    // Create new group.
    fn new(creator: Client, group_id: &[u8], ciphersuite_name: CiphersuiteName) -> Group;
    // Join a group from a welcome message
    // TODO: add support for Welcome Extensions
    fn new_from_welcome(
        joiner: Client,
        welcome: Welcome,
        ratchet_tree: RatchetTree,
        tree_hash: &[u8],
    ) -> Result<Group, WelcomeError>;

    // Create handshake messages
    fn create_add_proposal(
        &self,
        aad: &[u8],
        joiner_key_package: KeyPackage,
    ) -> (MLSPlaintext, Proposal);
    fn create_update_proposal(
        &self,
        aad: &[u8],
        key_package: KeyPackage,
    ) -> (MLSPlaintext, Proposal);
    fn create_remove_proposal(
        &self,
        aad: &[u8],
        removed_index: LeafIndex,
    ) -> (MLSPlaintext, Proposal);
    fn create_commit(
        &self,
        aad: &[u8],
        proposals: Vec<(Sender, Proposal)>,
        own_key_packages: Vec<(HPKEPrivateKey, KeyPackage)>,
        force_self_update: bool,
    ) -> (MLSPlaintext, Option<Welcome>);

    // Apply a Commit message
    fn apply_commit(
        &mut self,
        mls_plaintext: MLSPlaintext,
        proposals: Vec<(Sender, Proposal)>,
        own_key_packages: Vec<(HPKEPrivateKey, KeyPackage)>,
    );

    // Create application message
    fn create_application_message(&self, aad: &[u8], msg: &[u8]) -> MLSPlaintext;

    // Encrypt/Decrypt MLS message
    fn encrypt(&mut self, mls_plaintext: MLSPlaintext) -> MLSCiphertext;
    fn decrypt(&mut self, mls_ciphertext: MLSCiphertext) -> MLSPlaintext;

    // Exporter
    // TODO: add the label and implement the whole exporter
    fn get_exporter_secret(&self) -> Vec<u8>;

    // Validation
    fn validate_welcome(welcome: Welcome) -> WelcomeValidationResult;
    fn validate_proposal(&self, proposal: Proposal) -> ProposalValidationResult;
    fn validate_commit(&self, commit: Commit) -> CommitValidationResult;
    fn validate_mls_plaintext(&self, mls_plaintext: MLSPlaintext) -> MlsPlaintextValidationResult;
    fn validate_proposal_against_policy(
        &self,
        proposal: Proposal,
    ) -> ProposalPolicyValidationResult;
    fn validate_commit_against_policy(
        &self,
        commit: Commit,
        proposals: Vec<Proposal>,
    ) -> CommitPolicyValidationResult;
}
pub struct Group {
    pub ciphersuite_name: CiphersuiteName,
    pub client: Client,
    pub group_context: GroupContext,
    pub generation: u32,
    pub epoch_secrets: EpochSecrets,
    pub astree: ASTree,
    pub tree: RatchetTree,
    pub interim_transcript_hash: Vec<u8>,
}

impl GroupOps for Group {
    fn new(creator: Client, id: &[u8], ciphersuite_name: CiphersuiteName) -> Group {
        let group_id = GroupId { value: id.to_vec() };
        let ciphersuite = *creator.get_ciphersuite(&ciphersuite_name);
        let identity = creator.get_identity(&ciphersuite_name);
        let kpb = KeyPackageBundle::new(ciphersuite, identity, None); // TODO remove clone
        let epoch_secrets = EpochSecrets::new();
        let astree = ASTree::new(
            ciphersuite,
            &epoch_secrets.application_secret,
            LeafIndex::from(1u32),
        );
        let tree = RatchetTree::new(ciphersuite, kpb);
        let group_context = GroupContext {
            group_id,
            epoch: GroupEpoch(0),
            tree_hash: tree.compute_tree_hash(),
            confirmed_transcript_hash: vec![],
        };
        let interim_transcript_hash = vec![];
        Group {
            ciphersuite_name,
            client: creator,
            group_context,
            generation: 0,
            epoch_secrets,
            astree,
            tree,
            interim_transcript_hash,
        }
    }
    // Join a group from a welcome message
    fn new_from_welcome(
        joiner: Client,
        welcome: Welcome,
        ratchet_tree: RatchetTree,
        tree_hash: &[u8],
    ) -> Result<Group, WelcomeError> {
        // TODO: Remove consumed key from client
        let ciphersuite_name = welcome.cipher_suite;
        let ciphersuite = Ciphersuite::new(ciphersuite_name);
        // TODO: check the extensions to see if the tree is in there
        let mut tree = ratchet_tree;
        let (key_package, private_key, egs) =
            match joiner.get_key_package_from_welcome_secrets(&welcome.secrets) {
                Some((kp, pk, egs)) => (kp, pk, egs),
                None => return Err(WelcomeError::JoinerSecretNotFound),
            };
        if &ciphersuite != key_package.get_cipher_suite() {
            return Err(WelcomeError::CiphersuiteMismatch);
        }
        let group_secrets_bytes =
            ciphersuite.hpke_open(egs.encrypted_group_secrets, &private_key, &[], &[]);
        let group_secrets = GroupSecrets::decode(&mut Cursor::new(&group_secrets_bytes)).unwrap();
        let welcome_secret = ciphersuite
            .hkdf_expand(
                &group_secrets.joiner_secret,
                b"mls 1.0 welcome",
                ciphersuite.hash_length(),
            )
            .unwrap();
        let welcome_nonce = AeadNonce::from_slice(
            &ciphersuite
                .hkdf_expand(&welcome_secret, b"nonce", ciphersuite.aead_nonce_length())
                .unwrap(),
        );
        let welcome_key = AeadKey::from_slice(
            &ciphersuite
                .hkdf_expand(&welcome_secret, b"key", ciphersuite.aead_key_length())
                .unwrap(),
        );
        let group_info_bytes = ciphersuite
            .aead_open(
                &welcome.encrypted_group_info,
                &[],
                &welcome_key,
                &welcome_nonce,
            )
            .unwrap();
        let group_info = GroupInfo::decode_detached(&group_info_bytes).unwrap();
        if tree_hash != &group_info.tree_hash[..] {
            return Err(WelcomeError::TreeHashMismatch);
        }
        let signer_node = tree.nodes[NodeIndex::from(group_info.signer_index).as_usize()].clone();
        let signer_key_package = signer_node.key_package.unwrap();
        let payload = group_info.unsigned_payload().unwrap();
        if !signer_key_package
            .get_credential()
            .verify(&payload, &group_info.signature)
        {
            return Err(WelcomeError::InvalidGroupInfoSignature);
        }
        let nodes = tree.public_key_tree();
        if !RatchetTree::verify_integrity(&ciphersuite, &nodes) {
            return Err(WelcomeError::InvalidRatchetTree);
        }
        let mut index_option = None;
        for (i, node_option) in nodes.iter().enumerate() {
            if let Some(node) = node_option {
                if let Some(kp) = node.key_package.clone() {
                    if kp == key_package {
                        index_option = Some(NodeIndex::from(i));
                        break;
                    }
                }
            }
        }
        let index = if let Some(index) = index_option {
            index
        } else {
            return Err(WelcomeError::SelfNotInTree);
        };
        if let Some(path_secret) = group_secrets.path_secret {
            let common_ancestor =
                treemath::common_ancestor(index, NodeIndex::from(group_info.signer_index));
            let common_path = treemath::dirpath_root(common_ancestor, tree.leaf_count());
            let (path_secrets, _commit_secret) = OwnLeaf::continue_path_secrets(
                &ciphersuite,
                &path_secret.path_secret,
                common_path.len(),
            );
            let keypairs = OwnLeaf::generate_path_keypairs(&ciphersuite, path_secrets);
            tree.merge_keypairs(keypairs.clone(), common_path.clone());

            let mut path_keypairs = PathKeypairs::new();
            path_keypairs.add(keypairs, common_path);
            tree.own_leaf.path_keypairs = path_keypairs;
        }

        let group_context = GroupContext {
            group_id: group_info.group_id,
            epoch: group_info.epoch,
            tree_hash: tree.compute_tree_hash(),
            confirmed_transcript_hash: group_info.confirmed_transcript_hash,
        };
        let group_state = &group_context.encode_detached().unwrap();
        let epoch_secrets = EpochSecrets::derive_epoch_secrets(
            &ciphersuite,
            &group_secrets.joiner_secret,
            vec![],
            group_state,
        );
        let astree = ASTree::new(
            ciphersuite,
            &epoch_secrets.application_secret,
            tree.leaf_count(),
        );

        if ConfirmationTag::new(
            &ciphersuite,
            &epoch_secrets.confirmation_key,
            &group_context.confirmed_transcript_hash,
        ) != ConfirmationTag(group_info.confirmation)
        {
            Err(WelcomeError::ConfirmationTagMismatch)
        } else {
            Ok(Group {
                ciphersuite_name: welcome.cipher_suite,
                client: joiner,
                group_context,
                generation: 0,
                epoch_secrets,
                astree,
                tree,
                interim_transcript_hash: group_info.interim_transcript_hash,
            })
        }
    }

    // Create handshake messages
    fn create_add_proposal(
        &self,
        aad: &[u8],
        joiner_key_package: KeyPackage,
    ) -> (MLSPlaintext, Proposal) {
        let add_proposal = AddProposal {
            key_package: joiner_key_package,
        };
        let proposal = Proposal::Add(add_proposal);
        let content = MLSPlaintextContentType::Proposal(proposal.clone());
        let mls_plaintext = MLSPlaintext::new(
            self.get_sender_index(),
            aad,
            content,
            &self.get_identity().keypair,
            &self.get_context(),
        );
        (mls_plaintext, proposal)
    }
    fn create_update_proposal(
        &self,
        aad: &[u8],
        key_package: KeyPackage,
    ) -> (MLSPlaintext, Proposal) {
        let update_proposal = UpdateProposal { key_package };
        let proposal = Proposal::Update(update_proposal);
        let content = MLSPlaintextContentType::Proposal(proposal.clone());
        let mls_plaintext = MLSPlaintext::new(
            self.get_sender_index(),
            aad,
            content,
            &self.get_identity().keypair,
            &self.get_context(),
        );
        (mls_plaintext, proposal)
    }
    fn create_remove_proposal(
        &self,
        aad: &[u8],
        removed_index: LeafIndex,
    ) -> (MLSPlaintext, Proposal) {
        let remove_proposal = RemoveProposal {
            removed: removed_index.as_u32(),
        };
        let proposal = Proposal::Remove(remove_proposal);
        let content = MLSPlaintextContentType::Proposal(proposal.clone());
        let mls_plaintext = MLSPlaintext::new(
            self.get_sender_index(),
            aad,
            content,
            &self.get_identity().keypair,
            &self.get_context(),
        );
        (mls_plaintext, proposal)
    }
    fn create_commit(
        &self,
        aad: &[u8],
        proposals: Vec<(Sender, Proposal)>,
        own_key_packages: Vec<(HPKEPrivateKey, KeyPackage)>,
        force_self_update: bool,
    ) -> (MLSPlaintext, Option<Welcome>) {
        let ciphersuite = self.get_ciphersuite();
        // TODO Dedup proposals
        let mut public_queue = ProposalQueue::new();
        for (sender, proposal) in proposals {
            let queued_proposal = QueuedProposal::new(proposal, sender.as_leaf_index(), None);
            public_queue.add(queued_proposal, &ciphersuite);
        }
        let proposal_id_list = public_queue.get_commit_lists(&ciphersuite);
        let mut new_tree = self.tree.clone();

        let mut pending_kpbs = vec![];
        for (pk, kp) in own_key_packages {
            pending_kpbs.push(KeyPackageBundle::from_key_package(kp, pk));
        }

        let (membership_changes, invited_members, _self_removed) =
            new_tree.apply_proposals(proposal_id_list.clone(), public_queue, pending_kpbs);

        let path_required = membership_changes.path_required() || force_self_update;

        // TODO: store new keys in Client
        let (path, path_secrets_option, commit_secret) = if path_required {
            let keypair = ciphersuite.new_hpke_keypair();
            let (commit_secret, kpb, path, path_secrets) = new_tree.update_own_leaf(
                self.get_identity(),
                Some(&keypair),
                None,
                &self.group_context.serialize(),
                true,
            );
            //self.pending_kpbs.push(kpb);
            (path, path_secrets, commit_secret)
        } else {
            let commit_secret = CommitSecret(zero(self.get_ciphersuite().hash_length()));
            (None, None, commit_secret)
        };

        let commit = Commit {
            updates: proposal_id_list.updates,
            removes: proposal_id_list.removes,
            adds: proposal_id_list.adds,
            path,
        };

        let mut new_epoch = self.group_context.epoch;
        new_epoch.increment();

        let confirmed_transcript_hash = Self::update_confirmed_transcript_hash(
            self.get_ciphersuite(),
            &MLSPlaintextCommitContent::new(
                &self.group_context,
                self.get_sender_index(),
                commit.clone(),
            ),
            &self.interim_transcript_hash,
        );

        let new_group_context = GroupContext {
            group_id: self.group_context.group_id.clone(),
            epoch: new_epoch,
            tree_hash: new_tree.compute_tree_hash(),
            confirmed_transcript_hash: confirmed_transcript_hash.clone(),
        };

        let mut new_epoch_secrets = self.epoch_secrets.clone();
        let epoch_secret = new_epoch_secrets.get_new_epoch_secrets(
            &ciphersuite,
            commit_secret,
            None,
            &new_group_context.serialize(),
        );

        let confirmation_tag = ConfirmationTag::new(
            &ciphersuite,
            &new_epoch_secrets.confirmation_key,
            &confirmed_transcript_hash,
        );

        let content = MLSPlaintextContentType::Commit((commit, confirmation_tag.clone()));
        let mls_plaintext = MLSPlaintext::new(
            self.get_sender_index(),
            aad,
            content,
            &self.get_identity().keypair,
            &self.get_context(),
        );

        let interim_transcript_hash = Self::update_interim_transcript_hash(
            &ciphersuite,
            &mls_plaintext,
            &confirmed_transcript_hash,
        );

        if !membership_changes.adds.is_empty() {
            let public_tree = RatchetTreeExtension::new(new_tree.public_key_tree());
            let ratchet_tree_extension = public_tree.to_extension();
            let tree_hash = ciphersuite.hash(&ratchet_tree_extension.extension_data);

            let mut group_info = GroupInfo {
                group_id: new_group_context.group_id.clone(),
                epoch: new_group_context.epoch,
                tree_hash,
                confirmed_transcript_hash,
                interim_transcript_hash,
                extensions: vec![],
                confirmation: confirmation_tag.0,
                signer_index: self.get_sender_index(),
                signature: Signature::new_empty(),
            };
            group_info.signature = group_info.sign(&self.get_identity());

            let welcome_secret = ciphersuite
                .hkdf_expand(&epoch_secret, b"mls 1.0 welcome", ciphersuite.hash_length())
                .unwrap();
            let welcome_nonce = AeadNonce::from_slice(
                &ciphersuite
                    .hkdf_expand(&welcome_secret, b"nonce", ciphersuite.aead_nonce_length())
                    .unwrap(),
            );
            let welcome_key = AeadKey::from_slice(
                &ciphersuite
                    .hkdf_expand(&welcome_secret, b"key", ciphersuite.aead_key_length())
                    .unwrap(),
            );

            let encrypted_group_info = ciphersuite
                .aead_seal(
                    &group_info.encode_detached().unwrap(),
                    &[],
                    &welcome_key,
                    &welcome_nonce,
                )
                .unwrap();

            let mut plaintext_secrets = vec![];
            for (index, add_proposal) in invited_members.clone() {
                let key_package = add_proposal.key_package;
                let key_package_hash = ciphersuite.hash(&key_package.encode_detached().unwrap());
                let path_secret = if path_required {
                    let common_ancestor =
                        treemath::common_ancestor(index, self.tree.own_leaf.leaf_index);
                    let dirpath = treemath::dirpath_root(
                        self.tree.own_leaf.leaf_index,
                        new_tree.leaf_count(),
                    );
                    let position = dirpath.iter().position(|&x| x == common_ancestor).unwrap();
                    let path_secrets = path_secrets_option.clone().unwrap();
                    let path_secret = path_secrets[position].clone();
                    Some(PathSecret { path_secret })
                } else {
                    None
                };

                let group_secrets = GroupSecrets {
                    joiner_secret: epoch_secret.clone(),
                    path_secret,
                };
                let group_secrets_bytes = group_secrets.encode_detached().unwrap();
                plaintext_secrets.push((
                    key_package.get_hpke_init_key().clone(),
                    group_secrets_bytes,
                    key_package_hash,
                ));
            }
            let secrets = plaintext_secrets
                .par_iter()
                .map(|(init_key, bytes, key_package_hash)| {
                    let encrypted_group_secrets = ciphersuite.hpke_seal(init_key, &[], &[], bytes);
                    EncryptedGroupSecrets {
                        key_package_hash: key_package_hash.clone(),
                        encrypted_group_secrets,
                    }
                })
                .collect();
            let welcome = Welcome {
                version: ProtocolVersion::Mls10,
                cipher_suite: self.ciphersuite_name,
                secrets,
                encrypted_group_info,
            };
            (mls_plaintext, Some(welcome))
        } else {
            (mls_plaintext, None)
        }
    }

    // Apply a Commit message
    fn apply_commit(
        &mut self,
        mls_plaintext: MLSPlaintext,
        proposals: Vec<(Sender, Proposal)>,
        own_key_packages: Vec<(HPKEPrivateKey, KeyPackage)>,
    ) {
        let ciphersuite = self.get_ciphersuite();
        let mut public_queue = ProposalQueue::new();
        for (sender, proposal) in proposals {
            let queued_proposal = QueuedProposal::new(proposal, sender.as_leaf_index(), None);
            public_queue.add(queued_proposal, &ciphersuite);
        }
        //let proposal_id_list = public_queue.get_commit_lists(&ciphersuite);
        //let mut new_tree = self.tree.clone();

        let mut pending_kpbs = vec![];
        for (pk, kp) in own_key_packages {
            pending_kpbs.push(KeyPackageBundle::from_key_package(kp, pk));
        }

        let sender = mls_plaintext.sender.sender;
        let is_own_commit = mls_plaintext.sender.as_node_index() == self.tree.own_leaf.leaf_index;
        // TODO return an error in case of failure
        debug_assert_eq!(mls_plaintext.epoch, self.group_context.epoch);
        let (commit, confirmation) = match mls_plaintext.content.clone() {
            MLSPlaintextContentType::Commit((commit, confirmation)) => (commit, confirmation),
            _ => panic!("No Commit in MLSPlaintext"),
        };

        let mut new_tree = self.tree.clone();

        let proposal_id_list = ProposalIDList {
            updates: commit.updates.clone(),
            removes: commit.removes.clone(),
            adds: commit.adds.clone(),
        };

        let (membership_changes, _invited_members, self_removed) =
            new_tree.apply_proposals(proposal_id_list, public_queue, pending_kpbs.clone());

        // TODO save this state in the group to prevent future operations
        if self_removed {
            return;
        }

        let commit_secret = if let Some(path) = commit.path.clone() {
            let kp = path.leaf_key_package.clone();
            // TODO return an error in case of failure
            debug_assert!(kp.verify());
            debug_assert!(mls_plaintext.verify(&self.group_context, kp.get_credential()));
            if is_own_commit {
                let own_kpb = pending_kpbs
                    .iter()
                    .find(|&kpb| kpb.get_key_package() == &kp)
                    .unwrap();
                let (commit_secret, _, _, _) = new_tree.update_own_leaf(
                    self.get_identity(),
                    None,
                    Some(own_kpb.clone()),
                    &self.group_context.serialize(),
                    false,
                );
                commit_secret
            } else {
                new_tree.update_direct_path(
                    sender,
                    path.clone(),
                    path.leaf_key_package,
                    &self.group_context.serialize(),
                )
            }
        } else {
            let path_required = membership_changes.path_required();
            debug_assert!(!path_required); // TODO: error handling
            CommitSecret(zero(self.get_ciphersuite().hash_length()))
        };

        let mut new_epoch = self.group_context.epoch;
        new_epoch.increment();

        let confirmed_transcript_hash = Self::update_confirmed_transcript_hash(
            self.get_ciphersuite(),
            &MLSPlaintextCommitContent::new(
                &self.group_context,
                mls_plaintext.sender.sender,
                commit.clone(),
            ),
            &self.interim_transcript_hash,
        );

        let new_group_context = GroupContext {
            group_id: self.group_context.group_id.clone(),
            epoch: new_epoch,
            tree_hash: new_tree.compute_tree_hash(),
            confirmed_transcript_hash: confirmed_transcript_hash.clone(),
        };

        let mut new_epoch_secrets = self.epoch_secrets.clone();
        new_epoch_secrets.get_new_epoch_secrets(
            &ciphersuite,
            commit_secret,
            None,
            &new_group_context.serialize(),
        );

        let interim_transcript_hash = Self::update_interim_transcript_hash(
            &ciphersuite,
            &mls_plaintext,
            &confirmed_transcript_hash,
        );

        debug_assert_eq!(
            ConfirmationTag::new(
                &ciphersuite,
                &new_epoch_secrets.confirmation_key,
                &confirmed_transcript_hash
            ),
            confirmation
        );

        if let Some(path) = commit.path {
            if !is_own_commit {
                let parent_hash = new_tree.compute_parent_hash(NodeIndex::from(sender));

                if let Some(received_parent_hash) = path
                    .leaf_key_package
                    .get_extension(ExtensionType::ParentHash)
                {
                    if let ExtensionPayload::ParentHash(parent_hash_inner) = received_parent_hash {
                        debug_assert_eq!(parent_hash, parent_hash_inner.parent_hash);
                    } else {
                        panic!("Wrong extension type: expected ParentHashExtension");
                    };
                } else {
                    panic!("Commit didn't contain a ParentHash extension");
                }
            }
        }

        self.tree = new_tree;
        self.group_context = new_group_context;
        self.epoch_secrets = new_epoch_secrets;
        self.interim_transcript_hash = interim_transcript_hash;
        self.astree = ASTree::new(
            *self.get_ciphersuite(),
            &self.epoch_secrets.application_secret,
            self.tree.leaf_count(),
        );
    }

    // Create application message
    fn create_application_message(&self, aad: &[u8], msg: &[u8]) -> MLSPlaintext {
        let content = MLSPlaintextContentType::Application(msg.to_vec());
        MLSPlaintext::new(
            self.get_sender_index(),
            aad,
            content,
            &self.get_identity().keypair,
            &self.get_context(),
        )
    }

    // Encrypt/Decrypt MLS message
    fn encrypt(&mut self, mls_plaintext: MLSPlaintext) -> MLSCiphertext {
        let context = &self.get_context();
        MLSCiphertext::new_from_plaintext(
            &mls_plaintext,
            &self.get_ciphersuite().clone(),
            &mut self.astree,
            &self.epoch_secrets,
            context,
        )
    }
    fn decrypt(&mut self, mls_ciphertext: MLSCiphertext) -> MLSPlaintext {
        let context = &self.get_context();
        //let mls_ciphertext = MLSCiphertext::decode_detached(&mls_ciphertext).unwrap();
        mls_ciphertext.to_plaintext(
            &self.get_ciphersuite().clone(),
            &self.roster(),
            &self.epoch_secrets,
            &mut self.astree,
            context,
        )
    }

    // Exporter
    fn get_exporter_secret(&self) -> Vec<u8> {
        unimplemented!()
    }

    // Validation
    fn validate_welcome(welcome_msg: Welcome) -> WelcomeValidationResult {
        unimplemented!()
    }
    fn validate_proposal(&self, proposal: Proposal) -> ProposalValidationResult {
        unimplemented!()
    }
    fn validate_commit(&self, commit: Commit) -> CommitValidationResult {
        unimplemented!()
    }
    fn validate_mls_plaintext(&self, mls_plaintext: MLSPlaintext) -> MlsPlaintextValidationResult {
        unimplemented!()
    }
    fn validate_proposal_against_policy(
        &self,
        proposal: Proposal,
    ) -> ProposalPolicyValidationResult {
        unimplemented!()
    }
    fn validate_commit_against_policy(
        &self,
        commit: Commit,
        proposals: Vec<Proposal>,
    ) -> CommitPolicyValidationResult {
        unimplemented!()
    }
}

impl Group {
    pub fn update_confirmed_transcript_hash(
        ciphersuite: &Ciphersuite,
        mls_plaintext_commit_content: &MLSPlaintextCommitContent,
        interim_transcript_hash: &[u8],
    ) -> Vec<u8> {
        let mls_plaintext_commit_content_bytes =
            mls_plaintext_commit_content.encode_detached().unwrap();
        ciphersuite.hash(&[interim_transcript_hash, &mls_plaintext_commit_content_bytes].concat())
    }
    pub fn update_interim_transcript_hash(
        ciphersuite: &Ciphersuite,
        mls_plaintext: &MLSPlaintext,
        confirmed_transcript_hash: &[u8],
    ) -> Vec<u8> {
        let mls_plaintext_auth_data_bytes =
            &MLSPlaintextCommitAuthData::from(mls_plaintext.clone())
                .encode_detached()
                .unwrap();
        ciphersuite.hash(
            &[
                &confirmed_transcript_hash,
                &mls_plaintext_auth_data_bytes[..],
            ]
            .concat(),
        )
    }
    pub fn roster(&self) -> Vec<Credential> {
        let mut roster = Vec::with_capacity(self.tree.leaf_count().as_usize());
        for i in 0..self.tree.leaf_count().as_usize() {
            let node = self.tree.nodes[NodeIndex::from(LeafIndex::from(i)).as_usize()].clone();
            let credential = node.key_package.unwrap().get_credential().clone();
            roster.push(credential);
        }
        roster
    }
    pub fn get_sender_index(&self) -> LeafIndex {
        LeafIndex::from(self.tree.own_leaf.leaf_index)
    }
    fn get_ciphersuite(&self) -> &Ciphersuite {
        self.client.get_ciphersuite(&self.ciphersuite_name)
    }
    fn get_identity(&self) -> &Identity {
        self.client.get_identity(&self.ciphersuite_name)
    }
    fn get_context(&self) -> GroupContext {
        self.group_context.clone()
    }
}

impl Codec for Group {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.ciphersuite_name.encode(buffer)?;
        self.client.encode(buffer)?;
        self.group_context.encode(buffer)?;
        self.generation.encode(buffer)?;
        self.epoch_secrets.encode(buffer)?;
        self.astree.encode(buffer)?;
        self.tree.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.interim_transcript_hash)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let ciphersuite_name = CiphersuiteName::decode(cursor)?;
        let client = Client::decode(cursor)?;
        let group_context = GroupContext::decode(cursor)?;
        let generation = u32::decode(cursor)?;
        let epoch_secrets = EpochSecrets::decode(cursor)?;
        let astree = ASTree::decode(cursor)?;
        let tree = RatchetTree::decode(cursor)?;
        let interim_transcript_hash = decode_vec(VecSize::VecU8, cursor)?;
        let group = Group {
            ciphersuite_name,
            client,
            group_context,
            generation,
            epoch_secrets,
            astree,
            tree,
            interim_transcript_hash,
        };
        Ok(group)
    }
}

pub enum GroupError {
    Codec(CodecError),
}

impl From<CodecError> for GroupError {
    fn from(err: CodecError) -> GroupError {
        GroupError::Codec(err)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct GroupId {
    pub value: Vec<u8>,
}

impl GroupId {
    pub fn random() -> Self {
        Self {
            value: randombytes(16),
        }
    }
    pub fn from_slice(bytes: &[u8]) -> Self {
        GroupId {
            value: bytes.to_vec(),
        }
    }
    pub fn as_slice(&self) -> Vec<u8> {
        self.value.clone()
    }
}

impl Codec for GroupId {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.value)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU8, cursor)?;
        Ok(GroupId { value })
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct GroupEpoch(pub u64);

impl GroupEpoch {
    pub fn increment(&mut self) {
        self.0 += 1;
    }
}

impl Codec for GroupEpoch {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let inner = u64::decode(cursor)?;
        Ok(GroupEpoch(inner))
    }
}

#[derive(Debug, Clone)]
pub struct GroupContext {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
}

impl GroupContext {
    pub fn serialize(&self) -> Vec<u8> {
        self.encode_detached().unwrap()
    }
}

impl Codec for GroupContext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.tree_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.confirmed_transcript_hash)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let tree_hash = decode_vec(VecSize::VecU8, cursor)?;
        let confirmed_transcript_hash = decode_vec(VecSize::VecU8, cursor)?;
        Ok(GroupContext {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
        })
    }
}

#[derive(Clone, Copy)]
pub struct GroupConfig {
    pub(crate) padding_block_size: u32,
    pub(crate) additional_as_epochs: u32,
}

impl GroupConfig {
    /// Create a new `GroupConfig` with the given ciphersuite.
    pub fn new(ciphersuite: Ciphersuite) -> Self {
        Self {
            padding_block_size: 10,
            additional_as_epochs: 0,
        }
    }

    /// Get the padding block size used in this config.
    pub fn get_padding_block_size(&self) -> u32 {
        self.padding_block_size
    }
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            padding_block_size: 10,
            additional_as_epochs: 0,
        }
    }
}

impl Codec for GroupConfig {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.padding_block_size.encode(buffer)?;
        self.additional_as_epochs.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let padding_block_size = u32::decode(cursor)?;
        let additional_as_epochs = u32::decode(cursor)?;
        Ok(GroupConfig {
            padding_block_size,
            additional_as_epochs,
        })
    }
}
