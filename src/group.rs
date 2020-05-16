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

use astree::*;
use codec::*;
use creds::*;
use crypto::aead;
use crypto::hash;
use crypto::hkdf;
use crypto::hpke::*;
use crypto::signatures::*;
use framing::*;
use kp::*;
use messages::*;
use schedule::*;
use tree::*;
use treemath;
use utils::*;
use validator::*;

pub struct Group {
    pub config: GroupConfig,
    pub identity: Identity,
    pub group_context: GroupContext,
    pub generation: u32,
    pub epoch_secrets: EpochSecrets,
    pub astree: ASTree,
    pub tree: Tree,
    pub public_queue: ProposalQueue,
    pub own_queue: ProposalQueue,
    pub pending_kpbs: Vec<KeyPackageBundle>,
    pub interim_transcript_hash: Vec<u8>,
}

impl Codec for Group {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.config.encode(buffer)?;
        self.identity.encode(buffer)?;
        self.group_context.encode(buffer)?;
        self.generation.encode(buffer)?;
        self.epoch_secrets.encode(buffer)?;
        self.astree.encode(buffer)?;
        self.tree.encode(buffer)?;
        self.public_queue.encode(buffer)?;
        self.own_queue.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.pending_kpbs)?;
        encode_vec(VecSize::VecU8, buffer, &self.interim_transcript_hash)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let config = GroupConfig::decode(cursor)?;
        let identity = Identity::decode(cursor)?;
        let group_context = GroupContext::decode(cursor)?;
        let generation = u32::decode(cursor)?;
        let epoch_secrets = EpochSecrets::decode(cursor)?;
        let astree = ASTree::decode(cursor)?;
        let tree = Tree::decode(cursor)?;
        let public_queue = ProposalQueue::decode(cursor)?;
        let own_queue = ProposalQueue::decode(cursor)?;
        let pending_kpbs = decode_vec(VecSize::VecU32, cursor)?;
        let interim_transcript_hash = decode_vec(VecSize::VecU8, cursor)?;
        let group = Group {
            config,
            identity,
            group_context,
            generation,
            epoch_secrets,
            astree,
            tree,
            public_queue,
            own_queue,
            pending_kpbs,
            interim_transcript_hash,
        };
        Ok(group)
    }
}

impl Group {
    pub fn new(identity: Identity, group_id: GroupId, config: GroupConfig) -> Self {
        let kpb = KeyPackageBundle::new(config.ciphersuite, &identity, None);
        let epoch_secrets = EpochSecrets::new();
        let astree = ASTree::new(
            config.ciphersuite,
            &epoch_secrets.application_secret,
            RosterIndex::from(1u32),
        );
        let tree = Tree::new(config.ciphersuite, kpb);
        let group_context = GroupContext {
            group_id,
            epoch: GroupEpoch(0),
            tree_hash: tree.compute_tree_hash(),
            confirmed_transcript_hash: vec![],
        };
        let interim_transcript_hash = vec![];
        Group {
            config,
            identity,
            group_context,
            generation: 0,
            epoch_secrets,
            astree,
            tree,
            public_queue: ProposalQueue::new(config.ciphersuite),
            own_queue: ProposalQueue::new(config.ciphersuite),
            pending_kpbs: vec![],
            interim_transcript_hash,
        }
    }
    pub fn new_from_welcome(identity: Identity, welcome: Welcome, kpb: KeyPackageBundle) -> Group {
        let ciphersuite = welcome.cipher_suite;
        if ciphersuite != kpb.key_package.cipher_suite {
            panic!("Ciphersuite mismatch"); // TODO error handling
        }
        // TODO do this in kp.rs
        let key_package_hash = hash::hash(
            ciphersuite.into(),
            &kpb.key_package.encode_detached().unwrap(),
        );
        let secret_option = welcome
            .secrets
            .iter()
            .find(|&secret| secret.key_package_hash == key_package_hash);
        if secret_option.is_none() {
            panic!("No secret found in Welcome"); // TODO error handling
        }
        let secret = secret_option.unwrap();
        let group_secrets_bytes = secret
            .encrypted_group_secrets
            .open(ciphersuite, &kpb.private_key, None, None)
            .unwrap();
        let group_secrets = GroupSecrets::decode(&mut Cursor::new(&group_secrets_bytes)).unwrap();
        let welcome_secret = hkdf::expand(
            ciphersuite.into(),
            &group_secrets.epoch_secret,
            b"mls 1.0 welcome",
            hash::hash_length(ciphersuite.into()),
        )
        .unwrap();
        let welcome_nonce = aead::Nonce::from_slice(
            &hkdf::expand(
                ciphersuite.into(),
                &welcome_secret,
                b"nonce",
                aead::Nonce::nonce_length(ciphersuite.into()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let welcome_key = aead::AEADKey::from_slice(
            ciphersuite.into(),
            &hkdf::expand(
                ciphersuite.into(),
                &welcome_secret,
                b"key",
                aead::AEADKey::key_length(ciphersuite.into()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let group_info_bytes = aead::aead_open(
            ciphersuite.into(),
            &welcome.encrypted_group_info,
            &[],
            &welcome_key,
            &welcome_nonce,
        )
        .unwrap();
        let group_info = GroupInfo::decode_detached(&group_info_bytes).unwrap();
        //let group_info = GroupInfo::decode(&mut Cursor::new(&group_info_bytes)).unwrap();
        let signer_node = group_info.tree[TreeIndex::from(group_info.signer_index).as_usize()]
            .clone()
            .unwrap();
        assert_eq!(signer_node.node_type, NodeType::Leaf);
        let signer_key_package = signer_node.key_package.unwrap();
        assert!(signer_key_package.self_verify());
        let payload = group_info.unsigned_payload().unwrap();
        assert!(signer_key_package
            .credential
            .verify(&payload, &group_info.signature));
        let nodes = group_info.tree;
        assert!(Tree::verify_integrity(ciphersuite, &nodes));
        let mut index_option = None;
        for (i, node_option) in nodes.iter().enumerate() {
            if let Some(node) = node_option {
                if let Some(kp) = node.key_package.clone() {
                    if kp == kpb.key_package {
                        index_option = Some(TreeIndex::from(i));
                        break;
                    }
                }
            }
        }
        assert!(index_option.is_some());
        let index = if let Some(index) = index_option {
            index
        } else {
            panic!("Own key package not found in welcome tree");
        };
        let mut tree = Tree::new_from_nodes(ciphersuite, kpb, &nodes, index);
        let common_ancestor =
            treemath::common_ancestor(index, TreeIndex::from(group_info.signer_index));
        let common_path = treemath::dirpath_root(common_ancestor, tree.leaf_count());
        let (path_secrets, _commit_secret) = OwnLeaf::continue_path_secrets(
            ciphersuite,
            &group_secrets.path_secret,
            common_path.len(),
        );
        let keypairs = OwnLeaf::generate_path_keypairs(ciphersuite, path_secrets);
        tree.merge_keypairs(keypairs.clone(), common_path.clone());

        let mut path_keypairs = PathKeypairs::new();
        path_keypairs.add(keypairs, common_path);
        tree.own_leaf.path_keypairs = path_keypairs;

        let config = GroupConfig {
            ciphersuite,
            padding_block_size: GROUP_CONFIG_DEFAULT.padding_block_size,
            update_policy: GROUP_CONFIG_DEFAULT.update_policy,
        };
        let group_context = GroupContext {
            group_id: group_info.group_id,
            epoch: group_info.epoch,
            tree_hash: tree.compute_tree_hash(),
            confirmed_transcript_hash: group_info.confirmed_transcript_hash,
        };
        let group_state = &group_context.encode_detached().unwrap();
        let epoch_secrets = EpochSecrets::derive_epoch_secrets(
            ciphersuite,
            &group_secrets.epoch_secret,
            vec![],
            group_state,
        );
        let astree = ASTree::new(
            ciphersuite,
            &epoch_secrets.application_secret,
            tree.leaf_count(),
        );

        assert_eq!(
            Confirmation::new(
                ciphersuite,
                &epoch_secrets.confirmation_key,
                &group_context.confirmed_transcript_hash
            ),
            Confirmation(group_info.confirmation)
        );

        Group {
            config,
            identity,
            group_context,
            generation: 0,
            epoch_secrets,
            astree,
            tree,
            public_queue: ProposalQueue::new(config.ciphersuite),
            own_queue: ProposalQueue::new(config.ciphersuite),
            pending_kpbs: vec![],
            interim_transcript_hash: group_info.interim_transcript_hash,
        }
    }
    pub fn create_add_proposal(
        &mut self,
        kp: &KeyPackage,
        authenticated_data: Option<&[u8]>,
    ) -> MLSPlaintext {
        let add_proposal = AddProposal {
            key_package: kp.clone(), // TODO Check kp
        };
        let proposal = Proposal::Add(add_proposal);
        self.add_own_proposal(proposal.clone());
        let content = MLSPlaintextContentType::Proposal(proposal);
        MLSPlaintext::new(
            self.get_sender_index(),
            authenticated_data.unwrap_or(&[]),
            content,
            &self.identity.keypair,
            &self.get_context(),
        )
    }
    pub fn create_update_proposal(&mut self, authenticated_data: Option<&[u8]>) -> MLSPlaintext {
        let kpb = KeyPackageBundle::new(self.config.ciphersuite, &self.identity, None);
        let update_proposal = UpdateProposal {
            key_package: kpb.key_package.clone(), // TODO Check KP
        };
        let proposal = Proposal::Update(update_proposal);
        self.add_own_proposal(proposal.clone());
        self.pending_kpbs.push(kpb);
        let content = MLSPlaintextContentType::Proposal(proposal);
        MLSPlaintext::new(
            self.get_sender_index(),
            authenticated_data.unwrap_or(&[]),
            content,
            &self.identity.keypair,
            &self.get_context(),
        )
    }
    pub fn create_remove_proposal(
        &mut self,
        removed: u32,
        authenticated_data: Option<&[u8]>,
    ) -> MLSPlaintext {
        let remove_proposal = RemoveProposal { removed };
        let proposal = Proposal::Remove(remove_proposal); // TODO Check index
        self.add_own_proposal(proposal.clone());
        let content = MLSPlaintextContentType::Proposal(proposal);
        MLSPlaintext::new(
            self.get_sender_index(),
            authenticated_data.unwrap_or(&[]),
            content,
            &self.identity.keypair,
            &self.get_context(),
        )
    }
    fn add_own_proposal(&mut self, proposal: Proposal) {
        // TODO remove kpb from QueuedProposal or get rid of this altogether
        let queued_proposal = QueuedProposal::new(proposal, self.get_sender_index(), None);
        self.own_queue.add(queued_proposal.clone());
        self.public_queue.add(queued_proposal);
    }
    pub fn create_commit(
        &mut self,
        authenticated_data: Option<&[u8]>,
    ) -> (MLSPlaintext, Welcome, MembershipChanges) {
        let ciphersuite = self.config.ciphersuite;
        // TODO Dedup proposals
        let proposal_id_list = self.public_queue.clone().get_commit_lists();
        let mut new_tree = self.tree.clone();

        let (membership_changes, invited_members, _self_removed) = new_tree.apply_proposals(
            proposal_id_list.clone(),
            self.public_queue.clone(),
            self.pending_kpbs.clone(),
        );

        let keypair = HPKEKeyPair::new(self.config.ciphersuite.into()).unwrap();
        let (path, path_secrets, commit_secret, kpb) =
            new_tree.update_own_leaf(&self.identity, Some(&keypair), None);
        let commit = Commit {
            updates: proposal_id_list.updates,
            removes: proposal_id_list.removes,
            adds: proposal_id_list.adds,
            key_package: kpb.key_package.clone(),
            path,
        };

        new_tree.print("Create commit: tree after update_own_leaf");

        let mut new_epoch = self.group_context.epoch;
        new_epoch.increment();

        let confirmed_transcript_hash = Self::update_confirmed_transcript_hash(
            self.config.ciphersuite,
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
            ciphersuite,
            commit_secret,
            None,
            &new_group_context.serialize(),
        );

        let confirmation = Confirmation::new(
            ciphersuite,
            &new_epoch_secrets.confirmation_key,
            &confirmed_transcript_hash,
        );

        let content = MLSPlaintextContentType::Commit((commit, confirmation.clone()));
        let mls_plaintext = MLSPlaintext::new(
            self.get_sender_index(),
            authenticated_data.unwrap_or(&[]),
            content,
            &self.identity.keypair,
            &self.get_context(),
        );

        let interim_transcript_hash = Self::update_interim_transcript_hash(
            ciphersuite,
            &mls_plaintext,
            &confirmed_transcript_hash,
        );

        let mut group_info = GroupInfo {
            group_id: new_group_context.group_id.clone(),
            epoch: new_group_context.epoch,
            tree: new_tree.public_key_tree(),
            confirmed_transcript_hash,
            interim_transcript_hash,
            extensions: vec![],
            confirmation: confirmation.0,
            signer_index: self.get_sender_index(),
            signature: Signature::new_empty(),
        };
        group_info.signature = group_info.sign(&self.identity);

        let welcome_secret = hkdf::expand(
            ciphersuite.into(),
            &epoch_secret,
            b"mls 1.0 welcome",
            hash::hash_length(ciphersuite.into()),
        )
        .unwrap();
        let welcome_nonce = aead::Nonce::from_slice(
            &hkdf::expand(
                ciphersuite.into(),
                &welcome_secret,
                b"nonce",
                aead::Nonce::nonce_length(ciphersuite.into()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let welcome_key = aead::AEADKey::from_slice(
            ciphersuite.into(),
            &hkdf::expand(
                ciphersuite.into(),
                &welcome_secret,
                b"key",
                aead::AEADKey::key_length(ciphersuite.into()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        let encrypted_group_info = aead::aead_seal(
            ciphersuite.into(),
            &group_info.encode_detached().unwrap(),
            &[],
            &welcome_key,
            &welcome_nonce,
        )
        .unwrap();

        let mut secrets = vec![];
        for (index, add_proposal) in invited_members.clone() {
            let key_package = add_proposal.key_package;
            let key_package_hash =
                hash::hash(ciphersuite.into(), &key_package.encode_detached().unwrap());
            let common_ancestor = treemath::common_ancestor(index, self.tree.own_leaf.leaf_index);
            let dirpath =
                treemath::dirpath_root(self.tree.own_leaf.leaf_index, new_tree.leaf_count());
            let position = dirpath.iter().position(|&x| x == common_ancestor).unwrap();
            let path_secret = path_secrets[position].clone();
            let group_secrets = GroupSecrets {
                epoch_secret: epoch_secret.clone(),
                path_secret,
            };
            let group_secrets_bytes = group_secrets.encode_detached().unwrap();
            let encrypted_group_secrets = HpkeCiphertext::seal(
                ciphersuite,
                &key_package.hpke_init_key,
                &group_secrets_bytes,
                None,
                None,
            )
            .unwrap();
            let encrypted_group_secrets = EncryptedGroupSecrets {
                key_package_hash,
                encrypted_group_secrets,
            };
            secrets.push(encrypted_group_secrets);
        }
        let welcome = Welcome {
            version: ProtocolVersion::Mls10,
            cipher_suite: ciphersuite,
            secrets,
            encrypted_group_info,
        };

        self.pending_kpbs.push(kpb);

        (mls_plaintext, welcome, membership_changes)
    }
    pub fn process_commit(&mut self, mls_plaintext: MLSPlaintext) -> MembershipChanges {
        let ciphersuite = self.config.ciphersuite;
        let sender = mls_plaintext.sender.sender;
        let is_own_commit = mls_plaintext.sender.as_tree_index() == self.tree.own_leaf.leaf_index;
        // TODO return an error in case of failure
        assert_eq!(mls_plaintext.epoch, self.group_context.epoch);
        let (commit, confirmation) = match mls_plaintext.content.clone() {
            MLSPlaintextContentType::Commit((commit, confirmation)) => (commit, confirmation),
            _ => panic!("No Commit in MLSPlaintext"),
        };
        let kp = commit.key_package.clone();
        // TODO return an error in case of failure
        assert!(kp.self_verify());
        assert!(mls_plaintext.verify(&self.group_context, &kp.credential));

        let mut new_tree = self.tree.clone();

        let proposal_id_list = ProposalIDList {
            updates: commit.updates.clone(),
            removes: commit.removes.clone(),
            adds: commit.adds.clone(),
        };

        let (membership_changes, _invited_members, self_removed) = new_tree.apply_proposals(
            proposal_id_list,
            self.public_queue.clone(),
            self.pending_kpbs.clone(),
        );

        // TODO save this state in the group to prevent future operations
        if self_removed {
            return membership_changes;
        }

        let commit_secret = if is_own_commit {
            let own_kpb = self
                .pending_kpbs
                .iter()
                .find(|&kpb| kpb.key_package == kp)
                .unwrap();
            // TODO no need to encrypt to copath
            let (_path, _path_secrets, commit_secret, _kpb) =
                new_tree.update_own_leaf(&self.identity, None, Some(own_kpb.clone()));
            new_tree.print("Process commit: tree after update_own_leaf");
            commit_secret
        } else {
            new_tree.update_direct_path(sender, commit.path.clone(), commit.key_package.clone())
        };

        let mut new_epoch = self.group_context.epoch;
        new_epoch.increment();

        let confirmed_transcript_hash = Self::update_confirmed_transcript_hash(
            self.config.ciphersuite,
            &MLSPlaintextCommitContent::new(
                &self.group_context,
                mls_plaintext.sender.sender,
                commit,
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
            ciphersuite,
            commit_secret,
            None,
            &new_group_context.serialize(),
        );

        let interim_transcript_hash = Self::update_interim_transcript_hash(
            ciphersuite,
            &mls_plaintext,
            &confirmed_transcript_hash,
        );

        new_tree.print("Process commit: ");

        assert_eq!(
            Confirmation::new(
                ciphersuite,
                &new_epoch_secrets.confirmation_key,
                &confirmed_transcript_hash
            ),
            confirmation
        );

        if !is_own_commit {
            let parent_hash = new_tree.compute_parent_hash(TreeIndex::from(sender));

            if let Some(received_parent_hash) = kp.get_extension(ExtensionType::ParentHash) {
                if let ExtensionPayload::ParentHash(parent_hash_inner) = received_parent_hash {
                    assert_eq!(parent_hash, parent_hash_inner.parent_hash);
                } else {
                    panic!("Wrong extension type: expected ParentHashExtension");
                };
            } else {
                panic!("Commit didn't contain a ParentHash extension");
            }
        }

        self.tree = new_tree;
        self.group_context = new_group_context;
        self.epoch_secrets = new_epoch_secrets;
        self.interim_transcript_hash = interim_transcript_hash;
        self.astree = ASTree::new(
            self.config.ciphersuite,
            &self.epoch_secrets.application_secret,
            self.tree.leaf_count(),
        );
        self.own_queue = ProposalQueue::new(self.config.ciphersuite);
        self.public_queue = ProposalQueue::new(self.config.ciphersuite);

        // TODO: return discarded proposals
        membership_changes
    }
    pub fn process_proposal(&mut self, mls_plaintext: MLSPlaintext) {
        let validator = Validator::new(&self);
        assert_eq!(mls_plaintext.content_type, ContentType::Proposal);
        let proposal_option = match mls_plaintext.content {
            MLSPlaintextContentType::Proposal(proposal) => Some(proposal),
            _ => None,
        };
        assert!(proposal_option.is_some());
        if let Some(proposal) = proposal_option {
            assert!(validator.validate_proposal(&proposal.clone(), mls_plaintext.sender));
            let queued_proposal = QueuedProposal {
                proposal,
                sender: mls_plaintext.sender,
                own_kpb: None,
            };
            self.public_queue.add(queued_proposal);
        }
    }
    pub fn create_application_message(
        &mut self,
        message: &[u8],
        authenticated_data: Option<&[u8]>,
    ) -> MLSPlaintext {
        let content = MLSPlaintextContentType::Application(message.to_vec());
        MLSPlaintext::new(
            self.get_sender_index(),
            authenticated_data.unwrap_or(&[]),
            content,
            &self.identity.keypair,
            &self.get_context(),
        )
    }
    pub fn encrypt(&mut self, mls_plaintext: &MLSPlaintext) -> Vec<u8> {
        let context = &self.get_context();
        let mls_ciphertext = MLSCiphertext::new_from_plaintext(
            &mls_plaintext,
            &mut self.astree,
            &self.epoch_secrets,
            context,
            self.config,
        );
        mls_ciphertext.encode_detached().unwrap() // TODO: error handling
    }
    pub fn decrypt(&mut self, message: &[u8]) -> MLSPlaintext {
        let context = &self.get_context();
        let mls_ciphertext = MLSCiphertext::decode_detached(&message).unwrap();
        mls_ciphertext.to_plaintext(
            &self.roster(),
            &self.epoch_secrets,
            &mut self.astree,
            context,
            self.config,
        )
    }
    pub fn update_confirmed_transcript_hash(
        ciphersuite: CipherSuite,
        mls_plaintext_commit_content: &MLSPlaintextCommitContent,
        interim_transcript_hash: &[u8],
    ) -> Vec<u8> {
        let mls_plaintext_commit_content_bytes =
            mls_plaintext_commit_content.encode_detached().unwrap();
        hash::hash(
            ciphersuite.into(),
            &[interim_transcript_hash, &mls_plaintext_commit_content_bytes].concat(),
        )
    }
    pub fn update_interim_transcript_hash(
        ciphersuite: CipherSuite,
        mls_plaintext: &MLSPlaintext,
        confirmed_transcript_hash: &[u8],
    ) -> Vec<u8> {
        let mls_plaintext_auth_data_bytes =
            &MLSPlaintextCommitAuthData::from(mls_plaintext.clone())
                .encode_detached()
                .unwrap();
        hash::hash(
            ciphersuite.into(),
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
            let node = self.tree.nodes[TreeIndex::from(RosterIndex::from(i)).as_usize()].clone();
            let credential = node.key_package.unwrap().credential;
            roster.push(credential);
        }
        roster
    }
    pub fn get_sender_index(&self) -> RosterIndex {
        RosterIndex::from(self.tree.own_leaf.leaf_index)
    }
    fn get_context(&self) -> GroupContext {
        self.group_context.clone()
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
    pub fn from_bytes(bytes: &[u8]) -> Self {
        GroupId {
            value: bytes.to_vec(),
        }
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
    pub ciphersuite: CipherSuite,
    pub padding_block_size: u32,
    pub update_policy: u8, // FIXME
}

impl Codec for GroupConfig {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.ciphersuite.encode(buffer)?;
        self.padding_block_size.encode(buffer)?;
        self.update_policy.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let ciphersuite = CipherSuite::decode(cursor)?;
        let padding_block_size = u32::decode(cursor)?;
        let update_policy = u8::decode(cursor)?;
        Ok(GroupConfig {
            ciphersuite,
            padding_block_size,
            update_policy,
        })
    }
}

pub const GROUP_CONFIG_DEFAULT: GroupConfig = GroupConfig {
    ciphersuite: CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519,
    padding_block_size: 10,
    update_policy: 0,
};

#[test]
fn group_operations() {
    let ciphersuite = CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519;

    // Define identities
    let alice_identity = Identity::new(ciphersuite, "Alice".into());
    let bob_identity = Identity::new(ciphersuite, "Bob".into());
    let charlie_identity = Identity::new(ciphersuite, "Charlie".into());

    let _alice_credential = BasicCredential::from(&alice_identity);
    let _bob_credential = BasicCredential::from(&bob_identity);
    let _charlie_credential = BasicCredential::from(&bob_identity);

    // Generate UserInitKeys
    let bob_init_key_bundle = KeyPackageBundle::new(ciphersuite, &bob_identity, None);
    let bob_init_key = bob_init_key_bundle.key_package.clone();

    let charlie_init_key_bundle = KeyPackageBundle::new(ciphersuite, &charlie_identity, None);
    let charlie_init_key = charlie_init_key_bundle.key_package.clone();

    // Create a group with Alice
    let mut config = GROUP_CONFIG_DEFAULT;
    config.ciphersuite = ciphersuite;

    let mut group_alice = Group::new(alice_identity, GroupId::random(), config);

    // Alice sends a message to herself
    let message_alice = [1, 2, 3];
    let mls_plaintext = group_alice.create_application_message(&message_alice, Some(&[4, 5, 6]));
    let encrypted_message = group_alice.encrypt(&mls_plaintext);
    let decrypted_mls_plaintext = group_alice.decrypt(&encrypted_message);
    assert_eq!(mls_plaintext, decrypted_mls_plaintext);

    // Alice adds Bob
    let _bob_add_proposal = group_alice.create_add_proposal(&bob_init_key, None);

    let (commit1, welcome_alice_bob, ms1) = group_alice.create_commit(None);
    println!("{:?}", ms1);

    group_alice.process_commit(commit1);

    let mut group_bob =
        Group::new_from_welcome(bob_identity, welcome_alice_bob, bob_init_key_bundle);

    assert_eq!(group_alice.tree.nodes, group_bob.tree.nodes);

    // Alice sends a message to Bob
    let message_alice = [1, 2, 3];
    let mls_plaintext_alice = group_alice.create_application_message(&message_alice, None);
    let encrypted_message = group_alice.encrypt(&mls_plaintext_alice);
    let mls_plaintext_bob = group_bob.decrypt(&encrypted_message);
    assert_eq!(mls_plaintext_alice, mls_plaintext_bob);

    // Bob updates and commits
    let update_proposal_bob = group_bob.create_update_proposal(None);
    let (commit2, _welcome, ms2) = group_bob.create_commit(None);
    println!("{:?}", ms2);

    group_alice.process_proposal(update_proposal_bob);
    group_alice.process_commit(commit2.clone());
    group_bob.process_commit(commit2);

    // Alice updates and commits
    let update_proposal_alice = group_alice.create_update_proposal(None);
    let (commit3, _welcome, ms3) = group_alice.create_commit(None);
    println!("{:?}", ms3);

    group_bob.process_proposal(update_proposal_alice);
    group_alice.process_commit(commit3.clone());
    group_bob.process_commit(commit3);

    // Alice updates and Bob commits
    let update_proposal_alice = group_alice.create_update_proposal(None);
    group_bob.process_proposal(update_proposal_alice);
    let (commit4, _welcome, ms4) = group_bob.create_commit(None);
    println!("{:?}", ms4);

    group_bob.process_commit(commit4.clone());
    group_alice.process_commit(commit4);

    // Bob updates and Alice commits
    let update_proposal_bob = group_bob.create_update_proposal(None);
    group_alice.process_proposal(update_proposal_bob);
    let (commit5, _welcome, ms5) = group_alice.create_commit(None);
    println!("{:?}", ms5);

    group_alice.process_commit(commit5.clone());
    group_bob.process_commit(commit5);

    // Bob adds Charlie
    let add_proposal = group_bob.create_add_proposal(&charlie_init_key, None);
    group_alice.process_proposal(add_proposal);

    let (commit6, welcome, ms6) = group_bob.create_commit(None);
    println!("{:?}", ms6);

    group_alice.process_commit(commit6.clone());
    group_bob.process_commit(commit6);

    let mut group_charlie =
        Group::new_from_welcome(charlie_identity, welcome, charlie_init_key_bundle);

    // Charlie updates
    let update_proposal_charlie = group_charlie.create_update_proposal(None);

    group_alice.process_proposal(update_proposal_charlie.clone());
    group_bob.process_proposal(update_proposal_charlie);

    let (commit7, _welcome, ms7) = group_charlie.create_commit(None);
    println!("{:?}", ms7);

    group_alice.process_commit(commit7.clone());
    group_bob.process_commit(commit7.clone());
    group_charlie.process_commit(commit7);

    // Alice updates
    let update_proposal_alice = group_alice.create_update_proposal(None);

    group_bob.process_proposal(update_proposal_alice.clone());
    group_charlie.process_proposal(update_proposal_alice);

    let (commit8, _welcome, ms8) = group_alice.create_commit(None);
    println!("{:?}", ms8);

    group_alice.process_commit(commit8.clone());
    group_bob.process_commit(commit8.clone());
    group_charlie.process_commit(commit8);

    // Charlie removes Bob
    let remove_proposal_charlie = group_charlie.create_remove_proposal(2, None);

    group_alice.process_proposal(remove_proposal_charlie.clone());
    group_bob.process_proposal(remove_proposal_charlie);

    let (commit9, _welcome, ms9) = group_charlie.create_commit(None);
    println!("{:?}", ms9);

    group_alice.process_commit(commit9.clone());
    group_bob.process_commit(commit9.clone());
    group_charlie.process_commit(commit9);
}
