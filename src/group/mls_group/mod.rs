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

mod api;
mod apply_commit;
mod create_commit;
mod new_from_welcome;

use crate::ciphersuite::*;
use crate::codec::*;
use crate::framing::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::{proposals::*, *};
use crate::schedule::*;
use crate::tree::{index::*, node::*, secret_tree::*, *};

pub use api::*;

use std::cell::{Ref, RefCell};
use std::convert::TryFrom;

pub struct MlsGroup {
    ciphersuite: Ciphersuite,
    group_context: GroupContext,
    generation: u32,
    epoch_secrets: EpochSecrets,
    secret_tree: RefCell<SecretTree>,
    tree: RefCell<RatchetTree>,
    interim_transcript_hash: Vec<u8>,
}

impl Api for MlsGroup {
    fn new(
        id: &[u8],
        ciphersuite_name: CiphersuiteName,
        key_package_bundle: KeyPackageBundle,
    ) -> MlsGroup {
        let group_id = GroupId { value: id.to_vec() };
        let epoch_secrets = EpochSecrets::new();
        let secret_tree = SecretTree::new(&epoch_secrets.encryption_secret, LeafIndex::from(1u32));
        let (private_key, key_package) = (
            key_package_bundle.private_key,
            key_package_bundle.key_package,
        );
        let kpb = KeyPackageBundle::from_values(key_package, private_key);
        let tree = RatchetTree::new(ciphersuite_name, kpb);
        let group_context = GroupContext {
            group_id,
            epoch: GroupEpoch(0),
            tree_hash: tree.compute_tree_hash(),
            confirmed_transcript_hash: vec![],
        };
        let interim_transcript_hash = vec![];
        MlsGroup {
            ciphersuite: Ciphersuite::new(ciphersuite_name),
            group_context,
            generation: 0,
            epoch_secrets,
            secret_tree: RefCell::new(secret_tree),
            tree: RefCell::new(tree),
            interim_transcript_hash,
        }
    }
    // Join a group from a welcome message
    fn new_from_welcome(
        welcome: Welcome,
        nodes_option: Option<Vec<Option<Node>>>,
        kpb: KeyPackageBundle,
    ) -> Result<Self, WelcomeError> {
        Self::new_from_welcome_internal(welcome, nodes_option, kpb)
    }

    // === Create handshake messages ===
    // TODO: share functionality between these.

    // 11.1.1. Add
    // struct {
    //     KeyPackage key_package;
    // } Add;
    fn create_add_proposal(
        &self,
        aad: &[u8],
        signature_key: &SignaturePrivateKey,
        joiner_key_package: KeyPackage,
    ) -> MLSPlaintext {
        let add_proposal = AddProposal {
            key_package: joiner_key_package,
        };
        let proposal = Proposal::Add(add_proposal);
        let content = MLSPlaintextContentType::Proposal(proposal);
        MLSPlaintext::new(
            &self.ciphersuite,
            self.get_sender_index(),
            aad,
            content,
            signature_key,
            &self.get_context(),
        )
    }

    // 11.1.2. Update
    // struct {
    //     KeyPackage key_package;
    // } Update;
    fn create_update_proposal(
        &self,
        aad: &[u8],
        signature_key: &SignaturePrivateKey,
        key_package: KeyPackage,
    ) -> MLSPlaintext {
        let update_proposal = UpdateProposal { key_package };
        let proposal = Proposal::Update(update_proposal);
        let content = MLSPlaintextContentType::Proposal(proposal);
        MLSPlaintext::new(
            &self.ciphersuite,
            self.get_sender_index(),
            aad,
            content,
            signature_key,
            &self.get_context(),
        )
    }

    // 11.1.3. Remove
    // struct {
    //     uint32 removed;
    // } Remove;
    fn create_remove_proposal(
        &self,
        aad: &[u8],
        signature_key: &SignaturePrivateKey,
        removed_index: LeafIndex,
    ) -> MLSPlaintext {
        let remove_proposal = RemoveProposal {
            removed: removed_index.into(),
        };
        let proposal = Proposal::Remove(remove_proposal);
        let content = MLSPlaintextContentType::Proposal(proposal);
        MLSPlaintext::new(
            &self.ciphersuite,
            self.get_sender_index(),
            aad,
            content,
            signature_key,
            &self.get_context(),
        )
    }

    // === ===

    // 11.2. Commit
    // opaque ProposalID<0..255>;
    //
    // struct {
    //     ProposalID proposals<0..2^32-1>;
    //     optional<UpdatePath> path;
    // } Commit;
    fn create_commit(
        &self,
        aad: &[u8],
        signature_key: &SignaturePrivateKey,
        proposals: Vec<MLSPlaintext>,
        force_self_update: bool,
    ) -> CreateCommitResult {
        self.create_commit_internal(aad, signature_key, proposals, force_self_update)
    }

    // Apply a Commit message
    fn apply_commit(
        &mut self,
        mls_plaintext: MLSPlaintext,
        proposals: Vec<MLSPlaintext>,
        own_key_packages: Vec<KeyPackageBundle>,
    ) -> Result<(), ApplyCommitError> {
        self.apply_commit_internal(mls_plaintext, proposals, own_key_packages)
    }

    // Create application message
    fn create_application_message(
        &mut self,
        aad: &[u8],
        msg: &[u8],
        signature_key: &SignaturePrivateKey,
    ) -> MLSCiphertext {
        let content = MLSPlaintextContentType::Application(msg.to_vec());
        let mls_plaintext = MLSPlaintext::new(
            &self.ciphersuite,
            self.get_sender_index(),
            aad,
            content,
            signature_key,
            &self.get_context(),
        );
        self.encrypt(mls_plaintext)
    }

    // Encrypt/Decrypt MLS message
    fn encrypt(&mut self, mls_plaintext: MLSPlaintext) -> MLSCiphertext {
        let mut secret_tree = self.secret_tree.borrow_mut();
        let secret_type = SecretType::try_from(&mls_plaintext).unwrap();
        let (generation, ratchet_secrets) = secret_tree.get_secret_for_encryption(
            &self.ciphersuite,
            mls_plaintext.sender.sender,
            secret_type,
        );
        MLSCiphertext::new_from_plaintext(&mls_plaintext, &self, generation, &ratchet_secrets)
    }

    fn decrypt(&mut self, mls_ciphertext: MLSCiphertext) -> Result<MLSPlaintext, DecryptionError> {
        let tree = self.tree.borrow();
        let mut roster = Vec::new();
        for i in 0..tree.leaf_count().as_usize() {
            let node = &tree.nodes[NodeIndex::from(i).as_usize()];
            let credential = if let Some(kp) = &node.key_package {
                kp.get_credential()
            } else {
                panic!("Missing key package");
            };
            roster.push(credential);
        }

        Ok(mls_ciphertext.to_plaintext(
            &self.ciphersuite,
            &roster,
            &self.epoch_secrets,
            &mut self.secret_tree.borrow_mut(),
            &self.group_context,
        )?)
    }

    // Exporter
    fn export_secret(&self, label: &str, key_length: usize) -> Vec<u8> {
        mls_exporter(
            self.get_ciphersuite(),
            &self.epoch_secrets,
            label,
            &self.get_context(),
            key_length,
        )
    }
}

impl Codec for MlsGroup {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.ciphersuite.encode(buffer)?;
        self.group_context.encode(buffer)?;
        self.generation.encode(buffer)?;
        self.epoch_secrets.encode(buffer)?;
        self.secret_tree.borrow().encode(buffer)?;
        self.tree.borrow().encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.interim_transcript_hash)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let ciphersuite = Ciphersuite::decode(cursor)?;
        let group_context = GroupContext::decode(cursor)?;
        let generation = u32::decode(cursor)?;
        let epoch_secrets = EpochSecrets::decode(cursor)?;
        let secret_tree = SecretTree::decode(cursor)?;
        let tree = RatchetTree::decode(cursor)?;
        let interim_transcript_hash = decode_vec(VecSize::VecU8, cursor)?;
        let group = MlsGroup {
            ciphersuite,
            group_context,
            generation,
            epoch_secrets,
            secret_tree: RefCell::new(secret_tree),
            tree: RefCell::new(tree),
            interim_transcript_hash,
        };
        Ok(group)
    }
}

impl MlsGroup {
    pub fn get_tree(&self) -> Ref<RatchetTree> {
        self.tree.borrow()
    }
    fn get_sender_index(&self) -> LeafIndex {
        self.tree.borrow().get_own_node_index().into()
    }
    pub(crate) fn get_ciphersuite(&self) -> &Ciphersuite {
        &self.ciphersuite
    }

    pub(crate) fn get_context(&self) -> &GroupContext {
        &self.group_context
    }

    pub(crate) fn get_epoch_secrets(&self) -> &EpochSecrets {
        &self.epoch_secrets
    }
}

// Helper functions

fn update_confirmed_transcript_hash(
    ciphersuite: &Ciphersuite,
    mls_plaintext_commit_content: &MLSPlaintextCommitContent,
    interim_transcript_hash: &[u8],
) -> Vec<u8> {
    let commit_content_bytes = mls_plaintext_commit_content.serialize();
    ciphersuite.hash(&[interim_transcript_hash, &commit_content_bytes].concat())
}

fn update_interim_transcript_hash(
    ciphersuite: &Ciphersuite,
    mls_plaintext_commit_auth_data: &MLSPlaintextCommitAuthData,
    confirmed_transcript_hash: &[u8],
) -> Vec<u8> {
    let commit_auth_data_bytes = mls_plaintext_commit_auth_data.serialize();
    ciphersuite.hash(&[confirmed_transcript_hash, &commit_auth_data_bytes].concat())
}

fn compute_welcome_key_nonce(
    ciphersuite: &Ciphersuite,
    joiner_secret: &[u8],
) -> (AeadKey, AeadNonce) {
    let welcome_secret = ciphersuite
        .hkdf_expand(joiner_secret, b"mls 1.0 welcome", ciphersuite.hash_length())
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
    (welcome_key, welcome_nonce)
}
