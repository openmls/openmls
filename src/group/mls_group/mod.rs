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
use crate::client::*;
use crate::codec::*;
use crate::creds::*;
use crate::framing::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::*;
use crate::schedule::*;
use crate::tree::astree::*;
use crate::tree::*;

pub use api::*;
use apply_commit::*;
use create_commit::*;
use new_from_welcome::*;

pub struct MlsGroup {
    ciphersuite_name: CiphersuiteName,
    client: Client,
    group_context: GroupContext,
    generation: u32,
    epoch_secrets: EpochSecrets,
    astree: ASTree,
    tree: RatchetTree,
    interim_transcript_hash: Vec<u8>,
}

impl Api for MlsGroup {
    fn new(creator: Client, id: &[u8], ciphersuite_name: CiphersuiteName) -> MlsGroup {
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
        MlsGroup {
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
        nodes_option: Option<Vec<Option<Node>>>,
        kpb: KeyPackageBundle,
    ) -> Result<MlsGroup, WelcomeError> {
        new_from_welcome(joiner, welcome, nodes_option, kpb)
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
    ) -> (MLSPlaintext, Option<Welcome>, Option<KeyPackageBundle>) {
        create_commit(self, aad, proposals, own_key_packages, force_self_update)
    }

    // Apply a Commit message
    fn apply_commit(
        &mut self,
        mls_plaintext: MLSPlaintext,
        proposals: Vec<(Sender, Proposal)>,
        own_key_packages: Vec<(HPKEPrivateKey, KeyPackage)>,
    ) -> Result<(), ApplyCommitError> {
        apply_commit(self, mls_plaintext, proposals, own_key_packages)
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
        mls_ciphertext.to_plaintext(
            &self.get_ciphersuite().clone(),
            &self.roster(),
            &self.epoch_secrets,
            &mut self.astree,
            context,
        )
    }

    // Exporter
    fn get_exporter_secret(&self, label: &str, key_length: usize) -> Vec<u8> {
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
        let group = MlsGroup {
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

impl MlsGroup {
    pub fn get_tree(&self) -> &RatchetTree {
        &self.tree
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
    fn get_sender_index(&self) -> LeafIndex {
        LeafIndex::from(self.tree.get_own_index())
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

// Helper functions

fn update_confirmed_transcript_hash(
    ciphersuite: &Ciphersuite,
    mls_plaintext_commit_content: &MLSPlaintextCommitContent,
    interim_transcript_hash: &[u8],
) -> Vec<u8> {
    let mls_plaintext_commit_content_bytes =
        mls_plaintext_commit_content.encode_detached().unwrap();
    ciphersuite.hash(&[interim_transcript_hash, &mls_plaintext_commit_content_bytes].concat())
}

fn update_interim_transcript_hash(
    ciphersuite: &Ciphersuite,
    mls_plaintext: &MLSPlaintext,
    confirmed_transcript_hash: &[u8],
) -> Vec<u8> {
    let mls_plaintext_auth_data_bytes = &MLSPlaintextCommitAuthData::from(mls_plaintext.clone())
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
