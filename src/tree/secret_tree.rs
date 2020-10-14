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

use crate::ciphersuite::*;
use crate::codec::*;
use crate::framing::*;
use crate::schedule::*;
use crate::tree::{index::*, sender_ratchet::*, treemath::*};
use std::convert::TryFrom;

#[derive(Debug, PartialEq)]
pub enum SecretTreeError {
    TooDistantInThePast,
    TooDistantInTheFuture,
    IndexOutOfBounds,
}

#[derive(Debug, Copy, Clone)]
pub enum SecretType {
    HandshakeSecret,
    ApplicationSecret,
}

#[derive(Debug)]
pub enum SecretTypeError {
    InvalidContentType,
}

impl TryFrom<&ContentType> for SecretType {
    type Error = SecretTypeError;

    fn try_from(content_type: &ContentType) -> Result<SecretType, SecretTypeError> {
        match content_type {
            ContentType::Application => Ok(SecretType::ApplicationSecret),
            ContentType::Commit => Ok(SecretType::HandshakeSecret),
            ContentType::Proposal => Ok(SecretType::HandshakeSecret),
            _ => Err(SecretTypeError::InvalidContentType),
        }
    }
}

impl TryFrom<&MLSPlaintext> for SecretType {
    type Error = SecretTypeError;

    fn try_from(mls_plaintext: &MLSPlaintext) -> Result<SecretType, SecretTypeError> {
        SecretType::try_from(&mls_plaintext.content_type)
    }
}

/// Derives secrets for inner nodes of a SecretTree
pub(crate) fn derive_tree_secret(
    ciphersuite: &Ciphersuite,
    secret: &[u8],
    label: &str,
    node: u32,
    generation: u32,
    length: usize,
) -> Vec<u8> {
    let tree_context = TreeContext { node, generation };
    let serialized_tree_context = tree_context.encode_detached().unwrap();
    hkdf_expand_label(ciphersuite, secret, label, &serialized_tree_context, length)
}

#[derive(Debug, PartialEq)]
pub struct RatchetSecrets {
    nonce: AeadNonce,
    key: AeadKey,
}

impl RatchetSecrets {
    pub(crate) fn new(nonce: AeadNonce, key: AeadKey) -> Self {
        RatchetSecrets { nonce, key }
    }

    /// Get a reference to the key.
    pub(crate) fn get_key(&self) -> &AeadKey {
        &self.key
    }

    /// Get a reference to the nonce.
    pub(crate) fn get_nonce(&self) -> &AeadNonce {
        &self.nonce
    }
}

pub struct TreeContext {
    node: u32,
    generation: u32,
}

impl Codec for TreeContext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node.encode(buffer)?;
        self.generation.encode(buffer)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let node = u32::decode(cursor)?;
    //     let generation = u32::decode(cursor)?;
    //     Ok(ApplicationContext { node, generation })
    // }
}

#[derive(Clone)]
pub struct SecretTreeNode {
    pub secret: Vec<u8>,
}

pub struct SecretTree {
    nodes: Vec<Option<SecretTreeNode>>,
    handshake_sender_ratchets: Vec<Option<SenderRatchet>>,
    application_sender_ratchets: Vec<Option<SenderRatchet>>,
    size: LeafIndex,
}

impl Codec for SecretTree {
    // fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
    //     self.group.get_ciphersuite().encode(buffer)?;
    //     encode_vec(VecSize::VecU32, buffer, &self.nodes)?;
    //     encode_vec(VecSize::VecU32, buffer, &self.sender_ratchets)?;
    //     self.size.encode(buffer)?;
    //     Ok(())
    // }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let ciphersuite = Ciphersuite::decode(cursor)?;
    //     let nodes = decode_vec(VecSize::VecU32, cursor)?;
    //     let sender_ratchets = decode_vec(VecSize::VecU32, cursor)?;
    //     let size = LeafIndex::from(u32::decode(cursor)?);
    //     Ok(ASTree {
    //         ciphersuite,
    //         nodes,
    //         sender_ratchets,
    //         size,
    //     })
    // }
}

impl SecretTree {
    /// Creates a new SecretTree based on an `encryption_secret` and group size `size`.
    /// The inner nodes of the tree and the SenderRatchets only get initialized when secrets
    /// are requested either through `get_secret()` or `next_secret()`.
    pub fn new(encryption_secret: &[u8], size: LeafIndex) -> Self {
        let root = root(size);
        let num_indices = NodeIndex::from(size).as_usize() - 1;
        let mut nodes = vec![None; num_indices];
        nodes[root.as_usize()] = Some(SecretTreeNode {
            secret: encryption_secret.to_vec(),
        });

        SecretTree {
            nodes,
            handshake_sender_ratchets: vec![None; size.as_usize()],
            application_sender_ratchets: vec![None; size.as_usize()],
            size,
        }
    }

    /// Get current generation for a specific SenderRatchet
    pub fn get_generation(&self, index: LeafIndex, secret_type: SecretType) -> u32 {
        match self.get_ratchet_opt(index, secret_type) {
            Some(sender_ratchet) => sender_ratchet.get_generation(),
            None => 0,
        }
    }

    /// Initializes a specific SenderRatchet pair for a given index by calculating and deleteing the appropriate values in the SecretTree
    fn initialize_sender_ratchets(
        &mut self,
        ciphersuite: &Ciphersuite,
        index: LeafIndex,
    ) -> Result<(), SecretTreeError> {
        if index >= self.size {
            return Err(SecretTreeError::IndexOutOfBounds);
        }
        // Check if SenderRatchets are already initialized
        if self
            .get_ratchet_opt(index, SecretType::HandshakeSecret)
            .is_some()
            && self
                .get_ratchet_opt(index, SecretType::ApplicationSecret)
                .is_some()
        {
            return Ok(());
        }
        // Calculate direct path
        let index_in_tree = NodeIndex::from(index);
        let mut dir_path = vec![index_in_tree];
        dir_path.extend(dirpath(index_in_tree, self.size));
        dir_path.push(root(self.size));
        let mut empty_nodes: Vec<NodeIndex> = vec![];
        for n in dir_path {
            empty_nodes.push(n);
            if self.nodes[n.as_usize()].is_some() {
                break;
            }
        }
        // Remove leaf and invert direct path
        empty_nodes.remove(0);
        empty_nodes.reverse();
        // Find empty nodes
        for n in empty_nodes {
            self.derive_down(ciphersuite, n);
        }
        // Calculate node secret and initialize SenderRatchets
        let node_secret = &self.nodes[index_in_tree.as_usize()]
            .as_ref()
            .unwrap()
            .secret;
        let handshake_ratchet_secret = derive_tree_secret(
            ciphersuite,
            node_secret,
            "handshake",
            index.as_u32(),
            0,
            ciphersuite.hkdf_length(),
        );
        let handshake_sender_ratchet = SenderRatchet::new(index, &handshake_ratchet_secret);
        self.handshake_sender_ratchets[index.as_usize()] = Some(handshake_sender_ratchet);
        let application_ratchet_secret = derive_tree_secret(
            ciphersuite,
            node_secret,
            "application",
            index.as_u32(),
            0,
            ciphersuite.hkdf_length(),
        );
        let application_sender_ratchet = SenderRatchet::new(index, &application_ratchet_secret);
        self.application_sender_ratchets[index.as_usize()] = Some(application_sender_ratchet);
        // Delete leaf node
        self.nodes[index_in_tree.as_usize()] = None;
        Ok(())
    }

    /// Return RatchetSecrets for a given index and generation. This should be called when decrypting
    /// an MLSCiphertext received fromanother member. Returns an error if index or genartion are out of bound.
    pub fn get_secret_for_decryption(
        &mut self,
        ciphersuite: &Ciphersuite,
        index: LeafIndex,
        secret_type: SecretType,
        generation: u32,
    ) -> Result<RatchetSecrets, SecretTreeError> {
        // Check tree bounds
        if index >= self.size {
            return Err(SecretTreeError::IndexOutOfBounds);
        }
        if self.get_ratchet_opt(index, secret_type).is_none() {
            self.initialize_sender_ratchets(ciphersuite, index)?;
        }
        let sender_ratchet = self.get_ratchet_mut(index, secret_type);
        sender_ratchet.get_secret_for_decryption(ciphersuite, generation)
    }

    /// Return the next RatchetSecrets that should be used for encryption and then increments the generation.
    pub fn get_secret_for_encryption(
        &mut self,
        ciphersuite: &Ciphersuite,
        index: LeafIndex,
        secret_type: SecretType,
    ) -> (u32, RatchetSecrets) {
        if self.get_ratchet_opt(index, secret_type).is_none() {
            self.initialize_sender_ratchets(ciphersuite, index)
                .expect("Index out of bounds");
        }
        let sender_ratchet = self.get_ratchet_mut(index, secret_type);
        sender_ratchet.get_secret_for_encryption(ciphersuite)
    }

    /// Returns a mutable reference to a specific SenderRatchet. The SenderRatchet needs to be initialized.
    fn get_ratchet_mut(&mut self, index: LeafIndex, secret_type: SecretType) -> &mut SenderRatchet {
        let sender_ratchets = match secret_type {
            SecretType::HandshakeSecret => &mut self.handshake_sender_ratchets,
            SecretType::ApplicationSecret => &mut self.application_sender_ratchets,
        };
        sender_ratchets
            .get_mut(index.as_usize())
            .expect("SenderRatchets not initialized")
            .as_mut()
            .expect("SecretTree not initialized")
    }

    /// Returns an optional reference to a specific SenderRatchet
    fn get_ratchet_opt(&self, index: LeafIndex, secret_type: SecretType) -> Option<&SenderRatchet> {
        let sender_ratchets = match secret_type {
            SecretType::HandshakeSecret => &self.handshake_sender_ratchets,
            SecretType::ApplicationSecret => &self.application_sender_ratchets,
        };
        sender_ratchets
            .get(index.as_usize())
            .expect("SenderRatchets not initialized")
            .as_ref()
    }

    /// Derives the secrets for the child leaves in a SecretTree and blanks the parent leaf.
    fn derive_down(&mut self, ciphersuite: &Ciphersuite, index_in_tree: NodeIndex) {
        let hkdf_len = ciphersuite.hkdf_length();
        let node_secret = &self.nodes[index_in_tree.as_usize()]
            .as_ref()
            .unwrap()
            .secret;
        let left_index = left(index_in_tree);
        let right_index = right(index_in_tree, self.size);
        let left_secret = derive_tree_secret(
            &ciphersuite,
            &node_secret,
            "tree",
            left_index.as_u32(),
            0,
            hkdf_len,
        );
        let right_secret = derive_tree_secret(
            &ciphersuite,
            &node_secret,
            "tree",
            right_index.as_u32(),
            0,
            hkdf_len,
        );
        self.nodes[left_index.as_usize()] = Some(SecretTreeNode {
            secret: left_secret,
        });
        self.nodes[right_index.as_usize()] = Some(SecretTreeNode {
            secret: right_secret,
        });
        self.nodes[index_in_tree.as_usize()] = None;
    }
}
