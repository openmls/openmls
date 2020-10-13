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
use crate::schedule::*;
use crate::tree::{index::*, sender_ratchet::*, treemath::*};

// TODO: get rif of Ciphersuite (pass it in get_secret)

#[derive(Debug, PartialEq)]
pub enum ASError {
    TooDistantInThePast,
    TooDistantInTheFuture,
    IndexOutOfBounds,
}

pub(crate) fn derive_app_secret(
    ciphersuite: &Ciphersuite,
    secret: &[u8],
    label: &str,
    node: u32,
    generation: u32,
    length: usize,
) -> Vec<u8> {
    let application_context = ApplicationContext { node, generation };
    let serialized_application_context = application_context.encode_detached().unwrap();
    hkdf_expand_label(
        ciphersuite,
        secret,
        label,
        &serialized_application_context,
        length,
    )
}

#[derive(Debug, PartialEq)]
pub struct ApplicationSecrets {
    nonce: AeadNonce,
    key: AeadKey,
}

impl ApplicationSecrets {
    pub(crate) fn new(nonce: AeadNonce, key: AeadKey) -> Self {
        Self { nonce, key }
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

pub struct ApplicationContext {
    node: u32,
    generation: u32,
}

impl Codec for ApplicationContext {
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
pub struct ASTreeNode {
    pub secret: Vec<u8>,
}

pub struct ASTree {
    nodes: Vec<Option<ASTreeNode>>,
    sender_ratchets: Vec<Option<SenderRatchet>>,
    size: LeafIndex,
}

impl Codec for ASTree {
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

impl ASTree {
    pub fn new(application_secret: &[u8], size: LeafIndex) -> Self {
        let mut out = Self {
            nodes: vec![],
            sender_ratchets: vec![None; size.as_usize()],
            size,
        };
        out.set_application_secrets(application_secret);
        out
    }
    pub(crate) fn set_application_secrets(&mut self, application_secret: &[u8]) {
        let root = root(self.size);
        let num_indices = NodeIndex::from(self.size).as_usize() - 1;
        let mut nodes = vec![None; num_indices];
        nodes[root.as_usize()] = Some(ASTreeNode {
            secret: application_secret.to_vec(),
        });
        self.nodes = nodes;
    }
    pub(crate) fn set_size(&mut self, size: LeafIndex) {
        self.size = size;
    }

    pub fn get_generation(&self, sender: LeafIndex) -> u32 {
        if let Some(sender_ratchet) = &self.sender_ratchets[sender.as_usize()] {
            sender_ratchet.get_generation()
        } else {
            0
        }
    }

    pub fn get_secret(
        &mut self,
        ciphersuite: &Ciphersuite,
        index: LeafIndex,
        generation: u32,
    ) -> Result<ApplicationSecrets, ASError> {
        let index_in_tree = NodeIndex::from(index);
        if index >= self.size {
            return Err(ASError::IndexOutOfBounds);
        }
        if let Some(ratchet_opt) = self.sender_ratchets.get_mut(index.as_usize()) {
            if let Some(ratchet) = ratchet_opt {
                return ratchet.get_secret(generation, ciphersuite);
            }
        }
        let mut dir_path = vec![index_in_tree];
        dir_path.extend(
            dirpath(index_in_tree, self.size)
                .expect("get_secret: Error when computing direct path."),
        );
        dir_path.push(root(self.size));
        let mut empty_nodes: Vec<NodeIndex> = vec![];
        for n in dir_path {
            empty_nodes.push(n);
            if self.nodes[n.as_usize()].is_some() {
                break;
            }
        }
        empty_nodes.remove(0);
        empty_nodes.reverse();
        for n in empty_nodes {
            self.hash_down(ciphersuite, n);
        }
        let node_secret = &self.nodes[index_in_tree.as_usize()].clone().unwrap().secret;
        let mut sender_ratchet = SenderRatchet::new(index, node_secret);
        let application_secret = sender_ratchet.get_secret(generation, ciphersuite);
        self.nodes[index_in_tree.as_usize()] = None;
        self.sender_ratchets[index.as_usize()] = Some(sender_ratchet);
        application_secret
    }

    fn hash_down(&mut self, ciphersuite: &Ciphersuite, index_in_tree: NodeIndex) {
        let hash_len = ciphersuite.hash_length();
        let node_secret = &self.nodes[index_in_tree.as_usize()].clone().unwrap().secret;
        let left_index =
            left(index_in_tree).expect("hash_down: Error when computing left child of node.");
        let right_index = right(index_in_tree, self.size)
            .expect("hash_down: Error when computing right child of node.");
        let left_secret = derive_app_secret(
            &ciphersuite,
            &node_secret,
            "tree",
            left_index.as_u32(),
            0,
            hash_len,
        );
        let right_secret = derive_app_secret(
            &ciphersuite,
            &node_secret,
            "tree",
            right_index.as_u32(),
            0,
            hash_len,
        );
        self.nodes[left_index.as_usize()] = Some(ASTreeNode {
            secret: left_secret,
        });
        self.nodes[right_index.as_usize()] = Some(ASTreeNode {
            secret: right_secret,
        });
        self.nodes[index_in_tree.as_usize()] = None;
    }
}
