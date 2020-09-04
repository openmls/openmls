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
use crate::messages::*;
use crate::schedule::*;
use crate::tree::treemath::*;

const OUT_OF_ORDER_TOLERANCE: u32 = 5;
const MAXIMUM_FORWARD_DISTANCE: u32 = 1000;

// TODO: get rif of Ciphersuite (pass it in get_secret)

#[derive(Debug, PartialEq)]
pub enum ASError {
    TooDistantInThePast,
    TooDistantInTheFuture,
    IndexOutOfBounds,
}

fn derive_app_secret(
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
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let node = u32::decode(cursor)?;
        let generation = u32::decode(cursor)?;
        Ok(ApplicationContext { node, generation })
    }
}

#[derive(Clone)]
pub struct ASTreeNode {
    pub secret: Vec<u8>,
}

#[derive(Clone)]
pub struct SenderRatchet {
    ciphersuite: Ciphersuite,
    index: LeafIndex,
    generation: u32,
    past_secrets: Vec<Vec<u8>>,
}

impl Codec for SenderRatchet {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.ciphersuite.encode(buffer)?;
        self.index.encode(buffer)?;
        self.generation.encode(buffer)?;
        let len = self.past_secrets.len();
        (len as u32).encode(buffer)?;
        for i in 0..len {
            encode_vec(VecSize::VecU8, buffer, &self.past_secrets[i])?;
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let ciphersuite = Ciphersuite::decode(cursor)?;
        let index = LeafIndex::from(u32::decode(cursor)?);
        let generation = u32::decode(cursor)?;
        let len = u32::decode(cursor)? as usize;
        let mut past_secrets = vec![];
        for _ in 0..len {
            let secret = decode_vec(VecSize::VecU8, cursor)?;
            past_secrets.push(secret);
        }
        Ok(SenderRatchet {
            ciphersuite,
            index,
            generation,
            past_secrets,
        })
    }
}

impl SenderRatchet {
    pub fn new(index: LeafIndex, secret: &[u8], ciphersuite: Ciphersuite) -> Self {
        Self {
            ciphersuite,
            index,
            generation: 0,
            past_secrets: vec![secret.to_vec()],
        }
    }
    pub fn get_secret(&mut self, generation: u32) -> Result<ApplicationSecrets, ASError> {
        if generation > (self.generation + MAXIMUM_FORWARD_DISTANCE) {
            return Err(ASError::TooDistantInTheFuture);
        }
        if generation < self.generation && (self.generation - generation) >= OUT_OF_ORDER_TOLERANCE
        {
            return Err(ASError::TooDistantInThePast);
        }
        if generation <= self.generation {
            let window_index =
                (self.past_secrets.len() as u32 - (self.generation - generation) - 1) as usize;
            let secret = self.past_secrets.get(window_index).unwrap().clone();
            let application_secrets = self.derive_key_nonce(&secret, generation);
            Ok(application_secrets)
        } else {
            for _ in 0..(generation - self.generation) {
                if self.past_secrets.len() == OUT_OF_ORDER_TOLERANCE as usize {
                    self.past_secrets.remove(0);
                }
                let new_secret = self.ratchet_secret(self.past_secrets.last().unwrap());
                self.past_secrets.push(new_secret);
            }
            let secret = self.past_secrets.last().unwrap();
            let application_secrets = self.derive_key_nonce(&secret, generation);
            self.generation = generation;
            Ok(application_secrets)
        }
    }
    fn ratchet_secret(&self, secret: &[u8]) -> Vec<u8> {
        derive_app_secret(
            &self.ciphersuite,
            secret,
            "app-secret",
            self.index.into(),
            self.generation,
            self.ciphersuite.hash_length(),
        )
    }
    fn derive_key_nonce(&self, secret: &[u8], generation: u32) -> ApplicationSecrets {
        let nonce = derive_app_secret(
            &self.ciphersuite,
            secret,
            "app-nonce",
            self.index.into(),
            generation,
            self.ciphersuite.aead_nonce_length(),
        );
        let key = derive_app_secret(
            &self.ciphersuite,
            secret,
            "app-key",
            self.index.into(),
            generation,
            self.ciphersuite.aead_key_length(),
        );
        ApplicationSecrets {
            nonce: AeadNonce::from_slice(&nonce),
            key: AeadKey::from_slice(&key),
        }
    }
}

pub struct ASTree {
    ciphersuite: Ciphersuite,
    nodes: Vec<Option<ASTreeNode>>,
    sender_ratchets: Vec<Option<SenderRatchet>>,
    size: LeafIndex,
}

impl Codec for ASTree {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.ciphersuite.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.nodes)?;
        encode_vec(VecSize::VecU32, buffer, &self.sender_ratchets)?;
        self.size.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let ciphersuite = Ciphersuite::decode(cursor)?;
        let nodes = decode_vec(VecSize::VecU32, cursor)?;
        let sender_ratchets = decode_vec(VecSize::VecU32, cursor)?;
        let size = LeafIndex::from(u32::decode(cursor)?);
        Ok(ASTree {
            ciphersuite,
            nodes,
            sender_ratchets,
            size,
        })
    }
}

impl ASTree {
    pub fn new(ciphersuite: Ciphersuite, application_secret: &[u8], size: LeafIndex) -> Self {
        let root = root(size);
        let num_indices = NodeIndex::from(size).as_usize() - 1;

        let mut nodes = vec![None; num_indices];
        nodes[root.as_usize()] = Some(ASTreeNode {
            secret: application_secret.to_vec(),
        });
        let sender_ratchets = vec![None; size.as_usize()];
        Self {
            ciphersuite,
            nodes,
            sender_ratchets,
            size,
        }
    }

    pub fn get_generation(&self, sender: LeafIndex) -> u32 {
        if let Some(sender_ratchet) = &self.sender_ratchets[sender.as_usize()] {
            sender_ratchet.generation
        } else {
            0
        }
    }

    pub fn get_secret(
        &mut self,
        index: LeafIndex,
        generation: u32,
    ) -> Result<ApplicationSecrets, ASError> {
        let index_in_tree = NodeIndex::from(index);
        if index >= self.size {
            return Err(ASError::IndexOutOfBounds);
        }
        if let Some(ratchet_opt) = self.sender_ratchets.get_mut(index.as_usize()) {
            if let Some(ratchet) = ratchet_opt {
                return ratchet.get_secret(generation);
            }
        }
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
        empty_nodes.remove(0);
        empty_nodes.reverse();
        for n in empty_nodes {
            self.hash_down(n);
        }
        let node_secret = &self.nodes[index_in_tree.as_usize()].clone().unwrap().secret;
        let mut sender_ratchet = SenderRatchet::new(index, node_secret, self.ciphersuite);
        let application_secret = sender_ratchet.get_secret(generation);
        self.nodes[index_in_tree.as_usize()] = None;
        self.sender_ratchets[index.as_usize()] = Some(sender_ratchet);
        application_secret
    }

    fn hash_down(&mut self, index_in_tree: NodeIndex) {
        let hash_len = self.ciphersuite.hash_length();
        let node_secret = &self.nodes[index_in_tree.as_usize()].clone().unwrap().secret;
        let left_index = left(index_in_tree);
        let right_index = right(index_in_tree, self.size);
        let left_secret = derive_app_secret(
            &self.ciphersuite,
            &node_secret,
            "tree",
            left_index.as_u32(),
            0,
            hash_len,
        );
        let right_secret = derive_app_secret(
            &self.ciphersuite,
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
