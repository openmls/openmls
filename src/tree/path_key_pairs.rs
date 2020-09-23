//! A data structure holding HPKE key pairs for a path in the tree.
//!
//! * TODO: probably shouldn't own key pairs.
//! * TODO: replace `Vec` with a hash map.
//! * TODO: `add` should return error on invalid inputs
//!
use super::index::NodeIndex;
use crate::ciphersuite::HPKEKeyPair;
use crate::codec::{encode_vec, Codec, CodecError, VecSize};

#[derive(Default, Debug, Clone)]
pub struct PathKeypairs {
    keypairs: Vec<Option<HPKEKeyPair>>,
}

impl PathKeypairs {
    pub fn new() -> Self {
        PathKeypairs { keypairs: vec![] }
    }
    pub fn add(&mut self, keypairs: &[HPKEKeyPair], path: &[NodeIndex]) {
        fn extend_vec(tree_keypairs: &mut PathKeypairs, max_index: NodeIndex) {
            while tree_keypairs.keypairs.len() <= max_index.as_usize() {
                tree_keypairs.keypairs.push(None);
            }
        }
        assert_eq!(keypairs.len(), path.len());
        for i in 0..path.len() {
            let index = path[i];
            extend_vec(self, index);
            self.keypairs[index.as_usize()] = Some(keypairs[i].clone());
        }
    }
    pub fn get(&self, index: NodeIndex) -> Option<&HPKEKeyPair> {
        if index.as_usize() >= self.keypairs.len() {
            return None;
        }
        match self.keypairs.get(index.as_usize()) {
            Some(keypair_option) => keypair_option.as_ref(),
            None => None,
        }
    }
}

impl Codec for PathKeypairs {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU32, buffer, &self.keypairs)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let keypairs = decode_vec(VecSize::VecU32, cursor)?;
    //     Ok(PathKeypairs { keypairs })
    // }
}
