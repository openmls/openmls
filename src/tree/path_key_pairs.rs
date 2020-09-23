//! A data structure holding HPKE key pairs for a path in the tree.
//!

// TODO: probably shouldn't own key pairs.
// TODO: #25 replace `Vec` with a hash map.
// TODO: `add` should return error on invalid inputs
// TODO: #24 This should not hold key pairs but again only private keys. The corresponding
//       public keys are in the tree nodes.
//
use super::index::NodeIndex;
use crate::ciphersuite::HPKEKeyPair;
use crate::codec::{encode_vec, Codec, CodecError, VecSize};

#[derive(Default, Debug)]
pub struct PathKeypairs {
    key_pairs: Vec<Option<HPKEKeyPair>>,
}

impl PathKeypairs {
    pub fn add(&mut self, key_pairs: &[HPKEKeyPair], path: &[NodeIndex]) {
        fn extend_vec(tree_keypairs: &mut PathKeypairs, max_index: NodeIndex) {
            while tree_keypairs.key_pairs.len() <= max_index.as_usize() {
                tree_keypairs.key_pairs.push(None);
            }
        }
        assert_eq!(key_pairs.len(), path.len());
        for i in 0..path.len() {
            let index = path[i];
            extend_vec(self, index);
            self.key_pairs[index.as_usize()] = Some(key_pairs[i].clone());
        }
    }
    pub fn get(&self, index: NodeIndex) -> Option<&HPKEKeyPair> {
        if index.as_usize() >= self.key_pairs.len() {
            return None;
        }
        match self.key_pairs.get(index.as_usize()) {
            Some(keypair_option) => keypair_option.as_ref(),
            None => None,
        }
    }
}

impl Codec for PathKeypairs {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU32, buffer, &self.key_pairs)?;
        Ok(())
    }
}
