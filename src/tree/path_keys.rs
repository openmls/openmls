//! A data structure holding HPKE key pairs for a path in the tree.
//!

use super::{index::NodeIndex, TreeError};
use crate::ciphersuite::HPKEPrivateKey;
use std::collections::HashMap;

/// A set of keys for a path stored as `HashMap` with entries `(NodeIndex, HPKEPrivateKey)`.
#[derive(Default, Debug)]
pub(crate) struct PathKeys {
    keys: HashMap<NodeIndex, HPKEPrivateKey>,
}

impl PathKeys {
    /// Add a slice of `HPKEPrivateKey`s with the indices given in `path` to this set of `PathKeys`.
    ///
    /// This consumes the private keys.
    pub fn add(
        &mut self,
        private_keys: Vec<HPKEPrivateKey>,
        path: &[NodeIndex],
    ) -> Result<(), TreeError> {
        // TODO: #42 operate on path index not NodeIndex.
        // TODO: make the API less error prone.
        assert_eq!(private_keys.len(), path.len());
        if private_keys.len() != path.len() {
            return Err(TreeError::InvalidArguments);
        }
        let mut private_keys = private_keys;

        for (i, private_key) in private_keys.drain(..).enumerate() {
            let index = path[i];
            if self.keys.insert(index, private_key).is_some() {
                return Err(TreeError::DuplicateIndex);
            }
        }

        Ok(())
    }
    pub fn get(&self, index: NodeIndex) -> Option<&HPKEPrivateKey> {
        self.keys.get(&index)
    }
}