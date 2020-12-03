//! A data structure holding HPKE key pairs for a path in the tree.

use super::index::NodeIndex;
use crate::ciphersuite::HPKEPrivateKey;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A set of keys for a path stored as `HashMap` with entries `(NodeIndex, HPKEPrivateKey)`.
#[derive(Default, PartialEq, Debug, Serialize, Deserialize)]
pub(crate) struct PathKeys {
    keys: HashMap<NodeIndex, HPKEPrivateKey>,
}

impl PathKeys {
    /// Add a slice of `HPKEPrivateKey`s with the indices given in `path` to
    /// this set of `PathKeys`.
    ///
    /// This consumes the private keys.
    pub fn add(&mut self, private_keys: Vec<HPKEPrivateKey>, path: &[NodeIndex]) {
        // TODO: #42 operate on path index not NodeIndex.
        debug_assert_eq!(
            private_keys.len(),
            path.len(),
            "Library error: different length"
        );
        let mut private_keys = private_keys;

        for (i, private_key) in private_keys.drain(..).enumerate() {
            let index = path[i];
            self.keys.insert(index, private_key);
        }
    }

    /// Get an HPKE private key for a given node index.
    pub fn get(&self, index: NodeIndex) -> Option<&HPKEPrivateKey> {
        self.keys.get(&index)
    }
}
