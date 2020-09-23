//! A data structure holding information about the leaf node in the tree that
//! belongs to the current client.
//!

// TODO: Functions should operate on `self`.

use super::{index::NodeIndex, path_key_pairs::PathKeypairs};
use crate::ciphersuite::{Ciphersuite, HPKEKeyPair, HPKEPrivateKey};
use crate::codec::{Codec, CodecError};
use crate::messages::CommitSecret;
use crate::schedule::hkdf_expand_label;

#[derive(Debug)]
pub(crate) struct OwnLeaf {
    // The index of the node corresponding to this leaf information.
    node_index: NodeIndex,

    // This is the HPKE private key corresponding to the HPKEPublicKey in the
    // node with index `node_index`.
    hpke_private_key: HPKEPrivateKey,

    // A vector of HPKEKeyPairs in the path from this leaf.
    path_keypairs: PathKeypairs,
}

impl OwnLeaf {
    pub(crate) fn new(
        hpke_private_key: HPKEPrivateKey,
        node_index: NodeIndex,
        path_keypairs: PathKeypairs,
    ) -> Self {
        Self {
            hpke_private_key,
            node_index,
            path_keypairs,
        }
    }

    // === Setter and Getter ===

    pub(crate) fn get_hpke_private_key(&self) -> &HPKEPrivateKey {
        &self.hpke_private_key
    }
    pub(crate) fn get_node_index(&self) -> NodeIndex {
        self.node_index
    }
    pub(crate) fn get_path_key_pairs(&self) -> &PathKeypairs {
        &self.path_keypairs
    }
    pub(crate) fn get_path_key_pairs_mut(&mut self) -> &mut PathKeypairs {
        &mut self.path_keypairs
    }
    pub(crate) fn set_path_key_pairs(&mut self, new_key_pairs: PathKeypairs) {
        self.path_keypairs = new_key_pairs;
    }

    /// Generate `n` path secrets with the given `start_secret`.
    ///
    /// From 5.4. Ratchet Tree Evolution:
    /// ```text
    /// path_secret[0] = DeriveSecret(leaf_secret, "path")
    /// path_secret[n] = DeriveSecret(path_secret[n-1], "path")
    /// ```
    ///
    /// Returns a vector of path secrets.
    pub(crate) fn generate_path_secrets(
        ciphersuite: &Ciphersuite,
        start_secret: &[u8],
        start_on_leaf: bool,
        n: usize,
    ) -> Vec<Vec<u8>> {
        let hash_len = ciphersuite.hash_length();
        let start_secret = if start_on_leaf {
            hkdf_expand_label(ciphersuite, start_secret, "path", &[], hash_len)
        } else {
            start_secret.to_vec()
        };
        let mut path_secrets = vec![start_secret];
        for i in 0..n - 1 {
            let path_secret =
                hkdf_expand_label(ciphersuite, &path_secrets[i], "path", &[], hash_len);
            path_secrets.push(path_secret);
        }
        path_secrets
    }

    /// Generate the commit secret for the given `path_secret`.
    ///
    /// From 11.2. Commit:
    /// `Define commit_secret as the value path_secret[n+1] derived from the path_secret[n] value assigned to the root node.`
    ///
    /// From 5.4. Ratchet Tree Evolution:
    /// `path_secret[n] = DeriveSecret(path_secret[n-1], "path")`
    ///
    /// Returns a path secret that's a `CommitSecret`.
    pub(crate) fn generate_commit_secret(
        ciphersuite: &Ciphersuite,
        path_secret: &[u8],
    ) -> CommitSecret {
        CommitSecret(hkdf_expand_label(
            ciphersuite,
            &path_secret,
            "path",
            &[],
            ciphersuite.hash_length(),
        ))
    }

    /// Generate HPKE key pairs for all path secrets in `path_secrets`.
    ///
    /// From 5.4. Ratchet Tree Evolution:
    /// ```text
    /// leaf_priv, leaf_pub = KEM.DeriveKeyPair(leaf_node_secret)
    /// node_priv[n], node_pub[n] = KEM.DeriveKeyPair(node_secret[n])
    /// ```
    ///
    /// Returns a vector of `HPKEKeyPair`.
    pub(crate) fn generate_path_keypairs(
        ciphersuite: &Ciphersuite,
        path_secrets: &[Vec<u8>],
    ) -> Vec<HPKEKeyPair> {
        let hash_len = ciphersuite.hash_length();
        let mut keypairs = vec![];
        for path_secret in path_secrets {
            let node_secret = hkdf_expand_label(ciphersuite, &path_secret, "node", &[], hash_len);
            let keypair = HPKEKeyPair::derive(&node_secret, ciphersuite);
            keypairs.push(keypair);
        }
        keypairs
    }
}

impl Codec for OwnLeaf {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        // FIXME: do we need this encode? Private keys should not be encoded if not absolutely necessary.
        // self.hpke_private_key.encode(buffer)?;
        self.node_index.as_u32().encode(buffer)?;
        self.path_keypairs.encode(buffer)?;
        Ok(())
    }
}
