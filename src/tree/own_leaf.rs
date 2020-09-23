//! A data structure holding information about the leaf node in the tree that
//! belongs to the current client.
//!

// TODO: Functions should operate on `self`.
// TODO: The key package must not be stored in here. It's in the node already.
//       Only the HPKE private key might potentially be stored in here.

use super::{index::NodeIndex, path_key_pairs::PathKeypairs};
use crate::ciphersuite::{Ciphersuite, HPKEKeyPair};
use crate::codec::{Codec, CodecError};
use crate::key_packages::KeyPackageBundle;
use crate::messages::CommitSecret;
use crate::schedule::hkdf_expand_label;

#[derive(Debug)]
pub(crate) struct OwnLeaf {
    kpb: KeyPackageBundle,
    node_index: NodeIndex,
    path_keypairs: PathKeypairs,
}

impl OwnLeaf {
    pub(crate) fn new(
        kpb: KeyPackageBundle,
        node_index: NodeIndex,
        path_keypairs: PathKeypairs,
    ) -> Self {
        Self {
            kpb,
            node_index,
            path_keypairs,
        }
    }

    // === Setter and Getter ===

    pub(crate) fn get_kpb(&self) -> &KeyPackageBundle {
        &self.kpb
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
        self.kpb.encode(buffer)?;
        self.node_index.as_u32().encode(buffer)?;
        self.path_keypairs.encode(buffer)?;
        Ok(())
    }
}
