//! A data structure holding information about the leaf node in the tree that
//! belongs to the current client.
//!

use super::{index::NodeIndex, path_keys::PathKeys};
use crate::ciphersuite::{Ciphersuite, HPKEPrivateKey, HPKEPublicKey};
use crate::key_packages::*;
use crate::messages::CommitSecret;
use crate::schedule::hkdf_expand_label;

pub(crate) type PathSecrets = Vec<Vec<u8>>;
#[derive(Debug)]
pub(crate) struct PrivateTree {
    // The index of the node corresponding to this leaf information.
    node_index: NodeIndex,

    // This is the HPKE private key corresponding to the HPKEPublicKey in the
    // node with index `node_index`.
    hpke_private_key: Option<HPKEPrivateKey>,

    // A vector of HPKEKeyPairs in the path from this leaf.
    path_keys: PathKeys,

    // Commit secret.
    commit_secret: CommitSecret,

    // Leaf secret.
    // Path secrets and node secret are derived from this secret.

    // Path secrets.
    // Path secrets bderived from the leaf secret.
    path_secrets: PathSecrets,
}

impl PrivateTree {
    /// Create a new empty placeholder `PrivateTree` with default values and no `HPKEPrivateKey`
    pub(crate) fn new(node_index: NodeIndex) -> PrivateTree {
        PrivateTree {
            node_index,
            hpke_private_key: None,
            path_keys: PathKeys::default(),
            commit_secret: CommitSecret::default(),
            path_secrets: PathSecrets::default(),
        }
    }
    /// Create a minimal `PrivateTree` setting only the private key.
    /// The private key is derived from the leaf secret contained in the KeyPackageBundle.
    pub(crate) fn from_key_package_bundle(
        node_index: NodeIndex,
        key_package_bundle: &KeyPackageBundle,
    ) -> Self {
        let leaf_secret = key_package_bundle.get_leaf_secret();
        let ciphersuite = Ciphersuite::new(key_package_bundle.key_package.cipher_suite());
        let leaf_node_secret =
            KeyPackageBundle::derive_leaf_node_secret(&ciphersuite, &leaf_secret);
        let keypair = ciphersuite.derive_hpke_keypair(&leaf_node_secret);
        let (private_key, _) = keypair.into_keys();

        Self {
            node_index,
            hpke_private_key: Some(private_key),
            path_keys: PathKeys::default(),
            commit_secret: CommitSecret::default(),
            path_secrets: vec![],
        }
    }

    /// Creates a `PrivateTree` with a new private key, leaf secret and path
    /// The private key is derived from the leaf secret contained in the KeyPackageBundle.
    pub(crate) fn new_with_keys(
        ciphersuite: &Ciphersuite,
        node_index: NodeIndex,
        key_package_bundle: &KeyPackageBundle,
        path: &[NodeIndex],
    ) -> (Self, Vec<HPKEPublicKey>) {
        let mut private_tree = PrivateTree::from_key_package_bundle(node_index, key_package_bundle);

        // Compute path secrets and generate keypairs
        let public_keys = private_tree.generate_path_secrets(
            ciphersuite,
            key_package_bundle.get_leaf_secret(),
            path,
        );

        (private_tree, public_keys)
    }

    // === Setter and Getter ===

    pub(crate) fn get_hpke_private_key(&self) -> &HPKEPrivateKey {
        match &self.hpke_private_key {
            Some(private_key) => private_key,
            None => panic!("Library error, private key was never initialised"),
        }
    }
    pub(crate) fn get_node_index(&self) -> NodeIndex {
        self.node_index
    }
    pub(crate) fn get_path_keys(&self) -> &PathKeys {
        &self.path_keys
    }
    pub(crate) fn get_commit_secret(&self) -> CommitSecret {
        self.commit_secret.clone()
    }
    pub(crate) fn get_path_secrets(&self) -> &[Vec<u8>] {
        &self.path_secrets
    }

    /// Generate `n` path secrets with the given `leaf_secret`.
    ///
    /// From 5.4. Ratchet Tree Evolution:
    /// ```text
    /// path_secret[0] = DeriveSecret(leaf_secret, "path")
    /// path_secret[n] = DeriveSecret(path_secret[n-1], "path")
    /// ```
    ///
    /// Note that this overrides the `path_secrets`.
    pub(crate) fn generate_path_secrets(
        &mut self,
        ciphersuite: &Ciphersuite,
        leaf_secret: &[u8],
        path: &[NodeIndex],
    ) -> Vec<HPKEPublicKey> {
        let hash_len = ciphersuite.hash_length();

        let mut path_secrets = vec![];
        if !path.is_empty() {
            let path_secret = hkdf_expand_label(ciphersuite, leaf_secret, "path", &[], hash_len);
            path_secrets.push(path_secret);
        }

        for i in 1..path.len() {
            let path_secret =
                hkdf_expand_label(ciphersuite, &path_secrets[i - 1], "path", &[], hash_len);
            path_secrets.push(path_secret);
        }
        self.path_secrets = path_secrets;

        // Generate the Commit Secret
        self.generate_commit_secret(ciphersuite);

        // Generate keypair and return public keys
        self.generate_path_keypairs(ciphersuite, path)
    }

    /// Generate `n` path secrets with the given `start_secret`.
    ///
    /// From 5.4. Ratchet Tree Evolution:
    /// ```text
    /// path_secret[0] = DeriveSecret(leaf_secret, "path")
    /// path_secret[n] = DeriveSecret(path_secret[n-1], "path")
    /// ```
    ///
    /// Note that this overrides the `path_secrets`.
    pub(crate) fn continue_path_secrets(
        &mut self,
        ciphersuite: &Ciphersuite,
        start_secret: Vec<u8>,
        path: &[NodeIndex],
    ) -> Vec<HPKEPublicKey> {
        let hash_len = ciphersuite.hash_length();
        let mut path_secrets = vec![start_secret];
        for i in 1..path.len() {
            let path_secret =
                hkdf_expand_label(ciphersuite, &path_secrets[i - 1], "path", &[], hash_len);
            path_secrets.push(path_secret);
        }
        self.path_secrets = path_secrets;

        // Generate the Commit Secret
        self.generate_commit_secret(ciphersuite);

        // Generate keypair and return public keys
        self.generate_path_keypairs(ciphersuite, path)
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
    fn generate_commit_secret(&mut self, ciphersuite: &Ciphersuite) {
        let path_secret = self.path_secrets.last().unwrap();

        self.commit_secret = CommitSecret(hkdf_expand_label(
            ciphersuite,
            &path_secret,
            "path",
            &[],
            ciphersuite.hash_length(),
        ));
    }

    /// Generate HPKE key pairs for all path secrets in `path_secrets`.
    ///
    /// From 5.4. Ratchet Tree Evolution:
    /// ```text
    /// leaf_priv, leaf_pub = KEM.DeriveKeyPair(leaf_node_secret)
    /// node_priv[n], node_pub[n] = KEM.DeriveKeyPair(node_secret[n])
    /// ```
    ///
    /// Note that this **extends** existing `path_keys` in this leaf.
    ///
    /// Returns a vector of `HPKEPublicKey`.
    fn generate_path_keypairs(
        &mut self,
        ciphersuite: &Ciphersuite,
        path: &[NodeIndex],
    ) -> Vec<HPKEPublicKey> {
        let hash_len = ciphersuite.hash_length();
        let mut private_keys = vec![];
        let mut public_keys = vec![];

        // Derive key pairs for all nodes in the direct path.
        for path_secret in self.path_secrets.iter() {
            let node_secret = hkdf_expand_label(ciphersuite, &path_secret, "node", &[], hash_len);
            let keypair = ciphersuite.derive_hpke_keypair(&node_secret);
            let (private_key, public_key) = keypair.into_keys();
            public_keys.push(public_key);
            private_keys.push(private_key);
        }

        // Store private keys.
        self.path_keys.add(private_keys, &path);

        // Return public keys.
        public_keys
    }
}
