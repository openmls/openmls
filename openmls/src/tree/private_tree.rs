//! A data structure holding information about the leaf node in the tree that
//! belongs to the current client.

use super::{index::NodeIndex, path_keys::PathKeys, *};
use crate::prelude::Secret;
use crate::{
    ciphersuite::{Ciphersuite, HpkePrivateKey, HpkePublicKey},
    messages::PathSecret,
};

pub(crate) type PathSecrets = Vec<PathSecret>;

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct PrivateTree {
    // The index of the node corresponding to this leaf information.
    leaf_index: LeafIndex,

    // This is the HPKE private key corresponding to the HpkePublicKey in the
    // node with index `node_index`.
    hpke_private_key: Option<HpkePrivateKey>,

    // A vector of HPKEKeyPairs in the path from this leaf.
    path_keys: PathKeys,

    // Commit secret.
    commit_secret: Option<CommitSecret>,

    // Leaf secret.
    // Path secrets and node secret are derived from this secret.

    // Path secrets.
    // Path secrets derived from the leaf secret.
    path_secrets: PathSecrets,
}

impl PrivateTree {
    /// Create a new empty placeholder `PrivateTree` with default values and no
    /// `HpkePrivateKey`
    pub(crate) fn new(leaf_index: LeafIndex) -> PrivateTree {
        PrivateTree {
            leaf_index,
            hpke_private_key: None,
            path_keys: PathKeys::default(),
            commit_secret: None,
            path_secrets: PathSecrets::default(),
        }
    }
    /// Create a minimal `PrivateTree` setting only the private key.
    /// This function is used to initialize a `PrivateTree` with a
    /// leaf secret. Further secrets like path secrets and keypairs
    /// will only be derived in a further step. The HPKE private key is
    /// derived from the leaf secret contained in the KeyPackageBundle.
    pub(crate) fn from_leaf_secret(leaf_index: LeafIndex, leaf_secret: &Secret) -> Self {
        // let leaf_secret = key_package_bundle.leaf_secret();
        // let ciphersuite = key_package_bundle.key_package.ciphersuite();
        let leaf_node_secret = derive_leaf_node_secret(leaf_secret);
        let keypair = leaf_secret
            .ciphersuite()
            .derive_hpke_keypair(&leaf_node_secret);
        let (private_key, _) = keypair.into_keys();

        Self {
            leaf_index,
            hpke_private_key: Some(private_key),
            path_keys: PathKeys::default(),
            commit_secret: None,
            path_secrets: Vec::default(),
        }
    }

    /// Creates a `PrivateTree` with a new private key, leaf secret and path
    /// The private key is derived from the leaf secret.
    pub(crate) fn new_with_keys(
        ciphersuite: &Ciphersuite,
        leaf_index: LeafIndex,
        leaf_secret: &Secret,
        path: &[NodeIndex],
    ) -> (Self, Vec<HpkePublicKey>) {
        let mut private_tree = PrivateTree::from_leaf_secret(leaf_index, leaf_secret);

        // Compute path secrets and generate keypairs
        let public_keys = private_tree.generate_path_secrets(ciphersuite, leaf_secret, path);

        (private_tree, public_keys)
    }

    // === Setter and Getter ===

    pub(crate) fn hpke_private_key(&self) -> &HpkePrivateKey {
        match &self.hpke_private_key {
            Some(private_key) => private_key,
            None => panic!("Library error, private key was never initialized"),
        }
    }
    pub(crate) fn leaf_index(&self) -> LeafIndex {
        self.leaf_index
    }
    pub(crate) fn path_keys(&self) -> &PathKeys {
        &self.path_keys
    }
    pub(crate) fn commit_secret(&self) -> Option<&CommitSecret> {
        self.commit_secret.as_ref()
    }
    pub(crate) fn path_secrets(&self) -> &[PathSecret] {
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
        leaf_secret: &Secret,
        path: &[NodeIndex],
    ) -> Vec<HpkePublicKey> {
        let path_secrets = if path.is_empty() {
            vec![]
        } else {
            // FIXME: remove unwrap
            vec![PathSecret {
                path_secret: leaf_secret
                    .kdf_expand_label("path", &[], ciphersuite.hash_length())
                    .unwrap(),
            }]
        };

        self.derive_path_secrets(ciphersuite, path_secrets, path)
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
        start_secret: PathSecret,
        path: &[NodeIndex],
    ) -> Vec<HpkePublicKey> {
        let path_secrets = vec![start_secret];
        self.derive_path_secrets(ciphersuite, path_secrets, path)
    }

    /// This function generates the path secrets internally and is only called
    /// from either `generate_path_secrets` or `continue_path_secrets`.
    fn derive_path_secrets(
        &mut self,
        ciphersuite: &Ciphersuite,
        path_secrets: Vec<PathSecret>,
        path: &[NodeIndex],
    ) -> Vec<HpkePublicKey> {
        let hash_len = ciphersuite.hash_length();

        let mut path_secrets = path_secrets;

        for i in 1..path.len() {
            // FIXME: remove unwrap
            let path_secret = path_secrets[i - 1]
                .path_secret
                .kdf_expand_label("path", &[], hash_len)
                .unwrap();
            path_secrets.push(PathSecret { path_secret });
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
    /// `Define commit_secret as the value path_secret[n+1] derived from the
    /// path_secret[n] value assigned to the root node.`
    ///
    /// From 5.4. Ratchet Tree Evolution:
    /// `path_secret[n] = DeriveSecret(path_secret[n-1], "path")`
    ///
    /// Returns a path secret that's a `CommitSecret`.
    fn generate_commit_secret(&mut self, ciphersuite: &Ciphersuite) {
        let path_secret = self.path_secrets.last().unwrap();
        self.commit_secret = Some(CommitSecret::new(ciphersuite, &path_secret.path_secret));
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
    /// Returns a vector of `HpkePublicKey`.
    fn generate_path_keypairs(
        &mut self,
        ciphersuite: &Ciphersuite,
        path: &[NodeIndex],
    ) -> Vec<HpkePublicKey> {
        let hash_len = ciphersuite.hash_length();
        let mut private_keys = vec![];
        let mut public_keys = vec![];

        // Derive key pairs for all nodes in the direct path.
        for path_secret in self.path_secrets.iter() {
            // FIXME: remove unwrap
            let node_secret = path_secret
                .path_secret
                .kdf_expand_label("node", &[], hash_len)
                .unwrap();
            let keypair = ciphersuite.derive_hpke_keypair(&node_secret);
            let (private_key, public_key) = keypair.into_keys();
            public_keys.push(public_key);
            private_keys.push(private_key);
        }

        // Store private keys.
        self.path_keys.add(private_keys, path);

        // Return public keys.
        public_keys
    }
}
