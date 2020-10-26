//! A data structure holding information about the leaf node in the tree that
//! belongs to the current client.
//!

use super::{index::NodeIndex, path_keys::PathKeys, TreeError};
use crate::ciphersuite::{Ciphersuite, HPKEPrivateKey, HPKEPublicKey};
use crate::codec::{Codec, CodecError};
use crate::messages::CommitSecret;
use crate::schedule::hkdf_expand_label;

pub(crate) type PathSecrets = Vec<Vec<u8>>;
#[derive(Debug)]
pub(crate) struct PrivateTree {
    // The index of the node corresponding to this leaf information.
    node_index: NodeIndex,

    // This is the HPKE private key corresponding to the HPKEPublicKey in the
    // node with index `node_index`.
    hpke_private_key: HPKEPrivateKey,

    // A vector of HPKEKeyPairs in the path from this leaf.
    path_keys: PathKeys,

    // Commit secret.
    commit_secret: CommitSecret,

    // Path secrets.
    // The first entry here must be the hpke_private_key.
    path_secrets: PathSecrets,
}

impl PrivateTree {
    /// Create a minimal `PrivateTree` setting only the private key.
    pub(crate) fn from_private_key(
        node_index: NodeIndex,
        hpke_private_key: HPKEPrivateKey,
    ) -> Self {
        Self {
            node_index,
            hpke_private_key,
            path_keys: PathKeys::default(),
            commit_secret: CommitSecret::default(),
            path_secrets: Vec::default(),
        }
    }

    /// Generate a new `PrivateTree` based on the input values.
    pub(crate) fn new_raw(
        ciphersuite: &Ciphersuite,
        node_index: NodeIndex,
        hpke_private_key: HPKEPrivateKey,
        direct_path: &[NodeIndex],
    ) -> Result<(Self, Vec<HPKEPublicKey>), TreeError> {
        let mut out = Self::from_private_key(node_index, hpke_private_key);
        let public_keys = out.update(ciphersuite, None, direct_path)?;
        Ok((out, public_keys))
    }

    /// Update this tree with a new private key and path
    pub(crate) fn update(
        &mut self,
        ciphersuite: &Ciphersuite,
        hpke_private_key: Option<HPKEPrivateKey>,
        path: &[NodeIndex],
    ) -> Result<Vec<HPKEPublicKey>, TreeError> {
        // Set new private key if present.
        if let Some(k) = hpke_private_key {
            self.hpke_private_key = k
        }

        // Compute path secrets.
        self.generate_path_secrets(ciphersuite, None, path.len());

        // Compute commit secret.
        self.generate_commit_secret(ciphersuite)?;

        // Clean the path keys for the update.
        self.path_keys.clear();

        // Generate key pairs and return.
        let public_keys = self.generate_path_keypairs(ciphersuite, path)?;
        Ok(public_keys)
    }

    /// Generate a new `PrivateTree` and populate it with pre-computed values.
    pub(crate) fn new(
        hpke_private_key: HPKEPrivateKey,
        node_index: NodeIndex,
        path_keys: PathKeys,
        commit_secret: CommitSecret,
        path_secrets: PathSecrets,
    ) -> Self {
        Self {
            hpke_private_key,
            node_index,
            path_keys,
            commit_secret,
            path_secrets,
        }
    }

    // === Setter and Getter ===

    pub(crate) fn get_hpke_private_key(&self) -> &HPKEPrivateKey {
        &self.hpke_private_key
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

    /// Generate `n` path secrets with the given `start_secret`.
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
        start_secret: Option<&[u8]>,
        n: usize,
    ) {
        let hash_len = ciphersuite.hash_length();
        let start_secret = match start_secret {
            Some(secret) => hkdf_expand_label(ciphersuite, secret, "path", &[], hash_len),
            None => self.hpke_private_key.as_slice().to_vec(),
        };
        let mut path_secrets = vec![start_secret];
        for i in 0..n - 1 {
            let path_secret =
                hkdf_expand_label(ciphersuite, &path_secrets[i], "path", &[], hash_len);
            path_secrets.push(path_secret);
        }
        self.path_secrets = path_secrets
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
        &mut self,
        ciphersuite: &Ciphersuite,
    ) -> Result<(), TreeError> {
        let path_secret = match self.path_secrets.last() {
            Some(ps) => ps,
            None => return Err(TreeError::NoneError),
        };

        self.commit_secret = CommitSecret(hkdf_expand_label(
            ciphersuite,
            &path_secret,
            "path",
            &[],
            ciphersuite.hash_length(),
        ));

        Ok(())
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
    pub(crate) fn generate_path_keypairs(
        &mut self,
        ciphersuite: &Ciphersuite,
        path: &[NodeIndex],
    ) -> Result<Vec<HPKEPublicKey>, TreeError> {
        // TODO: Get rid of the potential for error here.
        assert_eq!(self.path_secrets.len(), path.len());
        if self.path_secrets.len() != path.len() {
            return Err(TreeError::InvalidArguments);
        }

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
        println!("Path indices: {:?}", path);
        self.path_keys.add(private_keys, &path)?;

        // Return public keys.
        Ok(public_keys)
    }
}

impl Codec for PrivateTree {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        // FIXME: do we need this encode? Private keys should not be encoded if not absolutely necessary.
        // self.hpke_private_key.encode(buffer)?;
        self.node_index.as_u32().encode(buffer)?;
        // self.path_keys.encode(buffer)?;
        Ok(())
    }
}
