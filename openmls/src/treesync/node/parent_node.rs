use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsCryptoProvider};
use tls_codec::{TlsByteVecU8, TlsVecU32};

use crate::{
    ciphersuite::CryptoError,
    schedule::CommitSecret,
    treesync::treekem::{UpdatePath, UpdatePathNode},
};

use super::TreeSyncNodeError;

use crate::{
    binary_tree::LeafIndex,
    ciphersuite::{Ciphersuite, HpkePrivateKey, HpkePublicKey},
    messages::{PathSecret, PathSecretError},
    treesync::hashes::ParentHashInput,
};

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct ParentNode {
    public_key: HpkePublicKey,
    parent_hash: TlsByteVecU8,
    unmerged_leaves: TlsVecU32<LeafIndex>,
    private_key_option: Option<HpkePrivateKey>,
}

impl tls_codec::Deserialize for ParentNode {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let public_key = HpkePublicKey::tls_deserialize(bytes)?;
        let parent_hash = TlsByteVecU8::tls_deserialize(bytes)?;
        let unmerged_leaves = TlsVecU32::tls_deserialize(bytes)?;
        Ok(Self {
            public_key,
            parent_hash,
            unmerged_leaves,
            private_key_option: None,
        })
    }
}

impl tls_codec::Size for ParentNode {
    fn tls_serialized_len(&self) -> usize {
        self.public_key.tls_serialized_len()
            + self.parent_hash.tls_serialized_len()
            + self.unmerged_leaves.tls_serialized_len()
    }
}

impl tls_codec::Size for &ParentNode {
    fn tls_serialized_len(&self) -> usize {
        self.public_key.tls_serialized_len()
            + self.parent_hash.tls_serialized_len()
            + self.unmerged_leaves.tls_serialized_len()
    }
}

impl tls_codec::Serialize for &ParentNode {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.public_key.tls_serialize(writer)?;
        written += self.parent_hash.tls_serialize(writer)?;
        self.unmerged_leaves
            .tls_serialize(writer)
            .map(|l| l + written)
    }
}

impl From<(HpkePublicKey, HpkePrivateKey)> for ParentNode {
    fn from((public_key, private_key): (HpkePublicKey, HpkePrivateKey)) -> Self {
        let parent_node: ParentNode = public_key.into();
        parent_node.set_private_key(private_key);
        parent_node
    }
}

impl From<HpkePublicKey> for ParentNode {
    fn from(public_key: HpkePublicKey) -> Self {
        Self {
            public_key,
            parent_hash: vec![].into(),
            unmerged_leaves: vec![].into(),
            private_key_option: None,
        }
    }
}

pub(crate) struct PlainUpdatePathNode {
    public_key: HpkePublicKey,
    path_secret: PathSecret,
}

impl PlainUpdatePathNode {
    pub(in crate::treesync) fn encrypt(
        &self,
        backend: &impl OpenMlsCrypto,
        ciphersuite: &Ciphersuite,
        public_keys: &[HpkePublicKey],
        group_context: &[u8],
    ) -> UpdatePathNode {
        let mut encrypted_path_secrets = Vec::new();
        for pk in public_keys {
            let encrypted_path_secret =
                self.path_secret
                    .encrypt(backend, ciphersuite, pk, group_context);
            encrypted_path_secrets.push(encrypted_path_secret);
        }
        UpdatePathNode {
            public_key: self.public_key.clone(),
            encrypted_path_secrets: encrypted_path_secrets.into(),
        }
    }
}

impl ParentNode {
    /// Derives a path from the given path secret, where the `node_secret` of
    /// the first node is immediately derived from the given `path_secret`.
    /// Returns the resulting vector of `ParentNode`s, as well as the
    /// intermediary `PathSecret`s. Note, that the last of the `PathSecret`s is
    /// the `CommitSecret`.
    pub(crate) fn derive_path(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        path_secret: PathSecret,
        path_length: usize,
    ) -> Result<(Vec<Self>, Vec<PlainUpdatePathNode>, CommitSecret), ParentNodeError> {
        let mut path = Vec::new();
        let mut update_path_nodes = Vec::new();
        let mut path_secret_option = Some(path_secret);
        for _ in 0..path_length {
            let path_secret = path_secret_option
                .take()
                .ok_or(ParentNodeError::LibraryError)?;
            let (public_key, private_key) = path_secret.derive_key_pair(backend, ciphersuite)?;
            let parent_node = (public_key.clone(), private_key).into();
            path.push(parent_node);
            // Derive the next path secret.
            path_secret_option = Some(path_secret.derive_path_secret(backend, ciphersuite)?);
            // Store the current path secret and the derived public key for
            // later encryption.
            let update_path_node = PlainUpdatePathNode {
                public_key,
                path_secret,
            };
            update_path_nodes.push(update_path_node);
        }
        let commit_secret = path_secret_option
            .take()
            .ok_or(ParentNodeError::LibraryError)?
            .into();
        Ok((path, update_path_nodes, commit_secret))
    }

    /// Return the value of the node relevant for the parent hash and tree hash.
    /// In case of MLS, this would be the node's HPKEPublicKey. TreeSync
    /// can then gather everything necessary to build the `ParentHashInput`,
    /// `LeafNodeHashInput` and `ParentNodeTreeHashInput` structs for a given node.
    pub(crate) fn node_content(&self) -> &HpkePublicKey {
        &self.public_key
    }

    pub(crate) fn public_key(&self) -> &HpkePublicKey {
        &self.public_key
    }

    pub(crate) fn private_key(&self) -> &Option<HpkePrivateKey> {
        &self.private_key_option
    }

    pub(crate) fn set_private_key(&mut self, private_key: HpkePrivateKey) {
        self.private_key_option = Some(private_key)
    }

    /// Get the list of unmerged leaves.
    pub(crate) fn unmerged_leaves(&self) -> &[LeafIndex] {
        self.unmerged_leaves.as_slice()
    }

    /// Clear the list of unmerged leaves.
    fn clear_unmerged_leaves(&mut self) {
        self.unmerged_leaves = Vec::new().into()
    }

    /// Add a `LeafIndex` to the node's list of unmerged leaves.
    pub(in crate::treesync) fn add_unmerged_leaf(&mut self, leaf_index: LeafIndex) {
        self.unmerged_leaves.push(leaf_index)
    }

    /// Compute the parent hash value of this node.
    pub(in crate::treesync) fn compute_parent_hash(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        parent_hash: &[u8],
        original_child_resolution: &[HpkePublicKey],
    ) -> Result<Vec<u8>, TreeSyncNodeError> {
        let parent_hash_input =
            ParentHashInput::new(&self.public_key, &parent_hash, original_child_resolution);
        Ok(parent_hash_input.hash(backend, ciphersuite)?)
    }

    pub(in crate::treesync) fn set_parent_hash(&mut self, parent_hash: Vec<u8>) {
        self.parent_hash = parent_hash.into()
    }

    /// Get the parent hash value of this node.
    pub(crate) fn parent_hash(&self) -> &[u8] {
        self.parent_hash.as_slice()
    }
}

implement_error! {
    pub enum ParentNodeError {
        Simple {
            LibraryError = "An unrecoverable error has occurred.",
        }
        Complex {
            CryptoError(CryptoError) = "An error occurred during key derivation.",
            DerivationError(PathSecretError) = "An error occurred during key derivation.",
        }
    }
}
