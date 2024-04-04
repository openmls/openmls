use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, CryptoError};
use thiserror::Error;
use tls_codec::{Error as TlsCodecError, TlsSerialize, TlsSize};

use super::*;
use crate::{
    binary_tree::{
        array_representation::{
            direct_path, left, right, root, ParentNodeIndex, TreeNodeIndex, TreeSize,
        },
        LeafNodeIndex,
    },
    framing::*,
    schedule::*,
    tree::sender_ratchet::*,
};

/// Secret tree error
#[derive(Error, Debug, Eq, PartialEq, Clone)]
pub enum SecretTreeError {
    /// Generation is too old to be processed.
    #[error("Generation is too old to be processed.")]
    TooDistantInThePast,
    /// Generation is too far in the future to be processed.
    #[error("Generation is too far in the future to be processed.")]
    TooDistantInTheFuture,
    /// Index out of bounds
    #[error("Index out of bounds")]
    IndexOutOfBounds,
    /// The requested secret was deleted to preserve forward secrecy.
    #[error("The requested secret was deleted to preserve forward secrecy.")]
    SecretReuseError,
    /// Cannot create decryption secrets from own sender ratchet or encryption secrets from the sender ratchets of other members.
    #[error("Cannot create decryption secrets from own sender ratchet or encryption secrets from the sender ratchets of other members.")]
    RatchetTypeError,
    /// Ratchet generation has reached `u32::MAX`.
    #[error("Ratchet generation has reached `u32::MAX`.")]
    RatchetTooLong,
    /// An unrecoverable error has occurred due to a bug in the implementation.
    #[error("An unrecoverable error has occurred due to a bug in the implementation.")]
    LibraryError,
    /// See [`TlsCodecError`] for more details.
    #[error(transparent)]
    CodecError(#[from] TlsCodecError),
    /// See [`CryptoError`] for more details.
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum SecretType {
    HandshakeSecret,
    ApplicationSecret,
}

impl From<&ContentType> for SecretType {
    fn from(content_type: &ContentType) -> SecretType {
        match content_type {
            ContentType::Application => SecretType::ApplicationSecret,
            ContentType::Commit => SecretType::HandshakeSecret,
            ContentType::Proposal => SecretType::HandshakeSecret,
        }
    }
}

impl From<&PublicMessage> for SecretType {
    fn from(public_message: &PublicMessage) -> SecretType {
        SecretType::from(&public_message.content_type())
    }
}

/// Derives secrets for inner nodes of a SecretTree. This function corresponds
/// to the `DeriveTreeSecret` defined in Section 10.1 of the MLS specification.
#[inline]
pub(crate) fn derive_tree_secret(
    ciphersuite: Ciphersuite,
    secret: &Secret,
    label: &str,
    generation: u32,
    length: usize,
    crypto: &impl OpenMlsCrypto,
) -> Result<Secret, SecretTreeError> {
    log::debug!(
        "Derive tree secret with label \"{}\" in generation {} of length {}",
        label,
        generation,
        length
    );
    log_crypto!(trace, "Input secret {:x?}", secret.as_slice());

    let secret = secret.kdf_expand_label(
        crypto,
        ciphersuite,
        label,
        &generation.to_be_bytes(),
        length,
    )?;
    log_crypto!(trace, "Derived secret {:x?}", secret.as_slice());
    Ok(secret)
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub(crate) struct TreeContext {
    pub(crate) node: u32,
    pub(crate) generation: u32,
}

#[derive(Debug, Serialize, Deserialize, TlsSerialize, TlsSize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
pub(crate) struct SecretTreeNode {
    pub(crate) secret: Secret,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
#[cfg_attr(any(feature = "crypto-debug", test), derive(Debug))]
pub(crate) struct SecretTree {
    own_index: LeafNodeIndex,
    leaf_nodes: Vec<Option<SecretTreeNode>>,
    parent_nodes: Vec<Option<SecretTreeNode>>,
    handshake_sender_ratchets: Vec<Option<SenderRatchet>>,
    application_sender_ratchets: Vec<Option<SenderRatchet>>,
    size: TreeSize,
}

impl SecretTree {
    /// Creates a new SecretTree based on an `encryption_secret` and group size
    /// `size`. The inner nodes of the tree and the SenderRatchets only get
    /// initialized when secrets are requested either through `secret()`
    /// or `next_secret()`.
    pub(crate) fn new(
        encryption_secret: EncryptionSecret,
        size: TreeSize,
        own_index: LeafNodeIndex,
    ) -> Self {
        let leaf_count = size.leaf_count() as usize;
        let leaf_nodes = std::iter::repeat_with(|| None).take(leaf_count).collect();
        let parent_nodes = std::iter::repeat_with(|| None).take(leaf_count).collect();
        let handshake_sender_ratchets = std::iter::repeat_with(|| None).take(leaf_count).collect();
        let application_sender_ratchets =
            std::iter::repeat_with(|| None).take(leaf_count).collect();

        let mut secret_tree = SecretTree {
            own_index,
            leaf_nodes,
            parent_nodes,
            handshake_sender_ratchets,
            application_sender_ratchets,
            size,
        };

        // Set the encryption secret in the root node. We ignore the Result
        // here, since the we rely on the tree math to be correct, i.e.
        // root(size) < size.
        let _ = secret_tree.set_node(
            root(size),
            Some(SecretTreeNode {
                secret: encryption_secret.consume_secret(),
            }),
        );

        secret_tree
    }

    /// Get current generation for a specific SenderRatchet
    #[cfg(test)]
    pub(crate) fn generation(&self, index: LeafNodeIndex, secret_type: SecretType) -> u32 {
        match self
            .ratchet_opt(index, secret_type)
            .expect("Index out of bounds.")
        {
            Some(sender_ratchet) => sender_ratchet.generation(),
            None => 0,
        }
    }

    /// Initializes a specific SenderRatchet pair for a given index by
    /// calculating and deleting the appropriate values in the SecretTree
    fn initialize_sender_ratchets(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        index: LeafNodeIndex,
    ) -> Result<(), SecretTreeError> {
        log::trace!("Initializing sender ratchets for {index:?} with {ciphersuite}");
        if index.u32() >= self.size.leaf_count() {
            log::error!("Index is larger than the tree size.");
            return Err(SecretTreeError::IndexOutOfBounds);
        }
        // Check if SenderRatchets are already initialized
        if self
            .ratchet_opt(index, SecretType::HandshakeSecret)?
            .is_some()
            && self
                .ratchet_opt(index, SecretType::ApplicationSecret)?
                .is_some()
        {
            log::trace!("The sender ratchets are initialized already.");
            return Ok(());
        }

        // If we don't have a secret in the leaf node, we derive it
        if self.get_node(index.into())?.is_none() {
            // Collect empty nodes in the direct path until a non-empty node is
            // found
            let mut empty_nodes: Vec<ParentNodeIndex> = Vec::new();
            let direct_path = direct_path(index, self.size);
            log::trace!("Direct path for node {index:?}: {:?}", direct_path);
            for parent_node in direct_path {
                empty_nodes.push(parent_node);
                // Stop if we find a non-empty node
                if self.get_node(parent_node.into())?.is_some() {
                    break;
                }
            }

            // Invert direct path
            empty_nodes.reverse();

            // Derive the secrets down all the way to the leaf node
            for n in empty_nodes {
                log::trace!("Derive down for parent node {n:?}.");
                self.derive_down(ciphersuite, crypto, n)?;
            }
        }

        // Calculate node secret and initialize SenderRatchets
        let node_secret = match self.get_node(index.into())? {
            Some(node) => &node.secret,
            // We just derived all necessary nodes so this should not happen
            None => {
                return Err(SecretTreeError::LibraryError);
            }
        };

        log::trace!("Deriving leaf node secrets for leaf {index:?}");

        let handshake_ratchet_secret = node_secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "handshake",
            b"",
            ciphersuite.hash_length(),
        )?;
        let application_ratchet_secret = node_secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "application",
            b"",
            ciphersuite.hash_length(),
        )?;

        log_crypto!(
            trace,
            "handshake ratchet secret {handshake_ratchet_secret:x?}"
        );
        log_crypto!(
            trace,
            "application ratchet secret {application_ratchet_secret:x?}"
        );

        // Initialize SenderRatchets, we differentiate between the own SenderRatchets
        // and the SenderRatchets of other members
        let (handshake_sender_ratchet, application_sender_ratchet) = if index == self.own_index {
            let handshake_sender_ratchet = SenderRatchet::EncryptionRatchet(
                RatchetSecret::initial_ratchet_secret(handshake_ratchet_secret),
            );
            let application_sender_ratchet = SenderRatchet::EncryptionRatchet(
                RatchetSecret::initial_ratchet_secret(application_ratchet_secret),
            );

            (handshake_sender_ratchet, application_sender_ratchet)
        } else {
            let handshake_sender_ratchet =
                SenderRatchet::DecryptionRatchet(DecryptionRatchet::new(handshake_ratchet_secret));
            let application_sender_ratchet = SenderRatchet::DecryptionRatchet(
                DecryptionRatchet::new(application_ratchet_secret),
            );

            (handshake_sender_ratchet, application_sender_ratchet)
        };

        *self
            .handshake_sender_ratchets
            .get_mut(index.usize())
            .ok_or(SecretTreeError::IndexOutOfBounds)? = Some(handshake_sender_ratchet);
        *self
            .application_sender_ratchets
            .get_mut(index.usize())
            .ok_or(SecretTreeError::IndexOutOfBounds)? = Some(application_sender_ratchet);

        // Delete leaf node
        self.set_node(index.into(), None)
    }

    /// Return RatchetSecrets for a given index and generation. This should be
    /// called when decrypting an PrivateMessage received from another member.
    /// Returns an error if index or generation are out of bound.
    pub(crate) fn secret_for_decryption(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        index: LeafNodeIndex,
        secret_type: SecretType,
        generation: u32,
        configuration: &SenderRatchetConfiguration,
    ) -> Result<RatchetKeyMaterial, SecretTreeError> {
        log::debug!(
            "Generating {:?} decryption secret for {:?} in generation {} with {}",
            secret_type,
            index,
            generation,
            ciphersuite,
        );
        // Check tree bounds
        if index.u32() >= self.size.leaf_count() {
            log::error!("Sender index is not in the tree.");
            return Err(SecretTreeError::IndexOutOfBounds);
        }
        if self.ratchet_opt(index, secret_type)?.is_none() {
            log::trace!("   initialize sender ratchets");
            self.initialize_sender_ratchets(ciphersuite, crypto, index)?;
        }
        match self.ratchet_mut(index, secret_type)? {
            SenderRatchet::EncryptionRatchet(_) => {
                log::error!("This is the wrong ratchet type.");
                Err(SecretTreeError::RatchetTypeError)
            }
            SenderRatchet::DecryptionRatchet(dec_ratchet) => {
                log::trace!("   getting secret for decryption");
                dec_ratchet.secret_for_decryption(ciphersuite, crypto, generation, configuration)
            }
        }
    }

    /// Return the next RatchetSecrets that should be used for encryption and
    /// then increments the generation.
    pub(crate) fn secret_for_encryption(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        index: LeafNodeIndex,
        secret_type: SecretType,
    ) -> Result<(u32, RatchetKeyMaterial), SecretTreeError> {
        if self.ratchet_opt(index, secret_type)?.is_none() {
            self.initialize_sender_ratchets(ciphersuite, crypto, index)?;
        }
        match self.ratchet_mut(index, secret_type)? {
            SenderRatchet::DecryptionRatchet(_) => {
                log::error!("Invalid ratchet type. Got decryption, expected encryption.");
                Err(SecretTreeError::RatchetTypeError)
            }
            SenderRatchet::EncryptionRatchet(enc_ratchet) => {
                enc_ratchet.ratchet_forward(crypto, ciphersuite)
            }
        }
    }

    /// Returns a mutable reference to a specific SenderRatchet. The
    /// SenderRatchet needs to be initialized.
    fn ratchet_mut(
        &mut self,
        index: LeafNodeIndex,
        secret_type: SecretType,
    ) -> Result<&mut SenderRatchet, SecretTreeError> {
        let sender_ratchets = match secret_type {
            SecretType::HandshakeSecret => &mut self.handshake_sender_ratchets,
            SecretType::ApplicationSecret => &mut self.application_sender_ratchets,
        };
        sender_ratchets
            .get_mut(index.usize())
            .and_then(|r| r.as_mut())
            .ok_or(SecretTreeError::IndexOutOfBounds)
    }

    /// Returns an optional reference to a specific SenderRatchet
    fn ratchet_opt(
        &self,
        index: LeafNodeIndex,
        secret_type: SecretType,
    ) -> Result<Option<&SenderRatchet>, SecretTreeError> {
        let sender_ratchets = match secret_type {
            SecretType::HandshakeSecret => &self.handshake_sender_ratchets,
            SecretType::ApplicationSecret => &self.application_sender_ratchets,
        };
        match sender_ratchets.get(index.usize()) {
            Some(sender_ratchet_option) => Ok(sender_ratchet_option.as_ref()),
            None => Err(SecretTreeError::IndexOutOfBounds),
        }
    }

    /// Derives the secrets for the child nodes in a SecretTree and blanks the
    /// parent node.
    fn derive_down(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        index_in_tree: ParentNodeIndex,
    ) -> Result<(), SecretTreeError> {
        log::debug!(
            "Deriving tree secret for parent node {} with {}",
            index_in_tree.u32(),
            ciphersuite
        );
        let hash_len = ciphersuite.hash_length();
        let node_secret = match &self.get_node(index_in_tree.into())? {
            Some(node) => &node.secret,
            // This function only gets called top to bottom, so this should not happen
            None => {
                return Err(SecretTreeError::LibraryError);
            }
        };
        log_crypto!(trace, "Node secret: {:x?}", node_secret.as_slice());
        let left_index = left(index_in_tree);
        let right_index = right(index_in_tree);
        let left_secret =
            node_secret.kdf_expand_label(crypto, ciphersuite, "tree", b"left", hash_len)?;
        let right_secret =
            node_secret.kdf_expand_label(crypto, ciphersuite, "tree", b"right", hash_len)?;
        log_crypto!(
            trace,
            "Left node ({}) secret: {:x?}",
            left_index.test_u32(),
            left_secret.as_slice()
        );
        log_crypto!(
            trace,
            "Right node ({}) secret: {:x?}",
            right_index.test_u32(),
            right_secret.as_slice()
        );

        // Populate left child
        self.set_node(
            left_index,
            Some(SecretTreeNode {
                secret: left_secret,
            }),
        )?;

        // Populate right child
        self.set_node(
            right_index,
            Some(SecretTreeNode {
                secret: right_secret,
            }),
        )?;

        // Delete parent node
        self.set_node(index_in_tree.into(), None)
    }

    fn get_node(&self, index: TreeNodeIndex) -> Result<Option<&SecretTreeNode>, SecretTreeError> {
        match index {
            TreeNodeIndex::Leaf(leaf_index) => Ok(self
                .leaf_nodes
                .get(leaf_index.usize())
                .ok_or(SecretTreeError::IndexOutOfBounds)?
                .as_ref()),
            TreeNodeIndex::Parent(parent_index) => Ok(self
                .parent_nodes
                .get(parent_index.usize())
                .ok_or(SecretTreeError::IndexOutOfBounds)?
                .as_ref()),
        }
    }

    fn set_node(
        &mut self,
        index: TreeNodeIndex,
        node: Option<SecretTreeNode>,
    ) -> Result<(), SecretTreeError> {
        match index {
            TreeNodeIndex::Leaf(leaf_index) => {
                *self
                    .leaf_nodes
                    .get_mut(leaf_index.usize())
                    .ok_or(SecretTreeError::IndexOutOfBounds)? = node;
            }
            TreeNodeIndex::Parent(parent_index) => {
                *self
                    .parent_nodes
                    .get_mut(parent_index.usize())
                    .ok_or(SecretTreeError::IndexOutOfBounds)? = node;
            }
        }
        Ok(())
    }
}
