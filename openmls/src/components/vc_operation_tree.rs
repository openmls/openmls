//! Virtual Client Operation Secret Tree (mls-virtual-clients draft).
//!
//! A tree of secrets with the same structure as the RFC 9420 secret tree
//! (Section 9): it has the same set of nodes and edges as the emulation
//! group's ratchet tree at the corresponding epoch, parent-to-child node
//! derivation uses the same `"tree"` label with `"left"` / `"right"`
//! context, and each leaf is expanded once it is first used. It differs
//! from the RFC 9420 secret tree in two ways: the root is the
//! per-emulation-epoch `epoch_base_secret` rather than a secret derived
//! from `encryption_secret`, and each leaf expands into one operation
//! ratchet per [`VirtualClientOperationType`] instead of a handshake and an
//! application sender ratchet.
//!
//! Each ratchet hands out one [`OperationSecret`] per generation, bound to
//! the spec's `OperationContext`
//! `(epoch_id, leaf_index, generation, operation_type, operation_context)`.
//!
//! Forward secrecy mirrors the RFC 9420 secret tree: parent node secrets
//! are deleted once their children are derived, a leaf secret is deleted as
//! soon as the initial ratchet secrets for all operation types have been
//! derived, and ratchet heads plus generation secrets are deleted as soon
//! as the operation secret of a generation has been derived. Deriving for a
//! generation ahead of the ratchet head retains only the
//! context-independent `operation_generation_secret` of each skipped
//! generation, since the final operation secret also binds the (then still
//! unknown) operation context. The retained entry is deleted when the
//! operation for that generation arrives. Retention is bounded by
//! [`MAXIMUM_FORWARD_DISTANCE`] and [`OUT_OF_ORDER_TOLERANCE`].

use std::collections::BTreeMap;

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use tls_codec::{Serialize as _, TlsSerialize, TlsSize};

use crate::{
    binary_tree::{
        array_representation::{
            direct_path, left, right, root, ParentNodeIndex, TreeNodeIndex, TreeSize,
        },
        LeafNodeIndex,
    },
    ciphersuite::Secret,
    components::vc_derivation_info::{
        EpochId, OperationSecret, VirtualClientOperationType, VirtualClientsError,
    },
    tree::secret_tree::derive_child_secrets,
    utils::vector_converter,
};

/// `ExpandWithLabel` label for the initial operation ratchet secret of each
/// operation type, expanded from a leaf secret.
const OPERATION_RATCHET_INIT_LABEL: &str = "vc operation init";
/// `DeriveSecret` label for the per-generation `operation_generation_secret`.
const OPERATION_GENERATION_LABEL: &str = "VC Operation Secret";
/// `DeriveSecret` label for advancing an operation ratchet to the next
/// generation.
const OPERATION_RATCHET_ADVANCE_LABEL: &str = "VC Operation Ratchet";
/// `ExpandWithLabel` label for the final operation secret, expanded from an
/// `operation_generation_secret` with the TLS-serialized [`OperationContext`].
const OPERATION_SECRET_LABEL: &str = "vc operation";

/// How far beyond the current ratchet head a requested generation may lie.
/// Requests further out fail with
/// [`VirtualClientsError::OperationGenerationTooDistant`], which also stops a
/// malicious sibling from forcing up to `u32::MAX` KDF steps through a
/// fabricated `generation` in a commit's `DerivationInfo`.
///
/// Operation ratchets advance once per virtual-client operation rather than
/// once per message, so legitimate gaps stay small: commits within one
/// higher-level group are DS-ordered, but one tree spans all higher-level
/// groups of the virtual client, so operations from different groups can be
/// processed out of allocation order, and DS-rejected commits leave burned
/// generations that receivers skip. This bound and
/// [`OUT_OF_ORDER_TOLERANCE`] can become configurable later alongside the
/// planned emulation-group configuration.
const MAXIMUM_FORWARD_DISTANCE: u32 = 1024;

/// How many skipped `operation_generation_secret`s a ratchet retains.
/// Skipping past more than this many unconsumed generations evicts the oldest
/// retained entries first, after which they fail with
/// [`VirtualClientsError::OperationGenerationConsumed`]. The draft says
/// implementations SHOULD bound how many skipped generations they retain,
/// since every retained secret weakens forward secrecy within the emulation
/// epoch. See [`MAXIMUM_FORWARD_DISTANCE`] for why legitimate gaps stay
/// small and for the plan to make both bounds configurable.
const OUT_OF_ORDER_TOLERANCE: usize = 32;

/// Per-emulation-epoch Virtual Client Operation Secret Tree.
///
/// Rooted at the epoch's `epoch_base_secret` and shaped like the emulation
/// group's ratchet tree at the corresponding epoch (sized by the leaf
/// count, including blank leaves). Node secrets and per-leaf operation
/// ratchets are derived lazily on first use, and consumed material is deleted
/// as it is used (see the module documentation for the forward-secrecy
/// rules).
///
/// # Concurrency
///
/// One tree is shared by all higher-level groups the virtual client is a
/// member of. Every derivation mutates it, so a load-derive-store cycle
/// against the storage provider must be atomic per emulation epoch.
/// Applications that process messages for multiple higher-level groups in
/// parallel must serialize these cycles. Two concurrent cycles on separate
/// copies of the tree can allocate the same generation for two different
/// operations (the key reuse the draft forbids) and last-write-wins
/// persistence loses the other copy's punctured nodes and retained skipped
/// generations.
#[derive(Debug, Serialize, Deserialize)]
pub struct OperationSecretTree {
    leaf_nodes: Vec<Option<Secret>>,
    parent_nodes: Vec<Option<Secret>>,
    operation_ratchets: Vec<Option<LeafOperationRatchets>>,
    size: TreeSize,
}

impl OperationSecretTree {
    /// Create a tree rooted at `epoch_base_secret` with the given `size`.
    /// The inner node secrets and the operation ratchets only get derived
    /// when operation secrets are requested.
    ///
    /// `Secret` and `TreeSize` are crate-internal, so unlike the derivation
    /// methods this constructor cannot be `pub`.
    pub(crate) fn new(epoch_base_secret: Secret, size: TreeSize) -> Self {
        let leaf_count = size.leaf_count() as usize;
        let mut tree = Self {
            leaf_nodes: std::iter::repeat_with(|| None).take(leaf_count).collect(),
            parent_nodes: std::iter::repeat_with(|| None).take(leaf_count).collect(),
            operation_ratchets: std::iter::repeat_with(|| None).take(leaf_count).collect(),
            size,
        };
        // Set the epoch base secret in the root node. We ignore the Result
        // here, since we rely on the tree math to be correct, i.e.
        // root(size) < size.
        let _ = tree.set_node(root(size), Some(epoch_base_secret));
        tree
    }

    /// Derive the operation secret for the given coordinates, advancing the
    /// per-leaf, per-operation-type ratchet as necessary.
    ///
    /// Deriving for a generation ahead of the ratchet head advances the head
    /// past it while retaining the context-independent generation secrets of
    /// the skipped generations (at most [`OUT_OF_ORDER_TOLERANCE`], oldest
    /// evicted first), so the corresponding operations can still be processed
    /// when they arrive. Asking for a generation whose operation secret was
    /// already derived or evicted fails with
    /// [`VirtualClientsError::OperationGenerationConsumed`], a generation
    /// more than [`MAXIMUM_FORWARD_DISTANCE`] beyond the head fails with
    /// [`VirtualClientsError::OperationGenerationTooDistant`], and a leaf
    /// index outside the tree fails with
    /// [`VirtualClientsError::IndexOutOfBounds`].
    ///
    /// # Warning
    ///
    /// This mutates the tree: it advances and punctures ratchets. The caller
    /// MUST persist the mutated tree before any other cycle reads it, as a
    /// single atomic load-derive-store per emulation epoch. Deriving against
    /// a stale copy, or not persisting before the next derive, re-serves a
    /// consumed generation and reuses key material, the reuse the draft
    /// forbids. See the type-level `# Concurrency` note.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_operation_secret(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_id: &EpochId,
        leaf_index: LeafNodeIndex,
        operation_type: VirtualClientOperationType,
        generation: u32,
        operation_context: &[u8],
    ) -> Result<OperationSecret, VirtualClientsError> {
        let ratchet = self.ratchet_mut(crypto, ciphersuite, leaf_index, operation_type)?;
        let operation_generation_secret =
            ratchet.generation_secret(crypto, ciphersuite, generation)?;
        let context = OperationContext {
            epoch_id: epoch_id.clone(),
            leaf_index,
            generation,
            operation_type,
            operation_context: operation_context.to_vec(),
        };
        // `operation_generation_secret` is dropped when this function
        // returns, deleting it as required by the spec.
        context.expand_operation_secret(crypto, ciphersuite, &operation_generation_secret)
    }

    /// Advance the caller's own ratchet for `operation_type` at
    /// `own_leaf_index` and return the generation it was at together with the
    /// operation secret for that generation. Use this when sending an
    /// operation. Receivers re-derive the same secret positionally via
    /// [`OperationSecretTree::derive_operation_secret`].
    ///
    /// # Warning
    ///
    /// This mutates the tree: it advances the own ratchet by one generation.
    /// The caller MUST persist the mutated tree in the same atomic
    /// load-derive-store cycle, before the allocated generation can be
    /// observed on the wire. Allocating from a stale copy, or persisting
    /// late, lets two operations share a generation and reuse key material,
    /// the reuse the draft forbids. See the type-level `# Concurrency` note.
    pub fn next_operation_secret(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_id: &EpochId,
        own_leaf_index: LeafNodeIndex,
        operation_type: VirtualClientOperationType,
        operation_context: &[u8],
    ) -> Result<(u32, OperationSecret), VirtualClientsError> {
        let generation = self
            .ratchet_mut(crypto, ciphersuite, own_leaf_index, operation_type)?
            .head_generation();
        let operation_secret = self.derive_operation_secret(
            crypto,
            ciphersuite,
            epoch_id,
            own_leaf_index,
            operation_type,
            generation,
            operation_context,
        )?;
        Ok((generation, operation_secret))
    }

    /// Return the ratchet for `(leaf_index, operation_type)`, initializing
    /// the leaf's operation ratchets first if necessary.
    fn ratchet_mut(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        leaf_index: LeafNodeIndex,
        operation_type: VirtualClientOperationType,
    ) -> Result<&mut OperationRatchet, VirtualClientsError> {
        if leaf_index.u32() >= self.size.leaf_count() {
            log::error!("vc: leaf index is larger than the operation secret tree size.");
            return Err(VirtualClientsError::IndexOutOfBounds);
        }
        if self
            .operation_ratchets
            .get(leaf_index.usize())
            .ok_or(VirtualClientsError::IndexOutOfBounds)?
            .is_none()
        {
            self.initialize_leaf_ratchets(crypto, ciphersuite, leaf_index)?;
        }
        let ratchets = self
            .operation_ratchets
            .get_mut(leaf_index.usize())
            .and_then(|ratchets| ratchets.as_mut())
            // We just initialized the ratchets, so this should not happen.
            .ok_or(VirtualClientsError::LibraryError)?;
        Ok(ratchets.ratchet_mut(operation_type))
    }

    /// Derive the node secrets down to `leaf_index`, expand the leaf secret
    /// into one initial ratchet secret per operation type and delete it.
    fn initialize_leaf_ratchets(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        leaf_index: LeafNodeIndex,
    ) -> Result<(), VirtualClientsError> {
        // If we don't have a secret in the leaf node, we derive it from the
        // closest populated ancestor.
        if self.get_node(leaf_index.into())?.is_none() {
            // Collect empty nodes in the direct path until a non-empty node
            // is found.
            let mut empty_nodes: Vec<ParentNodeIndex> = Vec::new();
            for parent_node in direct_path(leaf_index, self.size) {
                empty_nodes.push(parent_node);
                if self.get_node(parent_node.into())?.is_some() {
                    break;
                }
            }
            // Derive the secrets down all the way to the leaf node, deleting
            // each parent secret once its children are populated.
            empty_nodes.reverse();
            for parent_node in empty_nodes {
                self.derive_down(crypto, ciphersuite, parent_node)?;
            }
        }

        // Take the leaf secret out of the tree: the spec requires deleting
        // it as soon as the initial ratchet secrets for all operation types
        // have been derived. `initialize` consumes and drops it.
        let leaf_secret = self
            .leaf_nodes
            .get_mut(leaf_index.usize())
            .ok_or(VirtualClientsError::IndexOutOfBounds)?
            .take()
            // We just derived all necessary nodes, so this should not happen.
            .ok_or(VirtualClientsError::LibraryError)?;
        let ratchets = LeafOperationRatchets::initialize(crypto, ciphersuite, leaf_secret)?;
        *self
            .operation_ratchets
            .get_mut(leaf_index.usize())
            .ok_or(VirtualClientsError::IndexOutOfBounds)? = Some(ratchets);
        Ok(())
    }

    /// Derive the secrets for the child nodes of a parent node, deleting the
    /// parent node's secret.
    fn derive_down(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        parent_index: ParentNodeIndex,
    ) -> Result<(), VirtualClientsError> {
        let parent_secret = self
            .parent_nodes
            .get_mut(parent_index.usize())
            .ok_or(VirtualClientsError::IndexOutOfBounds)?
            // Taking the secret deletes the parent node.
            .take()
            // This function only gets called top to bottom, so this should
            // not happen.
            .ok_or(VirtualClientsError::LibraryError)?;
        let (left_secret, right_secret) =
            derive_child_secrets(&parent_secret, crypto, ciphersuite)?;
        self.set_node(left(parent_index), Some(left_secret))?;
        self.set_node(right(parent_index), Some(right_secret))?;
        Ok(())
    }

    fn get_node(&self, index: TreeNodeIndex) -> Result<Option<&Secret>, VirtualClientsError> {
        match index {
            TreeNodeIndex::Leaf(leaf_index) => Ok(self
                .leaf_nodes
                .get(leaf_index.usize())
                .ok_or(VirtualClientsError::IndexOutOfBounds)?
                .as_ref()),
            TreeNodeIndex::Parent(parent_index) => Ok(self
                .parent_nodes
                .get(parent_index.usize())
                .ok_or(VirtualClientsError::IndexOutOfBounds)?
                .as_ref()),
        }
    }

    fn set_node(
        &mut self,
        index: TreeNodeIndex,
        secret: Option<Secret>,
    ) -> Result<(), VirtualClientsError> {
        match index {
            TreeNodeIndex::Leaf(leaf_index) => {
                *self
                    .leaf_nodes
                    .get_mut(leaf_index.usize())
                    .ok_or(VirtualClientsError::IndexOutOfBounds)? = secret;
            }
            TreeNodeIndex::Parent(parent_index) => {
                *self
                    .parent_nodes
                    .get_mut(parent_index.usize())
                    .ok_or(VirtualClientsError::IndexOutOfBounds)? = secret;
            }
        }
        Ok(())
    }
}

/// The per-operation-type ratchets expanded from one leaf secret, one per
/// non-reserved [`VirtualClientOperationType`].
#[derive(Debug, Serialize, Deserialize)]
struct LeafOperationRatchets {
    key_package: OperationRatchet,
    leaf_node: OperationRatchet,
    application: OperationRatchet,
}

impl LeafOperationRatchets {
    /// Expand `leaf_secret` into the initial ratchet secret for every
    /// non-reserved operation type:
    ///
    /// ```text
    /// operation_ratchet_secret[operation_type][0] =
    ///   ExpandWithLabel(leaf_secret, "vc operation init", operation_type, Kdf.Nh)
    /// ```
    ///
    /// where `operation_type` is the TLS-encoded
    /// [`VirtualClientOperationType`] value. `leaf_secret` is consumed and
    /// dropped here, per the spec requirement to delete it as soon as the
    /// initial ratchet secrets for all operation types have been derived.
    fn initialize(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        leaf_secret: Secret,
    ) -> Result<Self, VirtualClientsError> {
        let initial_ratchet_secret =
            |operation_type: VirtualClientOperationType| -> Result<Secret, VirtualClientsError> {
                let context = operation_type.tls_serialize_detached()?;
                Ok(leaf_secret.kdf_expand_label(
                    crypto,
                    ciphersuite,
                    OPERATION_RATCHET_INIT_LABEL,
                    &context,
                    ciphersuite.hash_length(),
                )?)
            };
        Ok(Self {
            key_package: OperationRatchet::new(initial_ratchet_secret(
                VirtualClientOperationType::KeyPackage,
            )?),
            leaf_node: OperationRatchet::new(initial_ratchet_secret(
                VirtualClientOperationType::LeafNode,
            )?),
            application: OperationRatchet::new(initial_ratchet_secret(
                VirtualClientOperationType::Application,
            )?),
        })
    }

    fn ratchet_mut(&mut self, operation_type: VirtualClientOperationType) -> &mut OperationRatchet {
        match operation_type {
            VirtualClientOperationType::KeyPackage => &mut self.key_package,
            VirtualClientOperationType::LeafNode => &mut self.leaf_node,
            VirtualClientOperationType::Application => &mut self.application,
        }
    }
}

/// A single operation ratchet: the current ratchet head plus the
/// context-independent `operation_generation_secret`s retained for
/// generations that were skipped over.
#[derive(Debug, Serialize, Deserialize)]
struct OperationRatchet {
    /// The `operation_ratchet_secret` for `next_generation`.
    ratchet_secret: Secret,
    next_generation: u32,
    /// Retained `operation_generation_secret`s of skipped generations,
    /// deleted when the operation for the generation arrives. A generation
    /// below `next_generation` without an entry here was already consumed.
    #[serde(with = "vector_converter")]
    retained_generation_secrets: BTreeMap<u32, Secret>,
}

impl OperationRatchet {
    fn new(initial_ratchet_secret: Secret) -> Self {
        Self {
            ratchet_secret: initial_ratchet_secret,
            next_generation: 0,
            retained_generation_secrets: BTreeMap::new(),
        }
    }

    /// The generation the ratchet head is currently at, i.e. the generation
    /// the next own operation would use.
    fn head_generation(&self) -> u32 {
        self.next_generation
    }

    /// Return the `operation_generation_secret` for `generation`, advancing
    /// the ratchet head past it if necessary. Skipped generations retain
    /// their generation secret, keeping at most [`OUT_OF_ORDER_TOLERANCE`]
    /// entries by evicting the oldest first. Asking for a generation that was
    /// already consumed or evicted fails with
    /// [`VirtualClientsError::OperationGenerationConsumed`], and a generation
    /// more than [`MAXIMUM_FORWARD_DISTANCE`] beyond the head fails with
    /// [`VirtualClientsError::OperationGenerationTooDistant`] without
    /// advancing the head.
    fn generation_secret(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        generation: u32,
    ) -> Result<Secret, VirtualClientsError> {
        if generation < self.next_generation {
            // Removing the entry deletes the retained secret once the caller
            // drops it.
            return self
                .retained_generation_secrets
                .remove(&generation)
                .ok_or(VirtualClientsError::OperationGenerationConsumed);
        }
        if self.next_generation < u32::MAX - MAXIMUM_FORWARD_DISTANCE
            && generation > self.next_generation + MAXIMUM_FORWARD_DISTANCE
        {
            log::error!(
                "vc: requested operation generation {generation} is more than \
                 {MAXIMUM_FORWARD_DISTANCE} beyond the ratchet head {}.",
                self.next_generation
            );
            return Err(VirtualClientsError::OperationGenerationTooDistant);
        }
        while self.next_generation < generation {
            let skipped_generation = self.next_generation;
            let skipped_secret = self.advance(crypto, ciphersuite)?;
            self.retained_generation_secrets
                .insert(skipped_generation, skipped_secret);
        }
        // Evict the oldest retained entries first, dropping their secrets.
        while self.retained_generation_secrets.len() > OUT_OF_ORDER_TOLERANCE {
            self.retained_generation_secrets.pop_first();
        }
        self.advance(crypto, ciphersuite)
    }

    /// One ratchet step:
    ///
    /// ```text
    /// operation_generation_secret =
    ///   DeriveSecret(operation_ratchet_secret, "VC Operation Secret")
    /// next_operation_ratchet_secret =
    ///   DeriveSecret(operation_ratchet_secret, "VC Operation Ratchet")
    /// ```
    ///
    /// Returns the `operation_generation_secret` for the head generation and
    /// advances the head, deleting the consumed `operation_ratchet_secret`.
    fn advance(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<Secret, VirtualClientsError> {
        if self.next_generation == u32::MAX {
            return Err(VirtualClientsError::OperationRatchetTooLong);
        }
        let operation_generation_secret =
            self.ratchet_secret
                .derive_secret(crypto, ciphersuite, OPERATION_GENERATION_LABEL)?;
        // Overwriting the head deletes the consumed ratchet secret.
        self.ratchet_secret = self.ratchet_secret.derive_secret(
            crypto,
            ciphersuite,
            OPERATION_RATCHET_ADVANCE_LABEL,
        )?;
        self.next_generation += 1;
        Ok(operation_generation_secret)
    }
}

/// Context bound into each operation secret (mls-virtual-clients draft
/// `OperationContext`):
///
/// ```text
/// struct {
///   opaque epoch_id<V>;
///   uint32 leaf_index;
///   uint32 generation;
///   VirtualClientOperationType operation_type;
///   opaque operation_context<V>;
/// } OperationContext
/// ```
#[derive(Debug, TlsSize, TlsSerialize)]
struct OperationContext {
    epoch_id: EpochId,
    leaf_index: LeafNodeIndex,
    generation: u32,
    operation_type: VirtualClientOperationType,
    operation_context: Vec<u8>,
}

impl OperationContext {
    /// Expand the final operation secret:
    ///
    /// ```text
    /// operation_secret =
    ///   ExpandWithLabel(operation_generation_secret, "vc operation",
    ///                   OperationContext, Kdf.Nh)
    /// ```
    fn expand_operation_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        operation_generation_secret: &Secret,
    ) -> Result<OperationSecret, VirtualClientsError> {
        let context = self.tls_serialize_detached()?;
        let operation_secret = operation_generation_secret.kdf_expand_label(
            crypto,
            ciphersuite,
            OPERATION_SECRET_LABEL,
            &context,
            ciphersuite.hash_length(),
        )?;
        Ok(OperationSecret::from(operation_secret))
    }
}

#[cfg(test)]
mod tests {
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::{random::OpenMlsRand, OpenMlsProvider};

    use super::*;
    use crate::components::vc_derivation_info::EmulatorEpochSecret;

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    /// Build two trees from the same `epoch_base_secret` (one sender-side,
    /// one receiver-side instance), going through the real per-epoch
    /// derivation chain.
    fn setup(
        leaf_count: u32,
    ) -> (
        OpenMlsRustCrypto,
        EpochId,
        OperationSecretTree,
        OperationSecretTree,
    ) {
        let provider = OpenMlsRustCrypto::default();
        let emulator = EmulatorEpochSecret::new(
            &provider
                .rand()
                .random_vec(CIPHERSUITE.hash_length())
                .expect("randomness"),
        );
        let epoch_id = emulator
            .derive_epoch_id(provider.crypto(), CIPHERSUITE)
            .expect("derive epoch id");
        let epoch_base_secret = emulator
            .derive_epoch_base_secret(provider.crypto(), CIPHERSUITE)
            .expect("derive epoch base secret");
        let size = TreeSize::from_leaf_count(leaf_count);
        let tree_a = OperationSecretTree::new(epoch_base_secret.clone(), size);
        let tree_b = OperationSecretTree::new(epoch_base_secret, size);
        (provider, epoch_id, tree_a, tree_b)
    }

    /// Two instances built from the same `epoch_base_secret` and size must
    /// agree on the operation secret for the same coordinates and context,
    /// regardless of the order in which they derive.
    #[test]
    fn cross_instance_agreement() {
        let (provider, epoch_id, mut tree_a, mut tree_b) = setup(8);
        let secret_a = tree_a
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                LeafNodeIndex::new(2),
                VirtualClientOperationType::LeafNode,
                3,
                b"commit context",
            )
            .expect("derive on tree a");
        // Tree b derives generations 0..=3 in order before reaching the same
        // coordinates.
        for generation in 0..3 {
            tree_b
                .derive_operation_secret(
                    provider.crypto(),
                    CIPHERSUITE,
                    &epoch_id,
                    LeafNodeIndex::new(2),
                    VirtualClientOperationType::LeafNode,
                    generation,
                    b"earlier context",
                )
                .expect("derive earlier generation on tree b");
        }
        let secret_b = tree_b
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                LeafNodeIndex::new(2),
                VirtualClientOperationType::LeafNode,
                3,
                b"commit context",
            )
            .expect("derive on tree b");
        assert_eq!(secret_a.as_slice(), secret_b.as_slice());
    }

    /// Different generations, leaves, operation types, and contexts must all
    /// yield different operation secrets.
    #[test]
    fn coordinates_and_context_bind_the_secret() {
        let (provider, epoch_id, mut tree_a, mut tree_b) = setup(8);
        let derive = |tree: &mut OperationSecretTree,
                      leaf: u32,
                      operation_type: VirtualClientOperationType,
                      generation: u32,
                      context: &[u8]| {
            tree.derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                LeafNodeIndex::new(leaf),
                operation_type,
                generation,
                context,
            )
            .expect("derive operation secret")
        };
        let leaf_node = VirtualClientOperationType::LeafNode;
        let baseline = derive(&mut tree_a, 0, leaf_node, 0, b"ctx");
        let other_generation = derive(&mut tree_a, 0, leaf_node, 1, b"ctx");
        let other_leaf = derive(&mut tree_a, 1, leaf_node, 0, b"ctx");
        let other_type = derive(
            &mut tree_a,
            0,
            VirtualClientOperationType::KeyPackage,
            0,
            b"ctx",
        );
        // Same coordinates as the baseline, but a different context. Derived
        // on the second instance because the baseline consumed generation 0.
        let other_context = derive(&mut tree_b, 0, leaf_node, 0, b"other ctx");
        let secrets = [
            baseline.as_slice(),
            other_generation.as_slice(),
            other_leaf.as_slice(),
            other_type.as_slice(),
            other_context.as_slice(),
        ];
        for (i, secret) in secrets.iter().enumerate() {
            for other in &secrets[i + 1..] {
                assert_ne!(secret, other);
            }
        }
    }

    /// Skipping ahead retains the skipped generations: deriving generation 5
    /// first, generations 0 through 4 each still succeed exactly once, and
    /// re-asking for any consumed generation fails. Skipped derivations match
    /// an instance that derives in order.
    #[test]
    fn out_of_order_derivation_and_consumption() {
        let (provider, epoch_id, mut tree_a, mut tree_b) = setup(4);
        let leaf = LeafNodeIndex::new(0);
        let operation_type = VirtualClientOperationType::Application;
        let context_for = |generation: u32| format!("operation {generation}").into_bytes();
        let in_order: Vec<_> = (0..=5)
            .map(|generation| {
                tree_b
                    .derive_operation_secret(
                        provider.crypto(),
                        CIPHERSUITE,
                        &epoch_id,
                        leaf,
                        operation_type,
                        generation,
                        &context_for(generation),
                    )
                    .expect("in-order derivation")
            })
            .collect();

        // Generation 5 first, skipping 0..=4.
        let skipped_ahead = tree_a
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                5,
                &context_for(5),
            )
            .expect("derive generation 5");
        assert_eq!(skipped_ahead.as_slice(), in_order[5].as_slice());

        // Generations 0 through 4 still succeed exactly once.
        for generation in 0..5 {
            let retained = tree_a
                .derive_operation_secret(
                    provider.crypto(),
                    CIPHERSUITE,
                    &epoch_id,
                    leaf,
                    operation_type,
                    generation,
                    &context_for(generation),
                )
                .expect("derive retained generation");
            assert_eq!(
                retained.as_slice(),
                in_order[generation as usize].as_slice()
            );
        }

        // Re-asking for any consumed generation fails, including generation 5.
        for generation in 0..=5 {
            let err = tree_a
                .derive_operation_secret(
                    provider.crypto(),
                    CIPHERSUITE,
                    &epoch_id,
                    leaf,
                    operation_type,
                    generation,
                    &context_for(generation),
                )
                .expect_err("consumed generation must fail");
            assert_eq!(err, VirtualClientsError::OperationGenerationConsumed);
        }

        // A leaf index outside the tree is rejected.
        let out_of_bounds = LeafNodeIndex::new(TreeSize::from_leaf_count(4).leaf_count());
        let err = tree_a
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                out_of_bounds,
                operation_type,
                0,
                b"ctx",
            )
            .expect_err("out-of-bounds leaf index must fail");
        assert_eq!(err, VirtualClientsError::IndexOutOfBounds);
    }

    /// The "next own operation" method yields sequential generations whose
    /// secrets match what a second instance derives positionally.
    #[test]
    fn next_operation_secret_advances_sequentially() {
        let (provider, epoch_id, mut tree_a, mut tree_b) = setup(4);
        let leaf = LeafNodeIndex::new(1);
        let operation_type = VirtualClientOperationType::KeyPackage;
        for expected_generation in 0..3 {
            let context = format!("key package {expected_generation}").into_bytes();
            let (generation, own_secret) = tree_a
                .next_operation_secret(
                    provider.crypto(),
                    CIPHERSUITE,
                    &epoch_id,
                    leaf,
                    operation_type,
                    &context,
                )
                .expect("next operation secret");
            assert_eq!(generation, expected_generation);
            let positional = tree_b
                .derive_operation_secret(
                    provider.crypto(),
                    CIPHERSUITE,
                    &epoch_id,
                    leaf,
                    operation_type,
                    generation,
                    &context,
                )
                .expect("positional derivation");
            assert_eq!(own_secret.as_slice(), positional.as_slice());
        }
    }

    /// A serde round-trip of a tree mid-state (some generations consumed,
    /// some skipped) preserves behavior: the round-tripped tree still serves
    /// retained skipped generations, still refuses consumed ones, and
    /// continues at the right head generation.
    #[test]
    fn serde_roundtrip_preserves_ratchet_state() {
        let (provider, epoch_id, mut tree_a, mut tree_b) = setup(4);
        let leaf = LeafNodeIndex::new(2);
        let operation_type = VirtualClientOperationType::LeafNode;
        // Skip ahead to generation 4 (retaining 0..=3), then consume
        // generation 1 from the retained entries.
        tree_a
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                4,
                b"four",
            )
            .expect("derive generation 4");
        tree_a
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                1,
                b"one",
            )
            .expect("derive retained generation 1");

        let serialized = serde_json::to_vec(&tree_a).expect("serialize tree");
        let mut restored: OperationSecretTree =
            serde_json::from_slice(&serialized).expect("deserialize tree");

        // A retained skipped generation is still served and agrees with a
        // second instance.
        let restored_secret = restored
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                2,
                b"two",
            )
            .expect("derive retained generation after round-trip");
        let positional = tree_b
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                2,
                b"two",
            )
            .expect("positional derivation");
        assert_eq!(restored_secret.as_slice(), positional.as_slice());

        // Consumed generations are still refused.
        for (generation, context) in [(1, b"one".as_slice()), (4, b"four".as_slice())] {
            let err = restored
                .derive_operation_secret(
                    provider.crypto(),
                    CIPHERSUITE,
                    &epoch_id,
                    leaf,
                    operation_type,
                    generation,
                    context,
                )
                .expect_err("consumed generation must fail after round-trip");
            assert_eq!(err, VirtualClientsError::OperationGenerationConsumed);
        }

        // The ratchet head continues right after the skipped-ahead
        // generation.
        let (generation, _secret) = restored
            .next_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                b"five",
            )
            .expect("next operation secret after round-trip");
        assert_eq!(generation, 5);
    }

    /// A generation more than [`MAXIMUM_FORWARD_DISTANCE`] beyond the head is
    /// rejected without advancing the head: the next own operation still
    /// allocates generation 0.
    #[test]
    fn forward_distance_bound_rejects_without_advancing() {
        let (provider, epoch_id, mut tree_a, _tree_b) = setup(4);
        let leaf = LeafNodeIndex::new(0);
        let operation_type = VirtualClientOperationType::LeafNode;
        let err = tree_a
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                MAXIMUM_FORWARD_DISTANCE + 1,
                b"ctx",
            )
            .expect_err("generation beyond the forward distance must fail");
        assert_eq!(err, VirtualClientsError::OperationGenerationTooDistant);

        // The head is unchanged: the next in-window derivation is still
        // generation 0.
        let (generation, _secret) = tree_a
            .next_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                b"ctx",
            )
            .expect("next operation secret after rejected request");
        assert_eq!(generation, 0);
    }

    /// A generation exactly at the forward-distance limit succeeds.
    #[test]
    fn forward_distance_boundary_succeeds() {
        let (provider, epoch_id, mut tree_a, _tree_b) = setup(4);
        let leaf = LeafNodeIndex::new(0);
        let operation_type = VirtualClientOperationType::LeafNode;
        tree_a
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                MAXIMUM_FORWARD_DISTANCE,
                b"ctx",
            )
            .expect("generation at the forward-distance limit must succeed");
        // The head sits right behind the consumed generation.
        let (generation, _secret) = tree_a
            .next_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                b"ctx",
            )
            .expect("next operation secret after skipping to the limit");
        assert_eq!(generation, MAXIMUM_FORWARD_DISTANCE + 1);
    }

    /// Skipping more unconsumed generations than [`OUT_OF_ORDER_TOLERANCE`]
    /// evicts the oldest retained entries first: the evicted generation fails
    /// as consumed, while the oldest generation still within the window is
    /// served exactly once and agrees with an in-order instance.
    #[test]
    fn skipping_beyond_tolerance_evicts_oldest() {
        let (provider, epoch_id, mut tree_a, mut tree_b) = setup(4);
        let leaf = LeafNodeIndex::new(0);
        let operation_type = VirtualClientOperationType::Application;
        let tolerance = OUT_OF_ORDER_TOLERANCE as u32;
        // Skipping 0..=tolerance retains one entry more than the tolerance,
        // evicting generation 0.
        let skip_to = tolerance + 1;
        tree_a
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                skip_to,
                b"ctx",
            )
            .expect("skipping derivation");

        // The evicted generation 0 reports as consumed.
        let err = tree_a
            .derive_operation_secret(
                provider.crypto(),
                CIPHERSUITE,
                &epoch_id,
                leaf,
                operation_type,
                0,
                b"ctx",
            )
            .expect_err("evicted generation must fail");
        assert_eq!(err, VirtualClientsError::OperationGenerationConsumed);

        // Reference values from an instance that derives strictly in order.
        let mut in_order = Vec::new();
        for generation in 0..=tolerance {
            let secret = tree_b
                .derive_operation_secret(
                    provider.crypto(),
                    CIPHERSUITE,
                    &epoch_id,
                    leaf,
                    operation_type,
                    generation,
                    b"ctx",
                )
                .expect("in-order derivation");
            in_order.push(secret);
        }

        // The oldest and newest generations within the window are still
        // served, agree with the in-order instance, and are served exactly
        // once.
        for generation in [1, tolerance] {
            let retained = tree_a
                .derive_operation_secret(
                    provider.crypto(),
                    CIPHERSUITE,
                    &epoch_id,
                    leaf,
                    operation_type,
                    generation,
                    b"ctx",
                )
                .expect("retained generation within the window");
            assert_eq!(
                retained.as_slice(),
                in_order[generation as usize].as_slice()
            );
            let err = tree_a
                .derive_operation_secret(
                    provider.crypto(),
                    CIPHERSUITE,
                    &epoch_id,
                    leaf,
                    operation_type,
                    generation,
                    b"ctx",
                )
                .expect_err("second request for the same generation must fail");
            assert_eq!(err, VirtualClientsError::OperationGenerationConsumed);
        }
    }
}
