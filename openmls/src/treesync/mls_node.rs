use hpke::HpkePublicKey;

use super::treesyncable::{TreeSyncLeaf, TreeSyncParent, TreeSyncable, TreeSyncableMut};

use crate::{
    binary_tree::NodeIndex,
    ciphersuite::signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
    extensions::{ExtensionType::ParentHash, ParentHashExtension},
    key_packages::KeyPackage,
    prelude::KeyPackagePayload,
};

pub(crate) enum MlsNode {
    Parent(ParentNode),
    Leaf(LeafNode),
}

pub(crate) struct ParentNode {
    public_key: HpkePublicKey,
    unmerged_leaves: Vec<NodeIndex>,
    parent_hash: Vec<u8>,
    tree_hash: Vec<u8>,
}

// TODO: Do we really need the mutable/immutable distinction for ParentNode?
impl TreeSyncParent for ParentNode {
    type TreeSyncParentMut = ParentNode;

    fn to_mut(self) -> Self::TreeSyncParentMut {
        self
    }

    fn to_immut(tsp_mut: Self::TreeSyncParentMut) -> Self {
        tsp_mut
    }
}

pub(crate) struct UnverifiedLeafNode {
    tree_hash: Vec<u8>,
    key_package: KeyPackage,
}

impl Verifiable for UnverifiedLeafNode {
    fn unsigned_payload(&self) -> Result<Vec<u8>, crate::codec::CodecError> {
        self.key_package.unsigned_payload()
    }

    fn signature(&self) -> &crate::ciphersuite::Signature {
        self.key_package.signature()
    }
}

pub(crate) struct LeafNode {
    // For caching the tree hash of the leaf node.
    tree_hash: Vec<u8>,
    key_package: KeyPackage,
}

impl SignedStruct<KeyPackagePayload> for LeafNode {
    fn from_payload(payload: KeyPackagePayload, signature: crate::ciphersuite::Signature) -> Self {
        let key_package = KeyPackage::from_payload(payload, signature);
        Self {
            tree_hash: vec![],
            key_package,
        }
    }
}

impl TreeSyncable for LeafNode {
    fn node_content(&self) -> &[u8] {
        &self.key_package.hpke_init_key().as_slice()
    }

    fn unmerged_leaves(&self) -> Result<&[NodeIndex], Self::TreeSyncableError> {
        Err(Self::TreeSyncableError::NodeTypeError)
    }

    fn parent_hash(&self) -> &[u8] {
        self.key_package
            .extension_with_type(ParentHash)
            // We can unwrap here, because leaf nodes can only be created
            // from key packages that contain an parent hash extension.
            .unwrap()
            .to_parent_hash_extension()
            // We can unwrap here, because we just checked, that the type of
            // the extension is `ParentHash`.
            .unwrap()
            .parent_hash()
    }

    fn tree_hash(&self) -> &[u8] {
        &self.tree_hash
    }

    type TreeSyncableError = MlsNodeError;
}

pub(crate) struct LeafNodeMut {
    // For caching the tree hash of the leaf node.
    tree_hash: Vec<u8>,
    key_package: KeyPackagePayload,
}

impl TreeSyncableMut for LeafNodeMut {
    fn set_tree_hash(&mut self, tree_hash: Vec<u8>) {
        self.tree_hash = tree_hash
    }

    fn clear_unmerged_leaves(&mut self) -> Result<(), Self::TreeSyncableMutError> {
        Err(Self::TreeSyncableMutError::NodeTypeError)
    }

    fn add_unmerged_leaf(
        &mut self,
        _node_index: NodeIndex,
    ) -> Result<(), Self::TreeSyncableMutError> {
        Err(Self::TreeSyncableMutError::NodeTypeError)
    }

    fn set_parent_hash(&mut self, parent_hash: Vec<u8>) {
        let parent_hash_extension = ParentHashExtension::new(&parent_hash);
        self.key_package
            .add_extension(Box::new(parent_hash_extension));
    }

    type TreeSyncableMutError = MlsNodeError;
}

impl Signable for LeafNodeMut {
    type SignedOutput = LeafNode;

    fn unsigned_payload(&self) -> Result<Vec<u8>, crate::codec::CodecError> {
        self.key_package.unsigned_payload()
    }
}

impl SignedStruct<LeafNodeMut> for LeafNode {
    fn from_payload(payload: LeafNodeMut, signature: crate::ciphersuite::Signature) -> Self {
        Self {
            tree_hash: payload.tree_hash,
            key_package: KeyPackage::from_payload(payload.key_package, signature),
        }
    }
}

impl TreeSyncLeaf for LeafNode {
    type UnverifiedLeaf = UnverifiedLeafNode;

    type UnsignedLeaf = LeafNodeMut;

    type SignedLeaf = LeafNode;
}

impl VerifiedStruct<UnverifiedLeafNode> for LeafNode {
    fn from_verifiable(verifiable: UnverifiedLeafNode) -> Self {
        Self {
            tree_hash: verifiable.tree_hash,
            key_package: KeyPackage::from_verifiable(verifiable.key_package),
        }
    }
}

impl TreeSyncable for ParentNode {
    type TreeSyncableError = MlsNodeError;
    fn node_content(&self) -> &[u8] {
        self.public_key.as_slice()
    }

    fn unmerged_leaves(&self) -> Result<&[NodeIndex], Self::TreeSyncableError> {
        Ok(&self.unmerged_leaves)
    }

    fn parent_hash(&self) -> &[u8] {
        &self.parent_hash
    }

    fn tree_hash(&self) -> &[u8] {
        &self.tree_hash
    }
}

impl TreeSyncableMut for ParentNode {
    fn clear_unmerged_leaves(&mut self) -> Result<(), Self::TreeSyncableMutError> {
        Ok(self.unmerged_leaves = vec![])
    }

    fn add_unmerged_leaf(
        &mut self,
        node_index: NodeIndex,
    ) -> Result<(), Self::TreeSyncableMutError> {
        Ok(self.unmerged_leaves.push(node_index))
    }

    fn set_parent_hash(&mut self, parent_hash: Vec<u8>) {
        self.parent_hash = parent_hash
    }

    fn set_tree_hash(&mut self, tree_hash: Vec<u8>) {
        self.parent_hash = tree_hash
    }

    type TreeSyncableMutError = MlsNodeError;
}

implement_error! {
    pub enum MlsNodeError {
        NodeVerificationError = "Could not verify this node.",
        NodeTypeError = "The given node is of the wrong type.",
    }
}

//enum MlsNode {
//    Parent(ParentNode),
//    Leaf(LeafNode),
//}
//
//impl TreeSyncNode for MlsNode {
//    fn node_content(&self) -> &[u8] {
//        match self {
//            MlsNode::Parent(parent_node) => parent_node.public_key.as_slice(),
//            MlsNode::Leaf(leaf_node) => leaf_node.key_package.hpke_init_key().as_slice(),
//        }
//    }
//
//    fn unmerged_leaves(&self) -> Result<&[NodeIndex], TreeSyncNodeError> {
//        match self {
//            MlsNode::Parent(parent_node) => Ok(&parent_node.unmerged_leaves),
//            MlsNode::Leaf(_) => Err(TreeSyncNodeError::NodeTypeError),
//        }
//    }
//
//    fn clear_unmerged_leaves(&mut self) -> Result<(), TreeSyncNodeError> {
//        match *self {
//            // Or should I call `clear()` here instead?
//            MlsNode::Parent(ref mut parent_node) => {
//                parent_node.unmerged_leaves = vec![];
//                Ok(())
//            }
//            MlsNode::Leaf(_) => Err(TreeSyncNodeError::NodeTypeError),
//        }
//    }
//
//    fn add_unmerged_leaf(&mut self, node_index: NodeIndex) -> Result<(), TreeSyncNodeError> {
//        match self {
//            MlsNode::Parent(parent_node) => {
//                parent_node.unmerged_leaves.push(node_index);
//                Ok(())
//            }
//            MlsNode::Leaf(_) => Err(TreeSyncNodeError::NodeTypeError),
//        }
//    }
//
//    fn set_parent_hash(&mut self, parent_hash: Vec<u8>) {
//        match *self {
//            MlsNode::Parent(ref mut parent_node) => parent_node.parent_hash = parent_hash,
//            MlsNode::Leaf(ref mut leaf_node) => {
//                let parent_hash_extension = ParentHashExtension::new(&parent_hash);
//                leaf_node
//                    .key_package
//                    .add_extension(Box::new(parent_hash_extension));
//            }
//        }
//    }
//
//    fn parent_hash(&self) -> &[u8] {
//        match self {
//            MlsNode::Parent(parent_node) => &parent_node.parent_hash,
//            MlsNode::Leaf(leaf_node) => leaf_node
//                .key_package
//                .extension_with_type(ParentHash)
//                // We can unwrap here, because leaf nodes can only be created
//                // from key packages that contain an parent hash extension.
//                .unwrap()
//                .to_parent_hash_extension()
//                // We can unwrap here, because we just checked, that the type of
//                // the extension is `ParentHash`.
//                .unwrap()
//                .parent_hash(),
//        }
//    }
//
//    fn set_tree_hash(&mut self, tree_hash: Vec<u8>) {
//        match *self {
//            MlsNode::Parent(ref mut parent_node) => parent_node.tree_hash = tree_hash,
//            MlsNode::Leaf(ref mut leaf_node) => leaf_node.tree_hash = tree_hash,
//        }
//    }
//
//    fn tree_hash(&self) -> &[u8] {
//        match self {
//            MlsNode::Parent(parent_node) => parent_node.tree_hash,
//            MlsNode::Leaf(leaf_node) => leaf_node.tree_hash,
//        }
//    }
//
//    fn verify(&self) -> Result<bool, super::treesyncnode::TreeSyncNodeError> {
//        match self {
//            MlsNode::Parent(parent_node) => todo!(),
//            MlsNode::Leaf(key_package) => todo!(),
//        }
//    }
//}
