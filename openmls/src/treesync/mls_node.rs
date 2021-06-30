use std::option::Option;

use hpke::HpkePublicKey;

use super::treesyncable::{
    TreeSyncLeaf, TreeSyncNode, TreeSyncParent, TreeSyncParentMut, TreeSyncable, TreeSyncableMut,
};

use crate::{
    binary_tree::NodeIndex,
    ciphersuite::signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
    extensions::{ExtensionType::ParentHash, ParentHashExtension},
    key_packages::KeyPackage,
    prelude::KeyPackagePayload,
};

pub(crate) enum MlsNodeContent {
    Parent(ParentNode),
    Leaf(LeafNode),
}

pub(crate) struct MlsNode {
    node_content: Option<MlsNodeContent>,
    tree_hash: Vec<u8>,
}

impl Default for MlsNode {
    fn default() -> Self {
        Self {
            node_content: None,
            tree_hash: vec![],
        }
    }
}

impl TreeSyncNode for MlsNode {
    fn tree_hash(&self) -> &[u8] {
        &self.tree_hash
    }

    fn node_content(&self) -> Option<&dyn TreeSyncable> {
        match &self.node_content {
            Some(content) => match content {
                MlsNodeContent::Parent(parent) => Some(parent),
                MlsNodeContent::Leaf(leaf) => Some(leaf),
            },
            None => None,
        }
    }

    fn set_tree_hash(&mut self, tree_hash: Vec<u8>) {
        self.tree_hash = tree_hash
    }
}

pub(crate) struct ParentNode {
    public_key: HpkePublicKey,
    unmerged_leaves: Vec<NodeIndex>,
    parent_hash: Vec<u8>,
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

    fn unmerged_leaves(&self) -> &[NodeIndex] {
        &self.unmerged_leaves
    }
}

impl TreeSyncParentMut for ParentNode {
    fn clear_unmerged_leaves(&mut self) {
        self.unmerged_leaves = vec![]
    }

    fn add_unmerged_leaf(&mut self, node_index: NodeIndex) {
        self.unmerged_leaves.push(node_index)
    }
}

pub(crate) struct LeafNode {
    key_package: KeyPackage,
}

pub(crate) struct UnverifiedLeafNode {
    unverified_key_package: KeyPackage,
}

impl Verifiable for UnverifiedLeafNode {
    fn unsigned_payload(&self) -> Result<Vec<u8>, crate::codec::CodecError> {
        self.unverified_key_package.unsigned_payload()
    }

    fn signature(&self) -> &crate::ciphersuite::Signature {
        self.unverified_key_package.signature()
    }
}

impl SignedStruct<KeyPackagePayload> for LeafNode {
    fn from_payload(payload: KeyPackagePayload, signature: crate::ciphersuite::Signature) -> Self {
        let key_package = KeyPackage::from_payload(payload, signature);
        Self { key_package }
    }
}

impl TreeSyncable for LeafNode {
    fn node_content(&self) -> &[u8] {
        &self.key_package.hpke_init_key().as_slice()
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
}

pub(crate) struct LeafNodeMut {
    key_package: KeyPackagePayload,
}

impl TreeSyncableMut for LeafNodeMut {
    fn set_parent_hash(&mut self, parent_hash: Vec<u8>) {
        let parent_hash_extension = ParentHashExtension::new(&parent_hash);
        self.key_package
            .add_extension(Box::new(parent_hash_extension));
    }
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
            key_package: KeyPackage::from_verifiable(verifiable.unverified_key_package),
        }
    }
}

impl TreeSyncable for ParentNode {
    fn node_content(&self) -> &[u8] {
        self.public_key.as_slice()
    }

    fn parent_hash(&self) -> &[u8] {
        &self.parent_hash
    }
}

impl TreeSyncableMut for ParentNode {
    fn set_parent_hash(&mut self, parent_hash: Vec<u8>) {
        self.parent_hash = parent_hash
    }
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
