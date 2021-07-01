use std::collections::HashMap;

use treesync_update::{TreeSyncUpdate, UnsignedTreeSyncUpdate};

use crate::{
    binary_tree::{treemath::direct_path, FLBBinaryTree, NodeIndex, TreeSize},
    treesync::mls_node::MlsNodeContent,
};

use super::{
    mls_node::{LeafNode, MlsNode, ParentNode},
    treesync_update,
    treesyncable::TreeSyncNode,
    TreeSync, TreeSyncDiff,
};

pub(crate) struct MlsTreeSync<T: FLBBinaryTree<MlsNode>> {
    tree: T,
}

impl<T: FLBBinaryTree<MlsNode>> TreeSync<ParentNode, LeafNode> for MlsTreeSync<T> {
    fn tree_hash(&self) -> &[u8] {
        self.tree.root().tree_hash()
    }

    fn merge_diff(
        &mut self,
        tree_sync_diff: Self::TreeSyncDiff,
    ) -> Result<(), Self::TreeSyncError> {
        // This has to do all the validation and conversions between verifiable
        // and verified structs.

        // We might also want to do some parenthash verification here.
        todo!()
    }

    fn empty_diff(&self) -> Self::TreeSyncDiff {
        let mut blank_leaves = Vec::new();
        // Optimization opportunity: This could probably be kept track of by the
        // tree. Note, that we initialize the blank leaves in reverse order
        // here, so we can pop the last index when we fill a blank spot.
        for leaf_index in self.tree.leaf_count()..0 {
            if self
                .tree
                .node(leaf_index * 2)
                // We can unwrap here, as we know from leaf_count that the leaf is
                // inside of the tree.
                .unwrap()
                .node_content()
                .is_none()
            {
                blank_leaves.push(leaf_index)
            }
        }
        MlsTreeSyncDiff {
            nodes: HashMap::new(),
            tree_size: self.tree.size(),
            blank_leaves,
            original_tree: &self,
        }
    }

    type TreeSyncError = MlsTreeSyncError;

    type TreeSyncDiff<'a> = MlsTreeSyncDiff<'a, T>;
}

struct MlsTreeSyncDiff<'a, T: FLBBinaryTree<MlsNode>> {
    original_tree: &'a MlsTreeSync<T>,
    // This is the tree size already considering operations stored in this diff.
    tree_size: TreeSize,
    nodes: HashMap<NodeIndex, MlsNode>,
    // Indices of the blank leaves of the original tree. If operations have been
    // performed on this diff, the blank diffs here might not be the same as on
    // the original tree.
    blank_leaves: Vec<NodeIndex>,
}

impl<'a, T: FLBBinaryTree<MlsNode>> TreeSyncDiff<ParentNode, LeafNode> for MlsTreeSyncDiff<'a, T> {
    fn update_leaf(
        &mut self,
        leaf_node: LeafNode,
        leaf_index: NodeIndex,
    ) -> Result<(), MlsTreeSyncError> {
        // Insert the leaf node at the given index.
        let node = MlsNode::from(MlsNodeContent::Leaf(leaf_node));

        //    MlsNode {
        //    node_content: Some(MlsNodeContent::Leaf(leaf_node)),
        //    tree_hash: vec![],
        //};
        self.nodes.insert(leaf_index, node);

        // Blank the direct path of the given leaf by first computing the direct
        // path...
        let direct_path = direct_path(leaf_index, self.tree_size)
            .map_err(|_| MlsTreeSyncError::InvalidLeafUpdate)?;

        // And then blanking the corresponding nodes.
        for index in &direct_path {
            self.nodes.insert(*index, MlsNode::default());
        }

        Ok(())
    }

    fn add_leaf(&mut self, leaf_node: LeafNode) -> Result<(), MlsTreeSyncError> {
        let node = MlsNode::from(leaf_node);
        // If there's an empty leaf, put the new leaf there.
        if let Some(leaf_index) = self.blank_leaves.pop() {
            self.nodes.insert(leaf_index, node);
        }
        // Otherwise, extend the tree by a blank and a new leaf.
        else {
            self.nodes.insert(self.tree_size, MlsNode::default());
            self.nodes.insert(self.tree_size + 1, node);
            self.tree_size += 2;
        };
        Ok(())
    }

    fn remove_leaf(&mut self, leaf_index: NodeIndex) -> Result<(), MlsTreeSyncError> {
        todo!()
    }

    fn process_update_path(&mut self, update: TreeSyncUpdate<ParentNode, LeafNode>) -> () {
        todo!()
    }

    fn create_update_path(
        &mut self,
        update: UnsignedTreeSyncUpdate<ParentNode, LeafNode>,
    ) -> Result<TreeSyncUpdate<ParentNode, LeafNode>, MlsTreeSyncError> {
        todo!()
    }

    fn tree_hash(&self) -> Vec<u8> {
        todo!()
    }

    type TreeSyncDiffError = MlsTreeSyncError;
}

implement_error! {
    pub enum MlsTreeSyncError {
        InvalidLeafUpdate = "Given leaf index is outside of the tree.",
        NodeVerificationError = "Could not verify this node.",
        NodeTypeError = "The given node is of the wrong type.",
    }
}
