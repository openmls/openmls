use super::FLBBinaryTree;
use super::FLBBinaryTreeError;
use super::NodeIndex;

pub(crate) struct ABinaryTree<T> {
    nodes: Vec<T>,
}

pub(crate) fn log2(x: NodeIndex) -> NodeIndex {
    if x == 0 {
        return 0;
    }
    let mut k = 0;
    while (x >> k) > 0 {
        k += 1
    }
    k - 1
}

impl<T> ABinaryTree<T> {
    /// Check if a given index is still within the tree.
    fn node_in_tree(&self, node_index: NodeIndex) -> Result<(), FLBBinaryTreeError> {
        if node_index as usize >= self.nodes.len() {
            Err(FLBBinaryTreeError::OutOfRange)
        } else {
            Ok(())
        }
    }

    fn root(&self) -> NodeIndex {
        (1usize << log2(self.nodes.len())) - 1
    }

    fn leaf_count(&self) -> NodeIndex {
        let n = self.nodes.len();
        if n == 0 {
            0
        } else {
            2 * (n - 1) + 1
        }
    }

    fn unsafe_parent(&self, index: NodeIndex) -> Result<NodeIndex, FLBBinaryTreeError> {
        self.node_in_tree(index)?;
        let n = self.leaf_count();
        if index == self.root() {
            return Err(TreeMathError::RootHasNoParent);
        }
        let mut p = parent_step(x);
        while p >= node_width(n) {
            let new_p = parent_step(p);
            if new_p == p {
                return Err(TreeMathError::InvalidInput);
            }
            p = new_p;
        }
        Ok(NodeIndex::from(p))
    }
}

impl<T> FLBBinaryTree<T> for ABinaryTree<T> {
    fn node(&self, node_index: NodeIndex) -> Result<&T, FLBBinaryTreeError> {
        self.nodes
            .get(node_index as usize)
            .ok_or(FLBBinaryTreeError::OutOfRange)
    }

    fn node_mut(&mut self, node_index: NodeIndex) -> Result<&mut T, super::FLBBinaryTreeError> {
        self.nodes
            .get_mut(node_index as usize)
            .ok_or(FLBBinaryTreeError::OutOfRange)
    }

    fn add(&mut self, node_1: T, node_2: T) -> Result<(), FLBBinaryTreeError> {
        self.nodes.push(node_1);
        self.nodes.push(node_2);
        Ok(())
    }

    fn remove(&mut self) -> Result<(), FLBBinaryTreeError> {
        self.nodes.pop();
        self.nodes.pop();
        Ok(())
    }

    fn direct_path(&self, start_index: NodeIndex) -> Result<Vec<NodeIndex>, FLBBinaryTreeError> {
        self.node_in_tree(start_index)?;
        let r = self.root();
        if start_index == r {
            return Ok(vec![r]);
        }

        let mut d = vec![];
        let mut x = start_index;
        while x != r {
            x = unsafe_parent(x, size)?;
            d.push(x);
        }
        Ok(d)
    }

    fn co_path(&self, start_index: NodeIndex) -> Result<Vec<NodeIndex>, FLBBinaryTreeError> {
        todo!()
    }
}
