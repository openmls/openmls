//! Errors for BinaryTree operations.

implement_error! {
    pub enum BinaryTreeError {
        Simple {
            IndexOutOfBounds = "Input index is out of bounds.",
            LeafHasNoChildren = "Attempting to access the child of a leaf.",
            RootHasNoParent = "Attempting to access the parent of the root.",
            TreeNotFull = "Attempting to modify the tree such that it's not full anymore.",
            NotEnoughNodes = "Attempting to remove more nodes than are present in the tree.",
        }
        Complex {}
    }
}
