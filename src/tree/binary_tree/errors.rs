use std::error::Error;

use crate::tree::treemath::TreeMathError;

#[derive(Debug)]
pub enum BinaryTreeError {
    /// This is not an application message.
    IndexOutOfBounds,
}

implement_enum_display!(BinaryTreeError);

impl Error for BinaryTreeError {
    fn description(&self) -> &str {
        match self {
            Self::IndexOutOfBounds => "This index does not point to a node within the tree.",
        }
    }
}

impl From<TreeMathError> for BinaryTreeError {
    fn from(_: TreeMathError) -> Self {
        BinaryTreeError::IndexOutOfBounds
    }
}
