use crate::ciphersuite::CryptoError;

implement_error! {
    pub enum TreeError {
        Simple {
            InvalidArguments = "Invalid arguments.",
            InvalidUpdatePath = "The computed update path is invalid.",
            InvalidTree = "The tree is not valid.",
            NotAParentNode = "The node is not a parent node.",
        }
        Complex {
            PathSecretDecryptionError(CryptoError) =
                "Error while decrypting `PathSecret`.",
        }
    }
}

implement_error! {
    pub enum ParentHashError {
        EndedWithLeafNode = "The search for a valid child ended with a leaf node.",
        AllChecksFailed = "All checks failed: Neither child has the right parent hash.",
        InputNotParentNode = "The input node is not a parent node.",
        EmptyParentNode = "The parent node was blank.",
    }
}
