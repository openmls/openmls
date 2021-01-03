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
