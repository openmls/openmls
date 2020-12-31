use crate::ciphersuite::CryptoError;
use crate::config::ConfigError;

implement_error! {
    pub enum TreeError {
        Simple {
            InvalidArguments = "Invalid arguments.",
            InvalidUpdatePath = "The computed update path is invalid.",
            InvalidTree = "The tree is not valid.",
            NotAParentNode = "The node is not a parent node.",
        }
        Complex {
            ConfigError(ConfigError) =
                "See [`ConfigError`](`crate::config::ConfigError`) for details.",
            PathSecretDecryptionError(CryptoError) =
                "Error while decrypting `PathSecret`.",
        }
    }
}
