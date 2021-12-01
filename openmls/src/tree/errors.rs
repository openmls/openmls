use openmls_traits::types::CryptoError;
use tls_codec::Error as TlsCodecError;

use crate::credentials::CredentialError;

implement_error! {
    pub enum TreeError {
        Simple {
            InvalidArguments = "Invalid arguments.",
            InvalidUpdatePath = "The computed update path is invalid.",
            InvalidTree = "The tree is not valid.",
            NotAParentNode = "The node is not a parent node.",
        }
        Complex {
            CredentialError(CredentialError) =
                    "See [`CredentialError`](`crate::credentials::CredentialError`) for details",
            CodecError(TlsCodecError) =
                    "TLS (de)serialization error occurred.",
            CryptoError(CryptoError) =
                    "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
        }
    }
}

implement_error! {
    pub enum ParentHashError {
        Simple {
            EndedWithLeafNode = "The search for a valid child ended with a leaf node.",
            AllChecksFailed = "All checks failed: Neither child has the right parent hash.",
            InputNotParentNode = "The input node is not a parent node.",
            NotAParentNode = "The node is not a parent node.",
            EmptyParentNode = "The parent node was blank.",
        }
        Complex {
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
        }
    }
}
