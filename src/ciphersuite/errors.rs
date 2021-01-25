//! # Crypto errors
//!
//! This file defines a set of errors thrown by crypto operations.

implement_error! {
    pub(crate) enum HKDFError {
        InvalidLength = "The HKDF output is empty.",
    }
}

implement_error! {
    pub enum CryptoError {
        CryptoLibraryError = "Unrecoverable error in the crypto library.",
        HpkeDecryptionError = "Error while decrypting an HPKE ciphertext.",
        UnsupportedSignatureScheme = "This SignatureScheme is not supported.",
    }
}
