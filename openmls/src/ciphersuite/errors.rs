//! # Crypto errors
//!
//! This file defines a set of errors thrown by crypto operations.

implement_error! {
    pub(crate) enum HkdfError {
        InvalidLength = "The HKDF output is empty.",
    }
}

implement_error! {
    pub enum CryptoError {
        CryptoLibraryError = "Unrecoverable error in the crypto library.",
        HpkeDecryptionError = "Error while decrypting an HPKE ciphertext.",
        UnsupportedSignatureScheme = "This SignatureScheme is not supported.",
        KdfLabelTooLarge = "The requested Kdf label length is too large.",
        KdfSerializationError = "Serialization of the Kdf label failed.",
        HkdfOutputLengthInvalid = "The requested HKDF output length is invalid",
    }
}

impl From<HkdfError> for CryptoError {
    fn from(e: HkdfError) -> Self {
        match e {
            HkdfError::InvalidLength => Self::HkdfOutputLengthInvalid,
        }
    }
}
