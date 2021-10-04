//! # Crypto errors
//!
//! This file defines a set of errors thrown by crypto operations.

use evercrypt::signature::Error as EvercryptSignatureError;

implement_error! {
    pub enum CryptoError {
        CryptoLibraryError = "Unrecoverable error in the crypto library.",
        AeadDecryptionError = "Error while decrypting AEAD ciphertext.",
        HpkeDecryptionError = "Error while decrypting an HPKE ciphertext.",
        UnsupportedSignatureScheme = "This SignatureScheme is not supported.",
        KdfLabelTooLarge = "The requested Kdf label length is too large.",
        KdfSerializationError = "Serialization of the Kdf label failed.",
        HkdfOutputLengthInvalid = "The requested HKDF output length is invalid",
        InsufficientRandomness = "Error getting enough randomness",
        InvalidSignature = "The signature could not be verified",
        UnsupportedAeadAlgorithm = "The requested AEAD scheme is not supported",
        UnsupportedKdf = "The requested KDF algorithm is not supported",
        InvalidLength = "The HKDF output is empty.",
        UnsupportedHashAlgorithm = "Unsupported hash algorithm",
    }
}

implement_error! {
    pub enum SignatureError {
        InvalidSignature = "Error while validating signature.",
        InvalidPublicKey = "The given public key is invalid.",
        SigningError = "Error while signing payload.",
        UnknownAlgorithm = "The given algorithm is unknown or unsupported.",
        EncodingError = "Error while DER encoding ECDSA signature.",
        DecodingError = "Error while DER decoding ECDSA signature.",
        LibraryError = "An internal error occurred.",
        KeyGenerationError = "Error while generating signature keypair.",
    }
}

impl From<EvercryptSignatureError> for SignatureError {
    fn from(e: EvercryptSignatureError) -> Self {
        match e {
            EvercryptSignatureError::InvalidPoint => SignatureError::InvalidPublicKey,
            EvercryptSignatureError::UnknownAlgorithm => SignatureError::UnknownAlgorithm,
            EvercryptSignatureError::HashAlgorithmMissing => SignatureError::LibraryError,
            EvercryptSignatureError::InvalidSignature => SignatureError::InvalidSignature,
            EvercryptSignatureError::KeyGenError => SignatureError::KeyGenerationError,
            EvercryptSignatureError::NonceMissing => SignatureError::SigningError,
        }
    }
}
