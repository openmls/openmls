//! # Crypto errors
//!
//! This file defines a set of errors thrown by crypto operations.

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
        SignatureEncodingError = "Error while encoding signature",
        SignatureDecodingError = "Error while decoding signature",
    }
}
