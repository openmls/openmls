use crate::ciphersuite::*;
use crate::codec::CodecError;
use crate::config::ConfigError;

implement_error! {
    pub enum CredentialError {
        Simple {
            UnsupportedCredentialType = "Unsupported credential type.",
            InvalidSignature = "Invalid signature.",
            SignatureError = "Error while signing.",
        }
        Complex {
            ConfigError(ConfigError) = "See `ConfigError` for details.",
            CryptoError(CryptoError) = "See `CryptoError` for details.",
            CodecError(CodecError) = "See `CodecError` for details.",
        }
    }
}
