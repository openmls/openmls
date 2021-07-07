use crate::ciphersuite::*;
use crate::config::ConfigError;
use tls_codec::Error as TlsError;

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
            CodecError(TlsError) = "See [`tls_codec::Error`] for details.",
        }
    }
}
