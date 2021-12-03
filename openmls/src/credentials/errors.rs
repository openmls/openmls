use crate::config::ConfigError;
use openmls_traits::types::CryptoError;
use tls_codec::Error as TlsCodecError;

implement_error! {
    pub enum CredentialError {
        Simple {
            UnsupportedCredentialType = "Unsupported credential type.",
            InvalidSignature = "Invalid signature.",
        }
        Complex {
            ConfigError(ConfigError) = "See `ConfigError` for details.",
            CryptoError(CryptoError) = "See `CryptoError` for details.",
            CodecError(TlsCodecError) = "See [`tls_codec::Error`] for details.",
        }
    }
}
