use openmls_traits::types::CryptoError;
use thiserror::Error;
use tls_codec::Error as TlsCodecError;

#[derive(Error, Debug, PartialEq, Clone)]
pub enum CredentialError {
    #[error("Unsupported credential type.")]
    UnsupportedCredentialType,
    #[error("Invalid signature.")]
    InvalidSignature,
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
    #[error(transparent)]
    CodecError(#[from] TlsCodecError),
}
