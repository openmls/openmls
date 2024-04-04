use crate::types::{CryptoError, SignatureScheme};
/// Trait errors.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SignerError {
    CryptoError(CryptoError),
    InvalidSignature,
    SigningError,
}

/// Sign the provided payload and return a signature.
pub trait Signer {
    /// Sign the provided payload.
    ///
    /// Returns a signature on success or an Error.
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError>;

    /// The [`SignatureScheme`] of this signer.
    fn signature_scheme(&self) -> SignatureScheme;
}
