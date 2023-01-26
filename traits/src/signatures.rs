use crate::types::Error;

/// Sign the provided payload and return a signature.
pub trait Signer {
    /// Sign the provided payload.
    ///
    /// Returns a signature on success or an Error.
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error>;
}
