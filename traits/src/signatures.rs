use crate::types::Error;

/// Sign the provided payload and return a signature.
pub trait Signer<Signature> {
    /// Sign the provided payload.
    ///
    /// Returns a signature on success or an Error.
    fn sign(&self, payload: &[u8]) -> Result<Signature, Error>;
}

/// A [`Signer`] that outputs [`Vec<u8>`].
pub trait ByteSigner: Signer<Vec<u8>> {}
