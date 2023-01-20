use crate::types::Error;

/// Sign the provided payload and return a signature.
pub trait Signer<Signature> {
    type Error;

    /// Sign the provided payload.
    ///
    /// Returns a signature on success or an Error.
    fn sign(&self, payload: &[u8]) -> Result<Signature, Self::Error>;
}

/// Verify the provided payload.
pub trait Verifier<Signature: ?Sized> {
    /// Verify that the provided signature for a given payload is valid.
    ///
    /// Returns `()` when the signature is valid, or an [`Error`] if not.
    fn verify(&self, payload: &[u8], signature: &Signature) -> Result<(), Error>;
}

/// A [`Signer`] that outputs [`Vec<u8>`].
pub trait ByteSigner: Signer<Vec<u8>> {}

/// A [`Verifier`] that takes [`Vec<u8>`] signatures.
pub trait ByteVerifier: Verifier<[u8]> {}
