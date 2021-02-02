use crate::ciphersuite::*;
use crate::credentials::*;

/// The `Signable` trait is implemented by all struct that are being signed.
/// The implementation has to provide the `unsigned_payload` function.
pub trait Signable: Sized {
    fn unsigned_payload(&self) -> Result<Vec<u8>, crate::codec::CodecError>;

    /// Sign the payload with the given `id`.
    ///
    /// Returns a `Signature`.
    fn sign(&self, credential_bundle: &CredentialBundle) -> Signature {
        let payload = self.unsigned_payload().unwrap();
        credential_bundle.sign(&payload).unwrap()
    }

    /// Verifies the payload against the given `credential` and `signature`.
    ///
    /// Returns `Ok(())` if the signature is valid and
    /// `CredentialError::InvalidSignature` otherwise.
    fn verify(
        &self,
        credential: &Credential,
        signature: &Signature,
    ) -> Result<(), CredentialError> {
        let payload = self.unsigned_payload().unwrap();
        credential.verify(&payload, signature)
    }
}
