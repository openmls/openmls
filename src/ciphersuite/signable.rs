use crate::ciphersuite::*;
use crate::credentials::*;

/// This trait must be implemented by all structs that contain a self-signature.
pub trait SignedStruct<T> {
    /// Build a signed struct version from the payload struct.
    fn from_payload(payload: T, signature: Signature) -> Self;
}

/// The `Signable` trait is implemented by all struct that are being signed.
/// The implementation has to provide the `unsigned_payload` function.
pub trait Signable: Sized {
    type SignedOutput;

    fn unsigned_payload(&self) -> Result<Vec<u8>, crate::codec::CodecError>;

    /// Sign the payload with the given `id`.
    ///
    /// Returns a `Signature`.
    fn sign(
        self,
        credential_bundle: &CredentialBundle,
    ) -> Result<Self::SignedOutput, CredentialError>
    where
        Self::SignedOutput: SignedStruct<Self>,
    {
        let payload = self.unsigned_payload()?;
        let signature = credential_bundle
            .sign(&payload)
            .map_err(|_| CredentialError::SignatureError)?;
        Ok(Self::SignedOutput::from_payload(self, signature))
    }
}

pub trait Verifiable {
    fn unsigned_payload(&self) -> Result<Vec<u8>, crate::codec::CodecError>;
    fn signature(&self) -> &Signature;

    /// Verifies the payload against the given `credential` and `signature`.
    ///
    /// Returns `Ok(())` if the signature is valid and
    /// `CredentialError::InvalidSignature` otherwise.
    fn verify(&self, credential: &Credential) -> Result<(), CredentialError> {
        let payload = self.unsigned_payload()?;
        credential.verify(&payload, self.signature())
    }
}
