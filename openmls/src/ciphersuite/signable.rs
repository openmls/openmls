use crate::{
    ciphersuite::Signature,
    codec::CodecError,
    credentials::{Credential, CredentialBundle, CredentialError},
};

/// This trait must be implemented by all structs that contain a self-signature.
pub trait SignedStruct<T> {
    /// Build a signed struct version from the payload struct.
    fn from_payload(payload: T, signature: Signature) -> Self;
}

/// The `Signable` trait is implemented by all struct that are being signed.
/// The implementation has to provide the `unsigned_payload` function.
pub trait Signable: Sized {
    type SignedOutput;

    /// Return the unsigned, serialized payload that should be signed.
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError>;

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

/// The verifiable trait must be implemented by any struct that is signed with
/// a credential. The actual `verify` method is provided.
/// The `unsigned_payload` and `signature` functions have to be implemented for
/// each struct, returning the serialized payload and the signature respectively.
///
/// Note that `Verifiable` should not be implemented on the same struct as
/// `Signable`. If this appears to be necessary, it is probably a sign that the
/// struct implementing them aren't well defined. Not that both traits define an
/// `unsigned_payload` function.
pub trait Verifiable {
    /// Return the unsigned, serialized payload that should be verified.
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError>;

    /// A reference to the signature to be verified.
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
