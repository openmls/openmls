use crate::{
    ciphersuite::Signature,
    credentials::{Credential, CredentialBundle, CredentialError},
};

/// This trait must be implemented by all structs that contain a self-signature.
pub trait SignedStruct<T> {
    /// Build a signed struct version from the payload struct.
    fn from_payload(payload: T, signature: Signature) -> Self;
}

/// This trait must be implemented by all structs that contain a verified
/// self-signature.
pub trait VerifiedStruct<T> {
    /// This type is used to prevent users of the trait from bypassing `verify`
    /// by simply calling `from_verifiable`. `Seal` should be a dummy type
    /// defined in a private module as follows:
    /// ```
    /// mod private_mod {
    ///     pub struct Seal;
    ///
    ///     impl Default for Seal {
    ///         fn default() -> Self {
    ///             Seal {}
    ///         }
    ///     }
    /// }
    /// ```
    type SealingType: Default;

    /// Build a verified struct version from the payload struct. This function
    /// is only meant to be called by the implementation of the `Verifiable`
    /// trait corresponding to this `VerifiedStruct`.
    #[doc(hidden)]
    fn from_verifiable(verifiable: T, _seal: Self::SealingType) -> Self;
}

/// The `Signable` trait is implemented by all struct that are being signed.
/// The implementation has to provide the `unsigned_payload` function.
pub trait Signable: Sized {
    type SignedOutput;

    /// Return the unsigned, serialized payload that should be signed.
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error>;

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
        let signature = credential_bundle.sign(&payload)?;
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
pub trait Verifiable: Sized {
    /// Return the unsigned, serialized payload that should be verified.
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error>;

    /// A reference to the signature to be verified.
    fn signature(&self) -> &Signature;

    /// Verifies the payload against the given `credential`.
    /// The signature is fetched via the [`Verifiable::signature()`] function and
    /// the payload via [`Verifiable::unsigned_payload()`].
    ///
    /// Returns `Ok(Self::VerifiedOutput)` if the signature is valid and
    /// `CredentialError::InvalidSignature` otherwise.
    fn verify<T>(self, credential: &Credential) -> Result<T, CredentialError>
    where
        T: VerifiedStruct<Self>,
    {
        let payload = self.unsigned_payload()?;
        credential.verify(&payload, self.signature())?;
        Ok(T::from_verifiable(self, T::SealingType::default()))
    }

    /// Verifies the payload against the given `credential`.
    /// The signature is fetched via the [`Verifiable::signature()`] function and
    /// the payload via [`Verifiable::unsigned_payload()`].
    ///
    /// Returns `Ok(())` if the signature is valid and
    /// `CredentialError::InvalidSignature` otherwise.
    fn verify_no_out(&self, credential: &Credential) -> Result<(), CredentialError> {
        let payload = self.unsigned_payload()?;
        credential.verify(&payload, self.signature())
    }
}
