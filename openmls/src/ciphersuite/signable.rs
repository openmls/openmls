//! This module defines traits used for signing and verifying
//! structs from the MLS protocol spec.
//!
//! # Type-Enforced Verification
//!
//! This module contains four traits, each describing the property they enable
//! upon implementation: [`Signable`], [`SignedStruct`], [`Verifiable`] and
//! [`VerifiedStruct`].
//!
//! Each trait represents the state of a struct in a sender-receiver flow with
//! the following transitions.
//!
//! * the signer creates an instance of a struct that implements [`Signable`]
//! * the signer signs it, consuming the [`Signable`] struct and producing a [`SignedStruct`]
//! * the signer serializes the struct and sends it to the verifier
//! * the verifier deserializes the byte-string into a struct implementing [`Verifiable`]
//! * the verifier verifies the struct, consuming the [`Verifiable`] struct and producing a [`VerifiedStruct`]
//!
//! Using this process, we can ensure that only structs implementing
//! [`SignedStruct`] are sent over the wire and only structs implementing
//! [`VerifiedStruct`] are used on the verifier side as input for further
//! processing functions.
//!
//! For the type-safety to work, it is important that [`Signable`] and
//! [`SignedStruct`] are implemented by distinct structs. The same goes for
//! [`Verifiable`] and [`VerifiedStruct`]. In addition, only the
//! [`SignedStruct`] should implement the [`tls_codec::Serialize`] trait.
//! Similarly, only the [`Verifiable`] struct should implement the
//! [`tls_codec::Deserialize`] trait.

use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    ciphersuite::Signature,
    credentials::{errors::CredentialError, Credential, CredentialBundle},
    error::LibraryError,
};

use super::SignaturePublicKey;

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
    /// The type of the object once it's signed.
    type SignedOutput;

    /// Return the unsigned, serialized payload that should be signed.
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error>;

    /// Sign the payload with the given `id`.
    ///
    /// Returns a `Signature`.
    fn sign(
        self,
        backend: &impl OpenMlsCryptoProvider,
        credential_bundle: &CredentialBundle,
    ) -> Result<Self::SignedOutput, LibraryError>
    where
        Self::SignedOutput: SignedStruct<Self>,
    {
        let payload = self
            .unsigned_payload()
            .map_err(LibraryError::missing_bound_check)?;
        let signature = credential_bundle
            .sign(backend, &payload)
            .map_err(LibraryError::unexpected_crypto_error)?;
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
    fn verify<T>(
        self,
        backend: &impl OpenMlsCryptoProvider,
        credential: &Credential,
    ) -> Result<T, CredentialError>
    where
        T: VerifiedStruct<Self>,
    {
        let payload = self
            .unsigned_payload()
            .map_err(LibraryError::missing_bound_check)?;
        credential.verify(backend, &payload, self.signature())?;
        Ok(T::from_verifiable(self, T::SealingType::default()))
    }

    /// Verifies the payload against the given `SignatureKey`.
    /// The signature is fetched via the [`Verifiable::signature()`] function and
    /// the payload via [`Verifiable::unsigned_payload()`].
    ///
    /// Returns `Ok(Self::VerifiedOutput)` if the signature is valid and
    /// `CredentialError::InvalidSignature` otherwise.
    fn verify_with_key<T>(
        self,
        backend: &impl OpenMlsCryptoProvider,
        signature_public_key: &SignaturePublicKey,
    ) -> Result<T, CredentialError>
    where
        T: VerifiedStruct<Self>,
    {
        let payload = self
            .unsigned_payload()
            .map_err(LibraryError::missing_bound_check)?;
        signature_public_key
            .verify(backend, self.signature(), &payload)
            .map_err(|_| CredentialError::InvalidSignature)?;
        Ok(T::from_verifiable(self, T::SealingType::default()))
    }

    /// Verifies the payload against the given `credential`.
    /// The signature is fetched via the [`Verifiable::signature()`] function and
    /// the payload via [`Verifiable::unsigned_payload()`].
    ///
    /// Returns `Ok(())` if the signature is valid and
    /// `CredentialError::InvalidSignature` otherwise.
    fn verify_no_out(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        credential: &Credential,
    ) -> Result<(), CredentialError> {
        let payload = self
            .unsigned_payload()
            .map_err(LibraryError::missing_bound_check)?;
        credential.verify(backend, &payload, self.signature())
    }
}
