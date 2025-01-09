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

use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer};
use thiserror::Error;
use tls_codec::Serialize;

use crate::ciphersuite::{OpenMlsSignaturePublicKey, SignContent, Signature};

/// Signature generation and verification errors.
/// The only information relayed with this error is whether the signature
/// verification or generation failed.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum SignatureError {
    /// Signature verification failed
    #[error("Signature verification failed.")]
    VerificationError,
    /// Signature generation failed
    #[error("Signature generation failed.")]
    SigningError,
}

/// This trait must be implemented by all structs that contain a self-signature.
pub trait SignedStruct<T> {
    /// Build a signed struct version from the payload struct.
    fn from_payload(payload: T, signature: Signature) -> Self;
}

/// The `Signable` trait is implemented by all struct that are being signed.
/// The implementation has to provide the `unsigned_payload` function.
pub trait Signable: Sized {
    /// The type of the object once it's signed.
    type SignedOutput;

    /// Return the unsigned, serialized payload that should be signed.
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error>;

    /// Return the string label used for labeled signing.
    fn label(&self) -> &str;

    /// Sign the payload with the given `private_key`.
    ///
    /// Returns a `Signature`.
    fn sign(self, signer: &impl Signer) -> Result<Self::SignedOutput, SignatureError>
    where
        Self::SignedOutput: SignedStruct<Self>,
    {
        let payload = self
            .unsigned_payload()
            .map_err(|_| SignatureError::SigningError)?;
        let payload = match SignContent::new(self.label(), payload.into()).tls_serialize_detached()
        {
            Ok(p) => p,
            Err(e) => {
                log::error!("Serializing SignContent failed, {:?}", e);
                return Err(SignatureError::SigningError);
            }
        };
        let signature = signer
            .sign(&payload)
            .map_err(|_| SignatureError::SigningError)?;

        Ok(Self::SignedOutput::from_payload(self, signature.into()))
    }
}

/// This marker trait must be implemented by all structs that contain a verified
/// self-signature.
pub trait VerifiedStruct {}

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
    /// The type used for representing the verified data. Must implement the marker trait
    /// [`VerifiedStruct`].
    type VerifiedStruct: VerifiedStruct;

    /// Return the unsigned, serialized payload that should be verified.
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error>;

    /// A reference to the signature to be verified.
    fn signature(&self) -> &Signature;

    /// Return the string label used for labeled verification.
    fn label(&self) -> &str;

    /// Verifies the payload against the given `credential`.
    /// Usually this is implemented by first checking that `self.verify_no_out()`
    /// does not return an error, and then converting the value into
    /// `Self::VerifiedStruct`.
    ///
    /// Returns `Ok(Self::VerifiedOutput)` if the signature is valid and
    /// `CredentialError::InvalidSignature` otherwise.
    fn verify(
        self,
        crypto: &impl OpenMlsCrypto,
        pk: &OpenMlsSignaturePublicKey,
    ) -> Result<Self::VerifiedStruct, SignatureError>;

    /// Verifies the payload against the given public key.
    /// The signature is fetched via the [`Verifiable::signature()`] function and
    /// the payload via [`Verifiable::unsigned_payload()`].
    ///
    /// Returns `Ok(())` if the signature is valid and
    /// [`SignatureError::VerificationError`] otherwise.
    fn verify_no_out(
        &self,
        crypto: &impl OpenMlsCrypto,
        pk: &OpenMlsSignaturePublicKey,
    ) -> Result<(), SignatureError> {
        let payload = self
            .unsigned_payload()
            .map_err(|_| SignatureError::VerificationError)?;
        let sign_content = SignContent::new(self.label(), payload.into());
        let payload = match sign_content.tls_serialize_detached() {
            Ok(p) => p,
            Err(e) => {
                log::error!("Serializing SignContent failed, {:?}", e);
                return Err(SignatureError::VerificationError);
            }
        };
        // https://validation.openmls.tech/#valn1301
        crypto
            .verify_signature(
                pk.signature_scheme(),
                &payload,
                pk.as_slice(),
                self.signature().value(),
            )
            .map_err(|_| SignatureError::VerificationError)
    }
}
