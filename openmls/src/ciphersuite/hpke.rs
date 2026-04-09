//! ### Public-Key Encryption
//!
//! As with signing, MLS includes a label and context in encryption operations to
//! avoid confusion between ciphertexts produced for different purposes.  Encryption
//! and decryption including this label and context are done as follows:
//!
//! ```text
//! EncryptWithLabel(PublicKey, Label, Context, Plaintext) =
//!   SealBase(PublicKey, EncryptContext, "", Plaintext)
//!
//! DecryptWithLabel(PrivateKey, Label, Context, KEMOutput, Ciphertext) =
//!   OpenBase(KEMOutput, PrivateKey, EncryptContext, "", Ciphertext)
//! ```
//!
//! Where EncryptContext is specified as:
//!
//! ```text
//! struct {
//!   opaque label<V>;
//!   opaque context<V>;
//! } EncryptContext;
//! ```
//!
//! And its fields set to:
//!
//! ```text
//! label = "MLS 1.0 " + Label;
//! context = Context;
//! ```
//!
//! Here, the functions `SealBase` and `OpenBase` are defined RFC9180, using the
//! HPKE algorithms specified by the group's ciphersuite.  If MLS extensions
//! require HPKE encryption operations, they should re-use the EncryptWithLabel
//! construction, using a distinct label.  To avoid collisions in these labels, an
//! IANA registry is defined in mls-public-key-encryption-labels.

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, CryptoError, HpkeCiphertext},
};
use thiserror::Error;
use tls_codec::{Serialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

use super::LABEL_PREFIX;

#[cfg(feature = "extensions-draft-08")]
use crate::component::{ComponentId, ComponentOperationLabel};

/// HPKE labeled encryption errors.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum Error {
    /// Error while serializing content. This should only happen if a bounds check was missing.
    #[error(
        "Error while serializing content. This should only happen if a bounds check was missing."
    )]
    MissingBoundCheck,

    /// Decryption failed.
    #[error("Decryption failed.")]
    DecryptionFailed,
}

impl From<tls_codec::Error> for Error {
    fn from(_: tls_codec::Error) -> Self {
        Self::MissingBoundCheck
    }
}

impl From<CryptoError> for Error {
    fn from(_: CryptoError) -> Self {
        Self::DecryptionFailed
    }
}

/// Context for HPKE encryption
#[derive(Debug, Clone, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub struct EncryptContext {
    /// Prefixed with LABEL_PREFIX
    label: VLBytes,
    context: VLBytes,
}

impl EncryptContext {
    /// Create a new [`EncryptContext`] from a string label and the content bytes.
    /// Ensures that the prefix LABEL_PREFIX is prepended to the label.
    pub(crate) fn new(label: &str, context: VLBytes) -> Self {
        let label_string = LABEL_PREFIX.to_owned() + label;
        let label = label_string.as_bytes().into();
        Self { label, context }
    }

    #[cfg(feature = "extensions-draft-08")]
    pub(crate) fn new_from_component_operation_label(
        label: ComponentOperationLabel,
        context: VLBytes,
    ) -> Result<Self, Error> {
        let serialized_label = label.tls_serialize_detached()?;

        // Prefix the serialized label with the LABEL_PREFIX bytes
        // Note that the spec isn't precise here. There are different ways to
        // combine these. https://github.com/mlswg/mls-extensions/issues/79
        let mut label = LABEL_PREFIX.as_bytes().to_vec();
        label.extend(serialized_label);

        Ok(Self {
            label: label.into(),
            context,
        })
    }
}

impl From<(&str, &[u8])> for EncryptContext {
    fn from((label, context): (&str, &[u8])) -> Self {
        Self::new(label, context.into())
    }
}

/// Encrypt to an HPKE key with a label.
pub(crate) fn encrypt_with_label(
    public_key: &[u8],
    label: &str,
    context: &[u8],
    plaintext: &[u8],
    ciphersuite: Ciphersuite,
    crypto: &impl OpenMlsCrypto,
) -> Result<HpkeCiphertext, Error> {
    let context: EncryptContext = (label, context).into();

    log_crypto!(
        debug,
        "HPKE Encrypt with label `{label}` and ciphersuite `{ciphersuite:?}`:"
    );

    encrypt_with_label_internal(public_key, context, plaintext, ciphersuite, crypto)
}

fn encrypt_with_label_internal(
    public_key: &[u8],
    context: EncryptContext,
    plaintext: &[u8],
    ciphersuite: Ciphersuite,
    crypto: &impl OpenMlsCrypto,
) -> Result<HpkeCiphertext, Error> {
    let context = context.tls_serialize_detached()?;

    log_crypto!(debug, "* context:     {context:x?}");
    log_crypto!(debug, "* public key:  {public_key:x?}");
    log_crypto!(debug, "* plaintext:   {plaintext:x?}");

    let cipher = crypto.hpke_seal(
        ciphersuite.hpke_config(),
        public_key,
        &context,
        &[],
        plaintext,
    )?;

    log_crypto!(debug, "* ciphertext:  {:x?}", cipher);

    Ok(cipher)
}

/// Context for [`safe_encrypt_with_label`] and [`safe_decrypt_with_label`].
#[cfg(feature = "extensions-draft-08")]
pub struct SafeEncryptionContext<'a> {
    /// The [`ComponentId`] to use.
    pub component_id: ComponentId,

    /// A label
    pub label: &'a str,

    /// An optional context.
    pub context: &'a [u8],
}

/// Encrypt the provided `plaintext` for the `public_key`.
/// The [`SafeEncryptionContext`] is used to set the [`ComponentId`], `label`,
/// and optional `context`.
///
/// Returns an [`HpkeCiphertext`] or an [`enum@Error`].
#[cfg(feature = "extensions-draft-08")]
pub fn safe_encrypt_with_label(
    public_key: &[u8],
    plaintext: &[u8],
    ciphersuite: Ciphersuite,
    context: SafeEncryptionContext,
    crypto: &impl OpenMlsCrypto,
) -> Result<HpkeCiphertext, Error> {
    let component_operation_label =
        ComponentOperationLabel::new(context.component_id, context.label);

    let context = EncryptContext::new_from_component_operation_label(
        component_operation_label,
        context.context.into(),
    )?;

    encrypt_with_label_internal(public_key, context, plaintext, ciphersuite, crypto)
}

/// Decrypt with HPKE and label.
pub(crate) fn decrypt_with_label(
    private_key: &[u8],
    label: &str,
    context: &[u8],
    ciphertext: &HpkeCiphertext,
    ciphersuite: Ciphersuite,
    crypto: &impl OpenMlsCrypto,
) -> Result<Vec<u8>, Error> {
    log_crypto!(
        debug,
        "HPKE Decrypt with label `{label}` and `ciphersuite` {ciphersuite:?}:"
    );

    let context: EncryptContext = (label, context).into();

    decrypt_with_label_internal(private_key, context, ciphertext, ciphersuite, crypto)
}

fn decrypt_with_label_internal(
    private_key: &[u8],
    context: EncryptContext,
    ciphertext: &HpkeCiphertext,
    ciphersuite: Ciphersuite,
    crypto: &impl OpenMlsCrypto,
) -> Result<Vec<u8>, Error> {
    let context = context.tls_serialize_detached()?;

    log_crypto!(debug, "* context:     {context:x?}");
    log_crypto!(debug, "* private key: {private_key:x?}");
    log_crypto!(debug, "* ciphertext:  {ciphertext:x?}");

    let plaintext = crypto
        .hpke_open(
            ciphersuite.hpke_config(),
            ciphertext,
            private_key,
            &context,
            &[],
        )
        .map_err(|e| e.into());

    log_crypto!(debug, "* plaintext:   {plaintext:x?}");

    plaintext
}

#[cfg(feature = "extensions-draft-08")]
/// Decrypt the provided `ciphertext` with the `private_key`.
/// The [`SafeEncryptionContext`] is used to set the [`ComponentId`], `label`,
/// and optional `context`.
///
/// Returns an [`HpkeCiphertext`] or an [`enum@Error`].
pub fn safe_decrypt_with_label(
    private_key: &[u8],
    ciphertext: &HpkeCiphertext,
    ciphersuite: Ciphersuite,
    context: SafeEncryptionContext,
    crypto: &impl OpenMlsCrypto,
) -> Result<Vec<u8>, Error> {
    let component_operation_label =
        ComponentOperationLabel::new(context.component_id, context.label);

    let context: EncryptContext = EncryptContext::new_from_component_operation_label(
        component_operation_label,
        context.context.into(),
    )?;

    decrypt_with_label_internal(private_key, context, ciphertext, ciphersuite, crypto)
}
