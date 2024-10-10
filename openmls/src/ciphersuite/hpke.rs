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

/// HPKE labeled encryption errors.
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum Error {
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
    label: VLBytes,
    context: VLBytes,
}

impl EncryptContext {
    /// Create a new [`EncryptContext`] from a string label and the content bytes.
    pub fn new(label: &str, context: VLBytes) -> Self {
        let label_string = LABEL_PREFIX.to_owned() + label;
        let label = label_string.as_bytes().into();
        Self { label, context }
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
    let context = context.tls_serialize_detached()?;

    log_crypto!(
        debug,
        "HPKE Encrypt with label `{label}` and ciphersuite `{ciphersuite:?}`:"
    );
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

/// Decrypt with HPKE and label.
pub(crate) fn decrypt_with_label(
    private_key: &[u8],
    label: &str,
    context: &[u8],
    ciphertext: &HpkeCiphertext,
    ciphersuite: Ciphersuite,
    crypto: &impl OpenMlsCrypto,
) -> Result<Vec<u8>, Error> {
    let context: EncryptContext = (label, context).into();
    let context = context.tls_serialize_detached()?;

    log_crypto!(
        debug,
        "HPKE Decrypt with label `{label}` and `ciphersuite` {ciphersuite:?}:"
    );
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
