//! Signatures.
//!
//! This module contains structs for creating signature keys, issuing signatures and verifying them.

use super::{LABEL_PREFIX, *};

/// Signature.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct Signature {
    value: VLBytes,
}

/// Labeled signature content.
///
/// ```text
/// struct {
///     opaque label<V> = "MLS 1.0 " + Label;
///     opaque content<V> = Content;
/// } SignContent;
/// ```
#[derive(Debug, Clone, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub struct SignContent {
    label: VLBytes,
    content: VLBytes,
}

/// A public signature key.
#[derive(
    Eq,
    PartialEq,
    Hash,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct SignaturePublicKey {
    pub(in crate::ciphersuite) value: VLBytes,
}

/// A public signature key.
#[derive(Eq, PartialEq, Hash, Debug, Clone, Serialize, Deserialize)]
pub struct OpenMlsSignaturePublicKey {
    signature_scheme: SignatureScheme,
    pub(in crate::ciphersuite) value: VLBytes,
}
