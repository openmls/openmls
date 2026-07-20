use openmls_traits::types::VerifiableCiphersuite;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

#[cfg(doc)]
use super::LeafNode;
use crate::{
    credentials::CredentialType,
    extensions::ExtensionType,
    messages::proposals::ProposalType,
    versions::ProtocolVersion,
};

/// Capabilities of [`LeafNode`]s.
///
/// ```text
/// struct {
///     ProtocolVersion versions<V>;
///     CipherSuite ciphersuites<V>;
///     ExtensionType extensions<V>;
///     ProposalType proposals<V>;
///     CredentialType credentials<V>;
/// } Capabilities;
/// ```
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct Capabilities {
    pub(super) versions: Vec<ProtocolVersion>,
    pub(super) ciphersuites: Vec<VerifiableCiphersuite>,
    pub(super) extensions: Vec<ExtensionType>,
    pub(super) proposals: Vec<ProposalType>,
    pub(super) credentials: Vec<CredentialType>,
}
