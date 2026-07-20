use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

use super::{Deserialize, Serialize};

/// # Application Identifiers
///
/// Within MLS, a KeyPackage is identified by its hash ([`KeyPackageRef`](`crate::ciphersuite::hash_ref::KeyPackageRef`)).
/// The application id extension allows applications to add an explicit,
/// application-defined identifier to a KeyPackage.
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct ApplicationIdExtension {
    key_id: VLBytes,
}
