use super::*;

/// 7.1 Content Authentication
///
/// opaque MAC<V>;
#[derive(
    Debug, Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
pub(crate) struct Mac {
    pub(crate) mac_value: VLBytes,
}
