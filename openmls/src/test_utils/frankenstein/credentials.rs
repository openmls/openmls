use tls_codec::*;

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenCredential {
    credential_type: u16,
    serialized_credential_content: VLBytes,
}
