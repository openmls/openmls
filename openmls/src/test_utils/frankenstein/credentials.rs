use tls_codec::*;

use crate::credentials::Credential;

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenCredential {
    credential_type: u16,
    serialized_credential_content: VLBytes,
}

impl From<Credential> for FrankenCredential {
    fn from(value: Credential) -> Self {
        FrankenCredential {
            credential_type: value.credential_type().into(),
            serialized_credential_content: value.serialized_content().to_owned().into(),
        }
    }
}
