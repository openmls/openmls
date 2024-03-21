use crate::tls_codec::{self, TlsDeserialize, TlsSerialize, TlsSize};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

use crate::ClientKeyPackages;

#[derive(
    Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize, PartialEq, Serialize, Deserialize,
)]
pub struct AuthToken {
    token: Vec<u8>,
}

impl Default for AuthToken {
    fn default() -> Self {
        Self::random()
    }
}

impl AuthToken {
    pub(super) fn random() -> Self {
        let token = thread_rng().gen::<[u8; 32]>().to_vec();
        Self { token }
    }
}

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct RegisterClientRequest {
    pub key_packages: ClientKeyPackages,
}

pub struct RegisterClientErrorResponse {
    pub message: String,
}

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct RegisterClientSuccessResponse {
    pub auth_token: AuthToken,
}

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct PublishKeyPackagesRequest {
    pub key_packages: ClientKeyPackages,
    pub auth_token: AuthToken,
}

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct RecvMessageRequest {
    pub auth_token: AuthToken,
}
