use crate::VLBytes;
use serde::{Deserialize, Serialize};
use tls_codec::SecretVLBytes;

pub type HpkePublicKey = VLBytes;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkePrivateKey(pub SecretVLBytes);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeKeyPair {
    pub private: HpkePrivateKey,
    pub public: HpkePublicKey,
}
