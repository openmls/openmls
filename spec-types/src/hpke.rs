use serde::{Deserialize, Serialize};
use tls_codec::{
    SecretVLBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes,
};

#[derive(
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct HpkePublicKey(pub VLBytes);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkePrivateKey(pub SecretVLBytes);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeKeyPair {
    pub private: HpkePrivateKey,
    pub public: HpkePublicKey,
}
