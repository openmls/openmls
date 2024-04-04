use tls_codec::SecretVLBytes;
use tls_codec::VLBytes;

#[derive(Hash, Debug, PartialEq, Eq, Clone)]
pub struct HpkePublicKey(pub(super) VLBytes);

// TODO: zeroize
#[derive(PartialEq, Eq)]
pub struct HpkePrivateKey(pub(super) SecretVLBytes);

pub struct HpkeKeyPair {
    pub(super) private: HpkePrivateKey,
    pub(super) public: HpkePublicKey,
}
