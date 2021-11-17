use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{TlsByteVecU8, TlsVecU32};

use super::TreeSyncNodeError;

use crate::{
    binary_tree::LeafIndex,
    ciphersuite::{Ciphersuite, HpkePrivateKey, HpkePublicKey},
    prelude::KeyPackage,
    treesync::hashes::ParentHashInput,
};

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct LeafNode {
    key_package: KeyPackage,
    private_key_option: Option<HpkePrivateKey>,
}

impl tls_codec::Deserialize for LeafNode {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let key_package = KeyPackage::tls_deserialize(bytes)?;
        Ok(Self {
            key_package,
            private_key_option: None,
        })
    }
}

impl tls_codec::Size for LeafNode {
    fn tls_serialized_len(&self) -> usize {
        self.key_package.tls_serialized_len()
    }
}
impl tls_codec::Size for &LeafNode {
    fn tls_serialized_len(&self) -> usize {
        self.key_package.tls_serialized_len()
    }
}

impl tls_codec::Serialize for &LeafNode {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.key_package.tls_serialize(writer)
    }
}

impl LeafNode {
    pub(crate) fn public_key(&self) -> &HpkePublicKey {
        &self.key_package.hpke_init_key()
    }

    pub(crate) fn private_key(&self) -> &Option<HpkePrivateKey> {
        &self.private_key_option
    }

    pub(crate) fn set_private_key(&mut self, private_key: HpkePrivateKey) {
        self.private_key_option = Some(private_key)
    }

    pub(crate) fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }
}

impl From<KeyPackage> for LeafNode {
    fn from(key_package: KeyPackage) -> Self {
        LeafNode {
            key_package,
            private_key_option: None,
        }
    }
}
