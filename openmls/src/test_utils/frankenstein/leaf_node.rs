use std::ops::{Deref, DerefMut};

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer, types::Ciphersuite, OpenMlsProvider};
use tls_codec::*;

use super::key_package::{FrankenExtension, FrankenLifetime};
use crate::{
    ciphersuite::{
        signable::{Signable, SignedStruct},
        signature::Signature,
    },
    treesync::{node::leaf_node::LeafNodeIn, LeafNode},
};

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenLeafNode {
    pub payload: FrankenLeafNodeTbs,
    pub signature: VLBytes,
}

impl FrankenLeafNode {
    // Re-sign the LeafNode
    pub fn resign(&mut self, signer: &impl Signer) {
        let new_self = self.payload.clone().sign(signer).unwrap();
        let _ = std::mem::replace(self, new_self);
    }
}

impl Deref for FrankenLeafNode {
    type Target = FrankenLeafNodeTbs;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl DerefMut for FrankenLeafNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.payload
    }
}

impl SignedStruct<FrankenLeafNodeTbs> for FrankenLeafNode {
    fn from_payload(payload: FrankenLeafNodeTbs, signature: Signature) -> Self {
        Self {
            payload,
            signature: signature.as_slice().to_owned().into(),
        }
    }
}

const LEAF_NODE_SIGNATURE_LABEL: &str = "LeafNodeTBS";

impl Signable for FrankenLeafNodeTbs {
    type SignedOutput = FrankenLeafNode;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        LEAF_NODE_SIGNATURE_LABEL
    }
}

impl From<LeafNode> for FrankenLeafNode {
    fn from(ln: LeafNode) -> Self {
        FrankenLeafNode::tls_deserialize(&mut ln.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
    }
}

impl From<FrankenLeafNode> for LeafNode {
    fn from(fln: FrankenLeafNode) -> Self {
        LeafNodeIn::tls_deserialize(&mut fln.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
            .into()
    }
}

impl From<FrankenLeafNode> for LeafNodeIn {
    fn from(fln: FrankenLeafNode) -> Self {
        LeafNodeIn::tls_deserialize(&mut fln.tls_serialize_detached().unwrap().as_slice()).unwrap()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenLeafNodeTbs {
    pub encryption_key: VLBytes,
    pub signature_key: VLBytes,
    pub credential: FrankenCredential,
    pub capabilities: FrankenCapabilities,
    pub leaf_node_source: FrankenLeafNodeSource,
    pub extensions: Vec<FrankenExtension>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenCredential {
    pub credential_type: u16,
    pub serialized_credential_content: VLBytes,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenCapabilities {
    pub versions: Vec<u16>,
    pub ciphersuites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub proposals: Vec<u16>,
    pub credentials: Vec<u16>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u8)]
pub enum FrankenLeafNodeSource {
    #[tls_codec(discriminant = 1)]
    KeyPackage(FrankenLifetime),
    Update,
    Commit(VLBytes),
}
