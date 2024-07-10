use std::ops::{Deref, DerefMut};

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer, types::Ciphersuite, OpenMlsProvider};
use tls_codec::*;

use super::{extensions::FrankenExtension, key_package::FrankenLifetime, FrankenCredential};
use crate::{
    binary_tree::{array_representation::tree, LeafNodeIndex},
    ciphersuite::{
        signable::{Signable, SignedStruct},
        signature::Signature,
    },
    group::GroupId,
    treesync::{
        node::leaf_node::{LeafNodeIn, LeafNodeTbs, TreePosition},
        LeafNode,
    },
};

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenLeafNode {
    pub payload: FrankenLeafNodePayload,
    pub signature: VLBytes,
}

impl FrankenLeafNode {
    // Re-sign the LeafNode
    pub fn resign(&mut self, tree_position: Option<FrankenTreePosition>, signer: &impl Signer) {
        let tbs = FrankenLeafNodeTbs {
            payload: self.payload.clone(),
            tree_position,
        };
        let new_self = tbs.sign(signer).unwrap();
        let _ = std::mem::replace(self, new_self);
    }
}

impl Deref for FrankenLeafNode {
    type Target = FrankenLeafNodePayload;

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
    fn from_payload(tbs: FrankenLeafNodeTbs, signature: Signature) -> Self {
        Self {
            payload: tbs.payload,
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
pub struct FrankenLeafNodePayload {
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
pub struct FrankenTreePosition {
    pub group_id: VLBytes,
    pub leaf_index: u32,
}

impl From<TreePosition> for FrankenTreePosition {
    fn from(tp: TreePosition) -> Self {
        let (group_id, leaf_index) = tp.into_parts();
        Self {
            group_id: group_id.as_slice().to_owned().into(),
            leaf_index: leaf_index.u32(),
        }
    }
}

impl From<FrankenTreePosition> for TreePosition {
    fn from(ftp: FrankenTreePosition) -> Self {
        Self::new(
            GroupId::from_slice(ftp.group_id.as_slice()),
            LeafNodeIndex::new(ftp.leaf_index),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSize)]
pub struct FrankenLeafNodeTbs {
    pub payload: FrankenLeafNodePayload,
    pub tree_position: Option<FrankenTreePosition>,
}

impl FrankenLeafNodeTbs {
    fn deserialize_without_treeposition<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error> {
        let payload = FrankenLeafNodePayload::tls_deserialize(bytes)?;

        Ok(Self {
            payload,
            tree_position: None,
        })
    }

    fn deserialize_with_treeposition<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error> {
        let payload = FrankenLeafNodePayload::tls_deserialize(bytes)?;
        let tree_position = FrankenTreePosition::tls_deserialize(bytes)?;
        Ok(Self {
            payload,
            tree_position: Some(tree_position),
        })
    }
}

impl Deserialize for FrankenLeafNodeTbs {
    fn tls_deserialize<R: std::io::prelude::Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let payload = FrankenLeafNodePayload::tls_deserialize(bytes)?;
        let tree_position = match payload.leaf_node_source {
            FrankenLeafNodeSource::KeyPackage(_) => None,
            FrankenLeafNodeSource::Update | FrankenLeafNodeSource::Commit(_) => {
                let tree_position = FrankenTreePosition::tls_deserialize(bytes)?;
                Some(tree_position)
            }
        };

        Ok(Self {
            payload,
            tree_position,
        })
    }
}

impl DeserializeBytes for FrankenLeafNodeTbs {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let (payload, rest) = FrankenLeafNodePayload::tls_deserialize_bytes(bytes)?;
        let (tree_position, rest) = match payload.leaf_node_source {
            FrankenLeafNodeSource::KeyPackage(_) => (None, rest),
            FrankenLeafNodeSource::Update | FrankenLeafNodeSource::Commit(_) => {
                let (tree_position, rest) = FrankenTreePosition::tls_deserialize_bytes(bytes)?;
                (Some(tree_position), rest)
            }
        };

        Ok((
            Self {
                payload,
                tree_position,
            },
            rest,
        ))
    }
}

impl Serialize for FrankenLeafNodeTbs {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut written = self.payload.tls_serialize(writer)?;

        if let Some(tree_info) = &self.tree_position {
            written += tree_info.tls_serialize(writer)?
        };

        Ok(written)
    }
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
