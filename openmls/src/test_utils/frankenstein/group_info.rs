use std::ops::{Deref, DerefMut};

use tls_codec::*;

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer, types::Ciphersuite, OpenMlsProvider};

use crate::{
    ciphersuite::{
        signable::{Signable, SignedStruct},
        signature::{OpenMlsSignaturePublicKey, Signature},
    },
    group::GroupContext,
    messages::group_info::GroupInfo,
};

use super::extensions::FrankenExtension;

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenGroupInfo {
    pub payload: FrankenGroupInfoTbs,
    pub signature: VLBytes,
}

impl FrankenGroupInfo {
    // Re-sign both the KeyPackage and the enclosed LeafNode
    pub fn resign(&mut self, signer: &impl Signer) {
        let new_self = self.payload.clone().sign(signer).unwrap();
        let _ = std::mem::replace(self, new_self);
    }
}

impl Deref for FrankenGroupInfo {
    type Target = FrankenGroupInfoTbs;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl DerefMut for FrankenGroupInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.payload
    }
}

impl SignedStruct<FrankenGroupInfoTbs> for FrankenGroupInfo {
    fn from_payload(payload: FrankenGroupInfoTbs, signature: Signature) -> Self {
        Self {
            payload,
            signature: signature.as_slice().to_owned().into(),
        }
    }
}

const SIGNATURE_GROUP_INFO_LABEL: &str = "GroupInfoTBS";

impl Signable for FrankenGroupInfoTbs {
    type SignedOutput = FrankenGroupInfo;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        SIGNATURE_GROUP_INFO_LABEL
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenGroupInfoTbs {
    pub group_context: FrankenGroupContext,
    pub extensions: Vec<FrankenExtension>,
    pub confirmation_tag: VLBytes,
    pub signer: u32,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenGroupContext {
    protocol_version: u16,
    ciphersuite: u16,
    group_id: VLBytes,
    epoch: u64,
    tree_hash: VLBytes,
    confirmed_transcript_hash: VLBytes,
    extensions: Vec<FrankenExtension>,
}

impl From<GroupContext> for FrankenGroupContext {
    fn from(value: GroupContext) -> Self {
        let extensions = value
            .extensions()
            .iter()
            .map(|ext| ext.clone().into())
            .collect();
        FrankenGroupContext {
            protocol_version: match value.protocol_version() {
                crate::versions::ProtocolVersion::Mls10 => 1,
                crate::versions::ProtocolVersion::Other(other) => other,
            },
            ciphersuite: value.ciphersuite().into(),
            group_id: value.group_id().as_slice().to_vec().into(),
            epoch: value.epoch().as_u64(),
            tree_hash: value.tree_hash().to_vec().into(),
            confirmed_transcript_hash: value.confirmed_transcript_hash().to_vec().into(),
            extensions,
        }
    }
}

impl From<GroupInfo> for FrankenGroupInfo {
    fn from(ln: GroupInfo) -> Self {
        FrankenGroupInfo::tls_deserialize(&mut ln.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
    }
}

impl From<FrankenGroupInfo> for GroupInfo {
    fn from(fln: FrankenGroupInfo) -> Self {
        GroupInfo::tls_deserialize(&mut fln.tls_serialize_detached().unwrap().as_slice()).unwrap()
    }
}
