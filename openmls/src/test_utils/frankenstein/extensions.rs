use tls_codec::*;

use crate::{
    extensions::{
        ApplicationIdExtension, Extension, RatchetTreeExtension, RequiredCapabilitiesExtension,
    },
    treesync::{node::NodeIn, Node, ParentNode},
};

use super::{FrankenCredential, FrankenLeafNode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrankenExtensionType {
    ApplicationId,
    RatchetTree,
    RequiredCapabilities,
    ExternalPub,
    ExternalSenders,
    LastResort,
    Unknown(u16),
}

impl From<u16> for FrankenExtensionType {
    fn from(a: u16) -> Self {
        match a {
            1 => FrankenExtensionType::ApplicationId,
            2 => FrankenExtensionType::RatchetTree,
            3 => FrankenExtensionType::RequiredCapabilities,
            4 => FrankenExtensionType::ExternalPub,
            5 => FrankenExtensionType::ExternalSenders,
            10 => FrankenExtensionType::LastResort,
            unknown => FrankenExtensionType::Unknown(unknown),
        }
    }
}

impl From<FrankenExtensionType> for u16 {
    fn from(value: FrankenExtensionType) -> Self {
        match value {
            FrankenExtensionType::ApplicationId => 1,
            FrankenExtensionType::RatchetTree => 2,
            FrankenExtensionType::RequiredCapabilities => 3,
            FrankenExtensionType::ExternalPub => 4,
            FrankenExtensionType::ExternalSenders => 5,
            FrankenExtensionType::LastResort => 10,
            FrankenExtensionType::Unknown(unknown) => unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum FrankenExtension {
    ApplicationId(FrankenApplicationIdExtension),
    RatchetTree(FrankenRatchetTreeExtension),
    RequiredCapabilities(FrankenRequiredCapabilitiesExtension),
    ExternalPub(FrankenExternalPubExtension),
    ExternalSenders(FrankenExternalSendersExtension),
    LastResort,
    Unknown(u16, VLBytes),
}

impl FrankenExtension {
    pub const fn extension_type(&self) -> FrankenExtensionType {
        match self {
            FrankenExtension::ApplicationId(_) => FrankenExtensionType::ApplicationId,
            FrankenExtension::RatchetTree(_) => FrankenExtensionType::RatchetTree,
            FrankenExtension::RequiredCapabilities(_) => FrankenExtensionType::RequiredCapabilities,
            FrankenExtension::ExternalPub(_) => FrankenExtensionType::ExternalPub,
            FrankenExtension::ExternalSenders(_) => FrankenExtensionType::ExternalSenders,
            FrankenExtension::LastResort => FrankenExtensionType::LastResort,
            FrankenExtension::Unknown(kind, _) => FrankenExtensionType::Unknown(*kind),
        }
    }
}

impl From<Extension> for FrankenExtension {
    fn from(value: Extension) -> Self {
        let bytes = value.tls_serialize_detached().unwrap();
        FrankenExtension::tls_deserialize(&mut bytes.as_slice()).unwrap()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenApplicationIdExtension {
    pub key_id: VLBytes,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenRatchetTreeExtension {
    pub ratchet_tree: Vec<Option<FrankenNode>>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum FrankenNode {
    #[tls_codec(discriminant = 1)]
    LeafNode(FrankenLeafNode),
    #[tls_codec(discriminant = 2)]
    ParentNode(FrankenParentNode),
}

impl From<Node> for FrankenNode {
    fn from(value: Node) -> Self {
        let bytes = value.tls_serialize_detached().unwrap();
        FrankenNode::tls_deserialize(&mut bytes.as_slice()).unwrap()
    }
}

impl From<NodeIn> for FrankenNode {
    fn from(value: NodeIn) -> Self {
        let bytes = value.tls_serialize_detached().unwrap();
        FrankenNode::tls_deserialize(&mut bytes.as_slice()).unwrap()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenParentNode {
    pub encryption_key: VLBytes,
    pub parent_hash: VLBytes,
    pub unmerged_leaves: Vec<u32>,
}

impl From<ParentNode> for FrankenParentNode {
    fn from(value: ParentNode) -> Self {
        let bytes = value.tls_serialize_detached().unwrap();
        Self::tls_deserialize(&mut bytes.as_slice()).unwrap()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenRequiredCapabilitiesExtension {
    pub extension_types: Vec<u16>,
    pub proposal_types: Vec<u16>,
    pub credential_types: Vec<u16>,
}

impl From<RequiredCapabilitiesExtension> for FrankenRequiredCapabilitiesExtension {
    fn from(value: RequiredCapabilitiesExtension) -> Self {
        let bytes = value.tls_serialize_detached().unwrap();
        Self::tls_deserialize(&mut bytes.as_slice()).unwrap()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenExternalPubExtension {
    external_pub: VLBytes,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenExternalSendersExtension {
    external_senders: Vec<FrankenExternalSender>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenExternalSender {
    pub signature_key: VLBytes,
    pub credential: FrankenCredential,
}
