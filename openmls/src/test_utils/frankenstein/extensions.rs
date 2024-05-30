use tls_codec::*;

use crate::{extensions::{ApplicationIdExtension, Extension, RatchetTreeExtension}, treesync::{node::NodeIn, Node, ParentNode}};

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
        match value {
            Extension::ApplicationId(app_id) => FrankenExtension::ApplicationId(app_id.into()),
            Extension::RatchetTree(ratchet_tree) => {
                FrankenExtension::RatchetTree(ratchet_tree.into())
            }
            Extension::RequiredCapabilities(req_cap) => FrankenExtension::RequiredCapabilities(req_cap.into())
            Extension::ExternalPub(ext_pub) => FrankenExtension::ExternalPub(ext_pub.into()),
            Extension::ExternalSenders(ext_senders) => FrankenExtension::ExternalSenders(ext_senders.into()),
            Extension::LastResort(last_resort) => FrankenExtension::LastResort(last_resort.into()),
            Extension::Unknown(ext_type, data) => FrankenExtension::Unknown(ext_type, data.0.into()),
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenApplicationIdExtension {
    pub key_id: VLBytes,
}

impl From<ApplicationIdExtension> for FrankenApplicationIdExtension {
    fn from(value: ApplicationIdExtension) -> Self {
        FrankenApplicationIdExtension {
            key_id: value.as_slice().to_vec().into(),
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenRatchetTreeExtension {
    pub ratchet_tree: Vec<Option<FrankenNode>>,
}

#[cfg(feature = "test-utils")]
impl From<RatchetTreeExtension> for FrankenRatchetTreeExtension {
    fn from(value: RatchetTreeExtension) -> Self {
        FrankenRatchetTreeExtension {
            ratchet_tree: value.ratchet_tree().nodes().iter().map(|opt_node|{opt_node.map(|node| node.into())}).collect()
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u8)]
pub enum FrankenNode {
    #[tls_codec(discriminant = 1)]
    LeafNode(FrankenLeafNode),
    #[tls_codec(discriminant = 2)]
    ParentNode(FrankenParentNode),
}

impl From<Node> for FrankenNode {
    fn from(value: Node) -> Self {
        match value {
            Node::LeafNode(leaf) => FrankenNode::LeafNode(leaf.into()),
            Node::ParentNode(parent) => FrankenNode::ParentNode(parent.into()),
        }
    }
}

impl From<NodeIn> for FrankenNode {
    fn from(value: NodeIn) -> Self {
        match value {
            NodeIn::LeafNode(leaf) => FrankenNode::LeafNode(leaf.into()),
            NodeIn::ParentNode(parent) => FrankenNode::ParentNode(parent.into()),
        }
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
        FrankenParentNode {
            encryption_key: value.encryption_key().as_slice().to_vec().into(),
            parent_hash: value.parent_hash().to_vec().into(),
            unmerged_leaves: value.unmerged_leaves().iter().map(|idx| idx.u32()).collect(),
        }
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
