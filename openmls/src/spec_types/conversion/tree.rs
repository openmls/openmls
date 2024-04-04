use crate::{messages::group_info, spec_types as private_types};
use openmls_spec_types as public_types;

impl private_types::tree::RatchetTree {
    pub(in crate::spec_types) fn from_public(
        ratchet_tree: public_types::tree::RatchetTree,
    ) -> Self {
        Self(
            ratchet_tree
                .0
                .into_iter()
                .map(|opt_node| opt_node.map(|node| private_types::tree::Node::from_public(node)))
                .collect(),
        )
    }
}

impl private_types::tree::Node {
    pub(in crate::spec_types) fn from_public(node: public_types::tree::Node) -> Self {
        match node {
            public_types::tree::Node::LeafNode(leaf_node) => {
                Self::LeafNode(private_types::tree::LeafNode::from_public(leaf_node))
            }
            public_types::tree::Node::ParentNode(parent_node) => {
                Self::ParentNode(private_types::tree::ParentNode::from_public(parent_node))
            }
        }
    }
}

impl private_types::tree::LeafNodeIndex {
    pub(in crate::spec_types) fn from_public(
        leaf_node_index: public_types::tree::LeafNodeIndex,
    ) -> Self {
        Self(leaf_node_index.0)
    }
}

impl private_types::tree::UnmergedLeaves {
    pub(in crate::spec_types) fn from_public(
        unmerged_leaves: public_types::tree::UnmergedLeaves,
    ) -> Self {
        Self {
            list: unmerged_leaves
                .list
                .into_iter()
                .map(|leaf_node_index| {
                    private_types::tree::LeafNodeIndex::from_public(leaf_node_index)
                })
                .collect(),
        }
    }
}

impl private_types::tree::ParentNode {
    pub(in crate::spec_types) fn from_public(parent_node: public_types::tree::ParentNode) -> Self {
        Self {
            encryption_key: private_types::keys::EncryptionKey::from_public(
                parent_node.encryption_key,
            ),
            parent_hash: parent_node.parent_hash.into(),
            unmerged_leaves: private_types::tree::UnmergedLeaves::from_public(
                parent_node.unmerged_leaves,
            ),
        }
    }
}

impl private_types::tree::LeafNode {
    pub(in crate::spec_types) fn from_public(leaf_node: public_types::tree::LeafNode) -> Self {
        Self {
            payload: private_types::tree::LeafNodePayload::from_public(leaf_node.payload),
            signature: private_types::Signature::from_public(leaf_node.signature),
        }
    }
}

impl private_types::tree::LeafNodePayload {
    pub(in crate::spec_types) fn from_public(payload: public_types::tree::LeafNodePayload) -> Self {
        Self {
            encryption_key: private_types::keys::EncryptionKey::from_public(payload.encryption_key),
            signature_key: private_types::keys::SignaturePublicKey::from_public(
                payload.signature_key,
            ),
            credential: private_types::credential::Credential::from_public(payload.credential),
            capabilities: private_types::tree::Capabilities::from_public(payload.capabilities),
            leaf_node_source: private_types::tree::LeafNodeSource::from_public(
                payload.leaf_node_source,
            ),
            extensions: private_types::extensions::Extensions::from_public(payload.extensions),
        }
    }
}

impl private_types::tree::LeafNodeSource {
    pub(in crate::spec_types) fn from_public(source: public_types::tree::LeafNodeSource) -> Self {
        match source {
            public_types::tree::LeafNodeSource::KeyPackage(lifetime) => {
                Self::KeyPackage(private_types::Lifetime::from_public(lifetime))
            }
            public_types::tree::LeafNodeSource::Update => Self::Update,
            public_types::tree::LeafNodeSource::Commit(parent_hash) => {
                Self::Commit(parent_hash.into())
            }
        }
    }
}

impl private_types::tree::Capabilities {
    pub(in crate::spec_types) fn from_public(
        capabilities: public_types::tree::Capabilities,
    ) -> Self {
        Self {
            versions: capabilities
                .versions
                .into_iter()
                .map(private_types::ProtocolVersion::from_public)
                .collect(),
            ciphersuites: capabilities
                .ciphersuites
                .into_iter()
                .map(private_types::Ciphersuite::from_public)
                .collect(),
            extensions: capabilities
                .extensions
                .into_iter()
                .map(private_types::extensions::ExtensionType::from_public)
                .collect(),
            proposals: capabilities
                .proposals
                .into_iter()
                .map(private_types::proposals::ProposalType::from_public)
                .collect(),
            credentials: capabilities
                .credentials
                .into_iter()
                .map(private_types::credential::CredentialType::from_public)
                .collect(),
        }
    }
}
