use crate::spec_types as private_types;
use crate::spec_types::conversion::unchecked::PrivateSpecType;
use openmls_spec_types as public_types;

impl PrivateSpecType for private_types::tree::RatchetTree {
    type Public = public_types::tree::RatchetTree;
    fn from_public_unchecked(ratchet_tree: public_types::tree::RatchetTree) -> Self {
        Self(
            ratchet_tree
                .0
                .into_iter()
                .map(|opt_node| {
                    opt_node.map(|node| private_types::tree::Node::from_public_unchecked(node))
                })
                .collect(),
        )
    }
}

impl PrivateSpecType for private_types::tree::Node {
    type Public = public_types::tree::Node;
    fn from_public_unchecked(node: public_types::tree::Node) -> Self {
        match node {
            public_types::tree::Node::LeafNode(leaf_node) => Self::LeafNode(
                private_types::tree::LeafNode::from_public_unchecked(leaf_node),
            ),
            public_types::tree::Node::ParentNode(parent_node) => Self::ParentNode(
                private_types::tree::ParentNode::from_public_unchecked(parent_node),
            ),
        }
    }
}

impl PrivateSpecType for private_types::tree::LeafNodeIndex {
    type Public = public_types::tree::LeafNodeIndex;
    fn from_public_unchecked(leaf_node_index: public_types::tree::LeafNodeIndex) -> Self {
        Self(leaf_node_index.0)
    }
}

impl PrivateSpecType for private_types::tree::UnmergedLeaves {
    type Public = public_types::tree::UnmergedLeaves;
    fn from_public_unchecked(unmerged_leaves: public_types::tree::UnmergedLeaves) -> Self {
        Self {
            list: unmerged_leaves
                .list
                .into_iter()
                .map(|leaf_node_index| {
                    private_types::tree::LeafNodeIndex::from_public_unchecked(leaf_node_index)
                })
                .collect(),
        }
    }
}

impl PrivateSpecType for private_types::tree::ParentNode {
    type Public = public_types::tree::ParentNode;
    fn from_public_unchecked(parent_node: public_types::tree::ParentNode) -> Self {
        Self {
            encryption_key: private_types::keys::EncryptionKey::from_public_unchecked(
                parent_node.encryption_key,
            ),
            parent_hash: parent_node.parent_hash.into(),
            unmerged_leaves: private_types::tree::UnmergedLeaves::from_public_unchecked(
                parent_node.unmerged_leaves,
            ),
        }
    }
}

impl PrivateSpecType for private_types::tree::LeafNode {
    type Public = public_types::tree::LeafNode;
    fn from_public_unchecked(leaf_node: public_types::tree::LeafNode) -> Self {
        Self {
            payload: private_types::tree::LeafNodePayload::from_public_unchecked(leaf_node.payload),
            signature: private_types::Signature::from_public_unchecked(leaf_node.signature),
        }
    }
}

impl PrivateSpecType for private_types::tree::LeafNodePayload {
    type Public = public_types::tree::LeafNodePayload;
    fn from_public_unchecked(payload: public_types::tree::LeafNodePayload) -> Self {
        Self {
            encryption_key: private_types::keys::EncryptionKey::from_public_unchecked(
                payload.encryption_key,
            ),
            signature_key: private_types::keys::SignaturePublicKey::from_public_unchecked(
                payload.signature_key,
            ),
            credential: private_types::credential::Credential::from_public_unchecked(
                payload.credential,
            ),
            capabilities: private_types::tree::Capabilities::from_public_unchecked(
                payload.capabilities,
            ),
            leaf_node_source: private_types::tree::LeafNodeSource::from_public_unchecked(
                payload.leaf_node_source,
            ),
            extensions: private_types::extensions::Extensions::from_public_unchecked(
                payload.extensions,
            ),
        }
    }
}

impl PrivateSpecType for private_types::tree::LeafNodeSource {
    type Public = public_types::tree::LeafNodeSource;
    fn from_public_unchecked(source: public_types::tree::LeafNodeSource) -> Self {
        match source {
            public_types::tree::LeafNodeSource::KeyPackage(lifetime) => {
                Self::KeyPackage(private_types::Lifetime::from_public_unchecked(lifetime))
            }
            public_types::tree::LeafNodeSource::Update => Self::Update,
            public_types::tree::LeafNodeSource::Commit(parent_hash) => {
                Self::Commit(parent_hash.into())
            }
        }
    }
}

impl PrivateSpecType for private_types::tree::Capabilities {
    type Public = public_types::tree::Capabilities;
    fn from_public_unchecked(capabilities: public_types::tree::Capabilities) -> Self {
        Self {
            versions: capabilities
                .versions
                .into_iter()
                .map(private_types::ProtocolVersion::from_public_unchecked)
                .collect(),
            ciphersuites: capabilities
                .ciphersuites
                .into_iter()
                .map(private_types::Ciphersuite::from_public_unchecked)
                .collect(),
            extensions: capabilities
                .extensions
                .into_iter()
                .map(private_types::extensions::ExtensionType::from_public_unchecked)
                .collect(),
            proposals: capabilities
                .proposals
                .into_iter()
                .map(private_types::proposals::ProposalType::from_public_unchecked)
                .collect(),
            credentials: capabilities
                .credentials
                .into_iter()
                .map(private_types::credential::CredentialType::from_public_unchecked)
                .collect(),
        }
    }
}
