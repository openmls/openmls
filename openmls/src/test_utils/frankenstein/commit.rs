use tls_codec::*;

use super::{FrankenLeafNode, FrankenProposal};

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenCommit {
    pub proposals: Vec<FrankenProposalOrRef>,
    pub path: Option<FrankenUpdatePathIn>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum FrankenProposalOrRef {
    #[tls_codec(discriminant = 1)]
    Proposal(FrankenProposal),
    Reference(VLBytes),
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenUpdatePathIn {
    pub leaf_node: FrankenLeafNode,
    pub nodes: Vec<FrankenUpdatePathNode>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenUpdatePathNode {
    pub public_key: VLBytes,
    pub encrypted_path_secrets: Vec<FrankenHpkeCiphertext>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenHpkeCiphertext {
    pub kem_output: VLBytes,
    pub ciphertext: VLBytes,
}
