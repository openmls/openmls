//! # Proposals
//!
//! This module defines all the different types of Proposals.
//!
//! To find out if a specific proposal type is supported,
//! [`ProposalType::is_supported()`] can be used.

use std::convert::TryFrom;

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{Serialize as TlsSerializeTrait, TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::hash_ref::{make_proposal_ref, KeyPackageRef, ProposalRef},
    error::LibraryError,
    extensions::Extensions,
    framing::{
        mls_auth_content::AuthenticatedContent, mls_content::FramedContentBody, ContentType,
    },
    group::GroupId,
    key_packages::*,
    prelude::LeafNode,
    schedule::psk::*,
    versions::ProtocolVersion,
};

/// ## MLS Proposal Types
///
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// // See IANA registry for registered values
/// uint16 ProposalType;
/// ```
///
/// | Value           | Name                     | Recommended | Path Required | Reference |
/// |:================|:=========================|:============|:==============|:==========|
/// | 0x0000          | RESERVED                 | N/A         | N/A           | RFC XXXX  |
/// | 0x0001          | add                      | Y           | N             | RFC XXXX  |
/// | 0x0002          | update                   | Y           | Y             | RFC XXXX  |
/// | 0x0003          | remove                   | Y           | Y             | RFC XXXX  |
/// | 0x0004          | psk                      | Y           | N             | RFC XXXX  |
/// | 0x0005          | reinit                   | Y           | N             | RFC XXXX  |
/// | 0x0006          | external_init            | Y           | Y             | RFC XXXX  |
/// | 0x0007          | group_context_extensions | Y           | Y             | RFC XXXX  |
/// | 0xf000 - 0xffff | Reserved for Private Use | N/A         | N/A           | RFC XXXX  |
///
/// # Extensions
///
/// | Value  | Name    | Recommended | Path Required | Reference | Notes                        |
/// |:=======|:========|:============|:==============|:==========|:=============================|
/// | 0x0008 | app_ack | Y           | Y             | RFC XXXX  | draft-ietf-mls-extensions-00 |
#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Debug,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
    Serialize,
    Deserialize,
)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum ProposalType {
    Add = 1,
    Update = 2,
    Remove = 3,
    Presharedkey = 4,
    Reinit = 5,
    ExternalInit = 6,
    GroupContextExtensions = 7,
    AppAck = 8,
}

impl ProposalType {
    /// Check whether a proposal type is supported or not. Returns `true`
    /// if a proposal is supported and `false` otherwise.
    pub fn is_supported(&self) -> bool {
        match self {
            ProposalType::Add
            | ProposalType::Update
            | ProposalType::Remove
            | ProposalType::Presharedkey
            | ProposalType::Reinit
            | ProposalType::ExternalInit
            | ProposalType::GroupContextExtensions => true,
            ProposalType::AppAck => false,
        }
    }

    /// Returns `true` if the proposal type requires a path and `false`
    pub fn is_path_required(&self) -> bool {
        match self {
            Self::Add
            | Self::Presharedkey
            | Self::Reinit
            | Self::AppAck
            | Self::GroupContextExtensions => false,
            Self::Update | Self::Remove | Self::ExternalInit => true,
        }
    }
}

impl TryFrom<u16> for ProposalType {
    type Error = &'static str;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ProposalType::Add),
            2 => Ok(ProposalType::Update),
            3 => Ok(ProposalType::Remove),
            4 => Ok(ProposalType::Presharedkey),
            5 => Ok(ProposalType::Reinit),
            6 => Ok(ProposalType::ExternalInit),
            7 => Ok(ProposalType::GroupContextExtensions),
            8 => Ok(ProposalType::AppAck),
            _ => Err("Unknown proposal type."),
        }
    }
}

/// Proposal.
///
/// This `enum` contains the different proposals in its variants.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     ProposalType msg_type;
///     select (Proposal.msg_type) {
///         case add:                      Add;
///         case update:                   Update;
///         case remove:                   Remove;
///         case psk:                      PreSharedKey;
///         case reinit:                   ReInit;
///         case external_init:            ExternalInit;
///         case group_context_extensions: GroupContextExtensions;
///     };
/// } Proposal;
/// ```
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSize, TlsSerialize)]
#[allow(missing_docs)]
#[repr(u16)]
pub enum Proposal {
    #[tls_codec(discriminant = 1)]
    Add(AddProposal),
    #[tls_codec(discriminant = 2)]
    Update(UpdateProposal),
    #[tls_codec(discriminant = 3)]
    Remove(RemoveProposal),
    #[tls_codec(discriminant = 4)]
    PreSharedKey(PreSharedKeyProposal),
    #[tls_codec(discriminant = 5)]
    ReInit(ReInitProposal),
    #[tls_codec(discriminant = 6)]
    ExternalInit(ExternalInitProposal),
    #[tls_codec(discriminant = 7)]
    GroupContextExtensions(GroupContextExtensionProposal),
    // # Extensions
    // TODO(#916): `AppAck` is not in draft-ietf-mls-protocol-17 but
    //             was moved to `draft-ietf-mls-extensions-00`.
    #[tls_codec(discriminant = 8)]
    AppAck(AppAckProposal),
}

impl Proposal {
    /// Returns the proposal type.
    pub fn proposal_type(&self) -> ProposalType {
        match self {
            Proposal::Add(_) => ProposalType::Add,
            Proposal::Update(_) => ProposalType::Update,
            Proposal::Remove(_) => ProposalType::Remove,
            Proposal::PreSharedKey(_) => ProposalType::Presharedkey,
            Proposal::ReInit(_) => ProposalType::Reinit,
            Proposal::ExternalInit(_) => ProposalType::ExternalInit,
            Proposal::GroupContextExtensions(_) => ProposalType::GroupContextExtensions,
            Proposal::AppAck(_) => ProposalType::AppAck,
        }
    }

    pub(crate) fn is_type(&self, proposal_type: ProposalType) -> bool {
        self.proposal_type() == proposal_type
    }

    /// Indicates whether a Commit containing this [Proposal] requires a path.
    pub fn is_path_required(&self) -> bool {
        self.proposal_type().is_path_required()
    }
}

/// Add Proposal.
///
/// An Add proposal requests that a client with a specified [`KeyPackage`] be added to the group.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     KeyPackage key_package;
/// } Add;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct AddProposal {
    pub(crate) key_package: KeyPackage,
}

impl AddProposal {
    /// Returns a reference to the key package in the proposal.
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }
}

/// Update Proposal.
///
/// An Update proposal is a similar mechanism to [`AddProposal`] with the distinction that it
/// replaces the sender's [`LeafNode`] in the tree instead of adding a new leaf to the tree.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     LeafNode leaf_node;
/// } Update;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct UpdateProposal {
    pub(crate) leaf_node: LeafNode,
}

impl UpdateProposal {
    /// Returns a reference to the key package in the proposal.
    pub fn leaf_node(&self) -> &LeafNode {
        &self.leaf_node
    }
}

/// Remove Proposal.
///
/// A Remove proposal requests that the member with the leaf index removed be removed from the group.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     uint32 removed;
/// } Remove;
/// ```
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct RemoveProposal {
    pub(crate) removed: LeafNodeIndex,
}

impl RemoveProposal {
    /// Returns the leaf index of the removed leaf in this proposal.
    pub fn removed(&self) -> LeafNodeIndex {
        self.removed
    }
}

/// PreSharedKey Proposal.
///
/// A PreSharedKey proposal can be used to request that a pre-shared key be injected into the key
/// schedule in the process of advancing the epoch.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     PreSharedKeyID psk;
/// } PreSharedKey;
/// ```
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct PreSharedKeyProposal {
    psk: PreSharedKeyId,
}

impl PreSharedKeyProposal {
    /// Returns the [`PreSharedKeyId`] and consume this proposal.
    pub(crate) fn into_psk_id(self) -> PreSharedKeyId {
        self.psk
    }
}

#[cfg(test)]
impl PreSharedKeyProposal {
    /// Create a new PSK proposal
    pub(crate) fn new(psk: PreSharedKeyId) -> Self {
        Self { psk }
    }
}

/// ReInit Proposal.
///
/// A ReInit proposal represents a request to reinitialize the group with different parameters, for
/// example, to increase the version number or to change the ciphersuite. The reinitialization is
/// done by creating a completely new group and shutting down the old one.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     opaque group_id<V>;
///     ProtocolVersion version;
///     CipherSuite cipher_suite;
///     Extension extensions<V>;
/// } ReInit;
/// ```
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ReInitProposal {
    pub(crate) group_id: GroupId,
    pub(crate) version: ProtocolVersion,
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) extensions: Extensions,
}

/// ExternalInit Proposal.
///
/// An ExternalInit proposal is used by new members that want to join a group by using an external
/// commit. This proposal can only be used in that context.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///   opaque kem_output<V>;
/// } ExternalInit;
/// ```
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ExternalInitProposal {
    kem_output: VLBytes,
}

impl ExternalInitProposal {
    /// Returns the `kem_output` contained in the proposal.
    pub(crate) fn kem_output(&self) -> &[u8] {
        self.kem_output.as_slice()
    }
}

impl From<Vec<u8>> for ExternalInitProposal {
    fn from(kem_output: Vec<u8>) -> Self {
        ExternalInitProposal {
            kem_output: kem_output.into(),
        }
    }
}

// TODO: #291 Implement AppAck

/// AppAck Proposal.
///
/// This is not yet supported.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct AppAckProposal {
    received_ranges: Vec<MessageRange>,
}

/// GroupContextExtensions Proposal.
///
/// A GroupContextExtensions proposal is used to update the list of extensions in the GroupContext
/// for the group.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///   Extension extensions<V>;
/// } GroupContextExtensions;
/// ```
#[derive(
    Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct GroupContextExtensionProposal {
    extensions: Extensions,
}

impl GroupContextExtensionProposal {
    /// Create a new [`GroupContextExtensionProposal`].
    #[cfg(test)]
    pub(crate) fn new(extensions: Extensions) -> Self {
        Self { extensions }
    }
}

// Crate-only types

/// 11.2 Commit
///
/// enum {
///   reserved(0),
///   proposal(1)
///   reference(2),
///   (255)
/// } ProposalOrRefType;
///
/// struct {
///   ProposalOrRefType type;
///   select (ProposalOrRef.type) {
///     case proposal:  Proposal proposal;
///     case reference: opaque hash<0..255>;
///   }
/// } ProposalOrRef;
///
/// Type of Proposal, either by value or by reference
/// We only implement the values (1, 2), other values are not valid
/// and will yield `ProposalOrRefTypeError::UnknownValue` when decoded.
#[derive(
    PartialEq, Clone, Copy, Debug, TlsSerialize, TlsDeserialize, TlsSize, Serialize, Deserialize,
)]
#[repr(u8)]
pub(crate) enum ProposalOrRefType {
    Proposal = 1,
    Reference = 2,
}

/// Type of Proposal, either by value or by reference.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProposalOrRef {
    #[tls_codec(discriminant = 1)]
    Proposal(Proposal),
    Reference(ProposalRef),
}

#[derive(Error, Debug)]
pub(crate) enum ProposalRefError {
    #[error("Expected `Proposal`, got `{wrong:?}`.")]
    AuthenticatedContentHasWrongType { wrong: ContentType },
    #[error(transparent)]
    Other(#[from] LibraryError),
}

impl ProposalRef {
    pub(crate) fn from_authenticated_content(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        authenticated_content: &AuthenticatedContent,
    ) -> Result<Self, ProposalRefError> {
        if !matches!(
            authenticated_content.content(),
            FramedContentBody::Proposal(_)
        ) {
            return Err(ProposalRefError::AuthenticatedContentHasWrongType {
                wrong: authenticated_content.content().content_type(),
            });
        };

        let encoded = authenticated_content
            .tls_serialize_detached()
            .map_err(|error| ProposalRefError::Other(LibraryError::missing_bound_check(error)))?;

        make_proposal_ref(&encoded, ciphersuite, crypto)
            .map_err(|error| ProposalRefError::Other(LibraryError::unexpected_crypto_error(error)))
    }

    /// Note: A [`ProposalRef`] should be calculated by using TLS-serialized [`AuthenticatedContent`]
    ///       as value input and not the TLS-serialized proposal. However, to spare us a major refactoring,
    ///       we calculate it from the raw value in some places that do not interact with the outside world.
    pub(crate) fn from_raw_proposal(
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        proposal: &Proposal,
    ) -> Result<Self, LibraryError> {
        // This is used for hash domain separation.
        let mut data = b"Internal OpenMLS ProposalRef Label".to_vec();

        let mut encoded = proposal
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        data.append(&mut encoded);

        make_proposal_ref(&data, ciphersuite, backend.crypto())
            .map_err(LibraryError::unexpected_crypto_error)
    }
}

/// TODO: #291 Implement AppAck
/// ```text
/// struct {
///     KeyPackageRef sender;
///     uint32 first_generation;
///     uint32 last_generation;
/// } MessageRange;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub(crate) struct MessageRange {
    sender: KeyPackageRef,
    first_generation: u32,
    last_generation: u32,
}
