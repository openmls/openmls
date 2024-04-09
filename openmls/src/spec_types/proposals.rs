use openmls_traits::crypto::OpenMlsCrypto;
use serde::Serialize;
use tls_codec::{Serialize as _, TlsSerialize, TlsSize};

use crate::error::LibraryError;
use crate::framing::{mls_auth_content::AuthenticatedContent, mls_content::FramedContentBody};
use crate::messages::proposals::ProposalRefError;

use crate::ciphersuite::hash_ref::make_proposal_ref;

use super::{
    extensions::{Extensions, SenderExtensionIndex},
    key_package::{KeyPackage, KeyPackageRef},
    psk::PreSharedKeyId,
    tree::{LeafNode, LeafNodeIndex},
    Ciphersuite, GroupId, HashReference, ProtocolVersion, VLBytes,
};

/// ## MLS Proposal Types
///
///
/// ```c
/// // draft-ietf-mls-protocol-20
/// // See IANA registry for registered values
/// uint16 ProposalType;
/// ```
///
/// | Value           | Name                     | R | Ext | Path | Ref      |
/// |-----------------|--------------------------|---|-----|------|----------|
/// | 0x0000          | RESERVED                 | - | -   | -    | RFC XXXX |
/// | 0x0001          | add                      | Y | Y   | N    | RFC XXXX |
/// | 0x0002          | update                   | Y | N   | Y    | RFC XXXX |
/// | 0x0003          | remove                   | Y | Y   | Y    | RFC XXXX |
/// | 0x0004          | psk                      | Y | Y   | N    | RFC XXXX |
/// | 0x0005          | reinit                   | Y | Y   | N    | RFC XXXX |
/// | 0x0006          | external_init            | Y | N   | Y    | RFC XXXX |
/// | 0x0007          | group_context_extensions | Y | Y   | Y    | RFC XXXX |
/// | 0x0A0A          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0x1A1A          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0x2A2A          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0x3A3A          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0x4A4A          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0x5A5A          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0x6A6A          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0x7A7A          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0x8A8A          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0x9A9A          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0xAAAA          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0xBABA          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0xCACA          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0xDADA          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0xEAEA          | GREASE                   | Y | -   | -    | RFC XXXX |
/// | 0xF000 - 0xFFFF | Reserved for Private Use | - | -   | -    | RFC XXXX |
///
/// # Extensions
///
/// | Value  | Name    | Recommended | Path Required | Reference | Notes                        |
/// |:=======|:========|:============|:==============|:==========|:=============================|
/// | 0x0008 | app_ack | Y           | Y             | RFC XXXX  | draft-ietf-mls-extensions-00 |
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Serialize)]
#[allow(missing_docs)]
pub enum ProposalType {
    Add,
    Update,
    Remove,
    PreSharedKey,
    Reinit,
    ExternalInit,
    GroupContextExtensions,
    AppAck,
    Unknown(u16),
}

impl ProposalType {
    /// Check whether a proposal type is supported or not. Returns `true`
    /// if a proposal is supported and `false` otherwise.
    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            ProposalType::Add
                | ProposalType::Update
                | ProposalType::Remove
                | ProposalType::PreSharedKey
                | ProposalType::Reinit
                | ProposalType::ExternalInit
                | ProposalType::GroupContextExtensions
        )
    }

    /// Returns `true` if the proposal type requires a path and `false`
    pub fn is_path_required(&self) -> bool {
        matches!(
            self,
            Self::Update | Self::Remove | Self::ExternalInit | Self::GroupContextExtensions
        )
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
#[derive(Debug, PartialEq, Clone, Serialize, TlsSize, TlsSerialize)]
#[allow(missing_docs)]
#[repr(u16)]
pub enum Proposal {
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    PreSharedKey(PreSharedKeyProposal),
    ReInit(ReInitProposal),
    ExternalInit(ExternalInitProposal),
    GroupContextExtensions(GroupContextExtensionProposal),
    // # Extensions
    // TODO(#916): `AppAck` is not in draft-ietf-mls-protocol-17 but
    //             was moved to `draft-ietf-mls-extensions-00`.
    AppAck(AppAckProposal),
}

impl Proposal {
    /// Returns the proposal type.
    pub fn proposal_type(&self) -> ProposalType {
        match self {
            Proposal::Add(_) => ProposalType::Add,
            Proposal::Update(_) => ProposalType::Update,
            Proposal::Remove(_) => ProposalType::Remove,
            Proposal::PreSharedKey(_) => ProposalType::PreSharedKey,
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
#[derive(Debug, PartialEq, Clone, Serialize, TlsSize, TlsSerialize)]
pub struct AddProposal {
    pub(crate) key_package: KeyPackage,
}

impl AddProposal {
    /// Returns a reference to the key package in the proposal.
    pub(crate) fn key_package(&self) -> &KeyPackage {
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
#[derive(Debug, PartialEq, Clone, Serialize, TlsSize, TlsSerialize)]
pub struct UpdateProposal {
    pub(crate) leaf_node: LeafNode,
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
#[derive(Debug, PartialEq, Clone, Serialize, TlsSize, TlsSerialize)]
pub struct RemoveProposal {
    pub(super) removed: LeafNodeIndex,
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
#[derive(Debug, PartialEq, Clone, Serialize, TlsSize, TlsSerialize)]
pub struct PreSharedKeyProposal {
    pub(super) psk: PreSharedKeyId,
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
#[derive(Debug, PartialEq, Clone, Serialize, TlsSize, TlsSerialize)]
pub struct ReInitProposal {
    pub(super) group_id: GroupId,
    pub(super) version: ProtocolVersion,
    pub(super) ciphersuite: Ciphersuite,
    pub(super) extensions: Extensions,
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
#[derive(Debug, PartialEq, Clone, Serialize, TlsSize, TlsSerialize)]
pub struct ExternalInitProposal {
    pub(super) kem_output: VLBytes,
}

/// TODO: #291 Implement AppAck
/// ```text
/// struct {
///     KeyPackageRef sender;
///     uint32 first_generation;
///     uint32 last_generation;
/// } MessageRange;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, TlsSize, TlsSerialize)]
pub struct MessageRange {
    pub(super) sender: KeyPackageRef,
    pub(super) first_generation: u32,
    pub(super) last_generation: u32,
}
/// AppAck Proposal.
///
/// This is not yet supported.
#[derive(Debug, PartialEq, Clone, Serialize, TlsSize, TlsSerialize)]
pub struct AppAckProposal {
    pub(super) received_ranges: Vec<MessageRange>,
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
#[derive(Debug, PartialEq, Clone, Serialize, TlsSize, TlsSerialize)]
pub struct GroupContextExtensionProposal {
    pub(super) extensions: Extensions,
}

/// A reference to a proposal.
/// This value uniquely identifies a proposal.
#[derive(Debug, Clone, PartialEq, Hash, Eq, Ord, PartialOrd)]
pub struct ProposalRef(pub(super) HashReference);

impl ProposalRef {
    pub(crate) fn from_authenticated_content_by_ref(
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
        crypto: &impl OpenMlsCrypto,
        proposal: &Proposal,
    ) -> Result<Self, LibraryError> {
        // This is used for hash domain separation.
        let mut data = b"Internal OpenMLS ProposalRef Label".to_vec();

        let mut encoded = proposal
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        data.append(&mut encoded);

        make_proposal_ref(&data, ciphersuite, crypto).map_err(LibraryError::unexpected_crypto_error)
    }
}

/// All possible sender types according to the MLS protocol spec.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// enum {
///     reserved(0),
///     member(1),
///     external(2),
///     new_member_proposal(3),
///     new_member_commit(4),
///     (255)
/// } SenderType;
///
/// // draft-ietf-mls-protocol-16
/// struct {
///     SenderType sender_type;
///     select (Sender.sender_type) {
///         case member:
///             uint32 leaf_index;
///         case external:
///             uint32 sender_index;
///         case new_member_commit:
///         case new_member_proposal:
///             struct{};
///     }
/// } Sender;
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(u8)]
pub enum Sender {
    /// The sender is a member of the group
    Member(LeafNodeIndex),
    /// The sender is not a member of the group and has an external value instead
    /// The index refers to the [crate::extensions::ExternalSendersExtension] and is 0 indexed
    External(SenderExtensionIndex),
    /// The sender is a new member of the group that joins itself through
    /// an [External Add proposal](crate::messages::external_proposals::JoinProposal)
    NewMemberProposal,
    /// The sender is a new member of the group that joins itself through
    /// an [External Commit](crate::group::mls_group::MlsGroup::join_by_external_commit)
    NewMemberCommit,
}

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
#[derive(PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum ProposalOrRefType {
    /// Proposal by value.
    Proposal = 1,
    /// Proposal by reference
    Reference = 2,
}

/// Type of Proposal, either by value or by reference.
#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProposalOrRef {
    Proposal(Proposal),
    Reference(ProposalRef),
}
