//! # Proposals
//!
//! This module defines all the different types of Proposals.

use std::io::{Read, Write};

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes, Error, Serialize as TlsSerializeTrait,
    Size, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes,
};

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

#[cfg(feature = "extensions-draft-08")]
use crate::component::ComponentId;

/// ## MLS Proposal Types
///
///
/// ```c
/// // RFC 9420
/// // See IANA registry for registered values
/// uint16 ProposalType;
/// ```
///
/// | Value           | Name                     | R | Ext | Path | Ref      |
/// |-----------------|--------------------------|---|-----|------|----------|
/// | 0x0000          | RESERVED                 | - | -   | -    | RFC 9420 |
/// | 0x0001          | add                      | Y | Y   | N    | RFC 9420 |
/// | 0x0002          | update                   | Y | N   | Y    | RFC 9420 |
/// | 0x0003          | remove                   | Y | Y   | Y    | RFC 9420 |
/// | 0x0004          | psk                      | Y | Y   | N    | RFC 9420 |
/// | 0x0005          | reinit                   | Y | Y   | N    | RFC 9420 |
/// | 0x0006          | external_init            | Y | N   | Y    | RFC 9420 |
/// | 0x0007          | group_context_extensions | Y | Y   | Y    | RFC 9420 |
/// | 0x0A0A          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0x1A1A          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0x2A2A          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0x3A3A          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0x4A4A          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0x5A5A          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0x6A6A          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0x7A7A          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0x8A8A          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0x9A9A          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0xAAAA          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0xBABA          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0xCACA          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0xDADA          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0xEAEA          | GREASE                   | Y | -   | -    | RFC 9420 |
/// | 0xF000 - 0xFFFF | Reserved for Private Use | - | -   | -    | RFC 9420 |
///
/// # Extensions
///
/// | Value  | Name          | Recommended | Path Required | Reference | Notes                        |
/// |:=======|:==============|:============|:==============|:==========|:=============================|
/// | 0x0009 | app_ephemeral | Y           | N             | RFC XXXX  | draft-ietf-mls-extensions-08 |
/// | 0x000a | self_remove   | Y           | Y             | RFC XXXX  | draft-ietf-mls-extensions-07 |
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Serialize, Deserialize, Hash)]
#[allow(missing_docs)]
pub enum ProposalType {
    Add,
    Update,
    Remove,
    PreSharedKey,
    Reinit,
    ExternalInit,
    GroupContextExtensions,
    SelfRemove,
    #[cfg(feature = "extensions-draft-08")]
    AppEphemeral,
    Grease(u16),
    Custom(u16),
}

impl ProposalType {
    /// Returns true for all proposal types that are considered "default" by the
    /// spec.
    pub(crate) fn is_default(self) -> bool {
        match self {
            ProposalType::Add
            | ProposalType::Update
            | ProposalType::Remove
            | ProposalType::PreSharedKey
            | ProposalType::Reinit
            | ProposalType::ExternalInit
            | ProposalType::GroupContextExtensions => true,
            ProposalType::SelfRemove | ProposalType::Grease(_) | ProposalType::Custom(_) => false,
            #[cfg(feature = "extensions-draft-08")]
            ProposalType::AppEphemeral => false,
        }
    }

    /// Returns true if this is a GREASE proposal type.
    ///
    /// GREASE values are used to ensure implementations properly handle unknown
    /// proposal types. See [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5).
    pub fn is_grease(&self) -> bool {
        matches!(self, ProposalType::Grease(_))
    }
}

impl Size for ProposalType {
    fn tls_serialized_len(&self) -> usize {
        2
    }
}

impl TlsDeserializeTrait for ProposalType {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut proposal_type = [0u8; 2];
        bytes.read_exact(&mut proposal_type)?;

        Ok(ProposalType::from(u16::from_be_bytes(proposal_type)))
    }
}

impl TlsSerializeTrait for ProposalType {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(&u16::from(*self).to_be_bytes())?;

        Ok(2)
    }
}

impl DeserializeBytes for ProposalType {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let proposal_type = ProposalType::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[proposal_type.tls_serialized_len()..];
        Ok((proposal_type, remainder))
    }
}

impl ProposalType {
    /// Returns `true` if the proposal type requires a path and `false`
    pub fn is_path_required(&self) -> bool {
        matches!(
            self,
            Self::Update
                | Self::Remove
                | Self::ExternalInit
                | Self::GroupContextExtensions
                | Self::SelfRemove
        )
    }
}

impl From<u16> for ProposalType {
    fn from(value: u16) -> Self {
        match value {
            1 => ProposalType::Add,
            2 => ProposalType::Update,
            3 => ProposalType::Remove,
            4 => ProposalType::PreSharedKey,
            5 => ProposalType::Reinit,
            6 => ProposalType::ExternalInit,
            7 => ProposalType::GroupContextExtensions,
            #[cfg(feature = "extensions-draft-08")]
            0x0009 => ProposalType::AppEphemeral,
            0x000a => ProposalType::SelfRemove,
            other if crate::grease::is_grease_value(other) => ProposalType::Grease(other),
            other => ProposalType::Custom(other),
        }
    }
}

impl From<ProposalType> for u16 {
    fn from(value: ProposalType) -> Self {
        match value {
            ProposalType::Add => 1,
            ProposalType::Update => 2,
            ProposalType::Remove => 3,
            ProposalType::PreSharedKey => 4,
            ProposalType::Reinit => 5,
            ProposalType::ExternalInit => 6,
            ProposalType::GroupContextExtensions => 7,
            #[cfg(feature = "extensions-draft-08")]
            ProposalType::AppEphemeral => 0x0009,
            ProposalType::SelfRemove => 0x000a,
            ProposalType::Grease(id) => id,
            ProposalType::Custom(id) => id,
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
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
#[repr(u16)]
pub enum Proposal {
    Add(Box<AddProposal>),
    Update(Box<UpdateProposal>),
    Remove(Box<RemoveProposal>),
    PreSharedKey(Box<PreSharedKeyProposal>),
    ReInit(Box<ReInitProposal>),
    ExternalInit(Box<ExternalInitProposal>),
    GroupContextExtensions(Box<GroupContextExtensionProposal>),
    // # Extensions
    // A SelfRemove proposal is an empty struct.
    SelfRemove,
    #[cfg(feature = "extensions-draft-08")]
    AppEphemeral(Box<AppEphemeralProposal>),
    Custom(Box<CustomProposal>),
}

impl Proposal {
    /// Build a remove proposal.
    pub(crate) fn remove(r: RemoveProposal) -> Self {
        Self::Remove(Box::new(r))
    }

    /// Build an add proposal.
    pub(crate) fn add(a: AddProposal) -> Self {
        Self::Add(Box::new(a))
    }

    /// Build a custom proposal.
    pub(crate) fn custom(c: CustomProposal) -> Self {
        Self::Custom(Box::new(c))
    }

    /// Build a psk proposal.
    pub(crate) fn psk(p: PreSharedKeyProposal) -> Self {
        Self::PreSharedKey(Box::new(p))
    }

    /// Build an update proposal.
    pub(crate) fn update(p: UpdateProposal) -> Self {
        Self::Update(Box::new(p))
    }

    /// Build a GroupContextExtensionProposal proposal.
    pub(crate) fn group_context_extensions(p: GroupContextExtensionProposal) -> Self {
        Self::GroupContextExtensions(Box::new(p))
    }

    /// Build an ExternalInit proposal.
    pub(crate) fn external_init(p: ExternalInitProposal) -> Self {
        Self::ExternalInit(Box::new(p))
    }

    #[cfg(test)]
    /// Build a ReInit proposal.
    pub(crate) fn re_init(p: ReInitProposal) -> Self {
        Self::ReInit(Box::new(p))
    }

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
            Proposal::SelfRemove => ProposalType::SelfRemove,
            #[cfg(feature = "extensions-draft-08")]
            Proposal::AppEphemeral(_) => ProposalType::AppEphemeral,
            Proposal::Custom(custom) => ProposalType::Custom(custom.proposal_type.to_owned()),
        }
    }

    pub(crate) fn is_type(&self, proposal_type: ProposalType) -> bool {
        self.proposal_type() == proposal_type
    }

    /// Indicates whether a Commit containing this [Proposal] requires a path.
    pub fn is_path_required(&self) -> bool {
        self.proposal_type().is_path_required()
    }

    pub(crate) fn has_lower_priority_than(&self, new_proposal: &Proposal) -> bool {
        match (self, new_proposal) {
            // Updates have the lowest priority.
            (Proposal::Update(_), _) => true,
            // Removes have a higher priority than Updates.
            (Proposal::Remove(_), Proposal::Update(_)) => false,
            // Later Removes trump earlier Removes
            (Proposal::Remove(_), Proposal::Remove(_)) => true,
            // SelfRemoves have the highest priority.
            (_, Proposal::SelfRemove) => true,
            // All other combinations are invalid
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    // Get this proposal as a `RemoveProposal`.
    pub(crate) fn as_remove(&self) -> Option<&RemoveProposal> {
        if let Self::Remove(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// Returns `true` if the proposal is [`Remove`].
    ///
    /// [`Remove`]: Proposal::Remove
    #[must_use]
    pub fn is_remove(&self) -> bool {
        matches!(self, Self::Remove(..))
    }
}

/// Add Proposal.
///
/// An Add proposal requests that a client with a specified [`KeyPackage`] be
/// added to the group.
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
/// An Update proposal is a similar mechanism to [`AddProposal`] with the
/// distinction that it replaces the sender's [`LeafNode`] in the tree instead
/// of adding a new leaf to the tree.
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
    /// Returns a reference to the leaf node in the proposal.
    pub fn leaf_node(&self) -> &LeafNode {
        &self.leaf_node
    }
}

/// Remove Proposal.
///
/// A Remove proposal requests that the member with the leaf index removed be
/// removed from the group.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     uint32 removed;
/// } Remove;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
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
/// A PreSharedKey proposal can be used to request that a pre-shared key be
/// injected into the key schedule in the process of advancing the epoch.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     PreSharedKeyID psk;
/// } PreSharedKey;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
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

impl PreSharedKeyProposal {
    /// Create a new PSK proposal
    pub fn new(psk: PreSharedKeyId) -> Self {
        Self { psk }
    }
}

/// ReInit Proposal.
///
/// A ReInit proposal represents a request to reinitialize the group with
/// different parameters, for example, to increase the version number or to
/// change the ciphersuite. The reinitialization is done by creating a
/// completely new group and shutting down the old one.
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
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct ReInitProposal {
    pub(crate) group_id: GroupId,
    pub(crate) version: ProtocolVersion,
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) extensions: Extensions,
}

/// ExternalInit Proposal.
///
/// An ExternalInit proposal is used by new members that want to join a group by
/// using an external commit. This proposal can only be used in that context.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///   opaque kem_output<V>;
/// } ExternalInit;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
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

#[cfg(feature = "extensions-draft-08")]
/// AppAck object.
///
/// This is not yet supported.
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct AppAck {
    received_ranges: Vec<MessageRange>,
}

#[cfg(feature = "extensions-draft-08")]
/// AppEphemeral proposal.
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct AppEphemeralProposal {
    /// The unique [`ComponentId`] associated with the proposal.
    component_id: ComponentId,
    /// Application data.
    data: VLBytes,
}
#[cfg(feature = "extensions-draft-08")]
impl AppEphemeralProposal {
    /// Create a new [`AppEphemeralProposal`].
    pub fn new(component_id: ComponentId, data: Vec<u8>) -> Self {
        Self {
            component_id,
            data: data.into(),
        }
    }
    /// Returns the `component_id` contained in the proposal.
    pub fn component_id(&self) -> ComponentId {
        self.component_id
    }

    /// Returns the `data` contained in the proposal.
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }
}

/// GroupContextExtensions Proposal.
///
/// A GroupContextExtensions proposal is used to update the list of extensions
/// in the GroupContext for the group.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///   Extension extensions<V>;
/// } GroupContextExtensions;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct GroupContextExtensionProposal {
    extensions: Extensions,
}

impl GroupContextExtensionProposal {
    /// Create a new [`GroupContextExtensionProposal`].
    pub(crate) fn new(extensions: Extensions) -> Self {
        Self { extensions }
    }

    /// Get the extensions of the proposal
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
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
    PartialEq,
    Clone,
    Copy,
    Debug,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
pub enum ProposalOrRefType {
    /// Proposal by value.
    Proposal = 1,
    /// Proposal by reference
    Reference = 2,
}

/// Type of Proposal, either by value or by reference.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
#[allow(missing_docs)]
pub(crate) enum ProposalOrRef {
    #[tls_codec(discriminant = 1)]
    Proposal(Box<Proposal>),
    Reference(Box<ProposalRef>),
}

impl ProposalOrRef {
    /// Create a proposal by value.
    pub(crate) fn proposal(p: Proposal) -> Self {
        Self::Proposal(Box::new(p))
    }

    /// Create a proposal by reference.
    pub(crate) fn reference(p: ProposalRef) -> Self {
        Self::Reference(Box::new(p))
    }

    pub(crate) fn as_proposal(&self) -> Option<&Proposal> {
        if let Self::Proposal(v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub(crate) fn as_reference(&self) -> Option<&ProposalRef> {
        if let Self::Reference(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

impl From<Proposal> for ProposalOrRef {
    fn from(value: Proposal) -> Self {
        Self::proposal(value)
    }
}

impl From<ProposalRef> for ProposalOrRef {
    fn from(value: ProposalRef) -> Self {
        Self::reference(value)
    }
}

#[derive(Error, Debug)]
pub(crate) enum ProposalRefError {
    #[error("Expected `Proposal`, got `{wrong:?}`.")]
    AuthenticatedContentHasWrongType { wrong: ContentType },
    #[error(transparent)]
    Other(#[from] LibraryError),
}

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

    /// Note: A [`ProposalRef`] should be calculated by using TLS-serialized
    /// [`AuthenticatedContent`]       as value input and not the
    /// TLS-serialized proposal. However, to spare us a major refactoring,
    ///       we calculate it from the raw value in some places that do not
    /// interact with the outside world.
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

/// ```text
/// struct {
///     KeyPackageRef sender;
///     uint32 first_generation;
///     uint32 last_generation;
/// } MessageRange;
/// ```
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub(crate) struct MessageRange {
    sender: KeyPackageRef,
    first_generation: u32,
    last_generation: u32,
}

/// A custom proposal with semantics to be implemented by the application.
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
)]
pub struct CustomProposal {
    proposal_type: u16,
    payload: Vec<u8>,
}

impl CustomProposal {
    /// Generate a new custom proposal.
    pub fn new(proposal_type: u16, payload: Vec<u8>) -> Self {
        Self {
            proposal_type,
            payload,
        }
    }

    /// Returns the proposal type of this [`CustomProposal`].
    pub fn proposal_type(&self) -> u16 {
        self.proposal_type
    }

    /// Returns the payload of this [`CustomProposal`].
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[cfg(test)]
mod tests {
    use tls_codec::{Deserialize, Serialize};

    use super::ProposalType;

    #[test]
    fn that_unknown_proposal_types_are_de_serialized_correctly() {
        // Use non-GREASE unknown values for testing (GREASE values have pattern 0x_A_A)
        let proposal_types = [0x0000u16, 0x0B0B, 0x7C7C, 0xF000, 0xFFFF];

        for proposal_type in proposal_types.into_iter() {
            // Construct an unknown proposal type.
            let test = proposal_type.to_be_bytes().to_vec();

            // Test deserialization.
            let got = ProposalType::tls_deserialize_exact(&test).unwrap();

            match got {
                ProposalType::Custom(got_proposal_type) => {
                    assert_eq!(proposal_type, got_proposal_type);
                }
                other => panic!("Expected `ProposalType::Unknown`, got `{other:?}`."),
            }

            // Test serialization.
            let got_serialized = got.tls_serialize_detached().unwrap();
            assert_eq!(test, got_serialized);
        }
    }
}
