//! This module contains the [`FramedContentIn`] struct and associated helper structs
//! such as [`FramedContentTbsIn`], as well as their implementations.

use crate::{
    group::{GroupEpoch, GroupId},
    messages::{proposals_in::ProposalIn, CommitIn},
};

use super::{mls_auth_content_in::AuthenticatedContentIn, ContentType, Sender};

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     Sender sender;
///     opaque authenticated_data<V>;
///
///     // ... continued in [FramedContentBody] ...
/// } FramedContent;
/// ```
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub(crate) struct FramedContentIn {
    pub(super) group_id: GroupId,
    pub(super) epoch: GroupEpoch,
    pub(super) sender: Sender,
    pub(super) authenticated_data: VLBytes,
    pub(super) body: FramedContentBodyIn,
}

impl From<AuthenticatedContentIn> for FramedContentIn {
    fn from(mls_auth_content: AuthenticatedContentIn) -> Self {
        mls_auth_content.content
    }
}

/// ```c
/// struct {
///     // ... continued from [FramedContent] ...
///
///     ContentType content_type;
///     select (FramedContent.content_type) {
///         case application:
///           opaque application_data<V>;
///         case proposal:
///           Proposal proposal;
///         case commit:
///           Commit commit;
///     }
/// } FramedContent;
/// ```
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
#[repr(u8)]
pub(crate) enum FramedContentBodyIn {
    #[tls_codec(discriminant = 1)]
    Application(VLBytes),
    #[tls_codec(discriminant = 2)]
    Proposal(ProposalIn),
    #[tls_codec(discriminant = 3)]
    Commit(Box<CommitIn>),
}

impl FramedContentBodyIn {
    /// Returns the [`ContentType`].
    pub(crate) fn content_type(&self) -> ContentType {
        match self {
            FramedContentBodyIn::Application(_) => ContentType::Application,
            FramedContentBodyIn::Proposal(_) => ContentType::Proposal,
            FramedContentBodyIn::Commit(_) => ContentType::Commit,
        }
    }
}
