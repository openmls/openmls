//! This module contains the [`FramedContent`] struct and associated helper structs
//! such as [`FramedContentTbs`], as well as their implementations.

use crate::{
    group::{GroupEpoch, GroupId},
    messages::{proposals::Proposal, Commit},
};

use super::{mls_auth_content::AuthenticatedContent, Sender};

use serde::{Deserialize, Serialize};
use tls_codec::{TlsSerialize, TlsSize, VLBytes};

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
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub(crate) struct FramedContent {
    pub(super) group_id: GroupId,
    pub(super) epoch: GroupEpoch,
    pub(super) sender: Sender,
    pub(super) authenticated_data: VLBytes,

    pub(super) body: FramedContentBody,
}

impl From<AuthenticatedContent> for FramedContent {
    fn from(mls_auth_content: AuthenticatedContent) -> Self {
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
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
pub(crate) enum FramedContentBody {
    #[tls_codec(discriminant = 1)]
    Application(VLBytes),
    #[tls_codec(discriminant = 2)]
    Proposal(Proposal),
    #[tls_codec(discriminant = 3)]
    Commit(Box<Commit>),
}
