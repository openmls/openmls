//! # PublicMessage
//!
//! A PublicMessage is a framing structure for MLS messages. It can contain
//! Proposals, Commits and application messages.

use std::io::Write;

use tls_codec::{
    Serialize as TlsSerializeTrait, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
};

use super::{mls_auth_content::FramedContentAuthData, mls_content::FramedContent, *};

/// Wrapper around a `Mac` used for type safety.
#[derive(
    Debug, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub(crate) struct MembershipTag(pub(crate) Mac);

/// [`PublicMessage`] is a framing structure for MLS messages. It can contain
/// Proposals, Commits and application messages.
///
/// 9. Message framing
///
/// ```c
/// // draft-ietf-mls-protocol-17
///
/// struct {
///     FramedContent content;
///     FramedContentAuthData auth;
///     optional<MAC> membership_tag;
/// } PublicMessage;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicMessage {
    pub(crate) content: FramedContent,
    pub(crate) auth: FramedContentAuthData,
    pub(crate) membership_tag: Option<MembershipTag>,
}

// -------------------------------------------------------------------------------------------------

/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     WireFormat wire_format;
///     FramedContent content; /* with content_type == commit */
///     opaque signature<V>;
///} ConfirmedTranscriptHashInput;
/// ```
#[derive(TlsSerialize, TlsSize)]
pub(crate) struct ConfirmedTranscriptHashInput<'a> {
    pub(super) wire_format: WireFormat,
    pub(super) mls_content: &'a FramedContent,
    pub(super) signature: &'a Signature,
}

// -------------------------------------------------------------------------------------------------

/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     MAC confirmation_tag;
/// } InterimTranscriptHashInput;
/// ```
#[derive(TlsSerialize, TlsSize)]
pub(crate) struct InterimTranscriptHashInput<'a> {
    pub(crate) confirmation_tag: &'a ConfirmationTag,
}

impl Size for PublicMessage {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.content.tls_serialized_len()
            + self.auth.tls_serialized_len()
            + if let Some(membership_tag) = &self.membership_tag {
                membership_tag.tls_serialized_len()
            } else {
                0
            }
    }
}

impl TlsSerializeTrait for PublicMessage {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        // Serialize the content, not the TBS.
        let mut written = self.content.tls_serialize(writer)?;
        written += self.auth.tls_serialize(writer)?;
        written += if let Some(membership_tag) = &self.membership_tag {
            membership_tag.tls_serialize(writer)?
        } else {
            0
        };
        Ok(written)
    }
}
