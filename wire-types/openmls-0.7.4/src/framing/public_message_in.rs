//! # PublicMessageIn
//!
//! A PublicMessageIn is a framing structure for MLS messages. It can contain
//! Proposals, Commits and application messages.

use super::{mls_auth_content::FramedContentAuthData, mls_content_in::FramedContentIn, *};

use std::io::{Read, Write};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

/// [`PublicMessageIn`] is a framing structure for MLS messages. It can contain
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
pub struct PublicMessageIn {
    pub(crate) content: FramedContentIn,
    pub(crate) auth: FramedContentAuthData,
    pub(crate) membership_tag: Option<MembershipTag>,
}

impl PublicMessageIn {
    /// Build an [`PublicMessageIn`].
    pub(crate) fn new(
        content: FramedContentIn,
        auth: FramedContentAuthData,
        membership_tag: Option<MembershipTag>,
    ) -> Self {
        Self {
            content,
            auth,
            membership_tag,
        }
    }
}

impl TlsDeserializeTrait for PublicMessageIn {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        let content = FramedContentIn::tls_deserialize(bytes)?;
        let auth = FramedContentAuthData::deserialize(bytes, content.body.content_type())?;
        let membership_tag = if content.sender.is_member() {
            Some(MembershipTag::tls_deserialize(bytes)?)
        } else {
            None
        };

        Ok(PublicMessageIn::new(content, auth, membership_tag))
    }
}

impl DeserializeBytes for PublicMessageIn {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let message = PublicMessageIn::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[message.tls_serialized_len()..];
        Ok((message, remainder))
    }
}

impl Size for PublicMessageIn {
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

impl TlsSerializeTrait for PublicMessageIn {
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
