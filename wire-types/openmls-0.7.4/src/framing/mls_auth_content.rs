//! # MLS content authentication
//!
//! This module contains structs and implementation that pertain to content
//! authentication in MLS.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait, Size, TlsSerialize, TlsSize,
};

use super::{mls_content::FramedContent, ConfirmationTag, ContentType, Signature, WireFormat};

/// 7.1 Content Authentication
///
/// ```c
/// // draft-ietf-mls-protocol-17
///
/// struct {
///    /* SignWithLabel(., "FramedContentTBS", FramedContentTBS) */
///    opaque signature<V>;
///    select (FramedContent.content_type) {
///        case commit:
///            /*
///              MAC(confirmation_key,
///                  GroupContext.confirmed_transcript_hash)
///            */
///            MAC confirmation_tag;
///        case application:
///        case proposal:
///            struct{};
///    };
///} FramedContentAuthData;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FramedContentAuthData {
    pub(super) signature: Signature,
    pub(super) confirmation_tag: Option<ConfirmationTag>,
}

impl FramedContentAuthData {
    pub(crate) fn deserialize<R: Read>(
        bytes: &mut R,
        content_type: ContentType,
    ) -> Result<Self, tls_codec::Error> {
        let signature = Signature::tls_deserialize(bytes)?;
        let confirmation_tag = if matches!(content_type, ContentType::Commit) {
            Some(ConfirmationTag::tls_deserialize(bytes)?)
        } else {
            None
        };
        Ok(Self {
            signature,
            confirmation_tag,
        })
    }
}

/// 6 Message Framing
///
/// ```c
/// // draft-ietf-mls-protocol-17
///
/// struct {
///     WireFormat wire_format;
///     FramedContent content;
///     FramedContentAuthData auth;
/// } AuthenticatedContent;
/// ```
#[derive(Debug, Clone, TlsSerialize, TlsSize)]
pub(crate) struct AuthenticatedContent {
    pub(super) wire_format: WireFormat,
    pub(super) content: FramedContent,
    pub(super) auth: FramedContentAuthData,
}

impl Size for FramedContentAuthData {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.signature.tls_serialized_len()
            + if let Some(confirmation_tag) = &self.confirmation_tag {
                confirmation_tag.tls_serialized_len()
            } else {
                0
            }
    }
}

impl TlsSerializeTrait for FramedContentAuthData {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.signature.tls_serialize(writer)?;
        written += if let Some(confirmation_tag) = &self.confirmation_tag {
            confirmation_tag.tls_serialize(writer)?
        } else {
            0
        };
        Ok(written)
    }
}
