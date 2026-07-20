//! # MLS content authentication
//!
//! This module contains structs and implementation that pertain to content
//! authentication in MLS. Besides structs that directly represent structs in
//! the MLS specification, this module also contains
//! [`VerifiableAuthenticatedContentIn`], a wrapper struct which ensures that the
//! signatures are verified before the content of an MLS [`PrivateMessageIn`] or
//! [`PublicMessageIn`] can be accessed by processing functions of OpenMLS.

use std::io::Read;

use super::{mls_auth_content::*, mls_content_in::*, *};

#[cfg(doc)]
use super::{PrivateMessageIn, PublicMessageIn};

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
#[derive(Debug, Clone, TlsSize)]
pub(crate) struct AuthenticatedContentIn {
    pub(super) wire_format: WireFormat,
    pub(super) content: FramedContentIn,
    pub(super) auth: FramedContentAuthData,
}

/// Note: we can't `derive(tls_codec::Deserialize)` because [`FramedContentAuthData`] cannot
///       implement the usual `tls_codec::Deserialize` as it requires the content type as parameter.
impl tls_codec::Deserialize for AuthenticatedContentIn {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let content = FramedContentIn::tls_deserialize(bytes)?;
        // Here, content type is requires as parameter for deserialization.
        let auth = FramedContentAuthData::deserialize(bytes, content.body.content_type())?;

        Ok(Self {
            wire_format,
            content,
            auth,
        })
    }
}
