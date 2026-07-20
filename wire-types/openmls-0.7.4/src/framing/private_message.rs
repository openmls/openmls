use tls_codec::{TlsSerialize, TlsSize};

use super::*;

/// `PrivateMessage` is the framing struct for an encrypted `PublicMessage`.
/// This message format is meant to be sent to and received from the Delivery
/// Service.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     ContentType content_type;
///     opaque authenticated_data<V>;
///     opaque encrypted_sender_data<V>;
///     opaque ciphertext<V>;
/// } PrivateMessage;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, TlsSerialize, TlsSize)]
pub struct PrivateMessage {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) content_type: ContentType,
    pub(crate) authenticated_data: VLBytes,
    pub(crate) encrypted_sender_data: VLBytes,
    pub(crate) ciphertext: VLBytes,
}

#[derive(TlsSerialize, TlsSize)]
pub(crate) struct PrivateContentAad<'a> {
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) content_type: ContentType,
    pub(crate) authenticated_data: VLByteSlice<'a>,
}
