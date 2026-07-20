use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

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
#[derive(
    Debug, PartialEq, Eq, Clone, TlsSerialize, TlsSize, TlsDeserialize, TlsDeserializeBytes,
)]
pub struct PrivateMessageIn {
    group_id: GroupId,
    epoch: GroupEpoch,
    content_type: ContentType,
    authenticated_data: VLBytes,
    encrypted_sender_data: VLBytes,
    ciphertext: VLBytes,
}
