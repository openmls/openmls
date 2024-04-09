use crate::Signature;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

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
#[derive(
    PartialEq,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    TlsSize,
    TlsDeserializeBytes,
    TlsDeserialize,
    TlsSerialize,
)]
pub struct FramedContentAuthData {
    pub signature: Signature,
    pub confirmation_tag: Option<ConfirmationTag>,
}

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
pub struct ConfirmationTag(pub Mac);

// Constant time comparison.
impl PartialEq for Mac {
    fn eq(&self, other: &Mac) -> bool {
        equal_ct(self.mac_value.as_slice(), other.mac_value.as_slice())
    }
}

/// 7.1 Content Authentication
///
/// opaque MAC<V>;
#[derive(
    Debug, Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
pub struct Mac {
    pub mac_value: VLBytes,
}

/// Compare two byte slices in a way that's hopefully not optimised out by the
/// compiler.
#[inline(never)]
fn equal_ct(a: &[u8], b: &[u8]) -> bool {
    let mut diff = 0u8;
    for (l, r) in a.iter().zip(b.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}
