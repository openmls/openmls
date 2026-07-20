use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};
use crate::treesync::RatchetTreeIn;

/// # Ratchet Tree Extension.
///
/// The ratchet tree extension contains a list of (optional) [`Node`](crate::treesync::node::Node)s that
/// represent the public state of the tree in an MLS group.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// optional<Node> ratchet_tree<V>;
/// ```
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct RatchetTreeExtension {
    ratchet_tree: RatchetTreeIn,
}
