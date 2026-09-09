use tls_codec::{TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{binary_tree::LeafNodeIndex, components::vc_derivation_info::EpochId};

/// The coordinates of one application secret in a virtual client's operation
/// secret tree.
#[derive(Debug, Clone, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserializeBytes)]
pub struct VcApplicationSecretInfo {
    /// The derivation epoch the secret was taken from.
    pub epoch_id: EpochId,
    /// The sender's leaf index in the emulation group, identifying the
    /// application ratchet the generation was allocated from.
    pub leaf_index: LeafNodeIndex,
    /// The application-ratchet generation the sender consumed.
    pub generation: u32,
}
