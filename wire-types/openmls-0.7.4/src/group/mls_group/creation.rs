use serde::{Deserialize, Serialize};

/// Verify or skip the validation of leaf node lifetimes in the ratchet tree
/// when joining a group.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeafNodeLifetimePolicy {
    /// Verify the lifetime of leaf nodes in the ratchet tree.
    ///
    /// **NOTE:** Only leaf nodes that have never been updated have a lifetime.
    #[default]
    Verify,

    /// Skip the verification of the lifeimte in leaf nodes in the ratchet tree.
    Skip,
}
