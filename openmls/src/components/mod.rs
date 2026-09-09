/// Virtual-clients-draft derivation chain: types and helpers for the
/// per-commit material the application supplies on the sender side and
/// the receiver re-derives.
#[cfg(feature = "virtual-clients-draft")]
pub mod vc_derivation_info;

/// Virtual Client Operation Secret Tree (mls-virtual-clients draft): a
/// per-derivation-epoch secret tree whose leaves expand into one operation
/// ratchet per operation type.
#[cfg(feature = "virtual-clients-draft")]
pub mod vc_operation_tree;

/// Application secrets of a virtual client (mls-virtual-clients draft).
#[cfg(feature = "virtual-clients-draft")]
pub mod vc_application_secret;

/// Virtual-clients commit data (mls-virtual-clients draft): the Safe AAD item a
/// virtual client attaches to a commit to declare its in-use derivation epochs
/// and the actions the commit performs.
#[cfg(feature = "virtual-clients-draft")]
pub mod vc_commit_data;
