/// Virtual-clients-draft derivation chain: types and helpers for the
/// per-commit material the application supplies on the sender side and
/// the receiver re-derives.
#[cfg(feature = "virtual-clients-draft")]
pub mod vc_derivation_info;

/// Virtual Client Operation Secret Tree (mls-virtual-clients draft): a
/// per-emulation-epoch secret tree whose leaves expand into one operation
/// ratchet per operation type.
#[cfg(feature = "virtual-clients-draft")]
pub mod vc_operation_tree;
