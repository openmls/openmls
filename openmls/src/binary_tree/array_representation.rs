#[cfg(any(feature = "test-utils", test))]
pub mod kat_treemath;

pub(crate) mod diff;
pub(crate) mod tree;

#[allow(dead_code)]
/// FIXME: There's some dead code in treemath that will be used in treesync in
/// the future.
pub(super) mod treemath;
