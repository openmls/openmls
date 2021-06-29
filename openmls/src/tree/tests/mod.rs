//! Tree unit tests.

#[cfg(any(feature = "expose-test-vectors", test))]
pub mod kat_encryption;
#[cfg(any(feature = "expose-test-vectors", test))]
pub mod kat_treemath;

#[cfg(test)]
mod test_hashes;
#[cfg(test)]
mod test_index;
#[cfg(test)]
mod test_path_keys;
#[cfg(test)]
mod test_private_tree;
#[cfg(test)]
mod test_resolution;
#[cfg(test)]
mod test_secret_tree;
#[cfg(test)]
mod test_treemath;
#[cfg(test)]
mod test_util;
