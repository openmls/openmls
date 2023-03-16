//! A framework to create integration tests of the "raw" core_group API.
//! # Test utils
//!
//! Most tests require to set up groups, clients, credentials, and identities.
//! This module implements helpers to do that.

#[cfg(any(feature = "test-utils", test))]
fn log2(x: u32) -> usize {
    if x == 0 {
        return 0;
    }
    let mut k = 0;
    while (x >> k) > 0 {
        k += 1
    }
    k - 1
}

#[cfg(any(feature = "test-utils", test))]
pub(crate) fn root(size: u32) -> u32 {
    (1 << log2(size)) - 1
}
