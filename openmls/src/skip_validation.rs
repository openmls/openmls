//! This module contains helpers for skipping validation. It is built such that setting the flag to
//! disable validation can only by set when the "test-utils" feature is enabled.
//! This module is used in two places, and they use different parts of it.
//! Code that performs validation and wants to check whether a check is disabled only uses the
//! [`is_disabled`] submodule. It contains getter functions that read the current state of the
//! flag.
//! Test code that disables checks uses the code in the [`checks`] submodule. It contains a module
//! for each check that can be disabled, and a getter for a handle, protected by a [`Mutex`]. This
//! is done because the flag state is shared between tests, and tests that set and unset the same
//! checks are not safe to run concurrently.
//! For example, a test could cann [`checks::confirmation_tag::handle`] to get a handle to disable
//! and re-enable the validation of confirmation tags.

pub(crate) mod is_disabled {
    use super::checks::*;

    pub(crate) fn confirmation_tag() -> bool {
        confirmation_tag::FLAG.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn leaf_node_lifetime() -> bool {
        leaf_node_lifetime::FLAG.load(core::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
use std::sync::atomic::AtomicBool;

/// Contains a reference to a flag. Provides convenience functions to set and clear the flag.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub struct SkipValidationHandle {
    // we keep this field so we can see which handle this is when printing it. we don't need it otherwise
    #[allow(dead_code)]
    name: &'static str,
    flag: &'static AtomicBool,
}

/// Contains the flags and functions that return handles to control them.
pub(crate) mod checks {
    /// Disables validation of the confirmation_tag.
    pub(crate) mod confirmation_tag {
        use std::sync::atomic::AtomicBool;

        /// A way of disabling verification and validation of confirmation tags.
        pub(in crate::skip_validation) static FLAG: AtomicBool = AtomicBool::new(false);

        #[cfg(test)]
        pub(crate) use lock::handle;

        #[cfg(test)]
        mod lock {
            use super::FLAG;
            use crate::skip_validation::SkipValidationHandle;
            use once_cell::sync::Lazy;
            use std::sync::{Mutex, MutexGuard};

            /// The name of the check that can be skipped here
            const NAME: &str = "confirmation_tag";

            /// A mutex needed to run tests that use this flag sequentially
            static MUTEX: Lazy<Mutex<SkipValidationHandle>> =
                Lazy::new(|| Mutex::new(SkipValidationHandle::new_confirmation_tag_handle()));

            /// Takes the mutex and returns the control handle to the validation skipper
            pub(crate) fn handle() -> MutexGuard<'static, SkipValidationHandle> {
                MUTEX.lock().unwrap_or_else(|e| {
                    panic!("error taking skip-validation mutex for '{NAME}': {e}")
                })
            }

            impl SkipValidationHandle {
                pub fn new_confirmation_tag_handle() -> Self {
                    Self {
                        name: NAME,
                        flag: &FLAG,
                    }
                }
            }
        }
    }

    /// Disables validation of leaf node lifetimes
    pub(crate) mod leaf_node_lifetime {
        use std::sync::atomic::AtomicBool;

        /// A way of disabling verification and validation of leaf node lifetimes.
        pub(in crate::skip_validation) static FLAG: AtomicBool = AtomicBool::new(false);

        #[cfg(test)]
        pub(crate) use lock::handle;

        #[cfg(test)]
        mod lock {
            use super::FLAG;
            use crate::skip_validation::SkipValidationHandle;
            use once_cell::sync::Lazy;
            use std::sync::{Mutex, MutexGuard};

            /// The name of the check that can be skipped here
            const NAME: &str = "leaf_node_lifetime";

            /// A mutex needed to run tests that use this flag sequentially
            static MUTEX: Lazy<Mutex<SkipValidationHandle>> =
                Lazy::new(|| Mutex::new(SkipValidationHandle::new_leaf_node_lifetime_handle()));

            /// Takes the mutex and returns the control handle to the validation skipper
            pub(crate) fn handle() -> MutexGuard<'static, SkipValidationHandle> {
                MUTEX.lock().unwrap_or_else(|e| {
                    panic!("error taking skip-validation mutex for '{NAME}': {e}")
                })
            }

            impl SkipValidationHandle {
                pub fn new_leaf_node_lifetime_handle() -> Self {
                    Self {
                        name: NAME,
                        flag: &FLAG,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
impl SkipValidationHandle {
    /// Disables validation for the check controlled by this handle
    pub fn disable_validation(self) {
        self.flag.store(true, core::sync::atomic::Ordering::Relaxed);
    }

    /// Enables validation for the check controlled by this handle
    pub fn enable_validation(self) {
        self.flag
            .store(false, core::sync::atomic::Ordering::Relaxed);
    }

    /// Runs function `f` with validation disabled
    pub fn with_disabled<R, F: FnMut() -> R>(self, mut f: F) -> R {
        self.disable_validation();
        let r = f();
        self.enable_validation();
        r
    }
}
