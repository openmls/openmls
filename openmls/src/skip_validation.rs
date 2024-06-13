//! This module contains helpers for skipping validation. It is built such that setting the flag to
//! disable validation can only by set when the "test-utils" feature is enabled.
//! This module is used in two places, and they use different parts of it.
//! Code that performs validation and wants to check whether a check is disabled only uses the
//! [`is_disabled`] submodule. It contains getter functions that read the current state of the
//! flag.
//! Test code that disables checks uses the code in the [`checks`] submodule. It contains a module
//! for each check that can be disabled, and a getter for a handle, protected by a [`Mutex`]. This
//! is done because the flag state is shared between tests, and tests that set and unset the same
//! tests are not safe to run concurrently.
//! For example, a test could cann [`checks::confirmation_tag::handle`] to get a handle to disable
//! and re-enable the validation of confirmation tags.

#[cfg(feature = "test-utils")]
use std::sync::atomic::AtomicBool;

pub(crate) mod is_disabled {
    use super::checks::*;

    pub(crate) fn confirmation_tag() -> bool {
        confirmation_tag::FLAG.load(core::sync::atomic::Ordering::Relaxed)
    }
}

/// Contains the flags and functions that return handles to control them.
pub(crate) mod checks {
    #[cfg(feature = "test-utils")]
    use super::SkipValidationHandle;

    /// Disables validation of the confirmation_tag.
    pub(crate) mod confirmation_tag {
        use std::sync::atomic::AtomicBool;

        #[cfg(feature = "test-utils")]
        use super::SkipValidationHandle;

        #[cfg(feature = "test-utils")]
        use once_cell::sync::Lazy;

        #[cfg(feature = "test-utils")]
        use std::sync::{Mutex, MutexGuard};

        #[cfg(feature = "test-utils")]
        /// The name of the check that can be skipped here
        const NAME: &str = "confirmation_tag";

        /// A way of disabling verification and validation of confirmation tags.
        pub(in crate::skip_validation) static FLAG: AtomicBool = AtomicBool::new(false);

        /// A mutex needed to run tests that use this flag sequentially
        #[cfg(feature = "test-utils")]
        pub static MUTEX: Lazy<Mutex<SkipValidationHandle>> =
            Lazy::new(|| Mutex::new(SkipValidationHandle::new_confirmation_tag_handle()));

        /// Takes the mutex and returns the control handle to the validation skipper
        #[cfg(feature = "test-utils")]
        pub(crate) fn handle() -> MutexGuard<'static, SkipValidationHandle> {
            MUTEX
                .lock()
                .unwrap_or_else(|e| panic!("error taking skip-validation mutex for '{NAME}': {e}"))
        }

        #[cfg(feature = "test-utils")]
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

/// Contains a reference to a flag. Provides convenience functions to set and clear the flag.
#[derive(Clone, Copy, Debug)]
#[cfg(feature = "test-utils")]
pub(crate) struct SkipValidationHandle {
    name: &'static str,
    flag: &'static AtomicBool,
}

#[cfg(feature = "test-utils")]
impl SkipValidationHandle {
    /// Disables validation for the check controlled by this handle
    #[cfg(feature = "test-utils")]
    pub(crate) fn disable_validation(self) {
        self.flag.store(true, core::sync::atomic::Ordering::Relaxed);
    }

    /// Enables validation for the check controlled by this handle
    pub(crate) fn enable_validation(self) {
        self.flag
            .store(false, core::sync::atomic::Ordering::Relaxed);
    }
}
