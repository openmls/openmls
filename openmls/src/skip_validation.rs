use once_cell::sync::Lazy;
use std::sync::{atomic::AtomicBool, Mutex};

pub(crate) mod is_disabled {
    use super::checks::*;

    pub(crate) fn confirmation_tag() -> bool {
        let value = confirmation_tag::FLAG.load(core::sync::atomic::Ordering::Relaxed);
        println!("READING FLAG: ATOMIC BOOL 'confirmation_tag' HAS VALUE {value}");
        value
    }
}

pub(crate) mod checks {
    use super::*;

    pub(crate) mod confirmation_tag {
        use std::sync::MutexGuard;

        use super::*;

        const NAME: &str = "confirmation_tag";

        /// A way of disabling verification and validation of confirmation tags.
        pub(in crate::skip_validation) static FLAG: AtomicBool = AtomicBool::new(false);

        /// A mutex needed to run tests that use this flag sequentially
        #[cfg(feature = "test-utils")]
        pub static MUTEX: Lazy<Mutex<SkipValidationHandle>> =
            Lazy::new(|| Mutex::new(SkipValidationHandle::new_confirmation_tag_handle()));

        /// takes the mutex and returns the control handle to the validation skipper
        #[cfg(feature = "test-utils")]
        pub(crate) fn handle() -> MutexGuard<'static, SkipValidationHandle> {
            MUTEX
                .lock()
                .unwrap_or_else(|e| panic!("error taking skip-validation mutex for '{NAME}': {e}"))
        }

        impl SkipValidationHandle {
            pub(in crate::skip_validation) fn new_confirmation_tag_handle() -> Self {
                Self {
                    name: NAME,
                    flag: &FLAG,
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SkipValidationHandle {
    name: &'static str,
    flag: &'static AtomicBool,
}

impl SkipValidationHandle {
    pub(crate) fn disable_validation(self) {
        println!("DISABLING VALIDATION OF '{}'", self.name);
        self.flag.store(true, core::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn enable_validation(self) {
        println!("ENABLING VALIDATION OF  '{}'", self.name);
        self.flag
            .store(false, core::sync::atomic::Ordering::Relaxed);
    }
}
