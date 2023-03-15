// === The folowing functions aren't necessarily cryptographically secure!

#[cfg(any(feature = "test-utils", test))]
use rand::{rngs::OsRng, RngCore};

#[cfg(any(feature = "test-utils", test))]
pub fn random_u32() -> u32 {
    OsRng.next_u32()
}

#[cfg(any(feature = "test-utils", test))]
pub fn random_u64() -> u64 {
    OsRng.next_u64()
}

#[cfg(any(feature = "test-utils", test))]
pub fn random_u8() -> u8 {
    let mut b = [0u8; 1];
    OsRng.fill_bytes(&mut b);
    b[0]
}

pub(crate) fn zero(length: usize) -> Vec<u8> {
    vec![0u8; length]
}

// With the crypto-debug feature enabled sensitive crypto parts can be logged.
#[cfg(feature = "crypto-debug")]
macro_rules! log_crypto {
    (debug, $($arg:tt)*) => ({
        log::debug!($($arg)*);
    });
    (trace, $($arg:tt)*) => ({
        log::trace!($($arg)*);
    })
}

// With the content-debug feature enabled sensitive message content parts can be logged.
#[cfg(feature = "content-debug")]
macro_rules! log_content {
    (debug, $($arg:tt)*) => ({
        log::debug!($($arg)*);
    });
    (trace, $($arg:tt)*) => ({
        log::trace!($($arg)*);
    })
}

#[cfg(not(feature = "crypto-debug"))]
macro_rules! log_crypto {
    (debug, $($arg:tt)*) => {{}};
    (trace, $($arg:tt)*) => {{}};
}

#[cfg(not(feature = "content-debug"))]
macro_rules! log_content {
    (debug, $($arg:tt)*) => {{}};
    (trace, $($arg:tt)*) => {{}};
}
