//! # OpenMLS Errors
//!
//! Each module has their own errors it is returning. This module will defines
//! helper macros and functions to define OpenMLS errors.
use std::fmt::Display;

use backtrace::Backtrace;
// Re-export errors.
pub use crate::treesync::errors::{ApplyUpdatePathError, PublicTreeError};
use openmls_traits::types::CryptoError;
use thiserror::Error;
use tls_codec::Error as TlsCodecError;

/// Generic error type that indicates unrecoverable errors in the library.
///
/// This error has 3 subtypes:
///
/// **MissingBoundsCheck**
///
/// This error is returned when the library tries to serialize data that is too big for the
/// MLS structs. In particular, when element lists contain more elements than the theoretical maximum
/// defined in the spec, the serialization will fail. This should not happen when all input values are checked.
///
/// **CryptoEror**
///
/// This error is returned if the underlying crypto provider encountered an unexpected error. Possible reasons
/// for this could be: the implementation of the crypto provider is not correct, the key material is not correct,
/// the crypto provider does not support all functions required. Another reason could be that the OpenMLS library
/// does not use the crypto provider API correctly.
///
/// **Custom**
///
/// This error is returned in situations where the implementation would otherwise use an `unwrap()`.
/// If applications receive this error, it clearly indicates an implementation mistake in OpenMLS. The error
/// includes a string that can give some more context about where the error originated and helps debugging.
///
/// In all cases, when a `LibraryError` is returned, applications should try to recover gracefully from it.
/// It is recommended to log the error for potential debugging.
#[derive(Error, Debug, PartialEq, Clone)]
pub struct LibraryError {
    internal: InternalLibraryError,
}

impl LibraryError {
    /// A custom error (typically to avoid an unwrap())
    pub(crate) fn custom(s: &'static str) -> Self {
        let bt = Backtrace::new();
        let display_string = format!("Error description: {}\n Backtrace:\n{:?}", s, bt);
        Self {
            internal: InternalLibraryError::Custom(display_string),
        }
    }

    /// Used when encoding doesn't work because of missing bound checks
    pub(crate) fn missing_bound_check(e: TlsCodecError) -> Self {
        Self {
            internal: InternalLibraryError::MissingBoundsCheck(e),
        }
    }

    /// Used when the crypto provider returns an unexpected error
    pub(crate) fn unexpected_crypto_error(e: CryptoError) -> Self {
        Self {
            internal: InternalLibraryError::CryptoError(e),
        }
    }
}

impl Display for LibraryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.internal)
    }
}

/// Internal enum to differentiate between the different types of library errors
#[derive(Error, Debug, PartialEq, Clone)]
enum InternalLibraryError {
    /// See [`TlsCodecError`] for more details.
    #[error(transparent)]
    MissingBoundsCheck(#[from] TlsCodecError),
    /// See [`CryptoError`] for more details.
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
    #[error("Custom library error: {0}")]
    Custom(String),
}

/// A wrapper struct for an error string. This can be used when no complex error
/// variant is needed.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorString(String);

impl From<String> for ErrorString {
    fn from(s: String) -> Self {
        Self(s)
    }
}
impl From<&str> for ErrorString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::error::Error for ErrorString {}

impl std::fmt::Display for ErrorString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl ErrorString {
    pub(crate) fn _description(&self) -> String {
        self.0.clone()
    }
}

/*

Note to maintainers

The thiserror crate does not add any documentation to enum variants and this needs to be done manually.
The best way to do this if you don't want to duplicate the string manually is to use the following regex:

Add comments for naked variants:

 ([,|{])\n(\s+)#\[error\("([a-z0-9 .,-_'^:]+)"\)\]

 $1
 $2/// $3
 $2#[error("$3")]

 Add comments for nested variants:

 ([,|{])\n([\s]+)#\[error\(transparent\)\]\n[\s]+(([A-Z][a-z0-9]+)+)\(#\[from\] (([A-Z][a-z0-9]+)+)\)

 $1
 $2/// See [`$5`] for more details.
 $2#[error(transparent)]
 $2$3(#[from] $5)

 The above was tested in VSCode, but should be easily adaptable to other tools.

*/
