//! # OpenMLS Errors
//!
//! Each module has their own errors it is returning. This module will defines
//! helper macros and functions to define OpenMLS errors.
//!
//! ## Error handling
//!
//! Most function calls in the library return a `Result` and can therefore surface errors to the library consumer.
//! Errors can have different sources, depending on their nature. The following list explains the different error sources and how to handle them:
//!
//! ### Errors in dependencies
//!
//! The OpenMLS library relies on external dependencies for cryptographic primitives and storage of cryptographic key material. See the traits in the [User Manual] for more details on the dependencies.
//! When an unexpected error occurs in one of those dependencies, it is usually surfaced as a `LibraryError` to the consumer.
//!
//! ### Errors induced by wrong API use
//!
//! Whenever the caller calls an OpenMLS function with invalid input, an error is returned. Examples of wrong input can be: Adding a member twice to a group, interacting with an inactive group, removing inexistent
//! members from a group, etc. The precise error message depends on the function called, and the error will typically be an `enum` with explicit variants that state the reason for the error.
//! Consumers can branch on the variants of the `enum` and take action accordingly.
//!
//! ### Errors induced by processing invalid payload
//!
//! The library processes external payload in the form of messages sent over a network, or state loaded from disk. In both cases, multi-layered checks need to be done to make sure the payload
//! is syntactically and semantically correct. The syntax checks typically all happen at the serialization level and get detected early on. Semantic validation is more complex because data needs to be evaluated
//! in context. You can find more details about validation in the validation chapter of the [User Manual].
//! These errors are surfaced to the consumer at various stages of the processing, and the processing is aborted for the payload in question. Much like errors induced by wrong API usage, these errors are `enums` that
//! contain explicit variants for every error type. Consumers can branch on these variants to take action according to the specific error.
//!
//! ### Correctness errors in the library itself
//!
//! While the library has good test coverage in the form of unit & integration tests, theoretical correctness errors cannot be completely excluded. Should such an error occur, consumers will get
//! a `LibraryError` as a return value that contains backtraces indicating where in the code the error occurred and a short string for context. These details are important for debugging the library in such a case.
//! Consumers should save this information.
//!
//! All errors derive [`thiserror::Error`](https://docs.rs/thiserror/latest/thiserror/) as well as
//! [`Debug`](`std::fmt::Debug`), [`PartialEq`](`std::cmp::PartialEq`), and [`Clone`](`std::clone::Clone`).

use openmls_traits::types::CryptoError;
use std::fmt::Display;
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
/// **CryptoError**
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
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub struct LibraryError {
    internal: InternalLibraryError,
}

impl LibraryError {
    /// A custom error (typically to avoid an unwrap())
    pub(crate) fn custom(s: &'static str) -> Self {
        #[cfg(feature = "backtrace")]
        let display_string = format!(
            "Error description: {s}\n Backtrace:\n{:?}",
            backtrace::Backtrace::new()
        );
        #[cfg(not(feature = "backtrace"))]
        let display_string = format!("Error description: {s}");

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
#[derive(Error, PartialEq, Eq, Clone)]
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

impl std::fmt::Debug for InternalLibraryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InternalLibraryError::MissingBoundsCheck(e) => f
                .debug_struct("InternalLibraryError")
                .field("MissingBoundsCheck", e)
                .finish(),
            InternalLibraryError::CryptoError(e) => f
                .debug_struct("InternalLibraryError")
                .field("CryptoError", e)
                .finish(),
            InternalLibraryError::Custom(s) => writeln!(f, "InternalLibraryError: {s}"),
        }
    }
}

/// A wrapper struct for an error string. This can be used when no complex error
/// variant is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
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
