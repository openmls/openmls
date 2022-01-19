//! # OpenMLS Errors
//!
//! Each module has their own errors it is returning. This module will defines
//! helper macros and functions to define OpenMLS errors.
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
/// TODO: #78
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
pub enum LibraryError {
    #[error(transparent)]
    MissingBoundsCheck(#[from] TlsCodecError),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
    #[error("Custom library error: {0}")]
    Custom(&'static str),
}

// Macro helpers

macro_rules! as_item {
    ($i:item) => {
        $i
    };
}
macro_rules! as_expr {
    ($e:expr) => {
        $e
    };
}

/// A macro implementing the boilerplate for OpenMLS error enums.
macro_rules! implement_error {
    // The first rule is for simple error types that don't hold payloads.
    (
        $visibility:vis enum $src_name:ident {
            $(
                $var_name:ident = $description:literal,
            )*
        }
    ) => {
        implement_error! {
                $visibility enum $src_name {
                    Simple {
                        $(
                            $var_name = $description,
                        )*
                    }
                    Complex {}
                }
        }
    };
    // This is for complex error types where every variant holds a payload.
    (
        $visibility:vis enum $src_name:ident {
            $(
                $var_name:ident$var_payload:tt = $description:literal,
            )*
        }
    ) => {
        implement_error! {
                $visibility enum $src_name {
                    Simple {}
                    Complex {
                        $(
                            $var_name$var_payload = $description,
                        )*
                    }
                }
        }
    };

    // This implements the actual logic and is used by both simple and complex
    // errors. When an error type needs both, they have to be marked accordingly.
    (
        $visibility:vis enum $src_name:ident {
            Simple {
                $(
                    $var_name_simple:ident = $description_simple:literal,
                )*
            }
            Complex {
                $(
                    $var_name:ident($var_payload:tt) = $description:literal,
                )*
            }
        }
    ) => {
        as_item!{
            #[derive(Debug, PartialEq, Clone)]
            $visibility enum $src_name {
                $(
                    #[doc = $description]
                    $var_name($var_payload),
                )*
                $(
                    #[doc = $description_simple]
                    $var_name_simple,
                )*
            }
        }

        $(
            impl From<$var_payload> for $src_name {
                fn from(e: $var_payload) -> Self {
                    as_expr! {
                        $src_name::$var_name(e)
                    }
                }
            }
        )*

        impl std::fmt::Display for $src_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_fmt(format_args!("{:?}: {}", self, self._description()))
            }
        }

        impl std::error::Error for $src_name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                as_expr! {
                    match self {
                        $(
                            $src_name::$var_name(e) => Some(e),
                        )*
                        $(
                            $src_name::$var_name_simple => None,
                        )*
                    }
                }
            }
        }

        impl $src_name {
            pub(crate) fn _description(&self) -> String {
                as_expr! {
                    match self {
                        $(
                            $src_name::$var_name(e) => format!("{}: {}", $description, e),
                        )*
                        $(
                            $src_name::$var_name_simple => format!("{}", $description_simple),
                        )*
                    }
                }
            }
        }
    };
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
