//! # OpenMLS Errors
//!
//! Each module has their own errors it is returning. This module will defines
//! helper macros and functions to define OpenMLS errors.
//!
//! TODO: define global enum with integer error codes for FFI usage.

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
                            $src_name::$var_name(e) => format!("{}: {}", $description, e._description()),
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

/// A wrapper struct for an arbitrary error payload as byte vector. This can be
/// used when additional data is provided to the error.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorPayload(Vec<u8>);

impl From<Vec<u8>> for ErrorPayload {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}
impl From<&[u8]> for ErrorPayload {
    fn from(s: &[u8]) -> Self {
        Self(s.to_vec())
    }
}

impl std::error::Error for ErrorPayload {}

impl std::fmt::Display for ErrorPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.0))
    }
}

impl ErrorPayload {
    pub(crate) fn _description(&self) -> String {
        format!("{:?}", self.0.clone())
    }
}
