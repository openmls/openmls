//! # Crypto errors
//!
//! This file defines a set of errors thrown by crypto operations.

use std::error::Error;

#[derive(Debug)]
pub(crate) enum HKDFError {
    InvalidLength,
}

#[derive(Debug, PartialEq)]
pub(crate) enum HpkeError {
    DecryptionError,
}

#[derive(Debug)]
pub(crate) enum CryptoError {
    CryptoLibraryError,
}

implement_enum_display!(HKDFError);
implement_enum_display!(CryptoError);

impl Error for HKDFError {
    fn description(&self) -> &str {
        match self {
            Self::InvalidLength => "The HKDF output is empty.",
        }
    }
}

impl Error for CryptoError {
    fn description(&self) -> &str {
        match self {
            Self::CryptoLibraryError => "Unrecoverable error in the crypto library.",
        }
    }
}
