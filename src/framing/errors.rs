//! # Framing errors.
//!
//! `MLSPlaintextError` and `MLSCiphertextError` are thrown on errors
//! handling `MLSPlaintext` and `MLSCiphertext`.
use std::error::Error;

#[derive(Debug)]
#[repr(u16)]
pub enum MLSPlaintextError {
    /// This is not an application message.
    NotAnApplicationMessage = 0,
}
#[derive(Debug, PartialEq)]
#[repr(u16)]
pub enum MLSCiphertextError {
    /// Invalid content type in message.
    InvalidContentType = 1,

    /// Ratcheting secret generation is not found.
    GenerationOutOfBound = 2,

    /// Sender is not part of the group
    UnknownSender = 3,
}

implement_enum_display!(MLSPlaintextError);
implement_enum_display!(MLSCiphertextError);

impl Error for MLSPlaintextError {
    fn description(&self) -> &str {
        match self {
            Self::NotAnApplicationMessage => {
                "The MLSPlaintext message is not an application message."
            }
        }
    }
}

impl Error for MLSCiphertextError {
    fn description(&self) -> &str {
        match self {
            Self::InvalidContentType => "The MLSCiphertext has an invalid content type.",
            Self::GenerationOutOfBound => {
                "Couldn't find a ratcheting secret for the given sender and generation."
            }
            Self::UnknownSender => "The sender of the MLSCiphertext is not part of the group.",
        }
    }
}
