//! # Framing errors.
//!
//! `MlsPlaintextError` and `MlsCiphertextError` are thrown on errors
//! handling `MlsPlaintext` and `MlsCiphertext`.

use crate::codec::CodecError;
use crate::credentials::CredentialError;
use crate::tree::secret_tree::SecretTreeError;

implement_error! {
    pub enum MlsPlaintextError {
        NotAnApplicationMessage = "The MlsPlaintext message is not an application message.",
        UnknownSender = "Sender is not part of the group",
        InvalidSignature = "The MlsPlaintext signature is invalid",
        InvalidMembershipTag = "The MlsPlaintext membership tag is invalid",
    }
}

implement_error! {
    pub enum MlsCiphertextError {
        Simple {
            InvalidContentType = "The MlsCiphertext has an invalid content type.",
            GenerationOutOfBound = "Couldn't find a ratcheting secret for the given sender and generation.",
            EncryptionError = "An error occurred while encrypting.",
            DecryptionError = "An error occurred while decrypting.",
        }
        Complex {
            PlaintextError(MlsPlaintextError) = "MlsPlaintext error",
            SecretTreeError(SecretTreeError) = "SecretTree error",
            CodecError(CodecError) = "Codec error",
        }
    }
}

implement_error! {
    pub enum VerificationError {
        Simple {
            MissingMembershipTag = "The MlsPlaintext membership tag is missing",
            InvalidMembershipTag = "The MlsPlaintext membership tag is invalid",
        }
        Complex {
            CodecError(CodecError) = "Codec error",
            CredentialError(CredentialError) = "Credential error",
        }
    }
}
