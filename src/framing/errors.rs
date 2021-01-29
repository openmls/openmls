//! # Framing errors.
//!
//! `MLSPlaintextError` and `MLSCiphertextError` are thrown on errors
//! handling `MLSPlaintext` and `MLSCiphertext`.

use crate::codec::CodecError;
use crate::credentials::CredentialError;
use crate::tree::secret_tree::SecretTreeError;

implement_error! {
    pub enum MLSPlaintextError {
        NotAnApplicationMessage = "The MLSPlaintext message is not an application message.",
        UnknownSender = "Sender is not part of the group",
        InvalidSignature = "The MLSPlaintext signature is invalid",
        InvalidMembershipTag = "The MLSPlaintext membership tag is invalid",
    }
}

implement_error! {
    pub enum MLSCiphertextError {
        Simple {
            InvalidContentType = "The MLSCiphertext has an invalid content type.",
            GenerationOutOfBound = "Couldn't find a ratcheting secret for the given sender and generation.",
            EncryptionError = "An error occured while encrypting.",
            DecryptionError = "An error occured while decrypting.",
        }
        Complex {
            PlaintextError(MLSPlaintextError) = "MLSPlaintext error",
            SecretTreeError(SecretTreeError) = "SecretTree error",
            CodecError(CodecError) = "Codec error",
        }
    }
}

implement_error! {
    pub enum VerificationError {
        Simple {
            MissingMembershipTag = "The MLSPlaintext membership tag is missing",
            InvalidMembershipTag = "The MLSPlaintext membership tag is invalid",
        }
        Complex {
            CodecError(CodecError) = "Codec error",
            CredentialError(CredentialError) = "Credential error",
        }
    }
}
