//! # Framing errors.
//!
//! `MlsPlaintextError` and `MlsCiphertextError` are thrown on errors
//! handling `MlsPlaintext` and `MlsCiphertext`.

use crate::credentials::CredentialError;
use crate::tree::secret_tree::SecretTreeError;
use tls_codec::Error as TlsCodecError;

implement_error! {
    pub enum MlsPlaintextError {
        Simple {
            NotAnApplicationMessage = "The MlsPlaintext message is not an application message.",
            UnknownSender = "Sender is not part of the group",
            InvalidSignature = "The MlsPlaintext signature is invalid",
            InvalidMembershipTag = "The MlsPlaintext membership tag is invalid",
        }
        Complex {
            CodecError(TlsCodecError) = "TLS Codec error",
            CredentialError(CredentialError) = "See [`CredentialError`](`crate::credentials::CredentialError`) for details.",
            VerificationError(VerificationError) = "See [`VerificationError`](`VerificationError`) for details.",
        }
    }
}

implement_error! {
    pub enum MlsCiphertextError {
        Simple {
            InvalidContentType = "The MlsCiphertext has an invalid content type.",
            GenerationOutOfBound = "Couldn't find a ratcheting secret for the given sender and generation.",
            EncryptionError = "An error occurred while encrypting.",
            DecryptionError = "An error occurred while decrypting.",
            WrongWireFormat = "The WireFormat was MLSPlaintext.",
        }
        Complex {
            PlaintextError(MlsPlaintextError) = "MlsPlaintext error",
            SecretTreeError(SecretTreeError) = "SecretTree error",
            CodecError(TlsCodecError) = "TLS codec error",
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
            CredentialError(CredentialError) = "Credential error",
        }
    }
}
