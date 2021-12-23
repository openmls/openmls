//! # Framing errors.
//!
//! `MlsPlaintextError` and `MlsCiphertextError` are thrown on errors
//! handling `MlsPlaintext` and `MlsCiphertext`.

use crate::credentials::CredentialError;
use crate::schedule::errors::MembershipKeyError;
use crate::tree::secret_tree::SecretTreeError;
use openmls_traits::types::CryptoError;
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
            MembershipKeyError(MembershipKeyError) = "See [`MembershipKeyError`](`MembershipKeyError`) for details.",
            CryptoError(CryptoError) = "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
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
            CryptoError(CryptoError) = "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
            SenderError(SenderError) = "See [`SenderError`] for details.",
        }
    }
}

implement_error! {
    pub enum SenderError {
        NotAMember = "The requested client is not a member of the group.",
        NotAPreConfigured = "The requested sender is not a preconfigured one.",
        UnknownSender = "Unknown sender",
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

implement_error! {
    pub enum ValidationError {
        Simple {
            NotAnApplicationMessage = "The MlsPlaintext message is not an application message.",
            NotACommit = "The MlsPlaintext message is not a Commit despite the sender begin of type NewMember.",
            NoPath = "The Commit doesn't have a path despite the sender being of type NewMember.",
            UnencryptedApplicationMessage = "The MlsPlaintext contains an application message but was not encrypted.",
            UnknownSender = "Sender is not part of the group",
            MissingMembershipTag = "The membership tag is missing.",
            MissingConfirmationTag = "The confirmation tag is missing.",
            WrongWireFormat = "Wrong wire format.",
            LibraryError = "A library error occured",
        }
        Complex {
            CodecError(TlsCodecError) = "TLS Codec error",
            CredentialError(CredentialError) = "See [`CredentialError`](`crate::credentials::CredentialError`) for details.",
            MlsPlaintextError(MlsPlaintextError) = "See [`MlsPlaintextError`](`MlsPlaintextError`) for details.",
            MlsCiphertextError(MlsCiphertextError) = "See [`MlsCiphertextError`](`MlsCiphertextError`) for details.",
        }
    }
}

implement_error! {
    pub enum MlsMessageError {
        DecodingError = "The message could not be decoded.",
        EncodingError = "The message could not be encoded.",
        NotAMember = "The requested client is not a member of the group.",
        NotAPreConfigured = "The requested sender is not a preconfigured one.",
        UnknownSender = "Unknown sender",
    }
}
