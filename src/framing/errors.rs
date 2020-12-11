//! # Framing errors.
//!
//! `MLSPlaintextError` and `MLSCiphertextError` are thrown on errors
//! handling `MLSPlaintext` and `MLSCiphertext`.

implement_error! {
    pub enum MLSPlaintextError {
        NotAnApplicationMessage = "The MLSPlaintext message is not an application message.",
    }
}

implement_error! {
    pub enum MLSCiphertextError {
        InvalidContentType = "The MLSCiphertext has an invalid content type.",
        GenerationOutOfBound = "Couldn't find a ratcheting secret for the given sender and generation.",
        UnknownSender = "Sender is not part of the group",
    }
}
