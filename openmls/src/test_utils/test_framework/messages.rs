//! This module contains code to serialize `MlsMessage`/`MlsMessageIn` as used
//! by the MlsGroup API, which the Clients are built on. These
//! serialization/deserialization functions attach an additional byte that
//! indicates if a message is a plaintext or a ciphertext

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// Enum defining encodings for the different message types/
#[derive(Debug, Clone, Copy, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum MessageType {
    /// An MlsCiphertext message.
    MlsCiphertext = 0,

    /// An MlsPlaintext message.
    MlsPlaintext = 1,
}
