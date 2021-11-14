//! This module contains code to serialize `MlsMessage`/`MlsMessageIn` as used
//! by the Managed API, which the Clients are built on. These
//! serialization/deserialization functions attach an additional byte that
//! indicates if a message is a plaintext or a ciphertext

//use crate::prelude::{MlsCiphertext, MlsMessageIn, VerifiableMlsPlaintext};

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

/*
impl tls_codec::Size for MlsMessageIn {
    fn tls_serialized_len(&self) -> usize {
        MessageType::MlsCiphertext.tls_serialized_len()
            + match self {
                MlsMessageIn::Plaintext(p) => p.tls_serialized_len(),
                MlsMessageIn::Ciphertext(c) => c.tls_serialized_len(),
            }
    }
}

impl tls_codec::Serialize for MlsMessageIn {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written;
        match self {
            MlsMessageIn::Ciphertext(m) => {
                written = MessageType::MlsCiphertext.tls_serialize(writer)?;
                m.tls_serialize(writer)
            }
            MlsMessageIn::Plaintext(m) => {
                written = MessageType::MlsPlaintext.tls_serialize(writer)?;
                m.tls_serialize(writer)
            }
        }
        .map(|l| l + written)
    }
}

impl tls_codec::Deserialize for MlsMessageIn {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let msg_type = MessageType::tls_deserialize(bytes)?;
        Ok(match msg_type {
            MessageType::MlsCiphertext => {
                MlsMessageIn::Ciphertext(MlsCiphertext::tls_deserialize(bytes)?)
            }
            MessageType::MlsPlaintext => {
                MlsMessageIn::Plaintext(VerifiableMlsPlaintext::tls_deserialize(bytes)?)
            }
        })
    }
}
*/
