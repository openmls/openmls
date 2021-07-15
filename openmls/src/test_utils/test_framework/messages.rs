//! This module contains code to convert messages between the
//! `MlsMessage`/`MlsMessageIn` formats as used by the Managed API, which the
//! Clients are built on and the `DsMlsMessage`, which includes the message type
//! in its serialized form.

use crate::{
    group::MlsMessageIn,
    prelude::{MlsCiphertext, VerifiableMlsPlaintext},
};

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

impl<'a> tls_codec::Size for MlsMessageIn<'a> {
    fn tls_serialized_len(&self) -> usize {
        MessageType::MlsCiphertext.tls_serialized_len()
            + match self {
                MlsMessageIn::Plaintext(p) => p.tls_serialized_len(),
                MlsMessageIn::Ciphertext(c) => c.tls_serialized_len(),
            }
    }
}

impl<'a> tls_codec::Serialize for MlsMessageIn<'a> {
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

impl<'a> tls_codec::Deserialize for MlsMessageIn<'a> {
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
