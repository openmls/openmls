//! # OpenMLS Delivery Service Library
//!
//! This library provides structs and necessary implementations to interact with
//! the OpenMLS DS.
//!
//! Clients are represented by the `ClientInfo` struct.

use openmls::prelude::*;

/// Information about a client.
/// To register a new client create a new `ClientInfo` and send it to
/// `/clients/register`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ClientInfo {
    pub client_name: String,
    pub key_packages: ClientKeyPackages,
    pub id: Vec<u8>,
    pub msgs: Vec<MlsMessage>,
    pub welcome_queue: Vec<Welcome>,
}

/// The DS returns a list of key packages for a client as `ClientKeyPackages`.
/// This is a tuple struct holding a vector of `(Vec<u8>, KeyPackage)` tuples,
/// where the first value is the key package hash (output of `KeyPackage::hash`)
/// and the second value is the corresponding key package.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ClientKeyPackages(pub Vec<(Vec<u8>, KeyPackage)>);

impl ClientInfo {
    /// Create a new `ClientInfo` struct for a given client name and vector of
    /// key packages with corresponding hashes.
    pub fn new(client_name: String, key_packages: Vec<(Vec<u8>, KeyPackage)>) -> Self {
        Self {
            client_name,
            id: key_packages[0].1.credential().identity().to_vec(),
            key_packages: ClientKeyPackages(key_packages),
            msgs: Vec::new(),
            welcome_queue: Vec::new(),
        }
    }

    /// The identity of a client is defined as the identity of the first key
    /// package right now.
    pub fn id(&self) -> &[u8] {
        self.id.as_slice()
    }
}

/// The DS returns a list of messages on `/recv/{name}`, which is a
/// `Vec<Message>`. A `Message` is either an `MLSMessage` or a `Welcome` message
/// (see OpenMLS) for details.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// An `MLSMessage` is either an OpenMLS `MlsCiphertext` or `MlsPlaintext`.
    MlsMessage(MlsMessage),

    /// An OpenMLS `Welcome` message.
    Welcome(Welcome),
}

/// Enum defining encodings for the different message types/
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum MessageType {
    /// An MlsCiphertext message.
    MlsCiphertext = 0,

    /// An MlsPlaintext message.
    MlsPlaintext = 1,

    /// A Welcome message.
    Welcome = 2,
}

/// An MLS group message.
/// This is an `MLSMessage` plus the list of recipients as a vector of client
/// names.
#[derive(Debug)]
pub struct GroupMessage {
    pub msg: MlsMessage,
    pub recipients: Vec<Vec<u8>>,
}

impl GroupMessage {
    /// Create a new `GroupMessage` taking an `MLSMessage` and slice of
    /// recipient names.
    pub fn new(msg: MlsMessage, recipients: &[Vec<u8>]) -> Self {
        Self {
            msg,
            recipients: recipients.to_vec(),
        }
    }

    /// Get the group ID as plain byte vector.
    pub fn group_id(&self) -> Vec<u8> {
        self.msg.group_id()
    }

    /// Get the epoch as plain u64.
    pub fn epoch(&self) -> u64 {
        self.msg.epoch()
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.msg.is_handshake_message()
    }
}

impl Codec for ClientKeyPackages {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(buffer)
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_packages = Vec::<(Vec<u8>, KeyPackage)>::decode(cursor)?;
        Ok(ClientKeyPackages(key_packages))
    }
}

impl Codec for ClientInfo {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.client_name.encode(buffer)?;
        self.key_packages.encode(buffer)
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let client_name = String::decode(cursor)?;
        let key_packages = Vec::<(Vec<u8>, KeyPackage)>::decode(cursor)?;
        Ok(Self::new(client_name, key_packages))
    }
}

impl Codec for MessageType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = u8::decode(cursor)?;
        match value {
            0 => Ok(Self::MlsCiphertext),
            1 => Ok(Self::MlsPlaintext),
            2 => Ok(Self::Welcome),
            _ => Err(CodecError::DecodingError),
        }
    }
}

impl Codec for Message {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Message::MlsMessage(m) => match m {
                MlsMessage::Ciphertext(m) => {
                    MessageType::MlsCiphertext.encode(buffer)?;
                    m.encode(buffer)?;
                }
                MlsMessage::Plaintext(m) => {
                    MessageType::MlsPlaintext.encode(buffer)?;
                    m.encode(buffer)?;
                }
            },
            Message::Welcome(m) => {
                MessageType::Welcome.encode(buffer)?;
                m.encode(buffer)?;
            }
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let msg_type = MessageType::decode(cursor)?;
        let msg = match msg_type {
            MessageType::MlsCiphertext => {
                Message::MlsMessage(MlsMessage::Ciphertext(MlsCiphertext::decode(cursor)?))
            }
            MessageType::MlsPlaintext => {
                Message::MlsMessage(MlsMessage::Plaintext(MlsPlaintext::decode(cursor)?))
            }
            MessageType::Welcome => Message::Welcome(Welcome::decode(cursor)?),
        };
        Ok(msg)
    }
}

impl Codec for GroupMessage {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match &self.msg {
            MlsMessage::Ciphertext(m) => {
                MessageType::MlsCiphertext.encode(buffer)?;
                m.encode(buffer)?;
            }
            MlsMessage::Plaintext(m) => {
                MessageType::MlsPlaintext.encode(buffer)?;
                m.encode(buffer)?;
            }
        }
        self.recipients.encode(buffer)
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let msg_type = MessageType::decode(cursor)?;
        let msg = match msg_type {
            MessageType::MlsCiphertext => MlsMessage::Ciphertext(MlsCiphertext::decode(cursor)?),
            MessageType::MlsPlaintext => MlsMessage::Plaintext(MlsPlaintext::decode(cursor)?),
            _ => return Err(CodecError::DecodingError),
        };

        let recipients = Vec::<Vec<u8>>::decode(cursor)?;
        Ok(Self { msg, recipients })
    }
}
