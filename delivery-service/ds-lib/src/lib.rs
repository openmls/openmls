//! # OpenMLS Delivery Service Library
//!
//! This library provides structs and necessary implementations to interact with
//! the OpenMLS DS.
//!
//! Clients are represented by the `ClientInfo` struct.

use openmls::{framing::VerifiableMlsPlaintext, prelude::*};

/// Information about a client.
/// To register a new client create a new `ClientInfo` and send it to
/// `/clients/register`.
#[derive(Debug, Default, Clone)]
pub struct ClientInfo<'a> {
    pub client_name: String,
    pub key_packages: ClientKeyPackages,
    pub id: Vec<u8>,
    pub msgs: Vec<DsMlsMessage<'a>>,
    pub welcome_queue: Vec<Welcome>,
}

/// The DS returns a list of key packages for a client as `ClientKeyPackages`.
/// This is a tuple struct holding a vector of `(Vec<u8>, KeyPackage)` tuples,
/// where the first value is the key package hash (output of `KeyPackage::hash`)
/// and the second value is the corresponding key package.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ClientKeyPackages(pub Vec<(Vec<u8>, KeyPackage)>);

impl<'a> ClientInfo<'a> {
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

/// Unified message type similar to the one in the managed group.
/// But this version only operates on [`VerifiableMlsPlaintext`].
#[derive(Debug, Clone)]
pub enum DsMlsMessage<'a> {
    /// An OpenMLS `MlsPlaintext`.
    Plaintext(VerifiableMlsPlaintext<'a>),

    /// An OpenMLS `MlsCiphertext`.
    Ciphertext(MlsCiphertext),
}

impl<'a> DsMlsMessage<'a> {
    /// Get the group id.
    pub fn group_id(&self) -> &[u8] {
        match self {
            DsMlsMessage::Plaintext(p) => p.payload().group_id(),
            DsMlsMessage::Ciphertext(c) => c.group_id.as_slice(),
        }
    }

    /// Get the epoch as plain u64.
    pub fn epoch(&self) -> u64 {
        match self {
            DsMlsMessage::Ciphertext(m) => m.epoch.0,
            DsMlsMessage::Plaintext(m) => m.payload().epoch().0,
        }
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        match self {
            DsMlsMessage::Ciphertext(m) => m.is_handshake_message(),
            DsMlsMessage::Plaintext(m) => m.payload().is_handshake_message(),
        }
    }
}

/// The DS returns a list of messages on `/recv/{name}`, which is a
/// `Vec<Message>`. A `Message` is either an `MLSMessage` or a `Welcome` message
/// (see OpenMLS) for details.
#[derive(Debug)]
pub enum Message<'a> {
    /// An `MLSMessage` is either an OpenMLS `MlsCiphertext` or `MlsPlaintext`.
    MlsMessage(DsMlsMessage<'a>),

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
pub struct GroupMessage<'a> {
    pub msg: DsMlsMessage<'a>,
    pub recipients: Vec<Vec<u8>>,
}

impl<'a> GroupMessage<'a> {
    /// Create a new `GroupMessage` taking an `DsMlsMessage` and slice of
    /// recipient names.
    pub fn new(msg: DsMlsMessage<'a>, recipients: &[Vec<u8>]) -> Self {
        Self {
            msg,
            recipients: recipients.to_vec(),
        }
    }

    /// Get the group ID as plain byte slice.
    pub fn group_id(&self) -> &[u8] {
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

impl Encode for ClientKeyPackages {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(buffer)
    }
}

impl Decode for ClientKeyPackages {
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_packages = Vec::<(Vec<u8>, KeyPackage)>::decode(cursor)?;
        Ok(ClientKeyPackages(key_packages))
    }
}

impl<'a> Encode for ClientInfo<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.client_name.encode(buffer)?;
        self.key_packages.encode(buffer)
    }
}

impl<'a> Decode for ClientInfo<'a> {
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let client_name = String::decode(cursor)?;
        let key_packages = Vec::<(Vec<u8>, KeyPackage)>::decode(cursor)?;
        Ok(Self::new(client_name, key_packages))
    }
}

impl Encode for MessageType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)
    }
}
impl Decode for MessageType {
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

impl<'a> Encode for Message<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Message::MlsMessage(m) => match m {
                DsMlsMessage::Ciphertext(m) => {
                    MessageType::MlsCiphertext.encode(buffer)?;
                    m.encode(buffer)?;
                }
                DsMlsMessage::Plaintext(m) => {
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
}

impl<'a> Decode for Message<'a> {
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let msg_type = MessageType::decode(cursor)?;
        let msg = match msg_type {
            MessageType::MlsCiphertext => {
                Message::MlsMessage(DsMlsMessage::Ciphertext(MlsCiphertext::decode(cursor)?))
            }
            MessageType::MlsPlaintext => Message::MlsMessage(DsMlsMessage::Plaintext(
                VerifiableMlsPlaintext::decode(cursor)?,
            )),
            MessageType::Welcome => Message::Welcome(Welcome::decode(cursor)?),
        };
        Ok(msg)
    }
}

impl<'a> Encode for GroupMessage<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match &self.msg {
            DsMlsMessage::Ciphertext(m) => {
                MessageType::MlsCiphertext.encode(buffer)?;
                m.encode(buffer)?;
            }
            DsMlsMessage::Plaintext(m) => {
                MessageType::MlsPlaintext.encode(buffer)?;
                m.encode(buffer)?;
            }
        }
        self.recipients.encode(buffer)
    }
}

impl<'a> Decode for GroupMessage<'a> {
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let msg_type = MessageType::decode(cursor)?;
        let msg = match msg_type {
            MessageType::MlsCiphertext => DsMlsMessage::Ciphertext(MlsCiphertext::decode(cursor)?),
            MessageType::MlsPlaintext => {
                DsMlsMessage::Plaintext(VerifiableMlsPlaintext::decode(cursor)?)
            }
            _ => return Err(CodecError::DecodingError),
        };

        let recipients = Vec::<Vec<u8>>::decode(cursor)?;
        Ok(Self { msg, recipients })
    }
}
