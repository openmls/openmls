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
    pub msgs: Vec<MLSMessage>,
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
            key_packages: ClientKeyPackages(key_packages),
            msgs: Vec::new(),
            welcome_queue: Vec::new(),
        }
    }
}

/// The DS returns a list of messages on `/recv/{name}`, which is a `Vec<Message>`.
/// A `Message` is either an `MLSMessage` or a `Welcome` message (see OpenMLS)
/// for details.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// An `MLSMessage` is either an OpenMLS `MLSCiphertext` or `MLSPlaintext`.
    MLSMessage(MLSMessage),

    /// An OpenMLS `Welcome` message.
    Welcome(Welcome),
}

/// A generalisation of the `MLSCiphertext` and `MLSPlaintext` messages from
/// OpenMLS.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum MLSMessage {
    /// An OpenMLS `MLSCiphertext`.
    MLSCiphertext(MLSCiphertext),

    /// An OpenMLS `MLSPlaintext`.
    MLSPlaintext(MLSPlaintext),
}

impl MLSMessage {
    /// Get the group ID as plain byte vector.
    pub fn group_id(&self) -> Vec<u8> {
        match self {
            MLSMessage::MLSCiphertext(m) => m.group_id.as_slice(),
            MLSMessage::MLSPlaintext(m) => m.group_id.as_slice(),
        }
    }

    /// Get the epoch as plain u64.
    pub fn epoch(&self) -> u64 {
        match self {
            MLSMessage::MLSCiphertext(m) => m.epoch.0,
            MLSMessage::MLSPlaintext(m) => m.epoch.0,
        }
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        match self {
            MLSMessage::MLSCiphertext(m) => m.is_handshake_message(),
            MLSMessage::MLSPlaintext(m) => m.is_handshake_message(),
        }
    }
}

/// Enum defining encodings for the different message types/
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum MessageType {
    /// An MLSCiphertext message.
    MLSCiphertext = 0,

    /// An MLSPlaintext message.
    MLSPlaintext = 1,

    /// A Welcome message.
    Welcome = 2,
}

/// An MLS group message.
/// This is an `MLSMessage` plus the list of recipients as a vector of client names.
#[derive(Debug)]
pub struct GroupMessage {
    pub msg: MLSMessage,
    pub recipients: Vec<String>,
}

impl GroupMessage {
    /// Create a new `GroupMessage` taking an `MLSMessage` and slice of recipient
    /// names.
    pub fn new(msg: MLSMessage, recipients: &[String]) -> Self {
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
        (self.0.len() as u32).encode(buffer)?;
        for (hash, key_package) in self.0.iter() {
            encode_vec(VecSize::VecU16, buffer, &hash)?;
            key_package.encode(buffer)?;
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let length = u32::decode(cursor)?;
        let mut key_packages = Vec::with_capacity(length as usize);
        for _ in 0..length {
            let hash = decode_vec(VecSize::VecU16, cursor)?;
            let key_package = KeyPackage::decode(cursor)?;
            key_packages.push((hash, key_package));
        }
        Ok(ClientKeyPackages(key_packages))
    }
}

impl Codec for ClientInfo {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        let client_name_bytes = self.client_name.as_bytes();
        (client_name_bytes.len() as u16).encode(buffer)?;
        buffer.extend_from_slice(&client_name_bytes);

        (self.key_packages.0.len() as u16).encode(buffer)?;
        for key_package in self.key_packages.0.iter() {
            encode_vec(VecSize::VecU16, buffer, &key_package.0)?;
            key_package.1.encode(buffer)?;
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let client_name_length = u16::decode(cursor)?;
        let client_name = std::str::from_utf8(cursor.consume(client_name_length.into())?)
            .unwrap()
            .to_string();

        let mut key_packages = Vec::new();
        let num_key_packages = u16::decode(cursor)?;
        for _ in 0..num_key_packages {
            let hash = decode_vec(VecSize::VecU16, cursor)?;
            let key_package = KeyPackage::decode(cursor)?;
            key_packages.push((hash, key_package));
        }
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
            0 => Ok(Self::MLSCiphertext),
            1 => Ok(Self::MLSPlaintext),
            2 => Ok(Self::Welcome),
            _ => Err(CodecError::DecodingError),
        }
    }
}

impl Codec for Message {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Message::MLSMessage(m) => match m {
                MLSMessage::MLSCiphertext(m) => {
                    MessageType::MLSCiphertext.encode(buffer)?;
                    m.encode(buffer)?;
                }
                MLSMessage::MLSPlaintext(m) => {
                    MessageType::MLSPlaintext.encode(buffer)?;
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
            MessageType::MLSCiphertext => {
                Message::MLSMessage(MLSMessage::MLSCiphertext(MLSCiphertext::decode(cursor)?))
            }
            MessageType::MLSPlaintext => {
                Message::MLSMessage(MLSMessage::MLSPlaintext(MLSPlaintext::decode(cursor)?))
            }
            MessageType::Welcome => Message::Welcome(Welcome::decode(cursor)?),
        };
        Ok(msg)
    }
}

impl Codec for GroupMessage {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match &self.msg {
            MLSMessage::MLSCiphertext(m) => {
                MessageType::MLSCiphertext.encode(buffer)?;
                m.encode(buffer)?;
            }
            MLSMessage::MLSPlaintext(m) => {
                MessageType::MLSPlaintext.encode(buffer)?;
                m.encode(buffer)?;
            }
        }
        (self.recipients.len() as u16).encode(buffer)?;
        for recipient in self.recipients.iter() {
            let recipient_bytes = recipient.as_bytes();
            (recipient_bytes.len() as u16).encode(buffer)?;
            buffer.extend_from_slice(&recipient_bytes);
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let msg_type = MessageType::decode(cursor)?;
        let msg = match msg_type {
            MessageType::MLSCiphertext => MLSMessage::MLSCiphertext(MLSCiphertext::decode(cursor)?),
            MessageType::MLSPlaintext => MLSMessage::MLSPlaintext(MLSPlaintext::decode(cursor)?),
            _ => return Err(CodecError::DecodingError),
        };

        let num_clients = u16::decode(cursor)?;
        let mut recipients = Vec::new();
        for _ in 0..num_clients {
            let client_name_length = u16::decode(cursor)?;
            let client_name = std::str::from_utf8(cursor.consume(client_name_length.into())?)
                .unwrap()
                .to_string();
            recipients.push(client_name);
        }
        Ok(Self { msg, recipients })
    }
}
