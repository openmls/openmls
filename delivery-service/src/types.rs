use super::*;

/// Information about a client.
/// To register a new client create a new `ClientInfo` and send it to `/clients/register`.
#[derive(Debug, Default, Clone)]
pub(crate) struct ClientInfo {
    pub(crate) client_name: String,
    pub(crate) key_packages: ClientKeyPackages,
    pub(crate) msgs: Vec<MLSMessage>,
    pub(crate) welcome_queue: Vec<Welcome>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct ClientKeyPackages(pub(crate) Vec<(KeyPackageHash, KeyPackage)>);

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

impl ClientInfo {
    pub(crate) fn new(
        client_name: String,
        key_packages: Vec<(KeyPackageHash, KeyPackage)>,
    ) -> Self {
        Self {
            client_name,
            key_packages: ClientKeyPackages(key_packages),
            msgs: Vec::new(),
            welcome_queue: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    MLSMessage(MLSMessage),
    Welcome(Welcome),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum MLSMessage {
    MLSCiphertext(MLSCiphertext),
    MLSPlaintext(MLSPlaintext),
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum MessageType {
    MLSCiphertext = 0,
    MLSPlaintext = 1,
    Welcome = 2,
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

/// An MLS group message.
/// This is an `MLSMessage` plus the list of recipients.
#[derive(Debug)]
pub struct GroupMessage {
    pub(crate) msg: MLSMessage,
    pub(crate) recipients: Vec<String>,
}

impl GroupMessage {
    pub fn new(msg: MLSMessage, recipients: &[String]) -> Self {
        Self {
            msg,
            recipients: recipients.to_vec(),
        }
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
