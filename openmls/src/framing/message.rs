use super::*;

/// Unified message type for MLS messages.
/// Since the memory footprint can differ considerably between [`VerifiableMlsPlaintext`]
/// and [`MlsCiphertext`], we use `Box<T>` for more efficient memory allocation.
/// This is only used internally, externally we use either [`MlsMessageIn`] or
/// [`MlsMessageOut`], depending on the context.
#[derive(PartialEq, Debug, Clone)]
pub(crate) enum MlsMessage {
    /// An OpenMLS `VerifiableMlsPlaintext`.
    Plaintext(Box<VerifiableMlsPlaintext>),

    /// An OpenMLS `MlsCiphertext`.
    Ciphertext(Box<MlsCiphertext>),
}

impl MlsMessage {
    /// Get the wire format
    pub fn wire_format(&self) -> WireFormat {
        match self {
            MlsMessage::Ciphertext(_) => WireFormat::MlsCiphertext,
            MlsMessage::Plaintext(_) => WireFormat::MlsPlaintext,
        }
    }

    /// Get the group ID
    pub fn group_id(&self) -> &GroupId {
        match self {
            MlsMessage::Ciphertext(m) => m.group_id(),
            MlsMessage::Plaintext(m) => m.group_id(),
        }
    }

    /// Get the epoch
    pub fn epoch(&self) -> GroupEpoch {
        match self {
            MlsMessage::Ciphertext(m) => m.epoch(),
            MlsMessage::Plaintext(m) => m.epoch(),
        }
    }

    /// Get the content type
    pub fn content_type(&self) -> ContentType {
        match self {
            MlsMessage::Ciphertext(m) => m.content_type(),
            MlsMessage::Plaintext(m) => m.content_type(),
        }
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.content_type().is_handshake_message()
    }
}

/// Unified message type for incoming MLS messages.
#[derive(Debug, Clone, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct MlsMessageIn {
    pub(crate) mls_message: MlsMessage,
}

impl MlsMessageIn {
    /// Get the wire format
    pub fn wire_format(&self) -> WireFormat {
        self.mls_message.wire_format()
    }

    /// Get the group ID
    pub fn group_id(&self) -> &GroupId {
        self.mls_message.group_id()
    }

    /// Get the epoch
    pub fn epoch(&self) -> GroupEpoch {
        self.mls_message.epoch()
    }

    /// Get the content type
    pub fn content_type(&self) -> ContentType {
        self.mls_message.content_type()
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.mls_message.is_handshake_message()
    }
}

/// Unified message type for outgoing MLS messages.
#[derive(PartialEq, Debug, Clone, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct MlsMessageOut {
    pub(crate) mls_message: MlsMessage,
}

impl From<VerifiableMlsPlaintext> for MlsMessageOut {
    fn from(plaintext: VerifiableMlsPlaintext) -> Self {
        Self {
            mls_message: MlsMessage::Plaintext(Box::new(plaintext)),
        }
    }
}

impl From<MlsPlaintext> for MlsMessageOut {
    fn from(plaintext: MlsPlaintext) -> Self {
        Self {
            mls_message: MlsMessage::Plaintext(Box::new(VerifiableMlsPlaintext::from_plaintext(
                plaintext, None,
            ))),
        }
    }
}

impl From<MlsCiphertext> for MlsMessageOut {
    fn from(ciphertext: MlsCiphertext) -> Self {
        Self {
            mls_message: MlsMessage::Ciphertext(Box::new(ciphertext)),
        }
    }
}

impl MlsMessageOut {
    /// Get the wire format
    pub fn wire_format(&self) -> WireFormat {
        self.mls_message.wire_format()
    }

    /// Get the group ID
    pub fn group_id(&self) -> &GroupId {
        self.mls_message.group_id()
    }

    /// Get the epoch
    pub fn epoch(&self) -> GroupEpoch {
        self.mls_message.epoch()
    }

    /// Get the content type
    pub fn content_type(&self) -> ContentType {
        self.mls_message.content_type()
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.mls_message.is_handshake_message()
    }
}

impl From<MlsMessageOut> for MlsMessageIn {
    fn from(message: MlsMessageOut) -> Self {
        MlsMessageIn {
            mls_message: message.mls_message,
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<VerifiableMlsPlaintext> for MlsMessageIn {
    fn from(plaintext: VerifiableMlsPlaintext) -> Self {
        Self {
            mls_message: MlsMessage::Plaintext(Box::new(plaintext)),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<MlsCiphertext> for MlsMessageIn {
    fn from(ciphertext: MlsCiphertext) -> Self {
        Self {
            mls_message: MlsMessage::Ciphertext(Box::new(ciphertext)),
        }
    }
}
