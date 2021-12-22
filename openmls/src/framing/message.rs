use super::*;

/// Unified message type for incoming MLS messages.
/// Since the memory footprint can differ considerably between [`VerifiableMlsPlaintext`]
/// and [`MlsCiphertext`], we use `Box<T>` for more efficient memory allocation.
#[derive(Debug, Clone)]
pub enum MlsMessageIn {
    /// An OpenMLS `VerifiableMlsPlaintext`.
    Plaintext(Box<VerifiableMlsPlaintext>),

    /// An OpenMLS `MlsCiphertext`.
    Ciphertext(Box<MlsCiphertext>),
}

impl MlsMessageIn {
    /// Get the wire format
    pub fn wire_format(&self) -> WireFormat {
        match self {
            MlsMessageIn::Ciphertext(_) => WireFormat::MlsCiphertext,
            MlsMessageIn::Plaintext(_) => WireFormat::MlsPlaintext,
        }
    }

    /// Get the group ID
    pub fn group_id(&self) -> &GroupId {
        match self {
            MlsMessageIn::Ciphertext(m) => m.group_id(),
            MlsMessageIn::Plaintext(m) => m.group_id(),
        }
    }

    /// Get the epoch
    pub fn epoch(&self) -> GroupEpoch {
        match self {
            MlsMessageIn::Ciphertext(m) => m.epoch(),
            MlsMessageIn::Plaintext(m) => m.epoch(),
        }
    }

    /// Get the content type
    pub fn content_type(&self) -> ContentType {
        match self {
            MlsMessageIn::Ciphertext(m) => m.content_type(),
            MlsMessageIn::Plaintext(m) => m.content_type(),
        }
    }
}

/// Unified message type for outgoing MLS messages.
/// Since the memory footprint can differ considerably between [`MlsPlaintext`]
/// and [`MlsCiphertext`], we use `Box<T>` for more efficient memory allocation.
#[derive(PartialEq, Debug, Clone)]
pub enum MlsMessageOut {
    /// An OpenMLS `MlsPlaintext`.
    Plaintext(Box<MlsPlaintext>),

    /// An OpenMLS `MlsCiphertext`.
    Ciphertext(Box<MlsCiphertext>),
}

impl From<MlsPlaintext> for MlsMessageOut {
    fn from(mls_plaintext: MlsPlaintext) -> Self {
        MlsMessageOut::Plaintext(Box::new(mls_plaintext))
    }
}

impl From<MlsCiphertext> for MlsMessageOut {
    fn from(mls_ciphertext: MlsCiphertext) -> Self {
        MlsMessageOut::Ciphertext(Box::new(mls_ciphertext))
    }
}

impl MlsMessageOut {
    /// Get the group ID as plain byte vector.
    pub fn group_id(&self) -> &[u8] {
        match self {
            MlsMessageOut::Ciphertext(m) => m.group_id().as_slice(),
            MlsMessageOut::Plaintext(m) => m.group_id().as_slice(),
        }
    }

    /// Get the epoch as plain u64.
    pub fn epoch(&self) -> u64 {
        match self {
            MlsMessageOut::Ciphertext(m) => m.epoch().0,
            MlsMessageOut::Plaintext(m) => m.epoch().0,
        }
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        match self {
            MlsMessageOut::Ciphertext(m) => m.is_handshake_message(),
            MlsMessageOut::Plaintext(m) => m.is_handshake_message(),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<MlsMessageOut> for MlsMessageIn {
    fn from(message: MlsMessageOut) -> Self {
        match message {
            MlsMessageOut::Plaintext(pt) => {
                MlsMessageIn::Plaintext(Box::new(VerifiableMlsPlaintext::from_plaintext(*pt, None)))
            }
            MlsMessageOut::Ciphertext(ct) => MlsMessageIn::Ciphertext(Box::new(*ct)),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<VerifiableMlsPlaintext> for MlsMessageIn {
    fn from(plaintext: VerifiableMlsPlaintext) -> Self {
        MlsMessageIn::Plaintext(Box::new(plaintext))
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<MlsCiphertext> for MlsMessageIn {
    fn from(ciphertext: MlsCiphertext) -> Self {
        MlsMessageIn::Ciphertext(Box::new(ciphertext))
    }
}
