use super::*;

/// Unified message type for incoming MLS messages
#[derive(Debug, Clone)]
pub enum MlsMessageIn {
    /// An OpenMLS `VerifiableMlsPlaintext`.
    Plaintext(VerifiableMlsPlaintext),

    /// An OpenMLS `MlsCiphertext`.
    Ciphertext(MlsCiphertext),
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
            MlsMessageIn::Ciphertext(m) => m.epoch,
            MlsMessageIn::Plaintext(m) => m.epoch(),
        }
    }
}

/// Unified message type for outgoing MLS messages
#[derive(PartialEq, Debug, Clone)]
pub enum MlsMessageOut {
    /// An OpenMLS `MlsPlaintext`.
    Plaintext(MlsPlaintext),

    /// An OpenMLS `MlsCiphertext`.
    Ciphertext(MlsCiphertext),
}

impl From<MlsPlaintext> for MlsMessageOut {
    fn from(mls_plaintext: MlsPlaintext) -> Self {
        MlsMessageOut::Plaintext(mls_plaintext)
    }
}

impl From<MlsCiphertext> for MlsMessageOut {
    fn from(mls_ciphertext: MlsCiphertext) -> Self {
        MlsMessageOut::Ciphertext(mls_ciphertext)
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
            MlsMessageOut::Ciphertext(m) => m.epoch.0,
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
                MlsMessageIn::Plaintext(VerifiableMlsPlaintext::from_plaintext(pt, None))
            }
            MlsMessageOut::Ciphertext(ct) => MlsMessageIn::Ciphertext(ct),
        }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<VerifiableMlsPlaintext> for MlsMessageIn {
    fn from(plaintext: VerifiableMlsPlaintext) -> Self {
        MlsMessageIn::Plaintext(plaintext)
    }
}
