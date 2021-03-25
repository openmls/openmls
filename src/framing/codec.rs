use crate::config::{Config, ProtocolVersion};

use super::*;
use std::convert::TryFrom;

impl Codec for MLSPlaintext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.sender.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        self.content_type.encode(buffer)?;
        self.content.encode(buffer)?;
        self.signature.encode(buffer)?;
        self.confirmation_tag.encode(buffer)?;
        self.membership_tag.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        log_content!(debug, "Decoding MLSPlaintext {:x?}", cursor.raw());
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let sender = Sender::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let content = MLSPlaintextContentType::decode(content_type, cursor)?;
        let signature = Signature::decode(cursor)?;
        let confirmation_tag = Option::<ConfirmationTag>::decode(cursor)?;
        let membership_tag = Option::<MembershipTag>::decode(cursor)?;

        Ok(MLSPlaintext {
            group_id,
            epoch,
            sender,
            authenticated_data,
            content_type,
            content,
            signature,
            confirmation_tag,
            membership_tag,
        })
    }
}

impl MLSPlaintext {
    /// Decode an `MLSPlaintext` with ciphersuite and protocol version information.
    /// This should be used instead of the raw decoding function in order to
    /// update the `MLSPlaintext` with the missing information.
    pub fn decode_with_context(
        bytes: &[u8],
        ciphersuite_name: CiphersuiteName,
        version: ProtocolVersion,
    ) -> Result<Self, CodecError> {
        let cursor = &mut Cursor::new(bytes);
        let mut plaintext = Self::decode(cursor)?;
        let ciphersuite = Config::ciphersuite(ciphersuite_name)?;
        if let Some(tag) = &mut plaintext.membership_tag {
            tag.config(ciphersuite, version)
        };
        if let Some(tag) = &mut plaintext.confirmation_tag {
            tag.config(ciphersuite, version);
        };
        Ok(plaintext)
    }
}

impl Codec for MLSCiphertext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.content_type.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        encode_vec(VecSize::VecU8, buffer, &self.encrypted_sender_data)?;
        encode_vec(VecSize::VecU32, buffer, &self.ciphertext)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        log::debug!("Decoding MLSCiphertext {:x?}", cursor.raw());
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        let encrypted_sender_data = decode_vec(VecSize::VecU8, cursor)?;
        let ciphertext = decode_vec(VecSize::VecU32, cursor)?;
        Ok(MLSCiphertext {
            group_id,
            epoch,
            content_type,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        })
    }
}

impl Codec for ContentType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        ContentType::try_from(u8::decode(cursor)?)
    }
}

impl Codec for MLSPlaintextContentType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            MLSPlaintextContentType::Application(application_data) => {
                encode_vec(VecSize::VecU32, buffer, application_data)?;
            }
            MLSPlaintextContentType::Proposal(proposal) => {
                proposal.encode(buffer)?;
            }
            MLSPlaintextContentType::Commit(commit) => {
                commit.encode(buffer)?;
            }
        }
        Ok(())
    }
}

impl MLSPlaintextContentType {
    fn decode(content_type: ContentType, cursor: &mut Cursor) -> Result<Self, CodecError> {
        match content_type {
            ContentType::Application => {
                let application_data = decode_vec(VecSize::VecU32, cursor)?;
                Ok(MLSPlaintextContentType::Application(application_data))
            }
            ContentType::Proposal => {
                let proposal = Proposal::decode(cursor)?;
                Ok(MLSPlaintextContentType::Proposal(proposal))
            }
            ContentType::Commit => {
                let commit = Commit::decode(cursor)?;
                Ok(MLSPlaintextContentType::Commit(commit))
            }
        }
    }
}

impl Codec for Mac {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, self.mac_value.to_bytes())?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let mac_value = decode_vec(VecSize::VecU8, cursor)?;
        // The secret is instantiated with default values here because we don't
        // know the correct values. They have to be set before use. Otherwise
        // operations on the Mac will fail.
        Ok(Self {
            mac_value: Secret::from_slice(
                &mac_value,
                ProtocolVersion::default(),
                Ciphersuite::default(),
            ),
        })
    }
}

impl Codec for MembershipTag {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let mac = Mac::decode(cursor)?;
        Ok(Self(mac))
    }
}

impl<'a> Codec for MLSPlaintextTBS<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        if let Some(ref serialized_context) = self.serialized_context_option {
            buffer.extend_from_slice(serialized_context);
        }
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.sender.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        self.content_type.encode(buffer)?;
        self.payload.encode(buffer)?;
        Ok(())
    }
}

impl Codec for MLSSenderData {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.sender.encode(buffer)?;
        self.generation.encode(buffer)?;
        self.reuse_guard.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let sender = LeafIndex::from(u32::decode(cursor)?);
        let generation = u32::decode(cursor)?;
        let reuse_guard = ReuseGuard::decode(cursor)?;

        Ok(MLSSenderData {
            sender,
            generation,
            reuse_guard,
        })
    }
}

impl Codec for MLSSenderDataAAD {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.content_type.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        Ok(Self {
            group_id,
            epoch,
            content_type,
        })
    }
}

impl MLSCiphertextContent {
    pub(crate) fn decode(
        content_type: ContentType,
        cursor: &mut Cursor,
    ) -> Result<Self, CodecError> {
        log_content!(debug, "Decoding MLSCiphertextContent {:x?}", cursor.raw());
        let content = match content_type {
            ContentType::Application => {
                let application_data = decode_vec(VecSize::VecU32, cursor)?;
                MLSPlaintextContentType::Application(application_data)
            }
            ContentType::Proposal => {
                let proposal = Proposal::decode(cursor)?;
                MLSPlaintextContentType::Proposal(proposal)
            }
            ContentType::Commit => {
                let commit = Commit::decode(cursor)?;
                MLSPlaintextContentType::Commit(commit)
            }
        };
        let signature = Signature::decode(cursor)?;
        let confirmation_tag = Option::<ConfirmationTag>::decode(cursor)?;
        let padding = decode_vec(VecSize::VecU16, cursor)?;
        Ok(MLSCiphertextContent {
            content,
            signature,
            confirmation_tag,
            padding,
        })
    }
}

impl Codec for MLSCiphertextContentAAD {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.content_type.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        Ok(MLSCiphertextContentAAD {
            group_id,
            epoch,
            content_type,
            authenticated_data,
        })
    }
}

impl<'a> Codec for MLSPlaintextCommitContent<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.sender.encode(buffer)?;
        self.content_type.encode(buffer)?;
        self.commit.encode(buffer)?;
        self.signature.encode(buffer)?;
        Ok(())
    }
}

impl<'a> Codec for MLSPlaintextCommitAuthData<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.confirmation_tag.encode(buffer)?;
        Ok(())
    }
}

impl Codec for SenderType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        match SenderType::try_from(u8::decode(cursor)?) {
            Ok(sender_type) => Ok(sender_type),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

impl Codec for Sender {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.sender_type.encode(buffer)?;
        self.sender.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let sender_type = SenderType::decode(cursor)?;
        let sender = LeafIndex::from(u32::decode(cursor)?);
        Ok(Sender {
            sender_type,
            sender,
        })
    }
}
