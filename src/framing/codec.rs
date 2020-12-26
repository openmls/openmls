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
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let sender = Sender::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let content = MLSPlaintextContentType::decode(cursor)?;
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
        match ContentType::try_from(u8::decode(cursor)?) {
            Ok(content_type) => Ok(content_type),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

impl Codec for MLSPlaintextContentType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            MLSPlaintextContentType::Application(application_data) => {
                ContentType::Application.encode(buffer)?;
                encode_vec(VecSize::VecU32, buffer, application_data)?;
            }
            MLSPlaintextContentType::Proposal(proposal) => {
                ContentType::Proposal.encode(buffer)?;
                proposal.encode(buffer)?;
            }
            MLSPlaintextContentType::Commit(commit) => {
                ContentType::Commit.encode(buffer)?;
                commit.encode(buffer)?;
            }
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let content_type = match ContentType::try_from(u8::decode(cursor)?) {
            Ok(content_type) => content_type,
            Err(_) => return Err(CodecError::DecodingError),
        };
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
        encode_vec(VecSize::VecU8, buffer, &self.mac_value)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let mac_value = decode_vec(VecSize::VecU8, cursor)?;
        Ok(Self { mac_value })
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

impl Codec for MLSCiphertextContent {
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let content = MLSPlaintextContentType::decode(cursor)?;
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
