use super::*;

impl Codec for MLSPlaintext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.sender.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.authenticated_data)?;
        self.content_type.encode(buffer)?;
        self.content.encode(buffer)?;
        self.signature.encode(buffer)?;
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

        Ok(MLSPlaintext {
            group_id,
            epoch,
            sender,
            authenticated_data,
            content_type,
            content,
            signature,
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
        Ok(ContentType::from(u8::decode(cursor)?))
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
            MLSPlaintextContentType::Commit((commit, confirmation_tag)) => {
                ContentType::Commit.encode(buffer)?;
                commit.encode(buffer)?;
                confirmation_tag.encode(buffer)?;
            }
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let content_type = ContentType::from(u8::decode(cursor)?);
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
                let confirmation_tag = ConfirmationTag::decode(cursor)?;
                Ok(MLSPlaintextContentType::Commit((commit, confirmation_tag)))
            }
            _ => Err(CodecError::DecodingError),
        }
    }
}

impl Codec for MLSPlaintextTBS {
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

impl Codec for MLSCiphertextSenderDataAAD {
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
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.content.encode(buffer)?;
        self.signature.encode(buffer)?;
        encode_vec(VecSize::VecU16, buffer, &self.padding)?;
        Ok(())
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

impl Codec for MLSPlaintextCommitContent {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.sender.encode(buffer)?;
        self.content_type.encode(buffer)?;
        self.commit.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let sender = Sender::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let commit = Commit::decode(cursor)?;
        Ok(MLSPlaintextCommitContent {
            group_id,
            epoch,
            sender,
            content_type,
            commit,
        })
    }
}

impl Codec for MLSPlaintextCommitAuthData {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.confirmation_tag)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let confirmation_tag = decode_vec(VecSize::VecU8, cursor)?;
        Ok(MLSPlaintextCommitAuthData { confirmation_tag })
    }
}
