use super::*;
use std::convert::TryFrom;

impl Encode for MlsPlaintext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id().encode(buffer)?;
        self.epoch().encode(buffer)?;
        self.sender().encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, self.authenticated_data())?;
        self.content_type().encode(buffer)?;
        self.content().encode(buffer)?;
        self.signature().encode(buffer)?;
        self.confirmation_tag().encode(buffer)?;
        self.membership_tag().encode(buffer)?;
        Ok(())
    }
}

impl<'a> Decode for VerifiableMlsPlaintext<'a> {
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        log_content!(debug, "Decoding VerifiableMlsPlaintext {:x?}", cursor.raw());
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let sender = Sender::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let content = MlsPlaintextContentType::decode(content_type, cursor)?;
        let signature = Signature::decode(cursor)?;
        let confirmation_tag = Option::<ConfirmationTag>::decode(cursor)?;
        let membership_tag = Option::<MembershipTag>::decode(cursor)?;

        let verifiable = VerifiableMlsPlaintext::new(
            MlsPlaintextTbs::new(
                None,
                group_id,
                epoch,
                sender,
                authenticated_data,
                content_type,
                content,
            ),
            signature,
            confirmation_tag,
            membership_tag,
        );

        Ok(verifiable)
    }
}

impl<'a> Encode for VerifiableMlsPlaintext<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.tbs.group_id.encode(buffer)?;
        self.tbs.epoch.encode(buffer)?;
        self.tbs.sender.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.tbs.authenticated_data)?;
        self.tbs.content_type.encode(buffer)?;
        self.tbs.payload.encode(buffer)?;
        self.signature.encode(buffer)?;
        self.confirmation_tag.encode(buffer)?;
        self.membership_tag.encode(buffer)?;
        Ok(())
    }
}

implement_codec! {
    MlsCiphertext,
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
        log::debug!("Decoding MlsCiphertext {:x?}", cursor.raw());
        let group_id = GroupId::decode(cursor)?;
        let epoch = GroupEpoch::decode(cursor)?;
        let content_type = ContentType::decode(cursor)?;
        let authenticated_data = decode_vec(VecSize::VecU32, cursor)?;
        let encrypted_sender_data = decode_vec(VecSize::VecU8, cursor)?;
        let ciphertext = decode_vec(VecSize::VecU32, cursor)?;
        Ok(MlsCiphertext {
            group_id,
            epoch,
            content_type,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        })
    }
}

implement_codec! {
    ContentType,
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        ContentType::try_from(u8::decode(cursor)?)
    }
}

impl Encode for MlsPlaintextContentType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            MlsPlaintextContentType::Application(application_data) => {
                encode_vec(VecSize::VecU32, buffer, application_data)?;
            }
            MlsPlaintextContentType::Proposal(proposal) => {
                proposal.encode(buffer)?;
            }
            MlsPlaintextContentType::Commit(commit) => {
                commit.encode(buffer)?;
            }
        }
        Ok(())
    }
}

impl MlsPlaintextContentType {
    fn decode(content_type: ContentType, cursor: &mut Cursor) -> Result<Self, CodecError> {
        match content_type {
            ContentType::Application => {
                let application_data = decode_vec(VecSize::VecU32, cursor)?;
                Ok(MlsPlaintextContentType::Application(application_data))
            }
            ContentType::Proposal => {
                let proposal = Proposal::decode(cursor)?;
                Ok(MlsPlaintextContentType::Proposal(proposal))
            }
            ContentType::Commit => {
                let commit = Commit::decode(cursor)?;
                Ok(MlsPlaintextContentType::Commit(commit))
            }
        }
    }
}

implement_codec! {
    Mac,
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.mac_value)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let mac_value = decode_vec(VecSize::VecU8, cursor)?;
        Ok(Self { mac_value })
    }
}

implement_codec! {
    MembershipTag,
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let mac = Mac::decode(cursor)?;
        Ok(Self(mac))
    }
}

pub(super) fn encode_plaintext_tbs<'a>(
    serialized_context: impl Into<Option<&'a [u8]>>,
    group_id: &GroupId,
    epoch: &GroupEpoch,
    sender: &Sender,
    authenticated_data: &[u8],
    content_type: &ContentType,
    payload: &MlsPlaintextContentType,
    buffer: &mut Vec<u8>,
) -> Result<(), CodecError> {
    if let Some(ref serialized_context) = serialized_context.into() {
        buffer.extend_from_slice(serialized_context);
    }
    group_id.encode(buffer)?;
    epoch.encode(buffer)?;
    sender.encode(buffer)?;
    encode_vec(VecSize::VecU32, buffer, authenticated_data)?;
    content_type.encode(buffer)?;
    payload.encode(buffer)?;
    Ok(())
}

impl<'a> Encode for MlsPlaintextTbs<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_plaintext_tbs(
            self.serialized_context,
            &self.group_id,
            &self.epoch,
            &self.sender,
            &self.authenticated_data,
            &self.content_type,
            &self.payload,
            buffer,
        )
    }
}

implement_codec! {
    MlsSenderData,
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

        Ok(MlsSenderData {
            sender,
            generation,
            reuse_guard,
        })
    }
}

implement_codec! {
    MlsSenderDataAad,
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

impl MlsCiphertextContent {
    pub(crate) fn decode(
        content_type: ContentType,
        cursor: &mut Cursor,
    ) -> Result<Self, CodecError> {
        log_content!(debug, "Decoding MlsCiphertextContent {:x?}", cursor.raw());
        let content = match content_type {
            ContentType::Application => {
                let application_data = decode_vec(VecSize::VecU32, cursor)?;
                MlsPlaintextContentType::Application(application_data)
            }
            ContentType::Proposal => {
                let proposal = Proposal::decode(cursor)?;
                MlsPlaintextContentType::Proposal(proposal)
            }
            ContentType::Commit => {
                let commit = Commit::decode(cursor)?;
                MlsPlaintextContentType::Commit(commit)
            }
        };
        let signature = Signature::decode(cursor)?;
        let confirmation_tag = Option::<ConfirmationTag>::decode(cursor)?;
        let padding = decode_vec(VecSize::VecU16, cursor)?;
        Ok(MlsCiphertextContent {
            content,
            signature,
            confirmation_tag,
            padding,
        })
    }
}

implement_codec! {
    MlsCiphertextContentAad,
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
        Ok(MlsCiphertextContentAad {
            group_id,
            epoch,
            content_type,
            authenticated_data,
        })
    }
}

impl<'a> Encode for MlsPlaintextCommitContent<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        self.sender.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, self.authenticated_data)?;
        self.content_type.encode(buffer)?;
        self.commit.encode(buffer)?;
        self.signature.encode(buffer)?;
        Ok(())
    }
}

impl<'a> Encode for MlsPlaintextCommitAuthData<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.confirmation_tag.encode(buffer)?;
        Ok(())
    }
}

implement_codec! {
    SenderType,
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

implement_codec! {
    Sender,
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
