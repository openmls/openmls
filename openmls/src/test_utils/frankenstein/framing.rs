use tls_codec::*;

use crate::{
    framing::{
        MlsMessageIn, MlsMessageOut, PrivateMessage, PrivateMessageIn, PublicMessage,
        PublicMessageIn,
    },
    messages::Welcome,
};

use super::{
    commit::FrankenCommit, group_info::FrankenGroupInfo, FrankenKeyPackage, FrankenProposal,
};

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenMlsMessage {
    pub version: u16,
    pub body: FrankenMlsMessageBody,
}

#[allow(clippy::large_enum_variant)]
#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u16)]
pub enum FrankenMlsMessageBody {
    #[tls_codec(discriminant = 1)]
    PublicMessage(FrankenPublicMessage),
    #[tls_codec(discriminant = 2)]
    PrivateMessage(FrankenPrivateMessage),
    #[tls_codec(discriminant = 3)]
    Welcome(FrankenWelcome),
    #[tls_codec(discriminant = 4)]
    GroupInfo(FrankenGroupInfo),
    #[tls_codec(discriminant = 5)]
    KeyPackage(FrankenKeyPackage),
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenPublicMessage {
    pub content: FrankenFramedContent,
    pub auth: FrankenFramedContentAuthData,
    pub membership_tag: Option<VLBytes>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenFramedContent {
    pub group_id: VLBytes,
    pub epoch: u64,
    pub sender: FrankenSender,
    pub authenticated_data: VLBytes,
    pub body: FrankenFramedContentBody,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u8)]
pub enum FrankenSender {
    #[tls_codec(discriminant = 1)]
    Member(u32),
    External(u32),
    NewMemberProposal,
    NewMemberCommit,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u8)]
pub enum FrankenFramedContentBody {
    #[tls_codec(discriminant = 1)]
    Application(VLBytes),
    #[tls_codec(discriminant = 2)]
    Proposal(FrankenProposal),
    #[tls_codec(discriminant = 3)]
    Commit(FrankenCommit),
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenPrivateMessage {
    pub group_id: VLBytes,
    pub epoch: VLBytes,
    pub content_type: FrankenContentType,
    pub authenticated_data: VLBytes,
    pub encrypted_sender_data: VLBytes,
    pub ciphertext: VLBytes,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenWelcome {
    pub cipher_suite: u16,
    pub secrets: Vec<FrankenEncryptedGroupSecrets>,
    pub encrypted_group_info: VLBytes,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenFramedContentAuthData {
    pub signature: VLBytes,
    pub confirmation_tag: Option<VLBytes>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
#[repr(u8)]
pub enum FrankenContentType {
    Application = 1,
    Proposal = 2,
    Commit = 3,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenEncryptedGroupSecrets {
    pub new_member: VLBytes,
    pub encrypted_group_secrets: VLBytes,
}

impl From<MlsMessageOut> for FrankenMlsMessage {
    fn from(ln: MlsMessageOut) -> Self {
        FrankenMlsMessage::tls_deserialize(&mut ln.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
    }
}

impl From<FrankenMlsMessage> for MlsMessageOut {
    fn from(fln: FrankenMlsMessage) -> Self {
        MlsMessageIn::tls_deserialize(&mut fln.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
            .into()
    }
}

impl From<PublicMessage> for FrankenPublicMessage {
    fn from(ln: PublicMessage) -> Self {
        FrankenPublicMessage::tls_deserialize(&mut ln.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
    }
}

impl From<FrankenPublicMessage> for PublicMessage {
    fn from(fln: FrankenPublicMessage) -> Self {
        PublicMessageIn::tls_deserialize(&mut fln.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
            .into()
    }
}

impl From<PrivateMessage> for FrankenPrivateMessage {
    fn from(ln: PrivateMessage) -> Self {
        FrankenPrivateMessage::tls_deserialize(&mut ln.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
    }
}

impl From<FrankenPrivateMessage> for PrivateMessage {
    fn from(fln: FrankenPrivateMessage) -> Self {
        PrivateMessageIn::tls_deserialize(&mut fln.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
            .into()
    }
}

impl From<Welcome> for FrankenWelcome {
    fn from(ln: Welcome) -> Self {
        FrankenWelcome::tls_deserialize(&mut ln.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
    }
}

impl From<FrankenWelcome> for Welcome {
    fn from(fln: FrankenWelcome) -> Self {
        Welcome::tls_deserialize(&mut fln.tls_serialize_detached().unwrap().as_slice()).unwrap()
    }
}
