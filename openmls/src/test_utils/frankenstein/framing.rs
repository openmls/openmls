use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, types::Ciphersuite};
use tls_codec::*;

use crate::{
    binary_tree::LeafNodeIndex,
    extensions::SenderExtensionIndex,
    framing::Sender,
    framing::{
        mls_content::{AuthenticatedContentTbm, FramedContentBody, FramedContentTbs},
        mls_content_in::FramedContentBodyIn,
        MlsMessageIn, MlsMessageOut, PrivateMessage, PrivateMessageIn, PublicMessage,
        PublicMessageIn, WireFormat,
    },
    group::GroupContext,
    messages::{ConfirmationTag, Welcome},
    prelude_test::signable::Signable,
    schedule::{ConfirmationKey, MembershipKey},
};

use super::{
    commit::FrankenCommit,
    compute_confirmation_tag, compute_membership_tag,
    group_info::{FrankenGroupContext, FrankenGroupInfo},
    sign_with_label, FrankenKeyPackage, FrankenProposal,
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

impl FrankenPublicMessage {
    pub(crate) fn auth(
        provider: &impl crate::storage::OpenMlsProvider,
        ciphersuite: openmls_traits::types::Ciphersuite,
        signer: &impl Signer,
        content: FrankenFramedContent,
        group_context: Option<&FrankenGroupContext>,
        membership_key: Option<&[u8]>,
        confirmation_tag_info: Option<(&[u8], &[u8])>, // ConfirmationKey and confirmed_transcript_hash
    ) -> Self {
        let version = 1; // MLS 1.0
        let wire_format = 1; // PublicMessage

        let franken_tbs = FrankenFramedContentTbs {
            version: 1,
            wire_format: 1, // PublicMessage
            content: &content,
            group_context,
        };

        let auth = FrankenFramedContentAuthData::build(
            provider.crypto(),
            ciphersuite,
            signer,
            version,
            wire_format,
            &content,
            group_context,
            confirmation_tag_info,
        );

        let tbm = FrankenAuthenticatedContentTbm {
            content_tbs: franken_tbs,
            auth: auth.clone(),
        };

        let membership_tag = membership_key.map(|membership_key| {
            compute_membership_tag(provider.crypto(), ciphersuite, membership_key, &tbm)
        });

        FrankenPublicMessage {
            content,
            auth,
            membership_tag,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub struct FrankenFramedContentAuthData {
    pub signature: VLBytes,
    pub confirmation_tag: Option<VLBytes>,
}

impl Serialize for FrankenFramedContentAuthData {
    fn tls_serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut written = 0;
        written += self.signature.tls_serialize(writer)?;
        if let Some(confirmation_tag) = &self.confirmation_tag {
            written += confirmation_tag.tls_serialize(writer)?;
        }
        Ok(written)
    }
}

impl FrankenFramedContentAuthData {
    pub fn build(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        signer: &impl Signer,
        version: u16,
        wire_format: u16,
        content: &FrankenFramedContent,
        group_context: Option<&FrankenGroupContext>,
        confirmation_tag_info: Option<(&[u8], &[u8])>, // conf_key and conf_ts_hash
    ) -> Self {
        let content_tbs = FrankenFramedContentTbs {
            version,
            wire_format,
            content,
            group_context,
        };

        let confirmation_tag =
            confirmation_tag_info.map(|(confirmation_key, confirmed_transcript_hash)| {
                compute_confirmation_tag(
                    crypto,
                    ciphersuite,
                    confirmation_key,
                    confirmed_transcript_hash,
                )
            });

        let content_tbs_serialized = content_tbs.tls_serialize_detached().unwrap();

        let signature =
            sign_with_label(signer, b"FramedContentTBS", &content_tbs_serialized).into();

        Self {
            signature,
            confirmation_tag,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSize)]
pub struct FrankenFramedContentTbs<'a> {
    version: u16,
    wire_format: u16,
    content: &'a FrankenFramedContent,
    group_context: Option<&'a FrankenGroupContext>,
}

impl<'a> Serialize for FrankenFramedContentTbs<'a> {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut written = 4; // contains the two u16 version and wire_format
        writer.write_all(&self.version.to_be_bytes())?;
        writer.write_all(&self.wire_format.to_be_bytes())?;
        written += self.content.tls_serialize(writer)?;
        if let Some(group_context) = &self.group_context {
            written += group_context.tls_serialize(writer)?;
        }

        Ok(written)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsSize)]
pub struct FrankenAuthenticatedContentTbm<'a> {
    content_tbs: FrankenFramedContentTbs<'a>,
    auth: FrankenFramedContentAuthData,
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

impl From<FrankenFramedContentBody> for FramedContentBodyIn {
    fn from(value: FrankenFramedContentBody) -> Self {
        FramedContentBodyIn::tls_deserialize(
            &mut value.tls_serialize_detached().unwrap().as_slice(),
        )
        .unwrap()
    }
}

impl From<FrankenFramedContentBody> for FramedContentBody {
    fn from(value: FrankenFramedContentBody) -> Self {
        FramedContentBodyIn::from(value).into()
    }
}

impl From<Sender> for FrankenSender {
    fn from(value: Sender) -> Self {
        match value {
            Sender::Member(i) => FrankenSender::Member(i.u32()),
            // this cast is safe, because the index method casts it from u32 to usize for some
            // reason, so it's known to fit u32
            Sender::External(i) => FrankenSender::External(i.index() as u32),
            Sender::NewMemberProposal => FrankenSender::NewMemberProposal,
            Sender::NewMemberCommit => FrankenSender::NewMemberCommit,
        }
    }
}

impl From<FrankenSender> for Sender {
    fn from(value: FrankenSender) -> Self {
        match value {
            FrankenSender::Member(i) => Sender::Member(LeafNodeIndex::new(i)),
            FrankenSender::External(i) => Sender::External(SenderExtensionIndex::new(i)),
            FrankenSender::NewMemberProposal => Sender::NewMemberProposal,
            FrankenSender::NewMemberCommit => Sender::NewMemberCommit,
        }
    }
}
