use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, types::Ciphersuite};
use tls_codec::*;

use crate::{
    binary_tree::LeafNodeIndex,
    extensions::SenderExtensionIndex,
    framing::{
        mls_content::{AuthenticatedContentTbm, FramedContentBody, FramedContentTbs},
        mls_content_in::FramedContentBodyIn,
        MlsMessageIn, MlsMessageOut, PrivateMessage, PrivateMessageIn, PublicMessage,
        PublicMessageIn, Sender, WireFormat,
    },
    group::GroupContext,
    messages::{ConfirmationTag, Welcome},
    prelude_test::signable::Signable,
    schedule::{ConfirmationKey, MembershipKey},
};

use super::{
    commit::FrankenCommit,
    compute_membership_tag,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrankenPublicMessage {
    pub content: FrankenFramedContent,
    pub auth: FrankenFramedContentAuthData,
    pub membership_tag: Option<VLBytes>,
}

impl tls_codec::Size for FrankenPublicMessage {
    fn tls_serialized_len(&self) -> usize {
        let tag_len = self
            .membership_tag
            .as_ref()
            .map_or(0, |tag| tag.tls_serialized_len());

        self.content.tls_serialized_len() + self.auth.tls_serialized_len() + tag_len
    }
}

impl Deserialize for FrankenPublicMessage {
    fn tls_deserialize<R: std::io::prelude::Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let content = FrankenFramedContent::tls_deserialize(bytes)?;
        let auth = if matches!(content.body, FrankenFramedContentBody::Commit(_)) {
            FrankenFramedContentAuthData::tls_deserialize_with_tag(bytes)?
        } else {
            FrankenFramedContentAuthData::tls_deserialize_without_tag(bytes)?
        };

        let membership_tag = if matches!(content.sender, FrankenSender::Member(_)) {
            Some(VLBytes::tls_deserialize(bytes)?)
        } else {
            None
        };

        Ok(Self {
            content,
            auth,
            membership_tag,
        })
    }
}

impl DeserializeBytes for FrankenPublicMessage {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let (content, bytes) = FrankenFramedContent::tls_deserialize_bytes(bytes)?;
        let (auth, bytes) = match content.body {
            FrankenFramedContentBody::Commit(_) => {
                FrankenFramedContentAuthData::tls_deserialize_bytes_with_tag(bytes)
            }
            _ => FrankenFramedContentAuthData::tls_deserialize_bytes_without_tag(bytes),
        }?;
        let (membership_tag, bytes) = match content.sender {
            FrankenSender::Member(_) => {
                let (tag, bytes) = VLBytes::tls_deserialize_bytes(bytes)?;
                (Some(tag), bytes)
            }
            _ => (None, bytes),
        };

        Ok((
            Self {
                content,
                auth,
                membership_tag,
            },
            bytes,
        ))
    }
}

impl Serialize for FrankenPublicMessage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut written = 0;
        written += self.content.tls_serialize(writer)?;
        written += self.auth.tls_serialize(writer)?;
        if let Some(tag) = &self.membership_tag {
            written += tag.tls_serialize(writer)?;
        }

        Ok(written)
    }
}

impl FrankenPublicMessage {
    /// auth builds a mostly(!) valid fake public message. However, it does not compute a correct
    /// confirmation_tag. If the caller wants to process a message that requires a
    /// confirmation_tag, they have two options:
    ///
    /// 1. build a valid tag themselves and provide it through the option
    /// 2. provide a dummy tag and disable the verification of confirmation tags using
    ///    [`crate::disable_confirmation_tag_verification`].
    ///    NB: Usually, confirmation tag verification should be turned back on after the call that
    ///    needs to be tricked!
    pub(crate) fn auth(
        provider: &impl crate::storage::OpenMlsProvider,
        ciphersuite: openmls_traits::types::Ciphersuite,
        signer: &impl Signer,
        content: FrankenFramedContent,
        group_context: Option<&FrankenGroupContext>,
        membership_key: Option<&[u8]>,
        confirmation_tag: Option<VLBytes>,
    ) -> Self {
        let version = 1; // MLS 1.0
        let wire_format = 1; // PublicMessage

        let franken_tbs = FrankenFramedContentTbs {
            version,
            wire_format,
            content: &content,
            group_context,
        };

        let auth = FrankenFramedContentAuthData::build(
            signer,
            version,
            wire_format,
            &content,
            group_context,
            confirmation_tag,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrankenFramedContentAuthData {
    pub signature: VLBytes,
    pub confirmation_tag: Option<VLBytes>,
}

impl FrankenFramedContentAuthData {
    pub fn tls_deserialize_with_tag<R: std::io::Read>(
        bytes: &mut R,
    ) -> Result<Self, tls_codec::Error> {
        let signature = VLBytes::tls_deserialize(bytes)?;
        let confirmation_tag = VLBytes::tls_deserialize(bytes)?;

        Ok(Self {
            signature,
            confirmation_tag: Some(confirmation_tag),
        })
    }

    pub fn tls_deserialize_bytes_with_tag(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error> {
        let (signature, bytes) = VLBytes::tls_deserialize_bytes(bytes)?;
        let (confirmation_tag, bytes) = VLBytes::tls_deserialize_bytes(bytes)?;

        Ok((
            Self {
                signature,
                confirmation_tag: Some(confirmation_tag),
            },
            bytes,
        ))
    }

    pub fn tls_deserialize_without_tag<R: std::io::Read>(
        bytes: &mut R,
    ) -> Result<Self, tls_codec::Error> {
        let signature = VLBytes::tls_deserialize(bytes)?;

        Ok(Self {
            signature,
            confirmation_tag: None,
        })
    }

    pub fn tls_deserialize_bytes_without_tag(
        bytes: &[u8],
    ) -> Result<(Self, &[u8]), tls_codec::Error> {
        let (signature, bytes) = VLBytes::tls_deserialize_bytes(bytes)?;

        Ok((
            Self {
                signature,
                confirmation_tag: None,
            },
            bytes,
        ))
    }
}

impl tls_codec::Size for FrankenFramedContentAuthData {
    fn tls_serialized_len(&self) -> usize {
        if let Some(tag) = &self.confirmation_tag {
            self.signature.tls_serialized_len() + tag.tls_serialized_len()
        } else {
            self.signature.tls_serialized_len()
        }
    }
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
        signer: &impl Signer,
        version: u16,
        wire_format: u16,
        content: &FrankenFramedContent,
        group_context: Option<&FrankenGroupContext>,
        confirmation_tag: Option<VLBytes>,
    ) -> Self {
        let content_tbs = FrankenFramedContentTbs {
            version,
            wire_format,
            content,
            group_context,
        };

        let content_tbs_serialized = content_tbs.tls_serialize_detached().unwrap();

        let signature =
            sign_with_label(signer, b"FramedContentTBS", &content_tbs_serialized).into();

        Self {
            signature,
            confirmation_tag,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrankenFramedContentTbs<'a> {
    version: u16,
    wire_format: u16,
    content: &'a FrankenFramedContent,
    group_context: Option<&'a FrankenGroupContext>,
}

impl tls_codec::Size for FrankenFramedContentTbs<'_> {
    fn tls_serialized_len(&self) -> usize {
        if let Some(ctx) = self.group_context {
            4 + self.content.tls_serialized_len() + ctx.tls_serialized_len()
        } else {
            4 + self.content.tls_serialized_len()
        }
    }
}

impl Serialize for FrankenFramedContentTbs<'_> {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(&self.version.to_be_bytes())?;
        writer.write_all(&self.wire_format.to_be_bytes())?;

        let mut written = 4; // contains the two u16 version and wire_format
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
