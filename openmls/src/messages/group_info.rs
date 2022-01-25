use std::io::{Read, Write};

use super::*;

#[derive(TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct GroupInfoTbs {
    version: ProtocolVersion,
    ciphersuite: CiphersuiteName,
    group_id: GroupId,
    epoch: GroupEpoch,
    tree_hash: TlsByteVecU8,
    confirmed_transcript_hash: TlsByteVecU8,
    group_context_extensions: TlsVecU32<Extension>,
    other_extensions: TlsVecU32<Extension>,
    confirmation_tag: ConfirmationTag,
    signer: KeyPackageRef,
}

impl GroupInfoTbs {
    /// Create a new group info payload struct.
    pub(crate) fn new(
        version: ProtocolVersion,
        ciphersuite: CiphersuiteName,
        group_context: &GroupContext,
        other_extensions: &[Extension],
        confirmation_tag: ConfirmationTag,
        signer: &KeyPackageRef,
    ) -> Self {
        Self {
            version,
            ciphersuite,
            group_id: group_context.group_id().clone(),
            epoch: group_context.epoch(),
            tree_hash: group_context.tree_hash().to_vec().into(),
            confirmed_transcript_hash: group_context.confirmed_transcript_hash().to_vec().into(),
            group_context_extensions: group_context.extensions().to_vec().into(),
            other_extensions: other_extensions.into(),
            confirmation_tag,
            signer: signer.clone(),
        }
    }
}

impl Signable for GroupInfoTbs {
    type SignedOutput = GroupInfo;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }
}

/// GroupInfo
///
/// The struct is split into the payload and the signature.
/// `GroupInfoPayload` holds the actual values, stored in `payload` here.
///
/// > 11.2.2. Welcoming New Members
///
/// ```text
/// struct {
///   ProtocolVersion version = mls10;
///   opaque group_id<0..255>;
///   uint64 epoch;
///   opaque tree_hash<0..255>;
///   opaque confirmed_transcript_hash<0..255>;
///   Extension group_context_extensions<0..2^32-1>;
///   Extension other_extensions<0..2^32-1>;
///   MAC confirmation_tag;
///   KeyPackageRef signer;
///   opaque signature<0..2^16-1>;
/// } GroupInfo;
/// ```
pub(crate) struct GroupInfo {
    payload: GroupInfoTbs,
    signature: Signature,
}

impl GroupInfo {
    /// Get the signer.
    pub(crate) fn signer(&self) -> &KeyPackageRef {
        &self.payload.signer
    }

    /// Get the version.
    pub(crate) fn version(&self) -> ProtocolVersion {
        self.payload.version
    }

    /// Get the ciphersuite.
    pub(crate) fn ciphersuite(&self) -> CiphersuiteName {
        self.payload.ciphersuite
    }

    /// Get the group ID.
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.payload.group_id
    }

    /// Get the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.payload.epoch
    }

    /// Get the tree hash.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        self.payload.tree_hash.as_slice()
    }

    /// Get the confirmed transcript hash.
    pub(crate) fn confirmed_transcript_hash(&self) -> &[u8] {
        self.payload.confirmed_transcript_hash.as_slice()
    }

    /// Get the confirmed tag.
    pub(crate) fn confirmation_tag(&self) -> &ConfirmationTag {
        &self.payload.confirmation_tag
    }

    /// Get other application extensions.
    pub(crate) fn other_extensions(&self) -> &[Extension] {
        self.payload.other_extensions.as_slice()
    }

    /// Get the [`GroupContext`] extensions.
    pub(crate) fn group_context_extensions(&self) -> &[Extension] {
        self.payload.group_context_extensions.as_slice()
    }

    /// Set the group info's other extensions.
    #[cfg(test)]
    pub(crate) fn set_other_extensions(&mut self, extensions: Vec<Extension>) {
        self.payload.other_extensions = extensions.into();
    }

    /// Re-sign the group info.
    #[cfg(test)]
    pub(crate) fn re_sign(
        self,
        credential_bundle: &CredentialBundle,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, CredentialError> {
        self.payload.sign(backend, credential_bundle)
    }
}
impl VerifiedStruct<VerifiableGroupInfo> for GroupInfo {
    fn from_verifiable(v: group_info::VerifiableGroupInfo, _seal: Self::SealingType) -> Self {
        Self {
            payload: v.payload,
            signature: v.signature,
        }
    }

    type SealingType = private_mod::Seal;
}

#[derive(TlsSize)]
pub(crate) struct VerifiableGroupInfo {
    payload: GroupInfoTbs,
    signature: Signature,
}

impl VerifiableGroupInfo {
    /// Get the `ProtocolVersion` of the unverified
    /// `GroupInfo`.
    pub(crate) fn version(&self) -> ProtocolVersion {
        self.payload.version
    }

    /// Get a reference to the `Ciphersuite` of the unverified
    /// `GroupInfo`.
    pub(crate) fn ciphersuite(&self) -> CiphersuiteName {
        self.payload.ciphersuite
    }

    /// Get a reference to the `GroupId` of the unverified
    /// `GroupInfo`.
    pub(crate) fn group_id(&self) -> GroupId {
        self.payload.group_id
    }

    /// Get a reference to the `Epoch` of the unverified
    /// `GroupInfo`.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.payload.epoch
    }

    /// Get a reference to the `tree_hash` of the unverified
    /// `GroupInfo`.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        self.payload.tree_hash.as_slice()
    }

    /// Get the `LeafIndex` of the signer of the unverified `GroupInfo`.
    pub(crate) fn signer(&self) -> &KeyPackageRef {
        &self.payload.signer
    }

    /// Get a reference to the non [`GroupContext`] extensions of the unverified
    /// `GroupInfo`.
    pub(crate) fn other_extensions(&self) -> &[Extension] {
        self.payload.other_extensions.as_slice()
    }

    /// Get a reference to the [`GroupContext`] extensions of the unverified
    /// `GroupInfo`.
    pub(crate) fn group_context_extensions(&self) -> &[Extension] {
        self.payload.group_context_extensions.as_slice()
    }
}

impl Verifiable for VerifiableGroupInfo {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.payload.unsigned_payload()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl From<VerifiableGroupInfo> for GroupInfo {
    fn from(group_info: VerifiableGroupInfo) -> Self {
        Self {
            payload: group_info.payload,
            signature: group_info.signature,
        }
    }
}

impl SignedStruct<GroupInfoTbs> for GroupInfo {
    fn from_payload(payload: GroupInfoTbs, signature: Signature) -> Self {
        Self { payload, signature }
    }
}

mod private_mod {
    #[derive(Default)]
    pub struct Seal;
}

impl tls_codec::Size for GroupInfo {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        let payload_len = match self.payload.unsigned_payload() {
            Ok(p) => p.len(),
            Err(e) => {
                log::error!("Unable to get unsigned payload from GroupInfo {:?}", e);
                0
            }
        };
        payload_len + self.signature.tls_serialized_len()
    }
}

impl tls_codec::Serialize for GroupInfo {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let unsigned_payload = &self.payload.unsigned_payload()?;
        let written = writer.write(unsigned_payload)?;
        debug_assert_eq!(written, unsigned_payload.len());
        self.signature.tls_serialize(writer).map(|l| l + written)
    }
}

impl tls_codec::Deserialize for VerifiableGroupInfo {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let payload = GroupInfoTbs::tls_deserialize(bytes)?;
        let signature = Signature::tls_deserialize(bytes)?;
        Ok(VerifiableGroupInfo { payload, signature })
    }
}
