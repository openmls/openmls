//! This module contains all types related to group info handling.

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::Ciphersuite;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use thiserror::Error;
use tls_codec::{
    Deserialize, Serialize as TlsSerializeTrait, TlsDeserialize, TlsDeserializeBytes, TlsSerialize,
    TlsSize,
};

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
        AeadKey, AeadNonce, Signature,
    },
    extensions::{errors::InvalidExtensionError, Extension, Extensions},
    group::{GroupContext, GroupEpoch, GroupId},
    messages::ConfirmationTag,
};

const SIGNATURE_GROUP_INFO_LABEL: &str = "GroupInfoTBS";

/// A type that represents a group info of which the signature has not been verified.
/// It implements the [`Verifiable`] trait and can be turned into a group info by calling
/// `verify(...)` with the signature key of the [`Credential`](crate::credentials::Credential).
/// When receiving a serialized group info, it can only be deserialized into a
/// [`VerifiableGroupInfo`], which can then be turned into a group info as described above.
#[derive(Debug, PartialEq, Clone, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(TlsSerialize))]
pub struct VerifiableGroupInfo {
    payload: GroupInfoTBS,
    signature: Signature,
}

/// Error related to group info.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum GroupInfoError {
    /// Decryption failed.
    #[error("Decryption failed.")]
    DecryptionFailed,
    /// Malformed.
    #[error("Malformed.")]
    Malformed,
}

impl VerifiableGroupInfo {
    /// Create a new [`VerifiableGroupInfo`] from its contents.
    pub fn new(
        group_context: GroupContext,
        extensions: Extensions,
        confirmation_tag: ConfirmationTag,
        signer: LeafNodeIndex,
        signature: Signature,
    ) -> Self {
        let payload = GroupInfoTBS {
            group_context,
            extensions,
            confirmation_tag,
            signer,
        };
        Self { payload, signature }
    }

    pub(crate) fn try_from_ciphertext(
        skey: &AeadKey,
        nonce: &AeadNonce,
        ciphertext: &[u8],
        context: &[u8],
        crypto: &impl OpenMlsCrypto,
    ) -> Result<Self, GroupInfoError> {
        let verifiable_group_info_plaintext = skey
            .aead_open(crypto, ciphertext, context, nonce)
            .map_err(|_| GroupInfoError::DecryptionFailed)?;

        let mut verifiable_group_info_plaintext_slice = verifiable_group_info_plaintext.as_slice();

        let verifiable_group_info =
            VerifiableGroupInfo::tls_deserialize(&mut verifiable_group_info_plaintext_slice)
                .map_err(|_| GroupInfoError::Malformed)?;

        if !verifiable_group_info_plaintext_slice.is_empty() {
            return Err(GroupInfoError::Malformed);
        }

        Ok(verifiable_group_info)
    }

    /// Get (unverified) ciphersuite of the verifiable group info.
    ///
    /// Note: This method should only be used when necessary to verify the group info signature.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.payload.group_context.ciphersuite()
    }

    /// Get (unverified) signer of the verifiable group info.
    ///
    /// Note: This method should only be used when necessary to verify the group info signature.
    pub(crate) fn signer(&self) -> LeafNodeIndex {
        self.payload.signer
    }

    /// Get (unverified) extensions of the verifiable group info.
    ///
    /// Note: This method should only be used when necessary to verify the group info signature.
    pub fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }

    /// Get (unverified) group ID of the verifiable group info.
    ///
    /// Note: This method should only be used when necessary to verify the group
    /// info signature.
    pub fn group_id(&self) -> &GroupId {
        self.payload.group_context.group_id()
    }

    /// Get (unverified) epoch of the verifiable group info.
    ///
    /// Note: This method should only be used when necessary to verify the group
    /// info signature.
    pub fn epoch(&self) -> GroupEpoch {
        self.payload.group_context.epoch()
    }
}

#[cfg(test)]
impl VerifiableGroupInfo {
    pub(crate) fn payload_mut(&mut self) -> &mut GroupInfoTBS {
        &mut self.payload
    }

    /// Break the signature for testing purposes.
    pub(crate) fn break_signature(&mut self) {
        self.signature.modify(b"");
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<VerifiableGroupInfo> for GroupInfo {
    fn from(vgi: VerifiableGroupInfo) -> Self {
        GroupInfo {
            payload: vgi.payload,
            signature: vgi.signature,
            serialized_payload: None,
        }
    }
}

/// GroupInfo
///
/// Note: The struct is split into a `GroupInfoTBS` payload and a signature.
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     GroupContext group_context;
///     Extension extensions<V>;
///     MAC confirmation_tag;
///     uint32 signer;
///     /* SignWithLabel(., "GroupInfoTBS", GroupInfoTBS) */
///     opaque signature<V>;
/// } GroupInfo;
/// ```
#[derive(Debug, PartialEq, Clone, TlsSize, SerdeSerialize, SerdeDeserialize)]
#[cfg_attr(feature = "test-utils", derive(TlsDeserialize))]
pub struct GroupInfo {
    payload: GroupInfoTBS,
    signature: Signature,
    #[serde(skip)]
    #[tls_codec(skip)]
    serialized_payload: Option<Vec<u8>>,
}

impl TlsSerializeTrait for GroupInfo {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = 0;
        if let Some(ref bytes) = self.serialized_payload {
            written += writer.write(bytes)?;
        } else {
            written += self.payload.tls_serialize(writer)?;
        }
        written += self.signature.tls_serialize(writer)?;
        Ok(written)
    }
}

impl GroupInfo {
    /// Returns the group context.
    pub fn group_context(&self) -> &GroupContext {
        &self.payload.group_context
    }

    /// Returns the [`GroupInfo`] extensions.
    pub fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }

    /// Returns the [`GroupInfo`] signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the confirmation tag.
    pub(crate) fn confirmation_tag(&self) -> &ConfirmationTag {
        &self.payload.confirmation_tag
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn into_verifiable_group_info(self) -> VerifiableGroupInfo {
        VerifiableGroupInfo {
            payload: GroupInfoTBS {
                group_context: self.payload.group_context,
                extensions: self.payload.extensions,
                confirmation_tag: self.payload.confirmation_tag,
                signer: self.payload.signer,
            },
            signature: self.signature,
        }
    }
}

/// GroupInfo (To Be Signed)
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     GroupContext group_context;
///     Extension extensions<V>;
///     MAC confirmation_tag;
///     uint32 signer;
/// } GroupInfoTBS;
/// ```
#[derive(
    Debug,
    PartialEq,
    Clone,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
    SerdeSerialize,
    SerdeDeserialize,
)]
pub(crate) struct GroupInfoTBS {
    group_context: GroupContext,
    extensions: Extensions,
    confirmation_tag: ConfirmationTag,
    signer: LeafNodeIndex,
}

impl GroupInfoTBS {
    /// Create a new to-be-signed group info.
    pub(crate) fn new(
        group_context: GroupContext,
        extensions: Extensions,
        confirmation_tag: ConfirmationTag,
        signer: LeafNodeIndex,
    ) -> Result<Self, InvalidExtensionError> {
        // validate the extensions
        for extension_type in extensions.iter().map(Extension::extension_type) {
            if extension_type.is_valid_in_group_info() == Some(false) {
                return Err(InvalidExtensionError::IllegalInGroupInfo);
            }
        }

        Ok(Self {
            group_context,
            extensions,
            confirmation_tag,
            signer,
        })
    }
}

#[cfg(test)]
impl GroupInfoTBS {
    pub(crate) fn group_context_mut(&mut self) -> &mut GroupContext {
        &mut self.group_context
    }
}

// -------------------------------------------------------------------------------------------------

impl Signable for GroupInfoTBS {
    type SignedOutput = GroupInfo;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        SIGNATURE_GROUP_INFO_LABEL
    }
}

impl SignedStruct<GroupInfoTBS> for GroupInfo {
    fn from_payload(
        payload: GroupInfoTBS,
        signature: Signature,
        serialized_payload: Vec<u8>,
    ) -> Self {
        Self {
            payload,
            signature,
            serialized_payload: Some(serialized_payload),
        }
    }
}

impl Verifiable for VerifiableGroupInfo {
    type VerifiedStruct = GroupInfo;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.payload.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        SIGNATURE_GROUP_INFO_LABEL
    }

    fn verify(
        self,
        crypto: &impl OpenMlsCrypto,
        pk: &crate::ciphersuite::OpenMlsSignaturePublicKey,
    ) -> Result<Self::VerifiedStruct, crate::ciphersuite::signable::SignatureError> {
        self.verify_no_out(crypto, pk)?;
        Ok(GroupInfo {
            payload: self.payload,
            signature: self.signature,
            serialized_payload: None,
        })
    }
}

impl VerifiedStruct for GroupInfo {}
