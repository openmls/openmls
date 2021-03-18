use crate::ciphersuite::{signable::*, *};
use crate::codec::*;
use crate::config::Config;
use crate::config::ProtocolVersion;
use crate::credentials::*;
use crate::extensions::*;
use crate::framing::Mac;
use crate::group::*;
use crate::schedule::psk::PreSharedKeys;
use crate::schedule::{ConfirmationKey, JoinerSecret};
use crate::tree::{index::*, *};

use serde::{Deserialize, Serialize};

mod codec;

pub mod errors;
pub(crate) mod proposals;

pub use codec::*;
pub use errors::*;
use proposals::*;

#[cfg(test)]
mod tests;

/// Welcome Messages
///
/// > 11.2.2. Welcoming New Members
///
/// ```text
/// struct {
///   ProtocolVersion version = mls10;
///   CipherSuite cipher_suite;
///   EncryptedGroupSecrets secrets<0..2^32-1>;
///   opaque encrypted_group_info<1..2^32-1>;
/// } Welcome;
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Welcome {
    version: ProtocolVersion,
    cipher_suite: &'static Ciphersuite,
    secrets: Vec<EncryptedGroupSecrets>,
    encrypted_group_info: Vec<u8>,
}

/// EncryptedGroupSecrets
///
/// > 11.2.2. Welcoming New Members
///
/// ```text
/// struct {
///   opaque key_package_hash<1..255>;
///   HPKECiphertext encrypted_group_secrets;
/// } EncryptedGroupSecrets;
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptedGroupSecrets {
    pub key_package_hash: Vec<u8>,
    pub encrypted_group_secrets: HpkeCiphertext,
}

impl Welcome {
    /// Create a new welcome message from the provided data.
    /// Note that secrets and the encrypted group info are consumed.
    pub(crate) fn new(
        version: ProtocolVersion,
        cipher_suite: &'static Ciphersuite,
        secrets: Vec<EncryptedGroupSecrets>,
        encrypted_group_info: Vec<u8>,
    ) -> Self {
        Self {
            version,
            cipher_suite,
            secrets,
            encrypted_group_info,
        }
    }

    /// Get a reference to the ciphersuite in this Welcome message.
    pub(crate) fn ciphersuite(&self) -> &'static Ciphersuite {
        self.cipher_suite
    }

    /// Get a reference to the encrypted group secrets in this Welcome message.
    pub fn secrets(&self) -> &[EncryptedGroupSecrets] {
        &self.secrets
    }

    /// Get a reference to the encrypted group info.
    pub(crate) fn encrypted_group_info(&self) -> &[u8] {
        &self.encrypted_group_info
    }

    /// Set the welcome's encrypted group info.
    #[cfg(test)]
    pub fn set_encrypted_group_info(&mut self, encrypted_group_info: Vec<u8>) {
        self.encrypted_group_info = encrypted_group_info;
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Commit {
    pub(crate) proposals: Vec<ProposalOrRef>,
    pub(crate) path: Option<UpdatePath>,
}

impl Commit {
    /// Returns `true` if the commit contains an update path. `false` otherwise.
    pub fn has_path(&self) -> bool {
        self.path.is_some()
    }
}

/// Confirmation tag field of MLSPlaintext. For type saftey this is a wrapper
/// around a `Mac`.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ConfirmationTag(pub(crate) Mac);

impl ConfirmationTag {
    /// Create a new confirmation tag.
    ///
    /// >  11.2. Commit
    ///
    /// ```text
    /// MLSPlaintext.confirmation_tag =
    ///     MAC(confirmation_key, GroupContext.confirmed_transcript_hash)
    /// ```
    pub fn new(
        ciphersuite: &Ciphersuite,
        confirmation_key: &ConfirmationKey,
        confirmed_transcript_hash: &[u8],
    ) -> Self {
        ConfirmationTag(
            ciphersuite
                .mac(
                    confirmation_key.secret(),
                    &Secret::from(confirmed_transcript_hash.to_vec()),
                )
                .into(),
        )
    }
}

impl From<ConfirmationTag> for Vec<u8> {
    fn from(confirmation_tag: ConfirmationTag) -> Self {
        confirmation_tag.0.into()
    }
}

impl From<Vec<u8>> for ConfirmationTag {
    fn from(bytes: Vec<u8>) -> Self {
        ConfirmationTag(bytes.into())
    }
}

/// GroupInfo
///
/// > 11.2.2. Welcoming New Members
///
/// ```text
/// struct {
///   opaque group_id<0..255>;
///   uint64 epoch;
///   opaque tree_hash<0..255>;
///   opaque confirmed_transcript_hash<0..255>;
///   Extension extensions<0..2^32-1>;
///   MAC confirmation_tag;
///   uint32 signer_index;
///   opaque signature<0..2^16-1>;
/// } GroupInfo;
/// ```
pub(crate) struct GroupInfo {
    group_id: GroupId,
    epoch: GroupEpoch,
    tree_hash: Vec<u8>,
    confirmed_transcript_hash: Vec<u8>,
    extensions: Vec<Box<dyn Extension>>,
    confirmation_tag: Vec<u8>,
    signer_index: LeafIndex,
    signature: Signature,
}

impl GroupInfo {
    pub(crate) fn new(
        group_id: GroupId,
        epoch: GroupEpoch,
        tree_hash: Vec<u8>,
        confirmed_transcript_hash: Vec<u8>,
        extensions: Vec<Box<dyn Extension>>,
        confirmation_tag: ConfirmationTag,
        signer_index: LeafIndex,
    ) -> Self {
        Self {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            extensions,
            confirmation_tag: confirmation_tag.into(),
            signer_index,
            signature: Signature::new_empty(),
        }
    }

    /// Get the tree hash as byte slice.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        &self.tree_hash
    }

    /// Get the signer index.
    pub(crate) fn signer_index(&self) -> LeafIndex {
        self.signer_index
    }

    /// Get the signature.
    pub(crate) fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Set the signature.
    pub(crate) fn set_signature(&mut self, signature: Signature) {
        self.signature = signature;
    }

    /// Get the group ID.
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Get the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Get the confirmed transcript hash.
    pub(crate) fn confirmed_transcript_hash(&self) -> &[u8] {
        &self.confirmed_transcript_hash
    }

    /// Get the confirmed tag.
    pub(crate) fn confirmation_tag(&self) -> ConfirmationTag {
        ConfirmationTag::from(self.confirmation_tag.clone())
    }

    /// Get the extensions.
    pub(crate) fn extensions(&self) -> &[Box<dyn Extension>] {
        &self.extensions
    }

    /// Set the group info's extensions.
    #[cfg(test)]
    pub(crate) fn set_extensions(&mut self, extensions: Vec<Box<dyn Extension>>) {
        self.extensions = extensions;
    }
}

impl Signable for GroupInfo {
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        let buffer = &mut vec![];
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.tree_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.confirmed_transcript_hash)?;
        encode_extensions(&self.extensions, buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.confirmation_tag)?;
        self.signer_index.encode(buffer)?;
        Ok(buffer.to_vec())
    }
}

/// PathSecret
///
/// > 11.2.2. Welcoming New Members
///
/// ```text
/// struct {
///   opaque path_secret<1..255>;
/// } PathSecret;
/// ```
pub(crate) struct PathSecret {
    pub path_secret: Secret,
}

/// GroupSecrets
///
/// > 11.2.2. Welcoming New Members
///
/// ```text
/// struct {
///   opaque joiner_secret<1..255>;
///   optional<PathSecret> path_secret;
///   optional<PreSharedKeys> psks;
/// } GroupSecrets;
/// ```

pub(crate) struct GroupSecrets {
    pub(crate) joiner_secret: JoinerSecret,
    pub(crate) path_secret: Option<PathSecret>,
    pub(crate) psks: Option<PreSharedKeys>,
}

impl GroupSecrets {
    /// Create new encoded group secrets.
    pub(crate) fn new_encoded<'a>(
        joiner_secret: &JoinerSecret,
        path_secret: Option<PathSecret>,
        psks_option: impl Into<Option<&'a PreSharedKeys>> + crate::codec::Codec,
    ) -> Result<Vec<u8>, CodecError> {
        let buffer = &mut Vec::new();
        joiner_secret.encode(buffer)?;
        path_secret.encode(buffer)?;
        psks_option.encode(buffer)?;
        Ok(buffer.to_vec())
    }
}

/// PublicGroupState
///
/// ```text
/// struct {
///     CipherSuite cipher_suite;
///     opaque group_id<0..255>;
///     uint64 epoch;
///     opaque tree_hash<0..255>;
///     opaque interim_transcript_hash<0..255>;
///     Extension extensions<0..2^32-1>;
///     HPKEPublicKey external_pub;
///     uint32 signer_index;
///     opaque signature<0..2^16-1>;
/// } PublicGroupState;
/// ```
#[derive(PartialEq, Debug)]
pub struct PublicGroupState {
    pub(crate) ciphersuite: CiphersuiteName,
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) tree_hash: Vec<u8>,
    pub(crate) interim_transcript_hash: Vec<u8>,
    pub(crate) extensions: Vec<Box<dyn Extension>>,
    pub(crate) external_pub: HPKEPublicKey,
    pub(crate) signer_index: LeafIndex,
    pub(crate) signature: Signature,
}

impl PublicGroupState {
    /// Creates a new `PublicGroupState` struct from the current internal state
    /// of the group and signs it.
    pub(crate) fn new(
        mls_group: &MlsGroup,
        credential_bundle: &CredentialBundle,
    ) -> Result<Self, CredentialError> {
        let ciphersuite = mls_group.ciphersuite();
        let (_external_priv, external_pub) = mls_group
            .epoch_secrets()
            .external_secret()
            .derive_external_keypair(ciphersuite)
            .into_keys();

        let group_id = mls_group.group_id().clone();
        let epoch = mls_group.context().epoch();
        let tree_hash = mls_group.tree().tree_hash();
        let interim_transcript_hash = mls_group.interim_transcript_hash().to_vec();
        let extensions = mls_group.extensions();

        let pgstbs = PublicGroupStateTBS {
            group_id: &group_id,
            epoch: &epoch,
            tree_hash: &tree_hash,
            interim_transcript_hash: &interim_transcript_hash,
            extensions: &extensions,
            external_pub: &external_pub,
        };
        let signature = pgstbs.sign(credential_bundle)?;
        Ok(Self {
            ciphersuite: ciphersuite.name(),
            group_id,
            epoch,
            tree_hash,
            interim_transcript_hash,
            extensions,
            external_pub,
            signer_index: mls_group.sender_index(),
            signature,
        })
    }

    /// Verifies the signature of the `PublicGroupState`.
    /// Returns `Ok(())` in case of success and `CredentialError` otherwise.
    pub fn verify(&self, credential_bundle: &CredentialBundle) -> Result<(), CredentialError> {
        let pgstbs = PublicGroupStateTBS {
            group_id: &self.group_id,
            epoch: &self.epoch,
            tree_hash: &self.tree_hash,
            interim_transcript_hash: &self.interim_transcript_hash,
            extensions: &self.extensions,
            external_pub: &self.external_pub,
        };
        let payload = pgstbs
            .encode_detached()
            .map_err(CredentialError::CodecError)?;
        credential_bundle
            .credential()
            .verify(&payload, &self.signature)
    }
}

/// PublicGroupStateTBS
///
/// ```text
/// struct {
///     opaque group_id<0..255>;
///     uint64 epoch;
///     opaque tree_hash<0..255>;
///     opaque interim_transcript_hash<0..255>;
///     Extension extensions<0..2^32-1>;
///     HPKEPublicKey external_pub;
/// } PublicGroupStateTBS;
/// ```
pub(crate) struct PublicGroupStateTBS<'a> {
    pub(crate) group_id: &'a GroupId,
    pub(crate) epoch: &'a GroupEpoch,
    pub(crate) tree_hash: &'a [u8],
    pub(crate) interim_transcript_hash: &'a [u8],
    pub(crate) extensions: &'a [Box<dyn Extension>],
    pub(crate) external_pub: &'a HPKEPublicKey,
}

impl<'a> PublicGroupStateTBS<'a> {
    /// Signs the `PublicGroupStateTBS` with a `CredentialBundle`.
    fn sign(&self, credential_bundle: &CredentialBundle) -> Result<Signature, CredentialError> {
        let payload = self
            .encode_detached()
            .map_err(CredentialError::CodecError)?;
        credential_bundle
            .sign(&payload)
            .map_err(|_| CredentialError::SignatureError)
    }
}
