use crate::ciphersuite::{signable::*, *};
use crate::codec::*;
use crate::config::Config;
use crate::config::ProtocolVersion;
use crate::extensions::*;
use crate::group::*;
use crate::schedule::psk::PreSharedKeys;
use crate::schedule::JoinerSecret;
use crate::tree::{index::*, *};

mod codec;
pub(crate) mod proposals;
pub use codec::*;
use proposals::*;

#[cfg(test)]
mod test_proposals;

#[cfg(test)]
mod test_welcome;

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
    pub fn ciphersuite(&self) -> &'static Ciphersuite {
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
}

#[derive(Debug, PartialEq, Clone)]
pub struct Commit {
    pub(crate) proposals: Vec<ProposalID>,
    pub(crate) path: Option<UpdatePath>,
}

impl Commit {
    /// Returns `true` if the commit contains an update path. `false` otherwise.
    pub fn has_path(&self) -> bool {
        self.path.is_some()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConfirmationTag(pub(crate) Vec<u8>);

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
        confirmation_key: &Secret,
        confirmed_transcript_hash: &[u8],
    ) -> Self {
        ConfirmationTag(
            ciphersuite
                .hkdf_extract(
                    Some(confirmation_key),
                    &Secret::from(confirmed_transcript_hash.to_vec()),
                )
                .to_vec(),
        )
    }

    /// Get a copy of the raw byte vector.
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
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
        confirmation_tag: Vec<u8>,
        signer_index: LeafIndex,
    ) -> Self {
        Self {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            extensions,
            confirmation_tag,
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
    pub(crate) fn confirmation_tag(&self) -> &[u8] {
        &self.confirmation_tag
    }

    /// Get the extensions.
    pub(crate) fn extensions(&self) -> &[Box<dyn Extension>] {
        &self.extensions
    }

    /// Get the extensions as mutable reference.
    pub(crate) fn extensions_mut(&mut self) -> &mut Vec<Box<dyn Extension>> {
        &mut self.extensions
    }
}

impl GroupInfo {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = Cursor::new(bytes);
        let group_id = GroupId::decode(&mut cursor)?;
        let epoch = GroupEpoch::decode(&mut cursor)?;
        let tree_hash = decode_vec(VecSize::VecU8, &mut cursor)?;
        let confirmed_transcript_hash = decode_vec(VecSize::VecU8, &mut cursor)?;
        let extensions = extensions_vec_from_cursor(&mut cursor)?;
        let confirmation_tag = decode_vec(VecSize::VecU8, &mut cursor)?;
        let signer_index = LeafIndex::from(u32::decode(&mut cursor)?);
        let signature = Signature::decode(&mut cursor)?;
        Ok(GroupInfo {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            extensions,
            confirmation_tag,
            signer_index,
            signature,
        })
    }
}

impl Signable for GroupInfo {
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        let buffer = &mut vec![];
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.tree_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.confirmed_transcript_hash)?;
        // Get extensions encoded. We need to build a Vec::<ExtensionStruct> first.
        let encoded_extensions: Vec<ExtensionStruct> = self
            .extensions
            .iter()
            .map(|e| e.to_extension_struct())
            .collect();
        encode_vec(VecSize::VecU16, buffer, &encoded_extensions)?;
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
#[allow(dead_code)]
pub(crate) struct GroupSecrets {
    pub(crate) joiner_secret: JoinerSecret,
    pub(crate) path_secret: Option<PathSecret>,
    pub(crate) psks: Option<PreSharedKeys>,
}

impl GroupSecrets {
    /// Create a new group secret.
    pub(crate) fn new(joiner_secret: JoinerSecret, path_secret: Option<PathSecret>) -> Self {
        Self {
            joiner_secret,
            path_secret,
            psks: None,
        }
    }
}
