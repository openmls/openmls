use crate::ciphersuite::{signable::*, *};
use crate::codec::*;
use crate::config::Config;
use crate::config::ProtocolVersion;
use crate::extensions::*;
use crate::group::*;
use crate::schedule::JoinerSecret;
use crate::tree::{index::*, *};

pub(crate) mod proposals;
use proposals::*;

#[cfg(test)]
mod test_proposals;

#[cfg(test)]
mod test_welcome;

#[derive(Debug, PartialEq, Clone)]
pub struct Commit {
    pub proposals: Vec<ProposalID>,
    pub path: Option<UpdatePath>,
}

impl Codec for Commit {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU32, buffer, &self.proposals)?;
        self.path.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let proposals = decode_vec(VecSize::VecU32, cursor)?;
        let path = Option::<UpdatePath>::decode(cursor)?;
        Ok(Commit { proposals, path })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConfirmationTag(pub Vec<u8>);

impl ConfirmationTag {
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
    pub fn new_empty() -> Self {
        ConfirmationTag(vec![])
    }
    pub fn as_slice(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Codec for ConfirmationTag {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.0)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let inner = decode_vec(VecSize::VecU8, cursor)?;
        Ok(ConfirmationTag(inner))
    }
}

pub struct GroupInfo {
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

impl Codec for GroupInfo {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.append(&mut self.unsigned_payload()?);
        self.signature.encode(buffer)?;
        Ok(())
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

pub struct PathSecret {
    pub path_secret: Secret,
}

impl Codec for PathSecret {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.path_secret.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let path_secret = Secret::decode(cursor)?;
        Ok(PathSecret { path_secret })
    }
}

pub struct GroupSecrets {
    pub joiner_secret: JoinerSecret,
    pub path_secret: Option<PathSecret>,
}

impl Codec for GroupSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.joiner_secret.encode(buffer)?;
        self.path_secret.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let joiner_secret = JoinerSecret::decode(cursor)?;
        let path_secret = Option::<PathSecret>::decode(cursor)?;
        Ok(GroupSecrets {
            joiner_secret,
            path_secret,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncryptedGroupSecrets {
    pub key_package_hash: Vec<u8>,
    pub encrypted_group_secrets: HpkeCiphertext,
}

impl Codec for EncryptedGroupSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.key_package_hash)?;
        self.encrypted_group_secrets.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_package_hash = decode_vec(VecSize::VecU8, cursor)?;
        let encrypted_group_secrets = HpkeCiphertext::decode(cursor)?;
        Ok(EncryptedGroupSecrets {
            key_package_hash,
            encrypted_group_secrets,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Welcome {
    version: ProtocolVersion,
    cipher_suite: &'static Ciphersuite,
    secrets: Vec<EncryptedGroupSecrets>,
    encrypted_group_info: Vec<u8>,
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

    /// Get a reference to the ciphersuite in this Welcome message.
    pub fn get_secrets_ref(&self) -> &[EncryptedGroupSecrets] {
        &self.secrets
    }

    /// Get a reference to the encrypted group info.
    pub(crate) fn get_encrypted_group_info_ref(&self) -> &[u8] {
        &self.encrypted_group_info
    }
}

impl Codec for Welcome {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.version.encode(buffer)?;
        self.cipher_suite.name().encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.secrets)?;
        encode_vec(VecSize::VecU32, buffer, &self.encrypted_group_info)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let version = ProtocolVersion::decode(cursor)?;
        let cipher_suite = CiphersuiteName::decode(cursor)?;
        let secrets = decode_vec(VecSize::VecU32, cursor)?;
        let encrypted_group_info = decode_vec(VecSize::VecU32, cursor)?;
        Ok(Welcome {
            version,
            cipher_suite: Config::ciphersuite(cipher_suite)?,
            secrets,
            encrypted_group_info,
        })
    }
}
