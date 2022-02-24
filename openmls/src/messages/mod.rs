//! # Messages
//!
//! This module contains the types and implementations for Commit & Welcome messages,
//! as well as Proposals & the public group state used for External Commits.

use crate::{
    ciphersuite::hash_ref::KeyPackageRef,
    ciphersuite::{signable::*, *},
    error::LibraryError,
    extensions::*,
    group::*,
    schedule::{psk::PreSharedKeys, JoinerSecret},
    treesync::treekem::UpdatePath,
    versions::ProtocolVersion,
};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, CryptoError, HpkeCiphertext},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Private
use proposals::*;
use tls_codec::{Serialize as TlsSerializeTrait, *};

// Public
pub mod codec;
pub mod proposals;
pub mod public_group_state;

// Tests
#[cfg(test)]
mod tests;
#[cfg(test)]
use crate::credentials::CredentialBundle;
#[cfg(any(feature = "test-utils", test))]
use crate::schedule::psk::{ExternalPsk, PreSharedKeyId, Psk};

// Public types

/// Welcome message
///
/// This message is generated when a new member is added to a group.
/// The invited member can use this message to join the group using
/// [`MlsGroup::new_from_welcome()`](crate::group::mls_group::MlsGroup::new_from_welcome()).
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Welcome {
    version: ProtocolVersion,
    cipher_suite: Ciphersuite,
    secrets: TlsVecU32<EncryptedGroupSecrets>,
    encrypted_group_info: TlsByteVecU32,
}

impl Welcome {
    /// Create a new welcome message from the provided data.
    /// Note that secrets and the encrypted group info are consumed.
    pub(crate) fn new(
        version: ProtocolVersion,
        cipher_suite: Ciphersuite,
        secrets: Vec<EncryptedGroupSecrets>,
        encrypted_group_info: Vec<u8>,
    ) -> Self {
        Self {
            version,
            cipher_suite,
            secrets: secrets.into(),
            encrypted_group_info: encrypted_group_info.into(),
        }
    }

    /// Returns a reference to the ciphersuite in this Welcome message.
    pub(crate) fn ciphersuite(&self) -> Ciphersuite {
        self.cipher_suite
    }

    /// Returns a reference to the encrypted group secrets in this Welcome message.
    pub fn secrets(&self) -> &[EncryptedGroupSecrets] {
        self.secrets.as_slice()
    }

    /// Returns a reference to the encrypted group info.
    pub(crate) fn encrypted_group_info(&self) -> &[u8] {
        self.encrypted_group_info.as_slice()
    }

    /// Returns a reference to the protocol version in the `Welcome`.
    pub(crate) fn version(&self) -> &ProtocolVersion {
        &self.version
    }

    /// Set the welcome's encrypted group info.
    #[cfg(test)]
    pub fn set_encrypted_group_info(&mut self, encrypted_group_info: Vec<u8>) {
        self.encrypted_group_info = encrypted_group_info.into();
    }
}

/// EncryptedGroupSecrets
///
/// This is part of a [`Welcome`] message. It can be used to correlate the correct secrets with each new member.
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct EncryptedGroupSecrets {
    /// Key package reference of the new member
    new_member: KeyPackageRef,
    /// Ciphertext of the encrypted group secret
    encrypted_group_secrets: HpkeCiphertext,
}

impl EncryptedGroupSecrets {
    /// Build a new [`EncryptedGroupSecrets`].
    pub fn new(new_member: KeyPackageRef, encrypted_group_secrets: HpkeCiphertext) -> Self {
        Self {
            new_member,
            encrypted_group_secrets,
        }
    }

    /// Returns the encrypted group secrets' new [`KeyPackageRef`].
    pub fn new_member(&self) -> KeyPackageRef {
        self.new_member
    }

    /// Returns a reference to the encrypted group secrets' encrypted group secrets.
    pub(crate) fn encrypted_group_secrets(&self) -> &HpkeCiphertext {
        &self.encrypted_group_secrets
    }
}

// Crate-only types

/// Commit.
///
/// A Commit message initiates a new epoch for the group,
/// based on a collection of Proposals. It instructs group
/// members to update their representation of the state of
/// the group by applying the proposals and advancing the
/// key schedule.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub(crate) struct Commit {
    pub(crate) proposals: TlsVecU32<ProposalOrRef>,
    pub(crate) path: Option<UpdatePath>,
}

impl Commit {
    /// Returns `true` if the commit contains an update path. `false` otherwise.
    #[cfg(test)]
    pub fn has_path(&self) -> bool {
        self.path.is_some()
    }

    /// Returns the update path of the Commit if it has one.
    pub(crate) fn path(&self) -> &Option<UpdatePath> {
        &self.path
    }
}

/// Confirmation tag field of MlsPlaintext. For type safety this is a wrapper
/// around a `Mac`.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ConfirmationTag(pub(crate) Mac);

#[derive(TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct GroupInfoPayload {
    group_id: GroupId,
    epoch: GroupEpoch,
    tree_hash: TlsByteVecU8,
    confirmed_transcript_hash: TlsByteVecU8,
    group_context_extensions: TlsVecU32<Extension>,
    other_extensions: TlsVecU32<Extension>,
    confirmation_tag: ConfirmationTag,
    signer: KeyPackageRef,
}

impl GroupInfoPayload {
    #[allow(clippy::too_many_arguments)] // TODO: #569 refactor GroupInfoPayload
    /// Create a new group info payload struct.
    pub(crate) fn new(
        group_id: GroupId,
        epoch: impl Into<GroupEpoch>,
        tree_hash: Vec<u8>,
        confirmed_transcript_hash: Vec<u8>,
        group_context_extensions: &[Extension],
        other_extensions: &[Extension],
        confirmation_tag: ConfirmationTag,
        signer: &KeyPackageRef,
    ) -> Self {
        Self {
            group_id,
            epoch: epoch.into(),
            tree_hash: tree_hash.into(),
            confirmed_transcript_hash: confirmed_transcript_hash.into(),
            group_context_extensions: group_context_extensions.into(),
            other_extensions: other_extensions.into(),
            confirmation_tag,
            signer: *signer,
        }
    }
}

impl Signable for GroupInfoPayload {
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
///   opaque group_id<0..255>;
///   uint64 epoch;
///   opaque tree_hash<0..255>;
///   opaque confirmed_transcript_hash<0..255>;
///   Extension extensions<0..2^32-1>;
///   MAC confirmation_tag;
///   KeyPackageRef signer;
///   opaque signature<0..2^16-1>;
/// } GroupInfo;
/// ```
pub(crate) struct GroupInfo {
    payload: GroupInfoPayload,
    signature: Signature,
}

impl GroupInfo {
    /// Returns the signer.
    pub(crate) fn signer(&self) -> &KeyPackageRef {
        &self.payload.signer
    }

    /// Returns the group ID.
    pub(crate) fn group_id(&self) -> &GroupId {
        &self.payload.group_id
    }

    /// Returns the epoch.
    pub(crate) fn epoch(&self) -> GroupEpoch {
        self.payload.epoch
    }

    /// Returns the confirmed transcript hash.
    pub(crate) fn confirmed_transcript_hash(&self) -> &[u8] {
        self.payload.confirmed_transcript_hash.as_slice()
    }

    /// Returns the confirmed tag.
    pub(crate) fn confirmation_tag(&self) -> &ConfirmationTag {
        &self.payload.confirmation_tag
    }

    /// Returns other application extensions.
    pub(crate) fn other_extensions(&self) -> &[Extension] {
        self.payload.other_extensions.as_slice()
    }

    /// Returns the [`GroupContext`] extensions.
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
    ) -> Result<Self, LibraryError> {
        self.payload.sign(backend, credential_bundle)
    }
}

impl Verifiable for GroupInfo {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.payload.unsigned_payload()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl SignedStruct<GroupInfoPayload> for GroupInfo {
    fn from_payload(payload: GroupInfoPayload, signature: Signature) -> Self {
        Self { payload, signature }
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
#[derive(Debug, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
pub(crate) struct PathSecret {
    pub(crate) path_secret: Secret,
}

impl From<Secret> for PathSecret {
    fn from(path_secret: Secret) -> Self {
        Self { path_secret }
    }
}

impl PathSecret {
    /// Derives a node secret which in turn is used to derive an HpkeKeyPair.
    pub(crate) fn derive_key_pair(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<(HpkePublicKey, HpkePrivateKey), LibraryError> {
        let node_secret = self
            .path_secret
            .kdf_expand_label(backend, "node", &[], ciphersuite.hash_length())
            .map_err(LibraryError::unexpected_crypto_error)?;
        let key_pair = backend
            .crypto()
            .derive_hpke_keypair(ciphersuite.hpke_config(), node_secret.as_slice());

        Ok((
            HpkePublicKey::from(key_pair.public),
            HpkePrivateKey::from(key_pair.private),
        ))
    }

    /// Derives a path secret.
    pub(crate) fn derive_path_secret(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
    ) -> Result<Self, LibraryError> {
        let path_secret = self
            .path_secret
            .kdf_expand_label(backend, "path", &[], ciphersuite.hash_length())
            .map_err(LibraryError::unexpected_crypto_error)?;
        Ok(Self { path_secret })
    }

    /// Encrypt the path secret under the given `HpkePublicKey` using the given
    /// `group_context`.
    pub(crate) fn encrypt(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        public_key: &HpkePublicKey,
        group_context: &[u8],
    ) -> HpkeCiphertext {
        backend.crypto().hpke_seal(
            ciphersuite.hpke_config(),
            public_key.as_slice(),
            group_context,
            &[],
            self.path_secret.as_slice(),
        )
    }

    /// Consume the `PathSecret`, returning the internal `Secret` value.
    pub(crate) fn secret(self) -> Secret {
        self.path_secret
    }

    /// Decrypt a given `HpkeCiphertext` using the `private_key` and `group_context`.
    ///
    /// Returns the decrypted `PathSecret`. Returns an error if the decryption
    /// was unsuccessful.
    ///
    /// ValSem203: Path secrets must decrypt correctly
    pub(crate) fn decrypt(
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: Ciphersuite,
        version: ProtocolVersion,
        ciphertext: &HpkeCiphertext,
        private_key: &HpkePrivateKey,
        group_context: &[u8],
    ) -> Result<PathSecret, PathSecretError> {
        // ValSem203: Path secrets must decrypt correctly
        let secret_bytes = backend.crypto().hpke_open(
            ciphersuite.hpke_config(),
            ciphertext,
            private_key.as_slice(),
            group_context,
            &[],
        )?;
        let path_secret = Secret::from_slice(&secret_bytes, version, ciphersuite);
        Ok(Self { path_secret })
    }
}

/// Path secret error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum PathSecretError {
    /// See [`CryptoError`] for more details.
    #[error(transparent)]
    DecryptionError(#[from] CryptoError),
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
#[derive(TlsDeserialize, TlsSize)]
pub(crate) struct GroupSecrets {
    pub(crate) joiner_secret: JoinerSecret,
    pub(crate) path_secret: Option<PathSecret>,
    pub(crate) psks: PreSharedKeys,
}

#[derive(TlsSerialize, TlsSize)]
struct EncodedGroupSecrets<'a> {
    pub(crate) joiner_secret: &'a JoinerSecret,
    pub(crate) path_secret: Option<&'a PathSecret>,
    pub(crate) psks: &'a PreSharedKeys,
}

impl GroupSecrets {
    /// Create new encoded group secrets.
    pub(crate) fn new_encoded<'a>(
        joiner_secret: &JoinerSecret,
        path_secret: Option<&'a PathSecret>,
        psks: &'a PreSharedKeys,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        EncodedGroupSecrets {
            joiner_secret,
            path_secret,
            psks,
        }
        .tls_serialize_detached()
    }

    /// Set the config for the secrets, i.e. cipher suite and MLS version.
    pub(crate) fn config(
        mut self,
        ciphersuite: Ciphersuite,
        mls_version: ProtocolVersion,
    ) -> GroupSecrets {
        self.joiner_secret.config(ciphersuite, mls_version);
        if let Some(s) = &mut self.path_secret {
            s.path_secret.config(ciphersuite, mls_version);
        }
        self
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn random_encoded(
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        version: ProtocolVersion,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        use openmls_traits::random::OpenMlsRand;

        let psk_id = PreSharedKeyId::new(
            ciphersuite,
            backend.rand(),
            Psk::External(ExternalPsk::new(
                backend
                    .rand()
                    .random_vec(ciphersuite.hash_length())
                    .expect("Not enough randomness."),
            )),
        )
        .expect("An unexpected error occurred.");
        let psks = PreSharedKeys {
            psks: vec![psk_id].into(),
        };

        GroupSecrets::new_encoded(
            &JoinerSecret::random(ciphersuite, backend, version),
            Some(&PathSecret {
                path_secret: Secret::random(ciphersuite, backend, version)
                    .expect("Not enough randomness."),
            }),
            &psks,
        )
    }
}
