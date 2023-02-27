//! # Messages
//!
//! This module contains the types and implementations for Commit & Welcome messages,
//! as well as Proposals & the group info used for External Commits.

use crate::{
    ciphersuite::{hash_ref::KeyPackageRef, *},
    error::LibraryError,
    schedule::{psk::PreSharedKeyId, JoinerSecret},
    treesync::{
        node::encryption_keys::{EncryptionKey, EncryptionKeyPair, EncryptionPrivateKey},
        treekem::UpdatePath,
    },
    versions::ProtocolVersion,
};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, HpkeCiphertext},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Private
use proposals::*;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerializeTrait, *};

// Public
pub mod external_proposals;
pub mod group_info;
pub mod proposals;

// Tests
#[cfg(test)]
mod tests;
#[cfg(test)]
use crate::schedule::psk::{ExternalPsk, Psk};

// Public types

/// Welcome message
///
/// This message is generated when a new member is added to a group.
/// The invited member can use this message to join the group using
/// [`MlsGroup::new_from_welcome()`](crate::group::mls_group::MlsGroup::new_from_welcome()).
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///   CipherSuite cipher_suite;
///   EncryptedGroupSecrets secrets<V>;
///   opaque encrypted_group_info<V>;
/// } Welcome;
/// ```
#[derive(Clone, Debug, Eq, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Welcome {
    cipher_suite: Ciphersuite,
    secrets: Vec<EncryptedGroupSecrets>,
    encrypted_group_info: VLBytes,
}

impl Welcome {
    /// Create a new welcome message from the provided data.
    /// Note that secrets and the encrypted group info are consumed.
    pub(crate) fn new(
        cipher_suite: Ciphersuite,
        secrets: Vec<EncryptedGroupSecrets>,
        encrypted_group_info: Vec<u8>,
    ) -> Self {
        Self {
            cipher_suite,
            secrets,
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

    /// Set the welcome's encrypted group info.
    #[cfg(test)]
    pub fn set_encrypted_group_info(&mut self, encrypted_group_info: Vec<u8>) {
        self.encrypted_group_info = encrypted_group_info.into();
    }
}

/// EncryptedGroupSecrets
///
/// This is part of a [`Welcome`] message. It can be used to correlate the correct secrets with each new member.
#[derive(Clone, Debug, Eq, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
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
        self.new_member.clone()
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
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     ProposalOrRef proposals<V>;
///     optional<UpdatePath> path;
/// } Commit;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub(crate) struct Commit {
    pub(crate) proposals: Vec<ProposalOrRef>,
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

/// Confirmation tag field of PublicMessage. For type safety this is a wrapper
/// around a `Mac`.
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ConfirmationTag(pub(crate) Mac);

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
    ) -> Result<EncryptionKeyPair, LibraryError> {
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
        )
            .into())
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
        public_key: &EncryptionKey,
        group_context: &[u8],
    ) -> Result<HpkeCiphertext, LibraryError> {
        public_key.encrypt(
            backend,
            ciphersuite,
            group_context,
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
        private_key: &EncryptionPrivateKey,
        group_context: &[u8],
    ) -> Result<PathSecret, PathSecretError> {
        // ValSem203: Path secrets must decrypt correctly
        private_key
            .decrypt(backend, ciphersuite, version, ciphertext, group_context)
            .map(|path_secret| Self { path_secret })
            .map_err(|e| e.into())
    }
}

/// Path secret error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum PathSecretError {
    /// See [`hpke::Error`] for more details.
    #[error(transparent)]
    DecryptionError(#[from] hpke::Error),
}

/// GroupSecrets
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///   opaque joiner_secret<V>;
///   optional<PathSecret> path_secret;
///   PreSharedKeyID psks<V>;
/// } GroupSecrets;
/// ```
#[derive(Debug, TlsDeserialize, TlsSize)]
pub(crate) struct GroupSecrets {
    pub(crate) joiner_secret: JoinerSecret,
    pub(crate) path_secret: Option<PathSecret>,
    pub(crate) psks: Vec<PreSharedKeyId>,
}

#[derive(TlsSerialize, TlsSize)]
struct EncodedGroupSecrets<'a> {
    pub(crate) joiner_secret: &'a JoinerSecret,
    pub(crate) path_secret: Option<&'a PathSecret>,
    pub(crate) psks: &'a [PreSharedKeyId],
}

/// Error related to group secrets.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum GroupSecretsError {
    /// Decryption failed.
    #[error("Decryption failed.")]
    DecryptionFailed,
    /// Malformed.
    #[error("Malformed.")]
    Malformed,
}

impl GroupSecrets {
    /// Try to decrypt (and parse) a ciphertext into group secrets.
    pub(crate) fn try_from_ciphertext(
        skey: &HpkePrivateKey,
        ciphertext: &HpkeCiphertext,
        context: &[u8],
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<Self, GroupSecretsError> {
        let group_secrets_plaintext = hpke::decrypt_with_label(
            skey.as_slice(),
            "Welcome",
            context,
            ciphertext,
            ciphersuite,
            crypto,
        )
        .map_err(|_| GroupSecretsError::DecryptionFailed)?;

        let mut group_secrets_plaintext_slice = &mut group_secrets_plaintext.as_slice();

        let group_secrets = GroupSecrets::tls_deserialize(&mut group_secrets_plaintext_slice)
            .map_err(|_| GroupSecretsError::Malformed)?
            // TODO(#1065)
            .config(ciphersuite, ProtocolVersion::Mls10);

        // Check that no extraneous data was encrypted.
        if !group_secrets_plaintext_slice.is_empty() {
            return Err(GroupSecretsError::Malformed);
        }

        Ok(group_secrets)
    }

    /// Create new encoded group secrets.
    pub(crate) fn new_encoded<'a>(
        joiner_secret: &JoinerSecret,
        path_secret: Option<&'a PathSecret>,
        psks: &'a [PreSharedKeyId],
    ) -> Result<Vec<u8>, tls_codec::Error> {
        EncodedGroupSecrets {
            joiner_secret,
            path_secret,
            psks,
        }
        .tls_serialize_detached()
    }

    /// Set the config for the secrets, i.e. ciphersuite and MLS version.
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
}

#[cfg(test)]
impl GroupSecrets {
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
        let psks = vec![psk_id];

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
