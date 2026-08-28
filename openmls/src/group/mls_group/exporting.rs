use std::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use errors::{ExportGroupInfoError, ExportSecretError};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer};
use zeroize::ZeroizeOnDrop;

use crate::{
    ciphersuite::{HpkePublicKey, Secret},
    extensions::errors::InvalidExtensionError,
    schedule::{EpochAuthenticator, ResumptionPskSecret},
};
#[cfg(feature = "extensions-draft")]
use crate::{
    component::ComponentId,
    group::{PendingSafeExportSecretError, SafeExportSecretError},
};

use super::*;

/// A secret exported from a group.
///
/// The marker type `T` records which export function produced the secret, so
/// secrets from different export paths cannot be confused.
pub struct ExportedSecret<T> {
    secret: Secret,
    _marker: PhantomData<T>,
}

/// Marker for secrets exported via [`MlsGroup::export_secret`].
pub struct GroupExport;

/// Marker for secrets exported via [`StagedCommit::export_secret`].
pub struct StagedCommitExport;

/// Marker for secrets exported via [`StagedWelcome::export_secret`].
pub struct StagedWelcomeExport;

/// Marker for secrets exported via [`ProcessedWelcome::export_secret`].
pub struct ProcessedWelcomeExport;

/// Marker for secrets exported via [`MlsGroup::safe_export_secret`].
#[cfg(feature = "extensions-draft")]
pub struct GroupSafeExport;

/// Marker for secrets exported via
/// [`MlsGroup::safe_export_secret_from_pending`].
#[cfg(feature = "extensions-draft")]
pub struct PendingSafeExport;

/// Marker for secrets exported via [`StagedCommit::safe_export_secret`] or
/// [`ProcessedMessage::safe_export_secret`].
///
/// [`ProcessedMessage::safe_export_secret`]: crate::framing::ProcessedMessage::safe_export_secret
#[cfg(feature = "extensions-draft")]
pub struct StagedCommitSafeExport;

impl<T> ExportedSecret<T> {
    pub(crate) fn new(secret: Secret) -> Self {
        Self {
            secret,
            _marker: PhantomData,
        }
    }

    /// Returns the secret bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

#[cfg(feature = "extensions-draft")]
impl ExportedSecret<StagedCommitSafeExport> {
    /// Re-wraps a safe export of a staged commit as a safe export of the
    /// pending commit, for [`MlsGroup::safe_export_secret_from_pending`].
    pub(crate) fn into_pending_safe_export(self) -> ExportedSecret<PendingSafeExport> {
        ExportedSecret::new(self.secret)
    }
}

impl<T> AsRef<[u8]> for ExportedSecret<T> {
    fn as_ref(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

// The inner [`Secret`] is zeroized when dropped.
impl<T> ZeroizeOnDrop for ExportedSecret<T> {}

impl<T> Debug for ExportedSecret<T> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("ExportedSecret")
            .field("secret", &self.secret)
            .finish()
    }
}

impl<T, U> PartialEq<ExportedSecret<U>> for ExportedSecret<T> {
    // Constant time comparison.
    fn eq(&self, other: &ExportedSecret<U>) -> bool {
        self.secret == other.secret
    }
}

impl MlsGroup {
    // === Export secrets ===

    /// Exports a secret from the current epoch.
    /// Returns [`ExportSecretError::KeyLengthTooLong`] if the requested
    /// key length is too long.
    /// Returns [`ExportSecretError::GroupStateError(MlsGroupStateError::UseAfterEviction)`](MlsGroupStateError::UseAfterEviction)
    /// if the group is not active.
    pub fn export_secret<CryptoProvider: OpenMlsCrypto>(
        &self,
        crypto: &CryptoProvider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<ExportedSecret<GroupExport>, ExportSecretError> {
        if key_length > u16::MAX as usize {
            log::error!("Got a key that is larger than u16::MAX");
            return Err(ExportSecretError::KeyLengthTooLong);
        }

        if self.is_active() {
            Ok(ExportedSecret::new(
                self.group_epoch_secrets
                    .exporter_secret()
                    .derive_exported_secret(self.ciphersuite(), crypto, label, context, key_length)
                    .map_err(LibraryError::unexpected_crypto_error)?,
            ))
        } else {
            Err(ExportSecretError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ))
        }
    }

    /// Export a secret from the forward secure exporter for the component with
    /// the given component ID.
    #[cfg(feature = "extensions-draft")]
    pub fn safe_export_secret<Crypto: OpenMlsCrypto, Storage: StorageProvider>(
        &mut self,
        crypto: &Crypto,
        storage: &Storage,
        component_id: ComponentId,
    ) -> Result<ExportedSecret<GroupSafeExport>, SafeExportSecretError<Storage::Error>> {
        if !self.is_active() {
            return Err(SafeExportSecretError::GroupState(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        let group_id = self.public_group.group_id();
        let ciphersuite = self.ciphersuite();
        let Some(application_export_tree) = self.application_export_tree.as_mut() else {
            return Err(SafeExportSecretError::Unsupported);
        };
        let component_secret =
            application_export_tree.safe_export_secret(crypto, ciphersuite, component_id)?;
        storage
            .write_application_export_tree(group_id, application_export_tree)
            .map_err(SafeExportSecretError::Storage)?;

        Ok(ExportedSecret::new(component_secret))
    }

    /// Export a secret from the forward secure exporter of the pending commit
    /// state for the component with the given component ID.
    #[cfg(feature = "extensions-draft")]
    pub fn safe_export_secret_from_pending<Provider: StorageProvider>(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        storage: &Provider,
        component_id: ComponentId,
    ) -> Result<ExportedSecret<PendingSafeExport>, PendingSafeExportSecretError<Provider::Error>>
    {
        let group_id = self.group_id().clone();
        let MlsGroupState::PendingCommit(ref mut group_state) = self.group_state else {
            return Err(PendingSafeExportSecretError::NoPendingCommit);
        };
        let PendingCommitState::Member(ref mut staged_commit) = **group_state else {
            return Err(PendingSafeExportSecretError::NotGroupMember);
        };
        let secret = staged_commit.safe_export_secret(crypto, component_id)?;
        storage
            .write_group_state(&group_id, &self.group_state)
            .map_err(PendingSafeExportSecretError::Storage)?;
        Ok(secret.into_pending_safe_export())
    }

    /// Returns the epoch authenticator of the current epoch.
    pub fn epoch_authenticator(&self) -> &EpochAuthenticator {
        self.group_epoch_secrets().epoch_authenticator()
    }

    /// Returns the resumption PSK secret of the current epoch.
    pub fn resumption_psk_secret(&self) -> &ResumptionPskSecret {
        self.group_epoch_secrets().resumption_psk()
    }

    /// Export the information a sub-group branch needs from this (parent) group,
    /// as described in [RFC 9420 §11.3].
    ///
    /// Hand the resulting [`BranchInfo`] to the sender
    /// ([`MlsGroupBuilder::branch`](crate::group::MlsGroupBuilder::branch)) and to
    /// the receiver
    /// ([`StagedWelcome::build_from_branch`](crate::group::StagedWelcome::build_from_branch)).
    ///
    /// The returned [`BranchInfo`] carries this group's resumption PSK secret,
    /// which is sensitive key material.
    ///
    /// [RFC 9420 §11.3]: https://www.rfc-editor.org/rfc/rfc9420.html#name-subgroup-branching
    pub fn branch_info(&self) -> BranchInfo {
        BranchInfo {
            version: self.version(),
            ciphersuite: self.ciphersuite(),
            group_id: self.group_id().clone(),
            epoch: self.epoch(),
            resumption_psk_secret: self.resumption_psk_secret().clone(),
            member_credentials: self.members().map(|m| m.credential).collect(),
        }
    }

    /// Returns a resumption psk for a given epoch. If no resumption psk
    /// is available for that epoch,  `None` is returned.
    pub fn get_past_resumption_psk(&self, epoch: GroupEpoch) -> Option<&ResumptionPskSecret> {
        self.resumption_psk_store.get(epoch)
    }

    /// Export a group info object for this group.
    pub fn export_group_info<CryptoProvider: OpenMlsCrypto>(
        &self,
        crypto: &CryptoProvider,
        signer: &impl Signer,
        with_ratchet_tree: bool,
    ) -> Result<MlsMessageOut, ExportGroupInfoError> {
        self.export_group_info_with_additional_extensions(crypto, signer, with_ratchet_tree, None)
    }

    /// Export a group info object for this group, with additional extensions.
    ///
    ///  Returns an error if a  [`RatchetTreeExtension`] or [`ExternalPubExtension`] is added
    ///  directly here.
    pub fn export_group_info_with_additional_extensions<CryptoProvider: OpenMlsCrypto>(
        &self,
        crypto: &CryptoProvider,
        signer: &impl Signer,
        with_ratchet_tree: bool,
        additional_extensions: impl IntoIterator<Item = Extension>,
    ) -> Result<MlsMessageOut, ExportGroupInfoError> {
        let extensions = {
            let ratchet_tree_extension = || {
                Extension::RatchetTree(RatchetTreeExtension::new(
                    self.public_group().export_ratchet_tree(),
                ))
            };

            let external_pub_extension = || -> Result<Extension, ExportGroupInfoError> {
                let external_pub = self
                    .group_epoch_secrets()
                    .external_secret()
                    .derive_external_keypair(crypto, self.ciphersuite())
                    .map_err(LibraryError::unexpected_crypto_error)?
                    .public;
                Ok(Extension::ExternalPub(ExternalPubExtension::new(
                    HpkePublicKey::from(external_pub),
                )))
            };

            let mut extensions = if with_ratchet_tree {
                vec![ratchet_tree_extension(), external_pub_extension()?]
            } else {
                vec![external_pub_extension()?]
            };

            extensions.extend(
                additional_extensions
                    .into_iter()
                    .map(|extension| {
                        if extension.as_ratchet_tree_extension().is_ok()
                            || extension.as_external_pub_extension().is_ok()
                        {
                            Err(InvalidExtensionError::CannotAddDirectlyToGroupInfo)
                        } else {
                            Ok(extension)
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );

            Extensions::from_vec(extensions)?
        };

        // Create to-be-signed group info.
        let group_info_tbs = GroupInfoTBS::new(
            self.context().clone(),
            extensions,
            self.message_secrets()
                .confirmation_key()
                .tag(
                    crypto,
                    self.ciphersuite(),
                    self.context().confirmed_transcript_hash(),
                )
                .map_err(LibraryError::unexpected_crypto_error)?,
            self.own_leaf_index(),
        )?;

        // Sign to-be-signed group info.
        let group_info = group_info_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))?;
        Ok(group_info.into())
    }
}
