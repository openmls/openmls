use errors::{ExportGroupInfoError, ExportSecretError};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer};

#[cfg(feature = "extensions-draft-08")]
use crate::group::{PendingSafeExportSecretError, SafeExportSecretError};
use crate::{
    ciphersuite::HpkePublicKey,
    schedule::{EpochAuthenticator, ResumptionPskSecret},
};

use super::*;

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
    ) -> Result<Vec<u8>, ExportSecretError> {
        if key_length > u16::MAX as usize {
            log::error!("Got a key that is larger than u16::MAX");
            return Err(ExportSecretError::KeyLengthTooLong);
        }

        if self.is_active() {
            Ok(self
                .group_epoch_secrets
                .exporter_secret()
                .derive_exported_secret(self.ciphersuite(), crypto, label, context, key_length)
                .map_err(LibraryError::unexpected_crypto_error)?)
        } else {
            Err(ExportSecretError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ))
        }
    }

    /// Export a secret from the forward secure exporter for the component with
    /// the given component ID.
    #[cfg(feature = "extensions-draft-08")]
    pub fn safe_export_secret<Crypto: OpenMlsCrypto, Storage: StorageProvider>(
        &mut self,
        crypto: &Crypto,
        storage: &Storage,
        component_id: u16,
    ) -> Result<Vec<u8>, SafeExportSecretError<Storage::Error>> {
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

        Ok(component_secret.as_slice().to_vec())
    }

    /// Export a secret from the forward secure exporter of the pending commit
    /// state for the component with the given component ID.
    #[cfg(feature = "extensions-draft-08")]
    pub fn safe_export_secret_from_pending<Provider: StorageProvider>(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        storage: &Provider,
        component_id: u16,
    ) -> Result<Vec<u8>, PendingSafeExportSecretError<Provider::Error>> {
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
        Ok(secret.as_slice().to_vec())
    }

    /// Returns the epoch authenticator of the current epoch.
    pub fn epoch_authenticator(&self) -> &EpochAuthenticator {
        self.group_epoch_secrets().epoch_authenticator()
    }

    /// Returns the resumption PSK secret of the current epoch.
    pub fn resumption_psk_secret(&self) -> &ResumptionPskSecret {
        self.group_epoch_secrets().resumption_psk()
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

            if with_ratchet_tree {
                Extensions::from_vec(vec![ratchet_tree_extension(), external_pub_extension()?])
                    .map_err(|_| {
                        LibraryError::custom(
                            "There should not have been duplicate extensions here.",
                        )
                    })?
            } else {
                Extensions::single(external_pub_extension()?)
            }
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
