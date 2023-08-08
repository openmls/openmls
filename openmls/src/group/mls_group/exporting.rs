use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;

use crate::{group::errors::ExporterError, schedule::EpochAuthenticator};

use super::*;

impl MlsGroup {
    // === Export secrets ===

    /// Exports a secret from the current epoch.
    /// Returns [`ExportSecretError::KeyLengthTooLong`] if the requested
    /// key length is too long.
    /// Returns [`ExportSecretError::GroupStateError(MlsGroupStateError::UseAfterEviction)`](MlsGroupStateError::UseAfterEviction)
    /// if the group is not active.
    pub fn export_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, ExportSecretError> {
        if self.is_active() {
            Ok(self
                .group
                .export_secret(crypto, label, context, key_length)
                .map_err(|e| match e {
                    ExporterError::LibraryError(e) => e.into(),
                    ExporterError::KeyLengthTooLong => ExportSecretError::KeyLengthTooLong,
                })?)
        } else {
            Err(ExportSecretError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ))
        }
    }

    /// Returns the epoch authenticator of the current epoch.
    pub fn epoch_authenticator(&self) -> &EpochAuthenticator {
        self.group.epoch_authenticator()
    }

    /// Returns the resumption PSK secret of the current epoch.
    pub fn resumption_psk_secret(&self) -> &ResumptionPskSecret {
        self.group.resumption_psk_secret()
    }

    /// Returns a resumption psk for a given epoch. If no resumption psk
    /// is available for that epoch,  `None` is returned.
    pub fn get_past_resumption_psk(&self, epoch: GroupEpoch) -> Option<&ResumptionPskSecret> {
        self.group.resumption_psk_store.get(epoch)
    }

    /// Export a group info object for this group.
    pub fn export_group_info(
        &self,
        crypto: &impl OpenMlsCrypto,
        signer: &impl Signer,
        with_ratchet_tree: bool,
    ) -> Result<MlsMessageOut, ExportGroupInfoError> {
        Ok(self
            .group
            .export_group_info(crypto, signer, with_ratchet_tree)?
            .into())
    }
}
