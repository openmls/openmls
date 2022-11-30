use tls_codec::Serialize;

use crate::{group::errors::ExporterError, messages::GroupInfo, schedule::EpochAuthenticator};

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
        backend: &impl OpenMlsCryptoProvider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, ExportSecretError> {
        if self.is_active() {
            Ok(self
                .group
                .export_secret(backend, label, context, key_length)
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
        self.resumption_psk_store.get(epoch)
    }

    /// Export a group info object for this group.
    pub fn export_group_info(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        with_ratchet_tree: bool,
    ) -> Result<GroupInfo, ExportGroupInfoError> {
        match self.credential() {
            Ok(credential) => {
                let credential_bundle: CredentialBundle = backend
                    .key_store()
                    .read(
                        &credential
                            .signature_key()
                            .tls_serialize_detached()
                            .map_err(LibraryError::missing_bound_check)?,
                    )
                    .ok_or(ExportGroupInfoError::NoMatchingCredentialBundle)?;
                Ok(self
                    .group
                    .export_group_info(backend, &credential_bundle, with_ratchet_tree)?)
            }
            Err(e) => Err(e.into()),
        }
    }
}
