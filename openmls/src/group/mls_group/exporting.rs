use tls_codec::Serialize;

use crate::{
    group::errors::ExporterError, messages::public_group_state::PublicGroupState,
    schedule::AuthenticationSecret,
};

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

    /// Returns the authentication secret of the current epoch.
    pub fn authentication_secret(&self) -> &AuthenticationSecret {
        self.group.authentication_secret()
    }

    /// Returns the resumption secret of the current epoch.
    pub fn resumption_secret(&self) -> &ResumptionSecret {
        self.group.resumption_secret()
    }

    /// Returns a resumption secret for a given epoch. If no resumption secret
    /// is available for that epoch,  `None` is returned.
    pub fn get_past_resumption_secret(&self, epoch: GroupEpoch) -> Option<&ResumptionSecret> {
        self.resumption_secret_store.get(epoch)
    }

    // === Export public group state ===

    /// Exports the public group state.
    pub fn export_public_group_state(
        &self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<PublicGroupState, ExportPublicGroupStateError> {
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
                    .ok_or(ExportPublicGroupStateError::NoMatchingCredentialBundle)?;
                Ok(self
                    .group
                    .export_public_group_state(backend, &credential_bundle)?)
            }
            Err(e) => Err(e.into()),
        }
    }
}
