use crate::messages::GroupInfo;

use super::*;

impl MlsGroup {
    // === Export secrets ===

    /// Exports a secret from the current epoch
    pub fn export_secret(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, MlsGroupError> {
        if self.is_active() {
            Ok(self
                .group
                .export_secret(backend, label, context, key_length)?)
        } else {
            Err(MlsGroupError::UseAfterEviction(UseAfterEviction::Error))
        }
    }

    /// Returns the authentication secret
    pub fn authentication_secret(&self) -> Vec<u8> {
        self.group.authentication_secret()
    }

    /// Returns a resumption secret for a given epoch. If no resumption secret
    /// is available `None` is returned.
    pub fn get_resumption_secret(&self, epoch: GroupEpoch) -> Option<&ResumptionSecret> {
        self.resumption_secret_store.get(epoch)
    }

    // === Export public group state ===

    /// Returns the `GroupInfo` object of this group and epoch for use in an
    /// external commit. In particular, the returned `GroupInfo` instance
    /// includes an `ExternalPub` extension.
    pub fn export_group_info(
        &self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<GroupInfo, MlsGroupError> {
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(self.credential()?.signature_key())
            .ok_or(MlsGroupError::NoMatchingCredentialBundle)?;
        Ok(self.group.export_group_info(backend, &credential_bundle)?)
    }
}
