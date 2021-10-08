use super::*;

impl ManagedGroup {
    // === Export secrets ===

    /// Exports a secret from the current epoch
    pub fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, ManagedGroupError> {
        if self.active {
            Ok(self.group.export_secret(label, context, key_length)?)
        } else {
            Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error))
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
}
