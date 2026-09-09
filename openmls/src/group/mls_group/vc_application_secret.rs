use crate::components::{
    vc_application_secret::VcApplicationSecretInfo,
    vc_derivation_info::{
        load_vc_epoch_state_and_tree, require_newest_vc_derivation_epoch,
        VirtualClientOperationType, VirtualClientsError,
    },
};

use super::*;

impl MlsGroup {
    /// Use the `operation_context` to derive the next application secret from
    /// the head of this client's own application ratchet in this emulation
    /// group's newest derivation epoch.
    ///
    /// Returns the secret together with the [`VcApplicationSecretInfo`] a
    /// sibling emulator client needs to rederive it with
    /// [`Self::derive_vc_application_secret`]. The secret has the same length
    /// as the emulation group's KDF hash.
    ///
    /// # Warning
    ///
    /// This consumes a generation of the operation secret tree, which is shared
    /// by every operation of the virtual client. Two concurrent calls against
    /// the same derivation epoch can allocate the same generation twice, so an
    /// application that derives from several threads must serialize its calls.
    /// See the `# Concurrency` note on [`OperationSecretTree`].
    ///
    /// [`OperationSecretTree`]: crate::components::vc_operation_tree::OperationSecretTree
    pub fn next_vc_application_secret<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        operation_context: &[u8],
    ) -> Result<(VcApplicationSecretInfo, Vec<u8>), VirtualClientsError> {
        let epoch_id = require_newest_vc_derivation_epoch(provider.storage(), self.group_id())?;
        let (state, mut operation_tree) = load_vc_epoch_state_and_tree(provider, &epoch_id)?;
        let (leaf_index, _epoch_encryption_key, emulation_ciphersuite) = state.into_parts();
        let (generation, operation_secret) = operation_tree.next_operation_secret(
            provider.crypto(),
            emulation_ciphersuite,
            &epoch_id,
            leaf_index,
            VirtualClientOperationType::Application,
            operation_context,
        )?;
        provider
            .storage()
            .write_vc_operation_tree(&epoch_id, &operation_tree)
            .map_err(|e| {
                log::error!(
                    "vc: persist operation tree after allocating an application secret failed: {e:?}"
                );
                VirtualClientsError::StorageError
            })?;
        let info = VcApplicationSecretInfo {
            epoch_id,
            leaf_index,
            generation,
        };
        Ok((info, operation_secret.as_slice().to_vec()))
    }

    /// Rederive the application secret a sibling emulator client of this
    /// emulation group took from its own application ratchet, from the
    /// [`VcApplicationSecretInfo`] it published and the `operation_context` the
    /// application agreed on.
    ///
    /// The same concurrency requirement as for
    /// [`Self::next_vc_application_secret`] applies.
    pub fn derive_vc_application_secret<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        info: &VcApplicationSecretInfo,
        operation_context: &[u8],
    ) -> Result<Vec<u8>, VirtualClientsError> {
        let (state, mut operation_tree) = load_vc_epoch_state_and_tree(provider, &info.epoch_id)?;
        let (own_leaf_index, _epoch_encryption_key, emulation_ciphersuite) = state.into_parts();
        if info.leaf_index == own_leaf_index {
            log::error!("vc: application secret coordinates name the caller's own leaf index.");
            return Err(VirtualClientsError::OwnLeafIndex);
        }
        let operation_secret = operation_tree.derive_operation_secret(
            provider.crypto(),
            emulation_ciphersuite,
            &info.epoch_id,
            info.leaf_index,
            VirtualClientOperationType::Application,
            info.generation,
            operation_context,
        )?;
        provider
            .storage()
            .write_vc_operation_tree(&info.epoch_id, &operation_tree)
            .map_err(|e| {
                log::error!(
                    "vc: persist operation tree after rederiving an application secret failed: {e:?}"
                );
                VirtualClientsError::StorageError
            })?;
        Ok(operation_secret.as_slice().to_vec())
    }
}
