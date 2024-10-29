use openmls_traits::crypto::OpenMlsCrypto;

use crate::{
    ciphersuite::Secret,
    framing::mls_auth_content::AuthenticatedContent,
    group::{ProcessMessageError, StageCommitError},
    prelude::Credential,
    schedule::{psk::load_psks, PreSharedKeyId},
    storage::StorageProvider,
    treesync::node::encryption_keys::EncryptionKeyPair,
};

use super::{MlsGroup, ProcessedMessage, ProtocolMessage};

impl MlsGroup {
    pub(super) fn init_message_processing(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        message: impl Into<ProtocolMessage>,
    ) -> Result<InitialProcessingState, ProcessMessageError> {
        let (authenticated_content, credential) =
            self.decrypt_and_verify_message(crypto, message)?;

        Ok(InitialProcessingState {
            group: self,
            authenticated_content,
            credential,
        })
    }
}

pub(super) struct InitialProcessingState<'a> {
    group: &'a mut MlsGroup,
    authenticated_content: AuthenticatedContent,
    credential: Credential,
}

pub(super) struct LoadedKeyMaterial {
    psks: Vec<(PreSharedKeyId, Secret)>,
    old_epoch_keypairs: Vec<EncryptionKeyPair>,
    leaf_node_keypairs: Vec<EncryptionKeyPair>,
}

impl<'a> InitialProcessingState<'a> {
    pub(super) fn load_key_material(
        self,
        storage: &impl StorageProvider,
    ) -> Result<LoadedRequiredKeyMaterial<'a>, ProcessMessageError> {
        let (old_epoch_keypairs, leaf_node_keypairs) =
            self.group.read_decryption_keypairs(storage)?;

        let psk_ids = self
            .authenticated_content
            .committed_psk_proposals(self.group.proposal_store());

        let psks = load_psks(storage, &self.group.resumption_psk_store, &psk_ids)
            .map_err(|e| ProcessMessageError::InvalidCommit(StageCommitError::PskError(e)))?;

        let loaded_key_material = LoadedKeyMaterial {
            psks,
            old_epoch_keypairs,
            leaf_node_keypairs,
        };

        Ok(LoadedRequiredKeyMaterial {
            initial_state: self,
            loaded_key_material,
        })
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn inject_io_state(
        self,
        loaded_key_material: LoadedKeyMaterial,
    ) -> LoadedRequiredKeyMaterial<'a> {
        LoadedRequiredKeyMaterial {
            initial_state: self,
            loaded_key_material,
        }
    }
}

pub(super) struct LoadedRequiredKeyMaterial<'a> {
    initial_state: InitialProcessingState<'a>,
    loaded_key_material: LoadedKeyMaterial,
}

impl<'a> LoadedRequiredKeyMaterial<'a> {
    pub(super) fn finalize(
        self,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<ProcessedMessage, ProcessMessageError> {
        let InitialProcessingState {
            group,
            authenticated_content,
            credential,
        } = self.initial_state;
        let LoadedKeyMaterial {
            psks,
            old_epoch_keypairs,
            leaf_node_keypairs,
        } = self.loaded_key_material;

        group.process_authenticated_content(
            crypto,
            authenticated_content,
            credential,
            psks,
            old_epoch_keypairs,
            leaf_node_keypairs,
        )
    }
}
