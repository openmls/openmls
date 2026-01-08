//! A proof-of-concept `MlsGroup` illustrating async functions that can load a group from the
//! storage provider manager.

use openmls::prelude::GroupId;
#[cfg(test)]
use openmls::prelude::{CredentialWithKey, MlsGroupCreateConfig, MlsMessageOut};

use crate::Error;

/// (For illustration purposes) a wrapper for the MlsGroup, which provides
/// an async load operation.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MlsGroup {
    #[allow(dead_code)]
    group: openmls::prelude::MlsGroup,
}

impl MlsGroup {
    /// Loads the state of the group with given id from persisted state.
    pub async fn load<Storage: crate::traits::StorageProviderManager>(
        storage: &Storage,
        group_id: &GroupId,
    ) -> Result<Option<Self>, Error> {
        // use all traits
        use crate::traits::*;

        // get a handle and lock the storage provider
        let handle = storage.get_handle(group_id)?;
        let guard = handle.lock().await;

        // retrieve the underlying StorageProvider
        // TODO: might be a better API if this and getting the guard were a single call
        let provider = guard.provider();

        // retrieve the group from the StorageProvider
        let mls_group = openmls::prelude::MlsGroup::load(provider, group_id).map_err(|_| Error)?;

        Ok(mls_group.map(|group| Self { group }))

        // guard and handle should be dropped at the end of this block
    }

    #[cfg(test)]
    /// (For testing) Create and store an MlsGroup.
    /// XXX: hacky way to acquire the lock
    async fn new_with_group_id(
        provider: &crate::provider::Provider,
        signer: &impl openmls_traits::signatures::Signer,
        mls_group_create_config: &MlsGroupCreateConfig,
        group_id: GroupId,
        credential_with_key: CredentialWithKey,
    ) -> Result<Self, Error> {
        // use all traits
        use crate::traits::*;

        // get a handle and lock the storage provider
        let handle = provider.storage_manager().get_handle(&group_id)?;
        let _guard = handle.lock().await;

        openmls::prelude::MlsGroup::new_with_group_id(
            provider,
            signer,
            mls_group_create_config,
            group_id,
            credential_with_key,
        )
        .map(|group| Self { group })
        .map_err(|_| Error)
    }

    #[cfg(test)]
    /// (For testing) Create an application message
    /// XXX: hacky way to acquire the lock.
    async fn create_message(
        &mut self,
        provider: &crate::provider::Provider,
        signer: &impl openmls_traits::signatures::Signer,
        message: &[u8],
    ) -> Result<MlsMessageOut, Error> {
        // use all traits
        use crate::traits::*;

        // NOTE: this is read from the in-memory representation of the PublicGroup.
        let group_id = self.group.group_id();

        // get a handle and lock the storage provider
        let handle = provider.storage_manager().get_handle(group_id)?;
        let _guard = handle.lock().await;

        self.group
            .create_message(provider, signer, message)
            .map_err(|_| Error)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use openmls::prelude::Ciphersuite;
    use openmls::test_utils::single_group_test_framework::*;

    const TEST_CIPHERSUITE: Ciphersuite =
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

    /// Helper method for initializing a group (locking)
    async fn init_group(
        provider: &crate::provider::Provider,
        group_id: &GroupId,
    ) -> (MlsGroup, impl openmls_traits::signatures::Signer) {
        // create a new credential with key and signer
        let (credential_with_key, signer) = generate_credential(
            b"alice".into(),
            TEST_CIPHERSUITE.signature_algorithm(),
            provider,
        );

        // create a group (also writes to storage provider)
        let group = crate::mls_group::MlsGroup::new_with_group_id(
            provider,
            &signer,
            &MlsGroupCreateConfig::default(),
            group_id.clone(),
            credential_with_key,
        )
        .await
        .unwrap();

        (group, signer)
    }

    // simple test
    #[tokio::test]
    async fn test_load_store_group() {
        use crate::traits::*;

        // initialize the provider
        let provider = crate::provider::Provider::default();

        // initialize a GroupId and the group
        let group_id = GroupId::from_slice(b"group");
        let (group_orig, _) = init_group(&provider, &group_id).await;

        // test loading the group from storage
        let group_loaded = crate::mls_group::MlsGroup::load(provider.storage_manager(), &group_id)
            .await
            .expect("loading failed with error")
            .expect("no group available");

        // check that the groups match
        assert_eq!(group_orig, group_loaded);
    }

    // Test async message handling
    #[tokio::test]
    async fn test_async_message_creation() {
        // initialize the provider
        let provider = crate::provider::Provider::default();

        // initialize a GroupId and the group
        let group_id = GroupId::from_slice(b"group");
        let (mut group, signer) = init_group(&provider, &group_id).await;

        // create application messages
        group
            .create_message(&provider, &signer, b"my_other_message")
            .await
            .unwrap();
    }
}
