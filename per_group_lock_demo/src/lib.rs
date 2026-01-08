mod data_lock_handler;

pub mod mls_group;
pub mod provider;
pub mod traits;

#[derive(Debug)]
pub struct Error;

#[cfg(test)]
mod test {

    use crate::provider::*;
    use crate::traits::*;
    use openmls::prelude::{GroupId, MlsGroupState};
    use openmls_traits::storage::StorageProvider;

    #[tokio::test]
    async fn basic_example() {
        // initialize a new provider
        let provider = Provider::default();
        let my_id = GroupId::from_slice(b"my_id");

        // get a lock handle for the new id
        let handle = provider.storage_manager().get_handle(&my_id).unwrap();
        {
            // acquire a lock
            let guard = handle.lock().await;
            let storage_provider = guard.provider();
            storage_provider
                .write_group_state(&my_id, &MlsGroupState::Operational)
                .unwrap();

            assert_eq!(provider.storage_manager().num_locks(), 1);
        }

        drop(handle);

        assert_eq!(provider.storage_manager().num_locks(), 0);

        // check that the data was updated correctly
        assert!(matches!(
            provider
                .storage_manager()
                .memory_storage()
                .group_state(&my_id)
                .unwrap(),
            Some(MlsGroupState::Operational)
        ));
    }
}
