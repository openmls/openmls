use openmls_libcrux_crypto::Provider;
use openmls_traits::{storage::*, OpenMlsProvider};

// Test type
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestGroupId(Vec<u8>);
impl traits::GroupId<CURRENT_VERSION> for TestGroupId {}
impl Key<CURRENT_VERSION> for TestGroupId {}

// Test type
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug, Clone)]
enum TestGroupState {
    Missing,
    Operational,
}
impl traits::GroupState<CURRENT_VERSION> for TestGroupState {}
impl Entity<CURRENT_VERSION> for TestGroupState {}

/// A basic example with `openmls_libcrux_provider::Provider`, which uses the
/// `MemoryStorageManager`.
#[tokio::test]
async fn basic_example() {
    // initialize a new provider
    let provider = Provider::default();
    let my_id = TestGroupId(b"my_id".to_vec());

    // get a lock handle for the new id
    let handle = provider.storage_manager().get_handle(&my_id).unwrap();
    {
        // acquire a lock
        let storage_provider = handle.lock().await;

        // write some data
        storage_provider
            .write_group_state(&TestGroupState::Operational)
            .unwrap();

        // check that the data was updated correctly
        assert!(matches!(
            storage_provider.group_state().unwrap(),
            Some(TestGroupState::Operational)
        ));

        // the lock is dropped
    }
}
