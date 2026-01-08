use super::{MemoryStorageError, MemoryStorageInner};

use std::sync::Arc;

use openmls_traits::storage::CURRENT_VERSION;

type SerializedGroupId = Vec<u8>;

/// An entry in a `LockHandleRegistry`.
/// This struct keeps track of the mutex representing the mutex that
/// can be used to acquire a lock for a given SerializedGroupId.
struct Entry {
    /// A mutex containing a dummy value, representing the
    /// relevant mutex for a given SerializedGroupId.
    mutex: Arc<tokio::sync::Mutex<()>>,

    /// The total number of handles that exist for this entry
    /// NOTE: `Arc::strong_count()` is not used here, since
    /// in theory the `mutex` field could be cloned again, e.g.
    /// for testing purposes, but what this entry should track is
    /// always how many handles exist for the underlying LockHandleRegistry.
    /// However, since this mutex is not directly exposed outside this module,
    /// it should _never_ be cloned in an unexpected way.
    handle_count: usize,
}

/// A registry of mutexes that can be used to acquire a lock for a given SerializedGroupId.
///
/// NOTE: since the registry wraps the HashMap in an `std::sync::Mutex`, locking it
/// could block the executor.
type LockHandleRegistry = std::sync::Mutex<std::collections::HashMap<SerializedGroupId, Entry>>;

/// A handle that can be used to acquire a lock for a given SerializedGroupId.
/// This struct also contains a reference to the underlying storage,
/// which is used by a `MemoryStorageGuard` to access the data.
pub struct Handle<'a> {
    // TODO: reference?
    serialized_group_id: SerializedGroupId,
    storage: &'a MemoryStorageInner,
    registry: Arc<LockHandleRegistry>,
    mutex: Arc<tokio::sync::Mutex<()>>,
}

impl Drop for Handle<'_> {
    fn drop(&mut self) {
        // acquire the lock on the registry
        // NOTE: since this is a synchronous mutex,
        // the executor could be blocked here.
        let mut registry = self.registry.lock().unwrap();

        // retrieve the entry
        let Some(Entry { handle_count, .. }) = registry.get_mut(&self.serialized_group_id) else {
            unreachable!();
        };

        // NOTE: the count should be at least 1 (representing the current handle)
        debug_assert!(*handle_count >= 1);

        // check the count
        if *handle_count == 1 {
            // remove the entry from the registry
            let _ = registry.remove(&self.serialized_group_id);
        } else {
            *handle_count -= 1;
        }
    }
}

impl openmls_traits::storage::StorageProviderHandle<{ CURRENT_VERSION }> for Handle<'_> {
    type Guard<'lock>
        = MemoryStorageGuard<'lock>
    where
        Self: 'lock;

    /// Acquire a lock on the StorageProvider for this group.
    async fn lock(&self) -> Self::Guard<'_> {
        let Self {
            serialized_group_id,
            storage,
            mutex,
            ..
        } = self;

        // acquire the lock
        let _guard = mutex.lock().await;

        Self::Guard {
            serialized_group_id: super::SerializedGroupIdRef {
                bytes: serialized_group_id,
            },
            storage,
            _guard,
        }
    }
}

/// A struct representing a lock handler that can be used
/// to lock the storage provider for a specific `SerializedGroupId` key.
#[derive(Default)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone))]
pub struct MemoryStorageManager {
    /// The registry of mutexes used to acquire a lock for an individual key.
    registry: Arc<LockHandleRegistry>,

    /// The underlying storage provider
    /// NOTE: This is an `Arc` so that the `MemoryStorageManager` can be cloned,
    /// to share across threads in tests.
    storage_provider: Arc<MemoryStorageInner>,
}

impl MemoryStorageManager {
    #[cfg(feature = "test-utils")]
    /// For testing: get the number of entries in the registry
    pub fn num_locks(&self) -> usize {
        // retrieve the registry of locks
        let registry = self.registry.lock().unwrap();

        // get the length of the registry
        registry.len()
    }
}

impl openmls_traits::storage::StorageProviderManager<{ CURRENT_VERSION }> for MemoryStorageManager {
    type Error = MemoryStorageError;
    type Handle<'a> = Handle<'a>;
    /// Lock the provided id.
    fn get_handle<GroupId: openmls_traits::storage::traits::GroupId<{ CURRENT_VERSION }>>(
        &self,
        id: &GroupId,
    ) -> Result<Handle<'_>, MemoryStorageError> {
        // retrieve the registry of locks
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| MemoryStorageError::LockError)?;

        // serialize the GroupId
        let serialized_group_id = serde_json::to_vec(id)?;

        // retrieve the correct mutex from the registry,
        // inserting if not included yet.
        let entry = registry
            .entry(serialized_group_id.clone())
            .or_insert_with(|| Entry {
                handle_count: 0,
                mutex: Arc::new(tokio::sync::Mutex::new(())),
            });

        // clone the reference to the mutex
        let mutex = Arc::clone(&entry.mutex);

        // increment the count for the number of handles
        entry.handle_count += 1;

        Ok(Handle {
            serialized_group_id,
            storage: &self.storage_provider,
            registry: Arc::clone(&self.registry),
            mutex,
        })

        // lock on registry should be released here
    }
}

/// A wrapper around a `MutexGuard` representing a lock for a given SerializedGroupId.
/// The `Guard` contains a reference to the underlying storage,
/// which is used to access the data.
pub struct MemoryStorageGuard<'lock> {
    // TODO: use this id later to ensure that all operations use correct id
    pub(super) serialized_group_id: super::SerializedGroupIdRef<'lock>,
    pub(super) storage: &'lock MemoryStorageInner,
    _guard: tokio::sync::MutexGuard<'lock, ()>,
}
