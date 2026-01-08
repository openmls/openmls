//! Example implementation of a SerializedGroupId lock handler

type SerializedGroupId = Vec<u8>;
use openmls_memory_storage::MemoryStorage;

use std::sync::Arc;

use crate::Error;

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

/// A wrapper around a `MutexGuard` representing a lock for a given SerializedGroupId.
/// The `Guard` contains a reference to the underlying storage,
/// which is used to access the data.
pub struct Guard<'lock, 'a: 'lock> {
    // TODO: use this id later to ensure that all operations use correct id
    #[allow(dead_code)]
    id: &'lock SerializedGroupId,
    storage_provider: &'a MemoryStorage,
    _guard: tokio::sync::MutexGuard<'lock, ()>,
}

impl crate::traits::StorageProviderGuard<{ crate::traits::CURRENT_VERSION }> for Guard<'_, '_> {
    type Provider = MemoryStorage;

    fn provider(&self) -> &Self::Provider {
        self.storage_provider
    }
}

/// A handle that can be used to acquire a lock for a given SerializedGroupId.
/// This struct also contains a reference to the underlying storage,
/// which is used by a `Guard` to access the data.
pub struct Handle<'a> {
    id: SerializedGroupId,
    storage_provider: &'a MemoryStorage,
    registry: Arc<LockHandleRegistry>,
    mutex: Arc<tokio::sync::Mutex<()>>,
}

impl crate::traits::StorageProviderHandle<{ crate::traits::CURRENT_VERSION }> for Handle<'_> {
    type Guard<'lock, 'a: 'lock>
        = Guard<'lock, 'a>
    where
        Self: 'a;

    /// Acquire a lock on the StorageProvider for this group.
    async fn lock(&self) -> Guard<'_, '_> {
        let Self {
            id,
            storage_provider,
            mutex,
            ..
        } = self;

        // acquire the lock
        let _guard = mutex.lock().await;

        Guard {
            id,
            storage_provider,
            _guard,
        }
    }
}

impl Drop for Handle<'_> {
    fn drop(&mut self) {
        // acquire the lock on the registry
        // NOTE: since this is a synchronous mutex,
        // the executor could be blocked here.
        let mut registry = self.registry.lock().unwrap();

        // retrieve the entry
        let Some(Entry { handle_count, .. }) = registry.get_mut(&self.id) else {
            unreachable!();
        };

        // NOTE: the count should be at least 1 (representing the current handle)
        debug_assert!(*handle_count >= 1);

        // check the count
        if *handle_count == 1 {
            // remove the entry from the registry
            let _ = registry.remove(&self.id);
        } else {
            *handle_count -= 1;
        }
    }
}

/// A struct representing a lock handler that can be used
/// to lock the storage provider for a specific `SerializedGroupId` key.
#[derive(Default)]
#[cfg_attr(test, derive(Clone))]
pub struct DataLockHandler {
    /// The registry of mutexes used to acquire a lock for an individual key.
    registry: Arc<LockHandleRegistry>,

    /// The underlying storage provider
    /// NOTE: This is an `Arc` so that the `DataLockHandler` can be cloned,
    /// to share across threads in tests.
    storage_provider: Arc<MemoryStorage>,
}

impl DataLockHandler {
    #[cfg(test)]
    /// For testing: get the number of entries in the registry
    pub(crate) fn num_locks(&self) -> usize {
        // retrieve the registry of locks
        let registry = self.registry.lock().unwrap();

        // get the length of the registry
        registry.len()
    }

    #[cfg(test)]
    /// For testing: get a reference to the MemoryStorage directly
    pub(crate) fn memory_storage(&self) -> &MemoryStorage {
        &self.storage_provider
    }
}

impl crate::traits::StorageProviderManager<{ crate::traits::CURRENT_VERSION }> for DataLockHandler {
    type Handle<'a> = Handle<'a>;
    /// Lock the provided id.
    fn get_handle<
        GroupId: openmls_traits::storage::traits::GroupId<{ crate::traits::CURRENT_VERSION }>,
    >(
        &self,
        id: &GroupId,
    ) -> Result<Handle<'_>, Error> {
        // retrieve the registry of locks
        let mut registry = self.registry.lock().map_err(|_| Error)?;

        // serialize the GroupId
        let serialized_id = serde_json::to_vec(id).map_err(|_| Error)?;

        // retrieve the correct mutex from the registry,
        // inserting if not included yet.
        let entry = registry
            .entry(serialized_id.clone())
            .or_insert_with(|| Entry {
                handle_count: 0,
                mutex: Arc::new(tokio::sync::Mutex::new(())),
            });

        // clone the reference to the mutex
        let mutex = Arc::clone(&entry.mutex);

        // increment the count for the number of handles
        entry.handle_count += 1;

        Ok(Handle {
            id: serialized_id,
            storage_provider: &self.storage_provider,
            registry: Arc::clone(&self.registry),
            mutex,
        })

        // lock on registry should be released here
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::traits::*;
    use openmls::prelude::GroupId;

    // Test that the internal counts are handled correctly (based on Gemini output)
    #[test]
    fn test_handles_managed_correctly() {
        let lock_handler = DataLockHandler::default();
        let my_id = GroupId::from_slice(b"my_id");

        let handle1 = lock_handler.get_handle(&my_id).unwrap();
        assert_eq!(lock_handler.num_locks(), 1);

        {
            let _handle2 = lock_handler.get_handle(&my_id).unwrap();
            assert_eq!(lock_handler.num_locks(), 1);

            // handle is dropped here
        }

        // Verify the entry persists
        assert_eq!(lock_handler.num_locks(), 1);

        drop(handle1);

        // Verify cleanup
        assert_eq!(lock_handler.num_locks(), 0);
    }

    // Simple test (based on Gemini output)
    #[tokio::test]
    async fn test_mutex_and_cleanup() {
        let lock_handler = DataLockHandler::default();
        let my_id = GroupId::from_slice(b"my_id");

        let handler1 = lock_handler.clone();
        let id_1 = my_id.clone();
        let task1 = tokio::spawn(async move {
            let handle = handler1.get_handle(&id_1).unwrap();
            let _guard = handle.lock().await;

            assert_eq!(handler1.num_locks(), 1);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let handler2 = lock_handler.clone();
        let id_2 = my_id.clone();
        let task2 = tokio::spawn(async move {
            // ensure task1 gets the lock first
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            // get the handle (don't lock yet)
            let handle = handler2.get_handle(&id_2).unwrap();

            let start = std::time::Instant::now();
            let _guard = handle.lock().await;
            let duration = start.elapsed();

            assert!(duration >= std::time::Duration::from_millis(80));
        });

        let _ = tokio::join!(task1, task2);

        assert_eq!(lock_handler.num_locks(), 0);
    }

    // Test high contention scenario (based on Gemini output)
    #[tokio::test]
    async fn test_high_contention() {
        use rand::Rng;
        // use AtomicUsize for test counters
        use std::sync::atomic::{AtomicUsize, Ordering};

        let lock_handler = DataLockHandler::default();

        // define keys and counters
        let keys = vec![
            GroupId::from_slice(b"key_1"),
            GroupId::from_slice(b"key_2"),
            GroupId::from_slice(b"key_3"),
        ];
        let counters: Vec<Arc<AtomicUsize>> = vec![
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        ];

        let mut handles = vec![];
        let iterations_per_task = 1000;
        let num_tasks = 500;

        for _ in 0..num_tasks {
            let lock_handler = lock_handler.clone();
            let keys = keys.clone();
            let counters = counters.clone();

            handles.push(tokio::spawn(async move {
                for _ in 0..iterations_per_task {
                    // pick one of the keys randomly
                    let index = {
                        let mut rng = rand::rng();

                        rng.random_range(0..keys.len())
                    };
                    let group_id = &keys[index];

                    // 1. Get the handle (registers the key if not present)
                    let key_handle = lock_handler.get_handle(group_id).unwrap();

                    // 2. Lock it (async wait)
                    let _guard = key_handle.lock().await;

                    // 3. Increment the specific counter
                    // Add a tiny yield to simulate work and encourage overlap
                    tokio::task::yield_now().await;
                    counters[index].fetch_add(1, Ordering::SeqCst);

                    // 4. Drop guard and handle automatically here
                }
            }));
        }

        // wait for all tasks to complete
        futures::future::join_all(handles).await;

        // Check 1: Check if total increments match expected
        let total_ops: usize = counters.iter().map(|c| c.load(Ordering::SeqCst)).sum();
        assert_eq!(
            total_ops,
            num_tasks * iterations_per_task,
            "Some updates were lost!"
        );

        // Check 2: Cleanup completed correctly
        assert_eq!(
            lock_handler.num_locks(),
            0,
            "Registry should be empty after high contention test"
        )
    }
}
