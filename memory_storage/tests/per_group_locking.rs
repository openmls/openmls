use openmls_memory_storage::MemoryStorageManager;
use openmls_traits::storage::*;
use std::sync::Arc;

// Test type
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestGroupId(Vec<u8>);
impl traits::GroupId<CURRENT_VERSION> for TestGroupId {}
impl Key<CURRENT_VERSION> for TestGroupId {}

// Test that the internal counts are handled correctly (based on Gemini output)
#[test]
fn test_handles_managed_correctly() {
    let lock_handler = MemoryStorageManager::default();
    let my_id = TestGroupId(b"my_id".to_vec());

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
    let lock_handler = MemoryStorageManager::default();
    let my_id = TestGroupId(b"my_id".to_vec());

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

    let lock_handler = MemoryStorageManager::default();

    // define keys and counters
    let keys = vec![
        TestGroupId(b"key_1".to_vec()),
        TestGroupId(b"key_2".to_vec()),
        TestGroupId(b"key_3".to_vec()),
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
