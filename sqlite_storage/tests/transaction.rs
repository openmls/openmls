use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::storage::{
    traits::{self},
    Entity, Key, StorageProvider,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Default)]
struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestGroupId(Vec<u8>);
impl traits::GroupId<1> for TestGroupId {}
impl Key<1> for TestGroupId {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
struct ProposalRef(usize);
impl traits::ProposalRef<1> for ProposalRef {}
impl Key<1> for ProposalRef {}
impl Entity<1> for ProposalRef {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct Proposal(Vec<u8>);
impl traits::QueuedProposal<1> for Proposal {}
impl Entity<1> for Proposal {}

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new(test_name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "openmls_sqlite_storage_{test_name}_{}_{}.sqlite",
            process::id(),
            unique
        ));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let base = self.path.display().to_string();
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{base}{suffix}"));
        }
    }
}

fn open_storage(path: &Path) -> SqliteStorageProvider<JsonCodec, Connection> {
    let connection = Connection::open(path).unwrap();
    let mut storage = SqliteStorageProvider::<JsonCodec, Connection>::new(connection);
    storage.run_migrations().unwrap();
    storage
}

#[test]
fn transaction_commits_persisted_changes() {
    let db = TempDb::new("commit");
    let group_id = TestGroupId(b"commit-group".to_vec());
    let proposal_a = Proposal(b"proposal-a".to_vec());
    let proposal_b = Proposal(b"proposal-b".to_vec());

    {
        let mut storage = open_storage(db.path());
        storage
            .transaction(|tx_storage| {
                tx_storage.queue_proposal(&group_id, &ProposalRef(1), &proposal_a)?;
                tx_storage.queue_proposal(&group_id, &ProposalRef(2), &proposal_b)?;
                Ok(())
            })
            .unwrap();
    }

    let storage = open_storage(db.path());
    let proposals: Vec<(ProposalRef, Proposal)> = storage.queued_proposals(&group_id).unwrap();
    assert_eq!(
        vec![
            (ProposalRef(1), proposal_a.clone()),
            (ProposalRef(2), proposal_b.clone()),
        ],
        proposals
    );
}

#[test]
fn transaction_rolls_back_persisted_changes_on_error() {
    let db = TempDb::new("rollback");
    let group_id = TestGroupId(b"rollback-group".to_vec());
    let proposal = Proposal(b"proposal-rollback".to_vec());

    {
        let mut storage = open_storage(db.path());
        let result: Result<(), rusqlite::Error> = storage.transaction(|tx_storage| {
            tx_storage.queue_proposal(&group_id, &ProposalRef(1), &proposal)?;
            Err(rusqlite::Error::InvalidQuery)
        });
        assert!(matches!(result, Err(rusqlite::Error::InvalidQuery)));
    }

    let storage = open_storage(db.path());
    let proposals: Vec<(ProposalRef, Proposal)> = storage.queued_proposals(&group_id).unwrap();
    assert!(proposals.is_empty());
}
