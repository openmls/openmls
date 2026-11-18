//! The migrations run as one transaction, so an interrupted or failed run
//! leaves the store as it was before the run.
//!
//! With one transaction per migration and another one for its history row,
//! a process that dies between the two leaves the migration applied but
//! unrecorded, and the next `run_migrations` applies it again. V3 and later
//! are not safe to apply twice (`CREATE TABLE` without `IF NOT EXISTS`,
//! `DROP TABLE` of a table already gone), so that store could never be
//! opened again.

use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use rusqlite::Connection;
use serde::Serialize;

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

fn table_exists(connection: &Connection, name: &str) -> bool {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .unwrap();
    count == 1
}

const HISTORY: &str = "openmls_sqlite_storage_migrations";

fn recorded_migrations(connection: &Connection) -> i64 {
    if !table_exists(connection, HISTORY) {
        return 0;
    }
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {HISTORY}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

/// The state a crash leaves between a migration's SQL and its history row:
/// a trigger aborts the insert of `version`'s history row after its SQL ran.
/// The history table is refinery's own, created ahead of the run so that the
/// trigger can be attached to it.
fn interrupt_before_history_row(connection: &Connection, version: u32) {
    connection
        .execute_batch(&format!(
            "CREATE TABLE {HISTORY} (
                 version INT4 PRIMARY KEY,
                 name VARCHAR(255),
                 applied_on VARCHAR(255),
                 checksum VARCHAR(255));
             CREATE TRIGGER interrupt BEFORE INSERT ON {HISTORY}
             WHEN NEW.version = {version}
             BEGIN SELECT RAISE(ABORT, 'interrupted before the history row'); END;"
        ))
        .unwrap();
}

#[test]
fn an_interrupted_migration_is_not_left_applied_without_its_history_row() {
    let mut connection = Connection::open_in_memory().unwrap();
    interrupt_before_history_row(&connection, 3);

    let interrupted = SqliteStorageProvider::<JsonCodec, _>::new(&mut connection).run_migrations();

    assert!(interrupted.is_err(), "the interrupted run must fail");
    assert!(
        !table_exists(&connection, "vc_emulation_group_secrets"),
        "V3 must not stay applied without its history row"
    );

    // The next run starts from the state before the interrupted one.
    connection.execute_batch("DROP TRIGGER interrupt;").unwrap();
    SqliteStorageProvider::<JsonCodec, _>::new(&mut connection)
        .run_migrations()
        .expect("the next run must complete the migrations");
}

/// V2 fails on a table it is about to create; V1 must not survive it.
#[test]
fn a_failing_migration_rolls_back_the_whole_run() {
    let mut connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch("CREATE TABLE openmls_group_data_new (obstacle INTEGER);")
        .unwrap();

    let result = SqliteStorageProvider::<JsonCodec, _>::new(&mut connection).run_migrations();

    assert!(result.is_err(), "V2 must fail on the existing table");
    assert_eq!(
        recorded_migrations(&connection),
        0,
        "no migration of a failed run may be recorded"
    );
    assert!(
        !table_exists(&connection, "openmls_encryption_keys"),
        "V1's tables must be rolled back with the run"
    );

    // Once the obstacle is gone, the same store migrates completely.
    connection
        .execute_batch("DROP TABLE openmls_group_data_new;")
        .unwrap();
    SqliteStorageProvider::<JsonCodec, _>::new(&mut connection)
        .run_migrations()
        .unwrap();
    assert!(table_exists(&connection, "openmls_encryption_keys"));
    assert!(recorded_migrations(&connection) > 1);
}
