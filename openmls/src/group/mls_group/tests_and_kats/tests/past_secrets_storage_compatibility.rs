#![cfg(not(target_arch = "wasm32"))]

use crate::prelude::*;
use crate::prelude::{mls_group::MessageSecretsStore, past_secrets::MessageSecretsWithTimestamp};
use crate::schedule::message_secrets::MessageSecrets;

use openmls_rust_crypto::RustCrypto as CryptoProvider;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::storage::StorageProvider;
use serde::Serialize;

const SQL_STATEMENTS_PATH: &str = "src/group/mls_group/tests_and_kats/tests/dump.sql";
const TEST_GROUP_ID: &[u8] = b"test_group_id";

fn load_statements(filename: &str) -> String {
    std::fs::read_to_string(filename).unwrap()
}

/// Test storage format compatibility with earlier storage formats
/// serialized `MessageSecrets` should automatically be mapped to `MessageSecretsWithTimestamp`
/// with a `None` timestamp.
/// - Sets up a provider using an in-memory Sqlite database
/// - Loads data from a Sqlite dump using an earlier version of the MessageSecretsStore (openmls =
///   0.8.1)
/// - Check that an MlsGroup can be loaded from the storage provider
/// - Check that the group's MessageSecretsStore can be loaded from the storage provider
/// - Ensure that the values were deserialized correctly into the new format
/// - Check the serialization/deserialization of this MessageSecretsStore, both before and after
///   making additional changes
#[test]
fn test_storage_compatibility() {
    {
        // load SQL statements
        let sql_statements = load_statements(SQL_STATEMENTS_PATH);
        // prepare the DB
        let conn = Connection::open_in_memory().expect("error opening database connection");
        conn.execute_batch(&sql_statements)
            .expect("error executing sqlite statements");

        // set up a new provider using the connection
        let alice_provider = &Provider::new(conn);

        let group_id = GroupId::from_slice(TEST_GROUP_ID);

        // ensure the group can be loaded from storage
        let alice_group = MlsGroup::load(alice_provider.storage(), &group_id)
            .expect("error loading group from storage")
            .expect("no group available for this group id");
        // retrieve the ciphersuite
        let ciphersuite = alice_group.ciphersuite();

        // load the message secrets
        let mut message_secrets_store: MessageSecretsStore = alice_provider
            .storage()
            .message_secrets(&group_id)
            .expect("error loading message secrets from storage")
            .expect("no message secrets available for this group id");

        // ensure that all deserialized timestamps are None
        assert!(message_secrets_store
            .iter_past_epoch_trees()
            .all(|tree| tree.timestamp().is_none()));

        // ensure that the store matches the result of serializing/deserializing it
        message_secrets_store.ensure_deserialization_matches();

        // modify the loaded MessageSecretsStore, adding a new past epoch tree with a timestamp
        message_secrets_store.add_past_epoch_tree(
            0,
            MessageSecrets::random(ciphersuite, alice_provider.rand(), LeafNodeIndex::new(0))
                .with_timestamp(std::time::SystemTime::now()),
            Vec::new(),
        );

        // ensure that the store matches the result of serializing/deserializing it
        message_secrets_store.ensure_deserialization_matches();
    }
}

/// Test that `MessageSecretsWithTimestamp` is correctly serialized and deserialized
#[test]
fn test_serialize_deserialize() {
    // set up a basic provider
    let provider = openmls_libcrux_crypto::Provider::default();

    // create a MessageSecrets
    let message_secrets = MessageSecrets::random(
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        provider.rand(),
        LeafNodeIndex::new(0),
    );

    // serialize MessageSecrets -> deserialize MessageSecretsWithTimestamp
    let serialized = serde_json::to_vec(&message_secrets).expect("error when serializing");
    let deserialized: MessageSecretsWithTimestamp =
        serde_json::from_slice(&serialized).expect("error when deserializing");
    assert!(deserialized == message_secrets.clone().with_timestamp(None));

    // serialize MessageSecretsWithTimestamp -> deserialize MessageSecretsWithTimestamp
    let with_timestamp = message_secrets.with_timestamp(std::time::SystemTime::now());
    let serialized = serde_json::to_vec(&with_timestamp).expect("error when serializing");
    let deserialized: MessageSecretsWithTimestamp =
        serde_json::from_slice(&serialized).expect("error when deserializing");
    assert!(deserialized == with_timestamp);
}

/// A test provider backed by a Sqlite storage provider.
struct Provider {
    crypto: CryptoProvider,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}

impl Provider {
    fn new(conn: Connection) -> Self {
        Self {
            crypto: CryptoProvider::default(),
            storage: SqliteStorageProvider::new(conn),
        }
    }
}

/// A test codec.
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

impl MessageSecretsStore {
    /// A helper function that checks that a [`MessageSecretsStore`] is serialized
    /// and deserialized correctly.
    fn ensure_deserialization_matches(&self) {
        let serialized = serde_json::to_vec(self).expect("error when serializing");
        let deserialized: MessageSecretsStore =
            serde_json::from_slice(&serialized).expect("error when deserializing");

        // check equality
        assert_eq!(self, &deserialized);
    }
}

/// Test that old `EpochTree` payloads containing `Member` (with `encryption_key`)
/// deserialize correctly into the new format using `PastEpochMember` (without
/// `encryption_key`), and that the new format omits `encryption_key` on serialization.
#[test]
fn past_epoch_member_compat() {
    use crate::group::mls_group::past_secrets::PastEpochMember;

    // Serialize a full Member (old format with encryption_key)
    let member = Member::new(
        LeafNodeIndex::new(5),
        vec![99, 99, 99],
        vec![42, 43, 44],
        BasicCredential::new(b"Alice".to_vec()).into(),
    );
    let member_json = serde_json::to_string(&member).expect("error serializing Member");
    assert!(member_json.contains("encryption_key"));

    // Deserialize as PastEpochMember — encryption_key should be silently ignored
    let past_member: PastEpochMember = serde_json::from_str(&member_json)
        .expect("error deserializing old Member as PastEpochMember");
    assert_eq!(past_member.index, LeafNodeIndex::new(5));
    assert_eq!(past_member.signature_key, vec![42, 43, 44]);

    // Re-serialize — encryption_key should NOT be in the output
    let reserialized = serde_json::to_string(&past_member).expect("error serializing");
    assert!(
        !reserialized.contains("encryption_key"),
        "new format should not contain encryption_key"
    );

    // Round-trip
    let roundtripped: PastEpochMember =
        serde_json::from_str(&reserialized).expect("error deserializing new format");
    assert_eq!(past_member, roundtripped);
}

/// Test that the existing SQL dump (created with old Member format including
/// encryption_key) can be loaded, modified, and round-tripped correctly
/// with the new PastEpochMember format.
#[test]
fn storage_compatibility_with_past_epoch_member() {
    let sql_statements = load_statements(SQL_STATEMENTS_PATH);
    let conn = Connection::open_in_memory().expect("error opening database connection");
    conn.execute_batch(&sql_statements)
        .expect("error executing sqlite statements");

    let alice_provider = &Provider::new(conn);
    let group_id = GroupId::from_slice(TEST_GROUP_ID);
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    // Load the old-format store
    let mut store: MessageSecretsStore = alice_provider
        .storage()
        .message_secrets(&group_id)
        .expect("error loading message secrets")
        .expect("no message secrets available");

    // Add a new epoch with PastEpochMember leaves
    use crate::group::mls_group::past_secrets::PastEpochMember;
    let leaves = vec![PastEpochMember {
        index: LeafNodeIndex::new(0),
        credential: BasicCredential::new(b"Alice".to_vec()).into(),
        signature_key: vec![1, 2, 3, 4],
    }];
    store.add_past_epoch_tree(
        99u64,
        MessageSecrets::random(ciphersuite, alice_provider.rand(), LeafNodeIndex::new(0))
            .with_timestamp(std::time::SystemTime::now()),
        leaves,
    );

    // Verify the new epoch's leaves are accessible
    let leaves_map = store.leaves_for_epoch(GroupEpoch::from(99u64));
    assert_eq!(leaves_map.len(), 1);
    let member = leaves_map[&LeafNodeIndex::new(0)];
    assert_eq!(member.signature_key, vec![1, 2, 3, 4]);

    // Round-trip serialization
    store.ensure_deserialization_matches();

    // Verify encryption_key is not in the serialized output
    let serialized = serde_json::to_string(&store).expect("error serializing");
    assert!(
        !serialized.contains("encryption_key"),
        "serialized store should not contain encryption_key"
    );
}
