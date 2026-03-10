use crate::prelude::mls_group::MessageSecretsStore;
use crate::prelude::*;
use crate::schedule::message_secrets::MessageSecrets;

use openmls_libcrux_crypto::CryptoProvider;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::storage::StorageProvider;
use serde::Serialize;

const TEST_GROUP_ID: &[u8] = b"test_group_id";

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

struct Provider {
    crypto: CryptoProvider,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
}

impl Provider {
    fn new(conn: Connection) -> Self {
        Self {
            crypto: CryptoProvider::new().unwrap(),
            storage: SqliteStorageProvider::new(conn),
        }
    }
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

impl MessageSecretsStore {
    fn ensure_deserialization_matches(&self) {
        let serialized = serde_json::to_vec(self).expect("error when serializing");
        let deserialized: MessageSecretsStore =
            serde_json::from_slice(&serialized).expect("error when deserializing");

        // check equality
        assert_eq!(self, &deserialized);
    }
}

/// Test storage format compatibility with earlier storage formats
/// serialized `MessageSecrets` should automatically be mapped to `MessageSecretsWithTimestamp`
/// with a `None` timestamp.
#[test]
fn test_storage_compatibility() {
    {
        // prepare the DB
        let conn = Connection::open_in_memory().unwrap();
        let statements = include_str!("dump.sql");
        conn.execute_batch(&statements).unwrap();

        // set up a new provider
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
