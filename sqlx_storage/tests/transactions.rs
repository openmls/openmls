use openmls::prelude::{test_utils::new_credential, *};
use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto, types::CryptoError};
use serde::Serialize;

pub use openmls_libcrux_crypto::CryptoProvider;

/// Example for transactions with a sqlx provider
/// uses `openmls_libcrux_crypto::Provider`, which is an OpenMlsProvider implementation
/// that has been adapted to use an in-memory sqlx/sqlite provider as its storage provider,
/// and to provide a transaction interface.
///
/// `Provider::get_transaction()` initializes a transaction that locks
/// the database for reads and writes, and returns a transaction wrapper
/// that can be provided as an OpenMlsProvider to OpenMLS methods.
#[tokio::test(flavor = "multi_thread")]
async fn example_openmls_provider_level_transactions() {
    // this provider includes a sqlx/sqlite provider
    // allows retrieving a provider with transaction
    let alice_provider = &ExampleProvider::new().unwrap();
    let ciphersuite = alice_provider.crypto().supported_ciphersuites()[0];

    // Generate credentials with keys
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(WireFormatPolicy::default())
        .ciphersuite(ciphersuite)
        .build();

    let group_id = GroupId::from_slice(b"Test Group");

    // Create a group within a transaction, with rollback
    {
        // get transaction
        let provider = alice_provider.get_transaction().await.unwrap();

        // perform operation
        let _alice_group = MlsGroup::new_with_group_id(
            &provider,
            &alice_signer,
            &mls_group_create_config,
            group_id.clone(),
            alice_credential.clone(),
        )
        .expect("An unexpected error occurred.");

        // rollback transaction automatically
    }

    // try to load the group, to check if the transaction was rolled back
    {
        // get a new transaction
        let provider = alice_provider.get_transaction().await.unwrap();

        // no group info should be retrievable
        assert!(
            MlsGroup::load(provider.storage(), &group_id)
                .unwrap()
                .is_none()
        );
    }

    // Create a group within a transaction, and commit the changes
    {
        // get transaction
        let provider = alice_provider.get_transaction().await.unwrap();

        // perform operation
        let _alice_group = MlsGroup::new_with_group_id(
            &provider,
            &alice_signer,
            &mls_group_create_config,
            group_id.clone(),
            alice_credential.clone(),
        )
        .expect("An unexpected error occurred.");

        // commit transaction
        provider.commit().await.unwrap();
    }

    // load the group, to check if the transaction was committed successfully
    {
        // get transaction
        let provider = alice_provider.get_transaction().await.unwrap();

        // group has now been written
        assert!(
            MlsGroup::load(provider.storage(), &group_id)
                .unwrap()
                .is_some()
        );
    }
}

/// An example provider with a transaction-capable sqlx/sqlite storage provider.
pub struct ExampleProvider {
    crypto: openmls_libcrux_crypto::CryptoProvider,
    storage: openmls_sqlx_storage::SqliteStorageProvider<JsonCodec>,
}

/// A transaction created on the [`ExampleProvider`].
///
/// If this provider falls out of scope, the transaction rolls back automatically.
pub struct ProviderWithTransaction<'a> {
    /// Reference to the [`ExampleProvider`]'s crypto provider.
    crypto: &'a openmls_libcrux_crypto::CryptoProvider,
    /// A storage handle with an in-progress exclusive transaction.
    transaction: openmls_sqlx_storage::SqliteStorageProviderWithTransaction<'a, JsonCodec>,
}

impl ProviderWithTransaction<'_> {
    /// Commit a database transaction.
    pub async fn commit(self) -> Result<(), sqlx::Error> {
        self.transaction.commit_transaction().await
    }

    /// Roll back a database transcaction.
    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        self.transaction.rollback_transaction().await
    }
}

impl ExampleProvider {
    /// Create a transaction on the storage provider.
    /// The returned [`ProviderWithTransaction`] can be used as an [`OpenMlsProvider`]
    /// with the OpenMLS APIs.
    pub async fn get_transaction<'a>(&'a self) -> Result<ProviderWithTransaction<'a>, sqlx::Error> {
        let transaction = self.storage.get_transaction().await?;
        Ok(ProviderWithTransaction {
            transaction,
            crypto: &self.crypto,
        })
    }

    /// Set up a new provider.
    pub fn new() -> Result<Self, CryptoError> {
        let crypto = openmls_libcrux_crypto::CryptoProvider::new()?;

        // set up the storage provider
        let mut storage = openmls_sqlx_storage::SqliteStorageProvider::<JsonCodec>::default();
        storage.run_migrations().expect("failed to run migrations");

        Ok(Self { crypto, storage })
    }
}

/// OpenMlsProvider implementation for the main ExampleProvider.
impl OpenMlsProvider for ExampleProvider {
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProvider = openmls_sqlx_storage::SqliteStorageProvider<JsonCodec>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// OpenMlsProvider implementation for the transaction interface.
impl<'a> OpenMlsProvider for ProviderWithTransaction<'a> {
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProvider =
        openmls_sqlx_storage::SqliteStorageProviderWithTransaction<'a, JsonCodec>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.transaction
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        self.crypto
    }
}

/// An example codec.
#[derive(Default)]
pub struct JsonCodec;

impl openmls_sqlx_storage::Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}
