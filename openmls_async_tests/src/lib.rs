//! End-to-end tests for the async mode of OpenMLS.
//!
//! The same group flow runs against the SQLx storage provider and against the
//! memory storage of `OpenMlsRustCrypto`. The flow is generic over the
//! provider and is checked to produce a `Send` future, so that code which is
//! generic over the provider can spawn OpenMLS futures on a multi-threaded
//! runtime.
//!
//! The `test_utils` tests run the test frameworks of the `test-utils` feature
//! in async mode.

#[cfg(test)]
mod test_utils;

#[cfg(test)]
mod tests {
    use std::{future::Future, sync::Arc};

    use openmls::prelude::tls_codec::Deserialize;
    use openmls::{
        credentials::{BasicCredential, CredentialWithKey},
        prelude::*,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
    use openmls_sqlx_storage::{Codec, SqliteStorageProvider};
    use serde::Serialize;
    use sqlx::{Connection, SqliteConnection};

    #[derive(Default)]
    struct JsonCodec;

    impl Codec for JsonCodec {
        type Error = serde_json::Error;

        fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Self::Error> {
            serde_json::to_vec(value)
        }

        fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
            serde_json::from_slice(slice)
        }
    }

    struct SqlxTestProvider<'a> {
        crypto: RustCrypto,
        storage: SqliteStorageProvider<'a, JsonCodec>,
    }

    impl<'a> OpenMlsProvider for SqlxTestProvider<'a> {
        type CryptoProvider = RustCrypto;
        type RandProvider = RustCrypto;
        type StorageProvider = SqliteStorageProvider<'a, JsonCodec>;

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

    async fn new_credential<P: OpenMlsProvider>(
        provider: &P,
        identity: &[u8],
        signature_scheme: SignatureScheme,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        let credential = BasicCredential::new(identity.to_vec());
        let signature_keys = SignatureKeyPair::new(signature_scheme).unwrap();
        signature_keys
            .store(provider.storage())
            .await
            .expect("store signature key");

        (
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signature_keys.public().into(),
            },
            signature_keys,
        )
    }

    /// Alice creates a group, adds Bob, and sends Bob an application message.
    /// Bob then loads his group from storage and decrypts a second message.
    async fn group_flow<P: OpenMlsProvider>(alice_provider: &P, bob_provider: &P) {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let group_id = GroupId::from_slice(b"async-group");

        let (alice_credential, alice_signer) =
            new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm()).await;
        let (bob_credential, bob_signer) =
            new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm()).await;

        let bob_key_package = KeyPackage::builder()
            .build(ciphersuite, bob_provider, &bob_signer, bob_credential)
            .await
            .expect("key package build failed")
            .key_package()
            .to_owned();

        let create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .build();

        let mut alice_group = MlsGroup::new_with_group_id(
            alice_provider,
            &alice_signer,
            &create_config,
            group_id.clone(),
            alice_credential,
        )
        .await
        .expect("group creation failed");

        let (_, welcome, _) = alice_group
            .add_members_without_update(alice_provider, &alice_signer, &[bob_key_package])
            .await
            .expect("add members failed");
        alice_group
            .merge_pending_commit(alice_provider)
            .await
            .expect("merge pending commit failed");

        let welcome = match transmit(welcome).extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            other => panic!("expected a welcome, got {other:?}"),
        };
        let bob_group = StagedWelcome::new_from_welcome(
            bob_provider,
            create_config.join_config(),
            welcome,
            Some(alice_group.export_ratchet_tree().into()),
        )
        .await
        .expect("staged welcome failed")
        .into_group(bob_provider)
        .await
        .expect("group from welcome failed");
        drop(bob_group);

        let mut bob_group = MlsGroup::load(bob_provider.storage(), &group_id)
            .await
            .expect("load group failed")
            .expect("group missing from storage");

        for message in [b"first message".as_slice(), b"second message".as_slice()] {
            let outgoing = alice_group
                .create_message(alice_provider, &alice_signer, message)
                .await
                .expect("create message failed");
            let protocol_message = transmit(outgoing)
                .try_into_protocol_message()
                .expect("protocol message expected");
            let processed = bob_group
                .process_message(bob_provider, protocol_message)
                .await
                .expect("process message failed");
            let ProcessedMessageContent::ApplicationMessage(application_message) =
                processed.into_content()
            else {
                panic!("expected an application message");
            };
            assert_eq!(application_message.into_bytes(), message);
        }

        bob_group
            .self_update(bob_provider, &bob_signer, LeafNodeParameters::default())
            .await
            .expect("self update failed");
        bob_group
            .merge_pending_commit(bob_provider)
            .await
            .expect("merge self update failed");
        assert_eq!(bob_group.epoch().as_u64(), 2);
    }

    fn transmit(message: MlsMessageOut) -> MlsMessageIn {
        let bytes = message.to_bytes().expect("message serialization failed");
        MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
            .expect("message deserialization failed")
    }

    /// Compiles only if the generic group flow is `Send` for every provider
    /// that is `Sync`.
    fn send_group_flow<'a, P: OpenMlsProvider + Sync>(
        alice_provider: &'a P,
        bob_provider: &'a P,
    ) -> impl Future<Output = ()> + Send + 'a {
        group_flow(alice_provider, bob_provider)
    }

    async fn sqlx_storage(
        connection: &mut SqliteConnection,
    ) -> SqliteStorageProvider<'_, JsonCodec> {
        let mut storage = SqliteStorageProvider::<JsonCodec>::new(connection);
        storage.run_migrations().await.expect("migrate storage");
        storage
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn group_flow_with_sqlx_storage() {
        let mut alice_connection = SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("connect alice storage");
        let mut bob_connection = SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("connect bob storage");

        let alice_provider = SqlxTestProvider {
            crypto: RustCrypto::default(),
            storage: sqlx_storage(&mut alice_connection).await,
        };
        let bob_provider = SqlxTestProvider {
            crypto: RustCrypto::default(),
            storage: sqlx_storage(&mut bob_connection).await,
        };

        send_group_flow(&alice_provider, &bob_provider).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn group_flow_with_memory_storage_on_spawned_task() {
        let alice_provider = Arc::new(OpenMlsRustCrypto::default());
        let bob_provider = Arc::new(OpenMlsRustCrypto::default());

        tokio::spawn(async move { send_group_flow(&*alice_provider, &*bob_provider).await })
            .await
            .expect("group flow task failed");
    }
}
